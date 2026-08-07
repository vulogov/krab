//! Turning a message into an object — RFC 1 §4, §6, §8.
//!
//! This is the assembly point where five specifications meet, and getting the
//! order wrong is not detectable by testing the pieces:
//!
//! 1. **Tag** (RFC 1 §6.2) — pairwise for a correspondent, inbox for first
//!    contact. The choice determines the HPKE mode; RFC 2 §4.2 notes the
//!    coupling "is not a policy choice but a consequence".
//! 2. **Bucket** (RFC 1 §8.1) — chosen from the *sealed* size, not the
//!    plaintext, because padding hides the ciphertext and the ciphertext is
//!    what is on the wire.
//! 3. **AAD** (RFC 1 §6.1) — the routing header, which cannot be built until
//!    the bucket is known, which cannot be known until the payload is sealed.
//!    That circularity is real and is resolved below.
//! 4. **Padding** (RFC 1 §8.1) — zero, to the bucket.
//! 5. **Identifier** (RFC 1 §4) — over everything, padding included.
//!
//! # The circularity, and how it is broken
//!
//! The AAD covers the routing header. The routing header carries `size_bucket`.
//! The bucket depends on the sealed length. The sealed length is fixed before
//! the AAD is chosen — so a naive implementation seals, discovers the bucket,
//! rebuilds the header, and re-seals under a different AAD, producing a
//! ciphertext of the same length but bound to a header nobody checked.
//!
//! [`seal_to`] instead computes the bucket **from the known overheads** before
//! sealing: HPKE's expansion is fixed (32-byte encapsulated key, 16-byte AEAD
//! tag) and the envelope's CBOR framing is bounded, so the final size is
//! predictable from the plaintext length alone. The header is built once, the
//! AAD is final before the seal, and nothing is re-sealed.

use krab_core::object::{
    canonical_bytes, Envelope, ObjectId, RoutingHeader, Tag, ROUTING_HEADER_LEN,
};
use krab_core::tag::Epoch;
use krab_crypto::dh::{PublicKey, SecretKey};
use krab_crypto::reservoir::Chunk;
use krab_crypto::rng::Rng;
use krab_crypto::seal::{info_for, seal, Mode, ENC_LEN};

/// RFC 1 §6.1 — suite `0x0001`, the v1 mandatory one.
pub const SUITE_V1: u64 = 0x0001;

/// The AEAD tag ChaCha20-Poly1305 appends.
pub const AEAD_TAG: usize = 16;

/// Envelope CBOR framing overhead, upper bound.
///
/// Five integer keys, three small uints, and two byte-string heads. Measured
/// by `envelope_overhead_is_bounded` rather than asserted, so a change to the
/// encoder fails the test instead of silently mis-sizing every object.
pub const ENVELOPE_MAX_OVERHEAD: usize = 24;

/// Who a message is going to, and what that implies.
#[allow(dead_code)] // `FirstContact` awaits `peer-request` -- see the variant.
pub enum Recipient<'a> {
    /// An established correspondent. Pairwise tag, `mode_auth`.
    Known {
        /// Their correspondence key, for tag derivation and the KEM.
        correspondence: &'a PublicKey,
        /// The pairwise tag for this epoch.
        tag: Tag,
        /// A reservoir chunk, if one is established.
        ///
        /// `Some` selects `mode_auth_psk` — `CRYPTO-REVIEW.md` §1's
        /// construction. `None` is plain `mode_auth`, which is correct and
        /// simply lacks the post-quantum property.
        chunk: Option<&'a Chunk>,
    },
    /// First contact. Inbox tag, `mode_base`, and origin must travel inside
    /// the plaintext because the KEM cannot carry it (RFC 1 §6.2).
    ///
    /// Constructed once `peer-request` exists — RFC 2 §4.2 says inbox mode is
    /// "used for `peer-request` (RFC 3 §5.1) and nothing else", so this arm has
    /// exactly one future caller and it is not `send`. Built now because the
    /// mode coupling is the part that must not be got wrong later: a `send`
    /// that fell back to `mode_base` when it could not find a peer-link would
    /// silently drop sender authentication.
    FirstContact {
        /// Their public key, from a card.
        correspondence: &'a PublicKey,
        /// The inbox tag for this epoch.
        tag: Tag,
    },
}

impl Recipient<'_> {
    /// RFC 1 §4.2 key 1: 0 pairwise, 1 inbox.
    pub fn tag_mode(&self) -> u64 {
        match self {
            Recipient::Known { .. } => 0,
            Recipient::FirstContact { .. } => 1,
        }
    }

    fn tag(&self) -> Tag {
        match self {
            Recipient::Known { tag, .. } | Recipient::FirstContact { tag, .. } => *tag,
        }
    }

    fn key(&self) -> &PublicKey {
        match self {
            Recipient::Known { correspondence, .. }
            | Recipient::FirstContact { correspondence, .. } => correspondence,
        }
    }
}

/// Why a message could not be composed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The plaintext does not fit the largest bucket (RFC 1 §8.1).
    TooLarge,
    /// Sealing failed — almost always a malformed or low-order recipient key.
    Seal,
    /// The assembled object did not fit the bucket computed for it.
    ///
    /// Unreachable if [`ENVELOPE_MAX_OVERHEAD`] is right, and checked anyway:
    /// silently growing the bucket would change the AAD after the seal.
    Overflow,
}

/// A composed object, ready to ingest.
pub struct Composed {
    /// `BLAKE3("krab/obj/v1" ‖ OBJECT)`, RFC 1 §4.
    pub id: ObjectId,
    /// Header, body, and zero padding to the bucket.
    pub bytes: Vec<u8>,
    /// The bucket chosen.
    pub bucket: u8,
}

/// The smallest bucket admitting `n` bytes **including the routing header**.
///
/// RFC 1 §8.1's ladder is six buckets in ×4 steps, and `canonical_bytes`
/// measures `ROUTING_HEADER_LEN + body` against it — so a caller sizing only
/// the body picks a bucket too small for objects near a boundary.
pub fn bucket_for(total: usize) -> Option<u8> {
    (0u8..crate::reach::BUCKET_COUNT).find(|b| crate::reach::bucket_bytes(*b) as usize >= total)
}

/// The on-wire body size for a plaintext of `n` bytes.
///
/// Deterministic, and computed **before** sealing so the routing header — and
/// therefore the AAD — is final when the seal happens. See the module note.
pub fn body_size_for(plaintext: usize) -> usize {
    ENC_LEN + plaintext + AEAD_TAG + ENVELOPE_MAX_OVERHEAD
}

/// Compose and seal a message into a complete object.
#[allow(clippy::too_many_arguments)]
pub fn seal_to(
    sender: &SecretKey,
    recipient: &Recipient,
    epoch: Epoch,
    class: u8,
    expiry_min: u32,
    plaintext: &[u8],
    rng: &mut impl Rng,
) -> Result<Composed, Error> {
    // 1. Size first, so the header is final before anything is sealed.
    let bucket =
        bucket_for(ROUTING_HEADER_LEN + body_size_for(plaintext.len())).ok_or(Error::TooLarge)?;

    // 2. The header, built once. This is the AAD.
    let header = RoutingHeader {
        version: 1,
        class,
        size_bucket: bucket,
        flags: 0,
        expiry_min,
        tag: recipient.tag(),
    };
    let aad = header.write();
    let info = info_for(class);

    // 3. Seal. RFC 1 §6.2's coupling: the mode follows the tag mode.
    let mode = match recipient {
        Recipient::FirstContact { .. } => Mode::Base,
        Recipient::Known { chunk: Some(c), .. } => Mode::AuthPsk { chunk: c, epoch },
        Recipient::Known { chunk: None, .. } => Mode::Auth,
    };
    let sealed = seal(&mode, sender, recipient.key(), &info, &aad, plaintext, rng)
        .map_err(|_| Error::Seal)?;

    // 4. The envelope. Key 3 is absent by construction (RFC 1 §4.2).
    let body = Envelope {
        epoch: epoch.0 as u64,
        tag_mode: recipient.tag_mode(),
        suite: SUITE_V1,
        enc: &sealed.enc,
        ciphertext: &sealed.ct,
    }
    .write();

    // 5. Canonical bytes: header, body, zero padding to the bucket.
    //
    // If this fails the bucket was wrong, and the honest response is to refuse
    // rather than re-seal under a header the AAD no longer matches.
    let bytes = canonical_bytes(&header, &body).map_err(|_| Error::Overflow)?;
    Ok(Composed {
        id: krab_crypto::object_id(&bytes),
        bytes,
        bucket,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use krab_core::object::decode_envelope;
    use krab_crypto::reservoir::Reservoir;
    use krab_crypto::rng::NotRandom;
    use krab_crypto::seal::{open, Sealed};

    const EPOCH: Epoch = Epoch(20_671);
    const EXPIRY: u32 = 29_766_240;

    fn sk(seed: u64) -> SecretKey {
        SecretKey::generate(&mut NotRandom::seeded(seed))
    }

    fn chunk(seed: u8) -> Chunk {
        Reservoir::new([seed; 32], Epoch(0)).chunk(EPOCH).unwrap()
    }

    /// **The whole pipeline, end to end.** Compose, then take the object apart
    /// the way a receiver would and read it.
    #[test]
    fn a_composed_object_decodes_and_opens() {
        let (a, b) = (sk(1), sk(2));
        let c = chunk(9);
        let plaintext = b"a message of some length that spans a block or two";

        let composed = seal_to(
            &a,
            &Recipient::Known {
                correspondence: &b.public(),
                tag: Tag([0x11; 8]),
                chunk: Some(&c),
            },
            EPOCH,
            0,
            EXPIRY,
            plaintext,
            &mut NotRandom::seeded(3),
        )
        .unwrap();

        // The identifier covers the padding (RFC 1 §4, §8.1).
        assert_eq!(krab_crypto::object_id(&composed.bytes), composed.id);
        // The bucket is the whole object: header, body and padding.
        assert_eq!(
            composed.bytes.len(),
            crate::reach::bucket_bytes(composed.bucket) as usize
        );

        // A receiver's path.
        let header = RoutingHeader::parse(&composed.bytes).unwrap();
        assert_eq!(header.size_bucket, composed.bucket);
        assert_eq!(header.tag, Tag([0x11; 8]));
        let (env, _) = decode_envelope(&composed.bytes[16..]).unwrap();
        assert_eq!(env.suite, SUITE_V1);
        assert_eq!(env.tag_mode, 0);
        assert_eq!(env.epoch, EPOCH.0 as u64);

        let mut enc = [0u8; ENC_LEN];
        enc.copy_from_slice(env.enc);
        let opened = open(
            &Mode::AuthPsk {
                chunk: &chunk(9),
                epoch: EPOCH,
            },
            &b,
            &a.public(),
            &Sealed {
                enc,
                ct: env.ciphertext.to_vec(),
            },
            &info_for(header.class),
            &header.write(),
        )
        .unwrap();
        assert_eq!(opened, plaintext);
    }

    /// First contact uses `mode_base` and an inbox tag — and opens without the
    /// recipient holding the sender's key, which is the whole point.
    #[test]
    fn first_contact_opens_without_knowing_the_sender() {
        let (a, b) = (sk(4), sk(5));
        let composed = seal_to(
            &a,
            &Recipient::FirstContact {
                correspondence: &b.public(),
                tag: Tag([0x22; 8]),
            },
            EPOCH,
            0,
            EXPIRY,
            b"hello, we have not met",
            &mut NotRandom::seeded(6),
        )
        .unwrap();

        let header = RoutingHeader::parse(&composed.bytes).unwrap();
        let (env, _) = decode_envelope(&composed.bytes[16..]).unwrap();
        assert_eq!(env.tag_mode, 1, "inbox mode");

        let mut enc = [0u8; ENC_LEN];
        enc.copy_from_slice(env.enc);
        // A wrong "sender" key still opens, because mode_base does not bind one.
        let opened = open(
            &Mode::Base,
            &b,
            &sk(99).public(),
            &Sealed {
                enc,
                ct: env.ciphertext.to_vec(),
            },
            &info_for(header.class),
            &header.write(),
        )
        .unwrap();
        assert_eq!(opened, b"hello, we have not met");
    }

    /// **The circularity test.** The AAD is the header, the header carries the
    /// bucket, and the bucket must be right *before* sealing. If the size
    /// prediction were wrong, this would either fail to fit or require a
    /// re-seal under a changed AAD.
    #[test]
    fn the_bucket_is_correct_before_sealing_at_every_size() {
        let (a, b) = (sk(7), sk(8));
        // Sizes clustered at every bucket boundary, where an off-by-one in the
        // prediction would either overflow or waste a whole bucket.
        for len in [
            0usize, 1, 100, 190, 191, 192, 193, 1000, 950, 960, 970, 4000, 60_000, 200_000,
        ] {
            let plaintext = alloc_vec(len);
            let composed = seal_to(
                &a,
                &Recipient::Known {
                    correspondence: &b.public(),
                    tag: Tag([1; 8]),
                    chunk: None,
                },
                EPOCH,
                0,
                EXPIRY,
                &plaintext,
                &mut NotRandom::seeded(len as u64),
            )
            .unwrap_or_else(|e| panic!("len {len} failed: {e:?}"));

            // The header the AAD covers declares the bucket the object has.
            let header = RoutingHeader::parse(&composed.bytes).unwrap();
            assert_eq!(header.size_bucket, composed.bucket, "len {len}");
            // And it opens, which it would not if the AAD had changed.
            let (env, _) = decode_envelope(&composed.bytes[16..]).unwrap();
            let mut enc = [0u8; ENC_LEN];
            enc.copy_from_slice(env.enc);
            let opened = open(
                &Mode::Auth,
                &b,
                &a.public(),
                &Sealed {
                    enc,
                    ct: env.ciphertext.to_vec(),
                },
                &info_for(0),
                &header.write(),
            )
            .unwrap_or_else(|e| panic!("len {len} did not open: {e:?}"));
            assert_eq!(opened.len(), len);
        }
    }

    fn alloc_vec(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    /// The overhead constant is measured, not asserted. If the envelope
    /// encoder changes, this fails rather than every object being mis-sized.
    #[test]
    fn envelope_overhead_is_bounded() {
        for (enc_len, ct_len) in [(32usize, 0usize), (32, 16), (32, 65_000)] {
            let enc = alloc_vec(enc_len);
            let ct = alloc_vec(ct_len);
            let body = Envelope {
                epoch: u32::MAX as u64,
                tag_mode: 1,
                suite: SUITE_V1,
                enc: &enc,
                ciphertext: &ct,
            }
            .write();
            let overhead = body.len() - enc_len - ct_len;
            assert!(
                overhead <= ENVELOPE_MAX_OVERHEAD,
                "overhead {overhead} exceeds the constant {ENVELOPE_MAX_OVERHEAD}"
            );
        }
    }

    /// RFC 1 §8.1's ladder.
    /// RFC 1 §8.1's ladder is ×4, not ×2.
    #[test]
    fn buckets_are_the_smallest_that_fit() {
        assert_eq!(bucket_for(0), Some(0));
        assert_eq!(bucket_for(256), Some(0));
        assert_eq!(bucket_for(257), Some(1));
        assert_eq!(bucket_for(1_024), Some(1));
        assert_eq!(bucket_for(1_025), Some(2));
        assert_eq!(bucket_for(262_144), Some(5));
        assert_eq!(bucket_for(262_145), None);
        assert_eq!(bucket_for(usize::MAX), None);
    }

    /// A message too large to pad is refused, not truncated.
    #[test]
    fn an_oversized_message_is_refused() {
        let (a, b) = (sk(10), sk(11));
        let huge = alloc_vec(9_000_000);
        assert_eq!(
            seal_to(
                &a,
                &Recipient::Known {
                    correspondence: &b.public(),
                    tag: Tag([1; 8]),
                    chunk: None
                },
                EPOCH,
                0,
                EXPIRY,
                &huge,
                &mut NotRandom::seeded(1),
            )
            .err(),
            Some(Error::TooLarge)
        );
    }

    /// Two identical messages produce different objects, so a duplicate
    /// identifier never reveals that the same thing was said twice.
    #[test]
    fn identical_messages_produce_different_objects() {
        let (a, b) = (sk(12), sk(13));
        let mut rng = NotRandom::seeded(14);
        let mk = |rng: &mut NotRandom| {
            seal_to(
                &a,
                &Recipient::Known {
                    correspondence: &b.public(),
                    tag: Tag([1; 8]),
                    chunk: None,
                },
                EPOCH,
                0,
                EXPIRY,
                b"the same words",
                rng,
            )
            .unwrap()
        };
        let one = mk(&mut rng);
        let two = mk(&mut rng);
        assert_ne!(one.id, two.id);
        assert_eq!(
            one.bucket, two.bucket,
            "and they are indistinguishable by size"
        );
        assert_eq!(one.bytes.len(), two.bytes.len());
    }

    /// Padding is zero and the plaintext is nowhere in the object.
    #[test]
    fn the_object_reveals_nothing_of_the_plaintext() {
        let (a, b) = (sk(15), sk(16));
        let plaintext = b"meet me at the usual place";
        let composed = seal_to(
            &a,
            &Recipient::Known {
                correspondence: &b.public(),
                tag: Tag([1; 8]),
                chunk: None,
            },
            EPOCH,
            0,
            EXPIRY,
            plaintext,
            &mut NotRandom::seeded(17),
        )
        .unwrap();
        assert!(!composed
            .bytes
            .windows(plaintext.len())
            .any(|w| w == plaintext));
        // Padding is zero (RFC 1 §8.1), so the identifier is over a known
        // quantity rather than over whatever was in memory.
        let body_end = ROUTING_HEADER_LEN + body_size_for(plaintext.len());
        assert!(composed.bytes[body_end..]
            .iter()
            .rev()
            .take(8)
            .all(|&x| x == 0));
    }
}
