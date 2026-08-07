//! HPKE sealing — RFC 1 §6, RFC 9180.
//!
//! Suite `0x0001`, the v1 mandatory one: DHKEM(X25519, HKDF-SHA256) /
//! HKDF-SHA256 / ChaCha20-Poly1305.
//!
//! # Mode follows tag mode, and that coupling is normative
//!
//! RFC 1 §6.2:
//!
//! | tag mode | recipient knows sender | HPKE mode | authentication |
//! |---|---|---|---|
//! | 0 pairwise | yes | `mode_auth` | deniable |
//! | 1 inbox | no | `mode_base` | inner Ed25519 signature |
//!
//! `mode_auth` folds the sender's static key into the KEM, so the recipient —
//! and only the recipient — can verify origin. A third party holding the
//! ciphertext and both public keys learns nothing, and it saves the 64 bytes an
//! inner signature costs.
//!
//! It is *impossible* for first contact: decapsulation needs the sender's
//! static public key as an input, which a recipient meeting someone for the
//! first time does not have. RFC 2 §4.2 puts it well — the coupling "is
//! therefore not a policy choice but a consequence."
//!
//! # `mode_auth_psk`, and the fix to `CRYPTO-REVIEW.md` §1
//!
//! **This module implements the recommended construction, not RFC 7 §6 as
//! written.** §6's `msg_key = HKDF(chunk_N, "krab/msg/v1" ‖ tag)` derives one
//! key per (pair, epoch), because `tag` is constant for a pair across an epoch
//! and `chunk_N` is constant by definition. Every message a pair exchanges in a
//! day would share a key. RFC 7 §6 marks it `⚠ DEFECTIVE` and says it MUST NOT
//! be implemented; this is the fix it names, awaiting adoption:
//!
//! > "supply `chunk_N` as an HPKE PSK under `mode_auth_psk` (RFC 9180 §5.1.4)
//! > with the epoch as `psk_id`."
//!
//! Three properties hold at once, which is why this shape and not another:
//!
//! - **Per-message keys.** The ephemeral `skE` enters the key schedule, so two
//!   messages in one epoch derive different keys. This is what §6 lacked.
//! - **Post-quantum.** The PSK is a symmetric secret established out of band
//!   (RFC 7 §6.2, and `RFC-7-review.md` §10 on why the channel matters). An
//!   adversary who breaks X25519 from a recording still lacks it.
//! - **Deniability and forward secrecy** are unchanged: `mode_auth` still
//!   authenticates to the recipient alone, and §4's shredding still bounds
//!   exposure at epoch granularity.
//!
//! RFC 1 §6.1's suite space accommodates it, so **RFC 1 stays frozen** — only
//! RFC 7 §6 needs amending. Until it is, an implementation following §6
//! literally and this one will not interoperate, and that is the safer
//! direction to fail in.

use crate::dh::{PublicKey, SecretKey};
use crate::reservoir::Chunk;
use crate::rng::Rng;
use alloc::vec::Vec;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, PskBundle, Serializable};
use krab_core::tag::Epoch;

/// RFC 1 §6.1's `info` prefix. Frozen.
pub const INFO_PREFIX: &[u8] = b"krab/v1/";

/// Length of the encapsulated key for X25519 DHKEM.
pub const ENC_LEN: usize = 32;

/// What sealing or opening refused to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A public key was malformed or low-order.
    BadKey,
    /// Decryption failed: wrong key, wrong AAD, wrong mode, or tampering.
    ///
    /// One variant on purpose. Distinguishing them tells an attacker which of
    /// their guesses was structurally closer, and the recipient's remedy is the
    /// same in every case: the object is not for them, or is not intact.
    Open,
    /// The encapsulated key was not [`ENC_LEN`] bytes.
    Malformed,
}

/// How a message is authenticated. Follows tag mode — see the module docs.
pub enum Mode<'a> {
    /// First contact. RFC 2 §4.2's inbox tag, and an inner Ed25519 signature
    /// carries origin because the KEM cannot.
    Base,
    /// An established correspondent, with no reservoir.
    Auth,
    /// An established correspondent with a reservoir chunk as PSK.
    ///
    /// The construction `CRYPTO-REVIEW.md` §1 recommends.
    AuthPsk {
        /// `chunk_N` from [`crate::reservoir::Reservoir::chunk`].
        chunk: &'a Chunk,
        /// The epoch, used as `psk_id` so a chunk cannot be replayed into
        /// another epoch's schedule.
        epoch: Epoch,
    },
}

/// `info = "krab/v1/" ‖ class`, RFC 1 §6.1.
pub fn info_for(class: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(INFO_PREFIX.len() + 1);
    v.extend_from_slice(INFO_PREFIX);
    v.push(class);
    v
}

/// A sealed message: the encapsulated key and the ciphertext.
pub struct Sealed {
    /// The KEM output. 32 bytes for X25519.
    pub enc: [u8; ENC_LEN],
    /// Ciphertext with the AEAD tag appended.
    pub ct: Vec<u8>,
}

/// Bridge [`Rng`] to what `hpke` wants.
///
/// Randomness stays an argument all the way down; this adapter is the only
/// place the two trait shapes meet.
struct RngBridge<'a, R: Rng>(&'a mut R);

// `rand_core` 0.10 defines the fallible trait and derives the infallible one
// from it by blanket impl, so `TryRng` is what an implementor writes. Aliased
// throughout because this crate has its own `Rng`, and the two are different
// ideas: ours is "a source a caller supplies", theirs is "what the algorithm
// asks for".
//
// `Error = Infallible` is the honest type. `crate::Rng::fill` cannot report
// failure, by design — an entropy source that can fail silently is worse than
// one that panics, so `entropy::OsRng` panics and this never sees an error.
impl<R: Rng> rand_core::TryRng for RngBridge<'_, R> {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.0.fill(&mut b);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.0.fill(&mut b);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill(dst);
        Ok(())
    }
}

impl<R: Rng> rand_core::TryCryptoRng for RngBridge<'_, R> {}

/// Seal `plaintext` to `recipient`.
///
/// `aad` is RFC 1 §6.1's `ROUTING_HEADER ‖ deterministic_cbor(body with key 5
/// omitted)`. It binds expiry, tag, class, epoch and suite, so a relay that
/// mutates the expiry to force indefinite storage produces something
/// undecryptable — and since expiry is also inside the identifier, the object
/// is no longer the object it claims to be. Tampering is doubly dead.
pub fn seal(
    mode: &Mode,
    sender: &SecretKey,
    recipient: &PublicKey,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut impl Rng,
) -> Result<Sealed, Error> {
    let pk_r = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&recipient.0)
        .map_err(|_| Error::BadKey)?;
    let sk_s = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&sender.to_bytes())
        .map_err(|_| Error::BadKey)?;
    let pk_s = <X25519HkdfSha256 as Kem>::sk_to_pk(&sk_s);
    let keypair = (sk_s, pk_s);

    let psk_id = mode_psk_id(mode);
    let op = match mode {
        Mode::Base => OpModeS::Base,
        Mode::Auth => OpModeS::Auth(keypair),
        Mode::AuthPsk { chunk, .. } => {
            let bundle = PskBundle::new(chunk.expose(), &psk_id).map_err(|_| Error::BadKey)?;
            OpModeS::AuthPsk(keypair, bundle)
        }
    };

    let mut bridge = RngBridge(rng);
    // `_with_rng` rather than the plain form: the plain one is gated on the
    // `getrandom` feature, which this crate does not enable. Randomness is an
    // argument here too.
    let (enc, ct) =
        hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &op,
            &pk_r,
            info,
            plaintext,
            aad,
            &mut bridge,
        )
        .map_err(|_| Error::BadKey)?;

    let bytes = Serializable::to_bytes(&enc);
    let mut out = [0u8; ENC_LEN];
    out.copy_from_slice(&bytes);
    Ok(Sealed { enc: out, ct })
}

/// Open what [`seal`] produced.
///
/// `sender` is the sender's static public key, required by `mode_auth` and
/// `mode_auth_psk` and ignored by `mode_base`.
pub fn open(
    mode: &Mode,
    recipient: &SecretKey,
    sender: &PublicKey,
    sealed: &Sealed,
    info: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    let sk_r = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&recipient.to_bytes())
        .map_err(|_| Error::BadKey)?;
    let pk_s =
        <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&sender.0).map_err(|_| Error::BadKey)?;
    let enc = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&sealed.enc)
        .map_err(|_| Error::Malformed)?;

    let psk_id = mode_psk_id(mode);
    let op = match mode {
        Mode::Base => OpModeR::Base,
        Mode::Auth => OpModeR::Auth(pk_s),
        Mode::AuthPsk { chunk, .. } => {
            let bundle = PskBundle::new(chunk.expose(), &psk_id).map_err(|_| Error::BadKey)?;
            OpModeR::AuthPsk(pk_s, bundle)
        }
    };

    hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &op, &sk_r, &enc, info, &sealed.ct, aad,
    )
    .map_err(|_| Error::Open)
}

/// The `psk_id`: the epoch, little-endian, matching every other epoch encoding
/// in the series (RFC 2 §4.1).
///
/// RFC 9180 §5.1.2 requires `psk_id` be bound into the key schedule, so a chunk
/// cannot be replayed into a different epoch's context even if an
/// implementation somehow supplied the wrong one.
fn mode_psk_id(mode: &Mode) -> Vec<u8> {
    match mode {
        Mode::AuthPsk { epoch, .. } => epoch.to_le_bytes().to_vec(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dh::SecretKey;
    use crate::reservoir::Reservoir;
    use crate::rng::NotRandom;

    const NOW: Epoch = Epoch(20_671);

    fn sk(seed: u64) -> SecretKey {
        SecretKey::generate(&mut NotRandom::seeded(seed))
    }

    fn chunk() -> Chunk {
        Reservoir::new([0x77; 32], Epoch(0)).chunk(NOW).unwrap()
    }

    /// RFC 1 §6.1 — `info = "krab/v1/" ‖ class`.
    #[test]
    fn info_binds_the_class() {
        assert_eq!(info_for(0), b"krab/v1/\x00");
        assert_eq!(info_for(1), b"krab/v1/\x01");
        assert_ne!(info_for(0), info_for(1));
    }

    /// Every mode round-trips.
    #[test]
    fn each_mode_seals_and_opens() {
        let (a, b) = (sk(1), sk(2));
        let c = chunk();
        let info = info_for(0);
        let aad = b"routing header and body";
        let msg = b"the quick brown fox";

        for mode in [
            Mode::Base,
            Mode::Auth,
            Mode::AuthPsk {
                chunk: &c,
                epoch: NOW,
            },
        ] {
            let mut rng = NotRandom::seeded(9);
            let sealed = seal(&mode, &a, &b.public(), &info, aad, msg, &mut rng).unwrap();
            assert_eq!(sealed.enc.len(), ENC_LEN);
            assert_ne!(&sealed.ct[..], &msg[..], "it is actually encrypted");
            // ChaCha20-Poly1305 adds a 16-byte tag.
            assert_eq!(sealed.ct.len(), msg.len() + 16);

            let out = open(&mode, &b, &a.public(), &sealed, &info, aad).unwrap();
            assert_eq!(out, msg);
        }
    }

    /// **The fix to `CRYPTO-REVIEW.md` §1, demonstrated.**
    ///
    /// Two messages in the *same epoch* with the *same chunk* and the *same
    /// tag* must not share a key. Under RFC 7 §6 as written they would — the
    /// derivation has no per-message input at all. Here the ephemeral makes
    /// every ciphertext independent.
    #[test]
    fn two_messages_in_one_epoch_do_not_share_a_key() {
        let (a, b) = (sk(3), sk(4));
        let c = chunk();
        let mode = Mode::AuthPsk {
            chunk: &c,
            epoch: NOW,
        };
        let info = info_for(0);
        // Identical AAD: same routing header, same tag, same epoch. Everything
        // §6's derivation took as input is held constant.
        let aad = b"identical routing header";
        let msg = b"identical plaintext";

        let mut rng = NotRandom::seeded(1);
        let one = seal(&mode, &a, &b.public(), &info, aad, msg, &mut rng).unwrap();
        let two = seal(&mode, &a, &b.public(), &info, aad, msg, &mut rng).unwrap();

        assert_ne!(one.enc, two.enc, "different ephemerals");
        assert_ne!(one.ct, two.ct, "and therefore different ciphertexts");
        // Both still open — independence is not achieved by breaking anything.
        assert_eq!(open(&mode, &b, &a.public(), &one, &info, aad).unwrap(), msg);
        assert_eq!(open(&mode, &b, &a.public(), &two, &info, aad).unwrap(), msg);
    }

    /// **The post-quantum property.** Without the chunk, the recipient's own
    /// private key is not enough — which is exactly what an adversary who
    /// breaks X25519 would have.
    #[test]
    fn the_psk_is_required_even_holding_the_recipients_private_key() {
        let (a, b) = (sk(5), sk(6));
        let c = chunk();
        let info = info_for(0);
        let mut rng = NotRandom::seeded(2);
        let sealed = seal(
            &Mode::AuthPsk {
                chunk: &c,
                epoch: NOW,
            },
            &a,
            &b.public(),
            &info,
            b"aad",
            b"secret",
            &mut rng,
        )
        .unwrap();

        // Holding b's private key and a's public key, without the chunk.
        assert_eq!(
            open(&Mode::Auth, &b, &a.public(), &sealed, &info, b"aad"),
            Err(Error::Open),
            "breaking X25519 must not be sufficient"
        );
        // And with a different chunk.
        let wrong = Reservoir::new([0x11; 32], Epoch(0)).chunk(NOW).unwrap();
        assert_eq!(
            open(
                &Mode::AuthPsk {
                    chunk: &wrong,
                    epoch: NOW
                },
                &b,
                &a.public(),
                &sealed,
                &info,
                b"aad"
            ),
            Err(Error::Open)
        );
    }

    /// The epoch is the `psk_id`, so a chunk cannot be replayed into another
    /// epoch's schedule (RFC 9180 §5.1.2).
    #[test]
    fn a_chunk_is_bound_to_its_epoch() {
        let (a, b) = (sk(7), sk(8));
        let c = chunk();
        let info = info_for(0);
        let mut rng = NotRandom::seeded(3);
        let sealed = seal(
            &Mode::AuthPsk {
                chunk: &c,
                epoch: NOW,
            },
            &a,
            &b.public(),
            &info,
            b"aad",
            b"m",
            &mut rng,
        )
        .unwrap();

        assert_eq!(
            open(
                &Mode::AuthPsk {
                    chunk: &c,
                    epoch: Epoch(NOW.0 + 1)
                },
                &b,
                &a.public(),
                &sealed,
                &info,
                b"aad"
            ),
            Err(Error::Open),
            "the same chunk under a different epoch must not open it"
        );
    }

    /// **RFC 1 §6.1's AAD is load-bearing.** A relay that edits the expiry to
    /// force indefinite storage produces something that will not decrypt.
    #[test]
    fn tampering_with_the_aad_makes_the_object_undecryptable() {
        let (a, b) = (sk(9), sk(10));
        let info = info_for(0);
        let mut rng = NotRandom::seeded(4);
        let aad = b"expiry=29766240 tag=abcdefgh";
        let sealed = seal(&Mode::Auth, &a, &b.public(), &info, aad, b"m", &mut rng).unwrap();

        let edited = b"expiry=99999999 tag=abcdefgh";
        assert_eq!(
            open(&Mode::Auth, &b, &a.public(), &sealed, &info, edited),
            Err(Error::Open)
        );
        // And the class, via info.
        assert_eq!(
            open(&Mode::Auth, &b, &a.public(), &sealed, &info_for(1), aad),
            Err(Error::Open)
        );
    }

    /// `mode_auth` authenticates the sender to the recipient: a message sealed
    /// by someone else does not open as though it came from `a`.
    #[test]
    fn auth_mode_binds_the_sender() {
        let (a, b, imposter) = (sk(11), sk(12), sk(13));
        let info = info_for(0);
        let mut rng = NotRandom::seeded(5);
        let sealed = seal(
            &Mode::Auth,
            &imposter,
            &b.public(),
            &info,
            b"aad",
            b"m",
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            open(&Mode::Auth, &b, &a.public(), &sealed, &info, b"aad"),
            Err(Error::Open),
            "claiming a different sender must fail"
        );
        assert!(open(&Mode::Auth, &b, &imposter.public(), &sealed, &info, b"aad").is_ok());
    }

    /// A message is for one recipient.
    #[test]
    fn a_third_party_cannot_open_it() {
        let (a, b, c3) = (sk(14), sk(15), sk(16));
        let info = info_for(0);
        let mut rng = NotRandom::seeded(6);
        let sealed = seal(&Mode::Auth, &a, &b.public(), &info, b"aad", b"m", &mut rng).unwrap();
        assert_eq!(
            open(&Mode::Auth, &c3, &a.public(), &sealed, &info, b"aad"),
            Err(Error::Open)
        );
    }

    /// Every byte of a sealed message is covered: flipping any one of them
    /// makes it fail to open.
    #[test]
    fn every_byte_of_the_ciphertext_is_authenticated() {
        let (a, b) = (sk(17), sk(18));
        let info = info_for(0);
        let mut rng = NotRandom::seeded(7);
        let sealed = seal(
            &Mode::Auth,
            &a,
            &b.public(),
            &info,
            b"aad",
            b"a longer message",
            &mut rng,
        )
        .unwrap();

        for i in 0..sealed.ct.len() {
            let mut torn = Sealed {
                enc: sealed.enc,
                ct: sealed.ct.clone(),
            };
            torn.ct[i] ^= 1;
            assert_eq!(
                open(&Mode::Auth, &b, &a.public(), &torn, &info, b"aad"),
                Err(Error::Open),
                "byte {i} was not authenticated"
            );
        }
        for i in 0..ENC_LEN {
            let mut torn = Sealed {
                enc: sealed.enc,
                ct: sealed.ct.clone(),
            };
            torn.enc[i] ^= 1;
            assert!(
                open(&Mode::Auth, &b, &a.public(), &torn, &info, b"aad").is_err(),
                "encapsulated key byte {i} was not covered"
            );
        }
    }

    /// A malformed key is refused rather than panicking.
    #[test]
    fn malformed_input_does_not_panic() {
        let a = sk(19);
        let info = info_for(0);
        let mut rng = NotRandom::seeded(8);
        let bad = PublicKey([0u8; 32]);
        // Sealing to a low-order key must not produce a usable message.
        let r = seal(&Mode::Auth, &a, &bad, &info, b"", b"m", &mut rng);
        if let Ok(s) = r {
            assert!(open(&Mode::Auth, &a, &bad, &s, &info, b"").is_err());
        }
        let sealed = Sealed {
            enc: [0xFF; 32],
            ct: alloc::vec![0u8; 4],
        };
        assert!(open(&Mode::Auth, &a, &a.public(), &sealed, &info, b"").is_err());
    }
}
