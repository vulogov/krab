//! Signed, unencrypted corpus objects — RFC 1 §5.2, `Class::Bulletin`.
//!
//! The class covers "channels, prekey batches, rollcall": three payloads that
//! share one shape. Each is **public, signed, and flooded**, and each is the
//! answer to a problem that would otherwise need a server.
//!
//! # Public is the point, and the cost
//!
//! A sealed object hides everything but its size and expiry. A bulletin hides
//! nothing: its author, its payload, and the fact that this node chose to
//! carry it are all readable by anyone who holds a copy. That is what makes
//! the corpus a prekey server (RFC 7 §5) and a channel host (RFC 6) without
//! either existing, and it is why RFC 6 §3.6 makes carrying them an explicit
//! decision rather than a default.
//!
//! **A bulletin is not recallable.** RFC 3 §6.1 forbids a recall mechanism —
//! permanently, because a recall mechanism is a censorship mechanism and
//! cannot be made selective. Once flooded, a bulletin exists until it expires.
//!
//! # Why the domain is inside the signature
//!
//! Every payload here is signed by the same identity key that signs cards,
//! credentials and re-keys. Without a domain prefix, a signature made over a
//! prekey batch would verify against a channel post of the same bytes — the
//! defect `RFC-3-review.md` §8 found in the credential and the reason
//! `peering::DOMAIN_CARD` exists.
//!
//! # What this deliberately does not do
//!
//! It does not encrypt, and it does not authenticate the *carrier*. A relay
//! that passes a bulletin on says nothing about believing it; verification is
//! the reader's job, against the author's key, on arrival.

use krab_core::cbor;
use krab_core::object::{Class, ObjectId, RoutingHeader, ROUTING_HEADER_LEN};
use krab_crypto::sign::{Sig, SigningKey, VerifyingKey};

/// What a bulletin carries. The value is inside the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// A batch of one-time prekeys — RFC 7 §5.
    Prekeys = 1,
    /// A channel post — RFC 6.
    Post = 2,
}

impl Kind {
    fn from_byte(b: u8) -> Option<Kind> {
        match b {
            1 => Some(Kind::Prekeys),
            2 => Some(Kind::Post),
            _ => None,
        }
    }

    /// The signing domain. Distinct per kind, so a signature over one cannot
    /// be replayed as the other.
    pub fn domain(&self) -> &'static [u8] {
        match self {
            Kind::Prekeys => b"krab/bulletin/prekeys/v1",
            Kind::Post => b"krab/bulletin/post/v1",
        }
    }
}

/// A signed public object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bulletin {
    /// What it carries.
    pub kind: Kind,
    /// The author's identity public key. **In the clear** — a bulletin is
    /// attributable by construction, which is the difference between it and a
    /// sealed message.
    pub author: [u8; 32],
    /// The epoch it was published in.
    pub epoch: u32,
    /// The payload, interpreted per `kind`.
    pub payload: Vec<u8>,
    /// Ed25519 over `Kind::domain() ‖ signed_bytes()`.
    pub sig: [u8; 64],
}

impl Bulletin {
    /// The bytes a signature covers, without the signature itself.
    fn signed_bytes(kind: Kind, author: &[u8; 32], epoch: u32, payload: &[u8]) -> Vec<u8> {
        let mut w = cbor::Writer::new();
        w.map(4)
            .uint(1)
            .uint(kind as u64)
            .uint(2)
            .bstr(author)
            .uint(3)
            .uint(epoch as u64)
            .uint(4)
            .bstr(payload);
        let body = w.finish();
        let mut out = Vec::with_capacity(kind.domain().len() + body.len());
        out.extend_from_slice(kind.domain());
        out.extend_from_slice(&body);
        out
    }

    /// Sign and publish.
    pub fn create(kind: Kind, identity: &SigningKey, epoch: u32, payload: Vec<u8>) -> Bulletin {
        let author = identity.verifying_key().to_bytes();
        let sig = identity.sign(&Self::signed_bytes(kind, &author, epoch, &payload));
        Bulletin {
            kind,
            author,
            epoch,
            payload,
            sig: sig.0,
        }
    }

    /// Whether the signature is the author's.
    ///
    /// **Every reader checks this**, on arrival, against the key in the
    /// bulletin — and then must decide separately whether that key is anyone
    /// they know. A valid signature proves only that the holder of some key
    /// wrote it.
    pub fn verify(&self) -> bool {
        let vk = VerifyingKey::from_bytes(self.author);
        vk.verify(
            &Self::signed_bytes(self.kind, &self.author, self.epoch, &self.payload),
            &Sig(self.sig),
        )
    }

    /// The author's node id.
    pub fn node_id(&self) -> [u8; 32] {
        VerifyingKey::from_bytes(self.author).node_id()
    }

    /// Deterministic CBOR — RFC 1 §4.3.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = cbor::Writer::new();
        w.map(5)
            .uint(1)
            .uint(self.kind as u64)
            .uint(2)
            .bstr(&self.author)
            .uint(3)
            .uint(self.epoch as u64)
            .uint(4)
            .bstr(&self.payload)
            .uint(5)
            .bstr(&self.sig);
        w.finish()
    }

    /// Decode. **Pre-authentication input** — a bulletin arrives by flooding
    /// from anyone, so nothing here may panic or allocate on a declared count.
    pub fn decode(bytes: &[u8]) -> Option<Bulletin> {
        let mut r = cbor::Reader::new(bytes);
        let mut m = r.map().ok()?;
        if m.left() != 5 {
            return None;
        }
        let kind = Kind::from_byte(u8::try_from(uint_at(&mut m, 1)?).ok()?)?;
        let author = bstr_at(&mut m, 2)?.try_into().ok()?;
        let epoch = u32::try_from(uint_at(&mut m, 3)?).ok()?;
        let payload = bstr_at(&mut m, 4)?.to_vec();
        let sig: [u8; 64] = bstr_at(&mut m, 5)?.try_into().ok()?;
        Some(Bulletin {
            kind,
            author,
            epoch,
            payload,
            sig,
        })
    }
}

/// Wrap a bulletin as a corpus object: routing header, payload, padding.
///
/// A bulletin is not an object until it has a header. Without one the store
/// rejects it as malformed — and an `ingest` whose error is discarded looks
/// exactly like one that worked, which is how a published batch can reach
/// nobody while the node reports success.
///
/// # The tag
///
/// Derived from the author's node id, so a reader who knows *whose* bulletins
/// they want can filter for them the same way they filter sealed mail. This is
/// not a secret: a bulletin is public and attributable by construction, and a
/// tag that hid the author would only hide it from the recipient.
pub fn into_object(b: &Bulletin, now_min: u32, ttl_min: u32) -> Option<(ObjectId, Vec<u8>)> {
    let body = b.encode();
    let bucket = RoutingHeader::bucket_for((ROUTING_HEADER_LEN + body.len()) as u32)?;
    let header = RoutingHeader {
        version: 1,
        class: Class::Bulletin as u8,
        size_bucket: bucket,
        flags: 0,
        expiry_min: now_min.saturating_add(ttl_min),
        tag: krab_crypto::hash::channel_tag(&b.node_id()),
    };

    // Padded to the bucket, like every other object — RFC 1 §8.1. A bulletin
    // whose true length showed through would leak how many prekeys a node has
    // left, which §6.3 forbids for exactly the same reason it forbids early
    // exit on decryption.
    let total = krab_core::object::BUCKETS[bucket as usize] as usize;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&header.write());
    out.extend_from_slice(&body);
    out.resize(total, 0);
    Some((krab_crypto::hash::object_id(&out), out))
}

/// Read a bulletin back out of a corpus object.
///
/// Returns `None` for anything that is not a well-formed, **verifying**
/// bulletin — so a caller cannot accidentally act on an unauthenticated one.
pub fn from_object(bytes: &[u8]) -> Option<Bulletin> {
    let header = RoutingHeader::parse(bytes).ok()?;
    if header.class != Class::Bulletin as u8 {
        return None;
    }
    // The padding is zeros, and CBOR decoding stops at the end of the map, so
    // the trailing bytes are simply not read.
    let b = Bulletin::decode(&bytes[ROUTING_HEADER_LEN..])?;
    b.verify().then_some(b)
}

fn at<'a>(m: &mut cbor::MapReader<'a, '_>, k: u64) -> Option<cbor::Item<'a>> {
    (m.key().ok()?? == k).then_some(())?;
    m.value().ok()
}

fn uint_at(m: &mut cbor::MapReader, k: u64) -> Option<u64> {
    match at(m, k)? {
        cbor::Item::Uint(v) => Some(v),
        _ => None,
    }
}

fn bstr_at<'a>(m: &mut cbor::MapReader<'a, '_>, k: u64) -> Option<&'a [u8]> {
    match at(m, k)? {
        cbor::Item::Bstr(b) => Some(b),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use krab_crypto::rng::NotRandom;

    fn key(seed: u64) -> SigningKey {
        SigningKey::generate(&mut NotRandom::seeded(seed))
    }

    #[test]
    fn a_bulletin_round_trips_and_verifies() {
        let k = key(1);
        let b = Bulletin::create(Kind::Prekeys, &k, 20_000, b"a batch".to_vec());
        assert!(b.verify());
        let back = Bulletin::decode(&b.encode()).expect("decodes");
        assert_eq!(back, b);
        assert!(back.verify());
    }

    /// **The domain must separate the kinds.** Without it, a signature over a
    /// prekey batch verifies against a channel post of the same bytes — the
    /// defect `RFC-3-review.md` §8 found in the credential.
    #[test]
    fn a_signature_over_one_kind_does_not_verify_as_another() {
        let k = key(1);
        let prekeys = Bulletin::create(Kind::Prekeys, &k, 20_000, b"same bytes".to_vec());
        let forged = Bulletin {
            kind: Kind::Post,
            ..prekeys.clone()
        };
        assert!(prekeys.verify());
        assert!(!forged.verify(), "the kind is outside the signature");
    }

    /// Every field is covered. A field a signature does not cover is a field
    /// an attacker edits.
    #[test]
    fn every_field_is_inside_the_signature() {
        let k = key(1);
        let b = Bulletin::create(Kind::Post, &k, 20_000, b"hello".to_vec());

        let mut epoch = b.clone();
        epoch.epoch += 1;
        assert!(!epoch.verify(), "the epoch is unsigned");

        let mut payload = b.clone();
        payload.payload = b"goodbye".to_vec();
        assert!(!payload.verify(), "the payload is unsigned");

        let mut author = b.clone();
        author.author = key(2).verifying_key().to_bytes();
        assert!(!author.verify(), "the author is unsigned");
    }

    /// Another key's signature does not pass, whatever it claims.
    #[test]
    fn an_impostors_signature_is_refused() {
        let real = Bulletin::create(Kind::Post, &key(1), 20_000, b"hello".to_vec());
        let fake = Bulletin::create(Kind::Post, &key(2), 20_000, b"hello".to_vec());
        // Claim to be the first author, keep the second's signature.
        let forged = Bulletin {
            author: real.author,
            ..fake
        };
        assert!(!forged.verify());
    }

    /// A bulletin arrives by flooding from anyone. Nothing here may panic.
    #[test]
    fn malformed_bulletins_are_refused_without_panicking() {
        assert_eq!(Bulletin::decode(&[]), None);
        assert_eq!(Bulletin::decode(&[0xa5]), None);
        // A declared length with nothing behind it.
        let mut raw = vec![0xa5, 0x01, 0x01, 0x02, 0x5a];
        raw.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(Bulletin::decode(&raw), None);

        let good = Bulletin::create(Kind::Post, &key(1), 1, b"x".to_vec()).encode();
        for cut in 0..good.len() {
            let _ = Bulletin::decode(&good[..cut]);
        }
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0xff;
            if let Some(b) = Bulletin::decode(&bad) {
                // Anything that still decodes must fail verification, unless
                // the flipped byte was outside the signed material — which it
                // never is, because every field is signed.
                assert!(!b.verify() || b == Bulletin::decode(&good).unwrap());
            }
        }
    }

    /// An unknown kind is refused rather than guessed. A future kind must not
    /// be interpreted as one this version happens to know.
    #[test]
    fn an_unknown_kind_is_refused() {
        let good = Bulletin::create(Kind::Post, &key(1), 1, b"x".to_vec());
        let mut w = cbor::Writer::new();
        w.map(5)
            .uint(1)
            .uint(99)
            .uint(2)
            .bstr(&good.author)
            .uint(3)
            .uint(1)
            .uint(4)
            .bstr(b"x")
            .uint(5)
            .bstr(&good.sig);
        assert_eq!(Bulletin::decode(&w.finish()), None);
    }

    /// **A bulletin must become a real object**, or the store rejects it as
    /// malformed and a discarded `ingest` error makes that look like success.
    #[test]
    fn a_bulletin_wraps_into_an_object_and_back() {
        let b = Bulletin::create(Kind::Prekeys, &key(1), 20_000, vec![7u8; 300]);
        let (id, bytes) = into_object(&b, 1_000, 64_800).expect("it wraps");

        let header = RoutingHeader::parse(&bytes).expect("a valid header");
        assert_eq!(header.class, Class::Bulletin as u8);
        assert_eq!(header.expiry_min, 1_000 + 64_800);
        assert_eq!(id, krab_crypto::hash::object_id(&bytes), "id names content");

        // Padded to its bucket, so the true length does not show through.
        assert_eq!(
            bytes.len(),
            krab_core::object::BUCKETS[header.size_bucket as usize] as usize
        );

        assert_eq!(from_object(&bytes), Some(b));
    }

    /// `from_object` returns nothing for a bulletin that does not verify, so a
    /// caller cannot act on an unauthenticated one by forgetting to check.
    #[test]
    fn an_object_holding_a_forged_bulletin_yields_nothing() {
        let b = Bulletin::create(Kind::Post, &key(1), 20_000, b"hello".to_vec());
        let (_, mut bytes) = into_object(&b, 0, 100).expect("it wraps");
        // Flip a payload byte, leaving the header intact.
        let i = ROUTING_HEADER_LEN + 20;
        bytes[i] ^= 0xff;
        assert_eq!(from_object(&bytes), None);

        // And a sealed object is not a bulletin, however well-formed.
        let mut sealed = bytes.clone();
        sealed[1] = Class::Sealed as u8;
        assert_eq!(from_object(&sealed), None);
    }
}
