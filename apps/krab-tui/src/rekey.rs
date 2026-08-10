//! The re-key payload: fresh entropy, and the policy that rides with it.
//!
//! `krab_crypto::rekey` holds the derivation. This holds what actually travels
//! and how it is authenticated, which is a separate question with a separate
//! failure mode.
//!
//! # Two layers, and why both
//!
//! The payload is **sealed** under a carrier key derived from `root_n`, and
//! **signed** with the sender's identity key. Neither alone is enough:
//!
//! - Sealed only: anyone holding the reservoir — which after a disk compromise
//!   includes the adversary — can forge a contribution and steer the next root
//!   to a value they know. The healing property in `krab_crypto::rekey` would
//!   then be worth nothing, because the compromise that `dh` is supposed to
//!   heal is exactly the one that hands over the carrier key.
//! - Signed only: the contribution is a secret and would be in the clear
//!   inside the Noise session, which is X25519 — recorded now, opened later.
//!
//! So the two compromises stay separate: reading the disk does not let you
//! forge a re-key, and holding the identity key does not let you read one.
//!
//! # Why policy is here
//!
//! `Policy` is signed into the card at peering and **never propagates again**.
//! A peer who stops relaying, shrinks their retention, or changes what
//! channels they carry has no way to say so, and the other end goes on
//! believing terms that were agreed once and have since changed.
//!
//! A re-key is a periodic, authenticated, encrypted, peer-to-peer state
//! update. So is a policy change. They are the same shape, and building two
//! mechanisms for one shape is how two mechanisms come to disagree.

use crate::peering::Policy;
use krab_core::cbor;
use krab_crypto::channel::CarriagePolicy;

/// What one end sends the other during a re-key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    /// This end's fresh 32 bytes.
    pub contribution: [u8; 32],
    /// The ratchet index this produces.
    pub index: u32,
    /// Current terms. Sent every time rather than on change, so a peer that
    /// missed one re-key is not carrying stale terms until the next change
    /// happens to occur.
    pub policy: Policy,
    /// Whether this node carries channel bulletins, and which — RFC 6 §3.6.
    ///
    /// Absent from `Policy` because `Policy` goes in the card, which is
    /// published; what channels a node carries is a statement about its
    /// operator's jurisdiction and interests.
    pub carriage: CarriagePolicy,
    /// The longest TTL this node will accept on an object, in minutes.
    ///
    /// Not in `Policy` either, and not anywhere else: `MAX_TTL` is a global
    /// constant, so a node that wants to hold less has no way to say so and a
    /// node that would hold more cannot offer.
    pub max_ttl_minutes: u32,
}

/// Deterministic CBOR, RFC 1 §4.3: ascending uint keys, definite lengths.
impl Payload {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = cbor::Writer::new();
        w.map(10)
            .uint(1)
            .bstr(&self.contribution)
            .uint(2)
            .uint(self.index as u64)
            .uint(3)
            .uint(self.policy.max_bucket as u64)
            .uint(4)
            .bool(self.policy.relay)
            .uint(5)
            .uint(self.policy.retention_bytes)
            .uint(6)
            .uint(self.policy.shard_bits as u64)
            .uint(7)
            .uint(self.max_ttl_minutes as u64)
            .uint(8)
            .bool(self.carriage.enabled)
            .uint(9)
            .uint(self.carriage.shard_bits as u64)
            .uint(10)
            .uint(self.carriage.shard);
        w.finish()
    }

    /// Decode. **Pre-authentication input** in the sense that matters: it has
    /// been sealed and signed by the time it arrives here, but a peer whose
    /// disk was seized is still a peer, so nothing here may panic or allocate
    /// on a declared count.
    pub fn decode(bytes: &[u8]) -> Option<Payload> {
        let mut r = cbor::Reader::new(bytes);
        let mut m = r.map().ok()?;
        if m.left() != 10 {
            return None;
        }
        let contribution = bstr32(&mut m, 1)?;
        let index = u32::try_from(uint_at(&mut m, 2)?).ok()?;
        let max_bucket = u8::try_from(uint_at(&mut m, 3)?).ok()?;
        let relay = bool_at(&mut m, 4)?;
        let retention_bytes = uint_at(&mut m, 5)?;
        let policy_shard_bits = u8::try_from(uint_at(&mut m, 6)?).ok()?;
        let max_ttl_minutes = u32::try_from(uint_at(&mut m, 7)?).ok()?;
        // Three keys, not one packed integer. `shard` is 64 bits wide and
        // packing it alongside two other fields loses it — which is how a
        // field comes to round-trip as its default and stop propagating,
        // exactly the defect this whole payload exists to close.
        let enabled = bool_at(&mut m, 8)?;
        let carriage_shard_bits = u8::try_from(uint_at(&mut m, 9)?).ok()?;
        // RFC 6 §3.4's space is 32 bits; wider divides the anonymity set by a
        // number with no meaning.
        if carriage_shard_bits > 32 {
            return None;
        }
        let shard = uint_at(&mut m, 10)?;
        let carriage = CarriagePolicy {
            enabled,
            shard_bits: carriage_shard_bits,
            shard,
        };

        Some(Payload {
            contribution,
            index,
            policy: Policy {
                max_bucket,
                relay,
                retention_bytes,
                shard_bits: policy_shard_bits,
            },
            carriage,
            max_ttl_minutes,
        })
    }
}

/// Read the value for `k`, refusing any other key.
///
/// RFC 1 §4.3 fixes the order, so a map arriving in a different one is not a
/// map this code has to accommodate — it is a map that was not produced by
/// this code, and guessing what it meant is how a parser grows an attack
/// surface.
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

fn bool_at(m: &mut cbor::MapReader, k: u64) -> Option<bool> {
    match at(m, k)? {
        cbor::Item::Bool(v) => Some(v),
        _ => None,
    }
}

fn bstr32(m: &mut cbor::MapReader, k: u64) -> Option<[u8; 32]> {
    match at(m, k)? {
        // Exactly 32. A short contribution is a re-key with less entropy than
        // it claims, and padding it would hide that.
        cbor::Item::Bstr(b) => b.try_into().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> Payload {
        Payload {
            contribution: [0xab; 32],
            index: 77,
            policy: Policy {
                max_bucket: 4,
                relay: false,
                retention_bytes: 12_345,
                shard_bits: 3,
            },
            carriage: CarriagePolicy {
                enabled: true,
                shard_bits: 6,
                shard: 41,
            },
            max_ttl_minutes: 64_800,
        }
    }

    #[test]
    fn a_payload_round_trips() {
        let p = payload();
        assert_eq!(Payload::decode(&p.encode()), Some(p));
    }

    /// Every field must survive. A field that round-trips as its default is a
    /// field that is not actually being propagated — which is the whole defect
    /// this closes.
    #[test]
    fn every_field_survives_the_round_trip() {
        let p = payload();
        let got = Payload::decode(&p.encode()).expect("decodes");
        assert_eq!(got.contribution, [0xab; 32]);
        assert_eq!(got.index, 77);
        assert_eq!(got.policy.max_bucket, 4);
        assert!(!got.policy.relay, "relay=false decoded as true");
        assert_eq!(got.policy.retention_bytes, 12_345);
        assert_eq!(got.policy.shard_bits, 3);
        assert!(got.carriage.enabled);
        assert_eq!(got.carriage.shard_bits, 6);
        assert_eq!(got.carriage.shard, 41, "which bucket is not propagating");
        assert_eq!(got.max_ttl_minutes, 64_800);
    }

    /// Carriage disabled is the default and must not be confused with
    /// carriage enabled at zero shard bits — the difference is "I host public
    /// content" versus "I do not", per RFC 6 §3.6.
    #[test]
    fn carriage_disabled_is_distinct_from_carriage_at_zero_shards() {
        let mut p = payload();
        p.carriage = CarriagePolicy {
            enabled: false,
            shard_bits: 0,
            shard: 0,
        };
        let off = Payload::decode(&p.encode()).expect("decodes");
        p.carriage.enabled = true;
        let on = Payload::decode(&p.encode()).expect("decodes");
        assert!(!off.carriage.enabled);
        assert!(on.carriage.enabled);
        assert_ne!(off, on, "\"I do not host public content\" was lost");
    }

    /// Nothing panics on malformed input, and nothing is accepted from it.
    #[test]
    fn malformed_payloads_are_refused_without_panicking() {
        assert_eq!(Payload::decode(&[]), None);
        assert_eq!(Payload::decode(&[0xaa]), None, "a map header and nothing");

        let good = payload().encode();
        for cut in 0..good.len() {
            let _ = Payload::decode(&good[..cut]);
        }
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0xff;
            let _ = Payload::decode(&bad);
        }
    }

    /// A contribution of the wrong width is refused rather than padded — a
    /// short one would be a re-key with less entropy than it claims.
    #[test]
    fn a_short_contribution_is_refused() {
        let mut w = cbor::Writer::new();
        w.map(10)
            .uint(1)
            .bstr(&[0u8; 16])
            .uint(2)
            .uint(1)
            .uint(3)
            .uint(5)
            .uint(4)
            .bool(true)
            .uint(5)
            .uint(1)
            .uint(6)
            .uint(0)
            .uint(7)
            .uint(1)
            .uint(8)
            .bool(false)
            .uint(9)
            .uint(0)
            .uint(10)
            .uint(0);
        assert_eq!(Payload::decode(&w.finish()), None);
    }

    /// A shard count wider than the channel space means nothing, so it is not
    /// silently clamped into meaning something.
    #[test]
    fn an_impossible_shard_count_is_refused() {
        let mut p = payload();
        p.carriage.shard_bits = 33;
        assert_eq!(Payload::decode(&p.encode()), None);
        p.carriage.shard_bits = 32;
        assert!(Payload::decode(&p.encode()).is_some());
    }
}
