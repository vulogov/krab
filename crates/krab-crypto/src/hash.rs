//! Content addressing and identifier derivation.
//!
//! Every hash in Krab is BLAKE3-256 over a **frozen domain string** followed by
//! the input. The domain strings are permanent (RFC 1 §1): once objects exist,
//! changing one changes every identifier derived through it.
//!
//! # Why the domains live here and not in `krab-core`
//!
//! `krab-core` holds the domain *labels* it needs for pure work (tag epochs,
//! shard extraction). The labels that feed a hash live beside the hash, so that
//! a reader checking `object_id` against RFC 1 §4 sees the whole derivation in
//! one place rather than assembling it from two crates.

use krab_core::object::{ObjectId, Tag};

/// RFC 1 §4 — object identifier.
pub const DOMAIN_OBJECT: &[u8] = b"krab/obj/v1";
/// RFC 3 §2 — node identifier.
pub const DOMAIN_NODE: &[u8] = b"krab/node/v1";
/// RFC 6 §3.1 — channel identifier, and RFC 1 §5.2's bulletin tag.
pub const DOMAIN_CHANNEL: &[u8] = b"krab/chan/v1";

/// `id = BLAKE3-256("krab/obj/v1" ‖ OBJECT)`, RFC 1 §4.
///
/// `object` MUST be the canonical bytes from `krab_core::object::canonical_bytes`
/// — header, body, and zero padding to the declared bucket. The identifier
/// covers the padding, which is why RFC 1 §8.1 fixes it at zero.
///
/// FEC and armor are applied *after* this point and MUST NOT participate
/// (RFC 1 §3). That is what lets a gateway transcode between an IP link and a
/// LoRa link without fracturing the corpus.
pub fn object_id(object: &[u8]) -> ObjectId {
    ObjectId(domain_hash(DOMAIN_OBJECT, object))
}

/// `node_id = BLAKE3-256("krab/node/v1" ‖ ed25519_pk)`, RFC 3 §2.
///
/// Self-certifying: there is no authority, no registry, and no name
/// resolution. A node identifier is a key, and keys cannot be squatted.
pub fn node_id(ed25519_pk: &[u8; 32]) -> [u8; 32] {
    domain_hash(DOMAIN_NODE, ed25519_pk)
}

/// `channel_id = BLAKE3-256("krab/chan/v1" ‖ ed25519_pk)`, RFC 6 §3.1.
pub fn channel_id(ed25519_pk: &[u8; 32]) -> [u8; 32] {
    domain_hash(DOMAIN_CHANNEL, ed25519_pk)
}

/// A bulletin's tag: the leading 8 bytes of `BLAKE3("krab/chan/v1" ‖
/// channel_id)`, RFC 1 §5.2.
///
/// **This is the one place in Krab where a tag is deliberately linkable**,
/// because a channel is a public feed. RFC 0 I-2's namespace separation is what
/// makes that safe: a bulletin tag is distinguished by the `class` byte in the
/// frozen header and can never be mistaken for a `sealed` tag.
///
/// Note that `DOMAIN_CHANNEL` appears at both levels — once deriving the
/// channel identifier and once deriving its tag. That is what RFC 6 §3.1 and
/// RFC 1 §5.2 specify between them; distinct labels would have been cleaner
/// and the inputs differ in provenance, so it is a smell rather than a defect.
/// Recorded in `Documentation/CRYPTO-REVIEW.md` §8.
pub fn channel_tag(channel_id: &[u8; 32]) -> Tag {
    let h = domain_hash(DOMAIN_CHANNEL, channel_id);
    let mut t = [0u8; 8];
    t.copy_from_slice(&h[..8]);
    Tag(t)
}

/// BLAKE3-256 over `domain ‖ input`.
fn domain_hash(domain: &[u8], input: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(input);
    *h.finalize().as_bytes()
}

/// An additively composable range fingerprint, RFC 5 §4.4.
///
/// `Σ BLAKE3(id) mod 2²⁵⁶`, held as four little-endian 64-bit limbs.
///
/// # Why addition rather than XOR
///
/// RFC 5 §4.4: XOR is malleable — an adversary who can choose identifiers can
/// craft a set that cancels, making a divergent range look synchronised and
/// silently withholding objects. Addition is harder to cancel.
///
/// # What actually makes it safe
///
/// Addition is *also* malleable, just less conveniently: a modular sum is not
/// collision-resistant in the hash sense, and an adversary free to choose
/// identifiers could search for sets whose sums agree.
///
/// **The property is inherited from content addressing, not from the
/// fingerprint.** Identifiers are BLAKE3 outputs over canonical bytes, so an
/// adversary cannot choose one without doing the work to find an object that
/// hashes to it. RFC 5 §4.4 gives the XOR argument and omits this one; it is
/// the load-bearing half. Recorded in `Documentation/RFC-5-review.md`.
///
/// # Why composable
///
/// A range fingerprint must be readable from a prefix-sum index in `O(1)`
/// rather than by rescanning the range — that is the single storage property
/// RBSR depends on (RFC 5 §7), and it is why `Fingerprint` supports both
/// addition and subtraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Fingerprint([u64; 4]);

impl Fingerprint {
    /// The empty range.
    pub const ZERO: Fingerprint = Fingerprint([0; 4]);

    /// The contribution one object makes.
    pub fn of(id: &ObjectId) -> Fingerprint {
        let h = domain_hash(b"krab/fp/v1", &id.0);
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let mut b = [0u8; 8];
            b.copy_from_slice(&h[i * 8..(i + 1) * 8]);
            *limb = u64::from_le_bytes(b);
        }
        Fingerprint(limbs)
    }

    /// Add a range's fingerprint to this one, mod 2²⁵⁶.
    ///
    /// Not `std::ops::Add`: that trait's contract carries no notion of the
    /// modulus, and a fingerprint that silently participated in generic
    /// numeric code would be a worse bug than the naming collision.
    #[allow(clippy::should_implement_trait)]
    // The index walks two limb arrays and a carry in lockstep; an iterator
    // rewrite would obscure the carry chain, which is the whole function.
    #[allow(clippy::needless_range_loop)]
    pub fn add(self, other: Fingerprint) -> Fingerprint {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let (s, c1) = self.0[i].overflowing_add(other.0[i]);
            let (s, c2) = s.overflowing_add(carry);
            out[i] = s;
            carry = (c1 as u64) | (c2 as u64);
        }
        Fingerprint(out)
    }

    /// Remove a range's fingerprint, mod 2²⁵⁶.
    ///
    /// The inverse of [`Fingerprint::add`], which is what makes a prefix-sum
    /// index answer an arbitrary range in constant time.
    #[allow(clippy::should_implement_trait)]
    #[allow(clippy::needless_range_loop)]
    pub fn sub(self, other: Fingerprint) -> Fingerprint {
        let mut out = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (d, b1) = self.0[i].overflowing_sub(other.0[i]);
            let (d, b2) = d.overflowing_sub(borrow);
            out[i] = d;
            borrow = (b1 as u64) | (b2 as u64);
        }
        Fingerprint(out)
    }

    /// Accumulate every identifier in an iterator.
    pub fn over<'a>(ids: impl Iterator<Item = &'a ObjectId>) -> Fingerprint {
        ids.fold(Fingerprint::ZERO, |acc, id| acc.add(Fingerprint::of(id)))
    }

    /// Wire encoding: 32 bytes, little-endian limbs.
    pub fn to_bytes(self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for i in 0..4 {
            b[i * 8..(i + 1) * 8].copy_from_slice(&self.0[i].to_le_bytes());
        }
        b
    }

    /// Decode from the wire.
    pub fn from_bytes(b: &[u8; 32]) -> Fingerprint {
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let mut x = [0u8; 8];
            x.copy_from_slice(&b[i * 8..(i + 1) * 8]);
            *limb = u64::from_le_bytes(x);
        }
        Fingerprint(limbs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn id(n: u8) -> ObjectId {
        ObjectId([n; 32])
    }

    #[test]
    fn identifiers_are_domain_separated() {
        let k = [7u8; 32];
        // Same input, three domains, three results. A shared domain would let
        // a node identifier be presented as a channel identifier.
        assert_ne!(node_id(&k), channel_id(&k));
        assert_ne!(node_id(&k), object_id(&k).0);
        assert_ne!(channel_id(&k), object_id(&k).0);
    }

    #[test]
    fn object_id_covers_every_byte_including_padding() {
        let mut a = alloc::vec![0u8; 256];
        a[0] = 1;
        let mut b = a.clone();
        // A single flipped padding byte is a different object. This is what
        // makes RFC 1 §8.1's zero-padding rule checkable rather than advisory.
        b[255] = 1;
        assert_ne!(object_id(&a), object_id(&b));
    }

    #[test]
    fn object_id_is_deterministic() {
        let o = alloc::vec![0xABu8; 1024];
        assert_eq!(object_id(&o), object_id(&o));
    }

    /// RFC 1 §5.2 — a bulletin tag is 8 bytes and derives from the channel id.
    #[test]
    fn channel_tag_is_stable_and_eight_bytes() {
        let ch = channel_id(&[3u8; 32]);
        let t = channel_tag(&ch);
        assert_eq!(t, channel_tag(&ch), "stable — a channel is a public feed");
        assert_eq!(t.0.len(), 8);
        assert_ne!(t, channel_tag(&channel_id(&[4u8; 32])));
    }

    #[test]
    fn fingerprint_is_order_independent() {
        let ids: Vec<ObjectId> = (0..8).map(id).collect();
        let forward = Fingerprint::over(ids.iter());
        let backward = Fingerprint::over(ids.iter().rev());
        assert_eq!(
            forward, backward,
            "a range fingerprint cannot depend on scan order"
        );
    }

    /// The property RBSR needs from the storage layer: any range's fingerprint
    /// is a difference of two prefix sums, in constant time.
    #[test]
    fn fingerprint_composes_and_decomposes() {
        let ids: Vec<ObjectId> = (0..16).map(id).collect();
        let whole = Fingerprint::over(ids.iter());
        let left = Fingerprint::over(ids[..6].iter());
        let right = Fingerprint::over(ids[6..].iter());
        assert_eq!(left.add(right), whole);
        assert_eq!(whole.sub(left), right);
        assert_eq!(whole.sub(right), left);
    }

    #[test]
    fn fingerprint_add_and_sub_are_inverse_across_the_wrap() {
        // Force a carry out of the top limb.
        let big = Fingerprint([u64::MAX; 4]);
        let one = Fingerprint([1, 0, 0, 0]);
        assert_eq!(big.add(one), Fingerprint::ZERO, "wraps mod 2^256");
        assert_eq!(Fingerprint::ZERO.sub(one), big, "borrows mod 2^256");
    }

    #[test]
    fn differing_sets_have_differing_fingerprints() {
        let a = Fingerprint::over([id(1), id(2), id(3)].iter());
        let b = Fingerprint::over([id(1), id(2), id(4)].iter());
        assert_ne!(a, b, "a divergent range must not look synchronised");
    }

    #[test]
    fn fingerprint_round_trips_the_wire_encoding() {
        let f = Fingerprint::over([id(9), id(11)].iter());
        assert_eq!(Fingerprint::from_bytes(&f.to_bytes()), f);
        assert_eq!(f.to_bytes().len(), 32, "RFC 5 §4.4 — 32-byte fingerprint");
    }

    /// Empty range is the additive identity, so an absent sub-range costs
    /// nothing and RBSR can prune it without a special case.
    #[test]
    fn empty_range_is_the_identity() {
        let f = Fingerprint::over([id(5)].iter());
        assert_eq!(f.add(Fingerprint::ZERO), f);
        assert_eq!(Fingerprint::over(core::iter::empty()), Fingerprint::ZERO);
    }
}
