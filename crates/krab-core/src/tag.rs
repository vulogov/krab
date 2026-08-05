//! Per-epoch destination tag derivation (RFC 2).
//!
//! # I-2, namespace separation
//!
//! Node identifiers and destination tags are disjoint namespaces. Enforcing
//! that is the reason this module exists separately from `object`.
//!
//! # Epoch
//!
//! One clock, one counter, shared by tag derivation, key erasure, and the
//! reservoir (RFC 0 §11). Epoch length is blocking item B3 and is the hardest
//! of them: sneakernet pushes long, unlinkability pushes short.

use crate::object::Tag;

/// Epoch counter. Length is blocking item B3 (24 h vs 7 d) and unsettled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Epoch(pub u64);

/// Derive the pairwise tag `HKDF(X25519(sk_a, pk_b), "tag" || epoch)`.
///
/// Unlinkable across epochs to anyone without the shared secret.
pub fn pairwise_tag(_shared_secret: &[u8; 32], _epoch: Epoch) -> Tag {
    // Awaiting RFC 2.
    Tag([0u8; 32])
}

/// Derive the first-contact inbox tag `HKDF(pk_recipient, "inbox" || epoch)`.
///
/// Linkable within an epoch by anyone holding the recipient's public key.
/// That is a deliberate, documented tradeoff and its use is confined to first
/// contact (RFC 2).
pub fn inbox_tag(_recipient_pk: &[u8; 32], _epoch: Epoch) -> Tag {
    // Awaiting RFC 2.
    Tag([0u8; 32])
}

/// Extract the shard prefix: the leading `k` bits of a tag.
///
/// The privacy/scale dial, and a per-link parameter rather than a property of
/// the object. Per SIM-0 §7 sharding is mandatory above roughly n = 5 000, so
/// the field must exist in v1 even where v1 ships `k = 0` everywhere — it is
/// inside the identifier hash and cannot be added later.
pub fn shard_of(_tag: &Tag, _k: u8) -> u64 {
    // Awaiting RFC 2.
    0
}
