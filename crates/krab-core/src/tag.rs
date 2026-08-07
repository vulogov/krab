//! Epochs, shard extraction, and the domain labels for tag derivation.
//!
//! **Derivation itself lives in `krab-crypto`**, because it needs X25519 and
//! HKDF and this crate is zero-dependency. What lives here is everything that
//! is pure: the epoch counter, the shard dial, and the frozen domain strings
//! both crates must agree on.
//!
//! # I-2, namespace separation
//!
//! Node identifiers and destination tags are disjoint namespaces (RFC 2 §2).
//! The failure mode RFC 2 names is concrete: a presence beacon carrying a tag
//! beside a timestamp publishes an identifier, a time and a network location
//! together, which is a tracking beacon and undoes the tag scheme for the cost
//! of one convenient field.

use crate::object::Tag;

/// Epoch length in seconds, RFC 1 §2.
pub const EPOCH_SECS: u64 = 86_400;

/// Acceptance window in epochs, RFC 1 §2 and §6.2.
///
/// `EPOCH_WINDOW ≥ MAX_TTL / EPOCH`. A deployment MAY widen it and MUST NOT
/// narrow it: an object delivered inside the TTL this protocol declares valid
/// may arrive up to `MAX_TTL / EPOCH` epochs after the epoch its tag derives
/// from, and a recipient with a narrower window simply never computed that tag
/// — the object is accepted, stored, and undecryptable.
pub const EPOCH_WINDOW: u32 = 45;

/// Domain label for pairwise tag derivation, RFC 2 §4.1. Frozen.
pub const LABEL_TAG: &[u8] = b"krab/tag/v1";
/// Domain label for inbox tag derivation, RFC 2 §4.2. Frozen.
pub const LABEL_INBOX: &[u8] = b"krab/inbox/v1";
/// Domain label for deterministic prekey indexing, RFC 2 §7.2. Frozen.
pub const LABEL_PREKEY_INDEX: &[u8] = b"krab/pkidx/v1";

/// Epoch counter — days since the Unix epoch.
///
/// One clock and one counter shared by tag derivation, key erasure and the
/// reservoir (RFC 0 §11). Note that the three do **not** share a retention
/// period: erasure lags rotation by `EPOCH_WINDOW`, because a chunk must
/// outlive the objects it decrypts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Epoch(pub u32);

impl Epoch {
    /// The epoch containing `unix_secs`.
    ///
    /// Time is an argument, never read from a clock — that is what keeps this
    /// crate replayable under the simulator and the fuzzer.
    pub fn at(unix_secs: u64) -> Epoch {
        Epoch((unix_secs / EPOCH_SECS) as u32)
    }

    /// Whether `self` falls inside the acceptance window around `now`.
    pub fn accepted_at(&self, now: Epoch) -> bool {
        self.0.abs_diff(now.0) <= EPOCH_WINDOW
    }

    /// Every epoch a recipient must precompute tags for, around `now`.
    ///
    /// RFC 2 §4.3 sizes the resulting table: correspondents × (2W+1), which at
    /// 50 correspondents and ±45 is 4 550 entries and 55 KB.
    pub fn window(now: Epoch) -> impl Iterator<Item = Epoch> {
        let lo = now.0.saturating_sub(EPOCH_WINDOW);
        let hi = now.0.saturating_add(EPOCH_WINDOW);
        (lo..=hi).map(Epoch)
    }

    /// Little-endian encoding, as it appears in a derivation label.
    pub fn to_le_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
}

/// Extract the shard: the leading `k` bits of a tag (RFC 2 §6).
///
/// `k` is a **link** parameter, not an object property, which is why enabling
/// sharding later needs no format change — the shard derives from the tag,
/// and the tag is already in the frozen header.
///
/// RFC 2 §6's warning is worth restating wherever this is called: `k` bits
/// reduce a node's load by 2ᵏ and reduce the recipient's anonymity set by
/// exactly the same factor. There is no value of `k` that is free.
pub fn shard_of(tag: &Tag, k: u8) -> u64 {
    if k == 0 {
        return 0;
    }
    let k = k.min(64);
    u64::from_be_bytes(tag.0) >> (64 - k)
}

/// Fraction of the corpus a `k`-bit shard admits — and, identically, the
/// fraction of the network a recipient's anonymity set is reduced to.
pub fn shard_share(k: u8) -> f64 {
    1.0 / (1u64 << k.min(63)) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_is_days_since_unix() {
        assert_eq!(Epoch::at(0), Epoch(0));
        assert_eq!(Epoch::at(EPOCH_SECS - 1), Epoch(0));
        assert_eq!(Epoch::at(EPOCH_SECS), Epoch(1));
        // 2026-08-05 is day 20671.
        assert_eq!(Epoch::at(20_671 * EPOCH_SECS + 3_600), Epoch(20_671));
    }

    /// RFC 1 §6.2: the window must cover MAX_TTL, not a latency percentile.
    #[test]
    fn window_covers_max_ttl() {
        const MAX_TTL_DAYS: u32 = 45;
        // Constant on both sides, and deliberately so: this asserts a
        // *relationship between two constants*, which is the only kind of
        // check that catches someone narrowing EPOCH_WINDOW later. Clippy
        // reads a constant assertion as a mistake; here it is the mechanism.
        #[allow(clippy::assertions_on_constants)]
        assert!(
            EPOCH_WINDOW >= MAX_TTL_DAYS,
            "an object delivered inside its declared TTL must still be recognisable"
        );
        let now = Epoch(20_671);
        // An object created at the far edge of MAX_TTL is still accepted.
        assert!(Epoch(now.0 - MAX_TTL_DAYS).accepted_at(now));
        assert!(!Epoch(now.0 - EPOCH_WINDOW - 1).accepted_at(now));
    }

    /// RFC 2 §4.3's table size, which krab-sizes also reproduces.
    #[test]
    fn precomputation_window_matches_rfc2() {
        let n = Epoch::window(Epoch(20_671)).count();
        assert_eq!(n, 2 * EPOCH_WINDOW as usize + 1);
        assert_eq!(50 * n, 4_550, "50 correspondents at ±45");
    }

    #[test]
    fn shard_takes_leading_bits() {
        let tag = Tag([0xFF, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(shard_of(&tag, 0), 0);
        assert_eq!(shard_of(&tag, 1), 1);
        assert_eq!(shard_of(&tag, 4), 0xF);
        assert_eq!(shard_of(&tag, 8), 0xFF);
        let tag = Tag([0x80, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(shard_of(&tag, 1), 1);
        assert_eq!(shard_of(&tag, 2), 0b10);
    }

    /// RFC 2 §6: "the two columns are the same number."
    #[test]
    fn shard_share_halves_load_and_anonymity_identically() {
        assert_eq!(shard_share(0), 1.0);
        assert_eq!(shard_share(1), 0.5);
        assert_eq!(shard_share(4), 0.0625);
        assert!((shard_share(5) - 0.03125).abs() < 1e-12);
    }

    #[test]
    fn shard_never_panics() {
        let tag = Tag([0xAB; 8]);
        for k in 0u8..=255 {
            let _ = shard_of(&tag, k);
            let _ = shard_share(k);
        }
    }
}
