//! RFC 2 tag arithmetic: precomputation, false matches, shard dial, and the
//! corrected prekey batch sizing.
//!
//! # The erratum is the load-bearing part
//!
//! RFC 2 §8.1 corrects RFC 7 §5.3 and RFC 6 §2.8. Both sized prekey batches by
//! *messages received*, which is right only under random prekey selection.
//! RFC 7 §13 made deterministic indexing mandatory — `i = H(sender ‖ batch)
//! mod N` — under which a sender draws one index per batch period however many
//! messages it sends. The driver is therefore *distinct correspondents*.
//!
//! [`prekey_batch_for_correspondents`] implements the corrected rule and
//! [`tests::erratum_removes_the_max_object_ceiling`] checks the consequence.

use crate::keys::prekey_batch_wire;
use crate::object::{bucket_for, MAX_OBJECT};

/// Bytes per precomputed tag-table entry: 8-byte tag plus a 4-byte index.
pub const TAG_ENTRY: usize = 12;
/// Microseconds for one static-static X25519, RFC 2 §4.3.
pub const ECDH_US: f64 = 60.0;
/// Microseconds for one HKDF-Expand, RFC 2 §4.3.
pub const HKDF_US: f64 = 1.5;
/// SIM-0 §7 ingress, as RFC 2 §6 rounds it.
pub const INGRESS_MB: f64 = 0.0625;

/// Entries in the precomputation table: correspondents × (2W+1).
pub fn table_entries(correspondents: usize, window: usize) -> usize {
    correspondents * (2 * window + 1)
}

/// Table size in bytes.
pub fn table_bytes(correspondents: usize, window: usize) -> usize {
    table_entries(correspondents, window) * TAG_ENTRY
}

/// One-off ECDH cost, milliseconds — computed once per correspondent.
pub fn ecdh_ms(correspondents: usize) -> f64 {
    correspondents as f64 * ECDH_US / 1000.0
}

/// HKDF cost to rebuild the whole table, milliseconds.
pub fn hkdf_ms(correspondents: usize, window: usize) -> f64 {
    table_entries(correspondents, window) as f64 * HKDF_US / 1000.0
}

/// Probability that some unrelated object in a corpus collides with the table.
pub fn false_match_p(corpus: usize, entries: usize) -> f64 {
    corpus as f64 * entries as f64 / 2f64.powi(64)
}

/// Ingress per node per day at a given shard width, MB.
pub fn shard_ingress_mb(n: usize, k: u32) -> f64 {
    INGRESS_MB * n as f64 / 2f64.powi(k as i32)
}

/// Shard width needed to hold ingress at or below `target_mb`.
pub fn shard_k_for(n: usize, target_mb: f64) -> u32 {
    (INGRESS_MB * n as f64 / target_mb).log2().ceil().max(0.0) as u32
}

/// Expected number of senders sharing an index: birthday over S senders, N keys.
pub fn index_collisions(senders: usize, batch: usize) -> f64 {
    (senders * senders) as f64 / (2.0 * batch as f64)
}

/// RFC 2 §7.3's corrected sizing: `N ≥ 5 × correspondents`, rounded to a power
/// of two, which holds expected sharing at or below 10% of senders.
pub fn prekey_batch_for_correspondents(correspondents: usize) -> usize {
    (correspondents * 5).next_power_of_two()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(got: f64, want: f64, rel: f64) -> bool {
        (got - want).abs() / want.abs().max(1e-30) < rel
    }

    /// RFC 2 §4.3's precomputation table, reproduced exactly.
    #[test]
    fn precomputation_table_matches_rfc2() {
        // (correspondents, window, entries, bytes, ecdh ms, hkdf ms)
        let want = [
            (10usize, 30usize, 610usize, 7_320usize, 0.6f64, 0.9f64),
            (25, 30, 1_525, 18_300, 1.5, 2.3),
            (50, 30, 3_050, 36_600, 3.0, 4.6),
            (50, 45, 4_550, 54_600, 3.0, 6.8),
            (200, 30, 12_200, 146_400, 12.0, 18.3),
            (500, 45, 45_500, 546_000, 30.0, 68.2),
        ];
        for (c, w, entries, bytes, ecdh, hkdf) in want {
            assert_eq!(table_entries(c, w), entries, "{c} correspondents, ±{w}");
            assert_eq!(table_bytes(c, w), bytes, "{c} correspondents, ±{w} bytes");
            assert!(close(ecdh_ms(c), ecdh, 0.02), "{c} ECDH");
            assert!(close(hkdf_ms(c, w), hkdf, 0.02), "{c},±{w} HKDF");
        }
    }

    /// RFC 2 §4.4's false-match probabilities.
    #[test]
    fn false_match_table_matches_rfc2() {
        for (corpus, entries, p) in [
            (10_000usize, 1_525usize, 8.267e-13f64),
            (10_000, 22_750, 1.233e-11),
            (100_000, 1_525, 8.267e-12),
            (500_000, 22_750, 6.166e-10),
        ] {
            assert!(close(false_match_p(corpus, entries), p, 0.01), "{corpus}/{entries}");
        }
    }

    /// RFC 2 §6's shard table, and its sizing rule.
    #[test]
    fn shard_table_matches_rfc2() {
        // RFC 2 gives these to two significant figures, so k=8's 2.4414
        // prints as "2.4" — a 1.7% gap that is typography, not arithmetic.
        for (k, mb) in [(0u32, 625.0f64), (1, 312.5), (2, 156.2), (4, 39.1), (6, 9.8), (8, 2.4)] {
            assert!(close(shard_ingress_mb(10_000, k), mb, 0.02), "k={k}");
        }
        // "k=4 at n=10 000, k=7 at n=100 000" for a 50 MB/day target.
        assert_eq!(shard_k_for(10_000, 50.0), 4);
        assert_eq!(shard_k_for(100_000, 50.0), 7);
    }

    /// RFC 2 §7.3's collision figures and sizing rule.
    #[test]
    fn prekey_sizing_matches_rfc2() {
        for (correspondents, batch, shared) in [
            (10usize, 64usize, 0.78f64),
            (25, 128, 2.44),
            (50, 256, 4.88),
            (100, 512, 9.77),
            (200, 1_024, 19.53),
        ] {
            assert_eq!(prekey_batch_for_correspondents(correspondents), batch, "{correspondents}");
            assert!(close(index_collisions(correspondents, batch), shared, 0.02));
            // The rule's stated property: at most 10% of senders share.
            assert!(index_collisions(correspondents, batch) / correspondents as f64 <= 0.10 + 1e-9);
        }
    }

    /// RFC 2 §8.1's corrected-versus-published comparison.
    #[test]
    fn erratum_shrink_factors_match_rfc2() {
        // (correspondents, published batch, corrected batch, shrink)
        for (c, old, new, shrink) in [
            (12usize, 256usize, 64usize, 4usize),   // solo, 5 msg/d, 30 d
            (25, 512, 128, 4),                      // group of 20, 7 d
            (49, 2_048, 256, 8),                    // group of 50, 7 d
            (49, 8_192, 256, 32),                   // group of 50, 30 d
            (100, 8_192, 512, 16),                  // busy node, 100 msg/d
        ] {
            assert_eq!(prekey_batch_for_correspondents(c), new, "{c} correspondents");
            assert_eq!(old / new, shrink, "{c} shrink factor");
        }
    }

    /// The consequence: the `MAX_OBJECT` ceiling RFC 7 §5.3 and RFC 6 §2.8
    /// derived no longer binds.
    #[test]
    fn erratum_removes_the_max_object_ceiling() {
        // RFC 7 §5.3's impossible case: 100 msg/day republished monthly.
        assert!(prekey_batch_wire(8_192) > MAX_OBJECT, "published model overflows");
        // Under the corrected model that node has ~100 correspondents.
        let corrected = prekey_batch_for_correspondents(100);
        assert_eq!(corrected, 512);
        assert!(prekey_batch_wire(corrected) < MAX_OBJECT);
        // RFC 6 §2.8's 50-member group, monthly: 256 keys, 8312 B.
        assert_eq!(prekey_batch_for_correspondents(49), 256);
        assert_eq!(prekey_batch_wire(256), 8_312);
        assert_eq!(bucket_for(8_312), Some(16_384));
        // Even 4096 keys fits, so nothing in the plausible range overflows.
        assert_eq!(prekey_batch_wire(4_096), 131_192);
        assert!(prekey_batch_wire(4_096) < MAX_OBJECT);
    }

    /// RFC 2 §5 sets W to ±30 by default. RFC 1 §2 and §6.2 require
    /// W ≥ MAX_TTL / EPOCH = 45, and forbid narrowing below it. The two
    /// documents disagree; see RFC-2-review.md §1.
    #[test]
    fn rfc2_default_window_is_below_what_rfc1_requires() {
        const MAX_TTL_D: usize = 45;
        const EPOCH_D: usize = 1;
        let rfc1_floor = MAX_TTL_D / EPOCH_D;
        let rfc2_default = 30;
        let rfc2_minimum = 14;
        assert!(rfc2_default < rfc1_floor, "RFC 2 default ±{rfc2_default} < RFC 1 floor ±{rfc1_floor}");
        assert!(rfc2_minimum < rfc1_floor, "RFC 2 minimum ±{rfc2_minimum} < RFC 1 floor ±{rfc1_floor}");
    }

    /// RFC 2 §9 declares the precomputation table key material. RFC 7 §2.1's
    /// footprint omits it, and RFC 7 §9's mlock argument rests on that
    /// footprint being under 100 KB.
    #[test]
    fn tag_table_breaks_rfc7_s_under_100kb_claim() {
        const RFC7_FOOTPRINT: usize = 82_732;
        assert!(RFC7_FOOTPRINT < 100_000);
        for (c, w) in [(50usize, 45usize), (200, 30), (500, 45)] {
            assert!(
                RFC7_FOOTPRINT + table_bytes(c, w) > 100_000,
                "{c} correspondents at ±{w} should exceed the claim"
            );
        }
    }
}
