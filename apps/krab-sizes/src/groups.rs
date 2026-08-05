//! RFC 6 group and channel cost.
//!
//! Groups are fan-out: a G-member group turns one authored message into G−1
//! sealed objects, so corpus load is quadratic in group size. Channels are a
//! single flooded object regardless of audience.
//!
//! Every figure RFC 6 publishes is derived here from SIM-0's traffic model
//! (2 messages per member per day) and RFC 1's size buckets.
//!
//! # A bucket inconsistency worth knowing about
//!
//! RFC 6 §2.3 costs a group message at the 1 KB bucket and §2.4 costs the same
//! message at 256 B for the LoRa table. Both reproduce only with their own
//! constant, which is why [`GROUP_BUCKET`] and [`LORA_GROUP_BUCKET`] differ.
//! Flagged in `Documentation/RFC-6-review.md`.

/// SIM-0 §1 traffic model.
pub const MSGS_PER_MEMBER_DAY: usize = 2;
/// RFC 6 §2.3 costs a fanned-out group message at the 1 KB bucket.
pub const GROUP_BUCKET: usize = 1_024;
/// RFC 6 §2.4's LoRa table costs the same message at the 256 B bucket.
pub const LORA_GROUP_BUCKET: usize = 256;
/// RFC 6 §3.3's assumed channel post size.
pub const CHANNEL_POST: usize = 4_096;
/// SIM-0 §2 baseline ingress per node at n=500, MB/day.
pub const BASELINE_MB_DAY: f64 = 31.0;
/// RFC 1 §8.3 / SIM-0 §1: LoRa frame payload and sustained rate.
pub const LORA_PAYLOAD: usize = 51;
pub const LORA_BPS: f64 = 0.85;

/// Objects per day the whole network stores for one G-member group.
pub fn group_objects_per_day(g: usize) -> usize {
    g * MSGS_PER_MEMBER_DAY * g.saturating_sub(1)
}

/// Corpus load per day from one group, MB.
pub fn group_mb_day(g: usize) -> f64 {
    group_objects_per_day(g) as f64 * GROUP_BUCKET as f64 / 1e6
}

/// Messages a member receives per day from one G-member group.
pub fn received_per_day(g: usize) -> usize {
    g.saturating_sub(1) * MSGS_PER_MEMBER_DAY
}

/// Objects per day under a shared sender key — one per authored message.
pub fn shared_key_objects_per_day(g: usize) -> usize {
    g * MSGS_PER_MEMBER_DAY
}

/// Background object arrival rate per hour across a network of `n` nodes.
pub fn background_per_hour(n: usize) -> f64 {
    n as f64 * MSGS_PER_MEMBER_DAY as f64 / 24.0
}

/// Emission window needed so a fan-out burst lifts the local arrival rate by
/// no more than `lift`.
///
/// RFC 6 §2.7 uses a 10% lift. The threshold is a stated heuristic rather than
/// a detection model — see the review.
pub fn stagger_hours(g: usize, n: usize, lift: f64) -> f64 {
    g.saturating_sub(1) as f64 / (lift * background_per_hour(n))
}

/// LoRa frames and airtime in seconds for one group message.
pub fn lora_group_message(g: usize) -> (usize, f64) {
    let copies = g.saturating_sub(1);
    let frames_per_copy = LORA_GROUP_BUCKET.div_ceil(LORA_PAYLOAD);
    let airtime = copies as f64 * LORA_GROUP_BUCKET as f64 / LORA_BPS;
    (copies * frames_per_copy, airtime)
}

/// Channel corpus load per day, MB.
pub fn channel_mb_day(posts_per_day: usize, size: usize) -> f64 {
    posts_per_day as f64 * size as f64 / 1e6
}

/// Network-wide fan-out multiplier when group messaging is the norm rather
/// than the exception: every authored message becomes G−1 objects.
///
/// RFC 6 §2.3 reports one group against the whole network baseline, which is a
/// different and much smaller quantity. See the review.
pub fn systemic_multiplier(g: usize) -> usize {
    g.saturating_sub(1).max(1)
}

/// Network size at which sharding becomes mandatory, given a fan-out
/// multiplier. RFC 0 §8.3 puts the un-fanned threshold near n=5000.
pub fn shard_threshold(multiplier: usize) -> f64 {
    const INGRESS_PER_NODE_PER_NODE: f64 = 0.063; // MB/day, SIM-0 §7
    const SHARD_AT_MB: f64 = 310.0;
    SHARD_AT_MB / (INGRESS_PER_NODE_PER_NODE * multiplier as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(got: f64, want: f64, tol: f64) -> bool {
        (got - want).abs() <= tol
    }

    /// RFC 6 §2.3's fan-out table, reproduced exactly.
    #[test]
    fn fanout_table_matches_rfc6() {
        // (G, objects/day, MB/day, share of baseline %, received/day)
        let want = [
            (3usize, 12usize, 0.01f64, 0.0f64, 4usize),
            (5, 40, 0.04, 0.0, 8),
            (10, 180, 0.18, 1.0, 18),
            (20, 760, 0.78, 3.0, 38),
            (30, 1_740, 1.78, 6.0, 58),
            (50, 4_900, 5.02, 16.0, 98),
            (100, 19_800, 20.28, 65.0, 198),
            (200, 79_600, 81.51, 263.0, 398),
        ];
        for (g, objs, mb, share, recv) in want {
            assert_eq!(group_objects_per_day(g), objs, "G={g} objects/day");
            assert!(close(group_mb_day(g), mb, 0.01), "G={g} MB/day");
            assert!(
                close(100.0 * group_mb_day(g) / BASELINE_MB_DAY, share, 0.6),
                "G={g} share of baseline"
            );
            assert_eq!(received_per_day(g), recv, "G={g} received/day");
        }
    }

    /// RFC 6 §2.4's fan-out-versus-shared-key ratios.
    #[test]
    fn shared_key_comparison_matches_rfc6() {
        for (g, shared, ratio) in
            [(5usize, 10usize, 4usize), (10, 20, 9), (20, 40, 19), (50, 100, 49), (100, 200, 99)]
        {
            assert_eq!(shared_key_objects_per_day(g), shared, "G={g} shared-key objects");
            assert_eq!(group_objects_per_day(g) / shared, ratio, "G={g} ratio");
        }
    }

    /// RFC 6 §2.7's emission-stagger table, reproduced exactly.
    #[test]
    fn stagger_table_matches_rfc6() {
        for (n, background, w10, w20, w50) in [
            (100usize, 8.3f64, 10.8f64, 22.8f64, 58.8f64),
            (500, 41.7, 2.2, 4.6, 11.8),
            (2_000, 166.7, 0.5, 1.1, 2.9),
        ] {
            assert!(close(background_per_hour(n), background, 0.1), "n={n} background");
            assert!(close(stagger_hours(10, n, 0.10), w10, 0.1), "n={n} G=10");
            assert!(close(stagger_hours(20, n, 0.10), w20, 0.1), "n={n} G=20");
            assert!(close(stagger_hours(50, n, 0.10), w50, 0.1), "n={n} G=50");
        }
    }

    /// RFC 6 §2.4's LoRa table, reproduced exactly.
    #[test]
    fn lora_table_matches_rfc6() {
        for (g, frames, hours) in
            [(3usize, 12usize, 0.2f64), (5, 24, 0.3), (10, 54, 0.8), (20, 114, 1.6)]
        {
            let (f, secs) = lora_group_message(g);
            assert_eq!(f, frames, "G={g} frames");
            assert!(close(secs / 3600.0, hours, 0.05), "G={g} airtime");
        }
    }

    /// RFC 6 §3.3's channel table, reproduced exactly.
    #[test]
    fn channel_table_matches_rfc6() {
        for (posts, size, mb, hundred) in [
            (1usize, 4_096usize, 0.004f64, 0.4f64),
            (10, 4_096, 0.041, 4.1),
            (50, 4_096, 0.205, 20.5),
            (10, 65_536, 0.655, 65.5),
        ] {
            assert!(close(channel_mb_day(posts, size), mb, 0.001), "{posts}/day at {size} B");
            assert!(close(channel_mb_day(posts, size) * 100.0, hundred, 0.05), "x100 channels");
        }
    }

    /// RFC 6's "a group of 20 costs 380x a channel post".
    ///
    /// It holds only against a single-author channel at the same per-author
    /// rate: 760 objects against 2. The like-for-like per-message figure is
    /// 19x, which is the number §2.4 uses.
    #[test]
    fn the_380x_claim_is_per_author_not_per_message() {
        assert_eq!(group_objects_per_day(20) / MSGS_PER_MEMBER_DAY, 380);
        assert_eq!(group_objects_per_day(20) / shared_key_objects_per_day(20), 19);
    }

    /// The systemic figure RFC 6 §2.3 does not report: when group messaging is
    /// the norm, the multiplier is G−1 network-wide, which moves RFC 0 §8.3's
    /// sharding threshold by the same factor.
    #[test]
    fn systemic_fanout_moves_the_sharding_threshold() {
        assert_eq!(systemic_multiplier(20), 19);
        let t = shard_threshold(systemic_multiplier(20));
        assert!((250.0..270.0).contains(&t), "threshold {t:.0}, expected ~260");
        // Un-fanned, RFC 0 §8.3's ~5000.
        let base = shard_threshold(1);
        assert!((4_800.0..5_000.0).contains(&base), "baseline {base:.0}");
    }
}
