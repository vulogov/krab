//! RFC 7 key-material sizing.
//!
//! # What is derivable and what is recovered
//!
//! The reservoir, decapsulation and footprint figures follow from constants
//! RFC 7 states outright (32 B chunks, 60 B wrapped records, 100 µs per
//! X25519 decapsulation) and are computed here.
//!
//! The prekey-batch wire size carries a 120-byte constant that RFC 7 does not
//! decompose — it publishes `wire = 32·N + 120` without saying what the 120
//! is made of, and a `bulletin` body per RFC 1 §5.2 does not obviously
//! account for it. It is recovered from RFC 7's own table and flagged in
//! `Documentation/RFC-7-review.md`, exactly as RFC 3's fragment wrapper was.

use crate::object::{bucket_for, MAX_OBJECT};

/// One reservoir chunk, RFC 7 §6.
pub const CHUNK: usize = 32;
/// One wrapped record: 32 key + 16 AEAD tag + 12 nonce. RFC 7 §4.1.
pub const WRAPPED_RECORD: usize = 60;
/// X25519 public or private key.
pub const X25519: usize = 32;
/// Ed25519 keypair as backed up, RFC 7 §11.
pub const IDENTITY: usize = 64;
/// A `peer-link` credential with one endpoint, RFC 3 §3.
pub const CREDENTIAL: usize = 416;

/// Per-batch wire overhead above the raw public keys. Recovered from RFC 7
/// §5.3/§5.4, which are self-consistent at exactly this value across all six
/// batch sizes.
pub const PREKEY_OVERHEAD: usize = 120;

/// Microseconds per X25519 decapsulation, RFC 7 §5.5.
pub const DECAP_US: f64 = 100.0;
/// Live prekey batches inside the acceptance window, RFC 7 §5.5.
pub const LIVE_BATCHES: usize = 3;

/// Reservoir material held for `peers` peers at `epochs` epochs of retention.
pub fn reservoir(peers: usize, epochs: usize) -> usize {
    peers * epochs * CHUNK
}

/// Raw one-time-pad material for the same traffic, RFC 7 §6.1's comparison.
pub fn raw_pad(msgs_per_day: usize, days: usize, bucket: usize) -> usize {
    msgs_per_day * days * bucket
}

/// Wire size of a published prekey batch of `n` keys.
pub fn prekey_batch_wire(n: usize) -> usize {
    n * X25519 + PREKEY_OVERHEAD
}

/// Keys consumed over a republish interval, before headroom.
pub fn prekeys_needed(msgs_per_day: usize, republish_days: usize) -> usize {
    msgs_per_day * republish_days
}

/// Batch size chosen for `needed` keys: next power of two at 1.5× headroom
/// (RFC 7 §5.3's rule).
pub fn batch_for(needed: usize) -> usize {
    let want = (needed * 3).div_ceil(2);
    want.next_power_of_two()
}

/// Milliseconds to trial-decapsulate one tag-matched object.
pub fn decap_ms(batch: usize, deterministic: bool) -> f64 {
    let attempts = if deterministic {
        LIVE_BATCHES
    } else {
        batch * LIVE_BATCHES
    };
    attempts as f64 * DECAP_US / 1000.0
}

/// Total secret material on disk, RFC 7 §2.1.
pub fn footprint(peers: usize, epochs: usize, batch: usize) -> usize {
    reservoir(peers, epochs)          // reservoir chunks
        + epochs * WRAPPED_RECORD     // epoch wrappers
        + batch * X25519              // prekey privates
        + peers * CREDENTIAL          // peer credentials
        + peers * X25519              // noise statics
        + IDENTITY
}

/// Does a published batch of `n` keys fit under a link's object gate?
pub fn batch_crosses(n: usize, gate: usize) -> bool {
    bucket_for(prekey_batch_wire(n)).is_some_and(|b| b <= gate)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7 §2.1 / the reservoir table, reproduced exactly.
    #[test]
    fn reservoir_table_matches_rfc7() {
        for (eps, per_peer, twenty_five) in [
            (30usize, 960usize, 24_000usize),
            (45, 1_440, 36_000),
            (60, 1_920, 48_000),
            (90, 2_880, 72_000),
        ] {
            assert_eq!(reservoir(1, eps), per_peer, "{eps} epochs, one peer");
            assert_eq!(reservoir(25, eps), twenty_five, "{eps} epochs, 25 peers");
        }
        assert_eq!(reservoir(1, 365), 11_680, "one peer-year");
    }

    /// RFC 7 §6.1's headline: 6400x smaller than a raw pad.
    #[test]
    fn reservoir_beats_raw_pad_by_6400x() {
        let pad = raw_pad(50, 365, 4_096);
        let res = reservoir(1, 365);
        assert_eq!(pad, 74_752_000);
        assert_eq!(pad / res, 6_400);
    }

    /// RFC 7 §5.3's batch-sizing table, reproduced exactly.
    #[test]
    fn batch_sizing_matches_rfc7() {
        // (msgs/day, republish days, needed, batch, wire, bucket)
        let want = [
            (
                5usize,
                30usize,
                150usize,
                256usize,
                8_312usize,
                Some(16_384usize),
            ),
            (20, 30, 600, 1_024, 32_888, Some(65_536)),
            (20, 7, 140, 256, 8_312, Some(16_384)),
            (50, 7, 350, 1_024, 32_888, Some(65_536)),
            (100, 7, 700, 2_048, 65_656, Some(262_144)),
            (100, 30, 3_000, 8_192, 262_264, None), // exceeds MAX_OBJECT
        ];
        for (per_day, republish, needed, batch, wire, bucket) in want {
            assert_eq!(prekeys_needed(per_day, republish), needed);
            assert_eq!(batch_for(needed), batch, "batch for {needed} needed");
            assert_eq!(prekey_batch_wire(batch), wire, "wire for batch {batch}");
            assert_eq!(bucket_for(wire), bucket, "bucket for {wire} B");
        }
        assert!(prekey_batch_wire(8_192) > MAX_OBJECT);
    }

    /// RFC 7 §5.4: no batch crosses a link gated at 512 bytes.
    #[test]
    fn no_batch_crosses_a_512_byte_gate() {
        for n in [64usize, 128, 256, 512, 1_024, 2_048] {
            assert!(
                !batch_crosses(n, 512),
                "batch {n} should not cross a 512 B gate"
            );
        }
    }

    /// But RFC 1 §8.3 tabulates LoRa airtime up to the 4096-byte bucket, and
    /// at that gate the smallest batch does cross. The two documents assume
    /// different LoRa gates; see RFC-7-review.md.
    #[test]
    fn a_small_batch_does_cross_at_rfc1_s_lora_gate() {
        assert!(
            batch_crosses(64, 4_096),
            "batch 64 is 2168 B -> 4096 bucket"
        );
        assert!(
            !batch_crosses(128, 4_096),
            "batch 128 is 4216 B -> 16384 bucket"
        );
    }

    /// RFC 7 §5.5's decapsulation table, reproduced exactly.
    #[test]
    fn decapsulation_cost_matches_rfc7() {
        for (batch, exhaustive) in [
            (64usize, 19.2f64),
            (128, 38.4),
            (512, 153.6),
            (2_048, 614.4),
        ] {
            assert!(
                (decap_ms(batch, false) - exhaustive).abs() < 0.05,
                "batch {batch}"
            );
            assert!(
                (decap_ms(batch, true) - 0.30).abs() < 0.01,
                "batch {batch} deterministic"
            );
        }
        // At 200 tag-matched objects in one reconciliation.
        assert!((decap_ms(512, false) * 200.0 / 1000.0 - 30.7).abs() < 0.1);
        assert!((decap_ms(2_048, false) * 200.0 / 1000.0 - 122.9).abs() < 0.1);
        assert!((decap_ms(2_048, true) * 200.0 / 1000.0 - 0.06).abs() < 0.01);
    }

    /// RFC 7 §2.1's footprint, reproduced exactly.
    #[test]
    fn footprint_matches_rfc7() {
        assert_eq!(reservoir(25, 45), 36_000);
        assert_eq!(45 * WRAPPED_RECORD, 2_700);
        assert_eq!(1_024 * X25519, 32_768);
        assert_eq!(25 * CREDENTIAL, 10_400);
        assert_eq!(25 * X25519, 800);
        assert_eq!(footprint(25, 45, 1_024), 82_732);
    }

    /// §9's mlock argument rests on "under 100 KB". True at the batch size
    /// §2.1 assumes, and not at the largest batch §5.3 permits.
    #[test]
    fn under_100kb_holds_only_at_the_assumed_batch_size() {
        assert!(footprint(25, 45, 1_024) < 100_000);
        assert!(footprint(25, 45, 2_048) > 100_000);
    }
}
