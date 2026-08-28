//! What a peer's control messages cost this node — RFC 5 §12.
//!
//! Run with `cargo test --release -p krab-store --test range_cost -- --ignored
//! --nocapture`. Ignored by default because it is a measurement, not an
//! assertion: it prints wall-clock, and wall-clock on a shared machine is not
//! something a test suite should fail on.

use krab_core::object::{canonical_bytes, RoutingHeader, Tag};
use krab_store::Store;

const DAY: u32 = 1_440;
const MAX_TTL: u32 = 45 * DAY;

fn object(expiry_min: u32, salt: u32) -> (krab_core::object::ObjectId, Vec<u8>) {
    let h = RoutingHeader {
        version: 1,
        class: 0,
        size_bucket: 0,
        flags: 0,
        expiry_min,
        tag: Tag(salt.to_le_bytes().repeat(2).try_into().unwrap()),
    };
    let bytes = canonical_bytes(&h, &salt.to_le_bytes().repeat(10)).unwrap();
    (krab_crypto::object_id(&bytes), bytes)
}

fn corpus(n: u32) -> Store {
    let mut s = Store::new();
    for i in 0..n {
        // Spread across the whole 45-day retention window, as real expiries are.
        let (id, b) = object(1 + (i % MAX_TTL), i);
        let _ = s.ingest(id, b, 0, MAX_TTL);
    }
    s
}

#[test]
#[ignore = "measurement, not an assertion"]
fn what_one_batch_of_ranges_costs() {
    for n in [1_000u32, 10_000, 50_000] {
        let s = corpus(n);
        assert_eq!(s.len(), n as usize, "corpus did not build");

        // One frame holds 1 342 `Range` rows — measured, not estimated — and
        // `respond` describes each one, a `count` and a `fingerprint`, before
        // deciding anything. RFC 5 §4.4's round cap lets a peer send eight
        // such frames per session.
        let batch = 1_342;
        let t = std::time::Instant::now();
        let mut sink = 0u64;
        for i in 0..batch {
            let lo = (i as u32 * 37) % MAX_TTL;
            let hi = lo.saturating_add(DAY);
            sink += s.count_in_range(lo, hi) as u64;
            sink = sink.wrapping_add(s.range_fingerprint(lo, hi).to_bytes()[0] as u64);
        }
        let one = t.elapsed();
        println!(
            "corpus {n:>6}: one batch of {batch} ranges {one:>10.3?}   \
             a session's eight {:>10.3?}   (sink {sink})",
            one * 8
        );
    }
}
