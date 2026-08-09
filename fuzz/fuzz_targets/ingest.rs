//! `Store::ingest` — RFC 1 §11's `I1`–`I6` gauntlet.
//!
//! The most consequential predicate in the system: everything downstream
//! assumes an object in the store passed all six checks. Three of the six were
//! missing at various points and nothing failed, so this target asserts the
//! *postcondition* rather than the checks — whatever the input, an object that
//! entered the store must satisfy what the store promises.
#![no_main]

use krab_store::index::Store;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut store = Store::new();
    let now = 29_766_000u32;

    // Offered under its own identifier, and under a wrong one.
    let id = krab_crypto::object_id(data);
    let _ = store.ingest(id, data.to_vec(), now, u32::MAX);
    let _ = store.ingest(krab_crypto::object_id(b"elsewhere"), data.to_vec(), now, u32::MAX);

    // **The postcondition.** Whatever was accepted, these hold.
    for held in store.ids_in_order() {
        let bytes = store.get(held).expect("indexed but absent");
        // I5 — the identifier names the content.
        assert_eq!(krab_crypto::object_id(bytes), *held, "I5 violated");
        // I1 — the length equals the declared bucket.
        let h = krab_core::object::RoutingHeader::parse(bytes).expect("I3/I4 violated");
        assert_eq!(bytes.len(), h.bucket_size() as usize, "I1 violated");
        // I3 — version and class are recognised.
        assert_eq!(h.version, 1, "I3 violated");
        assert!(krab_core::object::Class::from_byte(h.class).is_some(), "I3 violated");
        // I2 — expiry is in the future.
        assert!(h.expiry_min > now, "I2 violated");
    }

    // Operations on whatever survived must not panic.
    let _ = store.range_fingerprint(0, u32::MAX);
    let _ = store.count_in_range(0, u32::MAX);
    let _ = store.watermark();
});
