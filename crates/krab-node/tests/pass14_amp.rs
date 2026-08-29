//! Pass 14 measurement: work per `Range` message scales with the range count
//! the attacker puts in one frame, which nothing bounds.
use krab_core::object::{canonical_bytes, RoutingHeader, Tag};
use krab_node::node::StoreView;
use krab_proto::control::Range;
use krab_proto::recon::respond;
use krab_store::index::Store;

const NOW: u32 = 29_766_000;

fn object(salt: u32) -> (krab_core::object::ObjectId, Vec<u8>) {
    let h = RoutingHeader {
        version: 1,
        class: 0,
        size_bucket: 0,
        flags: 0,
        expiry_min: NOW + 40_000 + salt,
        tag: Tag((salt as u64).to_le_bytes()),
    };
    let b =
        canonical_bytes(&h, &krab_core::object::example_sealed_body((salt % 251) as u8)).unwrap();
    (krab_crypto::object_id(&b), b)
}

#[test]
fn measure_range_amplification() {
    let n = 100_000u32;
    let mut s = Store::new();
    for salt in 0..n {
        let (id, b) = object(salt);
        let _ = s.ingest(id, b, NOW, u32::MAX);
    }
    eprintln!("stored {}", s.len());

    // The attacker's frame: as many ranges as fit, each offset by one minute
    // from a bucket edge so the whole-bucket shortcut cannot apply, each with
    // a fingerprint that cannot match so the descent never prunes.
    let lo0 = NOW + 40_000;
    let ranges: Vec<Range> = (0..1337u32)
        .map(|i| Range {
            lo: lo0 + 1 + i,
            hi: lo0 + 1 + i + 1_440,
            fingerprint: krab_crypto::Fingerprint::ZERO,
            count: 0,
        })
        .collect();

    let wire = krab_proto::control::Control::Range(ranges.clone()).write();
    eprintln!("frame carrying {} ranges = {} bytes", ranges.len(), wire.len());

    let view = StoreView(&mut s);
    let t = std::time::Instant::now();
    let out = respond(&view, &ranges);
    let d = t.elapsed();
    eprintln!(
        "one Range message: {:?}  (descend={} list={} leaves={})",
        d,
        out.descend.len(),
        out.list.len(),
        out.leaves.len()
    );
    eprintln!("x8 rounds => {:?} of CPU for {} bytes x8 uploaded", d * 8, wire.len());
}
