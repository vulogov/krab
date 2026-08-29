//! Pass 14: does an honest RBSR descent produce a `Range` frame that cannot
//! be sent? `frame::MAX_FRAME` is 65 535 and nothing caps `Response::descend`.
use krab_core::object::{canonical_bytes, RoutingHeader, Tag};
use krab_node::node::StoreView;
use krab_proto::control::{Control, Range};
use krab_proto::recon::{describe, respond, RBSR_MAX_ROUNDS};
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

fn store(salts: impl Iterator<Item = u32>) -> Store {
    let mut s = Store::new();
    for salt in salts {
        let (id, b) = object(salt);
        let _ = s.ingest(id, b, NOW, u32::MAX);
    }
    s
}

fn run(n: u32, label: &str) {
    // Two peers that diverge everywhere: disjoint halves of the same window.
    let mut a = store((0..n).filter(|i| i % 2 == 0));
    let mut b = store((0..n).filter(|i| i % 2 == 1));
    let (va, vb) = (StoreView(&mut a), StoreView(&mut b));

    let lo = NOW;
    let hi = NOW + 40_000 + n + 10;
    let mut offered = vec![describe(&va, lo, hi)];
    let mut worst = 0usize;

    // Alternate responder each round, as the two halves of the real exchange
    // do: a describes, b responds, a responds to b's descend, and so on.
    for round in 1..=RBSR_MAX_ROUNDS {
        let me: &dyn krab_proto::recon::Corpus = if round % 2 == 1 { &vb } else { &va };
        let resp = respond(me, &offered);
        let mut out = resp.descend;
        for (l, h) in resp.leaves {
            out.push(describe(me, l, h));
        }
        if out.is_empty() {
            break;
        }
        let bytes = Control::Range(out.clone()).write().len();
        // The RBSR arm sends `answer.list` as one Manifest, with no `.take`.
        let mbytes = if resp.list.is_empty() {
            0
        } else {
            Control::Manifest { filter_digest: [0u8; 32], entries: resp.list.clone() }
                .write()
                .len()
        };
        worst = worst.max(bytes).max(mbytes);
        eprintln!(
            "{label} round {round}: Range frame = {} bytes{}, Manifest frame = {} bytes{}",
            bytes,
            if bytes > 65_535 { " <-- OVER" } else { "" },
            mbytes,
            if mbytes > 65_535 { " <-- OVER" } else { "" }
        );
        offered = out;
    }
    eprintln!("{label}: worst Range frame = {worst} bytes (MAX_FRAME = 65535)\n");
}

#[test]
fn rbsr_descent_frame_sizes() {
    for n in [10_000u32, 20_000, 30_000, 50_000, 100_000] {
        run(n, &format!("n={n}"));
    }
}
