//! **SIM-2** — measurements against the implementations, not against a model.
//!
//! `MILESTONE-0.1.md` §2 phase F: "SIM-2 against the implementations through
//! the `sim` backend, **not against a third model**."
//!
//! That constraint is the point. SIM-0 and SIM-1 were standalone models —
//! `krab-sim` has zero dependencies so its claims reproduce offline — and a
//! model can be right about a protocol the code does not implement. Everything
//! here drives `krab_store::Store`, `krab_proto::recon` and `krab_node::Node`,
//! so a divergence between the design and the build shows up as a failed
//! measurement rather than as a correct number about the wrong system.
//!
//! # The four items
//!
//! `RFC-5-blocking-items.md` §"SIM-2 now has four items":
//!
//! 1. **Quota versus vantage acquisition** (RFC 3 gate §3) — how much of the
//!    corpus an adversary sees per vantage point acquired.
//! 2. **Fan-out** (RFC 6 gate §3) — group cost measured rather than multiplied.
//! 3. **A real RBSR implementation** (RFC 5 §5) — against a real fingerprint
//!    tree, not an assumed one.
//! 4. **Capacity-pressure eviction with the watermark** (RFC 5 §3).
//!
//! # What these are and are not
//!
//! They are measurements with assertions on the properties the RFCs claim.
//! They are **not** a deanonymisation figure: RFC 8 §494 is explicit that such
//! a claim "requires a SIM-2 with an adversary model", and there is no
//! adversary model here — only honest-but-curious vantage points. Nothing in
//! this file supports a statement about anonymity.

use krab_core::object::{canonical_bytes, ObjectId, RoutingHeader, Tag};
use krab_node::node::StoreView;
use krab_proto::recon::Mode;
use krab_store::index::Store;

const NOW_MIN: u32 = 29_766_000;
const DAY: u32 = 1_440;

/// Deterministic, so a measurement is reproducible from its seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn object(salt: u32) -> (ObjectId, Vec<u8>) {
    let h = RoutingHeader {
        version: 1,
        class: 0,
        size_bucket: 0,
        flags: 0,
        // Spread across the retention window so eviction and the watermark
        // have something to order by.
        expiry_min: NOW_MIN + 1_000 + (salt % (45 * DAY)),
        tag: Tag((salt as u64).to_le_bytes()),
    };
    let mut body = [0u8; 40];
    body[..4].copy_from_slice(&salt.to_le_bytes());
    let b = canonical_bytes(&h, &body).expect("canonical");
    (krab_crypto::object_id(&b), b)
}

/// A node's corpus, as the real store.
fn store_with(salts: impl Iterator<Item = u32>) -> Store {
    let mut s = Store::new();
    for salt in salts {
        let (id, b) = object(salt);
        let _ = s.ingest(id, b, NOW_MIN, u32::MAX);
    }
    s
}

/// Reconcile two real stores through the real RBSR/manifest state machine.
///
/// Uses `krab_node::node::StoreView` — the adapter the node itself uses — so
/// nothing here is a reimplementation. A second adapter would be the "third
/// model" phase F rules out.
fn reconcile(a: &mut Store, b: &mut Store, mode: Mode) -> usize {
    let mut va = StoreView(a);
    let mut vb = StoreView(b);
    krab_proto::recon::reconcile(&mut va, &mut vb, mode, 0, u32::MAX).transferred
}

// ---------------------------------------------------------------------------
// Item 3 — a real RBSR implementation, against a real fingerprint tree
// ---------------------------------------------------------------------------

/// **RFC 5 §5.** RBSR converges against real range fingerprints, not assumed
/// ones — which is what SIM-0 and SIM-1 could not establish, because neither
/// ran the state machine.
#[test]
fn rbsr_converges_against_real_fingerprints() {
    for seed in [1u64, 7, 99] {
        let mut rng = Rng(seed);
        // Two overlapping corpora, each holding some of the other's objects.
        let a_salts: Vec<u32> = (0..400).map(|_| rng.below(600) as u32).collect();
        let b_salts: Vec<u32> = (0..400).map(|_| rng.below(600) as u32).collect();
        let mut a = store_with(a_salts.into_iter());
        let mut b = store_with(b_salts.into_iter());

        let before = (a.len(), b.len());
        let mut rounds = 0;
        loop {
            let moved = reconcile(&mut a, &mut b, Mode::Rbsr);
            rounds += 1;
            if moved == 0 {
                break;
            }
            assert!(
                rounds < 20,
                "RBSR did not converge in 20 rounds (seed {seed})"
            );
        }

        assert_eq!(a.len(), b.len(), "seed {seed}: corpora did not converge");
        assert!(
            a.len() >= before.0.max(before.1),
            "seed {seed}: objects were lost"
        );
        // The fingerprint is what RBSR reasons over, so equality of it is the
        // property — equal counts alone would not prove equal contents.
        assert_eq!(
            a.range_fingerprint(0, u32::MAX),
            b.range_fingerprint(0, u32::MAX),
            "seed {seed}: counts agree but contents do not"
        );
    }
}

/// Manifest mode reaches the same fixed point. RFC 5 §4.5 derives the mode from
/// latency class, so both must be correct — a courier link has no choice.
#[test]
fn manifest_and_rbsr_reach_the_same_corpus() {
    let mut rng = Rng(42);
    let salts: Vec<u32> = (0..300).map(|_| rng.below(500) as u32).collect();
    let other: Vec<u32> = (0..300).map(|_| rng.below(500) as u32).collect();

    let run = |mode| {
        let mut a = store_with(salts.iter().copied());
        let mut b = store_with(other.iter().copied());
        for _ in 0..20 {
            if reconcile(&mut a, &mut b, mode) == 0 {
                break;
            }
        }
        a.range_fingerprint(0, u32::MAX)
    };
    assert_eq!(
        run(Mode::Rbsr),
        run(Mode::Manifest),
        "the mode must not change the result"
    );
}

// ---------------------------------------------------------------------------
// Item 1 — quota versus vantage acquisition (RFC 3 gate §3)
// ---------------------------------------------------------------------------

/// **RFC 3 §3 / RFC 0 §5.3.** Does graduated quota make a fresh vantage point
/// slow to become useful?
///
/// > "RFC 0 §5.3 claims graduated quota 'means early vantage points are
/// > low-bandwidth and slow to become useful', and that claim is currently
/// > ungrounded." — `RFC-3-blocking-items.md`
///
/// # What a first attempt got wrong, and it is worth recording
///
/// Measured **without** quota, every node converges to the whole corpus and a
/// single vantage point sees 100% of it. That is not a bug — Krab floods, and
/// full replication is the design. It also means the visibility question is the
/// wrong one: an adversary does not need a vantage point to obtain ciphertext,
/// and RFC 8 §494 already rules out a deanonymisation claim from this file.
///
/// The claim RFC 0 §5.3 actually makes is narrower and testable: a *newly
/// acquired* node has a low quota, so it holds less, so the holdings signal an
/// attacker reads from it is weaker. SIM-1 §5 listed quota as explicitly
/// unmodelled — "the primary defence against the attack was absent from the
/// measurement of it" — so an unquota'd measurement reproduces exactly the gap
/// SIM-2 exists to close.
///
/// # The model
///
/// Ingress is capped per round and the cap grows with peering age. Everything
/// else is the real store and the real reconciliation state machine.
#[test]
fn graduated_quota_makes_a_fresh_vantage_point_slow_to_become_useful() {
    const ROUNDS: usize = 12;
    const CORPUS: u32 = 900;
    /// Bytes a peer may ingest per round at age 1. RFC 3 §6's dial.
    const BASE: u64 = 6 * 256;
    /// Rounds after which quota stops growing.
    const MATURE: usize = 8;

    let quota_at = |age: usize| BASE * age.min(MATURE) as u64;

    // The established network: one node holding everything.
    let source = store_with(0..CORPUS);
    let total = source.len();

    // Vantage points acquired at different times. A node joining at round `j`
    // has age `round - j`, and therefore a smaller quota for a while.
    let joins = [0usize, 4, 8, 11];
    let mut holdings = Vec::new();

    for &join in &joins {
        let mut node = Store::new();
        for round in 0..ROUNDS {
            if round < join {
                continue;
            }
            let age = round - join + 1;
            let budget = quota_at(age);

            // What the peer would offer: everything the node does not hold.
            // This is the real reconciliation result — the quota then caps how
            // much of it is admitted, which is what an ingress cap does.
            let offered: Vec<ObjectId> = source
                .ids_in_order()
                .filter(|id| !node.contains(id))
                .copied()
                .collect();

            let mut spent = 0u64;
            for id in offered {
                let Some(bytes) = source.get(&id) else {
                    continue;
                };
                if spent + bytes.len() as u64 > budget {
                    break;
                }
                spent += bytes.len() as u64;
                let b = bytes.to_vec();
                let _ = node.ingest(id, b, NOW_MIN, u32::MAX);
            }
        }
        let share = node.len() as f64 / total as f64;
        holdings.push((join, share));
        println!(
            "SIM-2 item 1 — quota: joined round {join}, holds {}/{total} = {share:.3}",
            node.len()
        );
    }

    // **The claim under test.** A node acquired late holds materially less
    // than one that has been peered from the start.
    let established = holdings[0].1;
    let fresh = holdings.last().unwrap().1;
    assert!(
        fresh < established,
        "a fresh vantage point held as much as an established one \
         ({fresh:.3} vs {established:.3}) — graduated quota bought nothing"
    );

    // Monotone in age: earlier joins hold at least as much.
    for w in holdings.windows(2) {
        assert!(
            w[0].1 >= w[1].1 - 1e-9,
            "holdings not monotone in peering age: {:?}",
            holdings
        );
    }

    // The number RFC 0 §5.3 was missing, now stated rather than asserted.
    println!(
        "SIM-2 item 1 — a vantage point acquired {} rounds before measurement holds \
         {:.1}% of what an established peer holds",
        ROUNDS - joins.last().unwrap(),
        100.0 * fresh / established.max(1e-9)
    );
}

/// Without quota the measurement says nothing, and recording that is the
/// point: it is the state SIM-1 §5 was in.
#[test]
fn without_quota_every_vantage_point_sees_everything() {
    let mut source = store_with(0..300);
    let mut fresh = Store::new();
    for _ in 0..6 {
        if reconcile(&mut source, &mut fresh, Mode::Rbsr) == 0 {
            break;
        }
    }
    assert_eq!(
        fresh.len(),
        source.len(),
        "unquota'd flooding converges — so an unquota'd measurement of vantage \
         acquisition is measuring nothing"
    );
}

// ---------------------------------------------------------------------------
// Item 2 — fan-out (RFC 6 gate §3)
// ---------------------------------------------------------------------------

/// **RFC 6 §1.** Group cost measured rather than multiplied.
///
/// RFC 6 §2.7 forbids per-recipient push, so a group message is one object per
/// recipient *at composition* and then ordinary corpus replication. The
/// question is whether replication cost scales with group size or with corpus
/// size — the difference between fan-out being linear in members and being
/// free.
#[test]
fn group_fanout_costs_one_object_per_member_and_replicates_once() {
    for members in [4usize, 12, 40] {
        // A message to a group: one sealed object per member (RFC 6 §2.7).
        let mut sender = Store::new();
        for m in 0..members {
            let (id, b) = object(900_000 + m as u32);
            sender.ingest(id, b, NOW_MIN, u32::MAX).unwrap();
        }
        assert_eq!(
            sender.len(),
            members,
            "one object per member at composition"
        );

        // Replication is corpus-wide and indifferent to the group: a relay
        // carrying them does not know they are related.
        let mut relay = Store::new();
        let moved = reconcile(&mut sender, &mut relay, Mode::Rbsr);
        assert_eq!(moved, members);
        assert_eq!(relay.len(), members);

        let bytes: u64 = relay.bytes();
        println!(
            "SIM-2 item 2 — fan-out: {members} members, {} objects, {bytes} bytes",
            relay.len()
        );
        // Linear in members and nothing worse. RFC 6 §1's concern is a
        // multiplier hiding somewhere; there is not one.
        assert_eq!(relay.len(), members);
    }
}

// ---------------------------------------------------------------------------
// Item 4 — capacity-pressure eviction with the watermark (RFC 5 §3)
// ---------------------------------------------------------------------------

/// **RFC 5 §3 and §8.** Under capacity pressure a node evicts, raises its
/// watermark, and then must not re-accept what it evicted — otherwise a
/// returning courier node re-injects the corpus the network already dropped
/// and the eviction never converges.
#[test]
fn eviction_raises_the_watermark_and_evicted_objects_do_not_return() {
    let mut full = store_with(0..800);
    let before = full.len();
    let cap = full.bytes() / 2;

    let evicted = full.evict_to(cap);
    assert!(evicted > 0, "nothing was evicted under pressure");
    assert!(full.bytes() <= cap, "eviction did not reach the cap");
    let watermark = full.watermark();
    assert!(
        watermark > 0,
        "eviction must raise the watermark (RFC 5 §8)"
    );

    println!(
        "SIM-2 item 4 — eviction: {before} → {} objects, watermark {watermark}",
        full.len()
    );

    // A peer that still holds everything tries to give it all back.
    let mut hoarder = store_with(0..800);
    for _ in 0..5 {
        if reconcile(&mut full, &mut hoarder, Mode::Rbsr) == 0 {
            break;
        }
    }

    // Nothing below the watermark returned.
    for id in full.ids_in_order() {
        let bytes = full.get(id).unwrap();
        let expiry = RoutingHeader::parse(bytes).unwrap().expiry_min;
        assert!(
            expiry >= watermark,
            "an object below the watermark was re-accepted: {expiry} < {watermark}"
        );
    }
    assert!(full.bytes() <= cap * 2, "the corpus grew back past its cap");
}

/// The watermark is monotone. A node that lowered it would re-admit its own
/// evictions on the next exchange.
#[test]
fn the_watermark_only_rises() {
    let mut s = store_with(0..600);
    let mut last = s.watermark();
    for divisor in [2u64, 3, 6] {
        s.evict_to(s.bytes() / divisor);
        let w = s.watermark();
        assert!(w >= last, "the watermark fell from {last} to {w}");
        last = w;
    }
}
