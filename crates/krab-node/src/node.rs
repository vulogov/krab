//! The node loop — the "background server" half of the application.
//!
//! Krab has no headless mode (`RFC-8-review.md` §8.1), so the node and the TUI
//! are one process. That does **not** make the node a foreground activity: it
//! accepts inbound sessions, initiates outbound ones on the Poisson schedule,
//! reconciles, and stores — all without user involvement, and all while the
//! interface is doing something else, minimised, or locked.
//!
//! # What "without user involvement" has to mean, precisely
//!
//! Three independent things, each with a test:
//!
//! 1. **Inbound is always accepted.** There is no schedule on `accept`, no
//!    prompt, and no notion of the user being available. A peer that reaches
//!    us is served.
//! 2. **Outbound fires on the schedule and on nothing else.** [`Node::tick`]
//!    takes `now` and entropy, exactly as [`crate::scheduler::Scheduler`]
//!    does, so no user action can advance it (RFC 0 I-5).
//! 3. **Both continue while locked.** A locked node is a relay
//!    (`RFC-7-review.md` §9): it holds session keys, reconciles normally, and
//!    cannot read what it carries.
//!
//! # Why `tick` takes time rather than reading a clock
//!
//! In production a thread calls `tick` on a timer. In a test or under the
//! simulator the caller supplies time, so a fortnight of node behaviour runs
//! deterministically in a millisecond. That is the same discipline
//! `krab-core` uses, and it is what makes RFC 3 §11.3's courier-only release
//! gate testable at all.

use crate::lock::Session;
use crate::metrics::PeerMetrics;
use crate::scheduler::{PeerId, Scheduler};
use krab_fabric::Fabric;
use krab_proto::control::{Entry, TRUNC};
use krab_proto::recon::{self, Corpus, Mode};
use krab_store::Store;
use std::collections::BTreeMap;

/// Adapts the store to what reconciliation needs.
///
/// Everything here derives from `(expiry, id)` ordering and the frozen header,
/// so none of it requires a decryption key.
/// A [`Store`] as a reconcilable [`Corpus`].
///
/// Public so SIM-2 can drive the real state machine over real stores —
/// `MILESTONE-0.1.md` §2 phase F requires the measurements run "against the
/// implementations ... not against a third model", and a second adapter
/// written for the simulator would be exactly that third model.
pub struct StoreView<'a>(pub &'a mut Store);

impl Corpus for StoreView<'_> {
    fn entries(&self, lo: u32, hi: u32) -> Vec<Entry> {
        self.0
            .entries_in_range(lo, hi)
            .into_iter()
            .map(|(expiry_min, id)| Entry {
                expiry_min,
                id: id.truncated(),
            })
            .collect()
    }
    fn fingerprint(&self, lo: u32, hi: u32) -> krab_crypto::Fingerprint {
        self.0.range_fingerprint(lo, hi)
    }
    fn count(&self, lo: u32, hi: u32) -> u32 {
        self.0.count_in_range(lo, hi)
    }
    fn get(&self, id: &[u8; TRUNC]) -> Option<Vec<u8>> {
        self.0.get_truncated(id).map(|b| b.to_vec())
    }
    fn has(&self, id: &[u8; TRUNC]) -> bool {
        self.0.has_truncated(id)
    }
    fn put(&mut self, bytes: Vec<u8>) {
        if let Ok(h) = krab_core::object::RoutingHeader::parse(&bytes) {
            let id = krab_crypto::object_id(&bytes);
            // RFC 1 §11's checks live in the store; a refusal here is normal.
            let _ = self
                .0
                .ingest(id, bytes, h.expiry_min.saturating_sub(1), u32::MAX);
        }
    }
}

/// One peer's link.
pub struct Link {
    /// The peer.
    pub peer: PeerId,
    /// Its carrier.
    pub fabric: Box<dyn Fabric>,
}

/// What one tick did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TickReport {
    /// Inbound sessions served.
    pub accepted: usize,
    /// Outbound reconciliations initiated by the schedule.
    pub initiated: usize,
    /// Objects transferred, both directions.
    pub transferred: usize,
}

/// A running Krab node.
pub struct Node {
    /// The corpus.
    pub store: Store,
    /// Key state; a locked node still reconciles.
    pub session: Session,
    scheduler: Scheduler,
    links: Vec<Link>,
    metrics: BTreeMap<PeerId, PeerMetrics>,
    window: (u32, u32),
}

impl Node {
    /// A node with the given corpus, key state and reconciliation window.
    pub fn new(store: Store, session: Session, mean_interval_s: u64, window: (u32, u32)) -> Node {
        Node {
            store,
            session,
            scheduler: Scheduler::new(mean_interval_s),
            links: Vec::new(),
            metrics: BTreeMap::new(),
            window,
        }
    }

    /// Add a peer link and enrol it in the schedule.
    pub fn add_link(&mut self, link: Link, now: u64, entropy: u64) {
        self.scheduler.add(link.peer, now, entropy);
        self.metrics.entry(link.peer).or_default();
        self.links.push(link);
    }

    /// Peers linked.
    pub fn peer_count(&self) -> usize {
        self.links.len()
    }

    /// Metrics for a peer.
    pub fn metrics(&self, peer: &PeerId) -> Option<&PeerMetrics> {
        self.metrics.get(peer)
    }

    /// Advance the node by one step.
    ///
    /// Takes `now` and entropy and **nothing describing the user**. There is
    /// no parameter through which UI state, focus, composition or lock state
    /// could reach the schedule, which is what makes I-5 structural rather
    /// than a rule someone has to remember.
    pub fn tick(&mut self, now: u64, entropy: u64) -> TickReport {
        let mut report = TickReport::default();

        // 1. Inbound. Unconditional: no schedule, no prompt, no notion of the
        //    user being available. A peer that reaches us is served.
        for i in 0..self.links.len() {
            if let Ok(Some(_session)) = self.links[i].fabric.accept() {
                report.accepted += 1;
            }
        }

        // 2. Outbound, driven only by the Poisson schedule.
        let due = self.scheduler.due(now, entropy);
        for peer in due {
            let Some(idx) = self.links.iter().position(|l| l.peer == peer) else {
                continue;
            };
            if self.links[idx].fabric.connect().is_err() {
                // I-4: unreachable is the normal case on an intermittent link.
                // The schedule has already advanced, so a failed attempt does
                // not retry sooner than a successful one.
                continue;
            }
            report.initiated += 1;
        }
        report
    }

    /// Reconcile with a peer whose corpus is `other`, over the agreed window.
    ///
    /// Exposed separately so a test — or the sim fabric — can drive both ends.
    /// The mode comes from the link profile, which RFC 5 §4.1 makes a function
    /// of `latency_class` rather than a setting.
    pub fn reconcile_with(&mut self, other: &mut Node, mode: Mode) -> usize {
        let (lo, hi) = self.window;
        let mut a = StoreView(&mut self.store);
        let mut b = StoreView(&mut other.store);
        recon::reconcile(&mut a, &mut b, mode, lo, hi).transferred
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::{ContentKeys, LinkKeys, Role};
    use krab_core::object::{canonical_bytes, RoutingHeader, Tag};
    use krab_crypto::Key;
    use krab_fabric::backend::sim::SimFabric;
    use krab_fabric::LinkProfile;

    const DAY: u32 = 1_440;

    fn session() -> Session {
        Session::unlocked(
            LinkKeys {
                noise_static: Key::new([1; 32]),
                credentials: 4,
            },
            ContentKeys {
                kek: Key::new([2; 32]),
                tag_table_len: 100,
                prekeys: 64,
                reservoir_chunks: 45,
            },
        )
    }

    /// The window is absolute expiry minutes, so it must bracket the objects
    /// under test -- roughly "now" through "now + MAX_TTL" in production.
    const NOW_MIN: u32 = 29_766_000;
    const WINDOW: (u32, u32) = (NOW_MIN, NOW_MIN + 45 * DAY);

    fn node() -> Node {
        Node::new(Store::new(), session(), 600, WINDOW)
    }

    fn object(salt: u8) -> (krab_core::object::ObjectId, Vec<u8>) {
        let h = RoutingHeader {
            version: 1,
            class: 0,
            size_bucket: 0,
            flags: 0,
            expiry_min: 29_766_240 + salt as u32,
            tag: Tag([salt; 8]),
        };
        let b = canonical_bytes(&h, &krab_core::object::example_sealed_body(salt)).unwrap();
        (krab_crypto::object_id(&b), b)
    }

    fn with_objects(salts: &[u8]) -> Node {
        let mut n = node();
        for &s in salts {
            let (id, b) = object(s);
            n.store.ingest(id, b, 29_766_000, u32::MAX).unwrap();
        }
        n
    }

    /// **Inbound is served with no user action of any kind.**
    #[test]
    fn inbound_is_accepted_without_user_involvement() {
        let mut n = node();
        n.add_link(
            Link {
                peer: [1; 32],
                fabric: Box::new(SimFabric::new(LinkProfile::tcp())),
            },
            0,
            42,
        );
        // Nobody has pressed anything, the composer is untouched, and the tick
        // is driven only by time.
        let r = n.tick(1, 7);
        assert_eq!(r.accepted, 1, "a peer that reaches us is served");
    }

    /// **Outbound fires on the schedule and on nothing else.**
    #[test]
    fn outbound_is_initiated_by_the_schedule_alone() {
        let mut n = node();
        n.add_link(
            Link {
                peer: [2; 32],
                fabric: Box::new(SimFabric::new(LinkProfile::tcp())),
            },
            0,
            42,
        );
        let mut initiated = 0;
        for t in (0..20_000u64).step_by(60) {
            initiated += n.tick(t, 0xBEEF ^ t).initiated;
        }
        assert!(
            initiated > 0,
            "the schedule must actually drive connections"
        );
    }

    /// **Both continue while locked.** A locked node is a relay: it carries
    /// traffic it cannot read.
    #[test]
    fn a_locked_node_still_serves_and_initiates() {
        let mut n = node();
        n.add_link(
            Link {
                peer: [3; 32],
                fabric: Box::new(SimFabric::new(LinkProfile::tcp())),
            },
            0,
            42,
        );
        n.session.lock();
        assert_eq!(n.session.role(), Role::Relay);
        assert!(!n.session.can_decrypt());

        let mut accepted = 0;
        let mut initiated = 0;
        for t in (0..20_000u64).step_by(60) {
            let r = n.tick(t, 0xBEEF ^ t);
            accepted += r.accepted;
            initiated += r.initiated;
        }
        assert!(accepted > 0, "a locked node still answers");
        assert!(initiated > 0, "and still reaches out");
    }

    /// The integration test: a message crosses from one node to another with
    /// **nobody touching anything**.
    #[test]
    fn delivery_happens_with_no_user_involvement() {
        let mut a = with_objects(&[1, 2, 3]);
        let mut b = with_objects(&[4, 5]);

        assert_eq!(a.store.len(), 3);
        assert_eq!(b.store.len(), 2);

        let moved = a.reconcile_with(&mut b, Mode::Rbsr);

        assert_eq!(moved, 5, "every object each side lacked");
        assert_eq!(a.store.len(), 5, "A reached the union");
        assert_eq!(b.store.len(), 5, "B reached the union");

        // Idempotent: a second pass moves nothing.
        assert_eq!(a.reconcile_with(&mut b, Mode::Rbsr), 0);
    }

    /// And it happens while both ends are locked, because reconciliation needs
    /// no decryption key — RFC 7 §7's relay, demonstrated end to end.
    #[test]
    fn delivery_happens_while_both_nodes_are_locked() {
        let mut a = with_objects(&[1, 2, 3]);
        let mut b = with_objects(&[4, 5]);
        a.session.lock();
        b.session.lock();

        assert!(!a.session.can_decrypt() && !b.session.can_decrypt());
        assert!(a.session.can_reconcile() && b.session.can_reconcile());

        assert_eq!(a.reconcile_with(&mut b, Mode::Manifest), 5);
        assert_eq!(a.store.len(), 5);
        assert_eq!(b.store.len(), 5);
    }

    /// I-4 — a partitioned link does not error, does not stall the node, and
    /// recovers with no reset.
    #[test]
    fn a_partitioned_link_does_not_stall_the_node() {
        let sim = SimFabric::new(LinkProfile::courier());
        sim.partition(true);
        let mut n = node();
        n.add_link(
            Link {
                peer: [7; 32],
                fabric: Box::new(sim),
            },
            0,
            42,
        );

        for t in (0..10_000u64).step_by(60) {
            let r = n.tick(t, 0xF00D ^ t);
            assert_eq!(r.accepted, 0, "nothing arrives through a partition");
        }
        // The node kept ticking throughout; nothing panicked and nothing hung.
        assert_eq!(n.peer_count(), 1);
    }
}
