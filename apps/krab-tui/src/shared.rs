//! The corpus, reachable from a background exchange — and the trap in doing it.
//!
//! RFC 8's node is also the client. The author's requirement was explicit:
//!
//! > "As TUI is client and 'server in background', send/receive shall be in
//! > background regardless frontend user activity."
//!
//! Reconciliation previously ran inside the render loop, between `event::poll`
//! calls. A slow exchange therefore froze the interface — and on a serial link
//! at 11 520 B/s (RFC 4 §5.3) a few megabytes is minutes. **The lock chord was
//! unavailable for the whole of it**, which is the one keystroke an operator
//! might need urgently, and a peer trickling bytes could hold the interface
//! hostage deliberately.
//!
//! # The trap: locking once around the exchange
//!
//! Moving the exchange to a thread is only half the fix. The obvious next step
//! is to hand that thread a `MutexGuard` for the duration — which reintroduces
//! the freeze through the lock instead of through the loop. The interface then
//! blocks on `lock()` rather than on `recv()`, for exactly as long, and the
//! symptom is identical.
//!
//! [`SharedStore`] therefore locks **per `Corpus` operation** and never across
//! one. The exchange holds no lock while waiting on a socket, so the interface
//! reads between operations and stays responsive through an exchange of any
//! length.
//!
//! # What this admits, stated plainly
//!
//! Fine-grained locking means the corpus can change *during* an exchange —
//! `send` may add an object between two calls the exchange makes. That is
//! benign here and it is worth saying why rather than leaving it to be
//! rediscovered:
//!
//! - **Reconciliation is resumable by design** (RFC 5). Missing an object this
//!   round costs one scheduled interval, not correctness.
//! - **Objects are immutable and content-addressed**, so nothing an exchange
//!   read can be altered under it — only added to or expired.
//! - **`ingest` is the only mutation that admits data**, and it applies RFC 1
//!   §11's `I1`–`I6` whichever thread calls it.
//!
//! **Two calls are not a consistent pair.** `count(lo, hi)` and
//! `entries(lo, hi)` may disagree by whatever landed between them, and so may
//! `fingerprint` and `count`. Each call is internally consistent; no two are
//! jointly so. A reader wanting both must take the lock once itself via
//! [`SharedStore::with`].
//!
//! That is safe for reconciliation and would not be for everything. RBSR uses
//! `fingerprint` and `count` to decide where to descend, so an interleaved
//! write can send it down a range that has since changed — costing a wasted
//! descent, not a wrong answer, because the next round sees the new state and
//! convergence is a fixed point rather than a single pass.
//!
//! A protocol needing a consistent snapshot across a whole exchange would need
//! a different structure. RFC 5's does not, and that is what makes this safe.

use krab_core::object::RoutingHeader;
use krab_crypto::Fingerprint;
use krab_proto::control::{Entry, TRUNC};
use krab_proto::recon::Corpus;
use krab_store::index::Store;
use std::sync::{Arc, Mutex};

/// A corpus several threads may reach.
#[derive(Clone)]
pub struct SharedStore(Arc<Mutex<Store>>);

impl SharedStore {
    /// Wrap a store.
    pub fn new(store: Store) -> SharedStore {
        SharedStore(Arc::new(Mutex::new(store)))
    }

    /// Run `f` with the store locked.
    ///
    /// **Do not hold the result across I/O.** The whole point of this type is
    /// that the lock is taken and released around each operation; a caller that
    /// keeps it while waiting on a socket has rebuilt the freeze.
    pub fn with<R>(&self, f: impl FnOnce(&mut Store) -> R) -> R {
        // A poisoned lock means a thread panicked mid-operation. The store is
        // append-only and content-addressed, so what is there is still
        // self-consistent — recovering is correct, and refusing would turn one
        // thread's panic into permanent unavailability.
        let mut guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut guard)
    }

    /// Objects held.
    pub fn len(&self) -> usize {
        self.with(|s| s.len())
    }

    /// Whether the corpus is empty.
    ///
    /// Kept alongside `len` because clippy asks for it and because a caller
    /// that wants it should not reach for `len() == 0` under the lock.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.with(|s| s.is_empty())
    }
}

/// The minute a store treats as "now" for ingest.
///
/// Passed rather than read: `krab-store` takes time as an argument and this
/// type must not become the place a clock sneaks in.
pub struct ExchangeView {
    store: SharedStore,
    now_min: u32,
    /// What this node is willing to host — RFC 6 §3.6.
    ///
    /// **Enforced here, not merely recorded.** `channel carry` was a setting
    /// the interface reported, persisted and warned about twice, and which
    /// filtered nothing: a node with carriage off stored every channel post it
    /// was offered. RFC 8 §4.3 makes enabling a statement about what the node
    /// *is*, with consequences that depend on the operator's jurisdiction, so
    /// a setting that does not bind is worse than an absent one — it is a
    /// false claim about legal exposure.
    carriage: krab_crypto::CarriagePolicy,
    /// This link's budget for the day — RFC 3 §6.
    ///
    /// Shared with the interface thread, which persists it once the exchange
    /// reports. A budget the process forgets on restart is not a budget.
    budget: Option<Budget>,
    /// The agreed scope of this exchange — RFC 3 §7.3.
    ///
    /// **Enforced here, for the reason above.** The filter digest makes the
    /// two sides *agree* on the scope; nothing about a matching digest stops a
    /// peer offering rows outside it afterwards. RFC 3 §6.1's model is that a
    /// peer is held to what it signed rather than trusted to honour it, so the
    /// agreement and the enforcement are separate and both are here.
    filter: crate::filter::Filter,
}

/// A link's budget, shared between the exchange thread and the interface.
#[derive(Clone)]
pub struct Budget {
    /// What has crossed today.
    pub spend: std::sync::Arc<Mutex<crate::quota::Spend>>,
    /// Bytes per day this node accepts from the peer — RFC 3 §6.
    pub bytes_per_day: u64,
    /// Objects per day.
    pub objects_per_day: u64,
}

impl ExchangeView {
    /// A corpus view for one exchange.
    pub fn new(
        store: SharedStore,
        now_min: u32,
        carriage: krab_crypto::CarriagePolicy,
        filter: crate::filter::Filter,
    ) -> ExchangeView {
        ExchangeView {
            store,
            now_min,
            carriage,
            filter,
            budget: None,
        }
    }

    /// Hold this exchange to RFC 3 §6's budget.
    pub fn with_budget(mut self, budget: Budget) -> ExchangeView {
        self.budget = Some(budget);
        self
    }

    /// A view with no agreed scope, for tests and for a link that has none.
    #[cfg(test)]
    pub fn new_unscoped(
        store: SharedStore,
        now_min: u32,
        carriage: krab_crypto::CarriagePolicy,
    ) -> ExchangeView {
        ExchangeView::new(store, now_min, carriage, crate::filter::Filter::unscoped())
    }

    /// Whether this node will carry `bytes`.
    ///
    /// Sealed objects are always carried: relaying ciphertext for people the
    /// operator chose is what a Krab node *is*, and RFC 1 §10 has a relay
    /// filter on the raw class byte without decoding anything.
    ///
    /// Bulletins are public content, and carrying them is the decision RFC 6
    /// §3.6 makes explicit. A **channel post** is subject to the shard prefix;
    /// a prekey batch or roster is not, because those are how peers reach each
    /// other and refusing them would break peering to punish nobody.
    fn will_carry(&self, bytes: &[u8]) -> bool {
        let Ok(header) = RoutingHeader::parse(bytes) else {
            // Malformed: `ingest` will refuse it anyway, and deciding
            // carriage on something that does not parse is deciding on noise.
            return true;
        };
        if header.class != krab_core::object::Class::Bulletin as u8 {
            return true;
        }
        match crate::channels::from_object(bytes) {
            // A channel post. Accepted by prefix, never by exact identifier:
            // an exact list is a list of your interests handed to your peer
            // (RFC 6 §3.4).
            Some(post) => self.carriage.accepts(&post.channel_id()),
            // A prekey batch or a roster — infrastructure, not content.
            None => true,
        }
    }
}

impl Corpus for ExchangeView {
    fn entries(&self, lo: u32, hi: u32) -> Vec<Entry> {
        self.store.with(|s| {
            s.entries_in_range(lo, hi)
                .into_iter()
                .map(|(expiry_min, id)| Entry {
                    expiry_min,
                    id: id.truncated(),
                })
                .collect()
        })
    }
    fn fingerprint(&self, lo: u32, hi: u32) -> Fingerprint {
        self.store.with(|s| s.range_fingerprint(lo, hi))
    }
    fn count(&self, lo: u32, hi: u32) -> u32 {
        self.store.with(|s| s.count_in_range(lo, hi))
    }
    fn get(&self, id: &[u8; TRUNC]) -> Option<Vec<u8>> {
        self.store.with(|s| s.get_truncated(id).map(|b| b.to_vec()))
    }
    fn has(&self, id: &[u8; TRUNC]) -> bool {
        self.store.with(|s| s.has_truncated(id))
    }
    fn put(&mut self, bytes: Vec<u8>) {
        // RFC 6 §3.6 — before anything else, because the question is whether
        // this node hosts the object at all, not whether it is well-formed.
        if !self.will_carry(&bytes) {
            return;
        }
        // RFC 3 §7.3 — and outside the agreed scope is not a smaller answer
        // but a different one. A peer that signed a filter and then offers
        // rows beyond it is exceeding what it agreed to; accepting them would
        // make the signature decorative.
        if let Ok(header) = RoutingHeader::parse(&bytes) {
            if !self.filter.admits(&header, self.now_min) {
                return;
            }
        }
        // RFC 3 §6 — the byte and object budget on the link, checked before
        // the object lands and charged only if it does. Exceeding it stops
        // acceptance for the rest of the window and nothing else: §6.2 makes
        // disconnection "the limit case, not the mechanism", and RFC 0 I-4
        // makes a quiet link normal.
        if let Some(b) = &self.budget {
            let mut spend = b.spend.lock().unwrap_or_else(|e| e.into_inner());
            if !spend.admits(bytes.len(), b.bytes_per_day, b.objects_per_day) {
                return;
            }
            // Charged before `ingest`, which may refuse the object under RFC 1
            // §11. That is deliberate: the bytes crossed the link either way,
            // and a peer that could spend nothing by sending rejects would
            // have found the way around the budget.
            spend.charge(bytes.len());
        }
        // RFC 1 §11's I1–I6 apply here exactly as they do on the main thread:
        // `ingest` is the only path that admits data and it checks regardless
        // of which thread calls it.
        let id = krab_crypto::object_id(&bytes);
        self.store.with(|s| {
            let _ = s.ingest(id, bytes, self.now_min, u32::MAX);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use krab_core::object::{canonical_bytes, RoutingHeader, Tag};

    const NOW: u32 = 29_766_000;

    /// Carriage that hosts everything, for the tests that are about locking
    /// rather than about what a node is willing to host.
    fn carry_all() -> krab_crypto::CarriagePolicy {
        krab_crypto::CarriagePolicy {
            enabled: true,
            shard_bits: 0,
            shard: 0,
        }
    }

    fn object(salt: u32) -> Vec<u8> {
        let h = RoutingHeader {
            version: 1,
            class: 0,
            size_bucket: 0,
            flags: 0,
            expiry_min: NOW + 40_000 + salt,
            tag: Tag((salt as u64).to_le_bytes()),
        };
        canonical_bytes(&h, &[(salt % 251) as u8; 40]).unwrap()
    }

    /// **The property the fix depends on.** The lock is released between
    /// operations, so another thread reads while an exchange is in progress.
    /// Holding it across the exchange would rebuild the freeze through the
    /// lock instead of through the loop.
    #[test]
    fn the_lock_is_released_between_operations() {
        let shared = SharedStore::new(Store::new());
        let mut view = ExchangeView::new(
            shared.clone(),
            NOW,
            carry_all(),
            crate::filter::Filter::unscoped(),
        );

        let reader = shared.clone();
        let handle = std::thread::spawn(move || {
            // If `put` held the lock for the duration of the exchange this
            // would block until the loop below finished.
            let mut seen = 0;
            for _ in 0..200 {
                seen = seen.max(reader.len());
                std::thread::sleep(std::time::Duration::from_micros(50));
            }
            seen
        });

        for salt in 0..200 {
            view.put(object(salt));
        }
        let seen = handle.join().unwrap();
        assert!(seen > 0, "a reader never observed the corpus mid-exchange");
        assert_eq!(shared.len(), 200);
    }

    /// Concurrent ingest of the same object is idempotent — content addressing
    /// makes duplicate suppression a property rather than a race (RFC 0 I-1).
    #[test]
    fn concurrent_ingest_of_the_same_object_is_idempotent() {
        let shared = SharedStore::new(Store::new());
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let s = shared.clone();
                std::thread::spawn(move || {
                    let mut v =
                        ExchangeView::new(s, NOW, carry_all(), crate::filter::Filter::unscoped());
                    for salt in 0..40 {
                        v.put(object(salt));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(shared.len(), 40, "eight threads produced duplicates");
    }

    /// **RFC 1 §11 holds on every thread.** `ingest` is the only path that
    /// admits data, so garbage from a background exchange is refused exactly
    /// as it would be on the main thread.
    #[test]
    fn the_ingest_checks_apply_from_any_thread() {
        let shared = SharedStore::new(Store::new());
        let handles: Vec<_> = (0..4)
            .map(|i| {
                let s = shared.clone();
                std::thread::spawn(move || {
                    let mut v =
                        ExchangeView::new(s, NOW, carry_all(), crate::filter::Filter::unscoped());
                    v.put(vec![0xFFu8; 256]); // not a valid object
                    v.put(object(i));
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        shared.with(|s| {
            assert_eq!(s.len(), 4, "garbage entered the corpus");
            for id in s.ids_in_order() {
                assert_eq!(krab_crypto::object_id(s.get(id).unwrap()), *id);
            }
        });
    }

    /// A panicking thread must not make the corpus permanently unavailable.
    /// The store is append-only and content-addressed, so what is there is
    /// still self-consistent.
    #[test]
    fn a_poisoned_lock_is_recovered_from() {
        let shared = SharedStore::new(Store::new());
        let mut view = ExchangeView::new(
            shared.clone(),
            NOW,
            carry_all(),
            crate::filter::Filter::unscoped(),
        );
        view.put(object(1));

        let poisoner = shared.clone();
        let _ = std::thread::spawn(move || {
            poisoner.with(|_| panic!("a thread died holding the lock"));
        })
        .join();

        // Still usable, and still consistent.
        assert_eq!(shared.len(), 1);
        let mut v2 = ExchangeView::new(
            shared.clone(),
            NOW,
            carry_all(),
            crate::filter::Filter::unscoped(),
        );
        v2.put(object(2));
        assert_eq!(shared.len(), 2);
    }

    /// **Two calls are not a consistent pair, and that is the design.**
    ///
    /// An earlier version of this test asserted `count` and `entries` agreed
    /// mid-write. They do not and must not be expected to: each call takes the
    /// lock separately, which is the whole point — holding it across both
    /// would rebuild the freeze. A reader wanting a consistent pair takes the
    /// lock once itself.
    #[test]
    fn two_calls_are_not_a_consistent_pair_but_one_lock_is() {
        let shared = SharedStore::new(Store::new());
        let writer = {
            let s = shared.clone();
            std::thread::spawn(move || {
                let mut v =
                    ExchangeView::new(s, NOW, carry_all(), crate::filter::Filter::unscoped());
                for salt in 0..300 {
                    v.put(object(salt));
                }
            })
        };
        let reader = {
            let s = shared.clone();
            std::thread::spawn(move || {
                for _ in 0..300 {
                    // One lock, so the pair is consistent.
                    s.with(|st| {
                        let n = st.count_in_range(0, u32::MAX);
                        let e = st.entries_in_range(0, u32::MAX);
                        assert_eq!(n as usize, e.len(), "one lock must be consistent");
                    });
                }
            })
        };
        writer.join().unwrap();
        reader.join().unwrap();
        assert_eq!(shared.len(), 300);
    }

    /// Readers and writers interleaving must not lose or corrupt objects.
    #[test]
    fn interleaved_readers_and_writers_agree_at_the_end() {
        let shared = SharedStore::new(Store::new());
        let writer = {
            let s = shared.clone();
            std::thread::spawn(move || {
                let mut v =
                    ExchangeView::new(s, NOW, carry_all(), crate::filter::Filter::unscoped());
                for salt in 0..300 {
                    v.put(object(salt));
                }
            })
        };
        let reader = {
            let s = shared.clone();
            std::thread::spawn(move || {
                for _ in 0..300 {
                    let v = ExchangeView::new(
                        s.clone(),
                        NOW,
                        carry_all(),
                        crate::filter::Filter::unscoped(),
                    );
                    // Each call is internally consistent: entries never
                    // contains a duplicate or a torn row, whatever is landing.
                    let e = v.entries(0, u32::MAX);
                    let mut ids: Vec<_> = e.iter().map(|x| x.id).collect();
                    let before = ids.len();
                    ids.sort_unstable();
                    ids.dedup();
                    assert_eq!(ids.len(), before, "a single read was torn");
                }
            })
        };
        writer.join().unwrap();
        reader.join().unwrap();
        assert_eq!(shared.len(), 300);
    }

    /// **RFC 6 §3.6, enforced.** `channel carry` was recorded, persisted and
    /// warned about twice, and filtered nothing — a node with carriage off
    /// stored every channel post it was offered. A setting that does not bind
    /// is worse than an absent one: RFC 8 §4.3 makes this a claim about the
    /// operator's legal exposure.
    #[test]
    fn a_node_with_carriage_off_does_not_host_channel_posts() {
        use krab_crypto::channel::Channel;
        use krab_crypto::rng::NotRandom;

        let c = Channel::create(&mut NotRandom::seeded(1));
        let post = c.post(1, "text/plain", b"public content");
        let (_, bytes) = crate::channels::into_object(&post, 0, 100).expect("wraps");

        let off = SharedStore::new(Store::new());
        let mut view = ExchangeView::new(
            off.clone(),
            0,
            krab_crypto::CarriagePolicy::default(),
            crate::filter::Filter::unscoped(),
        );
        assert!(!view.carriage.enabled, "carriage must default to off");
        view.put(bytes.clone());
        assert!(
            off.is_empty(),
            "a node with carriage off hosted a channel post"
        );

        // And with it on, the same object is carried.
        let on = SharedStore::new(Store::new());
        let mut view = ExchangeView::new_unscoped(
            on.clone(),
            0,
            krab_crypto::CarriagePolicy {
                enabled: true,
                shard_bits: 0,
                shard: 0,
            },
        );
        view.put(bytes);
        assert_eq!(on.len(), 1, "carriage on did not carry");
    }

    /// Sealed mail is carried whatever the carriage decision is. Relaying
    /// ciphertext for people the operator chose is what a Krab node is; the
    /// decision is about hosting *public* content.
    #[test]
    fn carriage_off_still_relays_sealed_mail() {
        let store = SharedStore::new(Store::new());
        let mut view = ExchangeView::new(
            store.clone(),
            0,
            krab_crypto::CarriagePolicy::default(),
            crate::filter::Filter::unscoped(),
        );
        view.put(object(1));
        assert_eq!(store.len(), 1, "a sealed object was refused");
    }

    /// A prekey batch and a roster are infrastructure, not content: refusing
    /// them would break peering to punish nobody.
    #[test]
    fn carriage_off_still_relays_prekeys_and_rosters() {
        use krab_crypto::rng::NotRandom;
        use krab_crypto::sign::SigningKey;

        let k = SigningKey::generate(&mut NotRandom::seeded(4));
        for kind in [
            crate::bulletin::Kind::Prekeys,
            crate::bulletin::Kind::Roster,
        ] {
            let b = crate::bulletin::Bulletin::create(kind, &k, 1, b"payload".to_vec());
            let (_, bytes) = crate::bulletin::into_object(&b, 0, 100).expect("wraps");
            let store = SharedStore::new(Store::new());
            let mut view = ExchangeView::new(
                store.clone(),
                0,
                krab_crypto::CarriagePolicy::default(),
                crate::filter::Filter::unscoped(),
            );
            view.put(bytes);
            assert_eq!(store.len(), 1, "{kind:?} was refused with carriage off");
        }
    }

    /// **Acceptance is by prefix, never by exact identifier.** An exact list
    /// is a list of your interests handed to your peer, and a peer curious
    /// whether you follow channel X can simply add X and watch (RFC 6 §3.4).
    #[test]
    fn carriage_accepts_a_shard_and_not_a_named_channel() {
        use krab_crypto::channel::Channel;
        use krab_crypto::rng::NotRandom;

        // A policy accepting one 1-bit shard carries about half of everything
        // and never exactly one channel.
        let policy = krab_crypto::CarriagePolicy {
            enabled: true,
            shard_bits: 1,
            shard: 0,
        };
        let mut carried = 0;
        let mut refused = 0;
        for seed in 0..32u64 {
            let c = Channel::create(&mut NotRandom::seeded(seed));
            let post = c.post(1, "text/plain", b"x");
            let (_, bytes) = crate::channels::into_object(&post, 0, 100).expect("wraps");
            let store = SharedStore::new(Store::new());
            let mut view = ExchangeView::new_unscoped(store.clone(), 0, policy);
            view.put(bytes);
            if store.is_empty() {
                refused += 1;
            } else {
                carried += 1;
            }
        }
        assert!(
            carried > 0 && refused > 0,
            "a 1-bit shard carried {carried} and refused {refused} — it is not a prefix"
        );
    }
}
