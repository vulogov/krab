//! Poisson reconciliation scheduling, RFC 0 I-5 and RFC 5 §6.1.
//!
//! ```text
//! Reconciliation MUST run on a Poisson schedule with randomised interval and
//! randomised peer order, independent of user activity, mail arrival, queue
//! depth, and application focus.
//! ```
//!
//! # Why this is enforced by the API rather than by a rule
//!
//! A node that syncs more eagerly when it has mail correlates itself with a tag
//! stream **without any decryption occurring**, and an observer needs only
//! arrival timing to exploit it (RFC 0 §5.3's intersection attack).
//!
//! RFC 5 §6.1 calls this the invariant most likely to be destroyed by a later
//! optimisation, because event-driven sync looks strictly better on every
//! metric a performance test measures. RFC 8 §5.1 identifies the actual
//! mechanism: *"Event-driven sync is not reintroduced by someone deciding to
//! weaken privacy; it is reintroduced by someone fixing what looks like a
//! bug."*
//!
//! So [`Scheduler::due`] takes **`now` and entropy, and nothing else**. There
//! is no parameter through which mail arrival, queue depth, focus, or lock
//! state could be expressed, which is why the scheduler cannot acquire one by
//! accident. Adding such a parameter is a visible API change, not a quiet
//! edit — the same discipline `krab_store::Store::evict_to` uses for I-6.

use std::collections::BTreeMap;

/// Identifies a peer within the scheduler.
pub type PeerId = [u8; 32];

/// A Poisson schedule over a peer set.
#[derive(Debug, Clone)]
pub struct Scheduler {
    mean_interval_s: u64,
    next: BTreeMap<PeerId, u64>,
}

impl Scheduler {
    /// A scheduler with the given mean interval between attempts per link.
    ///
    /// RFC 5 §5 recommends lengthening this on links whose `latency_class` is
    /// not `Interactive`, since manifest cost is per-exchange.
    pub fn new(mean_interval_s: u64) -> Scheduler {
        Scheduler { mean_interval_s: mean_interval_s.max(1), next: BTreeMap::new() }
    }

    /// Mean interval, seconds.
    pub fn mean_interval_s(&self) -> u64 {
        self.mean_interval_s
    }

    /// Enrol a peer, drawing its first attempt.
    pub fn add(&mut self, peer: PeerId, now: u64, entropy: u64) {
        self.next.insert(peer, Self::draw(now, self.mean_interval_s, entropy));
    }

    /// Remove a peer.
    pub fn remove(&mut self, peer: &PeerId) {
        self.next.remove(peer);
    }

    /// Peers enrolled.
    pub fn len(&self) -> usize {
        self.next.len()
    }

    /// Whether no peer is enrolled.
    pub fn is_empty(&self) -> bool {
        self.next.is_empty()
    }

    /// When a peer is next due.
    pub fn next_due(&self, peer: &PeerId) -> Option<u64> {
        self.next.get(peer).copied()
    }

    /// Peers due at or before `now`, in **randomised order**.
    ///
    /// Order matters as much as interval: RFC 5 §6.2 requires that no single
    /// peer be predictably a node's only source for any region of the corpus,
    /// because that is the eclipse condition and it is invisible without the
    /// unique-source-contribution metric.
    ///
    /// Each returned peer is rescheduled immediately, so a caller that drops
    /// the result still advances the schedule — a reconciliation that failed
    /// must not retry sooner than one that succeeded, or failure becomes an
    /// observable timing signal.
    pub fn due(&mut self, now: u64, entropy: u64) -> Vec<PeerId> {
        let mut ready: Vec<PeerId> =
            self.next.iter().filter(|(_, &t)| t <= now).map(|(p, _)| *p).collect();

        // Fisher-Yates from the supplied entropy: deterministic per seed, so
        // the simulator and the fuzzer replay exactly.
        let mut e = mix(entropy) | 1;
        for i in (1..ready.len()).rev() {
            e = e.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            ready.swap(i, (e >> 33) as usize % (i + 1));
        }

        for (i, p) in ready.iter().enumerate() {
            let seed = entropy.rotate_left(((i % 63) + 1) as u32) ^ (i as u64);
            self.next.insert(*p, Self::draw(now, self.mean_interval_s, seed));
        }
        ready
    }

    /// Exponential inverse-CDF draw. Memoryless, which is what makes the
    /// schedule unpredictable from any single observation.
    ///
    /// The entropy is **mixed before use**. Taking the caller's value directly
    /// makes the draw pathological on poorly-distributed input: a small
    /// counter has almost all its high bits clear, so `u` lands near zero and
    /// `-ln(u)` produces an interval tens of times the mean. A caller passing
    /// a loop index or a peer number is a realistic mistake, and it would
    /// present as "sync mysteriously never happens" rather than as an error.
    fn draw(now: u64, mean_s: u64, entropy: u64) -> u64 {
        let u = ((mix(entropy) >> 11) as f64) / ((1u64 << 53) as f64);
        let u = if u <= 0.0 { f64::MIN_POSITIVE } else { u };
        now.saturating_add((-(u.ln()) * mean_s as f64) as u64)
    }
}

/// SplitMix64 finaliser. Spreads a poorly-distributed input across all 64
/// bits, so [`Scheduler::draw`] behaves the same for a counter as for a
/// cryptographic draw.
fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut x = z;
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(n: u8) -> PeerId {
        [n; 32]
    }

    #[test]
    fn peers_become_due_and_are_rescheduled() {
        let mut s = Scheduler::new(3_600);
        s.add(peer(1), 0, 12345);
        let at = s.next_due(&peer(1)).unwrap();

        assert!(s.due(at.saturating_sub(1), 7).is_empty(), "not due yet");
        assert_eq!(s.due(at, 7), vec![peer(1)]);
        assert!(s.next_due(&peer(1)).unwrap() > at, "rescheduled forward");
    }

    /// RFC 5 §6.2 — randomised peer order, or a peer becomes predictably your
    /// only source for a region of the corpus.
    #[test]
    fn order_is_randomised_across_entropy() {
        let mut orders = std::collections::BTreeSet::new();
        for e in 0..64u64 {
            let mut s = Scheduler::new(60);
            for n in 1..=6 {
                s.add(peer(n), 0, 1);
            }
            orders.insert(s.due(u64::MAX / 2, e.wrapping_mul(0x9E37_79B9_7F4A_7C15)));
        }
        assert!(orders.len() > 1, "peer order must not be fixed");
    }

    /// The distribution is exponential, so intervals vary widely and the mean
    /// is preserved. A fixed interval would be trivially predictable.
    #[test]
    fn intervals_are_exponentially_distributed_around_the_mean() {
        let mean = 3_600u64;
        let mut samples = Vec::new();
        for e in 1..2_000u64 {
            let mut s = Scheduler::new(mean);
            s.add(peer(1), 0, e);
            samples.push(s.next_due(&peer(1)).unwrap());
        }
        let avg = samples.iter().sum::<u64>() as f64 / samples.len() as f64;
        assert!((mean as f64 * 0.8..mean as f64 * 1.2).contains(&avg), "mean {avg} off");
        let spread = samples.iter().copied().max().unwrap() - samples.iter().copied().min().unwrap();
        assert!(spread > mean * 3, "exponential, not near-constant: spread {spread}");
    }

    /// **The I-5 absence test.**
    ///
    /// RFC 5 §6.1 asks for a test asserting that inter-sync intervals are
    /// uncorrelated with message events. The strongest form of that assertion
    /// is structural: the scheduler is driven only by `now` and entropy, so an
    /// identical sequence of calls produces an identical schedule no matter
    /// what the node is doing. There is no third input to vary.
    #[test]
    fn schedule_is_independent_of_everything_but_time_and_entropy() {
        let run = || {
            let mut s = Scheduler::new(600);
            for n in 1..=4 {
                s.add(peer(n), 0, 0xDEAD_BEEF ^ n as u64);
            }
            let mut fired = Vec::new();
            for t in (0..20_000).step_by(60) {
                fired.extend(s.due(t, 0xCAFE ^ t));
            }
            fired
        };
        // Two runs identical in time and entropy, differing in every way the
        // node could otherwise vary -- mail arriving, queue depth, focus, lock
        // state -- because none of those is reachable from here.
        assert_eq!(run(), run(), "schedule must depend on nothing else");
        assert!(!run().is_empty(), "and it must actually fire");
    }

    /// A small counter must schedule like a cryptographic draw, or "sync
    /// mysteriously never happens" is a caller mistake the API invites.
    #[test]
    fn poor_entropy_still_schedules_near_the_mean() {
        let mean = 600u64;
        let mut samples = Vec::new();
        for e in 0..500u64 {
            let mut s = Scheduler::new(mean);
            s.add(peer(1), 0, e); // a bare counter, the realistic mistake
            samples.push(s.next_due(&peer(1)).unwrap());
        }
        let avg = samples.iter().sum::<u64>() as f64 / samples.len() as f64;
        assert!((mean as f64 * 0.7..mean as f64 * 1.4).contains(&avg), "mean {avg} off");
    }

    /// A failed reconciliation must not retry sooner than a successful one, or
    /// failure becomes an observable timing signal.
    #[test]
    fn a_dropped_result_still_advances_the_schedule() {
        let mut s = Scheduler::new(600);
        s.add(peer(1), 0, 99);
        let at = s.next_due(&peer(1)).unwrap();
        let _ = s.due(at, 5); // caller ignores it, e.g. the link was down
        assert!(s.next_due(&peer(1)).unwrap() > at);
    }
}
