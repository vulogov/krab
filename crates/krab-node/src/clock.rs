//! The median-of-peers clock check — RFC 2 §5.1.
//!
//! ```text
//! Implementations MUST NOT emit objects when the median-of-peers time estimate
//! diverges from the local clock by more than the skew tolerance (±6 h, RFC 1 §2).
//! ```
//!
//! §5.1 explains both why it is asymmetric and where the estimate comes from:
//!
//! > Emitting with a bad clock poisons other nodes' stores with wrong expiry,
//! > and that damage cannot be undone. Receiving with a bad clock only hurts
//! > the node itself.
//!
//! > The corpus is itself a clock: objects carry creation timestamps from many
//! > independent senders, and a running median over recently received objects
//! > from multiple peers is a serviceable sanity check requiring no
//! > infrastructure.
//!
//! # Objects do not carry creation timestamps, and cannot be made to
//!
//! That second paragraph describes a field that does not exist. RFC 1 §4.1's
//! routing header is **frozen forever** and carries `expiry_min`, not a
//! creation time; RFC 0 I-3 says "nothing else may be added". The only
//! emission-time value a receiver can read without a key is the tag `epoch` in
//! the §4.2 envelope, which is **one day** wide.
//!
//! Adding a finer timestamp would not be a small amendment either. A precise
//! emission time in the clear, on every object, is a traffic-analysis gift:
//! RFC 3 §12 forbids *retaining* per-object arrival times as "a forensic
//! reconstruction of the graph and its timing gradients", and putting the
//! sender's own clock on the wire hands the same gradients to every relay for
//! free.
//!
//! So the check here is coarser than ±6 h and says so. It detects divergence
//! of **more than one day**, which is the resolution the observable data
//! supports. `Documentation/RFC-ERRATA.md` E-6 records the gap rather than
//! leaving a `± 6 h` constant in the source that nothing could enforce.
//!
//! # Why the sample is one number per exchange
//!
//! A naive running median over received objects measures the **age of the
//! backlog**, not the network's clock. Reconciliation moves old objects: a
//! node returning after a month receives a month of history, whose median
//! epoch is a fortnight old, and would conclude its own clock is a fortnight
//! fast — exactly backwards, and it would refuse to emit at the moment it had
//! most to say.
//!
//! Taking the **maximum epoch within one exchange** removes that bias: a peer
//! with a correct clock almost always has something recent, and the newest
//! thing it holds is a lower bound on its clock. Taking the **median across
//! exchanges** is the robustness §5.1 asks for, since one peer lying about the
//! time contributes one sample.
//!
//! "Multiple peers" is therefore satisfied by structure rather than by
//! attribution: each sample comes from one exchange, and no record says which
//! peer it was. RFC 3 §12 is untouched — there is no arrival time and no per
//! object provenance here, only a bounded ring of integers in memory.

/// How many exchanges the estimate remembers.
///
/// Bounded because this is a running node's memory, and small because the
/// median of 32 samples is already robust against a minority of liars while
/// staying responsive to a clock that has just been corrected.
pub const SAMPLES: usize = 32;

/// How far the local clock may diverge from the median before emission stops,
/// in epochs.
///
/// **Two, not one.** A one-epoch difference is what a few minutes of skew
/// looks like across a midnight boundary, so treating it as divergence would
/// stop a correctly-set node from emitting for part of every day. Two epochs
/// guarantees more than a full day of real divergence.
///
/// This is weaker than RFC 2 §5.1's ±6 h and is the finest threshold the
/// observable data supports — see the module note and errata E-6.
pub const MAX_SKEW_EPOCHS: u32 = 2;

/// A running estimate of what this node's peers think the time is.
#[derive(Debug, Default, Clone)]
pub struct PeerClock {
    /// One epoch per exchange, oldest overwritten.
    seen: Vec<u32>,
    at: usize,
}

/// What the check says about emitting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// No estimate yet — a node with no peers, or one that has not reconciled.
    ///
    /// **Emission is permitted.** §5.1's requirement is conditional on having
    /// a median-of-peers estimate, and a node that has never spoken to anyone
    /// has none. Refusing here would make a fresh node unable to compose its
    /// first message, which no reading of §5.1 asks for.
    Unknown,
    /// The local clock agrees with the peers, within tolerance.
    Agrees {
        /// Signed difference in epochs, local minus peers.
        off_by: i64,
    },
    /// The local clock diverges. **Emission must stop.**
    Diverges {
        /// Signed difference in epochs, local minus peers. Positive means this
        /// node's clock is ahead — the direction §5.1 calls damaging, because
        /// the expiry it writes is wrong in every other node's store.
        off_by: i64,
    },
}

impl PeerClock {
    /// A fresh estimate that has observed nothing.
    pub fn new() -> PeerClock {
        PeerClock::default()
    }

    /// Record one exchange's highest observed epoch.
    ///
    /// One call per exchange, not per object — see the module note on why the
    /// per-object median measures backlog age instead of the clock.
    pub fn observe_exchange(&mut self, max_epoch: u32) {
        if self.seen.len() < SAMPLES {
            self.seen.push(max_epoch);
        } else {
            self.seen[self.at] = max_epoch;
            self.at = (self.at + 1) % SAMPLES;
        }
    }

    /// How many exchanges have contributed.
    pub fn samples(&self) -> usize {
        self.seen.len()
    }

    /// The median epoch this node's peers appear to be in.
    pub fn median(&self) -> Option<u32> {
        if self.seen.is_empty() {
            return None;
        }
        let mut v = self.seen.clone();
        v.sort_unstable();
        // The lower median for an even count. Which of the two is taken
        // matters only when they differ, and taking the lower biases the
        // estimate *behind* — the conservative direction, since a node that
        // wrongly believes it is ahead stops emitting, and a node that wrongly
        // believes it is on time keeps poisoning stores.
        Some(v[(v.len() - 1) / 2])
    }

    /// Whether this node may emit, given its local epoch.
    pub fn verdict(&self, local_epoch: u32) -> Verdict {
        let Some(median) = self.median() else {
            return Verdict::Unknown;
        };
        let off_by = local_epoch as i64 - median as i64;
        if off_by.unsigned_abs() >= MAX_SKEW_EPOCHS as u64 {
            Verdict::Diverges { off_by }
        } else {
            Verdict::Agrees { off_by }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clock(samples: &[u32]) -> PeerClock {
        let mut c = PeerClock::new();
        for &s in samples {
            c.observe_exchange(s);
        }
        c
    }

    /// **A node with no peers may emit.** §5.1's requirement is conditional on
    /// having an estimate; refusing without one would stop a fresh node from
    /// composing its first message.
    #[test]
    fn no_samples_permits_emission() {
        assert_eq!(PeerClock::new().verdict(20_000), Verdict::Unknown);
        assert_eq!(PeerClock::new().median(), None);
    }

    /// Agreement, and the one-epoch case that must **not** trip: a few minutes
    /// of skew across midnight puts two correct nodes in different epochs.
    #[test]
    fn one_epoch_apart_is_midnight_and_not_divergence() {
        let c = clock(&[20_000; 5]);
        assert!(matches!(c.verdict(20_000), Verdict::Agrees { off_by: 0 }));
        assert!(matches!(c.verdict(20_001), Verdict::Agrees { off_by: 1 }));
        assert!(matches!(c.verdict(19_999), Verdict::Agrees { off_by: -1 }));
    }

    /// **Two epochs is more than a day of real divergence, in both
    /// directions.** Ahead is the damaging one — §5.1's asymmetry — but a
    /// clock a week behind writes tags nobody computes, so both stop emission.
    #[test]
    fn two_epochs_apart_stops_emission() {
        let c = clock(&[20_000; 5]);
        assert!(matches!(c.verdict(20_002), Verdict::Diverges { off_by: 2 }));
        assert!(matches!(
            c.verdict(19_998),
            Verdict::Diverges { off_by: -2 }
        ));
        assert!(matches!(
            c.verdict(20_100),
            Verdict::Diverges { off_by: 100 }
        ));
    }

    /// **One peer lying contributes one sample.** That is the whole reason
    /// §5.1 says median rather than maximum: a single peer claiming to be a
    /// year in the future would otherwise stop this node emitting at all.
    #[test]
    fn a_single_liar_does_not_move_the_median() {
        let mut c = clock(&[20_000; 8]);
        c.observe_exchange(30_000);
        assert_eq!(c.median(), Some(20_000));
        assert!(matches!(c.verdict(20_000), Verdict::Agrees { .. }));
    }

    /// A majority of liars *does* move it, and that is not a defect this layer
    /// can fix: an estimate derived from peers is only as good as the peers.
    /// Recorded so the bound is stated rather than assumed away.
    #[test]
    fn a_majority_moves_it_and_that_is_the_bound() {
        let c = clock(&[20_000, 20_000, 30_000, 30_000, 30_000]);
        assert_eq!(c.median(), Some(30_000));
    }

    /// The ring is bounded, and a corrected clock is believed once enough
    /// exchanges have happened — the estimate must not be permanently
    /// poisoned by history.
    #[test]
    fn the_ring_is_bounded_and_forgets() {
        let mut c = PeerClock::new();
        for _ in 0..SAMPLES * 3 {
            c.observe_exchange(20_000);
        }
        assert_eq!(c.samples(), SAMPLES);
        for _ in 0..SAMPLES {
            c.observe_exchange(20_050);
        }
        assert_eq!(c.median(), Some(20_050), "the estimate never caught up");
    }

    /// The lower median for an even count, which biases the estimate behind —
    /// the conservative direction, since it makes this node more likely to
    /// believe it is ahead and stop.
    #[test]
    fn an_even_count_takes_the_lower_median() {
        assert_eq!(clock(&[10, 20]).median(), Some(10));
        assert_eq!(clock(&[10, 20, 30, 40]).median(), Some(20));
    }
}
