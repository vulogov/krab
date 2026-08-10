//! Background activity in the command pane — with provenance, and with limits.
//!
//! Send and receive run on their own threads and the operator should be able to
//! see what they did. The question is how much, and RFC 3 §12 answers it:
//!
//! > "Per-peer, windowed, aggregates only — RFC 3 §12 forbids per-object
//! > provenance, because **arrival timestamps and per-object attribution
//! > reconstruct the graph and its timing gradients on disk** for a seizing
//! > adversary."
//!
//! # What that rules in and out
//!
//! The operative words are *on disk*. §12 is about a durable artifact, and a
//! transient display is a different thing — the same distinction RFC 7 §8 makes
//! for plaintext, which exists "only while displayed".
//!
//! So provenance is allowed, under four constraints, each following from a
//! clause of §12 rather than from taste:
//!
//! | constraint | why |
//! |---|---|
//! | **never written** | §12's concern is the on-disk artifact |
//! | **bounded ring** | unbounded scrollback *is* a log, whatever it is called |
//! | **no wall-clock times** | §12 names timestamps first; they are the timing gradient |
//! | **cleared on lock** | a locked screen must not show who this node talks to |
//!
//! Ordering is preserved and timing is not. "12 objects from q3m9, then 3 from
//! m4k2" tells an operator their links are working. "12 objects from q3m9 at
//! 14:32:07" is a timing gradient, and it is the same sentence with one field
//! added.
//!
//! # A relay keeps counting, and stops showing
//!
//! Reconciliation continues while locked — that is the whole point of the
//! relay role. So the counters keep moving: `PeerMetrics` is the durable,
//! aggregate, §12-compliant record and is unaffected here.
//!
//! What clears is this ring. A locked node is one an operator has walked away
//! from, and a screen listing correspondents is exactly what someone who picks
//! up the laptop should not find.

use std::collections::VecDeque;

/// How many lines the ring holds.
///
/// Deliberately small. Large enough that an operator watching a reconciliation
/// sees it happen; small enough that it cannot accumulate into a session
/// history of who this node talked to.
pub const CAPACITY: usize = 64;

/// What a background thread did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A transport came up.
    LinkUp {
        /// Short peer identifier.
        peer: String,
        /// Transport kind, as displayed.
        kind: &'static str,
    },
    /// A peering mixed fresh entropy — `krab_crypto::rekey`.
    ///
    /// Worth a line: it is the event that makes a past compromise stop
    /// mattering, and an operator watching for one wants to see it happen.
    Rekeyed {
        /// Short peer identifier.
        peer: String,
        /// The ratchet index adopted.
        index: u32,
    },
    /// A transport went down or failed.
    LinkDown {
        /// Short peer identifier.
        peer: String,
    },
    /// A scheduled reconciliation completed.
    ///
    /// Counts only. Which objects moved is exactly the per-object attribution
    /// §12 forbids, and the aggregate is what `peers` reports anyway.
    Reconciled {
        /// Short peer identifier.
        peer: String,
        /// Objects accepted.
        received: usize,
        /// Objects sent.
        sent: usize,
    },
    /// An exchange failed.
    Failed {
        /// Short peer identifier.
        peer: String,
        /// What went wrong, as a fixed string — never a formatted error that
        /// might carry an address or an identifier.
        why: &'static str,
    },
}

impl Event {
    /// The peer this concerns.
    ///
    /// Exposed so a caller can group or filter by peer without parsing the
    /// rendered line — parsing display output back into structure is how a
    /// transient view becomes a durable record by accident.
    #[allow(dead_code)]
    pub fn peer(&self) -> &str {
        match self {
            Event::LinkUp { peer, .. }
            | Event::Rekeyed { peer, .. }
            | Event::LinkDown { peer }
            | Event::Reconciled { peer, .. }
            | Event::Failed { peer, .. } => peer,
        }
    }

    /// One line, for the command pane.
    ///
    /// **No timestamp**, by construction — there is no field to put one in and
    /// no clock is consulted. §12 names arrival timestamps first among the
    /// things that reconstruct a timing gradient.
    pub fn line(&self) -> String {
        match self {
            Event::LinkUp { peer, kind } => format!("{peer}  link up ({kind})"),
            Event::Rekeyed { peer, index } => format!("{peer}  re-keyed at {index}"),
            Event::LinkDown { peer } => format!("{peer}  link down"),
            Event::Reconciled {
                peer,
                received,
                sent,
            } => {
                format!("{peer}  reconciled  +{received} received  −{sent} sent")
            }
            Event::Failed { peer, why } => format!("{peer}  {why}"),
        }
    }
}

/// A bounded, transient record of background activity.
///
/// Holds no clock, no file handle, and no way to acquire either.
#[derive(Default)]
pub struct ActivityLog {
    lines: VecDeque<Event>,
}

impl ActivityLog {
    /// An empty log.
    pub fn new() -> ActivityLog {
        ActivityLog {
            lines: VecDeque::new(),
        }
    }

    /// Record an event, evicting the oldest if full.
    pub fn push(&mut self, e: Event) {
        if self.lines.len() == CAPACITY {
            self.lines.pop_front();
        }
        self.lines.push_back(e);
    }

    /// The most recent `n` lines, newest last.
    pub fn recent(&self, n: usize) -> Vec<String> {
        let skip = self.lines.len().saturating_sub(n);
        self.lines.iter().skip(skip).map(|e| e.line()).collect()
    }

    /// Everything held.
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// Drop everything — called on lock.
    ///
    /// The counters in `PeerMetrics` are unaffected: they are aggregates and
    /// are what §12 permits to persist. This is the transient view.
    pub fn clear(&mut self) {
        self.lines.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log_with(n: usize) -> ActivityLog {
        let mut l = ActivityLog::new();
        for i in 0..n {
            l.push(Event::Reconciled {
                peer: format!("peer{i:02}"),
                received: i,
                sent: 0,
            });
        }
        l
    }

    /// **Bounded.** Unbounded scrollback is a log whatever it is called, and a
    /// session history of who this node talked to is the artifact §12 forbids.
    #[test]
    fn the_ring_is_bounded_and_evicts_the_oldest() {
        let l = log_with(CAPACITY * 3);
        assert_eq!(l.len(), CAPACITY);
        let lines = l.recent(CAPACITY);
        assert!(lines.last().unwrap().starts_with("peer"), "{lines:?}");
        // The earliest peers are gone.
        assert!(!lines.iter().any(|s| s.starts_with("peer00")));
    }

    /// **No timestamps.** §12 names them first among the things that
    /// reconstruct a timing gradient, and `Event` has no field to hold one.
    #[test]
    fn no_line_carries_a_time() {
        let l = log_with(8);
        for line in l.recent(8) {
            for marker in [':', 'T'] {
                // A clock time would need a separator; peer identifiers are
                // hex and counts are digits.
                assert!(
                    !line.contains(marker) || marker == 'T' && !line.contains("T0"),
                    "{line:?} looks like it carries a time"
                );
            }
            assert!(!line.contains("20 2"), "{line:?}");
        }
    }

    /// **Aggregates, not objects.** Counts are permitted; which objects moved
    /// is the per-object attribution §12 forbids.
    #[test]
    fn lines_carry_counts_and_never_identifiers() {
        let e = Event::Reconciled {
            peer: "q3m9".into(),
            received: 12,
            sent: 3,
        };
        let line = e.line();
        assert!(line.contains("q3m9"));
        assert!(line.contains("+12") && line.contains("3"));
        for leak in ["id=", "0x", "obj", "tag"] {
            assert!(!line.contains(leak), "{line:?} leaks {leak:?}");
        }
    }

    /// **Cleared on lock.** A locked node is one someone walked away from, and
    /// a screen listing correspondents is what a person picking up the laptop
    /// should not find.
    #[test]
    fn clearing_removes_every_trace() {
        let mut l = log_with(20);
        assert_ne!(l.len(), 0);
        l.clear();
        assert_eq!(l.len(), 0);
        assert!(l.recent(64).is_empty());
    }

    /// Failure reasons are fixed strings, so a formatted error cannot smuggle
    /// an address or an identifier onto the screen.
    #[test]
    fn failure_reasons_are_fixed_strings() {
        let e = Event::Failed {
            peer: "m4k2".into(),
            why: "handshake refused",
        };
        assert_eq!(e.line(), "m4k2  handshake refused");
        // The type enforces it: `why` is `&'static str`, so a runtime-formatted
        // message cannot be stored here without changing the signature.
    }

    #[test]
    fn recent_returns_newest_last_and_never_more_than_asked() {
        let l = log_with(10);
        let r = l.recent(3);
        assert_eq!(r.len(), 3);
        assert!(r[2].starts_with("peer09"), "{r:?}");
    }

    #[test]
    fn an_empty_log_is_not_an_error() {
        let l = ActivityLog::new();
        assert_eq!(l.len(), 0);
        assert!(l.recent(10).is_empty());
    }
}
