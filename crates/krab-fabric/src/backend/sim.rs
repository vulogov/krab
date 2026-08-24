//! Simulation backend, RFC 4 §5.6.
//!
//! **Not a test double — a first-class backend.** Gossip convergence bugs are
//! effectively undebuggable in production, so the seam that makes them
//! reproducible is part of the design rather than beside it. SIM-0 is built on
//! it, and SIM-2 should drive the real implementations through it rather than
//! measuring a third model.
//!
//! Deterministic: **no clock and no randomness.** Partitions and per-message
//! loss are injected explicitly, so a failing case is a seed and a script
//! rather than a rerun and a hope.
//!
//! # `recv` blocks, and an earlier version did not
//!
//! [`Session::recv`] returns `None` for *"the peer is finished"*. The first
//! version of this backend returned `None` whenever its queue happened to be
//! empty, which is a different statement — *"nothing has arrived yet"* — and
//! the two are indistinguishable to a caller.
//!
//! Both exchange drivers treat `None` as end-of-session and break. So driving
//! a real reconciliation over this backend ended at the first empty poll, and
//! reported a transfer count that was simply the number of objects that
//! happened to fit before the first gap. Not an error — a **plausible smaller
//! number**, which is the worst failure available to a measurement.
//!
//! That is why `MILESTONE-0.1.md` §2.2's third gate went unmet while the
//! backend it names sat here looking finished: SIM-2 could not run through it
//! and get a true answer, so it reconciled stores directly instead.
//!
//! `recv` therefore waits until a message arrives, the far end closes, or the
//! wire stalls. Waiting is on a condition variable rather than a sleep, so
//! there is still no clock: two ends both blocked with both queues empty is
//! detected as a stall and both are woken with `None`, because on a wire with
//! exactly two ends and no timers, nothing can ever arrive from anywhere else.

use crate::{Error, Fabric, LinkProfile, Session};
use krab_proto::control::Control;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;

/// A shared in-memory wire between two ends.
#[derive(Debug, Default)]
struct Wire {
    a_to_b: VecDeque<Control>,
    b_to_a: VecDeque<Control>,
    partitioned: bool,
    /// Messages silently dropped, for asserting what a partition cost.
    dropped: usize,
    /// Whether a session exists for each end and has not closed.
    ///
    /// Both start `false`: a wire with no session on the far end has no peer
    /// to be waiting for, so `recv` answers `None` immediately rather than
    /// blocking on someone who will never arrive.
    a_open: bool,
    b_open: bool,
    /// Ends currently blocked inside `recv`.
    waiting: usize,
    /// Bumped when a stall is declared, so the *other* blocked end learns of
    /// it on waking rather than going back to sleep.
    stall_epoch: u64,
}

impl Wire {
    /// Ends that could still send something.
    fn open(&self) -> usize {
        usize::from(self.a_open) + usize::from(self.b_open)
    }
}

/// One end of a simulated link.
pub struct SimSession {
    wire: Arc<Mutex<Wire>>,
    arrived: Arc<Condvar>,
    /// `true` for the initiating end.
    is_a: bool,
    closed: bool,
}

impl SimSession {
    /// Mark this end shut and wake anyone waiting on it.
    ///
    /// Called by both [`Session::close`] and [`Drop`]. A dropped end that left
    /// the flag set would block the far end until the stall detector caught
    /// it, which reports as a spurious `None` rather than a clean finish.
    fn shut(&mut self) {
        let mut w = self.wire.lock().expect("sim wire poisoned");
        if self.is_a {
            w.a_open = false;
        } else {
            w.b_open = false;
        }
        drop(w);
        self.arrived.notify_all();
    }
}

impl Drop for SimSession {
    fn drop(&mut self) {
        if !self.closed {
            self.shut();
        }
    }
}

impl Session for SimSession {
    fn send(&mut self, msg: &Control) -> Result<(), Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        let mut w = self.wire.lock().expect("sim wire poisoned");
        if w.partitioned {
            // I-4: unreachable is normal, not an escalation. The message is
            // lost exactly as it would be on a real intermittent link.
            w.dropped += 1;
            return Ok(());
        }
        if self.is_a {
            w.a_to_b.push_back(msg.clone());
        } else {
            w.b_to_a.push_back(msg.clone());
        }
        drop(w);
        self.arrived.notify_all();
        Ok(())
    }

    /// Wait for the next message, the far end closing, or a stall.
    ///
    /// See the module header: returning `None` for a momentarily empty queue
    /// is what kept SIM-2 off this backend, because every driver reads `None`
    /// as "the peer is finished" and stops.
    fn recv(&mut self) -> Result<Option<Control>, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        let mut w = self.wire.lock().expect("sim wire poisoned");
        let seen = w.stall_epoch;
        loop {
            // A partition is unreachability, not a message: the peer may have
            // plenty to say and no way to say it. Blocking here would hang a
            // node for the duration of an outage that I-4 calls normal.
            if w.partitioned {
                return Ok(None);
            }
            // The queue first, before any reason to give up. A message already
            // waiting outranks every one of them, including a stall another
            // end declared while this one was asleep.
            let queued = if self.is_a {
                w.b_to_a.pop_front()
            } else {
                w.a_to_b.pop_front()
            };
            if let Some(msg) = queued {
                return Ok(Some(msg));
            }
            // Nothing queued. If no session holds the other end, nothing ever
            // will — that is the contract's `None`.
            let peer_open = if self.is_a { w.b_open } else { w.a_open };
            if !peer_open {
                return Ok(None);
            }
            // Someone declared a stall while this end slept, and the check
            // above found nothing to contradict it.
            if w.stall_epoch != seen {
                return Ok(None);
            }
            // Both ends live and **both queues** empty, with every open end
            // waiting: no one is left to send and nothing is in flight, so on
            // a two-ended wire with no timers nothing can arrive from
            // anywhere. Say so rather than hanging, and bump the epoch so the
            // end already asleep learns of it instead of waiting again.
            //
            // Testing only this end's inbound queue is not enough, and the
            // difference is not theoretical: an RBSR responder that had just
            // pushed a batch of ranges saw its *own* queue empty, called it a
            // stall, and woke the initiator out from under the message it was
            // about to read. The descent ended one round in, having moved
            // nothing, and reported success.
            let idle = w.a_to_b.is_empty() && w.b_to_a.is_empty();
            if idle && w.waiting + 1 >= w.open() {
                w.stall_epoch = w.stall_epoch.wrapping_add(1);
                drop(w);
                self.arrived.notify_all();
                return Ok(None);
            }
            w.waiting += 1;
            w = self.arrived.wait(w).expect("sim wire poisoned");
            w.waiting -= 1;
        }
    }

    fn close(&mut self) -> Result<(), Error> {
        self.shut();
        self.closed = true;
        Ok(())
    }
}

/// A simulated link.
pub struct SimFabric {
    profile: LinkProfile,
    wire: Arc<Mutex<Wire>>,
    arrived: Arc<Condvar>,
}

impl SimFabric {
    /// A link with the given profile.
    pub fn new(profile: LinkProfile) -> SimFabric {
        SimFabric {
            profile,
            wire: Arc::new(Mutex::new(Wire::default())),
            arrived: Arc::new(Condvar::new()),
        }
    }

    /// The other end of the same wire.
    pub fn counterpart(&self, profile: LinkProfile) -> SimFabric {
        SimFabric {
            profile,
            wire: Arc::clone(&self.wire),
            arrived: Arc::clone(&self.arrived),
        }
    }

    /// Partition the link. Sends are dropped and receives return nothing.
    pub fn partition(&self, on: bool) {
        self.wire.lock().expect("sim wire poisoned").partitioned = on;
        // Wake anyone blocked: a partition turns a wait into an immediate
        // `None`, and an end asleep from before the outage would otherwise
        // stay asleep through it.
        self.arrived.notify_all();
    }

    /// Messages lost to partitions so far.
    pub fn dropped(&self) -> usize {
        self.wire.lock().expect("sim wire poisoned").dropped
    }

    /// A session as the initiating end.
    ///
    /// Marks the end open, so a second exchange over the same wire works after
    /// the first one closed its sessions.
    pub fn end_a(&self) -> SimSession {
        self.wire.lock().expect("sim wire poisoned").a_open = true;
        SimSession {
            wire: Arc::clone(&self.wire),
            arrived: Arc::clone(&self.arrived),
            is_a: true,
            closed: false,
        }
    }

    /// A session as the responding end.
    pub fn end_b(&self) -> SimSession {
        self.wire.lock().expect("sim wire poisoned").b_open = true;
        SimSession {
            wire: Arc::clone(&self.wire),
            arrived: Arc::clone(&self.arrived),
            is_a: false,
            closed: false,
        }
    }
}

impl Fabric for SimFabric {
    fn profile(&self) -> &LinkProfile {
        &self.profile
    }
    fn connect(&self) -> Result<Box<dyn Session>, Error> {
        if self.wire.lock().expect("sim wire poisoned").partitioned {
            return Err(Error::Unreachable);
        }
        Ok(Box::new(self.end_a()))
    }
    fn accept(&self) -> Result<Option<Box<dyn Session>>, Error> {
        if self.wire.lock().expect("sim wire poisoned").partitioned {
            return Ok(None);
        }
        Ok(Some(Box::new(self.end_b())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_cross_in_both_directions_in_order() {
        let f = SimFabric::new(LinkProfile::tcp());
        let (mut a, mut b) = (f.end_a(), f.end_b());

        a.send(&Control::Done).unwrap();
        a.send(&Control::Bye { reason: 1 }).unwrap();
        assert_eq!(b.recv().unwrap(), Some(Control::Done));
        assert_eq!(b.recv().unwrap(), Some(Control::Bye { reason: 1 }));

        b.send(&Control::RangeDone).unwrap();
        assert_eq!(a.recv().unwrap(), Some(Control::RangeDone));
    }

    /// **`None` means the peer is finished, and nothing else.**
    ///
    /// An earlier version of this test asserted that a drained queue answers
    /// `None` while the far end was still open. That is the defect described
    /// in the module header, written down as an expectation: both exchange
    /// drivers read `None` as end-of-session, so a momentary gap ended the
    /// reconciliation and reported a plausible smaller number.
    #[test]
    fn an_empty_queue_is_not_a_finished_peer() {
        let f = SimFabric::new(LinkProfile::tcp());
        let (mut a, mut b) = (f.end_a(), f.end_b());

        a.send(&Control::Done).unwrap();
        assert_eq!(b.recv().unwrap(), Some(Control::Done));

        // Drained, and `a` is still live. Only closing it finishes the peer.
        a.close().unwrap();
        assert_eq!(b.recv().unwrap(), None, "a closed end is a finished peer");
    }

    /// A wire with no session on the far end has no one to wait for.
    #[test]
    fn a_wire_with_one_end_does_not_block() {
        let f = SimFabric::new(LinkProfile::tcp());
        let mut only = f.end_a();
        assert_eq!(only.recv().unwrap(), None);
    }

    /// **A dropped end releases the other.** Not every caller closes; the
    /// exchange drivers return early on error and let the session fall out of
    /// scope, and the far end must see a finished peer rather than a stall.
    #[test]
    fn dropping_an_end_finishes_the_peer() {
        let f = SimFabric::new(LinkProfile::tcp());
        let (a, mut b) = (f.end_a(), f.end_b());
        drop(a);
        assert_eq!(b.recv().unwrap(), None);
    }

    /// **Both ends waiting is a stall, not a hang.** Two ends, two empty
    /// queues, no clock and no third party: nothing can arrive, and saying so
    /// is better than deadlocking a test suite with no diagnostic.
    #[test]
    fn two_ends_both_waiting_are_woken_rather_than_deadlocked() {
        let f = SimFabric::new(LinkProfile::tcp());
        let (mut a, mut b) = (f.end_a(), f.end_b());
        let h = std::thread::spawn(move || b.recv().unwrap());
        assert_eq!(a.recv().unwrap(), None, "the detecting end");
        assert_eq!(h.join().unwrap(), None, "and the end already asleep");
    }

    /// A session survives the wire being reused: a second exchange opens fresh
    /// ends over the same `SimFabric`, which is how a multi-round
    /// reconciliation runs.
    #[test]
    fn the_wire_is_reusable_after_both_ends_close() {
        let f = SimFabric::new(LinkProfile::tcp());
        {
            let (mut a, mut b) = (f.end_a(), f.end_b());
            a.send(&Control::Done).unwrap();
            assert_eq!(b.recv().unwrap(), Some(Control::Done));
        }
        let (mut a, mut b) = (f.end_a(), f.end_b());
        a.send(&Control::RangeDone).unwrap();
        assert_eq!(b.recv().unwrap(), Some(Control::RangeDone));
    }

    /// I-4 — an unreachable peer is the normal case on an intermittent link,
    /// not a condition to escalate.
    #[test]
    fn a_partition_loses_messages_without_erroring() {
        let f = SimFabric::new(LinkProfile::courier());
        let (mut a, mut b) = (f.end_a(), f.end_b());

        f.partition(true);
        a.send(&Control::Done).unwrap();
        assert_eq!(b.recv().unwrap(), None, "nothing arrives");
        assert_eq!(f.dropped(), 1);
        assert!(matches!(f.connect(), Err(Error::Unreachable)));

        f.partition(false);
        a.send(&Control::Done).unwrap();
        assert_eq!(
            b.recv().unwrap(),
            Some(Control::Done),
            "recovers with no reset"
        );
    }

    #[test]
    fn a_closed_session_refuses_further_traffic() {
        let f = SimFabric::new(LinkProfile::tcp());
        let mut a = f.end_a();
        a.close().unwrap();
        assert!(matches!(a.send(&Control::Done), Err(Error::Closed)));
        assert!(matches!(a.recv(), Err(Error::Closed)));
    }
}
