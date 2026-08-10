//! Simulation backend, RFC 4 §5.6.
//!
//! **Not a test double — a first-class backend.** Gossip convergence bugs are
//! effectively undebuggable in production, so the seam that makes them
//! reproducible is part of the design rather than beside it. SIM-0 is built on
//! it, and SIM-2 should drive the real implementations through it rather than
//! measuring a third model.
//!
//! Deterministic: no clock, no randomness, no threads. Partitions and
//! per-message loss are injected explicitly, so a failing case is a seed and a
//! script rather than a rerun and a hope.

use crate::{Error, Fabric, LinkProfile, Session};
use krab_proto::control::Control;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;

/// A shared in-memory wire between two ends.
#[derive(Debug, Default)]
struct Wire {
    a_to_b: VecDeque<Control>,
    b_to_a: VecDeque<Control>,
    partitioned: bool,
    /// Messages silently dropped, for asserting what a partition cost.
    dropped: usize,
}

/// One end of a simulated link.
pub struct SimSession {
    wire: Arc<Mutex<Wire>>,
    /// `true` for the initiating end.
    is_a: bool,
    closed: bool,
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
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Control>, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        let mut w = self.wire.lock().expect("sim wire poisoned");
        if w.partitioned {
            return Ok(None);
        }
        Ok(if self.is_a {
            w.b_to_a.pop_front()
        } else {
            w.a_to_b.pop_front()
        })
    }

    fn close(&mut self) -> Result<(), Error> {
        self.closed = true;
        Ok(())
    }
}

/// A simulated link.
pub struct SimFabric {
    profile: LinkProfile,
    wire: Arc<Mutex<Wire>>,
}

impl SimFabric {
    /// A link with the given profile.
    pub fn new(profile: LinkProfile) -> SimFabric {
        SimFabric {
            profile,
            wire: Arc::new(Mutex::new(Wire::default())),
        }
    }

    /// The other end of the same wire.
    pub fn counterpart(&self, profile: LinkProfile) -> SimFabric {
        SimFabric {
            profile,
            wire: Arc::clone(&self.wire),
        }
    }

    /// Partition the link. Sends are dropped and receives return nothing.
    pub fn partition(&self, on: bool) {
        self.wire.lock().expect("sim wire poisoned").partitioned = on;
    }

    /// Messages lost to partitions so far.
    pub fn dropped(&self) -> usize {
        self.wire.lock().expect("sim wire poisoned").dropped
    }

    /// A session as the initiating end.
    pub fn end_a(&self) -> SimSession {
        SimSession {
            wire: Arc::clone(&self.wire),
            is_a: true,
            closed: false,
        }
    }

    /// A session as the responding end.
    pub fn end_b(&self) -> SimSession {
        SimSession {
            wire: Arc::clone(&self.wire),
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
        assert_eq!(b.recv().unwrap(), None);

        b.send(&Control::RangeDone).unwrap();
        assert_eq!(a.recv().unwrap(), Some(Control::RangeDone));
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
