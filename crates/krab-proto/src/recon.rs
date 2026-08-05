//! Reconciliation state machine (RFC 5).
//!
//! Two modes, selected per `LinkProfile`:
//!
//! - **Courier / high-latency: full manifest, one round trip.** Zero
//!   round-trip algorithms only. Bandwidth is free, latency is days.
//! - **Interactive: RBSR** over `(expiry, id)` with additive composable
//!   fingerprints. Optional, probably not v1.
//!
//! Bloom filters are ruled out explicitly: their false positives fail in the
//! message-loss direction. The reasoning is recorded so the idea is not
//! reintroduced as an optimisation.

use crate::control::Control;

/// Reconciliation mode for a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Full manifest, one round trip. Correct where latency dominates.
    FullManifest,
    /// Range-based set reconciliation. Correct where round trips are cheap
    /// and bandwidth is not.
    Rbsr,
}

/// State of one reconciliation session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Awaiting `Hello`.
    Idle,
    /// Filter agreed, awaiting `Manifest`.
    Greeted,
    /// Manifest received, computing the difference.
    Diffing,
    /// Transferring objects.
    Transferring,
    /// Session closed.
    Closed,
}

/// A reconciliation session. Pure: `step` is a total function from state and
/// input to state and output.
#[derive(Debug)]
pub struct Session {
    /// Current state.
    pub state: State,
    /// Negotiated mode.
    pub mode: Mode,
}

impl Session {
    /// Create a session in `Idle`.
    pub fn new(mode: Mode) -> Self {
        Session { state: State::Idle, mode }
    }

    /// Consume one control message, producing zero or more in reply.
    ///
    /// Never panics and never blocks: this is the fuzz target.
    pub fn step(&mut self, _input: &Control) -> Vec<Control> {
        // Awaiting RFC 5.
        Vec::new()
    }
}
