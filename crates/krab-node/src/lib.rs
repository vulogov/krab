//! Scheduler, sync loop, key management, and peering.
//!
//! # I-5, scheduled not event-driven
//!
//! Reconciliation runs on a Poisson schedule regardless of user activity, mail
//! arrival, application focus, or queue depth. Sync timing MUST NOT correlate
//! with user behaviour.
//!
//! RFC 0 §5.3 names this the invariant most likely to be broken by a later
//! battery optimisation, so the scheduler exposes no "sync now on new mail"
//! entry point at all. Adding one is a protocol change, not a tuning change.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod lock;
pub mod metrics;
pub mod peering;
pub mod scheduler;
pub mod sync;
pub mod warnings;

/// Node role (RFC 0 §4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Always-on, reachable, unattended. Holds a link key and ciphertext it
    /// cannot read, and **no message decryption keys**. Seizure yields
    /// nothing not already replicated across the network.
    ///
    /// Deployments SHOULD prefer this for any node that runs without a human
    /// present, because it is the configuration with nothing to protect.
    Relay,
    /// Intermittent, passphrase-protected on unlock. Holds decryption keys
    /// only while in use.
    Mailbox,
    /// No inbound reachability; polls a boss node. Narrow shard subscription,
    /// short retention. Mobile and CGNAT deployments are points.
    Point,
}
