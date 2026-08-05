//! Transport abstraction and backends (RFC 4).
//!
//! # I-4, transport indifference
//!
//! Nothing above the `Fabric` boundary may assume a transport is anonymous,
//! reachable, low-latency, or online.
//!
//! The test, applied to every proposed API on this boundary: does it still
//! work when the only link is a USB stick delivered fortnightly?

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod backend;
pub mod profile;

use krab_proto::control::Control;

/// Transport-level errors.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Underlying I/O failure.
    Io(std::io::Error),
    /// The peer is not reachable now. Not fatal: on an intermittent link this
    /// is the normal case, not an error condition to escalate.
    Unreachable,
    /// The link's capacity budget for this window is exhausted.
    Exhausted,
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// A concrete carrier for one link.
///
/// Deliberately not `async`: a courier backend completes over days, and
/// modelling that as a pending future would encode an availability assumption
/// this trait exists to forbid.
pub trait Fabric {
    /// Static description of what this link can carry.
    fn profile(&self) -> &profile::LinkProfile;

    /// Offer a control message toward the peer.
    fn publish(&mut self, msg: &Control) -> Result<(), Error>;

    /// Collect control messages that have arrived since the last call.
    fn subscribe(&mut self) -> Result<Vec<Control>, Error>;

    /// Fetch object bytes by identifier, where the carrier supports it.
    fn fetch(&mut self, ids: &[krab_core::object::ObjectId]) -> Result<Vec<Vec<u8>>, Error>;

    /// Run one reconciliation round against the peer.
    fn reconcile(&mut self) -> Result<(), Error>;
}
