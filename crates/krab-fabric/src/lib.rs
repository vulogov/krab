//! Transport abstraction and backends, RFC 4.
//!
//! # I-4, transport indifference
//!
//! Nothing above this boundary may assume a transport is anonymous, reachable,
//! low-latency, or online. The test, applied to every proposed API here:
//! **does it still work when the only link is a USB stick delivered
//! fortnightly?**
//!
//! RFC 4 §2 turns that from a review convention into a structural property:
//! *if the courier backend cannot implement an operation, that operation does
//! not belong in the protocol.* [`courier`] is therefore built early and
//! deliberately, so the boundary is forced to be honest before anything
//! depends on it.
//!
//! # Departure from RFC 4 §2's signature
//!
//! RFC 4 §2 gives `Fabric` and `Session` as **`async` traits**. This
//! implements them synchronously, because async and RFC 4 §10 are in conflict:
//!
//! > "One peer set may mix a Tor link to a distant contact, plain IPv6 to a
//! > friend, LoRa to a neighbour, and a USB stick to a colleague."
//!
//! A heterogeneous peer set needs `dyn Fabric`. Native `async fn` in a trait
//! is not dyn-safe, so an async `Fabric` forces either `async-trait` — a
//! third-party dependency in a crate the workspace keeps dependency-free, and
//! a boxed allocation per call — or a `Box<dyn Fabric>` that cannot exist.
//!
//! Nothing is lost. A courier session's *operations* are fast local file work;
//! the days are between sessions, not inside one. The node drives the sync
//! loop on its own thread (RFC 5 §6.1's Poisson schedule is a scheduler, not a
//! reactor), so blocking calls are the natural shape and the `sim` backend
//! stays deterministic without a runtime.
//!
//! Recorded as a finding against RFC 4 §2 rather than silently diverging.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod backend;
pub mod deadline;
pub mod frame;
pub mod noise;
pub mod profile;

pub use profile::{LatencyClass, LinkProfile, MaxBucket};

use krab_proto::control::Control;

/// Transport-level errors.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Underlying I/O failure.
    Io(std::io::Error),
    /// The peer is not reachable now.
    ///
    /// **Not fatal.** On an intermittent link this is the normal case, not a
    /// condition to escalate — I-4 forbids assuming reachability.
    Unreachable,
    /// The link's capacity budget for this window is exhausted.
    Exhausted,
    /// A frame was malformed or exceeded the length limit.
    Frame,
    /// The session has ended.
    Closed,
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Unreachable => f.write_str("peer not reachable now"),
            Error::Exhausted => f.write_str("link budget exhausted"),
            Error::Frame => f.write_str("malformed frame"),
            Error::Closed => f.write_str("session closed"),
        }
    }
}

impl std::error::Error for Error {}

/// One reconciliation session over a concrete carrier.
///
/// Expressed in **control messages, not bytes or connections**, which is what
/// lets the courier backend implement it: `send` appends to an archive and
/// `recv` reads from one.
///
/// `Send`, because an exchange must run off the interface thread. RFC 8's node
/// is also the client, and a reconciliation that blocks the render loop makes
/// the lock chord unavailable for the duration — which is exactly when an
/// operator may need it.
pub trait Session: Send {
    /// Offer a control message toward the peer.
    fn send(&mut self, msg: &Control) -> Result<(), Error>;

    /// Take the next control message, or `None` if the peer is finished.
    ///
    /// Returns `None` rather than blocking forever on a courier archive that
    /// has been read to the end — "the peer said nothing more" and "the peer
    /// is unreachable" are different, and only the first is normal.
    fn recv(&mut self) -> Result<Option<Control>, Error>;

    /// Finish, flushing anything buffered.
    fn close(&mut self) -> Result<(), Error>;
}

/// A concrete carrier for one link.
///
/// Object-safe on purpose: RFC 4 §10 requires a client to show which links
/// provide location and volume privacy, which means holding a heterogeneous
/// set of them at once.
pub trait Fabric {
    /// Static description of what this link can carry.
    fn profile(&self) -> &LinkProfile;

    /// Open a session toward the peer.
    fn connect(&self) -> Result<Box<dyn Session>, Error>;

    /// Accept an inbound session, if one is waiting.
    fn accept(&self) -> Result<Option<Box<dyn Session>>, Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4 §10 needs a heterogeneous peer set, so the trait must be
    /// object-safe. This is the test that would fail if someone made it async.
    #[test]
    fn fabric_is_object_safe() {
        let links: Vec<Box<dyn Fabric>> = vec![
            Box::new(backend::sim::SimFabric::new(LinkProfile::tcp())),
            Box::new(backend::sim::SimFabric::new(LinkProfile::lora_sf10())),
        ];
        let kinds: Vec<&str> = links.iter().map(|l| l.profile().kind).collect();
        assert_eq!(kinds, vec!["tcp", "lora"]);
    }
}
