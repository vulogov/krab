//! Concrete `Fabric` backends (RFC 4).
//!
//! Wire protocol is Noise IK over a length-delimited byte stream, with static
//! keys taken from the peer credential. No TLS, no certificates, no second
//! identity system.
//!
//! Explicitly rejected: ZMQ (no SOCKS5, C dependency, cannot degrade to a
//! file) and QUIC (UDP; onion services are TCP-only).

pub mod courier;

#[cfg(feature = "serial")]
pub mod serial;

#[cfg(feature = "tcp")]
pub mod listener;
pub mod tcp;

// RFC 4 §5.2's Tor backend. `socks` dials, `tor` launches and drives the
// daemon; both need `tcp`'s stream machinery, which is why the `socks` feature
// enables it.
#[cfg(feature = "socks")]
pub mod socks;
#[cfg(feature = "socks")]
pub mod tor;

pub mod sim;
