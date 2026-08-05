//! Concrete `Fabric` backends (RFC 4).
//!
//! Wire protocol is Noise IK over a length-delimited byte stream, with static
//! keys taken from the peer credential. No TLS, no certificates, no second
//! identity system.
//!
//! Explicitly rejected: ZMQ (no SOCKS5, C dependency, cannot degrade to a
//! file) and QUIC (UDP; onion services are TCP-only).

#[cfg(feature = "courier")]
pub mod courier;
#[cfg(feature = "serial")]
pub mod serial;
#[cfg(feature = "sim")]
pub mod sim;
#[cfg(feature = "socks")]
pub mod socks;
#[cfg(feature = "tcp")]
pub mod tcp;
