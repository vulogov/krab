//! Krab object format, cryptography, tag derivation, and filters.
//!
//! # Invariant (RFC 0 §4.3)
//!
//! This crate MUST NOT perform I/O, read a clock, or source randomness. Time
//! and entropy are arguments.
//!
//! The invariant is enforced by the compiler, not by review: the crate is
//! `no_std`, so `std::time::SystemTime`, `std::fs`, `std::io` and ambient RNG
//! are simply not reachable. A dependency that drags in `std` fails the build.
//! This is what allows identical code to run in production, under the
//! deterministic simulator, and under a fuzzer with no `cfg` branching.
//!
//! # Status
//!
//! Scaffold. RFC 1 (Object Format and Cryptography) is not yet at Draft, and
//! per the RFC series plan §1 it MUST NOT reach Draft until blocking items
//! B2 (frozen routing header) and B3 (parameter table) are settled. Nothing
//! here is stable, and no wire format is frozen.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

pub mod filter;
pub mod object;
pub mod tag;

/// Cryptographic domain-separation root.
///
/// Blocking item B0 is resolved: the project name is **Krab**. This string
/// appears in every domain-separation label and in the link frame magic, and
/// is frozen permanently once objects exist (RFC series plan §1, B0).
pub const DOMAIN: &str = "krab";

/// Errors surfaced by pure `krab-core` operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Input was not well-formed for the claimed version.
    Malformed,
    /// A known object version carried an envelope key that is not defined for
    /// it. RFC 0 §10.1: within a known version, unknown keys MUST be rejected.
    UnknownEnvelopeKey,
    /// Object version is newer than this build understands. Relays MUST still
    /// route, filter, and expire such objects from the frozen header alone.
    UnsupportedVersion(u16),
    /// Authenticated decryption failed.
    Decrypt,
}
