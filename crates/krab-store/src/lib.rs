//! TTL-bucketed segment store, rebuildable index, and the crypto-shredding
//! key hierarchy (RFC 5 storage, RFC 7 custody).
//!
//! # I-6, uniform eviction
//!
//! Objects are evicted oldest-first, uniformly across shards. Eviction policy
//! MUST NOT depend on any property of the object other than its age.
//!
//! Per SIM-0 §6 this matters *more* under partial coverage, not less: when a
//! node holds only part of the corpus, *which* objects it holds is the entire
//! question, and any policy-driven holding set is an oracle.
//!
//! # I-7, cryptographic erasure
//!
//! Forward secrecy comes from destroying keys, never from overwriting data.
//! Overwrite-based deletion is not reliable on flash storage and MUST NOT be
//! relied upon. Eviction is file deletion; erasure is key destruction.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod index;
pub use index::{Reject, Store};
pub mod keys;
pub mod segment;

/// Store-level errors.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Underlying I/O failure.
    Io(std::io::Error),
    /// A segment failed hash verification on ingest.
    Corrupt,
    /// The requested epoch's key has been shredded; the data is unreadable by
    /// design (I-7).
    Shredded,
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
