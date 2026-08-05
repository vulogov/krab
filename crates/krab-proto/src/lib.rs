//! Control messages and the reconciliation state machine (RFC 5).
//!
//! This crate is a pure state machine: it consumes control messages and emits
//! control messages, and touches neither a socket nor a clock. That is what
//! makes it a property-test and fuzz target — reconciliation is reachable
//! pre-authentication, so it is untrusted input by definition.
//!
//! # Property under test
//!
//! For any two stores and any filter, reconciliation converges to the filtered
//! union in bounded rounds under reordering and duplication.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod control;
pub mod recon;
