//! **Krab** — friend-to-friend, store-and-forward messaging over any
//! transport.
//!
//! Krab is FidoNet with modern cryptography. Nodes exchange an encrypted,
//! content-addressed object corpus over whatever transport is available — IP,
//! Tor, LoRa, serial, X.25, or a hand-carried USB stick — with peers chosen
//! individually, out of band, by their operators.
//!
//! There is no discovery, no directory, no bootstrap server, no
//! proof-of-work, and no infrastructure of any kind.
//!
//! # Status
//!
//! Scaffold. No RFC in the series is normative until it reaches Draft and its
//! dependencies are satisfied. RFC 1 (Object Format and Cryptography) is the
//! document that cannot be revised, and per the series plan it MUST NOT reach
//! Draft until blocking items B2 and B3 are settled. Nothing here is stable.
//!
//! # What Krab is not
//!
//! Not a replacement for Signal, Matrix, or email. Slower by orders of
//! magnitude, unjoinable without knowing a participant, and it makes no
//! delivery guarantee. It is appropriate where those costs buy something:
//! operation without infrastructure, resistance to mass passive collection,
//! resistance to Sybil-based vantage acquisition, and the ability to carry
//! traffic across links no conventional messenger can use.
//!
//! # Layout
//!
//! This crate is a facade. The split beneath it is by dependency direction
//! and is load-bearing rather than cosmetic — it is what makes deterministic
//! testing, fuzzing, and headless operation possible.
//!
//! | crate | role |
//! |---|---|
//! | [`core`] | object format, crypto, tags, filters. No I/O, no clock, no ambient randomness |
//! | [`store`] | TTL-bucketed segments, rebuildable index, crypto-shredding keys |
//! | [`proto`] | control messages, reconciliation state machine |
//! | [`fabric`] | `Fabric` trait and backends |
//! | [`node`] | scheduler, sync loop, key management, peering |

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub use krab_core as core;
pub use krab_fabric as fabric;
pub use krab_node as node;
pub use krab_proto as proto;
pub use krab_store as store;

/// Cryptographic domain-separation root (blocking item B0, resolved: "krab").
pub use krab_core::DOMAIN;
