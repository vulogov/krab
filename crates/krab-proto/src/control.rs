//! Control opcodes (RFC 5).
//!
//! Control messages are **not objects**: never stored, never hashed, never
//! relayed. They exist only for the duration of one reconciliation.

use krab_core::filter::Filter;
use krab_core::object::ObjectId;

/// The five control opcodes.
///
/// Not `Eq`: `coverage_by_age` carries floats.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Control {
    /// Open a reconciliation, announcing the agreed filter and capabilities.
    Hello {
        /// Filter derived from the signed credential, so both sides provably
        /// agree on scope.
        filter: Filter,
        /// Fraction of the live corpus this node holds, by age bucket
        /// (RFC 0 §7.4). Surfaced so a peer can tell whether the possession
        /// argument actually holds for this node.
        coverage_by_age: Vec<f64>,
    },
    /// Offer what the sender holds within the filter.
    ///
    /// # Cost (SIM-0 audit)
    ///
    /// A full manifest at n=500 is roughly 14 000 identifiers. At 32 bytes
    /// that is ~448 KB — about 24× a single LoRa sync window and 6× that
    /// link's entire daily budget. Manifest encoding is therefore not a
    /// detail; it decides whether a constrained link can reconcile at all,
    /// and it is the open question SIM-1 exists to answer.
    Manifest {
        /// Object identifiers, or a compressed range encoding thereof.
        ids: Vec<ObjectId>,
    },
    /// Request a subset of a manifest.
    Want {
        /// Requested identifiers.
        ids: Vec<ObjectId>,
    },
    /// Deliver one object's canonical bytes.
    Obj {
        /// Canonical encoding, verified against its identifier on ingest.
        bytes: Vec<u8>,
    },
    /// Close cleanly.
    Bye,
}
