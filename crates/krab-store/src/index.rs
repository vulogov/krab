//! Rebuildable ordered index over `(expiry, id)`, with per-bucket count and
//! fingerprint aggregates.
//!
//! The index is derived state: it can always be rebuilt by rescanning
//! segments, so a corrupt index is a delay rather than data loss.

use krab_core::object::ObjectId;

/// Per-bucket aggregate, sized for cheap manifest construction and for the
/// additive composable fingerprints RBSR needs (RFC 5).
#[derive(Debug, Clone, Copy, Default)]
pub struct BucketAggregate {
    /// Number of objects in the bucket.
    pub count: u64,
    /// Additive fingerprint over the bucket's object identifiers.
    pub fingerprint: [u8; 32],
}

/// Ordered index over the corpus.
#[derive(Debug, Default)]
pub struct Index {
    /// Object identifiers in `(expiry, id)` order.
    pub ids: Vec<ObjectId>,
    /// Aggregates, parallel to the segment set.
    pub buckets: Vec<BucketAggregate>,
}

impl Index {
    /// Coverage measurement (RFC 0 §7.4): the fraction of the live corpus this
    /// node holds.
    ///
    /// Nodes MUST measure and surface this — a node in the weak regime cannot
    /// currently tell that it is there.
    ///
    /// # Measure it by age, not only in aggregate
    ///
    /// The SIM-0 audit found that a single scalar is actively misleading under
    /// austere transport: measured coverage was 37% overall but ranged from 3%
    /// for the youngest objects to 82% for the oldest, because propagation
    /// takes longer than TTL. The scalar is a mean over that ramp and
    /// describes no actual holding probability. `coverage_by_age` is therefore
    /// the reportable form, and the scalar is derived from it.
    pub fn coverage_by_age(&self, _live_corpus_estimate: &[BucketAggregate]) -> Vec<f64> {
        // Awaiting RFC 5's presence capability fields.
        Vec::new()
    }
}
