//! TTL-bucketed append-only segments.
//!
//! Objects are grouped into segments by expiry bucket, so that expiry is a
//! prefix operation and eviction is a file deletion rather than a compaction.

/// An append-only segment covering one TTL bucket.
#[derive(Debug)]
pub struct Segment {
    /// Inclusive lower bound of this bucket's expiry range, Unix seconds.
    pub expiry_floor: u64,
    /// Exclusive upper bound.
    pub expiry_ceil: u64,
    /// Objects currently in the segment.
    pub count: u64,
    /// Bytes currently in the segment.
    pub bytes: u64,
}

/// Ordered set of segments making up a node's corpus.
#[derive(Debug, Default)]
pub struct SegmentSet {
    /// Segments, ordered by `expiry_floor`.
    pub segments: Vec<Segment>,
}

impl SegmentSet {
    /// Evict the oldest segment. This is the only eviction primitive, so that
    /// I-6 holds by construction: there is no way to express a policy that
    /// selects on anything but age.
    pub fn evict_oldest(&mut self) -> Option<Segment> {
        if self.segments.is_empty() {
            None
        } else {
            Some(self.segments.remove(0))
        }
    }

    /// Live object count and byte total across all segments.
    pub fn live(&self) -> (u64, u64) {
        self.segments.iter().fold((0, 0), |(c, b), s| (c + s.count, b + s.bytes))
    }
}
