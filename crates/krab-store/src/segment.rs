//! TTL-bucketed append-only segments, RFC 5 §7.
//!
//! Objects are immutable and expire in bulk, so a general-purpose key-value
//! store is the wrong shape. Grouping by expiry bucket makes eviction a whole-
//! file `unlink()`: no compaction, no tombstone sweep, no fragmentation, no
//! write amplification. Courier export is a copy of whole segment files.
//!
//! Segments are in-memory here. File backing is phase C of
//! `Documentation/MILESTONE-0.1.md` and changes nothing above this module —
//! which is the point of keeping the layout this simple.

use krab_core::object::ObjectId;
use krab_crypto::Fingerprint;

/// Bucket granularity: one day, matching the epoch (RFC 1 §2).
///
/// `MAX_TTL` is 45 days, so a node holds at most 46 live segments.
pub const BUCKET_MINUTES: u32 = 1_440;

/// Which segment an object with this expiry belongs to.
pub fn bucket_of(expiry_min: u32) -> u32 {
    expiry_min / BUCKET_MINUTES
}

/// An append-only segment: every object expiring in one bucket.
#[derive(Debug, Default, Clone)]
pub struct Segment {
    bucket: u32,
    entries: Vec<(ObjectId, Vec<u8>)>,
    fingerprint: Fingerprint,
    bytes: u64,
}

impl Segment {
    /// An empty segment for `bucket`.
    pub fn new(bucket: u32) -> Segment {
        Segment { bucket, entries: Vec::new(), fingerprint: Fingerprint::ZERO, bytes: 0 }
    }

    /// The expiry bucket this segment covers.
    pub fn bucket(&self) -> u32 {
        self.bucket
    }

    /// Objects held.
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Bytes held.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// The segment's additive fingerprint, maintained on append so a range
    /// summary never rescans (RFC 5 §7).
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// Append. The caller has already checked for duplicates against the index.
    pub fn append(&mut self, id: ObjectId, bytes: Vec<u8>) {
        self.bytes += bytes.len() as u64;
        self.fingerprint = self.fingerprint.add(Fingerprint::of(&id));
        self.entries.push((id, bytes));
    }

    /// Fetch by identifier.
    pub fn get(&self, id: &ObjectId) -> Option<&[u8]> {
        self.entries.iter().find(|e| &e.0 == id).map(|e| e.1.as_slice())
    }

    /// Every identifier held, in append order.
    pub fn ids(&self) -> impl Iterator<Item = &ObjectId> {
        self.entries.iter().map(|e| &e.0)
    }

    /// Every object, for an index rebuild or a courier export.
    pub fn entries(&self) -> impl Iterator<Item = (&ObjectId, &[u8])> {
        self.entries.iter().map(|e| (&e.0, e.1.as_slice()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> ObjectId {
        ObjectId([n; 32])
    }

    #[test]
    fn bucket_is_one_day() {
        assert_eq!(bucket_of(0), 0);
        assert_eq!(bucket_of(BUCKET_MINUTES - 1), 0);
        assert_eq!(bucket_of(BUCKET_MINUTES), 1);
        // MAX_TTL is 45 days, so a node holds at most 46 live segments.
        assert_eq!(bucket_of(45 * BUCKET_MINUTES) - bucket_of(0), 45);
    }

    #[test]
    fn fingerprint_is_maintained_on_append_not_rescanned() {
        let mut s = Segment::new(0);
        s.append(id(1), vec![0; 10]);
        s.append(id(2), vec![0; 20]);
        assert_eq!(s.fingerprint(), Fingerprint::over([id(1), id(2)].iter()));
        assert_eq!(s.count(), 2);
        assert_eq!(s.bytes(), 30);
    }

    #[test]
    fn append_order_does_not_change_the_fingerprint() {
        let mut a = Segment::new(0);
        a.append(id(1), vec![0; 4]);
        a.append(id(2), vec![0; 4]);
        let mut b = Segment::new(0);
        b.append(id(2), vec![0; 4]);
        b.append(id(1), vec![0; 4]);
        assert_eq!(a.fingerprint(), b.fingerprint());
    }
}
