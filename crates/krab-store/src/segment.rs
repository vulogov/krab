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

/// The first minute in `bucket`.
pub fn bucket_start(bucket: u32) -> u32 {
    bucket.saturating_mul(BUCKET_MINUTES)
}

/// The exclusive upper edge of `bucket` — one past the last minute in it.
///
/// # Why this is a function, and why it returns `u64`
///
/// The top bucket is `u32::MAX / BUCKET_MINUTES`, and one past its start does
/// not fit: `(2_982_616 + 1) * 1_440` is 4_294_968_480, which is 1_185 more
/// than `u32::MAX`. Written inline as `(b + 1) * BUCKET_MINUTES` the
/// expression panicked in a debug build and, worse, wrapped to 1_184 in a
/// release build — a bound so small that `expire` unlinked the segment as
/// though it were already dead while the very next line's `retain` kept its
/// index entries, leaving the index describing objects no segment holds.
///
/// The type is the fix. Saturating into `u32` would be *safe* but not
/// *correct*: `bucket_end(top) == u32::MAX` would say the range `[0,
/// u32::MAX)` wholly contains a bucket that also holds the minute `u32::MAX`,
/// which that half-open range excludes. Callers that need a `u32` — a
/// tombstone bound, a watermark — clamp explicitly and say which direction
/// they are erring in.
///
/// Ingest refuses expiries this far out (RFC 1 §11 I2), so no honest path
/// reaches the top bucket. That is a reason the bug had not fired, not a
/// reason to leave the arithmetic partial: a bound that holds only because a
/// check elsewhere holds is one edit deep.
pub fn bucket_end(bucket: u32) -> u64 {
    bucket as u64 * BUCKET_MINUTES as u64 + BUCKET_MINUTES as u64
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
        Segment {
            bucket,
            entries: Vec::new(),
            fingerprint: Fingerprint::ZERO,
            bytes: 0,
        }
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
        self.entries
            .iter()
            .find(|e| &e.0 == id)
            .map(|e| e.1.as_slice())
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

    /// `bucket_end` is total, which the inline expression it replaced was not:
    /// the top bucket's edge is 1_185 past `u32::MAX`.
    #[test]
    fn the_bucket_edge_is_total() {
        assert_eq!(bucket_end(0), BUCKET_MINUTES as u64);
        assert_eq!(bucket_end(44), 45 * BUCKET_MINUTES as u64);
        // The one that overflowed — and it is genuinely past `u32::MAX`, not
        // clamped to it, so a range ending at `u32::MAX` does not contain it.
        let top = u32::MAX / BUCKET_MINUTES;
        assert_eq!(bucket_end(top), 4_294_968_480);
        assert!(bucket_end(top) > u32::MAX as u64);
        assert_eq!(bucket_end(u32::MAX), (u32::MAX as u64 + 1) * 1_440);

        // Every edge bounds its own bucket, and the next one starts there.
        // That is the property `expire`, `evict_to` and the range queries all
        // rest on, and it must hold at the top as well as everywhere else.
        for b in [0, 1, 45, 1_000, top - 1, top] {
            assert_eq!(bucket_end(b), bucket_start(b) as u64 + BUCKET_MINUTES as u64);
            assert_eq!(bucket_of(bucket_start(b)), b);
            if b < top {
                assert_eq!(bucket_start(b + 1) as u64, bucket_end(b));
            }
        }
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
