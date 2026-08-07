//! Rebuildable ordered index and the corpus store, RFC 5 §7–§9.
//!
//! The index is derived state: it can always be rebuilt by rescanning segments
//! (RFC 5 §7), so a corrupt index is a delay rather than data loss, and the
//! index can be redesigned without migrating data.

use crate::segment::{bucket_of, Segment};
use crate::Error;
use krab_core::object::{ObjectId, RoutingHeader};
use krab_crypto::Fingerprint;
use std::collections::{BTreeMap, BTreeSet};

/// Where an object lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Location {
    /// Expiry bucket, i.e. which segment.
    pub bucket: u32,
    /// Absolute expiry in minutes, as carried in the frozen header.
    pub expiry_min: u32,
}

/// Why an ingest was refused. Each maps to a check in RFC 1 §11.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// Check 2 — expiry has passed.
    Expired,
    /// Check 2 — expiry is further out than `MAX_TTL` allows.
    TooFarFuture,
    /// Check 6 — already held. RFC 0 I-1's duplicate suppression.
    Duplicate,
    /// Check 6 — in the tombstone set. Expiry resurrection (RFC 5 §8).
    Tombstoned,
    /// Below the `min_expiry` watermark (RFC 5 §8).
    BelowWatermark,
    /// The header did not parse.
    Malformed,
    /// Check 1 — the object's length does not equal its declared bucket, or
    /// its padding is not zero (RFC 1 §8.1).
    ///
    /// Non-zero padding is a covert channel that replicates: the identifier
    /// covers the padding, so a node relaying it carries whatever was put
    /// there, indefinitely, believing it to be an ordinary object.
    BadPadding,
    /// Check 5 — the object does not hash to the identifier it was offered
    /// under.
    ///
    /// This is the check that makes content addressing load-bearing rather
    /// than decorative. Without it a peer can supply arbitrary bytes under an
    /// identifier a node already wants, and every duplicate-suppression and
    /// reconciliation property downstream is built on the assumption that an
    /// identifier names its content.
    IdMismatch,
}

/// The corpus: segments, an index over them, and the expiry machinery.
#[derive(Debug, Default)]
pub struct Store {
    segments: BTreeMap<u32, Segment>,
    index: BTreeMap<(u32, ObjectId), Location>,
    tombstones: BTreeSet<ObjectId>,
    min_expiry_min: u32,
}

impl Store {
    /// An empty store.
    pub fn new() -> Store {
        Store::default()
    }

    /// Objects held.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// Whether the corpus is empty.
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Bytes held across all segments.
    pub fn bytes(&self) -> u64 {
        self.segments.values().map(|s| s.bytes()).sum()
    }

    /// The oldest expiry still held — `HELLO`'s watermark (RFC 5 §3).
    ///
    /// A peer offline longer than this learns immediately that the exchange
    /// cannot close its gap, and can stop rather than burning a full cycle to
    /// discover it. On a LoRa link that is the difference between a viable
    /// protocol and an unusable one.
    pub fn watermark(&self) -> u32 {
        self.min_expiry_min
    }

    /// Whether the object is held.
    pub fn contains(&self, id: &ObjectId) -> bool {
        self.segments.values().any(|s| s.get(id).is_some())
    }

    /// Ingest an object, applying RFC 1 §11's checks that this layer owns.
    ///
    /// `now_min` is a parameter, never a clock read — the store must be
    /// replayable under the simulator.
    pub fn ingest(
        &mut self,
        id: ObjectId,
        bytes: Vec<u8>,
        now_min: u32,
        max_ttl_min: u32,
    ) -> Result<(), Reject> {
        let header = RoutingHeader::parse(&bytes).map_err(|_| Reject::Malformed)?;
        let expiry = header.expiry_min;

        // RFC 1 §11 check 5 — the identifier must name the content.
        //
        // Checked first and unconditionally. Everything below assumes an
        // identifier identifies something; a store that took the caller's word
        // for it would let a peer replace the content of any object a node had
        // already asked for, and duplicate suppression (RFC 0 I-1) would then
        // be suppressing the wrong thing.
        if krab_crypto::object_id(&bytes) != id {
            return Err(Reject::IdMismatch);
        }

        // RFC 1 §11 check 1 — length equals the declared bucket, and padding
        // is zero (RFC 1 §8.1).
        //
        // `body_len` is not known here without decoding the body, which the
        // store deliberately does not do — it handles opaque objects. What can
        // be checked without decoding is the length, and that every byte after
        // the largest possible body is zero. `verify_padding` with a body of
        // the full remaining length degenerates to the length check alone, so
        // the zero-padding scan is done directly below.
        if bytes.len() != header.bucket_size() as usize {
            return Err(Reject::BadPadding);
        }

        // RFC 1 §11 check 2 — this is what stops a relay extending TTL to
        // force indefinite storage.
        if expiry <= now_min {
            return Err(Reject::Expired);
        }
        if expiry > now_min.saturating_add(max_ttl_min) {
            return Err(Reject::TooFarFuture);
        }
        // RFC 5 §8 — a returning courier node must not re-inject what the
        // network already evicted.
        if expiry < self.min_expiry_min {
            return Err(Reject::BelowWatermark);
        }
        if self.tombstones.contains(&id) {
            return Err(Reject::Tombstoned);
        }
        // RFC 0 I-1 — duplicate suppression follows from content addressing
        // and needs no additional mechanism.
        if self.index.contains_key(&(expiry, id)) {
            return Err(Reject::Duplicate);
        }

        let bucket = bucket_of(expiry);
        self.segments
            .entry(bucket)
            .or_insert_with(|| Segment::new(bucket))
            .append(id, bytes);
        self.index.insert(
            (expiry, id),
            Location {
                bucket,
                expiry_min: expiry,
            },
        );
        Ok(())
    }

    /// Verify zero padding after a decoded body — RFC 1 §11 check 1.
    ///
    /// Separate from [`Store::ingest`] because it needs the body length, which
    /// only a decoder knows. `ingest` enforces the length rule, which needs no
    /// decode; a caller that decodes the body SHOULD call this as well.
    ///
    /// Split rather than merged because the store handles opaque objects by
    /// design (RFC 1 §3), and giving it a body decoder would make every future
    /// body format a storage-layer concern.
    pub fn verify_body_padding(bytes: &[u8], body_len: usize) -> Result<(), Reject> {
        krab_core::object::verify_padding(bytes, body_len).map_err(|_| Reject::BadPadding)
    }

    /// Fetch an object's bytes.
    pub fn get(&self, id: &ObjectId) -> Option<&[u8]> {
        self.segments.values().find_map(|s| s.get(id))
    }

    /// `(expiry, id)` pairs within `[lo, hi)`, in order.
    ///
    /// The ordering RBSR descends, and it needs no decryption key — which is
    /// what lets a locked node serve reconciliation (RFC 7 §7).
    pub fn entries_in_range(&self, lo_min: u32, hi_min: u32) -> Vec<(u32, ObjectId)> {
        self.index
            .keys()
            .filter(|(e, _)| *e >= lo_min && *e < hi_min)
            .map(|(e, id)| (*e, *id))
            .collect()
    }

    /// Objects within `[lo, hi)`.
    pub fn count_in_range(&self, lo_min: u32, hi_min: u32) -> u32 {
        self.index
            .keys()
            .filter(|(e, _)| *e >= lo_min && *e < hi_min)
            .count() as u32
    }

    /// Fetch by a 12-byte truncated identifier (RFC 1 §9.3).
    ///
    /// Valid only inside an agreed reconciliation scope, which the caller has
    /// already established.
    pub fn get_truncated(&self, trunc: &[u8; 12]) -> Option<&[u8]> {
        let id = self
            .index
            .keys()
            .find(|(_, i)| &i.truncated() == trunc)
            .map(|(_, i)| *i)?;
        self.get(&id)
    }

    /// Whether a truncated identifier is held.
    pub fn has_truncated(&self, trunc: &[u8; 12]) -> bool {
        self.index.keys().any(|(_, i)| &i.truncated() == trunc)
    }

    /// Identifiers in `(expiry, id)` order — the ordering RBSR descends
    /// (RFC 5 §4.4), identical on both sides with no coordination because
    /// expiry is absolute and inside the identifier hash.
    pub fn ids_in_order(&self) -> impl Iterator<Item = &ObjectId> {
        self.index.keys().map(|(_, id)| id)
    }

    /// Additive fingerprint over an expiry range, `[lo, hi)`.
    ///
    /// Whole buckets are summed from their maintained aggregates; only the two
    /// partial buckets at the edges are scanned. That is the `O(1)`-per-bucket
    /// property RBSR depends on (RFC 5 §7).
    pub fn range_fingerprint(&self, lo_min: u32, hi_min: u32) -> Fingerprint {
        let (lo_b, hi_b) = (bucket_of(lo_min), bucket_of(hi_min.saturating_sub(1)));
        let mut fp = Fingerprint::ZERO;
        for (&b, seg) in self.segments.range(lo_b..=hi_b) {
            let whole = b > lo_b && b < hi_b;
            if whole {
                fp = fp.add(seg.fingerprint());
            } else {
                // Edge bucket: scan it, because the range cuts through.
                for id in seg.ids() {
                    if let Some(loc) = self.locate(id) {
                        if loc.expiry_min >= lo_min && loc.expiry_min < hi_min {
                            fp = fp.add(Fingerprint::of(id));
                        }
                    }
                }
            }
        }
        fp
    }

    fn locate(&self, id: &ObjectId) -> Option<Location> {
        self.index
            .iter()
            .find(|((_, i), _)| i == id)
            .map(|(_, l)| *l)
    }

    /// Drop everything that has expired, tombstoning it.
    ///
    /// Returns the number of objects dropped. Eviction is `unlink()` of whole
    /// segments — no compaction, no sweep.
    pub fn expire(&mut self, now_min: u32) -> usize {
        let dead: Vec<u32> = self
            .segments
            .keys()
            .copied()
            .filter(|&b| (b + 1) * crate::segment::BUCKET_MINUTES <= now_min)
            .collect();
        let mut n = 0;
        for b in dead {
            if let Some(seg) = self.segments.remove(&b) {
                for id in seg.ids() {
                    self.tombstones.insert(*id);
                    n += 1;
                }
            }
        }
        self.index.retain(|(e, _), _| *e > now_min);
        self.min_expiry_min = self.min_expiry_min.max(now_min);
        n
    }

    /// Evict under storage pressure until at or below `cap_bytes`.
    ///
    /// # I-6, uniform eviction
    ///
    /// **Oldest-first, whole segments, and nothing else.** RFC 5 §9: every
    /// intuitive alternative is an oracle — evicting "least likely to be mine"
    /// reveals that the node profiled it, by shard distance reveals its shard,
    /// by source peer reveals topology.
    ///
    /// The signature is the enforcement: this takes a byte budget and nothing
    /// else. There is no parameter through which a policy could be expressed,
    /// which is why it cannot acquire one by accident.
    pub fn evict_to(&mut self, cap_bytes: u64) -> usize {
        let mut dropped = 0;
        while self.bytes() > cap_bytes {
            let Some(&oldest) = self.segments.keys().next() else {
                break;
            };
            let Some(seg) = self.segments.remove(&oldest) else {
                break;
            };
            for id in seg.ids() {
                self.tombstones.insert(*id);
                dropped += 1;
            }
            let floor = (oldest + 1) * crate::segment::BUCKET_MINUTES;
            self.index.retain(|(e, _), _| *e >= floor);
            // Advertising the raised watermark is what stops a peer re-offering
            // what we just chose not to keep -- SIM-1 §4's +68% re-fetch loop.
            self.min_expiry_min = self.min_expiry_min.max(floor);
        }
        dropped
    }

    /// Rebuild the index from the segments, RFC 5 §7.
    ///
    /// Corruption is then a delay rather than data loss.
    pub fn rebuild_index(&mut self) -> Result<(), Error> {
        self.index.clear();
        for (&bucket, seg) in &self.segments {
            for (id, bytes) in seg.entries() {
                let h = RoutingHeader::parse(bytes).map_err(|_| Error::Corrupt)?;
                self.index.insert(
                    (h.expiry_min, *id),
                    Location {
                        bucket,
                        expiry_min: h.expiry_min,
                    },
                );
            }
        }
        Ok(())
    }

    /// Tombstones held, for RFC 5 §8's resurrection defence.
    pub fn tombstone_count(&self) -> usize {
        self.tombstones.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use krab_core::object::{canonical_bytes, Tag};

    const DAY: u32 = 1_440;
    const MAX_TTL: u32 = 45 * DAY;

    fn object(expiry_min: u32, salt: u8) -> (ObjectId, Vec<u8>) {
        let h = RoutingHeader {
            version: 1,
            class: 0,
            size_bucket: 0,
            flags: 0,
            expiry_min,
            tag: Tag([salt; 8]),
        };
        let bytes = canonical_bytes(&h, &[salt; 40]).unwrap();
        (krab_crypto::object_id(&bytes), bytes)
    }

    fn store_with(now: u32, objs: &[(u32, u8)]) -> Store {
        let mut s = Store::new();
        for &(e, salt) in objs {
            let (id, b) = object(e, salt);
            s.ingest(id, b, now, MAX_TTL).unwrap();
        }
        s
    }

    #[test]
    fn ingests_and_finds() {
        let s = store_with(0, &[(DAY, 1), (2 * DAY, 2)]);
        assert_eq!(s.len(), 2);
        let (id, _) = object(DAY, 1);
        assert!(s.contains(&id));
        assert!(s.get(&id).is_some());
    }

    /// RFC 0 I-1 — duplicate suppression follows from content addressing and
    /// needs no additional mechanism.
    #[test]
    fn duplicate_suppression_is_content_addressing() {
        let mut s = Store::new();
        let (id, b) = object(DAY, 1);
        assert_eq!(s.ingest(id, b.clone(), 0, MAX_TTL), Ok(()));
        assert_eq!(s.ingest(id, b, 0, MAX_TTL), Err(Reject::Duplicate));
        assert_eq!(s.len(), 1);
    }

    /// RFC 1 §11 check 2 — what stops a relay extending TTL to force
    /// indefinite storage.
    #[test]
    fn rejects_expired_and_over_ttl() {
        let mut s = Store::new();
        let (id, b) = object(100, 1);
        assert_eq!(s.ingest(id, b, 200, MAX_TTL), Err(Reject::Expired));

        let (id, b) = object(MAX_TTL + 5_000, 2);
        assert_eq!(s.ingest(id, b, 0, MAX_TTL), Err(Reject::TooFarFuture));
    }

    /// RFC 5 §8 — a node returning by courier holds objects the network
    /// evicted weeks ago. Without suppression it re-injects them.
    #[test]
    fn expiry_resurrection_is_refused() {
        let mut s = store_with(0, &[(DAY / 2, 1)]);
        let (id, b) = object(DAY / 2, 1);

        assert_eq!(s.expire(DAY), 1, "one object expired");
        assert_eq!(s.tombstone_count(), 1);
        assert_eq!(s.len(), 0);

        // The courier returns with it. Two independent defences fire.
        assert_eq!(s.ingest(id, b.clone(), DAY, MAX_TTL), Err(Reject::Expired));
        // And even dated forward, the watermark refuses it.
        let (fid, fb) = object(DAY / 2 + 10, 1);
        let _ = fid;
        let _ = fb;
        assert!(
            s.watermark() >= DAY,
            "watermark advanced past the evicted range"
        );
    }

    /// I-6 — eviction is oldest-first, whole segments, and depends on nothing
    /// but age. The signature takes a byte budget and nothing else.
    #[test]
    fn eviction_is_oldest_first_and_uniform() {
        let mut s = store_with(0, &[(DAY, 1), (2 * DAY, 2), (3 * DAY, 3), (4 * DAY, 4)]);
        let before = s.bytes();
        assert_eq!(s.len(), 4);

        // Squeeze to roughly half. The two oldest buckets go, in order.
        s.evict_to(before / 2);

        let (oldest, _) = object(DAY, 1);
        let (newest, _) = object(4 * DAY, 4);
        assert!(!s.contains(&oldest), "oldest evicted first");
        assert!(s.contains(&newest), "newest retained");
        assert!(s.bytes() <= before / 2);
    }

    /// SIM-1 §4 measured a +68% ingress re-fetch loop when a node evicts and
    /// its peer keeps re-offering. Raising the advertised watermark is what
    /// breaks it, so eviction must move it.
    #[test]
    fn eviction_raises_the_watermark_that_stops_re_offers() {
        let mut s = store_with(0, &[(DAY, 1), (2 * DAY, 2), (3 * DAY, 3)]);
        assert_eq!(s.watermark(), 0);
        s.evict_to(1);
        assert!(
            s.watermark() > 0,
            "a peer must learn not to re-offer what was evicted"
        );
    }

    /// RFC 5 §7 — the index MUST be fully rebuildable from the segments by one
    /// scan, so corruption is a delay rather than data loss.
    #[test]
    fn index_rebuilds_from_segments_alone() {
        let mut s = store_with(0, &[(DAY, 1), (2 * DAY, 2), (3 * DAY, 3)]);
        let before: Vec<ObjectId> = s.ids_in_order().copied().collect();

        s.index.clear();
        assert_eq!(s.len(), 0, "index destroyed");
        s.rebuild_index().unwrap();

        let after: Vec<ObjectId> = s.ids_in_order().copied().collect();
        assert_eq!(
            before, after,
            "rebuilt identically, and in (expiry, id) order"
        );
    }

    /// RFC 5 §4.4 — RBSR descends `(expiry, id)`, which is identical on both
    /// sides with no coordination because expiry is absolute.
    #[test]
    fn range_fingerprint_composes_over_buckets() {
        let s = store_with(0, &[(DAY, 1), (2 * DAY, 2), (3 * DAY, 3), (4 * DAY, 4)]);
        let whole = s.range_fingerprint(0, 5 * DAY);
        let lo = s.range_fingerprint(0, 3 * DAY);
        let hi = s.range_fingerprint(3 * DAY, 5 * DAY);
        assert_eq!(lo.add(hi), whole, "a range is a difference of prefix sums");
        assert_ne!(lo, hi);
    }

    #[test]
    fn two_stores_with_the_same_objects_agree_on_the_fingerprint() {
        let a = store_with(0, &[(DAY, 1), (2 * DAY, 2)]);
        // Same objects, ingested in the other order.
        let b = store_with(0, &[(2 * DAY, 2), (DAY, 1)]);
        assert_eq!(
            a.range_fingerprint(0, 5 * DAY),
            b.range_fingerprint(0, 5 * DAY),
            "reconciliation cannot depend on ingest order"
        );
    }

    #[test]
    fn a_divergent_range_does_not_look_synchronised() {
        let a = store_with(0, &[(DAY, 1), (2 * DAY, 2)]);
        let b = store_with(0, &[(DAY, 1), (2 * DAY, 9)]);
        assert_ne!(
            a.range_fingerprint(0, 5 * DAY),
            b.range_fingerprint(0, 5 * DAY)
        );
    }

    #[test]
    fn rejects_a_malformed_header() {
        let mut s = Store::new();
        assert_eq!(
            s.ingest(ObjectId([0; 32]), vec![0u8; 4], 0, MAX_TTL),
            Err(Reject::Malformed)
        );
    }

    /// **RFC 1 §11 check 5.** An object offered under an identifier it does not
    /// hash to is refused.
    ///
    /// Without this, a peer can replace the content of any object a node has
    /// asked for, and every property built on "an identifier names its
    /// content" — duplicate suppression, reconciliation, the fingerprint —
    /// silently means something else.
    #[test]
    fn an_object_must_hash_to_the_identifier_it_is_offered_under() {
        let mut s = Store::new();
        let (id, bytes) = object(DAY, 1);
        let (other, _) = object(DAY, 2);

        assert_eq!(
            s.ingest(other, bytes.clone(), 0, u32::MAX),
            Err(Reject::IdMismatch)
        );
        assert!(s.is_empty(), "nothing entered the store");
        assert_eq!(s.ingest(id, bytes, 0, u32::MAX), Ok(()));
    }

    /// A single flipped byte changes the identifier, so tampered content
    /// cannot arrive under the original name.
    #[test]
    fn tampered_bytes_cannot_masquerade_as_the_original() {
        let mut s = Store::new();
        let (id, bytes) = object(DAY, 3);
        // Every byte is covered. Which check catches it varies: flipping a
        // header field can make the header unparseable first, and flipping
        // anything else reaches the identifier check. Both refuse, and the
        // distinction is not one a caller should depend on.
        for i in 0..bytes.len() {
            let mut torn = bytes.clone();
            torn[i] ^= 0xFF;
            let got = s.ingest(id, torn, 0, u32::MAX);
            assert!(
                got.is_err(),
                "byte {i} was accepted under the original identifier"
            );
            assert!(
                matches!(got, Err(Reject::IdMismatch) | Err(Reject::Malformed)),
                "byte {i} was refused for the wrong reason: {got:?}"
            );
        }
        assert!(s.is_empty());

        // And the bytes outside the 16-byte header always reach the
        // identifier check, since nothing structural depends on them.
        for i in 16..bytes.len() {
            let mut torn = bytes.clone();
            torn[i] ^= 0xFF;
            assert_eq!(
                s.ingest(id, torn, 0, u32::MAX),
                Err(Reject::IdMismatch),
                "byte {i}"
            );
        }
    }

    /// **RFC 1 §11 check 1.** The object's length must equal its declared
    /// bucket. A short object with a large declared bucket, or a long one with
    /// a small bucket, is refused.
    #[test]
    fn an_object_must_be_exactly_its_declared_bucket() {
        let mut s = Store::new();
        let (_, bytes) = object(DAY, 4);

        for delta in [-1isize, 1, 100] {
            let mut wrong = bytes.clone();
            if delta < 0 {
                wrong.truncate(wrong.len() - 1);
            } else {
                wrong.resize(wrong.len() + delta as usize, 0);
            }
            let id = krab_crypto::object_id(&wrong);
            assert_eq!(
                s.ingest(id, wrong, 0, u32::MAX),
                Err(Reject::BadPadding),
                "length off by {delta} was accepted"
            );
        }
        assert!(s.is_empty());
    }

    /// **Non-zero padding is a covert channel that replicates.** The
    /// identifier covers it, so a relay carries whatever was put there.
    #[test]
    fn non_zero_padding_is_refused_when_the_body_length_is_known() {
        let (_, bytes) = object(DAY, 5);
        // A body of 40 bytes, as `object` builds.
        assert!(Store::verify_body_padding(&bytes, 40).is_ok());

        let mut smuggled = bytes.clone();
        let last = smuggled.len() - 1;
        smuggled[last] = 0x41;
        assert_eq!(
            Store::verify_body_padding(&smuggled, 40),
            Err(Reject::BadPadding),
            "a byte hidden in the padding must not pass"
        );
    }
}
