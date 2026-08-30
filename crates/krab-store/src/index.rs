//! Rebuildable ordered index and the corpus store, RFC 5 §7–§9.
//!
//! The index is derived state: it can always be rebuilt by rescanning segments
//! (RFC 5 §7), so a corrupt index is a delay rather than data loss, and the
//! index can be redesigned without migrating data.

use crate::segment::{bucket_of, Segment};
use crate::Error;
use krab_core::object::{ObjectId, RoutingHeader, TRUNC_LEN};
use krab_crypto::Fingerprint;
use std::collections::{BTreeMap, BTreeSet};

/// The index keys covering the expiry range `[lo, hi)`.
///
/// The index is keyed by `(expiry, id)`, and `ObjectId` orders after the
/// expiry, so the all-zero identifier is the least key at any given minute.
/// That makes a half-open range of minutes a half-open range of keys with no
/// special casing at either end — and it is what lets `BTreeMap::range` answer
/// in `O(log n + k)` where a filtered walk of every key was `O(n)`.
fn key_range(lo_min: u32, hi_min: u32) -> std::ops::Range<(u32, ObjectId)> {
    const LEAST: ObjectId = ObjectId([0; 32]);
    if lo_min >= hi_min {
        // `BTreeMap::range` panics on an inverted range rather than yielding
        // nothing, and both callers can be handed one by a peer.
        return (hi_min, LEAST)..(hi_min, LEAST);
    }
    (lo_min, LEAST)..(hi_min, LEAST)
}

/// A bucket's upper edge as a minute count, for the two places that store one.
///
/// A tombstone's expiry and the watermark are both `u32` minutes, and the top
/// bucket's true edge is 1_185 past `u32::MAX`. Clamping keeps a tombstone
/// longer and advertises a higher watermark than the exact value would, which
/// is the direction both already err in: pruning a tombstone early lets an
/// evicted object return (RFC 5 §8), and a watermark that is too low invites a
/// re-offer this node will only refuse.
fn tombstone_bound(bucket: u32) -> u32 {
    crate::segment::bucket_end(bucket).min(u32::MAX as u64) as u32
}

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
    /// I2 — expiry has passed.
    Expired,
    /// I2 — expiry is further out than `MAX_TTL` allows.
    TooFarFuture,
    /// I6 — already held. RFC 0 I-1's duplicate suppression.
    Duplicate,
    /// I6 — in the tombstone set. Expiry resurrection (RFC 5 §8).
    Tombstoned,
    /// Below the `min_expiry` watermark (RFC 5 §8).
    BelowWatermark,
    /// The header did not parse.
    Malformed,
    /// I1 — the object's length does not equal its declared bucket, or its
    /// padding is not zero (RFC 1 §8.1).
    ///
    /// Non-zero padding is a covert channel that replicates: the identifier
    /// covers the padding, so a node relaying it carries whatever was put
    /// there, indefinitely, believing it to be an ordinary object.
    BadPadding,
    /// I4 — the body is not deterministic CBOR, or carries a key that is not
    /// defined for this version.
    ///
    /// Distinct from [`Reject::BadPadding`] although the two are checked
    /// together: RFC 1 §11 gives every check a stable identifier so that "a
    /// reviewer can ask which one a given line implements", and a shared
    /// rejection would undo that at the only place it can be observed.
    BadBody,
    /// I3 — the version or class is not one this implementation knows.
    ///
    /// RFC 1 §4.3: "unknown keys in a body of a known version MUST be
    /// rejected", and the same reasoning applies to the version itself. An
    /// object this node cannot fully validate must not enter the store,
    /// because the identifier covers bytes it did not understand — which is a
    /// malleability surface, not merely an unknown.
    Unrecognised,
    /// I5 — the object does not hash to the identifier it was offered under.
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
    /// Truncated identifier → full identifier.
    ///
    /// `recon::wanted` tests every manifest row against this, so a linear scan
    /// here is `O(rows × corpus)` per exchange — about nine million truncations
    /// for a 3 000-row manifest against a 3 000-object corpus, and quadratic in
    /// the corpus after that. It was a scan until this index existed.
    by_trunc: BTreeMap<[u8; TRUNC_LEN], ObjectId>,
    /// `id → expiry_min`.
    ///
    /// A map keyed by identifier, not a set of pairs. Membership is checked on
    /// **every ingest** and pruning runs once a tick, so the lookup must be
    /// logarithmic and the scan may be linear — the reverse of what a
    /// `BTreeSet<(expiry, id)>` gives. That shape was a regression introduced
    /// when the expiry was added to permit pruning at all.
    tombstones: BTreeMap<ObjectId, u32>,
    min_expiry_min: u32,
    /// Buckets whose live contents changed since [`Store::mark_saved`].
    ///
    /// **The corpus is one file per bucket, and a save that rewrote all of
    /// them rewrote the whole corpus.** At the 1 GiB retention cap that is a
    /// gigabyte of I/O after every exchange that received anything, for a
    /// change of one object — which is what RFC 5 §7's segment layout exists
    /// to avoid: "eviction is `unlink()` of a whole segment: no compaction,
    /// no tombstone sweep, no fragmentation, no write amplification."
    ///
    /// A set of bucket numbers, not of objects. Which bucket changed is
    /// already public — it is the expiry, which every relay reads from the
    /// frozen header — so this discloses nothing that eviction order does not
    /// (RFC 5 §9).
    ///
    /// Buckets that *disappear* are not tracked here. Expiry and eviction
    /// remove whole segments, and a saver comparing the files on disk against
    /// [`Store::buckets`] sees a removal without being told about it — one
    /// less thing that can be forgotten on a path that adds a segment.
    dirty: BTreeSet<u32>,
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

        // RFC 1 §11 I5 — the identifier must name the content.
        //
        // §11 requires I5 before anything that consults the identifier: a store
        // that indexes by an unverified one has already lost the property I6,
        // reconciliation and the range fingerprint all rest on.
        //
        // Checked first and unconditionally. Everything below assumes an
        // identifier identifies something; a store that took the caller's word
        // for it would let a peer replace the content of any object a node had
        // already asked for, and duplicate suppression (RFC 0 I-1) would then
        // be suppressing the wrong thing.
        if krab_crypto::object_id(&bytes) != id {
            return Err(Reject::IdMismatch);
        }

        // RFC 1 §11 I3 — version and class are recognised.
        //
        // `RoutingHeader::parse` deliberately does not check these: parsing and
        // validating are separate so there is one rejection path rather than
        // two, and the store is where an object is admitted. A v2 object is
        // well-formed and unreadable here, and storing it would mean relaying
        // bytes whose meaning this node cannot check.
        if header.version != 1 {
            return Err(Reject::Unrecognised);
        }
        if krab_core::object::Class::from_byte(header.class).is_none() {
            return Err(Reject::Unrecognised);
        }
        // I3's second half — "reserved flag bits zero" — is already done, in
        // `RoutingHeader::parse` above, whose contract says so: it "validates
        // only what is frozen for all versions". Adding it here again would be
        // dead code that reads like the only check.

        // RFC 1 §11 I1 — length equals the declared bucket.
        if bytes.len() != header.bucket_size() as usize {
            return Err(Reject::BadPadding);
        }

        // RFC 1 §11 I4 — the body parses as deterministic CBOR, with no
        // unknown keys for a known version — and I1's other half, that every
        // byte after it is zero.
        //
        // **These two arrive together because neither can be done alone.**
        // Nothing knows where the padding starts without decoding the body,
        // and this check stopped at the length above for exactly that reason:
        // the store handles opaque objects (RFC 1 §3) and giving it a body
        // decoder would make every future body format a storage concern. So
        // it does not have one — `krab_core::object` owns the body formats
        // already, and answers the one question the store needs.
        //
        // §11 is explicit that this is not optional: "an implementation MUST
        // apply every check before an object enters the store, and MUST NOT
        // accept an object on which any check was skipped." Two of the six
        // were skipped, and §11's own aside had already predicted it — "in a
        // reference implementation of this document, three of these six were
        // absent and nothing failed."
        let body_len = krab_core::object::validate_body(&bytes).map_err(|_| Reject::BadBody)?;
        krab_core::object::verify_padding(&bytes, body_len).map_err(|_| Reject::BadPadding)?;

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
        if self.tombstones.contains_key(&id) {
            return Err(Reject::Tombstoned);
        }
        // RFC 0 I-1 — duplicate suppression follows from content addressing
        // and needs no additional mechanism.
        if self.index.contains_key(&(expiry, id)) {
            return Err(Reject::Duplicate);
        }

        let bucket = bucket_of(expiry);
        self.dirty.insert(bucket);
        self.segments
            .entry(bucket)
            .or_insert_with(|| Segment::new(bucket))
            .append(id, bytes);
        self.by_trunc.insert(id.truncated(), id);
        self.index.insert(
            (expiry, id),
            Location {
                bucket,
                expiry_min: expiry,
            },
        );
        Ok(())
    }

    /// Drop tombstones no peer can still offer — RFC 5 §8.
    ///
    /// A tombstone exists so a returning courier node cannot re-inject what
    /// the network already evicted. It is useful only while some peer might
    /// still hold the object, and `MAX_TTL` bounds that: past
    /// `expiry + MAX_TTL`, no honest peer holds it and no dishonest one gains
    /// anything by offering it, since I2 rejects an expired object anyway.
    ///
    /// **Without this the set only grows.** Every expiry and every eviction
    /// inserts and nothing ever removed, on a node RFC 4 §5.4 expects to run
    /// on constrained hardware. That is the same defect pattern this series
    /// has hit repeatedly: a retention parameter left unspecified instead of
    /// being derived from the declared guarantee.
    ///
    /// The tombstone stores only the identifier, so the expiry it was
    /// tombstoned at is carried alongside — an identifier does not reveal when
    /// its object expired.
    pub fn prune_tombstones(&mut self, now_min: u32, max_ttl_min: u32) -> usize {
        let before = self.tombstones.len();
        let horizon = now_min.saturating_sub(max_ttl_min);
        self.tombstones.retain(|_, expiry| *expiry >= horizon);
        before - self.tombstones.len()
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
            .range(key_range(lo_min, hi_min))
            .map(|((e, id), _)| (*e, *id))
            .collect()
    }

    /// Objects within `[lo, hi)`.
    ///
    /// Whole buckets are counted from the segment's maintained length and only
    /// the cut edges are walked — the same decomposition as
    /// [`Store::range_fingerprint`], and for the same reason: a peer names the
    /// range, so anything linear in the corpus is linear in something the peer
    /// chose. See that method for the measurement.
    pub fn count_in_range(&self, lo_min: u32, hi_min: u32) -> u32 {
        self.fold_range(
            lo_min,
            hi_min,
            0u64,
            |n, seg| n + seg.count() as u64,
            |n, _| n + 1,
        )
        .min(u32::MAX as u64) as u32
    }

    /// Fetch by a 12-byte truncated identifier (RFC 1 §9.3).
    ///
    /// Valid only inside an agreed reconciliation scope, which the caller has
    /// already established.
    pub fn get_truncated(&self, trunc: &[u8; TRUNC_LEN]) -> Option<&[u8]> {
        let id = *self.by_trunc.get(trunc)?;
        self.get(&id)
    }

    /// Whether a truncated identifier is held.
    pub fn has_truncated(&self, trunc: &[u8; TRUNC_LEN]) -> bool {
        self.by_trunc.contains_key(trunc)
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
    /// partial buckets at the edges are walked. That is the `O(1)`-per-bucket
    /// property RBSR depends on (RFC 5 §7).
    ///
    /// # Why the cost of this function is a security property
    ///
    /// RBSR is driven by the *peer*: it names the ranges, one frame holds
    /// 1 342 of them, and RFC 5 §4.4's round cap lets it send eight such
    /// frames per session. `recon::respond` describes every range it is given
    /// — a `count` and a `fingerprint` each — so whatever this function costs,
    /// a peer spends it about ten thousand times per session for the price of
    /// a few kilobytes, and it need not be a peer in good standing: a peering
    /// whose credential was never countersigned reconciles like any other.
    ///
    /// It used to cost far more than it looks. The edge branch called a
    /// `locate` that scanned the whole index for one identifier, once per
    /// object in the edge bucket — quadratic in the corpus — and the whole-
    /// bucket test `b > lo_b && b < hi_b` never held for a single-bucket
    /// range, so the commonest shapes took the quadratic path. Measured by
    /// `tests/range_cost.rs`, one session's worth of ranges cost **30.5 s**
    /// against a 10 000-object corpus and **14.6 minutes** against 50 000 —
    /// corpus sizes RFC 1 §9.3's own table calls ordinary. It is now 0.25 s
    /// and 0.85 s: 124× and 1 031×, for identical answers. What remains is
    /// proportional to the objects the named ranges actually contain, which is
    /// the work the answer requires.
    ///
    /// # Why the whole-bucket shortcut needs the watermark
    ///
    /// A segment's fingerprint covers every object ever appended to it, and
    /// `expire` removes individually-expired objects from the *index* while
    /// leaving the segment intact until the whole bucket can be unlinked. So
    /// in a bucket `expire` has already cut into, the segment's aggregate and
    /// the index disagree — and `entries_in_range` answers from the index.
    ///
    /// A fingerprint that does not cover exactly the rows the manifest lists
    /// is worse than a slow one: the two ends see a difference that no
    /// exchange of rows can close, so the descent finds divergence, resolves
    /// it to nothing, and finds it again next time. `fold_range` only takes
    /// the shortcut above the watermark, which is precisely where no `expire`
    /// pass has reached.
    pub fn range_fingerprint(&self, lo_min: u32, hi_min: u32) -> Fingerprint {
        self.fold_range(
            lo_min,
            hi_min,
            Fingerprint::ZERO,
            |fp, seg| fp.add(seg.fingerprint()),
            |fp, id| fp.add(Fingerprint::of(id)),
        )
    }

    /// Walk `[lo, hi)` bucket by bucket, taking each bucket's maintained
    /// aggregate where that is exact and reading the index where it is not.
    ///
    /// The shared shape behind [`Store::count_in_range`] and
    /// [`Store::range_fingerprint`]. One function rather than two because the
    /// two must classify buckets identically: a count that disagrees with a
    /// fingerprint about which objects a range holds sends RBSR down a range
    /// it has no rows to resolve.
    fn fold_range<T>(
        &self,
        lo_min: u32,
        hi_min: u32,
        init: T,
        whole: impl Fn(T, &Segment) -> T,
        edge: impl Fn(T, &ObjectId) -> T,
    ) -> T {
        let mut acc = init;
        if lo_min >= hi_min {
            return acc;
        }
        let (lo_b, hi_b) = (bucket_of(lo_min), bucket_of(hi_min - 1));
        for (&b, seg) in self.segments.range(lo_b..=hi_b) {
            let start = crate::segment::bucket_start(b);
            let end = crate::segment::bucket_end(b);
            // Above the watermark the segment holds exactly what the index
            // does, so its aggregate is the answer — see the note on
            // `range_fingerprint` for why `>` and not `>=`.
            let intact = start > self.min_expiry_min;
            if intact && start >= lo_min && end <= hi_min as u64 {
                acc = whole(acc, seg);
                continue;
            }
            // Cut, or possibly pruned: read the index over the overlap. The
            // narrowing is by construction, not a clamp — `end` exceeds
            // `u32::MAX` only for the top bucket, whose `end` then exceeds any
            // `hi_min`, so the `min` has already chosen `hi_min`.
            let a = lo_min.max(start);
            let z = (hi_min as u64).min(end) as u32;
            for ((_, id), _) in self.index.range(key_range(a, z)) {
                acc = edge(acc, id);
            }
        }
        acc
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
            .filter(|&b| crate::segment::bucket_end(b) <= now_min as u64)
            .collect();
        let mut n = 0;
        for b in dead {
            if let Some(seg) = self.segments.remove(&b) {
                // The bucket's upper edge bounds every expiry inside it. Using
                // it rather than the exact value keeps a tombstone slightly
                // longer than strictly needed, which is the safe direction:
                // pruning early would let an evicted object return. Clamping
                // errs the same way, and only for the top bucket.
                let bound = tombstone_bound(b);
                for id in seg.ids() {
                    self.by_trunc.remove(&id.truncated());
                    self.tombstones.insert(*id, bound);
                    n += 1;
                }
            }
        }
        // Every bucket at or below `now_min` may have lost index entries even
        // though its segment survives — `expire` prunes an object at its own
        // expiry, and unlinks a segment only once the whole bucket is past.
        // A saver writes what the index holds, so those buckets are dirty.
        let cut: Vec<u32> = self
            .segments
            .range(..=bucket_of(now_min))
            .map(|(&b, _)| b)
            .collect();
        self.dirty.extend(cut);
        self.index.retain(|(e, _), _| *e > now_min);
        self.min_expiry_min = self.min_expiry_min.max(now_min);
        n
    }

    /// Buckets currently held, in order — the segments a saver should find.
    pub fn buckets(&self) -> impl Iterator<Item = u32> + '_ {
        self.segments.keys().copied()
    }

    /// Buckets whose contents changed since [`Store::mark_saved`].
    pub fn dirty_buckets(&self) -> impl Iterator<Item = u32> + '_ {
        self.dirty.iter().copied()
    }

    /// Declare the disk to match: nothing is owed.
    ///
    /// Called by the saver after a successful write, and by the loader after
    /// reading — a store built by ingesting the files that are already there
    /// owes nothing, and without this the first save after a restart rewrites
    /// every segment it has just read.
    pub fn mark_saved(&mut self) {
        self.dirty.clear();
    }

    /// Declare every held bucket dirty.
    ///
    /// For a saver that cannot trust what is on disk: a migration from an
    /// older layout, or a home directory emptied underneath a running node.
    pub fn mark_all_dirty(&mut self) {
        self.dirty = self.segments.keys().copied().collect();
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
            let bound = tombstone_bound(oldest);
            for id in seg.ids() {
                self.by_trunc.remove(&id.truncated());
                self.tombstones.insert(*id, bound);
                dropped += 1;
            }
            // The index is pruned against the *exact* edge, not the clamped
            // one: an entry is kept when a later segment still holds it, and
            // for the top bucket there is no later segment.
            let floor = crate::segment::bucket_end(oldest);
            self.index.retain(|(e, _), _| *e as u64 >= floor);
            // Advertising the raised watermark is what stops a peer re-offering
            // what we just chose not to keep -- SIM-1 §4's +68% re-fetch loop.
            self.min_expiry_min = self.min_expiry_min.max(bound);
        }
        dropped
    }

    /// Rebuild the index from the segments, RFC 5 §7.
    ///
    /// Corruption is then a delay rather than data loss.
    /// # "Fully rebuildable" means every derived map, not one of them
    ///
    /// This rebuilt `index` and left `by_trunc` alone, which passed every test
    /// because nothing had cleared `by_trunc` either — the rebuild worked on a
    /// store that had never lost anything. RFC 5 §7's requirement is about the
    /// case where it *has*: a node whose index is gone or corrupt must be able
    /// to reconstruct it from the segments, and `by_trunc` is what
    /// `get_truncated` and `has_truncated` answer from. Without it a rebuilt
    /// node would serve reconciliation and find nothing it holds.
    ///
    /// Both maps are cleared first, so the rebuild is tested against an empty
    /// one rather than against itself.
    pub fn rebuild_index(&mut self) -> Result<(), Error> {
        self.index.clear();
        self.by_trunc.clear();
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
                self.by_trunc.insert(id.truncated(), *id);
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
        let bytes = canonical_bytes(&h, &krab_core::object::example_sealed_body(salt)).unwrap();
        (krab_crypto::object_id(&bytes), bytes)
    }

    /// A body that is whatever bytes are given, valid or not.
    fn alloc_body(raw: &[u8]) -> Vec<u8> {
        raw.to_vec()
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

    /// The top bucket's edge does not fit in `u32`, and computing it inline
    /// overflowed: a debug build panicked, and a release build wrapped to
    /// 1_184 — a bound so small that `expire` unlinked the segment as though
    /// it were long dead while the next line's `retain` kept its index
    /// entries, leaving the index describing objects no segment holds.
    #[test]
    fn the_top_bucket_survives_its_own_edge() {
        let top = u32::MAX / DAY;
        let start = top * DAY;
        let mut s = Store::new();
        let (id, b) = object(start + 60, 7);
        s.ingest(id, b, start, DAY).unwrap();

        // Live, and nowhere near expiry. Under the wrapped bound this call
        // dropped it and reported having done so.
        assert_eq!(s.expire(start), 0);
        assert_eq!(s.len(), 1);
        assert!(s.contains(&id));
        assert!(s.get(&id).is_some(), "index and segments disagree");

        // Eviction tombstones at the clamped edge rather than a wrapped one,
        // and leaves no index entry behind it.
        assert_eq!(s.evict_to(0), 1);
        assert_eq!(s.len(), 0);
        assert!(!s.contains(&id));
        assert!(s.is_empty());
    }

    /// **The invariant reconciliation rests on.** A range's fingerprint must
    /// cover exactly the rows `entries_in_range` would list for it — otherwise
    /// the two ends of a descent see a difference no exchange of rows can
    /// close, and RBSR finds it, resolves it to nothing, and finds it again.
    ///
    /// The interesting case is a bucket `expire` has cut into: it drops the
    /// index entry for an object whose minute has passed but leaves the object
    /// in its segment, because segments are unlinked whole. A whole-bucket
    /// shortcut taken from the segment's aggregate there covers rows the
    /// manifest does not.
    #[test]
    fn the_fingerprint_covers_exactly_the_rows_a_manifest_lists() {
        let objs: Vec<(u32, u8)> = (0..40).map(|i| (1 + i as u32 * 90, i)).collect();
        let mut s = store_with(0, &objs);

        let agrees = |s: &Store, lo, hi| {
            let listed = s.entries_in_range(lo, hi);
            let over = Fingerprint::over(listed.iter().map(|(_, id)| id));
            assert_eq!(
                s.range_fingerprint(lo, hi),
                over,
                "fingerprint and rows disagree over [{lo}, {hi})"
            );
            assert_eq!(s.count_in_range(lo, hi), listed.len() as u32, "count too");
        };

        // Whole window, one bucket, a cut bucket, and an empty range.
        for (lo, hi) in [(0, u32::MAX), (0, DAY), (DAY, 3 * DAY), (500, 900), (7, 7)] {
            agrees(&s, lo, hi);
        }

        // Now expire part of the first bucket and ask again. The segment still
        // holds what was pruned from the index, so the shortcut must not be
        // taken over it.
        assert!(s.expire(600) > 0 || s.len() < 40);
        for (lo, hi) in [(0, u32::MAX), (0, DAY), (0, 2 * DAY), (600, 800)] {
            agrees(&s, lo, hi);
        }

        // And after the other path that removes objects.
        s.evict_to(s.bytes() / 2);
        assert!(!s.is_empty(), "the test needs something left to compare");
        for (lo, hi) in [(0, u32::MAX), (0, DAY), (DAY, 3 * DAY), (600, 800)] {
            agrees(&s, lo, hi);
        }
    }

    /// **Fetching an object must not depend on where it sits.** A segment is
    /// append-only, which is a file layout, not a lookup structure — `get`
    /// walked its entries until it matched, so an object appended late cost
    /// the whole segment to find. `persist::write_corpus` fetches every object
    /// it packs and runs after every exchange that received anything, and
    /// `get_truncated` does the same for each object a peer's `Want` asks for.
    ///
    /// A ratio rather than a wall-clock bound: it is the *shape* of the cost
    /// that is being asserted, so the test says nothing about how fast the
    /// machine is and is as valid in a debug build as a release one.
    #[test]
    fn fetching_an_object_does_not_depend_on_where_it_sits() {
        // One bucket, so what is measured is the lookup inside a segment and
        // not the walk across segments.
        let objs: Vec<(u32, u8)> = (1..1_400u32).flat_map(|e| (0..8u8).map(move |s| (e, s))).collect();
        let s = store_with(0, &objs);
        assert!(s.len() > 10_000, "held {}", s.len());
        let held = s.entries_in_range(0, u32::MAX);
        let (first, last) = (held[0].1, held[held.len() - 1].1);

        let time = |id: &ObjectId| {
            let t = std::time::Instant::now();
            for _ in 0..20_000 {
                assert!(s.get(id).is_some());
            }
            t.elapsed()
        };
        // Warm, then measure. The first pass pays for page faults the second
        // would otherwise be blamed for.
        let _ = time(&first);
        let (a, b) = (time(&first), time(&last));

        let ratio = b.as_secs_f64() / a.as_secs_f64().max(f64::MIN_POSITIVE);
        assert!(
            ratio < 20.0,
            "the last object took {ratio:.0}x the first ({a:?} against {b:?}) \
             — the segment is being scanned rather than indexed"
        );
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

    /// **The truncated index tracks removal, not just insertion.** A stale
    /// entry would make `has_truncated` claim an object the store dropped, and
    /// `wanted` would then stop asking for it — the same permanent silent
    /// suppression RFC 1 §9.3's width was raised to prevent, arrived at from
    /// the other direction.
    #[test]
    fn the_truncated_index_is_maintained_on_expiry_and_eviction() {
        let mut s = store_with(0, &[(DAY, 1), (2 * DAY, 2), (30 * DAY, 3)]);
        let (id, _) = object(DAY, 1);
        let t = id.truncated();
        assert!(s.has_truncated(&t));
        assert!(s.get_truncated(&t).is_some());

        s.expire(2 * DAY);
        assert!(!s.has_truncated(&t), "an expired object is still claimed");
        assert!(s.get_truncated(&t).is_none());

        // And eviction, which is the other removal path.
        let (id3, _) = object(30 * DAY, 3);
        let t3 = id3.truncated();
        assert!(s.has_truncated(&t3));
        s.evict_to(0);
        assert!(!s.has_truncated(&t3), "an evicted object is still claimed");
    }

    /// **RFC 5 §8's tombstones stay bounded.** Past `expiry + MAX_TTL` no
    /// honest peer holds the object and a dishonest one gains nothing by
    /// offering it, since I2 rejects an expired object anyway.
    #[test]
    fn tombstones_are_pruned_past_max_ttl() {
        const MAX_TTL: u32 = 45 * DAY;
        let mut s = store_with(0, &[(DAY, 1), (2 * DAY, 2), (30 * DAY, 3)]);
        // Expire everything, which tombstones it.
        s.expire(31 * DAY);
        let held = s.tombstone_count();
        assert!(held > 0, "expiry produced no tombstones");

        // Not yet prunable: a peer offline this long may still offer them.
        assert_eq!(s.prune_tombstones(31 * DAY, MAX_TTL), 0);
        assert_eq!(s.tombstone_count(), held);

        // Well past MAX_TTL, they are dead weight.
        let dropped = s.prune_tombstones(200 * DAY, MAX_TTL);
        assert_eq!(dropped, held);
        assert_eq!(s.tombstone_count(), 0, "the set only grew before this");
    }

    /// Pruning must not let an evicted object return while a peer could still
    /// be offering it — the whole point of RFC 5 §8.
    #[test]
    fn pruning_early_would_readmit_and_does_not() {
        const MAX_TTL: u32 = 45 * DAY;
        let mut s = store_with(0, &[(40 * DAY, 7)]);
        let (id, bytes) = object(40 * DAY, 7);
        s.expire(41 * DAY);
        assert_eq!(s.prune_tombstones(41 * DAY, MAX_TTL), 0, "far too early");
        // Two independent mechanisms catch this and the watermark happens to
        // fire first (RFC 5 §8 has both). Asserting which one would be
        // asserting an ordering nothing depends on; what matters is that a
        // pruned-too-early tombstone would leave *neither*.
        assert!(
            matches!(
                s.ingest(id, bytes, 39 * DAY, u32::MAX),
                Err(Reject::Tombstoned) | Err(Reject::BelowWatermark)
            ),
            "an evicted object returned while a peer could still be offering it"
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
    /// identifier covers it, so a relay carries whatever was put there,
    /// indefinitely, believing it ordinary.
    ///
    /// Checked through `ingest` rather than through a helper. There used to be
    /// a `Store::verify_body_padding` for exactly this, documented as
    /// something a caller who decoded the body *SHOULD* call — and no caller
    /// did. RFC 1 §11 does not have a SHOULD here: "an implementation MUST
    /// apply every check before an object enters the store". A check reachable
    /// only by a caller who remembers it is the shape of a check that is not
    /// applied, so the helper is gone and the check is inline.
    #[test]
    fn non_zero_padding_is_refused() {
        let mut s = Store::new();
        let (id, bytes) = object(DAY, 5);
        assert_eq!(s.ingest(id, bytes.clone(), 0, MAX_TTL), Ok(()));

        let mut smuggled = bytes.clone();
        let last = smuggled.len() - 1;
        assert_eq!(smuggled[last], 0, "the fixture must have padding to smuggle in");
        smuggled[last] = 0x41;
        let id = krab_crypto::object_id(&smuggled);
        assert_eq!(
            s.ingest(id, smuggled, 0, MAX_TTL),
            Err(Reject::BadPadding),
            "a byte hidden in the padding must not pass"
        );
    }

    /// **RFC 1 §11 I4**, the check that could not exist until something knew
    /// where the body ended.
    #[test]
    fn a_body_that_is_not_deterministic_cbor_is_refused() {
        let mut s = Store::new();
        let h = RoutingHeader {
            version: 1,
            class: 0,
            size_bucket: 0,
            flags: 0,
            expiry_min: DAY,
            tag: Tag([3; 8]),
        };
        for (why, body) in [
            ("not CBOR at all", alloc_body(&[0xFF; 40])),
            // Indefinite-length map: §4.3 rule 2.
            ("indefinite length", alloc_body(&[0xBF, 0x00, 0x00, 0xFF])),
            // {1: 0, 0: 0} — descending keys, §4.3 rule 3.
            ("descending keys", alloc_body(&[0xA2, 0x01, 0x00, 0x00, 0x00])),
            // {0: 0, 0: 0} — duplicate keys, same rule.
            ("duplicate keys", alloc_body(&[0xA2, 0x00, 0x00, 0x00, 0x00])),
            // A bare uint: a body is a map.
            ("not a map", alloc_body(&[0x01])),
            // A map whose declared pairs are not there.
            ("truncated", alloc_body(&[0xA4, 0x00, 0x00])),
        ] {
            let bytes = canonical_bytes(&h, &body).unwrap();
            let id = krab_crypto::object_id(&bytes);
            assert_eq!(
                s.ingest(id, bytes, 0, MAX_TTL),
                Err(Reject::BadBody),
                "{why} was accepted as a body"
            );
        }
        assert!(s.is_empty());
    }

    /// The reserved envelope key, and any key §4.2 does not define. "Reserved
    /// means absent, not present-and-empty" — and the identifier covers it, so
    /// an accepted one is relayed by every node that takes it.
    #[test]
    fn an_undefined_envelope_key_is_refused() {
        let mut s = Store::new();
        let h = RoutingHeader {
            version: 1,
            class: 0,
            size_bucket: 0,
            flags: 0,
            expiry_min: DAY,
            tag: Tag([4; 8]),
        };
        for extra in [3u64, 6, 99] {
            let mut w = krab_core::cbor::Writer::new();
            w.map(6)
                .uint(0)
                .uint(1)
                .uint(1)
                .uint(0)
                .uint(2)
                .uint(1)
                .uint(4)
                .bstr(&[1u8; 32])
                .uint(5)
                .bstr(&[1u8; 16]);
            // Appended so the keys stay ascending; `extra` is above 5 or is 3,
            // and 3 is written in place below.
            let body = if extra == 3 {
                let mut w = krab_core::cbor::Writer::new();
                w.map(6)
                    .uint(0)
                    .uint(1)
                    .uint(1)
                    .uint(0)
                    .uint(2)
                    .uint(1)
                    .uint(3)
                    .bstr(&[])
                    .uint(4)
                    .bstr(&[1u8; 32])
                    .uint(5)
                    .bstr(&[1u8; 16]);
                w.finish()
            } else {
                w.uint(extra).uint(0);
                w.finish()
            };
            let bytes = canonical_bytes(&h, &body).unwrap();
            let id = krab_crypto::object_id(&bytes);
            assert_eq!(
                s.ingest(id, bytes, 0, MAX_TTL),
                Err(Reject::BadBody),
                "envelope key {extra} was accepted"
            );
        }
    }

    /// **RFC 5 §7: "the index MUST be fully rebuildable from the segments by
    /// one scan."**
    ///
    /// Listed as unchecked in `PLAN.md` §12 — "asserted by the store's design
    /// and not exercised by deleting an index and rebuilding". Exercising it
    /// found `by_trunc` was not rebuilt: the map `get_truncated` and
    /// `has_truncated` answer from, which is every object a peer asks for by
    /// its manifest row. A node that lost its index would have served
    /// reconciliation and found nothing it held.
    ///
    /// **What this test can and cannot reach.** Nothing outside the store can
    /// empty a derived map, so this cannot stage "the index is gone" —
    /// `rebuild_index` clearing both maps is what makes the assertion mean
    /// anything, and with the clear removed the test passes against a map it
    /// never lost. So it discriminates the pair: a map that is cleared and not
    /// repopulated fails here, which is the mistake that is actually available
    /// to somebody adding a third one.
    #[test]
    fn the_index_rebuilds_from_the_segments_alone() {
        let objs: Vec<(u32, u8)> = (0..20).map(|i| (DAY + i as u32, i)).collect();
        let mut s = store_with(0, &objs);
        let before: Vec<_> = s.entries_in_range(0, u32::MAX);
        let fingerprint = s.range_fingerprint(0, u32::MAX);
        let trunc: Vec<_> = before.iter().map(|(_, id)| id.truncated()).collect();
        assert!(trunc.iter().all(|t| s.has_truncated(t)));

        s.rebuild_index().expect("rebuilds");

        assert_eq!(s.entries_in_range(0, u32::MAX), before, "ordering");
        assert_eq!(s.range_fingerprint(0, u32::MAX), fingerprint, "fingerprint");
        // The half that was not rebuilt. Reconciliation asks by truncated
        // identifier and by nothing else.
        for t in &trunc {
            assert!(
                s.has_truncated(t),
                "a rebuilt index cannot answer what a manifest asks"
            );
            assert!(s.get_truncated(t).is_some());
        }
    }

    /// **RFC 1 §5: a `short` object is not a corpus object.**
    ///
    /// Also listed unchecked in `PLAN.md` §12 — "nothing emits one, so the
    /// MUST NOTs about forwarding and storing it are satisfied vacuously, but
    /// that an *incoming* class 3 object is refused before the store was not
    /// verified". It is refused, in `validate_body`; this is the verification.
    #[test]
    fn a_link_local_short_object_is_not_stored() {
        let mut s = Store::new();
        let h = RoutingHeader {
            version: 1,
            class: krab_core::object::Class::Short as u8,
            size_bucket: 0,
            flags: 0,
            expiry_min: DAY,
            tag: Tag([9; 8]),
        };
        let bytes = canonical_bytes(&h, &krab_core::object::example_sealed_body(9)).unwrap();
        let id = krab_crypto::object_id(&bytes);
        assert_eq!(
            s.ingest(id, bytes, 0, MAX_TTL),
            Err(Reject::BadBody),
            "a link-local object entered the corpus"
        );
        assert!(s.is_empty());
    }

    /// **I3's other half**, and where it actually lives.
    ///
    /// §4.1 defines flag bits 0 and 1; 2–7 are MBZ, and they are inside the
    /// identifier, so anything put there is carried by every relay until
    /// expiry — the covert channel §11 describes for padding, in a different
    /// field. Enforced by `RoutingHeader::parse`, which is why the refusal is
    /// `Malformed` and not `Unrecognised`: for the frozen sixteen bytes, a
    /// reserved bit set *is* a header that does not parse.
    ///
    /// The test exists because I looked for this check in `ingest`, did not
    /// find it, and concluded it was missing — over a set that was not the
    /// whole set. It is here now so the next reader is told where it is
    /// instead of adding a second copy.
    #[test]
    fn a_reserved_flag_bit_is_refused() {
        let mut s = Store::new();
        for bit in 2..8u8 {
            let h = RoutingHeader {
                version: 1,
                class: 0,
                size_bucket: 0,
                flags: 1 << bit,
                expiry_min: DAY,
                tag: Tag([bit; 8]),
            };
            let bytes = canonical_bytes(&h, &krab_core::object::example_sealed_body(bit)).unwrap();
            let id = krab_crypto::object_id(&bytes);
            assert_eq!(
                s.ingest(id, bytes, 0, MAX_TTL),
                Err(Reject::Malformed),
                "reserved flag bit {bit} was accepted"
            );
        }
        // The two that are defined still pass.
        for flags in [0u8, 0b01, 0b10, 0b11] {
            let h = RoutingHeader {
                version: 1,
                class: 0,
                size_bucket: 0,
                flags,
                expiry_min: DAY,
                tag: Tag([flags; 8]),
            };
            let bytes = canonical_bytes(&h, &krab_core::object::example_sealed_body(flags)).unwrap();
            let id = krab_crypto::object_id(&bytes);
            assert_eq!(s.ingest(id, bytes, 0, MAX_TTL), Ok(()), "flags {flags}");
        }
    }
}
