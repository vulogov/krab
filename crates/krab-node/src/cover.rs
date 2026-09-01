//! Cover traffic — RFC 1 §5.3 and §8.2.
//!
//! ```text
//! Poisson-emitted dummies. Body is a `sealed` body whose ciphertext is
//! indistinguishable random bytes. Tag is drawn uniformly at random.
//!
//! Cover objects MUST be indistinguishable from `sealed` objects to any party
//! other than the emitter — which means they MUST use class 0, not class 2.
//! ```
//!
//! And §8.2:
//!
//! ```text
//! `cover` traffic MUST match the bucket distribution of real traffic or it
//! is trivially separable.
//! ```
//!
//! # Class 0, and why class 2 exists at all
//!
//! `Class::ReservedCover = 2` is in the enumeration and nothing may ever emit
//! it. A distinct class byte would make every cover object separable by
//! reading one byte, which is the exact opposite of the point — so §5.3
//! reserves the value only "so that no future version assigns it a meaning
//! that would make cover traffic distinguishable". [`Cover::emit`] writes
//! class 0 and there is a test that fails if it ever writes 2.
//!
//! # Matching the distribution, and the consequence nobody expects
//!
//! §8.2 is a MUST, and it has a sharp corollary: **a node that has not
//! observed real traffic cannot emit cover.** There is no distribution to
//! match yet, and inventing one — uniform over buckets, say — produces
//! exactly the "trivially separable" traffic §8.2 forbids. Worse, a node whose
//! cover is separable is *more* legible than one emitting none: an observer
//! who can strip the cover learns which objects were real, and additionally
//! learns that this node runs cover at all.
//!
//! So [`Cover::emit`] returns `None` until [`Cover::observe`] has been fed,
//! and that is a feature rather than a limitation to work around.
//!
//! # What is matched
//!
//! §8.2 names the bucket. This matches the **bucket and the body length**,
//! because both are visible: the object is bucket-sized, and its body is CBOR
//! whose ciphertext length anyone can read without a key. Matching the bucket
//! alone would leave every cover object carrying a body length drawn from a
//! different distribution than real mail, which is separable by the same
//! argument §8.2 makes about buckets.
//!
//! The sample is drawn from a bounded ring of the most recent shapes, so it
//! tracks how this node's traffic looks *now* rather than how it looked when
//! the process started.
//!
//! # What this cannot do
//!
//! Cover hides *which* objects are real from someone counting objects. It does
//! not hide volume from someone measuring bytes over time unless it is emitted
//! on a schedule that itself carries no information — which is why §5.3 says
//! Poisson, and why [`Cover::emit`] takes the decision to emit from the
//! caller's scheduler rather than making it here.
//!
//! RFC 0 §7.3 is the honest bound: "volume privacy requires cover traffic, and
//! cover traffic is unaffordable on a constrained link". This is affordable on
//! TCP and Tor and is not affordable on LoRa, and nothing here overrides a
//! link profile that says so.

use std::collections::{BTreeSet, VecDeque};
use krab_core::object::{canonical_bytes, Class, Envelope, ObjectId, RoutingHeader, BUCKETS};
use krab_crypto::rng::Rng;

/// How many recent real-traffic shapes are remembered — §8.2's distribution.
///
/// Bounded because this is a running node's memory, and 256 is enough to
/// sample a distribution over six buckets without pretending to more precision
/// than a node's own traffic supports.
pub const OBSERVATIONS: usize = 256;

/// How many of this node's own cover identifiers are remembered.
///
/// §5.3: "Emitters track their own cover objects locally." Bounded, because an
/// unbounded set is a slow leak — and losing the oldest entries costs only a
/// wasted decryption attempt on an object that will expire anyway.
pub const MAX_TRACKED: usize = 4_096;

/// The visible shape of an object: what an observer without a key can read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Shape {
    bucket: u8,
    body_len: u16,
}

/// Cover-traffic generation and the emitter's own record of it.
#[derive(Debug, Default)]
pub struct Cover {
    /// A ring of recent real shapes. Oldest is overwritten.
    seen: Vec<Shape>,
    at: usize,
    /// This node's own cover, so it is never mistaken for mail.
    mine: BTreeSet<ObjectId>,
    order: VecDeque<ObjectId>,
}

impl Cover {
    /// A fresh emitter that has observed nothing and will emit nothing.
    pub fn new() -> Cover {
        Cover::default()
    }

    /// Record the shape of a **real** object passing through this node.
    ///
    /// Feed this from ingest, not from emission: §8.2 wants the distribution
    /// of real traffic, and a node that fed its own cover back in would drift
    /// toward matching itself.
    pub fn observe(&mut self, bytes: &[u8], body_len: usize) {
        let Ok(h) = RoutingHeader::parse(bytes) else {
            return;
        };
        // A body that cannot fit its own bucket is not a shape worth copying.
        if h.size_bucket as usize >= BUCKETS.len() || body_len > u16::MAX as usize {
            return;
        }
        let shape = Shape {
            bucket: h.size_bucket,
            body_len: body_len as u16,
        };
        if self.seen.len() < OBSERVATIONS {
            self.seen.push(shape);
        } else {
            self.seen[self.at] = shape;
            self.at = (self.at + 1) % OBSERVATIONS;
        }
    }

    /// How many real shapes have been observed.
    pub fn observations(&self) -> usize {
        self.seen.len()
    }

    /// Whether this identifier is cover this node emitted — §5.3.
    ///
    /// A caller uses it to skip decryption attempts on its own dummies. It is
    /// **not** a security boundary: a `false` for cover this node has
    /// forgotten costs one failed decryption and nothing else.
    pub fn is_mine(&self, id: &ObjectId) -> bool {
        self.mine.contains(id)
    }

    /// Emit one cover object, or `None` if no distribution has been observed.
    ///
    /// `epoch` and `expiry_min` are written into the object exactly as a real
    /// one would carry them, because both are in the clear.
    pub fn emit(&mut self, epoch: u64, expiry_min: u32, rng: &mut impl Rng) -> Option<Vec<u8>> {
        // §8.2. See the module note: no distribution, no cover.
        if self.seen.is_empty() {
            return None;
        }
        let shape = self.seen[pick(rng, self.seen.len())];

        let mut tag = [0u8; 8];
        rng.fill(&mut tag);

        let header = RoutingHeader {
            version: krab_core::object::VERSION,
            // **Class 0, never 2.** RFC 1 §5.3.
            class: Class::Sealed as u8,
            size_bucket: shape.bucket,
            // Reserved bits zero, like any emitted object (RFC 1 §10).
            flags: 0,
            expiry_min,
            tag: krab_core::object::Tag(tag),
        };

        let body = random_body(epoch, shape.body_len as usize, rng)?;
        let bytes = canonical_bytes(&header, &body).ok()?;

        let id = krab_crypto::hash::object_id(&bytes);
        self.remember(id);
        Some(bytes)
    }

    fn remember(&mut self, id: ObjectId) {
        if self.mine.insert(id) {
            self.order.push_back(id);
            if self.order.len() > MAX_TRACKED {
                if let Some(old) = self.order.pop_front() {
                    self.mine.remove(&old);
                }
            }
        }
    }
}

/// Uniform in `0..n` from the caller's generator.
///
/// Rejection-sampled rather than `% n`, which biases toward low values when
/// `n` does not divide the range. The bias would be tiny here and it would
/// also be a *fingerprint* — cover that favours some buckets is cover that
/// does not match the distribution §8.2 requires.
fn pick(rng: &mut impl Rng, n: usize) -> usize {
    debug_assert!(n > 0);
    let limit = (u32::MAX as u64 + 1) - ((u32::MAX as u64 + 1) % n as u64);
    loop {
        let mut b = [0u8; 4];
        rng.fill(&mut b);
        let v = u32::from_le_bytes(b) as u64;
        if v < limit {
            return (v % n as u64) as usize;
        }
    }
}

/// A §4.2 envelope of `target` encoded bytes whose ciphertext is random.
///
/// # Why this iterates
///
/// The envelope is CBOR, so its encoded length is not a fixed offset from the
/// ciphertext length: the length prefix grows by a byte at 24, 256 and 65 536.
/// Solving analytically would mean encoding CBOR's size rules a second time
/// here, and getting that subtly wrong produces cover a byte off from real
/// traffic — which is a fingerprint, not a rounding error. Adjusting against
/// the real encoder is shorter and cannot disagree with it.
fn random_body(epoch: u64, target: usize, rng: &mut impl Rng) -> Option<Vec<u8>> {
    // `enc` is an HPKE encapsulated key: always 32 bytes, and random bytes are
    // exactly what a real one looks like.
    let mut enc = [0u8; 32];
    rng.fill(&mut enc);

    let mut ct_len = target.saturating_sub(48);
    for _ in 0..8 {
        let mut ct = vec![0u8; ct_len];
        rng.fill(&mut ct);
        let body = Envelope {
            epoch,
            // Pairwise. Inbox-mode cover would advertise that this node
            // accepts inbox traffic, which is a fact about its policy.
            tag_mode: 0,
            suite: 1,
            enc: &enc,
            ciphertext: &ct,
        }
        .write();
        match body.len().cmp(&target) {
            core::cmp::Ordering::Equal => return Some(body),
            core::cmp::Ordering::Less => ct_len += target - body.len(),
            core::cmp::Ordering::Greater => {
                let over = body.len() - target;
                ct_len = ct_len.checked_sub(over)?;
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use krab_crypto::rng::Rng;

    /// A deterministic generator, so a test that samples a distribution is
    /// reproducible.
    struct Fixed(u64);
    impl Rng for Fixed {
        fn fill(&mut self, out: &mut [u8]) {
            for b in out.iter_mut() {
                // xorshift64*
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                *b = (self.0 >> 24) as u8;
            }
        }
    }

    fn real(bucket: u8, body_len: usize) -> (Vec<u8>, usize) {
        let h = RoutingHeader {
            version: krab_core::object::VERSION,
            class: Class::Sealed as u8,
            size_bucket: bucket,
            flags: 0,
            expiry_min: 1_000,
            tag: krab_core::object::Tag([7; 8]),
        };
        let body = random_body(1, body_len, &mut Fixed(99)).expect("body");
        (canonical_bytes(&h, &body).unwrap(), body.len())
    }

    /// **§8.2's corollary: no observations, no cover.** A node that has not
    /// seen real traffic cannot match its distribution, and emitting anyway
    /// would produce exactly the separable traffic §8.2 forbids.
    #[test]
    fn a_node_that_has_seen_nothing_emits_nothing() {
        let mut c = Cover::new();
        assert_eq!(c.observations(), 0);
        assert!(c.emit(1, 5_000, &mut Fixed(1)).is_none());
    }

    /// **RFC 1 §5.3: class 0, never class 2.** A distinct class byte would
    /// make every cover object separable by reading one byte.
    #[test]
    fn cover_is_class_zero() {
        let mut c = Cover::new();
        let (bytes, blen) = real(1, 200);
        c.observe(&bytes, blen);
        for _ in 0..20 {
            let cover = c.emit(1, 5_000, &mut Fixed(7)).expect("no cover");
            let h = RoutingHeader::parse(&cover).unwrap();
            assert_eq!(h.class, Class::Sealed as u8);
            assert_ne!(h.class, Class::ReservedCover as u8);
            assert_ne!(h.class, 2);
        }
    }

    /// **A cover object is a well-formed object.** If it were not, every relay
    /// would reject it at RFC 1 §11 and it would be separable by the fact that
    /// it never propagates.
    #[test]
    fn cover_passes_the_ingest_checks_a_real_object_must() {
        let mut c = Cover::new();
        let (bytes, blen) = real(2, 900);
        c.observe(&bytes, blen);
        let cover = c.emit(3, 5_000, &mut Fixed(11)).expect("no cover");

        let h = RoutingHeader::parse(&cover).unwrap();
        assert_eq!(cover.len(), h.bucket_size() as usize, "wrong bucket size");
        let body_len = krab_core::object::validate_body(&cover).expect("body is not valid §4.2");
        krab_core::object::verify_padding(&cover, body_len).expect("padding is not zero");
    }

    /// **§8.2: the bucket distribution is matched.** Cover drawn against a
    /// node that only ever sees bucket 3 must only ever be bucket 3 — the
    /// property that makes it not "trivially separable".
    #[test]
    fn cover_matches_the_observed_bucket_distribution() {
        let mut c = Cover::new();
        let (bytes, blen) = real(3, 4_000);
        for _ in 0..10 {
            c.observe(&bytes, blen);
        }
        let mut rng = Fixed(23);
        for _ in 0..50 {
            let cover = c.emit(1, 5_000, &mut rng).expect("no cover");
            assert_eq!(RoutingHeader::parse(&cover).unwrap().size_bucket, 3);
        }
    }

    /// Two observed buckets both appear, so the sampler is not pinned to one.
    #[test]
    fn a_mixed_distribution_produces_a_mix() {
        let mut c = Cover::new();
        let (b0, l0) = real(0, 100);
        let (b4, l4) = real(4, 60_000);
        for _ in 0..50 {
            c.observe(&b0, l0);
            c.observe(&b4, l4);
        }
        let mut rng = Fixed(31);
        let mut seen = [0usize; BUCKETS.len()];
        for _ in 0..200 {
            let cover = c.emit(1, 5_000, &mut rng).expect("no cover");
            seen[RoutingHeader::parse(&cover).unwrap().size_bucket as usize] += 1;
        }
        assert!(seen[0] > 0 && seen[4] > 0, "one bucket never appeared: {seen:?}");
        let other: usize = seen.iter().enumerate().filter(|(i, _)| *i != 0 && *i != 4).map(|(_, n)| n).sum();
        assert_eq!(other, 0, "a bucket nobody observed was emitted: {seen:?}");
    }

    /// **The body length is matched too**, because it is visible without a
    /// key — matching only the bucket would leave a second distribution
    /// separable by §8.2's own argument.
    #[test]
    fn cover_matches_the_observed_body_length() {
        let mut c = Cover::new();
        let (bytes, blen) = real(2, 1_500);
        c.observe(&bytes, blen);
        let cover = c.emit(1, 5_000, &mut Fixed(41)).expect("no cover");
        assert_eq!(krab_core::object::validate_body(&cover).unwrap(), blen);
    }

    /// **The tag is uniformly random** — RFC 1 §5.3 — so two cover objects do
    /// not share one, and cover is not linkable by tag.
    #[test]
    fn the_tag_is_random() {
        let mut c = Cover::new();
        let (bytes, blen) = real(1, 300);
        c.observe(&bytes, blen);
        let mut rng = Fixed(53);
        let mut tags = BTreeSet::new();
        for _ in 0..50 {
            let cover = c.emit(1, 5_000, &mut rng).expect("no cover");
            tags.insert(RoutingHeader::parse(&cover).unwrap().tag.0);
        }
        assert_eq!(tags.len(), 50, "cover tags repeated");
    }

    /// Two cover objects differ in their ciphertext, so they are not linkable
    /// by content either.
    #[test]
    fn two_cover_objects_are_not_identical() {
        let mut c = Cover::new();
        let (bytes, blen) = real(1, 300);
        c.observe(&bytes, blen);
        let mut rng = Fixed(67);
        let a = c.emit(1, 5_000, &mut rng).unwrap();
        let b = c.emit(1, 5_000, &mut rng).unwrap();
        assert_ne!(a, b);
    }

    /// **§5.3: emitters track their own cover**, and the record is bounded.
    #[test]
    fn the_emitter_remembers_its_own_cover_and_stays_bounded() {
        let mut c = Cover::new();
        let (bytes, blen) = real(0, 100);
        c.observe(&bytes, blen);
        let mut rng = Fixed(71);

        let mine = c.emit(1, 5_000, &mut rng).unwrap();
        let id = krab_crypto::hash::object_id(&mine);
        assert!(c.is_mine(&id));
        // A real object is not mistaken for cover.
        assert!(!c.is_mine(&krab_crypto::hash::object_id(&bytes)));

        for _ in 0..MAX_TRACKED + 50 {
            let _ = c.emit(1, 5_000, &mut rng);
        }
        assert!(c.mine.len() <= MAX_TRACKED, "the record grew unbounded");
        assert_eq!(c.mine.len(), c.order.len(), "the two halves drifted");
    }

    /// The observation ring is bounded and keeps working past its capacity.
    #[test]
    fn the_observation_ring_is_bounded() {
        let mut c = Cover::new();
        let (bytes, blen) = real(1, 300);
        for _ in 0..OBSERVATIONS * 3 {
            c.observe(&bytes, blen);
        }
        assert_eq!(c.observations(), OBSERVATIONS);
        assert!(c.emit(1, 5_000, &mut Fixed(83)).is_some());
    }

    /// A malformed observation is ignored rather than poisoning the
    /// distribution with a shape no real object has.
    #[test]
    fn a_malformed_observation_is_ignored() {
        let mut c = Cover::new();
        c.observe(&[], 0);
        c.observe(&[0u8; 4], 0);
        assert_eq!(c.observations(), 0);
        assert!(c.emit(1, 5_000, &mut Fixed(97)).is_none());
    }

    /// `pick` is uniform enough that no value is starved — a biased sampler
    /// would be a fingerprint, not a rounding error.
    #[test]
    fn the_sampler_reaches_every_value() {
        let mut rng = Fixed(101);
        let mut seen = [0usize; 6];
        for _ in 0..6_000 {
            seen[pick(&mut rng, 6)] += 1;
        }
        for (i, n) in seen.iter().enumerate() {
            assert!(*n > 700, "value {i} drawn only {n} times in 6000: {seen:?}");
        }
    }
}
