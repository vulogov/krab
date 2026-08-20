//! Three-tier prekeys — RFC 7 §5, RFC 1 §6.3.
//!
//! ```text
//! identity (Ed25519)            permanent, signs only
//!   └─ signed prekey (X25519)     rotates weekly–monthly
//!        └─ one-time prekeys       batch, single use
//! ```
//!
//! **The identity key is never a decryption key**, so worst-case exposure is
//! the signed-prekey rotation period rather than for ever. Batches are
//! published as signed `bulletin` objects (RFC 1 §5.2) — the corpus is the
//! prekey server, which is X3DH with no infrastructure.
//!
//! # One-time prekeys are not one-time
//!
//! Signal's server hands each key to exactly one requester and deletes it. A
//! Krab batch is **flooded**, so every correspondent receives the same batch
//! and two senders may independently pick prekey #7. The recipient therefore
//! cannot delete a private half on use without losing the second message.
//!
//! RFC 7 §5.2 requires both mitigations, and this module implements both:
//!
//! - **A deterministic per-sender index** ([`index_for`]) makes a collision a
//!   birthday problem rather than a certainty.
//! - **Delete on schedule, never on use** ([`Ring::retire`]). There is no
//!   method that consumes a key, and that absence is the mechanism.
//!
//! Forward-secrecy granularity is therefore the **batch period, not the
//! message**. That is weaker than Signal and is the honest consequence of
//! having no server.
//!
//! # Selection must leak nothing, including through timing
//!
//! RFC 1 §6.3: "The envelope MUST NOT indicate which recipient key was used …
//! Tier, rotation epoch, and exhaustion state leak similarly and are equally
//! forbidden."
//!
//! And the part that is easy to implement wrongly:
//!
//! > "Implementations MUST attempt the full set and **MUST NOT stop at first
//! > success**; early exit leaks index position, which correlates with prekey
//! > consumption and is a volume signal."
//!
//! [`Ring::candidates`] therefore returns *every* outstanding private key in a
//! fixed order, and the caller is expected to attempt all of them. There is no
//! `find` and no method that returns one key, because an API that could return
//! early is an API that eventually does.
//!
//! # Not available on a constrained link
//!
//! RFC 7 §5.4: even a 64-key batch is four times the LoRa object gate, so
//! **prekey forward secrecy is structurally unavailable to a LoRa-only
//! correspondent**. That is why the reservoir exists: it requires no
//! publishing of any kind after establishment, and is the only forward-secrecy
//! mechanism available on constrained links.

use crate::dh::{PublicKey, SecretKey};
use crate::rng::Rng;
use crate::sign::{Sig, SigningKey, VerifyingKey};
use alloc::vec::Vec;
use krab_core::object::MAX_OBJECT;
use krab_core::tag::{Epoch, LABEL_PREKEY_INDEX};

/// Domain label for a signed-prekey signature. Frozen.
///
/// Distinct from every other signing domain, per the general rule adopted into
/// RFC 3 §2.1: a signature over one document type is never valid over another.
pub const DOMAIN_PREKEY: &[u8] = b"krab/prekey/v1";

/// Bytes one published one-time prekey costs: the X25519 public key.
pub const PREKEY_WIRE: usize = 32;

/// Fixed cost of a published batch: signed prekey, its signature, the batch
/// identifier, epochs, and CBOR framing.
///
/// 120 bytes, which reproduces RFC 7 §5.3's published wire sizes exactly —
/// 8 312 B for 256 keys, 32 888 for 1 024, 65 656 for 2 048, and 262 264 for
/// 8 192, the last of which is the row §5.3 marks as exceeding `MAX_OBJECT`.
/// Pinned by `the_wire_sizes_reproduce_rfc7s_table`, so a change to the
/// encoding shows up against the RFC rather than quietly moving the cadence
/// bound.
pub const BATCH_OVERHEAD: usize = 120;

/// The middle tier — rotates weekly to monthly.
pub struct SignedPrekey {
    secret: SecretKey,
    /// The epoch this key was published for.
    pub epoch: Epoch,
    /// Ed25519 signature by the identity key over `DOMAIN_PREKEY ‖ pk ‖ epoch`.
    pub sig: Sig,
}

impl core::fmt::Debug for SignedPrekey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SignedPrekey(epoch: {})", self.epoch.0)
    }
}

impl SignedPrekey {
    /// The bytes an identity signs to publish a prekey.
    pub fn signed_bytes(pk: &PublicKey, epoch: Epoch) -> Vec<u8> {
        let mut out = Vec::with_capacity(DOMAIN_PREKEY.len() + 36);
        out.extend_from_slice(DOMAIN_PREKEY);
        out.extend_from_slice(&pk.0);
        out.extend_from_slice(&epoch.to_le_bytes());
        out
    }

    /// Generate and sign a prekey.
    ///
    /// The identity key signs and does not encrypt — RFC 7 §5.1's whole point.
    pub fn create(identity: &SigningKey, epoch: Epoch, rng: &mut impl Rng) -> SignedPrekey {
        let secret = SecretKey::generate(rng);
        let sig = identity.sign(&SignedPrekey::signed_bytes(&secret.public(), epoch));
        SignedPrekey { secret, epoch, sig }
    }

    /// Rebuild from stored parts.
    ///
    /// The signature is not re-checked here: it was verified when the key was
    /// created and this is the node's own sealed storage, not the wire. A
    /// caller reading someone *else's* signed prekey uses
    /// [`SignedPrekey::verify`].
    pub fn from_parts(secret: SecretKey, epoch: Epoch, sig: Sig) -> SignedPrekey {
        SignedPrekey { secret, epoch, sig }
    }

    /// The public half.
    pub fn public(&self) -> PublicKey {
        self.secret.public()
    }

    /// The private half, for decapsulation.
    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    /// Whether this prekey is genuinely signed by `identity`.
    ///
    /// The epoch is inside the signature, so a prekey cannot be replayed into
    /// a later rotation period to extend its life past what its owner intended.
    #[must_use]
    pub fn verify(pk: &PublicKey, epoch: Epoch, sig: &Sig, identity: &VerifyingKey) -> bool {
        identity.verify(&SignedPrekey::signed_bytes(pk, epoch), sig)
    }
}

/// A published batch of one-time prekeys.
///
/// The public halves. Flooded as a `bulletin`, so everyone has it — see the
/// module note on why "one-time" is a misnomer here.
pub struct PrekeyBatch {
    /// Identifies this batch, and enters [`index_for`].
    pub batch_id: [u8; 32],
    /// One-time public keys.
    pub keys: Vec<PublicKey>,
}

impl PrekeyBatch {
    /// Bytes this batch costs on the wire.
    pub fn wire_size(count: usize) -> usize {
        BATCH_OVERHEAD + count * PREKEY_WIRE
    }

    /// Whether a batch of `count` keys fits one object — RFC 7 §5.3.
    ///
    /// **Republish cadence is bounded by `MAX_OBJECT`.** A node receiving 100
    /// messages a day cannot republish monthly: the batch would not fit, and
    /// §5.3 requires high-traffic nodes republish weekly instead.
    pub fn fits_in_object(count: usize) -> bool {
        PrekeyBatch::wire_size(count) <= MAX_OBJECT as usize
    }

    /// Keys needed for a given traffic rate — RFC 7 §5.3.
    ///
    /// `received × republish_days × 1.5`, rounded up to a power of two. Group
    /// membership dominates: RFC 6's fan-out means a 20-person group delivers
    /// 19 messages per round to every member.
    pub fn size_for(received_per_day: u32, republish_days: u32) -> usize {
        let needed = (received_per_day as u64 * republish_days as u64 * 3 / 2).max(1);
        let mut n = 64usize;
        while (n as u64) < needed {
            n *= 2;
        }
        n
    }
}

/// The deterministic per-sender index — RFC 1 §6.3.
///
/// `i = H("krab/pkidx/v1" ‖ sender_id ‖ batch_id) mod N`
///
/// An optimisation, never a requirement: the recipient still attempts every
/// key ([`Ring::candidates`]), because a sender may not have used it and
/// because relying on it would make a mismatch look like a decryption failure.
///
/// **Not available in inbox mode.** First contact has no matched tag, so the
/// recipient does not know the sender and cannot compute the same index.
pub fn index_for(sender_id: &[u8; 32], batch_id: &[u8; 32], n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    let mut h = blake3::Hasher::new();
    h.update(LABEL_PREKEY_INDEX);
    h.update(sender_id);
    h.update(batch_id);
    let digest = h.finalize();
    let mut b = [0u8; 8];
    b.copy_from_slice(&digest.as_bytes()[..8]);
    (u64::from_le_bytes(b) % n as u64) as usize
}

/// A recipient's outstanding private keys.
///
/// Holds the signed prekey and the private halves of one or more batches — the
/// current one and any not yet retired, since RFC 7 §5.2 requires retirement on
/// a schedule rather than on use.
pub struct Ring {
    signed: SignedPrekey,
    /// `(batch_id, epoch published, private keys)`.
    batches: Vec<([u8; 32], Epoch, Vec<SecretKey>)>,
}

impl core::fmt::Debug for Ring {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Counts only. Exhaustion state is forbidden from the wire (RFC 1
        // §6.3) and there is no reason to put it in a log either.
        write!(f, "Ring(batches: {})", self.batches.len())
    }
}

impl Ring {
    /// A ring holding one signed prekey and no batches.
    pub fn new(signed: SignedPrekey) -> Ring {
        Ring {
            signed,
            batches: Vec::new(),
        }
    }

    /// Generate and adopt a batch, returning its public half for publication.
    pub fn add_batch(&mut self, count: usize, epoch: Epoch, rng: &mut impl Rng) -> PrekeyBatch {
        let secrets: Vec<SecretKey> = (0..count).map(|_| SecretKey::generate(rng)).collect();
        let keys: Vec<PublicKey> = secrets.iter().map(|s| s.public()).collect();

        // The batch identifier commits to its contents, so a batch cannot be
        // republished with different keys under the same name — which would
        // make `index_for` point somewhere else for the same sender.
        let mut h = blake3::Hasher::new();
        h.update(b"krab/batch/v1");
        for k in &keys {
            h.update(&k.0);
        }
        let batch_id = *h.finalize().as_bytes();

        self.batches.push((batch_id, epoch, secrets));
        PrekeyBatch { batch_id, keys }
    }

    /// **Every** outstanding private key, in a fixed order.
    ///
    /// RFC 1 §6.3: "Implementations MUST attempt the full set and MUST NOT stop
    /// at first success; early exit leaks index position, which correlates with
    /// prekey consumption and is a volume signal."
    ///
    /// So this returns the whole set and there is deliberately **no** method
    /// that returns one key or searches. A caller decapsulates against all of
    /// them and selects afterwards; an API that could return early is one that
    /// eventually does.
    ///
    /// The signed prekey is included, because §5.1's fallback on exhaustion
    /// must not be a separate code path — a distinct path is a distinct timing.
    pub fn candidates(&self) -> Vec<&SecretKey> {
        let mut out = Vec::with_capacity(self.total_keys() + 1);
        out.push(self.signed.secret());
        for (_, _, secrets) in &self.batches {
            out.extend(secrets.iter());
        }
        out
    }

    /// Retire batches published before `keep_from` — RFC 7 §5.2.
    ///
    /// **On a schedule, never on use.** A flooded batch reaches every
    /// correspondent, so two senders may pick the same key; deleting a private
    /// half when one message arrives loses the second. §5.2 sets the grace
    /// window at roughly twice the maximum delivery latency — weeks, on a
    /// courier route.
    ///
    /// There is no `consume` method anywhere in this module, and that absence
    /// is the mechanism rather than a convention.
    pub fn retire(&mut self, keep_from: Epoch) -> usize {
        let before = self.batches.len();
        self.batches.retain(|(_, epoch, _)| *epoch >= keep_from);
        before - self.batches.len()
    }

    /// The batches held, for storage.
    ///
    /// **With their epochs**, because [`Ring::retire`] is schedule-based and a
    /// ring reloaded without them cannot retire anything — it would either
    /// keep every key ever generated or drop keys that mail in flight was
    /// encapsulated to. RFC 1 §6.2 gives an object `MAX_TTL` to arrive.
    pub fn batches(&self) -> &[([u8; 32], Epoch, Vec<SecretKey>)] {
        &self.batches
    }

    /// Adopt stored batches.
    pub fn adopt(&mut self, batches: Vec<([u8; 32], Epoch, Vec<SecretKey>)>) {
        self.batches = batches;
    }

    /// Rotate the signed prekey — RFC 7 §5.1's weekly-to-monthly tier.
    pub fn rotate(&mut self, signed: SignedPrekey) {
        self.signed = signed;
    }

    /// The current signed prekey.
    pub fn signed(&self) -> &SignedPrekey {
        &self.signed
    }

    /// One-time keys still held.
    pub fn total_keys(&self) -> usize {
        self.batches.iter().map(|(_, _, s)| s.len()).sum()
    }

    /// Batches still held.
    pub fn batch_count(&self) -> usize {
        self.batches.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::NotRandom;

    const NOW: Epoch = Epoch(20_671);

    fn identity(seed: u64) -> SigningKey {
        SigningKey::generate(&mut NotRandom::seeded(seed))
    }

    fn ring(seed: u64) -> (Ring, SigningKey) {
        let id = identity(seed);
        let signed = SignedPrekey::create(&id, NOW, &mut NotRandom::seeded(seed + 100));
        (Ring::new(signed), id)
    }

    /// **RFC 7 §5.1 — the identity key signs and never decrypts.** Worst-case
    /// exposure is therefore the rotation period rather than for ever.
    #[test]
    fn the_identity_key_signs_and_is_not_a_decryption_key() {
        let (r, id) = ring(1);
        let pre = r.signed();
        assert!(SignedPrekey::verify(
            &pre.public(),
            pre.epoch,
            &pre.sig,
            &id.verifying_key()
        ));

        // The prekey's X25519 public half is unrelated to the Ed25519 identity.
        assert_ne!(pre.public().0, id.verifying_key().to_bytes());
        // And no candidate key is derived from the identity.
        for k in r.candidates() {
            assert_ne!(k.public().0, id.verifying_key().to_bytes());
        }
    }

    /// The epoch is inside the signature, so a prekey cannot be replayed into a
    /// later rotation period to outlive what its owner intended.
    #[test]
    fn a_signed_prekey_cannot_be_replayed_into_another_epoch() {
        let (r, id) = ring(2);
        let pre = r.signed();
        assert!(SignedPrekey::verify(
            &pre.public(),
            pre.epoch,
            &pre.sig,
            &id.verifying_key()
        ));
        assert!(!SignedPrekey::verify(
            &pre.public(),
            Epoch(NOW.0 + 1),
            &pre.sig,
            &id.verifying_key()
        ));
        // Nor attributed to another identity.
        assert!(!SignedPrekey::verify(
            &pre.public(),
            pre.epoch,
            &pre.sig,
            &identity(3).verifying_key()
        ));
    }

    /// **RFC 1 §6.3 — the full set, always.** The signed prekey is in the same
    /// list as the one-time keys, because §5.1's fallback on exhaustion must
    /// not be a separate code path: a distinct path is a distinct timing, and
    /// timing is exactly what §6.3 forbids leaking.
    #[test]
    fn the_candidate_set_is_complete_and_includes_the_fallback() {
        let (mut r, _) = ring(4);
        assert_eq!(r.candidates().len(), 1, "the signed prekey alone");

        r.add_batch(64, NOW, &mut NotRandom::seeded(5));
        assert_eq!(r.candidates().len(), 65, "batch plus the fallback");

        r.add_batch(64, Epoch(NOW.0 + 7), &mut NotRandom::seeded(6));
        assert_eq!(
            r.candidates().len(),
            129,
            "an unretired batch stays in the set"
        );

        // The order is fixed, so a caller cannot infer anything from position
        // across calls.
        let a: Vec<[u8; 32]> = r.candidates().iter().map(|k| k.public().0).collect();
        let b: Vec<[u8; 32]> = r.candidates().iter().map(|k| k.public().0).collect();
        assert_eq!(a, b);
    }

    /// **RFC 7 §5.2 — delete on schedule, never on use.** A flooded batch
    /// reaches everyone, so two senders may pick the same key; deleting a
    /// private half when one message arrives loses the second.
    #[test]
    fn keys_are_retired_by_schedule_and_never_by_use() {
        let (mut r, _) = ring(7);
        r.add_batch(32, NOW, &mut NotRandom::seeded(8));
        r.add_batch(32, Epoch(NOW.0 + 30), &mut NotRandom::seeded(9));
        assert_eq!(r.total_keys(), 64);

        // Using a key changes nothing — there is no method that could.
        let _ = r.candidates();
        let _ = r.candidates();
        assert_eq!(r.total_keys(), 64, "a key was consumed by being offered");

        // Only the schedule removes anything.
        assert_eq!(r.retire(Epoch(NOW.0 + 1)), 1);
        assert_eq!(r.total_keys(), 32);
        assert_eq!(r.retire(Epoch(NOW.0 + 31)), 1);
        assert_eq!(r.total_keys(), 0);

        // And the fallback survives exhaustion, which is §5.1's whole design.
        assert_eq!(r.candidates().len(), 1);
    }

    /// **RFC 1 §6.3's optimisation.** Both ends compute the same index from the
    /// sender identity and the batch, with nothing on the wire to say so.
    #[test]
    fn the_deterministic_index_agrees_on_both_sides() {
        let sender = [0x11u8; 32];
        let batch = [0x22u8; 32];
        for n in [64usize, 256, 1024] {
            let i = index_for(&sender, &batch, n);
            assert_eq!(i, index_for(&sender, &batch, n), "not deterministic");
            assert!(i < n, "index {i} out of range for {n}");
        }
        // Different senders land elsewhere, which is what makes a collision a
        // birthday problem rather than a certainty (RFC 7 §5.2).
        let mut seen = alloc::collections::BTreeSet::new();
        for s in 0u8..64 {
            seen.insert(index_for(&[s; 32], &batch, 256));
        }
        assert!(
            seen.len() > 40,
            "64 senders produced only {} indices",
            seen.len()
        );
        // And a different batch moves the same sender.
        assert_ne!(
            index_for(&sender, &batch, 256),
            index_for(&sender, &[0x33; 32], 256)
        );
    }

    /// A zero-length batch must not divide by zero — an exhausted node is an
    /// ordinary state, not an error.
    #[test]
    fn an_empty_batch_does_not_panic() {
        assert_eq!(index_for(&[1; 32], &[2; 32], 0), 0);
    }

    /// The batch identifier commits to its contents, so a batch cannot be
    /// republished with different keys under the same name — which would send
    /// `index_for` somewhere else for the same sender.
    #[test]
    fn the_batch_id_commits_to_its_keys() {
        let (mut a, _) = ring(10);
        let (mut b, _) = ring(11);
        let one = a.add_batch(16, NOW, &mut NotRandom::seeded(12));
        let two = b.add_batch(16, NOW, &mut NotRandom::seeded(12));
        assert_eq!(one.batch_id, two.batch_id, "same keys, same id");

        let (mut c, _) = ring(13);
        let three = c.add_batch(16, NOW, &mut NotRandom::seeded(99));
        assert_ne!(one.batch_id, three.batch_id, "different keys, different id");
    }

    /// **RFC 7 §5.3 — republish cadence is bounded by `MAX_OBJECT`.** A node
    /// receiving 100 messages a day cannot republish monthly.
    #[test]
    fn batch_sizing_matches_rfc7() {
        // §5.3's table.
        assert_eq!(PrekeyBatch::size_for(5, 30), 256);
        assert_eq!(PrekeyBatch::size_for(20, 7), 256);
        assert_eq!(PrekeyBatch::size_for(50, 7), 1_024);
        assert_eq!(PrekeyBatch::size_for(100, 7), 2_048);

        // The row that does not fit: 100/day republished monthly.
        let monthly = PrekeyBatch::size_for(100, 30);
        assert_eq!(monthly, 8_192);
        assert!(
            !PrekeyBatch::fits_in_object(monthly),
            "§5.3 says this exceeds MAX_OBJECT and it must be detectable"
        );
        // Weekly does fit, which is what §5.3 requires instead.
        assert!(PrekeyBatch::fits_in_object(PrekeyBatch::size_for(100, 7)));
    }

    /// **RFC 7 §5.3's wire sizes, to the byte.** These are published figures,
    /// and the last one is the boundary that forces weekly republication on a
    /// high-traffic node.
    #[test]
    fn the_wire_sizes_reproduce_rfc7s_table() {
        assert_eq!(PrekeyBatch::wire_size(256), 8_312);
        assert_eq!(PrekeyBatch::wire_size(1_024), 32_888);
        assert_eq!(PrekeyBatch::wire_size(2_048), 65_656);
        assert_eq!(PrekeyBatch::wire_size(8_192), 262_264);
        assert!(262_264 > MAX_OBJECT as usize, "§5.3's overflowing row");

        // §5.4's table.
        assert_eq!(PrekeyBatch::wire_size(64), 2_168);
        assert_eq!(PrekeyBatch::wire_size(128), 4_216);
        assert_eq!(PrekeyBatch::wire_size(512), 16_504);
    }

    /// **RFC 7 §5.4 — no batch crosses a LoRa link.** Even 64 keys is four
    /// times the gate, which is why the reservoir is the only forward-secrecy
    /// mechanism available on constrained links.
    #[test]
    fn no_batch_fits_a_lora_link() {
        const LORA_GATE: usize = 512;
        for n in [64usize, 128, 512, 2_048] {
            assert!(
                PrekeyBatch::wire_size(n) > LORA_GATE * 4,
                "a {n}-key batch is {} bytes and §5.4 says every batch is far over the gate",
                PrekeyBatch::wire_size(n)
            );
        }
    }

    #[test]
    fn a_ring_prints_no_secret_and_no_exhaustion_state() {
        let (mut r, _) = ring(14);
        r.add_batch(8, NOW, &mut NotRandom::seeded(15));
        let s = alloc::format!("{r:?}");
        assert_eq!(s, "Ring(batches: 1)");
        // Exhaustion state is forbidden on the wire (RFC 1 §6.3); there is no
        // reason to put it in a log either.
        assert!(!s.contains("8"), "{s}");
    }
}
