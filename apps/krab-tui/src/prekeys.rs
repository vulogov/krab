//! Prekeys on the wire and at rest — wiring `krab_crypto::prekey` to a node.
//!
//! The cryptography is in `krab_crypto::prekey`; this is the encoding of a
//! batch for publication, and of a ring for storage.
//!
//! # What a prekey buys
//!
//! Without one, every sealed message to a correspondent is encapsulated to
//! their **correspondence key**, which is permanent. An adversary who obtains
//! that key opens every message ever sent to it, including ones recorded years
//! earlier. With prekeys, the exposure is bounded by the batch period: RFC 7
//! §5's whole point is that the identity key is never a decryption key.
//!
//! # Why "one-time" is a misnomer here
//!
//! A batch is **flooded**, so every correspondent has all of it and two
//! senders may independently choose prekey #7. The recipient cannot delete a
//! private half on use without losing the other sender's message.
//! `krab_crypto::prekey` handles this with a deterministic per-sender index
//! and retirement on a schedule; what matters at this layer is that the ring
//! keeps *every* outstanding key until its epoch passes.

use krab_core::cbor;
use krab_core::tag::Epoch;
use krab_crypto::dh::{PublicKey, SecretKey};
use krab_crypto::prekey::{PrekeyBatch, Ring, SignedPrekey};
#[cfg(test)]
use krab_crypto::sign::SigningKey;
use krab_crypto::sign::{Sig, VerifyingKey};

/// A batch as published, with the signed prekey that vouches for the tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    /// Identifies the batch, and enters `prekey::index_for`.
    pub batch_id: [u8; 32],
    /// The signed prekey's public half — RFC 7 §5.1's fallback when the batch
    /// is exhausted, and the tier that bounds exposure.
    pub signed_pk: [u8; 32],
    /// The epoch the signed prekey was created for. Part of its signature.
    pub signed_epoch: u32,
    /// The signed prekey's signature, by the author's identity key.
    pub signed_sig: [u8; 64],
    /// One-time public halves.
    pub keys: Vec<[u8; 32]>,
}

/// How many one-time keys a batch carries.
///
/// From `PrekeyBatch::size_for(received_per_day, republish_days)` at one
/// message a day and a fortnight between republications — and then checked
/// against `fits_in_object`, because a batch that does not fit in one object
/// cannot be flooded as one bulletin and would have to be split, which RFC 7
/// §5.3 does not describe.
pub const BATCH_KEYS: usize = 64;

impl Published {
    /// Encode for a bulletin payload. Deterministic CBOR, RFC 1 §4.3.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = cbor::Writer::new();
        let mut flat = Vec::with_capacity(self.keys.len() * 32);
        for k in &self.keys {
            flat.extend_from_slice(k);
        }
        w.map(5)
            .uint(1)
            .bstr(&self.batch_id)
            .uint(2)
            .bstr(&self.signed_pk)
            .uint(3)
            .uint(self.signed_epoch as u64)
            .uint(4)
            .bstr(&self.signed_sig)
            .uint(5)
            .bstr(&flat);
        w.finish()
    }

    /// Decode. **Pre-authentication input**: a batch arrives by flooding from
    /// anyone, so nothing here allocates on a declared count — the key vector
    /// is sized by the bytes that actually arrived.
    pub fn decode(bytes: &[u8]) -> Option<Published> {
        let mut r = cbor::Reader::new(bytes);
        let mut m = r.map().ok()?;
        if m.left() != 5 {
            return None;
        }
        let batch_id = bstr_at(&mut m, 1)?.try_into().ok()?;
        let signed_pk = bstr_at(&mut m, 2)?.try_into().ok()?;
        let signed_epoch = u32::try_from(uint_at(&mut m, 3)?).ok()?;
        let signed_sig: [u8; 64] = bstr_at(&mut m, 4)?.try_into().ok()?;
        let flat = bstr_at(&mut m, 5)?;
        if flat.len() % 32 != 0 {
            return None;
        }
        // A batch larger than this cannot have been produced by
        // `BATCH_KEYS`, and accepting an arbitrary one lets a flooded object
        // decide how much memory a reader spends.
        if flat.len() / 32 > BATCH_KEYS * 4 {
            return None;
        }
        let keys = flat
            .chunks_exact(32)
            .map(|c| c.try_into().expect("32 bytes"))
            .collect();
        Some(Published {
            batch_id,
            signed_pk,
            signed_epoch,
            signed_sig,
            keys,
        })
    }

    /// Whether the signed prekey really is this author's.
    ///
    /// **The one-time keys are not individually signed** — RFC 7 §5 signs the
    /// tier, not each key, and the batch as a whole travels inside a signed
    /// bulletin. So this checks what the tier claims, and the bulletin's own
    /// signature covers the rest. A caller that verified the bulletin and then
    /// skipped this would accept a batch whose *fallback* key was forged.
    pub fn verify_signed_prekey(&self, author: &[u8; 32]) -> bool {
        SignedPrekey::verify(
            &PublicKey(self.signed_pk),
            Epoch(self.signed_epoch),
            &Sig(self.signed_sig),
            &VerifyingKey::from_bytes(*author),
        )
    }

    /// The key a sender should encapsulate to, for this sender and batch.
    ///
    /// `prekey::index_for` is deterministic in the pair, so two messages from
    /// the same sender reuse one key rather than consuming the batch, and two
    /// *different* senders collide only by birthday. Returns the signed prekey
    /// when the batch is empty — RFC 7 §5.1's fallback, which is why an
    /// exhausted batch degrades rather than failing.
    pub fn key_for(&self, sender_node_id: &[u8; 32]) -> PublicKey {
        if self.keys.is_empty() {
            return PublicKey(self.signed_pk);
        }
        let i = krab_crypto::prekey::index_for(sender_node_id, &self.batch_id, self.keys.len());
        PublicKey(self.keys[i])
    }
}

/// Publish a fresh batch from `ring`.
pub fn publish(ring: &mut Ring, epoch: Epoch, rng: &mut impl Rng) -> Published {
    let batch: PrekeyBatch = ring.add_batch(BATCH_KEYS, epoch, rng);
    let signed = ring.signed();
    Published {
        batch_id: batch.batch_id,
        signed_pk: signed.public().0,
        signed_epoch: signed.epoch.0,
        signed_sig: signed.sig.0,
        keys: batch.keys.iter().map(|k| k.0).collect(),
    }
}

use krab_crypto::rng::Rng;

/// A ring, wrapped for storage under the epoch key.
///
/// Private halves, so this is never written unsealed — the caller seals it
/// with `kek::seal_under` exactly as it does the reservoir.
pub fn encode_ring(ring: &Ring) -> Vec<u8> {
    let signed = ring.signed();
    let mut w = cbor::Writer::new();
    // Batches keep their identifiers and epochs. A ring reloaded without them
    // cannot retire on schedule, and would either hold every key it ever
    // generated or drop keys that mail still in flight was sealed to.
    let mut batches = cbor::Writer::new();
    let b = ring.batches();
    batches.array(b.len() * 3);
    for (id, epoch, keys) in b {
        let mut flat = Vec::with_capacity(keys.len() * 32);
        for k in keys {
            flat.extend_from_slice(&k.to_bytes());
        }
        batches.bstr(id).uint(epoch.0 as u64).bstr(&flat);
    }
    w.map(4)
        .uint(1)
        .bstr(&signed.secret().to_bytes())
        .uint(2)
        .uint(signed.epoch.0 as u64)
        .uint(3)
        .bstr(&signed.sig.0)
        .uint(4)
        .bstr(&batches.finish());
    w.finish()
}

/// Rebuild a ring from storage.
pub fn decode_ring(bytes: &[u8]) -> Option<Ring> {
    let mut r = cbor::Reader::new(bytes);
    let mut m = r.map().ok()?;
    if m.left() != 4 {
        return None;
    }
    let secret: [u8; 32] = bstr_at(&mut m, 1)?.try_into().ok()?;
    let epoch = Epoch(u32::try_from(uint_at(&mut m, 2)?).ok()?);
    let sig: [u8; 64] = bstr_at(&mut m, 3)?.try_into().ok()?;
    let raw = bstr_at(&mut m, 4)?;

    let mut ring = Ring::new(SignedPrekey::from_parts(
        SecretKey::from_bytes(secret),
        epoch,
        Sig(sig),
    ));
    let mut br = cbor::Reader::new(raw);
    let mut batches = Vec::new();
    if let Ok(cbor::Item::Array(n)) = br.item() {
        for _ in 0..n / 3 {
            let (Ok(cbor::Item::Bstr(id)), Ok(cbor::Item::Uint(e)), Ok(cbor::Item::Bstr(flat))) =
                (br.item(), br.item(), br.item())
            else {
                break;
            };
            let (Ok(id), Ok(e)) = (<[u8; 32]>::try_from(id), u32::try_from(e)) else {
                break;
            };
            if flat.len() % 32 != 0 || flat.len() / 32 > BATCH_KEYS * 4 {
                break;
            }
            let keys = flat
                .chunks_exact(32)
                .map(|c| SecretKey::from_bytes(c.try_into().expect("32 bytes")))
                .collect();
            batches.push((id, Epoch(e), keys));
        }
    }
    ring.adopt(batches);
    Some(ring)
}

/// The private keys a node should try when opening an object.
///
/// **Every one, in a fixed order.** RFC 1 §6.3 forbids stopping at the first
/// success, so this is a set and not a search — see `krab_crypto::prekey`'s
/// module documentation for why an API that could return early eventually
/// does.
pub fn stored_candidates(bytes: &[u8]) -> Option<Vec<SecretKey>> {
    // Through `decode_ring`, so there is one definition of the stored shape.
    // There were two: the encoding grew batch epochs and this reader kept
    // parsing the flat form, so it silently returned nothing and every message
    // sealed to a prekey stopped opening.
    let ring = decode_ring(bytes)?;
    Some(
        ring.candidates()
            .into_iter()
            .map(|k| SecretKey::from_bytes(k.to_bytes()))
            .collect(),
    )
}

fn at<'a>(m: &mut cbor::MapReader<'a, '_>, k: u64) -> Option<cbor::Item<'a>> {
    (m.key().ok()?? == k).then_some(())?;
    m.value().ok()
}

fn uint_at(m: &mut cbor::MapReader, k: u64) -> Option<u64> {
    match at(m, k)? {
        cbor::Item::Uint(v) => Some(v),
        _ => None,
    }
}

fn bstr_at<'a>(m: &mut cbor::MapReader<'a, '_>, k: u64) -> Option<&'a [u8]> {
    match at(m, k)? {
        cbor::Item::Bstr(b) => Some(b),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use krab_crypto::rng::NotRandom;

    fn ring(seed: u64) -> (Ring, SigningKey) {
        let mut rng = NotRandom::seeded(seed);
        let id = SigningKey::generate(&mut rng);
        let signed = SignedPrekey::create(&id, Epoch(20_000), &mut rng);
        (Ring::new(signed), id)
    }

    #[test]
    fn a_published_batch_round_trips() {
        let (mut r, _id) = ring(1);
        let p = publish(&mut r, Epoch(20_000), &mut NotRandom::seeded(9));
        assert_eq!(p.keys.len(), BATCH_KEYS);
        assert_eq!(Published::decode(&p.encode()), Some(p));
    }

    /// The signed prekey is checked against the author, so a batch whose
    /// fallback key was swapped is refused even though the bulletin around it
    /// verifies.
    #[test]
    fn a_forged_signed_prekey_is_refused() {
        let (mut r, id) = ring(1);
        let author = id.verifying_key().to_bytes();
        let p = publish(&mut r, Epoch(20_000), &mut NotRandom::seeded(9));
        assert!(p.verify_signed_prekey(&author));

        let swapped = Published {
            signed_pk: [7u8; 32],
            ..p.clone()
        };
        assert!(
            !swapped.verify_signed_prekey(&author),
            "the tier is unchecked"
        );

        // And it is bound to the author, not merely well-formed.
        let (mut r2, id2) = ring(2);
        let other = publish(&mut r2, Epoch(20_000), &mut NotRandom::seeded(9));
        assert!(!other.verify_signed_prekey(&author));
        assert!(other.verify_signed_prekey(&id2.verifying_key().to_bytes()));
    }

    /// **Deterministic per sender.** Two messages from one sender reuse one
    /// key rather than consuming the batch; two senders collide only by
    /// birthday.
    #[test]
    fn the_chosen_key_is_a_function_of_the_sender_and_the_batch() {
        let (mut r, _) = ring(1);
        let p = publish(&mut r, Epoch(20_000), &mut NotRandom::seeded(9));

        let alice = [1u8; 32];
        let bob = [2u8; 32];
        assert_eq!(
            p.key_for(&alice).0,
            p.key_for(&alice).0,
            "not deterministic"
        );
        assert_ne!(
            p.key_for(&alice).0,
            p.key_for(&bob).0,
            "two senders got the same key — index_for is not spreading"
        );
        // And the chosen key is one that was actually published.
        assert!(p.keys.contains(&p.key_for(&alice).0));
    }

    /// **An exhausted batch degrades to the signed prekey** — RFC 7 §5.1 —
    /// rather than failing, which would make a node unreachable until it
    /// republished.
    #[test]
    fn an_empty_batch_falls_back_to_the_signed_prekey() {
        let (mut r, _) = ring(1);
        let mut p = publish(&mut r, Epoch(20_000), &mut NotRandom::seeded(9));
        p.keys.clear();
        assert_eq!(p.key_for(&[1u8; 32]).0, p.signed_pk);
    }

    /// A ring stores every outstanding private key, so a message to any
    /// published prekey still opens.
    #[test]
    fn a_stored_ring_yields_every_candidate() {
        let (mut r, _) = ring(1);
        let p = publish(&mut r, Epoch(20_000), &mut NotRandom::seeded(9));
        let stored = stored_candidates(&encode_ring(&r)).expect("decodes");

        // Signed prekey plus the batch. `Ring::candidates` already includes
        // the signed prekey, so the count is not off by one.
        assert!(stored.len() >= p.keys.len(), "keys were lost in storage");

        // Every published public key has its private half here.
        for pk in &p.keys {
            assert!(
                stored.iter().any(|sk| sk.public().0 == *pk),
                "a published prekey has no stored private half"
            );
        }
    }

    /// A flooded object must not decide how much memory a reader spends.
    #[test]
    fn an_absurd_batch_is_refused() {
        let mut w = cbor::Writer::new();
        w.map(5)
            .uint(1)
            .bstr(&[0u8; 32])
            .uint(2)
            .bstr(&[0u8; 32])
            .uint(3)
            .uint(1)
            .uint(4)
            .bstr(&[0u8; 64])
            .uint(5)
            .bstr(&vec![0u8; 32 * (BATCH_KEYS * 4 + 1)]);
        assert_eq!(Published::decode(&w.finish()), None);

        // And a key list that is not a whole number of keys.
        let mut w = cbor::Writer::new();
        w.map(5)
            .uint(1)
            .bstr(&[0u8; 32])
            .uint(2)
            .bstr(&[0u8; 32])
            .uint(3)
            .uint(1)
            .uint(4)
            .bstr(&[0u8; 64])
            .uint(5)
            .bstr(&[0u8; 33]);
        assert_eq!(Published::decode(&w.finish()), None);
    }

    /// Nothing an attacker floods causes a panic.
    #[test]
    fn malformed_input_is_refused_without_panicking() {
        assert_eq!(Published::decode(&[]), None);
        assert!(stored_candidates(&[]).is_none());
        let (mut r, _) = ring(1);
        let good = publish(&mut r, Epoch(20_000), &mut NotRandom::seeded(9)).encode();
        for cut in 0..good.len().min(400) {
            let _ = Published::decode(&good[..cut]);
        }
    }

    /// A batch has to fit in one object, or it cannot be flooded as one
    /// bulletin — and RFC 7 §5.3 does not describe splitting one.
    #[test]
    fn the_batch_size_fits_in_a_single_object() {
        assert!(
            PrekeyBatch::fits_in_object(BATCH_KEYS),
            "BATCH_KEYS does not fit in one object"
        );
    }
}
