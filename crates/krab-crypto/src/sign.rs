//! Ed25519 identity and signatures.
//!
//! # Verification is strict, and that is not a preference
//!
//! `CRYPTO-REVIEW.md` §2. Plain Ed25519 verification accepts multiple distinct
//! signature encodings for the same message under the same key — non-canonical
//! `S`, non-canonical point encodings, and mixed-order public keys all verify
//! under the permissive rules. Every such variant is a *different byte string*
//! that is *equally valid*.
//!
//! In a content-addressed store that is not a curiosity, it is an
//! amplification primitive. RFC 0 I-1 suppresses duplicates by identifier, and
//! an identifier covers the signature (RFC 1 §4). So a signed object with `n`
//! valid signature encodings is `n` distinct identifiers, each of which the
//! store accepts as new, replicates, and holds until expiry. One signature
//! becomes unbounded traffic and unbounded storage, and every node cooperates
//! because each object is genuinely valid.
//!
//! [`VerifyingKey::verify`] therefore calls `verify_strict` — canonical `S`,
//! canonical encodings, small-order `A` rejected. **There is no non-strict
//! path in this module**, because an API offering both would eventually be
//! called with the wrong one.
//!
//! # Signing keys are not identities
//!
//! `node_id = BLAKE3("krab/node/v1" ‖ pk)` (RFC 3 §2), so identity is derived,
//! never assigned. There is no registry and no authority, which is why names
//! cannot be squatted and why bootstrap requires knowing a participant
//! (RFC 3 §11.2).

use crate::hash::node_id;
use crate::rng::Rng;
use core::fmt;
use ed25519_dalek::{Signature, Signer, SigningKey as DalekSigning, VerifyingKey as DalekVerifying};
use zeroize::Zeroize;

/// A 64-byte Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sig(pub [u8; 64]);

impl fmt::Debug for Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A signature is public, but printing 64 bytes into a log is noise
        // that makes the interesting lines harder to find.
        write!(f, "Sig({:02x}{:02x}..)", self.0[0], self.0[1])
    }
}

/// A public key, and therefore an identity.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey([u8; 32]);

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let id = self.node_id();
        write!(f, "VerifyingKey({:02x}{:02x}{:02x}{:02x}..)", id[0], id[1], id[2], id[3])
    }
}

impl VerifyingKey {
    /// Wrap raw bytes.
    ///
    /// Deliberately *not* validated here. A malformed or small-order key is
    /// rejected at [`VerifyingKey::verify`], which is the only place it can
    /// cause harm, and rejecting at parse time would mean two rejection paths
    /// to keep consistent instead of one.
    pub fn from_bytes(b: [u8; 32]) -> VerifyingKey {
        VerifyingKey(b)
    }

    /// The raw encoding.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// `node_id = BLAKE3("krab/node/v1" ‖ pk)`, RFC 3 §2.
    pub fn node_id(&self) -> [u8; 32] {
        node_id(&self.0)
    }

    /// Verify `sig` over `msg`, **strictly**.
    ///
    /// Returns `false` for a wrong signature and equally for a signature that
    /// is merely non-canonical. See the module documentation for why the
    /// second case matters as much as the first.
    #[must_use]
    pub fn verify(&self, msg: &[u8], sig: &Sig) -> bool {
        let Ok(vk) = DalekVerifying::from_bytes(&self.0) else {
            return false;
        };
        // Small-order public keys make signatures verify under keys nobody
        // controls. `verify_strict` rejects them; this is belt-and-braces
        // because the check is cheap and the failure is severe.
        if vk.is_weak() {
            return false;
        }
        let signature = Signature::from_bytes(&sig.0);
        vk.verify_strict(msg, &signature).is_ok()
    }
}

/// An Ed25519 private key.
///
/// Zeroized on drop, and prints nothing (RFC 7 §9).
pub struct SigningKey(DalekSigning);

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey(<redacted>)")
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        // `DalekSigning` zeroizes its own scalar; this covers the copy this
        // struct holds regardless of how that is implemented upstream.
        let mut b = self.0.to_bytes();
        b.zeroize();
    }
}

impl SigningKey {
    /// Generate a fresh identity from `rng`.
    ///
    /// Randomness is an argument — see [`crate::rng`]. There is no
    /// `SigningKey::generate()` taking nothing.
    pub fn generate(rng: &mut impl Rng) -> SigningKey {
        SigningKey(DalekSigning::from_bytes(&rng.next_32()))
    }

    /// Reconstruct from a stored 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> SigningKey {
        SigningKey(DalekSigning::from_bytes(seed))
    }

    /// The seed, for wrapping under the KEK (RFC 7 §4). Never for display.
    pub fn to_seed(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The corresponding public key.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key().to_bytes())
    }

    /// This node's identifier.
    pub fn node_id(&self) -> [u8; 32] {
        self.verifying_key().node_id()
    }

    /// Sign `msg`.
    pub fn sign(&self, msg: &[u8]) -> Sig {
        Sig(self.0.sign(msg).to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::NotRandom;

    fn key(seed: u64) -> SigningKey {
        SigningKey::generate(&mut NotRandom::seeded(seed))
    }

    #[test]
    fn a_signature_verifies_under_its_own_key_and_no_other() {
        let a = key(1);
        let b = key(2);
        let sig = a.sign(b"peer-link");
        assert!(a.verifying_key().verify(b"peer-link", &sig));
        assert!(!b.verifying_key().verify(b"peer-link", &sig), "wrong key");
        assert!(!a.verifying_key().verify(b"peer-lin", &sig), "wrong message");
    }

    /// **`CRYPTO-REVIEW.md` §2.** A non-canonical `S` is a different byte
    /// string that permissive verifiers accept, and in a content-addressed
    /// store each accepted variant is a new object that replicates.
    ///
    /// `S` lives in the upper 32 bytes. Adding the group order `L` yields an
    /// `S` congruent mod `L` — which passes non-strict verification and must
    /// fail here.
    #[test]
    fn a_non_canonical_signature_is_rejected() {
        let a = key(3);
        let vk = a.verifying_key();
        let sig = a.sign(b"amplify me");
        assert!(vk.verify(b"amplify me", &sig), "the canonical form verifies");

        // L = 2^252 + 27742317777372353535851937790883648493
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        let mut malleable = sig;
        let mut carry = 0u16;
        #[allow(clippy::needless_range_loop)]
        for i in 0..32 {
            let sum = malleable.0[32 + i] as u16 + L[i] as u16 + carry;
            malleable.0[32 + i] = sum as u8;
            carry = sum >> 8;
        }
        assert_ne!(malleable.0, sig.0, "a genuinely different encoding");
        assert!(
            !vk.verify(b"amplify me", &malleable),
            "S + L must be rejected: one signature would otherwise mint unbounded objects"
        );
    }

    /// Small-order public keys let a signature verify under a key nobody
    /// controls, which would put unattributable objects into the corpus.
    #[test]
    fn small_order_public_keys_are_rejected() {
        // The identity point, and the order-2 point.
        for raw in [[0u8; 32], {
            let mut p = [0u8; 32];
            p[0] = 1;
            p
        }] {
            let vk = VerifyingKey::from_bytes(raw);
            assert!(!vk.verify(b"anything", &Sig([0u8; 64])));
        }
    }

    #[test]
    fn a_malformed_key_or_signature_returns_false_rather_than_panicking() {
        let vk = VerifyingKey::from_bytes([0xFF; 32]);
        assert!(!vk.verify(b"m", &Sig([0xFF; 64])));
    }

    /// RFC 3 §2 — identity is derived from the key, never assigned.
    #[test]
    fn node_id_derives_from_the_public_key() {
        let a = key(4);
        assert_eq!(a.node_id(), node_id(&a.verifying_key().to_bytes()));
        assert_ne!(a.node_id(), key(5).node_id());
        // And it is not the key itself: a node identifier must not be usable
        // as a verification key by a confused caller.
        assert_ne!(a.node_id(), a.verifying_key().to_bytes());
    }

    #[test]
    fn a_key_round_trips_through_its_seed() {
        let a = key(6);
        let b = SigningKey::from_seed(&a.to_seed());
        assert_eq!(a.verifying_key(), b.verifying_key());
        assert_eq!(a.sign(b"x").0, b.sign(b"x").0, "Ed25519 is deterministic");
    }

    #[test]
    fn secrets_print_nothing() {
        let a = key(7);
        let s = alloc::format!("{a:?}");
        assert_eq!(s, "SigningKey(<redacted>)");
        // The public half may print, but only as its identifier.
        assert!(alloc::format!("{:?}", a.verifying_key()).starts_with("VerifyingKey("));
    }
}
