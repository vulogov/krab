//! X25519 — link statics and the correspondence key.
//!
//! Two distinct uses, deliberately not one key:
//!
//! - **Noise static** (RFC 4 §4.1), authenticating transport links.
//! - **Correspondence key** (RFC 2 §4.1), whose static-static agreement `S`
//!   seeds every pairwise tag with one peer.
//!
//! Sharing one key between them would tie a node's *network* identity to its
//! *tag* namespace, and RFC 2 §2's I-2 keeps those disjoint precisely so that
//! observing a link tells an adversary nothing about which tags to watch.
//!
//! # Low-order rejection
//!
//! `CRYPTO-REVIEW.md` §3. X25519 is not contributory: a peer who supplies a
//! low-order public key forces the shared secret to a fixed all-zero value
//! regardless of the other side's private key. Both parties then derive
//! identical tags from a secret the attacker also knows.
//!
//! [`agree`] returns `None` in that case rather than a zero secret. The check
//! is additive to RFC 1 §6.2 — it changes no derivation and forks no tag
//! space — so it is applied unconditionally.

use crate::rng::Rng;
use core::fmt;
use x25519_dalek::{PublicKey as DalekPublic, StaticSecret};

/// An X25519 public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(pub [u8; 32]);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({:02x}{:02x}..)", self.0[0], self.0[1])
    }
}

/// An X25519 private key. Zeroized on drop, prints nothing.
pub struct SecretKey(StaticSecret);

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

impl SecretKey {
    /// Generate from `rng`. Randomness is an argument — see [`crate::rng`].
    pub fn generate(rng: &mut impl Rng) -> SecretKey {
        SecretKey(StaticSecret::from(rng.next_32()))
    }

    /// Reconstruct from stored bytes.
    pub fn from_bytes(b: [u8; 32]) -> SecretKey {
        SecretKey(StaticSecret::from(b))
    }

    /// The clamped scalar, for wrapping under the KEK (RFC 7 §4).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The corresponding public key.
    pub fn public(&self) -> PublicKey {
        PublicKey(DalekPublic::from(&self.0).to_bytes())
    }
}

/// The shared secret `S`, held so it cannot be printed or copied casually.
pub struct Shared([u8; 32]);

impl fmt::Debug for Shared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Shared(<redacted>)")
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

impl Shared {
    /// The raw 32 bytes, for use as HKDF input keying material.
    ///
    /// Scoped to derivation. Nothing should hold the result.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Static-static agreement, `S = X25519(sk, pk)`.
///
/// Returns `None` if `pk` is low-order — see the module documentation. A
/// caller that treats `None` as "use zeros" has reintroduced the entire
/// problem, which is why there is no fallback variant of this function.
pub fn agree(sk: &SecretKey, pk: &PublicKey) -> Option<Shared> {
    let shared = sk.0.diffie_hellman(&DalekPublic::from(pk.0));
    if !shared.was_contributory() {
        return None;
    }
    Some(Shared(shared.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::NotRandom;

    fn sk(seed: u64) -> SecretKey {
        SecretKey::generate(&mut NotRandom::seeded(seed))
    }

    /// The property every pairwise tag depends on: sender and recipient
    /// compute the same `S` from opposite sides.
    #[test]
    fn agreement_is_symmetric() {
        let a = sk(1);
        let b = sk(2);
        let s_ab = agree(&a, &b.public()).unwrap();
        let s_ba = agree(&b, &a.public()).unwrap();
        assert_eq!(s_ab.as_bytes(), s_ba.as_bytes());
    }

    #[test]
    fn different_pairs_agree_on_different_secrets() {
        let (a, b, c) = (sk(1), sk(2), sk(3));
        let ab = agree(&a, &b.public()).unwrap();
        let ac = agree(&a, &c.public()).unwrap();
        assert_ne!(ab.as_bytes(), ac.as_bytes());
    }

    /// **`CRYPTO-REVIEW.md` §3.** A low-order public key forces `S` to zero
    /// for any private key. Rejected rather than returned.
    #[test]
    fn low_order_public_keys_are_rejected() {
        // The eight small-order points on Curve25519, little-endian. The last
        // three are p-1, p and p+1, which reduce to -1, 0 and 1.
        let field = |low: u8| {
            let mut v = [0xffu8; 32];
            v[0] = low;
            v[31] = 0x7f;
            v
        };
        let small: [[u8; 32]; 7] = [
            [0; 32],
            {
                let mut p = [0u8; 32];
                p[0] = 1;
                p
            },
            [
                0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
                0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
                0x5f, 0x49, 0xb8, 0x00,
            ],
            [
                0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
                0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
                0xd0, 0x9f, 0x11, 0x57,
            ],
            field(0xec),
            field(0xed),
            field(0xee),
        ];
        let a = sk(9);
        for raw in small {
            assert!(
                agree(&a, &PublicKey(raw)).is_none(),
                "a low-order key must not yield a shared secret both sides and the \
                 attacker agree on"
            );
        }
    }

    #[test]
    fn an_honest_key_still_agrees() {
        let a = sk(10);
        let b = sk(11);
        assert!(agree(&a, &b.public()).is_some());
    }

    #[test]
    fn secrets_print_nothing() {
        let a = sk(12);
        assert_eq!(alloc::format!("{a:?}"), "SecretKey(<redacted>)");
        let s = agree(&a, &sk(13).public()).unwrap();
        assert_eq!(alloc::format!("{s:?}"), "Shared(<redacted>)");
    }

    #[test]
    fn a_key_round_trips() {
        let a = sk(14);
        let b = SecretKey::from_bytes(a.to_bytes());
        assert_eq!(a.public(), b.public());
    }
}
