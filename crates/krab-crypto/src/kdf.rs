//! Tag derivation — RFC 1 §6.2, RFC 2 §4. **Frozen.**
//!
//! ```text
//! S       = X25519(sk_sender, pk_recipient)                  static-static
//! tag_e   = HKDF-Expand(S,            "krab/tag/v1"   ‖ u32_le(epoch), 8)
//! inbox_e = HKDF-Expand(pk_recipient, "krab/inbox/v1" ‖ u32_le(epoch), 8)
//! ```
//!
//! # Deviation from RFC 5869, implemented as specified
//!
//! `CRYPTO-REVIEW.md` §3. Both derivations call **Expand with no Extract**,
//! feeding a raw X25519 output — or, for inbox mode, a raw public key —
//! directly as the PRK.
//!
//! RFC 5869 §3.3 is explicit that Extract exists to condition non-uniform
//! input keying material, and a curve point encoding is not uniform. Expand
//! then keys HMAC-SHA256 with it, so the security of every tag rests on
//! HMAC-SHA256 remaining a PRF under a structured, biased key. That is widely
//! believed and not proven, and one extra HMAC would remove the assumption
//! entirely.
//!
//! **It is implemented as frozen anyway**, because the alternative is worse.
//! Adding Extract changes every tag every node computes; a corrected
//! implementation and a specification-conformant one would share no tags,
//! recognise none of each other's mail, and fail *silently* — RFC 0 §6 makes
//! delivery failure silent by design, so the symptom would be "some peers
//! never receive anything" with nothing in any log. A theoretical weakness is
//! preferable to a live interoperability fork.
//!
//! What is *additive* has been applied: [`crate::dh::agree`] rejects low-order
//! public keys, which changes no derivation and forks no tag space.
//!
//! # Which hash — an underspecification in §6.2
//!
//! §6.2 writes "HKDF-Expand" and never names the hash function. Taken alone it
//! is not implementable interoperably. §6.1 pins the suite's KDF as
//! HKDF-SHA256, and this module follows that reading.
//!
//! It is worth closing in the text, because the wrong inference is the
//! *natural* one: every other digest in Krab is BLAKE3, and an implementer who
//! reached for `blake3::derive_key` would produce a node that behaves
//! perfectly and shares no tags with anyone. Noted in
//! `Documentation/RFC-1-review.md`.
//!
//! # Why epoch bytes are little-endian
//!
//! RFC 1 §6.2 writes `u32(epoch)`; RFC 2 §4.1 writes `u32_le(epoch)`. The
//! explicit one governs, and it matches `krab_core::tag::Epoch::to_le_bytes`.

use crate::dh::{PublicKey, Shared};
use hkdf::Hkdf;
use krab_core::object::Tag;
use krab_core::tag::{Epoch, LABEL_INBOX, LABEL_TAG};
use sha2::Sha256;

/// `HKDF-Expand(prk, label ‖ u32_le(epoch), 8)`.
///
/// Private: the two callers below are the only correct uses, and an exported
/// general-purpose expander would invite a third with a fresh label that no
/// specification froze.
fn expand_tag(prk: &[u8; 32], label: &[u8], epoch: Epoch) -> Tag {
    // `from_prk` is Expand-with-no-Extract, which is the deviation documented
    // above. It cannot fail here: the PRK is 32 bytes and SHA-256's output is
    // 32 bytes, so the length precondition holds by construction.
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("32-byte PRK matches SHA-256 output length");
    let mut info = [0u8; 32];
    let n = label.len();
    info[..n].copy_from_slice(label);
    info[n..n + 4].copy_from_slice(&epoch.to_le_bytes());

    let mut out = [0u8; 8];
    hk.expand(&info[..n + 4], &mut out).expect("8 bytes is far below 255·HashLen");
    Tag(out)
}

/// The pairwise tag for `epoch`, RFC 1 §6.2 / RFC 2 §4.1.
///
/// Unlinkable across epochs and across senders. `S` is stable per pair, so a
/// caller should agree once and cache it — only this expansion repeats.
///
/// Both ends compute the same value, because `S` is symmetric.
pub fn pairwise_tag(s: &Shared, epoch: Epoch) -> Tag {
    expand_tag(s.as_bytes(), LABEL_TAG, epoch)
}

/// The inbox tag for `epoch`, RFC 1 §6.2 / RFC 2 §4.2 — first contact only.
///
/// Derived from a **public** key, so anyone holding it can compute this. That
/// is intended and it has a cost RFC 2 §4.2 states rather than hides: messages
/// to an inbox tag are linkable *within* an epoch. It rotates out.
///
/// Used for `peer-request` (RFC 3 §5.1) and nothing else. Inbox mode forces
/// `mode_base` HPKE, because `mode_auth` decapsulation needs the sender's
/// static public key and a first-contact recipient does not have it.
pub fn inbox_tag(recipient: &PublicKey, epoch: Epoch) -> Tag {
    expand_tag(&recipient.0, LABEL_INBOX, epoch)
}

/// Every pairwise tag a recipient must recognise around `now`.
///
/// `2·EPOCH_WINDOW + 1` entries per correspondent — 91 at ±45. RFC 2 §4.3
/// sizes the whole table at 4 550 entries and 55 KB for 50 correspondents.
///
/// The window is bounded by `MAX_TTL`, not by observed latency: an object
/// delivered at the far edge of the TTL this protocol declares valid must
/// still be recognisable, and a recipient with a narrower window simply never
/// computed that tag — the object is accepted, stored, and undecryptable.
pub fn pairwise_window(s: &Shared, now: Epoch) -> impl Iterator<Item = (Epoch, Tag)> + '_ {
    Epoch::window(now).map(move |e| (e, pairwise_tag(s, e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dh::{agree, SecretKey};
    use crate::rng::NotRandom;
    use alloc::vec::Vec;
    use krab_core::tag::EPOCH_WINDOW;

    fn sk(seed: u64) -> SecretKey {
        SecretKey::generate(&mut NotRandom::seeded(seed))
    }

    const NOW: Epoch = Epoch(20_671);

    /// **The property the whole scheme rests on.** Sender and recipient derive
    /// the same tag from opposite sides, without ever exchanging it.
    #[test]
    fn both_ends_derive_the_same_pairwise_tag() {
        let (a, b) = (sk(1), sk(2));
        let s_ab = agree(&a, &b.public()).unwrap();
        let s_ba = agree(&b, &a.public()).unwrap();
        assert_eq!(pairwise_tag(&s_ab, NOW), pairwise_tag(&s_ba, NOW));
    }

    /// RFC 2 §4.1 — unlinkable across epochs.
    #[test]
    fn a_pairwise_tag_changes_every_epoch() {
        let s = agree(&sk(1), &sk(2).public()).unwrap();
        let tags: Vec<Tag> = (0..10).map(|d| pairwise_tag(&s, Epoch(NOW.0 + d))).collect();
        for (i, t) in tags.iter().enumerate() {
            for (j, u) in tags.iter().enumerate() {
                assert!(i == j || t != u, "epochs {i} and {j} collide");
            }
        }
    }

    /// Unlinkable across senders: two correspondents of the same recipient
    /// produce unrelated tags in the same epoch.
    #[test]
    fn a_pairwise_tag_changes_across_senders() {
        let recipient = sk(9);
        let s1 = agree(&sk(1), &recipient.public()).unwrap();
        let s2 = agree(&sk(2), &recipient.public()).unwrap();
        assert_ne!(pairwise_tag(&s1, NOW), pairwise_tag(&s2, NOW));
    }

    /// RFC 2 §2, I-2 — tags and node identifiers are disjoint namespaces, and
    /// a pairwise tag must not equal the inbox tag of either party.
    #[test]
    fn pairwise_and_inbox_namespaces_do_not_collide() {
        let (a, b) = (sk(3), sk(4));
        let s = agree(&a, &b.public()).unwrap();
        let pw = pairwise_tag(&s, NOW);
        assert_ne!(pw, inbox_tag(&b.public(), NOW));
        assert_ne!(pw, inbox_tag(&a.public(), NOW));
    }

    /// RFC 2 §4.2 — an inbox tag is computable by anyone with the public key.
    /// That is the accepted cost of first contact, and it must hold exactly.
    #[test]
    fn an_inbox_tag_needs_only_the_public_key() {
        let recipient = sk(5);
        let pk = recipient.public();
        assert_eq!(inbox_tag(&pk, NOW), inbox_tag(&pk, NOW));
        assert_ne!(inbox_tag(&pk, NOW), inbox_tag(&pk, Epoch(NOW.0 + 1)), "rotates out");
        assert_ne!(inbox_tag(&pk, NOW), inbox_tag(&sk(6).public(), NOW));
    }

    /// RFC 2 §4.3's table, and RFC 1 §6.2's bound on the window.
    #[test]
    fn the_precomputation_window_covers_max_ttl() {
        let s = agree(&sk(7), &sk(8).public()).unwrap();
        let table: Vec<(Epoch, Tag)> = pairwise_window(&s, NOW).collect();
        assert_eq!(table.len(), 2 * EPOCH_WINDOW as usize + 1);
        assert_eq!(50 * table.len(), 4_550, "RFC 2 §4.3 — 50 correspondents");

        // Every entry is distinct, so the table is a usable lookup index.
        let mut seen: Vec<Tag> = table.iter().map(|(_, t)| *t).collect();
        seen.sort_by_key(|t| t.0);
        seen.dedup_by_key(|t| t.0);
        assert_eq!(seen.len(), table.len(), "a collision would misroute a decrypt");

        // And an object at the far edge of MAX_TTL is still in the table.
        let far = Epoch(NOW.0 - 45);
        assert!(table.iter().any(|(e, t)| *e == far && *t == pairwise_tag(&s, far)));
    }

    /// A tag is 8 bytes — RFC 1 §4.1's frozen header field.
    #[test]
    fn a_tag_is_eight_bytes_and_not_obviously_structured() {
        let s = agree(&sk(1), &sk(2).public()).unwrap();
        let t = pairwise_tag(&s, NOW);
        assert_eq!(t.0.len(), 8);
        assert_ne!(t.0, [0u8; 8]);
    }

    /// The derivation is frozen, so it is pinned to a literal. If this test
    /// fails, either a dependency changed HKDF-SHA256 or someone "fixed" the
    /// missing Extract — and every existing tag in every store just became
    /// unrecognisable.
    #[test]
    fn the_frozen_derivation_is_pinned() {
        // A fixed PRK rather than a DH output, so the vector does not depend
        // on x25519-dalek's clamping details.
        //
        // These two values were computed independently, from a Python HMAC
        // implementation rather than from this code, so the test pins the
        // *specification* and not merely this implementation's self-consistency:
        //
        //     T(1) = HMAC-SHA256(PRK, label ‖ u32_le(epoch) ‖ 0x01)[..8]
        let prk = [0x42u8; 32];
        assert_eq!(
            expand_tag(&prk, LABEL_TAG, Epoch(20_671)).0,
            [0x2d, 0xac, 0xec, 0xed, 0x91, 0xf7, 0x14, 0x8c],
        );
        assert_eq!(
            expand_tag(&prk, LABEL_INBOX, Epoch(20_671)).0,
            [0x24, 0x97, 0x43, 0xbc, 0x3e, 0xad, 0xc5, 0x95],
        );
    }
}
