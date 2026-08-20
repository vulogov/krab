//! Continuous re-keying of a peering — the hybrid ratchet.
//!
//! # Why this exists
//!
//! RFC 3 §11's ceremony establishes one reservoir root, out of band, and that
//! root then ratchets forward forever ([`crate::reservoir`]). Two things
//! follow from *forever*, and both are problems:
//!
//! 1. **It never heals.** An adversary who reads `root_n` once reads every
//!    root after it, because the ratchet is a pure function of its own state.
//!    There is no point at which a compromised peering becomes safe again.
//! 2. **It can die of absence.** [`crate::reservoir::Reservoir::MAX_ADVANCE`]
//!    is `2 · EPOCH_WINDOW` — 90 epochs, and an epoch is a day. A node offline
//!    longer than that cannot catch its ratchet up, and `advance_to` correctly
//!    refuses rather than destroying roots on what is more likely a bad clock.
//!    The peering is then permanently dead and has to be redone out of band.
//!
//! Re-keying fixes both by folding fresh entropy in from both ends.
//!
//! # Why the new entropy may cross the wire
//!
//! ```text
//! root_{n+1} = HKDF(root_n ‖ dh ‖ fresh_A ‖ fresh_B ‖ n+1)
//! ```
//!
//! `fresh_A` and `fresh_B` travel **in band**, encrypted under a carrier key
//! derived from `root_n` — and `root_n` has never crossed a channel. So the
//! key protecting them is one the adversary has never seen, and the chain
//! stays post-quantum with no further out-of-band steps ever.
//!
//! This is the whole point of the design. Establishing a root out of band is
//! expensive — a meeting, a posted stick, or thirty-two words read down a
//! phone line. Doing it **once, ever, per peer** is achievable for two people
//! on different continents. Doing it every time is not, and a protocol that
//! demands it gets `scp` instead.
//!
//! # Why `dh` is mixed in as well
//!
//! A purely symmetric chain gives no post-compromise security: `root_n` leaked
//! once is every future root leaked. Folding a fresh X25519 exchange into each
//! re-key locks that adversary out again at the next one — provided they
//! cannot break X25519, which is exactly the *classical* adversary a disk
//! compromise implies.
//!
//! The two components cover each other, and neither alone is enough:
//!
//! | Adversary | Beaten by |
//! |---|---|
//! | Records everything, breaks X25519 later | `root_n` — never on the wire |
//! | Reads the disk once, cannot break X25519 | `dh` — fresh each re-key |
//! | Both at once | nothing, and nothing can |
//!
//! # Ordering
//!
//! `fresh_A ‖ fresh_B` is ordered by **node id**, never by who spoke first.
//! Both ends must derive the same root, and a role negotiation is a round trip
//! that can disagree. Sorting by an identifier both ends already hold cannot.

use crate::rng::Rng;
use crate::secret::Secret;
use hkdf::Hkdf;
use sha2::Sha256;

/// Domain label for the carrier key that protects a contribution in flight.
pub const LABEL_CARRIER: &[u8] = b"krab/rekey/carrier/v1";

/// Domain label for the new root.
pub const LABEL_ROOT: &[u8] = b"krab/rekey/root/v1";

/// One end's fresh contribution to a re-key. Zeroized on drop.
pub type Contribution = Secret<32>;

/// How often a peering re-keys, in epochs.
///
/// # This number is the guarantee, not a tuning knob
///
/// > A reservoir compromised at time *T* stops protecting traffic within
/// > `REKEY_EPOCHS` epochs of *T*.
///
/// `EPOCH_WINDOW` falls out of that statement rather than being chosen
/// alongside it. Re-keying **faster** buys nothing: chunks inside the
/// acceptance window (RFC 1 §6.2) are retained anyway and stay derivable from
/// material the adversary already holds, so the exposure does not shrink.
/// Re-keying **slower** widens the stated window directly.
///
/// `AMENDMENTS.md` records five parameters that were anchored to a measured
/// percentile rather than to a declared guarantee. This one is anchored to the
/// guarantee, and if the guarantee changes this must change with it.
pub const REKEY_EPOCHS: u32 = krab_core::tag::EPOCH_WINDOW;

/// Derive the key that protects a contribution in flight.
///
/// From `root_n`, so an adversary needs the reservoir to read a re-key — and
/// an adversary with the reservoir already has everything this protects. The
/// carrier exists to stop *everyone else*, which is everyone.
pub fn carrier_key(root_n: &[u8; 32], n: u32) -> Secret<32> {
    Secret::new(expand(root_n, LABEL_CARRIER, n))
}

/// Derive `root_{n+1}`.
///
/// `mine` and `theirs` are paired with the node ids they came from, and the
/// pair sorts by id before mixing — see the module docs on ordering. Passing
/// them the wrong way round is therefore not an error either end can make.
///
/// `dh` is the output of a fresh X25519 exchange. It is **not** optional: a
/// re-key without it produces a chain that cannot heal, which is half the
/// reason this module exists.
pub fn next_root(
    root_n: &[u8; 32],
    dh: &[u8; 32],
    mine: (&[u8; 32], &Contribution),
    theirs: (&[u8; 32], &Contribution),
    n_plus_1: u32,
) -> [u8; 32] {
    let (first, second) = if mine.0 <= theirs.0 {
        (mine.1, theirs.1)
    } else {
        (theirs.1, mine.1)
    };

    // Everything into the salt, the old root as the PRK material. Concatenated
    // with fixed-width fields, so no length-extension ambiguity between the
    // components — every one of them is exactly 32 bytes.
    let mut ikm = [0u8; 128];
    ikm[..32].copy_from_slice(root_n);
    ikm[32..64].copy_from_slice(dh);
    ikm[64..96].copy_from_slice(first.expose());
    ikm[96..128].copy_from_slice(second.expose());

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut info = [0u8; 32];
    let l = LABEL_ROOT.len();
    info[..l].copy_from_slice(LABEL_ROOT);
    info[l..l + 4].copy_from_slice(&n_plus_1.to_le_bytes());
    let mut out = [0u8; 32];
    hk.expand(&info[..l + 4], &mut out)
        .expect("32 bytes is far below 255·HashLen");

    // The concatenation held two live secrets and the old root.
    use zeroize::Zeroize;
    ikm.zeroize();
    out
}

/// Domain for a re-seal — a root upgraded over a stronger channel.
pub const LABEL_RESEAL: &[u8] = b"krab/reseal/root/v1";

/// Derive a root from an existing one and two **out-of-band** contributions.
///
/// This is `peer reseal`: a peering established over a weak channel, later
/// strengthened without being redone. The peer-link, the message history and
/// the correspondent's identity all survive; only the root changes.
///
/// # Why there is no `dh` here, unlike [`next_root`]
///
/// A re-key mixes a fresh Diffie-Hellman exchange because its contributions
/// travel **over the session**, so an adversary who read the disk once could
/// read them off the wire and follow the chain forward; `dh` is what locks
/// them out again.
///
/// A re-seal's contributions never cross a recorded channel at all — that is
/// the entire point of the exercise. They are therefore strictly better than
/// `dh` at the job `dh` was doing, and adding one would mix a value the
/// adversary *can* attack into a root that otherwise does not depend on
/// asymmetric cryptography anywhere.
///
/// # Why the old root is still mixed in
///
/// So that a re-seal proves continuity. Only the two ends of the existing
/// peering hold `old_root`, so a third party who obtains both fresh
/// contributions — by being handed a stick, say — still cannot produce the
/// new root. Dropping it would make a re-seal indistinguishable from a fresh
/// peering with the same card, which is the shape of an impersonation.
///
/// And it costs nothing: the result is post-quantum as long as *either* input
/// is, and the fresh contributions are.
pub fn reseal_root(
    old_root: &[u8; 32],
    mine: (&[u8; 32], &Contribution),
    theirs: (&[u8; 32], &Contribution),
    epoch: u32,
) -> [u8; 32] {
    // Ordered by node id, for the reason `next_root` is: both ends must derive
    // the same value without negotiating who spoke first.
    let (first, second) = if mine.0 <= theirs.0 {
        (mine.1, theirs.1)
    } else {
        (theirs.1, mine.1)
    };

    let mut ikm = [0u8; 96];
    ikm[..32].copy_from_slice(old_root);
    ikm[32..64].copy_from_slice(first.expose());
    ikm[64..96].copy_from_slice(second.expose());

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut info = [0u8; 32];
    let l = LABEL_RESEAL.len();
    info[..l].copy_from_slice(LABEL_RESEAL);
    info[l..l + 4].copy_from_slice(&epoch.to_le_bytes());
    let mut out = [0u8; 32];
    hk.expand(&info[..l + 4], &mut out)
        .expect("32 bytes is far below 255·HashLen");

    use zeroize::Zeroize;
    ikm.zeroize();
    out
}

/// A fresh contribution.
pub fn contribute(rng: &mut impl Rng) -> Contribution {
    Secret::new(rng.next_32())
}

/// What the two ends must agree on before a root is accepted.
///
/// Both ends derive this from the same inputs and compare it over the
/// authenticated session. It is **not** a secret and must not be treated as
/// one — it is a checksum against a re-key that half-completed, where one end
/// advanced and the other did not and every subsequent tag silently fails to
/// match.
pub fn confirm_tag(new_root: &[u8; 32], n_plus_1: u32) -> [u8; 8] {
    // Derived from the root rather than hashed with it: the tag is published
    // over the session, and a hash of a live key is a 64-bit head start on
    // that key for anyone recording. An HKDF output discloses nothing.
    let full = expand(new_root, b"krab/rekey/confirm/v1", n_plus_1);
    let mut out = [0u8; 8];
    out.copy_from_slice(&full[..8]);
    out
}

fn expand(prk: &[u8; 32], label: &[u8], n: u32) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("32-byte PRK matches SHA-256 output length");
    let mut info = [0u8; 32];
    let l = label.len();
    info[..l].copy_from_slice(label);
    info[l..l + 4].copy_from_slice(&n.to_le_bytes());
    let mut out = [0u8; 32];
    hk.expand(&info[..l + 4], &mut out)
        .expect("32 bytes is far below 255·HashLen");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::NotRandom;

    fn contrib(seed: u8) -> Contribution {
        Secret::new([seed; 32])
    }

    /// **Both ends derive the same root without agreeing who spoke first.**
    /// The ordering rule is what makes a role negotiation unnecessary, and a
    /// role negotiation is a round trip that can disagree.
    #[test]
    fn both_ends_derive_the_same_root_in_either_order() {
        let root = [7u8; 32];
        let dh = [9u8; 32];
        let (id_a, id_b) = ([1u8; 32], [2u8; 32]);
        let (a, b) = (contrib(0xaa), contrib(0xbb));

        let from_a = next_root(&root, &dh, (&id_a, &a), (&id_b, &b), 5);
        let from_b = next_root(&root, &dh, (&id_b, &b), (&id_a, &a), 5);
        assert_eq!(from_a, from_b, "the two ends disagree about the new root");
    }

    /// Every input changes the root. A component that can be varied without
    /// effect is a component that is not being mixed in.
    #[test]
    fn every_component_is_load_bearing() {
        let root = [7u8; 32];
        let dh = [9u8; 32];
        let (id_a, id_b) = ([1u8; 32], [2u8; 32]);
        let (a, b) = (contrib(0xaa), contrib(0xbb));
        let base = next_root(&root, &dh, (&id_a, &a), (&id_b, &b), 5);

        assert_ne!(
            base,
            next_root(&[8u8; 32], &dh, (&id_a, &a), (&id_b, &b), 5),
            "the old root does not affect the new one"
        );
        assert_ne!(
            base,
            next_root(&root, &[10u8; 32], (&id_a, &a), (&id_b, &b), 5),
            "the DH output does not affect the new root — no healing"
        );
        assert_ne!(
            base,
            next_root(&root, &dh, (&id_a, &contrib(0xac)), (&id_b, &b), 5),
            "our own contribution does not affect the new root"
        );
        assert_ne!(
            base,
            next_root(&root, &dh, (&id_a, &a), (&id_b, &contrib(0xbc)), 5),
            "their contribution does not affect the new root"
        );
        assert_ne!(
            base,
            next_root(&root, &dh, (&id_a, &a), (&id_b, &b), 6),
            "the epoch does not affect the new root"
        );
    }

    /// **The chain heals.** An adversary holding `root_n` and every byte on
    /// the wire still does not hold `root_{n+1}`, because `dh` was never sent.
    /// This is the property a pure symmetric ratchet cannot have.
    #[test]
    fn a_leaked_root_does_not_yield_the_next_one() {
        let leaked = [7u8; 32];
        let (id_a, id_b) = ([1u8; 32], [2u8; 32]);
        let (a, b) = (contrib(0xaa), contrib(0xbb));

        // What the adversary can compute: they have the old root, so they can
        // derive the carrier and read both contributions off the wire.
        let real = next_root(&leaked, &[9u8; 32], (&id_a, &a), (&id_b, &b), 5);
        let guess = next_root(&leaked, &[0u8; 32], (&id_a, &a), (&id_b, &b), 5);
        assert_ne!(real, guess, "the DH output is not doing any work");
    }

    /// The carrier is a function of the root, so anyone without the reservoir
    /// cannot read a contribution in flight — which is everyone except an
    /// adversary who already has what it protects.
    #[test]
    fn the_carrier_key_is_bound_to_the_root_and_the_index() {
        let k1 = carrier_key(&[1u8; 32], 3);
        assert_ne!(k1.expose(), carrier_key(&[2u8; 32], 3).expose());
        assert_ne!(k1.expose(), carrier_key(&[1u8; 32], 4).expose());
        assert_ne!(
            k1.expose(),
            &[0u8; 32],
            "a carrier key of zeros would encrypt nothing"
        );
    }

    /// A re-key that half-completes is worse than one that fails: every tag
    /// silently stops matching and RFC 0 §6 guarantees nobody is told.
    #[test]
    fn the_confirmation_tag_detects_a_divergent_root() {
        let a = confirm_tag(&[1u8; 32], 5);
        assert_ne!(a, confirm_tag(&[2u8; 32], 5), "a different root confirms");
        assert_ne!(a, confirm_tag(&[1u8; 32], 6), "a different index confirms");
    }

    /// Contributions come from the argument, never from ambient randomness —
    /// the rule the whole crate is built on.
    #[test]
    fn a_contribution_is_drawn_from_the_supplied_generator() {
        let mut rng = NotRandom::seeded(4);
        let a = contribute(&mut rng);
        let mut same = NotRandom::seeded(4);
        assert_eq!(a.expose(), contribute(&mut same).expose());
    }

    /// The interval is the guarantee. If this fails, the guarantee in
    /// `REKEY_EPOCHS`' documentation is no longer the one being delivered.
    #[test]
    fn the_rekey_interval_matches_the_acceptance_window() {
        assert_eq!(REKEY_EPOCHS, krab_core::tag::EPOCH_WINDOW);
    }

    /// **A re-seal produces the same root at both ends**, from the old root
    /// and two out-of-band contributions, with no session between them.
    #[test]
    fn both_ends_reseal_to_the_same_root() {
        let old = [3u8; 32];
        let (id_a, id_b) = ([1u8; 32], [2u8; 32]);
        let (a, b) = (contrib(0xaa), contrib(0xbb));
        assert_eq!(
            reseal_root(&old, (&id_a, &a), (&id_b, &b), 9),
            reseal_root(&old, (&id_b, &b), (&id_a, &a), 9),
            "the two ends disagree"
        );
    }

    /// Every input is load-bearing, including the old root — which is what
    /// makes a re-seal prove continuity rather than being a fresh peering
    /// under an old card.
    #[test]
    fn a_reseal_needs_the_old_root_and_both_contributions() {
        let old = [3u8; 32];
        let (id_a, id_b) = ([1u8; 32], [2u8; 32]);
        let (a, b) = (contrib(0xaa), contrib(0xbb));
        let base = reseal_root(&old, (&id_a, &a), (&id_b, &b), 9);

        assert_ne!(
            base,
            reseal_root(&[4u8; 32], (&id_a, &a), (&id_b, &b), 9),
            "someone holding both fresh contributions could forge this"
        );
        assert_ne!(
            base,
            reseal_root(&old, (&id_a, &contrib(0xac)), (&id_b, &b), 9)
        );
        assert_ne!(
            base,
            reseal_root(&old, (&id_a, &a), (&id_b, &contrib(0xbc)), 9)
        );
        assert_ne!(base, reseal_root(&old, (&id_a, &a), (&id_b, &b), 10));
    }

    /// A re-seal is not a re-key, and must not collide with one: the same
    /// inputs under the two labels give different roots.
    #[test]
    fn a_reseal_is_domain_separated_from_a_rekey() {
        let old = [3u8; 32];
        let (id_a, id_b) = ([1u8; 32], [2u8; 32]);
        let (a, b) = (contrib(0xaa), contrib(0xbb));
        // `next_root` with an all-zero dh is the closest a re-key can come to
        // the same input set.
        assert_ne!(
            reseal_root(&old, (&id_a, &a), (&id_b, &b), 9),
            next_root(&old, &[0u8; 32], (&id_a, &a), (&id_b, &b), 9)
        );
    }
}
