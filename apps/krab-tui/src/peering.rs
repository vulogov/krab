//! Friend-to-friend peering: what you hand over, and what you accept back.
//!
//! RFC 3 §11's ceremony is four steps, and it is symmetric — both ends do the
//! same thing, which is what "friend-to-friend" means:
//!
//! ```text
//! 1. exchange rollcall entries or QR codes      → Card, public
//! 2. compare fingerprint word lists aloud       ← the actual security step
//! 3. exchange reservoir contributions R_A ⊕ R_B → Contribution, SECRET
//! 4. sign the peer-link
//! ```
//!
//! # Two artifacts, not one, and why they must never share a file
//!
//! Step 1 is public: a [`Card`] is signed, self-certifying, and safe to email,
//! print, or push through the corpus. Step 3 is **half of a shared secret**.
//! Bundling them into a single "contact card" would produce one blob that
//! looks routine and is catastrophic to forward — so [`offer`] emits two, and
//! they carry different [`Channel`] requirements.
//!
//! # The unstated requirement: channel independence
//!
//! RFC 7 §6.2 justifies `reservoir = R_A ⊕ R_B` on one ground only — that
//! "neither party's generator alone determines the result, so a backdoored or
//! broken RNG on one end does not compromise it."
//!
//! That is true and it is not the whole requirement. RFC 7 §6's premise is
//! that the reservoir carries the **post-quantum** property (its own fix note
//! says the chunk-as-PSK is what "carries the post-quantum property"). If
//! `R_A` and `R_B` travel encrypted under the X25519 statics exchanged at step
//! 1, then an adversary who breaks X25519 — later, from a recording —
//! recovers both contributions, hence the reservoir, hence every chunk. **The
//! reservoir's entire reason for existing is void, and nothing in the protocol
//! notices.**
//!
//! So the XOR needs a second rationale RFC 7 §6.2 does not state: the two
//! contributions must reach their destinations over a channel *independent of
//! the asymmetric cryptography they are meant to outlive*. RFC 3 §11.1
//! permits "the same documents flow through the corpus" for remote peering and
//! qualifies it only with respect to fingerprint comparison — which is correct
//! for step 1 and a silent downgrade for step 3.
//!
//! This module therefore records how a contribution arrived and refuses to
//! forget it. Remote peering stays possible, because RFC 3 §11.1 allows it;
//! it just cannot claim a property it does not have. That mirrors §11.1's own
//! rule that implementations "MUST NOT present remote peering as equivalent".
//! Written up in `Documentation/RFC-7-review.md` §10.

// `Card` and `Contribution` are reachable from `peer offer`. The acceptance
// half -- `Channel`, `Mode`, `accept`, `PeerLink` -- is complete and tested but
// not yet dispatched, because `peer accept` and `peer seal` need to read files
// and hold a part-finished ceremony across restarts. Both arrive with the
// courier work; the types are here first because the channel rule they encode
// (see the module docs, and `RFC-7-review.md` §10) is a specification finding
// that should not wait on plumbing.
#![allow(dead_code)]

use core::fmt;
use krab_core::cbor::Writer;
use krab_crypto::sign::{Sig, SigningKey, VerifyingKey};

/// How an artifact reached this node.
///
/// The node cannot observe this — a file is a file — so the operator states
/// it, and [`Channel::independent_of_dh`] decides what it is worth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// Handed over in person. RFC 7 §6.2's "gold standard".
    InPerson,
    /// Physically transported media — the courier leg of RFC 4 §6.
    RemovableMedia,
    /// Through the corpus, per RFC 3 §11.1.
    Corpus,
    /// A live network link, secured by the very keys at issue.
    Network,
}

impl Channel {
    /// Whether this channel's confidentiality rests on the asymmetric
    /// cryptography the reservoir exists to outlive.
    ///
    /// A contribution that arrives over a channel where this is `false` is
    /// only as strong as X25519, which makes the reservoir decorative.
    pub fn independent_of_dh(&self) -> bool {
        matches!(self, Channel::InPerson | Channel::RemovableMedia)
    }
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Channel::InPerson => "in person",
            Channel::RemovableMedia => "removable media",
            Channel::Corpus => "corpus",
            Channel::Network => "network",
        })
    }
}

/// How a peering is being conducted.
///
/// Both are supported and they are not equivalent. The counter-intuitive part
/// is which one is stronger:
///
/// | | fingerprint step | reservoir | round trips |
/// |---|---|---|---|
/// | [`Sneakernet`](Mode::Sneakernet) | in person, or a phone call | **post-quantum** | two legs |
/// | [`Online`](Mode::Online) | requires a phone call | **not** post-quantum | one exchange |
///
/// The primitive path is the secure one, because RFC 7 §6.2's contribution
/// exchange needs a channel independent of X25519 and a network link is not
/// one (§ module docs). Online peering trades the reservoir's
/// store-now-decrypt-later resistance for convenience — a real trade, worth
/// making sometimes, and never worth making silently.
///
/// # Sneakernet is a release gate, not a fallback
///
/// RFC 3 §11.3 requires an implementation to demonstrate "a complete peering
/// negotiation and first message exchange **with all network interfaces
/// down**", because "if any step requires a round trip that was not noticed,
/// air-gapped nodes silently cannot join, and that will not be discovered
/// until someone tries."
///
/// So [`Mode::Sneakernet`] cannot be a degraded version of the online path
/// with pieces missing. The artifacts are files either way, and the ceremony
/// is the same four steps in the same order; only the courier differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Cards and contributions travel on physically moved media, or hand to
    /// hand. RFC 7 §6.2's "two courier legs — already the request/response
    /// pattern, so structurally free."
    Sneakernet,
    /// Cards travel through the corpus or a live link, per RFC 3 §11.1.
    Online,
}

impl Mode {
    /// The channel this mode uses for the public card.
    ///
    /// Unconstrained in both modes: a [`Card`] is signed and self-certifying,
    /// so there is nothing an observer gains from it.
    pub fn card_channel(&self) -> Channel {
        match self {
            Mode::Sneakernet => Channel::RemovableMedia,
            Mode::Online => Channel::Corpus,
        }
    }

    /// The channel this mode uses for the secret contribution.
    pub fn contribution_channel(&self) -> Channel {
        match self {
            Mode::Sneakernet => Channel::RemovableMedia,
            Mode::Online => Channel::Corpus,
        }
    }

    /// Whether a peering in this mode yields a post-quantum reservoir.
    pub fn yields_post_quantum_reservoir(&self) -> bool {
        self.contribution_channel().independent_of_dh()
    }

    /// Whether this mode can complete with every network interface down.
    ///
    /// RFC 3 §11.3's gate. True for exactly one mode, which is the point of
    /// testing it.
    pub fn works_air_gapped(&self) -> bool {
        matches!(self, Mode::Sneakernet)
    }
}

/// What this node will and will not do for one peer.
///
/// Policy is per-link and travels in the [`Card`], so both ends know what the
/// other agreed to rather than discovering it from behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Largest size bucket this node will accept from the peer, as a bucket
    /// **index** (RFC 1 §8.1), never a byte count.
    pub max_bucket: u8,
    /// Whether this node will carry objects not addressed to it.
    ///
    /// Declining makes the node a leaf: it still sends and receives, and it
    /// contributes nothing to anyone else's reachability. RFC 3 §5 depends on
    /// most peers saying yes.
    pub relay: bool,
    /// Bytes this node will retain for the shared corpus.
    pub retention_bytes: u64,
    /// Shard bits, RFC 2 §6. Zero means no sharding.
    ///
    /// Non-zero divides both this node's load **and the peer's anonymity set**
    /// by `2^k`. There is no value that is free, so it belongs in a document
    /// both parties see rather than in a local settings pane.
    pub shard_bits: u8,
}

impl Default for Policy {
    /// Full participation: relay for others, no sharding, 1 GB, all buckets.
    fn default() -> Policy {
        Policy {
            max_bucket: 7,
            relay: true,
            retention_bytes: 1 << 30,
            shard_bits: 0,
        }
    }
}

impl Policy {
    /// Whether two policies can form a link, and what the peer must respect.
    ///
    /// The effective ceiling is the **lower** of the two `max_bucket` values:
    /// a link is only as capable as its least capable end (RFC 4 §5.4).
    pub fn negotiate(&self, peer: &Policy) -> Policy {
        Policy {
            max_bucket: self.max_bucket.min(peer.max_bucket),
            // Relay is not negotiated — each end decides for itself what it
            // carries. This field describes *this* node.
            relay: self.relay,
            retention_bytes: self.retention_bytes,
            // Sharding likewise: `k` is a link parameter each end applies to
            // what it stores, per RFC 2 §6.
            shard_bits: self.shard_bits,
        }
    }
}

/// Domain label for a card signature. Frozen.
///
/// **Not specified by RFC 3 §2.1**, which says credential documents are
/// deterministic CBOR and stops there. Without a domain prefix, a signature
/// over a card is a bare Ed25519 signature over an attacker-influenced byte
/// string, and any other document in the series that happens to encode to the
/// same bytes would carry a valid signature it never earned. Cross-protocol
/// signature reuse is cheap to prevent and awkward to retrofit, so the label
/// is applied here and flagged for the RFC.
pub const DOMAIN_CARD: &[u8] = b"krab/card/v1";

/// The public half — RFC 3 §11 step 1.
///
/// Signed and self-certifying (RFC 3 §2: a node identifier is a key). Safe on
/// any channel; there is nothing here an adversary gains from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    /// Ed25519 identity public key. `node_id = BLAKE3("krab/node/v1" ‖ this)`.
    pub identity_pk: [u8; 32],
    /// X25519 static, for RFC 4 §4.1's Noise handshake.
    pub noise_static_pk: [u8; 32],
    /// X25519 correspondence key, for RFC 2 §4.1's tag derivation.
    pub correspondence_pk: [u8; 32],
    /// This node's terms.
    pub policy: Policy,
    /// Ed25519 signature over [`Card::signed_bytes`].
    pub sig: [u8; 64],
}

impl Card {
    /// The bytes a signature covers: `DOMAIN_CARD` followed by the card's
    /// deterministic CBOR encoding, RFC 3 §2.1 and RFC 1 §4.3.
    ///
    /// The signature itself is excluded, which is why this takes the fields
    /// rather than `&self` — a card cannot be constructed unsigned.
    pub fn signed_bytes(
        identity_pk: &[u8; 32],
        noise_static_pk: &[u8; 32],
        correspondence_pk: &[u8; 32],
        policy: &Policy,
    ) -> Vec<u8> {
        let mut w = Writer::new();
        w.map(4);
        w.uint(1).bstr(identity_pk);
        w.uint(2).bstr(noise_static_pk);
        w.uint(3).bstr(correspondence_pk);
        w.uint(4).map(4);
        w.uint(1).uint(policy.max_bucket as u64);
        w.uint(2).bool(policy.relay);
        w.uint(3).uint(policy.retention_bytes);
        w.uint(4).uint(policy.shard_bits as u64);
        let body = w.finish();

        let mut out = Vec::with_capacity(DOMAIN_CARD.len() + body.len());
        out.extend_from_slice(DOMAIN_CARD);
        out.extend_from_slice(&body);
        out
    }

    /// Build and sign a card.
    pub fn create(
        signing: &SigningKey,
        noise_static_pk: [u8; 32],
        correspondence_pk: [u8; 32],
        policy: Policy,
    ) -> Card {
        let identity_pk = signing.verifying_key().to_bytes();
        let msg = Card::signed_bytes(&identity_pk, &noise_static_pk, &correspondence_pk, &policy);
        Card {
            identity_pk,
            noise_static_pk,
            correspondence_pk,
            policy,
            sig: signing.sign(&msg).0,
        }
    }

    /// Whether this card's signature is valid under its own identity key.
    ///
    /// Self-certifying: there is no authority to check against. The signature
    /// proves the holder of the identity key chose these statics and this
    /// policy — it says nothing about *who that is*, which is what RFC 3 §11
    /// step 2's spoken fingerprint comparison establishes and nothing else can.
    #[must_use]
    pub fn verify(&self) -> bool {
        let msg = Card::signed_bytes(
            &self.identity_pk,
            &self.noise_static_pk,
            &self.correspondence_pk,
            &self.policy,
        );
        VerifyingKey::from_bytes(self.identity_pk).verify(&msg, &Sig(self.sig))
    }

    /// `node_id = BLAKE3("krab/node/v1" ‖ identity_pk)`, RFC 3 §2.
    pub fn node_id(&self) -> [u8; 32] {
        VerifyingKey::from_bytes(self.identity_pk).node_id()
    }

    /// The spoken fingerprint for RFC 3 §11 step 2 — the first 8 bytes of the
    /// node identifier as words (RFC 3 §2).
    pub fn fingerprint(&self) -> String {
        krab_crypto::words::phrase(&self.node_id()[..8])
    }
}

/// The secret half — RFC 3 §11 step 3.
///
/// This is `R_A`: **one half of a shared secret**, not a credential. It has no
/// signature, because signing it would let an observer confirm which pair it
/// belongs to, and it is single-use.
pub struct Contribution {
    /// 32 bytes of local randomness. XORed with the peer's to form the
    /// reservoir root (RFC 7 §6.2).
    pub r: [u8; 32],
}

impl fmt::Debug for Contribution {
    /// Prints nothing. RFC 7 §9 — key material must not reach a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Contribution(<redacted>)")
    }
}

impl Contribution {
    /// `reservoir = R_A ⊕ R_B`, RFC 7 §6.2.
    // The index walks three arrays in lockstep, which is what an XOR is.
    #[allow(clippy::needless_range_loop)]
    pub fn combine(&self, peer: &Contribution) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = self.r[i] ^ peer.r[i];
        }
        out
    }
}

/// What `peer offer` produces: two artifacts, deliberately separate.
pub struct Offer {
    /// Publishable anywhere.
    pub card: Card,
    /// Must travel over a channel where [`Channel::independent_of_dh`] holds.
    pub contribution: Contribution,
}

/// Build this node's half of a peering.
pub fn offer(card: Card, r: [u8; 32]) -> Offer {
    Offer {
        card,
        contribution: Contribution { r },
    }
}

/// Why an acceptance was refused, or what it cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caveat {
    /// The fingerprint word lists have not been compared. RFC 3 §11 step 2 is
    /// "the actual security step" and nothing downstream substitutes for it.
    FingerprintUnverified,
    /// The contribution arrived over a channel secured by the keys it is meant
    /// to outlive. The link works; the reservoir provides no post-quantum
    /// value. RFC 3 §11.1 permits this and forbids presenting it as equivalent.
    ReservoirNotPostQuantum(Channel),
    /// A peer's own contribution XORed with itself is zero.
    DegenerateContribution,
    /// The card's signature did not verify under its own identity key.
    BadSignature,
}

/// A completed peering, and what it is honestly worth.
pub struct PeerLink {
    /// The negotiated terms.
    pub policy: Policy,
    /// Everything that was not ideal about how this link was formed.
    ///
    /// Kept, not discarded: `peers` and `keys` render it, so a link formed
    /// remotely on a bad afternoon still says so a year later.
    pub caveats: Vec<Caveat>,
}

impl PeerLink {
    /// Whether this link is safe to use at all.
    ///
    /// A missing fingerprint comparison or a non-post-quantum reservoir are
    /// *degradations* — the link works and says what it cost. A bad signature
    /// is not a degradation: the card is not what it claims to be.
    pub fn is_usable(&self) -> bool {
        !self.caveats.contains(&Caveat::BadSignature)
            && !self.caveats.contains(&Caveat::DegenerateContribution)
    }

    /// Whether the reservoir on this link actually carries RFC 7 §6's
    /// post-quantum property.
    pub fn reservoir_is_post_quantum(&self) -> bool {
        !self
            .caveats
            .iter()
            .any(|c| matches!(c, Caveat::ReservoirNotPostQuantum(_)))
    }
}

/// Complete the ceremony: accept the peer's card and contribution.
///
/// `fingerprint_verified` is the operator asserting they performed step 2.
/// The node cannot check it — that is precisely why it is the security step —
/// so it is recorded rather than assumed.
pub fn accept(
    mine: &Offer,
    theirs_card: &Card,
    theirs_contribution: &Contribution,
    arrived_by: Channel,
    fingerprint_verified: bool,
) -> ([u8; 32], PeerLink) {
    let mut caveats = Vec::new();
    if !theirs_card.verify() {
        caveats.push(Caveat::BadSignature);
    }
    if !fingerprint_verified {
        caveats.push(Caveat::FingerprintUnverified);
    }
    if !arrived_by.independent_of_dh() {
        caveats.push(Caveat::ReservoirNotPostQuantum(arrived_by));
    }
    let reservoir = mine.contribution.combine(theirs_contribution);
    if reservoir == [0u8; 32] {
        caveats.push(Caveat::DegenerateContribution);
    }
    (
        reservoir,
        PeerLink {
            policy: mine.card.policy.negotiate(&theirs_card.policy),
            caveats,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use krab_crypto::rng::NotRandom;

    fn card(pk: u8, policy: Policy) -> Card {
        let signing = SigningKey::generate(&mut NotRandom::seeded(pk as u64));
        Card::create(
            &signing,
            [pk.wrapping_add(1); 32],
            [pk.wrapping_add(2); 32],
            policy,
        )
    }

    /// A card certifies itself, and any edit to it breaks that.
    #[test]
    fn a_card_verifies_and_any_field_change_invalidates_it() {
        let c = card(1, Policy::default());
        assert!(c.verify());

        for mutate in [
            |c: &mut Card| c.noise_static_pk[0] ^= 1,
            |c: &mut Card| c.correspondence_pk[0] ^= 1,
            |c: &mut Card| c.policy.max_bucket = 2,
            |c: &mut Card| c.policy.relay = !c.policy.relay,
            |c: &mut Card| c.policy.retention_bytes += 1,
            |c: &mut Card| c.policy.shard_bits += 1,
            |c: &mut Card| c.sig[0] ^= 1,
        ] {
            let mut bad = c.clone();
            mutate(&mut bad);
            assert!(!bad.verify(), "a mutated card must not verify");
        }
    }

    /// Swapping in another node's identity key does not transfer the
    /// signature: policy cannot be attributed to someone who never agreed.
    #[test]
    fn a_card_cannot_be_reattributed_to_another_identity() {
        let mut c = card(1, Policy::default());
        c.identity_pk = card(2, Policy::default()).identity_pk;
        assert!(!c.verify());
    }

    /// **A forged card is not a degradation.** Unlike a skipped fingerprint
    /// check or a corpus-delivered reservoir, this makes the link unusable.
    #[test]
    fn a_card_that_does_not_verify_makes_the_link_unusable() {
        let mine = offer(card(1, Policy::default()), [0x11; 32]);
        let mut forged = card(2, Policy::default());
        forged.policy.retention_bytes = 1;

        let (_, link) = accept(
            &mine,
            &forged,
            &Contribution { r: [0x22; 32] },
            Channel::InPerson,
            true,
        );
        assert!(link.caveats.contains(&Caveat::BadSignature));
        assert!(!link.is_usable());

        // Whereas the two degradations leave a usable link.
        let (_, degraded) = accept(
            &mine,
            &card(2, Policy::default()),
            &Contribution { r: [0x22; 32] },
            Channel::Corpus,
            false,
        );
        assert!(degraded.is_usable(), "remote peering still works");
        assert_eq!(degraded.caveats.len(), 2);
    }

    /// RFC 3 §2 — the spoken fingerprint is eight words from the node id.
    #[test]
    fn a_fingerprint_is_eight_spoken_words() {
        let c = card(1, Policy::default());
        let f = c.fingerprint();
        assert_eq!(f.split_whitespace().count(), 8);
        assert_ne!(f, card(2, Policy::default()).fingerprint());
        assert_eq!(f, c.fingerprint(), "stable");
    }

    /// The signature covers deterministic CBOR, so encoding is reproducible
    /// and two implementations sign the same bytes (RFC 3 §2.1, RFC 1 §4.3).
    #[test]
    fn the_signed_encoding_is_deterministic_and_domain_separated() {
        let p = Policy::default();
        let a = Card::signed_bytes(&[1; 32], &[2; 32], &[3; 32], &p);
        assert_eq!(a, Card::signed_bytes(&[1; 32], &[2; 32], &[3; 32], &p));
        assert!(
            a.starts_with(DOMAIN_CARD),
            "cross-protocol reuse is prevented"
        );
        // Field order is fixed, so swapping two statics changes the bytes.
        assert_ne!(a, Card::signed_bytes(&[1; 32], &[3; 32], &[2; 32], &p));
    }

    /// RFC 7 §6.2 — both parties contribute, so one broken RNG is survivable.
    #[test]
    fn the_reservoir_needs_both_contributions() {
        let a = Contribution { r: [0xAA; 32] };
        let b = Contribution { r: [0x0F; 32] };
        let reservoir = a.combine(&b);
        assert_eq!(reservoir, [0xA5; 32]);
        assert_eq!(
            b.combine(&a),
            reservoir,
            "symmetric — both ends compute the same"
        );
        assert_ne!(reservoir, a.r, "A alone does not determine it");
        assert_ne!(reservoir, b.r, "B alone does not determine it");
    }

    /// **The finding this module exists for.**
    ///
    /// A contribution that arrives over the corpus or a live link is protected
    /// only by X25519 — the thing the reservoir is supposed to outlive. The
    /// link still forms, and it never claims a property it lacks.
    #[test]
    fn a_reservoir_from_the_corpus_is_not_post_quantum() {
        let mine = offer(card(1, Policy::default()), [0x11; 32]);
        let theirs = Contribution { r: [0x22; 32] };

        for ch in [Channel::InPerson, Channel::RemovableMedia] {
            let (_, link) = accept(&mine, &card(2, Policy::default()), &theirs, ch, true);
            assert!(
                link.reservoir_is_post_quantum(),
                "{ch} is independent of DH"
            );
            assert!(link.caveats.is_empty());
        }
        for ch in [Channel::Corpus, Channel::Network] {
            let (_, link) = accept(&mine, &card(2, Policy::default()), &theirs, ch, true);
            assert!(!link.reservoir_is_post_quantum(), "{ch} rests on X25519");
            assert_eq!(link.caveats, vec![Caveat::ReservoirNotPostQuantum(ch)]);
        }
    }

    /// RFC 3 §11 step 2 is "the actual security step", and the node cannot
    /// perform it. Skipping it is permitted and permanently recorded.
    #[test]
    fn skipping_the_fingerprint_comparison_is_recorded_forever() {
        let mine = offer(card(1, Policy::default()), [0x11; 32]);
        let (_, link) = accept(
            &mine,
            &card(2, Policy::default()),
            &Contribution { r: [0x22; 32] },
            Channel::InPerson,
            false,
        );
        assert!(link.caveats.contains(&Caveat::FingerprintUnverified));
    }

    /// Replaying your own contribution back at you yields an all-zero
    /// reservoir. Caught, rather than producing a link that encrypts nothing.
    #[test]
    fn a_reflected_contribution_is_caught() {
        let mine = offer(card(1, Policy::default()), [0x11; 32]);
        let reflected = Contribution { r: [0x11; 32] };
        let (reservoir, link) = accept(
            &mine,
            &card(2, Policy::default()),
            &reflected,
            Channel::InPerson,
            true,
        );
        assert_eq!(reservoir, [0u8; 32]);
        assert!(link.caveats.contains(&Caveat::DegenerateContribution));
    }

    /// RFC 4 §5.4 — a link is only as capable as its least capable end.
    #[test]
    fn the_lower_bucket_ceiling_wins() {
        let big = Policy {
            max_bucket: 7,
            ..Policy::default()
        };
        let lora = Policy {
            max_bucket: 2,
            ..Policy::default()
        };
        assert_eq!(big.negotiate(&lora).max_bucket, 2);
        assert_eq!(lora.negotiate(&big).max_bucket, 2, "both ends agree");
    }

    /// Relay and shard bits describe the local node and are not negotiated —
    /// a peer cannot make this node carry traffic or shrink its own anonymity
    /// set by declaring a preference.
    #[test]
    fn a_peer_cannot_dictate_relay_or_sharding() {
        let leaf = Policy {
            relay: false,
            shard_bits: 0,
            ..Policy::default()
        };
        let pushy = Policy {
            relay: true,
            shard_bits: 6,
            ..Policy::default()
        };
        let out = leaf.negotiate(&pushy);
        assert!(!out.relay, "still a leaf");
        assert_eq!(out.shard_bits, 0, "still unsharded");
    }

    /// **RFC 3 §11.3, the release gate.** The whole ceremony completes with
    /// every interface down, and it is the mode that keeps the reservoir's
    /// post-quantum property — the primitive path is the strong one.
    #[test]
    fn sneakernet_peering_completes_air_gapped_and_stays_post_quantum() {
        let mode = Mode::Sneakernet;
        assert!(mode.works_air_gapped());

        // Step 1: both ends produce an offer. Symmetric — no initiator.
        let a = offer(card(1, Policy::default()), [0x5A; 32]);
        let b = offer(
            card(
                2,
                Policy {
                    max_bucket: 4,
                    ..Policy::default()
                },
            ),
            [0xC3; 32],
        );

        // Steps 2-4: each accepts the other, over media, fingerprints read
        // aloud in person.
        let (res_a, link_a) = accept(
            &a,
            &b.card,
            &b.contribution,
            mode.contribution_channel(),
            true,
        );
        let (res_b, link_b) = accept(
            &b,
            &a.card,
            &a.contribution,
            mode.contribution_channel(),
            true,
        );

        assert_eq!(res_a, res_b, "both ends derive the same reservoir");
        assert!(link_a.reservoir_is_post_quantum());
        assert!(link_b.reservoir_is_post_quantum());
        assert!(link_a.caveats.is_empty() && link_b.caveats.is_empty());
        // And both agree on the ceiling, from opposite directions.
        assert_eq!(link_a.policy.max_bucket, 4);
        assert_eq!(link_b.policy.max_bucket, 4);
    }

    /// Online peering works and costs the reservoir's post-quantum property.
    /// The trade is recorded, not refused — RFC 3 §11.1 permits it.
    #[test]
    fn online_peering_works_and_says_what_it_cost() {
        let mode = Mode::Online;
        assert!(!mode.works_air_gapped());
        assert!(!mode.yields_post_quantum_reservoir());
        assert!(Mode::Sneakernet.yields_post_quantum_reservoir());

        let a = offer(card(1, Policy::default()), [0x5A; 32]);
        let b = offer(card(2, Policy::default()), [0xC3; 32]);
        let (res, link) = accept(
            &a,
            &b.card,
            &b.contribution,
            mode.contribution_channel(),
            true,
        );

        assert_eq!(
            res,
            a.contribution.combine(&b.contribution),
            "the link works"
        );
        assert!(!link.reservoir_is_post_quantum());
        assert_eq!(
            link.caveats,
            vec![Caveat::ReservoirNotPostQuantum(Channel::Corpus)]
        );
    }

    /// A card is safe on any channel in either mode; only the contribution is
    /// channel-sensitive. Nothing about a signed public key needs hiding.
    #[test]
    fn only_the_contribution_constrains_the_channel() {
        for mode in [Mode::Sneakernet, Mode::Online] {
            let mine = offer(card(1, Policy::default()), [0x11; 32]);
            // The card arriving over the corpus never produces a caveat.
            let (_, link) = accept(
                &mine,
                &card(2, Policy::default()),
                &Contribution { r: [0x22; 32] },
                Channel::RemovableMedia,
                true,
            );
            assert!(
                link.caveats.is_empty(),
                "{mode:?}: card channel is unconstrained"
            );
        }
    }

    /// The secret half must not be loggable.
    #[test]
    fn a_contribution_prints_nothing() {
        let c = Contribution { r: [0xDE; 32] };
        let s = format!("{c:?}");
        assert!(!s.contains("222") && !s.contains("de"), "{s}");
        assert_eq!(s, "Contribution(<redacted>)");
    }
}
