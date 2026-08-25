//! `peer-request` — first contact, RFC 3 §5.1.
//!
//! The one message a node can send to someone it has never met. It travels to
//! the recipient's **inbox tag** (RFC 1 §6.2, RFC 2 §4.2), which anyone holding
//! their public key can compute — and that is the entire mechanism, because at
//! first contact there is nothing else both parties share.
//!
//! # Why it cannot be deniable, and why that is right
//!
//! Inbox mode forces `mode_base`: `mode_auth` decapsulation requires the
//! sender's static public key as an input, and a recipient meeting someone for
//! the first time does not have it. RFC 2 §4.2 calls the coupling "not a policy
//! choice but a consequence."
//!
//! So origin travels as an **inner Ed25519 signature** instead, and RFC 3 §5.1
//! notes this is the right place for the deniability boundary to fall: a
//! first-contact message "is also the message a recipient is most likely to
//! want to be able to prove later."
//!
//! # The cost, stated rather than hidden
//!
//! An inbox tag is computable by anyone with the recipient's public key, so
//! messages to it are **linkable within an epoch** (RFC 2 §4.2). Two
//! peer-requests to the same person on the same day are visibly to the same
//! person. It rotates out at the epoch boundary and that is the whole
//! mitigation.
//!
//! RFC 2 §4.2 is explicit that this is "a real cost, accepted rather than
//! hidden", and that inbox mode is used "for `peer-request` (RFC 3 §5.1) and
//! nothing else." Nothing else in this implementation constructs one.
//!
//! # It reaches a node with no network at all
//!
//! Because it is an ordinary corpus object, a peer-request reaches someone
//! reachable only by courier (RFC 3 §5.1). That is why rollcall entries carry
//! no endpoints — a request does not need one.

use crate::credential;
use crate::introduction;
use crate::peering::Card;
use krab_core::cbor::{Error as CborError, Item, Reader, Writer};
use krab_crypto::sign::{Sig, SigningKey, VerifyingKey};

/// What a request's `evidence` field establishes — RFC 3 §5.1 key 4.
///
/// No variant means "accept". §10 gives the protocol the facts and the
/// operator the judgement, and a verdict called `Trusted` would be this module
/// making the second one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {
    /// No credential attached. Common and not a failure — most first contact
    /// is unvouched, and §5.1 makes the field optional.
    Absent,
    /// A credential that does not verify. See [`credential::Invalid`].
    Invalid(credential::Invalid),
    /// It verifies, and is between two nodes other than the introducer and
    /// the requester. **Any real credential verifies**, so this is the check
    /// that matters: without it, an attacker attaches somebody else's genuine
    /// peering and it passes.
    WrongParties,
    /// The introducer and the requester really did peer, mutually signed by
    /// both, unexpired. **Still not a reason to say yes.**
    Confirms,
}

/// Domain label for the inner signature. Frozen.
///
/// Distinct from `peering::DOMAIN_CARD` so a card signature is not a valid
/// request signature — the general rule proposed in `AMENDMENTS.md` §A.
pub const DOMAIN_REQUEST: &[u8] = b"krab/req/v1";

/// RFC 3 §5.1's document.
///
/// # The key numbers are §5.1's, and once were not
///
/// §5.1 tabulates keys 0–7, and an earlier encoder here flattened `terms`
/// across keys 5, 6 and 7. That put `relay` where §5.1 puts the **introduction
/// token** and `retention_bytes` where it puts the **note**, so a second
/// implementation written from the table would have disagreed about every
/// field after `to` — and, because a peer-request that fails to parse is
/// simply a peering that never happens, neither side would have learned why.
///
/// Fixed here rather than worked around, since adding key 6 was impossible
/// without it and gate 1 is about exactly this class of disagreement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRequest {
    /// Key 1 — the requester's keys, as a full card so the recipient learns
    /// everything needed to reply.
    pub from: Card,
    /// Key 2 — the recipient's node identifier.
    pub to: [u8; 32],
    /// Key 3 — the introducer's node id, when there is one (RFC 3 §10).
    ///
    /// Separate from the token so the recipient can say *whose* introduction
    /// this claims to be before evaluating anything, and so a request naming
    /// an introducer with no token is visibly that rather than silently
    /// unvouched.
    pub via: Option<[u8; 32]>,
    /// Key 4 — the introducer's `peer-link` with the requester (RFC 3 §5.1).
    ///
    /// **What makes the vouch checkable rather than merely signed.** §10 calls
    /// it "the cryptographic component: the introducer's signed link with the
    /// requester proves the vouch is real."
    ///
    /// A token alone says *someone* vouched. It is worth something only to an
    /// evaluator who already peers with that someone. Evidence adds a second,
    /// independent fact — that the introducer and the requester really did
    /// peer, mutually signed by both — which is checkable by anyone, including
    /// an evaluator who has never met the introducer.
    ///
    /// It is a deliberate disclosure of one graph edge to one party. RFC 3
    /// §9.1 forbids *publishing* a link; this is the opposite of publishing —
    /// it travels inside a sealed object addressed to the single node
    /// evaluating it, and only because the requester chose to send it.
    pub evidence: Option<credential::Credential>,
    /// Key 5 — proposed terms: what this node will accept from the recipient.
    ///
    /// `LinkTerms`, not `Policy`. RFC 3 §6's own example proposes "10 MB/day,
    /// 30 d retention, all shards, all classes" — three of those four have
    /// nowhere to live in a card's advertisement, so a request carrying one
    /// could not open a negotiation about anything §6 cares about.
    pub terms: credential::LinkTerms,
    /// Key 6 — an introduction token (RFC 3 §10), when there is one.
    ///
    /// **Private by construction.** It is only ever here, inside a sealed
    /// object addressed to the one party evaluating it. Nothing publishes a
    /// token, and there is no bulletin kind that could.
    pub token: Option<introduction::Token>,
    /// Key 7 — a free-text note, read by a human and by nothing else.
    ///
    /// RFC 3 §5.1 sizes the document at 683 B without one and 804 B with 120
    /// bytes of note — still a single QR code either way.
    pub note: String,
    /// The inner Ed25519 signature over everything above.
    ///
    /// Key 8. §5.1's table stops at 7 and §3 writes signatures as `—`, so the
    /// number is this implementation's choice; it is recorded in
    /// `AMENDMENTS.md` rather than left for a second implementation to guess.
    pub sig: [u8; 64],
}

impl PeerRequest {
    /// The bytes the signature covers.
    ///
    /// Optional fields are **omitted when absent**, never encoded as a null or
    /// an empty string: deterministic CBOR (RFC 1 §4.3) has one encoding per
    /// value, and a present-but-empty token is a different document from no
    /// token — one claims a vouch and the other does not.
    fn signed_bytes(
        from: &Card,
        to: &[u8; 32],
        via: Option<&[u8; 32]>,
        evidence: Option<&credential::Credential>,
        terms: &credential::LinkTerms,
        token: Option<&introduction::Token>,
        note: &str,
    ) -> Vec<u8> {
        // Keys 0, 1, 2, 5 and 7 always appear; 3, 4 and 6 only when present.
        let n = 5
            + usize::from(via.is_some())
            + usize::from(evidence.is_some())
            + usize::from(token.is_some());
        let mut w = Writer::new();
        w.map(n);
        w.uint(0).uint(1); // version
        w.uint(1).bstr(&from.encode());
        w.uint(2).bstr(to);
        if let Some(v) = via {
            w.uint(3).bstr(v);
        }
        if let Some(e) = evidence {
            w.uint(4).bstr(&e.encode());
        }
        w.uint(5).bstr(&terms.encode());
        if let Some(t) = token {
            w.uint(6).bstr(&t.encode());
        }
        w.uint(7).tstr(note);
        let body = w.finish();

        let mut out = Vec::with_capacity(DOMAIN_REQUEST.len() + body.len());
        out.extend_from_slice(DOMAIN_REQUEST);
        out.extend_from_slice(&body);
        out
    }

    /// Build and sign a request, with or without an introduction — RFC 3 §10.
    ///
    /// There is deliberately no shorter `create` taking no token. Two
    /// constructors for one document is how the unvouched path and the vouched
    /// path come to differ in something other than the token.
    ///
    /// `via` is taken from the token rather than passed separately, so the two
    /// cannot disagree: a request naming one introducer and carrying another's
    /// vouch is a document with no useful reading.
    pub fn create_introduced(
        signing: &SigningKey,
        from: Card,
        to: [u8; 32],
        terms: credential::LinkTerms,
        note: &str,
        token: Option<introduction::Token>,
        evidence: Option<credential::Credential>,
    ) -> PeerRequest {
        let via = token.as_ref().map(|t| t.introducer);
        // Evidence without a token names an introducer who vouched for
        // nothing, so it is dropped rather than sent: a credential is a graph
        // edge, and disclosing one that supports no claim is a disclosure for
        // no reason.
        let evidence = token.as_ref().and(evidence);
        let msg = PeerRequest::signed_bytes(
            &from,
            &to,
            via.as_ref(),
            evidence.as_ref(),
            &terms,
            token.as_ref(),
            note,
        );
        let sig = signing.sign(&msg).0;
        PeerRequest {
            from,
            to,
            via,
            evidence,
            terms,
            token,
            note: note.to_string(),
            sig,
        }
    }

    /// Whether the inner signature is valid.
    ///
    /// **This is the only thing authenticating the sender**, since `mode_base`
    /// binds no sender key. A caller that skipped it would accept a request
    /// from anyone claiming to be anyone.
    ///
    /// It also checks the embedded card, because a request whose card does not
    /// verify carries statics nobody vouched for — and those statics are what
    /// the recipient would peer with.
    #[must_use]
    pub fn verify(&self) -> bool {
        if !self.from.verify() {
            return false;
        }
        // A request naming an introducer the token does not match has no
        // useful reading — `create_introduced` derives one from the other, so
        // a mismatch means it was assembled somewhere else.
        if self.via != self.token.as_ref().map(|t| t.introducer) {
            return false;
        }
        // The signature must be by the identity the card names, or the request
        // is a valid card wrapped in someone else's claim.
        let msg = PeerRequest::signed_bytes(
            &self.from,
            &self.to,
            self.via.as_ref(),
            self.evidence.as_ref(),
            &self.terms,
            self.token.as_ref(),
            &self.note,
        );
        VerifyingKey::from_bytes(self.from.identity_pk).verify(&msg, &Sig(self.sig))
    }

    /// What the attached evidence proves — RFC 3 §5.1 key 4, §10.
    ///
    /// **Facts, not a judgement.** §10 divides the two deliberately: "the
    /// protocol establishes facts, the operator makes judgements." So this
    /// answers whether the introducer and the requester provably peered, and
    /// says nothing about whether that is reason enough.
    pub fn evidence_verdict(&self, now_s: u64) -> Evidence {
        let Some(cred) = &self.evidence else {
            return Evidence::Absent;
        };
        let Some(via) = self.via else {
            // Evidence naming no introducer supports no claim. `verify`
            // already refuses a `via` that disagrees with the token, so this
            // is a request assembled somewhere other than by this program.
            return Evidence::WrongParties;
        };
        if let Err(why) = cred.verify(now_s) {
            return Evidence::Invalid(why);
        }
        // **The parties must be the two this request is about.** A valid
        // credential between two other nodes proves a peering that has nothing
        // to do with the person asking — and it is exactly what an attacker
        // would attach, because any real credential verifies.
        if !cred.is_between(&via, &self.from.node_id()) {
            return Evidence::WrongParties;
        }
        Evidence::Confirms
    }

    /// Evaluate the introduction this request carries, if any — RFC 3 §10.
    ///
    /// Returns `None` when the request claims no introduction, which is not a
    /// failure: most first contacts are unvouched, and §10's token is
    /// optional in §5.1's table.
    ///
    /// **Bound to this request's sender.** The requester passed to
    /// [`introduction::Token::evaluate`] is the card's node id, not anything
    /// the token says, so a token minted for someone else cannot be attached
    /// to a request and pass.
    pub fn introduction(
        &self,
        introducer_key: Option<&VerifyingKey>,
        me: &[u8; 32],
        now_s: u64,
        spent: &introduction::Spent,
    ) -> Option<introduction::Verdict> {
        let token = self.token.as_ref()?;
        Some(token.evaluate(introducer_key, me, &self.from.node_id(), now_s, spent))
    }

    /// Whether this request is addressed to `node_id`.
    ///
    /// Checked separately from [`PeerRequest::verify`]: an inbox tag is
    /// computable by anyone, so a node will occasionally decrypt a request
    /// that opened by coincidence of tag collision. A valid request for
    /// someone else is not an attack and not an error.
    pub fn is_for(&self, node_id: &[u8; 32]) -> bool {
        self.to == *node_id
    }

    /// Deterministic CBOR, signature included.
    pub fn encode(&self) -> Vec<u8> {
        // As `signed_bytes`, plus key 8 for the signature.
        let n = 6
            + usize::from(self.via.is_some())
            + usize::from(self.evidence.is_some())
            + usize::from(self.token.is_some());
        let mut w = Writer::new();
        w.map(n);
        w.uint(0).uint(1);
        w.uint(1).bstr(&self.from.encode());
        w.uint(2).bstr(&self.to);
        if let Some(v) = &self.via {
            w.uint(3).bstr(v);
        }
        if let Some(e) = &self.evidence {
            w.uint(4).bstr(&e.encode());
        }
        w.uint(5).bstr(&self.terms.encode());
        if let Some(t) = &self.token {
            w.uint(6).bstr(&t.encode());
        }
        w.uint(7).tstr(&self.note);
        w.uint(8).bstr(&self.sig);
        w.finish()
    }

    /// Decode. **Does not verify** — see [`PeerRequest::verify`].
    pub fn decode(bytes: &[u8]) -> Result<PeerRequest, CborError> {
        let mut r = Reader::new(bytes);
        let mut m = r.map()?;
        let (mut from, mut to, mut note, mut sig) = (None, None, String::new(), None);
        let (mut via, mut token, mut terms) = (None, None, None);
        let mut evidence = None;
        // Keys 0, 1, 2, 5, 7 and 8 are required; 3 and 6 are optional, so the
        // mask covers the six that must appear and nothing else.
        let mut seen = 0u8;
        while let Some(key) = m.key()? {
            match (key, m.value()?) {
                (0, Item::Uint(1)) => seen |= 1,
                (1, Item::Bstr(b)) => {
                    from = Some(Card::decode(b)?);
                    seen |= 2;
                }
                (2, Item::Bstr(b)) => {
                    to = <[u8; 32]>::try_from(b).ok();
                    seen |= 4;
                }
                (3, Item::Bstr(b)) => {
                    via = Some(<[u8; 32]>::try_from(b).map_err(|_| CborError::Malformed)?);
                }
                (4, Item::Bstr(b)) => {
                    evidence = Some(credential::Credential::decode(b).ok_or(CborError::Malformed)?);
                }
                (5, Item::Bstr(b)) => {
                    terms = Some(credential::LinkTerms::decode(b).ok_or(CborError::Malformed)?);
                    seen |= 8;
                }
                (6, Item::Bstr(b)) => {
                    token = Some(introduction::Token::decode(b).ok_or(CborError::Malformed)?);
                }
                (7, Item::Tstr(t)) => {
                    note = t.to_string();
                    seen |= 16;
                }
                (8, Item::Bstr(b)) => {
                    sig = <[u8; 64]>::try_from(b).ok();
                    seen |= 32;
                }
                _ => return Err(CborError::Malformed),
            }
        }
        if seen != 0x3F {
            return Err(CborError::Truncated);
        }
        Ok(PeerRequest {
            from: from.ok_or(CborError::Truncated)?,
            to: to.ok_or(CborError::Truncated)?,
            via,
            evidence,
            terms: terms.ok_or(CborError::Truncated)?,
            token,
            note,
            sig: sig.ok_or(CborError::Truncated)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use krab_crypto::rng::NotRandom;

    fn signer(seed: u64) -> SigningKey {
        SigningKey::generate(&mut NotRandom::seeded(seed))
    }

    fn card_for(k: &SigningKey, seed: u8) -> Card {
        Card::create(
            k,
            [seed; 32],
            [seed.wrapping_add(1); 32],
            crate::peering::Policy::default(),
        )
    }

    fn request(seed: u64, to: [u8; 32], note: &str) -> PeerRequest {
        let k = signer(seed);
        let c = card_for(&k, seed as u8);
        PeerRequest::create_introduced(
            &k,
            c,
            to,
            credential::LinkTerms::default(),
            note,
            None,
            None,
        )
    }

    #[test]
    fn a_request_round_trips_and_verifies() {
        let r = request(1, [9; 32], "we met at the thing on Tuesday");
        assert!(r.verify());
        let back = PeerRequest::decode(&r.encode()).unwrap();
        assert_eq!(back, r);
        assert!(back.verify(), "the signature survives encoding");
    }

    /// **The inner signature is the only authentication.** `mode_base` binds no
    /// sender key, so a request that does not verify is a request from nobody.
    #[test]
    fn any_change_invalidates_the_inner_signature() {
        let r = request(2, [9; 32], "hello");
        for mutate in [
            |r: &mut PeerRequest| r.to[0] ^= 1,
            |r: &mut PeerRequest| r.note.push('!'),
            |r: &mut PeerRequest| r.terms.policy.max_bucket = 1,
            |r: &mut PeerRequest| r.terms.policy.relay = !r.terms.policy.relay,
            |r: &mut PeerRequest| r.terms.bytes_per_day += 1,
            |r: &mut PeerRequest| r.sig[0] ^= 1,
        ] {
            let mut bad = r.clone();
            mutate(&mut bad);
            assert!(!bad.verify(), "a mutated request must not verify");
        }
    }

    /// **A valid card wrapped in someone else's claim.** Swapping the embedded
    /// card keeps both artifacts individually valid and must still fail: the
    /// signature has to be by the identity the card names.
    #[test]
    fn a_request_cannot_carry_someone_elses_card() {
        let mut r = request(3, [9; 32], "note");
        let other = signer(4);
        r.from = card_for(&other, 4);
        assert!(r.from.verify(), "the substituted card is itself valid");
        assert!(!r.verify(), "but it is not who signed the request");
    }

    /// A card that does not verify carries statics nobody vouched for — and
    /// those statics are what the recipient would peer with.
    #[test]
    fn a_request_with_an_unverifiable_card_is_refused() {
        let mut r = request(5, [9; 32], "note");
        r.from.noise_static_pk[0] ^= 1;
        assert!(!r.from.verify());
        assert!(!r.verify());
    }

    /// An inbox tag is computable by anyone, so a request may open by
    /// coincidence. Being addressed elsewhere is not an attack.
    #[test]
    fn addressing_is_checked_separately_from_authenticity() {
        let r = request(6, [0xAA; 32], "note");
        assert!(r.verify(), "genuinely signed");
        assert!(r.is_for(&[0xAA; 32]));
        assert!(!r.is_for(&[0xBB; 32]), "and genuinely not for us");
    }

    /// RFC 3 §5.1's size: 683 B without a note, 804 B with 120 bytes of note.
    /// Both fit a single QR code, which is the property that matters.
    #[test]
    fn the_document_stays_within_a_single_qr_code() {
        let bare = request(7, [1; 32], "");
        let noted = request(7, [1; 32], &"x".repeat(120));
        assert!(bare.encode().len() < 900, "{} bytes", bare.encode().len());
        assert_eq!(noted.encode().len() - bare.encode().len(), 120 + 1);
        // A QR code at version 20 / level M holds about 1 060 bytes.
        assert!(
            noted.encode().len() < 1_060,
            "{} bytes",
            noted.encode().len()
        );
    }

    /// A free-text note is read by a human and by nothing else, so it must
    /// survive anything a human types.
    #[test]
    fn the_note_survives_arbitrary_text() {
        for note in ["", "→ café ✓", "line\nbreak", "\"quotes\" and \\slashes\\"] {
            let r = request(8, [2; 32], note);
            let back = PeerRequest::decode(&r.encode()).unwrap();
            assert_eq!(back.note, note);
            assert!(back.verify());
        }
    }

    #[test]
    fn malformed_input_is_refused_at_every_truncation() {
        let bytes = request(9, [3; 32], "note").encode();
        for n in 0..bytes.len() {
            let _ = PeerRequest::decode(&bytes[..n]);
        }
        assert!(PeerRequest::decode(&[]).is_err());
        assert!(PeerRequest::decode(&[0xFF; 20]).is_err());
    }

    /// The request domain is distinct from the card domain, so neither
    /// signature is valid as the other — `AMENDMENTS.md` §A's general rule.
    #[test]
    fn the_signing_domains_are_disjoint() {
        assert_ne!(DOMAIN_REQUEST, crate::peering::DOMAIN_CARD);
        let r = request(10, [4; 32], "n");
        assert!(
            PeerRequest::signed_bytes(&r.from, &r.to, None, None, &r.terms, None, &r.note)
                .starts_with(DOMAIN_REQUEST)
        );
    }
}
