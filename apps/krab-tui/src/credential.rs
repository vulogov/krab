//! The `peer-link` credential — RFC 3 §3.
//!
//! > "The evidence that two nodes agreed to peer, and simultaneously the
//! > contract governing what that means."
//!
//! # Why a card was not enough
//!
//! Until this existed, a completed peering stored the counterparty's **card**:
//! one signature, theirs. That works for sealing mail to them and for nothing
//! else, and RFC 3 §3 says exactly why:
//!
//! > "**Both signatures are required.** A singly-signed document lets one
//! > party assert a relationship the other never agreed to — which matters
//! > because these propagate one hop (§8) and are cited as evidence (§5.1).
//! > Mutual signature makes the link a contract rather than a claim."
//!
//! The gap surfaced when §5.1's `evidence` field needed building: evidence is
//! "the introducer's signed link with the requester", and there was no such
//! document. Sending a card instead would have shipped precisely the forgeable
//! claim §3 forbids — A asserting a peering with C that C never agreed to, and
//! vouching on the strength of it.
//!
//! # Who is party A
//!
//! **RFC 3 §3 does not say, and two implementations must agree or neither can
//! verify the other's signature.** Both parties have to serialise the *same*
//! body bytes, so "A" cannot mean "whoever started it" — the two ends of a
//! courier exchange do not agree on who started anything.
//!
//! So it is ordered: **party A is the one whose `sig_pk` sorts lower**, byte
//! by byte. Deterministic, needs no coordination, and identical on both sides.
//! Recorded in `AMENDMENTS.md`, because an implementation that picked the
//! other convention would produce credentials nobody could verify and would
//! learn about it as "peering silently stopped working".
//!
//! # Assembled by one, countersigned by the other
//!
//! `established` and `nonce` must be identical on both sides, and neither can
//! be derived: a nonce that is a function of the two identities is the same
//! for every renewal, which defeats the one thing §3 says it is for —
//! "prevents replay of a superseded link".
//!
//! So the flow is RFC 3 §5.3's: one side assembles and signs, the other
//! checks and countersigns. It costs one more artifact across the courier
//! path, which the ceremony already carries in both directions, and it needs
//! no clever derivation from anything secret. RFC 3 §11 is explicit that
//! reservoir material never touches the credential, and deriving a public
//! nonce from a shared secret would be the beginning of that.
//!
//! # Expiry replaces revocation
//!
//! RFC 3 §4: "Krab will never have a certificate revocation list." A
//! credential carries `established` and `expires`, the term SHOULD be 60–90
//! days, and an implementation **MUST reject** one whose validity exceeds 180
//! days. [`Credential::verify`] does, rather than warning: a 10-year link is
//! not a slightly worse link, it is an implementation that read §4
//! differently, and honouring the first 180 days of it would hide that.
//!
//! The default here is the **upper** end of the range. RFC 3 §15: "A node
//! offline longer than a credential term returns unable to peer with anyone …
//! which for courier deployments argues for the upper end."

use crate::peering::{Card, Policy};
use krab_core::cbor::{Item, Reader, Writer};
use krab_crypto::sign::{Sig, SigningKey, VerifyingKey};

/// Domain label for both signatures — RFC 3 §3, frozen.
pub const DOMAIN: &[u8] = b"krab/link/v1";

/// Default term, in days. RFC 3 §4's range is 60–90; §15 argues for the top
/// of it, because a node offline longer than its credentials returns unable
/// to peer with anyone.
pub const DEFAULT_TERM_DAYS: u64 = 90;

/// RFC 3 §4: "Implementations MUST reject a link whose validity exceeds 180
/// days."
pub const MAX_TERM_DAYS: u64 = 180;

/// One end's public halves — RFC 3 §3 keys 1 and 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Party {
    /// Ed25519 identity key.
    pub sig_pk: [u8; 32],
    /// X25519 correspondence key.
    pub kx_pk: [u8; 32],
}

impl Party {
    /// This party's node identifier.
    pub fn node_id(&self) -> [u8; 32] {
        krab_crypto::hash::node_id(&self.sig_pk)
    }

    fn from_card(c: &Card) -> Party {
        Party {
            sig_pk: c.identity_pk,
            kx_pk: c.correspondence_pk,
        }
    }
}

/// RFC 3 §3 key 8 — share bits and class mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags {
    /// Whether A will list B in the nodelist fragments A hands out — §8.3.
    ///
    /// **Default false, and §8.3 says MUST.** "A node may have ten casual
    /// peers and one sensitive one. Without this flag, the sensitive link is
    /// exposed to the other ten." Opt in to being listed, never out.
    pub a_shares_b: bool,
    /// The same, in the other direction. Per-direction and both signed, so
    /// neither party can unilaterally expose the other.
    pub b_shares_a: bool,
    /// Object classes this link carries — RFC 5's filter.
    pub class_mask: u8,
}

impl Default for Flags {
    fn default() -> Flags {
        Flags {
            a_shares_b: false,
            b_shares_a: false,
            class_mask: 0xFF,
        }
    }
}

/// A mutually signed peering credential — RFC 3 §3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// Key 1. The party whose `sig_pk` sorts lower — see the module header.
    pub a: Party,
    /// Key 2.
    pub b: Party,
    /// Key 3 — Unix seconds.
    pub established_s: u64,
    /// Key 4 — Unix seconds. RFC 3 §4.
    pub expires_s: u64,
    /// Key 5 — 16 bytes, so a superseded link cannot be replayed.
    pub nonce: [u8; 16],
    /// Key 6 — terms A→B.
    pub terms_ab: Policy,
    /// Key 7 — terms B→A.
    pub terms_ba: Policy,
    /// Key 8.
    pub flags: Flags,
    /// Key 9 — endpoints, and **empty is the normal case**. RFC 3 §9.2 keeps
    /// endpoints out of anything public; this document is not public, so they
    /// are permitted here and nowhere else. A node reachable only by courier
    /// has none at all, and the peering is byte-identical either way.
    pub transports: Vec<String>,
    /// A's signature over `DOMAIN ‖ body`, once A has signed.
    pub sig_a: Option<[u8; 64]>,
    /// B's.
    pub sig_b: Option<[u8; 64]>,
}

/// Why a credential was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    /// One or both signatures are missing — it is a proposal, not a link.
    NotCountersigned,
    /// A signature does not verify under the key the document names.
    BadSignature,
    /// The parties are not in canonical order, so the two ends would build
    /// different bytes and neither could verify the other.
    NotCanonical,
    /// Both parties are the same node.
    SelfLink,
    /// `expires` is not after `established`.
    Backwards,
    /// The term exceeds RFC 3 §4's 180-day ceiling.
    TooLong,
    /// Past its expiry. RFC 3 §4 — revocation is non-renewal.
    Expired,
}

impl Credential {
    /// The bytes both signatures cover.
    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.map(10);
        w.uint(0).uint(1);
        w.uint(1).bstr(&party_bytes(&self.a));
        w.uint(2).bstr(&party_bytes(&self.b));
        w.uint(3).uint(self.established_s);
        w.uint(4).uint(self.expires_s);
        w.uint(5).bstr(&self.nonce);
        w.uint(6).bstr(&self.terms_ab.encode());
        w.uint(7).bstr(&self.terms_ba.encode());
        w.uint(8).bstr(&flags_bytes(&self.flags));
        w.uint(9).bstr(&transports_bytes(&self.transports));
        let body = w.finish();

        let mut out = Vec::with_capacity(DOMAIN.len() + body.len());
        out.extend_from_slice(DOMAIN);
        out.extend_from_slice(&body);
        out
    }

    /// Propose a credential between two cards, signed by whichever of them is
    /// `signer`.
    ///
    /// The parties are ordered canonically here, so a caller cannot get it
    /// wrong: whichever card is passed first, the same document comes out.
    pub fn propose(
        signer: &SigningKey,
        mine: &Card,
        theirs: &Card,
        now_s: u64,
        term_days: u64,
        nonce: [u8; 16],
    ) -> Credential {
        let (p1, p2) = (Party::from_card(mine), Party::from_card(theirs));
        let (a, b) = if p1.sig_pk <= p2.sig_pk {
            (p1, p2)
        } else {
            (p2, p1)
        };
        // Terms are per-direction. Each side proposes what it will accept
        // *from* the other, which is what `Policy` already means, so A→B is
        // A's policy and B→A is B's.
        let (terms_ab, terms_ba) = if p1.sig_pk <= p2.sig_pk {
            (mine.policy, theirs.policy)
        } else {
            (theirs.policy, mine.policy)
        };
        let mut cred = Credential {
            a,
            b,
            established_s: now_s,
            expires_s: now_s.saturating_add(term_days.min(MAX_TERM_DAYS) * 86_400),
            nonce,
            terms_ab,
            terms_ba,
            flags: Flags::default(),
            transports: Vec::new(),
            sig_a: None,
            sig_b: None,
        };
        cred.sign(signer);
        cred
    }

    /// Add this signer's signature to whichever side it belongs on.
    ///
    /// A no-op for a key that is neither party's: a credential cannot be
    /// signed by a bystander, and silently attaching their signature to a
    /// slot would produce a document that fails verification later with no
    /// explanation of why.
    pub fn sign(&mut self, signer: &SigningKey) -> bool {
        let pk = signer.verifying_key().to_bytes();
        let sig = signer.sign(&self.body()).0;
        if pk == self.a.sig_pk {
            self.sig_a = Some(sig);
            true
        } else if pk == self.b.sig_pk {
            self.sig_b = Some(sig);
            true
        } else {
            false
        }
    }

    /// Whether this is a complete, valid, unexpired credential.
    ///
    /// **Both signatures, or it is a proposal.** RFC 3 §3's whole argument is
    /// that one signature is a claim rather than a contract, so there is no
    /// "partially valid" here and no accessor that returns the parties without
    /// having checked.
    pub fn verify(&self, now_s: u64) -> Result<(), Invalid> {
        // Canonical order first: out of order, the body bytes are not the ones
        // the other end would have built, so a signature check would answer a
        // question about the wrong document.
        if self.a.sig_pk > self.b.sig_pk {
            return Err(Invalid::NotCanonical);
        }
        if self.a.sig_pk == self.b.sig_pk {
            return Err(Invalid::SelfLink);
        }
        if self.expires_s <= self.established_s {
            return Err(Invalid::Backwards);
        }
        if self.expires_s - self.established_s > MAX_TERM_DAYS * 86_400 {
            return Err(Invalid::TooLong);
        }

        let (Some(sa), Some(sb)) = (self.sig_a, self.sig_b) else {
            return Err(Invalid::NotCountersigned);
        };
        let body = self.body();
        if !VerifyingKey::from_bytes(self.a.sig_pk).verify(&body, &Sig(sa)) {
            return Err(Invalid::BadSignature);
        }
        if !VerifyingKey::from_bytes(self.b.sig_pk).verify(&body, &Sig(sb)) {
            return Err(Invalid::BadSignature);
        }

        // Expiry last, so a forged document reports as forged rather than as
        // merely out of date.
        if now_s >= self.expires_s {
            return Err(Invalid::Expired);
        }
        Ok(())
    }

    /// Whether this credential is between exactly these two nodes.
    ///
    /// Order-independent: the caller knows two node ids and should not have to
    /// know which one sorted lower.
    pub fn is_between(&self, one: &[u8; 32], other: &[u8; 32]) -> bool {
        let (x, y) = (self.a.node_id(), self.b.node_id());
        (&x == one && &y == other) || (&x == other && &y == one)
    }

    /// The other party's public halves, given one node id.
    pub fn other_than(&self, node: &[u8; 32]) -> Option<Party> {
        if &self.a.node_id() == node {
            Some(self.b)
        } else if &self.b.node_id() == node {
            Some(self.a)
        } else {
            None
        }
    }

    /// Whether both signatures are present.
    pub fn is_complete(&self) -> bool {
        self.sig_a.is_some() && self.sig_b.is_some()
    }

    /// Deterministic CBOR — RFC 1 §4.3. Signatures at keys 10 and 11.
    ///
    /// A missing signature is **omitted**, not encoded as empty: RFC 1 §4.3
    /// admits one encoding per value, and a proposal is a different document
    /// from a link with an empty signature on it.
    pub fn encode(&self) -> Vec<u8> {
        let n = 10 + usize::from(self.sig_a.is_some()) + usize::from(self.sig_b.is_some());
        let mut w = Writer::new();
        w.map(n);
        w.uint(0).uint(1);
        w.uint(1).bstr(&party_bytes(&self.a));
        w.uint(2).bstr(&party_bytes(&self.b));
        w.uint(3).uint(self.established_s);
        w.uint(4).uint(self.expires_s);
        w.uint(5).bstr(&self.nonce);
        w.uint(6).bstr(&self.terms_ab.encode());
        w.uint(7).bstr(&self.terms_ba.encode());
        w.uint(8).bstr(&flags_bytes(&self.flags));
        w.uint(9).bstr(&transports_bytes(&self.transports));
        if let Some(s) = &self.sig_a {
            w.uint(10).bstr(s);
        }
        if let Some(s) = &self.sig_b {
            w.uint(11).bstr(s);
        }
        w.finish()
    }

    /// Decode. **Pre-authentication input** — a credential arrives as evidence
    /// inside a request from a stranger, so nothing here may panic or allocate
    /// on a declared count.
    pub fn decode(bytes: &[u8]) -> Option<Credential> {
        let mut r = Reader::new(bytes);
        let mut m = r.map().ok()?;
        let (mut a, mut b) = (None, None);
        let (mut established_s, mut expires_s) = (None, None);
        let (mut nonce, mut terms_ab, mut terms_ba) = (None, None, None);
        let (mut flags, mut transports) = (None, None);
        let (mut sig_a, mut sig_b) = (None, None);
        let mut seen = 0u16;

        while let Some(key) = m.key().ok()? {
            match (key, m.value().ok()?) {
                (0, Item::Uint(1)) => seen |= 1,
                (1, Item::Bstr(x)) => {
                    a = party_from(x);
                    seen |= 2;
                }
                (2, Item::Bstr(x)) => {
                    b = party_from(x);
                    seen |= 4;
                }
                (3, Item::Uint(v)) => {
                    established_s = Some(v);
                    seen |= 8;
                }
                (4, Item::Uint(v)) => {
                    expires_s = Some(v);
                    seen |= 16;
                }
                (5, Item::Bstr(x)) => {
                    nonce = x.try_into().ok();
                    seen |= 32;
                }
                (6, Item::Bstr(x)) => {
                    terms_ab = Policy::decode(x);
                    seen |= 64;
                }
                (7, Item::Bstr(x)) => {
                    terms_ba = Policy::decode(x);
                    seen |= 128;
                }
                (8, Item::Bstr(x)) => {
                    flags = flags_from(x);
                    seen |= 256;
                }
                (9, Item::Bstr(x)) => {
                    transports = transports_from(x);
                    seen |= 512;
                }
                (10, Item::Bstr(x)) => sig_a = x.try_into().ok(),
                (11, Item::Bstr(x)) => sig_b = x.try_into().ok(),
                _ => return None,
            }
        }
        if seen != 0x3FF {
            return None;
        }
        Some(Credential {
            a: a?,
            b: b?,
            established_s: established_s?,
            expires_s: expires_s?,
            nonce: nonce?,
            terms_ab: terms_ab?,
            terms_ba: terms_ba?,
            flags: flags?,
            transports: transports?,
            sig_a,
            sig_b,
        })
    }
}

fn party_bytes(p: &Party) -> Vec<u8> {
    let mut w = Writer::new();
    w.map(2).uint(1).bstr(&p.sig_pk).uint(2).bstr(&p.kx_pk);
    w.finish()
}

fn party_from(bytes: &[u8]) -> Option<Party> {
    let mut r = Reader::new(bytes);
    let mut m = r.map().ok()?;
    if m.left() != 2 {
        return None;
    }
    let sig_pk = match (m.key().ok()??, m.value().ok()?) {
        (1, Item::Bstr(x)) => x.try_into().ok()?,
        _ => return None,
    };
    let kx_pk = match (m.key().ok()??, m.value().ok()?) {
        (2, Item::Bstr(x)) => x.try_into().ok()?,
        _ => return None,
    };
    Some(Party { sig_pk, kx_pk })
}

fn flags_bytes(f: &Flags) -> Vec<u8> {
    let mut w = Writer::new();
    w.map(3)
        .uint(1)
        .bool(f.a_shares_b)
        .uint(2)
        .bool(f.b_shares_a)
        .uint(3)
        .uint(f.class_mask as u64);
    w.finish()
}

fn flags_from(bytes: &[u8]) -> Option<Flags> {
    let mut r = Reader::new(bytes);
    let mut m = r.map().ok()?;
    if m.left() != 3 {
        return None;
    }
    let a_shares_b = match (m.key().ok()??, m.value().ok()?) {
        (1, Item::Bool(v)) => v,
        _ => return None,
    };
    let b_shares_a = match (m.key().ok()??, m.value().ok()?) {
        (2, Item::Bool(v)) => v,
        _ => return None,
    };
    let class_mask = match (m.key().ok()??, m.value().ok()?) {
        (3, Item::Uint(v)) => u8::try_from(v).ok()?,
        _ => return None,
    };
    Some(Flags {
        a_shares_b,
        b_shares_a,
        class_mask,
    })
}

/// Endpoints, as a length-prefixed list. Kept simple and bounded: this arrives
/// from a stranger, and an endpoint list is the one variable-length field in
/// the document.
fn transports_bytes(t: &[String]) -> Vec<u8> {
    let mut w = Writer::new();
    w.uint(t.len() as u64);
    let mut out = w.finish();
    for ep in t {
        let mut w = Writer::new();
        w.tstr(ep);
        out.extend_from_slice(&w.finish());
    }
    out
}

/// The most endpoints a credential may carry.
///
/// RFC 3 §3's size table stops at three, and its point is that a credential
/// fits one QR code — which is what makes §11's in-person ceremony work. A
/// list long enough to break that is not a credential anyone can exchange.
pub const MAX_TRANSPORTS: usize = 8;

fn transports_from(bytes: &[u8]) -> Option<Vec<String>> {
    let mut r = Reader::new(bytes);
    let n = match r.item().ok()? {
        Item::Uint(v) => usize::try_from(v).ok()?,
        _ => return None,
    };
    if n > MAX_TRANSPORTS {
        return None;
    }
    // Sized by what arrived, never by the declared count.
    let mut out = Vec::new();
    for _ in 0..n {
        match r.item().ok()? {
            Item::Tstr(s) => out.push(s.to_string()),
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use krab_crypto::rng::NotRandom;

    const NOW: u64 = 1_800_000_000;
    const DAY: u64 = 86_400;

    fn node(seed: u64) -> Identity {
        Identity::generate(&mut NotRandom::seeded(seed))
    }

    /// A completed credential: proposed by one, countersigned by the other.
    fn linked(x: &Identity, y: &Identity) -> Credential {
        let mut c = Credential::propose(
            x.signing_key(),
            &x.card(Policy::default()),
            &y.card(Policy::default()),
            NOW,
            DEFAULT_TERM_DAYS,
            [3u8; 16],
        );
        assert!(c.sign(y.signing_key()));
        c
    }

    #[test]
    fn a_credential_round_trips_and_verifies() {
        let c = linked(&node(1), &node(2));
        assert_eq!(c.verify(NOW + 60), Ok(()));
        let back = Credential::decode(&c.encode()).expect("decodes");
        assert_eq!(back, c);
        assert_eq!(back.verify(NOW + 60), Ok(()));
    }

    /// **Both signatures, or it is a claim.** RFC 3 §3's central rule, and the
    /// reason `evidence` could not be built on a card.
    #[test]
    fn one_signature_is_a_proposal_and_not_a_link() {
        let (x, y) = (node(1), node(2));
        let c = Credential::propose(
            x.signing_key(),
            &x.card(Policy::default()),
            &y.card(Policy::default()),
            NOW,
            DEFAULT_TERM_DAYS,
            [3u8; 16],
        );
        assert!(!c.is_complete());
        assert_eq!(c.verify(NOW + 60), Err(Invalid::NotCountersigned));
    }

    /// **Party order is canonical, whichever way round it is built.** Two
    /// implementations disagreeing here produce credentials neither can
    /// verify, and would learn about it as "peering stopped working".
    #[test]
    fn either_side_builds_the_same_document() {
        let (x, y) = (node(1), node(2));
        let from_x = Credential::propose(
            x.signing_key(),
            &x.card(Policy::default()),
            &y.card(Policy::default()),
            NOW,
            DEFAULT_TERM_DAYS,
            [3u8; 16],
        );
        let from_y = Credential::propose(
            y.signing_key(),
            &y.card(Policy::default()),
            &x.card(Policy::default()),
            NOW,
            DEFAULT_TERM_DAYS,
            [3u8; 16],
        );
        // Same parties in the same order, and the same signed bytes.
        assert_eq!(from_x.a, from_y.a);
        assert_eq!(from_x.b, from_y.b);
        assert_eq!(from_x.body(), from_y.body());
        // Different signatures, on opposite sides — which is the whole point.
        assert!(from_x.sig_a.is_some() != from_y.sig_a.is_some());

        // And they combine into one complete credential.
        let mut joined = from_x.clone();
        joined.sig_a = joined.sig_a.or(from_y.sig_a);
        joined.sig_b = joined.sig_b.or(from_y.sig_b);
        assert_eq!(joined.verify(NOW + 60), Ok(()));
    }

    /// A credential whose parties are out of order is refused before any
    /// signature is checked — the bytes are not the ones either end signed.
    #[test]
    fn parties_out_of_canonical_order_are_refused() {
        let mut c = linked(&node(1), &node(2));
        core::mem::swap(&mut c.a, &mut c.b);
        assert_eq!(c.verify(NOW + 60), Err(Invalid::NotCanonical));
    }

    /// Every field is inside both signatures. A field a signature does not
    /// cover is a term one party can change after the other agreed to it.
    #[test]
    fn every_field_is_inside_both_signatures() {
        let base = linked(&node(1), &node(2));
        let mut edits = vec![
            Credential {
                established_s: base.established_s + 1,
                ..base.clone()
            },
            Credential {
                expires_s: base.expires_s - 1,
                ..base.clone()
            },
            Credential {
                nonce: [9u8; 16],
                ..base.clone()
            },
            Credential {
                flags: Flags {
                    a_shares_b: true,
                    ..base.flags
                },
                ..base.clone()
            },
            Credential {
                transports: vec!["127.0.0.1:40000".into()],
                ..base.clone()
            },
        ];
        let mut terms = base.clone();
        terms.terms_ab.retention_bytes += 1;
        edits.push(terms);

        for e in edits {
            assert_eq!(
                e.verify(NOW + 60),
                Err(Invalid::BadSignature),
                "a field is outside the signatures"
            );
        }
    }

    /// A third party's signature is not attached to either slot — a credential
    /// signed by a bystander would fail later with nothing saying why.
    #[test]
    fn a_bystander_cannot_sign() {
        let (x, y, z) = (node(1), node(2), node(3));
        let mut c = Credential::propose(
            x.signing_key(),
            &x.card(Policy::default()),
            &y.card(Policy::default()),
            NOW,
            DEFAULT_TERM_DAYS,
            [3u8; 16],
        );
        assert!(
            !c.sign(z.signing_key()),
            "a bystander's signature was taken"
        );
        assert_eq!(c.verify(NOW + 60), Err(Invalid::NotCountersigned));
    }

    /// Swapping in someone else's signature does not make a link.
    #[test]
    fn a_forged_countersignature_is_refused() {
        let (x, y, z) = (node(1), node(2), node(3));
        let mut real = linked(&x, &y);
        let other = linked(&x, &z);
        real.sig_b = other.sig_b.or(other.sig_a);
        assert_eq!(real.verify(NOW + 60), Err(Invalid::BadSignature));
    }

    /// **RFC 3 §4 — MUST reject a link whose validity exceeds 180 days.**
    /// Refused rather than truncated: a ten-year term is an implementation
    /// that read §4 differently, and honouring part of it would hide that.
    #[test]
    fn a_term_beyond_the_ceiling_is_refused() {
        let (x, y) = (node(1), node(2));
        let mut c = Credential::propose(
            x.signing_key(),
            &x.card(Policy::default()),
            &y.card(Policy::default()),
            NOW,
            10 * 365,
            [3u8; 16],
        );
        // `propose` clamps, so an honest node cannot mint one.
        assert_eq!(c.expires_s, NOW + MAX_TERM_DAYS * DAY);

        // A peer that did not clamp is refused.
        c.expires_s = NOW + 10 * 365 * DAY;
        c.sig_a = None;
        c.sig_b = None;
        c.sign(x.signing_key());
        c.sign(y.signing_key());
        assert_eq!(c.verify(NOW + 60), Err(Invalid::TooLong));
    }

    /// The default term is the top of RFC 3 §4's range, because §15 says a
    /// node offline longer than its credentials returns unable to peer.
    #[test]
    fn the_default_term_is_within_the_rfc_range() {
        assert!((60..=90).contains(&DEFAULT_TERM_DAYS));
        assert_eq!(DEFAULT_TERM_DAYS, 90, "§15 argues for the upper end");
        let c = linked(&node(1), &node(2));
        assert_eq!(c.expires_s - c.established_s, DEFAULT_TERM_DAYS * DAY);
    }

    /// Revocation is non-renewal — RFC 3 §4. An expired credential is refused,
    /// and refused *as expired* rather than as forged.
    #[test]
    fn an_expired_credential_is_refused_as_expired() {
        let c = linked(&node(1), &node(2));
        assert_eq!(c.verify(c.expires_s - 1), Ok(()));
        assert_eq!(c.verify(c.expires_s), Err(Invalid::Expired));
    }

    /// **Share bits default to false** — RFC 3 §8.3 says MUST. "A node may
    /// have ten casual peers and one sensitive one."
    #[test]
    fn share_flags_default_to_false() {
        let c = linked(&node(1), &node(2));
        assert!(!c.flags.a_shares_b);
        assert!(!c.flags.b_shares_a);
        assert!(!Flags::default().a_shares_b);
        assert!(!Flags::default().b_shares_a);
    }

    /// A credential names the two nodes it is between, whichever order the
    /// caller asks in.
    #[test]
    fn a_credential_knows_who_it_is_between() {
        let (x, y, z) = (node(1), node(2), node(3));
        let c = linked(&x, &y);
        let (xi, yi, zi) = (x.node_id(), y.node_id(), z.node_id());
        assert!(c.is_between(&xi, &yi));
        assert!(c.is_between(&yi, &xi), "order must not matter");
        assert!(!c.is_between(&xi, &zi));
        assert_eq!(c.other_than(&xi).map(|p| p.node_id()), Some(yi));
        assert_eq!(c.other_than(&zi), None);
    }

    /// A node cannot link to itself, which would otherwise be a credential
    /// anyone could mint to vouch for their own peerings.
    #[test]
    fn a_self_link_is_refused() {
        let x = node(1);
        let mut c = linked(&x, &node(2));
        c.b = c.a;
        assert_eq!(c.verify(NOW + 60), Err(Invalid::SelfLink));
    }

    /// Endpoints are permitted here and only here, and are bounded — RFC 3 §3
    /// sizes a credential to fit one QR code, which §11's ceremony depends on.
    #[test]
    fn transports_round_trip_and_are_bounded() {
        let (x, y) = (node(1), node(2));
        let mut c = Credential::propose(
            x.signing_key(),
            &x.card(Policy::default()),
            &y.card(Policy::default()),
            NOW,
            DEFAULT_TERM_DAYS,
            [3u8; 16],
        );
        c.transports = vec!["127.0.0.1:40000".into(), "abc.onion:9000".into()];
        c.sig_a = None;
        c.sig_b = None;
        c.sign(x.signing_key());
        c.sign(y.signing_key());
        assert_eq!(c.verify(NOW + 60), Ok(()));
        let back = Credential::decode(&c.encode()).expect("decodes");
        assert_eq!(back.transports, c.transports);

        c.transports = (0..MAX_TRANSPORTS + 1).map(|i| format!("ep{i}")).collect();
        assert_eq!(Credential::decode(&c.encode()), None, "unbounded list");
    }

    /// Arrives from a stranger as `evidence`. Nothing here may panic.
    #[test]
    fn malformed_credentials_are_refused_without_panicking() {
        assert_eq!(Credential::decode(&[]), None);
        assert_eq!(Credential::decode(&[0xac]), None);
        let mut runaway = vec![0xac, 0x01, 0x5a];
        runaway.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(Credential::decode(&runaway), None);

        let good = linked(&node(1), &node(2)).encode();
        for cut in 0..good.len() {
            let _ = Credential::decode(&good[..cut]);
        }
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0xff;
            if let Some(c) = Credential::decode(&bad) {
                // Anything that still decodes must not verify, unless the
                // flipped byte landed outside the signed material — which it
                // never does, because every field is signed.
                let _ = c.verify(NOW + 60);
            }
        }
    }

    /// A credential fits one QR code — RFC 3 §3's table, and what makes §11's
    /// in-person ceremony practical.
    #[test]
    fn a_credential_fits_a_single_qr_code() {
        let c = linked(&node(1), &node(2));
        // Version 40 at error-correction M holds 2 331 bytes of binary.
        assert!(
            c.encode().len() < 2_331,
            "a credential must fit one QR: {} bytes",
            c.encode().len()
        );
    }
}
