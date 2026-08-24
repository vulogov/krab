//! Introduction tokens — RFC 3 §10.
//!
//! > "Krab will not have a public endorsement or reputation score."
//!
//! The reasoning is worth keeping next to the code, because the feature that
//! would replace this one is always easier to build:
//!
//! > "Visible reputation concentrates: nodes with many endorsements become
//! > hubs, hubs become chokepoints, chokepoints become compulsion targets and
//! > single points of failure. FidoNet's coordinator hierarchy emerged this way
//! > — not by design, but because visible standing accumulates."
//!
//! So instead of a score there is a **private, single-use, expiring token**,
//! bound to the requester's key so it is non-transferable, scoped to one
//! introduction, and revealed only to the party evaluating it. It carries the
//! credibility of vouching with none of the persistence.
//!
//! # Four properties, and where each one lives
//!
//! | §10 says | here |
//! |---|---|
//! | private | it travels only inside a sealed `peer-request`; nothing publishes one |
//! | bound to the requester's key | [`Token::requester`] is inside the signature |
//! | scoped to one introduction | [`Token::target`] is too — it names *who* it introduces to |
//! | expiring in days | [`MAX_LIFETIME_S`], and [`Verdict::Expired`] |
//! | single-use | [`Spent`], which the evaluator keeps |
//!
//! Each is inside the signature or it is not a property. A token whose target
//! were unsigned would introduce its holder to anyone; one whose requester
//! were unsigned would be a bearer credential, which is the transferable
//! endorsement §10 exists to avoid.
//!
//! # The introducer is a lookup key, never a trust root
//!
//! [`Token::introducer`] is a node id, and [`Token::verify`] **will not accept
//! a key from the token itself** — the caller has to supply the verifying key,
//! which it gets from its own peer-links.
//!
//! This is the whole defence against the Sybil farming §10 names. If a token
//! carried its own signing key, anyone could mint one vouching for themselves
//! and the vouch would verify perfectly. It would be a valid signature by a
//! stranger, which is worth nothing and *looks* like something. Requiring the
//! evaluator to resolve the introducer first means an unknown introducer
//! produces [`Verdict::UnknownIntroducer`] rather than a green tick.
//!
//! # The protocol establishes facts; the operator makes the judgement
//!
//! §10 draws that line explicitly, and this module stops at the facts. It
//! answers *"did someone you peer with sign this, for you, for this person,
//! recently, and is it unspent"* — and nothing about whether that is
//! sufficient. There is no score, no threshold, and no accept path that does
//! not go through a human.
//!
//! # Why fourteen days rather than long enough to always arrive
//!
//! An object may take up to `MAX_TTL_DAYS` (45) to arrive, so a peer-request
//! carried by courier can outlive any token this module will mint. That is a
//! real limitation and it is deliberate.
//!
//! A token that lived 45 days would be a durable credential, and persistence
//! is precisely what §10 objects to — "the credibility of vouching with none
//! of the persistence". Stretching the lifetime to cover the worst-case
//! transit would trade the property for the convenience. So an introduction to
//! a courier-only node may arrive expired, and the operator then decides on
//! the note and the evidence, which is where §10 says the decision belongs
//! anyway.

use krab_core::cbor::{Item, Reader, Writer};
use krab_crypto::rng::Rng;
use krab_crypto::sign::{Sig, SigningKey, VerifyingKey};

/// Domain label for the signature. Frozen.
///
/// Distinct from every other document's, so a card, a request or a re-key
/// signature is not a valid token — `AMENDMENTS.md` §4's rule, which exists
/// because the credential was once the one signed document without one.
pub const DOMAIN: &[u8] = b"krab/introduction/v1";

/// The longest a token may live — RFC 3 §10's "expiring in days".
///
/// Fourteen. See the module header on why this deliberately does not stretch
/// to cover a courier's worst-case transit.
pub const MAX_LIFETIME_S: u64 = 14 * 24 * 3600;

/// A private, single-use, expiring vouch — RFC 3 §10.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// Who vouched, as a node id.
    ///
    /// **A lookup key, not a trust root.** [`Token::verify`] takes the
    /// verifying key as a separate argument precisely so this field cannot be
    /// the thing that decides whose signature counts.
    pub introducer: [u8; 32],
    /// The node this token is bound to. Inside the signature, so it is
    /// non-transferable: handing it to someone else produces
    /// [`Verdict::NotYours`] rather than an introduction.
    pub requester: [u8; 32],
    /// The node it introduces to. Also inside the signature — a token is
    /// scoped to one introduction, not to the holder's next N attempts.
    pub target: [u8; 32],
    /// Unix seconds after which it is worthless.
    pub expires_s: u64,
    /// Sixteen random bytes, naming this token for single-use tracking.
    ///
    /// Not a secret and not a key. It exists so that two tokens with identical
    /// fields are still distinguishable, which is what makes "spent" a
    /// statement about a token rather than about a pairing.
    pub nonce: [u8; 16],
    /// Ed25519 by the introducer over everything above.
    pub sig: [u8; 64],
}

/// What an evaluator concluded. **Facts only** — RFC 3 §10 leaves the
/// judgement to the operator, so there is no variant meaning "accept".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Signed by the named introducer, for this requester, for this node,
    /// unexpired and unspent. **Still not a decision.**
    Good,
    /// The introducer is not someone this node peers with, so the signature
    /// could be anyone's. §10's Sybil case.
    UnknownIntroducer,
    /// The signature is not the introducer's.
    BadSignature,
    /// Bound to a different requester — someone passed this on.
    NotYours,
    /// Scoped to an introduction to somebody else.
    NotForUs,
    /// Past its expiry.
    Expired,
    /// Minted with a lifetime longer than §10 allows. Refused rather than
    /// honoured for the part of it that is in range: a token claiming a year
    /// is an implementation that read §10 differently, and quietly accepting
    /// two weeks of it would hide that.
    Overlong,
    /// Seen before. §10's "single-use".
    Spent,
}

impl Token {
    /// The bytes the signature covers.
    fn signed_bytes(
        introducer: &[u8; 32],
        requester: &[u8; 32],
        target: &[u8; 32],
        expires_s: u64,
        nonce: &[u8; 16],
    ) -> Vec<u8> {
        let mut w = Writer::new();
        w.map(5)
            .uint(1)
            .bstr(introducer)
            .uint(2)
            .bstr(requester)
            .uint(3)
            .bstr(target)
            .uint(4)
            .uint(expires_s)
            .uint(5)
            .bstr(nonce);
        let body = w.finish();
        let mut out = Vec::with_capacity(DOMAIN.len() + body.len());
        out.extend_from_slice(DOMAIN);
        out.extend_from_slice(&body);
        out
    }

    /// Mint a token vouching for `requester`, for an introduction to `target`.
    ///
    /// `lifetime_s` is clamped to [`MAX_LIFETIME_S`]. Clamping rather than
    /// erroring because this is the *minting* side, where the operator asked
    /// for something out of range and the safe reading is the shorter one —
    /// the *evaluating* side refuses instead ([`Verdict::Overlong`]), because
    /// there the out-of-range value came from somebody else.
    pub fn create(
        introducer: &SigningKey,
        requester: [u8; 32],
        target: [u8; 32],
        now_s: u64,
        lifetime_s: u64,
        rng: &mut impl Rng,
    ) -> Token {
        let id = introducer.verifying_key().node_id();
        let expires_s = now_s.saturating_add(lifetime_s.min(MAX_LIFETIME_S));
        let mut nonce = [0u8; 16];
        rng.fill(&mut nonce);
        let sig = introducer
            .sign(&Token::signed_bytes(
                &id, &requester, &target, expires_s, &nonce,
            ))
            .0;
        Token {
            introducer: id,
            requester,
            target,
            expires_s,
            nonce,
            sig,
        }
    }

    /// Evaluate, given the introducer's key resolved from the evaluator's own
    /// peer-links.
    ///
    /// `introducer_key` is `None` when this node does not peer with whoever
    /// the token names. That is the common case for a token minted by a
    /// stranger, and it is the answer §10 wants: an endorsement from someone
    /// you have no relationship with is not evidence.
    ///
    /// `spent` answers whether this nonce has been seen. Passed in rather than
    /// looked up here, so the check cannot be skipped by calling a shorter
    /// function — there isn't one.
    pub fn evaluate(
        &self,
        introducer_key: Option<&VerifyingKey>,
        me: &[u8; 32],
        requester: &[u8; 32],
        now_s: u64,
        spent: &Spent,
    ) -> Verdict {
        let Some(vk) = introducer_key else {
            return Verdict::UnknownIntroducer;
        };
        // The supplied key must be the one the token names, or the caller
        // resolved the wrong peer and the whole check is about someone else.
        if vk.node_id() != self.introducer {
            return Verdict::UnknownIntroducer;
        }
        if !vk.verify(
            &Token::signed_bytes(
                &self.introducer,
                &self.requester,
                &self.target,
                self.expires_s,
                &self.nonce,
            ),
            &Sig(self.sig),
        ) {
            return Verdict::BadSignature;
        }
        // Binding before expiry: a token for the wrong person is not "expired",
        // and reporting the wrong reason sends an operator looking in the
        // wrong place.
        if &self.requester != requester {
            return Verdict::NotYours;
        }
        if &self.target != me {
            return Verdict::NotForUs;
        }
        if self.expires_s.saturating_sub(now_s) > MAX_LIFETIME_S {
            return Verdict::Overlong;
        }
        if now_s >= self.expires_s {
            return Verdict::Expired;
        }
        if spent.contains(&self.nonce) {
            return Verdict::Spent;
        }
        Verdict::Good
    }

    /// Deterministic CBOR — RFC 1 §4.3.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.map(6)
            .uint(1)
            .bstr(&self.introducer)
            .uint(2)
            .bstr(&self.requester)
            .uint(3)
            .bstr(&self.target)
            .uint(4)
            .uint(self.expires_s)
            .uint(5)
            .bstr(&self.nonce)
            .uint(6)
            .bstr(&self.sig);
        w.finish()
    }

    /// Decode. **Pre-authentication input** — a token arrives inside a request
    /// from someone this node has never met, so nothing here may panic or
    /// allocate on a declared length.
    pub fn decode(bytes: &[u8]) -> Option<Token> {
        let mut r = Reader::new(bytes);
        let mut m = r.map().ok()?;
        if m.left() != 6 {
            return None;
        }
        let introducer = bstr_at(&mut m, 1)?.try_into().ok()?;
        let requester = bstr_at(&mut m, 2)?.try_into().ok()?;
        let target = bstr_at(&mut m, 3)?.try_into().ok()?;
        let expires_s = match at(&mut m, 4)? {
            Item::Uint(v) => v,
            _ => return None,
        };
        let nonce = bstr_at(&mut m, 5)?.try_into().ok()?;
        let sig: [u8; 64] = bstr_at(&mut m, 6)?.try_into().ok()?;
        Some(Token {
            introducer,
            requester,
            target,
            expires_s,
            nonce,
            sig,
        })
    }
}

/// Nonces this node has already honoured — RFC 3 §10's "single-use".
///
/// # Why it is stored, and why it is bounded
///
/// Single-use is not a property of a token; it is a property of an
/// *evaluator's memory*. A node that forgot across a restart would honour
/// every token twice, and "single-use" would be a sentence in a document.
///
/// It is bounded by expiry rather than by count. A nonce whose token has
/// expired can be dropped, because the token is refused on expiry anyway and
/// keeping it would be keeping a record of who was introduced to this node —
/// exactly the accumulating trace §10 exists to avoid. So the set stays the
/// size of "introductions in the last fortnight" and then forgets, which is
/// the same discipline the corpus itself runs on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Spent {
    /// Nonce and the expiry it was honoured under.
    seen: Vec<([u8; 16], u64)>,
}

impl Spent {
    /// Whether this nonce has been honoured.
    pub fn contains(&self, nonce: &[u8; 16]) -> bool {
        self.seen.iter().any(|(n, _)| n == nonce)
    }

    /// Record a token as honoured. Idempotent.
    pub fn spend(&mut self, token: &Token) {
        if !self.contains(&token.nonce) {
            self.seen.push((token.nonce, token.expires_s));
        }
    }

    /// Drop nonces whose tokens have expired, and report how many went.
    ///
    /// Safe because an expired token is refused on its expiry, so forgetting
    /// its nonce cannot make it usable again.
    pub fn forget_expired(&mut self, now_s: u64) -> usize {
        let before = self.seen.len();
        self.seen.retain(|(_, exp)| *exp > now_s);
        before - self.seen.len()
    }

    /// How many are held.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether none are held.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Deterministic CBOR, for sealed storage.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let mut flat = Vec::with_capacity(self.seen.len() * 24);
        for (nonce, exp) in &self.seen {
            flat.extend_from_slice(nonce);
            flat.extend_from_slice(&exp.to_le_bytes());
        }
        w.map(1).uint(1).bstr(&flat);
        w.finish()
    }

    /// Decode. This is the node's own storage, but a corrupt file must not
    /// panic — and must not read as *fewer* spent tokens than were stored, so
    /// anything malformed yields nothing rather than a partial set.
    pub fn decode(bytes: &[u8]) -> Option<Spent> {
        let mut r = Reader::new(bytes);
        let mut m = r.map().ok()?;
        if m.left() != 1 {
            return None;
        }
        let flat = bstr_at(&mut m, 1)?;
        if flat.len() % 24 != 0 {
            return None;
        }
        let mut seen = Vec::with_capacity(flat.len() / 24);
        for c in flat.chunks_exact(24) {
            let nonce: [u8; 16] = c[..16].try_into().ok()?;
            let exp = u64::from_le_bytes(c[16..].try_into().ok()?);
            seen.push((nonce, exp));
        }
        Some(Spent { seen })
    }
}

/// A token as text, for handing to the person it vouches for.
///
/// **Hex, and never a file.** A token is a private vouch; writing one to disk
/// would leave a record that A vouched for C, which is the persistence RFC 3
/// §10 exists to avoid, and would need shredding afterwards. It is small,
/// single-use and short-lived, so the operator copies it and it exists nowhere
/// once both sides are done.
pub fn to_text(t: &Token) -> String {
    let mut s = String::with_capacity(t.encode().len() * 2);
    for b in t.encode() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Read a token back. **Pre-authentication input**: whatever the operator
/// pasted, which may be anything at all.
pub fn from_text(s: &str) -> Option<Token> {
    let s = s.trim();
    if s.len() % 2 != 0 || s.is_empty() {
        return None;
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    let raw = s.as_bytes();
    for pair in raw.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        bytes.push((hi * 16 + lo) as u8);
    }
    Token::decode(&bytes)
}

fn at<'a>(m: &mut krab_core::cbor::MapReader<'a, '_>, k: u64) -> Option<Item<'a>> {
    (m.key().ok()?? == k).then_some(())?;
    m.value().ok()
}

fn bstr_at<'a>(m: &mut krab_core::cbor::MapReader<'a, '_>, k: u64) -> Option<&'a [u8]> {
    match at(m, k)? {
        Item::Bstr(b) => Some(b),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use krab_crypto::rng::NotRandom;

    const NOW: u64 = 1_800_000_000;

    fn key(seed: u64) -> SigningKey {
        SigningKey::generate(&mut NotRandom::seeded(seed))
    }

    /// Introducer A, requester C, target B.
    fn parties() -> (SigningKey, [u8; 32], [u8; 32]) {
        let a = key(1);
        let c = key(2).verifying_key().node_id();
        let b = key(3).verifying_key().node_id();
        (a, c, b)
    }

    fn token(a: &SigningKey, c: [u8; 32], b: [u8; 32]) -> Token {
        Token::create(a, c, b, NOW, MAX_LIFETIME_S, &mut NotRandom::seeded(9))
    }

    #[test]
    fn a_token_round_trips_and_verifies() {
        let (a, c, b) = parties();
        let t = token(&a, c, b);
        assert_eq!(Token::decode(&t.encode()), Some(t.clone()));
        assert_eq!(
            t.evaluate(
                Some(&a.verifying_key()),
                &b,
                &c,
                NOW + 60,
                &Spent::default()
            ),
            Verdict::Good
        );
    }

    /// **Non-transferable** — RFC 3 §10 binds the token to the requester's
    /// key. Handing it on is the failure a bearer credential would allow, and
    /// a bearer credential is a transferable endorsement.
    #[test]
    fn a_token_handed_to_someone_else_is_worthless() {
        let (a, c, b) = parties();
        let stranger = key(4).verifying_key().node_id();
        let t = token(&a, c, b);
        assert_eq!(
            t.evaluate(
                Some(&a.verifying_key()),
                &b,
                &stranger,
                NOW + 60,
                &Spent::default()
            ),
            Verdict::NotYours
        );
    }

    /// **Scoped to one introduction.** A token for an introduction to B does
    /// not introduce its holder to anyone else.
    #[test]
    fn a_token_for_one_introduction_does_not_serve_another() {
        let (a, c, b) = parties();
        let elsewhere = key(5).verifying_key().node_id();
        let t = token(&a, c, b);
        assert_eq!(
            t.evaluate(
                Some(&a.verifying_key()),
                &elsewhere,
                &c,
                NOW + 60,
                &Spent::default()
            ),
            Verdict::NotForUs
        );
    }

    /// **The Sybil case, and the reason `verify` will not read a key out of
    /// the token.** A stranger mints a token vouching for themselves; the
    /// signature is perfectly valid and the token is worth nothing, and the
    /// only thing that distinguishes those two facts is whether the evaluator
    /// knows the introducer.
    #[test]
    fn a_stranger_vouching_for_themselves_is_refused() {
        let stranger = key(7);
        let c = key(2).verifying_key().node_id();
        let b = key(3).verifying_key().node_id();
        let t = Token::create(
            &stranger,
            c,
            b,
            NOW,
            MAX_LIFETIME_S,
            &mut NotRandom::seeded(1),
        );

        // Signed correctly by whoever minted it.
        assert!(stranger.verifying_key().verify(
            &Token::signed_bytes(
                &t.introducer,
                &t.requester,
                &t.target,
                t.expires_s,
                &t.nonce
            ),
            &Sig(t.sig)
        ));
        // And worth nothing to a node that does not peer with them.
        assert_eq!(
            t.evaluate(None, &b, &c, NOW + 60, &Spent::default()),
            Verdict::UnknownIntroducer
        );
    }

    /// Resolving the wrong peer's key is not an introduction either.
    #[test]
    fn a_key_that_is_not_the_named_introducers_is_refused() {
        let (a, c, b) = parties();
        let other = key(8);
        let t = token(&a, c, b);
        assert_eq!(
            t.evaluate(
                Some(&other.verifying_key()),
                &b,
                &c,
                NOW + 60,
                &Spent::default()
            ),
            Verdict::UnknownIntroducer
        );
    }

    /// Every field is inside the signature. A field a signature does not cover
    /// is a field an attacker edits — and here that would mean re-pointing a
    /// genuine vouch at a different person.
    #[test]
    fn every_field_is_inside_the_signature() {
        let (a, c, b) = parties();
        let vk = a.verifying_key();
        let t = token(&a, c, b);

        for edited in [
            Token {
                requester: [9u8; 32],
                ..t.clone()
            },
            Token {
                target: [9u8; 32],
                ..t.clone()
            },
            Token {
                expires_s: t.expires_s + 1,
                ..t.clone()
            },
            Token {
                nonce: [9u8; 16],
                ..t.clone()
            },
            Token {
                introducer: [9u8; 32],
                ..t.clone()
            },
        ] {
            let v = edited.evaluate(Some(&vk), &b, &c, NOW + 60, &Spent::default());
            assert!(
                v == Verdict::BadSignature || v == Verdict::UnknownIntroducer,
                "an edited field survived: {v:?}"
            );
        }
    }

    /// **Expiring in days** — RFC 3 §10.
    #[test]
    fn a_token_expires() {
        let (a, c, b) = parties();
        let t = token(&a, c, b);
        let vk = a.verifying_key();
        assert_eq!(
            t.evaluate(Some(&vk), &b, &c, t.expires_s - 1, &Spent::default()),
            Verdict::Good
        );
        assert_eq!(
            t.evaluate(Some(&vk), &b, &c, t.expires_s, &Spent::default()),
            Verdict::Expired
        );
    }

    /// A lifetime beyond §10's is clamped when minting and refused when
    /// evaluating. The asymmetry is deliberate: minting, the out-of-range
    /// value came from this operator and the safe reading is the shorter one;
    /// evaluating, it came from somebody else and quietly honouring part of it
    /// would hide an implementation that read §10 differently.
    #[test]
    fn a_lifetime_longer_than_the_rfc_allows_is_clamped_then_refused() {
        let (a, c, b) = parties();
        let year = 365 * 24 * 3600;
        let minted = Token::create(&a, c, b, NOW, year, &mut NotRandom::seeded(1));
        assert_eq!(minted.expires_s, NOW + MAX_LIFETIME_S, "not clamped");

        // A peer that did not clamp.
        let forged = Token::create(&a, c, b, NOW, 0, &mut NotRandom::seeded(1));
        let long = Token {
            expires_s: NOW + year,
            ..forged
        };
        // Re-sign it, so the only thing wrong is the lifetime.
        let long = Token {
            sig: a
                .sign(&Token::signed_bytes(
                    &long.introducer,
                    &long.requester,
                    &long.target,
                    long.expires_s,
                    &long.nonce,
                ))
                .0,
            ..long
        };
        assert_eq!(
            long.evaluate(Some(&a.verifying_key()), &b, &c, NOW, &Spent::default()),
            Verdict::Overlong
        );
    }

    /// **Single-use** — RFC 3 §10. The second presentation is refused.
    #[test]
    fn a_token_is_good_once() {
        let (a, c, b) = parties();
        let t = token(&a, c, b);
        let vk = a.verifying_key();
        let mut spent = Spent::default();

        assert_eq!(
            t.evaluate(Some(&vk), &b, &c, NOW + 60, &spent),
            Verdict::Good
        );
        spent.spend(&t);
        assert_eq!(
            t.evaluate(Some(&vk), &b, &c, NOW + 60, &spent),
            Verdict::Spent
        );
        // Spending twice is not an error and does not double-count.
        spent.spend(&t);
        assert_eq!(spent.len(), 1);
    }

    /// The spent set survives a restart, or single-use is a sentence in a
    /// document rather than a property.
    #[test]
    fn the_spent_set_round_trips_through_storage() {
        let (a, c, b) = parties();
        let mut spent = Spent::default();
        spent.spend(&token(&a, c, b));
        spent.spend(&Token::create(
            &a,
            c,
            b,
            NOW,
            MAX_LIFETIME_S,
            &mut NotRandom::seeded(11),
        ));
        assert_eq!(spent.len(), 2);

        let back = Spent::decode(&spent.encode()).expect("decodes");
        assert_eq!(back, spent);
    }

    /// **The set forgets.** A record of every introduction ever made to this
    /// node is the accumulating trace §10 exists to avoid, and an expired
    /// nonce protects nothing — the token is refused on expiry anyway.
    #[test]
    fn expired_nonces_are_forgotten_and_that_reopens_nothing() {
        let (a, c, b) = parties();
        let t = token(&a, c, b);
        let mut spent = Spent::default();
        spent.spend(&t);

        assert_eq!(spent.forget_expired(t.expires_s - 1), 0, "dropped too soon");
        assert_eq!(spent.forget_expired(t.expires_s), 1);
        assert!(spent.is_empty());

        // Forgotten, and still refused — on expiry rather than on the record.
        assert_eq!(
            t.evaluate(
                Some(&a.verifying_key()),
                &b,
                &c,
                t.expires_s + 1,
                &Spent::default()
            ),
            Verdict::Expired
        );
    }

    /// A token arrives inside a request from someone this node has never met.
    /// Nothing here may panic.
    #[test]
    fn malformed_tokens_are_refused_without_panicking() {
        assert_eq!(Token::decode(&[]), None);
        assert_eq!(Token::decode(&[0xa6]), None);
        let mut runaway = vec![0xa6, 0x01, 0x5a];
        runaway.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(Token::decode(&runaway), None);

        let (a, c, b) = parties();
        let good = token(&a, c, b).encode();
        for cut in 0..good.len() {
            let _ = Token::decode(&good[..cut]);
        }
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0xff;
            let _ = Token::decode(&bad);
        }

        assert_eq!(Spent::decode(&[]), None);
        // A trailing partial record is not a shorter spent set.
        let mut w = Writer::new();
        w.map(1).uint(1).bstr(&[0u8; 25]);
        assert_eq!(Spent::decode(&w.finish()), None);
    }

    /// Two tokens with identical fields are still distinguishable, which is
    /// what makes "spent" a statement about a token rather than about a pair
    /// of nodes.
    #[test]
    fn two_tokens_for_the_same_pair_are_distinct() {
        let (a, c, b) = parties();
        let one = Token::create(&a, c, b, NOW, MAX_LIFETIME_S, &mut NotRandom::seeded(1));
        let two = Token::create(&a, c, b, NOW, MAX_LIFETIME_S, &mut NotRandom::seeded(2));
        assert_ne!(one.nonce, two.nonce);

        let mut spent = Spent::default();
        spent.spend(&one);
        assert!(spent.contains(&one.nonce));
        assert!(!spent.contains(&two.nonce), "spending one spent the other");
    }

    /// The nonce comes from the supplied generator, never ambient — the rule
    /// the whole codebase is built on.
    #[test]
    fn the_nonce_comes_from_the_supplied_generator() {
        let (a, c, b) = parties();
        let one = Token::create(&a, c, b, NOW, MAX_LIFETIME_S, &mut NotRandom::seeded(4));
        let two = Token::create(&a, c, b, NOW, MAX_LIFETIME_S, &mut NotRandom::seeded(4));
        assert_eq!(one, two);
    }
}
