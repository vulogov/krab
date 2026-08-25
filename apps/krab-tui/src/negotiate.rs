//! `peer-counter`, and the negotiation chain — RFC 3 §5.2, §5.3.
//!
//! > "**The counter-offer is the step that matters.** Without it, peering is
//! > accept-or-reject and therefore binary: friend or stranger. With it,
//! > peering is negotiated, which is what makes §6 possible."
//!
//! ```text
//! peer-request  ──hash──▶  peer-counter  ──hash──▶  peer-link
//!    (X signs)              (B signs,               (both sign)
//!                            references
//!                            request hash)
//! ```
//!
//! # What it replaces
//!
//! Before this, a credential's terms came from [`LinkTerms::default`]. Both
//! parties got the same generous ceiling whatever either wanted, because a
//! card has nowhere to state a quota and nothing else was asked. Peering was
//! accept-or-reject — exactly the binary §5 says removes §6's whole point.
//!
//! # Terms are each party's own, not edits to the other's
//!
//! RFC 3 §6's example reads as a haggle:
//!
//! ```text
//! X requests:  10 MB/day, 30 d retention, all shards, all classes
//! B counters:   1 MB/day,  3 d retention, shard 0x0F, sealed + bulletin
//! X accepts.
//! ```
//!
//! It is not one number being pushed down. §6 says what B is doing: "you
//! allocate a sliver of capacity and observe" — B is stating **what B will
//! accept from X**, which is what `LinkTerms` means everywhere else (credential
//! key 6 is "terms A→B", what A accepts from B).
//!
//! So a counter revises the counterer's own offer, and the final credential
//! takes each party's latest statement for its own direction. That is what
//! makes "you can peer with a stranger at 1% trust" a thing one party can do
//! unilaterally, which is the whole claim.
//!
//! # Counters alternate
//!
//! §5.2 says "B MAY counter repeatedly", and each counter "references the
//! previous document's hash". Read together with §6's three-step example, a
//! chain is a conversation: each document answers the one before it, and the
//! party who wrote that one is not the party answering.
//!
//! [`Chain::verify`] enforces that. Without it a party can append a hundred
//! counters to its own last word and the chain stops being evidence of a
//! negotiation — §5.2's stated purpose is that "neither party can later
//! misrepresent what was offered", and a chain one party wrote alone
//! misrepresents by construction.
//!
//! # The chain is local evidence and MUST NOT be published
//!
//! §5.3. It names an introducer and is therefore graph information — the same
//! rule as §9.1's, applied to the negotiation rather than to the credential.
//! Nothing here encodes a chain into a bulletin, and there is no bulletin kind
//! that could carry one.

use crate::credential::LinkTerms;
use crate::request::PeerRequest;
use krab_core::cbor::{Item, Reader, Writer};
use krab_crypto::sign::{Sig, SigningKey, VerifyingKey};

/// Domain for a counter's signature. Frozen.
pub const DOMAIN: &[u8] = b"krab/counter/v1";

/// Domain for the hash that chains one document to the next.
pub const DOMAIN_LINK: &[u8] = b"krab/negotiate/v1";

/// The most counters a chain may carry.
///
/// §5.2 permits repeated countering and names no bound. A chain arrives from a
/// stranger, is verified signature by signature, and is stored — so it needs
/// one. Twenty is far past any negotiation a person will conduct and far short
/// of anything expensive.
pub const MAX_COUNTERS: usize = 20;

/// `H(document)` — what the next document in the chain references.
pub fn hash_of(encoded: &[u8]) -> [u8; 32] {
    krab_crypto::hash::domain_hash(DOMAIN_LINK, encoded)
}

/// RFC 3 §5.2's document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counter {
    /// Key 1 — `H` of the document this answers.
    ///
    /// What makes the negotiation "a verifiable chain", and what stops either
    /// party later misrepresenting what was offered: a counter is bound to one
    /// specific previous document and cannot be moved onto another.
    pub previous: [u8; 32],
    /// Key 2 — the countering party's identity key.
    ///
    /// The signing key, in the clear, because a chain is checked by whoever
    /// holds it and the alternative is a lookup they may not be able to make.
    /// It is checked against the request's parties by [`Chain::verify`], so it
    /// is not a trust root here any more than an introducer's is.
    pub from: [u8; 32],
    /// Key 3 — revised terms: what the countering party will accept.
    pub terms: LinkTerms,
    /// Key 4 — a note for the other operator to read.
    pub note: String,
    /// Ed25519 over `DOMAIN ‖ body`.
    pub sig: [u8; 64],
}

impl Counter {
    fn signed_bytes(
        previous: &[u8; 32],
        from: &[u8; 32],
        terms: &LinkTerms,
        note: &str,
    ) -> Vec<u8> {
        let mut w = Writer::new();
        w.map(4)
            .uint(1)
            .bstr(previous)
            .uint(2)
            .bstr(from)
            .uint(3)
            .bstr(&terms.encode())
            .uint(4)
            .tstr(note);
        let body = w.finish();
        let mut out = Vec::with_capacity(DOMAIN.len() + body.len());
        out.extend_from_slice(DOMAIN);
        out.extend_from_slice(&body);
        out
    }

    /// Counter the document whose hash is `previous`.
    pub fn create(
        signer: &SigningKey,
        previous: [u8; 32],
        terms: LinkTerms,
        note: &str,
    ) -> Counter {
        let from = signer.verifying_key().to_bytes();
        let sig = signer
            .sign(&Counter::signed_bytes(&previous, &from, &terms, note))
            .0;
        Counter {
            previous,
            from,
            terms,
            note: note.to_string(),
            sig,
        }
    }

    /// Whether the signature is the key this document names.
    ///
    /// **Not sufficient on its own.** A valid signature by a stranger is still
    /// a stranger's; [`Chain::verify`] is what ties `from` to a party of the
    /// request being negotiated.
    #[must_use]
    pub fn verify(&self) -> bool {
        VerifyingKey::from_bytes(self.from).verify(
            &Counter::signed_bytes(&self.previous, &self.from, &self.terms, &self.note),
            &Sig(self.sig),
        )
    }

    /// The countering party's node identifier.
    pub fn node_id(&self) -> [u8; 32] {
        krab_crypto::hash::node_id(&self.from)
    }

    /// Deterministic CBOR — RFC 1 §4.3.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.map(5)
            .uint(1)
            .bstr(&self.previous)
            .uint(2)
            .bstr(&self.from)
            .uint(3)
            .bstr(&self.terms.encode())
            .uint(4)
            .tstr(&self.note)
            .uint(5)
            .bstr(&self.sig);
        w.finish()
    }

    /// Decode. **Pre-authentication input** — a counter arrives from someone
    /// this node has not yet agreed to peer with.
    pub fn decode(bytes: &[u8]) -> Option<Counter> {
        let mut r = Reader::new(bytes);
        let mut m = r.map().ok()?;
        if m.left() != 5 {
            return None;
        }
        let previous = bstr_at(&mut m, 1)?.try_into().ok()?;
        let from = bstr_at(&mut m, 2)?.try_into().ok()?;
        let terms = LinkTerms::decode(bstr_at(&mut m, 3)?)?;
        let note = match at(&mut m, 4)? {
            Item::Tstr(t) => t.to_string(),
            _ => return None,
        };
        let sig: [u8; 64] = bstr_at(&mut m, 5)?.try_into().ok()?;
        Some(Counter {
            previous,
            from,
            terms,
            note,
            sig,
        })
    }
}

/// Why a chain was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Broken {
    /// The request's own signature does not verify.
    BadRequest,
    /// A counter's signature is not the key it names.
    BadSignature,
    /// A counter does not reference the document before it.
    NotChained,
    /// A counter was written by someone who is not a party to the request.
    Stranger,
    /// A party answered its own last word — see the module header.
    OutOfTurn,
    /// Longer than [`MAX_COUNTERS`].
    TooLong,
}

/// A negotiation: the request, and every counter since — RFC 3 §5.3.
///
/// Stored by **both** parties, and published by neither.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    /// The opening document.
    pub request: PeerRequest,
    /// Counters, oldest first.
    pub counters: Vec<Counter>,
}

impl Chain {
    /// Open a negotiation.
    pub fn new(request: PeerRequest) -> Chain {
        Chain {
            request,
            counters: Vec::new(),
        }
    }

    /// The hash the next document must reference.
    pub fn head(&self) -> [u8; 32] {
        match self.counters.last() {
            Some(c) => hash_of(&c.encode()),
            None => hash_of(&self.request.encode()),
        }
    }

    /// Whose turn it is to speak — the party who did not write the head.
    pub fn awaiting(&self) -> [u8; 32] {
        match self.counters.last() {
            Some(c) => {
                // The other party than the one who wrote it.
                let author = c.node_id();
                if author == self.request.from.node_id() {
                    self.request.to
                } else {
                    self.request.from.node_id()
                }
            }
            // The request was written by the requester, so the recipient
            // answers.
            None => self.request.to,
        }
    }

    /// Append a counter, checking it belongs here.
    pub fn push(&mut self, counter: Counter) -> Result<(), Broken> {
        self.check(&counter, self.counters.len())?;
        self.counters.push(counter);
        Ok(())
    }

    fn check(&self, c: &Counter, index: usize) -> Result<(), Broken> {
        if index >= MAX_COUNTERS {
            return Err(Broken::TooLong);
        }
        if !c.verify() {
            return Err(Broken::BadSignature);
        }
        // Bound to the document before it, or the chain is a set of unrelated
        // signed offers and neither party can prove what answered what.
        let expected = match index {
            0 => hash_of(&self.request.encode()),
            n => hash_of(&self.counters[n - 1].encode()),
        };
        if c.previous != expected {
            return Err(Broken::NotChained);
        }
        // A party to this request, and not a bystander with a valid signature.
        let author = c.node_id();
        let (x, b) = (self.request.from.node_id(), self.request.to);
        if author != x && author != b {
            return Err(Broken::Stranger);
        }
        // And not the party who wrote the document being answered.
        let previous_author = match index {
            0 => x,
            n => self.counters[n - 1].node_id(),
        };
        if author == previous_author {
            return Err(Broken::OutOfTurn);
        }
        Ok(())
    }

    /// Whether the whole chain holds together.
    ///
    /// Checked from the request forward, so a chain that is valid up to some
    /// point and forged after it fails at the forgery rather than passing on
    /// the strength of its opening.
    pub fn verify(&self) -> Result<(), Broken> {
        if !self.request.verify() {
            return Err(Broken::BadRequest);
        }
        if self.counters.len() > MAX_COUNTERS {
            return Err(Broken::TooLong);
        }
        for (i, c) in self.counters.iter().enumerate() {
            let partial = Chain {
                request: self.request.clone(),
                counters: self.counters[..i].to_vec(),
            };
            partial.check(c, i)?;
        }
        Ok(())
    }

    /// The terms each party has most recently stated it will accept.
    ///
    /// Returns `(requester's terms, recipient's terms)`. A party that has
    /// never spoken beyond the request falls back to what the request
    /// proposed; the recipient who has never countered has stated nothing, and
    /// gets `None` — a credential should not be built as though they had
    /// agreed to something they never said.
    pub fn settled(&self) -> (LinkTerms, Option<LinkTerms>) {
        let x = self.request.from.node_id();
        let mut theirs: Option<LinkTerms> = None;
        let mut mine = self.request.terms;
        for c in &self.counters {
            if c.node_id() == x {
                mine = c.terms;
            } else {
                theirs = Some(c.terms);
            }
        }
        (mine, theirs)
    }

    /// Deterministic CBOR, for local storage. Never published — §5.3.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let mut flat = Vec::new();
        for c in &self.counters {
            let b = c.encode();
            let mut n = Writer::new();
            n.uint(b.len() as u64);
            flat.extend_from_slice(&n.finish());
            flat.extend_from_slice(&b);
        }
        w.map(3)
            .uint(1)
            .bstr(&self.request.encode())
            .uint(2)
            .uint(self.counters.len() as u64)
            .uint(3)
            .bstr(&flat);
        w.finish()
    }

    /// Decode. Sized by what arrived, never by the declared count.
    pub fn decode(bytes: &[u8]) -> Option<Chain> {
        let mut r = Reader::new(bytes);
        let mut m = r.map().ok()?;
        if m.left() != 3 {
            return None;
        }
        let request = PeerRequest::decode(bstr_at(&mut m, 1)?).ok()?;
        let declared = match at(&mut m, 2)? {
            Item::Uint(v) => usize::try_from(v).ok()?,
            _ => return None,
        };
        if declared > MAX_COUNTERS {
            return None;
        }
        let flat = bstr_at(&mut m, 3)?;
        let mut counters = Vec::new();
        let mut rest = flat;
        while !rest.is_empty() {
            if counters.len() >= MAX_COUNTERS {
                return None;
            }
            let mut rr = Reader::new(rest);
            let len = match rr.item().ok()? {
                Item::Uint(v) => usize::try_from(v).ok()?,
                _ => return None,
            };
            let consumed = rest.len() - rr.remaining();
            let body = rest.get(consumed..consumed + len)?;
            counters.push(Counter::decode(body)?);
            rest = &rest[consumed + len..];
        }
        // The declared count must match what was actually there, or the
        // encoding is describing a different document from the one present.
        if counters.len() != declared {
            return None;
        }
        Some(Chain { request, counters })
    }
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
    use crate::identity::Identity;
    use crate::peering::Policy;
    use krab_crypto::rng::NotRandom;

    fn node(seed: u64) -> Identity {
        Identity::generate(&mut NotRandom::seeded(seed))
    }

    fn terms(mb: u64, days: u32) -> LinkTerms {
        LinkTerms {
            bytes_per_day: mb << 20,
            retention_days: days,
            ..LinkTerms::default()
        }
    }

    /// X requests, B counters, both sides can prove what was offered.
    fn opening(x: &Identity, b: &Identity, t: LinkTerms) -> Chain {
        Chain::new(PeerRequest::create_introduced(
            x.signing_key(),
            x.card(Policy::default()),
            b.node_id(),
            t,
            "hello",
            None,
            None,
        ))
    }

    /// **RFC 3 §6's example, end to end.**
    ///
    /// > X requests: 10 MB/day, 30 d retention …
    /// > B counters:  1 MB/day,  3 d retention …
    /// > X accepts.
    ///
    /// "You can peer with a stranger at 1% trust."
    #[test]
    fn a_stranger_can_be_peered_with_at_one_percent() {
        let (x, b) = (node(1), node(2));
        let mut chain = opening(&x, &b, terms(10, 30));
        let counter = Counter::create(
            b.signing_key(),
            chain.head(),
            terms(1, 3),
            "a sliver, and I will watch",
        );
        chain.push(counter).expect("a well-formed counter");
        assert_eq!(chain.verify(), Ok(()));

        let (xs, bs) = chain.settled();
        assert_eq!(xs.bytes_per_day, 10 << 20, "X's own offer stands");
        let bs = bs.expect("B has stated terms");
        assert_eq!(bs.bytes_per_day, 1 << 20, "B allocated a sliver");
        assert_eq!(bs.retention_days, 3);
    }

    /// **Without a counter, the recipient has stated nothing** — and a
    /// credential must not be built as though they had agreed to something.
    #[test]
    fn a_recipient_who_has_not_countered_has_agreed_to_nothing() {
        let (x, b) = (node(1), node(2));
        let chain = opening(&x, &b, terms(10, 30));
        let (xs, bs) = chain.settled();
        assert_eq!(xs.bytes_per_day, 10 << 20);
        assert_eq!(bs, None, "silence was read as agreement");
    }

    /// The chain is chained. A counter is bound to one previous document.
    #[test]
    fn a_counter_that_answers_nothing_is_refused() {
        let (x, b) = (node(1), node(2));
        let mut chain = opening(&x, &b, terms(10, 30));
        let stray = Counter::create(b.signing_key(), [9u8; 32], terms(1, 3), "");
        assert_eq!(chain.push(stray), Err(Broken::NotChained));
    }

    /// **Neither party can later misrepresent what was offered** — §5.2. A
    /// counter moved onto a different request breaks the hash.
    #[test]
    fn a_counter_cannot_be_moved_onto_another_negotiation() {
        let (x, b) = (node(1), node(2));
        let one = opening(&x, &b, terms(10, 30));
        let two = opening(&x, &b, terms(4, 30));
        assert_ne!(one.head(), two.head(), "two offers hashed the same");

        let counter = Counter::create(b.signing_key(), one.head(), terms(1, 3), "");
        let mut moved = two;
        assert_eq!(moved.push(counter), Err(Broken::NotChained));
    }

    /// A bystander's signature is valid and means nothing here.
    #[test]
    fn a_stranger_cannot_join_a_negotiation() {
        let (x, b, z) = (node(1), node(2), node(3));
        let mut chain = opening(&x, &b, terms(10, 30));
        let c = Counter::create(z.signing_key(), chain.head(), terms(1, 3), "");
        assert!(c.verify(), "the signature itself is fine");
        assert_eq!(chain.push(c), Err(Broken::Stranger));
    }

    /// **A party cannot answer its own last word.** A chain one party wrote
    /// alone misrepresents a negotiation by construction, which is the thing
    /// §5.2 says the chain prevents.
    #[test]
    fn a_party_cannot_counter_itself() {
        let (x, b) = (node(1), node(2));
        let mut chain = opening(&x, &b, terms(10, 30));
        // X wrote the request; X may not answer it.
        let own = Counter::create(x.signing_key(), chain.head(), terms(9, 30), "");
        assert_eq!(chain.push(own), Err(Broken::OutOfTurn));

        // B answers, then B may not answer again.
        chain
            .push(Counter::create(
                b.signing_key(),
                chain.head(),
                terms(1, 3),
                "",
            ))
            .unwrap();
        let again = Counter::create(b.signing_key(), chain.head(), terms(2, 3), "");
        assert_eq!(chain.push(again), Err(Broken::OutOfTurn));
    }

    /// Repeated countering, alternating — §5.2's "B MAY counter repeatedly".
    #[test]
    fn the_two_parties_may_haggle() {
        let (x, b) = (node(1), node(2));
        let mut chain = opening(&x, &b, terms(10, 30));
        for (i, who) in [&b, &x, &b, &x, &b].into_iter().enumerate() {
            let head = chain.head();
            chain
                .push(Counter::create(
                    who.signing_key(),
                    head,
                    terms(i as u64 + 1, 3),
                    "",
                ))
                .expect("alternating counters are fine");
        }
        assert_eq!(chain.verify(), Ok(()));
        assert_eq!(chain.counters.len(), 5);

        // The last word of each party is what settles.
        let (xs, bs) = chain.settled();
        assert_eq!(xs.bytes_per_day, 4 << 20, "X's fourth offer");
        assert_eq!(bs.unwrap().bytes_per_day, 5 << 20, "B's fifth");
    }

    /// Whose turn it is, so the interface can say so.
    #[test]
    fn the_chain_knows_whose_turn_it_is() {
        let (x, b) = (node(1), node(2));
        let mut chain = opening(&x, &b, terms(10, 30));
        assert_eq!(chain.awaiting(), b.node_id(), "the recipient answers first");
        chain
            .push(Counter::create(
                b.signing_key(),
                chain.head(),
                terms(1, 3),
                "",
            ))
            .unwrap();
        assert_eq!(chain.awaiting(), x.node_id());
    }

    /// **Verification walks the whole chain**, so a chain valid up to a point
    /// and forged after it fails at the forgery.
    #[test]
    fn a_chain_forged_after_a_valid_prefix_fails_at_the_forgery() {
        let (x, b, z) = (node(1), node(2), node(3));
        let mut chain = opening(&x, &b, terms(10, 30));
        chain
            .push(Counter::create(
                b.signing_key(),
                chain.head(),
                terms(1, 3),
                "",
            ))
            .unwrap();
        assert_eq!(chain.verify(), Ok(()));

        // Append a stranger's counter directly, bypassing `push`.
        let head = chain.head();
        chain
            .counters
            .push(Counter::create(z.signing_key(), head, terms(99, 45), ""));
        assert_eq!(chain.verify(), Err(Broken::Stranger));
    }

    /// An edited counter does not verify — every field is signed.
    #[test]
    fn every_field_of_a_counter_is_signed() {
        let (x, b) = (node(1), node(2));
        let chain = opening(&x, &b, terms(10, 30));
        let c = Counter::create(b.signing_key(), chain.head(), terms(1, 3), "note");

        let mut edited = c.clone();
        edited.terms = terms(99, 45);
        assert!(!edited.verify(), "the terms are unsigned");

        let mut renoted = c.clone();
        renoted.note = "something else".into();
        assert!(!renoted.verify(), "the note is unsigned");

        let mut rechained = c;
        rechained.previous = [1u8; 32];
        assert!(!rechained.verify(), "the chain link is unsigned");
    }

    /// A chain round-trips through storage with its counters intact.
    #[test]
    fn a_chain_round_trips() {
        let (x, b) = (node(1), node(2));
        let mut chain = opening(&x, &b, terms(10, 30));
        for who in [&b, &x, &b] {
            let head = chain.head();
            chain
                .push(Counter::create(who.signing_key(), head, terms(2, 5), "hi"))
                .unwrap();
        }
        let back = Chain::decode(&chain.encode()).expect("decodes");
        assert_eq!(back, chain);
        assert_eq!(back.verify(), Ok(()));
    }

    /// Arrives from a stranger. Nothing here may panic, and nothing may
    /// allocate on a declared count.
    #[test]
    fn malformed_input_is_refused_without_panicking() {
        assert_eq!(Counter::decode(&[]), None);
        assert_eq!(Chain::decode(&[]), None);
        let mut runaway = vec![0xa3, 0x01, 0x5a];
        runaway.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(Chain::decode(&runaway), None);

        let (x, b) = (node(1), node(2));
        let mut chain = opening(&x, &b, terms(10, 30));
        chain
            .push(Counter::create(
                b.signing_key(),
                chain.head(),
                terms(1, 3),
                "",
            ))
            .unwrap();
        let good = chain.encode();
        for cut in 0..good.len() {
            let _ = Chain::decode(&good[..cut]);
        }
        for i in 0..good.len().min(400) {
            let mut bad = good.clone();
            bad[i] ^= 0xff;
            if let Some(c) = Chain::decode(&bad) {
                let _ = c.verify();
            }
        }
    }

    /// A declared count that disagrees with what is present describes a
    /// different document from the one that arrived.
    #[test]
    fn a_lying_counter_count_is_refused() {
        let (x, b) = (node(1), node(2));
        let mut chain = opening(&x, &b, terms(10, 30));
        chain
            .push(Counter::create(
                b.signing_key(),
                chain.head(),
                terms(1, 3),
                "",
            ))
            .unwrap();
        let mut w = Writer::new();
        w.map(3)
            .uint(1)
            .bstr(&chain.request.encode())
            .uint(2)
            .uint(7)
            .uint(3)
            .bstr(&[]);
        assert_eq!(Chain::decode(&w.finish()), None);
    }

    /// The chain is bounded. §5.2 names no limit and one arrives from a
    /// stranger.
    #[test]
    fn a_chain_is_bounded() {
        let (x, b) = (node(1), node(2));
        let mut chain = opening(&x, &b, terms(10, 30));
        for i in 0..MAX_COUNTERS {
            let head = chain.head();
            let who = if i % 2 == 0 { &b } else { &x };
            chain
                .push(Counter::create(who.signing_key(), head, terms(1, 3), ""))
                .expect("within the bound");
        }
        let head = chain.head();
        assert_eq!(
            chain.push(Counter::create(b.signing_key(), head, terms(1, 3), "")),
            Err(Broken::TooLong)
        );
    }
}
