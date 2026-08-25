//! Nodelist fragments and `NODEDIFF` — RFC 3 §8.
//!
//! > "Source routing needs two-hop visibility. Nothing needs more.
//! >
//! > A node's fragment is the set of its currently valid `peer-link`
//! > credentials, signed, and **encrypted individually to each of its own
//! > peers**. Not published, not flooded, not readable by anyone at three
//! > hops."
//!
//! # Fragments are the graph
//!
//! RFC 3 §15 says it in four words, and it is the whole reason this module is
//! written the way it is:
//!
//! > "**Fragments are the graph.** §8.3's default-false share flag is the
//! > control. An operator who sets it true everywhere has published their
//! > social graph to their peers, one hop at a time."
//!
//! So the interesting code here is not the encoding. It is [`listable`], which
//! decides what a fragment may contain, and the two things it refuses.
//!
//! # The share flag is per direction, and direction is not obvious
//!
//! §8.3:
//!
//! ```text
//! a_shares_b : bool     A will list B in fragments A hands out
//! b_shares_a : bool
//! ```
//!
//! > "Per direction, both signed, so neither party can unilaterally expose the
//! > other. **Default MUST be false** — opt in to being listed, not out."
//!
//! The trap is that a credential's "party A" is **not** the fragment's author.
//! Parties are ordered canonically by `sig_pk` (see [`crate::credential`]), so
//! whether this node is A or B depends on a byte comparison it does not
//! control. A fragment builder that read `a_shares_b` because it thought of
//! itself as A would publish, for half its peerings, the flag the *other*
//! party set — and publishing a link on the strength of a permission the other
//! party gave themselves is precisely what §8.3's per-direction rule exists to
//! prevent.
//!
//! [`listable`] resolves the direction from the author's node id every time.
//!
//! # What a reader must check, and why it is not just the signature
//!
//! A fragment is signed by its author, so its *contents* are attributable. It
//! does not follow that the contents are true. [`Fragment::verify`] therefore
//! requires, for every listed credential:
//!
//! - it verifies on its own — both signatures, unexpired, canonical order;
//! - the **author is one of its two parties**, so a node cannot list a peering
//!   between two other people and grow its apparent reach;
//! - the share flag for the author's direction is set, so a node cannot
//!   publish a link the counterparty refused to have published.
//!
//! The third is the one that matters. Without it a node signs a fragment
//! listing a link whose `a_shares_b` is false, and the recipient — who has no
//! other way to know — treats it as a route. The flag is inside the
//! credential's signature, so the check is cheap and the forgery is not
//! possible; skipping the check is what would make it possible.
//!
//! # Sealed to each peer, never flooded
//!
//! §8 says "encrypted individually to each of its own peers", and §8.1 prices
//! it: `O(P²)` bytes, 1.05 MB at fifty peers, about 58 LoRa reconciliations.
//! That cost is the upper bound on peer count in §13's table, so it is not an
//! inefficiency to optimise away — it is the mechanism that keeps a fragment
//! from becoming a directory.
//!
//! Nothing here produces a bulletin, and there is no bulletin kind that could
//! carry a fragment.
//!
//! # `NODEDIFF`
//!
//! §8.2: full fragments weekly, deltas between, and "deltas MUST reference the
//! last full fragment by hash. A peer that has missed a delta requests the
//! full fragment." [`Delta`] carries that hash, and a reader that does not
//! hold the named base cannot apply one — which is the requesting condition,
//! made checkable rather than advisory.

use crate::credential::Credential;
use krab_core::cbor::{Item, Reader, Writer};
use krab_crypto::sign::{Sig, SigningKey, VerifyingKey};

/// Domain for a fragment's signature. Frozen.
pub const DOMAIN: &[u8] = b"krab/fragment/v1";

/// Domain for a delta's signature.
#[allow(dead_code)]
pub const DOMAIN_DELTA: &[u8] = b"krab/nodediff/v1";

/// Domain for the hash a delta references its base by.
#[allow(dead_code)]
pub const DOMAIN_BASE: &[u8] = b"krab/fragment-base/v1";

/// RFC 3 §8.2 — how often a full fragment should go out.
#[allow(dead_code)]
pub const FULL_INTERVAL_DAYS: u64 = 7;

/// The most links a fragment may list.
///
/// RFC 3 §13 recommends 8–25 peers and warns above 25 on constrained links;
/// §8.1 prices fifty at 1.05 MB per publication. Fifty is past every
/// recommendation and short of anything that would let a fragment from a
/// stranger cost a reader real memory.
pub const MAX_LINKS: usize = 50;

/// The bound must not fall below RFC 3 §13's upper recommendation — **checked
/// at compile time**, because a bound narrowed below what the RFC recommends
/// would silently truncate an operator's nodelist and present as peers who
/// stopped being reachable.
const _: () = assert!(
    MAX_LINKS >= 25,
    "MAX_LINKS is below RFC 3 §13's upper recommendation"
);

/// Whether `author` may list this credential in a fragment — RFC 3 §8.3.
///
/// **The direction is resolved from the author, not assumed.** A credential's
/// party A is whichever `sig_pk` sorts lower, which the author does not
/// control; reading `a_shares_b` regardless would publish, for half a node's
/// peerings, a permission the other party granted themselves.
pub fn listable(cred: &Credential, author: &[u8; 32]) -> bool {
    if cred.a.node_id() == *author {
        cred.flags.a_shares_b
    } else if cred.b.node_id() == *author {
        cred.flags.b_shares_a
    } else {
        // Not a party. Nothing to share.
        false
    }
}

/// A node's currently valid peer-links, signed — RFC 3 §8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    /// Key 1 — the author's identity key.
    pub author: [u8; 32],
    /// Key 2 — when it was published, Unix seconds.
    ///
    /// §8.2's cadence is weekly, and a reader holding two fragments from one
    /// author needs to know which is current. Not an arrival time: this is
    /// what the author says, inside their own signature, and RFC 3 §12's ban
    /// on retained arrival timestamps is untouched by it.
    pub published_s: u64,
    /// Key 3 — the credentials listed.
    pub links: Vec<Credential>,
    /// Ed25519 over `DOMAIN ‖ body`.
    pub sig: [u8; 64],
}

/// Why a fragment or delta was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bad {
    /// The signature is not the author's.
    Signature,
    /// A listed credential does not verify on its own.
    Link,
    /// A listed credential is not one of the author's peerings.
    NotTheirs,
    /// A listed credential's share flag, for the author's direction, is off.
    NotShared,
    /// Longer than [`MAX_LINKS`].
    TooLong,
    /// A delta whose base this reader does not hold — §8.2's "requests the
    /// full fragment".
    #[allow(dead_code)]
    UnknownBase,
}

impl Fragment {
    fn signed_bytes(author: &[u8; 32], published_s: u64, links: &[Credential]) -> Vec<u8> {
        let mut w = Writer::new();
        w.map(3)
            .uint(1)
            .bstr(author)
            .uint(2)
            .uint(published_s)
            .uint(3)
            .bstr(&pack(links));
        let body = w.finish();
        let mut out = Vec::with_capacity(DOMAIN.len() + body.len());
        out.extend_from_slice(DOMAIN);
        out.extend_from_slice(&body);
        out
    }

    /// Build a fragment from everything this node holds.
    ///
    /// **Filters rather than trusting the caller.** Handing this an
    /// unfiltered list of credentials must not produce a fragment that lists
    /// them: §15 calls the share flag "the control", and a control that
    /// depends on every caller remembering it is not one.
    pub fn create(
        signer: &SigningKey,
        published_s: u64,
        candidates: &[Credential],
        now_s: u64,
    ) -> Fragment {
        let author = signer.verifying_key().to_bytes();
        let id = krab_crypto::hash::node_id(&author);
        let links: Vec<Credential> = candidates
            .iter()
            // Expired links are not "currently valid" — §8's own word — and a
            // fragment listing one advertises a route that no longer exists.
            .filter(|c| c.verify(now_s).is_ok())
            .filter(|c| listable(c, &id))
            .take(MAX_LINKS)
            .cloned()
            .collect();
        let sig = signer
            .sign(&Fragment::signed_bytes(&author, published_s, &links))
            .0;
        Fragment {
            author,
            published_s,
            links,
            sig,
        }
    }

    /// The author's node identifier.
    pub fn node_id(&self) -> [u8; 32] {
        krab_crypto::hash::node_id(&self.author)
    }

    /// What a delta references this fragment by — §8.2.
    #[allow(dead_code)]
    pub fn base_hash(&self) -> [u8; 32] {
        krab_crypto::hash::domain_hash(DOMAIN_BASE, &self.encode())
    }

    /// Whether this fragment is one a reader may act on.
    ///
    /// See the module header: a valid signature makes the contents
    /// attributable, not true.
    pub fn verify(&self, now_s: u64) -> Result<(), Bad> {
        if self.links.len() > MAX_LINKS {
            return Err(Bad::TooLong);
        }
        if !VerifyingKey::from_bytes(self.author).verify(
            &Fragment::signed_bytes(&self.author, self.published_s, &self.links),
            &Sig(self.sig),
        ) {
            return Err(Bad::Signature);
        }
        let id = self.node_id();
        for c in &self.links {
            c.verify(now_s).map_err(|_| Bad::Link)?;
            if c.a.node_id() != id && c.b.node_id() != id {
                return Err(Bad::NotTheirs);
            }
            if !listable(c, &id) {
                return Err(Bad::NotShared);
            }
        }
        Ok(())
    }

    /// The node identifiers this fragment reveals as the author's peers.
    ///
    /// Two-hop visibility, and no more: a reader learns who the author peers
    /// with, which is one hop past its own. §8's opening sentence is that
    /// nothing needs more than that.
    pub fn reaches(&self) -> Vec<[u8; 32]> {
        let id = self.node_id();
        self.links
            .iter()
            .filter_map(|c| c.other_than(&id).map(|p| p.node_id()))
            .collect()
    }

    /// Deterministic CBOR — RFC 1 §4.3.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.map(4)
            .uint(1)
            .bstr(&self.author)
            .uint(2)
            .uint(self.published_s)
            .uint(3)
            .bstr(&pack(&self.links))
            .uint(4)
            .bstr(&self.sig);
        w.finish()
    }

    /// Decode. **Pre-authentication input** — a fragment arrives from a peer,
    /// and its contents arrive from beyond one.
    pub fn decode(bytes: &[u8]) -> Option<Fragment> {
        let mut r = Reader::new(bytes);
        let mut m = r.map().ok()?;
        if m.left() != 4 {
            return None;
        }
        let author = bstr_at(&mut m, 1)?.try_into().ok()?;
        let published_s = match at(&mut m, 2)? {
            Item::Uint(v) => v,
            _ => return None,
        };
        let links = unpack(bstr_at(&mut m, 3)?)?;
        let sig: [u8; 64] = bstr_at(&mut m, 4)?.try_into().ok()?;
        Some(Fragment {
            author,
            published_s,
            links,
            sig,
        })
    }
}

/// A `NODEDIFF` — RFC 3 §8.2.
///
/// > "Deltas MUST reference the last full fragment by hash. A peer that has
/// > missed a delta requests the full fragment."
///
/// # Built, tested, and **not yet wired** — stated rather than left to be found
///
/// `peer fragment` sends a full fragment every time. Nothing constructs a
/// `Delta` outside this module's tests, and `Fragment::base_hash` has no
/// production caller.
///
/// Two things are missing, both bookkeeping rather than protocol:
///
/// 1. **The base, per peer, on both sides.** A sender must remember which full
///    fragment each peer last received, and a reader must hold the base a
///    delta names — `apply` already refuses one it does not, which is §8.2's
///    "requests the full fragment" made checkable.
/// 2. **The cadence hook.** §8.2 says full fragments weekly
///    ([`FULL_INTERVAL_DAYS`]) with deltas between, which needs a decision in
///    the scheduler rather than in a command.
///
/// The cost of not having it is bandwidth and only bandwidth: §8.2's table
/// puts a one-link delta at 8× to 34× cheaper than a full fragment, which
/// matters on the austere links §8.1 prices and nowhere else. **No security
/// property depends on it** — a full fragment carries exactly what a delta
/// would and is checked identically.
///
/// Recorded here and in `MILESTONE-0.1.md` because this codebase's most common
/// defect is a thing built with no caller, and the two previous instances
/// (`exchange::respond_to`, `receive::scan_requests`) were both found by
/// accident months later.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delta {
    /// Key 1 — the author's identity key.
    pub author: [u8; 32],
    /// Key 2 — `H` of the full fragment this builds on.
    pub base: [u8; 32],
    /// Key 3 — when it was published.
    pub published_s: u64,
    /// Key 4 — links added or replaced since the base.
    pub added: Vec<Credential>,
    /// Key 5 — node identifiers no longer listed.
    ///
    /// A removal names a node, which is unavoidable: saying a link is gone
    /// requires saying which. It reveals nothing the base did not already —
    /// the reader was told about that peering when the base arrived.
    pub removed: Vec<[u8; 32]>,
    /// Ed25519 over `DOMAIN_DELTA ‖ body`.
    pub sig: [u8; 64],
}

#[allow(dead_code)]
impl Delta {
    fn signed_bytes(
        author: &[u8; 32],
        base: &[u8; 32],
        published_s: u64,
        added: &[Credential],
        removed: &[[u8; 32]],
    ) -> Vec<u8> {
        let mut flat = Vec::with_capacity(removed.len() * 32);
        for r in removed {
            flat.extend_from_slice(r);
        }
        let mut w = Writer::new();
        w.map(5)
            .uint(1)
            .bstr(author)
            .uint(2)
            .bstr(base)
            .uint(3)
            .uint(published_s)
            .uint(4)
            .bstr(&pack(added))
            .uint(5)
            .bstr(&flat);
        let body = w.finish();
        let mut out = Vec::with_capacity(DOMAIN_DELTA.len() + body.len());
        out.extend_from_slice(DOMAIN_DELTA);
        out.extend_from_slice(&body);
        out
    }

    /// Build a delta against `base`, filtered the same way a fragment is.
    pub fn create(
        signer: &SigningKey,
        base: &Fragment,
        published_s: u64,
        candidates: &[Credential],
        now_s: u64,
    ) -> Delta {
        let author = signer.verifying_key().to_bytes();
        let id = krab_crypto::hash::node_id(&author);
        let listed: Vec<[u8; 32]> = base.reaches();

        let current: Vec<Credential> = candidates
            .iter()
            .filter(|c| c.verify(now_s).is_ok())
            .filter(|c| listable(c, &id))
            .take(MAX_LINKS)
            .cloned()
            .collect();
        let now_ids: Vec<[u8; 32]> = current
            .iter()
            .filter_map(|c| c.other_than(&id).map(|p| p.node_id()))
            .collect();

        // Added: anything the base did not carry, or carried differently.
        let added: Vec<Credential> = current
            .iter()
            .filter(|c| {
                let who = c.other_than(&id).map(|p| p.node_id());
                match who {
                    Some(w) => !listed.contains(&w) || !base.links.contains(c),
                    None => false,
                }
            })
            .cloned()
            .collect();
        let removed: Vec<[u8; 32]> = listed
            .into_iter()
            .filter(|w| !now_ids.contains(w))
            .collect();

        let sig = signer
            .sign(&Delta::signed_bytes(
                &author,
                &base.base_hash(),
                published_s,
                &added,
                &removed,
            ))
            .0;
        Delta {
            author,
            base: base.base_hash(),
            published_s,
            added,
            removed,
            sig,
        }
    }

    /// The author's node identifier.
    pub fn node_id(&self) -> [u8; 32] {
        krab_crypto::hash::node_id(&self.author)
    }

    /// Apply to the base a reader holds, producing the current fragment view.
    ///
    /// **Refuses a base it was not built against** — §8.2's "a peer that has
    /// missed a delta requests the full fragment", expressed as a check rather
    /// than as advice. Applying a delta to the wrong base would silently
    /// produce a nodelist neither party ever signed.
    pub fn apply(&self, base: &Fragment, now_s: u64) -> Result<Vec<Credential>, Bad> {
        if base.base_hash() != self.base {
            return Err(Bad::UnknownBase);
        }
        if !VerifyingKey::from_bytes(self.author).verify(
            &Delta::signed_bytes(
                &self.author,
                &self.base,
                self.published_s,
                &self.added,
                &self.removed,
            ),
            &Sig(self.sig),
        ) {
            return Err(Bad::Signature);
        }
        if self.author != base.author {
            return Err(Bad::NotTheirs);
        }
        let id = self.node_id();
        // Everything added is checked exactly as a fragment's links are: a
        // delta is a fragment's contents arriving by another route, and a
        // weaker check here would be the way around the stronger one there.
        for c in &self.added {
            c.verify(now_s).map_err(|_| Bad::Link)?;
            if c.a.node_id() != id && c.b.node_id() != id {
                return Err(Bad::NotTheirs);
            }
            if !listable(c, &id) {
                return Err(Bad::NotShared);
            }
        }

        let mut out: Vec<Credential> = base
            .links
            .iter()
            .filter(|c| match c.other_than(&id) {
                Some(p) => !self.removed.contains(&p.node_id()),
                None => false,
            })
            .filter(|c| {
                // Replaced entries drop out; the added copy takes their place.
                !self.added.iter().any(|a| {
                    a.other_than(&id).map(|p| p.node_id()) == c.other_than(&id).map(|p| p.node_id())
                })
            })
            .cloned()
            .collect();
        out.extend(self.added.iter().cloned());
        if out.len() > MAX_LINKS {
            return Err(Bad::TooLong);
        }
        Ok(out)
    }

    /// Deterministic CBOR.
    pub fn encode(&self) -> Vec<u8> {
        let mut flat = Vec::with_capacity(self.removed.len() * 32);
        for r in &self.removed {
            flat.extend_from_slice(r);
        }
        let mut w = Writer::new();
        w.map(6)
            .uint(1)
            .bstr(&self.author)
            .uint(2)
            .bstr(&self.base)
            .uint(3)
            .uint(self.published_s)
            .uint(4)
            .bstr(&pack(&self.added))
            .uint(5)
            .bstr(&flat)
            .uint(6)
            .bstr(&self.sig);
        w.finish()
    }

    /// Decode. Pre-authentication input.
    pub fn decode(bytes: &[u8]) -> Option<Delta> {
        let mut r = Reader::new(bytes);
        let mut m = r.map().ok()?;
        if m.left() != 6 {
            return None;
        }
        let author = bstr_at(&mut m, 1)?.try_into().ok()?;
        let base = bstr_at(&mut m, 2)?.try_into().ok()?;
        let published_s = match at(&mut m, 3)? {
            Item::Uint(v) => v,
            _ => return None,
        };
        let added = unpack(bstr_at(&mut m, 4)?)?;
        let flat = bstr_at(&mut m, 5)?;
        if flat.len() % 32 != 0 || flat.len() / 32 > MAX_LINKS {
            return None;
        }
        let removed: Vec<[u8; 32]> = flat
            .chunks_exact(32)
            .map(|c| c.try_into().expect("32 bytes"))
            .collect();
        let sig: [u8; 64] = bstr_at(&mut m, 6)?.try_into().ok()?;
        Some(Delta {
            author,
            base,
            published_s,
            added,
            removed,
            sig,
        })
    }
}

/// Length-prefixed credentials. Sized by what arrived, never by a declared
/// count.
fn pack(links: &[Credential]) -> Vec<u8> {
    let mut out = Vec::new();
    for c in links {
        let b = c.encode();
        let mut w = Writer::new();
        w.uint(b.len() as u64);
        out.extend_from_slice(&w.finish());
        out.extend_from_slice(&b);
    }
    out
}

fn unpack(mut rest: &[u8]) -> Option<Vec<Credential>> {
    let mut out = Vec::new();
    while !rest.is_empty() {
        if out.len() >= MAX_LINKS {
            return None;
        }
        let mut r = Reader::new(rest);
        let len = match r.item().ok()? {
            Item::Uint(v) => usize::try_from(v).ok()?,
            _ => return None,
        };
        let consumed = rest.len() - r.remaining();
        let body = rest.get(consumed..consumed.checked_add(len)?)?;
        out.push(Credential::decode(body)?);
        rest = &rest[consumed + len..];
    }
    Some(out)
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
    use crate::credential::{Flags, DEFAULT_TERM_DAYS};
    use crate::identity::Identity;
    use crate::peering::Policy;
    use krab_crypto::rng::NotRandom;

    const NOW: u64 = 1_800_000_000;

    fn node(seed: u64) -> Identity {
        Identity::generate(&mut NotRandom::seeded(seed))
    }

    /// A completed credential between `x` and `y`, with the share flags set
    /// as named **for those two nodes** rather than for A and B.
    fn cred(x: &Identity, y: &Identity, x_shares: bool, y_shares: bool) -> Credential {
        let mut c = Credential::propose(
            x.signing_key(),
            &x.card(Policy::default()),
            &y.card(Policy::default()),
            NOW,
            DEFAULT_TERM_DAYS,
            [7u8; 16],
        );
        // Resolve the canonical order before setting the flags — which is the
        // whole point of the test helper.
        let (a_shares_b, b_shares_a) = if c.a.node_id() == x.node_id() {
            (x_shares, y_shares)
        } else {
            (y_shares, x_shares)
        };
        c.flags = Flags {
            a_shares_b,
            b_shares_a,
            ..Flags::default()
        };
        c.sig_a = None;
        c.sig_b = None;
        c.sign(x.signing_key());
        c.sign(y.signing_key());
        c
    }

    /// **RFC 3 §8.3's default is false, and it is a MUST.** "Opt in to being
    /// listed, not out."
    #[test]
    fn nothing_is_listed_by_default() {
        let (x, y) = (node(1), node(2));
        let c = cred(&x, &y, false, false);
        let f = Fragment::create(x.signing_key(), NOW, &[c], NOW + 60);
        assert!(f.links.is_empty(), "a default peering was published");
        assert_eq!(f.verify(NOW + 60), Ok(()));
        assert!(f.reaches().is_empty());
    }

    /// Opting in lists it, and only in the direction opted into.
    #[test]
    fn a_shared_link_is_listed_in_the_sharers_fragment_only() {
        let (x, y) = (node(1), node(2));
        // X will list Y; Y will not list X.
        let c = cred(&x, &y, true, false);

        let xf = Fragment::create(x.signing_key(), NOW, std::slice::from_ref(&c), NOW + 60);
        assert_eq!(xf.links.len(), 1, "X opted in and listed nothing");
        assert_eq!(xf.reaches(), vec![y.node_id()]);

        let yf = Fragment::create(y.signing_key(), NOW, std::slice::from_ref(&c), NOW + 60);
        assert!(
            yf.links.is_empty(),
            "Y published a link it never agreed to publish"
        );
    }

    /// **The direction is resolved from the author, not assumed.**
    ///
    /// A credential's party A is whichever `sig_pk` sorts lower, which no node
    /// controls. A builder reading `a_shares_b` regardless would publish, for
    /// half its peerings, the flag the *other* party set for themselves.
    ///
    /// Driven over many pairs so both orderings are exercised whichever way
    /// the keys happen to sort.
    #[test]
    fn the_share_direction_follows_the_author_not_the_party_order() {
        let mut seen_a = 0;
        let mut seen_b = 0;
        for seed in 0..24u64 {
            let (x, y) = (node(seed * 2 + 100), node(seed * 2 + 101));
            // X shares, Y does not — stated about the nodes, not about A/B.
            let c = cred(&x, &y, true, false);
            if c.a.node_id() == x.node_id() {
                seen_a += 1;
            } else {
                seen_b += 1;
            }
            assert!(listable(&c, &x.node_id()), "the sharer could not list");
            assert!(
                !listable(&c, &y.node_id()),
                "a node listed a link it never agreed to"
            );
        }
        assert!(seen_a > 0 && seen_b > 0, "only one ordering was exercised");
    }

    /// A node cannot list a peering between two other people — that would grow
    /// its apparent reach with somebody else's relationships.
    #[test]
    fn a_node_cannot_list_a_peering_it_is_not_part_of() {
        let (x, y, z) = (node(1), node(2), node(3));
        let theirs = cred(&y, &z, true, true);
        assert!(!listable(&theirs, &x.node_id()));

        // Built by filtering, so it simply does not appear.
        let f = Fragment::create(
            x.signing_key(),
            NOW,
            std::slice::from_ref(&theirs),
            NOW + 60,
        );
        assert!(f.links.is_empty());

        // And forced in by hand, a reader refuses it.
        let mut forged = Fragment {
            links: vec![theirs],
            ..f
        };
        forged.sig = x
            .signing_key()
            .sign(&Fragment::signed_bytes(
                &forged.author,
                forged.published_s,
                &forged.links,
            ))
            .0;
        assert_eq!(forged.verify(NOW + 60), Err(Bad::NotTheirs));
    }

    /// **A reader checks the flag too.** Otherwise a node signs a fragment
    /// listing a link the counterparty refused to have published, and the
    /// reader has no other way to know.
    #[test]
    fn a_reader_refuses_a_link_the_counterparty_did_not_share() {
        let (x, y) = (node(1), node(2));
        let unshared = cred(&x, &y, false, false);
        let mut f = Fragment::create(x.signing_key(), NOW, &[], NOW + 60);
        f.links = vec![unshared];
        f.sig = x
            .signing_key()
            .sign(&Fragment::signed_bytes(&f.author, f.published_s, &f.links))
            .0;
        assert_eq!(f.verify(NOW + 60), Err(Bad::NotShared));
    }

    /// "Currently valid" is §8's own word. An expired credential advertises a
    /// route that no longer exists.
    #[test]
    fn an_expired_link_is_not_currently_valid() {
        let (x, y) = (node(1), node(2));
        let c = cred(&x, &y, true, true);
        let after = c.expires_s + 1;
        let f = Fragment::create(x.signing_key(), NOW, &[c], after);
        assert!(f.links.is_empty(), "an expired peering was published");
    }

    /// Every field is signed, and a forged fragment does not verify.
    #[test]
    fn a_fragment_is_signed_end_to_end() {
        let (x, y) = (node(1), node(2));
        let shared_xy = cred(&x, &y, true, true);
        let f = Fragment::create(
            x.signing_key(),
            NOW,
            std::slice::from_ref(&shared_xy),
            NOW + 60,
        );
        assert_eq!(f.verify(NOW + 60), Ok(()));

        let mut moved = f.clone();
        moved.published_s += 1;
        assert_eq!(moved.verify(NOW + 60), Err(Bad::Signature));

        let mut emptied = f.clone();
        emptied.links.clear();
        assert_eq!(emptied.verify(NOW + 60), Err(Bad::Signature));

        let back = Fragment::decode(&f.encode()).expect("decodes");
        assert_eq!(back, f);
        assert_eq!(back.verify(NOW + 60), Ok(()));
    }

    /// **Two-hop visibility, and no more** — §8's opening sentence.
    #[test]
    fn a_fragment_reveals_one_hop_past_the_reader() {
        let (x, y, z) = (node(1), node(2), node(3));
        let f = Fragment::create(
            x.signing_key(),
            NOW,
            &[cred(&x, &y, true, true), cred(&x, &z, true, true)],
            NOW + 60,
        );
        let reach = f.reaches();
        assert_eq!(reach.len(), 2);
        assert!(reach.contains(&y.node_id()) && reach.contains(&z.node_id()));
        // And nothing about who *they* peer with.
        for c in &f.links {
            assert!(
                c.is_between(&x.node_id(), &y.node_id())
                    || c.is_between(&x.node_id(), &z.node_id())
            );
        }
    }

    /// **A delta references its base by hash** — §8.2 — and applying one to
    /// the wrong base is refused rather than silently producing a nodelist
    /// nobody signed.
    #[test]
    fn a_delta_applies_only_to_the_base_it_names() {
        let (x, y, z) = (node(1), node(2), node(3));
        let xy = cred(&x, &y, true, true);
        let xz = cred(&x, &z, true, true);

        let base = Fragment::create(x.signing_key(), NOW, std::slice::from_ref(&xy), NOW + 60);
        let d = Delta::create(
            x.signing_key(),
            &base,
            NOW + 86_400,
            &[xy.clone(), xz.clone()],
            NOW + 60,
        );
        assert_eq!(d.added.len(), 1, "only the new link is a delta");
        assert!(d.removed.is_empty());

        let applied = d.apply(&base, NOW + 60).expect("applies to its base");
        assert_eq!(applied.len(), 2);

        // A different base is refused — §8.2's "requests the full fragment".
        let other = Fragment::create(x.signing_key(), NOW + 1, &[xy], NOW + 60);
        assert_eq!(d.apply(&other, NOW + 60), Err(Bad::UnknownBase));
    }

    /// A removal drops the link, and reveals nothing the base had not.
    #[test]
    fn a_delta_can_remove_a_link() {
        let (x, y, z) = (node(1), node(2), node(3));
        let xy = cred(&x, &y, true, true);
        let xz = cred(&x, &z, true, true);
        let base = Fragment::create(x.signing_key(), NOW, &[xy.clone(), xz], NOW + 60);
        assert_eq!(base.links.len(), 2);

        let d = Delta::create(x.signing_key(), &base, NOW + 86_400, &[xy], NOW + 60);
        assert_eq!(d.removed.len(), 1, "the dropped peering was not recorded");
        let applied = d.apply(&base, NOW + 60).expect("applies");
        assert_eq!(applied.len(), 1);
    }

    /// A delta's contents are checked exactly as a fragment's are — otherwise
    /// it is the way around the stronger check.
    #[test]
    fn a_delta_cannot_smuggle_an_unshared_link() {
        let (x, y, z) = (node(1), node(2), node(3));
        let shared_xy = cred(&x, &y, true, true);
        let base = Fragment::create(
            x.signing_key(),
            NOW,
            std::slice::from_ref(&shared_xy),
            NOW + 60,
        );
        let unshared = cred(&x, &z, false, false);

        let mut d = Delta::create(x.signing_key(), &base, NOW + 86_400, &[], NOW + 60);
        d.added = vec![unshared];
        d.sig = x
            .signing_key()
            .sign(&Delta::signed_bytes(
                &d.author,
                &d.base,
                d.published_s,
                &d.added,
                &d.removed,
            ))
            .0;
        assert_eq!(d.apply(&base, NOW + 60), Err(Bad::NotShared));
    }

    /// A delta signed by somebody other than the base's author is refused.
    #[test]
    fn a_delta_from_another_author_is_refused() {
        let (x, y, z) = (node(1), node(2), node(3));
        let shared_xy = cred(&x, &y, true, true);
        let base = Fragment::create(
            x.signing_key(),
            NOW,
            std::slice::from_ref(&shared_xy),
            NOW + 60,
        );
        let mut d = Delta::create(z.signing_key(), &base, NOW + 86_400, &[], NOW + 60);
        d.base = base.base_hash();
        d.sig = z
            .signing_key()
            .sign(&Delta::signed_bytes(
                &d.author,
                &d.base,
                d.published_s,
                &d.added,
                &d.removed,
            ))
            .0;
        assert_eq!(d.apply(&base, NOW + 60), Err(Bad::NotTheirs));
    }

    /// Both documents round-trip, and both are bounded — they arrive from a
    /// peer and their contents from beyond one.
    #[test]
    fn malformed_input_is_refused_without_panicking() {
        assert_eq!(Fragment::decode(&[]), None);
        assert_eq!(Delta::decode(&[]), None);
        let mut runaway = vec![0xa4, 0x01, 0x5a];
        runaway.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(Fragment::decode(&runaway), None);

        let (x, y) = (node(1), node(2));
        let shared_xy = cred(&x, &y, true, true);
        let f = Fragment::create(
            x.signing_key(),
            NOW,
            std::slice::from_ref(&shared_xy),
            NOW + 60,
        );
        let good = f.encode();
        for cut in 0..good.len() {
            let _ = Fragment::decode(&good[..cut]);
        }
        for i in 0..good.len().min(400) {
            let mut bad = good.clone();
            bad[i] ^= 0xff;
            if let Some(g) = Fragment::decode(&bad) {
                let _ = g.verify(NOW + 60);
            }
        }

        let d = Delta::create(x.signing_key(), &f, NOW, &[], NOW + 60);
        let dg = d.encode();
        for cut in 0..dg.len() {
            let _ = Delta::decode(&dg[..cut]);
        }
        assert_eq!(Delta::decode(&dg), Some(d));
    }

    /// §8.1 prices a fragment at `O(P²)`, and §13 recommends 8–25 peers. The
    /// bound is past every recommendation and short of anything a stranger's
    /// document could spend a reader's memory on.
    #[test]
    fn a_fragment_is_bounded() {
        let (x, y) = (node(1), node(2));
        let f = Fragment {
            links: vec![cred(&x, &y, true, true); MAX_LINKS + 1],
            ..Fragment::create(x.signing_key(), NOW, &[], NOW + 60)
        };
        assert_eq!(f.verify(NOW + 60), Err(Bad::TooLong));
        assert_eq!(
            Fragment::decode(&f.encode()),
            None,
            "the encoding is bounded"
        );
    }
}
