//! Reconciliation, RFC 5 §4.
//!
//! Pure: this module consumes and produces control messages and touches
//! neither a socket nor a clock. That is what makes it the property-test and
//! fuzz target RFC 0 §9 asks for — reconciliation is reachable
//! pre-authentication, so it is untrusted input by definition.
//!
//! # Two modes, and the choice is not a preference
//!
//! SIM-1 §1 measured that reconciliation strategy has no safe default:
//!
//! - a full manifest **starves 98.3%** of LoRa reconciliations once the filter
//!   admits ordinary traffic
//! - RBSR **collapses austere delivery from 95.8% to 33.0%**, because each
//!   descent level costs a courier round trip of three days each way
//!
//! So [`Mode`] is selected per link from `latency_class`, and
//! `Documentation/RFC-5-blocking-items.md` §1 gives the procedure: a full
//! manifest is feasible iff it fits the per-sync window, RBSR is feasible iff
//! `depth × 2 × latency` fits well inside the TTL, and a link where neither
//! holds cannot reconcile and should say so at configuration time.

use crate::control::{Entry, Range, TRUNC};
use alloc::vec::Vec;
use krab_crypto::Fingerprint;

/// Reconciliation strategy for a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Full manifest, one round trip. Mandatory where `latency_class` is
    /// `Courier` (RFC 5 §4.3): a courier exchange has exactly one round trip
    /// available, and the archive is the protocol with the round trips removed.
    Manifest,
    /// Range-based set reconciliation. Correct where round trips are cheap and
    /// bandwidth is not.
    Rbsr,
}

/// RFC 5 §4.4 — stop splitting and just list, at or below this many objects.
pub const RBSR_LEAF: u32 = 32;
/// RFC 5 §4.4 — sub-ranges per split.
pub const RBSR_BRANCH: u32 = 16;
/// RFC 5 §4.4 — round-trip cap, after which fall back to [`Mode::Manifest`].
///
/// An adversarial peer can otherwise manufacture divergence patterns that
/// never converge, which RFC 5 §12 names as an amplification vector.
pub const RBSR_MAX_ROUNDS: usize = 8;

/// What reconciliation needs from a store. Deliberately minimal: everything
/// here is derivable from `(expiry, id)` ordering and the frozen header, so a
/// locked node can serve it without any decryption key (RFC 7 §7).
pub trait Corpus {
    /// Rows in `(expiry, id)` order within `[lo, hi)`.
    fn entries(&self, lo: u32, hi: u32) -> Vec<Entry>;
    /// Additive fingerprint over `[lo, hi)`.
    fn fingerprint(&self, lo: u32, hi: u32) -> Fingerprint;
    /// Objects in `[lo, hi)`.
    fn count(&self, lo: u32, hi: u32) -> u32;
    /// Canonical bytes for a truncated identifier, if held.
    fn get(&self, id: &[u8; TRUNC]) -> Option<Vec<u8>>;
    /// Whether the object is held.
    fn has(&self, id: &[u8; TRUNC]) -> bool;
    /// Ingest canonical bytes. Implementations apply RFC 1 §11's checks.
    fn put(&mut self, bytes: Vec<u8>);
}

/// Everything a peer offered that we lack.
///
/// This is the whole of manifest mode's difference computation, and RBSR's
/// leaf case reduces to it.
pub fn wanted<C: Corpus + ?Sized>(local: &C, offered: &[Entry]) -> Vec<[u8; TRUNC]> {
    offered
        .iter()
        .filter(|e| !local.has(&e.id))
        .map(|e| e.id)
        .collect()
}

/// Split a range into at most [`RBSR_BRANCH`] sub-ranges, RFC 5 §4.4.
///
/// Split by expiry span rather than by cardinality. Both sides must derive the
/// *same* boundaries with no coordination, and expiry is the only quantity
/// both sides agree on without exchanging anything — it is absolute and inside
/// the identifier hash. Splitting by relative cardinality, as RFC 5 §4.4's
/// prose suggests, would need the counts to match, which is precisely what is
/// in dispute during a descent.
pub fn split(range: &Range) -> Vec<(u32, u32)> {
    let span = range.hi.saturating_sub(range.lo);
    if span <= 1 {
        return Vec::new();
    }
    let n = RBSR_BRANCH.min(span);
    let step = span.div_ceil(n);
    let mut out = Vec::new();
    let mut lo = range.lo;
    while lo < range.hi {
        let hi = (lo.saturating_add(step)).min(range.hi);
        out.push((lo, hi));
        lo = hi;
    }
    out
}

/// Describe a range from the local corpus.
pub fn describe<C: Corpus + ?Sized>(local: &C, lo: u32, hi: u32) -> Range {
    Range {
        lo,
        hi,
        fingerprint: local.fingerprint(lo, hi),
        count: local.count(lo, hi),
    }
}

/// One side's response to a batch of ranges, RFC 5 §4.4.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Response {
    /// Ranges still in dispute, described from the responder's corpus.
    pub descend: Vec<Range>,
    /// The responder's own rows for every range it resolved as a leaf.
    pub list: Vec<Entry>,
    /// The leaf ranges themselves.
    ///
    /// **The peer must list these too.** A leaf means "this range differs and
    /// is small enough to enumerate" — and each side can only enumerate its
    /// own holdings, so a leaf resolved by one side is an instruction to both.
    /// Omitting this is the asymmetry that makes a descent silently
    /// one-directional: the initiator describes a range, the responder lists
    /// what *it* has, and nothing ever asks the initiator to list what *it*
    /// has.
    pub leaves: Vec<(u32, u32)>,
}

/// Respond to a batch of ranges, RFC 5 §4.4.
pub fn respond<C: Corpus + ?Sized>(local: &C, offered: &[Range]) -> Response {
    let mut out = Response::default();
    for r in offered {
        let mine = describe(local, r.lo, r.hi);
        if mine.fingerprint == r.fingerprint {
            // Agreed. Prune -- this is where RBSR's advantage comes from.
            continue;
        }
        let parts = split(r);
        if mine.count.max(r.count) <= RBSR_LEAF || parts.is_empty() {
            // `parts.is_empty()` is the termination guard: a range spanning a
            // single minute cannot be split further, so it must be listed
            // however many objects it holds, or the descent never converges.
            out.list.extend(local.entries(r.lo, r.hi));
            out.leaves.push((r.lo, r.hi));
        } else {
            for (lo, hi) in parts {
                out.descend.push(describe(local, lo, hi));
            }
        }
    }
    out
}

/// Outcome of a completed reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    /// Round trips consumed. Manifest mode is always 1.
    pub rounds: usize,
    /// Objects transferred, both directions.
    pub transferred: usize,
    /// Whether RBSR hit [`RBSR_MAX_ROUNDS`] and fell back.
    pub fell_back: bool,
}

/// Reconcile two corpora over `[lo, hi)` to the filtered union.
///
/// A driver rather than a transport: it sequences the same messages a session
/// would exchange, which is what lets the convergence property be tested
/// without a socket.
pub fn reconcile<A: Corpus + ?Sized, B: Corpus + ?Sized>(
    a: &mut A,
    b: &mut B,
    mode: Mode,
    lo: u32,
    hi: u32,
) -> Outcome {
    match mode {
        Mode::Manifest => {
            let (ma, mb) = (a.entries(lo, hi), b.entries(lo, hi));
            let to_b = wanted(b, &ma);
            let to_a = wanted(a, &mb);
            let mut n = 0;
            for id in &to_b {
                if let Some(bytes) = a.get(id) {
                    b.put(bytes);
                    n += 1;
                }
            }
            for id in &to_a {
                if let Some(bytes) = b.get(id) {
                    a.put(bytes);
                    n += 1;
                }
            }
            Outcome {
                rounds: 1,
                transferred: n,
                fell_back: false,
            }
        }
        Mode::Rbsr => {
            let mut pending = alloc::vec![describe(a, lo, hi)];
            let (mut listed_a, mut listed_b) = (Vec::new(), Vec::new());
            let mut rounds = 0;
            let mut fell_back = false;

            while !pending.is_empty() {
                if rounds >= RBSR_MAX_ROUNDS {
                    // RFC 5 §4.4 -- cap and fall back, or an adversarial peer
                    // manufactures a descent that never converges.
                    fell_back = true;
                    listed_a = a.entries(lo, hi);
                    listed_b = b.entries(lo, hi);
                    break;
                }
                rounds += 1;

                let rb = respond(b, &pending);
                listed_b.extend(rb.list);
                // A leaf binds both sides: B enumerated its holdings, so A
                // must enumerate its own for the same range.
                for &(l, h) in &rb.leaves {
                    listed_a.extend(a.entries(l, h));
                }
                if rb.descend.is_empty() {
                    break;
                }

                let ra = respond(a, &rb.descend);
                listed_a.extend(ra.list);
                for &(l, h) in &ra.leaves {
                    listed_b.extend(b.entries(l, h));
                }
                pending = ra.descend;
            }

            let mut n = 0;
            for id in wanted(b, &listed_a) {
                if let Some(bytes) = a.get(&id) {
                    b.put(bytes);
                    n += 1;
                }
            }
            for id in wanted(a, &listed_b) {
                if let Some(bytes) = b.get(&id) {
                    a.put(bytes);
                    n += 1;
                }
            }
            Outcome {
                rounds,
                transferred: n,
                fell_back,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use krab_core::object::{canonical_bytes, ObjectId, RoutingHeader, Tag};

    const DAY: u32 = 1_440;

    /// A corpus keyed by truncated identifier, enough for the state machine.
    #[derive(Default, Clone)]
    struct Mem {
        objs: BTreeMap<(u32, [u8; TRUNC]), (ObjectId, Vec<u8>)>,
    }

    fn make(expiry_min: u32, salt: u8) -> (ObjectId, Vec<u8>) {
        let h = RoutingHeader {
            version: 1,
            class: 0,
            size_bucket: 0,
            flags: 0,
            expiry_min,
            tag: Tag([salt; 8]),
        };
        let bytes = canonical_bytes(&h, &krab_core::object::example_sealed_body(salt)).unwrap();
        (krab_crypto::object_id(&bytes), bytes)
    }

    impl Mem {
        fn with(items: &[(u32, u8)]) -> Mem {
            let mut m = Mem::default();
            for &(e, s) in items {
                m.insert(e, s);
            }
            m
        }
        fn insert(&mut self, expiry: u32, salt: u8) {
            let (id, bytes) = make(expiry, salt);
            self.objs.insert((expiry, id.truncated()), (id, bytes));
        }
        fn ids(&self) -> Vec<[u8; TRUNC]> {
            self.objs.keys().map(|(_, i)| *i).collect()
        }
    }

    impl Corpus for Mem {
        fn entries(&self, lo: u32, hi: u32) -> Vec<Entry> {
            self.objs
                .range((lo, [0; TRUNC])..(hi, [0; TRUNC]))
                .map(|((e, i), _)| Entry {
                    expiry_min: *e,
                    id: *i,
                })
                .collect()
        }
        fn fingerprint(&self, lo: u32, hi: u32) -> Fingerprint {
            self.objs
                .range((lo, [0; TRUNC])..(hi, [0; TRUNC]))
                .fold(Fingerprint::ZERO, |a, (_, (id, _))| {
                    a.add(Fingerprint::of(id))
                })
        }
        fn count(&self, lo: u32, hi: u32) -> u32 {
            self.objs.range((lo, [0; TRUNC])..(hi, [0; TRUNC])).count() as u32
        }
        fn get(&self, id: &[u8; TRUNC]) -> Option<Vec<u8>> {
            self.objs
                .values()
                .find(|(i, _)| &i.truncated() == id)
                .map(|(_, b)| b.clone())
        }
        fn has(&self, id: &[u8; TRUNC]) -> bool {
            self.objs.keys().any(|(_, i)| i == id)
        }
        fn put(&mut self, bytes: Vec<u8>) {
            if let Ok(h) = RoutingHeader::parse(&bytes) {
                let id = krab_crypto::object_id(&bytes);
                self.objs
                    .insert((h.expiry_min, id.truncated()), (id, bytes));
            }
        }
    }

    /// RFC 0 §9's property, stated there as: *for any two stores and any
    /// filter, reconciliation converges to the filtered union in bounded
    /// rounds under reordering and duplication.*
    fn converges(mode: Mode, left: &[(u32, u8)], right: &[(u32, u8)]) {
        let (mut a, mut b) = (Mem::with(left), Mem::with(right));

        let mut union: Vec<[u8; TRUNC]> = a.ids();
        union.extend(b.ids());
        union.sort_unstable();
        union.dedup();

        let out = reconcile(&mut a, &mut b, mode, 0, 400 * DAY);

        let (mut ia, mut ib) = (a.ids(), b.ids());
        ia.sort_unstable();
        ib.sort_unstable();
        assert_eq!(ia, union, "{mode:?}: A did not reach the union");
        assert_eq!(ib, union, "{mode:?}: B did not reach the union");
        assert!(out.rounds <= RBSR_MAX_ROUNDS, "{mode:?}: unbounded rounds");

        // Idempotent: a second pass transfers nothing.
        let again = reconcile(&mut a, &mut b, mode, 0, 400 * DAY);
        assert_eq!(again.transferred, 0, "{mode:?}: not idempotent");
    }

    #[test]
    fn converges_in_both_modes() {
        for mode in [Mode::Manifest, Mode::Rbsr] {
            converges(mode, &[], &[]);
            converges(mode, &[(DAY, 1)], &[]);
            converges(mode, &[], &[(DAY, 1)]);
            converges(mode, &[(DAY, 1)], &[(DAY, 1)]);
            converges(
                mode,
                &[(DAY, 1), (2 * DAY, 2)],
                &[(2 * DAY, 2), (3 * DAY, 3)],
            );
        }
    }

    /// "under reordering" — ingest order must not affect the outcome.
    #[test]
    fn converges_under_reordering() {
        let fwd: Vec<(u32, u8)> = (1..40u8).map(|n| (n as u32 * 60, n)).collect();
        let rev: Vec<(u32, u8)> = fwd.iter().rev().copied().collect();
        for mode in [Mode::Manifest, Mode::Rbsr] {
            converges(mode, &fwd, &rev[..20]);
            converges(mode, &rev, &fwd[..20]);
        }
    }

    /// "under duplication" — the same object offered repeatedly is absorbed by
    /// content addressing (RFC 0 I-1), not by a dedup mechanism.
    #[test]
    fn converges_under_duplication() {
        let dup: Vec<(u32, u8)> = alloc::vec![(DAY, 1), (DAY, 1), (DAY, 1), (2 * DAY, 2)];
        for mode in [Mode::Manifest, Mode::Rbsr] {
            converges(mode, &dup, &[(2 * DAY, 2), (2 * DAY, 2)]);
        }
    }

    /// Disjoint corpora large enough to force a real descent.
    #[test]
    fn rbsr_descends_and_still_converges() {
        let a: Vec<(u32, u8)> = (0..120u8).map(|n| (n as u32 * 500 + 1, n)).collect();
        let b: Vec<(u32, u8)> = (120..240u8).map(|n| (n as u32 * 500 + 1, n)).collect();
        converges(Mode::Rbsr, &a, &b);
    }

    /// RBSR's advantage: an agreeing range is pruned without listing it.
    #[test]
    fn rbsr_prunes_agreeing_ranges() {
        let same: Vec<(u32, u8)> = (0..100u8).map(|n| (n as u32 * 500 + 1, n)).collect();
        let (mut a, mut b) = (Mem::with(&same), Mem::with(&same));
        let out = reconcile(&mut a, &mut b, Mode::Rbsr, 0, 400 * DAY);
        assert_eq!(out.transferred, 0);
        assert_eq!(
            out.rounds, 1,
            "identical corpora agree at the root, in one round"
        );
        assert!(!out.fell_back);
    }

    /// Both sides must derive identical boundaries with no coordination.
    #[test]
    fn split_is_deterministic_and_covers_without_gaps() {
        let r = Range {
            lo: 0,
            hi: 10_000,
            fingerprint: Fingerprint::ZERO,
            count: 999,
        };
        let parts = split(&r);
        assert_eq!(
            parts,
            split(&r),
            "both sides must derive the same boundaries"
        );
        assert!(parts.len() <= RBSR_BRANCH as usize);
        assert_eq!(parts.first().unwrap().0, r.lo);
        assert_eq!(parts.last().unwrap().1, r.hi);
        for w in parts.windows(2) {
            assert_eq!(w[0].1, w[1].0, "no gap, no overlap");
        }
    }

    #[test]
    fn split_terminates_on_degenerate_ranges() {
        for (lo, hi) in [(0u32, 0u32), (5, 5), (5, 6), (u32::MAX - 1, u32::MAX)] {
            let r = Range {
                lo,
                hi,
                fingerprint: Fingerprint::ZERO,
                count: 1,
            };
            assert!(split(&r).len() <= RBSR_BRANCH as usize);
        }
    }
}
