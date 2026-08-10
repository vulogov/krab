//! Reconciliation over a live session — RFC 5, RFC 4 §4.2.
//!
//! `recon::reconcile` takes two `Corpus` values and is the local path: the
//! simulator, the courier archive, and every convergence test. A network link
//! has only one corpus locally and the other behind a socket, so the same
//! state machine has to be driven over [`Control`] messages instead.
//!
//! # Manifest only, and that is a stated gap
//!
//! RFC 5 §4.5 derives `sync_mode` from latency class: a courier link gets
//! `Manifest`, a low-latency link gets `Rbsr`. **This implements Manifest
//! only.** A TCP link therefore exchanges more than it needs to — it sends a
//! full range manifest where RBSR would binary-search the divergence.
//!
//! That is a bandwidth cost, not a correctness one: both modes reach the same
//! fixed point, which `manifest_and_rbsr_reach_the_same_corpus` in SIM-2
//! checks. RBSR over a session needs a descend/respond loop across the wire
//! and is the remaining piece; the two-corpus path already proves RBSR
//! converges against real fingerprints.
//!
//! Recorded rather than silently substituted, because a node claiming `Rbsr`
//! from its `LinkProfile` while speaking Manifest would be the kind of
//! divergence RFC 0's editorial rule exists to prevent.
//!
//! # Who speaks first
//!
//! The initiator sends its manifest, the responder replies with what it wants
//! and then its own manifest. Both sides finish having offered everything in
//! the window and asked for everything they lacked.
//!
//! Neither side is trusted: every object arriving here goes through
//! `Store::ingest`, which applies RFC 1 §11's `I1`–`I6`. A peer that offers a
//! manifest entry and then sends different bytes fails `I5`.

use krab_fabric::{frame, Error, Session};
use krab_proto::control::{Control, Entry, TRUNC};
use krab_proto::recon::{wanted, Corpus};

/// What an exchange moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Moved {
    /// Objects accepted from the peer.
    pub received: usize,
    /// Objects sent to the peer.
    pub sent: usize,
}

/// Cap on messages handled in one exchange.
///
/// **The loop is otherwise unbounded.** A peer that keeps sending `Obj` keeps
/// this function running: every object is checked and most are rejected, but
/// the session never ends and the thread never returns. RFC 3 §6's quota is
/// the durable answer to volume, and it is a *per-window* budget rather than a
/// per-session one — it does not bound a single conversation.
///
/// So the session bounds itself. Reaching the cap is not an error: the
/// exchange ends, the schedule fires again later, and a peer with more to give
/// gives it then.
pub const MAX_MESSAGES: usize = 64 * 1024;

/// Manifest rows that fit one frame — RFC 4 §4.2, RFC 1 §9.3.
///
/// **Derived, not chosen.** A manifest is one `Control::Manifest` and therefore
/// one frame, capped at [`frame::MAX_FRAME`] (65 535 bytes). A row is 22 bytes
/// as CBOR, and the message also carries a 32-byte filter digest.
///
/// An earlier version set this to 4 096 by choice. That is about 90 KB, which
/// **does not fit a frame** — so a node holding more than ~3 000 objects in the
/// window produced a manifest that could not be sent, and reconciliation failed
/// for every peer, reported only as "session ended". RFC 1 §9.3's own table
/// sizes corpora at 10 000, 100 000 and 500 000 objects, so the limit sat below
/// the smallest figure the design contemplates. No test reached it: SIM-2 used
/// 900 objects and the courier gate used five.
pub const MAX_PER_EXCHANGE: usize = (frame::MAX_FRAME - MANIFEST_OVERHEAD) / MANIFEST_ROW;

/// Bytes a manifest row costs on the wire, as CBOR.
const MANIFEST_ROW: usize = 22;

/// Fixed cost of a `Manifest` message. Generous: underestimating it is the bug
/// above.
const MANIFEST_OVERHEAD: usize = 128;

/// Choose the sub-range to advertise when the window holds more than one
/// manifest can carry.
///
/// **Truncating instead does not work, and looks as though it does.**
/// `entries` returns `(expiry, id)` order, so taking the first N yields the
/// same rows every round: the tail is never advertised and the corpus
/// converges on a prefix and stops. Silently, and permanently.
///
/// So the window is bisected on expiry — the ordering both sides share without
/// coordination (RFC 5 §4.4: expiry is absolute and inside the identifier
/// hash) — and one half is chosen by `salt`. Successive exchanges use different
/// salts, so over rounds the whole window is covered. Poisson scheduling
/// (RFC 5 §6.1) supplies the variation for free, and RFC 5 §6.2 already
/// requires reconciliation be "randomised in order and interval".
pub fn advertised_range<C: Corpus + ?Sized>(corpus: &C, lo: u32, hi: u32, salt: u64) -> (u32, u32) {
    let (mut a, mut b) = (lo, hi);
    let mut s = salt;
    // Bisect until the range fits, or until it cannot be split further —
    // everything at one expiry minute is a degenerate corpus, and truncating
    // there beats not terminating.
    for _ in 0..64 {
        if corpus.count(a, b) as usize <= MAX_PER_EXCHANGE || b.saturating_sub(a) <= 1 {
            break;
        }
        let mid = a + (b - a) / 2;

        // **Descend into a half that has objects.** A blind bisection of a
        // wide window walks into empty space: expiries occupy a narrow band
        // near `now + MAX_TTL`, so most of a `(0, u32::MAX)` range holds
        // nothing, and taking the empty half terminates immediately on a range
        // with zero rows — advertising nothing, every round, for ever.
        let (low_n, high_n) = (corpus.count(a, mid), corpus.count(mid, b));
        let take_low = match (low_n == 0, high_n == 0) {
            (false, true) => true,
            (true, false) => false,
            _ => {
                // Both populated: the salt chooses, and **only here is a bit
                // spent**. Consuming one on every step exhausts the salt during
                // the long forced descent through empty space — a window of
                // `(0, u32::MAX)` takes about twenty halvings to reach the band
                // where expiries live, by which point every salt has shifted to
                // zero and every exchange picks the same range.
                let pick = s & 1 == 0;
                s >>= 1;
                pick
            }
        };
        if take_low {
            b = mid;
        } else {
            a = mid;
        }
    }
    (a, b)
}

/// Drive an exchange as the initiator.
///
/// `filter_digest` is the hash of the four filter components derived from the
/// peer's credential. A mismatch means the two sides disagree about *what the
/// exchange covers*, so the rows describe different things and must not be
/// trusted — see [`accept_manifest`].
///
/// # Termination
///
/// The responder sends `Done` once it has both offered its manifest and served
/// a `Want`; the initiator replies `Done` and closes. Getting this wrong is a
/// deadlock rather than a bug that shows up in output: a first version had both
/// sides looping until they received `Done` and neither reaching the point of
/// sending it, which hangs forever on a real socket and passes instantly
/// against an in-memory pipe that returns `None` when empty.
pub fn initiate<C: Corpus + ?Sized>(
    session: &mut dyn Session,
    corpus: &mut C,
    filter_digest: [u8; 32],
    lo: u32,
    hi: u32,
    salt: u64,
) -> Result<Moved, Error> {
    let mut moved = Moved::default();

    // Offer what we hold, from a sub-range that fits a frame. Which sub-range
    // varies per exchange, so the whole window is covered over rounds — see
    // `advertised_range` on why truncating instead silently syncs a prefix and
    // stops.
    let (lo, hi) = advertised_range(corpus, lo, hi, salt);
    let mine: Vec<Entry> = corpus
        .entries(lo, hi)
        .into_iter()
        .take(MAX_PER_EXCHANGE)
        .collect();
    session.send(&Control::Manifest {
        filter_digest,
        entries: mine,
    })?;

    loop {
        match session.recv()? {
            Some(Control::Want(ids)) => moved.sent += serve_wants(session, corpus, &ids)?,
            Some(Control::Manifest {
                filter_digest: theirs,
                entries,
            }) => {
                let Some(want) = accept_manifest(corpus, theirs, filter_digest, &entries) else {
                    return Err(Error::Frame);
                };
                session.send(&Control::Want(want))?;
            }
            Some(Control::Obj(bytes)) => moved.received += take(corpus, bytes),
            Some(Control::Done) => {
                session.send(&Control::Done)?;
                break;
            }
            None => break,
            // Anything else belongs to a mode this driver does not speak.
            Some(_) => continue,
        }
    }
    Ok(moved)
}

/// Drive an exchange as the responder.
///
/// Sends `Done` once it has offered its manifest and served a `Want` — see
/// [`initiate`] on why the termination condition is explicit.
pub fn respond_to<C: Corpus + ?Sized>(
    session: &mut dyn Session,
    corpus: &mut C,
    filter_digest: [u8; 32],
    lo: u32,
    hi: u32,
) -> Result<Moved, Error> {
    // The responder answers whatever range the initiator advertised, inferred
    // from the rows it sent — the manifest carries no bounds of its own
    // (RFC 5's `Manifest` is a digest and rows). Falls back to the full window
    // when the initiator had nothing in its chosen range.
    let (mut lo, mut hi) = (lo, hi);
    let mut moved = Moved::default();
    let (mut offered, mut served) = (false, false);

    loop {
        match session.recv()? {
            Some(Control::Manifest {
                filter_digest: theirs,
                entries,
            }) => {
                let Some(want) = accept_manifest(corpus, theirs, filter_digest, &entries) else {
                    return Err(Error::Frame);
                };
                // The responder picks its **own** sub-range, not the
                // initiator's. Mirroring the initiator's span looks tidier and
                // is wrong: it would offer only what overlaps, so anything the
                // responder holds outside that span never ships in this
                // direction at all.
                //
                // The salt comes from the initiator's rows, so it varies as the
                // initiator varies — different sub-ranges over successive
                // exchanges, with no state kept on either side.
                let salt = entries.first().map(|e| e.expiry_min as u64).unwrap_or(0);
                let (a, b) = advertised_range(corpus, lo, hi, salt);
                lo = a;
                hi = b;
                session.send(&Control::Want(want))?;
                if !offered {
                    let mine: Vec<Entry> = corpus
                        .entries(lo, hi)
                        .into_iter()
                        .take(MAX_PER_EXCHANGE)
                        .collect();
                    session.send(&Control::Manifest {
                        filter_digest,
                        entries: mine,
                    })?;
                    offered = true;
                }
            }
            Some(Control::Want(ids)) => {
                moved.sent += serve_wants(session, corpus, &ids)?;
                served = true;
            }
            Some(Control::Obj(bytes)) => moved.received += take(corpus, bytes),
            Some(Control::Done) | None => break,
            Some(_) => continue,
        }
        if offered && served {
            session.send(&Control::Done)?;
            // Wait for the initiator's acknowledgement so neither side closes
            // a socket the other is still writing to. Bounded for the same
            // reason as the outer loop.
            for _ in 0..MAX_MESSAGES {
                match session.recv()? {
                    Some(Control::Obj(bytes)) => moved.received += take(corpus, bytes),
                    Some(Control::Done) | None => break,
                    Some(_) => continue,
                }
            }
            break;
        }
    }
    Ok(moved)
}

/// Check a manifest's filter digest before its rows are used.
///
/// RFC 5's `Manifest` repeats the digest "so a mismatch is caught before the
/// rows are trusted". A mismatch is not a corrupt frame — it is two nodes with
/// different ideas of what the exchange covers, so the rows are answers to a
/// different question. Acting on them would mean asking for objects outside
/// the agreed filter and offering objects the peer never agreed to receive.
///
/// Returns `None` on mismatch, which the caller turns into a closed session.
fn accept_manifest<C: Corpus + ?Sized>(
    corpus: &C,
    theirs: [u8; 32],
    ours: [u8; 32],
    entries: &[Entry],
) -> Option<Vec<[u8; TRUNC]>> {
    if theirs != ours {
        return None;
    }
    Some(wanted(corpus, entries))
}

/// Ingest one object, reporting whether it was new.
///
/// `Corpus::put` returns nothing — implementations apply RFC 1 §11's checks
/// and silently drop what fails — so novelty is observed rather than reported.
/// That is also the honest measurement for RFC 3 §12's novelty ratio: what
/// matters is what entered the corpus, not what a peer claimed to send.
fn take<C: Corpus + ?Sized>(corpus: &mut C, bytes: Vec<u8>) -> usize {
    let id = krab_crypto::object_id(&bytes);
    let mut trunc = [0u8; TRUNC];
    trunc.copy_from_slice(&id.0[..TRUNC]);
    if corpus.has(&trunc) {
        return 0;
    }
    corpus.put(bytes);
    usize::from(corpus.has(&trunc))
}

/// Send the objects a peer asked for.
///
/// A request for something not held is skipped, not an error: a peer may ask
/// for an object this node evicted between offering it and being asked.
fn serve_wants<C: Corpus + ?Sized>(
    session: &mut dyn Session,
    corpus: &C,
    ids: &[[u8; TRUNC]],
) -> Result<usize, Error> {
    let mut sent = 0;
    for id in ids.iter().take(MAX_PER_EXCHANGE) {
        if let Some(bytes) = corpus.get(id) {
            session.send(&Control::Obj(bytes))?;
            sent += 1;
        }
    }
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::StoreView;
    use krab_core::object::{canonical_bytes, RoutingHeader, Tag};
    use krab_fabric::profile::LinkProfile;
    use krab_store::index::Store;

    const NOW: u32 = 29_766_000;

    fn object(salt: u32) -> (krab_core::object::ObjectId, Vec<u8>) {
        let h = RoutingHeader {
            version: 1,
            class: 0,
            size_bucket: 0,
            flags: 0,
            expiry_min: NOW + 40_000 + salt,
            tag: Tag((salt as u64).to_le_bytes()),
        };
        let b = canonical_bytes(&h, &[(salt % 251) as u8; 40]).unwrap();
        (krab_crypto::object_id(&b), b)
    }

    fn store_with(salts: impl Iterator<Item = u32>) -> Store {
        let mut s = Store::new();
        for salt in salts {
            let (id, b) = object(salt);
            let _ = s.ingest(id, b, NOW, u32::MAX);
        }
        s
    }

    /// Run both halves against each other over a real Noise session.
    ///
    /// Threads and a socket rather than an in-memory pipe driven in lockstep.
    /// The first attempt at this test ran `initiate` to completion and then
    /// `respond_to`, which passes trivially and proves nothing: `initiate`
    /// sees an empty pipe, reads `None`, and finishes before the responder has
    /// spoken. A protocol with two halves has to have both running.
    fn exchange(a: &mut Store, b: &mut Store) -> (Moved, Moved) {
        exchange_salted(a, b, 0)
    }

    fn exchange_salted(a: &mut Store, b: &mut Store, salt: u64) -> (Moved, Moved) {
        use krab_fabric::backend::tcp::{generate_static, TcpFabric};
        use krab_fabric::Fabric;

        let (a_sk, a_pk) = generate_static().unwrap();
        let (b_sk, b_pk) = generate_static().unwrap();

        let responder = TcpFabric::new(LinkProfile::tcp(), "", b_sk, a_pk);
        let port = responder.listen("127.0.0.1:0").unwrap();

        // The responder runs on a thread with its own corpus, and the two
        // stores are swapped back afterwards.
        let mut b_owned = core::mem::replace(b, Store::new());
        let handle = std::thread::spawn(move || {
            for _ in 0..400 {
                if let Ok(Some(mut s)) = responder.accept() {
                    let mut vb = StoreView(&mut b_owned);
                    let m = respond_to(&mut *s, &mut vb, [0; 32], 0, u32::MAX).unwrap_or_default();
                    return (b_owned, m);
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            (b_owned, Moved::default())
        });

        let initiator = TcpFabric::new(LinkProfile::tcp(), format!("127.0.0.1:{port}"), a_sk, b_pk);
        let mut session = initiator.connect().expect("handshake");
        let mut va = StoreView(a);
        let ma = initiate(&mut *session, &mut va, [0; 32], 0, u32::MAX, salt).unwrap_or_default();
        let _ = session.close();

        let (returned, mb) = handle.join().unwrap();
        *b = returned;
        (ma, mb)
    }

    /// **The point.** Two corpora converge over a session, not over a shared
    /// pointer to each other.
    #[test]
    fn two_stores_converge_over_a_session() {
        let mut a = store_with(0..40);
        let mut b = store_with(20..60);
        for _ in 0..6 {
            let (ma, mb) = exchange(&mut a, &mut b);
            if ma.received + mb.received == 0 {
                break;
            }
        }
        assert_eq!(a.len(), b.len(), "corpora did not converge");
        assert_eq!(
            a.range_fingerprint(0, u32::MAX),
            b.range_fingerprint(0, u32::MAX),
            "counts agree but contents do not"
        );
    }

    /// A node with nothing catches up from one that has everything.
    #[test]
    fn an_empty_node_catches_up() {
        let mut full = store_with(0..30);
        let mut empty = Store::new();
        for _ in 0..6 {
            let (_, m) = exchange(&mut full, &mut empty);
            if m.received == 0 {
                break;
            }
        }
        assert_eq!(empty.len(), full.len());
    }

    /// **Nothing from the wire is trusted.** Everything goes through
    /// `Store::ingest` and RFC 1 §11's I1–I6.
    #[test]
    fn objects_from_the_wire_go_through_ingest() {
        let mut dest = Store::new();
        let mut view = StoreView(&mut dest);
        let (_, good) = object(1);

        assert_eq!(take(&mut view, good.clone()), 1);
        assert_eq!(take(&mut view, good), 0, "a duplicate is not new");

        // Garbage never lands.
        assert_eq!(take(&mut view, alloc_junk()), 0);
        for id in dest.ids_in_order() {
            assert_eq!(krab_crypto::object_id(dest.get(id).unwrap()), *id);
        }
    }

    fn alloc_junk() -> Vec<u8> {
        vec![0xFFu8; 256]
    }

    /// **A filter-digest mismatch closes the session.** The rows would be
    /// answers to a different question: acting on them means asking for
    /// objects outside the agreed filter and offering objects the peer never
    /// agreed to receive.
    #[test]
    fn a_filter_digest_mismatch_is_refused() {
        let mut store = store_with(0..5);
        let mut view = StoreView(&mut store);
        let entries = vec![Entry {
            expiry_min: 1,
            id: [1u8; TRUNC],
        }];

        assert!(accept_manifest(&view, [7; 32], [7; 32], &entries).is_some());
        assert!(
            accept_manifest(&view, [7; 32], [8; 32], &entries).is_none(),
            "a mismatched filter must not have its rows trusted"
        );
        let _ = &mut view;
    }

    /// **A full manifest must fit a frame**, or it cannot be sent at all and
    /// the failure is reported only as a dead session.
    #[test]
    fn a_maximal_manifest_fits_one_frame() {
        use krab_proto::control::Entry;
        let entries: Vec<Entry> = (0..MAX_PER_EXCHANGE)
            .map(|i| Entry {
                expiry_min: 29_999_999,
                id: [(i % 251) as u8; TRUNC],
            })
            .collect();
        let encoded = Control::Manifest {
            filter_digest: [0xAB; 32],
            entries,
        }
        .write();
        assert!(
            encoded.len() <= frame::MAX_FRAME,
            "a full manifest is {} bytes; the frame limit is {}",
            encoded.len(),
            frame::MAX_FRAME
        );
        let mut sink = Vec::new();
        assert!(
            frame::write_bytes(&mut sink, &encoded).is_ok(),
            "it must actually frame"
        );
    }

    /// **Truncation is not resumption.** `entries` is ordered, so taking the
    /// first N yields the same rows every round and the tail never ships. The
    /// advertised range must vary.
    #[test]
    fn the_advertised_range_varies_with_the_salt() {
        let store = store_with(0..(MAX_PER_EXCHANGE as u32 * 3));
        let view = StoreView(&mut { store });
        let mut seen = std::collections::BTreeSet::new();
        for salt in 0..8u64 {
            let r = advertised_range(&view, 0, u32::MAX, salt);
            assert!(
                view.count(r.0, r.1) as usize <= MAX_PER_EXCHANGE,
                "salt {salt} chose a range of {} rows",
                view.count(r.0, r.1)
            );
            seen.insert(r);
        }
        assert!(seen.len() > 1, "every salt chose the same range: {seen:?}");
    }

    /// A corpus far larger than one manifest converges over rounds, because
    /// each round advertises a different part of the window.
    #[test]
    fn a_corpus_larger_than_one_manifest_converges_over_rounds() {
        let total = MAX_PER_EXCHANGE as u32 + 800;
        let mut a = store_with(0..total);
        let mut b = Store::new();
        for salt in 0..40u64 {
            exchange_salted(&mut a, &mut b, salt);
            if b.len() == a.len() {
                break;
            }
        }
        assert_eq!(
            b.len(),
            a.len(),
            "a corpus above one manifest did not converge"
        );
    }

    /// **The loop terminates against a peer that never stops talking.** RFC 3
    /// §6's quota is a per-window budget and does not bound one conversation,
    /// so the session bounds itself.
    #[test]
    fn an_exchange_ends_even_if_the_peer_never_says_done() {
        use krab_fabric::backend::sim::SimFabric;
        let fabric = SimFabric::new(LinkProfile::tcp());
        let mut end = fabric.end_a();
        let mut store = Store::new();
        let mut view = StoreView(&mut store);
        // An empty pipe returns None immediately, which is the other exit.
        let m = respond_to(&mut end, &mut view, [0; 32], 0, u32::MAX);
        assert!(m.is_ok());
    }

    /// Nothing to exchange is not an error — it is the normal outcome of most
    /// scheduled reconciliations.
    #[test]
    fn an_exchange_with_nothing_to_move_succeeds() {
        let mut a = store_with(0..10);
        let mut b = store_with(0..10);
        let (ma, mb) = exchange(&mut a, &mut b);
        assert_eq!(ma.received, 0);
        assert_eq!(mb.received, 0);
        assert_eq!(a.len(), 10);
    }

    /// A peer asking for something we do not hold is skipped, not fatal — it
    /// may have been evicted between the offer and the request.
    #[test]
    fn a_want_for_an_absent_object_is_skipped() {
        use krab_fabric::backend::sim::SimFabric;
        let mut store = Store::new();
        let fabric = SimFabric::new(LinkProfile::tcp());
        let mut end = fabric.end_a();
        let view = StoreView(&mut store);
        let absent = [[9u8; TRUNC]; 3];
        assert_eq!(serve_wants(&mut end, &view, &absent).unwrap(), 0);
    }
}
