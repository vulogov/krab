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

use krab_fabric::{Error, Session};
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

/// Cap on objects offered in one exchange.
///
/// Not a quota — RFC 3 §6's quota is the receiver's business, and a sender
/// cannot enforce it. This bounds a single session so one exchange cannot
/// occupy a link indefinitely, which matters on a constrained one where RFC 4
/// §4.1 requires sessions be held open across cycles.
pub const MAX_PER_EXCHANGE: usize = 4_096;

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
) -> Result<Moved, Error> {
    let mut moved = Moved::default();

    // Offer what we hold.
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
            // a socket the other is still writing to.
            while let Some(msg) = session.recv()? {
                match msg {
                    Control::Obj(bytes) => moved.received += take(corpus, bytes),
                    Control::Done => break,
                    _ => continue,
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
        let ma = initiate(&mut *session, &mut va, [0; 32], 0, u32::MAX).unwrap_or_default();
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
