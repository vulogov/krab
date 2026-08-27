//! Recognising and opening mail — RFC 2 §4.3, RFC 1 §6.
//!
//! # Recognition is a table lookup, not trial decryption
//!
//! A node cannot tell from an object who it is for: that is the whole point of
//! RFC 1 §6.2's tags. What it can do is precompute every tag it would
//! recognise and look up the one on the object.
//!
//! RFC 2 §4.3 sizes it: correspondents × (2W+1) entries, which at 50
//! correspondents and W=45 is 4 550 entries and 55 KB. One ECDH per
//! correspondent, cached; only the HKDF pass repeats on rollover.
//!
//! The alternative — attempting decryption against every correspondent for
//! every object — is `correspondents × objects` public-key operations per
//! sync, and on a node holding a few thousand objects that is not a
//! constant-factor difference.
//!
//! # The window is `MAX_TTL`, and getting it wrong is silent
//!
//! W is `EPOCH_WINDOW`, not a latency percentile (RFC 1 §6.2). An object
//! delivered at the far edge of the TTL this protocol declares valid arrives
//! up to 45 epochs after the epoch its tag derives from. A recipient with a
//! narrower window **simply never computed that tag**: §11 accepts the object,
//! the store keeps it, and it is undecryptable forever. Nothing surfaces it,
//! because RFC 0 §6 makes delivery failure silent by design.
//!
//! `krab_core` asserts `EPOCH_WINDOW >= MAX_TTL_DAYS` at compile time, so this
//! module cannot be built against a narrowed window.
//!
//! # Tag collisions are expected and are not an error
//!
//! Tags are 8 bytes. Across 4 550 entries a collision is unlikely but not
//! negligible, and across a large corpus an *accidental* match against an
//! object addressed to someone else is routine. [`Inbox::scan`] therefore
//! treats a tag match as a hint: it tries to open, and a failure is ordinary
//! rather than suspicious. The count is reported (RFC 3 §12's
//! tag-match/decrypt-fail ratio) because a *high* rate means something else —
//! usually that objects are arriving outside the window above.
//!
//! # Plaintext lives only while displayed
//!
//! RFC 7 §8. [`Message`] holds its plaintext, and the caller drops it when the
//! view changes. Nothing here writes a decrypted body anywhere, and there is
//! no cache — a second look re-derives it. That is also why there is no "Sent"
//! folder anywhere in Krab: an outbound message that survived its own
//! transmission would be a plaintext copy at rest with no expiry.

use krab_core::object::{decode_envelope, ObjectId, RoutingHeader, Tag, ROUTING_HEADER_LEN};
use krab_core::tag::Epoch;
use krab_crypto::dh::{PublicKey, SecretKey, Shared};
use krab_crypto::reservoir::Reservoir;
use krab_crypto::seal::{begin_open, info_for, Mode, ENC_LEN};
use krab_store::index::Store;
use std::collections::HashMap;

/// A correspondent this node can recognise mail from.
pub struct Correspondent {
    /// Short identifier, as displayed and as the peer-link is named.
    pub name: String,
    /// Their correspondence public key.
    pub correspondence: PublicKey,
    /// `S = X25519(our_sk, their_pk)`, computed once and reused.
    pub shared: Shared,
    /// The reservoir root, if the ceremony established one.
    pub reservoir: Option<Reservoir>,
}

/// Every tag this node would recognise, for the current window.
///
/// Rebuilt on epoch rollover. Holding it rather than deriving per object is
/// what makes recognition `O(1)` per object instead of `O(correspondents)`.
pub struct TagTable {
    /// tag → indices into the correspondent list.
    ///
    /// A `Vec` per tag because collisions are expected — see the module note.
    by_tag: HashMap<[u8; 8], Vec<(usize, Epoch)>>,
    /// The epoch this table was built for.
    built_for: Epoch,
}

impl TagTable {
    /// Build the table for `now`'s window.
    pub fn build(correspondents: &[Correspondent], now: Epoch) -> TagTable {
        let mut by_tag: HashMap<[u8; 8], Vec<(usize, Epoch)>> = HashMap::new();
        for (i, c) in correspondents.iter().enumerate() {
            for (epoch, tag) in krab_crypto::pairwise_window(&c.shared, now) {
                by_tag.entry(tag.0).or_default().push((i, epoch));
            }
        }
        TagTable {
            by_tag,
            built_for: now,
        }
    }

    /// Candidates for a tag. Empty means this object is not addressed here.
    pub fn candidates(&self, tag: &Tag) -> &[(usize, Epoch)] {
        self.by_tag.get(&tag.0).map(|v| &v[..]).unwrap_or(&[])
    }

    /// Whether the table still covers `now`.
    ///
    /// The table is a window around a specific epoch; using yesterday's table
    /// today loses the newest epoch and gains nothing, which would present as
    /// mail from the last day being undecryptable.
    pub fn is_current(&self, now: Epoch) -> bool {
        self.built_for == now
    }

    /// Entries held. RFC 2 §4.3's figure is 4 550 for 50 correspondents.
    pub fn len(&self) -> usize {
        self.by_tag.values().map(|v| v.len()).sum()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.by_tag.is_empty()
    }
}

/// What one opened object yielded: sender, epoch, body, nodelist, picture,
/// and whether the reservoir was in play.
type Opened = (
    String,
    Epoch,
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    bool,
);

/// A message this node could open.
pub struct Message {
    /// The object it came from.
    ///
    /// Held so a caller can re-derive the plaintext without a second scan. It
    /// is deliberately not displayed: RFC 3 §12 forbids per-object provenance
    /// in the accountability panel, and showing an identifier beside a message
    /// invites exactly the correlation that rule exists to prevent.
    #[allow(dead_code)]
    pub id: ObjectId,
    /// Who sent it.
    pub from: String,
    /// The epoch its tag derives from — not when it arrived, which this node
    /// deliberately does not record (RFC 3 §12).
    pub epoch: Epoch,
    /// A picture, if this message is one — RFC 8 §6.
    ///
    /// Held as bytes, never as text: a PNG through `from_utf8_lossy` is a
    /// destroyed PNG. **Lives only as long as this value does** (RFC 7 §8),
    /// like the body beside it.
    pub picture: Option<Vec<u8>>,
    /// A nodelist fragment or `NODEDIFF`, if this message is one — RFC 3 §8.
    ///
    /// Held as bytes for the same reason a picture is, and it is not a
    /// theoretical reason: a fragment is 32-byte keys and 64-byte signatures,
    /// so `from_utf8_lossy` replaces most of it with U+FFFD and every
    /// signature check fails. The first version of the fragment read path
    /// decoded `body.as_bytes()` and could never have worked.
    pub nodelist: Option<Vec<u8>>,
    /// Plaintext. **Lives only as long as this value does** (RFC 7 §8).
    pub body: String,
    /// Whether the reservoir was in play, so the interface can say what the
    /// message's post-quantum status actually is.
    pub post_quantum: bool,
}

/// What a scan found.
pub struct Scan {
    /// Messages opened, newest epoch first.
    pub messages: Vec<Message>,
    /// Objects whose tag matched but which did not open.
    ///
    /// RFC 3 §12's tag-match/decrypt-fail count. Ordinary at low rates —
    /// an 8-byte tag collides. A high rate means objects are arriving outside
    /// the acceptance window, which is otherwise invisible.
    pub tag_match_decrypt_fail: usize,
    /// Objects examined.
    pub examined: usize,
}

/// Whether a plaintext is a nodelist fragment or a `NODEDIFF` — RFC 3 §8.
///
/// Recognised **before** the lossy text conversion, like a picture, because
/// afterwards there is nothing left to recognise. Decoding both is the
/// discriminator: neither is valid text and neither collides with the other,
/// and both are verified by the caller before anything is believed.
fn is_nodelist(pt: &[u8]) -> bool {
    crate::fragment::Fragment::decode(pt).is_some() || crate::fragment::Delta::decode(pt).is_some()
}

/// A first-contact document this node could open — RFC 3 §5.
#[allow(clippy::large_enum_variant)]
pub enum Incoming {
    /// A request, already verified and addressed here.
    Request {
        /// The document.
        request: crate::request::PeerRequest,
        /// The epoch its inbox tag derives from.
        ///
        /// Held so a caller can say how old a request is without the node
        /// recording arrival times, which RFC 3 §12 forbids.
        #[allow(dead_code)]
        epoch: Epoch,
    },
    /// A counter answering one — §5.2. Verified, but whether it belongs to a
    /// negotiation this node is part of is a question only the chain can
    /// answer.
    Counter {
        /// The document.
        counter: crate::negotiate::Counter,
        /// The epoch its inbox tag derives from.
        #[allow(dead_code)]
        epoch: Epoch,
    },
}

/// Scan for first-contact requests on this node's own inbox tag.
///
/// Separate from [`Inbox::scan`] because the two use different HPKE modes and
/// different authentication: a pairwise message is authenticated by the KEM, a
/// request only by its inner signature. Merging them would mean one code path
/// where the authentication check is conditional, which is the shape of a
/// check that eventually gets skipped.
pub fn scan_requests(
    store: &Store,
    ours: &SecretKey,
    our_node_id: &[u8; 32],
    now: Epoch,
    window: (u32, u32),
) -> Vec<Incoming> {
    // An inbox tag needs only our own public key — which is the property that
    // makes first contact possible and makes it linkable within an epoch
    // (RFC 2 §4.2).
    let mut tags = std::collections::HashMap::new();
    for epoch in Epoch::window(now) {
        tags.insert(krab_crypto::inbox_tag(&ours.public(), epoch).0, epoch);
    }

    let mut out = Vec::new();
    for (_, id) in store.entries_in_range(window.0, window.1) {
        let Some(bytes) = store.get(&id) else {
            continue;
        };
        let Ok(header) = RoutingHeader::parse(bytes) else {
            continue;
        };
        let Some(&epoch) = tags.get(&header.tag.0) else {
            continue;
        };

        let Ok((env, _)) = decode_envelope(&bytes[ROUTING_HEADER_LEN..]) else {
            continue;
        };
        if env.tag_mode != 1 || env.enc.len() != ENC_LEN {
            continue;
        }
        let mut enc = [0u8; ENC_LEN];
        enc.copy_from_slice(env.enc);
        let aad = crate::compose::aad_for(&header, &env);

        // `mode_base`: no sender key is bound, so anyone may have sealed this.
        // The signature inside is what says who.
        let Ok(mut ctx) = begin_open(
            &Mode::Base,
            ours,
            &ours.public(),
            &enc,
            &info_for(header.class),
        ) else {
            continue;
        };
        let Ok(pt) = ctx.open(env.ciphertext, &aad) else {
            continue;
        };
        // A request, or a counter answering one — RFC 3 §5.2. Both travel to
        // the inbox tag, because at this point the two nodes are still
        // strangers and there is no other address either can use.
        //
        // Tried in order rather than discriminated by a tag byte: §5.1 fixes
        // the request's encoding and there is no spare field in it. The two
        // shapes do not collide — a counter's key 1 is a 32-byte hash where a
        // request's is a card — and **both are verified before use**, so a
        // misread is a refusal rather than a confusion.
        if let Ok(request) = crate::request::PeerRequest::decode(&pt) {
            // Both checks, and neither implies the other.
            if request.verify() && request.is_for(our_node_id) {
                out.push(Incoming::Request { request, epoch });
                continue;
            }
        }
        if let Some(counter) = crate::negotiate::Counter::decode(&pt) {
            // Addressing is not checked here: a counter names no recipient,
            // and the chain it belongs to is what says whether it is ours.
            // `Chain::push` refuses one that answers a document we do not
            // hold, which is the same question asked where it can be answered.
            if counter.verify() {
                out.push(Incoming::Counter { counter, epoch });
            }
        }
    }
    out
}

/// The recognition and decryption path.
pub struct Inbox;

/// How many trial decapsulations one scan may spend, and which
/// `(id, expiry)` pairs are known not to open.
///
/// **Bounded on purpose.** The keys are attacker-supplied identifiers, so an
/// unbounded cache is the same denial of service wearing the other hat: the
/// flood that used to cost CPU would cost memory instead. When it is full it
/// stops accepting new entries rather than evicting — a full cache still
/// answers correctly for everything in it, and the per-scan cap below is what
/// bounds the work for everything else.
#[derive(Debug, Default)]
pub struct Attempts {
    bad: std::collections::HashSet<([u8; 32], u32)>,
    spent: usize,
}

/// Entries kept. Each is 36 bytes plus set overhead, so this is tens of KB.
pub const MAX_REMEMBERED: usize = 4096;

/// Trial decapsulations one scan may spend.
///
/// RFC 2 §9 says "per peer per epoch"; this is per scan, which is stricter in
/// the direction that matters — a scan covers every peer and the whole epoch
/// window, so a per-scan bound bounds every per-peer figure inside it. It is
/// generous against honest traffic: a node whose correspondents send more than
/// this many objects that match a tag and fail to open, in one pass, is under
/// attack rather than busy.
pub const MAX_ATTEMPTS_PER_SCAN: usize = 256;

impl Attempts {
    /// A fresh budget. Made per scan; the cache within it persists across
    /// scans when the caller keeps it.
    pub fn new() -> Attempts {
        Attempts::default()
    }

    /// Whether this pair has already been shown not to open.
    pub fn known_bad(&self, id: &[u8; 32], expiry: u32) -> bool {
        self.bad.contains(&(*id, expiry))
    }

    /// Record a pair that did not open.
    pub fn remember_bad(&mut self, id: [u8; 32], expiry: u32) {
        if self.bad.len() < MAX_REMEMBERED {
            self.bad.insert((id, expiry));
        }
    }

    /// Spend one attempt. `false` once the budget for this scan is gone.
    pub fn charge(&mut self) -> bool {
        if self.spent >= MAX_ATTEMPTS_PER_SCAN {
            return false;
        }
        self.spent += 1;
        true
    }

    /// Start a new scan: the budget refills, the cache does not.
    pub fn refresh(&mut self) {
        self.spent = 0;
    }

    /// Drop everything. The caller does this when the correspondent set or
    /// the epoch changes, because either can change whether a pair opens.
    pub fn clear(&mut self) {
        self.bad.clear();
        self.spent = 0;
    }

    /// How many pairs are remembered. Used by the bound's test.
    #[cfg(test)]
    pub fn remembered(&self) -> usize {
        self.bad.len()
    }
}

impl Inbox {
    /// Scan the corpus for mail this node can open.
    ///
    /// Returns plaintext the caller is expected to drop when the view changes.
    /// Nothing is cached and nothing is written.
    /// A scan with no attempt state carried across calls.
    ///
    /// Only tests use this: production keeps an [`Attempts`] on the `App` so
    /// the cache outlives one pass, which is the point of having one.
    #[cfg(test)]
    pub fn scan(
        store: &Store,
        table: &TagTable,
        correspondents: &[Correspondent],
        ours: &[SecretKey],
        window: (u32, u32),
    ) -> Scan {
        let mut discard = Attempts::new();
        Self::scan_with(store, table, correspondents, ours, window, &mut discard)
    }

    /// As [`Inbox::scan`], but carrying the caller's attempt state across
    /// calls — which is the whole point of it.
    ///
    /// **RFC 2 §9 / RFC 1 §6.4.** An adversary who learns a current tag can
    /// flood objects bearing it, and each one costs a full constant-time
    /// trial decapsulation — about 10 ms — for nothing. Two requirements
    /// follow, and RFC 2 states both as MUST where RFC 1 states the second as
    /// SHOULD; the stricter governs:
    ///
    /// > Implementations MUST cache failed (id, epoch) pairs so a replay
    /// > costs one lookup. Implementations MUST cap inbox-tagged
    /// > decapsulation attempts per peer per epoch.
    ///
    /// Neither existed. Every object that matched a tag and failed to open
    /// was retried in full on every refresh, and refresh runs on every tick
    /// that drains an exchange — so an idle two-node network was already
    /// paying it, which is how this was noticed.
    pub fn scan_with(
        store: &Store,
        table: &TagTable,
        correspondents: &[Correspondent],
        ours: &[SecretKey],
        window: (u32, u32),
        attempts: &mut Attempts,
    ) -> Scan {
        let mut out = Scan {
            messages: Vec::new(),
            tag_match_decrypt_fail: 0,
            examined: 0,
        };

        for (_, id) in store.entries_in_range(window.0, window.1) {
            let Some(bytes) = store.get(&id) else {
                continue;
            };
            out.examined += 1;

            let Ok(header) = RoutingHeader::parse(bytes) else {
                continue;
            };
            let candidates = table.candidates(&header.tag);
            if candidates.is_empty() {
                // Not addressed here, and the node learns nothing else about
                // it. It is still stored and still relayed.
                continue;
            }

            // **The cache, before the work.** A pair that failed once fails
            // again: the object is immutable, the keys for that epoch are
            // fixed, and the only thing that could change the answer is a new
            // correspondent — which rebuilds the tag table and clears this.
            if attempts.known_bad(&id.0, header.expiry_min) {
                out.tag_match_decrypt_fail += 1;
                continue;
            }
            // **The cap.** Beyond it, tag-matching objects are left alone
            // this pass rather than decapsulated. They are still stored and
            // still relayed; what is refused is the CPU, which is the thing
            // being attacked.
            if !attempts.charge() {
                out.tag_match_decrypt_fail += 1;
                continue;
            }

            match Self::open_object(bytes, &header, candidates, correspondents, ours) {
                Some((from, epoch, body, nodelist, picture, pq)) => out.messages.push(Message {
                    id,
                    from,
                    epoch,
                    body,
                    nodelist,
                    picture,
                    post_quantum: pq,
                }),
                None => {
                    attempts.remember_bad(id.0, header.expiry_min);
                    out.tag_match_decrypt_fail += 1;
                }
            }
        }

        // Newest first. Ordering by epoch, not by arrival — this node does not
        // record arrival times (RFC 3 §12), and could not sort by them.
        out.messages.sort_by(|a, b| b.epoch.cmp(&a.epoch));
        out
    }

    /// Try every candidate for a matched tag.
    fn open_object(
        bytes: &[u8],
        header: &RoutingHeader,
        candidates: &[(usize, Epoch)],
        correspondents: &[Correspondent],
        ours: &[SecretKey],
    ) -> Option<Opened> {
        let (env, _) = decode_envelope(&bytes[ROUTING_HEADER_LEN..]).ok()?;
        if env.enc.len() != ENC_LEN {
            return None;
        }
        let mut enc = [0u8; ENC_LEN];
        enc.copy_from_slice(env.enc);

        // RFC 1 §6.1's AAD, from the one definition the sender also uses.
        let aad = crate::compose::aad_for(header, &env);
        let info = info_for(header.class);
        // Held rather than returned, so the loops below run to completion —
        // see the note on RFC 1 §6.3 further down.
        let mut opened: Option<Opened> = None;

        for (idx, tag_epoch) in candidates {
            let c = correspondents.get(*idx)?;
            // The envelope's epoch is authenticated by the AAD, so it can be
            // trusted once decryption succeeds — but the chunk is needed
            // *before* that, so the table's epoch is used to select it and a
            // mismatch simply fails to open.
            let epoch = Epoch(env.epoch as u32);
            if epoch != *tag_epoch {
                continue;
            }

            let chunk = c.reservoir.as_ref().and_then(|r| r.chunk(epoch));
            let modes: [Mode; 2] = match &chunk {
                Some(k) => [Mode::AuthPsk { chunk: k, epoch }, Mode::Auth],
                None => [Mode::Auth, Mode::Auth],
            };
            for (n, mode) in modes.iter().enumerate() {
                if n == 1 && chunk.is_none() {
                    break;
                }
                // **Every private key, and no early exit.** RFC 1 §6.3:
                // "Implementations MUST attempt the full set and MUST NOT stop
                // at first success; early exit leaks index position, which
                // correlates with prekey consumption and is a volume signal."
                //
                // So the loop runs to the end and the first success is kept
                // rather than returned. `krab_crypto::prekey::Ring` has no
                // method that returns one key for the same reason: an API that
                // can return early eventually does.
                for ours in ours {
                    let Ok(mut ctx) = begin_open(mode, ours, &c.correspondence, &enc, &info) else {
                        continue;
                    };
                    if let Ok(pt) = ctx.open(env.ciphertext, &aad) {
                        if opened.is_none() {
                            // A picture keeps its bytes; anything else is
                            // text. `from_utf8_lossy` on a PNG produces a
                            // string that is not the picture.
                            // Binary payloads keep their bytes; anything
                            // else is text. Both checks happen *before* the
                            // lossy conversion, because after it there is
                            // nothing left to recognise.
                            let (body, picture, nodelist) =
                                match crate::picture::from_plaintext(&pt) {
                                    Some(png) => (
                                        format!("[picture, {} bytes — `picture save`]", png.len()),
                                        Some(png.to_vec()),
                                        None,
                                    ),
                                    None if is_nodelist(&pt) => (
                                        "[nodelist — see `peers`]".to_string(),
                                        None,
                                        Some(pt.clone()),
                                    ),
                                    None => (String::from_utf8_lossy(&pt).into_owned(), None, None),
                                };
                            opened = Some((
                                c.name.clone(),
                                epoch,
                                body,
                                nodelist,
                                picture,
                                n == 0 && chunk.is_some(),
                            ));
                        }
                    }
                }
            }
        }
        opened
    }
}

#[cfg(test)]
mod attempt_tests {
    use super::*;

    /// **RFC 2 §9's cache.** A pair shown not to open is not tried again.
    #[test]
    fn a_failed_pair_is_remembered_and_not_retried() {
        let mut a = Attempts::new();
        let id = [7u8; 32];
        assert!(!a.known_bad(&id, 42));
        a.remember_bad(id, 42);
        assert!(a.known_bad(&id, 42));

        // Keyed on the pair: the same object in a different epoch window is a
        // different question and must still be attempted.
        assert!(!a.known_bad(&id, 43));
    }

    /// **The cache is bounded**, or the flood that cost CPU costs memory.
    #[test]
    fn the_cache_stops_growing_and_stays_correct() {
        let mut a = Attempts::new();
        for i in 0..(MAX_REMEMBERED + 500) {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            a.remember_bad(id, 1);
        }
        assert_eq!(a.remembered(), MAX_REMEMBERED, "the cache is unbounded");

        // Everything it did keep, it still answers correctly for.
        let mut first = [0u8; 32];
        first[..8].copy_from_slice(&0u64.to_le_bytes());
        assert!(a.known_bad(&first, 1));
    }

    /// **RFC 2 §9's cap.** Attempts are refused past the budget, and the
    /// budget refills per scan rather than per process.
    #[test]
    fn attempts_are_capped_per_scan_and_refill() {
        let mut a = Attempts::new();
        for _ in 0..MAX_ATTEMPTS_PER_SCAN {
            assert!(a.charge());
        }
        assert!(!a.charge(), "the cap does not bind");
        assert!(!a.charge());

        a.refresh();
        assert!(a.charge(), "the budget did not refill");
    }

    /// A cleared cache forgets, because a new correspondent can change
    /// whether a pair opens.
    #[test]
    fn clearing_forgets_everything() {
        let mut a = Attempts::new();
        a.remember_bad([1u8; 32], 9);
        let _ = a.charge();
        a.clear();
        assert!(!a.known_bad(&[1u8; 32], 9));
        assert_eq!(a.remembered(), 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compose::{seal_to, Recipient};
    use krab_core::tag::EPOCH_WINDOW;
    use krab_crypto::rng::NotRandom;

    const NOW: Epoch = Epoch(20_671);
    const WINDOW: (u32, u32) = (0, u32::MAX);

    fn sk(seed: u64) -> SecretKey {
        SecretKey::generate(&mut NotRandom::seeded(seed))
    }

    fn correspondent(
        name: &str,
        ours: &SecretKey,
        theirs: &SecretKey,
        root: Option<[u8; 32]>,
    ) -> Correspondent {
        Correspondent {
            name: name.into(),
            correspondence: theirs.public(),
            shared: krab_crypto::agree(ours, &theirs.public()).unwrap(),
            reservoir: root.map(|r| Reservoir::new(r, NOW)),
        }
    }

    /// Compose from `from` to `to`, and put it in a store.
    fn send_into(
        store: &mut Store,
        from: &SecretKey,
        to: &SecretKey,
        root: Option<[u8; 32]>,
        text: &str,
        epoch: Epoch,
    ) -> ObjectId {
        let shared = krab_crypto::agree(from, &to.public()).unwrap();
        let tag = krab_crypto::pairwise_tag(&shared, epoch);
        let chunk = root.map(|r| Reservoir::new(r, epoch).chunk(epoch).unwrap());
        let composed = seal_to(
            from,
            &Recipient::Known {
                correspondence: &to.public(),
                tag,
                chunk: chunk.as_ref(),
            },
            epoch,
            0,
            (epoch.0 + 45) * 1440,
            text.as_bytes(),
            &mut NotRandom::seeded(epoch.0 as u64 + text.len() as u64),
        )
        .unwrap();
        let id = composed.id;
        store
            .ingest(id, composed.bytes, epoch.0 * 1440, u32::MAX)
            .unwrap();
        id
    }

    /// **The loop closes.** A message composed by one node is recognised and
    /// opened by the other, from the object alone.
    #[test]
    fn a_message_is_recognised_and_opened() {
        let (alice, bob) = (sk(1), sk(2));
        let root = [0x5A; 32];
        let mut store = Store::new();
        send_into(
            &mut store,
            &alice,
            &bob,
            Some(root),
            "meet me thursday",
            NOW,
        );

        let peers = [correspondent("alice", &bob, &alice, Some(root))];
        let table = TagTable::build(&peers, NOW);
        let scan = Inbox::scan(&store, &table, &peers, std::slice::from_ref(&bob), WINDOW);

        assert_eq!(scan.messages.len(), 1, "{} examined", scan.examined);
        assert_eq!(scan.messages[0].body, "meet me thursday");
        assert_eq!(scan.messages[0].from, "alice");
        assert!(scan.messages[0].post_quantum, "the reservoir was in play");
        assert_eq!(scan.tag_match_decrypt_fail, 0);
    }

    /// Mail for someone else is stored and relayed and reveals nothing — the
    /// node cannot even tell it is mail.
    #[test]
    fn mail_for_someone_else_is_invisible() {
        let (alice, bob, carol) = (sk(3), sk(4), sk(5));
        let mut store = Store::new();
        send_into(&mut store, &alice, &carol, None, "not for bob", NOW);

        let peers = [correspondent("alice", &bob, &alice, None)];
        let table = TagTable::build(&peers, NOW);
        let scan = Inbox::scan(&store, &table, &peers, std::slice::from_ref(&bob), WINDOW);

        assert_eq!(scan.messages.len(), 0);
        assert_eq!(scan.tag_match_decrypt_fail, 0, "no tag matched at all");
        assert_eq!(
            scan.examined, 1,
            "it was still examined, stored and relayed"
        );
    }

    /// **RFC 1 §6.2's window, and the failure it prevents.** An object at the
    /// far edge of MAX_TTL is still recognised; one outside is not, and the
    /// node is told nothing.
    #[test]
    fn the_window_covers_max_ttl_and_the_edge_beyond_it_is_silent() {
        let (alice, bob) = (sk(6), sk(7));
        let peers = [correspondent("alice", &bob, &alice, None)];
        let table = TagTable::build(&peers, NOW);

        // The far edge of the declared TTL.
        let mut inside = Store::new();
        send_into(
            &mut inside,
            &alice,
            &bob,
            None,
            "just in time",
            Epoch(NOW.0 - 45),
        );
        assert_eq!(
            Inbox::scan(&inside, &table, &peers, std::slice::from_ref(&bob), WINDOW)
                .messages
                .len(),
            1
        );

        // One epoch past the window: accepted by the store, never recognised.
        let mut outside = Store::new();
        let id = send_into(
            &mut outside,
            &alice,
            &bob,
            None,
            "too late",
            Epoch(NOW.0 - EPOCH_WINDOW - 1),
        );
        let scan = Inbox::scan(&outside, &table, &peers, std::slice::from_ref(&bob), WINDOW);
        assert_eq!(scan.messages.len(), 0, "never computed that tag");
        assert_eq!(
            scan.tag_match_decrypt_fail, 0,
            "not even a tag match — nothing surfaces"
        );
        assert!(outside.contains(&id), "and the object is stored regardless");
    }

    /// RFC 2 §4.3's table size.
    #[test]
    fn the_table_is_the_size_rfc2_says() {
        let bob = sk(8);
        let peers: Vec<Correspondent> = (0..50)
            .map(|i| correspondent(&format!("p{i}"), &bob, &sk(100 + i), None))
            .collect();
        let table = TagTable::build(&peers, NOW);
        assert_eq!(table.len(), 50 * (2 * EPOCH_WINDOW as usize + 1));
        assert_eq!(table.len(), 4_550, "RFC 2 §4.3");
    }

    /// A stale table loses the newest epoch, which would present as "mail from
    /// today is undecryptable". Detectable rather than silent.
    #[test]
    fn a_stale_table_is_detectable() {
        let (alice, bob) = (sk(9), sk(10));
        let peers = [correspondent("alice", &bob, &alice, None)];
        let yesterday = TagTable::build(&peers, Epoch(NOW.0 - 1));
        assert!(!yesterday.is_current(NOW));
        assert!(TagTable::build(&peers, NOW).is_current(NOW));
    }

    /// Several correspondents, several messages, sorted newest first.
    #[test]
    fn messages_from_several_correspondents_are_ordered_by_epoch() {
        let bob = sk(11);
        let (alice, carol) = (sk(12), sk(13));
        let mut store = Store::new();
        send_into(&mut store, &alice, &bob, None, "older", Epoch(NOW.0 - 3));
        send_into(&mut store, &carol, &bob, None, "newest", NOW);
        send_into(&mut store, &alice, &bob, None, "middle", Epoch(NOW.0 - 1));

        let peers = [
            correspondent("alice", &bob, &alice, None),
            correspondent("carol", &bob, &carol, None),
        ];
        let scan = Inbox::scan(
            &store,
            &TagTable::build(&peers, NOW),
            &peers,
            std::slice::from_ref(&bob),
            WINDOW,
        );
        let bodies: Vec<&str> = scan.messages.iter().map(|m| m.body.as_str()).collect();
        assert_eq!(bodies, vec!["newest", "middle", "older"]);
        assert_eq!(scan.messages[0].from, "carol");
    }

    /// A message sealed without a reservoir opens, and says it had none —
    /// RFC 7 §5 makes the reservoir a conditional tier.
    #[test]
    fn a_message_without_a_reservoir_opens_and_says_so() {
        let (alice, bob) = (sk(14), sk(15));
        let mut store = Store::new();
        send_into(&mut store, &alice, &bob, None, "no pad", NOW);

        // The recipient has a reservoir configured; the sender did not use it.
        let peers = [correspondent("alice", &bob, &alice, Some([1; 32]))];
        let scan = Inbox::scan(
            &store,
            &TagTable::build(&peers, NOW),
            &peers,
            std::slice::from_ref(&bob),
            WINDOW,
        );
        assert_eq!(scan.messages.len(), 1);
        assert!(!scan.messages[0].post_quantum, "and it says so");
    }

    /// **The AAD is load-bearing.** A relay editing the expiry to force
    /// indefinite storage produces something that will not open.
    #[test]
    fn tampering_with_the_header_makes_it_undecryptable() {
        let (alice, bob) = (sk(16), sk(17));
        let mut store = Store::new();
        send_into(&mut store, &alice, &bob, None, "original", NOW);

        let id = *store.ids_in_order().next().unwrap();
        let mut raw = store.get(&id).unwrap().to_vec();
        // Bump the expiry, in the header.
        raw[4] = raw[4].wrapping_add(1);
        let mut tampered = Store::new();
        // It is a different object now, so it enters under a different id.
        let new_id = krab_crypto::object_id(&raw);
        tampered
            .ingest(new_id, raw, NOW.0 * 1440, u32::MAX)
            .unwrap();

        let peers = [correspondent("alice", &bob, &alice, None)];
        let scan = Inbox::scan(
            &tampered,
            &TagTable::build(&peers, NOW),
            &peers,
            std::slice::from_ref(&bob),
            WINDOW,
        );
        assert_eq!(scan.messages.len(), 0);
        assert_eq!(
            scan.tag_match_decrypt_fail, 1,
            "the tag still matched; it did not open"
        );
    }

    /// **The epoch and suite are bound too**, which the header alone does not
    /// cover. This is what RFC 1 §6.1's AAD prefix is for.
    #[test]
    fn tampering_with_the_envelope_epoch_makes_it_undecryptable() {
        let (alice, bob) = (sk(18), sk(19));
        let mut store = Store::new();
        send_into(&mut store, &alice, &bob, None, "original", NOW);
        let id = *store.ids_in_order().next().unwrap();
        let raw = store.get(&id).unwrap().to_vec();

        // Find the envelope's epoch and change it. The header is 16 bytes; the
        // envelope follows, and key 0's value is the epoch.
        let (env, _) = decode_envelope(&raw[ROUTING_HEADER_LEN..]).unwrap();
        assert_eq!(env.epoch, NOW.0 as u64);

        // Rebuild with a different declared epoch, keeping everything else.
        let forged_body = krab_core::object::Envelope {
            epoch: env.epoch + 1,
            tag_mode: env.tag_mode,
            suite: env.suite,
            enc: env.enc,
            ciphertext: env.ciphertext,
        }
        .write();
        let header = RoutingHeader::parse(&raw).unwrap();
        let forged = krab_core::object::canonical_bytes(&header, &forged_body).unwrap();
        let mut store2 = Store::new();
        store2
            .ingest(
                krab_crypto::object_id(&forged),
                forged,
                NOW.0 * 1440,
                u32::MAX,
            )
            .unwrap();

        let peers = [correspondent("alice", &bob, &alice, None)];
        let scan = Inbox::scan(
            &store2,
            &TagTable::build(&peers, NOW),
            &peers,
            std::slice::from_ref(&bob),
            WINDOW,
        );
        assert_eq!(scan.messages.len(), 0, "a re-declared epoch must not open");
    }

    /// An empty corpus and an empty correspondent list are ordinary states.
    #[test]
    fn empty_inputs_are_not_errors() {
        let bob = sk(20);
        let table = TagTable::build(&[], NOW);
        assert!(table.is_empty());
        let scan = Inbox::scan(
            &Store::new(),
            &table,
            &[],
            std::slice::from_ref(&bob),
            WINDOW,
        );
        assert_eq!(scan.messages.len(), 0);
        assert_eq!(scan.examined, 0);
    }
}
