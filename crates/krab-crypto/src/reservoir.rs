//! The epoch-chunked reservoir — RFC 7 §6.
//!
//! A shared secret between two peers, partitioned by epoch. At the close of
//! epoch `N` plus a grace window, `chunk_N` is destroyed and every message of
//! that epoch becomes permanently undecryptable — by anyone, including the
//! participants.
//!
//! # Size
//!
//! RFC 7 §6.1: a raw pad for one peer-year at 50 msg/day is 74.8 MB; the
//! reservoir is 11.7 KB. **6 400× smaller**, because keys are *derived* rather
//! than *consumed* — which also removes the consumption offset two parties
//! would otherwise have to keep in sync across a network that reorders,
//! duplicates and loses.
//!
//! # The chunk derivation is not in RFC 7
//!
//! §6 draws `reservoir → chunk_N (32 bytes, one per epoch)` and never says how.
//! Every other derivation in the series is written out; this one is an arrow.
//! Two implementations will not interoperate, and the failure is silent —
//! RFC 0 §6 makes delivery failure silent by design, so the symptom is "that
//! peer stopped being able to read my mail after we set up the reservoir".
//!
//! Implemented here as `HKDF-Expand(root, "krab/chunk/v1" ‖ u32_le(epoch), 32)`,
//! matching the shape of RFC 1 §6.2's tag derivation. **§6 must specify this
//! before RFC 7 leaves Draft.** Recorded in `Documentation/RFC-7-review.md` §11.
//!
//! # Why this is not the message key
//!
//! `CRYPTO-REVIEW.md` §1, the critical finding. RFC 7 §6 writes:
//!
//! ```text
//! msg_key = HKDF(chunk_N, "krab/msg/v1" ‖ tag)      ⚠ DEFECTIVE
//! ```
//!
//! `tag` is constant for a pair across an epoch (RFC 1 §6.2) and `chunk_N` is
//! constant by definition, so **every message a pair exchanges in a day gets
//! the same key**. Nothing per-message enters the derivation.
//!
//! This module therefore exposes chunks and no message-key function at all.
//! A chunk is consumed by [`crate::seal`] as an HPKE PSK under `mode_auth_psk`,
//! where the ephemeral `skE` makes the key schedule per-message while the PSK
//! carries the post-quantum property. There is deliberately no
//! `Reservoir::message_key`, because the safe construction and the defective
//! one differ by which function you call.

use crate::secret::Secret;
use alloc::collections::BTreeMap;
use hkdf::Hkdf;
use krab_core::tag::{Epoch, EPOCH_WINDOW};
use sha2::Sha256;

/// Domain label for chunk derivation. **Not specified by RFC 7 §6** — see the
/// module documentation.
pub const LABEL_CHUNK: &[u8] = b"krab/chunk/v1";

/// Domain label for the epoch ratchet.
///
/// **Also not specified by RFC 7 §6**, and its absence is worse than the
/// chunk label's — without a ratchet, §6's destruction claim is false. See
/// `CRYPTO-REVIEW.md` §11.
pub const LABEL_RATCHET: &[u8] = b"krab/ratchet/v1";

/// A per-epoch chunk. Zeroized on drop.
pub type Chunk = Secret<32>;

/// The reservoir: a **one-way ratchet** plus the chunks still inside the
/// retention window.
///
/// # Why this is a ratchet and not a root
///
/// RFC 7 §6 says that at the close of epoch N, `chunk_N` "is destroyed. Every
/// message of that epoch becomes permanently undecryptable — by anyone,
/// including the participants."
///
/// A static root cannot deliver that. `chunk_N = HKDF(reservoir, N)` is a pure
/// function, so anyone holding the reservoir recomputes any chunk they like in
/// microseconds. Destroying a chunk while retaining the value it derives from
/// destroys nothing.
///
/// The root also cannot simply be shredded with the epoch key, because epoch
/// N+1 needs it — so a naive implementation either keeps the root forever
/// (destruction is illusory) or loses the peering at the first shred.
///
/// A ratchet resolves both:
///
/// ```text
/// chunk_N  = HKDF(root_N, "krab/chunk/v1"   ‖ u32_le(N),   32)
/// root_N+1 = HKDF(root_N, "krab/ratchet/v1" ‖ u32_le(N+1), 32)
/// ```
///
/// `root_N` is destroyed once `root_N+1` exists. The peering survives, and
/// `chunk_N` becomes underivable — because inverting HKDF is the assumption
/// everything else here already rests on.
///
/// # Why chunks are retained rather than re-derived
///
/// RFC 1 §6.2's acceptance window is `MAX_TTL`, so an object may arrive up to
/// 45 epochs after the epoch its tag derives from. Those chunks must remain
/// available or the mail is stored and undecryptable — the silent failure
/// RFC 0 §6 guarantees nobody is told about.
///
/// So the retained window holds derived chunks, and the ratchet has already
/// passed them. 45 chunks at 32 bytes is 1 440 bytes, alongside RFC 7 §4.1's
/// 2 700 bytes of epoch wrappers.
pub struct Reservoir {
    /// `root_N` for the current epoch. Ratcheted forward, never rewound.
    root: Secret<32>,
    /// The epoch `root` corresponds to.
    epoch: Epoch,
    /// Derived chunks still inside the retention window.
    retained: BTreeMap<u32, Chunk>,
    /// The oldest epoch still retained.
    floor: Epoch,
}

impl core::fmt::Debug for Reservoir {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Operational metadata only.
        write!(
            f,
            "Reservoir(epoch: {}, floor: {}, retained: {})",
            self.epoch.0,
            self.floor.0,
            self.retained.len()
        )
    }
}

impl Reservoir {
    /// Adopt a root established by RFC 3 §11's ceremony, as of `epoch`.
    pub fn new(root: [u8; 32], epoch: Epoch) -> Reservoir {
        let mut r = Reservoir {
            root: Secret::new(root),
            epoch,
            retained: BTreeMap::new(),
            floor: epoch,
        };
        r.derive_current();
        r
    }

    fn derive_current(&mut self) {
        if self.root.is_destroyed() {
            return;
        }
        let c = expand(self.root.expose(), LABEL_CHUNK, self.epoch);
        self.retained.insert(self.epoch.0, c);
    }

    /// How far the ratchet will advance in one call.
    ///
    /// Beyond this, [`Reservoir::advance_to`] **refuses and changes nothing**.
    ///
    /// Twice the acceptance window: a node offline longer than `MAX_TTL` has
    /// already lost the mail it missed (RFC 1 §6.2), so advancing further
    /// serves nothing, and every value beyond it is more likely to be a wrong
    /// clock than a long absence.
    pub const MAX_ADVANCE: u32 = 2 * EPOCH_WINDOW;

    /// Advance to `to`, deriving each chunk on the way and destroying each
    /// intermediate root.
    ///
    /// Returns whether the ratchet moved. Idempotent, and **never rewinds**:
    /// asking to advance backwards is a no-op, because the alternative is a
    /// caller with a stale clock resurrecting a destroyed epoch.
    ///
    /// # Refusing an implausible jump is the point
    ///
    /// Advancing is **destructive and irreversible** — that is what makes the
    /// destruction claim in this module true. So it must not happen on
    /// unvalidated input, and a system clock is unvalidated input: an NTP
    /// correction, a restored VM snapshot, a dead CMOS battery or a typo can
    /// move it years.
    ///
    /// An earlier version capped the *iteration count* rather than refusing.
    /// A clock reading ten years ahead then ratcheted 1 460 epochs, destroyed
    /// every root on the way, and landed at neither the old epoch nor the
    /// requested one — while the peer stayed where it was. **The reservoir was
    /// permanently desynchronised for every correspondent by one bad clock
    /// reading, with no way back**, because the ratchet cannot rewind by
    /// design. A hardware fault became irreversible key loss.
    ///
    /// Refusing leaves the reservoir usable and makes the clock the operator's
    /// problem, which is where it belongs.
    #[must_use]
    pub fn advance_to(&mut self, to: Epoch) -> bool {
        if self.root.is_destroyed() || to <= self.epoch {
            return false;
        }
        if to.0 - self.epoch.0 > Self::MAX_ADVANCE {
            // Nothing is touched. The caller has a clock problem, not a
            // reservoir problem, and destroying key material would not fix it.
            return false;
        }
        let steps = to.0 - self.epoch.0;
        for _ in 0..steps {
            let next = Epoch(self.epoch.0 + 1);
            let new_root = expand32(self.root.expose(), LABEL_RATCHET, next);
            // The old root dies here. This line is the destruction claim.
            self.root.destroy();
            self.root = Secret::new(new_root);
            self.epoch = next;
            self.derive_current();
        }
        // Trim to RFC 1 §6.2's acceptance window automatically.
        //
        // Not left to the caller: a node resuming after a long gap ratchets
        // hundreds of steps, and a caller who forgot to trim would retain every
        // chunk it passed — turning a bounded window into an unbounded archive
        // of exactly the material §6 promises to destroy. Retaining more than
        // the window is never useful anyway, since an object older than it is
        // unrecognisable (RFC 1 §6.2).
        let floor = Epoch(self.epoch.0.saturating_sub(EPOCH_WINDOW));
        if floor > self.floor {
            self.floor = floor;
        }
        self.retained.retain(|&e, _| e >= self.floor.0);
        true
    }

    /// `chunk_N` for `epoch`, or `None` if it is outside the retained window.
    ///
    /// Returns `None` for a **future** epoch too: the chunk is derivable only
    /// after the ratchet reaches it, and a caller asking early would otherwise
    /// get a value that depends on a root it should not still hold.
    pub fn chunk(&self, epoch: Epoch) -> Option<Chunk> {
        self.retained
            .get(&epoch.0)
            .map(|c| Secret::new(*c.expose()))
    }

    /// Shred every chunk before `keep_from` — RFC 7 §4 and §6.
    ///
    /// Monotone, and now genuinely destructive: the chunk is dropped and the
    /// root it derived from is already gone, so nothing recomputes it.
    pub fn shred_before(&mut self, keep_from: Epoch) {
        if keep_from > self.floor {
            self.floor = keep_from;
        }
        self.retained.retain(|&e, _| e >= self.floor.0);
    }

    /// The oldest derivable epoch.
    pub fn floor(&self) -> Epoch {
        self.floor
    }

    /// The epoch the ratchet has reached.
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Chunks currently retained. RFC 1 §6.2's window is 45 either side.
    pub fn retained(&self) -> usize {
        self.retained.len()
    }

    /// The current root, for wrapping at rest.
    ///
    /// This is `root_N`, not the value the ceremony produced — that one no
    /// longer exists once the ratchet has moved. Storing it is what carries a
    /// peering across a restart.
    pub fn root_bytes(&self) -> Option<[u8; 32]> {
        if self.root.is_destroyed() {
            return None;
        }
        Some(*self.root.expose())
    }

    /// Adopt a re-keyed root, effective from `at`.
    ///
    /// See [`crate::rekey`]. The old root is destroyed here; the new one is
    /// **not** derivable from it, which is the entire point — that is what
    /// heals a compromise a pure ratchet cannot.
    ///
    /// # Retained chunks survive
    ///
    /// Chunks for epochs before `at` were derived from the old chain and stay
    /// exactly as they were. Mail already in flight was tagged with them, and
    /// RFC 1 §6.2 gives it up to `MAX_TTL` to arrive — dropping them here
    /// would silently strand every object in transit at the moment of a
    /// re-key, which is the failure RFC 0 §6 guarantees nobody is told about.
    ///
    /// # Refusing to go backwards
    ///
    /// `at` must be at or after the epoch the ratchet has reached. A re-key
    /// landing in the past would make a chunk derivable twice from two
    /// different chains, and the two ends would disagree about which.
    #[must_use]
    pub fn rekey(&mut self, new_root: [u8; 32], at: Epoch) -> bool {
        if at < self.epoch {
            return false;
        }
        self.root = Secret::new(new_root);
        self.epoch = at;
        // The chunk for `at` now comes from the new chain. Both ends derive it
        // the same way because both adopt the same root at the same epoch.
        self.derive_current();
        true
    }

    /// Destroy the root and every retained chunk. Every epoch, at once.
    pub fn destroy(&mut self) {
        self.root.destroy();
        for (_, c) in self.retained.iter_mut() {
            c.destroy();
        }
        self.retained.clear();
    }
}

fn expand(prk: &[u8; 32], label: &[u8], epoch: Epoch) -> Chunk {
    Secret::new(expand32(prk, label, epoch))
}

fn expand32(prk: &[u8; 32], label: &[u8], epoch: Epoch) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("32-byte PRK matches SHA-256 output length");
    let mut info = [0u8; 24];
    let n = label.len();
    info[..n].copy_from_slice(label);
    info[n..n + 4].copy_from_slice(&epoch.to_le_bytes());

    let mut out = [0u8; 32];
    hk.expand(&info[..n + 4], &mut out)
        .expect("32 bytes is far below 255·HashLen");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    const NOW: Epoch = Epoch(20_671);

    fn reservoir() -> Reservoir {
        let mut r = Reservoir::new([0x5A; 32], Epoch(NOW.0 - 45));
        let _ = r.advance_to(NOW);
        r
    }

    /// Both ends derive the same chunks from the same root, having ratcheted
    /// the same distance.
    #[test]
    fn the_same_root_and_the_same_ratchet_yield_the_same_chunks() {
        let a = reservoir();
        let b = reservoir();
        for d in 0..40u32 {
            let e = Epoch(NOW.0 - d);
            assert_eq!(
                a.chunk(e).map(|c| *c.expose()),
                b.chunk(e).map(|c| *c.expose()),
                "epoch {}",
                e.0
            );
        }
    }

    #[test]
    fn every_epoch_gets_a_distinct_chunk() {
        let r = reservoir();
        let mut seen: Vec<[u8; 32]> = (0..40u32)
            .filter_map(|d| r.chunk(Epoch(NOW.0 - d)).map(|c| *c.expose()))
            .collect();
        let before = seen.len();
        assert!(before > 30, "only {before} chunks retained");
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(
            seen.len(),
            before,
            "a repeated chunk would reuse keys across days"
        );
    }

    #[test]
    fn different_roots_share_no_chunks() {
        let mut a = Reservoir::new([1; 32], NOW);
        let mut b = Reservoir::new([2; 32], NOW);
        assert!(
            a.advance_to(Epoch(NOW.0 + 1)),
            "the advance must be within MAX_ADVANCE"
        );
        assert!(
            b.advance_to(Epoch(NOW.0 + 1)),
            "the advance must be within MAX_ADVANCE"
        );
        assert_ne!(
            a.chunk(NOW).map(|c| *c.expose()),
            b.chunk(NOW).map(|c| *c.expose())
        );
    }

    /// **The finding this rewrite exists for.** Under a static root, a shredded
    /// chunk was recomputable in microseconds from the value it derived from,
    /// so RFC 7 §6's "permanently undecryptable — by anyone, including the
    /// participants" was false. Under a ratchet it is true.
    #[test]
    fn a_shredded_chunk_cannot_be_recomputed_from_what_remains() {
        let mut r = reservoir();
        let target = Epoch(NOW.0 - 40);
        assert!(r.chunk(target).is_some());
        let before = *r.chunk(target).unwrap().expose();

        r.shred_before(Epoch(NOW.0 - 39));
        assert!(r.chunk(target).is_none(), "gone from the window");

        // And the root cannot regenerate it: the root has ratcheted past that
        // epoch, and the intermediate roots were destroyed on the way.
        let root = r.root_bytes().expect("the peering survives");
        let mut fresh = Reservoir::new(root, r.epoch());
        assert!(
            fresh.advance_to(Epoch(NOW.0 + 10)),
            "the advance must be within MAX_ADVANCE"
        );
        assert!(
            fresh.chunk(target).is_none(),
            "the current root regenerated a destroyed chunk"
        );
        // Nor does deriving directly from the current root reproduce it.
        assert_ne!(*expand(&root, LABEL_CHUNK, target).expose(), before);
    }

    /// **The peering survives the destruction**, which is the half a naive
    /// implementation gets wrong in the other direction: shredding the root
    /// with the epoch key would lose the correspondent entirely.
    #[test]
    fn the_peering_survives_across_epochs_and_a_restart() {
        let mut r = reservoir();
        let root = r.root_bytes().unwrap();
        let epoch = r.epoch();

        // A restart: only the wrapped root survived.
        let mut restored = Reservoir::new(root, epoch);
        assert!(
            restored.advance_to(Epoch(epoch.0 + 3)),
            "the advance must be within MAX_ADVANCE"
        );
        assert!(
            r.advance_to(Epoch(epoch.0 + 3)),
            "the advance must be within MAX_ADVANCE"
        );

        for d in 0..3u32 {
            let e = Epoch(epoch.0 + d);
            assert_eq!(
                r.chunk(e).map(|c| *c.expose()),
                restored.chunk(e).map(|c| *c.expose()),
                "epoch {} diverged across a restart",
                e.0
            );
        }
    }

    /// The ratchet never rewinds. A caller with a stale clock must not
    /// resurrect a destroyed epoch.
    #[test]
    fn the_ratchet_does_not_rewind() {
        let mut r = reservoir();
        let at = r.epoch();
        assert!(!r.advance_to(Epoch(at.0 - 10)), "backwards must be refused");
        assert_eq!(r.epoch(), at, "advancing backwards moved the ratchet");
        assert!(
            !r.advance_to(at),
            "advancing to the current epoch is a no-op"
        );
        assert_eq!(r.epoch(), at);
    }

    /// A future chunk is not derivable before the ratchet reaches it.
    #[test]
    fn a_future_chunk_is_not_available_early() {
        let r = reservoir();
        assert!(r.chunk(Epoch(NOW.0 + 1)).is_none());
        assert!(r.chunk(NOW).is_some());
    }

    /// RFC 1 §6.2's acceptance window: an object may arrive up to MAX_TTL after
    /// its epoch, so those chunks must still be there or the mail is stored and
    /// undecryptable, silently.
    #[test]
    fn the_retention_window_covers_max_ttl() {
        let mut r = Reservoir::new([7; 32], Epoch(NOW.0 - 45));
        let _ = r.advance_to(NOW);
        assert!(
            r.chunk(Epoch(NOW.0 - 45)).is_some(),
            "the far edge of MAX_TTL"
        );
        assert_eq!(r.retained(), 46, "45 epochs back plus today");
        assert_eq!(46 * 32, 1_472, "under 1.5 KB of chunks");
    }

    /// A gap inside the permitted advance stays bounded in memory: the ratchet
    /// passes every epoch and retains only RFC 1 §6.2's window.
    #[test]
    fn a_long_gap_does_not_accumulate_chunks() {
        let mut r = Reservoir::new([3; 32], Epoch(20_000));
        assert!(r.advance_to(Epoch(20_000 + Reservoir::MAX_ADVANCE)));
        assert_eq!(r.epoch(), Epoch(20_000 + Reservoir::MAX_ADVANCE));
        assert_eq!(
            r.retained(),
            EPOCH_WINDOW as usize + 1,
            "the window must stay bounded across a long gap"
        );
        assert!(r.chunk(r.epoch()).is_some(), "today");
        assert!(
            r.chunk(Epoch(r.epoch().0 - EPOCH_WINDOW)).is_some(),
            "the far edge of MAX_TTL"
        );
        assert!(r.chunk(Epoch(20_000)).is_none(), "long past the window");
    }

    /// Two nodes that were apart for different lengths of time still agree,
    /// because the ratchet is deterministic in the epoch and not in the path.
    #[test]
    fn nodes_that_resume_from_different_gaps_still_agree() {
        let mut steady = Reservoir::new([9; 32], Epoch(20_000));
        for e in 20_001..=20_050 {
            assert!(
                steady.advance_to(Epoch(e)),
                "the advance must be within MAX_ADVANCE"
            );
        }
        let mut returning = Reservoir::new([9; 32], Epoch(20_000));
        assert!(
            returning.advance_to(Epoch(20_050)),
            "the advance must be within MAX_ADVANCE"
        );

        assert_eq!(steady.epoch(), returning.epoch());
        assert_eq!(steady.root_bytes(), returning.root_bytes());
        for d in 0..40u32 {
            let e = Epoch(20_050 - d);
            assert_eq!(
                steady.chunk(e).map(|c| *c.expose()),
                returning.chunk(e).map(|c| *c.expose()),
                "epoch {} diverged",
                e.0
            );
        }
    }

    #[test]
    fn shredding_is_monotone() {
        let mut r = reservoir();
        r.shred_before(NOW);
        let high = r.floor();
        r.shred_before(Epoch(NOW.0 - 100));
        assert_eq!(r.floor(), high, "the floor fell");
        assert!(r.chunk(Epoch(NOW.0 - 1)).is_none());
    }

    #[test]
    fn destroying_ends_every_epoch_at_once() {
        let mut r = reservoir();
        assert!(r.chunk(NOW).is_some());
        r.destroy();
        assert!(r.root_bytes().is_none());
        for d in 0..46u32 {
            assert!(
                r.chunk(Epoch(NOW.0 - d)).is_none(),
                "epoch {} survived",
                NOW.0 - d
            );
        }
    }

    /// RFC 7 §6.1's figures.
    #[test]
    fn a_peer_year_costs_what_rfc7_says() {
        assert_eq!(365 * 32, 11_680, "under 12 KB for a peer-year");
        assert_eq!(45 * 32, 1_440, "a 45-epoch window");
    }

    #[test]
    fn a_reservoir_prints_no_secret() {
        let r = reservoir();
        let s = alloc::format!("{r:?}");
        assert!(s.starts_with("Reservoir(epoch:"), "{s}");
        assert!(!s.contains("5a") && !s.contains("90"), "{s}");
    }

    /// **A re-key must not strand mail already in flight.** Chunks derived
    /// from the old chain stay derivable, because RFC 1 §6.2 gives an object
    /// up to `MAX_TTL` to arrive and it was tagged before the re-key.
    #[test]
    fn a_rekey_keeps_the_chunks_mail_in_flight_was_tagged_with() {
        let mut r = Reservoir::new([1u8; 32], Epoch(100));
        assert!(r.advance_to(Epoch(110)));
        let old = r.chunk(Epoch(105)).expect("inside the window");

        assert!(r.rekey([9u8; 32], Epoch(110)));
        assert_eq!(
            r.chunk(Epoch(105)).map(|c| *c.expose()),
            Some(*old.expose()),
            "an object tagged before the re-key can no longer be opened"
        );
    }

    /// The new root is not derivable from the old one. This is the healing
    /// property, and it is the reason a re-key is not just a ratchet step.
    #[test]
    fn a_rekeyed_root_is_unrelated_to_the_one_it_replaced() {
        let mut a = Reservoir::new([1u8; 32], Epoch(100));
        let mut b = Reservoir::new([1u8; 32], Epoch(100));
        assert!(a.rekey([9u8; 32], Epoch(100)));
        // `b` ratchets instead. An adversary holding the old root gets this.
        assert!(b.advance_to(Epoch(101)));
        assert_ne!(a.root_bytes(), b.root_bytes());
        assert_ne!(
            a.chunk(Epoch(100)).map(|c| *c.expose()),
            b.chunk(Epoch(100)).map(|c| *c.expose()),
            "the re-keyed chunk is still derivable from the old chain"
        );
    }

    /// A re-key landing in the past would make one epoch derivable from two
    /// chains, and the two ends would disagree about which.
    #[test]
    fn a_rekey_cannot_go_backwards() {
        let mut r = Reservoir::new([1u8; 32], Epoch(100));
        assert!(r.advance_to(Epoch(110)));
        assert!(!r.rekey([9u8; 32], Epoch(109)), "it went backwards");
        assert_eq!(r.epoch(), Epoch(110), "and it changed something anyway");
    }

    /// Both ends adopting the same root at the same epoch derive the same
    /// chunks from then on. Without this the peering is silently dead.
    #[test]
    fn both_ends_agree_after_a_rekey() {
        let mut a = Reservoir::new([1u8; 32], Epoch(100));
        let mut b = Reservoir::new([1u8; 32], Epoch(100));
        assert!(a.advance_to(Epoch(105)));
        assert!(b.advance_to(Epoch(105)));

        let new = crate::rekey::next_root(
            &a.root_bytes().unwrap(),
            &[7u8; 32],
            (&[1u8; 32], &Secret::new([0xaa; 32])),
            (&[2u8; 32], &Secret::new([0xbb; 32])),
            105,
        );
        assert!(a.rekey(new, Epoch(105)));
        assert!(b.rekey(new, Epoch(105)));

        for e in 105..=110 {
            assert!(a.advance_to(Epoch(e)) || e == 105);
            assert!(b.advance_to(Epoch(e)) || e == 105);
            assert_eq!(
                a.chunk(Epoch(e)).map(|c| *c.expose()),
                b.chunk(Epoch(e)).map(|c| *c.expose()),
                "the two ends diverged at epoch {e}"
            );
        }
    }

    /// **The 90-day death.** `MAX_ADVANCE` refuses a longer gap, correctly —
    /// but that leaves the peering dead. A re-key re-seats both ends, which is
    /// what makes a returning node recoverable instead of lost.
    #[test]
    fn a_rekey_revives_a_peering_that_advance_refuses_to_close() {
        let mut r = Reservoir::new([1u8; 32], Epoch(100));
        let far = Epoch(100 + Reservoir::MAX_ADVANCE + 1);
        assert!(!r.advance_to(far), "the gap must be refused");
        assert_eq!(r.epoch(), Epoch(100), "and nothing touched");

        // The peering is not lost: a re-key seats it at the current epoch.
        assert!(r.rekey([9u8; 32], far));
        assert_eq!(r.epoch(), far);
        assert!(r.chunk(far).is_some(), "and it works again");
    }
}
