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
use hkdf::Hkdf;
use krab_core::tag::Epoch;
use sha2::Sha256;

/// Domain label for chunk derivation. **Not specified by RFC 7 §6** — see the
/// module documentation.
pub const LABEL_CHUNK: &[u8] = b"krab/chunk/v1";

/// A per-epoch chunk. Zeroized on drop.
pub type Chunk = Secret<32>;

/// The reservoir root, `R_A ⊕ R_B` (RFC 7 §6.2).
///
/// Held wrapped under the epoch key at rest; this is the in-memory form.
pub struct Reservoir {
    root: Secret<32>,
    /// The oldest epoch still derivable. Below this, chunks are shredded.
    floor: Epoch,
}

impl core::fmt::Debug for Reservoir {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The floor is operational metadata; the root is not.
        write!(f, "Reservoir(floor: {})", self.floor.0)
    }
}

impl Reservoir {
    /// Adopt a root established by RFC 3 §11's ceremony.
    ///
    /// `floor` is the first epoch this reservoir covers — chunks before it are
    /// never derivable, which is what makes shredding monotonic.
    pub fn new(root: [u8; 32], floor: Epoch) -> Reservoir {
        Reservoir {
            root: Secret::new(root),
            floor,
        }
    }

    /// `chunk_N` for `epoch`, or `None` if it has been shredded.
    ///
    /// Returning `None` rather than deriving anyway is the whole mechanism: the
    /// root still exists and the arithmetic would still work, so a caller that
    /// bypassed this would silently resurrect an epoch RFC 7 §4 promised was
    /// destroyed.
    pub fn chunk(&self, epoch: Epoch) -> Option<Chunk> {
        // Destruction is asked about directly rather than encoded as a
        // sentinel floor. A sentinel has a boundary, and a boundary in a
        // "can this still be derived" check is a bug that hands back a chunk
        // that was supposed to be gone.
        if self.root.is_destroyed() || epoch < self.floor {
            return None;
        }
        let hk = Hkdf::<Sha256>::from_prk(self.root.expose())
            .expect("32-byte root matches SHA-256 output length");
        let mut info = [0u8; 20];
        info[..LABEL_CHUNK.len()].copy_from_slice(LABEL_CHUNK);
        info[LABEL_CHUNK.len()..LABEL_CHUNK.len() + 4].copy_from_slice(&epoch.to_le_bytes());

        let mut out = [0u8; 32];
        hk.expand(&info[..LABEL_CHUNK.len() + 4], &mut out)
            .expect("32 bytes is far below 255·HashLen");
        let c = Secret::new(out);
        // `out` is a stack copy of a chunk.
        use zeroize::Zeroize;
        out.zeroize();
        Some(c)
    }

    /// Shred every chunk before `keep_from` — RFC 7 §4 and §6.
    ///
    /// Monotonic: the floor only rises. A caller cannot lower it to recover an
    /// epoch, because "erase" in this series means a thing becomes impossible,
    /// not merely unavailable.
    pub fn shred_before(&mut self, keep_from: Epoch) {
        if keep_from > self.floor {
            self.floor = keep_from;
        }
    }

    /// The oldest derivable epoch.
    pub fn floor(&self) -> Epoch {
        self.floor
    }

    /// Destroy the root. Every epoch becomes underivable at once.
    pub fn destroy(&mut self) {
        self.root.destroy();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    const NOW: Epoch = Epoch(20_671);

    fn reservoir() -> Reservoir {
        Reservoir::new([0x5A; 32], Epoch(NOW.0 - 45))
    }

    /// Both ends derive the same chunk from the same root — the property the
    /// whole scheme rests on, and the reason `R_A ⊕ R_B` must agree.
    #[test]
    fn the_same_root_yields_the_same_chunks() {
        let a = reservoir();
        let b = reservoir();
        for d in 0..5 {
            let e = Epoch(NOW.0 + d);
            assert_eq!(a.chunk(e).unwrap().expose(), b.chunk(e).unwrap().expose());
        }
    }

    /// Chunks are independent: compromising one exposes that epoch's traffic
    /// with that peer and nothing else (RFC 7 §6.1's stated tradeoff).
    #[test]
    fn every_epoch_gets_a_distinct_chunk() {
        let r = reservoir();
        let mut seen: Vec<[u8; 32]> = (0..40)
            .map(|d| *r.chunk(Epoch(NOW.0 + d)).unwrap().expose())
            .collect();
        let before = seen.len();
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
        let a = Reservoir::new([1; 32], Epoch(0));
        let b = Reservoir::new([2; 32], Epoch(0));
        assert_ne!(
            a.chunk(NOW).unwrap().expose(),
            b.chunk(NOW).unwrap().expose()
        );
    }

    /// **RFC 7 §4's promise.** A shredded epoch is not merely unavailable: it
    /// cannot be produced, even though the root is still right there.
    #[test]
    fn a_shredded_epoch_cannot_be_derived_though_the_root_remains() {
        let mut r = reservoir();
        let target = Epoch(NOW.0 - 45);
        assert!(r.chunk(target).is_some());

        r.shred_before(Epoch(NOW.0 - 44));
        assert!(r.chunk(target).is_none(), "gone");
        assert!(r.chunk(NOW).is_some(), "and only that epoch");
    }

    /// Shredding is monotonic — an epoch cannot be recovered by lowering the
    /// floor, because that would make "erase" mean "hide".
    #[test]
    fn the_floor_only_rises() {
        let mut r = reservoir();
        r.shred_before(Epoch(NOW.0));
        let high = r.floor();
        r.shred_before(Epoch(NOW.0 - 100));
        assert_eq!(r.floor(), high, "the floor did not drop");
        assert!(r.chunk(Epoch(NOW.0 - 1)).is_none());
    }

    /// Destroying the root ends every epoch, including the boundary ones an
    /// off-by-one would let through.
    #[test]
    fn destroying_the_root_ends_every_epoch_at_once() {
        let mut r = reservoir();
        assert!(r.chunk(NOW).is_some());
        r.destroy();
        for e in [
            Epoch(0),
            Epoch(NOW.0 - 45),
            NOW,
            Epoch(u32::MAX - 1),
            Epoch(u32::MAX),
        ] {
            assert!(r.chunk(e).is_none(), "epoch {} survived destruction", e.0);
        }
    }

    /// RFC 7 §6.1's figure: 45 epochs of retention is 45 chunks of 32 bytes.
    #[test]
    fn a_retention_window_costs_what_rfc7_says() {
        let n = 45usize;
        assert_eq!(n * 32, 1_440, "45 epochs at 32 bytes");
        // And a peer-year, §6.1's headline comparison.
        assert_eq!(365 * 32, 11_680, "under 12 KB for a peer-year");
    }

    #[test]
    fn a_reservoir_prints_no_secret() {
        let r = reservoir();
        let s = alloc::format!("{r:?}");
        assert!(s.starts_with("Reservoir(floor:"), "{s}");
        assert!(!s.contains("5a") && !s.contains("90"), "{s}");
    }
}
