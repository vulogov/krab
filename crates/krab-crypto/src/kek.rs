//! Crypto-shredding — RFC 7 §4.
//!
//! ```text
//! passphrase ──Argon2id──▶ KEK          memory only, never written
//!                           │ wraps
//!                     epoch wrapper key W_N     one per epoch, on disk, wrapped
//!                           │ wraps
//!         prekey privates · reservoir chunks · session state · message store
//! ```
//!
//! # Erasure means destroying a key, never deleting a file
//!
//! RFC 7 §4 is emphatic and worth restating at the implementation: **"where a
//! specification in this series says *erase*, it means destroy the wrapping
//! key."**
//!
//! Overwriting a file does not erase it. A flash translation layer may have
//! written the block anywhere, copied it during wear levelling, or retained it
//! in an over-provisioned region the filesystem cannot address. None of that is
//! visible from userspace, and no `fsync` changes it. Destroying `W_N` — a
//! 32-byte overwrite of an in-memory value plus removal of one 60-byte record —
//! makes every object beneath it undecryptable regardless of what the
//! controller did.
//!
//! So [`Hierarchy::shred_epoch`] is the only erasure primitive here, and there
//! is deliberately no function that deletes or overwrites stored data.
//!
//! # Parameters, and why they are stored
//!
//! RFC 7 §4.1 fixes Argon2id at m = 64 MiB, t = 3, p = 4, with a 16-byte random
//! salt. Implementations SHOULD calibrate to ~500 ms and **MUST store the
//! parameters alongside the salt** — otherwise raising the cost later locks
//! every existing store out permanently, since the KEK is the only root and
//! RFC 7 §11 makes message history explicitly unrecoverable.
//!
//! [`KekParams`] is therefore a stored record, not a constant.

use crate::rng::Rng;
use crate::secret::Key;
use alloc::vec::Vec;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use core::fmt;
use krab_core::tag::Epoch;
use zeroize::Zeroize;

/// RFC 7 §4.1 — memory cost, 64 MiB expressed in KiB.
pub const ARGON2_M_KIB: u32 = 65_536;
/// RFC 7 §4.1 — time cost.
pub const ARGON2_T: u32 = 3;
/// RFC 7 §4.1 — parallelism.
pub const ARGON2_P: u32 = 4;
/// RFC 7 §4.1 — salt length.
pub const SALT_LEN: usize = 16;
/// RFC 7 §4.1 — one wrapped record: 32 key + 16 tag + 12 nonce.
pub const WRAPPED_LEN: usize = 60;

/// The parameters a store was created with.
///
/// Stored beside the salt so that a future increase does not lock out an
/// existing store. A node reads these, not the constants above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KekParams {
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Time cost.
    pub t: u32,
    /// Parallelism.
    pub p: u32,
    /// Random, per-store.
    pub salt: [u8; SALT_LEN],
}

impl KekParams {
    /// Fresh parameters at RFC 7 §4.1's defaults, with a random salt.
    pub fn new(rng: &mut impl Rng) -> KekParams {
        let mut salt = [0u8; SALT_LEN];
        rng.fill(&mut salt);
        KekParams {
            m_kib: ARGON2_M_KIB,
            t: ARGON2_T,
            p: ARGON2_P,
            salt,
        }
    }
}

/// Why a KEK operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The stored parameters are not a valid Argon2id configuration.
    BadParams,
    /// Argon2id could not run — almost always insufficient memory for `m`.
    Kdf,
    /// Authentication failed: wrong passphrase, wrong epoch, or tampering.
    ///
    /// These are deliberately one variant. Distinguishing them would tell an
    /// attacker holding a seized disk which of their guesses was structurally
    /// closer, and the operator's remedy is identical in every case.
    Unwrap,
    /// A wrapped record was not [`WRAPPED_LEN`] bytes.
    Malformed,
}

/// The key-encryption key. Memory only; never written anywhere.
pub struct Kek(Key);

impl fmt::Debug for Kek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Kek(<redacted>)")
    }
}

impl Kek {
    /// Derive from a passphrase, RFC 7 §4.1.
    ///
    /// Costs `m_kib` of memory and roughly 500 ms at the specified parameters.
    /// That is the point: it is the only thing standing between a seized disk
    /// and everything on it.
    pub fn derive(passphrase: &[u8], params: &KekParams) -> Result<Kek, Error> {
        let p = Params::new(params.m_kib, params.t, params.p, Some(32))
            .map_err(|_| Error::BadParams)?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
        let mut out = [0u8; 32];
        argon
            .hash_password_into(passphrase, &params.salt, &mut out)
            .map_err(|_| Error::Kdf)?;
        let k = Key::new(out);
        out.zeroize();
        Ok(Kek(k))
    }

    /// Wrap an epoch key. The epoch is bound as AAD, so a wrapper lifted from
    /// one epoch's record cannot be replayed into another's.
    fn wrap(&self, epoch: Epoch, key: &[u8; 32], rng: &mut impl Rng) -> Result<Vec<u8>, Error> {
        let cipher = ChaCha20Poly1305::new(self.0.expose().into());
        let mut nonce = [0u8; 12];
        rng.fill(&mut nonce);
        let ct = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: key,
                    aad: &epoch.to_le_bytes(),
                },
            )
            .map_err(|_| Error::Unwrap)?;
        let mut out = Vec::with_capacity(WRAPPED_LEN);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Unwrap an epoch key.
    fn unwrap(&self, epoch: Epoch, record: &[u8]) -> Result<[u8; 32], Error> {
        if record.len() != WRAPPED_LEN {
            return Err(Error::Malformed);
        }
        let cipher = ChaCha20Poly1305::new(self.0.expose().into());
        let pt = cipher
            .decrypt(
                record[..12].try_into().map_err(|_| Error::Malformed)?,
                Payload {
                    msg: &record[12..],
                    aad: &epoch.to_le_bytes(),
                },
            )
            .map_err(|_| Error::Unwrap)?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&pt);
        Ok(key)
    }
}

/// Wrap a secret under an epoch key `W_N` — RFC 7 §4's third tier.
///
/// This is what "prekey privates · reservoir chunks · session state · message
/// store" means concretely: everything beneath `W_N` is sealed with it, so
/// destroying `W_N` destroys all of it at once regardless of what the storage
/// controller retained.
///
/// `context` is bound as AAD. Callers pass something that identifies what is
/// being wrapped, so a record cannot be lifted from one slot into another.
pub fn seal_under(
    epoch_key: &[u8; 32],
    context: &[u8],
    secret: &[u8],
    rng: &mut impl Rng,
) -> Result<Vec<u8>, Error> {
    let cipher = ChaCha20Poly1305::new(epoch_key.into());
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce);
    let ct = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: secret,
                aad: context,
            },
        )
        .map_err(|_| Error::Unwrap)?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unwrap what [`seal_under`] produced.
pub fn open_under(epoch_key: &[u8; 32], context: &[u8], record: &[u8]) -> Result<Vec<u8>, Error> {
    if record.len() < 12 + 16 {
        return Err(Error::Malformed);
    }
    let cipher = ChaCha20Poly1305::new(epoch_key.into());
    cipher
        .decrypt(
            record[..12].try_into().map_err(|_| Error::Malformed)?,
            Payload {
                msg: &record[12..],
                aad: context,
            },
        )
        .map_err(|_| Error::Unwrap)
}

/// The epoch wrapper hierarchy: `W_N` for each retained epoch, wrapped under
/// the KEK and stored.
///
/// Forty-five epochs of wrappers is 2 700 bytes (RFC 7 §4.1).
#[derive(Default)]
pub struct Hierarchy {
    records: Vec<(Epoch, Vec<u8>)>,
}

impl fmt::Debug for Hierarchy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Counts and epochs only — never a record.
        write!(f, "Hierarchy({} epochs)", self.records.len())
    }
}

impl Hierarchy {
    /// An empty hierarchy.
    pub fn new() -> Hierarchy {
        Hierarchy {
            records: Vec::new(),
        }
    }

    /// Create and store `W_N` for `epoch`, returning it for immediate use.
    ///
    /// Idempotent: an epoch that already has a wrapper keeps it, so calling
    /// this twice cannot silently orphan everything wrapped under the first.
    pub fn open_epoch(
        &mut self,
        kek: &Kek,
        epoch: Epoch,
        rng: &mut impl Rng,
    ) -> Result<[u8; 32], Error> {
        if let Ok(existing) = self.epoch_key(kek, epoch) {
            return Ok(existing);
        }
        let w = rng.next_32();
        let record = kek.wrap(epoch, &w, rng)?;
        self.records.push((epoch, record));
        Ok(w)
    }

    /// Recover `W_N`.
    pub fn epoch_key(&self, kek: &Kek, epoch: Epoch) -> Result<[u8; 32], Error> {
        let (_, record) = self
            .records
            .iter()
            .find(|(e, _)| *e == epoch)
            .ok_or(Error::Unwrap)?;
        kek.unwrap(epoch, record)
    }

    /// **Erase an epoch**, RFC 7 §4.
    ///
    /// Overwrites the wrapper record and drops it. Everything wrapped under
    /// `W_N` becomes permanently undecryptable — by anyone, including the
    /// participants — no matter what the storage controller retained.
    ///
    /// Returns whether an epoch was present, so a caller can distinguish
    /// "shredded" from "already gone" without a second lookup.
    pub fn shred_epoch(&mut self, epoch: Epoch) -> bool {
        let Some(i) = self.records.iter().position(|(e, _)| *e == epoch) else {
            return false;
        };
        let (_, mut record) = self.records.remove(i);
        record.zeroize();
        true
    }

    /// Shred every epoch older than `keep_from`. RFC 7 §4's retention sweep.
    pub fn shred_before(&mut self, keep_from: Epoch) -> usize {
        let doomed: Vec<Epoch> = self
            .records
            .iter()
            .filter(|(e, _)| *e < keep_from)
            .map(|(e, _)| *e)
            .collect();
        doomed.iter().filter(|e| self.shred_epoch(**e)).count()
    }

    /// Epochs currently recoverable.
    pub fn epochs(&self) -> impl Iterator<Item = Epoch> + '_ {
        self.records.iter().map(|(e, _)| *e)
    }

    /// Total stored size. 45 epochs is 2 700 bytes per RFC 7 §4.1.
    pub fn stored_bytes(&self) -> usize {
        self.records.iter().map(|(_, r)| r.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::NotRandom;

    /// Argon2id at 64 MiB is slow on purpose, so tests use a cheap
    /// configuration. The real parameters are exercised once, below.
    fn cheap(rng: &mut impl Rng) -> KekParams {
        KekParams {
            m_kib: 64,
            t: 1,
            p: 1,
            ..KekParams::new(rng)
        }
    }

    fn setup() -> (Kek, KekParams, NotRandom) {
        let mut rng = NotRandom::seeded(1);
        let params = cheap(&mut rng);
        (
            Kek::derive(b"correct horse battery staple", &params).unwrap(),
            params,
            rng,
        )
    }

    #[test]
    fn the_kek_is_deterministic_in_passphrase_and_salt() {
        let (kek, params, mut rng) = setup();
        let again = Kek::derive(b"correct horse battery staple", &params).unwrap();
        let mut h = Hierarchy::new();
        let w = h.open_epoch(&kek, Epoch(20_671), &mut rng).unwrap();
        assert_eq!(h.epoch_key(&again, Epoch(20_671)).unwrap(), w);
    }

    #[test]
    fn a_wrong_passphrase_does_not_unwrap() {
        let (kek, params, mut rng) = setup();
        let mut h = Hierarchy::new();
        h.open_epoch(&kek, Epoch(20_671), &mut rng).unwrap();
        let wrong = Kek::derive(b"correct horse battery stapl", &params).unwrap();
        assert_eq!(h.epoch_key(&wrong, Epoch(20_671)), Err(Error::Unwrap));
    }

    /// A different salt gives a different KEK from the same passphrase, so two
    /// stores never share a root.
    #[test]
    fn the_salt_separates_stores() {
        let mut rng = NotRandom::seeded(2);
        let p1 = cheap(&mut rng);
        let mut p2 = p1;
        p2.salt[0] ^= 1;
        let k1 = Kek::derive(b"pass", &p1).unwrap();
        let k2 = Kek::derive(b"pass", &p2).unwrap();
        let mut h = Hierarchy::new();
        h.open_epoch(&k1, Epoch(1), &mut rng).unwrap();
        assert_eq!(h.epoch_key(&k2, Epoch(1)), Err(Error::Unwrap));
    }

    /// **RFC 7 §4's whole point.** Destroying `W_N` makes that epoch
    /// unrecoverable even with the correct passphrase — the disk is irrelevant.
    #[test]
    fn shredding_an_epoch_is_irreversible_even_with_the_passphrase() {
        let (kek, _, mut rng) = setup();
        let mut h = Hierarchy::new();
        let target = Epoch(20_671);
        h.open_epoch(&kek, target, &mut rng).unwrap();
        h.open_epoch(&kek, Epoch(20_672), &mut rng).unwrap();

        assert!(h.epoch_key(&kek, target).is_ok());
        assert!(h.shred_epoch(target));
        assert_eq!(
            h.epoch_key(&kek, target),
            Err(Error::Unwrap),
            "gone for good"
        );
        // And only that epoch.
        assert!(h.epoch_key(&kek, Epoch(20_672)).is_ok());
        assert!(!h.shred_epoch(target), "already gone");
    }

    /// Epochs are independent: one shredded epoch does not disturb the rest,
    /// which is what makes §4 a *retention* mechanism rather than a kill switch.
    #[test]
    fn the_retention_sweep_keeps_the_window_and_drops_the_rest() {
        let (kek, _, mut rng) = setup();
        let mut h = Hierarchy::new();
        for d in 0..50 {
            h.open_epoch(&kek, Epoch(20_600 + d), &mut rng).unwrap();
        }
        let dropped = h.shred_before(Epoch(20_605));
        assert_eq!(dropped, 5);
        assert_eq!(h.epochs().count(), 45);
        assert!(h.epoch_key(&kek, Epoch(20_604)).is_err());
        assert!(h.epoch_key(&kek, Epoch(20_605)).is_ok());
    }

    /// RFC 7 §4.1 — 60 bytes per record, 2 700 for a 45-epoch window.
    #[test]
    fn a_wrapped_record_is_sixty_bytes() {
        let (kek, _, mut rng) = setup();
        let mut h = Hierarchy::new();
        for d in 0..45 {
            h.open_epoch(&kek, Epoch(20_600 + d), &mut rng).unwrap();
        }
        assert_eq!(h.stored_bytes(), 45 * WRAPPED_LEN);
        assert_eq!(h.stored_bytes(), 2_700, "RFC 7 §4.1");
    }

    /// The epoch is AAD, so a record cannot be lifted into another epoch's
    /// slot to resurrect a shredded one.
    #[test]
    fn a_wrapper_cannot_be_replayed_into_another_epoch() {
        let (kek, _, mut rng) = setup();
        let mut h = Hierarchy::new();
        h.open_epoch(&kek, Epoch(100), &mut rng).unwrap();
        let record = h.records[0].1.clone();

        let mut forged = Hierarchy::new();
        forged.records.push((Epoch(101), record));
        assert_eq!(forged.epoch_key(&kek, Epoch(101)), Err(Error::Unwrap));
    }

    #[test]
    fn opening_the_same_epoch_twice_does_not_orphan_the_first_key() {
        let (kek, _, mut rng) = setup();
        let mut h = Hierarchy::new();
        let first = h.open_epoch(&kek, Epoch(7), &mut rng).unwrap();
        let second = h.open_epoch(&kek, Epoch(7), &mut rng).unwrap();
        assert_eq!(first, second, "a second open must not replace W_N");
        assert_eq!(h.epochs().count(), 1);
    }

    #[test]
    fn a_truncated_record_is_rejected_without_panicking() {
        let (kek, _, _) = setup();
        let mut h = Hierarchy::new();
        h.records.push((Epoch(1), alloc::vec![0u8; 12]));
        assert_eq!(h.epoch_key(&kek, Epoch(1)), Err(Error::Malformed));
    }

    /// RFC 7 §4's third tier: a secret sealed under `W_N` dies with it.
    #[test]
    fn a_secret_sealed_under_an_epoch_key_dies_with_that_key() {
        let mut rng = NotRandom::seeded(11);
        let w = rng.next_32();
        let sealed = seal_under(&w, b"reservoir", b"half a shared secret", &mut rng).unwrap();
        assert_eq!(
            open_under(&w, b"reservoir", &sealed).unwrap(),
            b"half a shared secret"
        );

        // Wrong context, wrong key, and tampering all fail identically.
        assert_eq!(open_under(&w, b"prekey", &sealed), Err(Error::Unwrap));
        assert_eq!(
            open_under(&[0u8; 32], b"reservoir", &sealed),
            Err(Error::Unwrap)
        );
        let mut torn = sealed.clone();
        torn[13] ^= 1;
        assert_eq!(open_under(&w, b"reservoir", &torn), Err(Error::Unwrap));
        assert_eq!(
            open_under(&w, b"reservoir", &sealed[..10]),
            Err(Error::Malformed)
        );
    }

    /// Two seals of the same secret differ, so a stored record does not reveal
    /// that a ceremony was restarted with the same contribution.
    #[test]
    fn sealing_is_randomised() {
        let mut rng = NotRandom::seeded(12);
        let w = rng.next_32();
        let a = seal_under(&w, b"c", b"secret", &mut rng).unwrap();
        let b = seal_under(&w, b"c", b"secret", &mut rng).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn secrets_print_nothing() {
        let (kek, _, mut rng) = setup();
        assert_eq!(alloc::format!("{kek:?}"), "Kek(<redacted>)");
        let mut h = Hierarchy::new();
        h.open_epoch(&kek, Epoch(1), &mut rng).unwrap();
        assert_eq!(alloc::format!("{h:?}"), "Hierarchy(1 epochs)");
    }

    /// The real RFC 7 §4.1 parameters, run once. Slow by design — this is the
    /// ~500 ms that stands between a seized disk and the store.
    #[test]
    fn the_specified_parameters_work() {
        let mut rng = NotRandom::seeded(3);
        let params = KekParams::new(&mut rng);
        assert_eq!((params.m_kib, params.t, params.p), (65_536, 3, 4));
        assert_eq!(params.salt.len(), 16);
        let kek = Kek::derive(b"passphrase", &params).unwrap();
        let mut h = Hierarchy::new();
        assert!(h.open_epoch(&kek, Epoch(20_671), &mut rng).is_ok());
    }
}
