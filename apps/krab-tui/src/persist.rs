//! What survives a restart — RFC 7 §4, `Documentation/NO-CONFIG.md`.
//!
//! Four things, and each is either **wrapped** or **self-authenticating**:
//!
//! | file | protection | why |
//! |---|---|---|
//! | `identity.wrapped` | sealed under the KEK | the three private keys |
//! | `kek.params` | plaintext, self-checking | wrong params ⇒ nothing unwraps |
//! | `hierarchy.cbor` | already ciphertext | wrapped epoch keys (§4) |
//! | `corpus.krab` | content-addressed | every object hashes to its own name |
//!
//! Nothing else. No peer list, no window, no transport preference — a
//! remembered setting is configuration, and `NO-CONFIG.md` explains why a file
//! that can silently turn off delivery has no failure mode a user can act on.
//!
//! # The identity is under the KEK, not under `W_N`
//!
//! RFC 7 §4's hierarchy is `KEK → W_N → {prekey privates, reservoir chunks,
//! session state, message store}`. The identity is deliberately **not** in
//! that list, and putting it there would be a quiet catastrophe: shredding an
//! epoch is routine, and it would take the node's identity with it. RFC 7 §11
//! is explicit that losing identity means every peer re-verifies out of band,
//! in person, from scratch — so it must outlive the shredding schedule.
//!
//! # The corpus uses the courier archive format
//!
//! Not a separate on-disk format. The same flat length-prefixed records, the
//! same content-hash verification on load (RFC 4 §5.5).
//!
//! That is a security property, not a convenience: **loading your own store
//! exercises the same verification path as importing a stranger's stick.**
//! A private "trusted" format would be a second path with weaker checks, and
//! the disk is not trusted — RFC 7 §4's whole premise is that it may have been
//! tampered with while the node was off.
//!
//! # `kek.params` is plaintext and that is safe
//!
//! It holds the Argon2id salt and cost parameters, which RFC 7 §4.1 requires be
//! stored so a future increase does not lock out an existing store. None of it
//! is secret. Tampering with it is self-defeating: altered parameters produce a
//! different KEK, which unwraps nothing, which is a refusal rather than a
//! compromise.

use crate::identity::Identity;
use krab_core::cbor::{Item, Reader, Writer};
use krab_crypto::kek::{Kek, KekParams};
use krab_crypto::rng::Rng;
use krab_store::index::Store;
use std::path::Path;

/// Domain label binding the identity record to its purpose.
pub const CONTEXT_IDENTITY: &[u8] = b"krab/identity/v1";

/// Encode a reservoir for storage: the current root **and its ratchet epoch**.
///
/// RFC 7 §6.4 requires the peer-link record "the reservoir identifier and
/// current epoch", and the epoch is load-bearing rather than informational.
/// A root stored alone means a node returning after a gap infers the ratchet's
/// position, derives chunks at the wrong index, and its peer does not
/// recognise them — silently, because RFC 0 §6 makes delivery failure silent.
///
/// `CRYPTO-REVIEW.md` §11.5.
pub fn encode_reservoir(root: &[u8; 32], epoch: krab_core::tag::Epoch) -> Vec<u8> {
    let mut w = Writer::new();
    w.map(2);
    w.uint(1).uint(epoch.0 as u64);
    w.uint(2).bstr(root);
    w.finish()
}

/// Decode a stored reservoir.
///
/// A record without an epoch is refused rather than defaulted. Guessing would
/// mean guessing the ratchet position, and a wrong guess is the silent failure
/// above — better to fail loudly at load than to derive unrecognisable tags
/// for a day.
pub fn decode_reservoir(bytes: &[u8]) -> Result<([u8; 32], krab_core::tag::Epoch), Error> {
    let mut r = Reader::new(bytes);
    let mut m = r.map().map_err(|_| Error::Malformed)?;
    let (mut epoch, mut root) = (None, None);
    while let Some(key) = m.key().map_err(|_| Error::Malformed)? {
        match (key, m.value().map_err(|_| Error::Malformed)?) {
            (1, Item::Uint(v)) => epoch = u32::try_from(v).ok(),
            (2, Item::Bstr(b)) => root = <[u8; 32]>::try_from(b).ok(),
            _ => return Err(Error::Malformed),
        }
    }
    Ok((
        root.ok_or(Error::Malformed)?,
        krab_core::tag::Epoch(epoch.ok_or(Error::Malformed)?),
    ))
}

/// Domain label for the duress marker — RFC 7 §10.
///
/// Separate from [`CONTEXT_IDENTITY`] so the duress passphrase cannot open the
/// identity record and the real passphrase cannot open the duress record. An
/// adversary who compels one gets exactly what that one unlocks.
pub const CONTEXT_DURESS: &[u8] = b"krab/duress/v1";

/// What went wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Nothing stored here yet.
    Absent,
    /// A file did not parse.
    Malformed,
    /// The passphrase did not unwrap the identity.
    ///
    /// Deliberately indistinguishable from a tampered record: distinguishing
    /// them tells someone holding the disk which of their guesses was closer,
    /// and the operator's remedy is the same either way.
    Locked,
    /// The filesystem refused.
    Io,
}

/// Encode the KEK parameters. Plaintext — see the module note.
pub fn write_params(path: &Path, p: &KekParams) -> Result<(), Error> {
    let mut w = Writer::new();
    w.map(4);
    w.uint(1).uint(p.m_kib as u64);
    w.uint(2).uint(p.t as u64);
    w.uint(3).uint(p.p as u64);
    w.uint(4).bstr(&p.salt);
    std::fs::write(path, w.finish()).map_err(|_| Error::Io)
}

/// Read the KEK parameters.
pub fn read_params(path: &Path) -> Result<KekParams, Error> {
    let bytes = std::fs::read(path).map_err(|_| Error::Absent)?;
    let mut r = Reader::new(&bytes);
    let mut m = r.map().map_err(|_| Error::Malformed)?;
    let (mut m_kib, mut t, mut p, mut salt) = (None, None, None, None);
    while let Some(key) = m.key().map_err(|_| Error::Malformed)? {
        match (key, m.value().map_err(|_| Error::Malformed)?) {
            (1, Item::Uint(v)) => m_kib = u32::try_from(v).ok(),
            (2, Item::Uint(v)) => t = u32::try_from(v).ok(),
            (3, Item::Uint(v)) => p = u32::try_from(v).ok(),
            (4, Item::Bstr(b)) => salt = <[u8; 16]>::try_from(b).ok(),
            _ => return Err(Error::Malformed),
        }
    }
    Ok(KekParams {
        m_kib: m_kib.ok_or(Error::Malformed)?,
        t: t.ok_or(Error::Malformed)?,
        p: p.ok_or(Error::Malformed)?,
        salt: salt.ok_or(Error::Malformed)?,
    })
}

/// Seal the identity's three private keys under the KEK.
pub fn write_identity(
    path: &Path,
    id: &Identity,
    kek: &Kek,
    rng: &mut impl Rng,
) -> Result<(), Error> {
    let mut w = Writer::new();
    w.map(3);
    w.uint(1).bstr(&id.signing_seed());
    w.uint(2).bstr(&id.noise_bytes());
    w.uint(3).bstr(&id.correspondence_bytes());
    let plain = w.finish();

    let sealed = kek
        .seal(CONTEXT_IDENTITY, &plain, rng)
        .map_err(|_| Error::Io)?;
    std::fs::write(path, sealed).map_err(|_| Error::Io)
}

/// Recover the identity.
pub fn read_identity(path: &Path, kek: &Kek, params: KekParams) -> Result<Identity, Error> {
    let sealed = std::fs::read(path).map_err(|_| Error::Absent)?;
    let plain = kek
        .open(CONTEXT_IDENTITY, &sealed)
        .map_err(|_| Error::Locked)?;

    let mut r = Reader::new(&plain);
    let mut m = r.map().map_err(|_| Error::Malformed)?;
    let (mut sign, mut noise, mut corr) = (None, None, None);
    while let Some(key) = m.key().map_err(|_| Error::Malformed)? {
        match (key, m.value().map_err(|_| Error::Malformed)?) {
            (1, Item::Bstr(b)) => sign = <[u8; 32]>::try_from(b).ok(),
            (2, Item::Bstr(b)) => noise = <[u8; 32]>::try_from(b).ok(),
            (3, Item::Bstr(b)) => corr = <[u8; 32]>::try_from(b).ok(),
            _ => return Err(Error::Malformed),
        }
    }
    Ok(Identity::from_parts(
        &sign.ok_or(Error::Malformed)?,
        noise.ok_or(Error::Malformed)?,
        corr.ok_or(Error::Malformed)?,
        params,
    ))
}

/// Derive the KEK from a passphrase.
///
/// Thin, but it is the only place this crate touches key derivation — every
/// primitive lives behind `krab-crypto`'s single boundary, and adding `argon2`
/// here to save one call would perforate that for nothing.
pub fn kek_for(passphrase: &[u8], params: &KekParams) -> Result<Kek, Error> {
    Kek::derive(passphrase, params).map_err(|_| Error::Locked)
}

/// Write the corpus, in the courier archive format.
pub fn write_corpus(path: &Path, store: &Store) -> Result<usize, Error> {
    let profile = krab_fabric::profile::LinkProfile::courier();
    crate::courier::pack(store, path, (0, u32::MAX), &profile)
        .map(|p| p.objects)
        .map_err(|_| Error::Io)
}

/// Read the corpus back, verifying every object.
///
/// Uses the same path a stranger's archive takes. The disk is not trusted.
pub fn read_corpus(path: &Path, store: &mut Store, now_min: u32) -> Result<usize, Error> {
    if !path.exists() {
        return Err(Error::Absent);
    }
    crate::courier::import(store, path, now_min)
        .map(|i| i.accepted)
        .map_err(|_| Error::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use krab_crypto::rng::NotRandom;

    fn temp(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let d = std::env::temp_dir().join(format!(
            "krab-persist-{}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed),
            tag
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn cheap(rng: &mut impl Rng) -> KekParams {
        KekParams {
            m_kib: 64,
            t: 1,
            p: 1,
            ..KekParams::new(rng)
        }
    }

    /// **The whole point.** An identity written, the process gone, and the same
    /// keys recovered from a passphrase.
    #[test]
    fn an_identity_survives_a_restart() {
        let dir = temp("identity");
        let mut rng = NotRandom::seeded(1);
        let mut id = Identity::generate(&mut rng);
        id.kek_params = cheap(&mut rng);

        let kek = kek_for(b"correct horse", &id.kek_params).unwrap();
        write_params(&dir.join("kek.params"), &id.kek_params).unwrap();
        write_identity(&dir.join("identity.wrapped"), &id, &kek, &mut rng).unwrap();

        // A fresh process: nothing but the passphrase and the two files.
        let params = read_params(&dir.join("kek.params")).unwrap();
        let kek2 = kek_for(b"correct horse", &params).unwrap();
        let back = read_identity(&dir.join("identity.wrapped"), &kek2, params).unwrap();

        assert_eq!(back.node_id(), id.node_id(), "same identity");
        assert_eq!(back.fingerprint(), id.fingerprint());
        assert_eq!(
            back.card(crate::peering::Policy::default())
                .correspondence_pk,
            id.card(crate::peering::Policy::default()).correspondence_pk,
            "and the same tags with every existing peer"
        );
    }

    /// A wrong passphrase refuses, and says nothing about how wrong.
    #[test]
    fn a_wrong_passphrase_refuses() {
        let dir = temp("wrong-pass");
        let mut rng = NotRandom::seeded(2);
        let mut id = Identity::generate(&mut rng);
        id.kek_params = cheap(&mut rng);
        let kek = kek_for(b"the right one", &id.kek_params).unwrap();
        write_identity(&dir.join("identity.wrapped"), &id, &kek, &mut rng).unwrap();

        let wrong = kek_for(b"the right on", &id.kek_params).unwrap();
        assert_eq!(
            read_identity(&dir.join("identity.wrapped"), &wrong, id.kek_params).err(),
            Some(Error::Locked)
        );
    }

    /// **Tampering with the parameters is self-defeating**, which is why they
    /// can be plaintext: a changed salt or cost yields a different KEK, and a
    /// different KEK unwraps nothing.
    #[test]
    fn tampering_with_the_parameters_refuses_rather_than_compromises() {
        let dir = temp("params");
        let mut rng = NotRandom::seeded(3);
        let mut id = Identity::generate(&mut rng);
        id.kek_params = cheap(&mut rng);
        let kek = kek_for(b"pass", &id.kek_params).unwrap();
        write_params(&dir.join("kek.params"), &id.kek_params).unwrap();
        write_identity(&dir.join("identity.wrapped"), &id, &kek, &mut rng).unwrap();

        let mut tampered = read_params(&dir.join("kek.params")).unwrap();
        tampered.salt[0] ^= 1;
        let wrong = kek_for(b"pass", &tampered).unwrap();
        assert_eq!(
            read_identity(&dir.join("identity.wrapped"), &wrong, tampered).err(),
            Some(Error::Locked)
        );
    }

    /// RFC 7 §4.1 — the parameters round-trip exactly, so a future cost
    /// increase does not lock out an existing store.
    #[test]
    fn parameters_round_trip() {
        let dir = temp("param-rt");
        let p = KekParams::new(&mut NotRandom::seeded(4));
        write_params(&dir.join("kek.params"), &p).unwrap();
        assert_eq!(read_params(&dir.join("kek.params")).unwrap(), p);
        assert_eq!((p.m_kib, p.t, p.p), (65_536, 3, 4), "RFC 7 §4.1's defaults");
    }

    /// **The corpus reloads through the same path a stranger's archive takes.**
    #[test]
    fn the_corpus_survives_and_is_verified_on_the_way_back() {
        let dir = temp("corpus");
        let path = dir.join("corpus.krab");

        let mut store = Store::new();
        for salt in 0..5u8 {
            let h = krab_core::object::RoutingHeader {
                version: 1,
                class: 0,
                size_bucket: 0,
                flags: 0,
                expiry_min: 29_806_000 + salt as u32,
                tag: krab_core::object::Tag([salt; 8]),
            };
            let b = krab_core::object::canonical_bytes(&h, &[salt; 40]).unwrap();
            store
                .ingest(krab_crypto::object_id(&b), b, 29_766_000, u32::MAX)
                .unwrap();
        }
        assert_eq!(write_corpus(&path, &store).unwrap(), 5);

        let mut back = Store::new();
        assert_eq!(read_corpus(&path, &mut back, 29_766_000).unwrap(), 5);
        for id in store.ids_in_order() {
            assert_eq!(back.get(id), store.get(id));
        }
    }

    /// A corrupted corpus file does not put anything invalid into the store —
    /// the disk is not trusted, so the same checks apply as to a courier stick.
    #[test]
    fn a_corrupted_corpus_file_is_not_trusted() {
        let dir = temp("corpus-bad");
        let path = dir.join("corpus.krab");
        let mut store = Store::new();
        let h = krab_core::object::RoutingHeader {
            version: 1,
            class: 0,
            size_bucket: 0,
            flags: 0,
            expiry_min: 29_806_000,
            tag: krab_core::object::Tag([7; 8]),
        };
        let b = krab_core::object::canonical_bytes(&h, &[7u8; 40]).unwrap();
        let id = krab_crypto::object_id(&b);
        store.ingest(id, b, 29_766_000, u32::MAX).unwrap();
        write_corpus(&path, &store).unwrap();

        let intact = std::fs::read(&path).unwrap();
        let mut back = Store::new();
        for i in 0..intact.len() {
            let mut raw = intact.clone();
            raw[i] ^= 0xFF;
            std::fs::write(&path, &raw).unwrap();
            let _ = read_corpus(&path, &mut back, 29_766_000);
        }
        for oid in back.ids_in_order() {
            assert_eq!(krab_crypto::object_id(back.get(oid).unwrap()), *oid);
        }
    }

    /// **RFC 7 §6.4 / CRYPTO-REVIEW.md §11.5.** The ratchet position travels
    /// with the root, so a node returning after a gap resumes at the right
    /// index rather than inferring one.
    #[test]
    fn a_stored_reservoir_carries_its_ratchet_epoch() {
        let root = [0x5A; 32];
        let epoch = krab_core::tag::Epoch(20_671);
        let (back_root, back_epoch) = decode_reservoir(&encode_reservoir(&root, epoch)).unwrap();
        assert_eq!(back_root, root);
        assert_eq!(back_epoch, epoch);
    }

    /// A record without an epoch is refused, not defaulted. A guessed ratchet
    /// position produces tags a peer does not recognise, silently.
    #[test]
    fn a_reservoir_without_an_epoch_is_refused() {
        let mut w = Writer::new();
        w.map(1);
        w.uint(2).bstr(&[0u8; 32]);
        assert_eq!(decode_reservoir(&w.finish()).err(), Some(Error::Malformed));

        // And every truncation refuses rather than panicking.
        let good = encode_reservoir(&[1; 32], krab_core::tag::Epoch(5));
        for n in 0..good.len() {
            let _ = decode_reservoir(&good[..n]);
        }
    }

    /// A first run finds nothing and says so rather than failing.
    #[test]
    fn a_first_run_finds_nothing() {
        let dir = temp("empty");
        assert_eq!(read_params(&dir.join("kek.params")), Err(Error::Absent));
        assert_eq!(
            read_corpus(&dir.join("corpus.krab"), &mut Store::new(), 0),
            Err(Error::Absent)
        );
    }

    /// Malformed files are refused without panicking, at every truncation.
    #[test]
    fn malformed_files_do_not_panic() {
        let dir = temp("malformed");
        let p = dir.join("kek.params");
        let good = {
            write_params(&p, &KekParams::new(&mut NotRandom::seeded(5))).unwrap();
            std::fs::read(&p).unwrap()
        };
        for n in 0..good.len() {
            std::fs::write(&p, &good[..n]).unwrap();
            let _ = read_params(&p);
        }
        std::fs::write(&p, [0xFFu8; 40]).unwrap();
        assert!(read_params(&p).is_err());
    }
}
