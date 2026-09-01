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
//! # Every write here is atomic
//!
//! `crate::atomic::write` rather than `std::fs::write`. A crash mid-write to
//! `identity.wrapped` would otherwise leave a truncated file and destroy the
//! identity permanently — RFC 7 §11: "losing identity means every peer must
//! re-verify out of band, in person, from scratch." §11 prescribes an offline
//! backup for that loss; it did not anticipate that a routine save was one of
//! the ways to cause it.
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

/// Domain label for the onion service root — RFC 4 §5.2.
///
/// Distinct from [`CONTEXT_IDENTITY`] for the same reason [`CONTEXT_DURESS`]
/// is: an AEAD context is what stops a record sealed for one purpose opening
/// as another, and §5.2's whole requirement is that the onion key and the
/// identity key are not the same secret.
pub const CONTEXT_ONION: &[u8] = b"krab/onion-root/v1";

/// Seal this node's onion state under a KEK subkey.
///
/// The root **and both rotation counters** — RFC 4 §5.2's is "a rotatable
/// epoch counter", and a counter that is not stored is not rotatable: the
/// address would revert to counter 0 at the next start, which is a rotation
/// nobody asked for and nobody is told about.
///
/// The two counters are separate because the two endpoints rotate for
/// different reasons and at different rates (RFC 3 §9.2): the contact endpoint
/// is "freely rotatable" and expected to move often, the sync endpoint is the
/// address peers have written down.
pub fn write_onion_root(
    path: &Path,
    root: &krab_crypto::onion::OnionRoot,
    counters: (krab_crypto::onion::Counter, krab_crypto::onion::Counter),
    key: &[u8; 32],
    rng: &mut impl Rng,
) -> Result<(), Error> {
    let mut plain = [0u8; 40];
    plain[..32].copy_from_slice(root.as_bytes());
    plain[32..36].copy_from_slice(&counters.0.to_le_bytes());
    plain[36..].copy_from_slice(&counters.1.to_le_bytes());
    let sealed = krab_crypto::kek::seal_under(key, CONTEXT_ONION, &plain, rng)
        .map_err(|_| Error::Malformed)?;
    crate::atomic::write(path, &sealed).map_err(|_| Error::Malformed)
}

/// Read the onion service root and its two counters back.
///
/// [`Error::Absent`] means this node has never published an onion service,
/// which is the ordinary case and not a fault — the caller generates one.
///
/// # A 32-byte record is the old format, not a corrupt one
///
/// The first version stored the root alone. Refusing those would take an
/// existing node's permanent address away on upgrade, which is the loudest
/// possible failure for the least reason: the counters were 0 then, because
/// there was no way to advance them.
pub fn read_onion_root(
    path: &Path,
    key: &[u8; 32],
) -> Result<
    (
        krab_crypto::onion::OnionRoot,
        krab_crypto::onion::Counter,
        krab_crypto::onion::Counter,
    ),
    Error,
> {
    let sealed = std::fs::read(path).map_err(|_| Error::Absent)?;
    let plain =
        krab_crypto::kek::open_under(key, CONTEXT_ONION, &sealed).map_err(|_| Error::Locked)?;
    match plain.len() {
        32 => {
            let bytes = <[u8; 32]>::try_from(plain.as_slice()).map_err(|_| Error::Malformed)?;
            Ok((krab_crypto::onion::OnionRoot::from_bytes(bytes), 0, 0))
        }
        40 => {
            let bytes = <[u8; 32]>::try_from(&plain[..32]).map_err(|_| Error::Malformed)?;
            let sync = u32::from_le_bytes(plain[32..36].try_into().map_err(|_| Error::Malformed)?);
            let contact = u32::from_le_bytes(plain[36..].try_into().map_err(|_| Error::Malformed)?);
            Ok((
                krab_crypto::onion::OnionRoot::from_bytes(bytes),
                sync,
                contact,
            ))
        }
        _ => Err(Error::Malformed),
    }
}

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
    crate::atomic::write(path, &w.finish()).map_err(|_| Error::Io)
}

/// The largest Argon2 memory parameter a stored `params.cbor` may ask for.
///
/// One gibibyte, against RFC 7 §4.1's 64 MiB default. The file is read before
/// the KEK exists and so is unauthenticated by construction; without a ceiling,
/// anyone who can write it chooses this process's next allocation.
///
/// Generous rather than tight on purpose: a deployment that legitimately
/// raised the parameter must not find its own node refusing to unlock.
pub const MAX_ARGON2_M_KIB: u32 = 1 << 20;

/// Read the KEK parameters.
pub fn read_params(path: &Path) -> Result<KekParams, Error> {
    let bytes = std::fs::read(path).map_err(|_| Error::Absent)?;
    let mut r = Reader::new(&bytes);
    let mut m = r.map().map_err(|_| Error::Malformed)?;
    let (mut m_kib, mut t, mut p, mut salt) = (None, None, None, None);
    while let Some(key) = m.key().map_err(|_| Error::Malformed)? {
        match (key, m.value().map_err(|_| Error::Malformed)?) {
            // **Bounded before it becomes an allocation.** `params.cbor` is
            // read *before* any key exists, so it cannot be authenticated —
            // that is what it is for. An unbounded `m_kib` therefore lets
            // anyone who can write one file choose how many gibibytes Argon2
            // asks for on the next unlock. The ceiling is generous against
            // RFC 7 §4.1's 64 MiB and still refuses an address space.
            (1, Item::Uint(v)) => {
                m_kib = u32::try_from(v).ok().filter(|m| *m <= MAX_ARGON2_M_KIB)
            }
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
    // **The epoch hierarchy travels with the identity.** It did not, and
    // `open_epoch` therefore minted a fresh `W_N` on every start — so the
    // reservoir of every peering, the prekey ring, and the channel roster all
    // became unreadable on restart, silently, with no error anywhere. The
    // module note above has always listed `hierarchy.cbor`; nothing wrote it.
    let mut h = Writer::new();
    let records = id.hierarchy.records();
    h.array(records.len() * 2);
    for (epoch, record) in records {
        h.uint(epoch.0 as u64).bstr(record);
    }
    let hierarchy = h.finish();

    let mut w = Writer::new();
    w.map(4);
    w.uint(1).bstr(&id.signing_seed());
    w.uint(2).bstr(&id.noise_bytes());
    w.uint(3).bstr(&id.correspondence_bytes());
    w.uint(4).bstr(&hierarchy);
    let plain = w.finish();

    let sealed = kek
        .seal(CONTEXT_IDENTITY, &plain, rng)
        .map_err(|_| Error::Io)?;
    crate::atomic::write(path, &sealed).map_err(|_| Error::Io)
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
    let mut hierarchy = Vec::new();
    while let Some(key) = m.key().map_err(|_| Error::Malformed)? {
        match (key, m.value().map_err(|_| Error::Malformed)?) {
            (1, Item::Bstr(b)) => sign = <[u8; 32]>::try_from(b).ok(),
            (2, Item::Bstr(b)) => noise = <[u8; 32]>::try_from(b).ok(),
            (3, Item::Bstr(b)) => corr = <[u8; 32]>::try_from(b).ok(),
            // Absent in a store written before the hierarchy was persisted.
            // Such a node has already lost its epoch keys and cannot be given
            // them back; reading it as empty is the honest outcome, and it
            // still opens.
            (4, Item::Bstr(b)) => hierarchy = read_hierarchy(b),
            _ => return Err(Error::Malformed),
        }
    }
    let mut id = Identity::from_parts(
        &sign.ok_or(Error::Malformed)?,
        noise.ok_or(Error::Malformed)?,
        corr.ok_or(Error::Malformed)?,
        params,
    );
    id.hierarchy = krab_crypto::kek::Hierarchy::from_records(hierarchy);
    Ok(id)
}

/// Wrapped epoch keys, as stored. Ciphertext throughout.
///
/// A malformed run yields what parsed before it: this is the operator's own
/// disk, and dropping an entire hierarchy because its tail is damaged would
/// lose every epoch to save the ones already read.
fn read_hierarchy(bytes: &[u8]) -> Vec<(krab_core::tag::Epoch, Vec<u8>)> {
    let mut r = Reader::new(bytes);
    let mut out = Vec::new();
    let Ok(Item::Array(n)) = r.item() else {
        return out;
    };
    for _ in 0..n / 2 {
        let (Ok(Item::Uint(e)), Ok(Item::Bstr(rec))) = (r.item(), r.item()) else {
            break;
        };
        let Ok(e) = u32::try_from(e) else { break };
        out.push((krab_core::tag::Epoch(e), rec.to_vec()));
    }
    out
}

/// Derive the KEK from a passphrase.
///
/// Thin, but it is the only place this crate touches key derivation — every
/// primitive lives behind `krab-crypto`'s single boundary, and adding `argon2`
/// here to save one call would perforate that for nothing.
pub fn kek_for(passphrase: &[u8], params: &KekParams) -> Result<Kek, Error> {
    Kek::derive(passphrase, params).map_err(|_| Error::Locked)
}

/// The name a bucket's segment file has inside the corpus directory.
///
/// `.krab` because `artifact::wiped` already destroys every name with that
/// suffix and `shred::remove_matching` recurses — so a segment is covered by
/// `wipe` without a new rule, and a rule that has to be remembered is how both
/// of the failures `artifact` exists for happened.
fn segment_name(bucket: u32) -> String {
    format!("{bucket}.krab")
}

/// The bucket a segment file names, if it names one.
fn bucket_of_name(name: &str) -> Option<u32> {
    name.strip_suffix(".krab")?.parse().ok()
}

/// The half-open expiry window a bucket covers.
///
/// The top bucket's true edge is past `u32::MAX`, and clamping there excludes
/// the minute `u32::MAX` itself — which RFC 1 §11 I2 refuses at ingest, so no
/// object can be in it.
fn bucket_window(bucket: u32) -> (u32, u32) {
    let start = krab_store::segment::bucket_start(bucket);
    let end = krab_store::segment::bucket_end(bucket).min(u32::MAX as u64) as u32;
    (start, end)
}

/// Write the segments that changed, and remove the ones that are gone.
///
/// # One file per bucket, not one file for the corpus
///
/// This wrote the whole corpus into `corpus.krab` on every call, and it is
/// called after every exchange that received anything. At RFC 3 §5's default
/// retention — a gigabyte — that is a gigabyte of I/O to record one new
/// object, and it grows with the corpus rather than with the change.
///
/// RFC 5 §7 already said what the layout should be. Objects are grouped into
/// TTL buckets so that "eviction is `unlink()` of a whole segment: no
/// compaction, no tombstone sweep, no fragmentation, no write amplification.
/// Courier export is a copy of whole segment files." The store had the
/// buckets; only the writer did not use them.
///
/// So a save now touches the buckets that changed — usually one, since an
/// object's bucket is its expiry day.
///
/// # Removal is a sweep, not a notification
///
/// Expiry and eviction drop whole segments, and nothing tells this function
/// which. It compares the files on disk against [`Store::buckets`] instead, so
/// a segment that disappears is noticed without the store having to remember
/// to say so — one less thing a future edit can forget on the path that adds a
/// segment.
///
/// The files are **shredded**, not unlinked. A segment holds sealed objects,
/// so this is defence in depth and not the erasure — `shred`'s own module
/// documentation is careful about the difference — but an expired segment is
/// an artifact leaving the disk, and those are overwritten first.
///
/// Each segment is packed to a temporary and renamed, so a crash cannot
/// truncate one. Objects are recoverable from peers, but a node that lost half
/// its store on a power cut then spends its next reconciliations re-fetching
/// what it already had — and on a serial or courier link that is hours or
/// weeks.
pub fn write_corpus(dir: &Path, store: &mut Store, rng: &mut dyn Rng) -> Result<usize, Error> {
    std::fs::create_dir_all(dir).map_err(|_| Error::Io)?;
    let profile = krab_fabric::profile::LinkProfile::courier();

    let mut written = 0;
    for bucket in store.dirty_buckets().collect::<Vec<_>>() {
        let path = dir.join(segment_name(bucket));
        let tmp = crate::atomic::temp_for(&path);
        let (lo, hi) = bucket_window(bucket);
        let n = crate::courier::pack(store, &tmp, (lo, hi), &profile)
            .map(|p| p.objects)
            .map_err(|_| Error::Io)?;
        std::fs::rename(&tmp, &path).map_err(|_| Error::Io)?;
        written += n;
    }

    let held: std::collections::BTreeSet<u32> = store.buckets().collect();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(bucket) = bucket_of_name(&name) else {
                continue;
            };
            if !held.contains(&bucket) {
                crate::shred::remove(&entry.path(), rng);
            }
        }
    }

    // The renames are only durable once the directory entry is.
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    store.mark_saved();
    Ok(written)
}

/// Read the corpus back, verifying every object.
///
/// Uses the same path a stranger's archive takes. The disk is not trusted.
///
/// Every segment file in the directory is imported. A file that fails
/// verification contributes nothing and does not stop the others: the corpus
/// is content-addressed, so a damaged segment is a gap, and refusing to start
/// because one bucket is corrupt would turn a recoverable loss into a total
/// one.
pub fn read_corpus(dir: &Path, store: &mut Store, now_min: u32) -> Result<usize, Error> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Err(Error::Absent);
    };
    let (mut accepted, mut files) = (0, 0);
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if bucket_of_name(&name).is_none() {
            continue;
        }
        files += 1;
        if let Ok(i) = crate::courier::import(store, &entry.path(), now_min) {
            accepted += i.accepted;
        }
    }
    // What was just read is what is on disk, so nothing is owed. Without this
    // the first save after a restart rewrites every segment it has just read —
    // the whole-corpus write this layout replaced, once per start.
    store.mark_saved();
    if files == 0 {
        return Err(Error::Absent);
    }
    Ok(accepted)
}

/// Move a single-file `corpus.krab` into the per-bucket layout.
///
/// A node written by an earlier build has one file. This reads it through the
/// same verification path, writes the segments, and shreds the original. It
/// runs once, because afterwards the directory exists.
///
/// An upgrade that silently started with an empty corpus would look exactly
/// like the data loss this series keeps finding, so the migration is a step
/// rather than a fallback.
pub fn migrate_corpus(
    old: &Path,
    dir: &Path,
    store: &mut Store,
    now_min: u32,
    rng: &mut dyn Rng,
) -> Result<usize, Error> {
    if !old.exists() {
        return Err(Error::Absent);
    }
    let accepted = crate::courier::import(store, old, now_min)
        .map(|i| i.accepted)
        .map_err(|_| Error::Malformed)?;
    store.mark_all_dirty();
    write_corpus(dir, store, rng)?;
    crate::shred::remove(old, rng);
    Ok(accepted)
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
        let path = dir.join("corpus");

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
            let b = krab_core::object::canonical_bytes(
                &h,
                &krab_core::object::example_sealed_body(salt),
            )
            .unwrap();
            store
                .ingest(krab_crypto::object_id(&b), b, 29_766_000, u32::MAX)
                .unwrap();
        }
        let mut rng = NotRandom::seeded(4);
        assert_eq!(write_corpus(&path, &mut store, &mut rng).unwrap(), 5);

        let mut back = Store::new();
        assert_eq!(read_corpus(&path, &mut back, 29_766_000).unwrap(), 5);
        for id in store.ids_in_order() {
            assert_eq!(back.get(id), store.get(id));
        }
    }

    /// **A save writes the buckets that changed, and only those.**
    ///
    /// The whole point of the layout: one file per expiry bucket, so recording
    /// one new object costs one segment rather than the corpus. This used to
    /// rewrite everything on every call, after every exchange that received
    /// anything.
    #[test]
    fn a_save_touches_only_the_buckets_that_changed() {
        let dir = temp("corpus-incremental");
        let path = dir.join("corpus");
        let day = 1_440u32;
        let object = |bucket: u32, salt: u8| {
            let h = krab_core::object::RoutingHeader {
                version: 1,
                class: 0,
                size_bucket: 0,
                flags: 0,
                expiry_min: bucket * day + 1 + salt as u32,
                tag: krab_core::object::Tag([salt; 8]),
            };
            let b = krab_core::object::canonical_bytes(
                &h,
                &krab_core::object::example_sealed_body(salt),
            )
            .unwrap();
            (krab_crypto::object_id(&b), b)
        };

        let mut store = Store::new();
        let mut rng = NotRandom::seeded(9);
        for bucket in 20_000..20_004u32 {
            let (id, b) = object(bucket, bucket as u8);
            store.ingest(id, b, 0, u32::MAX).unwrap();
        }
        assert_eq!(write_corpus(&path, &mut store, &mut rng).unwrap(), 4);
        assert_eq!(
            std::fs::read_dir(&path).unwrap().count(),
            4,
            "one per bucket"
        );

        // Nothing changed: nothing is written.
        assert_eq!(write_corpus(&path, &mut store, &mut rng).unwrap(), 0);

        // Note the modification times, add one object, and check that exactly
        // one file moved. Times rather than contents, because "was rewritten
        // with identical bytes" is the failure being ruled out.
        let stamp = |b: u32| {
            std::fs::metadata(path.join(format!("{b}.krab")))
                .and_then(|m| m.modified())
                .unwrap()
        };
        let before: Vec<_> = (20_000..20_004).map(stamp).collect();
        std::thread::sleep(std::time::Duration::from_millis(20));

        let (id, b) = object(20_002, 200);
        store.ingest(id, b, 0, u32::MAX).unwrap();
        assert_eq!(write_corpus(&path, &mut store, &mut rng).unwrap(), 2);
        let after: Vec<_> = (20_000..20_004).map(stamp).collect();
        for (i, (a, b)) in before.iter().zip(after.iter()).enumerate() {
            if i == 2 {
                assert_ne!(a, b, "the changed bucket was not rewritten");
            } else {
                assert_eq!(a, b, "bucket {} was rewritten for nothing", 20_000 + i);
            }
        }

        // And a bucket that goes away takes its file with it.
        store.expire(20_001 * day);
        write_corpus(&path, &mut store, &mut rng).unwrap();
        assert!(
            !path.join("20000.krab").exists(),
            "an expired segment stayed"
        );
        assert!(
            path.join("20003.krab").exists(),
            "a live segment was removed"
        );
    }

    /// A node written by an earlier build has one file. It must not start
    /// empty — an upgrade that silently discards the corpus looks exactly like
    /// the data loss this series keeps finding.
    #[test]
    fn a_single_file_corpus_is_migrated_and_shredded() {
        let dir = temp("corpus-migrate");
        let old = dir.join("corpus.krab");
        let new = dir.join("corpus");

        // Write the old layout by hand: one archive over the whole window.
        let mut store = Store::new();
        for salt in 0..3u8 {
            let h = krab_core::object::RoutingHeader {
                version: 1,
                class: 0,
                size_bucket: 0,
                flags: 0,
                expiry_min: 29_806_000 + salt as u32,
                tag: krab_core::object::Tag([salt; 8]),
            };
            let b = krab_core::object::canonical_bytes(
                &h,
                &krab_core::object::example_sealed_body(salt),
            )
            .unwrap();
            store
                .ingest(krab_crypto::object_id(&b), b, 29_766_000, u32::MAX)
                .unwrap();
        }
        let profile = krab_fabric::profile::LinkProfile::courier();
        crate::courier::pack(&store, &old, (0, u32::MAX), &profile).unwrap();

        let mut back = Store::new();
        let mut rng = NotRandom::seeded(11);
        assert_eq!(
            migrate_corpus(&old, &new, &mut back, 29_766_000, &mut rng).unwrap(),
            3
        );
        assert!(!old.exists(), "the old file survived the migration");
        assert_eq!(back.len(), 3);

        // And the migrated node reads back exactly what it had.
        let mut again = Store::new();
        assert_eq!(read_corpus(&new, &mut again, 29_766_000).unwrap(), 3);
        for id in store.ids_in_order() {
            assert_eq!(again.get(id), store.get(id));
        }
    }

    /// A corrupted corpus file does not put anything invalid into the store —
    /// the disk is not trusted, so the same checks apply as to a courier stick.
    #[test]
    fn a_corrupted_corpus_file_is_not_trusted() {
        let dir = temp("corpus-bad");
        let path = dir.join("corpus");
        let mut store = Store::new();
        let h = krab_core::object::RoutingHeader {
            version: 1,
            class: 0,
            size_bucket: 0,
            flags: 0,
            expiry_min: 29_806_000,
            tag: krab_core::object::Tag([7; 8]),
        };
        let b = krab_core::object::canonical_bytes(&h, &krab_core::object::example_sealed_body(7))
            .unwrap();
        let id = krab_crypto::object_id(&b);
        store.ingest(id, b, 29_766_000, u32::MAX).unwrap();
        let mut rng = NotRandom::seeded(5);
        write_corpus(&path, &mut store, &mut rng).unwrap();

        // One bucket, so one segment file — and every byte of it is flipped in
        // turn, exactly as before the layout changed.
        let seg = std::fs::read_dir(&path)
            .unwrap()
            .flatten()
            .next()
            .unwrap()
            .path();
        let intact = std::fs::read(&seg).unwrap();
        let mut back = Store::new();
        for i in 0..intact.len() {
            let mut raw = intact.clone();
            raw[i] ^= 0xFF;
            std::fs::write(&seg, &raw).unwrap();
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
