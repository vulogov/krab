//! `pack` and `import` — courier archives, RFC 4 §5.5, RFC 8 §5.
//!
//! ```text
//! The container MUST be a flat sequence of length-prefixed records.
//! Filenames, if any, MUST be ignored entirely -- every object is named by its hash.
//! Compression MUST be off: objects are ciphertext and do not compress,
//!   and store-only makes decompression bombs impossible.
//! Every object MUST be verified by content hash on ingest (RFC 1 §11).
//! An implementation MUST NOT open a foreign database file.
//! ```
//!
//! # The archive is a window, not a diff
//!
//! This is the design decision in `pack`, and RFC 4 §5.5 does not state it —
//! but it hands over the reason it is affordable:
//!
//! > "**Capacity never binds.** A 128 GB medium holds 286× the measured n=500
//! > corpus and writes in 15 seconds. The constraint is human latency, always."
//!
//! An archive containing "what is new since last time" is a diff, and a diff
//! is a statement about what its author did between two dates. Hand three
//! successive sticks to the same courier and their contents reconstruct the
//! sender's composition schedule — precisely the correlation RFC 5 §6.1
//! forbids on the network, arriving by the back door.
//!
//! [`pack`] therefore writes a **time window of the corpus**: everything the
//! node holds in a range, its own objects and relayed objects alike,
//! indistinguishable from each other. Two archives written a day apart differ
//! by whatever the corpus gained, from any source.
//!
//! That costs bandwidth a diff would not. Capacity never binds, so it costs
//! nothing that matters — which is why §5.5's throwaway line about a 128 GB
//! medium is load-bearing rather than reassurance. Worth stating in the RFC:
//! an implementer optimising the obvious way produces a timing oracle.
//!
//! # The archive is hostile input
//!
//! [`import`] recomputes every identifier and hands nothing to the store it
//! has not hashed. A single corrupt record is skipped rather than aborting the
//! archive — a failing USB stick should not cost the whole delivery — but a
//! record that does not hash to its own content never reaches the corpus.
//!
//! There is no database here and no compression, per §5.5. The reason it names
//! is worth keeping visible: shipping the archive as SQLite is tempting and
//! means parsing an attacker-supplied database with a library that has a long
//! CVE history. Import into your own store; never open theirs.

use krab_fabric::backend::courier::{read_archive, CourierFabric};
use krab_fabric::profile::LinkProfile;
use krab_fabric::Fabric;
use krab_proto::control::Control;
use krab_store::index::Store;
use std::path::Path;

/// What `pack` wrote.
pub struct Packed {
    /// Objects written.
    pub objects: usize,
    /// Bytes on the medium.
    pub bytes: u64,
    /// The window covered, in minutes since the Unix epoch.
    pub window: (u32, u32),
}

/// What `import` found.
pub struct Imported {
    /// Objects accepted into the corpus.
    pub accepted: usize,
    /// Objects already held. Not an error — a courier carrying a window will
    /// mostly carry things you have, and that is the point.
    pub duplicate: usize,
    /// Records refused: bad hash, malformed, expired, or over quota.
    pub refused: usize,
}

impl Imported {
    /// Every record accounted for.
    pub fn total(&self) -> usize {
        self.accepted + self.duplicate + self.refused
    }
}

/// Write a window of the corpus to `path` — RFC 8 §5's `pack`.
///
/// `window` is a range in minutes. The caller picks it from `MAX_TTL`, not
/// from what changed: see the module documentation on why a diff is a timing
/// oracle.
pub fn pack(
    store: &Store,
    path: &Path,
    window: (u32, u32),
    profile: &LinkProfile,
) -> std::io::Result<Packed> {
    // A dummy inbox: `pack` writes and never reads. A courier link is always
    // writable and whether anyone carries it is not the protocol's business
    // (RFC 4 §5.5), so this path deliberately does not need to exist.
    let nowhere = path.with_extension("never-read");
    let fabric = CourierFabric::new(profile.clone(), path, &nowhere);
    let mut session = fabric
        .connect()
        .map_err(|e| std::io::Error::other(format!("{e:?}")))?;

    let mut objects = 0;
    for (_, id) in store.entries_in_range(window.0, window.1) {
        let Some(bytes) = store.get(&id) else {
            continue;
        };
        // A link that cannot carry an object must not have it written to its
        // medium — RFC 4 §5.4's ceiling applies to couriers too, and a LoRa
        // gateway reading this archive would silently drop what exceeds it.
        let Ok(header) = krab_core::object::RoutingHeader::parse(bytes) else {
            continue;
        };
        if !profile.max_bucket.admits(header.size_bucket) {
            continue;
        }
        if session.send(&Control::Obj(bytes.to_vec())).is_ok() {
            objects += 1;
        }
    }
    let _ = session.send(&Control::Done);
    session
        .close()
        .map_err(|e| std::io::Error::other(format!("{e:?}")))?;

    let bytes = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    Ok(Packed {
        objects,
        bytes,
        window,
    })
}

/// Ingest an archive — RFC 8 §5's `import`.
///
/// `path` names a file and nothing more: RFC 4 §5.5 requires filenames be
/// ignored entirely, and this function never inspects it beyond opening it.
pub fn import(store: &mut Store, path: &Path, now_min: u32) -> std::io::Result<Imported> {
    let records = read_archive(path).map_err(|e| std::io::Error::other(format!("{e:?}")))?;

    let mut out = Imported {
        accepted: 0,
        duplicate: 0,
        refused: 0,
    };
    for record in records {
        let Control::Obj(bytes) = record else {
            // Control messages other than objects carry no corpus content.
            // A courier archive holding a `Want` is not malformed, just
            // uninteresting — it was written for a reconciliation that will
            // not happen on this leg.
            continue;
        };
        // **The identifier is derived, never taken.** A courier cannot mislabel
        // an object because the label is not something anyone sends.
        let id = krab_crypto::object_id(&bytes);
        if store.contains(&id) {
            out.duplicate += 1;
            continue;
        }
        match store.ingest(id, bytes, now_min, u32::MAX) {
            Ok(()) => out.accepted += 1,
            // RFC 1 §11's checks: expiry, padding, bucket, version. A record
            // that fails one is skipped, not fatal — a failing medium should
            // not cost the whole delivery.
            Err(_) => out.refused += 1,
        }
    }
    Ok(out)
}

/// Objects an archive contains, verified without ingesting.
///
/// RFC 4 §5.5's "verified by content hash" as a separate step, so an operator
/// can check a stick before trusting it.
pub fn verify(path: &Path) -> Result<usize, usize> {
    CourierFabric::verify(path)
}

/// A human-readable companion, RFC 4 §5.5.
///
/// > "A separate human-readable `MANIFEST.hjson` MAY accompany the archive for
/// > the courier's benefit. **This is where HJSON is genuinely the right
/// > format: a human reads it, nothing signs it, and nothing hashes it.**"
///
/// It deliberately names no peer and lists no identifier. A courier who loses
/// the stick should not also have handed over a list of who talks to whom, and
/// the manifest is the one part of the archive that is not ciphertext.
pub fn manifest(packed: &Packed) -> String {
    format!(
        "{{\n  \
         # Krab courier archive. Nothing here is signed or hashed --\n  \
         # it is for the person carrying the medium, not for the software.\n  \
         objects: {}\n  \
         bytes: {}\n  \
         window_minutes: [{}, {}]\n  \
         format: \"flat length-prefixed records, uncompressed\"\n\
         }}\n",
        packed.objects, packed.bytes, packed.window.0, packed.window.1
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use krab_core::object::{canonical_bytes, ObjectId, RoutingHeader, Tag};

    const NOW_MIN: u32 = 29_766_000;

    fn temp(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let d = std::env::temp_dir().join(format!(
            "krab-courier-{}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed),
            tag
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn object(salt: u8) -> (ObjectId, Vec<u8>) {
        let h = RoutingHeader {
            version: 1,
            class: 0,
            size_bucket: 0,
            flags: 0,
            expiry_min: NOW_MIN + 40_000 + salt as u32,
            tag: Tag([salt; 8]),
        };
        let b = canonical_bytes(&h, &krab_core::object::example_sealed_body(salt)).unwrap();
        (krab_crypto::object_id(&b), b)
    }

    fn store_with(n: u8) -> Store {
        let mut s = Store::new();
        for salt in 0..n {
            let (id, b) = object(salt);
            s.ingest(id, b, NOW_MIN, u32::MAX).unwrap();
        }
        s
    }

    /// The round trip: pack a corpus, carry it, import it, and end up with the
    /// same objects.
    #[test]
    fn a_packed_archive_imports_into_an_empty_corpus() {
        let dir = temp("roundtrip");
        let archive = dir.join("out.krab");
        let source = store_with(5);

        let packed = pack(&source, &archive, (0, u32::MAX), &LinkProfile::courier()).unwrap();
        assert_eq!(packed.objects, 5);
        assert!(packed.bytes > 0);
        assert_eq!(verify(&archive), Ok(5));

        let mut dest = Store::new();
        let got = import(&mut dest, &archive, NOW_MIN).unwrap();
        assert_eq!(got.accepted, 5);
        assert_eq!(got.refused, 0);
        assert_eq!(dest.len(), 5);
        for salt in 0..5u8 {
            assert!(dest.contains(&object(salt).0));
        }
    }

    /// **RFC 4 §5.5 — filenames MUST be ignored entirely.** A courier renames
    /// things, and a stick labelled `photos.zip` must import identically.
    #[test]
    fn the_filename_is_ignored_entirely() {
        let dir = temp("names");
        let archive = dir.join("out.krab");
        pack(
            &store_with(3),
            &archive,
            (0, u32::MAX),
            &LinkProfile::courier(),
        )
        .unwrap();

        for name in ["DSC_0041.bin", "photos.zip", "no-extension", "..weird.name"] {
            let renamed = dir.join(name);
            std::fs::copy(&archive, &renamed).unwrap();
            let mut dest = Store::new();
            assert_eq!(
                import(&mut dest, &renamed, NOW_MIN).unwrap().accepted,
                3,
                "{name}"
            );
        }
    }

    /// **A tampered object never reaches the corpus under its claimed name.**
    /// The identifier is recomputed, so a courier cannot substitute content
    /// for an identifier a peer already holds.
    #[test]
    fn every_object_in_the_store_hashes_to_its_own_identifier() {
        let dir = temp("tamper");
        let archive = dir.join("out.krab");
        pack(
            &store_with(4),
            &archive,
            (0, u32::MAX),
            &LinkProfile::courier(),
        )
        .unwrap();

        let intact = std::fs::read(&archive).unwrap();
        let torn_path = dir.join("torn.krab");
        let mut dest = Store::new();
        // Every byte position, since an object is its own hash and no part of
        // an archive may be quietly wrong.
        for i in 0..intact.len() {
            let mut raw = intact.clone();
            raw[i] ^= 0xFF;
            std::fs::write(&torn_path, &raw).unwrap();
            let _ = import(&mut dest, &torn_path, NOW_MIN);
        }
        for id in dest.ids_in_order() {
            assert_eq!(krab_crypto::object_id(dest.get(id).unwrap()), *id);
        }
    }

    /// **The window, not the diff.** Two archives written from the same corpus
    /// carry the same objects — so successive sticks handed to one courier do
    /// not reconstruct what their author composed in between.
    #[test]
    fn two_archives_from_one_corpus_are_indistinguishable_in_content() {
        let dir = temp("window");
        let source = store_with(6);
        let (a, b) = (dir.join("mon.krab"), dir.join("tue.krab"));

        pack(&source, &a, (0, u32::MAX), &LinkProfile::courier()).unwrap();
        pack(&source, &b, (0, u32::MAX), &LinkProfile::courier()).unwrap();

        let ids = |p: &Path| {
            let mut s = Store::new();
            import(&mut s, p, NOW_MIN).unwrap();
            let mut v: Vec<ObjectId> = s.ids_in_order().copied().collect();
            v.sort_by_key(|i| i.0);
            v
        };
        assert_eq!(ids(&a), ids(&b), "an archive must not be a diff");
    }

    /// And an archive carries relayed objects alongside the node's own, so
    /// nothing in it distinguishes what its author wrote.
    #[test]
    fn a_window_carries_everything_in_range_regardless_of_origin() {
        let dir = temp("origin");
        let archive = dir.join("out.krab");
        // The store has no notion of "mine" to filter on -- which is the
        // structural form of this property, and this pins it.
        let source = store_with(4);
        let packed = pack(&source, &archive, (0, u32::MAX), &LinkProfile::courier()).unwrap();
        assert_eq!(packed.objects, source.len());
    }

    /// Re-importing is idempotent and cheap, which matters because a window
    /// archive is mostly things the recipient already has.
    #[test]
    fn re_importing_reports_duplicates_rather_than_failing() {
        let dir = temp("dupes");
        let archive = dir.join("out.krab");
        pack(
            &store_with(4),
            &archive,
            (0, u32::MAX),
            &LinkProfile::courier(),
        )
        .unwrap();

        let mut dest = Store::new();
        assert_eq!(import(&mut dest, &archive, NOW_MIN).unwrap().accepted, 4);
        let second = import(&mut dest, &archive, NOW_MIN).unwrap();
        assert_eq!(second.accepted, 0);
        assert_eq!(second.duplicate, 4);
        assert_eq!(second.refused, 0);
        assert_eq!(dest.len(), 4, "no growth");
    }

    /// **RFC 4 §5.4's ceiling applies to couriers.** A LoRa gateway reading a
    /// stick drops what it cannot carry, silently; refusing to write it is the
    /// only place that can be caught.
    #[test]
    fn a_constrained_profile_does_not_write_objects_it_cannot_carry() {
        let dir = temp("ceiling");
        let archive = dir.join("out.krab");
        let mut source = Store::new();

        let big_header = RoutingHeader {
            version: 1,
            class: 0,
            size_bucket: 2, // 4 096 bytes
            flags: 0,
            expiry_min: NOW_MIN + 40_000,
            tag: Tag([9; 8]),
        };
        let big = canonical_bytes(&big_header, &krab_core::object::example_sealed_body(7)).unwrap();
        source
            .ingest(krab_crypto::object_id(&big), big, NOW_MIN, u32::MAX)
            .unwrap();
        let (id, small) = object(1);
        source.ingest(id, small, NOW_MIN, u32::MAX).unwrap();

        let packed = pack(&source, &archive, (0, u32::MAX), &LinkProfile::lora_sf10()).unwrap();
        assert_eq!(packed.objects, 1, "only the object LoRa can carry");

        // The unconstrained courier profile carries both.
        let all = dir.join("all.krab");
        assert_eq!(
            pack(&source, &all, (0, u32::MAX), &LinkProfile::courier())
                .unwrap()
                .objects,
            2
        );
    }

    /// An empty corpus produces a readable archive rather than a missing file.
    #[test]
    fn an_empty_corpus_still_writes_a_valid_archive() {
        let dir = temp("empty");
        let archive = dir.join("out.krab");
        let packed = pack(
            &Store::new(),
            &archive,
            (0, u32::MAX),
            &LinkProfile::courier(),
        )
        .unwrap();
        assert_eq!(packed.objects, 0);
        assert_eq!(verify(&archive), Ok(0));
        let mut dest = Store::new();
        assert_eq!(import(&mut dest, &archive, NOW_MIN).unwrap().total(), 0);
    }

    /// Importing something that is not an archive fails without panicking and
    /// without touching the corpus.
    #[test]
    fn arbitrary_input_does_not_corrupt_the_store() {
        let dir = temp("garbage");
        let mut dest = Store::new();
        let (id, b) = object(3);
        dest.ingest(id, b, NOW_MIN, u32::MAX).unwrap();

        for junk in [
            &b"not an archive at all"[..],
            &[0xFF; 64],
            &[0x00; 4],
            // A plausible length prefix promising far more than follows.
            &[0xFF, 0xFF, 0xFF, 0x7F, 0x01],
        ] {
            let p = dir.join("junk.bin");
            std::fs::write(&p, junk).unwrap();
            let _ = import(&mut dest, &p, NOW_MIN);
        }
        assert_eq!(dest.len(), 1, "the corpus is untouched");
        assert!(dest.contains(&id));
    }

    /// Importing a path that does not exist is an error, not a panic.
    #[test]
    fn a_missing_archive_is_an_error() {
        let mut s = Store::new();
        assert!(import(&mut s, Path::new("/nonexistent/archive.krab"), NOW_MIN).is_err());
    }

    /// **The manifest names nobody.** It is the one part of the archive that
    /// is not ciphertext, so a lost stick must not also hand over a list of
    /// correspondents.
    #[test]
    fn the_manifest_carries_no_identifiers_or_peers() {
        let dir = temp("manifest");
        let archive = dir.join("out.krab");
        let packed = pack(
            &store_with(3),
            &archive,
            (0, u32::MAX),
            &LinkProfile::courier(),
        )
        .unwrap();
        let m = manifest(&packed);

        assert!(m.contains("objects: 3"), "{m}");
        assert!(
            m.contains("nothing here is signed")
                || m.contains("not signed")
                || m.contains("signed")
        );
        // No object identifiers, no tags, no peer names.
        for id in store_with(3).ids_in_order() {
            let hex = format!("{:02x}{:02x}", id.0[0], id.0[1]);
            assert!(!m.contains(&hex), "{m} leaks an identifier");
        }
        assert!(!m.contains("peer"), "{m}");
    }
}
