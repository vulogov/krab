//! Overwriting before deleting — defence in depth, and **not** a security
//! property.
//!
//! # What RFC 7 §4 says, and why this exists anyway
//!
//! > "**Implementations MUST NOT rely on file deletion or overwriting for any
//! > forward-secrecy property.** Where a specification in this series says
//! > *erase*, it means destroy the wrapping key."
//!
//! That is correct and this module does not contradict it. A flash translation
//! layer may have written a block anywhere, copied it during wear levelling, or
//! retained it in an over-provisioned region the filesystem cannot address.
//! None of that is visible from userspace and no `fsync` changes it. On a
//! copy-on-write filesystem — btrfs, ZFS, APFS — an overwrite may not touch the
//! original extent at all. On any of those, this function does nothing useful.
//!
//! **So every forward-secrecy property in Krab comes from destroying a key**,
//! and that is unchanged: `Kek`, `Hierarchy::shred_epoch`, and
//! `Reservoir::destroy` are where erasure actually happens.
//!
//! What this adds is the case those do not cover: **material that was never
//! wrapped.** The clearest is `peer.pad` — this node's own reservoir
//! contribution, written in the clear because it has to be handed to a person.
//! There is no key whose destruction removes it. Overwriting is the only thing
//! available, and on rotational media and on filesystems that overwrite in
//! place it works.
//!
//! The honest summary: this reduces the number of situations in which a
//! seized disk yields something, and it converts none of them into a
//! guarantee. It is applied because it is nearly free, not because it is
//! sufficient.
//!
//! # Why random rather than zeros
//!
//! Zeros are as effective against media analysis and worse for everything
//! else: a region of zeros on a device is visibly *a region that was
//! deliberately cleared*, which is a statement about the operator. Random
//! bytes are indistinguishable from the ciphertext that surrounds them, and
//! every other file Krab writes is ciphertext.

use krab_crypto::rng::Rng;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

/// Overwrite `path` with random bytes, flush to the device, and remove it.
///
/// Returns whether the file was there. A missing file is not an error — the
/// callers are cleanup paths, and "already gone" is the outcome they wanted.
///
/// **Never treat a `true` return as a guarantee the data is unrecoverable.**
/// See the module documentation.
pub fn remove(path: &Path, rng: &mut impl Rng) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    overwrite(path, meta.len(), rng);
    std::fs::remove_file(path).is_ok()
}

/// Overwrite in place without removing.
///
/// The length is preserved deliberately: writing fewer bytes leaves the tail,
/// and writing more may allocate new blocks and leave the original untouched —
/// which would be worse than doing nothing, because it looks like success.
fn overwrite(path: &Path, len: u64, rng: &mut impl Rng) {
    let Ok(mut f) = OpenOptions::new().write(true).open(path) else {
        return;
    };
    if f.seek(SeekFrom::Start(0)).is_err() {
        return;
    }

    let mut buf = [0u8; 4096];
    let mut written = 0u64;
    while written < len {
        let n = ((len - written) as usize).min(buf.len());
        rng.fill(&mut buf[..n]);
        if f.write_all(&buf[..n]).is_err() {
            return;
        }
        written += n as u64;
    }
    // Force it to the device. Without this the overwrite may live only in the
    // page cache and never reach the medium before the unlink frees the
    // blocks — which is the failure mode that makes this look like it worked.
    let _ = f.flush();
    let _ = f.sync_all();
}

/// Remove every file in a directory whose name matches, shredding each.
///
/// Used by `wipe`, which must not leave a peer-link or a wrapped reservoir
/// behind — those are useless without the KEK, but a list of who this node
/// peered with is not nothing.
pub fn remove_matching(dir: &Path, pred: impl Fn(&str) -> bool, rng: &mut impl Rng) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut n = 0;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if pred(&name) && remove(&entry.path(), rng) {
            n += 1;
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use krab_crypto::rng::NotRandom;

    fn temp(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let d = std::env::temp_dir().join(format!(
            "krab-shred-{}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed),
            tag
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_file_is_overwritten_and_removed() {
        let dir = temp("basic");
        let p = dir.join("secret");
        std::fs::write(&p, b"half a one-time pad").unwrap();

        assert!(remove(&p, &mut NotRandom::seeded(1)));
        assert!(!p.exists());
        assert!(!remove(&p, &mut NotRandom::seeded(1)), "already gone");
    }

    /// **The bytes are gone from the file before it is unlinked**, which is
    /// the part that can be tested. Whether they are gone from the *device*
    /// is not observable from here, and the module says so.
    #[test]
    fn the_content_is_replaced_before_the_unlink() {
        let dir = temp("content");
        let p = dir.join("pad");
        let secret = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        std::fs::write(&p, secret).unwrap();

        overwrite(&p, secret.len() as u64, &mut NotRandom::seeded(2));
        let after = std::fs::read(&p).unwrap();
        assert_eq!(after.len(), secret.len(), "the length is preserved");
        assert_ne!(after, secret);
        assert!(!after.iter().all(|&b| b == b'A'));
    }

    /// **Random, not zeros.** A cleared region of zeros is visibly a region
    /// someone deliberately cleared; random bytes look like the ciphertext
    /// every other Krab file contains.
    #[test]
    fn the_overwrite_is_random_not_zeros() {
        let dir = temp("random");
        let p = dir.join("f");
        std::fs::write(&p, vec![0xAAu8; 4096]).unwrap();
        overwrite(&p, 4096, &mut NotRandom::seeded(3));
        let after = std::fs::read(&p).unwrap();

        let zeros = after.iter().filter(|&&b| b == 0).count();
        assert!(
            zeros < 200,
            "{zeros} zero bytes in 4 KiB looks like a zero-fill"
        );
        // And two shreds differ, so the pattern is not a constant.
        std::fs::write(&p, vec![0xAAu8; 4096]).unwrap();
        overwrite(&p, 4096, &mut NotRandom::seeded(4));
        assert_ne!(std::fs::read(&p).unwrap(), after);
    }

    /// Files larger than the buffer are covered to the last byte.
    #[test]
    fn a_large_file_is_covered_completely() {
        let dir = temp("large");
        let p = dir.join("big");
        let n = 4096 * 3 + 17;
        std::fs::write(&p, vec![0x5Au8; n]).unwrap();
        overwrite(&p, n as u64, &mut NotRandom::seeded(5));
        let after = std::fs::read(&p).unwrap();
        assert_eq!(after.len(), n);
        // Random bytes contain 0x5A about 1/256 of the time, so ~48 in 12 KiB
        // is expected; an *unshredded* region would be all 0x5A.
        let runs = after
            .windows(64)
            .filter(|w| w.iter().all(|&b| b == 0x5A))
            .count();
        assert_eq!(runs, 0, "a 64-byte run of the original survived");
        // The tail specifically — an off-by-one here leaves the end intact.
        assert!(after[n - 17..].iter().any(|&b| b != 0x5A));
    }

    #[test]
    fn an_empty_file_is_handled() {
        let dir = temp("empty");
        let p = dir.join("nothing");
        std::fs::write(&p, b"").unwrap();
        assert!(remove(&p, &mut NotRandom::seeded(6)));
        assert!(!p.exists());
    }

    #[test]
    fn a_directory_is_not_shredded() {
        let dir = temp("dir");
        let sub = dir.join("subdir");
        std::fs::create_dir(&sub).unwrap();
        assert!(!remove(&sub, &mut NotRandom::seeded(7)), "not a file");
        assert!(sub.exists());
    }

    #[test]
    fn matching_files_are_removed_and_others_left() {
        let dir = temp("matching");
        for name in ["a.link", "b.link", "keep.txt", "c.reservoir"] {
            std::fs::write(dir.join(name), b"data").unwrap();
        }
        let n = remove_matching(
            &dir,
            |s| s.ends_with(".link") || s.ends_with(".reservoir"),
            &mut NotRandom::seeded(8),
        );
        assert_eq!(n, 3);
        assert!(dir.join("keep.txt").exists());
        assert!(!dir.join("a.link").exists());
    }
}
