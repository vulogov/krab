//! Writing a file so a crash cannot destroy what was already there.
//!
//! `std::fs::write` truncates and then writes. Between those two steps the file
//! is empty, and after a partial write it holds a prefix — so a power cut, an
//! OOM kill, or a laptop lid closing at the wrong moment leaves the old
//! contents gone and the new ones incomplete.
//!
//! For most files that is an inconvenience. For `identity.wrapped` it is
//! **permanent identity loss**, and RFC 7 §11 is explicit about the cost:
//!
//! > "Losing identity means every peer must re-verify out of band, in person,
//! > from scratch."
//!
//! The identity is rewritten on every `init` and on any operation that touches
//! the key hierarchy, so the window is not rare — it is every save. §11
//! anticipated identity loss and prescribed an offline backup for it; it did
//! not anticipate that a routine write was one of the ways to cause it.
//!
//! # The sequence, and why each step is needed
//!
//! ```text
//! 1. write the full contents to <path>.tmp
//! 2. fsync the temporary file          ← contents reach the medium
//! 3. rename <path>.tmp over <path>     ← atomic; readers see old or new
//! 4. fsync the containing directory    ← the rename itself reaches the medium
//! ```
//!
//! Step 2 without step 4 is the common half-measure: the data is durable but
//! the *directory entry pointing at it* may not be, so a crash can leave the
//! rename undone and the temporary file orphaned. Step 4 is a POSIX
//! requirement and a no-op on Windows, where `ReplaceFile` semantics cover it.
//!
//! # What this does not promise
//!
//! A filesystem that lies about `fsync` — and some do, on some hardware —
//! defeats all of it. This is the same category as
//! `Documentation/SECURE-DELETE.md`: the storage stack is not fully
//! controllable from userspace, so the guarantee is *"a crash leaves either the
//! old file or the new one"* and not *"the new one is definitely there"*.
//!
//! That weaker guarantee is the one that matters. Losing a save is
//! recoverable; losing the identity is not.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Write `contents` to `path`, atomically.
///
/// After this returns, a crash at any point leaves `path` holding either its
/// previous contents or the new ones — never a prefix and never nothing.
pub fn write(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let tmp = temp_for(path);

    {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        // **Owner-only, set at creation and not afterwards.**
        //
        // Every file this program writes goes through here, and they were all
        // landing at whatever the umask allowed — typically 0644, so the
        // wrapped identity, the corpus, the peer credentials and the quota
        // records were world-readable on a shared machine. The credentials are
        // the sharpest case: RFC 3 §15 calls them "non-repudiable", so a
        // readable one hands any local user the peer list *with cryptographic
        // proof*.
        //
        // Set in the open flags rather than with a `chmod` afterwards, because
        // a chmod leaves a window in which the file exists at the wider mode —
        // short, and on a multi-user machine that is exactly who is watching.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(contents)?;
        // The contents must reach the medium before the rename publishes them,
        // or the rename can land while the data has not.
        f.sync_all()?;
    }

    // Atomic on POSIX. On Windows `std::fs::rename` replaces an existing file,
    // which is what is wanted here — the older `MoveFile` behaviour of failing
    // on an existing destination would make this a delete-then-rename, and that
    // reintroduces the window this function exists to close.
    std::fs::rename(&tmp, path)?;

    // The rename is a directory operation, so durability of the *entry* needs
    // the directory synced. Without this a crash can leave the old name intact
    // and the temporary file orphaned.
    if let Some(dir) = path.parent() {
        // A directory cannot be opened for writing; read is enough to fsync it.
        // Not supported on every platform — on Windows this fails and is
        // correctly ignored, since `ReplaceFile` semantics already cover it.
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// The temporary path used for `path`.
///
/// Alongside the target rather than in a system temp directory: `rename` is
/// only atomic within a filesystem, and a separate temp directory is often a
/// different one. A cross-device rename falls back to copy-and-delete, which
/// is exactly the non-atomic write being avoided.
pub fn temp_for(path: &Path) -> std::path::PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

/// Remove a stale temporary left by a crash.
///
/// Not automatic on read: a leftover `.tmp` means a write did not complete, and
/// silently deleting it discards the only evidence. Swept at startup, where it
/// can be reported.
pub fn clear_stale(path: &Path) -> bool {
    std::fs::remove_file(temp_for(path)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let d = std::env::temp_dir().join(format!(
            "krab-atomic-{}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed),
            tag
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_file_is_written_and_readable() {
        let dir = temp_dir("basic");
        let p = dir.join("identity.wrapped");
        write(&p, b"sealed identity").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"sealed identity");
    }

    /// **The property.** The previous contents survive until the new ones are
    /// complete — there is no moment where the file is empty or truncated.
    #[test]
    fn the_old_contents_survive_until_the_new_ones_are_complete() {
        let dir = temp_dir("survive");
        let p = dir.join("identity.wrapped");
        write(&p, b"the original identity").unwrap();

        // Simulate a crash after the temporary is written and before the
        // rename: the file still holds what it held.
        let tmp = temp_for(&p);
        std::fs::write(&tmp, b"a partial replacement").unwrap();
        assert_eq!(
            std::fs::read(&p).unwrap(),
            b"the original identity",
            "a crash before the rename must leave the old contents"
        );

        // And completing the write replaces it wholly.
        write(&p, b"the new identity").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"the new identity");
    }

    /// The temporary lives beside the target, because `rename` is only atomic
    /// within a filesystem and a system temp directory is often another one.
    #[test]
    fn the_temporary_is_on_the_same_filesystem() {
        let p = Path::new("/some/dir/identity.wrapped");
        let t = temp_for(p);
        assert_eq!(
            t.parent(),
            p.parent(),
            "a cross-device rename is not atomic"
        );
        assert_ne!(t.file_name(), p.file_name());
    }

    /// A stale temporary is evidence that a write did not finish, so it is
    /// swept deliberately rather than silently on the next read.
    #[test]
    fn a_stale_temporary_is_detectable_and_clearable() {
        let dir = temp_dir("stale");
        let p = dir.join("corpus.krab");
        std::fs::write(temp_for(&p), b"interrupted").unwrap();
        assert!(temp_for(&p).exists());
        assert!(clear_stale(&p));
        assert!(!temp_for(&p).exists());
        assert!(!clear_stale(&p), "already gone");
    }

    /// Writing repeatedly leaves no temporaries behind — a `.tmp` accumulating
    /// beside every file would itself be a copy of the data.
    #[test]
    fn successful_writes_leave_nothing_behind() {
        let dir = temp_dir("clean");
        let p = dir.join("f");
        for i in 0..5 {
            write(&p, format!("round {i}").as_bytes()).unwrap();
        }
        assert!(!temp_for(&p).exists());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
    }

    /// An empty write is a real case — the corpus starts empty.
    #[test]
    fn an_empty_file_round_trips() {
        let dir = temp_dir("empty");
        let p = dir.join("corpus.krab");
        write(&p, b"").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"");
    }

    #[test]
    fn a_missing_directory_is_an_error_not_a_panic() {
        assert!(write(Path::new("/nonexistent/dir/f"), b"x").is_err());
    }
}
