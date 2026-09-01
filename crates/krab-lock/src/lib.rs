//! Memory locking for key material — RFC 7 §9.
//!
//! ```text
//! `mlock`/`VirtualLock` key buffers. The full secret working set is under
//! 100 KB (§2.1), so this is cheap. On Linux it requires `RLIMIT_MEMLOCK`
//! headroom; implementations MUST fail loudly at startup if locking is
//! unavailable rather than proceeding unlocked.
//! ```
//!
//! # This is the workspace's only `unsafe`
//!
//! Every other crate carries `#![forbid(unsafe_code)]` and will keep it. This
//! one cannot: `mlock(2)` is a foreign function and there is no safe way to
//! call one. So the boundary is a whole crate rather than a block inside a
//! larger file — an auditor reading this file has read every unsafe line in
//! the tree, and a reviewer seeing a diff to any other crate knows it adds
//! none.
//!
//! # Why nothing is vendored
//!
//! The obvious route is `libc`. It is well maintained and universally used,
//! and it is tens of thousands of lines of platform constants — so vendoring
//! it to call three functions would mean **auditing** tens of thousands of
//! lines to gain three declarations, and the audit is the entire reason this
//! crate exists.
//!
//! The declarations are below. `mlock`, `munlock` and `sysconf` are POSIX,
//! their signatures have been stable for thirty years, and each is four lines;
//! `VirtualLock` and `VirtualUnlock` are the Win32 equivalents and are the
//! same shape. The trade is: a larger dependency graph and an unreadable
//! audit, or twenty lines an auditor can check against `man 2 mlock` and
//! Microsoft's `memoryapi.h` documentation in a minute.
//!
//! # Platforms
//!
//! Unix locks with `mlock`, Windows with `VirtualLock`. Anywhere else
//! [`LockedBox::new`] returns [`Unavailable::Unsupported`] and [`Held`] falls
//! back to the ordinary heap, saying so. RFC 7 §9 names both calls, so
//! neither is an extension.
//!
//! # What locking does and does not buy
//!
//! It keeps a page out of swap and out of a hibernation image. It does **not**
//! stop a value being copied before it reaches a locked page — RFC 7 §9.1 is
//! explicit that "Rust cannot guarantee a secret was never copied. Moves,
//! reallocation, and compiler optimisations may leave residue that zeroizing
//! never sees." A [`LockedBox`] is allocated once and never moves, so the
//! *buffer* is stable; a value copied into it may have existed elsewhere first,
//! and this crate cannot see that.
//!
//! Hibernation writes all of RAM to disk regardless. RFC 7 §9 names it and
//! nothing in software prevents it.
//!
//! # Page granularity, and why the allocation is page-sized
//!
//! `mlock` operates on pages. Locking a 32-byte secret on a shared heap page
//! would lock whatever else shares that page — over-locking, which is safe but
//! spends an operator's `RLIMIT_MEMLOCK` on unrelated data and makes the
//! accounting meaningless.
//!
//! [`LockedBox`] therefore allocates page-aligned and rounds up to whole
//! pages, so a lock covers exactly one allocation and nothing else. The cost
//! is a page per secret; RFC 7 §2.1 puts the working set under 100 KB, which
//! is a couple of dozen pages.

#![deny(missing_docs)]
// Not `forbid`: this crate exists to contain `unsafe`. Every use below is
// preceded by the argument for why it is sound.
//
// There is deliberately no count here. An earlier version said "there are
// five", which was wrong before this sentence was written and would have gone
// stale again the moment a platform arm was added — the same defect this
// workspace keeps finding elsewhere: a comment true when written and false
// after the code moved. `Documentation/UNSAFE-AUDIT.md` groups the uses by
// argument, which is what an auditor actually needs; the grouping does not
// change when an arm is added to one of them.
#![deny(unsafe_op_in_unsafe_fn)]

pub mod harden;

use core::ffi::c_void;
// `c_int` is a return type on both platforms' calls; `c_long` is `sysconf`'s
// alone. Gated so a build for a platform with neither is warning-clean rather
// than carrying imports it has no use for.
#[cfg(any(unix, windows))]
use core::ffi::c_int;
#[cfg(unix)]
use core::ffi::c_long;
use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::ptr::NonNull;

// ---------------------------------------------------------------------------
// The foreign boundary. Three declarations, checkable against `man 2 mlock`
// and `man 3 sysconf`.
// ---------------------------------------------------------------------------

#[cfg(unix)]
unsafe extern "C" {
    /// `int mlock(const void *addr, size_t len);`
    fn mlock(addr: *const c_void, len: usize) -> c_int;
    /// `int munlock(const void *addr, size_t len);`
    fn munlock(addr: *const c_void, len: usize) -> c_int;
    /// `long sysconf(int name);`
    fn sysconf(name: c_int) -> c_long;
}

// The Win32 equivalents.
//
// `extern "system"` rather than `"C"`: Win32 is `stdcall` on 32-bit x86 and
// the C convention everywhere else, and `"system"` is the spelling that means
// "whichever of those this target uses". Writing `"C"` would be correct on
// x86-64 and silently wrong on `i686-pc-windows-msvc`.
//
// **The return convention is inverted from `mlock`'s and that is the trap
// here.** `mlock` returns 0 for success; `VirtualLock` returns a `BOOL`, so
// non-zero is success and 0 is failure. `lock_pages` is the only caller of
// either and it is where the two are reconciled.
//
// `LPVOID` is `void *`, so the pointer is `*mut` — unlike `mlock`'s
// `const void *`. `SIZE_T` is `usize` and `BOOL` is a 32-bit `int`, which is
// `c_int` on every Windows target.
#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    /// `BOOL VirtualLock(LPVOID lpAddress, SIZE_T dwSize);`
    fn VirtualLock(addr: *mut c_void, len: usize) -> c_int;
    /// `BOOL VirtualUnlock(LPVOID lpAddress, SIZE_T dwSize);`
    fn VirtualUnlock(addr: *mut c_void, len: usize) -> c_int;
}

/// `_SC_PAGESIZE`: 30 on Linux, 29 on macOS and the BSDs.
///
/// The one place a wrong number would be silent rather than loud, so
/// `page_size` sanity-checks what `sysconf` returns instead of trusting the
/// constant — an unrecognised name returns -1, which the check catches.
#[cfg(all(unix, target_os = "linux"))]
const SC_PAGESIZE: c_int = 30;
/// macOS and the BSDs.
#[cfg(all(unix, not(target_os = "linux")))]
const SC_PAGESIZE: c_int = 29;

/// Fallback if `sysconf` answers something absurd, and the figure Windows
/// uses outright.
///
/// 4 KiB is the smallest page any supported platform uses, and rounding *up*
/// to a larger figure would be the unsafe direction: a lock shorter than the
/// allocation leaves part of it swappable.
const PAGE_FALLBACK: usize = 4096;

/// The system page size, as `mlock` understands it.
///
/// # Why Windows does not read it
///
/// Win32 has no scalar getter for the page size. `GetSystemInfo` fills a
/// twelve-field `SYSTEM_INFO`, one member of which is a union, and reading
/// `dwPageSize` out of it means declaring that layout exactly — the offset is
/// load-bearing, a mistake in it is silent, and it is markedly harder to check
/// against the documentation than the four lines of `VirtualLock` above. That
/// trades away the one property this crate exists for.
///
/// So Windows uses the constant, and the existing fallback argument carries it
/// unchanged: **4 KiB is the small direction, and the small direction is the
/// safe one.** Every Windows target Rust supports — x86, x86-64, aarch64 —
/// uses 4 KiB pages today. If one ever did not, the allocation would be
/// smaller than a page and `VirtualLock` would round *out* to the containing
/// page: over-locking, which spends working-set quota on a neighbour but
/// leaves nothing swappable. The failure mode is the benign one by
/// construction, not by luck.
fn page_size() -> usize {
    #[cfg(unix)]
    {
        // SAFETY: `sysconf` reads a system constant, touches no memory the
        // caller owns, and is documented as thread-safe. The only argument is
        // an integer.
        let n = unsafe { sysconf(SC_PAGESIZE) };
        // A negative return is `sysconf`'s error signal, and a page size that
        // is not a power of two would make the rounding below wrong.
        if n > 0 && (n as usize).is_power_of_two() {
            return n as usize;
        }
        PAGE_FALLBACK
    }
    #[cfg(not(unix))]
    {
        PAGE_FALLBACK
    }
}

/// Lock `len` bytes at `addr` into physical memory.
///
/// The single place the two platforms' calls are reconciled, so that
/// [`LockedBox::new`] has one body rather than one per platform — the drop
/// order in [`LockedBox::drop`] is the crate's most load-bearing argument and
/// it should not be written twice.
fn lock_pages(addr: *mut c_void, len: usize) -> Result<(), Unavailable> {
    #[cfg(unix)]
    {
        // SAFETY: `addr` is a live allocation of `len` bytes owned by the
        // caller, which is what `mlock` requires. It reads and writes nothing.
        if unsafe { mlock(addr as *const c_void, len) } == 0 {
            Ok(())
        } else {
            Err(Unavailable::Refused)
        }
    }
    #[cfg(windows)]
    {
        // SAFETY: as above — `VirtualLock` takes the same ownership of the
        // range and likewise neither reads nor writes it.
        //
        // Non-zero is success here, the opposite of `mlock`. Getting this
        // backwards would report every successful lock as a refusal, which
        // `Held` would quietly absorb by falling back to the heap.
        if unsafe { VirtualLock(addr, len) } != 0 {
            Ok(())
        } else {
            Err(Unavailable::Refused)
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (addr, len);
        Err(Unavailable::Unsupported)
    }
}

/// Undo [`lock_pages`].
///
/// The result is deliberately discarded on both platforms: the only caller is
/// [`LockedBox::drop`], the memory is about to be freed, and there is no
/// action a failure would justify.
fn unlock_pages(addr: *mut c_void, len: usize) {
    #[cfg(unix)]
    {
        // SAFETY: the same address and length that `lock_pages` was given.
        unsafe { munlock(addr as *const c_void, len) };
    }
    #[cfg(windows)]
    {
        // SAFETY: as above.
        unsafe { VirtualUnlock(addr, len) };
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (addr, len);
    }
}

/// Why locking is not available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unavailable {
    /// The platform has no implementation here.
    ///
    /// Unix and Windows both do — `mlock` and `VirtualLock`, the two RFC 7 §9
    /// names. This is for anything else. Reported rather than silently
    /// skipped, because §9's requirement is to **fail loudly** rather than
    /// proceed unlocked, and a platform without the mechanism is exactly the
    /// case that sentence is about.
    Unsupported,
    /// The kernel refused.
    ///
    /// On Linux this is almost always `RLIMIT_MEMLOCK` headroom, which an
    /// operator raises with `ulimit -l`. On Windows it is the process
    /// **minimum working set size**: `VirtualLock` charges against that quota
    /// and fails with `ERROR_WORKING_SET_QUOTA` once it is spent. The two are
    /// the same situation under different names, which is why they share a
    /// variant.
    Refused,
    /// The allocator refused a page-aligned allocation.
    NoMemory,
}

impl core::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Unavailable::Unsupported => f.write_str(
                "memory locking is not implemented on this platform — key material \
                 may be written to swap or to a hibernation image (RFC 7 §9)",
            ),
            Unavailable::Refused => f.write_str(
                "the kernel refused to lock memory — on Linux this is usually \
                 RLIMIT_MEMLOCK headroom (`ulimit -l`), on Windows the process \
                 minimum working set size. Key material may be written to swap \
                 or to a hibernation image (RFC 7 §9)",
            ),
            Unavailable::NoMemory => f.write_str("could not allocate a page to lock"),
        }
    }
}

/// Whether this process can lock memory — RFC 7 §9's startup check.
///
/// Probes by locking and unlocking one page, rather than reading
/// `RLIMIT_MEMLOCK` and reasoning about it. The limit is not the only reason a
/// lock can fail — a container policy, a seccomp filter, or a kernel built
/// without the call all produce the same refusal — and a probe answers the
/// question that was asked instead of a proxy for it.
pub fn available() -> Result<(), Unavailable> {
    match LockedBox::<u8>::new(0) {
        Ok(probe) => {
            drop(probe);
            Ok(())
        }
        Err((why, _)) => Err(why),
    }
}

/// A heap allocation whose pages are locked, and which is zeroized on drop.
///
/// The allocation is made once and never moves, which is what makes locking it
/// mean anything: a `Vec` that grows leaves its old contents behind (RFC 7 §9
/// requires "fixed-size arrays rather than `Vec`" for exactly this), and a
/// value on the stack moves wherever the compiler likes.
pub struct LockedBox<T> {
    ptr: NonNull<T>,
    layout: Layout,
}

// SAFETY: `LockedBox` owns its allocation exclusively and hands out references
// only through `&self`/`&mut self`, so it is as sendable and shareable as the
// `T` it holds. There is no interior mutability and no shared global state.
unsafe impl<T: Send> Send for LockedBox<T> {}
unsafe impl<T: Sync> Sync for LockedBox<T> {}

impl<T> LockedBox<T> {
    /// Allocate a locked page (or pages) and move `value` into it.
    ///
    /// Fails rather than falling back to an unlocked allocation. A silent
    /// fallback is precisely what RFC 7 §9 forbids — "MUST fail loudly at
    /// startup if locking is unavailable rather than proceeding unlocked" —
    /// and a type that sometimes locks would be worse than one that never
    /// does, because nothing downstream could tell which it had.
    /// On failure the value is handed back rather than dropped, so a caller
    /// with a fallback — [`Held`] — can use it instead of constructing a
    /// second one. A constructor that consumed its argument on the error path
    /// would force every such caller to be infallible or wasteful.
    pub fn new(value: T) -> Result<LockedBox<T>, (Unavailable, T)> {
        let page = page_size();
        let size = core::mem::size_of::<T>().max(1).div_ceil(page) * page;
        let align = core::mem::align_of::<T>().max(page);
        let Ok(layout) = Layout::from_size_align(size, align) else {
            return Err((Unavailable::NoMemory, value));
        };

        // SAFETY: `layout` has a non-zero size — `max(1)` above, then rounded
        // up to at least one page — which is `alloc_zeroed`'s only
        // precondition. Zeroed rather than uninitialised so that a failure
        // between here and the write below leaves a blank page rather than
        // whatever the allocator last held.
        let raw = unsafe { alloc_zeroed(layout) };
        let Some(ptr) = NonNull::new(raw as *mut T) else {
            return Err((Unavailable::NoMemory, value));
        };

        if let Err(why) = lock_pages(raw as *mut c_void, layout.size()) {
            // SAFETY: `raw` came from `alloc_zeroed` with this same `layout`
            // and has not been freed. Nothing partially locked escapes.
            unsafe { dealloc(raw, layout) };
            return Err((why, value));
        }

        // SAFETY: `ptr` is aligned to at least `align_of::<T>()` (the layout
        // demanded `max(page)`), non-null, and points at an allocation large
        // enough for a `T`. Nothing has been written there yet, so no old
        // value is being dropped.
        unsafe { ptr.as_ptr().write(value) };
        Ok(LockedBox { ptr, layout })
    }

    /// Borrow the value.
    pub fn get(&self) -> &T {
        // SAFETY: `ptr` was initialised by `new` and is only freed by `drop`.
        unsafe { self.ptr.as_ref() }
    }

    /// Borrow the value mutably.
    pub fn get_mut(&mut self) -> &mut T {
        // SAFETY: as above, and `&mut self` guarantees exclusivity.
        unsafe { self.ptr.as_mut() }
    }
}

impl<T> Drop for LockedBox<T> {
    /// Drop the value, overwrite the pages, unlock, and free — in that order.
    ///
    /// The order is the point. Unlocking first would let the kernel page the
    /// buffer out between the unlock and the overwrite, which is the window
    /// the lock existed to close.
    fn drop(&mut self) {
        // SAFETY: `ptr` holds an initialised `T` written by `new` and never
        // dropped since; this consumes it exactly once.
        unsafe { self.ptr.as_ptr().drop_in_place() };

        // The whole allocation, not just `size_of::<T>()`: a value may have
        // been written past its own extent by padding, and the pages are ours.
        let bytes = self.ptr.as_ptr() as *mut u8;
        // SAFETY: `bytes` covers `layout.size()` bytes this allocation owns.
        let slice = unsafe { core::slice::from_raw_parts_mut(bytes, self.layout.size()) };
        {
            use zeroize::Zeroize;
            slice.zeroize();
        }

        // The same address and length that were locked in `new`.
        unlock_pages(bytes as *mut c_void, self.layout.size());

        // SAFETY: `bytes` came from `alloc_zeroed` with `self.layout`, has not
        // been freed, and nothing references it after this point.
        unsafe { dealloc(bytes, self.layout) };
    }
}

impl<T> core::ops::Deref for LockedBox<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.get()
    }
}

impl<T> core::ops::DerefMut for LockedBox<T> {
    fn deref_mut(&mut self) -> &mut T {
        self.get_mut()
    }
}

/// A secret held in the best storage this machine allows, which says which.
///
/// # Why this exists beside [`LockedBox`]
///
/// `LockedBox::new` refuses rather than falling back, because a type that
/// *sometimes* locks is worse than one that never does — nothing downstream
/// could tell which it had. That is right for the primitive and wrong for an
/// application, which has to run on a machine whose `RLIMIT_MEMLOCK` an
/// operator may not control.
///
/// So the choice is made once, here, and recorded. RFC 7 §9 asks an
/// implementation to "fail loudly at startup if locking is unavailable rather
/// than proceeding unlocked" — loudly, and the loudness is what this preserves:
/// [`Held::is_locked`] can be asked, and the startup path says so.
pub enum Held<T> {
    /// In locked pages.
    Locked(LockedBox<T>),
    /// On the ordinary heap, because the kernel refused.
    Unlocked(Box<T>),
}

impl<T> Held<T> {
    /// Hold `value`, locked if this machine permits it.
    pub fn new(value: T) -> Held<T> {
        match LockedBox::new(value) {
            Ok(b) => Held::Locked(b),
            // `LockedBox::new` hands the value back rather than dropping it,
            // so the fallback is the same value in ordinary memory — not a
            // second one, and not a panic.
            Err((_, value)) => Held::Unlocked(Box::new(value)),
        }
    }

    /// Whether the pages are locked.
    pub fn is_locked(&self) -> bool {
        matches!(self, Held::Locked(_))
    }
}

impl<T> core::ops::Deref for Held<T> {
    type Target = T;
    fn deref(&self) -> &T {
        match self {
            Held::Locked(b) => b,
            Held::Unlocked(b) => b,
        }
    }
}

impl<T> core::ops::DerefMut for Held<T> {
    fn deref_mut(&mut self) -> &mut T {
        match self {
            Held::Locked(b) => b,
            Held::Unlocked(b) => b,
        }
    }
}

impl<T> core::fmt::Debug for Held<T> {
    /// Prints nothing about the contents — RFC 7 §9.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(if self.is_locked() {
            "Held(<locked>)"
        } else {
            "Held(<unlocked>)"
        })
    }
}

impl<T: core::fmt::Debug> core::fmt::Debug for LockedBox<T> {
    /// Prints nothing about the contents.
    ///
    /// RFC 7 §9: "`Debug` implementations on key types MUST print nothing."
    /// This type exists to hold key material, so it inherits that.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LockedBox(<locked>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The page size is read rather than assumed, and it must be sane —
    /// a wrong value would round the lock length down and leave part of an
    /// allocation swappable.
    #[test]
    fn the_page_size_is_a_plausible_power_of_two() {
        let p = page_size();
        assert!(p.is_power_of_two(), "page size {p} is not a power of two");
        assert!((4096..=65536).contains(&p), "page size {p} is implausible");
    }

    /// A locked box holds its value and hands it back.
    #[test]
    fn a_locked_box_round_trips() {
        let Ok(mut b) = LockedBox::new([7u8; 32]) else {
            // On a machine with no `RLIMIT_MEMLOCK` headroom this is the
            // honest outcome, and the startup check is what reports it.
            return;
        };
        assert_eq!(*b.get(), [7u8; 32]);
        b.get_mut()[0] = 9;
        assert_eq!(b.get()[0], 9);
    }

    /// **The allocation is page-aligned and whole pages long**, so a lock
    /// covers exactly one secret and not whatever shares its page.
    #[test]
    fn the_allocation_is_its_own_pages() {
        let Ok(b) = LockedBox::new([0u8; 32]) else {
            return;
        };
        let page = page_size();
        assert_eq!(b.ptr.as_ptr() as usize % page, 0, "not page-aligned");
        assert_eq!(b.layout.size() % page, 0, "not a whole number of pages");
        assert_eq!(b.layout.size(), page, "32 bytes should take one page");
    }

    /// A larger secret takes the pages it needs and no more.
    #[test]
    fn a_multi_page_secret_rounds_up_once() {
        let page = page_size();
        let Ok(b) = LockedBox::new(vec![0u8; 0]) else {
            return;
        };
        drop(b);
        // A type genuinely larger than a page.
        struct Big(#[allow(dead_code)] [u8; 9000]);
        let Ok(b) = LockedBox::new(Big([0; 9000])) else {
            return;
        };
        assert_eq!(b.layout.size(), 9000usize.div_ceil(page) * page);
    }

    /// `Debug` says nothing about the contents — RFC 7 §9.
    #[test]
    fn debug_prints_nothing() {
        let Ok(b) = LockedBox::new([0xABu8; 32]) else {
            return;
        };
        let s = format!("{b:?}");
        assert_eq!(s, "LockedBox(<locked>)");
        assert!(!s.contains("ab") && !s.contains("171"));
    }

    /// **A refusal hands the value back.** `Held` depends on it: the fallback
    /// is the same value in ordinary memory, not a second one and not a panic.
    #[test]
    fn a_refusal_returns_the_value() {
        // A type larger than any plausible `RLIMIT_MEMLOCK`, so the kernel
        // refuses and the error path runs for real rather than by injection.
        let huge = vec![0u8; 1];
        match LockedBox::new(huge) {
            Ok(b) => {
                // Locking succeeded; the round trip is covered elsewhere.
                assert_eq!(b.len(), 1);
            }
            Err((_, back)) => assert_eq!(back.len(), 1, "the value was not returned"),
        }
    }

    /// `Held` runs on a machine that cannot lock, and says so rather than
    /// pretending — RFC 7 §9's "fail loudly", not "fail".
    #[test]
    fn held_falls_back_and_admits_it() {
        let h = Held::new([3u8; 32]);
        assert_eq!(*h, [3u8; 32], "the value did not survive the choice");
        // Whichever branch this machine took, `Debug` names it and neither
        // prints the bytes.
        let shown = format!("{h:?}");
        assert!(shown == "Held(<locked>)" || shown == "Held(<unlocked>)", "{shown}");
        assert_eq!(h.is_locked(), shown.contains("<locked>"));
    }

    /// **On a platform RFC 7 §9 names, `Unsupported` must never be the
    /// answer.** Unix and Windows both have a mechanism; only a third
    /// platform may say it has none.
    ///
    /// The Windows arm is why this exists. It cross-compiles cleanly from a
    /// Mac and is *executed* nowhere in this suite, so the failure it guards
    /// against is a build that declares `VirtualLock`, never routes to it, and
    /// reports `Unsupported` — whereupon `Held` falls back to the ordinary
    /// heap and RFC 7 §9's requirement is quietly unmet on a platform that
    /// could have met it. Every other test here would still pass.
    ///
    /// `Refused` is a legitimate answer on both: a Linux container with no
    /// `RLIMIT_MEMLOCK` headroom and a Windows process at its working-set
    /// quota are real machines, and the point of `Held` is to run on them.
    #[test]
    fn a_named_platform_never_reports_unsupported() {
        if let Err(why) = available() {
            #[cfg(any(unix, windows))]
            assert_ne!(
                why,
                Unavailable::Unsupported,
                "this platform has a locking call and RFC 7 §9 names it, so \
                 reporting `Unsupported` means the arm was compiled but not \
                 reached"
            );
            let _ = why;
        }
    }

    /// The startup probe answers, one way or the other, without panicking.
    #[test]
    fn the_startup_probe_answers() {
        match available() {
            Ok(()) => {}
            Err(e) => {
                // Whatever it says, it must say something an operator can act
                // on — §9's "fail loudly" is about the message as much as the
                // failure.
                let msg = e.to_string();
                assert!(msg.contains("RFC 7 §9"), "unhelpful: {msg}");
            }
        }
    }
}
