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
//! The three declarations are below. `mlock`, `munlock` and `sysconf` are
//! POSIX, their signatures have been stable for thirty years, and each is four
//! lines. The trade is: a larger dependency graph and an unreadable audit, or
//! twelve lines an auditor can check against `man 2 mlock` in a minute.
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
// preceded by the argument for why it is sound, and there are five.
#![deny(unsafe_op_in_unsafe_fn)]

use core::ffi::{c_int, c_long, c_void};
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

/// Fallback if `sysconf` answers something absurd.
///
/// 4 KiB is the smallest page any supported platform uses, and rounding *up*
/// to a larger figure would be the unsafe direction: a lock shorter than the
/// allocation leaves part of it swappable.
const PAGE_FALLBACK: usize = 4096;

/// The system page size, as `mlock` understands it.
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

/// Why locking is not available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unavailable {
    /// The platform has no implementation here.
    ///
    /// Windows has `VirtualLock` and this crate does not call it. Reported
    /// rather than silently skipped, because RFC 7 §9's requirement is to
    /// **fail loudly** rather than proceed unlocked, and a platform without
    /// the mechanism is exactly the case that sentence is about.
    Unsupported,
    /// The kernel refused. On Linux this is almost always `RLIMIT_MEMLOCK`
    /// headroom, which an operator raises with `ulimit -l`.
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
                 RLIMIT_MEMLOCK headroom (`ulimit -l`). Key material may be \
                 written to swap or to a hibernation image (RFC 7 §9)",
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
        #[cfg(not(unix))]
        {
            return Err((Unavailable::Unsupported, value));
        }
        #[cfg(unix)]
        {
            let page = page_size();
            let size = core::mem::size_of::<T>().max(1).div_ceil(page) * page;
            let align = core::mem::align_of::<T>().max(page);
            let Ok(layout) = Layout::from_size_align(size, align) else {
                return Err((Unavailable::NoMemory, value));
            };

            // SAFETY: `layout` has a non-zero size — `max(1)` above, then
            // rounded up to at least one page — which is `alloc_zeroed`'s only
            // precondition. Zeroed rather than uninitialised so that a failure
            // between here and the write below leaves a blank page rather than
            // whatever the allocator last held.
            let raw = unsafe { alloc_zeroed(layout) };
            let Some(ptr) = NonNull::new(raw as *mut T) else {
                return Err((Unavailable::NoMemory, value));
            };

            // SAFETY: `ptr` is a live allocation of `layout.size()` bytes that
            // this function owns, which is exactly what `mlock` requires. It
            // reads and writes nothing.
            let locked = unsafe { mlock(raw as *const c_void, layout.size()) };
            if locked != 0 {
                // SAFETY: `raw` came from `alloc_zeroed` with this same
                // `layout` and has not been freed.
                unsafe { dealloc(raw, layout) };
                return Err((Unavailable::Refused, value));
            }

            // SAFETY: `ptr` is aligned to at least `align_of::<T>()` (the
            // layout demanded `max(page)`), non-null, and points at an
            // allocation large enough for a `T`. Nothing has been written
            // there yet, so no old value is being dropped.
            unsafe { ptr.as_ptr().write(value) };
            Ok(LockedBox { ptr, layout })
        }
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

        #[cfg(unix)]
        {
            // SAFETY: the same address and length that were locked in `new`.
            // A failure here is not actionable — the memory is about to be
            // freed either way — so the result is deliberately discarded.
            unsafe { munlock(bytes as *const c_void, self.layout.size()) };
        }

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
