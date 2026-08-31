# The unsafe boundary — `krab-lock`, audited

RFC 7 §9 requires memory locking:

> `mlock`/`VirtualLock` key buffers. The full secret working set is under
> 100 KB (§2.1), so this is cheap. On Linux it requires `RLIMIT_MEMLOCK`
> headroom; implementations MUST fail loudly at startup if locking is
> unavailable rather than proceeding unlocked.

`mlock(2)` is a foreign function and there is no safe way to call one, so this
workspace has an unsafe boundary. This document is the audit of it.

## Why not a dependency

The obvious route is `libc`. It is well maintained, universally used, and tens
of thousands of lines of platform constants — so vendoring it to call three
functions would mean **auditing** tens of thousands of lines to gain three
declarations. The audit is the entire reason the boundary is a crate rather
than a block, and a dependency that cannot be audited defeats it.

`region` and `memsec` were also considered. Both are larger than the twelve
lines below, both bring their own dependency on `libc`, and neither does
anything this does not.

So nothing is vendored. The three declarations are written out, and each is
checkable against `man 2 mlock` and `man 3 sysconf` in a minute:

```rust
unsafe extern "C" {
    fn mlock(addr: *const c_void, len: usize) -> c_int;
    fn munlock(addr: *const c_void, len: usize) -> c_int;
    fn sysconf(name: c_int) -> c_long;
}
```

`usize` is the correct Rust spelling of `size_t` on every supported target;
`c_int` and `c_long` come from `core::ffi`, so the widths are the compiler's
and not this file's guess.

## Why a whole crate

Every other crate in the workspace carries `#![forbid(unsafe_code)]` and keeps
it. `krab-lock` carries `#![deny(unsafe_op_in_unsafe_fn)]` instead, and holds
all of it.

The value of that is entirely in one test —
`unsafe_code_lives_only_in_the_crate_that_exists_for_it` — which walks every
source file in the workspace and fails if the keyword appears anywhere else. It
reads the sources rather than trusting the attributes, because an attribute can
be removed in the same commit that adds the code it was guarding. Verified
against a deliberate violation.

So: an auditor who has read `crates/krab-lock/src/lib.rs` has read every unsafe
line in the tree, and a diff to any other crate cannot quietly add one.

## The unsafe operations, one at a time

Seven, and each carries its argument in the source beside it. Restated here so
this document is checkable without the file open.

### 1. `sysconf(_SC_PAGESIZE)`

Reads a system constant. Touches no memory the caller owns, takes one integer,
and is documented thread-safe. The return is validated before use — negative is
`sysconf`'s error signal, and a non-power-of-two would make the rounding wrong,
so both fall back to 4 KiB.

**The fallback direction matters.** 4 KiB is the smallest page any supported
platform uses. Falling back to a *larger* figure would be the unsafe direction:
`mlock` rounds a length down to a page boundary, so a lock computed from too
large a page could leave the tail of an allocation swappable.

### 2. `alloc_zeroed(layout)`

`layout` has a non-zero size — `size_of::<T>().max(1)` rounded up to at least
one page — which is `alloc_zeroed`'s only precondition. Zeroed rather than
uninitialised, so a failure between the allocation and the write leaves a blank
page rather than whatever the allocator last held there.

### 3. `mlock(raw, layout.size())`

`raw` is a live allocation of exactly `layout.size()` bytes that this function
owns. `mlock` reads and writes nothing. A non-zero return deallocates and
returns `Unavailable::Refused`, so no partially-locked allocation escapes.

### 4. `ptr.write(value)`

`ptr` is non-null, aligned to at least `align_of::<T>()` — the layout demanded
`max(page)`, and a page is a large power of two — and points at an allocation
large enough for a `T`. Nothing has been written there yet, so `write` is not
dropping an old value.

### 5. `ptr.as_ref()` / `as_mut()`

The pointer was initialised by `new` and is freed only by `drop`. `&mut self`
gives exclusivity for the mutable form.

### 6. `drop_in_place`, then `from_raw_parts_mut`, then `munlock`, then `dealloc`

**The order is the audit's most load-bearing point.** Unlocking before
overwriting would let the kernel page the buffer out between the two, which is
the window the lock existed to close. So: drop the value, overwrite the whole
allocation, unlock, free.

The overwrite covers `layout.size()` rather than `size_of::<T>()` — padding is
ours and may have been written through.

`munlock`'s result is deliberately discarded: the memory is about to be freed,
and there is no action a failure would justify.

### 7. `unsafe impl Send` / `Sync`

`LockedBox` owns its allocation exclusively, hands out references only through
`&self`/`&mut self`, has no interior mutability, and touches no global state.
So it is exactly as sendable and shareable as the `T` it holds, and both impls
are bounded on `T`.

## What this buys, and what it does not

It keeps a page out of swap and out of a hibernation image. That is all.

RFC 7 §9.1 is the honest statement and it is unchanged by this work:

> **Rust cannot guarantee a secret was never copied.** Moves, reallocation, and
> compiler optimisations may leave residue that zeroizing never sees. Fixed
> buffers and `mlock` reduce the exposure substantially; nothing eliminates it.

A `LockedBox` is allocated once and never moves, so the *buffer* is stable. A
value copied into it may have existed elsewhere first, and this crate cannot
see that. **Hibernation writes all of RAM to disk regardless**; RFC 7 §9 names
it and nothing in software prevents it.

## What is locked today

| secret | held in | note |
|---|---|---|
| the identity — three private keys | `Held<Identity>` | RFC 7 §11's irreplaceable one |
| epoch key `W_N` | **not locked** | `Option<[u8; 32]>`, copied on every read |
| KEK | **not locked** | transient; derived, used, dropped |
| reservoir roots | **not locked** | inside per-peer records |
| the tag table | **not locked** | RFC 2 §4.3 and §8 both ask for it |

**Only the identity, and the honesty is the point.** `epoch_key` is
`Option<[u8; 32]>` and every one of its forty-odd readers copies it onto the
stack — locking the field would leave the copies unlocked and buy almost
nothing while looking like it had bought everything. Moving those to references
is a real change to how key material is handed around, and it belongs in its
own pass rather than smuggled into this one.

The identity is the right first case because it is read **by reference**
everywhere, lives for the whole process, and is the secret RFC 7 §11 says
cannot be replaced: "losing identity means every peer must re-verify out of
band, in person, from scratch."

## `Held`, and why it is not `LockedBox`

`LockedBox::new` refuses rather than falling back — a type that *sometimes*
locks is worse than one that never does, because nothing downstream could tell
which it had. That is right for the primitive and wrong for an application,
which has to run on a machine whose `RLIMIT_MEMLOCK` an operator may not
control.

`Held` makes that choice once and records it: `is_locked()` can be asked, and
`Debug` prints `<locked>` or `<unlocked>` rather than either the bytes or a
claim. `LockedBox::new` hands the value back on failure so the fallback is the
same value in ordinary memory — not a second one, and not a panic.

## The startup check

RFC 7 §9 asks an implementation to "fail loudly at startup if locking is
unavailable rather than proceeding unlocked". `krab_lock::available()` probes
by locking and unlocking one page — the limit is not the only reason a lock can
fail (a container policy, a seccomp filter, a kernel built without the call all
produce the same refusal), and a probe answers the question that was asked
rather than a proxy for it.

**Loudly, and not fatally.** §9 lists memory locking among hardening measures,
beside disabling hibernation and swap, which this program also cannot do. A
node that refused to start on a machine with a low `RLIMIT_MEMLOCK` would be a
node an operator runs with the warning suppressed. What §9 forbids is
proceeding *silently* — which is what this did until now, by not having the
mechanism at all.

The message names the remedy (`ulimit -l`) and points at
`SECURE-DELETE.md`, and it is printed before the terminal is taken so it lands
on scrollback rather than in a pane that clears.
