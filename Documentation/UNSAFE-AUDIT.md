# The unsafe boundary — `krab-lock`, audited

RFC 7 §9 requires memory locking:

> `mlock`/`VirtualLock` key buffers. The full secret working set is under
> 100 KB (§2.1), so this is cheap. On Linux it requires `RLIMIT_MEMLOCK`
> headroom; implementations MUST fail loudly at startup if locking is
> unavailable rather than proceeding unlocked.

`mlock(2)` and `VirtualLock` are foreign functions and there is no safe way to
call one, so this workspace has an unsafe boundary. This document is the audit
of it.

**Both platforms are unsafe code and both are audited here.** RFC 7 §9 names
`mlock`/`VirtualLock` together, so the Windows arm is not an extension of the
requirement — it is the other half of it. It is also the half that is compiled
but never executed by this test suite, which is stated plainly in
[§ What the Windows arm is and is not verified to do](#what-the-windows-arm-is-and-is-not-verified-to-do)
rather than left for a reader to infer.

## Why not a dependency

The obvious route is `libc`. It is well maintained, universally used, and tens
of thousands of lines of platform constants — so vendoring it to call five
functions would mean **auditing** tens of thousands of lines to gain five
declarations. The audit is the entire reason the boundary is a crate rather
than a block, and a dependency that cannot be audited defeats it. The Windows
equivalent, `windows-sys`, is larger still.

`region` and `memsec` were also considered. Both are larger than the twenty
lines below, both bring their own dependency on `libc`, and neither does
anything this does not.

So nothing is vendored. The five declarations are written out, and each is
checkable against `man 2 mlock`, `man 3 sysconf`, or Microsoft's `memoryapi.h`
documentation in a minute:

```rust
#[cfg(unix)]
unsafe extern "C" {
    fn mlock(addr: *const c_void, len: usize) -> c_int;
    fn munlock(addr: *const c_void, len: usize) -> c_int;
    fn sysconf(name: c_int) -> c_long;
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn VirtualLock(addr: *mut c_void, len: usize) -> c_int;
    fn VirtualUnlock(addr: *mut c_void, len: usize) -> c_int;
}
```

`usize` is the correct Rust spelling of `size_t` and of `SIZE_T` on every
supported target; `c_int` and `c_long` come from `core::ffi`, so the widths are
the compiler's and not this file's guess.

Three details in the Windows block are load-bearing and each would fail
silently if wrong:

- **`extern "system"`, not `"C"`.** Win32 is `stdcall` on 32-bit x86 and the C
  convention everywhere else. `"C"` would be correct on x86-64 and wrong on
  `i686-pc-windows-msvc`.
- **The return convention is inverted.** `mlock` returns 0 for success;
  `VirtualLock` returns a `BOOL`, where non-zero is success. Reading it as
  `mlock`'s would report every successful lock as a refusal — and `Held` would
  absorb that by falling back to the heap, so the program would run, unlocked,
  saying it had tried. `lock_pages` is the single place the two are reconciled.
- **`*mut`, not `*const`.** `LPVOID` is `void *`. Cosmetic at the ABI, but the
  declaration is the audit artefact and it should say what the header says.

## Why the page size is a constant on Windows

Unix reads it with `sysconf(_SC_PAGESIZE)`. Win32 has no scalar getter:
`GetSystemInfo` fills a twelve-field `SYSTEM_INFO`, one member of which is a
union, and reading `dwPageSize` means declaring that layout exactly. The offset
is load-bearing, a mistake in it is silent, and the struct is markedly harder to
check against the documentation than the four lines of `VirtualLock` are. That
trades away the one property this crate exists for, to learn a number that is
4096 on every Windows target Rust supports.

So Windows uses the constant, and the existing fallback argument carries it
unchanged: **4 KiB is the small direction, and the small direction is the safe
one.** If a Windows target ever used larger pages, the allocation would be
smaller than a page and `VirtualLock` would round *out* to the containing page —
over-locking, which spends working-set quota on a neighbour but leaves nothing
swappable. The failure mode is the benign one by construction, not by luck.

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

So: an auditor who has read `crates/krab-lock/src/lib.rs` and
`crates/krab-lock/src/harden.rs` has read every unsafe line in the tree, and a
diff to any other crate cannot quietly add one.

**The crate outgrew its name.** It began as the memory-locking boundary and is
really the workspace's *FFI boundary* — the single place `unsafe` is permitted,
so the enforcement test can assert its absence everywhere else. `harden.rs` is
the second resident: RFC 7 §9's core-dump and debugger-attach measures are more
foreign calls and belong behind the same door. It is not renamed, because the
name appears in `Cargo.lock`, in every dependent manifest and in this document,
and a rename would cost more than the mild inaccuracy does.

## The unsafe operations, one at a time

Seven groups, and each carries its argument in the source beside it. Grouped
by argument rather than counted by keyword: operations 3 and 6 each cover two
platform arms making the same claim, and a count of `unsafe` tokens would have
changed when Windows was added while nothing an auditor needs to check did.
Restated here so
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

### 3. `lock_pages` — `mlock` on unix, `VirtualLock` on Windows

`raw` is a live allocation of exactly `layout.size()` bytes that this function
owns. Neither call reads or writes it. A failure deallocates and returns
`Unavailable::Refused`, so no partially-locked allocation escapes.

The two are wrapped in one function rather than branched at the call site so
that `LockedBox::new` has a single body and — more importantly — so the drop
order in operation 6, which is this crate's most load-bearing argument, is
written once rather than once per platform. The inverted success convention is
reconciled here and nowhere else.

### 4. `ptr.write(value)`

`ptr` is non-null, aligned to at least `align_of::<T>()` — the layout demanded
`max(page)`, and a page is a large power of two — and points at an allocation
large enough for a `T`. Nothing has been written there yet, so `write` is not
dropping an old value.

### 5. `ptr.as_ref()` / `as_mut()`

The pointer was initialised by `new` and is freed only by `drop`. `&mut self`
gives exclusivity for the mutable form.

### 6. `drop_in_place`, then `from_raw_parts_mut`, then `unlock_pages`, then `dealloc`

**The order is the audit's most load-bearing point.** Unlocking before
overwriting would let the kernel page the buffer out between the two, which is
the window the lock existed to close. So: drop the value, overwrite the whole
allocation, unlock, free.

The overwrite covers `layout.size()` rather than `size_of::<T>()` — padding is
ours and may have been written through.

`unlock_pages` — `munlock` or `VirtualUnlock` — discards its result on both
platforms: the memory is about to be freed, and there is no action a failure
would justify. Because the order above is written once inside `Drop` and the
platform difference is confined to `unlock_pages`, adding Windows could not
have reordered it on one platform only.

### 7. `unsafe impl Send` / `Sync`

`LockedBox` owns its allocation exclusively, hands out references only through
`&self`/`&mut self`, has no interior mutability, and touches no global state.
So it is exactly as sendable and shareable as the `T` it holds, and both impls
are bounded on `T`.

## What the Windows arm is and is not verified to do

Stated here rather than left to inference, because the honest answer is weaker
than "it works".

**Verified from this machine.** It type-checks and generates code for both
`x86_64-pc-windows-msvc` and `x86_64-pc-windows-gnu`, and `clippy` is clean on
both. So the declarations are well-formed, the `cfg` routing reaches them, and
the calling convention and types are accepted.

**Not verified.** Nothing here has ever executed `VirtualLock`. In particular:

- **`kernel32` linkage is unproven.** `cargo check` does not link, and no
  Windows linker is available on the development machine. `#[link(name =
  "kernel32")]` is the standard spelling and the library ships with both the
  Windows SDK and mingw-w64, so the risk is low — but low is not zero, and it
  is a link-time failure, which is the loud kind.
- **No test observes a lock succeeding on Windows.**
  `a_named_platform_never_reports_unsupported` asserts that a platform RFC 7 §9
  names never answers `Unsupported`. On Windows the `cfg` structure makes that
  answer unreachable anyway, so today the test guards against a *future*
  refactor rather than a present defect. It was verified to fire by forcing the
  unsupported path; a first attempt at that probe was itself vacuous, because
  it patched an error branch that a machine with working `mlock` never takes.

**What would close this:** running `cargo test -p krab-lock` on Windows. That
is one line in CI and it is the only thing that turns the arm from *compiled*
into *working*.

## Windows: what a successful lock buys there

RFC 7 §9 names `mlock` and `VirtualLock` in one breath, which reads as though
they were equivalent. For the purpose of the requirement they are, but an
operator on Windows should know three things that differ, none of which the
program can detect or fix.

**1. The quota is a working-set quota, not a memory limit.** `VirtualLock`
charges against the process *minimum working set size* and fails with
`ERROR_WORKING_SET_QUOTA` once that is spent. This is the analogue of Linux's
`RLIMIT_MEMLOCK`, and it is why both map to `Unavailable::Refused`. It is
raised with `SetProcessWorkingSetSize`, which this program does not call —
raising one's own quota to make a check pass is not hardening.

**2. Crash dumps contain locked pages.** A full-memory or complete crash dump,
and a full-process minidump written by Windows Error Reporting, capture process
memory without regard to whether it was locked. Locking does not mark a page as
undumpable on any platform, but Windows is where automatic dump collection and
upload is on by default, so the exposure is likelier to be *taken* rather than
merely possible. An operator holding an identity they cannot replace (RFC 7
§11) should consider whether error reporting is enabled.

**3. The pagefile is not encrypted by default.** Windows can encrypt it —
`fsutil behavior set EncryptPagingFile 1` — and does not out of the box. This
matters less once locking works, since the point of locking is that those pages
do not reach the pagefile; it matters for everything RFC 7 §9 does *not* cover,
which per the table below is most of the secret working set.

**And unchanged from every platform:** hibernation writes all of RAM to disk,
locked or not. RFC 7 §9 names it and nothing in software prevents it.

One further caveat is *believed but unverified*: that Windows may write locked
pages to the pagefile when an entire process working set is trimmed, for
instance across suspend. This is widely repeated and the author has not
confirmed it against current Microsoft documentation. It is recorded as
uncertain rather than asserted, and it does not change any advice above.

## `harden.rs` — RFC 7 §9's other two lines

§9 lists three measures beside locking, and this workspace had implemented one
of them and misdescribed it:

> `panic = "abort"`, `RLIMIT_CORE = 0`, `prctl(PR_SET_DUMPABLE, 0)`.
>
> `prctl(PR_SET_PTRACER, 0)` and Yama `ptrace_scope` — blocks same-user
> debugger attach, and is widely available and rarely applied.

**`panic = "abort"` is not a core-dump control.** Abort raises `SIGABRT`, whose
default disposition is to write a core file; unwinding writes none. So the one
measure that shipped is the one that makes a dump *more* likely, and the two
that suppress dumps were the ones missing. `Cargo.toml`, `SECURE-DELETE.md` and
`ADVERSARIAL-PASS.md` all stated the inverse; all three are corrected.

`krab_lock::harden::harden()` is called as the **first statement of `main`** —
before argument parsing, which can panic, and before the decoder-child check,
so the child process is hardened too. It never fails and never panics; it
returns what it achieved.

### The declarations

| call | platform | verified against |
|---|---|---|
| `setrlimit(RLIMIT_CORE, {0,0})` | unix | `sys/resource.h`; `sizeof(struct rlimit)` measured as 16 with `rlim_t = __uint64_t` |
| `prctl(PR_SET_DUMPABLE, 0)` | Linux | `man 2 prctl` |
| `prctl(PR_SET_PTRACER, 0)` | Linux | `man 2 prctl`; advisory, needs Yama |
| `ptrace(PT_DENY_ATTACH, …)` | macOS | `sys/ptrace.h`, constant 31 |
| `SetErrorMode(…)` | Windows | `errhandlingapi.h` |
| `IsDebuggerPresent()` | Windows | `debugapi.h` |

`rlim_t` is **not the same type on the two unixes** — macOS fixes it at
`__uint64_t`, glibc defines it as `unsigned long`, and Rust does not set
`_FILE_OFFSET_BITS`, so the symbol reached is the non-LFS one taking exactly
that. A single `u64` would be wrong on 32-bit Linux and would hand the kernel a
struct of the wrong size.

The hard limit is set to 0 as well as the soft one, deliberately: lowering a
hard limit is irreversible without privilege, so a later bug — or an attacker
holding this process's own rights — cannot raise it back.

`PR_SET_DUMPABLE` is set in **both** `disable_core_dumps` and
`block_debugger_attach`. It is idempotent, and the duplication is on purpose:
neither function should depend on the other having run first, and an ordering
that is load-bearing but unstated is the defect this workspace keeps finding.

### Verified empirically

On macOS both measures report `Blocked`, and the core-dump one was checked by
read-back rather than by trusting the return code: a child process inherits
rlimits, so running `ulimit -c; ulimit -Hc` in a child before and after shows
the hard limit going **`unlimited` → `0`**. The soft limit was already 0 on this
machine, so the return code alone would not have distinguished "applied" from
"no-op".

`PT_DENY_ATTACH` returning 0 is the only evidence for the debugger half; no
debugger was actually pointed at the process.

### What it does not do

**It stops nobody with root, Administrator, or the machine in their hands.**
`PR_SET_DUMPABLE` yields to `CAP_SYS_PTRACE`; `RLIMIT_CORE` limits the process,
not the kernel's ability to inspect it; every Windows mechanism yields to an
elevated token. RFC 7 §4's crypto-shredding is what addresses seizure. This is
defence in depth behind it.

Three further limits, each recorded rather than glossed:

- **Windows is `Partial`, and says so.** `SetErrorMode` suppresses the crash
  dialog; Windows Error Reporting can still collect a dump, which is machine
  policy this process cannot set for itself. `WerRegisterExcludedMemoryBlock`
  is the right long-term answer — it excludes a memory range from reports, and
  would pair naturally with `LockedBox` — but it is a hard link against Windows
  10 1709 and would refuse to start on anything older. That compatibility cut
  is worth making deliberately, not as a side effect of this change.
- **Windows cannot refuse a debugger.** `NtSetInformationThread(ThreadHideFrom­Debugger)`
  is undocumented, routinely defeated, and flagged as malware behaviour by the
  tooling an operator is likeliest to be running. `Unsupported` is the honest
  answer; claiming otherwise would be worse than admitting there is nothing.
- **macOS `PT_DENY_ATTACH` also stops the operator debugging their own node.**
  It does not distinguish whose debugger it is. That is the point of it and the
  cost of it.

`debugger_present()` is detection, not prevention, and is separate for that
reason. Linux answers from `/proc/self/status`'s `TracerPid` with no FFI at
all; Windows uses `IsDebuggerPresent`; macOS returns `None`, because answering
would mean declaring `kinfo_proc` — hundreds of bytes of nested structs whose
layout is load-bearing and whose mistakes are silent, which is the same trade
refused for `SYSTEM_INFO` above and refused the same way.

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
