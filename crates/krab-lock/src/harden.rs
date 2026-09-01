//! Process hardening — RFC 7 §9's two remaining lines.
//!
//! ```text
//! - `panic = "abort"`, `RLIMIT_CORE = 0`, `prctl(PR_SET_DUMPABLE, 0)`.
//! - `prctl(PR_SET_PTRACER, 0)` and Yama `ptrace_scope` — blocks same-user
//!   debugger attach, and is widely available and rarely applied.
//! ```
//!
//! Both were listed and neither was implemented. The workspace shipped only
//! `panic = "abort"`, which three documents described as the thing that stops a
//! core dump carrying key material.
//!
//! # `panic = "abort"` does the opposite
//!
//! Abort raises `SIGABRT`, and `SIGABRT`'s default disposition **is to write a
//! core dump**. Unwinding writes none. So the one item of §9's three that was
//! implemented is the one that makes a dump *more* likely, and the two that
//! actually suppress dumps — `RLIMIT_CORE` and `PR_SET_DUMPABLE` — were the
//! ones missing.
//!
//! `panic = "abort"` stays: it is there so a panic cannot unwind through a
//! partially-zeroized structure, which is a different and real argument. It is
//! simply not a core-dump control, and this module is what makes the sentence
//! those documents were reaching for true.
//!
//! # What this can and cannot do
//!
//! **It raises the cost for a same-privilege adversary. It stops nobody with
//! root, Administrator, or the machine in their hands.** `PR_SET_DUMPABLE`
//! yields to `CAP_SYS_PTRACE`; `RLIMIT_CORE` is a limit on the process, not on
//! the kernel's ability to inspect it; every Windows mechanism here yields to
//! an elevated token. Nothing below should be described to an operator as
//! protection against seizure — RFC 7 §4's crypto-shredding is what addresses
//! that, and this is defence in depth behind it.
//!
//! # Why it lives here
//!
//! Because it is `unsafe`. This crate began as the memory-locking boundary and
//! is really the workspace's **FFI boundary**: the one place `unsafe` is
//! permitted, so that the enforcement test can assert its absence everywhere
//! else. Hardening is more foreign calls, so it belongs behind the same door.

use core::ffi::c_int;

// ---------------------------------------------------------------------------
// The foreign boundary. Every constant below was read out of this machine's
// SDK headers or measured with a C program, not recalled — the file
// `sys/resource.h` gives `RLIMIT_CORE 4` and `sizeof(struct rlimit) == 16`
// with `rlim_t = __uint64_t`, and `sys/ptrace.h` gives `PT_DENY_ATTACH 31`.
// ---------------------------------------------------------------------------

/// `rlim_t`, which is not the same type on the two unixes.
///
/// macOS fixes it at `__uint64_t` regardless of architecture. glibc defines it
/// as `unsigned long`, so it follows the word size — and Rust does not set
/// `_FILE_OFFSET_BITS`, so the `setrlimit` symbol reached here is the
/// non-LFS one that takes exactly that.
///
/// Getting this wrong would pass a struct of the wrong size to the kernel,
/// which is the sort of mistake this crate exists to make checkable.
#[cfg(all(unix, target_os = "linux"))]
type RlimT = core::ffi::c_ulong;
/// macOS and the BSDs.
#[cfg(all(unix, not(target_os = "linux")))]
type RlimT = u64;

/// `struct rlimit { rlim_t rlim_cur; rlim_t rlim_max; };`
#[cfg(unix)]
#[repr(C)]
struct RLimit {
    cur: RlimT,
    max: RlimT,
}

/// `RLIMIT_CORE` — 4 on Linux, macOS and every BSD.
///
/// It is one of the original BSD resource numbers (`CPU 0, FSIZE 1, DATA 2,
/// STACK 3, CORE 4`) and has not moved since. Verified against this machine's
/// `sys/resource.h`.
#[cfg(unix)]
const RLIMIT_CORE: c_int = 4;

#[cfg(unix)]
unsafe extern "C" {
    /// `int setrlimit(int resource, const struct rlimit *rlim);`
    fn setrlimit(resource: c_int, rlim: *const RLimit) -> c_int;
}

// `prctl` is variadic in the header — `int prctl(int option, ...)` — and is
// declared that way rather than as five fixed longs, so the declaration says
// what `man 2 prctl` says. Linux passes the remaining arguments in registers
// identically either way on every architecture Rust supports.
#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn prctl(option: c_int, ...) -> c_int;
}

/// `PR_SET_DUMPABLE`.
///
/// **The strongest single call here.** Clearing it suppresses core dumps *and*
/// makes the process unattachable by a same-uid `ptrace`, because the kernel
/// gates ptrace on the dumpable flag. One call closes both of RFC 7 §9's
/// remaining lines on Linux.
#[cfg(target_os = "linux")]
const PR_SET_DUMPABLE: c_int = 4;

/// `PR_SET_PTRACER`, whose value is the ASCII of "Yama".
///
/// Setting it to 0 declares that no process may attach. It only means anything
/// where the Yama LSM is built in and `ptrace_scope` is 1; elsewhere it returns
/// `EINVAL`, which is why its result is advisory here and `PR_SET_DUMPABLE`
/// decides the outcome.
#[cfg(target_os = "linux")]
const PR_SET_PTRACER: c_int = 0x59616d61;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    /// `int ptrace(int request, pid_t pid, caddr_t addr, int data);`
    ///
    /// `caddr_t` is `char *` and `pid_t` is `i32`; both verified against this
    /// machine's `sys/ptrace.h` and `sys/_types/_caddr_t.h`.
    fn ptrace(request: c_int, pid: i32, addr: *mut core::ffi::c_char, data: c_int) -> c_int;
}

/// `PT_DENY_ATTACH` — macOS's refusal to be debugged.
///
/// Verified against `sys/ptrace.h`. Note the semantics: if a debugger is
/// *already* attached when this is called, the process is killed rather than
/// detached. That is the documented behaviour and it is the right one here.
#[cfg(target_os = "macos")]
const PT_DENY_ATTACH: c_int = 31;

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    /// `UINT SetErrorMode(UINT uMode);`
    fn SetErrorMode(mode: u32) -> u32;
    /// `BOOL IsDebuggerPresent(void);`
    fn IsDebuggerPresent() -> c_int;
}

/// `SEM_FAILCRITICALERRORS`.
#[cfg(windows)]
const SEM_FAILCRITICALERRORS: u32 = 0x0001;
/// `SEM_NOGPFAULTERRORBOX` — suppresses the Windows Error Reporting dialog.
#[cfg(windows)]
const SEM_NOGPFAULTERRORBOX: u32 = 0x0002;

// ---------------------------------------------------------------------------

/// What one hardening measure achieved.
///
/// Four outcomes rather than a `bool`, because "we called something" and "the
/// thing you wanted is now true" are different claims and this crate's habit
/// is not to conflate them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Applied, and believed effective against a same-privilege adversary.
    Blocked,
    /// Something was applied, and it does **not** fully achieve the goal.
    ///
    /// Windows only, and see [`Hardening::advice`] for what remains open.
    Partial,
    /// The platform has the mechanism and the kernel refused.
    Refused,
    /// No mechanism on this platform.
    Unsupported,
}

impl Outcome {
    /// Whether an operator can consider this measure done.
    pub fn is_effective(self) -> bool {
        matches!(self, Outcome::Blocked)
    }
}

/// The result of [`harden`], one line per RFC 7 §9 measure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hardening {
    /// `RLIMIT_CORE = 0`, `PR_SET_DUMPABLE = 0`, or `SetErrorMode`.
    pub core_dumps: Outcome,
    /// `PR_SET_DUMPABLE`/`PR_SET_PTRACER`, or `PT_DENY_ATTACH`.
    pub debugger_attach: Outcome,
}

impl Hardening {
    /// Whether both measures are effective.
    pub fn is_complete(&self) -> bool {
        self.core_dumps.is_effective() && self.debugger_attach.is_effective()
    }

    /// What to tell the operator, or `None` if there is nothing to say.
    ///
    /// One line, naming the remedy where one exists. The startup path prints
    /// this, so it must stay short enough to be read rather than skipped —
    /// the detail is `Documentation/UNSAFE-AUDIT.md`.
    pub fn advice(&self) -> Option<&'static str> {
        match (self.core_dumps, self.debugger_attach) {
            (Outcome::Blocked, Outcome::Blocked) => None,
            (Outcome::Partial, _) | (_, Outcome::Partial) => Some(
                "crash dumps are only partly suppressed on Windows — Windows \
                 Error Reporting can still capture key material. Disable it \
                 for this machine if the identity matters.",
            ),
            (Outcome::Refused, _) | (_, Outcome::Refused) => Some(
                "the kernel refused to disable core dumps or debugger attach — \
                 a core file or an attached debugger can expose key material.",
            ),
            _ => Some(
                "core dumps and debugger attach are not restricted on this \
                 platform — a core file or an attached debugger can expose key \
                 material.",
            ),
        }
    }
}

/// Apply RFC 7 §9's process hardening. Idempotent.
///
/// **Call this before any key material exists**, which in practice means as
/// early in `main` as possible. A core dump taken before `RLIMIT_CORE` is
/// cleared is exactly the dump this exists to prevent, and the window is real:
/// the passphrase prompt is not the first thing that runs.
///
/// It never fails and never panics. Every measure that does not apply is
/// reported rather than raised, because there is no machine on which refusing
/// to start would be the better answer — RFC 7 §9 lists these beside
/// "disable hibernation", which the program also cannot do.
///
/// # On macOS this stops you debugging your own node
///
/// `PT_DENY_ATTACH` does not distinguish an adversary's debugger from the
/// operator's. That is the point of it, and it is the cost of it.
pub fn harden() -> Hardening {
    Hardening {
        core_dumps: disable_core_dumps(),
        debugger_attach: block_debugger_attach(),
    }
}

/// Whether a debugger is attached right now, where that is knowable.
///
/// `None` means "this platform cannot say", which is not the same as "no" and
/// is why the return is an `Option` rather than a `bool` defaulting to false.
///
/// **Detection is not prevention** and is much weaker: an adversary who
/// controls the machine can attach after this returns, or hide from it. It is
/// here because a node that notices it is being traced can react — refuse to
/// unwrap the identity, or trip the panic wipe — and that decision belongs to
/// the caller, not to this function.
pub fn debugger_present() -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        // No FFI needed: the kernel already publishes this. `TracerPid` is 0
        // when nothing is attached and the tracer's pid otherwise.
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("TracerPid:") {
                return Some(rest.trim().parse::<u32>().ok()? != 0);
            }
        }
        None
    }
    #[cfg(windows)]
    {
        // SAFETY: takes no arguments, touches no memory the caller owns, and
        // reads one flag out of the process environment block.
        Some(unsafe { IsDebuggerPresent() } != 0)
    }
    // macOS can answer this with `sysctl(KERN_PROC)`, which means declaring
    // `kinfo_proc` — several hundred bytes of nested structs whose layout is
    // load-bearing and whose mistakes are silent. That is the same trade
    // refused for `SYSTEM_INFO` in `lib.rs`, and refused the same way: the
    // honest `None` is better than a struct nobody can check.
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        None
    }
}

/// `RLIMIT_CORE = 0`, and `PR_SET_DUMPABLE = 0` where it exists.
fn disable_core_dumps() -> Outcome {
    #[cfg(unix)]
    {
        let zero = RLimit { cur: 0, max: 0 };
        // SAFETY: `setrlimit` reads `sizeof(struct rlimit)` bytes through the
        // pointer and writes nothing. `RLimit` is `#[repr(C)]` with exactly
        // the two fields the header declares, in order, of the width measured
        // from this machine's headers. The reference is live for the call.
        //
        // Setting `max` to 0 as well is deliberate and irreversible for this
        // process: lowering the hard limit cannot be undone without privilege,
        // so a later bug — or an attacker with this process's own rights —
        // cannot raise the soft limit back.
        let ok = unsafe { setrlimit(RLIMIT_CORE, &zero) } == 0;

        #[cfg(target_os = "linux")]
        {
            // SAFETY: `prctl` with `PR_SET_DUMPABLE` takes an integer by
            // value and touches no memory the caller owns. The remaining
            // variadic arguments are unused by this option.
            let dumpable = unsafe { prctl(PR_SET_DUMPABLE, 0 as core::ffi::c_ulong) } == 0;
            // Either mechanism alone suppresses the dump; requiring both would
            // report a hardened process as unhardened.
            if ok || dumpable {
                Outcome::Blocked
            } else {
                Outcome::Refused
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            if ok {
                Outcome::Blocked
            } else {
                Outcome::Refused
            }
        }
    }
    #[cfg(windows)]
    {
        // SAFETY: takes and returns a bitmask by value and touches no memory
        // the caller owns.
        //
        // **`Partial`, and the honesty matters.** This suppresses the
        // crash dialog and the "critical error" box; it does not stop Windows
        // Error Reporting collecting a dump, which is a machine-wide policy
        // this process cannot set for itself. `WerRegisterExcludedMemoryBlock`
        // would let a locked page be excluded from dumps directly and is the
        // right long-term answer — it is not used yet because it is a hard
        // link against Windows 10 1709 and would refuse to start on anything
        // older, which is a compatibility cut worth making deliberately rather
        // than as a side effect of this change.
        unsafe { SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX) };
        Outcome::Partial
    }
    #[cfg(not(any(unix, windows)))]
    {
        Outcome::Unsupported
    }
}

/// Refuse debugger attach where the platform offers a way.
fn block_debugger_attach() -> Outcome {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: as in `disable_core_dumps` — integer arguments by value,
        // no memory touched.
        //
        // `PR_SET_DUMPABLE` is what actually blocks attach, because the kernel
        // gates `ptrace` on the dumpable flag. It is set here as well as in
        // `disable_core_dumps` so that neither function depends on the other
        // having run — this one is called second today, and an ordering that
        // is load-bearing but unstated is the defect this workspace keeps
        // finding. Both calls are idempotent.
        let dumpable = unsafe { prctl(PR_SET_DUMPABLE, 0 as core::ffi::c_ulong) } == 0;
        // Advisory: meaningful only where the Yama LSM is present, `EINVAL`
        // otherwise, so its failure must not decide the outcome.
        // SAFETY: as above.
        let _yama = unsafe { prctl(PR_SET_PTRACER, 0 as core::ffi::c_ulong) };
        if dumpable {
            Outcome::Blocked
        } else {
            Outcome::Refused
        }
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: `PT_DENY_ATTACH` ignores the pid, address and data
        // arguments; the null pointer is never dereferenced. The call touches
        // no memory this process owns.
        let r = unsafe { ptrace(PT_DENY_ATTACH, 0, core::ptr::null_mut(), 0) };
        if r == 0 {
            Outcome::Blocked
        } else {
            Outcome::Refused
        }
    }
    #[cfg(windows)]
    {
        // Windows has no supported way for a process to refuse a debugger.
        // `NtSetInformationThread(ThreadHideFromDebugger)` is undocumented,
        // routinely defeated, and flagged as malware behaviour by the tooling
        // an operator is likeliest to be running. Claiming `Blocked` for it
        // would be worse than admitting there is nothing.
        //
        // `debugger_present` still answers here, so a caller that wants to
        // react to a debugger can.
        Outcome::Unsupported
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        Outcome::Unsupported
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hardening applies, reports, and never panics.
    ///
    /// This really does harden the test process: after it runs, this binary
    /// has `RLIMIT_CORE` at 0 and — on macOS — refuses a debugger. That is
    /// intended. It is also why nothing here asserts a *specific* outcome:
    /// a container with an unusual seccomp profile may legitimately refuse,
    /// and a test that failed there would be testing the machine.
    #[test]
    fn hardening_applies_and_reports() {
        let h = harden();
        // Whatever happened, the two fields must be answerable and the advice
        // must be consistent with them.
        assert_eq!(h.advice().is_none(), h.is_complete());
        if h.is_complete() {
            assert!(h.core_dumps.is_effective() && h.debugger_attach.is_effective());
        }
    }

    /// **On a platform RFC 7 §9 names, core dumps must not report
    /// `Unsupported`.** Unix has `RLIMIT_CORE` and Windows has `SetErrorMode`;
    /// only a third platform may say it has nothing.
    ///
    /// The same guard as `lib.rs`'s `a_named_platform_never_reports_unsupported`
    /// and for the same reason: an arm that compiles but is never routed to
    /// would otherwise be indistinguishable from one that works.
    #[test]
    fn a_named_platform_attempts_core_dump_suppression() {
        let h = harden();
        #[cfg(any(unix, windows))]
        assert_ne!(
            h.core_dumps,
            Outcome::Unsupported,
            "this platform has a mechanism, so `Unsupported` means the arm was \
             compiled but not reached"
        );
        let _ = h;
    }

    /// **Prints what this machine actually granted.** Always passes.
    ///
    /// Its value is the CI log, not the assertion. Every other test here
    /// tolerates `Refused` and `Unsupported`, because a container with an
    /// unusual seccomp profile is a real machine and a test that failed there
    /// would be testing the machine rather than the code. The cost of that
    /// tolerance is that a green suite does not say *which* branch ran.
    ///
    /// On Windows that is the whole question — `Documentation/UNSAFE-AUDIT.md`
    /// records that the arm has never executed — so `cargo test -p krab-lock
    /// -- --nocapture` in CI turns a pass into evidence.
    #[test]
    fn report_what_this_platform_granted() {
        let h = harden();
        println!("platform  = {}", std::env::consts::OS);
        println!("locking   = {:?}", crate::available());
        println!("core dumps= {:?}", h.core_dumps);
        println!("debugger  = {:?}", h.debugger_attach);
        println!("advice    = {:?}", h.advice());
        println!("debugger present = {:?}", debugger_present());
    }

    /// Idempotent — `harden` is called once at startup, but nothing enforces
    /// that, and a second call must not change the answer or misbehave.
    #[test]
    fn hardening_is_idempotent() {
        let first = harden();
        let second = harden();
        assert_eq!(first, second);
    }

    /// The detector answers or admits it cannot, and does not panic.
    ///
    /// It must not claim a debugger under `cargo test`; a false positive here
    /// would be a node that trips its own wipe on a normal start.
    #[test]
    fn the_debugger_probe_does_not_cry_wolf() {
        assert_ne!(
            debugger_present(),
            Some(true),
            "reported a debugger under an ordinary test run — a false positive \
             here would be a node that trips its own wipe on a normal start"
        );
    }

    /// `Partial` is not `Blocked`, and `advice` says so.
    ///
    /// The distinction is the whole point of having four outcomes: Windows
    /// applies something real and still leaves key material reachable through
    /// Windows Error Reporting, and an operator must not read that as done.
    #[test]
    fn partial_is_not_effective_and_carries_advice() {
        assert!(!Outcome::Partial.is_effective());
        let h = Hardening {
            core_dumps: Outcome::Partial,
            debugger_attach: Outcome::Blocked,
        };
        assert!(!h.is_complete());
        assert!(h.advice().is_some_and(|a| a.contains("Windows")));
    }
}
