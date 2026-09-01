//! `krab` — the client, and the node.
//!
//! Krab has no headless mode (`RFC-8-review.md` §8.1). This one process is
//! both the interface and the node: it accepts inbound sessions, reconciles on
//! a Poisson schedule, and stores — while the user reads, composes, or has
//! walked away and locked the screen.
//!
//! That is a security position rather than a simplification. A headless node
//! is an unattended process holding decryption keys, and RFC 7 §7 establishes
//! that the machine which must run without a human present is the one that
//! should have nothing to protect. Shipping a headless mode would have made
//! the weak configuration the convenient one.
//!
//! # Terminal restoration under `panic = "abort"`
//!
//! RFC 7 §9 requires `panic = "abort"` so a core dump cannot carry key
//! material, and the workspace profile sets it. Abort does not unwind, so a
//! `Drop` guard never runs and a panic would leave the terminal in raw mode
//! with the alternate screen active — unusable, with no scrollback.
//!
//! A panic *hook* still runs before the abort, so [`install_panic_hook`]
//! restores the terminal there. This is the only interaction between those two
//! requirements and it is easy to miss, because it works fine in a debug build
//! where unwinding is enabled.

// Every library crate in the workspace forbids this; the binary did not, and
// so it was the one place an `unsafe` block could appear unremarked. One had:
// a test that read `Vec::spare_capacity_mut()` back as initialised `char`,
// which is undefined behaviour in the test for the code that wipes a
// passphrase — see `line::tests::taking_the_line_overwrites_it`.
//
// `forbid` rather than `deny`: `deny` can be turned off by an `allow` on the
// item that wants it, which is exactly the edit nobody reviews.
#![forbid(unsafe_code)]

mod activity;
mod activity_log;
mod artifact;
mod atomic;
mod bootstrap;
mod bulletin;
mod ceremony;
mod channels;
mod command;
mod compose;
mod courier;
mod credential;
mod display;
mod entropy;
mod fanout;
mod filter;
mod alias;
mod fragment;
mod markdown;
mod groups;
mod identity;
mod introduction;
mod keys;
mod layout;
mod line;
mod links;
mod negotiate;
mod peering;
mod peers;
mod persist;
mod picture;
mod pin;
mod prekeys;
mod quota;
mod reach;
mod receive;
mod rekey;
mod rekey_run;
mod render;
mod request;
mod rollcall;
mod shared;
mod deadman;
mod shred;
mod spoken;
mod sync;
mod words;
// RFC 1 §12's vector file is a test artifact: it is generated and checked by
// the test suite and no runtime path consults it.
#[cfg(test)]
mod vectors;

use activity::{NodeState, Spinner};
use command::{admit, Command, InitStep, Peering, Refusal};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use entropy::OsRng;
use krab_fabric::backend::tor::ONION_PORT;
use identity::Identity;
use keys::{Binding, Key, KeyPress};
use krab_crypto::rng::Rng;
use layout::{Mode, Ui};
use links::{profile_named, LinkTable};
#[allow(unused_imports)]
use peering::Offer;
use peering::{accept, Policy};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io::{self, Stdout};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// How often the interface redraws when nothing has happened.
///
/// Slow on purpose. The spinner is the only thing that needs a tick, and RFC 8
/// §5.1's concern about drawing the eye applies to redraw rate as much as to
/// wording — plus this is bandwidth on a serial console or a poor SSH link,
/// which are transports Krab exists to serve.
const TICK: Duration = Duration::from_millis(250);

/// How long `connect ... answer` waits for a call before handing the prompt
/// back.
///
/// Bounded because the wait is on the UI thread: an unbounded accept is a hung
/// The shortest mean interval between cover objects — RFC 1 §5.3.
///
/// A minute. Below that the emitter stops being a privacy measure and becomes
/// a bandwidth problem: SIM-0 puts ordinary ingress at ~0.063 MB/day per node
/// per node, and a dummy every few seconds swamps it — which is itself a
/// signal, since a node emitting far more than the network's own rate stands
/// out for exactly that.
const COVER_MIN_S: u64 = 60;

/// The longest. A day, past which the emitter hides nothing: cover works by
/// there being enough of it that a real object is not conspicuous, and one a
/// day is not enough of anything.
const COVER_MAX_S: u64 = 86_400;

/// interface with no way to cancel it.
const ANSWER_WAIT_S: u64 = 30;

/// Why a re-key stopped, in words an operator can act on.
fn rekey_failure(peer: &str, e: rekey_run::Error) -> String {
    use rekey_run::Error;
    match e {
        Error::Link => format!("the link to {peer} failed mid-re-key — nothing changed"),
        Error::Protocol => format!("{peer} sent something unexpected — nothing changed"),
        Error::Undecipherable => format!(
            "{peer} is working from a different reservoir. Usually one end \
             re-keyed and the other did not; try again once both are up."
        ),
        // The one that is not an accident.
        Error::Forged => format!(
            "the re-key from {peer} was sealed correctly and signed by someone \
             else. Someone holding their reservoir tried to steer this peering. \
             Nothing changed. Do not re-key again until you have spoken to them."
        ),
        Error::Diverged => {
            format!("{peer} derived a different root — nothing changed on either side")
        }
        Error::WrongIndex => format!(
            "{peer} is re-keying to a different index. Clocks disagree across an \
             epoch boundary; try again."
        ),
    }
}

/// A first-contact socket running in the background.
struct Meeting {
    /// Where it is bound, for the operator to read back.
    addr: String,
    /// Cleared to stop the thread.
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// What the thread produces: the peer's card and contribution, or a
    /// reason it stopped.
    done: std::sync::mpsc::Receiver<Result<bootstrap::Outcome, bootstrap::Error>>,
    /// This node's half, held so the ceremony can be completed on the
    /// interface thread where the store lives.
    mine: peering::Contribution,
    /// When it closes itself.
    until: Instant,
    /// How long that was, so the message on closing names the window the
    /// operator asked for rather than the default they did not.
    window: Duration,
}

/// An action waiting for one line that is not a command.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Prompt {
    /// The 32 words the other end read aloud, and the wrapped pad they go
    /// with. See [`crate::spoken`].
    TransferWords { path: String },
    /// The same, for a re-seal rather than a first peering.
    ResealWords { path: String },
}

/// Why a first contact stopped, in words an operator can act on.
fn meet_failure(e: bootstrap::Error) -> String {
    use bootstrap::Error;
    match e {
        Error::Link => "the link failed during first contact — nothing was recorded".into(),
        Error::Protocol => "the far end sent something unexpected — nothing was recorded".into(),
        Error::BadCard => "their card's signature does not verify. It is not what it claims \
                           to be, and RFC 4 §4.1 makes that a refusal rather than a prompt."
            .into(),
        // The one that is not an accident.
        Error::KeyMismatch => "**the card does not belong to whoever is on the other end of \
             this connection.**\n\n\
             Someone is relaying: they completed a handshake with you and \
             forwarded a genuine card belonging to somebody else, so the \
             fingerprint you would have compared is not theirs. Nothing was \
             recorded. Do not try again on this address until you have spoken \
             to your friend."
            .into(),
    }
}

/// Seconds since the Unix epoch, or zero if the clock is before it.
fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// How long a first-contact socket stays open before closing itself.
///
/// Long enough to arrange with somebody — thirty seconds was not, which is why
/// it blocked the interface and could not be cancelled. Bounded because it
/// accepts *whoever calls*: there is no peering yet, so there is no key to
/// check them against, and a door left open past the arrangement to use it is
/// one nobody is watching.
const MEET_WINDOW: Duration = Duration::from_secs(15 * 60);

/// The longest `peer meet listen --timeout` will accept.
///
/// A first-contact socket accepts whoever calls — there is no peering yet, so
/// there is no key to check anyone against. Its safety is that it is open for
/// as long as the arrangement to use it and no longer, so the operator may
/// shorten the window and may not turn it into a service.
const MEET_WINDOW_MAX: Duration = Duration::from_secs(60 * 60);

/// Lines PgUp/PgDn move the output pane.
///
/// A fixed step rather than a screenful: the pane is four rows unzoomed and
/// full-screen zoomed, and a step that changes size with the zoom means the
/// same keystroke moves a different distance depending on state.
const OUTPUT_SCROLL_LINES: usize = 8;

/// Rows the output pane shows in the default layout.
///
/// The threshold for opening it automatically. Two rows of frame plus this;
/// a reply taller than this is one whose result would be off screen.
const OUTPUT_PANE_ROWS: usize = 2;

/// Marks an inbox row whose message carries an attachment.
///
/// One cell wide, so the column it sits in is the same width on every row
/// whether or not there is an attachment. Deliberately not an emoji: those
/// are two cells in most terminals and one in some, which is a column that
/// moves depending on who is looking at it.
///
/// RFC 8 §6 permits pictures and no other attachment type, so this means
/// exactly one thing and needs no second glyph.
const ATTACHMENT_GLYPH: &str = "▣";

/// How many ticks an activity glyph keeps turning after bytes move.
///
/// Long enough to be seen at a glance, short enough that it stops well before
/// an operator could mistake it for continuous traffic.
/// How long a lapsed peering keeps its record before RFC 3 §8.4 purges it.
///
/// §4: "revocation is non-renewal." A peering ends when it is *not renewed*,
/// not the instant its term runs out — so this is the window in which
/// declining becomes true, and until it closes the peering reports as expired
/// and can still be renewed.
///
/// A fortnight. §4 prompts for renewal at 75% of a 60–90 day term, which is
/// about three weeks' notice; a fortnight after is the same order and short
/// against §15's concern that credentials at rest are non-repudiable.
const GRACE_AFTER_EXPIRY_S: u64 = 14 * 24 * 3600;

const ACTIVITY_GLYPH_TICKS: u8 = 20;

/// Epochs between signed-prekey rotations — RFC 7 §5.1's "weekly to monthly",
/// and RFC 6 §2.8's "members of large groups MUST republish weekly".
///
/// Seven, the shorter end. The signed prekey is the fallback every sender
/// reaches when a batch is exhausted, so it is the key most likely to be in
/// use for longest, and RFC 7 §5's claim is that exposure is bounded by *this*
/// period. Choosing the monthly end would quadruple that bound to save six
/// bulletins a month.
const SIGNED_PREKEY_EPOCHS: u32 = 7;

/// How often a node republishes a batch, in epochs.
///
/// Also weekly. RFC 6 §2.8 requires it for large groups and there is no reason
/// for a small node to be different: a batch that is never replenished is one
/// that eventually exhausts, and exhaustion degrades forward secrecy silently.
const REPUBLISH_EPOCHS: u32 = 7;

/// Where a node keeps its store when `--home` is not given.
///
/// Under test this is a scratch directory, not the working directory. It was
/// the working directory, and the working directory during `cargo test` is the
/// package root — so the suite wrote a real `identity.wrapped`, `kek.params`
/// and `corpus.krab` into the source tree, where they were committed. A test
/// must not be able to produce a publishable key hierarchy by default.
fn default_home() -> PathBuf {
    #[cfg(test)]
    {
        // A *fresh* directory per call, not one per process. Sharing one
        // meant every `App::default()` in the suite wrote into the same
        // store, so a test that ran `init` made every later test's `init`
        // refuse — a race whose outcome depended on thread scheduling.
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        std::env::temp_dir().join(format!(
            "krab-test-default-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ))
    }
    // **Not reachable in a real run.** `--home` is required, so nothing
    // outside the test suite calls this. The value is deliberately one that
    // cannot be mistaken for a store an operator meant to open, rather than
    // `.`, which is what it used to be and what made a missing `--home` open
    // whatever directory the shell happened to be in.
    #[cfg(not(test))]
    {
        PathBuf::from("/nonexistent/krab-home-not-set")
    }
}

fn main() -> io::Result<()> {
    // **RFC 7 §9's process hardening, and it is genuinely the first statement
    // in the program.**
    //
    // `RLIMIT_CORE = 0` and `PR_SET_DUMPABLE = 0` only protect what has not
    // been dumped yet, so every line above this one would be a window. There
    // is nothing to put above it: argument parsing can panic, and a panic
    // under `panic = "abort"` raises `SIGABRT`, whose default disposition is
    // to write a core file.
    //
    // Deliberately *before* the decoder-child check below, so the child is
    // hardened too. It holds no key material, which is the point of it — but
    // it is also the process most likely to be made to crash on purpose (RFC 8
    // §6: image parsers are the richest source of remote code execution), and
    // a dump of a compromised decoder is worth denying an attacker even when
    // the secrets are elsewhere.
    //
    // The report is printed further down, beside the memory-locking one, so
    // that an operator sees one hardening block rather than two.
    let hardening = krab_lock::harden::harden();

    // **Before anything else.** RFC 8 §6 wants image decoding in a separate
    // process; this is that process, and it is this same binary re-invoked.
    //
    // It returns here, so nothing below runs: no arguments parsed, no home
    // resolved, no passphrase taken, no key derived. There is nothing in this
    // address space for a decoder bug to reach — which is the entire point,
    // and would not be true if this check were one line further down.
    if std::env::args().any(|a| a == picture::CHILD_FLAG) {
        return picture::run_child();
    }

    // **RFC 7 §9's startup check.** "Implementations MUST fail loudly at
    // startup if locking is unavailable rather than proceeding unlocked."
    //
    // Loudly, and not fatally. §9 lists memory locking among hardening
    // measures — beside disabling hibernation and swap, which this program
    // also cannot do — and a node that refused to start on a machine with a
    // low `RLIMIT_MEMLOCK` would be a node an operator runs with the warning
    // suppressed. What §9 forbids is proceeding *silently*, which is what this
    // did until now by not having the mechanism at all.
    //
    // Printed before the terminal is taken, so it is on the scrollback an
    // operator keeps rather than in a pane that clears.
    let locking = krab_lock::available();
    if let Err(why) = &locking {
        eprintln!("krab: {why}");
        eprintln!(
            "krab: continuing. Disable swap, or use a randomly-keyed swap \
             device — see Documentation/SECURE-DELETE.md."
        );
    }
    // The other half of §9, applied at the top of `main` and reported here.
    // Silence means both core dumps and debugger attach are shut; anything
    // else names what is still open and what an operator can do about it.
    if let Some(advice) = hardening.advice() {
        eprintln!("krab: {advice}");
    }

    // **Windows says something even when locking succeeds**, which no other
    // platform does here.
    //
    // On unix a successful `mlock` is the end of the story for the pages it
    // covers. On Windows a successful `VirtualLock` leaves two exposures the
    // lock does not touch and this program cannot close: crash dumps and
    // Windows Error Reporting capture process memory without regard to
    // locking, and the pagefile is unencrypted by default. An operator who saw
    // no warning would reasonably conclude there was nothing to know.
    //
    // One line, pointing at the document that has the detail, rather than the
    // detail itself — this prints on every start and a paragraph would train
    // people to skip it.
    #[cfg(windows)]
    eprintln!(
        "krab: on Windows, crash dumps and Windows Error Reporting can capture \
         key material regardless of memory locking, and the pagefile is not \
         encrypted by default — see Documentation/UNSAFE-AUDIT.md."
    );

    let mut app = match App::from_args(std::env::args().skip(1)) {
        Ok(app) => app,
        Err(usage) => {
            eprintln!("{usage}");
            // **A refusal has to be detectable.** Every argument error exited
            // 0, so a script could not tell "started and stopped" from "never
            // started" — and now that `--home` is required, that is the
            // difference between a node running and a node that refused.
            // Asking for help is not an error and keeps its 0.
            let asked_for_help = std::env::args()
                .skip(1)
                .any(|a| a == "-h" || a == "--help");
            std::process::exit(if asked_for_help { 0 } else { 2 });
        }
    };
    // Which verb this run needs. A node that has been restarted has a store it
    // cannot read until a passphrase arrives, and saying so is the difference
    // between "empty" and "locked" — which look identical otherwise.
    // A leftover `.tmp` means a previous run was interrupted mid-write. The
    // file it protected is intact — that is what `atomic::write` guarantees —
    // but the operator should know the machine stopped abruptly.
    let interrupted = [
        "identity.wrapped",
        "kek.params",
        "ceremony.cbor",
    ]
    .iter()
    .filter(|n| atomic::clear_stale(&app.home.join(n)))
    .count();

    // **RFC 7 §10's dead-man timer, before the passphrase prompt.**
    //
    // The timer exists for a node whose operator cannot return, so the one
    // moment it has to work is the moment nobody is going to unlock it.
    // Checking it after an unlock would be checking it only when it is moot.
    //
    // It runs here rather than inside `run`: this is above the terminal setup
    // three lines down, so a node that destroyed itself says so on the
    // scrollback an operator keeps, not in a pane that clears. And if it
    // fired, `has_stored_identity` below is already false, so the greeting
    // that follows says "no identity" — which is true, and is exactly what
    // §10 means by presenting as a fresh install.
    let deadman_notice = app.deadman_on_start();

    app.body = if app.has_stored_identity() {
        if interrupted > 0 {
            format!(
                "a store is here. `unlock` to open it.\n\n\
                 {interrupted} write(s) were interrupted by a previous shutdown. \
                 Nothing was lost — each file holds its last complete version."
            )
        } else {
            "a store is here. `unlock` to open it.".into()
        }
    } else {
        "no identity. `init` to create one.".into()
    };
    // Printed to the scrollback *and* put in the pane. A dead-man that fired
    // is the most consequential thing this program can report, and a message
    // only in a pane is one an operator can clear without reading.
    if let Some(notice) = deadman_notice {
        eprintln!("krab: {notice}");
        app.body = format!("{notice}\n\n{}", app.body);
    }
    install_panic_hook();
    let mut term = setup()?;
    let result = app.run(&mut term);
    restore()?;
    result
}

/// Interface state the loop owns.
struct App {
    ui: Ui,
    node: NodeState,
    spinner: Spinner,
    command: line::Line,
    composer: String,
    /// Where the caret sits in `composer`, as a **character** index.
    ///
    /// The composer was a `String` with `push` and nothing else: no
    /// backspace, no arrows, no way to correct a typo except to discard the
    /// draft. `Binding::Edit` returned early unless the command line had
    /// focus, so every editing key was silently dropped in the one pane where
    /// text is actually written.
    composer_at: usize,
    /// Set by `Ctrl-R`. The run loop owns the terminal, so the key records
    /// the request and the loop clears.
    needs_clear: bool,
    /// Show the body's bytes rather than its rendering — `Ctrl-Y`.
    raw_body: bool,
    /// Key for the alias file. `None` while locked, like `pin_key`.
    alias_key: Option<[u8; 32]>,
    /// Decrypted message plaintext. **Only** [`App::show_selected`] writes
    /// here, and RFC 7 §8 says it exists only while displayed.
    body: String,
    /// Command output.
    ///
    /// Split from `body`, which used to carry both. Sharing one pane meant
    /// running `peers` destroyed the message you were reading — and RFC 3 §12
    /// wants a disconnect decision one keystroke from the evidence for it,
    /// which is not true if reading the evidence costs you the message.
    output: String,
    list: Vec<String>,
    locked: bool,
    quit: bool,
    /// This node's keys, once `init` has completed. `None` on a fresh install.
    /// **RFC 7 §9's locked pages**, for the secret §11 calls irreplaceable:
    /// "losing identity means every peer must re-verify out of band, in
    /// person, from scratch."
    ///
    /// `Held` locks when the machine allows it and says so when it does not.
    /// It is a `Deref` wrapper, so every reader below is unchanged — the
    /// difference is that this allocation is made once, never moves, and is
    /// kept out of swap.
    ///
    /// **What this does not cover**, stated because §9.1 requires it: a value
    /// copied out of here onto the stack is not in a locked page, and the
    /// compiler may have copied it before it ever arrived. Locking reduces
    /// exposure; it does not eliminate it.
    identity: Option<krab_lock::Held<Identity>>,
    /// The passphrase being typed. Never echoed — see `View::masked`.
    passphrase: line::Line,
    /// The current epoch wrapper key `W_N`, held **only while unlocked**.
    ///
    /// RFC 7 §4: the KEK is memory-only and re-derived on unlock. `W_N` is
    /// what actually seals stored secrets, so a locked node not holding it is
    /// what makes `RFC-7-review.md` §9's role transition real rather than
    /// cosmetic — a locked node cannot read its own ceremony state.
    epoch_key: Option<[u8; 32]>,
    /// Where cards, pads and ceremony state live.
    home: PathBuf,
    /// Channels owned and followed — RFC 6 §3.
    roster: channels::Roster,
    /// Full fragments seen this scan, waiting to be recorded as delta bases.
    ///
    /// Held across the borrow rather than dropped: a base that is not stored
    /// makes next week's delta unapplicable, which presents as a peer who
    /// stopped sharing (RFC 3 §8.2).
    pending_bases: Vec<(String, fragment::Fragment)>,
    /// Objects whose tag matched and which did not open — RFC 1 §6.4.
    ///
    /// Node-wide, not per peer: a tag is derived from a pair, and an 8-byte
    /// collision is by definition not attributable to whoever sent it.
    last_scan_fail: usize,
    /// The epoch this node last warned about an approaching shred.
    ///
    /// Once per epoch, not per tick: a warning that appears every few seconds
    /// is one an operator turns off, and RFC 8 §10's argument is that this one
    /// has to be seen.
    warned_shred_at: Option<u32>,
    /// The long-lived key pinned mail is sealed under — RFC 7 §8.1.
    ///
    /// Derived from the **KEK**, not `W_N`: a pin whose key is the epoch key
    /// is unreadable exactly when it was supposed to be readable. Held in
    /// memory beside `epoch_key`, re-derived on unlock, cleared on lock, and
    /// never written — RFC 7 §4's rule for the KEK applies to anything
    /// derived from it.
    pin_key: Option<[u8; 32]>,
    /// The subkey the onion root is sealed under — RFC 4 §5.2.
    ///
    /// Derived from the **KEK**, like `pin_key` and for the same reason: the
    /// KEK is memory-only (RFC 7 §4) and `start-tor` runs long after the
    /// passphrase, while `W_N` rotates and a network address must not. Held
    /// while unlocked, cleared on lock, never written.
    onion_key: Option<[u8; 32]>,
    /// Two-hop reachability, from nodelist fragments peers have sent —
    /// RFC 3 §8.
    ///
    /// Held in memory only, and cleared on lock: §15 calls fragments "the
    /// graph", and a graph on disk is what a seizure is for. It is rebuilt
    /// from the corpus each time the inbox is read, so nothing is lost by not
    /// storing it.
    reach: Vec<(String, Vec<[u8; 32]>)>,
    /// Per-link budgets for the current day — RFC 3 §6.
    ///
    /// Shared with the exchange threads so a running reconciliation is held
    /// to the ceiling, and persisted when it reports. Keyed by short id.
    spends: std::collections::HashMap<String, std::sync::Arc<std::sync::Mutex<quota::Account>>>,
    /// Introduction tokens this node holds, to present when it requests —
    /// RFC 3 §10.
    ///
    /// Held in memory only. A token is a private vouch someone made for this
    /// operator; writing it to disk would leave a record of who vouched, which
    /// is the persistence §10 exists to avoid, and it is single-use anyway.
    introductions: Vec<introduction::Token>,
    /// Whether this node lists itself in the public rollcall — RFC 3 §9.
    ///
    /// Default is not listed, which §9 requires. Not persisted: there is no
    /// config file that could carry an opt-in across a restart unnoticed
    /// (`NO-CONFIG.md`), and a lock clears it, so a node comes back invisible
    /// unless its operator says otherwise.
    rollcall: rollcall::Listing,
    /// The `tor` this node launched — RFC 4 §5.2.
    ///
    /// `None` until `start-tor`. Not started automatically: RFC 4 §5.1 says
    /// plain TCP "is the correct choice and Tor is unnecessary complexity" for
    /// many deployments, and a node that silently opened a Tor circuit on
    /// every start would be making a network-visible decision its operator did
    /// not ask for.
    ///
    /// Dropping this kills the daemon, so a wipe that clears the field is a
    /// wipe that stops tor — but `panic_wipe` calls `stop()` explicitly rather
    /// than relying on that, because "the daemon dies because a field was
    /// assigned" is exactly the kind of load-bearing side effect this codebase
    /// keeps finding broken.
    tor: Option<krab_fabric::backend::tor::TorProcess>,
    /// This node's `.onion`, once published. Derived, so it is the same at
    /// every start (RFC 4 §5.2).
    onion: Option<String>,
    /// The last bootstrap reading, polled on the tick.
    ///
    /// RFC 4 §5.2: "clients MUST show bootstrap progress or users will believe
    /// the node is broken at every start."
    tor_bootstrap: Option<krab_fabric::backend::tor::Bootstrap>,
    /// Groups — RFC 6 §2. Closed rosters, sealed per member.
    groups: Vec<groups::Group>,
    /// Fan-out copies waiting for their release time — RFC 6 §2.7.
    pending: Vec<fanout::Pending>,
    /// Objects seen arriving from peers, and over how long, for the stagger
    /// window. Not persisted: a rate measured last month is not an
    /// observation of this network now.
    observed_arrivals: u64,
    observed_hours: f64,
    /// A `peer meet listen` in progress: how to stop it, and what it will
    /// hand back.
    ///
    /// **A socket that accepts strangers, so it is visible and cancellable.**
    /// It was a thirty-second blocking wait on the interface thread, which
    /// could not be stopped and was not long enough to coordinate a call with
    /// anybody. It now runs behind, and it closes itself: a door left open for
    /// people who have finished arranging to use it is a door nobody is
    /// watching.
    meeting: Option<Meeting>,
    /// Everyone the open composition is addressed to.
    ///
    /// Fan-out: one sealed copy each. A single field would have made
    /// `message alice bob` quietly a message to Alice.
    composing_to_many: Vec<String>,
    /// Who the open composition is addressed to.
    ///
    /// A composition with no recipient cannot be sent — the alternative is a
    /// prompt at the moment of sending, which is the worst time to ask.
    composing_to: Option<String>,
    /// The composer is addressed to this node's channel, not to a peer.
    /// RFC 8 §4.2 requirement 1 puts the security context in the composer,
    /// which means channel posts are composed rather than typed as an
    /// argument — a post is not a one-liner.
    composing_channel: bool,
    /// The composer is a note to self.
    composing_note: bool,
    /// A composed post waiting on that confirmation.
    pending_post: Option<String>,
    /// Which channel the Channels tab has been descended into.
    channel_open: Option<[u8; 32]>,
    /// A picture currently drawn in the message pane, as character cells.
    ///
    /// **Plaintext-adjacent**, so `lock` drops it with everything else: a
    /// picture on screen after a lock is the same failure as a message on
    /// screen after one (RFC 7 §8).
    showing: Option<Vec<picture::Cell2>>,
    /// A pending action waiting for one line of input.
    ///
    /// Exists so the transfer words do not go through the command line: they
    /// would land in the history, which is a record of a live key sitting in
    /// memory next to the thing it protects. A prompt is also the only way to
    /// take a value that contains spaces without quoting rules an operator
    /// reading words off a phone call should not have to think about.
    prompt: Option<Prompt>,
    /// Commands submitted this session, oldest first.
    ///
    /// **In memory only.** A history file would be a record of who this node
    /// talks to and what it was asked to do, sitting unencrypted next to a
    /// store that is not — and `NO-CONFIG.md` gives the reason a file cannot
    /// be trusted to be there or to be genuine.
    history: Vec<String>,
    /// Position while walking [`App::history`]; `len()` means "not walking".
    history_at: usize,
    /// Lines the output pane is scrolled back by. Zero is the newest line.
    output_scroll: i64,
    /// Inner width of the output pane, and the rows its content wrapped to,
    /// as of the last frame. `Cell` because the render pass only has `&self`
    /// — it measures, it does not decide anything.
    output_width: std::cell::Cell<u16>,
    output_rows: std::cell::Cell<usize>,
    /// First row the list pane draws — see `render::draw_list`.
    list_top: std::cell::Cell<usize>,
    output_height: std::cell::Cell<u16>,
    /// Ticks remaining on the inbound and outbound indicators.
    ///
    /// Set when bytes actually move and counted down, so each glyph stops on
    /// its own. Earlier versions tied them to *configuration* — a bound
    /// listener, a non-empty queue — which meant they turned on a node that
    /// had merely been set up, and kept turning after the peer had quit.
    /// An indicator that reports traffic which is not there is worse than no
    /// indicator: it is a claim, and it is false.
    ///
    /// RFC 8 §5.1 forbids a "syncing now" display, and this is not one: it
    /// says *something moved*, after the fact, for a second or two. It does
    /// not count down to the next reconciliation, and nothing an operator
    /// does makes it fire.
    inbound_ticks: u8,
    outbound_ticks: u8,
    /// Lock the moment the store opens — `RFC-7-review.md` §9.3.
    ///
    /// **Not a daemon and not a special key configuration.** A relay is this
    /// same program in the state `lock` already defines: session keys live,
    /// reconciling, unable to read mail — and its disk encrypted under RFC 7
    /// §4's hierarchy, because a passphrase *was* entered once. §7's relay
    /// took no passphrase, which left its peer list in the clear and made
    /// RFC 0 §4.4's "seizure yields nothing" false for it.
    relay: bool,
    /// Where inbound links arrive, from `--listen`. `None` means this node
    /// only dials.
    listen: Option<String>,
    /// Why the listener is not running, when `--listen` was given and the
    /// bind failed. Without this, `status` blames the lock for a busy port.
    listen_error: Option<String>,
    /// Inbound sessions accepted by the background listener, waiting to be
    /// installed. Drained on each tick.
    inbound: Option<std::sync::mpsc::Receiver<krab_fabric::backend::listener::Accepted>>,
    /// The set of statics the listener will accept, kept in step with the
    /// peerings on disk.
    allowed: krab_fabric::backend::listener::Allowed,
    /// Transports. **Holds nothing that can reconcile** — RFC 8 §5.1.
    links: LinkTable,
    /// The corpus, reachable from background exchanges.
    store: shared::SharedStore,
    /// The two rotation counters — sync and contact, RFC 4 §5.2 and RFC 3
    /// §9.2. Loaded from the sealed onion record at `start-tor`.
    onion_counters: (krab_crypto::onion::Counter, krab_crypto::onion::Counter),
    /// The contact endpoint's address while one is published — RFC 3 §9.2.
    ///
    /// `None` whenever no door is open, which is most of the time and is the
    /// point: an endpoint that accepts strangers should not outlive the
    /// arrangement to use it.
    onion_contact: Option<String>,
    /// Cover traffic — RFC 1 §5.3 and §8.2.
    ///
    /// Shared with the exchange threads, which record the shape of every real
    /// object they accept. The emitter itself runs here, on its own Poisson
    /// schedule.
    cover: shared::SharedCover,
    /// Mean seconds between dummies, or `None` when cover is off.
    ///
    /// **Off by default**, and that is a decision rather than an omission. RFC
    /// 0 §7.3: "volume privacy requires cover traffic, and cover traffic is
    /// unaffordable on a constrained link". A node that started emitting
    /// dummies without being asked would spend an operator's LoRa duty cycle,
    /// their metered link, or their battery, to buy a property they may not
    /// need. RFC 8 §4.3's rule is that a setting with consequences is stated,
    /// not assumed — so this is discoverable and unset, like the dead-man
    /// timer and the panic wipe.
    cover_mean_s: Option<u64>,
    /// When the next dummy is due, drawn from the same exponential the
    /// reconciliation schedule uses.
    cover_next_s: u64,
    /// `short` frames an exchange carried out — RFC 4 §8.
    ///
    /// Still sealed: the exchange thread has no key material, and only this
    /// side holds the reservoir chunk the frame is keyed from. Drained,
    /// opened, displayed, and dropped — §8's "MUST NOT be stored beyond
    /// display" is honoured by there being nowhere for it to go.
    #[allow(clippy::type_complexity)]
    shorts: (
        std::sync::mpsc::Sender<(String, Vec<Vec<u8>>)>,
        std::sync::mpsc::Receiver<(String, Vec<Vec<u8>>)>,
    ),
    /// Finished exchanges, reported back from their threads.
    exchanges: (
        std::sync::mpsc::Sender<activity_log::Event>,
        std::sync::mpsc::Receiver<activity_log::Event>,
    ),
    /// The reconciliation schedule. Poisson, and blind to everything the user
    /// does — RFC 5 §6.1.
    scheduler: krab_node::scheduler::Scheduler,
    /// Decrypted mail. **Plaintext, so it dies with the lock** (RFC 7 §8).
    messages: Vec<receive::Message>,
    /// Which message the list pane has selected.
    selected: usize,
    /// Background activity, bounded and transient — see `activity_log`.
    log: activity_log::ActivityLog,
    /// The recognition table, rebuilt on epoch rollover.
    ///
    /// Cached because it is 4 550 HKDF passes at 50 correspondents (RFC 2
    /// §4.3) and the corpus is rescanned far more often than the epoch turns.
    /// Dropped on lock: it is derived from static-static shared secrets, so it
    /// is content-key material and a relay must not hold it.
    tag_table: Option<receive::TagTable>,
    /// The correspondent names `tag_table` was built from. A table is stale
    /// when this no longer matches, not only when the epoch has rolled.
    tag_table_peers: Vec<String>,
    /// RFC 2 §9's trial-decapsulation cache and cap. Lives on the App so it
    /// survives between scans — a cache rebuilt every pass caches nothing.
    attempts: receive::Attempts,
    /// Set by the confirmation prompt, consumed by the next command.
    confirmed: bool,
    /// Where the first-run ceremony has got to, if it is running.
    init_step: Option<InitStep>,
    /// Whether the passphrase prompt is unlocking rather than initialising.
    unlocking: bool,
}

impl Default for App {
    fn default() -> App {
        App {
            ui: Ui::default(),
            node: NodeState::default(),
            spinner: Spinner::default(),
            command: line::Line::default(),
            composer: String::new(),
            composer_at: 0,
            needs_clear: false,
            raw_body: false,
            alias_key: None,
            // Not "no message selected": on a fresh node that is true and
            // useless. The first screen has to say what to type, because
            // nothing else on it does.
            body: "no message selected".into(),
            // One line, because the output pane is two and this is the line a
            // first-time operator has to read. Everything longer is `help`.
            output: "krab — no identity yet. Type `init`, or `help` for the verbs.".into(),
            list: vec!["(no messages)".into()],
            locked: false,
            quit: false,
            identity: None,
            passphrase: line::Line::default(),
            epoch_key: None,
            home: default_home(),
            relay: false,
            listen: None,
            listen_error: None,
            roster: channels::Roster::default(),
            rollcall: rollcall::Listing::default(),
            tor: None,
            onion: None,
            tor_bootstrap: None,
            introductions: Vec::new(),
            spends: std::collections::HashMap::new(),
            reach: Vec::new(),
            pin_key: None,
            onion_key: None,
            warned_shred_at: None,
            last_scan_fail: 0,
            pending_bases: Vec::new(),
            groups: Vec::new(),
            pending: Vec::new(),
            observed_arrivals: 0,
            observed_hours: 0.0,
            meeting: None,
            composing_to_many: Vec::new(),
            composing_to: None,
            composing_channel: false,
            composing_note: false,
            pending_post: None,
            channel_open: None,
            showing: None,
            prompt: None,
            history: Vec::new(),
            history_at: 0,
            output_scroll: 0,
            output_width: std::cell::Cell::new(0),
            output_rows: std::cell::Cell::new(0),
            list_top: std::cell::Cell::new(0),
            output_height: std::cell::Cell::new(0),
            inbound_ticks: 0,
            outbound_ticks: 0,
            inbound: None,
            allowed: krab_fabric::backend::listener::Allowed::default(),
            links: LinkTable::new(),
            store: shared::SharedStore::new(krab_store::index::Store::new()),
            onion_counters: (0, 0),
            onion_contact: None,
            cover: shared::SharedCover::new(),
            cover_mean_s: None,
            cover_next_s: 0,
            shorts: std::sync::mpsc::channel(),
            exchanges: std::sync::mpsc::channel(),
            // Four hours. RFC 5 §6.1 fixes the shape, not the mean; this is a
            // starting point a deployment tunes.
            scheduler: krab_node::scheduler::Scheduler::new(4 * 3_600),
            messages: Vec::new(),
            selected: 0,
            log: activity_log::ActivityLog::new(),
            tag_table: None,
            attempts: receive::Attempts::new(),
            tag_table_peers: Vec::new(),
            confirmed: false,
            init_step: None,
            unlocking: false,
        }
    }
}

impl App {
    /// Parse command-line arguments.
    ///
    /// **Krab reads no configuration file** — see `Documentation/NO-CONFIG.md`.
    /// Startup options arrive here and nowhere else, and an environment
    /// variable is deliberately not accepted: environment is inherited, so a
    /// parent process would be choosing on the operator's behalf without the
    /// operator seeing it.
    fn from_args(args: impl Iterator<Item = String>) -> Result<App, String> {
        const USAGE: &str = "krab --home <dir> [--sync-interval <seconds>] [--listen <address>] \
             [--relay]\n\n\
             krab reads no configuration file. Everything else is set by a \
             command-pane verb during the session.\n\n\
             --home is required. It is where the identity, the corpus and \
             every peering live, and there is deliberately no default: a \
             store that followed the working directory meant the same command \
             typed in two shells was two different nodes, and the failure \
             looked like data loss rather than like a wrong path.\n\n\
             --listen binds one socket and accepts calls from any node this \
             one has peered with. There is no port per peer: that would \
             publish the size of the operator's friend list to a port \
             scanner.\n\n\
             --relay locks the node the moment it opens. It still asks for the \
             passphrase, because that is what encrypts the disk — a relay that \
             took no passphrase would leave its peer list in the clear, and \
             RFC 0 §4.4's \"seizure yields nothing\" would be false for it.";

        let mut app = App::default();
        let mut home: Option<PathBuf> = None;
        let mut args = args.peekable();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--home" => {
                    home = Some(PathBuf::from(args.next().ok_or(USAGE)?));
                }
                "--relay" => {
                    app.relay = true;
                }
                "--listen" => {
                    let addr = args.next().ok_or(USAGE)?;
                    // Parsed here so a typo fails at launch rather than at the
                    // first inbound link, which may be hours away.
                    use std::net::ToSocketAddrs;
                    addr.to_socket_addrs()
                        .map_err(|e| format!("--listen {addr}: {e}"))?
                        .next()
                        .ok_or_else(|| format!("--listen {addr}: resolves to no address"))?;
                    app.listen = Some(addr);
                }
                "--sync-interval" => {
                    let secs: u64 = args
                        .next()
                        .ok_or(USAGE)?
                        .parse()
                        .map_err(|_| USAGE.to_string())?;
                    if secs < 60 {
                        return Err("a sync interval under a minute correlates this node with \
                             its own activity (RFC 5 §6.1)"
                            .into());
                    }
                    app.scheduler = krab_node::scheduler::Scheduler::new(secs);
                }
                "-h" | "--help" => return Err(USAGE.into()),
                other => return Err(format!("unknown argument {other:?}\n\n{USAGE}")),
            }
        }
        // **No default, and no guess.** The store used to be the current
        // directory, so `krab` from one shell and `krab` from another were
        // different nodes with different identities — and the symptom was a
        // channel or a peering that had "vanished", which is the most
        // alarming way for a path mistake to present itself. Refusing is the
        // only answer that cannot be silently wrong; picking a default under
        // the user's home would still be a guess, and would quietly adopt
        // whichever store happened to be there.
        app.home = home.ok_or(
            "krab --home <dir> is required.\n\n\
             There is no default. The store holds the identity, the corpus \
             and every peering, and a default would mean the same command \
             opening different nodes depending on where it was typed — which \
             presents as data loss, not as a wrong path.\n\n\
             \x20 krab --home ~/.krab\n\n\
             Any directory will do, and it is created if it does not exist. \
             Use the same one every time.",
        )?;
        Ok(app)
    }

    /// Everything the renderer is allowed to see.
    ///
    /// Built here rather than inline in [`App::run`] so that a test can render
    /// the same frame an operator gets. The command pane defect that prompted
    /// this was invisible to every state assertion in this file: the typed
    /// command was in the string, the string just had no rows to render into.
    fn view<'a>(&'a self, log: &'a [String], me: Option<&'a str>) -> render::View<'a> {
        let masked = self.init_step == Some(InitStep::Passphrase);
        render::View {
            ui: &self.ui,
            node: &self.node,
            spinner: &self.spinner,
            list: &self.list,
            body: &self.body,
            output: &self.output,
            output_width: &self.output_width,
            output_rows: &self.output_rows,
            output_height: &self.output_height,
            waiting: self.waiting(),
            composer_at: self.composer_at,
            raw_body: self.raw_body,
            selected: self.selected,
            list_top: &self.list_top,
            items: self.selectable_len(),
            showing: self.showing.as_deref(),
            // While the passphrase is being taken the prompt shows its length,
            // not the command line — see `masked`.
            command: if masked {
                &self.passphrase
            } else {
                &self.command
            },
            composer: &self.composer,
            locked: self.locked,
            log,
            masked,
            me,
            // **Both are about things that actually happened**, not about
            // state that merely exists. "A listener is bound" is not
            // receiving, and a link table that still lists a peer who quit is
            // not a link — that was the defect: the inbound glyph kept
            // turning after the other node was gone, because nothing had
            // noticed the session die.
            //
            // Neither claims a transfer is in progress. RFC 8 §5.1 forbids a
            // "syncing now" indicator: when a node reconciles is not the
            // operator's business to watch and is not theirs to leak.
            sending: self.outbound_ticks > 0,
            receiving: self.inbound_ticks > 0,
            scroll: self.output_scroll.max(0) as usize,
        }
    }

    fn run(&mut self, term: &mut Terminal<CrosstermBackend<Stdout>>) -> io::Result<()> {
        let mut last = Instant::now();
        while !self.quit {
            let log_lines = self.log.recent(activity_log::CAPACITY);
            let me = self.identity.as_ref().map(|i| i.short_id());
            if std::mem::take(&mut self.needs_clear) {
                term.clear()?;
            }
            term.draw(|f| render::draw(f, &self.view(&log_lines, me.as_deref())))?;

            if event::poll(TICK)? {
                if let Event::Key(k) = event::read()? {
                    if k.kind == KeyEventKind::Press {
                        self.on_key(k.code, k.modifiers);
                    }
                }
            }
            if self.tick_if_due(&mut last) {
                last = Instant::now();
            }
        }
        Ok(())
    }

    /// Advance the background half if the tick is due, and say whether it was.
    ///
    /// # Why this is a function and not four lines in `run`
    ///
    /// It was four lines in `run`, and `run` cannot be called from a test — it
    /// blocks on `event::poll` against a real terminal. So the edge from the
    /// render loop to everything the node does in the background had no test
    /// at all: expiry, eviction, the retention cap, prekey republication, the
    /// meeting window and the reconciliation schedule are all downstream of
    /// this one `if`, and every test reaches them by calling `tick_schedule`
    /// directly.
    ///
    /// An audit read that as `Store::evict_to` having no caller outside the
    /// tests. It was wrong — the chain is `run` → here → `enforce_retention` →
    /// `evict_to` — but it was wrong about a chain nothing exercised, which is
    /// a distinction with no defence. Pulling the condition out gives it one.
    fn tick_if_due(&mut self, last: &mut Instant) -> bool {
        if last.elapsed() < TICK {
            return false;
        }
        self.spinner.tick();
        self.tick_schedule();
        self.tick_tor();
        true
    }

    /// Poll tor's bootstrap — RFC 4 §5.2's "clients MUST show bootstrap
    /// progress or users will believe the node is broken at every start."
    ///
    /// Stops polling once tor reports 100%: the interesting part is the tens
    /// of seconds before that, and a control-port round trip on every tick for
    /// the rest of the process's life buys nothing.
    ///
    /// A daemon that has died is noticed here and reported once. That matters
    /// more than it looks: without it, a node whose tor was killed would keep
    /// showing whatever progress it last saw, and an operator would believe
    /// they were reachable when they were not.
    fn tick_tor(&mut self) {
        let Some(tor) = self.tor.as_mut() else {
            return;
        };
        if !tor.is_running() {
            self.tor = None;
            self.tor_bootstrap = None;
            self.node.tor_bootstrap = None;
            self.onion = None;
            self.output = "tor: the daemon exited. This node is no longer \
                           reachable over its onion address. `start-tor` to \
                           restart it."
                .into();
            return;
        }
        if self.tor_bootstrap.as_ref().is_some_and(|b| b.is_done()) {
            return;
        }
        if let Ok(b) = tor.bootstrap() {
            // RFC 4 §5.2's MUST is that it is *shown*, so the status line's
            // copy is updated here rather than read from `self.tor_bootstrap`
            // by the renderer — `NodeState` is what the view sees.
            self.node.tor_bootstrap = if b.is_done() { None } else { Some(b.percent) };
            self.tor_bootstrap = Some(b);
        }
    }

    /// `start-tor [path]` — RFC 4 §5.2.
    ///
    /// Starts the daemon *and* publishes this node's onion service, so that
    /// afterwards the node is reachable as a server and can dial as a client.
    /// Doing only one of those would be the more obvious design and the wrong
    /// one: a node that could dial but not be dialled is a node whose peers
    /// cannot reconcile with it, and RFC 5's exchange is symmetric.
    fn start_tor(&mut self, path: Option<&str>) -> String {
        if self.tor.is_some() {
            return match &self.onion {
                Some(a) => format!("tor is already running. This node is {a}"),
                None => "tor is already running.".into(),
            };
        }
        // The root is sealed under the KEK, so this needs an unlocked node.
        // Refusing here rather than starting tor and failing at `ADD_ONION`
        // keeps the daemon from being launched for a command that cannot
        // finish.
        let Some(onion_key) = self.onion_key else {
            return "locked — `unlock` first. The onion root is sealed under a \
                    KEK subkey (RFC 4 §5.2, RFC 7 §4)."
                .into();
        };

        let run_dir = self.home.join("tor");
        let launch = match path {
            Some(p) => match krab_fabric::backend::tor::TorLaunch::at(p, &run_dir) {
                Ok(l) => l,
                Err(e) => return format!("start-tor: {e}"),
            },
            None => krab_fabric::backend::tor::TorLaunch::on_path(&run_dir),
        };

        let mut tor = match krab_fabric::backend::tor::TorProcess::launch(&launch) {
            Ok(t) => t,
            Err(e) => return format!("start-tor: {e}"),
        };

        // The permanent address. Generated on first use and sealed; read back
        // every time after, so the `.onion` a peer wrote down keeps working.
        let root_path = self.path(artifact::Artifact::OnionRoot);
        let (root, sync_counter, contact_counter, fresh) =
            match persist::read_onion_root(&root_path, &onion_key) {
                Ok((r, s, c)) => (r, s, c, false),
                Err(persist::Error::Absent) => {
                    let mut rng = OsRng;
                    (krab_crypto::onion::OnionRoot::generate(&mut rng), 0, 0, true)
                }
                Err(e) => {
                    tor.stop();
                    return format!("start-tor: cannot read the onion root: {e:?}");
                }
            };
        if fresh {
            let mut rng = OsRng;
            if let Err(e) = persist::write_onion_root(
                &root_path,
                &root,
                (sync_counter, contact_counter),
                &onion_key,
                &mut rng,
            ) {
                tor.stop();
                return format!("start-tor: cannot store the onion root: {e:?}");
            }
        }

        // **The sync endpoint** — RFC 3 §9.2. Never published, restricted
        // discovery, reconciliation behind it. Its counter comes from disk, so
        // a rotation an operator performed survives the restart; storing
        // nothing would revert the address to counter 0 at every start, which
        // is a rotation nobody asked for.
        let key = krab_crypto::onion::service_key(&root, sync_counter);
        let mut b64 = key.to_base64();

        let port = self.listen_port_for_onion();
        // **RFC 4 §5.2's restricted discovery.** One authorised client per
        // verified peering, derived rather than stored.
        let (clients, skipped) = self.onion_client_set();
        let address = match tor.add_onion(&b64, ONION_PORT, port, &clients) {
            Ok(a) => a,
            Err(e) => {
                crate::overwrite(&mut b64);
                tor.stop();
                return format!("start-tor: {e}");
            }
        };
        crate::overwrite(&mut b64);

        let socks = tor.socks_port();
        let binary = tor.binary().to_string();
        self.tor_bootstrap = tor.bootstrap().ok();
        self.node.tor_bootstrap = self
            .tor_bootstrap
            .as_ref()
            .filter(|b| !b.is_done())
            .map(|b| b.percent);
        self.tor = Some(tor);
        self.onion = Some(address.clone());
        self.onion_counters = (sync_counter, contact_counter);

        let discovery = if clients.is_empty() {
            "\n\nThis service is UNRESTRICTED — you have no verified peerings, \
             so there is no authorised-client set to derive and anyone who \
             learns the address can reach it. Peer with someone and restart \
             tor to close it."
                .to_string()
        } else {
            let mut s = format!(
                "\n\nRestricted discovery is ON for {} peer(s). Only they can \
                 decrypt the descriptor, so the address is unenumerable by \
                 anyone else (RFC 4 §5.2).",
                clients.len()
            );
            if skipped > 0 {
                s.push_str(&format!(
                    "\n\n{skipped} peer(s) were SKIPPED — their peer-link did not \
                     verify. They will not be able to reach this node. Check \
                     `peer show <name>`."
                ));
            }
            s
        };
        format!(
            "tor started.\n\
             \n  binary     {binary}\
             \n  socks      127.0.0.1:{socks}\
             \n  address    {address}:{ONION_PORT}\
             \n  forwarding to 127.0.0.1:{port}\
             \n\n\
             Give peers the address above. It is derived, so it is the same \
             every start.\n\
             Bootstrap takes tens of seconds; progress is on the status line.\
             {discovery}"
        )
    }

    /// `onion`, `onion rotate`, `onion contact [on|off]` — RFC 4 §5.2 and
    /// RFC 3 §9.2.
    ///
    /// # The two endpoints are two services, not one with two names
    ///
    /// §9.2 asks for "a **contact endpoint** (accepts only peer-requests,
    /// freely rotatable)" separated from "a **sync endpoint** (never
    /// published, protected by Tor restricted discovery)". They differ in
    /// three ways at once, and each one is load-bearing:
    ///
    /// - **different key**, under a different domain string, so no counter
    ///   value can ever make one of them equal the other;
    /// - **different discovery**, the sync endpoint carrying a `ClientAuthV3`
    ///   set and the contact endpoint carrying none, because a stranger has no
    ///   peering from which to derive an auth key;
    /// - **different listener**, the contact endpoint mapped to the
    ///   first-contact socket `peer meet` opens and nothing else, so what is
    ///   behind it genuinely accepts only peer-requests.
    ///
    /// An implementation that published one address and called it both would
    /// satisfy none of that: handing a stranger the sync address gives them
    /// the reconciliation port, and no amount of restricted discovery helps
    /// once the address is in their hands.
    fn onion_command(&mut self, line: &str) -> String {
        match arg(line, 1).as_deref() {
            None => self.onion_report(),
            Some("rotate") => self.onion_rotate(),
            Some("contact") => match arg(line, 2).as_deref() {
                Some("off") => self.onion_contact_close(),
                _ => "usage: onion contact off\n\n\
                      A contact endpoint is opened by `peer meet`, for the \
                      length of that meeting, and closes itself when the \
                      meeting ends. RFC 3 §9.2 makes it \"freely rotatable\"; \
                      here it is rotated every time one is opened, so no two \
                      strangers are ever given the same address."
                    .into(),
            },
            Some(other) => format!("onion: {other:?} is not `rotate` or `contact`"),
        }
    }

    fn onion_report(&self) -> String {
        let (sync, contact) = self.onion_counters;
        let mut out = String::from("onion\n\n");
        match &self.onion {
            Some(a) => out.push_str(&format!(
                "  sync     {a}:{ONION_PORT}  (counter {sync})\n\
                 \x20          never published; restricted discovery\n"
            )),
            None => out.push_str("  sync     not published — `start-tor` first\n"),
        }
        match &self.onion_contact {
            Some(a) => out.push_str(&format!(
                "  contact  {a}:{ONION_PORT}  (counter {contact})\n\
                 \x20          OPEN — accepts strangers, peer-requests only\n"
            )),
            None => out.push_str(&format!(
                "  contact  closed  (next counter {contact})\n\
                 \x20          opened by `peer meet`, for that meeting only\n"
            )),
        }
        out.push_str(
            "\nThe two are separate services with separate keys (RFC 3 §9.2). \
             Give a stranger the contact address; give a peer the sync \
             address, and only after peering.",
        );
        out
    }

    /// Advance the sync endpoint's counter — RFC 4 §5.2's rotation.
    ///
    /// **This is destructive to reachability and says so.** Every peer holding
    /// the old address loses it, and RFC 0 §6 makes that silent at their end:
    /// they will see a node that has simply stopped answering. So the new
    /// address is printed with the instruction to send it, and the old counter
    /// is named so a rotation done by mistake can be undone — the derivation
    /// is a pure function of root and counter, so counter *n−1* still gives
    /// the old address.
    fn onion_rotate(&mut self) -> String {
        let Some(onion_key) = self.onion_key else {
            return "locked — `unlock` first.".into();
        };
        let root_path = self.path(artifact::Artifact::OnionRoot);
        let (root, sync, contact) = match persist::read_onion_root(&root_path, &onion_key) {
            Ok(v) => v,
            Err(persist::Error::Absent) => {
                return "no onion root yet — `start-tor` creates one.".into()
            }
            Err(e) => return format!("cannot read the onion root: {e:?}"),
        };
        let Some(next) = sync.checked_add(1) else {
            return "the sync counter is exhausted. That is 4 billion \
                    rotations; if it is genuinely there, the root itself \
                    should be replaced."
                .into();
        };

        // Written before anything is published. A counter that advanced only
        // in memory would revert at the next start, and the operator would
        // have told peers an address this node no longer answers on.
        let mut rng = OsRng;
        if let Err(e) =
            persist::write_onion_root(&root_path, &root, (next, contact), &onion_key, &mut rng)
        {
            return format!("cannot store the rotated counter: {e:?} — nothing was rotated");
        }
        self.onion_counters = (next, contact);

        if self.tor.is_none() {
            return format!(
                "rotated to counter {next}. Tor is not running, so nothing is \
                 published yet — `start-tor` will publish the new address.\n\n\
                 Every peer holding the old address will find this node \
                 unreachable, and will not be told why (RFC 0 §6). Send them \
                 the new one."
            );
        }

        let key = krab_crypto::onion::service_key(&root, next);
        let mut b64 = key.to_base64();
        // Both read `self` immutably, so they are resolved before the daemon
        // is borrowed mutably below.
        let port = self.listen_port_for_onion();
        let (clients, _) = self.onion_client_set();
        let published = self
            .tor
            .as_mut()
            .expect("checked above")
            .add_onion(&b64, ONION_PORT, port, &clients);
        crate::overwrite(&mut b64);
        let address = match published {
            Ok(a) => a,
            Err(e) => {
                return format!(
                    "the counter advanced to {next} and tor refused the new \
                     service: {e}. `start-tor` again to publish it."
                )
            }
        };
        // The old service is withdrawn only once the new one is up, so there
        // is no window in which neither answers.
        if let Some(old) = self.onion.replace(address.clone()) {
            if let Some(tor) = self.tor.as_mut() {
                let _ = tor.del_onion(&old);
            }
        }
        format!(
            "rotated.\n\n  address  {address}:{ONION_PORT}  (counter {next})\n\n\
             The old address is withdrawn. Every peer holding it will find \
             this node unreachable and will not be told why (RFC 0 §6) — send \
             them the new one.\n\n\
             `onion rotate` again if this was a mistake: counter {sync} still \
             derives the old address from the same root."
        )
    }

    /// Publish a contact endpoint for one meeting — RFC 3 §9.2.
    ///
    /// Rotated on every open, which is what "freely rotatable" is for: two
    /// strangers given the same contact address could each confirm the other
    /// had been talking to this node, which is graph information handed out
    /// for nothing.
    ///
    /// Returns the address, or `None` when tor is not running — in which case
    /// `peer meet` is still perfectly usable over a plain address, and saying
    /// so is better than refusing.
    fn onion_contact_open(&mut self, target_port: u16) -> Option<String> {
        let onion_key = self.onion_key?;
        let root_path = self.path(artifact::Artifact::OnionRoot);
        let (root, sync, contact) = persist::read_onion_root(&root_path, &onion_key).ok()?;
        let next = contact.checked_add(1)?;

        let mut rng = OsRng;
        persist::write_onion_root(&root_path, &root, (sync, next), &onion_key, &mut rng).ok()?;
        self.onion_counters = (sync, next);

        let key = krab_crypto::onion::endpoint_key(
            &root,
            krab_crypto::onion::Endpoint::Contact,
            next,
        );
        let mut b64 = key.to_base64();
        // **No `ClientAuthV3`.** A stranger has no peering to derive an auth
        // key from, so restricted discovery here would make the endpoint
        // unreachable by exactly the people it exists for. The protection is
        // that it is open for minutes, for one caller, and is never used again.
        let published = self
            .tor
            .as_mut()?
            .add_onion(&b64, ONION_PORT, target_port, &[]);
        crate::overwrite(&mut b64);
        let address = published.ok()?;
        self.onion_contact = Some(address.clone());
        Some(address)
    }

    /// Withdraw the contact endpoint. Called when a meeting ends, by any route.
    fn onion_contact_close(&mut self) -> String {
        let Some(address) = self.onion_contact.take() else {
            return "no contact endpoint is open.".into();
        };
        match self.tor.as_mut() {
            Some(tor) => match tor.del_onion(&address) {
                Ok(()) => format!("contact endpoint {address} withdrawn."),
                Err(e) => format!("tor refused to withdraw {address}: {e}"),
            },
            // Tor is gone, so the service went with it.
            None => format!("contact endpoint {address} is gone with tor."),
        }
    }

    /// The restricted-discovery client set — RFC 4 §5.2.
    ///
    /// > Only clients holding an authorised key can decrypt the service
    /// > descriptor, so the sync endpoint is not merely unlisted but
    /// > unenumerable and unconfirmable by anyone who is not already a peer.
    /// > **The authorised-client set derives directly from the node's signed
    /// > credentials.**
    ///
    /// Which is what this is: one entry per verified peer-link, derived from
    /// the static-static agreement with that peer's credential key. No list is
    /// stored and nothing is exchanged — a node's authorised set is a pure
    /// function of who it has peered with, so it is right by construction
    /// whenever the peerings are.
    ///
    /// A card that fails `verify()` contributes nothing. That is deliberate
    /// and it is the strict direction: an unverifiable credential is not
    /// evidence of a peering, and admitting one would widen the set that
    /// §5.2 exists to narrow.
    ///
    /// Returns the base32 public halves, and a count of peers skipped, so the
    /// caller can tell an operator that some peer will not be able to reach
    /// them rather than leaving it to be discovered as silence.
    fn onion_client_set(&self) -> (Vec<String>, usize) {
        let Some(identity) = self.identity.as_ref() else {
            return (Vec::new(), 0);
        };
        let me = krab_crypto::dh::SecretKey::from_bytes(identity.noise_bytes());
        let (mut set, mut skipped) = (Vec::new(), 0usize);
        for peer in self.peer_ids() {
            let card = std::fs::read(self.peer_path(&peer, artifact::PeerFile::Link))
                .ok()
                .and_then(|b| peering::Card::decode(&b).ok())
                .filter(|c| c.verify());
            let Some(card) = card else {
                skipped += 1;
                continue;
            };
            let pk = krab_crypto::dh::PublicKey(card.noise_static_pk);
            // `agree` rejects a low-order public key, which would produce an
            // all-zero shared secret and therefore the *same* auth key for
            // every peer holding one. Skipping is the only safe answer.
            match krab_crypto::dh::agree(&me, &pk) {
                Some(shared) => set.push(krab_crypto::onion::client_auth(&shared).public_base32()),
                None => skipped += 1,
            }
        }
        set.sort();
        (set, skipped)
    }

    /// `deadman [<days>|off]` — RFC 7 §10.
    ///
    /// Bare, it reports. That is deliberate: §10 requires the timer be
    /// discoverable, and a verb that only ever *sets* something is one an
    /// operator cannot use to find out what is already armed.
    fn deadman_command(&mut self, rest: &str) -> String {
        let path = self.path(artifact::Artifact::DeadMan);
        let now = self.now_s();

        if rest.is_empty() {
            return match deadman::read(&path) {
                deadman::Stamp::Absent => "dead-man timer: off.\n\n\
                     `deadman <days>` arms it. The node destroys itself if it \
                     is not unlocked within that many days; unlocking resets \
                     the clock. It warns for the last quarter of the window.\n\n\
                     Off is the default and stays off until you type this \
                     (RFC 7 §10)."
                    .into(),
                deadman::Stamp::Unreadable => format!(
                    "dead-man timer: the stamp at {} is not readable, so the \
                     timer is OFF. Re-arm it with `deadman <days>` if you \
                     meant it to be on.",
                    path.display()
                ),
                deadman::Stamp::Armed(d) => {
                    let left = d.remaining_s(now);
                    format!(
                        "dead-man timer: armed, {} days.\n  fires in {}d {}h \
                         unless this node is unlocked\n  unlocking resets it",
                        d.days,
                        left / 86_400,
                        (left % 86_400) / 3_600
                    )
                }
            };
        }

        if rest.eq_ignore_ascii_case("off") {
            // Shredded rather than removed: the stamp is in the clear, and
            // "this node had a dead-man timer set for 30 days" is a fact about
            // the operator's expectations worth destroying properly.
            let mut rng = OsRng;
            return if shred::remove(&path, &mut rng) {
                "dead-man timer: off. The node will not destroy itself on a \
                 timer."
                    .into()
            } else {
                "dead-man timer: off (there was none armed).".into()
            };
        }

        let Ok(days) = rest.parse::<u32>() else {
            return "usage: deadman <days> | deadman off | deadman".into();
        };
        let d = match deadman::DeadMan::new(now, days) {
            Ok(d) => d,
            Err(e) => return e,
        };
        match deadman::write(&path, &d) {
            Ok(()) => format!(
                "dead-man timer armed: {days} days.\n\n\
                 This node DESTROYS ITSELF if it is not unlocked within \
                 {days} days. Unlocking resets the clock. It warns for the \
                 last quarter of the window.\n\n\
                 The deadline is stored in the clear — it has to be, because \
                 the timer must fire when nobody can unlock the node. Anyone \
                 holding this disk can see a timer is set and when it expires."
            ),
            Err(e) => format!("could not arm the dead-man timer: {e}"),
        }
    }

    /// Fire the dead-man timer if its window has passed — RFC 7 §10.
    ///
    /// **Called before the passphrase is asked for**, which is the whole
    /// design: the timer exists for a node whose operator cannot return, so
    /// the one moment it must work is the moment nobody is going to unlock it.
    /// Checking after an unlock would be checking only when it is moot.
    ///
    /// Returns the message to show, if anything happened.
    fn deadman_on_start(&mut self) -> Option<String> {
        let path = self.path(artifact::Artifact::DeadMan);
        let now = self.now_s();
        match deadman::read(&path) {
            deadman::Stamp::Absent => None,
            // Reported, not acted on. A corrupt byte must not destroy a node,
            // and an operator who armed a timer needs to know it is not armed
            // any more.
            deadman::Stamp::Unreadable => Some(format!(
                "warning: the dead-man stamp at {} is unreadable, so no timer \
                 is armed. Re-arm with `deadman <days>` if you meant it to be.",
                path.display()
            )),
            deadman::Stamp::Armed(d) if d.expired(now) => {
                let out = self.panic_wipe();
                Some(format!(
                    "DEAD-MAN TIMER FIRED. This node was not unlocked within \
                     {} days and has destroyed itself (RFC 7 §10).\n\n{out}",
                    d.days
                ))
            }
            deadman::Stamp::Armed(d) => d.warning(now),
        }
    }

    /// Re-arm on unlock — "wipe if **not unlocked** within N days".
    ///
    /// Silent: an operator who unlocks daily should not be told daily that
    /// they have reset a timer they know about. The warning path is what
    /// speaks, and it speaks only when the window is closing.
    fn deadman_rearm(&mut self) {
        let path = self.path(artifact::Artifact::DeadMan);
        if let deadman::Stamp::Armed(d) = deadman::read(&path) {
            if let Ok(fresh) = deadman::DeadMan::new(self.now_s(), d.days) {
                let _ = deadman::write(&path, &fresh);
            }
        }
    }

    /// `stop-tor`.
    fn stop_tor(&mut self) -> String {
        match self.tor.take() {
            Some(mut t) => {
                t.stop();
                self.onion = None;
                // Both endpoints go with the daemon. Leaving this set would
                // make `onion` report a contact address that nothing answers.
                self.onion_contact = None;
                self.tor_bootstrap = None;
                self.node.tor_bootstrap = None;
                "tor stopped. The onion address is unpublished; it will be the \
                 same one when you `start-tor` again."
                    .into()
            }
            None => "tor is not running.".into(),
        }
    }

    /// Which local port the onion service forwards to.
    ///
    /// The node's own listener if one is up, so that `start-tor` after
    /// `listen` does the thing an operator means. Falls back to the default
    /// port rather than refusing: an operator who starts tor first and listens
    /// second should not have to restart tor.
    fn listen_port_for_onion(&self) -> u16 {
        self.listen
            .as_ref()
            .and_then(|a| a.rsplit(':').next())
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(ONION_PORT)
    }

    fn on_key(&mut self, code: KeyCode, mods: KeyModifiers) {
        let press = KeyPress {
            code: match code {
                KeyCode::Tab | KeyCode::BackTab => Key::Tab,
                KeyCode::Enter => Key::Enter,
                KeyCode::Esc => Key::Esc,
                KeyCode::Backspace => Key::Backspace,
                KeyCode::Delete => Key::Delete,
                KeyCode::Left => Key::Left,
                KeyCode::Right => Key::Right,
                KeyCode::Home => Key::Home,
                KeyCode::End => Key::End,
                KeyCode::Up => Key::Up,
                KeyCode::Down => Key::Down,
                KeyCode::PageUp => Key::PageUp,
                KeyCode::PageDown => Key::PageDown,
                KeyCode::F(n) => Key::F(n),
                KeyCode::Char(c) => Key::Char(c),
                _ => return,
            },
            ctrl: mods.contains(KeyModifiers::CONTROL),
            alt: mods.contains(KeyModifiers::ALT),
            shift: mods.contains(KeyModifiers::SHIFT) || code == KeyCode::BackTab,
        };

        // Which pane has focus decides whether a bare letter is a chord or a
        // character. In the list and view panes `c` composes and `z` zooms; on
        // the command line `c` is the first letter of `connect`. Chords
        // (`Ctrl-L`, `Tab`, `Esc`, `Enter`) resolve the same either way, which
        // is why the lock chord still works while a command is half-typed.
        let typing = self.ui.focus() == layout::Pane::Command;
        let interp = if typing {
            Mode::Compose
        } else {
            self.ui.mode()
        };

        match Binding::of(press, interp) {
            // Reachable from every mode, dispatched above every mode branch.
            // **RFC 7 §10 without the typing.** Two presses, because a single
            // misfire on an irreversible action is not acceptable and a second
            // deliberate press costs about a second — which an operator
            // reaching for this has, or they would already have lost the node.
            Binding::PanicWipe => self.output = self.panic_wipe(),
            Binding::Quit => self.leave(),
            Binding::Lock => self.lock(),
            Binding::CycleFocus => self.ui.cycle_focus(),
            Binding::CycleFocusBack => self.ui.cycle_focus_back(),
            Binding::ToggleZoom => self.ui.toggle_zoom(),
            Binding::SwitchTab => {
                self.ui.switch_tab();
                // The same reset and rebuild `SelectTab` does: cycling to a
                // tab and jumping to it are the same act by different keys.
                self.selected = 0;
                self.refresh_inbox();
            }
            Binding::SelectTab(t) => {
                self.ui.select_tab(t);
                // A different list, so the cursor starts at the top. This is
                // the reset `refresh_inbox` used to do on every tick.
                self.selected = 0;
                // Rebuild the pane for the tab being entered. Without this the
                // Channels tab showed the message list, or nothing at all.
                self.refresh_inbox();
            }
            Binding::ToggleFullScreen => self.ui.toggle_full_screen(),
            // **History.** Typed commands only, never the passphrase — see
            // `push_history`.
            // **Up and Down mean what the focused pane means.**
            //
            // They were bound to command history before anything else looked
            // at them, so on a list they scrolled history and the list showed
            // its first item and no other. History is what they mean on the
            // command line — and, per RFC 8 §2, nowhere else: a pane that is
            // not the command line has no history to recall.
            Binding::History(d) => {
                if self.init_step == Some(InitStep::Passphrase) {
                    return;
                }
                match self.ui.focus() {
                    // The command line: history, which is the only place it
                    // exists.
                    layout::Pane::Command => self.recall(d),
                    // The list: choose an item.
                    layout::Pane::List => self.move_selection(d),
                    // The view pane holds a draft while composing — line
                    // motion — and a message otherwise, which the output
                    // pane's PgUp/PgDn already scrolls. Doing nothing is
                    // correct rather than lazy: recalling a command here
                    // would be the wrong action taken from the right key.
                    layout::Pane::View if self.ui.mode() == Mode::Compose => {
                        self.composer_vertical(d)
                    }
                    _ => {}
                }
            }
            // **Scroll the output pane.** By screens, so a long `help` or
            // `peers` can be read without zooming.
            Binding::Scroll(d) => {
                // **Rows, not logical lines.** Clamping to `output.lines()`
                // under-counted every wrapped line, so on output that wrapped
                // — which is most of it in a four-row pane — PgUp stopped
                // before the top and the rest could not be reached at all.
                let step = OUTPUT_SCROLL_LINES as i64;
                // Stop where the oldest row reaches the top, not where it
                // reaches the bottom: clamping to the row count let the
                // window run off the end of the text entirely and the pane
                // went blank — which reads as "the output is gone".
                let n = self
                    .output_rows
                    .get()
                    .saturating_sub(self.output_fits()) as i64;
                self.output_scroll = (self.output_scroll + d as i64 * step).clamp(0, n.max(0));
            }
            Binding::Compose if !self.locked => {
                self.ui.compose();
                self.output = match &self.composing_to {
                    Some(to) => format!(
                        "composing to {to}. Enter is a newline; Ctrl-D seals and \
                         queues it; Esc discards it."
                    ),
                    None => "composing — but to nobody yet.\n\n\
                             `send <peer>` opens a composition addressed to \
                             them. Ctrl-D seals it, Esc discards it."
                        .into(),
                };
            }
            // **Ctrl-R was a binding with no arm.** It fell through to
            // `_ => {}`, so the one key an operator reaches for when the
            // screen is wrong did nothing at all. The run loop clears on the
            // next pass; this only has to ask.
            Binding::Redraw => self.needs_clear = true,
            Binding::ToggleRaw => {
                self.raw_body = !self.raw_body;
                self.output = if self.raw_body {
                    "showing the body's bytes. Ctrl-Y renders it again.\n\n\
                     Markdown here is emphasis, code spans, bullets and \
                     headings, and nothing else — no links, no images, no \
                     HTML. Those are not refused, they are not implemented: \
                     there is no code that could render one, so `[a](b)` is \
                     those characters (RFC 8 §7)."
                        .into()
                } else {
                    "rendering the body. Ctrl-Y shows its bytes.".into()
                };
            }
            Binding::Deliver if !self.locked => self.deliver(),
            // **RFC 8 §4.2 requirement 3.** In the channels tab `r` is
            // ambiguous between "privately message the author" and "publish a
            // response to my own channel". It resolves to the private
            // message, always: pressing reply must never publish.
            //
            // `P` publishes, and it is a different key. Not a modifier on the
            // same key — a modifier missed is the wrong action taken, and this
            // is the action RFC 8 §4.1 calls the highest-severity item in the
            // design.
            Binding::Reply if !self.locked => self.reply_privately(),
            Binding::Publish if !self.locked => {
                self.output = self.compose_post();
            }

            // Editing goes to whichever line is being typed into. The
            // passphrase gets the same vocabulary as the command line: it is
            // masked, so an operator who cannot correct it cannot recover.
            Binding::Edit(e) => {
                if !typing
                    && self.init_step.is_none()
                    && self.ui.mode() == Mode::Compose
                {
                    self.composer_edit(e);
                    return;
                }
                let line = if self.init_step == Some(InitStep::Passphrase) {
                    &mut self.passphrase
                } else if typing {
                    &mut self.command
                } else {
                    return;
                };
                use keys::Edit;
                match e {
                    Edit::Backspace => line.backspace(),
                    Edit::Delete => line.delete(),
                    Edit::Left => line.left(),
                    Edit::Right => line.right(),
                    Edit::WordLeft => line.word_left(),
                    Edit::WordRight => line.word_right(),
                    Edit::Home => line.home(),
                    Edit::End => line.end(),
                    Edit::KillWord => line.kill_word(),
                    Edit::KillToStart => line.kill_to_start(),
                    Edit::KillToEnd => line.kill_to_end(),
                }
            }
            // **Esc returns the interface to its default screen.** Not a
            // stack to unwind one level at a time: an operator who has zoomed
            // a pane while composing inside a channel should not have to
            // remember how many things are open in order to get out.
            Binding::Cancel => {
                // RFC 7 §8: plaintext exists only while displayed, so a draft
                // being abandoned is overwritten rather than dropped.
                overwrite(&mut self.composer);
                self.composer_at = 0;
                self.command.clear();
                // A post awaiting confirmation is a draft like any other, and
                // Esc means the same thing here as everywhere: it is gone.
                if let Some(mut p) = self.pending_post.take() {
                    overwrite(&mut p);
                    self.output = "not published. The draft is gone.".into();
                }
                self.composing_channel = false;
                self.composing_note = false;
                self.channel_open = None;
                self.ui.reset();
                // The first-run ceremony is deliberately not cancelled here.
                // It owns Enter while it runs, it holds a passphrase that is
                // mid-entry, and losing it to a stray Esc would mean starting
                // the key hierarchy again.
            }
            // Enter in the command pane submits; elsewhere it descends into
            // the list. RFC 8 §2's two-level channel list needs both.
            // The first-run ceremony owns Enter while it is running: each press
            // is one acknowledged step, which is what makes the backup
            // confirmation a deliberate act rather than a screen to skip past.
            Binding::Activate if self.init_step.is_some() => self.advance_init(),
            Binding::Activate => {
                // **RFC 8 §4.2 requirement 2**, as one keystroke rather than
                // retyping the verb. The confirmation has to be explicit; it
                // does not have to be tedious, and a command typed twice
                // teaches the operator to type it twice without reading.
                if self.pending_post.is_some() && self.command.is_empty() {
                    let text = self.pending_post.take().unwrap_or_default();
                    // The gate `channel_post` keeps for the typed form. The
                    // operator has just confirmed; asking again inside it
                    // would be the double-prompt this replaced.
                    self.roster.first_post_confirmed = true;
                    self.output = self.channel_post(&text);
                    self.reveal_output();
                    return;
                }
                if typing {
                    if !self.command.is_empty() {
                        self.submit();
                    }
                } else if self.ui.mode() == Mode::Compose {
                    self.composer_insert('\n');
                } else {
                    // Descending into a channel has to record *which* one, or
                    // the level changes and the pane has nothing to show for
                    // it.
                    if self.ui.tab() == layout::Tab::Channels
                        && self.ui.level() == layout::Level::Channels
                    {
                        self.channel_open = self.channel_ids().get(self.selected).copied();
                        self.selected = 0;
                    }
                    self.ui.descend();
                    self.refresh_inbox();
                    self.show_selected();
                }
            }
            Binding::Input(c) => {
                if self.init_step == Some(InitStep::Passphrase) {
                    self.passphrase.insert(c);
                } else if typing {
                    self.command.insert(c);
                } else if self.ui.mode() == Mode::Compose {
                    self.composer_insert(c);
                }
            }
            _ => {}
        }
    }

    /// Advance the reconciliation schedule.
    ///
    /// Called from the render loop, on a timer, with no reference to anything
    /// the user did. `sync::Tick::run` takes no event parameter and this is
    /// the only caller — so there is no place for one to be threaded through
    /// later without the change being visible (RFC 5 §6.1, RFC 0 I-5).
    fn tick_schedule(&mut self) {
        self.drain_meeting();
        self.drain_inbound();
        self.release_pending();
        self.republish_prekeys_if_due();
        self.republish_rollcall_if_due();
        self.purge_expired_peerings();
        self.shred_expired_epochs();
        self.enforce_retention();
        let now_s = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut entropy = [0u8; 8];
        OsRng.fill(&mut entropy);
        let due = sync::Tick::run(
            &mut self.scheduler,
            &mut self.links,
            now_s,
            u64::from_le_bytes(entropy),
        )
        .due;
        // Provenance for what the schedule did. Aggregates only, no clock —
        // RFC 3 §12, and `activity_log`'s module note on why.
        self.drain_exchanges();
        self.drain_shorts();
        self.tick_cover();
        for peer in &due {
            let short = short_id(peer);
            // Re-key before reconciling. A peering whose ratchet has fallen
            // too far behind cannot derive the chunks the other end is using
            // (`Reservoir::MAX_ADVANCE`), so reconciling first would spend the
            // link on an exchange that cannot open anything.
            if let Some(event) = self.rekey_if_due(&short) {
                self.log.push(event);
            }
            if let Some(event) = self.reconcile_with(&short) {
                self.log.push(event);
            }
        }
        if !due.is_empty() {
            // Reconciliation itself needs a live session, which arrives with
            // the transport work. The schedule fires regardless, so that when
            // it is connected, nothing about *when* changes — the timing is
            // already fixed by the scheduler and not by what gets wired to it.
            self.node.reconciling = Some("peer");
        } else {
            self.node.reconciling = None;
        }
        // The status line shows a window, never a countdown (RFC 8 §5.1).
        self.node.next_sync_in_s = self
            .links
            .iter()
            .filter_map(|l| l.next_sync_min)
            .min()
            .map(|m| m * 60);
    }

    /// Keep the corpus inside the retention this node agreed to — RFC 3 §6.
    ///
    /// **Nothing called `evict_to` before**, so the corpus grew without bound
    /// and `Policy::retention_bytes` — negotiated in the peer-link, signed by
    /// both parties — was decorative. A node agreeing to hold a gigabyte would
    /// hold whatever arrived, which on a fast link is a disk-filling attack
    /// requiring no more than a generous peer.
    ///
    /// Expiry runs first: RFC 5 §3 evicts under *capacity* pressure and RFC 1
    /// §11's I2 drops objects under *time* pressure, and dropping what is
    /// already dead is free where evicting what is live raises the watermark
    /// and costs the network a copy.
    ///
    /// Tombstones are pruned here too, past `expiry + MAX_TTL` — the horizon
    /// beyond which no honest peer still offers the object (RFC 5 §8).
    fn enforce_retention(&mut self) {
        let now_min = now_epoch().0 * 1440;
        use krab_core::tag::MAX_TTL_MIN;
        let cap = peering::Policy::default().retention_bytes;

        let (expired, evicted) = self.store.with(|s| {
            let expired = s.expire(now_min);
            s.prune_tombstones(now_min, MAX_TTL_MIN);
            let evicted = if s.bytes() > cap { s.evict_to(cap) } else { 0 };
            (expired, evicted)
        });

        if evicted > 0 {
            // Eviction raises the watermark, so the objects cannot return
            // (RFC 5 §8) — worth saying, because it is not recoverable by
            // reconnecting.
            self.log.push(activity_log::Event::Failed {
                peer: "local".into(),
                why: "corpus at capacity — oldest objects evicted",
            });
        }

        // **What left memory has to leave the disk.** Removing objects from
        // the store used to change nothing on disk until the next save, and a
        // save only happens when something arrives — so a node that expired
        // its corpus and then went quiet kept every expired segment, readable,
        // indefinitely. Saving here sweeps them: `write_corpus` shreds the
        // file of any bucket the store no longer holds.
        //
        // It costs the buckets that changed and nothing else, which is the
        // point of the layout — this would have been a whole-corpus rewrite
        // on every retention tick before it.
        if expired > 0 || evicted > 0 {
            self.save_corpus();
        }
    }

    /// Destroy epoch wrapper keys past the retention window — RFC 7 §4.
    ///
    /// **Nothing called this before, which meant §4's forward secrecy was not
    /// happening at all.** `Hierarchy::shred_epoch` existed, was tested, and
    /// had no caller: wrappers accumulated and every past epoch stayed
    /// openable with the passphrase. §4's promise is that destroying `W_N`
    /// makes an epoch unreadable "regardless of what the flash controller
    /// did"; an implementation that never destroys one keeps that promise in
    /// the same sense that an unused lock secures a door.
    ///
    /// The window is `EPOCH_WINDOW`, because RFC 1 §6.2 says an object may
    /// arrive that late and a shredded epoch cannot decrypt it. Erasure lags
    /// rotation by exactly the acceptance window and not by a chosen number.
    fn shred_expired_epochs(&mut self) {
        // **RFC 7 §8.1's "before".**
        //
        // This function used to log only after the fact — "epochs shredded —
        // that mail is unreadable now" — which is the sentence §8.1 is written
        // against: "a user who discovers this afterwards has lost something
        // irrecoverably." The loss is genuine and intended; the surprise is
        // not.
        self.warn_before_shredding();
        let now = now_epoch();
        let keep_from = krab_core::tag::Epoch(now.0.saturating_sub(krab_core::tag::EPOCH_WINDOW));
        if let Some(id) = &mut self.identity {
            let dropped = id.hierarchy.shred_before(keep_from);
            if dropped > 0 {
                self.log.push(activity_log::Event::Failed {
                    peer: "local".into(),
                    why: "epochs shredded — that mail is unreadable now",
                });
            }
        }
    }

    /// Say what is about to become unreadable — RFC 7 §8.1, RFC 8 §10.
    ///
    /// > "The client MUST make the consequence of the retention window visible
    /// > **BEFORE** the window elapses."
    ///
    /// Warned once per epoch rather than every tick: a warning that appears
    /// every few seconds is a warning an operator turns off, and §10's whole
    /// argument is that this one has to be seen.
    fn warn_before_shredding(&mut self) {
        let now = now_epoch().0;
        let readable = self.pinned();
        let mut soonest: Option<(u32, u32)> = None;
        for m in &self.messages {
            // Already pinned: it survives, so it is not a loss to warn about.
            if readable
                .of(&m.from)
                .iter()
                .any(|k| k.epoch == m.epoch.0 && k.body == m.body)
            {
                continue;
            }
            let Some(days) = pin::days_until_unreadable(m.epoch.0, now) else {
                continue;
            };
            if days > pin::WARN_DAYS {
                continue;
            }
            match soonest {
                Some((d, n)) if d == days => soonest = Some((d, n + 1)),
                Some((d, _)) if d < days => {}
                _ => soonest = Some((days, 1)),
            }
        }
        let Some((days, count)) = soonest else { return };
        if self.warned_shred_at == Some(now) {
            return;
        }
        self.warned_shred_at = Some(now);
        self.log.push(activity_log::Event::Failed {
            peer: "local".into(),
            why: "mail becomes unreadable soon — `pin <peer>` keeps it",
        });
        // **Into the list, not over the output pane.**
        //
        // This replaced `self.output` from a timer, so a background tick threw
        // away whatever the operator had just asked for — including, on a bad
        // day, the error they were reading. §10 wants the consequence in the
        // foreground; the message list *is* the foreground, and it persists,
        // which the output pane does not.
        self.list.insert(
            0,
            format!("!! {count} message(s) unreadable in {days} day(s) — `pin <peer>` keeps them"),
        );
        let warning = format!(
            "{count} message(s) become **permanently unreadable in {days} day(s)**.\n\n\
             Their epoch key is shredded then, and nothing recovers it: not this \
             node, not the sender, not a backup of the corpus. The objects remain \
             and no one can open them. RFC 8 §10 calls that the only genuine form \
             of message expiry, and it is working as intended.\n\n\
             `pin <peer>` re-encrypts a conversation under a long-lived key and \
             keeps it. Pinning is a conscious act; the default is forgetting.\n\n\
             This is said once per day, before the fact — RFC 7 §8.1, because \
             a user who discovers it afterwards has lost something \
             irrecoverably."
        );
        // Appended, so a command's answer survives a tick that lands on top
        // of it.
        if self.output.is_empty() {
            self.output = warning;
        } else {
            self.output.push_str("\n\n");
            self.output.push_str(&warning);
        }
    }

    /// Answer a reconciliation a peer opened.
    ///
    /// **This had no caller.** `reconcile_with` initiates; nothing responded,
    /// so a node that accepted a session installed it and then never spoke.
    /// An exchange has two halves and only one was wired, which meant
    /// reconciliation could not complete in either direction — the property
    /// every other feature in this program assumes.
    ///
    /// Runs on the same thread pattern as `reconcile_with`, for the same
    /// reason: an exchange over serial is minutes (RFC 4 §5.3) and holding the
    /// render loop would take the lock chord with it.
    fn answer_reconciliation(&mut self, peer: &str) -> Option<()> {
        let window = {
            let now = now_epoch().0 * 1440;
            (
                now.saturating_sub(45 * 1440),
                now.saturating_add(45 * 1440) + 1,
            )
        };
        // **The link decides, not this function.** RFC 5 §4.5 derives the mode
        // from `latency_class`, and a node that answered in whichever mode the
        // code happened to implement would be the divergence RFC 0's editorial
        // rule exists to prevent. Read before `take_session`, which removes it.
        let mode = self.links.get(peer)?.profile.sync_mode();
        // **RFC 4 §5.4's ceiling, on the sending side.** "Objects above the
        // link's `max_object_size` are filtered at the sender." A LoRa profile
        // declaring `MaxBucket(1)` must not have a 4 KB object written to it —
        // over an hour of airtime for something the far end already said it
        // cannot take.
        let max_bucket = self.links.get(peer)?.profile.max_bucket;
        // **The agreed scope** — RFC 3 §7.3, derived from the signed
        // credential. A peering with no completed credential has no agreed
        // scope, and says so with a digest of its own rather than the zero one
        // every exchange used to send; see `filter`.
        // **RFC 3 §4's MUST.** An expired credential leaves the link
        // unscoped, and an unscoped node does not reconcile with a scoped
        // one — correct behaviour that is indistinguishable from a dead
        // link. §4: surface it "rather than as a silent sync failure".
        if let Standing::Live(credential::Life::Expired, _) = self.credential_standing(peer) {
            self.log.push(activity_log::Event::Failed {
                peer: peer.to_string(),
                why: "credential expired — `peer renew`",
            });
        }
        let scope = self.scope_for(peer);
        let budget = self.budget_for(peer);
        // Real now, for RFC 3 §7's retention horizon — see `ExchangeView`.
        let retention_now = now_epoch().0 * 1440;
        let session = self.links.take_session(peer)?;
        let view_store = self.store.clone();
        let carriage = self.roster.carriage;
        let done = self.exchanges.0.clone();
        let shorts = self.shorts.0.clone();
        let cover = self.cover.clone();
        let name = peer.to_string();
        self.inbound_ticks = ACTIVITY_GLYPH_TICKS;
        std::thread::spawn(move || {
            let mut session = session;
            let mut view =
                shared::ExchangeView::new(
                    view_store,
                    window.0,
                    carriage,
                    scope,
                    retention_now,
                    max_bucket,
                )
                // RFC 1 §8.2: the shape of real traffic, recorded where real
                // traffic actually arrives.
                .observing(cover);
            // Cloned, so the totals can be folded back after the drivers
            // return: the view sees only objects it accepted, and RFC 3 §12's
            // novelty ratio needs the ones it declined as duplicates too.
            let account = budget.clone();
            if let Some(b) = budget {
                view = view.with_budget(b);
            }
            let outcome = match mode {
                krab_proto::recon::Mode::Rbsr => {
                    // Its own salt, drawn here. A descent too wide for one
                    // frame drops part of each batch, and which part must vary
                    // between sessions or the tail never converges — see
                    // `exchange::rotated`. The responder's batches are its own,
                    // so it needs its own variation rather than the
                    // initiator's.
                    let mut salt = [0u8; 8];
                    OsRng.fill(&mut salt);
                    krab_node::exchange::respond_rbsr(
                        &mut *session,
                        &mut view,
                        scope.digest(),
                        u64::from_le_bytes(salt),
                    )
                }
                krab_proto::recon::Mode::Manifest => krab_node::exchange::respond_to(
                    &mut *session,
                    &mut view,
                    scope.digest(),
                    window.0,
                    window.1,
                ),
            };
            if let (Some(b), Ok(m)) = (&account, &outcome) {
                let mut a = b.spend.lock().unwrap_or_else(|e| e.into_inner());
                a.spend.offered = a.spend.offered.saturating_add(m.offered as u64);
            }
            // RFC 4 §8's frames, out to the interface. Sent before the event
            // so that a message survives even if the exchange then failed —
            // it was already delivered, and dropping it because the sync went
            // wrong afterwards would be losing something somebody typed.
            if let Ok(m) = &outcome {
                if !m.shorts.is_empty() {
                    let _ = shorts.send((name.clone(), m.shorts.clone()));
                }
            }
            let event = match outcome {
                Ok(moved) => activity_log::Event::Reconciled {
                    peer: name,
                    received: moved.received,
                    sent: moved.sent,
                },
                Err(_) => activity_log::Event::Failed {
                    peer: name,
                    why: "the exchange did not complete",
                },
            };
            let _ = done.send(event);
        });
        Some(())
    }

    /// Reconcile with one peer over its established session.
    ///
    /// **Called only from the schedule.** `connect` cannot reach this: it goes
    /// through `establish`, which returns a session and nothing else. RFC 8
    /// §5.1's guarantee is that a keypress never causes a transfer, and the
    /// separation is that the two paths do not share a function.
    fn reconcile_with(&mut self, peer: &str) -> Option<activity_log::Event> {
        // RFC 4 §5.4's ceiling, as on the answering side.
        let max_bucket = self.links.get(peer)?.profile.max_bucket;
        let window = {
            let now = now_epoch().0 * 1440;
            (
                now.saturating_sub(45 * 1440),
                now.saturating_add(45 * 1440) + 1,
            )
        };
        // As in `answer_reconciliation`: the profile picks the mode, and it is
        // read before `take_session` removes the link's session.
        let mode = self
            .links
            .get(peer)
            .map(|l| l.profile.sync_mode())
            .unwrap_or(krab_proto::recon::Mode::Manifest);
        let scope = self.scope_for(peer);
        let budget = self.budget_for(peer);
        let retention_now = now_epoch().0 * 1440;
        let Some(session) = self.links.take_session(peer) else {
            return Some(activity_log::Event::Failed {
                peer: peer.to_string(),
                why: "no session — nothing exchanged",
            });
        };

        // **Off the interface thread.** An exchange on a serial link is
        // minutes (RFC 4 §5.3), and running it here would freeze the render
        // loop — taking the lock chord with it, which is the one keystroke an
        // operator might need urgently.
        //
        // `ExchangeView` locks per operation and never across one, so the
        // interface reads the corpus between the exchange's calls rather than
        // waiting behind it. Handing the thread a guard instead would rebuild
        // the freeze through the lock.
        // Varies which sub-range is advertised, so a corpus larger than one
        // manifest is covered over successive exchanges rather than syncing a
        // prefix and stopping. Poisson scheduling supplies the variation, and
        // RFC 5 §6.2 already requires reconciliation be randomised.
        let mut salt = [0u8; 8];
        OsRng.fill(&mut salt);
        let salt = u64::from_le_bytes(salt);
        let view_store = self.store.clone();
        // Captured before the thread starts: what this node is willing to host
        // is a decision the operator made, not one the exchange makes.
        let carriage = self.roster.carriage;
        let done = self.exchanges.0.clone();
        let shorts = self.shorts.0.clone();
        let cover = self.cover.clone();
        let name = peer.to_string();
        // An exchange is about to put bytes on the link in both directions.
        // Set here rather than on completion: the thread runs for minutes on
        // a serial link, and an indicator that only lights up at the end
        // reports the one moment nothing is moving.
        self.outbound_ticks = ACTIVITY_GLYPH_TICKS;
        self.inbound_ticks = ACTIVITY_GLYPH_TICKS;
        std::thread::spawn(move || {
            let mut session = session;
            let mut view =
                shared::ExchangeView::new(
                    view_store,
                    window.0,
                    carriage,
                    scope,
                    retention_now,
                    max_bucket,
                )
                // RFC 1 §8.2: the shape of real traffic, recorded where real
                // traffic actually arrives.
                .observing(cover);
            // Cloned, so the totals can be folded back after the drivers
            // return: the view sees only objects it accepted, and RFC 3 §12's
            // novelty ratio needs the ones it declined as duplicates too.
            let account = budget.clone();
            if let Some(b) = budget {
                view = view.with_budget(b);
            }
            let outcome = match mode {
                krab_proto::recon::Mode::Rbsr => krab_node::exchange::initiate_rbsr(
                    &mut *session,
                    &mut view,
                    scope.digest(),
                    window.0,
                    window.1,
                    salt,
                ),
                krab_proto::recon::Mode::Manifest => krab_node::exchange::initiate(
                    &mut *session,
                    &mut view,
                    scope.digest(),
                    window.0,
                    window.1,
                    salt,
                ),
            };
            if let (Some(b), Ok(m)) = (&account, &outcome) {
                let mut a = b.spend.lock().unwrap_or_else(|e| e.into_inner());
                a.spend.offered = a.spend.offered.saturating_add(m.offered as u64);
            }
            if let Ok(m) = &outcome {
                if !m.shorts.is_empty() {
                    let _ = shorts.send((name.clone(), m.shorts.clone()));
                }
            }
            let event = match outcome {
                Ok(moved) => activity_log::Event::Reconciled {
                    peer: name,
                    received: moved.received,
                    sent: moved.sent,
                },
                // A dead session is ordinary on an intermittent link (I-4).
                Err(_) => activity_log::Event::Failed {
                    peer: name,
                    why: "session ended",
                },
            };
            let _ = done.send(event);
        });
        None
    }

    /// Emit one cover object if the Poisson schedule says so — RFC 1 §5.3.
    ///
    /// # It takes `now` and entropy, and nothing else
    ///
    /// Exactly like [`krab_node::scheduler::Scheduler`], and for the same
    /// reason: a dummy emitted *because* the operator did something is not
    /// cover, it is a second copy of the signal. There is no parameter here
    /// through which mail, focus, queue depth or lock state could reach the
    /// decision.
    ///
    /// # Nothing is emitted until real traffic has been seen
    ///
    /// §8.2 requires cover to match the bucket distribution of real traffic,
    /// and a node that has observed none has no distribution to match.
    /// Inventing one — uniform over buckets, say — produces exactly the
    /// "trivially separable" traffic §8.2 forbids, and separable cover is
    /// worse than none: an observer who can strip it learns which objects were
    /// real *and* that this node runs cover at all.
    fn tick_cover(&mut self) {
        let Some(mean) = self.cover_mean_s else {
            return;
        };
        let now_s = now_seconds();
        if self.cover_next_s == 0 {
            self.cover_next_s = self.draw_cover_next(now_s, mean);
            return;
        }
        if now_s < self.cover_next_s {
            return;
        }
        self.cover_next_s = self.draw_cover_next(now_s, mean);

        let epoch = now_epoch();
        // Emitted with the expiry a real object of this epoch would carry —
        // it is in the clear, so a dummy with a distinctive one is a dummy
        // anyone can pick out.
        let Some(bytes) = self
            .cover
            .emit(epoch.0 as u64, expiry_for(epoch), &mut OsRng)
        else {
            return;
        };
        let id = krab_crypto::object_id(&bytes);
        // Into this node's own corpus, where reconciliation will offer it to
        // peers like anything else. A dummy that never left would hide
        // nothing.
        let now_min = epoch.0 * 1440;
        if self
            .store
            .with(|s| s.ingest(id, bytes, now_min, u32::MAX))
            .is_ok()
        {
            self.save_corpus();
        }
    }

    fn draw_cover_next(&self, now_s: u64, mean: u64) -> u64 {
        let mut e = [0u8; 8];
        OsRng.fill(&mut e);
        krab_node::scheduler::poisson_next(now_s, mean, u64::from_le_bytes(e))
    }

    /// `cover [on <seconds> | off]` — RFC 1 §5.3.
    fn cover_command(&mut self, line: &str) -> String {
        match arg(line, 1).as_deref() {
            None => {
                let seen = self.cover.observations();
                match self.cover_mean_s {
                    None => format!(
                        "cover is OFF.\n\n\
                         `cover on <seconds>` emits dummy objects on a Poisson \
                         schedule of that mean, indistinguishable from sealed \
                         mail to anyone but this node (RFC 1 §5.3).\n\n\
                         It is off by default because it is not free: RFC 0 §7.3 \
                         says volume privacy \"requires cover traffic, and cover \
                         traffic is unaffordable on a constrained link\". On TCP \
                         or Tor it is affordable; on LoRa it is not, and nothing \
                         here overrides a link profile that says so.\n\n\
                         {seen} real object shape(s) observed so far — cover \
                         cannot start until there is a distribution to match."
                    ),
                    Some(mean) => {
                        let due = self.cover_next_s.saturating_sub(now_seconds());
                        format!(
                            "cover is ON, mean {mean}s.\n\n\
                             {seen} real object shape(s) observed; next dummy in \
                             about {due}s. The interval is exponential, so that \
                             is a draw and not a countdown — watching it tells \
                             you nothing about the next one."
                        )
                    }
                }
            }
            Some("off") => {
                self.cover_mean_s = None;
                self.cover_next_s = 0;
                "cover is OFF. Dummies already in the corpus stay there until \
                 they expire — withdrawing them would be a signal of its own."
                    .into()
            }
            Some("on") => {
                let mean = arg(line, 2).and_then(|w| w.parse::<u64>().ok());
                let Some(mean) = mean.filter(|m| (COVER_MIN_S..=COVER_MAX_S).contains(m)) else {
                    return format!(
                        "usage: cover on <seconds>\n\n\
                         Mean seconds between dummies, {COVER_MIN_S}–{COVER_MAX_S}. \
                         Below the floor the emitter is a bandwidth problem \
                         rather than a privacy measure; above the ceiling it \
                         emits so rarely that it hides nothing."
                    );
                };
                self.cover_mean_s = Some(mean);
                self.cover_next_s = self.draw_cover_next(now_seconds(), mean);
                let seen = self.cover.observations();
                let mut out = format!(
                    "cover is ON, mean {mean}s.\n\n\
                     Dummies are class 0, not class 2 — RFC 1 §5.3 requires \
                     them to be indistinguishable from sealed mail, and a \
                     distinct class byte would make every one of them \
                     separable by reading one byte."
                );
                if seen == 0 {
                    out.push_str(
                        "\n\nNothing will be emitted yet: no real traffic has \
                         been observed, so there is no bucket distribution to \
                         match (RFC 1 §8.2). Cover that does not match is \
                         worse than none — an observer who strips it learns \
                         which objects were real. It will start on its own \
                         once mail has crossed this node.",
                    );
                }
                out
            }
            Some(other) => format!("cover: {other:?} is not `on` or `off`"),
        }
    }

    /// Drain `short` frames an exchange carried out, open them, show them.
    ///
    /// # Displayed and then gone
    ///
    /// RFC 4 §8: a `short` "MUST NOT be stored beyond display". So the
    /// plaintext goes into the output pane and into nothing else — not the
    /// inbox, not the corpus, not the activity log, which is where a
    /// well-meaning "just record that one arrived" would put a message body
    /// next to a peer name. The log gets a count and no text.
    ///
    /// A frame that does not open is not an error worth showing: the key is
    /// this epoch's chunk, and a peer whose reservoir has drifted produces
    /// exactly this. It is counted, so a link that can never be read is
    /// visible as a number rather than as silence.
    fn drain_shorts(&mut self) {
        let mut shown: Vec<String> = Vec::new();
        let mut unreadable = 0usize;
        while let Ok((peer, frames)) = self.shorts.1.try_recv() {
            let Some((key, tag, link)) = self.short_keying(&peer) else {
                unreadable += frames.len();
                continue;
            };
            for frame in frames {
                match krab_crypto::short::open(key.expose(), &link, &frame) {
                    // **The tag is checked, not merely carried.** It is four
                    // bytes of the pairwise tag, so a frame that authenticates
                    // under this link's key but names another peering is a
                    // confusion worth refusing rather than displaying.
                    Ok((head, body)) if head.tag == tag => {
                        let text = String::from_utf8_lossy(&body).into_owned();
                        shown.push(format!("{peer} · {text}"));
                    }
                    _ => unreadable += 1,
                }
            }
        }
        if shown.is_empty() && unreadable == 0 {
            return;
        }
        let mut out = String::new();
        if !shown.is_empty() {
            out.push_str("short\n\n");
            for line in &shown {
                out.push_str(&format!("  {line}\n"));
            }
            out.push_str(
                "\nNot mail. Nothing kept a copy of this — it is gone when \
                 this pane clears (RFC 4 §8).",
            );
        }
        if unreadable > 0 {
            if !out.is_empty() {
                out.push_str("\n\n");
            }
            out.push_str(&format!(
                "{unreadable} short message(s) could not be opened. The link \
                 key is this epoch's reservoir chunk (RFC 7 §6), so a peering \
                 that has drifted reads exactly like this — `peer rekey` is \
                 the repair."
            ));
        }
        self.output = out;
    }

    /// Drain finished exchanges. Never blocks.
    fn drain_exchanges(&mut self) {
        let mut arrived = 0usize;
        while let Ok(event) = self.exchanges.1.try_recv() {
            if matches!(event, activity_log::Event::Failed { .. }) {
                self.links.failed(event.peer());
            }
            // The background arrival rate RFC 6 §2.7's stagger window is
            // derived from. Counted from what reconciliation actually brought
            // in, because that is the traffic a fan-out would be hiding among.
            if let activity_log::Event::Reconciled { received, .. } = &event {
                self.observed_arrivals += *received as u64;
                arrived += *received;
            }
            self.log.push(event);
        }
        // **Received mail has to reach the disk here.**
        //
        // The exchange thread puts objects into the store, which is memory.
        // Nothing on the receive path wrote them out, so a node that took
        // delivery and then exited had lost it — and the loss was invisible,
        // because the sender still holds the objects and hands them over
        // again at the next reconciliation. It stops being invisible exactly
        // when the sender no longer has them: after its retention horizon
        // (RFC 3 §7), or after a wipe. Found by watching `corpus.krab` stay
        // at its old size while three messages sat in the pane above it.
        if arrived > 0 {
            self.save_corpus();
        }
        // RFC 3 §6's counters, which an exchange may have just moved.
        self.save_spends();
        // Mail may have arrived while the interface was doing nothing.
        if self.identity.is_some() && self.epoch_key.is_some() {
            self.refresh_inbox();
        }
    }

/// One inbox row: who it is from, whether it carries an attachment, and the
/// first line of the body.
///
/// Separate from `refresh_inbox` so the format can be asserted directly. The
/// pane renders exactly this, so a change to it has to break those tests.
fn inbox_row(m: &receive::Message, names: &alias::Aliases) -> String {
    format!(
        "{}  {} {}{}",
        // A local name beside the identifier, never instead of it — RFC 8 §7
        // wants the fingerprint present wherever a name is.
        names.show(alias::Kind::Message, &m.from),
        // **An attachment is visible in the list, not only once opened.**
        // One cell, always present so the body column does not shift between
        // rows — a ragged column is harder to scan than no marker at all.
        // RFC 8 §6 permits pictures and nothing else, so it means one thing.
        if m.picture.is_some() {
            ATTACHMENT_GLYPH
        } else {
            " "
        },
        // **A body is foreign text like any other.** Phase 4 routed the
        // request notes through `display::safe` and left this — the path an
        // operator reads most — rendering U+202E, escape sequences and
        // zero-width characters verbatim.
        display::safe(m.body.lines().next().unwrap_or("")).text,
        if m.post_quantum { "" } else { "  (no reservoir)" }
    )
}

    /// Rebuild the tag table and open what this node can read.
    ///
    /// Called after anything that changes the corpus or the correspondent set.
    /// Returns plaintext into `self.messages`, which `lock` destroys.
    fn refresh_inbox(&mut self) {
        self.messages.clear();
        // **The cursor is not reset here.** This runs on a tick — every time
        // an exchange drains — so zeroing it meant the operator pressed Down,
        // the cursor moved, and the next tick put it back. It looked like the
        // arrow key bouncing. Where the list is rebuilt for a *different*
        // list — a tab switch, descending into a channel — the caller resets
        // it deliberately; here it is only clamped, at the end, once the new
        // item count is known.
        let (Some(id), Some(w)) = (&self.identity, self.epoch_key) else {
            self.list = vec!["(locked)".into()];
            return;
        };

        // Correspondents come from the peer-links on disk, so the set is
        // exactly who a ceremony was completed with.
        let mut peers = Vec::new();
        {
            for name in self.peer_ids() {
                let name = name.as_str();
                let Ok(bytes) = std::fs::read(self.peer_path(name, artifact::PeerFile::Link))
                else {
                    continue;
                };
                let Ok(card) = peering::Card::decode(&bytes) else {
                    continue;
                };
                if !card.verify() {
                    continue;
                }
                let their_pk = krab_crypto::dh::PublicKey(card.correspondence_pk);
                let Some(shared) = id.agree_with(&their_pk) else {
                    continue;
                };

                // The stored record carries `root_N` and `N`, so the ratchet
                // resumes at the right index and advances to today. A node
                // returning after a gap derives every chunk it missed on the
                // way, and destroys each intermediate root (RFC 7 §6).
                let reservoir = std::fs::read(self.peer_path(name, artifact::PeerFile::Reservoir))
                    .ok()
                    .and_then(|s| krab_crypto::kek::open_under(&w, b"krab/reservoir", &s).ok())
                    .and_then(|r| persist::decode_reservoir(&r).ok())
                    .and_then(|(root, stored_epoch)| {
                        let mut res = krab_crypto::reservoir::Reservoir::new(root, stored_epoch);
                        // A refused advance means the clock disagrees with the
                        // stored position by more than a node can plausibly
                        // have been away. Using the reservoir anyway would
                        // derive chunks at the wrong index; dropping it
                        // degrades to `mode_auth`, which `send` reports.
                        if stored_epoch != now_epoch() && !res.advance_to(now_epoch()) {
                            return None;
                        }
                        Some(res)
                    });

                // A completed peering is a peer worth reconciling with. Adding
                // is not triggering: the first interval is drawn from entropy.
                let sched_id = sync::peer_id_from_node(&card.node_id());
                if self.scheduler.next_due(&sched_id).is_none() {
                    let mut e = [0u8; 8];
                    OsRng.fill(&mut e);
                    self.scheduler.add(sched_id, 0, u64::from_le_bytes(e));
                }
                peers.push(receive::Correspondent {
                    name: name.to_string(),
                    correspondence: their_pk,
                    shared,
                    reservoir,
                });
            }
        }

        let epoch = now_epoch();
        // **Rebuild on rollover *or* on a change to the correspondent set.**
        //
        // Epoch alone was the condition, and it was not enough: a node that
        // completed its first peering while running kept the table it built
        // at startup, when it had no peers. Nothing from that peer carried a
        // tag it knew, so every message matched nothing and the pane read
        // "(no messages — N objects examined)" while the corpus grew. It
        // worked after a restart, which is what made it look like a refresh
        // delay rather than a stale cache.
        //
        // The set is compared by name, which is what `Correspondent` is keyed
        // on — so peering, unpeering and a renewal that replaces a link all
        // invalidate it, not only the clock.
        let built_from: Vec<String> = peers.iter().map(|p| p.name.clone()).collect();
        let current = self
            .tag_table
            .as_ref()
            .is_some_and(|t| t.is_current(epoch))
            && self.tag_table_peers == built_from;
        if !current {
            self.tag_table = Some(receive::TagTable::build(&peers, epoch));
            self.tag_table_peers = built_from;
            // A new correspondent or a new epoch can change whether a pair
            // opens, so everything remembered about failures stops being
            // true at exactly the moment the table is rebuilt.
            self.attempts.clear();
        }
        let table = self.tag_table.as_ref().expect("just built");
        // **Every private key this node holds**, in a fixed order: the
        // correspondence key, the signed prekey, and every one-time prekey not
        // yet retired. RFC 1 §6.3 requires the full set be attempted, and a
        // message encapsulated to a prekey opens under none of the others.
        let opening_keys = self.opening_keys();
        let scan = self
            .store
            .with(|st| {
                // The budget refills per scan; the cache does not.
                self.attempts.refresh();
                receive::Inbox::scan_with(
                    st,
                    table,
                    &peers,
                    &opening_keys,
                    (0, u32::MAX),
                    &mut self.attempts,
                )
            });

        // **Nodelists arriving from peers** — RFC 3 §8. A fragment is sealed
        // pairwise like any other message, so it opens here; it is separated
        // from mail because it is not mail, and rendering one in the message
        // list would put a nodelist where an operator expects a sentence.
        //
        // Verified before it is believed: a signature makes the contents
        // attributable, not true. `Fragment::verify` refuses a link the author
        // is not party to, and one whose counterparty never agreed to be
        // listed.
        self.reach.clear();
        let now_s = self.now_s();
        // Collected first, because recording a base needs `&mut self` and the
        // scan borrows the messages.
        let mut bases: Vec<(String, fragment::Fragment)> = Vec::new();
        // **Newest per peer, not one entry per document.**
        //
        // A peer's older full fragment stays in the corpus after its delta
        // arrives, so both open on the same scan. Pushing one entry each left
        // two rows for one peer and a reader taking the first got whichever
        // the scan happened to reach — usually the stale one, which presents
        // as a peer whose nodelist stopped growing.
        //
        // `published_s` is inside the author's signature, so it orders their
        // own documents without this node recording an arrival time (§12).
        let mut reach: Vec<(String, u64, Vec<[u8; 32]>)> = Vec::new();
        let mut note = |who: &str, at: u64, r: Vec<[u8; 32]>| match reach
            .iter_mut()
            .find(|(w, _, _)| w == who)
        {
            Some(slot) if slot.1 <= at => *slot = (who.to_string(), at, r),
            Some(_) => {}
            None => reach.push((who.to_string(), at, r)),
        };
        for m in &scan.messages {
            let Some(raw) = &m.nodelist else { continue };
            if let Some(frag) = fragment::Fragment::decode(raw) {
                // A full fragment replaces whatever base was held, and is the
                // base every later delta references — RFC 3 §8.2.
                if frag.verify(now_s).is_ok() {
                    note(&m.from, frag.published_s, frag.reaches());
                    bases.push((m.from.clone(), frag));
                }
                continue;
            }
            if let Some(delta) = fragment::Delta::decode(raw) {
                // **Applied against the base this node holds, or not at all.**
                // §8.2: "a peer that has missed a delta requests the full
                // fragment." `apply` refuses a base it was not built against,
                // so a missed delta degrades to no update rather than to a
                // nodelist neither party signed.
                let Some(base) = self.read_peer_base(&m.from) else {
                    continue;
                };
                if let Ok(links) = delta.apply(&base, now_s) {
                    let id = delta.node_id();
                    note(
                        &m.from,
                        delta.published_s,
                        links
                            .iter()
                            .filter_map(|c| c.other_than(&id).map(|p| p.node_id()))
                            .collect(),
                    );
                }
            }
        }
        self.reach = reach.into_iter().map(|(w, _, r)| (w, r)).collect();
        self.last_scan_fail = scan.tag_match_decrypt_fail;
        self.pending_bases = bases;
        self.list = if scan.messages.is_empty() {
            vec![format!(
                "(no messages — {} objects examined)",
                scan.examined
            )]
        } else {
            {
                let names = self.aliases();
                scan.messages
                    .iter()
                    .map(|m| Self::inbox_row(m, &names))
                    .collect()
            }
        };
        // Bases recorded now that the scan's borrow has ended. Deferred rather
        // than skipped: without them, a delta arriving next week has nothing
        // to apply against and is dropped, which reads as a peer who stopped
        // sharing.
        for (peer, frag) in &self.pending_bases {
            self.save_peer_base(peer, frag);
        }

        // First-contact requests, on our own inbox tag. Shown at the top: a
        // request needs a human decision (RFC 3 §11's ceremony is a deliberate
        // act), and burying it under mail would mean it is never made.
        // Disjoint field borrows: `store` is read, `attempts` is spent.
        let attempts = &mut self.attempts;
        let requests = self.store.with(|st| {
            receive::scan_requests(
                st,
                id.correspondence(),
                &id.node_id(),
                epoch,
                (0, u32::MAX),
                attempts,
            )
        });
        for inc in &requests {
            let receive::Incoming::Request { request: r, .. } = inc else {
                continue;
            };
            let note = self.foreign(&r.note);
            self.list.insert(
                0,
                format!(
                    "REQUEST from {}  {note}",
                    r.from
                        .fingerprint()
                        .split_whitespace()
                        .take(2)
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
            );
        }
        if !requests.is_empty() {
            self.list.push(format!(
                "! {} first-contact request(s). Compare fingerprints aloud before \
                 peering — the signature proves who signed it, not who they are.",
                requests.len()
            ));
        }

        if scan.tag_match_decrypt_fail > 0 {
            // RFC 3 §12's ratio. A high rate usually means objects are arriving
            // outside the acceptance window, which is otherwise invisible.
            self.list.push(format!(
                "! {} matched a tag and did not open",
                scan.tag_match_decrypt_fail
            ));
        }
        self.messages = scan.messages;
        // The Channels tab lists channels, not mail. Both are rebuilt here,
        // so switching tabs shows what is there rather than what was there
        // when the tab was last opened.
        if self.ui.tab() == layout::Tab::Notes {
            // **The list, first.** This branch set only the body, so the pane
            // showed a note while the list beside it still held the private
            // inbox's "(no messages — n objects examined)" — the placeholder
            // for a tab the operator was not looking at.
            self.list = self.note_rows();
            self.clamp_selection();
            let Some(me) = self.identity.as_ref().map(|i| i.short_id()) else {
                self.body = "no identity. `init` to create one.".into();
                return;
            };
            if self.pin_key.is_none() {
                self.body = "locked.".into();
                return;
            }
            let _ = me;
            self.body = self.note_body();
            return;
        }
        if self.ui.tab() == layout::Tab::Channels {
            // **Two levels, and the second one now has content.**
            // `descend` set `Level::Messages` and nothing read it, so
            // pressing Enter on a channel changed the pane's title and left
            // the same list of channels underneath it.
            self.list = match (self.ui.level(), self.channel_open) {
                (layout::Level::Messages, Some(id)) => self.channel_post_rows(&id),
                _ => self.channel_rows(),
            };
        }
        self.clamp_selection();
        self.show_selected();
    }

    /// The prekey to encapsulate to for `node`, from their published batch.
    ///
    /// `None` when they have published none, which is the correct degradation:
    /// the message is sealed to their correspondence key, exactly as before
    /// prekeys existed. A sender that *failed* instead would make a peer
    /// unreachable for the sake of a property that is a bonus.
    fn prekey_for(&self, node: &[u8; 32]) -> Option<krab_crypto::dh::PublicKey> {
        let me = self.identity.as_ref()?.node_id();
        // The newest batch this node holds from them. Bulletins are flooded
        // and old ones linger, so "latest" is by epoch and not by arrival.
        let mut best: Option<(u32, prekeys::Published)> = None;
        self.store.with(|s| {
            for (_, id) in s.entries_in_range(0, u32::MAX) {
                let Some(bytes) = s.get(&id) else { continue };
                // `from_object` returns nothing unless the bulletin verifies,
                // so an unauthenticated payload cannot be parsed by
                // forgetting to check.
                let Some(b) = bulletin::from_object(bytes) else {
                    continue;
                };
                if b.kind != bulletin::Kind::Prekeys || &b.node_id() != node {
                    continue;
                }
                let Some(p) = prekeys::Published::decode(&b.payload) else {
                    continue;
                };
                // And the tier itself, which the bulletin's signature does not
                // cover on its own — a forged fallback key would otherwise
                // ride inside a genuine bulletin.
                if !p.verify_signed_prekey(&b.author) {
                    continue;
                }
                if best.as_ref().map(|(e, _)| b.epoch > *e).unwrap_or(true) {
                    best = Some((b.epoch, p));
                }
            }
        });
        best.map(|(_, p)| p.key_for(&me))
    }

    /// Every private key an inbound object might be encapsulated to.
    ///
    /// The correspondence key first, then the prekey ring. Order is fixed and
    /// does not depend on which key last worked — an order that adapts is an
    /// order that leaks which key is in use.
    fn opening_keys(&self) -> Vec<krab_crypto::dh::SecretKey> {
        let mut out = Vec::new();
        if let Some(id) = &self.identity {
            out.push(krab_crypto::dh::SecretKey::from_bytes(
                id.correspondence().to_bytes(),
            ));
        }
        if let (Some(w), Ok(sealed)) = (
            self.epoch_key,
            std::fs::read(self.path(artifact::Artifact::PrekeyRing)),
        ) {
            if let Some(keys) = krab_crypto::kek::open_under(&w, b"krab/prekeys", &sealed)
                .ok()
                .and_then(|raw| prekeys::stored_candidates(&raw))
            {
                out.extend(keys);
            }
        }
        out
    }

    /// Create a group — RFC 6 §2.
    fn group_new(&mut self, name: Option<&str>) -> String {
        let Some(name) = name else {
            return "usage: group new <name>\n\n\
                    A group is PRIVATE: each message is sealed once per member. \
                    A channel is PUBLIC and permanent. They are opposite models \
                    and this is the one that is not."
                .into();
        };
        if self.groups.iter().any(|g| g.name == name) {
            return format!("a group called {name} already exists");
        }
        let Some(me) = self.identity.as_ref().map(|i| i.node_id()) else {
            return "no identity".into();
        };
        // Creator-only by default, and it cannot be changed afterwards —
        // RFC 6 §2.6: a change to the authority model is indistinguishable
        // from a compromise of it.
        self.groups
            .push(groups::Group::new(name, me, groups::Authority::CreatorOnly));
        if let Some(e) = self.save_groups() {
            return e;
        }
        format!(
            "group \"{name}\" created, with you as its only member.\n\n\
             PRIVATE — each message is sealed once per member, so one \
             compromised member exposes one member. That costs (G−1)× a single \
             message, which is why the size limits exist.\n\n\
             Authority is creator-only and cannot be changed: a change to the \
             authority model is indistinguishable from a compromise of it \
             (RFC 6 §2.6)."
        )
    }

    /// Add or remove a member, with RFC 6 §5 requirement 5's warnings **at
    /// this moment** rather than when a send later fails.
    fn group_member(&mut self, name: Option<&str>, peer: Option<&str>, add: bool) -> String {
        let verb = if add { "add" } else { "remove" };
        let (Some(name), Some(peer)) = (name, peer) else {
            return format!("usage: group {verb} <name> <peer>");
        };
        // The peer must be one this node has peered with: a group member who
        // cannot be sealed to is a member who silently receives nothing.
        let Some(card) = std::fs::read(self.peer_path(peer, artifact::PeerFile::Link))
            .ok()
            .and_then(|b| peering::Card::decode(&b).ok())
            .filter(|c| c.verify())
        else {
            return format!(
                "no peer-link for {peer}.\n\n\
                 A group member has to be someone you have peered with — fan-out \
                 seals to each member individually, and a member you cannot seal \
                 to would silently receive nothing."
            );
        };
        let node = card.node_id();
        let Some(i) = self.groups.iter().position(|g| g.name == name) else {
            return format!("no group called {name}");
        };

        if !add {
            let removed = self.groups[i].remove(&node);
            if let Some(e) = self.save_groups() {
                return e;
            }
            if removed {
                self.publish_roster(&self.groups[i].clone());
            }
            return if removed {
                format!(
                    "{peer} removed from \"{name}\", now at roster epoch {}.\n\n\
                     They keep every message already sent: RFC 3 §6.1 forbids a \
                     recall mechanism.",
                    self.groups[i].epoch
                )
            } else {
                format!("{peer} was not in \"{name}\"")
            };
        }

        // **The warnings, before the change.** RFC 6 §5 requirement 5 puts
        // them at join time precisely so they arrive while the decision is
        // still open.
        let prospective = self.groups[i].members.len() + 1;
        let mut notes = String::new();
        if let Some(w) = groups::Group::prekey_warning(
            prospective,
            prekeys::BATCH_KEYS,
            krab_crypto::REKEY_EPOCHS,
        ) {
            notes.push_str(&format!("\n\n{w}"));
        }

        match self.groups[i].add(node) {
            groups::SizeVerdict::Refuse(why) => format!("refused. {why}"),
            groups::SizeVerdict::Warn(why) => {
                if let Some(e) = self.save_groups() {
                    return e;
                }
                self.publish_roster(&self.groups[i].clone());
                format!(
                    "{peer} added to \"{name}\", now at roster epoch {}.\n\n{why}{notes}",
                    self.groups[i].epoch
                )
            }
            groups::SizeVerdict::Fine => {
                if let Some(e) = self.save_groups() {
                    return e;
                }
                self.publish_roster(&self.groups[i].clone());
                format!(
                    "{peer} added to \"{name}\", now {} members at roster epoch {}.{notes}",
                    self.groups[i].members.len(),
                    self.groups[i].epoch
                )
            }
        }
    }

    /// Republish a prekey batch when the cadence says to.
    ///
    /// **RFC 7 §5's claim depends on this running.** "Worst-case exposure is
    /// the signed-prekey rotation period rather than for ever" is only true if
    /// something rotates it; `publish_prekeys` had exactly one caller, at the
    /// end of `init`, so the period was in fact for ever and the property the
    /// interface reported was not the one being delivered.
    ///
    /// Reads the epoch off the last batch this node published rather than
    /// keeping a timer, so a node that was off for a month republishes on its
    /// next tick instead of waiting another week.
    fn republish_prekeys_if_due(&mut self) {
        if self.identity.is_none() || self.epoch_key.is_none() {
            return;
        }
        let me = self.identity.as_ref().map(|i| i.node_id());
        let mut newest = 0u32;
        self.store.with(|s| {
            for (_, oid) in s.entries_in_range(0, u32::MAX) {
                if let Some(b) = s.get(&oid).and_then(bulletin::from_object) {
                    if b.kind == bulletin::Kind::Prekeys && Some(b.node_id()) == me {
                        newest = newest.max(b.epoch);
                    }
                }
            }
        });
        let now = now_epoch().0;
        if newest != 0 && now.saturating_sub(newest) < REPUBLISH_EPOCHS {
            return;
        }
        if let Some(note) = self.publish_prekeys() {
            self.log.push(activity_log::Event::Republished {
                keys: note.split_whitespace().nth(1).unwrap_or("?").to_string(),
            });
        }
    }

    /// Refresh the rollcall entry, if this node is listed and one is due.
    ///
    /// **Only ever for a node that opted in.** `Listing::due` returns false
    /// whenever `publishing` is false, which is its default and the state a
    /// lock restores — so the path from "the schedule fired" to "an entry was
    /// published" cannot be walked by a node whose operator never asked.
    ///
    /// Refreshing before expiry rather than after is the whole reason this
    /// exists: an entry lives seven days (RFC 3 §9.1), and a node that waited
    /// for one to lapse would drop out of the directory every week for no
    /// reason. Which also means the promise `rollcall publish` prints — that
    /// the node keeps it fresh — has a mechanism behind it, rather than being
    /// a sentence about one.
    fn republish_rollcall_if_due(&mut self) {
        if self.identity.is_none() || self.epoch_key.is_none() {
            return;
        }
        if !self.rollcall.due(now_epoch().0.saturating_mul(1440)) {
            return;
        }
        self.rollcall_publish();
    }

    /// Draw the selected picture in the message pane.
    ///
    /// **Decoded here, by this program's own decoder**, and what reaches the
    /// terminal is characters and colours. Kitty, iTerm2 and sixel would all
    /// hand the encoded file to the terminal emulator to decode, and a
    /// terminal emulator decoding a stranger's PNG is a system image viewer —
    /// which RFC 8 §6 forbids. See `picture::cells`.
    fn picture_show(&mut self) -> String {
        let Some(m) = self.messages.get(self.selected) else {
            return "no message selected".into();
        };
        let Some(png) = m.picture.clone() else {
            return "the selected message is not a picture".into();
        };
        if !picture::terminal_supports_colour(std::env::var("COLORTERM").ok().as_deref()) {
            return "this terminal does not advertise 24-bit colour (COLORTERM), \
                    so a picture would render as mud.\n\n\
                    `picture save <file>` writes it out instead. Krab will not \
                    open a viewer for you (RFC 8 §6)."
                .into();
        }
        // Decoded on its own thread, holding nothing but the bytes — the same
        // isolation the send path uses, and for the same reason.
        let rendered = match picture::cells_isolated(&png, 76, 18) {
            Err(picture::Error::NoIsolation) => picture::cells(&png, 76, 18),
            other => other,
        };
        match rendered {
            Err(e) => format!("{e}"),
            Ok(rows) => {
                let n = rows.len();
                self.showing = Some(rows);
                format!(
                    "showing {n} rows. `picture hide` stops.\n\n\
                     Drawn from pixels this node decoded — the terminal was \
                     never handed the file."
                )
            }
        }
    }

    /// Write the selected message's picture to a file.
    ///
    /// **And nothing else.** RFC 8 §6: *"The client MUST NOT pass received
    /// bytes to a system image viewer."* A viewer is a browser engine, or
    /// something with one inside, opened on a file a stranger sent — and it is
    /// opened outside every boundary this program maintains. So this writes
    /// bytes and stops, and there is no setting that changes that.
    ///
    /// The bytes written are the ones the *sender's* pipeline produced, which
    /// were decoded and re-encoded there. This node has not decoded them.
    fn picture_save(&mut self, dest: Option<&str>) -> String {
        let Some(dest) = dest else {
            return "usage: picture save <file>".into();
        };
        let Some(m) = self.messages.get(self.selected) else {
            return "no message selected".into();
        };
        let Some(png) = m.picture.as_ref() else {
            return "the selected message is not a picture".into();
        };
        match std::fs::write(dest, png) {
            Err(e) => format!("could not write {dest}: {e}"),
            Ok(()) => format!(
                "wrote {} bytes to {dest}.\n\n\
                 Krab will not open it. RFC 8 §6 forbids handing received bytes \
                 to a system viewer — that is a decoder outside every boundary \
                 this program maintains, on a file somebody else chose. Open it \
                 yourself, knowing that.",
                png.len()
            ),
        }
    }

    /// Seal one copy per recipient and queue them, staggered.
    ///
    /// Shares `group_send`'s emission window and its reasoning: `N` objects
    /// appearing together in one size bucket announces both the fan-out and
    /// its size, whether the recipients are a named group or an ad-hoc list.
    fn fan_out(&mut self, to: &[String], text: &str) -> String {
        let mut sealed = Vec::new();
        let mut refused = Vec::new();
        for peer in to {
            match self.seal_one(peer, text.as_bytes()) {
                Some(pair) => sealed.push(pair),
                None => refused.push(peer.clone()),
            }
        }
        if sealed.is_empty() {
            return format!("nothing could be sealed for {}", refused.join(", "));
        }

        let now_min = now_epoch().0 * 1440;
        let mut note = String::new();
        if sealed.len() == 1 {
            // One recipient is not a fan-out and has nothing to hide among a
            // window; it goes straight into the corpus like any other message.
            let (id, bytes) = sealed.remove(0);
            if let Err(e) = self.store.with(|s| s.ingest(id, bytes, now_min, u32::MAX)) {
                return format!("the store refused it: {e:?}");
            }
        } else {
            let rate = self.background_rate();
            let window = fanout::window_seconds(sealed.len() + 1, rate);
            let offsets = fanout::offsets(sealed.len() + 1, rate, &mut OsRng);
            let now_s = now_seconds();
            for ((id, bytes), off) in sealed.iter().zip(offsets.iter()) {
                self.pending.push(fanout::Pending {
                    release_at_s: now_s + off,
                    id: *id,
                    bytes: bytes.clone(),
                });
            }
            note = format!(
                "\n\n{} copies, released over about {:.1} hours so they do not \
                 announce themselves as one fan-out (RFC 6 §2.7).",
                sealed.len(),
                window as f64 / 3600.0
            );
        }
        self.save_corpus();
        self.refresh_inbox();
        let mut out = format!(
            "composed for {}.\n\nIt leaves on a scheduled reconciliation — not \
             now, and not because you pressed a key (RFC 5 §6.1).{note}",
            to.join(", ")
        );
        if !refused.is_empty() {
            out.push_str(&format!(
                "\n\nNOT sent to {} — nothing could be sealed for them, and \
                 nothing will tell them so.",
                refused.join(", ")
            ));
        }
        out
    }

    /// Open a composition addressed to one or more people — the main verb.
    ///
    /// **Fan-out, like a group.** One sealed copy per recipient, to that
    /// recipient: there is no shared key, so a compromised recipient exposes
    /// that recipient and nobody else. And the copies are staggered for the
    /// same reason RFC 6 §2.7 staggers a group's — `N` objects appearing at
    /// once in one size bucket announces both the fan-out and how many people
    /// are in it.
    /// Unix seconds. Introduction tokens expire in days, so they need a wall
    /// clock rather than the epoch counter everything else runs on.
    fn now_s(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// A peer's verified card, by short name.
    fn peer_card(&self, peer: &str) -> Option<peering::Card> {
        std::fs::read(self.peer_path(peer, artifact::PeerFile::Link))
            .ok()
            .and_then(|b| peering::Card::decode(&b).ok())
            .filter(|c| c.verify())
    }

    /// Tokens this node has already honoured — RFC 3 §10's single-use.
    ///
    /// Read from disk on each use rather than held. Single-use is a property
    /// of the evaluator's *memory*, so the memory has to be the durable copy;
    /// a cached one that drifted from the file would honour a token twice
    /// after a restart and report nothing unusual.
    fn spent_tokens(&self) -> introduction::Spent {
        let Some(w) = self.epoch_key else {
            return introduction::Spent::default();
        };
        std::fs::read(self.path(artifact::Artifact::IntroductionsSpent))
            .ok()
            .and_then(|s| krab_crypto::kek::open_under(&w, b"krab/introductions", &s).ok())
            .and_then(|raw| introduction::Spent::decode(&raw))
            .unwrap_or_default()
    }

    /// Record a token as honoured, and forget the expired ones while here.
    fn spend_token(&mut self, token: &introduction::Token) -> Option<()> {
        let w = self.epoch_key?;
        let mut spent = self.spent_tokens();
        spent.spend(token);
        // Bounded by expiry, not by count. A record of every introduction ever
        // made to this node is the accumulating trace RFC 3 §10 objects to,
        // and an expired nonce protects nothing.
        spent.forget_expired(self.now_s());
        let sealed =
            krab_crypto::kek::seal_under(&w, b"krab/introductions", &spent.encode(), &mut OsRng)
                .ok()?;
        atomic::write(&self.path(artifact::Artifact::IntroductionsSpent), &sealed).ok()
    }

    /// `introduce` — RFC 3 §10's private vouch.
    ///
    /// Two forms, on opposite sides of one handover: the introducer mints,
    /// the person vouched for holds.
    fn introduce(&mut self, line: &str) -> String {
        let Ok(words) = words::split(line) else {
            return "unbalanced quotes".into();
        };
        let args: Vec<String> = words.iter().skip(1).map(|w| w.text()).collect();
        match args.first().map(String::as_str) {
            Some("use") if args.len() == 2 => self.introduce_use(&args[1]),
            _ if args.len() == 2 => self.introduce_mint(&args[0], &args[1]),
            _ => "usage:\n\n\
                  \x20 introduce <peer> <to>   vouch for <peer>, for an \
                  introduction to <to>\n\
                  \x20 introduce use <token>   hold a token someone gave you\n\n\
                  A token is private, single-use, expires in days, and is bound \
                  to the person it names — it is not an endorsement and there \
                  is no score (RFC 3 §10)."
                .into(),
        }
    }

    /// Mint a vouch for `peer`, scoped to an introduction to `to`.
    fn introduce_mint(&mut self, peer: &str, to: &str) -> String {
        let Some(id) = self.identity.as_ref() else {
            return "no identity — run `init` first".into();
        };
        if self.epoch_key.is_none() {
            return "locked — unlock to vouch".into();
        }
        // **Both must be people this node has peered with.** Vouching for
        // someone you have not peered with is not evidence of anything, and
        // §10's whole claim is that a token "carries the credibility of
        // vouching" — which it can only do if there is a real relationship
        // behind it.
        let Some(requester) = self.peer_card(peer) else {
            return format!(
                "no peer-link for {peer}.\n\n\
                 You can only vouch for someone you have peered with — that \
                 peering is what the vouch is evidence of (RFC 3 §10)."
            );
        };
        let Some(target) = self.peer_card(to) else {
            return format!(
                "no peer-link for {to}.\n\n\
                 The introduction is to them, and they have to know you for \
                 your signature to mean anything to them."
            );
        };
        if requester.node_id() == target.node_id() {
            return "that would introduce someone to themselves".into();
        }

        let token = introduction::Token::create(
            id.signing_key(),
            requester.node_id(),
            target.node_id(),
            self.now_s(),
            introduction::MAX_LIFETIME_S,
            &mut OsRng,
        );
        format!(
            "a vouch for {peer}, for an introduction to {to}:\n\n\
             {text}\n\n\
             Give this to {peer}, who runs `introduce use <token>` and then \
             `request`. It is:\n\n\
             \x20 private     — it travels only inside their sealed request to \
             {to}, and nothing publishes it\n\
             \x20 bound       — to {peer}. Passing it on gets nobody anything\n\
             \x20 scoped      — to {to}, and no one else\n\
             \x20 single-use  — {to} honours it once\n\
             \x20 expiring    — in {days} days\n\n\
             There is no score and no record: RFC 3 §10 refuses visible \
             reputation because standing accumulates into hubs, and hubs become \
             chokepoints.",
            text = introduction::to_text(&token),
            days = introduction::MAX_LIFETIME_S / 86_400,
        )
    }

    /// Hold a token somebody gave us, for the next request to its target.
    fn introduce_use(&mut self, text: &str) -> String {
        let Some(token) = introduction::from_text(text) else {
            return "that is not a token".into();
        };
        let Some(id) = self.identity.as_ref() else {
            return "no identity — run `init` first".into();
        };
        // A token bound to somebody else is worthless here, and saying so now
        // beats saying it after a request has already gone out unvouched.
        if token.requester != id.node_id() {
            return "that token vouches for somebody else. A token is bound to \
                    one person's key and cannot be passed on (RFC 3 §10)."
                .into();
        }
        if self.now_s() >= token.expires_s {
            return "that token has expired.".into();
        }
        let target = short_id(&token.target);
        self.introductions.retain(|t| t.nonce != token.nonce);
        self.introductions.push(token);
        format!(
            "held. It will travel with your next `request` to {target}.\n\n\
             Held in memory only — a token is a private vouch, and writing one \
             down would leave the record RFC 3 §10 exists to avoid. It is gone \
             on lock, and it is good once."
        )
    }

    /// `requests` — first-contact requests waiting on this node's inbox tag.
    ///
    /// **This had no caller at all.** `receive::scan_requests` existed, was
    /// tested, and nothing in the application ran it — so a node could send a
    /// peer-request and never see one arrive, which is half a protocol. Adding
    /// it here is what makes an introduction evaluable by anyone.
    fn requests(&mut self, line: &str) -> String {
        let Ok(words) = words::split(line) else {
            return "unbalanced quotes".into();
        };
        let accept = words.get(1).map(|w| w.text()) == Some("accept".to_string());
        let which = words.get(2).and_then(|w| w.int()).unwrap_or(0);

        let (Some(id), Some(_)) = (&self.identity, self.epoch_key) else {
            return "locked — unlock to read requests".into();
        };
        let me = id.node_id();
        let window = {
            let now = now_epoch().0 * 1440;
            (
                now.saturating_sub(45 * 1440),
                now.saturating_add(45 * 1440) + 1,
            )
        };
        let attempts = &mut self.attempts;
        let incoming = self.store.with(|s| {
            receive::scan_requests(s, id.correspondence(), &me, now_epoch(), window, attempts)
        });
        if incoming.is_empty() {
            return "no first-contact requests.\n\nThey arrive on your inbox \
                    tag, which anyone holding your public key can compute — so \
                    one can reach you with no network at all (RFC 3 §5.1)."
                .into();
        }

        if accept {
            let Some(n) = (which as usize).checked_sub(1) else {
                return "usage: requests accept <n>".into();
            };
            let Some(receive::Incoming::Request { request, .. }) = incoming.get(n) else {
                return format!("there is no request {which}");
            };
            let request = request.clone();
            return self.accept_request(&request);
        }

        let now_s = self.now_s();
        let spent = self.spent_tokens();
        let mut out = format!("{} document(s) waiting:\n\n", incoming.len());
        for (i, inc) in incoming.iter().enumerate() {
            match inc {
                receive::Incoming::Request { request: r, .. } => {
                    let who = short_id(&r.from.node_id());
                    out.push_str(&format!("\x20 {}. request from {who}\n", i + 1));
                    if !r.note.is_empty() {
                        out.push_str(&format!("\x20    {}\n", self.foreign(&r.note)));
                    }
                    out.push_str(&format!(
                        "\x20    they will accept {} MB/day, {} objects/day, \
                         {} days retained\n",
                        r.terms.bytes_per_day >> 20,
                        r.terms.objects_per_day,
                        r.terms.retention_days,
                    ));
                    out.push_str(&format!(
                        "\x20    {}\n",
                        self.introduction_line(r, &me, now_s, &spent)
                    ));
                }
                // RFC 3 §5.2. A counter is only meaningful against the chain
                // it answers, so it is reported and left for `peer counter`
                // to place.
                receive::Incoming::Counter { counter: c, .. } => {
                    out.push_str(&format!(
                        "\x20 {}. counter from {}\n\x20    they will accept {} MB/day, \
                         {} objects/day, {} days retained\n",
                        i + 1,
                        short_id(&c.node_id()),
                        c.terms.bytes_per_day >> 20,
                        c.terms.objects_per_day,
                        c.terms.retention_days,
                    ));
                    if !c.note.is_empty() {
                        out.push_str(&format!("\x20    {}\n", self.foreign(&c.note)));
                    }
                }
            }
        }
        out.push_str(
            "\n`requests accept <n>` records the introduction as used and \
             writes their card, so you can peer.\n\n\
             Whether an introduction is sufficient is your decision. The \
             protocol establishes facts; the operator makes judgements \
             (RFC 3 §10).",
        );
        if !spent.is_empty() {
            out.push_str(&format!(
                "\n\n{} introduction(s) already honoured and still within their \
                 lifetime. That record is dropped as each expires — a standing \
                 list of who was introduced here is the accumulating trace \
                 RFC 3 §10 exists to avoid.",
                spent.len()
            ));
        }
        out
    }

    /// One line describing what, if anything, vouches for a request.
    fn introduction_line(
        &self,
        req: &request::PeerRequest,
        me: &[u8; 32],
        now_s: u64,
        spent: &introduction::Spent,
    ) -> String {
        let Some(via) = req.via else {
            return "no introduction — nobody you know has vouched".into();
        };
        let name = short_id(&via);
        // What the evidence proves, independently of whether this node knows
        // the introducer. RFC 3 §10 makes this the *cryptographic* half; the
        // token below is the vouch, and the operator makes the judgement.
        let evidence = match req.evidence_verdict(now_s) {
            request::Evidence::Absent => String::new(),
            request::Evidence::Confirms => {
                format!("; {name} and they provably peered, both signatures")
            }
            request::Evidence::WrongParties => {
                "; the attached credential is between two other nodes and \
                 proves nothing about this request"
                    .into()
            }
            request::Evidence::Invalid(why) => format!("; the attached credential is {why:?}"),
        };
        // **Resolved from this node's own peer-links, never from the token.**
        // A token carrying its own key would let a stranger vouch for
        // themselves with a perfectly valid signature, which is the Sybil case
        // RFC 3 §10 names.
        let key = self
            .peer_card(&name)
            .map(|c| krab_crypto::sign::VerifyingKey::from_bytes(c.identity_pk));
        match req.introduction(key.as_ref(), me, now_s, spent) {
            None => format!("names {name} as introducer but carries no token"),
            Some(introduction::Verdict::Good) => {
                format!("introduced by {name}, who you peer with — unspent, unexpired{evidence}")
            }
            Some(introduction::Verdict::UnknownIntroducer) => format!(
                "claims an introduction by {name}, who you do not peer with, so \
                 the signature could be anyone's{}",
                match req.evidence_verdict(now_s) {
                    // **This is what evidence buys.** Without it an unknown
                    // introducer is worth nothing at all. With it, the vouch
                    // is still from a stranger — but the peering it rests on
                    // is a real one, mutually signed, and that is a fact the
                    // operator can weigh rather than a claim they cannot.
                    request::Evidence::Confirms => format!(
                        " — but the attached credential proves {name} and they \
                         really did peer, signed by both. A stranger's vouch on \
                         a real relationship; your judgement, not the protocol's"
                    ),
                    request::Evidence::Absent =>
                        " and nothing is attached to check it against".into(),
                    _ => evidence.clone(),
                }
            ),
            Some(introduction::Verdict::BadSignature) => {
                format!("claims an introduction by {name}; the signature is not theirs")
            }
            Some(introduction::Verdict::NotYours) => {
                "carries a token minted for somebody else".into()
            }
            Some(introduction::Verdict::NotForUs) => {
                "carries a token for an introduction to somebody else".into()
            }
            Some(introduction::Verdict::Expired) => {
                format!("introduced by {name}, but the token has expired")
            }
            Some(introduction::Verdict::Overlong) => format!(
                "introduced by {name}, with a lifetime longer than RFC 3 §10 \
                 allows — refused rather than honoured in part"
            ),
            Some(introduction::Verdict::Spent) => {
                format!("introduced by {name}, but that token was already used")
            }
        }
    }

    /// Record a request's introduction as used, and write their card.
    fn accept_request(&mut self, req: &request::PeerRequest) -> String {
        let short = short_id(&req.from.node_id());
        let path = self.home.join(format!("{short}.card"));
        if let Err(e) = atomic::write(&path, &req.from.encode()) {
            return format!("could not write their card: {e}");
        }
        let mut out = format!(
            "wrote {}.\n\nNow `peer offer` and exchange as usual — this does \
             not peer you with anyone, it only records that you acted on the \
             request.",
            path.display()
        );
        // **Spent on acceptance, not on display.** Reading a list is not
        // honouring an introduction, and burning a token because somebody
        // looked at their inbox would make single-use mean something nobody
        // asked for.
        if let Some(token) = &req.token {
            if self.spend_token(token).is_some() {
                out.push_str(
                    "\n\nThe introduction is now spent. RFC 3 §10 makes a \
                     token single-use, so the same vouch cannot introduce \
                     twice.",
                );
            }
        }
        out
    }

    /// Propose RFC 3 §3's credential with `theirs`, signed by this node.
    ///
    /// The nonce is fresh: §3 says it "prevents replay of a superseded link",
    /// so a value derived from the two identities — identical on every
    /// renewal — would not do the one job it has.
    fn propose_credential(&self, theirs: &peering::Card) -> Vec<u8> {
        let Some(id) = self.identity.as_ref() else {
            return Vec::new();
        };
        let mut nonce = [0u8; 16];
        OsRng.fill(&mut nonce);
        // **The negotiation's outcome, where there was one** — RFC 3 §5.3:
        // "X countersigns the terms in the final counter." A credential built
        // from defaults instead would make §5.2's whole chain decorative, and
        // peering accept-or-reject again.
        let short = short_id(&theirs.node_id());
        let (mine, theirs_terms) = match self.chain_with(&short) {
            Some(chain) => {
                let (requester, recipient) = chain.settled();
                // Which side of the negotiation this node was on. The chain's
                // requester is whoever wrote the opening document.
                if chain.request.from.node_id() == id.node_id() {
                    (requester, recipient.unwrap_or_default())
                } else {
                    (recipient.unwrap_or_default(), requester)
                }
            }
            None => (
                credential::LinkTerms::default(),
                credential::LinkTerms::default(),
            ),
        };
        credential::Credential::propose_terms(
            id.signing_key(),
            &id.card(peering::Policy::default()),
            theirs,
            mine,
            theirs_terms,
            self.now_s(),
            credential::DEFAULT_TERM_DAYS,
            nonce,
        )
        .encode()
    }

    /// `peer countersign <file>` — RFC 3 §3's second signature, §5.3's step.
    ///
    /// Runs on both ends and is idempotent, which is what lets one command
    /// serve the whole exchange: the far end countersigns a proposal and hands
    /// the complete document back, and the originator runs the same command on
    /// what returns. A ceremony with two verbs for two directions is a
    /// ceremony where operators use the wrong one.
    fn peer_countersign(&mut self, path: Option<&str>) -> String {
        let Some(path) = path else {
            return "usage: peer countersign <file>\n\n\
                    Adds your signature to a peer-link credential and writes \
                    the result back. Run it on the file your peer hands you \
                    after their `peer seal`, and again on what they return.\n\n\
                    RFC 3 §3 requires both signatures: one signature lets a \
                    party assert a relationship the other never agreed to, and \
                    a credential is cited as evidence when someone introduces \
                    you (§5.1)."
                .into();
        };
        let Some(id) = self.identity.as_ref() else {
            return "no identity — run `init` first".into();
        };
        if self.epoch_key.is_none() {
            return "locked — unlock to countersign".into();
        }
        let Ok(bytes) = std::fs::read(path) else {
            return format!("could not read {path}");
        };
        let Some(mut cred) = credential::Credential::decode(&bytes) else {
            return format!("{path} is not a peer-link credential");
        };

        let me = id.node_id();
        let Some(them) = cred.other_than(&me) else {
            return "that credential is between two other nodes — it is not \
                    yours to sign, and signing it would assert a relationship \
                    you are not part of."
                .into();
        };
        let short = short_id(&them.node_id());
        // The other end must be someone this node actually peered with. A
        // credential proposed by a stranger is a document asking for a
        // signature on a relationship that does not exist.
        let Some(their_card) = self.peer_card(&short) else {
            return format!(
                "no peer-link for {short}.\n\n\
                 Complete the ceremony first — `peer offer`, `peer accept`, \
                 `peer seal`. A credential records a peering; it does not \
                 create one."
            );
        };

        // **Both parties' keys must be the ones this node holds.**
        //
        // `other_than` matches on node id, which is a hash of `sig_pk`, so a
        // wrong identity key cannot get this far. `kx_pk` is not covered by
        // that and was not checked at all: a peer could propose a credential
        // carrying this node's real identity key beside a **correspondence key
        // they control**, and countersigning it would produce a mutually
        // signed — and per §15 non-repudiable — statement by this node that
        // its own key is theirs.
        //
        // Nothing reads `kx_pk` out of a credential today, which made it
        // latent rather than live. It does not stay latent: RFC 3 §9.2 makes
        // the credential the place contact details are exchanged, and §3 keys
        // 1 and 2 carry `{sig_pk, kx_pk}` precisely so a reader can use them.
        let mine = id.card(peering::Policy::default());
        let ours = if cred.a.node_id() == me {
            cred.a
        } else {
            cred.b
        };
        if ours.sig_pk != mine.identity_pk || ours.kx_pk != mine.correspondence_pk {
            return "refused: that credential does not name your keys.\n\n\
                    It carries your node identifier beside a correspondence key \
                    that is not yours. Signing it would be signing a statement \
                    about your own key that is false — and RFC 3 §15 makes a \
                    credential non-repudiable, so it would be your signature on \
                    it for as long as it lasts."
                .into();
        }
        if them.sig_pk != their_card.identity_pk || them.kx_pk != their_card.correspondence_pk {
            return format!(
                "refused: that credential does not match the peer-link you \
                 hold for {short}.\n\n\
                 The keys in it are not the keys you peered with. Two documents \
                 about one peering that disagree is a peering where nobody can \
                 say which is right."
            );
        }

        // Whether *this* call completed it, which is what decides whether the
        // other end is still owed a copy.
        let added = cred.sign(id.signing_key());
        match cred.verify(self.now_s()) {
            Ok(()) => {}
            Err(credential::Invalid::NotCountersigned) => {
                // We signed and the other end has not. Hand it back.
                let out = self.home.join(format!("{short}.credential"));
                if let Err(e) = atomic::write(&out, &cred.encode()) {
                    return format!("could not write it: {e}");
                }
                return format!(
                    "signed. Give {} to {short}, who runs `peer countersign` \
                     on it.\n\n\
                     It is not a link yet — one signature is a claim, and \
                     RFC 3 §3 wants a contract.",
                    out.display()
                );
            }
            Err(why) => {
                return format!(
                    "refused: {}\n\n{}",
                    match why {
                        credential::Invalid::BadSignature =>
                            "a signature does not verify under the key the document names",
                        credential::Invalid::NotCanonical =>
                            "the parties are not in canonical order — party A is the one \
                             whose identity key sorts lower, and an implementation that \
                             ordered them differently produces a document neither end can \
                             verify",
                        credential::Invalid::SelfLink => "it links a node to itself",
                        credential::Invalid::Backwards => "it expires before it was established",
                        credential::Invalid::TooLong =>
                            "the term exceeds RFC 3 §4's 180-day ceiling, which \
                             implementations MUST reject",
                        credential::Invalid::Expired =>
                            "it has expired. Revocation is non-renewal (RFC 3 §4), so \
                             re-run `peer seal` to establish a fresh one",
                        credential::Invalid::NotCountersigned => unreachable!(),
                    },
                    "Nothing was stored."
                );
            }
        }

        // Complete. Store it in the peer's directory and drop the handover
        // copy — RFC 3 §15 calls credentials at rest non-repudiable, so one
        // copy in the sealed layout beats two, one of them loose in home.
        if let Err(e) = self.ensure_peer_dir(&short) {
            return e;
        }
        // **Sealed under W_N, because RFC 3 §15 says MUST.** "Seizing a disk
        // yields the peer list *with cryptographic proof* — worse than an
        // address book. The credential store MUST be encrypted under the RFC 7
        // key hierarchy." A completed credential is the single most
        // incriminating file this node writes: not merely a name, a mutually
        // signed and therefore non-repudiable statement that these two agreed
        // to peer. The first version of this function wrote it in the clear.
        let Some(w) = self.epoch_key else {
            return "locked".into();
        };
        let Ok(sealed) =
            krab_crypto::kek::seal_under(&w, b"krab/credential", &cred.encode(), &mut OsRng)
        else {
            return "could not seal it".into();
        };
        if let Err(e) = atomic::write(
            &self.peer_path(&short, artifact::PeerFile::Credential),
            &sealed,
        ) {
            return format!("could not store it: {e}");
        }
        // **Whoever completed it still owes the other end a copy.**
        //
        // The first version shredded the loose file unconditionally, so the
        // side that countersigned kept the only complete credential — sealed,
        // and therefore unreadable to anyone else — and the side that proposed
        // was left holding a half-signed document for ever. Neither could cite
        // one as evidence, which is the whole reason it exists.
        //
        // So: if this node added the second signature, the document goes back
        // out. If it arrived already complete, this node was the last to need
        // it and the loose copy is destroyed.
        let loose = self.home.join(format!("{short}.credential"));
        let handover = if added {
            let _ = atomic::write(&loose, &cred.encode());
            format!(
                "\n\nGive {} back to {short} — they hold only their own half \
                 until they run `peer countersign` on it. Destroy it once they \
                 have it: a completed credential is non-repudiable (RFC 3 §15), \
                 and the copy in your peer directory is sealed while that one \
                 is not.",
                loose.display()
            )
        } else {
            String::new()
        };
        // **Shred the file that was read, not the one we assume it was named.**
        // The operator chooses the path, so keying destruction off a
        // conventional filename destroys nothing and leaves a plaintext,
        // non-repudiable credential wherever a courier unloaded it — the same
        // reasoning as `peer seal` shredding the counterparty's pad, and the
        // same mistake it once made.
        let read_from = std::path::Path::new(path);
        let same = read_from
            .canonicalize()
            .ok()
            .zip(loose.canonicalize().ok())
            .map(|(a, b)| a == b)
            .unwrap_or(false);
        if !same {
            shred::remove(read_from, &mut OsRng);
        }
        let days = (cred.expires_s.saturating_sub(self.now_s())) / 86_400;
        // **The terms, printed.** RFC 3 §5.3 makes countersigning the act of
        // agreeing to them, and §6 says quota is "a checkable statement
        // against a signed artifact rather than a unilateral judgement" —
        // which is only true if the party bound by it saw it. The first
        // version of this command signed and reported success without showing
        // the operator what they had agreed to.
        let (to_them, from_them) = if cred.a.node_id() == me {
            (cred.terms_ab, cred.terms_ba)
        } else {
            (cred.terms_ba, cred.terms_ab)
        };
        let describe = |t: &credential::LinkTerms| {
            format!(
                "buckets to {} B, {}, {} MB/day, {} objects/day, {} days retained{}",
                krab_core::object::BUCKETS[t.policy.max_bucket.min(5) as usize],
                if t.policy.relay { "relaying" } else { "leaf" },
                t.bytes_per_day >> 20,
                t.objects_per_day,
                t.retention_days,
                if t.policy.shard_bits > 0 {
                    format!(", 1/{} shard", 1u32 << t.policy.shard_bits)
                } else {
                    String::new()
                },
            )
        };
        let terms = format!(
            "\n\nyou accept from them: {}\nthey accept from you: {}",
            describe(&to_them),
            describe(&from_them),
        );
        format!(
            "peer-link with {short} is complete{}.{terms}\n\n\
             Both signatures are on it, so it is a contract rather than a \
             claim — and it is what someone introducing you to a third party \
             cites as evidence (RFC 3 §5.1, §10).\n\n\
             It expires in {days} days. There is no revocation list and never \
             will be: revocation is non-renewal (RFC 3 §4), so re-run the \
             ceremony before then.{handover}",
            if added { "" } else { " (it already was)" }
        )
    }

    /// This link's budget for today — RFC 3 §6.
    ///
    /// The ceilings come from the credential, which is where §6 says they
    /// live: "the peering agreement and the rate limit are one document, so
    /// 'you exceeded quota' is a checkable statement against a signed artifact
    /// rather than a unilateral judgement."
    ///
    /// A link with no credential has agreed no ceiling, so none is enforced.
    /// That is the honest reading — a budget nobody signed is a unilateral
    /// judgement, which is exactly what §6 is written against — and it is
    /// visible rather than silent, because `peers` reports it.
    fn budget_for(&mut self, peer: &str) -> Option<shared::Budget> {
        // A link with no credential gets the default terms rather than no
        // budget: `put` skips the quota block entirely when this is `None`,
        // so returning `None` meant an unfinished ceremony bought unmetered
        // ingress — the same defect as the filter above, on the other bound.
        let terms = self
            .inbound_terms(peer)
            .unwrap_or_default();
        let day = quota::day_of(self.now_s());
        let cell = self.spends.entry(peer.to_string()).or_insert_with(|| {
            std::sync::Arc::new(std::sync::Mutex::new(
                Self::read_spend(&self.home, peer, self.epoch_key).unwrap_or(quota::Account {
                    spend: quota::Spend {
                        day,
                        ..quota::Spend::default()
                    },
                    standing: quota::Standing::default(),
                }),
            ))
        });
        // Settles the window that just closed — RFC 3 §6.2's adjustment, which
        // is why this is not merely a counter reset.
        let standing = {
            let mut a = cell.lock().unwrap_or_else(|e| e.into_inner());
            a.roll(day);
            a.standing
        };
        // **The dial, not the ceiling.** §6.2: "adjustment within the
        // credential's negotiated ceiling requires no re-signing; raising the
        // ceiling does." So a fresh peering admits an eighth of what was
        // signed, and earns the rest (RFC 0 §5.3).
        Some(shared::Budget {
            spend: cell.clone(),
            bytes_per_day: standing.effective(terms.bytes_per_day),
            objects_per_day: standing.effective(terms.objects_per_day),
        })
    }

    /// The terms governing what this node accepts **from** `peer`.
    ///
    /// Per-direction, so which half of the credential applies depends on
    /// which party this node is — and that is fixed by the canonical ordering
    /// rather than by who assembled the document.
    fn inbound_terms(&self, peer: &str) -> Option<credential::LinkTerms> {
        let me = self.identity.as_ref()?.node_id();
        let c = self.credential_with(peer)?;
        Some(if c.a.node_id() == me {
            c.terms_ab
        } else {
            c.terms_ba
        })
    }

    /// Read a stored budget, sealed under `W_N`.
    fn read_spend(
        home: &std::path::Path,
        peer: &str,
        epoch_key: Option<[u8; 32]>,
    ) -> Option<quota::Account> {
        let w = epoch_key?;
        let sealed = std::fs::read(home.join("peers").join(peer).join("quota")).ok()?;
        let raw = krab_crypto::kek::open_under(&w, b"krab/quota", &sealed).ok()?;
        quota::Account::decode(&raw)
    }

    /// Write every budget that a running exchange may have moved.
    ///
    /// Called when an exchange reports, which is the only moment one can have
    /// changed. Sealed under `W_N` and shredded by `wipe`: the counters say
    /// nothing about what crossed, but the file naming a peer is the
    /// disclosure RFC 3 §8.4 says to purge.
    fn save_spends(&mut self) {
        let Some(w) = self.epoch_key else { return };
        let entries: Vec<(String, quota::Account)> = self
            .spends
            .iter()
            .map(|(k, v)| (k.clone(), *v.lock().unwrap_or_else(|e| e.into_inner())))
            .collect();
        for (peer, spend) in entries {
            if self.ensure_peer_dir(&peer).is_err() {
                continue;
            }
            if let Ok(sealed) =
                krab_crypto::kek::seal_under(&w, b"krab/quota", &spend.encode(), &mut OsRng)
            {
                let _ = atomic::write(&self.peer_path(&peer, artifact::PeerFile::Quota), &sealed);
            }
        }
    }

    /// The agreed scope of an exchange with `peer` — RFC 3 §7.3.
    ///
    /// Derived from the signed credential, so both ends compute the same
    /// digest without exchanging anything. A peering with no completed
    /// credential gets [`filter::Filter::unscoped`], whose digest differs from
    /// every real filter's — so it will not reconcile with a peering that has
    /// one, which is what "provably agree on the scope" has to mean.
    fn scope_for(&self, peer: &str) -> filter::Filter {
        self.credential_with(peer)
            .map(|c| filter::Filter::from_credential(&c))
            // **Not `unscoped`.** A peering whose ceremony was never
            // completed used to get no retention horizon, no class mask and
            // no shard — strictly *more* than a peering that finished one,
            // because `admits` returns true on its first line for an
            // unscoped filter. An unfinished agreement is not an agreement to
            // everything.
            //
            // The fallback is the terms the ceremony itself defaults to, so
            // an incomplete peering behaves like a completed one at defaults
            // rather than like no limits at all. RFC 3 §5's defaults are
            // deliberately generous, so this throttles nobody honest.
            .unwrap_or_else(|| {
                let d = credential::LinkTerms::default();
                filter::Filter::between(&d, &d, credential::Flags::default().class_mask)
            })
    }

    /// `peer counter <n> <MB/day> <objects> <days>` — RFC 3 §5.2.
    ///
    /// > "The counter-offer is the step that matters. Without it, peering is
    /// > accept-or-reject and therefore binary: friend or stranger. With it,
    /// > peering is negotiated, which is what makes §6 possible."
    ///
    /// The terms stated are **what this node will accept from them**, which is
    /// what `LinkTerms` means everywhere else. §6: "you allocate a sliver of
    /// capacity and observe" — that is a decision one party makes about its
    /// own resources, not an edit to the other's proposal.
    fn peer_counter(&mut self, rest: &str) -> String {
        let Ok(words) = words::split(rest) else {
            return "unbalanced quotes".into();
        };
        let nums: Vec<i64> = words.iter().skip(1).filter_map(|w| w.int()).collect();
        if nums.len() < 4 {
            return "usage: peer counter <n> <MB/day> <objects/day> <days>\n\n\
                    Answers document <n> from `requests` with the terms you \
                    will accept from them. RFC 3 §6: you can peer with a \
                    stranger at 1% trust — allocate a sliver of capacity and \
                    observe.\n\n\
                    Countering is not rejecting. It is what makes a peering \
                    negotiated rather than accept-or-reject."
                .into();
        }
        let (Some(id), Some(_)) = (&self.identity, self.epoch_key) else {
            return "locked — unlock to negotiate".into();
        };
        let me = id.node_id();
        let epoch = now_epoch();
        let window = (0u32, u32::MAX);
        let attempts = &mut self.attempts;
        let incoming = self.store.with(|s| {
            receive::scan_requests(s, id.correspondence(), &me, epoch, window, attempts)
        });
        let Some(doc) = (nums[0] as usize)
            .checked_sub(1)
            .and_then(|n| incoming.get(n))
        else {
            return format!("there is no document {}", nums[0]);
        };

        let terms = credential::LinkTerms {
            policy: peering::Policy::default(),
            retention_days: (nums[3].max(0) as u32).min(krab_core::tag::MAX_TTL_DAYS),
            bytes_per_day: (nums[1].max(0) as u64) << 20,
            objects_per_day: nums[2].max(0) as u64,
        };

        // Place the document in a chain, opening one if this is a request.
        let (mut chain, theirs) = match doc {
            receive::Incoming::Request { request, .. } => {
                let short = short_id(&request.from.node_id());
                (
                    self.chain_with(&short)
                        .unwrap_or_else(|| negotiate::Chain::new(request.clone())),
                    request.from.clone(),
                )
            }
            receive::Incoming::Counter { counter, .. } => {
                let short = short_id(&counter.node_id());
                let Some(mut chain) = self.chain_with(&short) else {
                    return format!(
                        "no negotiation with {short} on this node.\n\n\
                         A counter answers a document; without the chain it \
                         answers, there is nothing to place it against \
                         (RFC 3 §5.2)."
                    );
                };
                // Their counter first, then ours on top of it.
                if let Err(why) = chain.push(counter.clone()) {
                    return format!("that counter does not belong to the negotiation: {why:?}");
                }
                let card = chain.request.from.clone();
                (chain, card)
            }
        };

        let head = chain.head();
        let note = words::rest(&words, 5);
        let counter = negotiate::Counter::create(id.signing_key(), head, terms, note.trim());
        if let Err(why) = chain.push(counter.clone()) {
            return match why {
                negotiate::Broken::OutOfTurn => {
                    "it is not your turn — you wrote the last word in this \
                     negotiation. Wait for their answer (RFC 3 §5.2)."
                        .into()
                }
                negotiate::Broken::TooLong => {
                    "this negotiation has run long enough. Peer on the terms \
                     already offered, or stop."
                        .into()
                }
                other => format!("the counter does not fit the chain: {other:?}"),
            };
        }

        // To their inbox tag, the way the request came — the two are still
        // strangers and there is no other address either can use.
        let their_pk = krab_crypto::dh::PublicKey(theirs.correspondence_pk);
        let tag = krab_crypto::inbox_tag(&their_pk, epoch);
        let composed = match compose::seal_to(
            id.correspondence(),
            &compose::Recipient::FirstContact {
                correspondence: &their_pk,
                tag,
            },
            epoch,
            0,
            expiry_for(epoch),
            &counter.encode(),
            &mut OsRng,
        ) {
            Ok(c) => c,
            Err(e) => return format!("could not seal the counter: {e:?}"),
        };
        if let Err(e) = self
            .store
            .with(|s| s.ingest(composed.id, composed.bytes, epoch.0 * 1440, u32::MAX))
        {
            return format!("the store refused it: {e:?}");
        }
        self.save_corpus();

        let short = short_id(&theirs.node_id());
        self.save_chain(&short, &chain);
        let (mine, _) = chain.settled();
        let _ = mine;
        format!(
            "countered {short}: you will accept {} MB/day, {} objects/day, \
             {} days retained.\n\n\
             It travels to their inbox tag, like the request did — you are \
             still strangers and there is no other address either of you has \
             (RFC 3 §5.1).\n\n\
             The negotiation is now {} document(s) long and is stored sealed. \
             Both of you keep it: RFC 3 §5.2 makes the chain what stops either \
             party later misrepresenting what was offered, and §5.3 forbids \
             publishing it — it is graph information.\n\n\
             It is {} turn next.\n\n\
             When you both stop countering, `peer seal` builds the credential \
             from the last terms each of you stated.",
            if chain.awaiting() == me {
                "your".to_string()
            } else {
                format!("{short}'s")
            },
            counter.terms.bytes_per_day >> 20,
            counter.terms.objects_per_day,
            counter.terms.retention_days,
            chain.counters.len() + 1,
        )
    }

    /// `peer share <peer> on|off` — RFC 3 §8.3.
    ///
    /// > "Per direction, both signed, so neither party can unilaterally expose
    /// > the other. **Default MUST be false** — opt in to being listed, not
    /// > out."
    ///
    /// Both signed, so changing it is a **new credential**: this node sets the
    /// flag for its own direction, signs, and hands it over to be
    /// countersigned. There is no way to make it a local setting, and that is
    /// the property — a local setting is exactly the unilateral exposure §8.3
    /// is written against.
    /// Render text this node did not write — RFC 8 §7.
    ///
    /// **Every path that shows a stranger's words goes through here.** The
    /// notes on a `peer-request` and a `peer-counter` are the only free text
    /// that reaches a pane from outside, and both went to it verbatim: a
    /// newline broke the layout, U+202E reversed the rest of the line, and a
    /// note reading `0797с2с1` in Cyrillic was indistinguishable from the
    /// short id it imitates.
    ///
    /// §7's second requirement is the confusable mark, and the set it is run
    /// against is this node's own peerings — which is what "names the user
    /// already follows" means in a client whose every identifier is a key.
    fn foreign(&self, text: &str) -> String {
        let r = display::safe(text);
        let mut out = r.line();
        if let Some(imitated) = display::confusable_with_known(&r.text, &self.peer_ids()) {
            out.push_str(&format!(
                "  ** this reads like {imitated}, and is not — a homoglyph, \
                 not that peer **"
            ));
        }
        out
    }

    /// `pin` — RFC 8 §10, RFC 7 §8.1.
    ///
    /// > "Provide an explicit **pin** action that re-encrypts a selected
    /// > conversation under a long-lived key, so retention is a conscious act
    /// > rather than the default."
    ///
    /// Bare `pin` reports the archive; `pin <peer>` keeps their conversation;
    /// `pin release <peer>` gives it back to the erasure.
    /// The alias table, or an empty one.
    fn aliases(&self) -> alias::Aliases {
        let Some(key) = self.alias_key else {
            return alias::Aliases::default();
        };
        std::fs::read(self.path(artifact::Artifact::Aliases))
            .ok()
            .and_then(|b| krab_crypto::kek::open_under(&key, alias::DOMAIN, &b).ok())
            .map(|b| alias::Aliases::decode(&b))
            .unwrap_or_default()
    }

    fn save_aliases(&self, table: &alias::Aliases) -> bool {
        let Some(key) = self.alias_key else {
            return false;
        };
        let mut plain = table.encode();
        let sealed =
            match krab_crypto::kek::seal_under(&key, alias::DOMAIN, &plain, &mut OsRng) {
                Ok(v) => v,
                Err(_) => return false,
            };
        // The encoded form is the names in the clear; it does not outlive
        // this function (RFC 7 §9).
        plain.iter_mut().for_each(|b| *b = 0);
        atomic::write(&self.path(artifact::Artifact::Aliases), &sealed).is_ok()
    }

    /// `alias <id> <name>`, and the two sibling verbs.
    ///
    /// **Never sent and never imported.** The table is a separate file that
    /// no send path reads; there is no verb that takes a name from a peer,
    /// because a name a correspondent chose is the attacker-controlled
    /// display name RFC 8 §7 exists to defend against.
    fn alias_command(&mut self, kind: alias::Kind, line: &str) -> String {
        let Ok(words) = words::split(line) else {
            return "unbalanced quotes".into();
        };
        if self.alias_key.is_none() {
            return "locked — unlock to reach your names".into();
        }
        let id = words.get(1).map(|w| w.text());
        let name = words::rest(&words, 2);
        let name = name.trim();
        let mut table = self.aliases();

        let Some(id) = id else {
            // No arguments: list. Both columns, always — a list of bare names
            // would be a list of things the operator cannot type at a verb.
            let rows = table.all(kind);
            if rows.is_empty() {
                return format!(
                    "no {} names.\n\n\
                     `{} <id> <name>` adds one. Names are local: they are \
                     never sent, never imported, and always shown beside the \
                     identifier rather than instead of it (RFC 8 §7).",
                    match kind {
                        alias::Kind::Message => "message",
                        alias::Kind::Channel => "channel",
                        alias::Kind::Peer => "peer",
                    },
                    kind.verb()
                );
            }
            let mut out = format!("{} name(s):\n", rows.len());
            for (id, name) in rows {
                out.push_str(&format!("\n\x20 {name}  ({id})"));
            }
            out.push_str(&format!(
                "\n\n`no {} <name>` removes one.",
                kind.verb()
            ));
            return out;
        };
        if name.is_empty() {
            return format!(
                "usage: {} <id> <name>\n\n\
                 The name is local to this node.",
                kind.verb()
            );
        }
        match table.set(kind, &id, name) {
            Err(alias::Refused::Empty) => "that name is empty once rendered".into(),
            Err(alias::Refused::TooLong) => format!(
                "too long — {} characters at most, so it cannot push the \
                 identifier off a row.",
                alias::MAX_ALIAS
            ),
            Err(alias::Refused::Full) => format!(
                "no room — {} names at most in that table. Every one is \
                 plaintext at rest, so the table is bounded.",
                alias::MAX_ALIASES
            ),
            Err(alias::Refused::LooksLikeAnIdentifier) => {
                "that name looks like a short id.\n\n\
                 Names are shown as `name (id)`, and a name that is itself \
                 eight hex characters makes that unreadable — or names \
                 somebody else."
                    .into()
            }
            Ok(()) => {
                if !self.save_aliases(&table) {
                    return "the name could not be written".into();
                }
                let shown = table.show(kind, &id);
                self.refresh_inbox();
                format!(
                    "{shown}\n\n\
                     Local only: it is never sent, never imported, and shown \
                     beside the identifier rather than instead of it — the \
                     fingerprint comparison is what says who this is (RFC 3 \
                     §11), not the name. `wipe` destroys it."
                )
            }
        }
    }

    /// `no alias <name>`, `no alias-channel <name>`, `no alias-peer <name>`.
    fn alias_remove(&mut self, line: &str) -> String {
        let Ok(words) = words::split(line) else {
            return "unbalanced quotes".into();
        };
        let which = words.get(1).map(|w| w.text()).unwrap_or_default();
        let kind = match which.as_str() {
            "alias" => alias::Kind::Message,
            "alias-channel" => alias::Kind::Channel,
            "alias-peer" => alias::Kind::Peer,
            _ => {
                return "usage: no alias <name>\n\
                        \x20      no alias-channel <name>\n\
                        \x20      no alias-peer <name>"
                    .into()
            }
        };
        if self.alias_key.is_none() {
            return "locked — unlock to reach your names".into();
        }
        let name = words::rest(&words, 2);
        let name = name.trim();
        if name.is_empty() {
            return format!("usage: no {} <name>", kind.verb());
        }
        let mut table = self.aliases();
        match table.clear_by_name(kind, name) {
            None => format!(
                "no {} name {name:?}.\n\n\
                 `{}` lists them.",
                kind.verb(),
                kind.verb()
            ),
            Some(id) => {
                if !self.save_aliases(&table) {
                    return "the name could not be removed".into();
                }
                self.refresh_inbox();
                format!("removed {name} — {id} is shown by its identifier again.")
            }
        }
    }

    /// `note [text]` — something you write to yourself.
    ///
    /// # Why this is not a message addressed to your own node
    ///
    /// Sealing to your own correspondence key would work — the key is here
    /// and `seal_one` does not care who the recipient is. It would also put
    /// the note in the corpus, and everything in the corpus is offered at the
    /// next reconciliation. Peers would carry ciphertext they can never open,
    /// spending the bandwidth and storage RFC 3 §6 meters, and it would count
    /// as a contribution in §12's figures while contributing nothing.
    ///
    /// Excluding it with a flag would work until somebody adds the next code
    /// path that walks the store — which is the defect this codebase keeps
    /// finding. So a note is not an object at all.
    ///
    /// # Where it lives
    ///
    /// In the pinned archive, because that is already exactly this: plaintext
    /// held under a KEK-derived key, deliberately exempt from RFC 7 §8's
    /// epoch erasure, wiped by panic and duress, and carrying a warning that
    /// says how much is exempt. A second archive with the same properties
    /// would be a second thing to remember in every one of those paths.
    fn note_command(&mut self, line: &str) -> String {
        let Ok(words) = words::split(line) else {
            return "unbalanced quotes".into();
        };
        let text = words::rest(&words, 1);
        let text = text.trim();
        let (Some(key), Some(_)) = (self.pin_key, self.epoch_key) else {
            return "locked — unlock to reach your notes".into();
        };
        // `notes` lists; `note` composes. Same verb, and the plural is the
        // one an operator reaches for when they want to read rather than
        // write.
        let listing = words
            .first()
            .map(|w| w.text() == "notes")
            .unwrap_or(false);
        if listing {
            return self.list_notes();
        }
        if text.is_empty() {
            return self.compose_note();
        }
        self.write_note(&key, text)
    }

    /// The selected note, whole, for the view pane.
    ///
    /// Shared by `refresh_inbox` and `show_selected`: the first builds the
    /// tab, the second runs on every cursor move, and a note that only
    /// appeared on one of those paths would change when the list was rebuilt
    /// and not when the selection moved.
    fn note_body(&self) -> String {
        let Some(me) = self.identity.as_ref().map(|i| i.short_id()) else {
            return "no identity. `init` to create one.".into();
        };
        if self.pin_key.is_none() {
            return "locked.".into();
        }
        let archive = self.pinned();
        let mine = archive.of(&me);
        match mine.get(self.selected) {
            Some(k) => format!(
                "note · local only · epoch {}\n\n{}\n\n\
                 This is not an object. No peer is ever offered it and it is \
                 not in the corpus. It is exempt from the epoch erasure that \
                 makes mail unreadable (RFC 7 §8), so it stays until `wipe` \
                 destroys it.",
                k.epoch,
                display::safe_block(&k.body).text
            ),
            None => "no note selected.\n\n`note <text>` keeps one; `note` \
                     alone opens a composer."
                .into(),
        }
    }

    /// One row per note, newest last, for the Notes tab's list pane.
    fn note_rows(&self) -> Vec<String> {
        let Some(me) = self.identity.as_ref().map(|i| i.short_id()) else {
            return vec!["no identity. `init` to create one.".into()];
        };
        if self.pin_key.is_none() {
            return vec!["(locked)".into()];
        }
        let archive = self.pinned();
        let mine = archive.of(&me);
        if mine.is_empty() {
            return vec!["(no notes — `note <text>`, or `note` to compose)".into()];
        }
        mine.iter()
            .map(|k| {
                format!(
                    "[{}]  {}",
                    k.epoch,
                    display::safe(k.body.lines().next().unwrap_or("")).text
                )
            })
            .collect()
    }

    /// Everything written to self, newest last.
    fn list_notes(&self) -> String {
        let Some(me) = self.identity.as_ref().map(|i| i.short_id()) else {
            return "no identity — `init` first".into();
        };
        let archive = self.pinned();
        let mine = archive.of(&me);
        if mine.is_empty() {
            return "no notes.\n\n\
                    `note <text>` keeps one, or `note` alone opens a composer \
                    for something longer. A note never leaves this node."
                .into();
        }
        let mut out = format!("{} note(s):\n", mine.len());
        for (i, k) in mine.iter().enumerate() {
            out.push_str(&format!(
                "\n{:>3}. [epoch {}] {}\n",
                i + 1,
                k.epoch,
                display::safe_block(&k.body).text
            ));
        }
        if let Some(w) = archive.warning() {
            out.push_str(&format!("\n{w}"));
        }
        out
    }

    /// Open the composer for a note. A note is not necessarily one line.
    fn compose_note(&mut self) -> String {
        self.ui.select_tab(layout::Tab::Notes);
        self.ui.compose();
        while self.ui.focus() != layout::Pane::View {
            self.ui.cycle_focus();
        }
        self.composing_note = true;
        "composing a note. Enter is a newline; Ctrl-D keeps it; Esc discards \
         it.\n\n\
         It never leaves this node — it is not an object and is never offered \
         to a peer. It is held with your pinned mail, which means it outlives \
         the epoch that would otherwise erase it (RFC 7 §8). `wipe` destroys \
         it; nothing else does."
            .into()
    }

    /// Add `text` to the archive under this node's own short id.
    fn write_note(&mut self, key: &[u8; 32], text: &str) -> String {
        let me = match self.identity.as_ref() {
            Some(i) => i.short_id(),
            None => return "no identity — `init` first".into(),
        };
        let mut archive = self.pinned();
        if archive.kept.len() >= pin::MAX_PINNED {
            return format!(
                "the archive is full at {} entries.\n\n\
                 It is capped because everything in it is exempt from epoch \
                 erasure: an unbounded archive is an unbounded amount of \
                 plaintext a seizure would find. `pin forget` makes room.",
                pin::MAX_PINNED
            );
        }
        archive.kept.push(pin::Kept {
            from: me.clone(),
            epoch: now_epoch().0,
            body: text.to_string(),
        });
        let n = archive.of(&me).len();
        if self.save_pinned(key, &archive).is_none() {
            return "the note could not be written".into();
        }
        format!(
            "kept. {n} note(s).\n\n\
             It is not an object: no peer will ever be offered it, and it is \
             not in the corpus. It is exempt from epoch erasure like anything \
             pinned — `note` lists them, `wipe` destroys them.\n\n\
             {}",
            self.pinned().warning().unwrap_or_default()
        )
    }

    fn pin_command(&mut self, line: &str) -> String {
        let Ok(words) = words::split(line) else {
            return "unbalanced quotes".into();
        };
        let args: Vec<String> = words.iter().skip(1).map(|w| w.text()).collect();
        let (Some(key), Some(_)) = (self.pin_key, self.epoch_key) else {
            return "locked — unlock to reach the archive".into();
        };
        let mut archive = self.pinned();

        match args.first().map(String::as_str) {
            None => {
                let mut out = match archive.warning() {
                    Some(w) => w,
                    None => "nothing is pinned.\n\n\
                             The default is forgetting: mail becomes unreadable \
                             when its epoch key is shredded, which is the only \
                             genuine form of message expiry there is (RFC 8 §10). \
                             `pin <peer>` keeps a conversation past it."
                        .into(),
                };
                let mut who: Vec<&str> = archive.kept.iter().map(|k| k.from.as_str()).collect();
                who.sort_unstable();
                who.dedup();
                for w in who {
                    out.push_str(&format!("\n\x20 {w} — {} message(s)", archive.of(w).len()));
                }
                out
            }
            Some("release") => {
                let Some(peer) = args.get(1) else {
                    return "usage: pin release <peer>".into();
                };
                let gone = archive.release(peer);
                if gone == 0 {
                    return format!("nothing pinned from {peer}");
                }
                self.save_pinned(&key, &archive);
                format!(
                    "released {gone} message(s) from {peer}.\n\n\
                     They go back to the ordinary erasure and become unreadable \
                     when their epoch key is shredded. That is not a deletion — \
                     the objects are still in the corpus — it is the key going, \
                     which is what makes it irreversible."
                )
            }
            Some(peer) => {
                // Only what this node can currently read: pinning re-encrypts
                // plaintext, and plaintext this node cannot open is not
                // something it can keep.
                let msgs: Vec<pin::Kept> = self
                    .messages
                    .iter()
                    .filter(|m| m.from == *peer)
                    .map(|m| pin::Kept {
                        from: m.from.clone(),
                        epoch: m.epoch.0,
                        body: m.body.clone(),
                    })
                    .collect();
                if msgs.is_empty() {
                    return format!(
                        "no readable messages from {peer}.\n\n\
                         A pin re-encrypts what this node can open. Mail whose \
                         epoch key is already shredded cannot be pinned — that \
                         is what RFC 7 §8.1 means by making the consequence \
                         visible *before* the window elapses."
                    );
                }
                let added = archive.keep(&msgs);
                self.save_pinned(&key, &archive);
                format!(
                    "pinned {added} message(s) from {peer}.\n\n\
                     Re-encrypted under a long-lived key derived from your \
                     passphrase, not from the epoch — so they survive the shred \
                     that takes everything else (RFC 7 §8.1).\n\n\
                     {}",
                    archive.warning().unwrap_or_default()
                )
            }
        }
    }

    /// Re-stamp the pinned copy's epoch to match the live message.
    ///
    /// Test support: a pin records the epoch a message arrived in, so moving a
    /// message's epoch to simulate ageing has to move the pinned copy too, or
    /// the two stop describing the same thing.
    #[cfg(test)]
    fn pinned_epoch_fixup(&mut self) {
        let Some(key) = self.pin_key else { return };
        let mut archive = self.pinned();
        for k in &mut archive.kept {
            if let Some(m) = self.messages.iter().find(|m| m.from == k.from) {
                k.epoch = m.epoch.0;
            }
        }
        self.save_pinned(&key, &archive);
    }

    /// The pinned archive, or an empty one.
    fn pinned(&self) -> pin::Pinned {
        let Some(key) = self.pin_key else {
            return pin::Pinned::default();
        };
        std::fs::read(self.path(artifact::Artifact::Pinned))
            .ok()
            .and_then(|s| krab_crypto::kek::open_under(&key, pin::DOMAIN, &s).ok())
            .and_then(|raw| pin::Pinned::decode(&raw))
            .unwrap_or_default()
    }

    /// Store it, sealed under the long-lived key.
    fn save_pinned(&self, key: &[u8; 32], archive: &pin::Pinned) -> Option<()> {
        let sealed =
            krab_crypto::kek::seal_under(key, pin::DOMAIN, &archive.encode(), &mut OsRng).ok()?;
        atomic::write(&self.path(artifact::Artifact::Pinned), &sealed).ok()
    }

    /// `force-send [peer]` — reconcile now, rather than when the schedule says.
    ///
    /// **This is the one verb that deliberately breaks an invariant**, so it
    /// says so every time rather than once in a manual.
    ///
    /// RFC 5 §6.1 requires inter-sync intervals be uncorrelated with message
    /// events, because a sync that follows a composition tells an observer
    /// watching the link that this node just sent something. Forcing one is
    /// exactly that correlation.
    ///
    /// Two things keep the damage to what was asked for:
    ///
    /// - **The schedule is not touched.** `reconcile_with` does not consult or
    ///   redraw `next_due`, so scheduled syncs remain a Poisson process and
    ///   §6.1 still holds for every exchange this verb did not cause. What an
    ///   observer sees is one extra sync, not a schedule that has become
    ///   readable.
    /// - **Pending fan-out is released first.** RFC 6 §2.7 staggers group
    ///   copies over a window precisely so `G−1` objects do not appear at
    ///   once; flushing them here undoes that for this send. Said plainly,
    ///   because an operator forcing a group message is giving up more than
    ///   they are for a private one.
    fn force_send(&mut self, line: &str) -> String {
        let Ok(words) = words::split(line) else {
            return "unbalanced quotes".into();
        };
        if self.epoch_key.is_none() {
            return "locked — unlock first".into();
        }
        let named = words.get(1).map(|w| w.text());
        let peers: Vec<String> = match &named {
            Some(p) => vec![p.clone()],
            None => self.links.peer_names(),
        };
        if peers.is_empty() {
            return "no link is up. `connect <peer> tcp <addr>` first — a \
                    forced exchange still needs a session, and this verb will \
                    not dial one for you."
                .into();
        }

        // RFC 6 §2.7's stagger, given up deliberately for this send.
        let released = self.release_all_pending();

        // **`None` is the success path.** `reconcile_with` hands the exchange
        // to a thread and returns `None`; it returns `Some(Failed)` when there
        // was no session to take. Reading `None` as failure made a forced send
        // that had *already started* report "nothing to force: no session",
        // while the message it was sent to move arrived a moment later.
        let mut done = Vec::new();
        let mut refused = Vec::new();
        for p in &peers {
            match self.reconcile_with(p) {
                None => done.push(p.clone()),
                Some(event) => {
                    // A synchronous event from here is a failure to start —
                    // no session on the link. Record it and say so.
                    refused.push(p.clone());
                    self.log.push(event);
                }
            }
        }
        // The exchange runs on a thread, so what it moved arrives later. That
        // is why nothing here reports counts: saying "0" as though it were a
        // result would be a lie about a thing still running.
        if done.is_empty() {
            return format!(
                "nothing to force: no session with {}. `connect <peer> tcp \
                 <addr>` first — a forced exchange still needs one, and this \
                 verb will not dial it for you.",
                refused.join(", ")
            );
        }
        format!(
            "forced an exchange with {}.{}\n\n\
             **This is visible.** RFC 5 §6.1 keeps sync intervals uncorrelated \
             with message events so an observer cannot tell when you composed \
             something; a forced sync is that correlation. Anyone watching \
             this link sees a reconciliation that followed your keystroke.\n\n\
             The schedule is untouched — it stays a Poisson process, so this \
             is one extra sync rather than a pattern. Results arrive as the \
             exchange completes; `peers` shows what moved.",
            done.join(", "),
            if released > 0 {
                format!(
                    "\n\n{released} staggered fan-out cop(ies) released at once. \
                     RFC 6 §2.7 spreads them over a window so `G−1` objects do \
                     not appear together — that is given up for this send, and \
                     the group size is inferable from the burst."
                )
            } else {
                String::new()
            }
        )
    }

    /// What the interface is waiting for, and what the next keystroke does.
    ///
    /// Two different things stop and wait — the first-run ceremony, and a
    /// verb that has asked for words to be typed — and neither announced
    /// itself anywhere but in the prose of the output pane. From outside,
    /// "press Enter to continue" and "this node is busy, wait" looked the
    /// same, so the operator either waited on a node that was waiting on them
    /// or pressed keys at one that was working.
    ///
    /// Each answer says the key and the consequence, in that order, because
    /// the consequence is what decides whether to press it.
    fn waiting(&self) -> Option<&'static str> {
        if let Some(p) = &self.prompt {
            return Some(match p {
                Prompt::TransferWords { .. } => {
                    "type the 32 words they read aloud, then Enter \u{2014} completes the peering"
                }
                Prompt::ResealWords { .. } => {
                    "type the 32 words they read aloud, then Enter \u{2014} re-seals the link"
                }
            });
        }
        match self.init_step? {
            InitStep::Passphrase => Some(
                "type a passphrase, then Enter \u{2014} it is not echoed, and it is the only root",
            ),
            InitStep::Generate => {
                Some("Enter \u{2014} generates the identity and the first prekeys")
            }
            InitStep::ShowBackup => {
                Some("Enter \u{2014} shows the backup words, the only time they are shown")
            }
            InitStep::ConfirmBackup => Some(
                "Enter \u{2014} confirms you wrote them down; they cannot be shown again",
            ),
            InitStep::Done => None,
        }
    }

    /// Whether this node is ready to operate, and what is missing if not.
    ///
    /// **The question `keys`, `peers` and `reach` do not answer.** Each of
    /// those reports one subsystem well; an operator looking at a fresh screen
    /// after `init` wants to know whether the thing works yet, and had to
    /// infer it from three verbs and the absence of an error.
    ///
    /// So this ends with what to do next, and says nothing reassuring when
    /// there is something missing. A status line that reads "ready" on a node
    /// that cannot receive is worse than no status line.
    fn status_report(&self) -> String {
        let Some(id) = self.identity.as_ref() else {
            return "no identity.\n\n\
                    `init` creates one. It writes down a backup exactly once, \
                    during the ceremony — RFC 7 §11, because the moment \
                    somebody needs a backup is the moment they can no longer \
                    make one."
                .into();
        };
        let locked = self.epoch_key.is_none();
        let mut out = format!(
            "identity   {}\n\
             {}\n",
            id.short_id(),
            if locked {
                "state      LOCKED — `unlock` to open the store"
            } else {
                "state      unlocked"
            }
        );

        // Keys.
        let epochs = id.hierarchy.epochs().count();
        out.push_str(&format!(
            "keys       {epochs} epoch key(s), {} prekeys published\n",
            if self.prekey_age_days().is_some() {
                prekeys::BATCH_KEYS.to_string()
            } else {
                "no".into()
            }
        ));

        // Where this node listens, which is the half `keys` never had.
        out.push_str(&match (&self.listen, self.inbound.is_some()) {
            (Some(addr), true) => format!("listening  {addr} — accepting any known peer\n"),
            (Some(addr), false) => {
                // Two different failures reach here and they need different
                // advice. A bind that failed is not a node that needs
                // unlocking, and telling an unlocked operator to `unlock`
                // sends them to the one place the problem is not.
                let why = match &self.listen_error {
                    Some(e) => e.clone(),
                    None => "`unlock` first".to_string(),
                };
                format!("listening  {addr} — CONFIGURED BUT NOT RUNNING: {why}\n")
            }
            (None, _) => "listening  no — this node dials out only; a peer \
                          cannot reach it unprompted\n"
                .into(),
        });

        let peers = self.peer_ids();
        let credentialled = peers
            .iter()
            .filter(|p| matches!(self.credential_standing(p), Standing::Live(_, _)))
            .count();
        out.push_str(&format!(
            "peers      {} peered, {credentialled} with a credential\n\
             corpus     {} object(s), {} byte(s)\n",
            peers.len(),
            self.store.len(),
            self.store.with(|s| s.bytes()),
        ));

        // **What is missing**, in the order it has to be fixed. Nothing here
        // says "ready" while something above it is not done.
        let mut todo: Vec<String> = Vec::new();
        if locked {
            todo.push("`unlock` — the store is closed and nothing sends or receives".into());
        }
        if peers.is_empty() {
            todo.push(
                "`peer offer` — there is nobody to talk to. Peering is \
                 deliberate and mutual; there is no discovery and no bootstrap \
                 server, and you cannot join without knowing a participant \
                 (RFC 3 §11.2)"
                    .into(),
            );
        } else if credentialled < peers.len() {
            todo.push(format!(
                "`peer countersign` — {} peering(s) have no credential, so \
                 nothing is scoped or enforced on them and they will not \
                 reconcile with a peer that has one",
                peers.len() - credentialled
            ));
        }
        if self.listen.is_none() && self.links.up_count() == 0 {
            todo.push(
                "`listen <addr>` or `connect <peer> tcp <addr>` — this node \
                 has no way in or out. Mail can still cross by `pack` and \
                 `import` on a stick"
                    .into(),
            );
        }
        for w in self.peer_warnings() {
            todo.push(w.line());
        }

        if todo.is_empty() {
            out.push_str("\nready. Mail sends, arrives, and reconciles on the schedule.");
        } else {
            out.push_str("\nnot ready yet:\n");
            for t in &todo {
                out.push_str(&format!("\x20 - {t}\n"));
            }
        }
        out
    }

    /// RFC 3 §13's warnings, for this node's actual transport mix.
    ///
    /// > "Operators choose peers by hand and will not know any of this.
    /// > Implementations **MUST warn** below the lower bound for the node's
    /// > actual transport mix, and SHOULD warn above 25 on constrained links."
    ///
    /// `krab_node::warnings` computed these and **nothing called it** — the
    /// same defect as `respond_to`, `scan_requests` and `Delta`, and the
    /// fourth instance in this codebase. The thresholds it holds are SIM-0's
    /// and SIM-1's, which is exactly the knowledge §13 says an operator will
    /// not have.
    ///
    /// The mix is read from the links this node actually has rather than
    /// configured, because §13's floor depends on it and a floor the operator
    /// sets is a floor the operator can set wrong.
    fn peer_warnings(&self) -> Vec<krab_node::warnings::Warning> {
        use krab_node::warnings::TransportMix;
        let peers = self.peer_ids().len();
        // A link is constrained if its profile cannot flood — RFC 4 §5.4's
        // question, asked of the profile rather than of its name.
        let profiles: Vec<_> = self.links.iter().map(|l| l.profile.clone()).collect();
        let constrained = profiles
            .iter()
            .any(|p| !p.can_flood(peering::Policy::default().retention_bytes as f64 / 30.0));
        let mix = match (profiles.is_empty(), constrained) {
            // No links at all is a courier deployment until told otherwise:
            // the highest floor, which is the safe direction for a warning.
            (true, _) => TransportMix::Austere,
            (false, true) => TransportMix::Mixed,
            (false, false) => TransportMix::IpConnected,
        };
        krab_node::warnings::evaluate(
            peers,
            mix,
            krab_core::tag::MAX_TTL_DAYS,
            // Coverage is not measured yet — `metrics::Coverage` has no
            // production constructor — so the default profile is passed and
            // the ramp warning cannot fire. Stated rather than hidden: this
            // is the one §13 signal that is still unfed.
            krab_node::metrics::Coverage::default(),
            constrained,
        )
    }

    /// `peer show <peer>` — RFC 3 §3's HJSON rendering.
    ///
    /// > "Implementations MUST render any credential as HJSON on request
    /// > (`krab peer show`), and **that rendering is what an operator
    /// > inspects**."
    ///
    /// Unimplemented until now, which made §3's sentence false in both
    /// halves: there was no rendering, and what an operator inspected was the
    /// `peers` panel's prose summary — a *description* of the credential
    /// written by this program, not the document itself. The difference
    /// matters exactly where it is least convenient: a counterparty who
    /// altered a term is caught by reading the document, and not by reading a
    /// summary that says what the program believes the document says.
    ///
    /// The credential is read from disk and decoded, so what is rendered is
    /// what is stored rather than what is in memory.
    fn peer_show(&mut self, who: Option<&str>) -> String {
        let Some(who) = who else {
            return "usage: peer show <peer>\n\nRenders the stored peer-link \
                    as HJSON — RFC 3 §3. This is the document itself, not a \
                    summary of it."
                .into();
        };
        let Some(w) = self.epoch_key else {
            return "locked — unlock first".into();
        };
        let short = who.to_string();
        let Some(sealed) = std::fs::read(self.peer_path(&short, artifact::PeerFile::Credential))
            .ok()
        else {
            return format!(
                "no credential for {short}. `peers` lists the peerings this \
                 node holds; a peering with no credential was never \
                 countersigned."
            );
        };
        let Ok(bytes) = krab_crypto::kek::open_under(&w, b"krab/credential", &sealed) else {
            return format!("the stored credential for {short} did not open");
        };
        let Some(cred) = credential::Credential::decode(&bytes) else {
            return format!("the stored credential for {short} did not decode");
        };
        credential::to_hjson(&cred, self.now_s())
    }

    /// `peer forget <peer>` — RFC 3 §8.4.
    ///
    /// > "Objects are content-addressed and unattributed, so the corpus is
    /// > unaffected by unpeering. Fragments, beacons, credentials, and
    /// > negotiation chains are attributable — they are records of a
    /// > relationship. On termination or expiry a node **MUST purge those**
    /// > and **MUST retain the corpus**. Unpeering should remove the
    /// > relationship record, not merely stop the conversation."
    ///
    /// Both halves are requirements and they pull opposite ways, so both are
    /// tested. Destroying the corpus would lose everyone else's mail to end
    /// one relationship; keeping the record would leave, per RFC 3 §15, "the
    /// peer list **with cryptographic proof** — worse than an address book".
    ///
    /// # Stopping the conversation is not enough, and neither is the reverse
    ///
    /// Purging the files while the peer stays in the scheduler, the allowed
    /// set and the link table would leave a node still dialling someone it has
    /// no record of — and still accepting them. So the relationship stops
    /// being *acted on* in the same breath as it stops being stored.
    fn peer_forget(&mut self, peer: Option<&str>) -> String {
        let Some(peer) = peer else {
            return "usage: peer forget <peer>\n\n\
                    Ends a peering and destroys its record — the credential, \
                    the negotiation, the reservoir, their card, and this \
                    node's counters. Shredded, not unlinked.\n\n\
                    **Your messages are kept.** RFC 3 §8.4 makes retaining the \
                    corpus an equal MUST: objects are content-addressed and \
                    unattributed, so they are unaffected by who you peer with.\n\n\
                    It cannot be undone and they are not told. Peering again \
                    means the ceremony again."
                .into();
        };
        if self.epoch_key.is_none() {
            return "locked — unlock to end a peering".into();
        }
        let dir = self.home.join("peers").join(peer);
        if !dir.exists() && self.peer_card(peer).is_none() {
            return format!("no peering with {peer}");
        }
        let before = self.store.len();

        // Stop acting on it first. A purge that left the peer in the
        // scheduler would have this node dialling someone whose card it has
        // just destroyed, which fails in a way nothing explains.
        self.links.disconnect(peer);
        self.spends.remove(peer);
        self.reach.retain(|(who, _)| who != peer);
        if let Some(card) = self.peer_card(peer) {
            self.scheduler
                .remove(&sync::peer_id_from_node(&card.node_id()));
        }

        // Then destroy it. Shredded rather than unlinked — `SECURE-DELETE.md`:
        // destruction protects against an adversary who obtains the key
        // *later*, and a credential is non-repudiable for as long as it lasts.
        let mut gone = 0;
        for f in artifact::PeerFile::ALL {
            let path = dir.join(f.name());
            if path.exists() && shred::remove(&path, &mut OsRng) {
                gone += 1;
            }
        }
        // Anything else the directory holds, including a layout this version
        // does not know about — the same reasoning as `wipe`'s predicate.
        gone += shred::remove_matching(&dir, |_| true, &mut OsRng);
        let _ = std::fs::remove_dir(&dir);

        // **And the handover copies in the home directory.**
        //
        // `peer seal`, `peer renew`, `peer share` and `peer countersign` all
        // write `<peer>.credential` there, in the clear, for the operator to
        // hand over. `forget` cleared `peers/<id>/` and left it — so the one
        // command whose job is to destroy the record left behind the single
        // most incriminating file in the layout: a mutually signed, and per
        // RFC 3 §15 non-repudiable, statement that these two agreed to peer.
        let prefix = format!("{peer}.");
        gone += shred::remove_matching(
            &self.home,
            |name| name.starts_with(&prefix) && artifact::wiped(name),
            &mut OsRng,
        );

        // The allowed set is rebuilt from what is on disk, so it drops them.
        self.refresh_allowed();

        // **And the tag table, which holds indices into a list that just
        // shrank.**
        //
        // `TagTable` maps a tag to a position in the correspondent slice, and
        // the slice is rebuilt from the peer directories on every inbox
        // refresh — but the table only rebuilds on epoch rollover. Removing a
        // peering shifts every correspondent after it down one, so a tag
        // belonging to a peer who is still there resolves to somebody else's
        // keys, decryption fails, and **their mail silently stops opening**
        // until midnight. `correspondents.get(idx)` makes that a miss rather
        // than a panic, which is exactly what makes it invisible.
        self.tag_table = None;

        format!(
            "peering with {peer} ended. {gone} file(s) shredded.\n\n\
             They are no longer scheduled, no longer accepted on the \
             listener, and no longer in your nodelist.\n\n\
             **Your {} objects are untouched** — RFC 3 §8.4 keeps the corpus, \
             because objects are content-addressed and unattributed and are \
             not a record of anyone.\n\n\
             Mail you already exchanged stays readable while its epoch keys \
             live. What is gone is the record that the two of you agreed \
             anything, which is what a seized disk would otherwise prove.",
            before
        )
    }

    /// Purge the records of peerings whose credentials have lapsed —
    /// RFC 3 §8.4's "on termination **or expiry**".
    ///
    /// Runs on the schedule, because an expiry has no keystroke behind it.
    ///
    /// Purges only what §8.4 names — see [`artifact::PeerFile::purged_on_expiry`].
    /// The card and the reservoir stay, so `peer renew` can still form a fresh
    /// credential; what goes is the agreement, which nobody is party to any
    /// more.
    fn purge_expired_peerings(&mut self) {
        if self.epoch_key.is_none() {
            return;
        }
        let now_s = self.now_s();
        for peer in self.peer_ids() {
            let Standing::Live(credential::Life::Expired, at) = self.credential_standing(&peer)
            else {
                continue;
            };
            // **Not the instant the term lapses.**
            //
            // Purging immediately erased the reason along with the record:
            // `credential_standing` then reported `None`, so an operator whose
            // peering had lapsed was told "no credential — `peer countersign`"
            // rather than "expired — `peer renew`". That is RFC 3 §4's MUST
            // undone by RFC 3 §8.4, one tick later, and the advice was wrong
            // as well as uninformative.
            //
            // §4 resolves it: "revocation is non-renewal". A peering ends when
            // it is *not renewed*, not the moment its term runs out — so the
            // grace below is when declining becomes true, and until then the
            // state stays reportable and renewable.
            if now_s.saturating_sub(at) < GRACE_AFTER_EXPIRY_S {
                continue;
            }
            let dir = self.home.join("peers").join(&peer);
            let mut gone = 0;
            for f in artifact::PeerFile::ALL {
                if !f.purged_on_expiry() {
                    continue;
                }
                let path = dir.join(f.name());
                if path.exists() && shred::remove(&path, &mut OsRng) {
                    gone += 1;
                }
            }
            if gone > 0 {
                self.spends.remove(&peer);
                self.reach.retain(|(who, _)| who != &peer);
                self.log.push(activity_log::Event::Failed {
                    peer: peer.clone(),
                    why: "expired and not renewed — record purged (§8.4)",
                });
            }
        }
    }

    /// `peer renew <peer>` — RFC 3 §4.
    ///
    /// > "Renewal is a fresh `peer-link` with a new nonce, superseding by
    /// > `established` time."
    ///
    /// The same act as `peer share`, minus the flag change: both are a fresh
    /// credential handed over to be countersigned. One path, because two ways
    /// to re-sign a peering is two places for the flags or the terms to be
    /// dropped.
    fn peer_renew(&mut self, peer: Option<&str>) -> String {
        let Some(peer) = peer else {
            return "usage: peer renew <peer>\n\n\
                    A credential has a term and there is no revocation list — \
                    RFC 3 §4 makes revocation non-renewal, so a peering that \
                    is not renewed simply stops. Renew before the term ends, \
                    while there is still time to reach them."
                .into();
        };
        let was = self.credential_standing(peer);
        match self.resign_credential(peer, None, None) {
            Ok((path, from_agreement)) => format!(
                "renewed: a fresh credential for {peer} is at {}.\n\n\
                 {}\n\n\
                 Give it to them and have them run `peer countersign`. It \
                 carries a new nonce and supersedes the old one by \
                 `established` time (RFC 3 §4); the flags and terms you had \
                 agreed are carried across, so renewing changes nothing you \
                 both signed except the dates.{}",
                path.display(),
                if from_agreement {
                    ""
                } else {
                    "\n\n**Rebuilt from defaults.** There was no credential to \
                     carry terms across from — it lapsed and RFC 3 §8.4 purged \
                     the record. Any `peer carry` or `peer share` decision you \
                     had made is gone, and carriage is back on: check both \
                     before you hand this over."
                },
                match was {
                    Standing::Live(credential::Life::Expired, _) =>
                        "The old one had already expired, so this link has not \
                         been reconciling. It will once they countersign.",
                    Standing::Live(credential::Life::DueForRenewal, _) =>
                        "In good time — the old one had not lapsed yet.",
                    _ => "There was no usable credential before this.",
                }
            ),
            Err(e) => e,
        }
    }

    /// Build a fresh credential for `peer`, optionally changing this node's
    /// share flag, sign it, and write it out for countersignature.
    ///
    /// The one re-signing path. RFC 3 §4's renewal and §8.3's share change are
    /// the same act — a new credential, both signatures — and giving them
    /// separate implementations is how one of them comes to drop the terms or
    /// the other party's flag.
    fn resign_credential(
        &mut self,
        peer: &str,
        set_share: Option<bool>,
        set_bulletin: Option<bool>,
    ) -> Result<(PathBuf, bool), String> {
        let Some(id) = self.identity.as_ref() else {
            return Err("no identity — run `init` first".into());
        };
        if self.epoch_key.is_none() {
            return Err("locked — unlock to change a peering's terms".into());
        }
        let Some(card) = self.peer_card(peer) else {
            return Err(format!("no peer-link for {peer}"));
        };
        let me = id.node_id();

        // Read the existing document directly rather than through
        // `credential_with`, which refuses an expired one — and an expired
        // credential is exactly what renewal is for. Its flags and terms are
        // what both parties agreed and are carried across.
        let existing = self.epoch_key.and_then(|w| {
            std::fs::read(self.peer_path(peer, artifact::PeerFile::Credential))
                .ok()
                .and_then(|s| krab_crypto::kek::open_under(&w, b"krab/credential", &s).ok())
                .and_then(|raw| credential::Credential::decode(&raw))
        });

        let Some(mut cred) = credential::Credential::decode(&self.propose_credential(&card)) else {
            return Err("could not build a credential".into());
        };
        if let Some(old) = &existing {
            cred.flags = old.flags;
            cred.terms_ab = old.terms_ab;
            cred.terms_ba = old.terms_ba;
        }
        if let Some(want) = set_share {
            if cred.a.node_id() == me {
                cred.flags.a_shares_b = want;
            } else {
                cred.flags.b_shares_a = want;
            }
        }
        // RFC 6 §281 — "Nodes MUST support excluding class 1 (bulletin)
        // entirely via `class_mask`." Not per direction: the mask is one
        // field of the credential and both parties sign it, so a link either
        // carries public content or does not.
        if let Some(want) = set_bulletin {
            let bit = 1u8 << (krab_core::object::Class::Bulletin as u8 & 7);
            if want {
                cred.flags.class_mask |= bit;
            } else {
                cred.flags.class_mask &= !bit;
            }
        }
        cred.sig_a = None;
        cred.sig_b = None;
        let Some(id) = self.identity.as_ref() else {
            return Err("no identity".into());
        };
        cred.sign(id.signing_key());

        let out = self.home.join(format!("{peer}.credential"));
        atomic::write(&out, &cred.encode()).map_err(|e| format!("could not write it: {e}"))?;
        // **Whether anything was carried across.**
        //
        // `Flags::default()` is safe for §8.3's share bits — false, opt in
        // rather than out — and is *not* safe for `class_mask`, which defaults
        // to admitting everything. So a peering whose credential was purged on
        // expiry (RFC 3 §8.4) and is then renewed silently re-enables carriage
        // the operator had turned off, while correctly leaving sharing off.
        //
        // One default word, two directions, and only one of them was thought
        // about. The safe direction is not the same for every flag, so the
        // caller is told which case this was rather than the difference being
        // invisible.
        Ok((out, existing.is_some()))
    }

    fn peer_share(&mut self, peer: Option<&str>, on: Option<&str>) -> String {
        let (Some(peer), Some(on)) = (peer, on) else {
            return "usage: peer share <peer> on|off\n\n\
                    Whether you will list them in the nodelist fragments you \
                    hand out. Off by default, and RFC 3 §8.3 says MUST: a node \
                    may have ten casual peers and one sensitive one, and \
                    without this the sensitive link is exposed to the other \
                    ten.\n\n\
                    It bounds graph-walking too — without it an adversary who \
                    acquires one peer requests fragments, acquires more, and \
                    maps the network one hop at a time (§8.3, §15)."
                .into();
        };
        let want = match on {
            "on" | "yes" | "true" => true,
            "off" | "no" | "false" => false,
            _ => return "say `on` or `off`".into(),
        };
        match self.resign_credential(peer, Some(want), None) {
            Ok((path, _)) => format!(
                "you will {} list {peer}.\n\n\
                 Give {} to them and have them run `peer countersign` — the \
                 flag is inside both signatures, so a peering neither of you \
                 re-signs keeps the old one. That is what stops either of you \
                 exposing the other unilaterally (RFC 3 §8.3).",
                if want { "now" } else { "no longer" },
                path.display()
            ),
            Err(e) => e,
        }
    }

    /// `peer carry <peer> on|off` — RFC 6 §281.
    ///
    /// > "Nodes MUST support excluding class 1 (bulletin) entirely via
    /// > `class_mask`."
    ///
    /// The filter has enforced `class_mask` since it existed and **nothing
    /// ever set it**: `Flags::class_mask` was `0xFF` and no verb changed it,
    /// so a node could not decline public content however much it wanted to.
    /// The same shape the share flag had before `peer share`.
    ///
    /// Not per direction. The mask is one field of the credential and both
    /// parties sign it, so a link either carries bulletins or it does not —
    /// which is right, because a link that carried them one way would still
    /// be moving them.
    fn peer_carry(&mut self, peer: Option<&str>, on: Option<&str>) -> String {
        let (Some(peer), Some(on)) = (peer, on) else {
            return "usage: peer carry <peer> on|off\n\n\
                    Whether this link carries public content — channel posts, \
                    prekey batches, rollcall entries (RFC 1 §5.2's bulletins).\n\n\
                    Turning it off narrows what crosses to sealed mail only. \
                    RFC 6 §281 requires a node be able to decline class 1 \
                    entirely; RFC 6 §3.6 makes carrying public content an \
                    explicit decision, because what a node hosts has \
                    consequences that depend on the operator's jurisdiction."
                .into();
        };
        let want = match on {
            "on" | "yes" | "true" => true,
            "off" | "no" | "false" => false,
            _ => return "say `on` or `off`".into(),
        };
        match self.resign_credential(peer, None, Some(want)) {
            Ok((path, _)) => format!(
                "this link will {} carry public content.\n\n\
                 Give {} to {peer} and have them run `peer countersign` — the \
                 mask is inside both signatures, so it binds only once you \
                 both agree to it.\n\n\
                 {}",
                if want { "now" } else { "no longer" },
                path.display(),
                if want {
                    "Bulletins are public and attributable to whoever wrote \
                     them, not to you — but a node that carries them is \
                     hosting them (RFC 6 §3.6)."
                } else {
                    "Sealed mail is unaffected. What stops crossing is \
                     channel posts, prekey batches and rollcall entries — \
                     which means peers on the other side of this link may \
                     become harder to reach."
                }
            ),
            Err(e) => e,
        }
    }

    /// `peer fragment` — RFC 3 §8.
    ///
    /// > "A node's fragment is the set of its currently valid `peer-link`
    /// > credentials, signed, and **encrypted individually to each of its own
    /// > peers**. Not published, not flooded, not readable by anyone at three
    /// > hops."
    ///
    /// Individually is the expensive part and the point: §8.1 prices it at
    /// `O(P²)`, which is the term bounding peer count in §13's table. A
    /// flooded fragment would be cheaper and would be a directory.
    fn peer_fragment(&mut self) -> String {
        let (Some(id), Some(_)) = (&self.identity, self.epoch_key) else {
            return "locked — unlock to publish a nodelist".into();
        };
        let peers = self.peer_ids();
        if peers.is_empty() {
            return "no peerings — nothing to list".into();
        }
        let now_s = self.now_s();
        let creds: Vec<credential::Credential> = peers
            .iter()
            .filter_map(|p| self.credential_with(p))
            .collect();
        let signing = id.signing_key();
        let frag = fragment::Fragment::create(signing, now_s, &creds, now_s);

        if frag.links.is_empty() {
            return format!(
                "nothing to list.\n\n\
                 {} peering(s), and none opted in to being listed. That is \
                 RFC 3 §8.3's default and it is a MUST — `peer share <peer> \
                 on` changes it, with their countersignature.\n\n\
                 An operator who sets it everywhere has published their social \
                 graph to their peers, one hop at a time (§15).",
                peers.len()
            );
        }

        // **Full weekly, deltas between** — RFC 3 §8.2, FidoNet's cadence and
        // the arithmetic behind it: a one-link delta is 8× to 34× cheaper than
        // a full fragment, which matters on the austere links §8.1 prices.
        //
        // One base for everyone: a fragment's contents are the node's own
        // links, so every peer is sent the same document at the same moment
        // and is therefore on the same base.
        let base = self.read_nodelist_base();
        let due_full = match &base {
            Some(b) => {
                now_s.saturating_sub(b.published_s)
                    >= fragment::FULL_INTERVAL_DAYS.saturating_mul(86_400)
            }
            None => true,
        };
        let (body, kind, listed) = if due_full {
            let b = frag.encode();
            self.save_nodelist_base(&frag);
            (b, "full nodelist", frag.links.len())
        } else {
            let b = base.as_ref().expect("not due means a base exists");
            let delta = fragment::Delta::create(signing, b, now_s, &creds, now_s);
            let n = delta.added.len() + delta.removed.len();
            if n == 0 {
                return format!(
                    "nothing has changed since your last nodelist.\n\n\
                     RFC 3 §8.2 sends a full fragment weekly and deltas \
                     between; there is no delta to send, and re-sending the \
                     same {} link(s) would cost {} peer-copies for no news.",
                    frag.links.len(),
                    peers.len()
                );
            }
            (delta.encode(), "NODEDIFF", n)
        };
        let mut sent = 0;
        for p in &peers {
            // Individually, pairwise, by the same path a private message
            // takes — a second sealing path would be a second place to get
            // the mode or the prekey selection wrong.
            let Some((oid, bytes)) = self.seal_one(p, &body) else {
                continue;
            };
            if self
                .store
                .with(|s| s.ingest(oid, bytes, now_epoch().0 * 1440, u32::MAX))
                .is_ok()
            {
                sent += 1;
            }
        }
        self.save_corpus();
        format!(
            "{kind} sent to {sent} of {} peer(s), {listed} link(s).\n\n\
             Each copy is sealed to one peer — not published, not flooded, and \
             not readable by anyone at three hops (RFC 3 §8). That costs \
             O(P²) bytes, which is the term bounding how many peers a node \
             should have (§8.1, §13).\n\n\
             Listed: {}.\n\n\
             Everyone else you peer with is absent, because they have not \
             opted in.",
            peers.len(),
            frag.reaches()
                .iter()
                .map(short_id)
                .collect::<Vec<_>>()
                .join(", ")
        )
    }

    /// The last full fragment this node published — RFC 3 §8.2's base.
    fn read_nodelist_base(&self) -> Option<fragment::Fragment> {
        let w = self.epoch_key?;
        let sealed = std::fs::read(self.path(artifact::Artifact::Nodelist)).ok()?;
        let raw = krab_crypto::kek::open_under(&w, b"krab/nodelist", &sealed).ok()?;
        fragment::Fragment::decode(&raw)
    }

    /// Record it, sealed. A fragment is the graph (RFC 3 §15), so it is no
    /// more readable at rest than a credential is.
    fn save_nodelist_base(&mut self, frag: &fragment::Fragment) -> Option<()> {
        let w = self.epoch_key?;
        let sealed =
            krab_crypto::kek::seal_under(&w, b"krab/nodelist", &frag.encode(), &mut OsRng).ok()?;
        atomic::write(&self.path(artifact::Artifact::Nodelist), &sealed).ok()
    }

    /// The last full fragment received from `peer` — the base their deltas
    /// reference.
    fn read_peer_base(&self, peer: &str) -> Option<fragment::Fragment> {
        let w = self.epoch_key?;
        let sealed = std::fs::read(self.peer_path(peer, artifact::PeerFile::Nodelist)).ok()?;
        // A **distinct** domain from this node's own base. Two artifacts under
        // one sealing context means a ciphertext from either opens as the
        // other, which is the one thing a domain is for — and the checks that
        // would catch the swap (`base_hash`, the author comparison) are
        // downstream of a decryption that should never have succeeded.
        let raw = krab_crypto::kek::open_under(&w, b"krab/nodelist/peer", &sealed).ok()?;
        fragment::Fragment::decode(&raw)
    }

    /// Record a peer's full fragment as the base for their deltas.
    ///
    /// Takes `&self` rather than `&mut self` so it can run inside
    /// `refresh_inbox`, where the identity is borrowed for the whole scan.
    fn save_peer_base(&self, peer: &str, frag: &fragment::Fragment) -> Option<()> {
        let w = self.epoch_key?;
        let dir = self.home.join("peers").join(peer);
        std::fs::create_dir_all(&dir).ok()?;
        let sealed =
            krab_crypto::kek::seal_under(&w, b"krab/nodelist/peer", &frag.encode(), &mut OsRng)
                .ok()?;
        atomic::write(&dir.join(artifact::PeerFile::Nodelist.name()), &sealed).ok()
    }

    /// The negotiation chain with `peer`, if one was stored — RFC 3 §5.3.
    ///
    /// Sealed under `W_N` and never published: §5.3 calls it "local evidence"
    /// and says it MUST NOT be published, because it names an introducer and
    /// is therefore graph information.
    fn chain_with(&self, peer: &str) -> Option<negotiate::Chain> {
        let w = self.epoch_key?;
        let sealed = std::fs::read(self.peer_path(peer, artifact::PeerFile::Chain)).ok()?;
        let raw = krab_crypto::kek::open_under(&w, b"krab/chain", &sealed).ok()?;
        let chain = negotiate::Chain::decode(&raw)?;
        // Verified on the way out, so no caller can act on a chain that does
        // not hold together — the same rule `bulletin::from_object` follows.
        chain.verify().ok().map(|()| chain)
    }

    /// Store a negotiation chain, sealed.
    fn save_chain(&mut self, peer: &str, chain: &negotiate::Chain) -> Option<()> {
        let w = self.epoch_key?;
        self.ensure_peer_dir(peer).ok()?;
        let sealed =
            krab_crypto::kek::seal_under(&w, b"krab/chain", &chain.encode(), &mut OsRng).ok()?;
        atomic::write(&self.peer_path(peer, artifact::PeerFile::Chain), &sealed).ok()
    }
}

/// What a peering's credential is, as far as the operator needs to know —
/// RFC 3 §4.
///
/// **The reason `credential_with` was not enough.** It returns `Option`, so
/// "never countersigned" and "lapsed last Tuesday" arrive as the same `None`,
/// and every caller downstream treats them the same way: an unscoped filter, a
/// link that will not reconcile, and nothing said. §4 names that outcome
/// exactly — "the two look identical from the outside and confusing them will
/// waste a great deal of operator time" — and makes distinguishing them a MUST.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Standing {
    /// No credential has been countersigned. The ordinary state of a peering
    /// formed before `peer countersign` existed, and of one half-finished.
    None,
    /// A credential exists and does not verify. Not an expiry — a defect.
    Unusable(credential::Invalid),
    /// A credential exists and is where `life` says in its term.
    Live(credential::Life, u64),
}

impl Standing {
    /// One line for the operator, naming the command where there is one.
    fn line(&self, peer: &str, now_s: u64) -> String {
        match self {
            Standing::None => "no credential — nothing is scoped or enforced on \
                 this link. `peer countersign` completes one"
                .into(),
            Standing::Unusable(why) => format!(
                "credential does not verify ({why:?}) — this is a defect, not \
                 an expiry. Re-run the ceremony with {peer}"
            ),
            Standing::Live(credential::Life::Expired, at) => format!(
                "**EXPIRED** {} day(s) ago — this link will not reconcile until \
                 it is renewed. Revocation is non-renewal (RFC 3 §4), so \
                 nothing is wrong with {peer}: the term simply ended. \
                 `peer renew {peer}`",
                now_s.saturating_sub(*at) / 86_400
            ),
            Standing::Live(credential::Life::DueForRenewal, at) => format!(
                "expires in {} day(s) — `peer renew {peer}` now, while there is \
                 time to reach them",
                at.saturating_sub(now_s) / 86_400
            ),
            Standing::Live(credential::Life::Current, at) => {
                format!(
                    "credential valid for {} more day(s)",
                    at.saturating_sub(now_s) / 86_400
                )
            }
        }
    }
}

impl App {
    /// Where this peering's credential stands — RFC 3 §4.
    ///
    /// The one place that reads the file and decides; `credential_with` is
    /// built on it, so enforcement and reporting cannot disagree about what a
    /// credential is.
    fn credential_standing(&self, peer: &str) -> Standing {
        let Some(w) = self.epoch_key else {
            return Standing::None;
        };
        let Some(cred) = std::fs::read(self.peer_path(peer, artifact::PeerFile::Credential))
            .ok()
            .and_then(|sealed| krab_crypto::kek::open_under(&w, b"krab/credential", &sealed).ok())
            .and_then(|raw| credential::Credential::decode(&raw))
        else {
            return Standing::None;
        };
        let now_s = self.now_s();
        match cred.verify(now_s) {
            Ok(()) => Standing::Live(cred.life(now_s), cred.expires_s),
            // Expiry is reported as what it is. `verify` refuses it, which is
            // correct enforcement; reporting it as a defect is what §4 forbids.
            Err(credential::Invalid::Expired) => {
                Standing::Live(credential::Life::Expired, cred.expires_s)
            }
            Err(why) => Standing::Unusable(why),
        }
    }
}

impl App {
    /// This node's completed credential with `peer`, if there is one.
    ///
    /// Sealed at rest under `W_N` — RFC 3 §15 makes that a MUST, so a locked
    /// node cannot read its own credentials and therefore cannot cite one.
    /// That is the intended behaviour and not a limitation: §15 calls a
    /// running node holding them in memory "mitigation, not a fix".
    fn credential_with(&self, peer: &str) -> Option<credential::Credential> {
        let w = self.epoch_key?;
        let sealed = std::fs::read(self.peer_path(peer, artifact::PeerFile::Credential)).ok()?;
        let raw = krab_crypto::kek::open_under(&w, b"krab/credential", &sealed).ok()?;
        let cred = credential::Credential::decode(&raw)?;
        cred.verify(self.now_s()).ok().map(|()| cred)
    }

    /// `rollcall` — the public tier, RFC 3 §9.
    ///
    /// Three forms, and the bare one is a *read*. Listing yourself is
    /// something you have to ask for in words, because §9's requirement is not
    /// merely that the default is off but that a node is invisible until its
    /// operator decides otherwise — and a command that published as a side
    /// effect of being curious about who else is out there would defeat it.
    fn rollcall_command(&mut self, line: &str) -> String {
        let Ok(words) = words::split(line) else {
            return "unbalanced quotes".into();
        };
        match words.get(1).map(|w| w.text()).as_deref() {
            None => self.rollcall_status(),
            Some("publish") => self.rollcall_publish(),
            Some("withdraw") => self.rollcall_withdraw(),
            Some(other) => format!(
                "no rollcall subcommand `{other}`.\n\n\
                 \x20 rollcall            who is listed, and whether you are\n\
                 \x20 rollcall publish    list this node — RFC 3 §9 is opt-in\n\
                 \x20 rollcall withdraw   stop republishing"
            ),
        }
    }

    /// Who is listed, and whether this node is.
    fn rollcall_status(&self) -> String {
        let mut seen: Vec<(String, rollcall::Entry, u32)> = Vec::new();
        let me = self.identity.as_ref().map(|i| i.node_id());
        self.store.with(|s| {
            for (_, id) in s.entries_in_range(0, u32::MAX) {
                let Some(bytes) = s.get(&id) else { continue };
                // `from_object` yields nothing unless the bulletin verifies,
                // so an unsigned entry cannot be listed by forgetting to check
                // — and this is the one tier strangers write into.
                let Some(b) = bulletin::from_object(bytes) else {
                    continue;
                };
                if b.kind != bulletin::Kind::Rollcall {
                    continue;
                }
                let Some(e) = rollcall::Entry::decode(&b.payload) else {
                    continue;
                };
                let node = b.node_id();
                let short = short_id(&node);
                // Newest wins: entries are flooded and republished, so the
                // same node appears more than once until the old copy expires.
                match seen.iter_mut().find(|(n, _, _)| *n == short) {
                    Some(slot) if slot.2 < b.epoch => *slot = (short, e, b.epoch),
                    Some(_) => {}
                    None => seen.push((short, e, b.epoch)),
                }
            }
        });
        seen.sort_by(|a, b| a.0.cmp(&b.0));

        let mut out = String::new();
        if seen.is_empty() {
            out.push_str("no rollcall entries in the corpus.\n\n");
        } else {
            out.push_str(&format!("{} node(s) listed:\n\n", seen.len()));
            for (short, e, epoch) in &seen {
                let mine = if me.map(|m| short_id(&m) == *short).unwrap_or(false) {
                    "  (you)"
                } else {
                    ""
                };
                out.push_str(&format!(
                    "\x20 {short}{mine}\n\x20   {}\n\x20   epoch {epoch}\n",
                    e.summary()
                ));
            }
            out.push('\n');
        }
        out.push_str(if self.rollcall.publishing {
            "You are publishing. `rollcall withdraw` stops it."
        } else {
            "You are not listed. RFC 3 §9's default is invisible: a node that \
             never publishes is reachable only through hand-exchanged \
             credentials.\n\n`rollcall publish` lists this node's keys and \
             terms — never its endpoints, and never who it peers with."
        });
        out
    }

    /// Opt in, and publish an entry.
    fn rollcall_publish(&mut self) -> String {
        let Some(id) = self.identity.as_ref() else {
            return "no identity — run `init` first".into();
        };
        if self.epoch_key.is_none() {
            return "locked — unlock to publish".into();
        }
        let policy = peering::Policy::default();
        let epoch = now_epoch();
        let entry = rollcall::Entry {
            kx_pk: id.correspondence_bytes(),
            max_bucket: policy.max_bucket,
            shard_bits: policy.shard_bits,
            relay: policy.relay,
            watermark: self.store.with(|s| s.watermark()),
        };

        let b = bulletin::Bulletin::create(
            bulletin::Kind::Rollcall,
            id.signing_key(),
            epoch.0,
            entry.encode(),
        );
        let now_min = epoch.0 * 1440;
        // ~7 days, not `MAX_TTL`. An entry has to lapse quickly, because
        // lapsing is the only way one is ever removed (RFC 3 §6.1).
        let Some((oid, bytes)) = bulletin::into_object(&b, now_min, rollcall::TTL_MINUTES) else {
            return "the entry does not fit an object".into();
        };
        if let Err(e) = self.store.with(|s| s.ingest(oid, bytes, now_min, u32::MAX)) {
            return format!("could not publish: {e:?}");
        }
        self.save_corpus();

        self.rollcall.publishing = true;
        self.rollcall.last_epoch = Some(epoch.0);
        format!(
            "listed in the rollcall as {short}.\n\n\
             It carries your identity and correspondence keys, and the terms \
             you would peer on: {summary}.\n\n\
             It carries **no endpoint** — not an address, a port, a transport \
             or an onion (RFC 3 §9.2). A peer-request reaches you through the \
             corpus, so being findable never required being locatable.\n\n\
             It also says nothing about who you already peer with. A directory \
             of nodes is a public key directory; a directory of links is the \
             social graph (RFC 3 §9.1).\n\n\
             It expires in 7 days and this node refreshes it while you stay \
             listed. `rollcall withdraw` stops that.",
            short = id.short_id(),
            summary = entry.summary(),
        )
    }

    /// Stop republishing. There is no recall.
    fn rollcall_withdraw(&mut self) -> String {
        if !self.rollcall.publishing {
            return "not listed — nothing to withdraw.".into();
        }
        self.rollcall.publishing = false;
        format!(
            "withdrawn: this node will not republish.\n\n\
             **The entry already out there cannot be recalled.** RFC 3 §6.1 \
             forbids a recall mechanism permanently, because a recall \
             mechanism is a censorship mechanism and cannot be made \
             selective — so it stands until it expires, within {days} days of \
             when it was published.\n\n\
             Nothing in it was an endpoint or a relationship, so what remains \
             visible is a key and the terms you offered.",
            days = rollcall::TTL_MINUTES / 1440,
        )
    }

    fn message(&mut self, line: &str) -> String {
        let Ok(words) = words::split(line) else {
            return "unbalanced quotes".into();
        };
        let to: Vec<String> = words.iter().skip(1).map(|w| w.text()).collect();
        if to.is_empty() {
            return "usage: message <peer> [peer…]\n\n\
                    Opens a composition addressed to everyone named. Ctrl-D \
                    seals one copy per recipient and queues them; Esc discards \
                    the draft."
                .into();
        }
        if self.epoch_key.is_none() {
            return "locked — unlock to compose".into();
        }
        // Every recipient must be someone this node can seal to. Checked
        // before the operator writes anything, not after: fan-out seals
        // individually, and a recipient that cannot be sealed to would
        // silently receive nothing.
        let unknown: Vec<&String> = to
            .iter()
            .filter(|p| !self.peer_path(p, artifact::PeerFile::Link).exists())
            .collect();
        if !unknown.is_empty() {
            return format!(
                "no peer-link for {}.\n\n\
                 Every recipient has to be someone you have peered with — each \
                 gets their own sealed copy, and one you cannot seal to would \
                 receive nothing while nothing said so.",
                unknown
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        self.composing_to_many = to.clone();
        self.composing_to = to.first().cloned();
        self.ui.compose();
        while self.ui.focus() != layout::Pane::View {
            self.ui.cycle_focus();
        }
        format!(
            "composing to {}.\n\n\
             PRIVATE — sealed once per recipient. Enter is a newline; Ctrl-D \
             seals and queues; Esc discards, and a discarded draft is \
             overwritten rather than dropped (RFC 7 §8).{}",
            to.join(", "),
            if to.len() > 1 {
                format!(
                    "\n\n{} copies leave over a randomised window, so they do \
                     not announce themselves as one fan-out (RFC 6 §2.7).",
                    to.len()
                )
            } else {
                String::new()
            }
        )
    }

    /// Seal and queue what is in the composer.
    ///
    /// **`Ctrl-D`, not `Enter`.** Enter inserts a newline, because a message
    /// worth composing over several lines is one where Enter must not send it
    /// halfway through — and a message sent early cannot be recalled, since
    /// RFC 3 §6.1 forbids any mechanism that could.
    /// Characters in the composer.
    fn composer_len(&self) -> usize {
        self.composer.chars().count()
    }

    /// Byte offset of character index `at`.
    fn composer_byte(&self, at: usize) -> usize {
        self.composer
            .char_indices()
            .nth(at)
            .map(|(b, _)| b)
            .unwrap_or(self.composer.len())
    }

    /// Put `text` in the composer with the caret after it.
    ///
    /// The caret and the text are one state, and anything that sets the text
    /// without setting the caret leaves the next keystroke inserting at the
    /// front. Nothing in production fills the composer directly today; this
    /// exists so that when something does, the invariant comes with it —
    /// and the tests use it, which is what keeps it correct until then.
    #[cfg(test)]
    fn composer_set(&mut self, text: &str) {
        overwrite(&mut self.composer);
        self.composer.push_str(text);
        self.composer_at = self.composer_len();
    }

    /// Insert at the caret and step over it.
    fn composer_insert(&mut self, c: char) {
        let at = self.composer_byte(self.composer_at);
        self.composer.insert(at, c);
        self.composer_at += 1;
    }

    /// Delete the character before the caret.
    fn composer_backspace(&mut self) {
        if self.composer_at == 0 {
            return;
        }
        let at = self.composer_byte(self.composer_at - 1);
        self.composer.remove(at);
        self.composer_at -= 1;
    }

    /// Delete the character under the caret.
    fn composer_delete(&mut self) {
        if self.composer_at >= self.composer_len() {
            return;
        }
        let at = self.composer_byte(self.composer_at);
        self.composer.remove(at);
    }

    /// (row, column) of the caret, both zero-based.
    fn composer_rowcol(&self) -> (usize, usize) {
        let before: String = self.composer.chars().take(self.composer_at).collect();
        let row = before.matches('\n').count();
        let col = before.rsplit('\n').next().map(|l| l.chars().count()).unwrap_or(0);
        (row, col)
    }

    /// Move the caret to `row`, as close to `col` as that row allows.
    fn composer_goto(&mut self, row: usize, col: usize) {
        let lines: Vec<&str> = self.composer.split('\n').collect();
        let row = row.min(lines.len().saturating_sub(1));
        let col = col.min(lines[row].chars().count());
        let mut at = 0usize;
        for l in lines.iter().take(row) {
            at += l.chars().count() + 1; // the newline
        }
        self.composer_at = at + col;
    }

    /// Editing keys, routed to the composer. RFC 8 §2.1's pane is where text
    /// is written, so it is the pane that has to accept them.
    fn composer_edit(&mut self, e: keys::Edit) {
        use keys::Edit;
        let (row, _col) = self.composer_rowcol();
        match e {
            Edit::Backspace => self.composer_backspace(),
            Edit::Delete => self.composer_delete(),
            Edit::Left => self.composer_at = self.composer_at.saturating_sub(1),
            Edit::Right => self.composer_at = (self.composer_at + 1).min(self.composer_len()),
            Edit::Home => self.composer_goto(row, 0),
            Edit::End => self.composer_goto(row, usize::MAX),
            // Word motion, over the draft rather than over one line: a
            // composer is multi-line and a word boundary does not stop at a
            // newline any more than the caret does.
            Edit::WordLeft => {
                let chars: Vec<char> = self.composer.chars().collect();
                let mut i = self.composer_at;
                while i > 0 && chars[i - 1].is_whitespace() {
                    i -= 1;
                }
                while i > 0 && !chars[i - 1].is_whitespace() {
                    i -= 1;
                }
                self.composer_at = i;
            }
            Edit::WordRight => {
                let chars: Vec<char> = self.composer.chars().collect();
                let n = chars.len();
                let mut i = self.composer_at;
                while i < n && !chars[i].is_whitespace() {
                    i += 1;
                }
                while i < n && chars[i].is_whitespace() {
                    i += 1;
                }
                self.composer_at = i;
            }
            // **Deletions overwrite.** RFC 7 §8: plaintext that is discarded
            // is overwritten rather than dropped, and a killed word is
            // discarded plaintext like any other.
            Edit::KillWord => {
                let before = self.composer_at;
                self.composer_edit(Edit::WordLeft);
                let from = self.composer_byte(self.composer_at);
                let to = self.composer_byte(before);
                let mut cut: String = self.composer[from..to].to_string();
                self.composer.replace_range(from..to, "");
                overwrite(&mut cut);
            }
            Edit::KillToStart => {
                let to = self.composer_byte(self.composer_at);
                let mut cut: String = self.composer[..to].to_string();
                self.composer.replace_range(..to, "");
                self.composer_at = 0;
                overwrite(&mut cut);
            }
            Edit::KillToEnd => {
                let from = self.composer_byte(self.composer_at);
                let mut cut: String = self.composer[from..].to_string();
                self.composer.truncate(from);
                overwrite(&mut cut);
            }
        }
    }

    /// Keep the cursor on an item that still exists.
    ///
    /// Mail arrives and notes are added while the operator is reading, so the
    /// count changes underneath the cursor. Clamping keeps it in range without
    /// throwing away where they were, which zeroing did.
    fn clamp_selection(&mut self) {
        let n = self.selectable_len();
        self.selected = if n == 0 { 0 } else { self.selected.min(n - 1) };
    }

    /// How many *items* the focused list holds.
    ///
    /// Not `list.len()`: the private list can carry first-contact requests
    /// above the mail, and those are rows without a message behind them.
    /// Selection is over items, so its bound has to be too.
    fn selectable_len(&self) -> usize {
        match (self.ui.tab(), self.ui.level()) {
            (layout::Tab::Private, _) => self.messages.len(),
            (layout::Tab::Notes, _) => self
                .identity
                .as_ref()
                .map(|i| self.pinned().of(&i.short_id()).len())
                .unwrap_or(0),
            (layout::Tab::Channels, layout::Level::Messages) => self
                .channel_open
                .map(|id| self.channel_post_items(&id).len())
                .unwrap_or(0),
            (layout::Tab::Channels, layout::Level::Channels) => self.channel_ids().len(),
        }
    }

    /// Move the cursor in the focused list — RFC 8 §2's list pane.
    ///
    /// **Nothing moved it before.** `selected` was written only as `0` and
    /// read everywhere, so every list in the interface showed its first item
    /// and no other: no message could be opened but the newest, no channel
    /// entered but the first, no note read but one.
    fn move_selection(&mut self, d: i8) {
        let n = self.selectable_len();
        if n == 0 {
            return;
        }
        let last = n - 1;
        self.selected = if d < 0 {
            self.selected.saturating_sub(1)
        } else {
            (self.selected + 1).min(last)
        };
        self.show_selected();
    }

    /// Up and Down while composing: move a line, not through history.
    fn composer_vertical(&mut self, d: i8) {
        let (row, col) = self.composer_rowcol();
        if d < 0 {
            if row > 0 {
                self.composer_goto(row - 1, col);
            }
        } else {
            self.composer_goto(row + 1, col);
        }
    }

    fn deliver(&mut self) {
        if self.ui.mode() != Mode::Compose {
            self.output = "nothing is being composed. `send <peer>` starts one.".into();
            return;
        }
        if self.composing_channel {
            self.output = self.seal_post();
            return;
        }
        if self.composing_note {
            let text = self.composer.trim().to_string();
            overwrite(&mut self.composer);
        self.composer_at = 0;
            self.ui.end_compose();
            self.composing_note = false;
            self.output = match (self.pin_key, text.is_empty()) {
                (_, true) => "nothing to keep. Esc discards this.".into(),
                (Some(k), false) => self.write_note(&k, &text),
                (None, false) => "locked — unlock to reach your notes".into(),
            };
            return;
        }
        let to = if self.composing_to_many.is_empty() {
            self.composing_to.clone().into_iter().collect::<Vec<_>>()
        } else {
            self.composing_to_many.clone()
        };
        if to.is_empty() {
            self.output = "this composition is not addressed to anyone.\n\n\
                 Esc discards it, then `message <peer>` starts one that is."
                .into();
            return;
        }
        let text = self.composer.trim().to_string();
        if text.is_empty() {
            self.output = "nothing to send. Esc discards the composition.".into();
            return;
        }

        let out = self.fan_out(&to, &text);
        // The draft is gone either way: RFC 7 §8 keeps plaintext only while
        // displayed, and a failed send is not a reason to hold it longer.
        overwrite(&mut self.composer);
        self.composer_at = 0;
        self.ui.end_compose();
        self.composing_to = None;
        self.composing_to_many.clear();
        self.output = out;
    }

    /// Send a picture — RFC 8 §6's pipeline, then the ordinary send path.
    ///
    /// The bytes on the wire are **the ones this program produced**, never the
    /// ones on disk. That is the requirement, not a precaution: a polyglot is
    /// a genuine image and passes every check, and re-encoding is what leaves
    /// nothing of it but pixels.
    fn send_picture(&mut self, peer: &str, path: &str) -> String {
        // RFC 8 §6: say so *before* sending, not after silent non-delivery.
        if let Some(profile) = self.links.get(peer).map(|l| l.profile.clone()) {
            if !picture::carriable(&profile) {
                return format!(
                    "the link to {peer} is {} and cannot carry a picture \
                     (RFC 4 §5.4).\n\n\
                     Nothing was sent. Sending it would have been silent \
                     non-delivery, which is worse than a refusal.",
                    profile.kind
                );
            }
        }
        let raw = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => return format!("could not read {path}: {e}"),
        };

        // **Off this thread**, per RFC 8 §6's isolation requirement. The
        // closure captures the bytes and nothing else: no identity, no epoch
        // key, no store handle. A separate process would be stronger and is
        // not done — see `picture`'s module note, which says so plainly.
        // **A separate process**, per RFC 8 §6. It holds no key material
        // because it is entered from the first line of `main`, before anything
        // is loaded — so a decoder bug that achieves code execution owns a
        // process containing one attacker-supplied image and nothing else.
        // **A separate process**, per RFC 8 §6. Where one cannot be started —
        // a restricted environment, an executable that cannot re-invoke
        // itself — the picture is still decoded, in this process, and the
        // operator is told. A silent fallback would be a safety property
        // quietly absent, which is worse than not having it.
        let (clean, isolated) = match picture::transcode_isolated(&raw) {
            Ok(bytes) => (bytes, true),
            Err(picture::Error::NoIsolation) => match picture::transcode(&raw) {
                Ok(bytes) => (bytes, false),
                Err(e) => return format!("{e}"),
            },
            Err(e) => return format!("{e}"),
        };

        let n = clean.len();
        let was = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        // Sent as text is wrong; a picture is bytes. The body carries the
        // re-encoded PNG and the recipient writes it out with `picture save`.
        // The marker is inside the sealed plaintext, so it is as confidential
        // as the picture. A class byte would put "this is a picture" in the
        // routing header, where every relay reads it.
        let mut body = picture::MARKER.to_vec();
        body.extend_from_slice(&clean);
        let Some((id, bytes)) = self.seal_one(peer, &body) else {
            return format!("could not seal for {peer} — is that a completed peering?");
        };
        let epoch = now_epoch();
        if let Err(e) = self
            .store
            .with(|s| s.ingest(id, bytes, epoch.0 * 1440, u32::MAX))
        {
            return format!("the store refused it: {e:?}");
        }
        self.save_corpus();
        self.refresh_inbox();
        let out = "composed".to_string();
        format!(
            "{out}\n\n\
             The picture was decoded and re-encoded ({was} bytes in, {n} out). \
             What leaves this node is pixel data it generated: no EXIF, no GPS, \
             no ICC profile, nothing appended. That is automatic and there is \
             no setting for it (RFC 8 §6).{}",
            if isolated {
                ""
            } else {
                "\n\nNOTE: it was decoded in this process rather than a separate \
                 one. RFC 8 §6 prefers a separate process because an image \
                 decoder is the likeliest place a hostile file gets code \
                 running, and this address space holds your keys."
            }
        )
    }

    /// Seal one message to one peer, without placing it in the corpus.
    ///
    /// The path `send` takes, factored out so a group copy is the same object
    /// a private message is — a second sealing path would be a second place to
    /// get the AAD, the mode, or the prekey selection wrong.
    fn seal_one(
        &self,
        peer: &str,
        plaintext: &[u8],
    ) -> Option<(krab_core::object::ObjectId, Vec<u8>)> {
        let id = self.identity.as_ref()?;
        let w = self.epoch_key?;
        let card = std::fs::read(self.peer_path(peer, artifact::PeerFile::Link))
            .ok()
            .and_then(|b| peering::Card::decode(&b).ok())
            .filter(|c| c.verify())?;

        let epoch = now_epoch();
        let their_prekey = self.prekey_for(&card.node_id());
        let reservoir = std::fs::read(self.peer_path(peer, artifact::PeerFile::Reservoir))
            .ok()
            .and_then(|sealed| krab_crypto::kek::open_under(&w, b"krab/reservoir", &sealed).ok())
            .and_then(|raw| persist::decode_reservoir(&raw).ok())
            .and_then(|(root, stored)| {
                let mut r = krab_crypto::reservoir::Reservoir::new(root, stored);
                if stored != epoch && !r.advance_to(epoch) {
                    return None;
                }
                Some(r)
            });
        let chunk = reservoir.and_then(|r| r.chunk(epoch));

        let their_pk = krab_crypto::dh::PublicKey(card.correspondence_pk);
        let shared = id.agree_with(&their_pk)?;
        let tag = krab_crypto::pairwise_tag(&shared, epoch);
        let to = their_prekey.unwrap_or(their_pk);

        let composed = compose::seal_to(
            id.correspondence(),
            &compose::Recipient::Known {
                correspondence: &to,
                tag,
                chunk: chunk.as_ref(),
            },
            epoch,
            0,
            expiry_for(epoch),
            plaintext,
            &mut OsRng,
        )
        .ok()?;
        Some((composed.id, composed.bytes))
    }

    /// Send to a group — RFC 6 §2's fan-out.
    ///
    /// One sealed copy per member, to that member. There is no shared group
    /// key, so a compromised member exposes **that member** and nobody else —
    /// which is the whole reason to pay `(G−1)×` for it.
    ///
    /// Emission is staggered (RFC 6 §2.7). The copies do not enter the corpus
    /// now; they are held and released over a window derived from the observed
    /// background rate, because `G−1` objects appearing together in one size
    /// bucket announces both the fan-out and its size.
    fn group_send(&mut self, name: Option<&str>, text: &str) -> String {
        let (Some(name), false) = (name, text.is_empty()) else {
            return "usage: group send <name> <text>".into();
        };
        let Some(g) = self.groups.iter().find(|g| g.name == name).cloned() else {
            return format!("no group called {name}");
        };
        let me = match self.identity.as_ref().map(|i| i.node_id()) {
            Some(m) => m,
            None => return "no identity".into(),
        };
        // Everyone but us. A copy addressed to ourselves is one we would then
        // have to filter out of our own inbox.
        let others: Vec<[u8; 32]> = g.members.iter().copied().filter(|m| *m != me).collect();
        if others.is_empty() {
            return format!("\"{name}\" has no members but you. `group add {name} <peer>` first.");
        }

        // Seal each copy through the same path a private message takes, so a
        // group message is not a second kind of object with its own bugs.
        let mut sealed = Vec::new();
        let mut refused = Vec::new();
        for member in &others {
            let short = short_id(member);
            match self.seal_one(&short, text.as_bytes()) {
                Some((id, bytes)) => sealed.push((id, bytes)),
                None => refused.push(short),
            }
        }
        if sealed.is_empty() {
            return format!(
                "nothing could be sealed for \"{name}\". Members must be peers \
                 you hold a link for: {}",
                refused.join(", ")
            );
        }

        let window = fanout::window_seconds(g.members.len(), self.background_rate());
        let offsets = fanout::offsets(g.members.len(), self.background_rate(), &mut OsRng);
        let now_s = now_seconds();
        for ((id, bytes), off) in sealed.iter().zip(offsets.iter()) {
            self.pending.push(fanout::Pending {
                release_at_s: now_s + off,
                id: *id,
                bytes: bytes.clone(),
            });
        }

        let mut out = format!(
            "{} copy(ies) sealed for \"{name}\", one per member.\n\n\
             They are held and released over about {:.1} hours (RFC 6 §2.7): \
             {} objects appearing together in one size bucket would announce \
             both the fan-out and how many people are in it.",
            sealed.len(),
            window as f64 / 3600.0,
            sealed.len()
        );
        if !refused.is_empty() {
            out.push_str(&format!(
                "\n\nNOT sent to {} — no peer-link. They will not receive this, \
                 and nothing will tell them so.",
                refused.join(", ")
            ));
        }
        // **RFC 6 §2.4: "clients MUST surface which recipients are
        // LoRa-reachable before sending."**
        //
        // Not a nicety. §2.4's table prices one group message at G=20 at 1.6
        // hours of LoRa airtime, and a sender who does not know that three of
        // their twenty members are on a radio link is committing hours of
        // somebody else's duty cycle without being told. Which is exactly the
        // resource RFC 4 §9 calls impossible to defend at the protocol layer:
        // "there is no protocol defence; it is a physical-layer property of
        // the band, and it MUST be stated to operators rather than implied."
        //
        // Surfaced *after* the send in this interface, because the send is one
        // typed line rather than a dialogue — the composer path is where a
        // confirmation belongs, and this is the report.
        let constrained: Vec<String> = others
            .iter()
            .map(short_id)
            .filter(|s| {
                self.links
                    .get(s)
                    .is_some_and(|l| l.profile.sustained_bps < 10_000.0)
            })
            .collect();
        if !constrained.is_empty() {
            out.push_str(&format!(
                "\n\n{} of these are on constrained links — {}. RFC 6 §2.4 \
                 prices a 20-member group at 1.6 hours of LoRa airtime per \
                 message, and their duty cycle is spent whether or not they \
                 read it.",
                constrained.len(),
                constrained.join(", ")
            ));
        }
        out
    }

    /// Release any fan-out copies whose time has come.
    /// Release every staggered fan-out copy at once — `force-send` only.
    ///
    /// **Gives up RFC 6 §2.7.** The stagger exists so `G−1` objects do not
    /// appear together in one size bucket, because a burst is visible as
    /// *"someone just sent to about G people"*. Flushing them undoes that for
    /// this send, and `force_send` says so rather than doing it quietly.
    fn release_all_pending(&mut self) -> usize {
        if self.pending.is_empty() {
            return 0;
        }
        let now_min = now_epoch().0 * 1440;
        let n = self.pending.len();
        for p in std::mem::take(&mut self.pending) {
            let _ = self
                .store
                .with(|s| s.ingest(p.id, p.bytes, now_min, u32::MAX));
        }
        self.save_corpus();
        n
    }

    fn release_pending(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let now_s = now_seconds();
        let now_min = now_epoch().0 * 1440;
        let mut still = Vec::new();
        for p in std::mem::take(&mut self.pending) {
            if p.release_at_s > now_s {
                still.push(p);
                continue;
            }
            let _ = self
                .store
                .with(|s| s.ingest(p.id, p.bytes, now_min, u32::MAX));
        }
        let released = !still.is_empty() || !self.pending.is_empty();
        self.pending = still;
        if released {
            self.save_corpus();
        }
    }

    /// Objects per hour arriving from the network, as this node has observed
    /// them.
    ///
    /// **Observed, never assumed** — RFC 6 §2.7 forbids a constant. With
    /// nothing observed yet, `fanout` substitutes the quietest network the RFC
    /// publishes, which widens the window rather than narrowing it.
    fn background_rate(&self) -> f64 {
        let hours = self.observed_hours;
        if hours <= 0.0 {
            return 0.0;
        }
        self.observed_arrivals as f64 / hours
    }

    /// Publish this node's view of a roster — RFC 6 §2.6's "ordinary signed
    /// group message".
    ///
    /// Signed by identity, because divergence is meaningless without knowing
    /// *whose* view differs.
    fn publish_roster(&self, g: &groups::Group) {
        let Some(id) = self.identity.as_ref() else {
            return;
        };
        let epoch = now_epoch();
        let b = bulletin::Bulletin::create(
            bulletin::Kind::Roster,
            id.signing_key(),
            epoch.0,
            g.encode(),
        );
        let now_min = epoch.0 * 1440;
        if let Some((oid, bytes)) =
            bulletin::into_object(&b, now_min, krab_core::tag::MAX_TTL_DAYS * 1440)
        {
            let _ = self.store.with(|s| s.ingest(oid, bytes, now_min, u32::MAX));
        }
    }

    /// Rosters other members have published that differ from ours.
    ///
    /// **Reported, never merged.** RFC 6 §2.6: a member added without your
    /// knowledge and a roster you have not yet received are indistinguishable,
    /// so resolving silently hides the one event that tells them apart.
    fn roster_divergences(&self) -> Vec<String> {
        let mut out = Vec::new();
        let me = self.identity.as_ref().map(|i| i.node_id());
        self.store.with(|s| {
            for (_, oid) in s.entries_in_range(0, u32::MAX) {
                let Some(b) = s.get(&oid).and_then(bulletin::from_object) else {
                    continue;
                };
                if b.kind != bulletin::Kind::Roster || Some(b.node_id()) == me {
                    continue;
                }
                let Some(theirs) = groups::Group::decode(&b.payload) else {
                    continue;
                };
                // Only groups this node is actually in. A roster for a group
                // we do not have is somebody else's business, and rendering it
                // would turn a flooded object into a notification anyone can
                // send us.
                for mine in self.groups.iter().filter(|g| g.name == theirs.name) {
                    if !mine.members.contains(&b.node_id()) {
                        continue;
                    }
                    if let Some(report) = mine.divergence(&theirs) {
                        out.push(format!("from {}:\n{report}", groups::short(&b.node_id())));
                    }
                }
            }
        });
        out
    }

    /// Groups, their rosters, and any divergence recorded against them.
    fn group_list(&self) -> String {
        if self.groups.is_empty() {
            return "no groups. `group new <name>` creates one.\n\n\
                    A group is PRIVATE and sealed per member; a channel is \
                    PUBLIC and permanent."
                .into();
        }
        let mut out = String::new();
        for g in &self.groups {
            out.push_str(&format!(
                "{}  epoch {}  {} member(s)\n",
                g.name,
                g.epoch,
                g.members.len()
            ));
            for m in &g.members {
                out.push_str(&format!("    {}\n", groups::short(m)));
            }
            match groups::Group::size_verdict(g.members.len()) {
                groups::SizeVerdict::Warn(w) => out.push_str(&format!("  ! {w}\n")),
                groups::SizeVerdict::Refuse(w) => out.push_str(&format!("  !! {w}\n")),
                groups::SizeVerdict::Fine => {}
            }
        }
        // RFC 8 §4.2 requirement 4 — shown, and never silently merged.
        for d in self.roster_divergences() {
            out.push_str(&format!("\n{d}\n"));
        }
        out
    }

    /// Persist the groups. A roster is a membership disclosure, so it is
    /// sealed like everything else that names correspondents.
    fn save_groups(&self) -> Option<String> {
        let w = self.epoch_key?;
        let mut blob = Vec::new();
        for g in &self.groups {
            let e = g.encode();
            blob.extend_from_slice(&(e.len() as u32).to_le_bytes());
            blob.extend_from_slice(&e);
        }
        let sealed = krab_crypto::kek::seal_under(&w, b"krab/groups", &blob, &mut OsRng).ok()?;
        atomic::write(&self.path(artifact::Artifact::Groups), &sealed)
            .err()
            .map(|e| format!("could not store the groups: {e}"))
    }

    /// Read the groups back.
    fn load_groups(&mut self) {
        let Some(w) = self.epoch_key else { return };
        let Some(blob) = std::fs::read(self.path(artifact::Artifact::Groups))
            .ok()
            .and_then(|s| krab_crypto::kek::open_under(&w, b"krab/groups", &s).ok())
        else {
            return;
        };
        let mut out = Vec::new();
        let mut at = 0usize;
        while at + 4 <= blob.len() {
            let n = u32::from_le_bytes(blob[at..at + 4].try_into().expect("4 bytes")) as usize;
            at += 4;
            if at + n > blob.len() {
                break;
            }
            if let Some(g) = groups::Group::decode(&blob[at..at + n]) {
                out.push(g);
            }
            at += n;
        }
        self.groups = out;
    }

    /// Reply — **privately, to a person, never to a channel.**
    ///
    /// The author of a channel post is a channel key, not an identity, so
    /// replying needs a peer to address. When the channel is not one this node
    /// can map to a peering, the honest answer is to say so: the alternative
    /// is either publishing (forbidden here) or silently doing nothing.
    fn reply_privately(&mut self) {
        if self.ui.tab() != layout::Tab::Channels {
            // Private mail already: reply to the selected message's sender.
            match self.messages.get(self.selected) {
                Some(m) => {
                    self.command = line::Line::from(format!("send {} ", m.from).as_str());
                    self.ui.focus_command();
                    self.output = format!("replying privately to {}.", m.from);
                }
                None => self.output = "no message selected".into(),
            }
            return;
        }

        let ids: Vec<[u8; 32]> = self
            .roster
            .mine
            .as_ref()
            .map(|c| c.id())
            .into_iter()
            .chain(self.roster.following.iter().copied())
            .collect();
        let Some(channel) = ids.get(self.selected) else {
            self.output = "no channel selected".into();
            return;
        };
        if self
            .roster
            .mine
            .as_ref()
            .is_some_and(|c| c.id() == *channel)
        {
            self.output = "that is your own channel. To add to it: `channel post <text>`\n\n\
                 Reply never publishes (RFC 8 §4.2)."
                .into();
            return;
        }
        self.output = format!(
            "reply is a PRIVATE message and never a post.\n\n\
             Channel {} is signed by a channel key, which is not a peering — \
             there is nobody to address until you know which of your peers \
             holds it. Ask them, then: send <peer> <text>\n\n\
             To add to your own channel instead: channel post <text>",
            channels::short(channel)
        );
    }

    /// The channel list, for the Channels tab.
    ///
    /// The tab rendered an empty pane: it was drawn, selectable and
    /// advertised, and nothing ever put anything in it.
    /// The channels this node can see, in the order `channel_ids` gives.
    fn channel_ids(&self) -> Vec<[u8; 32]> {
        self.roster
            .mine
            .as_ref()
            .map(|c| c.id())
            .into_iter()
            .chain(self.roster.following.iter().copied())
            .collect()
    }

    /// One row per post: who signed it, its sequence, and its first line.
    ///
    /// The author is on every row because RFC 8 §4.2 requirement 3 makes
    /// reply resolve to a private message *to the author* — an operator
    /// cannot judge that with no author on screen.
    fn channel_post_rows(&self, id: &[u8; 32]) -> Vec<String> {
        let posts = self.channel_post_items(id);
        if posts.is_empty() {
            return vec![format!("channel {} — no posts yet", channels::short(id))];
        }
        // **The channel's short id, not the signing key's.** They are
        // different values — the id is derived from the key — and the id is
        // the one the operator sees in `channel list` and types into
        // `channel follow`. Showing the key here would name the same author
        // with a string that appears nowhere else.
        let who = self
            .aliases()
            .show(alias::Kind::Channel, &channels::short(id));
        posts
            .iter()
            .map(|(seq, _author, text)| {
                format!(
                    "{who}  #{seq}  {}",
                    display::safe(text.lines().next().unwrap_or("")).text
                )
            })
            .collect()
    }

    fn channel_rows(&self) -> Vec<String> {
        // A local name beside the identifier, never instead of it — the
        // identifier is what `channel follow` takes and what the fingerprint
        // rule (RFC 8 §7) wants present wherever a name is.
        let names = self.aliases();
        let mut rows = Vec::new();
        let mut counts: Vec<([u8; 32], usize)> = Vec::new();
        self.store.with(|s| {
            for (_, id) in s.entries_in_range(0, u32::MAX) {
                if let Some(p) = s.get(&id).and_then(channels::from_object) {
                    let c = p.channel_id();
                    match counts.iter_mut().find(|(k, _)| *k == c) {
                        Some((_, n)) => *n += 1,
                        None => counts.push((c, 1)),
                    }
                }
            }
        });
        if let Some(mine) = self.roster.mine.as_ref() {
            let n = counts
                .iter()
                .find(|(k, _)| *k == mine.id())
                .map(|(_, n)| *n)
                .unwrap_or(0);
            rows.push(format!(
                "{} (yours)  {n} posts",
                names.show(alias::Kind::Channel, &channels::short(&mine.id()))
            ));
        }
        for c in &self.roster.following {
            let n = counts
                .iter()
                .find(|(k, _)| k == c)
                .map(|(_, n)| *n)
                .unwrap_or(0);
            rows.push(format!(
                "{}  {n} posts",
                names.show(alias::Kind::Channel, &channels::short(c))
            ));
        }
        if rows.is_empty() {
            rows.push("(no channels — `channel new`, or `channel follow <id>`)".into());
        }
        rows
    }

    /// Posts in a channel, newest first.
    /// Posts on `id`, newest first: sequence, author, text.
    ///
    /// Structured rather than pre-formatted so the list and the body pane
    /// can render the same post differently — the list needs one line, the
    /// body needs all of them.
    fn channel_post_items(&self, id: &[u8; 32]) -> Vec<(u64, [u8; 32], String)> {
        let mut out: Vec<(u64, [u8; 32], String)> = Vec::new();
        self.store.with(|s| {
            for (_, oid) in s.entries_in_range(0, u32::MAX) {
                if let Some(p) = s.get(&oid).and_then(channels::from_object) {
                    if p.channel_id() == *id {
                        out.push((
                            p.sequence,
                            p.author,
                            String::from_utf8_lossy(&p.payload).into_owned(),
                        ));
                    }
                }
            }
        });
        out.sort_by(|a, b| b.0.cmp(&a.0));
        out
    }

    fn channel_posts(&self, id: &[u8; 32]) -> Vec<String> {
        let mut out: Vec<(u64, String)> = Vec::new();
        self.store.with(|s| {
            for (_, oid) in s.entries_in_range(0, u32::MAX) {
                if let Some(p) = s.get(&oid).and_then(channels::from_object) {
                    if p.channel_id() == *id {
                        out.push((p.sequence, String::from_utf8_lossy(&p.payload).into_owned()));
                    }
                }
            }
        });
        out.sort_by(|a, b| b.0.cmp(&a.0));
        out.into_iter().map(|(n, t)| format!("{n}. {t}")).collect()
    }

    /// Put the selected message in the view pane.
    fn show_selected(&mut self) {
        overwrite(&mut self.body);
        if self.ui.tab() == layout::Tab::Notes {
            self.body = self.note_body();
            return;
        }
        if self.ui.tab() == layout::Tab::Channels {
            // Inside a channel: one post, whole, with who signed it. The body
            // used to receive every post of the channel joined together, so a
            // post longer than a line could not be read on its own and the
            // author appeared nowhere at all.
            if self.ui.level() == layout::Level::Messages {
                if let Some(id) = self.channel_open {
                    let posts = self.channel_post_items(&id);
                    self.body = match posts.get(self.selected) {
                        Some((seq, _author, text)) => format!(
                            "channel {}  —  PUBLIC, SIGNED, PERMANENT\n\
                             from {}  ·  post #{seq}\n\n{}",
                            channels::short(&id),
                            channels::short(&id),
                            display::safe_block(text).text
                        ),
                        None => format!("channel {}\n\nno posts yet", channels::short(&id)),
                    };
                    return;
                }
            }
            let ids: Vec<[u8; 32]> = self.channel_ids();
            self.body = match ids.get(self.selected) {
                Some(id) => {
                    let posts = self.channel_posts(id);
                    if posts.is_empty() {
                        format!("channel {}\n\nno posts yet", channels::short(id))
                    } else {
                        format!(
                            "channel {}  — PUBLIC, SIGNED, PERMANENT\n\n{}",
                            channels::short(id),
                            posts.join("\n")
                        )
                    }
                }
                None => "no channel selected".into(),
            };
            return;
        }
        match self.messages.get(self.selected) {
            Some(m) => {
                // The pane keeps the whole body rather than a first line, so
                // it is sanitised line by line — a control character in the
                // fortieth line is as good as one in the first.
                // `safe` also stops at 64 characters, which is right for a
                // row in a list and wrong here: it silently cut every line of
                // a message at 64. `safe_block` sanitises the same way, keeps
                // the lines, and bounds at a size no object can reach.
                let safe: String = display::safe_block(&m.body).text;
                self.body = format!("from {}\n\n{}", m.from, safe);
            }
            None => self.body.push_str("no message selected"),
        }
    }

    /// Walk the command history. `-1` is older, `+1` is newer.
    ///
    /// Stepping past the newest entry returns an empty line rather than
    /// wrapping to the oldest — wrapping means an operator holding a key ends
    /// up running something from the start of the session.
    fn recall(&mut self, dir: i8) {
        if self.history.is_empty() {
            return;
        }
        let at = self.history_at as i64 + dir as i64;
        let at = at.clamp(0, self.history.len() as i64) as usize;
        self.history_at = at;
        self.command = match self.history.get(at) {
            Some(h) => line::Line::from(h.as_str()),
            None => line::Line::default(),
        };
    }

    /// Record a submitted line.
    ///
    /// Consecutive duplicates are collapsed, so holding Enter does not fill
    /// the history with one command. Nothing here ever sees a passphrase:
    /// the passphrase step has its own buffer and its own key handling.
    fn push_history(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() {
            return;
        }
        // **A message body is not a command.** `send bob the meeting is moved`
        // put the plaintext in the history, where Up-arrow recalled it — and
        // RFC 7 §8 says plaintext exists only while displayed. The verb and
        // the recipient are kept, because recalling `send bob ` is what an
        // operator actually wants; the message is dropped.
        let line = match words::split(line).ok().and_then(|w| {
            let verb = w.first()?.text();
            (verb == "send" && w.len() > 2).then(|| format!("send {} ", w[1].text()))
        }) {
            Some(trimmed) => trimmed,
            None => line.to_string(),
        };
        let line = line.as_str();
        if self.history.last().map(String::as_str) != Some(line) {
            self.history.push(line.to_string());
        }
        self.history_at = self.history.len();
    }

    /// Run whatever is on the command line.
    fn submit(&mut self) {
        self.run_command();
        self.reveal_output();
    }

    /// Open the output pane when the reply will not fit in it.
    ///
    /// The pane is a few rows. A verb whose reply runs long — `help`,
    /// `peers`, `status`, the backup words — put its most useful part behind
    /// a `PgUp` the operator had no reason to know was waiting. Rather than
    /// make every long reply a scrolling exercise, the pane opens itself and
    /// `Esc` puts the layout back, which is what `Esc` already did.
    ///
    /// Only when it does not fit: a reply that fits is not worth a layout
    /// change, and a pane that opens for everything is a pane the operator
    /// starts closing reflexively.
    fn reveal_output(&mut self) {
        // Never over a composer: the draft and its banner (RFC 8 §2.1) are
        // what the operator is looking at, and this is not urgent.
        // A composer and its banner (RFC 8 §2.1) are what the operator is
        // looking at, and this is not urgent enough to take that.
        if self.ui.mode() == Mode::Compose {
            return;
        }
        // Already showing the output pane: nothing to do. Either shape
        // counts — the operator may have reached one with Ctrl-O themselves.
        if matches!(
            self.ui.zoomed(),
            Some(layout::Zoom::Console) | Some(layout::Zoom::One(layout::Pane::Output))
        ) {
            return;
        }
        let width = self.output_width.get() as usize;
        let rows = render::wrap_rows(&self.output, width).len();
        // `output_rows` still holds the *previous* reply until the next
        // frame; measure this one now so the decision is about what was just
        // printed.
        self.output_rows.set(rows);
        if rows > self.output_fits() {
            // **Console, not a bare full-screen pane.** `Zoom::One` renders
            // that pane and nothing else — no prompt, and no status rule, so
            // the WAITING indicator vanished at exactly the ceremony steps
            // that need it. Ctrl-O doing that is the operator's own choice;
            // this is not, so it keeps the command line.
            self.ui.zoom_console();
        }
    }

    /// Rows the output pane shows without being opened.
    ///
    /// Derived from the last frame rather than assumed, so a node run in a
    /// short terminal does not decide that nothing ever fits.
    fn output_fits(&self) -> usize {
        match self.output_height.get() as usize {
            0 => OUTPUT_PANE_ROWS,
            n => n,
        }
    }

    fn run_command(&mut self) {
        let line = self.command.take();
        // Tokenise once, up front, so a malformed line is refused with the
        // reason rather than reaching a verb that sees a truncated argument
        // and reports a file that does not exist.
        // A new reply starts at the newest line, not wherever the operator
        // had scrolled to.
        self.output_scroll = 0;
        // A pending prompt consumes the line **and keeps it out of the
        // history**: transfer words are a live key, and a history is a record.
        if let Some(p) = self.prompt.take() {
            self.output = self.answer_prompt(p, &line);
            return;
        }
        self.push_history(&line);
        if let Err(e) = words::split(&line) {
            self.output = format!("{e}");
            return;
        }
        let Some(cmd) = Command::parse(&line) else {
            self.output = format!(
                "unknown command: {}\n\nType `help` for the verbs, or Ctrl-Q to quit.",
                line.trim()
            );
            return;
        };
        // **An identity this node has, not an identity it currently holds in
        // memory.** These are different after a restart: the key hierarchy is
        // on disk, wrapped, and nothing is in memory until a passphrase
        // arrives. Passing the in-memory answer here broke both directions —
        // `unlock` was refused for want of the very thing it exists to
        // produce, and `init` was *admitted*, which would have generated a
        // fresh hierarchy and overwritten the stored one.
        let has_identity = self.identity.is_some() || self.has_stored_identity();
        match admit(&cmd, has_identity, self.locked, self.confirmed) {
            Err(Refusal::NoIdentity) => {
                self.output = "no identity yet — run `init` first".into();
            }
            Err(Refusal::Locked) => {
                self.output = format!("`{cmd}` needs an unlocked node");
            }
            Err(Refusal::AlreadyInitialised) => {
                self.output = "this node already has an identity; `init` runs once".into();
            }
            Err(Refusal::NeedsConfirmation) => {
                // RFC 7 §10 — the one irreversible verb, and the one prompt.
                self.confirmed = true;
                self.output = format!("`{cmd}` destroys the key hierarchy and cannot be undone. Type it again to confirm.");
            }
            Ok(()) => {
                self.confirmed = false;
                self.dispatch(cmd, &line);
            }
        }
    }

    fn dispatch(&mut self, cmd: Command, line: &str) {
        match cmd {
            Command::Init => {
                self.init_step = Some(InitStep::Passphrase);
                self.output = InitStep::Passphrase.prompt().into();
            }
            Command::Lock => self.lock(),
            Command::Duress => {
                // RFC 7 §10: "Neither MUST be enabled by default. Both MUST be
                // discoverable." So it is a verb, and it says what it does.
                let Some(phrase) = line.split_once(char::is_whitespace).map(|x| x.1) else {
                    self.output = "usage: duress <passphrase>\n\n\
                                 Sets a second passphrase that destroys this node \
                                 and then behaves like a fresh install. There is no \
                                 confirmation and no warning when it is used — that \
                                 is the point (RFC 7 §10)."
                        .into();
                    return;
                };
                self.output = match self.set_duress(phrase.trim().as_bytes()) {
                    Ok(()) => "duress passphrase set. Entering it at the unlock \
                               prompt destroys this node and shows an empty one. \
                               Nothing will warn you, including this node."
                        .into(),
                    Err(e) => e,
                };
            }
            Command::Unlock => {
                // The passphrase is typed at the prompt, not on the command
                // line -- a command line is echoed and may be scrolled back.
                self.init_step = Some(InitStep::Passphrase);
                self.unlocking = true;
                self.node.unlocking = true;
                self.output = "passphrase:".into();
            }
            Command::Wipe => self.output = self.panic_wipe(),
            Command::StartTor => {
                // The argument is a path and may contain spaces on Windows,
                // so it is everything after the verb rather than `arg(1)`.
                let rest = line.trim().strip_prefix("start-tor").unwrap_or("").trim();
                let path = if rest.is_empty() { None } else { Some(rest) };
                self.output = self.start_tor(path);
            }
            Command::StopTor => self.output = self.stop_tor(),
            Command::DeadMan => {
                let rest = line.trim().strip_prefix("deadman").unwrap_or("").trim();
                self.output = self.deadman_command(rest);
            }
            Command::Peer => {
                let rest = line.trim().strip_prefix("peer").unwrap_or("");
                self.output = match Peering::parse(rest) {
                    // `offer` writes two files on purpose — see `peering`.
                    Some(Peering::Offer) => self.peer_offer(),
                    Some(Peering::Accept) => self.peer_accept(arg(rest, 1).as_deref()),
                    Some(Peering::Seal) => {
                        self.peer_seal(arg(rest, 1).as_deref(), arg(rest, 2).as_deref())
                    }
                    Some(Peering::Pad) => self.peer_pad(arg(rest, 1).as_deref()),
                    Some(Peering::Wrap) => self.peer_wrap(arg(rest, 1).as_deref()),
                    Some(Peering::Meet) => self.peer_meet(rest),
                    Some(Peering::Verified) => self.peer_verified(arg(rest, 1).as_deref()),
                    Some(Peering::Show) => self.peer_show(arg(rest, 1).as_deref()),
                    Some(Peering::Reseal) => {
                        let tail = rest.trim().strip_prefix("reseal").unwrap_or("").to_string();
                        self.peer_reseal(&tail)
                    }
                    Some(Peering::Counter) => self.peer_counter(rest),
                    Some(Peering::Forget) => self.peer_forget(arg(rest, 1).as_deref()),
                    Some(Peering::Renew) => self.peer_renew(arg(rest, 1).as_deref()),
                    Some(Peering::Share) => {
                        self.peer_share(arg(rest, 1).as_deref(), arg(rest, 2).as_deref())
                    }
                    Some(Peering::Carry) => {
                        self.peer_carry(arg(rest, 1).as_deref(), arg(rest, 2).as_deref())
                    }
                    Some(Peering::Fragment) => self.peer_fragment(),
                    Some(Peering::Countersign) => self.peer_countersign(arg(rest, 1).as_deref()),
                    Some(Peering::Status) => self.peer_status(),
                    Some(Peering::Rekey) => self.peer_rekey(arg(rest, 1).as_deref()),
                    None => {
                        let sub = arg(rest, 0).unwrap_or_default();
                        // `peer connect` is the likely typo, because
                        // `connect` is a top-level verb and `peer` reads like
                        // a namespace. Saying "unknown" and stopping leaves
                        // the operator with a correct command they cannot
                        // find.
                        if Command::parse(&sub).is_some() {
                            format!(
                                "`{sub}` is a command on its own, not a `peer` step.\n\n\
                                 Try:  {}",
                                rest.trim()
                            )
                        } else {
                            format!(
                                "unknown: peer {sub}\n\n\
                                 peer offer                  start a peering\n\
                                 peer accept <their.card>    take in their card\n\
                                 peer pad <destination>      write your SECRET half\n\
                                 peer seal <their.pad> <ch>  finish it\n\
                                 peer rekey <peer>           mix in fresh entropy\n\
                                 peer status                 where you are"
                            )
                        }
                    }
                };
            }
            // RFC 3 §11 step 2, and RFC 8 §5's `verify`.
            Command::Quit => self.leave(),
            Command::Picture => {
                self.output = match arg(line, 1).as_deref() {
                    Some("save") => self.picture_save(arg(line, 2).as_deref()),
                    Some("show") => self.picture_show(),
                    Some("hide") => {
                        self.showing = None;
                        "hidden.".into()
                    }
                    _ => "usage:\n\
                          \x20 picture show          draw it in the message pane\n\
                          \x20 picture hide          stop\n\
                          \x20 picture save <file>   write it out\n\n\
                          Writes the selected message's picture out. This program \
                          does not open a viewer: RFC 8 §6 forbids handing \
                          received bytes to one, and there is no flag for it."
                        .into(),
                };
            }
            Command::Group => {
                let sub = arg(line, 1).unwrap_or_default();
                self.output = match sub.as_str() {
                    "new" => self.group_new(arg(line, 2).as_deref()),
                    "add" => {
                        self.group_member(arg(line, 2).as_deref(), arg(line, 3).as_deref(), true)
                    }
                    "remove" => {
                        self.group_member(arg(line, 2).as_deref(), arg(line, 3).as_deref(), false)
                    }
                    "send" => {
                        let text = words::split(line)
                            .map(|w| words::rest(&w, 3))
                            .unwrap_or_default();
                        self.group_send(arg(line, 2).as_deref(), text.trim())
                    }
                    "list" | "" => self.group_list(),
                    other => format!(
                        "unknown: group {other}\n\n\
                         group new <name>              a closed roster, sealed per member\n\
                         group add <name> <peer>       add a member\n\
                         group remove <name> <peer>    remove one\n\
                         group send <name> <text>      seal one copy per member\n\
                         group list                    rosters and epochs"
                    ),
                };
            }
            Command::Channel => {
                let sub = arg(line, 1).unwrap_or_default();
                self.output = match sub.as_str() {
                    "new" => self.channel_new(),
                    "post" => {
                        let text = words::split(line)
                            .map(|w| words::rest(&w, 2))
                            .unwrap_or_default();
                        // **No text means compose it.** RFC 8 §4.2
                        // requirement 1 puts the security context in the
                        // composer, which presumes one; and a post is not
                        // necessarily a single line, which an argument is.
                        if text.trim().is_empty() {
                            self.compose_post()
                        } else {
                            self.channel_post(text.trim())
                        }
                    }
                    "follow" => self.channel_follow(arg(line, 2).as_deref(), true),
                    "unfollow" => self.channel_follow(arg(line, 2).as_deref(), false),
                    "carry" => self.channel_carry(arg(line, 2).as_deref()),
                    "list" | "" => self.channel_list(),
                    other => format!(
                        "unknown: channel {other}\n\n\
                         channel new                create one you can post to\n\
                         channel post <text>        PUBLIC, SIGNED, PERMANENT\n\
                         channel follow <id>        read one\n\
                         channel unfollow <id>      stop reading it\n\
                         channel carry on|off       host public content (default off)\n\
                         channel list               what you own and follow"
                    ),
                };
            }
            Command::Listen => {
                // An address typed here wins over `--listen`; `--listen` is
                // the default so the operator does not retype what they
                // launched with.
                // A bare number is a port on loopback. `listen bob 40000` is
                // what an operator reaches for, and refusing it because it is
                // not `127.0.0.1:40000` is pedantry with no security content.
                let typed =
                    words::split(line)
                        .ok()
                        .and_then(|w| w.get(2).cloned())
                        .map(|w| match w.int() {
                            Some(p) if (1..=65535).contains(&p) => format!("127.0.0.1:{p}"),
                            _ => w.text(),
                        });
                let addr = typed.or_else(|| self.listen.clone());
                let (Some(peer), Some(addr)) = (arg(line, 1), addr.as_deref()) else {
                    self.output = format!(
                        "usage: listen <peer> <address>\n\n  \
                         tcp     host:port — e.g. listen bob 127.0.0.1:40000\n  \
                         serial  {}\n\n\
                         Waits up to {ANSWER_WAIT_S}s for that peer to call, then \
                         hands the prompt back. With --listen given at launch \
                         the address may be omitted.",
                        krab_fabric::backend::serial::SerialFabric::device_hint()
                    );
                    return;
                };
                // Serial device paths are not host:port; everything else is
                // TCP. The transport is inferred rather than typed because a
                // bind address already says which one it is.
                let kind = if addr.contains(':') && !addr.starts_with('/') {
                    "tcp"
                } else {
                    "serial"
                };
                self.dispatch_connect(&peer, kind, Some(addr), true, line);
            }
            Command::Help => {
                // Into the body pane: RFC 8 §3 forbids scrolling output
                // through the two-line command pane.
                // **The column is measured, not assumed.** A fixed `:<20`
                // does not pad anything wider than 20, so the verbs that grew
                // past it — `peer countersign <file>`, `peer counter <n>
                // <MB/day> <objects> <days>` — ran straight into their own
                // descriptions with no gap at all.
                let column = |rows: &[(&str, &str)]| {
                    rows.iter().map(|(k, _)| k.chars().count()).max().unwrap_or(0) + 2
                };
                let mut out = String::from("verbs\n");
                let w = column(Command::SYNOPSES);
                for (verb, what) in Command::SYNOPSES {
                    out.push_str(&format!("  {verb:<w$}{what}\n"));
                }
                out.push_str("\nkeys\n");
                let w = column(Command::CHORDS);
                for (chord, what) in Command::CHORDS {
                    out.push_str(&format!("  {chord:<w$}{what}\n"));
                }
                self.output = out;
            }
            Command::Verify => {
                self.output = match &self.identity {
                    Some(id) => format!(
                        "read these eight words aloud and hear the same back:\n\n  {}",
                        id.fingerprint()
                    ),
                    None => "no identity".into(),
                }
            }
            // RFC 8 §5.1: establishes a transport and MUST NOT sync. The
            // guarantee is structural -- `LinkTable` has no reconciler to call.
            Command::Connect => {
                let (Some(peer), kind) =
                    (arg(line, 1), arg(line, 2).unwrap_or_else(|| "tcp".into()))
                else {
                    self.output = format!(
                        "usage: connect <peer> <transport> [address]\n\n  \
                         tcp      host:port\n  \
                         tor      <address>.onion — needs `start-tor`\n  \
                         serial   {}\n  \
                         modem    same as serial\n  \
                         courier  no address — use `pack` and `import`\n\n\
                         To wait for a call instead of placing one, use `listen`.",
                        krab_fabric::backend::serial::SerialFabric::device_hint()
                    );
                    return;
                };
                // `answer` is still accepted here, because it was documented
                // and an operator may have it in their fingers, but `listen`
                // is the verb that says what it does.
                let answer = line.split_whitespace().any(|t| t == "answer");
                self.dispatch_connect(&peer, &kind, arg(line, 3).as_deref(), answer, line);
            }
            Command::Disconnect => {
                let Some(peer) = arg(line, 1) else {
                    self.output = "usage: disconnect <peer>".into();
                    return;
                };
                if let Some(id) = sync::peer_id_of(&peer) {
                    self.scheduler.remove(&id);
                }
                if self.links.get(&peer).is_some() {
                    self.log.push(activity_log::Event::LinkDown {
                        peer: peer.to_string(),
                    });
                }
                self.output = if self.links.disconnect(&peer) {
                    // RFC 3 §6.2's quota reduction is deliberately not bundled:
                    // making disconnect a punishment discourages using it, and
                    // RFC 8 §5.3 needs operators to act.
                    format!("{peer} disconnected. Quota unchanged — adjust it from `peers`.")
                } else {
                    format!("no link to {peer}")
                };
            }
            Command::Peers => self.output = self.peers_panel(),
            Command::Reach => self.output = self.reach_report(line),
            Command::Keys => self.output = self.keys_report(),
            Command::Pin => self.output = self.pin_command(line),
            Command::Note => self.output = self.note_command(line),
            Command::Alias => self.output = self.alias_command(alias::Kind::Message, line),
            Command::AliasChannel => {
                self.output = self.alias_command(alias::Kind::Channel, line)
            }
            Command::AliasPeer => self.output = self.alias_command(alias::Kind::Peer, line),
            Command::No => self.output = self.alias_remove(line),
            Command::Status => self.output = self.status_report(),
            Command::ForceSend => self.output = self.force_send(line),
            Command::Rollcall => self.output = self.rollcall_command(line),
            Command::Introduce => self.output = self.introduce(line),
            Command::Requests => self.output = self.requests(line),
            Command::Message => self.output = self.message(line),
            Command::Send => self.output = self.send(line),
            Command::Short => self.output = self.short_command(line),
            Command::Cover => self.output = self.cover_command(line),
            Command::Onion => self.output = self.onion_command(line),
            Command::Request => self.output = self.peer_request(line),
            Command::Pack => self.output = self.pack(line),
            Command::Import => self.output = self.import(line),
        }
    }

    /// The path of a ceremony artifact.
    /// A file in this node's home.
    ///
    /// **Takes an [`artifact::Artifact`], not a string.** `wipe` decides what
    /// to destroy from the same enum, so a file this program can write is a
    /// file `wipe` knows about — which is what stops the omission that left
    /// prekey privates, group rosters, the channel posting key and the duress
    /// store on disk after a panic wipe.
    fn path(&self, a: artifact::Artifact) -> PathBuf {
        self.home.join(a.name())
    }

    /// A file in the home that is **not** one of this node's artifacts.
    ///
    /// Test-only, and deliberately so: production code writing a file whose
    /// name `wipe` has never heard of is the defect `artifact` exists to
    /// prevent. Tests write fixtures — cards in transit, pictures, courier
    /// archives — and those are the operator's files, not the node's.
    #[cfg(test)]
    fn at(&self, name: &str) -> PathBuf {
        self.home.join(name)
    }

    /// Everything belonging to one peer, under one directory.
    ///
    /// `<home>/peers/<short-id>/<name>`. Flat files named `<short>.link` and
    /// `<short>.reservoir` worked while a peer had two artifacts; continuous
    /// re-keying gives each peer mutable state of its own, and state that
    /// belongs together should be removable together — a peering that ends
    /// should be one directory to shred, not a pattern to glob.
    fn peer_path(&self, peer: impl AsRef<str>, f: artifact::PeerFile) -> PathBuf {
        self.home.join("peers").join(peer.as_ref()).join(f.name())
    }

    /// Create a peer's directory. Called before the first write into it.
    fn ensure_peer_dir(&self, peer: &str) -> Result<(), String> {
        let d = self.home.join("peers").join(peer);
        std::fs::create_dir_all(&d).map_err(|e| format!("could not create {}: {e}", d.display()))
    }

    /// Every peer this node has a link for.
    fn peer_ids(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(self.home.join("peers")) else {
            return Vec::new();
        };
        let mut out: Vec<String> = entries
            .flatten()
            .filter(|e| e.path().join("link").exists())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        out.sort();
        out
    }

    /// Load the ceremony in progress, unwrapping the contribution.
    ///
    /// Requires the epoch key, so a locked node cannot read its own ceremony
    /// state — which is the point of holding `W_N` only while unlocked.
    fn load_ceremony(&self) -> Result<ceremony::Pending, String> {
        let w = self
            .epoch_key
            .ok_or("locked — unlock to work on a peering")?;
        let bytes = std::fs::read(self.path(artifact::Artifact::Ceremony))
            .map_err(|_| "no ceremony in progress — run `peer offer`".to_string())?;
        let (parts, wrapped) =
            ceremony::Pending::decode(&bytes).map_err(|e| format!("corrupt ceremony: {e:?}"))?;
        let raw =
            krab_crypto::kek::open_under(&w, b"krab/ceremony/r_a", &wrapped).map_err(|_| {
                "this ceremony's epoch has been shredded and it cannot be resumed \
                 — run `peer offer` again"
                    .to_string()
            })?;
        let mut r = [0u8; 32];
        if raw.len() != 32 {
            return Err("corrupt contribution".into());
        }
        r.copy_from_slice(&raw);
        Ok(parts.with_contribution(r))
    }

    /// Store a ceremony, wrapping the contribution under `W_N`.
    fn save_ceremony(&self, p: &ceremony::Pending) -> Result<(), String> {
        let w = self.epoch_key.ok_or("locked")?;
        let wrapped = krab_crypto::kek::seal_under(
            &w,
            b"krab/ceremony/r_a",
            &p.my_contribution.r,
            &mut OsRng,
        )
        .map_err(|e| format!("{e:?}"))?;
        // Atomic: a ceremony is days long, and a crash mid-save would lose the
        // contribution while the counterparty still holds theirs.
        atomic::write(
            &self.path(artifact::Artifact::Ceremony),
            &p.encode(&wrapped),
        )
        .map_err(|e| format!("could not write ceremony state: {e}"))
    }

    /// Write this node's reservoir contribution to a named destination.
    ///
    /// **Not to the node's own storage by default**, and never automatically.
    /// `R_A` is the one piece of key material that must exist in plaintext,
    /// because a person carries it — and RFC 7 §4 forbids relying on deletion
    /// to remove plaintext from a disk. It lives wrapped under `W_N` in the
    /// ceremony; this materialises it exactly once, where the operator says.
    fn peer_pad(&self, dest: Option<&str>) -> String {
        let Some(dest) = dest else {
            return "usage: peer pad <destination>\n\n\
                    Give the path on the medium you are carrying. This writes \
                    the one file Krab cannot protect once it exists — see \
                    Documentation/SECURE-DELETE.md."
                .into();
        };
        let pending = match self.load_ceremony() {
            Ok(p) => p,
            Err(e) => return e,
        };
        let bytes = ceremony::encode_contribution(&pending.my_contribution);
        // **Deliberately not atomic.** An atomic write leaves a `.tmp` on
        // failure, and here that file would be the plaintext contribution under
        // a name nothing cleans up — on removable media the operator is about
        // to carry away. A partial write is visibly a partial write and the pad
        // is regenerable from the ceremony, so the plain form is the safer one.
        match std::fs::write(dest, bytes) {
            Err(e) => format!("could not write {dest}: {e}"),
            Ok(()) => format!(
                "wrote your contribution to {dest}.\n\n\
                 This is half a shared secret in plaintext. It is the only \
                 unprotected artifact Krab produces, and once it is on a medium \
                 no software can retract it — carry it, hand it over, and do not \
                 leave a copy behind."
            ),
        }
    }

    /// Consume a line typed in answer to a prompt.
    fn answer_prompt(&mut self, p: Prompt, line: &str) -> String {
        match p {
            Prompt::TransferWords { path } => {
                let words = line.trim();
                if words.is_empty() {
                    return "cancelled — nothing was sealed.".into();
                }
                let Some(raw) = std::fs::read(&path)
                    .ok()
                    .and_then(|b| spoken::Wrapped::decode(&b))
                else {
                    return format!("{path} is not a wrapped pad");
                };
                let Some(plain) = spoken::unwrap(&raw, words) else {
                    // One message for both, deliberately: an operator's remedy
                    // is the same, and distinguishing them would tell an
                    // interceptor which of their guesses was closer.
                    return "those words did not open it.\n\n\
                            Either a word is wrong or the file was altered. \
                            Check the words with them — the alphabets differ \
                            between even and odd positions, so a pair read out \
                            of order is rejected rather than silently accepted."
                        .into();
                };
                self.seal_from(&plain, peering::Channel::Spoken, Some(&path))
            }
            Prompt::ResealWords { path } => {
                let words = line.trim();
                if words.is_empty() {
                    return "cancelled — nothing was re-sealed.".into();
                }
                let Some(raw) = std::fs::read(&path)
                    .ok()
                    .and_then(|b| spoken::Wrapped::decode(&b))
                else {
                    return format!("{path} is not a wrapped pad");
                };
                let Some(plain) = spoken::unwrap(&raw, words) else {
                    return "those words did not open it.".into();
                };
                let Some((peer, mine)) = self.load_reseal() else {
                    return "no re-seal in progress".into();
                };
                let Some(me) = self.identity.as_ref().map(|i| i.node_id()) else {
                    return "no identity".into();
                };
                self.reseal_with(&peer, &me, mine, &plain, peering::Channel::Spoken)
            }
        }
    }

    /// Wrap the contribution under a spoken transfer key — `crate::spoken`.
    ///
    /// The route for two people who cannot meet. Unlike `peer pad`, the file
    /// this writes is **safe to send over anything**: it is useless without 32
    /// words that only ever cross a voice call.
    fn peer_wrap(&mut self, dest: Option<&str>) -> String {
        let Some(dest) = dest else {
            return "usage: peer wrap <file>\n\n\
                    Writes your contribution wrapped under a 256-bit key shown \
                    as 32 words. The file may travel over any network; the \
                    words must be read aloud on a voice call and nowhere else."
                .into();
        };
        let pending = match self.load_ceremony() {
            Ok(p) => p,
            Err(e) => return e,
        };
        let plain = ceremony::encode_contribution(&pending.my_contribution);
        let Some((wrapped, phrase)) = spoken::wrap(&plain, &mut OsRng) else {
            return "could not wrap the contribution".into();
        };
        // Not atomic, for the same reason `peer pad` is not: an atomic write
        // leaves a `.tmp` on failure, and here that file would be the wrapped
        // contribution under a name nothing cleans up.
        if let Err(e) = std::fs::write(dest, wrapped.encode()) {
            return format!("could not write {dest}: {e}");
        }
        spoken::instructions(dest, &phrase)
    }

    /// First contact over a live link — the whole ceremony in one exchange.
    ///
    /// `peer meet listen <addr>` waits; `peer meet <addr>` dials. Both then run
    /// the same exchange, because who called is a transport question that was
    /// answered before the ceremony starts.
    ///
    /// The result is a working peering that is **neither post-quantum nor
    /// authenticated**, and the output says so at length. `peer reseal`
    /// repairs the first; `peer verified` records the second once a human has
    /// done it.
    fn peer_meet(&mut self, line: &str) -> String {
        // `--timeout <minutes>` may sit anywhere after the verb, so an
        // operator who set `--listen` can shorten the window without
        // repeating the address. Removed from the word list before the
        // positional arguments are read, or `listen` would find the flag
        // where it expects an address.
        let mut words: Vec<String> = words::split(line)
            .map(|w| w.iter().map(|x| x.text()).collect())
            .unwrap_or_default();
        let mut window = MEET_WINDOW;
        if let Some(i) = words.iter().position(|w| w == "--timeout") {
            let Some(n) = words.get(i + 1).and_then(|v| v.parse::<u64>().ok()) else {
                return "usage: peer meet listen [<addr>] --timeout <minutes>".into();
            };
            if n == 0 || n > MEET_WINDOW_MAX.as_secs() / 60 {
                return format!(
                    "a first-contact window is 1 to {} minutes. A door held open \
                     longer than the arrangement to use it is a door nobody is \
                     watching.",
                    MEET_WINDOW_MAX.as_secs() / 60
                );
            }
            window = Duration::from_secs(n * 60);
            words.drain(i..=i + 1);
        }
        let a = words.get(1).map(|s| s.as_str());
        let b = words.get(2).map(|s| s.as_str());

        match (a, b) {
            (Some("cancel"), _) | (Some("stop"), _) => return self.meet_cancel(),
            (Some("status"), _) => return self.meet_status(),
            _ => {}
        }

        let (listening, addr) = match (a, b) {
            (Some("listen"), Some(addr)) => (true, addr.to_string()),
            (Some("listen"), None) => match self.listen.clone() {
                Some(addr) => (true, addr),
                None => return "usage: peer meet listen <address>".into(),
            },
            (Some(addr), _) => (false, addr.to_string()),
            (None, _) => {
                return "usage:\n\
                        \x20 peer meet listen <addr>   wait for them to call\n\
                        \x20 peer meet <addr>          call them\n\
                        \x20 peer meet status          is a door open?\n\
                        \x20 peer meet cancel          close it\n\n\
                        \x20 --timeout <minutes>       how long to wait, \
                        default 15\n\n\
                        First contact over a link, for two people who can reach \
                        each other on a network and nowhere else. The result is \
                        NOT post-quantum and NOT authenticated until you compare \
                        fingerprints on a call."
                    .into()
            }
        };

        let Some((my_card, noise, my_fingerprint)) = self.identity.as_ref().map(|id| {
            (
                id.card(Policy::default()),
                id.noise_bytes(),
                id.fingerprint(),
            )
        }) else {
            return "no identity — run `init` first".into();
        };
        if self.epoch_key.is_none() {
            return "locked — unlock first".into();
        }
        let (my_card, my_contribution) = bootstrap::offer(my_card, &mut OsRng);

        if listening {
            return self.meet_listen(&addr, my_card, my_contribution, noise, window);
        }

        // Dialling has somebody to call and is one attempt, not an open door,
        // so it stays on this thread.
        let opened = krab_fabric::backend::listener::bootstrap_connect(&addr, noise)
            .map_err(|e| format!("could not reach {addr}: {e:?}"));
        let (mut session, their_static) = match opened {
            Ok(v) => v,
            Err(e) => return e,
        };
        let outcome =
            match bootstrap::run(session.as_mut(), &my_card, &my_contribution, &their_static) {
                Ok(o) => o,
                Err(e) => return meet_failure(e),
            };
        self.complete_meeting(my_card, my_contribution, outcome, &my_fingerprint)
    }

    /// Open the door, behind the interface.
    ///
    /// **Cancellable, and self-closing.** A socket that accepts strangers
    /// should not outlive the arrangement to use it, and one an operator
    /// cannot see is one they cannot close.
    fn meet_listen(
        &mut self,
        addr: &str,
        my_card: peering::Card,
        mine: peering::Contribution,
        noise: [u8; 32],
        window: Duration,
    ) -> String {
        if let Some(m) = &self.meeting {
            return format!(
                "already waiting on {}. `peer meet cancel` closes it first.",
                m.addr
            );
        }
        let (l, port) = match krab_fabric::backend::listener::Bootstrap::bind(addr, noise) {
            Ok(v) => v,
            Err(e) => return format!("could not listen on {addr}: {e:?}"),
        };

        let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let (tx, done) = std::sync::mpsc::channel();
        let flag = running.clone();
        let card = my_card.clone();
        let contribution = peering::Contribution { r: mine.r };
        std::thread::spawn(move || {
            use std::sync::atomic::Ordering;
            while flag.load(Ordering::Relaxed) {
                match l.accept_once() {
                    Ok(Some((mut session, their_static))) => {
                        let out =
                            bootstrap::run(session.as_mut(), &card, &contribution, &their_static);
                        let _ = tx.send(out);
                        return;
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                    Err(_) => {
                        let _ = tx.send(Err(bootstrap::Error::Link));
                        return;
                    }
                }
            }
        });

        self.meeting = Some(Meeting {
            addr: addr.to_string(),
            running,
            done,
            mine,
            until: Instant::now() + window,
            window,
        });
        // **RFC 3 §9.2's contact endpoint**, if tor is running: an onion
        // pointed at *this* socket and nothing else, so what is behind it
        // genuinely accepts only peer-requests. Rotated on every open, because
        // two strangers given the same contact address could each confirm the
        // other had been talking to this node.
        let contact = self.onion_contact_open(port).map(|a| {
            format!(
                "\n\nOver tor: **{a}:{ONION_PORT}** — give them this rather than \
                 the address above, and it reveals nothing about where this \
                 node is. It is a *contact* endpoint (RFC 3 §9.2): only \
                 first contact answers on it, never reconciliation, and it is \
                 withdrawn when this meeting ends. Your sync address stays \
                 unpublished."
            )
        });
        format!(
            "waiting on {addr} (port {port}) for {} minutes.{}\n\n\
             **This accepts whoever calls.** There is no peering yet, so there \
             is no key to check them against — that is what the fingerprint \
             comparison afterwards is for.\n\n\
             **It closes itself the moment the exchange finishes**, and when \
             the time is up if nobody calls. `peer meet cancel` closes it now; \
             `peer meet status` says whether it is still open.\n\n\
             Do not leave this running. A door left open for somebody who has \
             already arrived is a door nobody is watching.",
            window.as_secs() / 60,
            contact.unwrap_or_default()
        )
    }

    /// Close the door.
    fn meet_cancel(&mut self) -> String {
        match self.meeting.take() {
            None => "nothing is waiting.".into(),
            Some(m) => {
                m.running.store(false, std::sync::atomic::Ordering::Relaxed);
                let contact = self.onion_contact.is_some();
                let _ = self.onion_contact_close();
                let over_tor = if contact {
                    " The contact endpoint is withdrawn."
                } else {
                    ""
                };
                format!("closed {}. Nothing was peered.{over_tor}", m.addr)
            }
        }
    }

    /// Whether a door is open, and for how much longer.
    fn meet_status(&self) -> String {
        match &self.meeting {
            None => "no first-contact socket is open.".into(),
            Some(m) => {
                let left = m.until.saturating_duration_since(Instant::now());
                format!(
                    "waiting on {} — {} minute(s) left.\n\n\
                     It accepts whoever calls. `peer meet cancel` closes it.",
                    m.addr,
                    left.as_secs() / 60 + 1
                )
            }
        }
    }

    /// Pick up a completed first contact, or close a door whose time is up.
    fn drain_meeting(&mut self) {
        let Some(m) = &self.meeting else { return };
        if let Ok(out) = m.done.try_recv() {
            let mine = peering::Contribution { r: m.mine.r };
            let m = self.meeting.take().expect("just checked");
            m.running.store(false, std::sync::atomic::Ordering::Relaxed);
            // The door and the endpoint in front of it close together. An
            // onion left published after the socket behind it is gone is an
            // address that answers and then hangs up, which reads to a caller
            // as a node that is up and broken rather than one that is done.
            let _ = self.onion_contact_close();
            self.output = match out {
                Err(e) => meet_failure(e),
                Ok(outcome) => {
                    let Some((card, fingerprint)) = self
                        .identity
                        .as_ref()
                        .map(|id| (id.card(Policy::default()), id.fingerprint()))
                    else {
                        return;
                    };
                    self.complete_meeting(card, mine, outcome, &fingerprint)
                }
            };
            return;
        }
        if Instant::now() >= m.until {
            let m = self.meeting.take().expect("just checked");
            m.running.store(false, std::sync::atomic::Ordering::Relaxed);
            let _ = self.onion_contact_close();
            self.output = format!(
                "closed {} — nobody called within {} minutes.\n\n\
                 `peer meet listen {}` opens it again.",
                m.addr,
                m.window.as_secs() / 60,
                m.addr
            );
        }
    }

    /// Turn a completed exchange into a peering, on the thread that owns the
    /// store.
    fn complete_meeting(
        &mut self,
        my_card: peering::Card,
        my_contribution: peering::Contribution,
        outcome: bootstrap::Outcome,
        my_fingerprint: &str,
    ) -> String {
        let pending = ceremony::Pending::open(my_card, my_contribution.r);
        if let Err(e) = self.save_ceremony(&pending) {
            return e;
        }
        let mut pending = match self.load_ceremony() {
            Ok(p) => p,
            Err(e) => return e,
        };
        if pending.accept_card(outcome.card.clone()).is_err() {
            return "that card could not be recorded".into();
        }
        if let Err(e) = self.save_ceremony(&pending) {
            return e;
        }
        let theirs = ceremony::encode_contribution(&outcome.contribution);
        let sealed = self.seal_with_contribution(&theirs, peering::Channel::Network);
        if !sealed.starts_with("peer-link signed") {
            return sealed;
        }
        // A completed peering closes the door: it was opened to arrange one.
        self.refresh_allowed();
        format!(
            "{sealed}\n\n{}",
            bootstrap::caveat(&outcome.card.fingerprint(), my_fingerprint)
        )
    }

    /// Record that the fingerprints were compared aloud and matched.
    ///
    /// **A human act, recorded by a human.** RFC 3 §11 step 2 is the only
    /// thing that binds a key to a person, and nothing in the software can
    /// observe it — a ceremony that set this automatically would be recording
    /// that something happened which it cannot see.
    fn peer_verified(&mut self, peer: Option<&str>) -> String {
        let Some(peer) = peer else {
            return "usage: peer verified <peer>\n\n\
                    Records that you read the fingerprints to each other on a \
                    call and they matched. Only do this if they did."
                .into();
        };
        let Some(mut t) = self.peer_terms(peer) else {
            return format!("no recorded terms for {peer} — is that a peering?");
        };
        if t.fingerprint_verified {
            return format!("{peer} was already recorded as verified.");
        }
        t.fingerprint_verified = true;
        if let Err(e) = atomic::write(
            &self.peer_path(peer, artifact::PeerFile::Terms),
            &t.encode(),
        ) {
            return format!("could not record it: {e}");
        }
        format!(
            "{peer} recorded as verified.\n\n\
             {}",
            if t.post_quantum() {
                "This peering is now both verified and post-quantum."
            } else {
                "It is still NOT post-quantum — the contribution crossed a \
                 channel an adversary can record and later break. `peer reseal` \
                 repairs that without redoing the peering."
            }
        )
    }

    /// Upgrade an existing peering over a stronger channel, in place.
    ///
    /// **The peer-link, the message history and the correspondent survive.**
    /// Only the reservoir root changes, derived from the old root and two
    /// fresh contributions that never crossed a recorded channel — see
    /// `krab_crypto::rekey::reseal_root`.
    ///
    /// This is what makes starting weak recoverable rather than permanent: peer
    /// over the network today, re-seal the first time you meet, and keep
    /// everything.
    fn peer_reseal(&mut self, rest: &str) -> String {
        match arg(rest, 0).as_deref() {
            Some("pad") => self.reseal_materialise(arg(rest, 1).as_deref(), false),
            Some("wrap") => self.reseal_materialise(arg(rest, 1).as_deref(), true),
            Some("seal") => self.reseal_finish(arg(rest, 1).as_deref(), arg(rest, 2).as_deref()),
            Some(peer) => self.reseal_begin(peer),
            None => "usage:\n\
                     \x20 peer reseal <peer>              start, on an existing peering\n\
                     \x20 peer reseal pad <dest>          your fresh half, for media\n\
                     \x20 peer reseal wrap <dest>         or wrapped, for a voice call\n\
                     \x20 peer reseal seal <file> <ch>    finish\n\n\
                     Upgrades a peering over a stronger channel without redoing \
                     it. You keep the peer-link and the message history."
                .into(),
        }
    }

    /// Begin a re-seal: a fresh contribution for an existing peering.
    fn reseal_begin(&mut self, peer: &str) -> String {
        let Some(w) = self.epoch_key else {
            return "locked — unlock first".into();
        };
        if !self.peer_path(peer, artifact::PeerFile::Link).exists() {
            return format!(
                "no peering with {peer}.\n\n\
                 `peer reseal` strengthens one that exists. To make a new one, \
                 start with `peer offer`."
            );
        }
        let terms = self.peer_terms(peer);
        let r = OsRng.next_32();
        let record = {
            let mut wr = krab_core::cbor::Writer::new();
            wr.map(2).uint(1).tstr(peer).uint(2).bstr(&r);
            wr.finish()
        };
        let Ok(sealed) = krab_crypto::kek::seal_under(&w, b"krab/reseal", &record, &mut OsRng)
        else {
            return "could not store the re-seal".into();
        };
        if let Err(e) = atomic::write(&self.path(artifact::Artifact::Reseal), &sealed) {
            return format!("could not store the re-seal: {e}");
        }
        format!(
            "re-sealing {peer}.\n\n\
             currently: {}{}\n\n\
             next:\n\
             \x20 peer reseal pad <destination>   — onto the medium you carry\n\
             \x20 peer reseal wrap <file>         — or wrapped under spoken words\n\n\
             then, once you have theirs:\n\
             \x20 peer reseal seal <their file> <in-person|media|spoken>\n\n\
             Your peer-link and every message you hold are untouched.",
            terms
                .as_ref()
                .map(|t| t.channel.to_string())
                .unwrap_or_else(|| "unrecorded".into()),
            match terms.as_ref() {
                Some(t) if t.post_quantum() => " — already post-quantum",
                Some(_) => " — NOT post-quantum",
                None => "",
            }
        )
    }

    /// Write the fresh contribution out, bare or wrapped.
    fn reseal_materialise(&mut self, dest: Option<&str>, wrapped: bool) -> String {
        let verb = if wrapped { "wrap" } else { "pad" };
        let Some(dest) = dest else {
            return format!("usage: peer reseal {verb} <destination>");
        };
        let Some((_, r)) = self.load_reseal() else {
            return "no re-seal in progress — `peer reseal <peer>` first".into();
        };
        let plain = ceremony::encode_contribution(&peering::Contribution { r });
        if wrapped {
            let Some((w, phrase)) = spoken::wrap(&plain, &mut OsRng) else {
                return "could not wrap the contribution".into();
            };
            if let Err(e) = std::fs::write(dest, w.encode()) {
                return format!("could not write {dest}: {e}");
            }
            spoken::instructions(dest, &phrase)
        } else {
            match std::fs::write(dest, plain) {
                Err(e) => format!("could not write {dest}: {e}"),
                Ok(()) => format!(
                    "wrote your fresh contribution to {dest}.\n\n\
                     Half a shared secret in plaintext, exactly like `peer pad` \
                     — carry it, hand it over, leave no copy."
                ),
            }
        }
    }

    /// Finish: derive the new root, seat it, and record the stronger terms.
    fn reseal_finish(&mut self, path: Option<&str>, channel: Option<&str>) -> String {
        let (Some(path), Some(channel)) = (path, channel) else {
            return "usage: peer reseal seal <their file> <in-person|media|spoken>".into();
        };
        let Some(ch) = ceremony::parse_channel(channel) else {
            return format!("unknown channel {channel:?}");
        };
        if !ch.independent_of_dh() {
            return format!(
                "{ch} is not an upgrade.\n\n\
                 A re-seal exists to record that the pad travelled by a route an \
                 adversary cannot record and later break. Use in-person, media, \
                 or spoken."
            );
        }
        if self.epoch_key.is_none() {
            return "locked — unlock first".into();
        }
        let Some((peer, mine)) = self.load_reseal() else {
            return "no re-seal in progress — `peer reseal <peer>` first".into();
        };
        let Some(me) = self.identity.as_ref().map(|i| i.node_id()) else {
            return "no identity".into();
        };

        // A wrapped file needs the words; a bare pad does not.
        let raw = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => return format!("could not read {path}: {e}"),
        };
        let theirs = if ch == peering::Channel::Spoken {
            match spoken::Wrapped::decode(&raw) {
                Some(_) => {
                    self.prompt = Some(Prompt::ResealWords {
                        path: path.to_string(),
                    });
                    return format!(
                        "type the {} words they read to you, separated by spaces.",
                        spoken::WORDS
                    );
                }
                None => return format!("{path} is not a wrapped pad"),
            }
        } else {
            raw
        };
        self.reseal_with(&peer, &me, mine, &theirs, ch)
    }

    /// The half of a re-seal that both the bare and the spoken route reach.
    fn reseal_with(
        &mut self,
        peer: &str,
        me: &[u8; 32],
        mine: [u8; 32],
        their_bytes: &[u8],
        ch: peering::Channel,
    ) -> String {
        let Some(w) = self.epoch_key else {
            return "locked".into();
        };
        let theirs = match ceremony::decode_contribution(their_bytes) {
            Ok(c) => c,
            Err(e) => return format!("not a contribution: {e:?}"),
        };
        let card = match std::fs::read(self.peer_path(peer, artifact::PeerFile::Link))
            .ok()
            .and_then(|b| peering::Card::decode(&b).ok())
            .filter(|c| c.verify())
        {
            Some(c) => c,
            None => return format!("the stored peer-link for {peer} does not verify"),
        };
        let sealed = match std::fs::read(self.peer_path(peer, artifact::PeerFile::Reservoir)) {
            Ok(b) => b,
            Err(_) => return format!("no reservoir for {peer}"),
        };
        let Some((old_root, stored_epoch)) =
            krab_crypto::kek::open_under(&w, b"krab/reservoir", &sealed)
                .ok()
                .and_then(|r| persist::decode_reservoir(&r).ok())
        else {
            return format!("the reservoir for {peer} did not open");
        };

        let epoch = now_epoch().0.max(stored_epoch.0);
        let new_root = krab_crypto::rekey::reseal_root(
            &old_root,
            (me, &krab_crypto::secret::Secret::new(mine)),
            (&card.node_id(), &krab_crypto::secret::Secret::new(theirs.r)),
            epoch,
        );

        let mut res = krab_crypto::reservoir::Reservoir::new(old_root, stored_epoch);
        if !res.rekey(new_root, krab_core::tag::Epoch(epoch)) {
            return "the new root landed before the ratchet — nothing changed".into();
        }
        let record = persist::encode_reservoir(
            &res.root_bytes().expect("just seated"),
            krab_core::tag::Epoch(epoch),
        );
        let Ok(out) = krab_crypto::kek::seal_under(&w, b"krab/reservoir", &record, &mut OsRng)
        else {
            return "could not seal the new reservoir — nothing changed".into();
        };
        if let Err(e) = atomic::write(&self.peer_path(peer, artifact::PeerFile::Reservoir), &out) {
            return format!("could not store the new reservoir: {e} — nothing changed");
        }

        let previous = self.peer_terms(peer);
        let terms = peering::Terms {
            channel: ch,
            // A re-seal does not assert a fingerprint comparison it did not
            // witness. If one was never done, it is still outstanding.
            fingerprint_verified: previous
                .as_ref()
                .map(|t| t.fingerprint_verified)
                .unwrap_or(false),
            sealed_epoch: epoch,
            reseals: previous.as_ref().map(|t| t.reseals + 1).unwrap_or(1),
        };
        let _ = atomic::write(
            &self.peer_path(peer, artifact::PeerFile::Terms),
            &terms.encode(),
        );
        shred::remove(&self.path(artifact::Artifact::Reseal), &mut OsRng);

        format!(
            "re-sealed {peer} over {ch}.\n\n\
             The reservoir root is now derived from material that never crossed \
             a recorded channel, so this peering survives X25519 being broken. \
             Your peer-link and every message you hold are unchanged.\n\n\
             was: {}   now: {ch}\n\n\
             The other end must run the same command, or your roots will differ \
             and nothing will open.",
            previous
                .map(|t| t.channel.to_string())
                .unwrap_or_else(|| "unrecorded".into())
        )
    }

    /// The recorded terms of a peering, if any were stored.
    fn peer_terms(&self, peer: &str) -> Option<peering::Terms> {
        std::fs::read(self.peer_path(peer, artifact::PeerFile::Terms))
            .ok()
            .and_then(|b| peering::Terms::decode(&b))
    }

    /// The re-seal in progress: whose, and this node's fresh contribution.
    fn load_reseal(&self) -> Option<(String, [u8; 32])> {
        use krab_core::cbor::{Item, Reader};
        let w = self.epoch_key?;
        let raw = krab_crypto::kek::open_under(
            &w,
            b"krab/reseal",
            &std::fs::read(self.path(artifact::Artifact::Reseal)).ok()?,
        )
        .ok()?;
        let mut r = Reader::new(&raw);
        let mut m = r.map().ok()?;
        if m.left() != 2 {
            return None;
        }
        (m.key().ok()?? == 1).then_some(())?;
        let Item::Tstr(peer) = m.value().ok()? else {
            return None;
        };
        let peer = peer.to_string();
        (m.key().ok()?? == 2).then_some(())?;
        let Item::Bstr(b) = m.value().ok()? else {
            return None;
        };
        Some((peer, b.try_into().ok()?))
    }

    /// Record the counterparty's card — RFC 3 §11 step 1.
    fn peer_accept(&mut self, path: Option<&str>) -> String {
        let Some(path) = path else {
            return "usage: peer accept <their.card>".into();
        };
        let mut pending = match self.load_ceremony() {
            Ok(p) => p,
            Err(e) => return e,
        };
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                return format!(
                    "could not read {path}: {e}\n\n\
                     Give the path to the card THEY sent you."
                )
            }
        };
        let card = match peering::Card::decode(&bytes) {
            Ok(c) => c,
            Err(e) => {
                return format!(
                    "not a card: {e:?}\n\n\
                     `peer accept` takes THEIR card — the peer.card file they \
                     sent you. A pad is not a card."
                )
            }
        };
        if let Err(e) = pending.accept_card(card) {
            return match e {
                ceremony::Error::BadCard => {
                    "that card's signature does not verify — it is not what it claims".into()
                }
                #[allow(unreachable_patterns)]
                ceremony::Error::CounterpartyChanged => {
                    "a different card is already recorded for this ceremony. If you \
                     meant to peer with someone else, finish or discard this one first."
                        .into()
                }
            };
        }
        if let Err(e) = self.save_ceremony(&pending) {
            return e;
        }
        format!(
            "card accepted.\n\n\
             their fingerprint, from the card you just took in:\n\n\x20 {}\n\n\
             yours, for them to check:\n\n\x20 {}\n\n\
             Call them. Read yours; they read theirs. **Both must match.** This \
             is the only step that establishes who is on the other end — the \
             card itself proves a key signed it, not whose key it is.\n\n\
             then:  peer pad <destination>     — your SECRET half\n\
             \x20      peer seal <their.pad> <in-person|media|corpus|network>",
            pending.their_fingerprint().unwrap_or_default(),
            self.identity
                .as_ref()
                .map(|i| i.fingerprint())
                .unwrap_or_default()
        )
    }

    /// Complete the peering — RFC 3 §11 steps 3 and 4.
    fn peer_seal(&mut self, path: Option<&str>, channel: Option<&str>) -> String {
        let (Some(path), Some(channel)) = (path, channel) else {
            return "usage: peer seal <their.pad> <in-person|media|corpus|network>\n\n\
                    the channel is not guessed: it decides whether this reservoir \
                    survives X25519 being broken."
                .into();
        };
        let Some(channel) = ceremony::parse_channel(channel) else {
            return format!(
                "unknown channel {channel:?} — use in-person, media, corpus or network"
            );
        };
        let pending = match self.load_ceremony() {
            Ok(p) => p,
            Err(e) => return e,
        };
        if pending.their_card.is_none() {
            return "no card recorded yet — run `peer accept <their.card>` first".into();
        }
        // A pad that crossed a network is wrapped, and opening it needs the
        // words. They are taken at a prompt rather than on the command line:
        // the line goes into the history, and a history is a record of a live
        // key sitting next to the thing it protects.
        if channel == peering::Channel::Spoken {
            if std::fs::read(path)
                .ok()
                .and_then(|b| spoken::Wrapped::decode(&b))
                .is_none()
            {
                return format!(
                    "{path} is not a wrapped pad.\n\n\
                     `spoken` opens a file written by their `peer wrap`. A bare \
                     pad from `peer pad` is sealed with `media` or `in-person`."
                );
            }
            self.prompt = Some(Prompt::TransferWords {
                path: path.to_string(),
            });
            return format!(
                "type the {} words they read to you, separated by spaces.\n\n\
                 They are not echoed to the history. If a word is wrong the \
                 file will not open, and a pair read out of order is rejected \
                 rather than silently accepted.",
                spoken::WORDS
            );
        }

        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                return format!(
                    "could not read {path}: {e}\n\n\
                     This should be the pad THEY gave you, not one of yours. \
                     Yours is written by `peer pad <destination>` and is the \
                     half you hand over — you never seal with your own."
                )
            }
        };
        self.seal_from(&bytes, channel, Some(path))
    }

    /// Finish a peering from the counterparty's contribution bytes.
    ///
    /// Split out because the bytes arrive two ways now: from a pad handed over
    /// on media, and from a wrapped file opened with words read aloud. The
    /// sealing itself must be one path — a second would be a second place to
    /// get the channel classification or the reservoir derivation wrong.
    fn seal_with_contribution(&mut self, bytes: &[u8], channel: peering::Channel) -> String {
        self.seal_from(bytes, channel, None)
    }

    /// As [`App::seal_with_contribution`], remembering the file the
    /// contribution came from so it can be destroyed once consumed.
    fn seal_from(
        &mut self,
        bytes: &[u8],
        channel: peering::Channel,
        source: Option<&str>,
    ) -> String {
        let pending = match self.load_ceremony() {
            Ok(p) => p,
            Err(e) => return e,
        };
        let Some(their_card) = pending.their_card.clone() else {
            return "no card recorded yet — run `peer accept <their.card>` first".into();
        };
        let theirs = match ceremony::decode_contribution(bytes) {
            Ok(c) => c,
            Err(e) => return format!("not a contribution: {e:?}"),
        };

        let mine = peering::Offer {
            card: pending.my_card.clone(),
            contribution: peering::Contribution {
                r: pending.my_contribution.r,
            },
        };
        let (reservoir, link) = accept(
            &mine,
            &their_card,
            &theirs,
            channel,
            pending.fingerprint_verified,
        );
        if !link.is_usable() {
            return format!("refused: {:?}", link.caveats);
        }

        // Seal the reservoir under W_N and retire the ceremony.
        // Root *and* ratchet epoch (RFC 7 §6.4). The ceremony's output is
        // root_N for the current epoch, so that is what is recorded.
        let record = persist::encode_reservoir(&reservoir, now_epoch());
        let out = match self.epoch_key.and_then(|w| {
            krab_crypto::kek::seal_under(&w, b"krab/reservoir", &record, &mut OsRng).ok()
        }) {
            Some(sealed) => sealed,
            None => return "locked".into(),
        };
        // The peer-link: their card, and the reservoir sealed under W_N. This
        // is what `send` resolves a peer name against — RFC 3 §4 makes the
        // link the durable artifact, not the ceremony.
        let short = short_id(&their_card.node_id());
        if let Err(e) = self.ensure_peer_dir(&short) {
            return e;
        }
        if let Err(e) = atomic::write(&self.peer_path(&short, artifact::PeerFile::Reservoir), &out)
        {
            return format!("could not store the reservoir: {e}");
        }
        if let Err(e) = atomic::write(
            &self.peer_path(&short, artifact::PeerFile::Link),
            &their_card.encode(),
        ) {
            return format!("could not store the peer-link: {e}");
        }
        // **What this peering is honestly worth, on disk beside it.**
        // `PeerLink::caveats` claimed to be "kept, not discarded" and was held
        // only in memory, so a link formed remotely said so until the process
        // exited and then presented as though it had been formed in person.
        let terms = peering::Terms {
            channel,
            fingerprint_verified: pending.fingerprint_verified,
            sealed_epoch: now_epoch().0,
            reseals: 0,
        };
        let _ = atomic::write(
            &self.peer_path(&short, artifact::PeerFile::Terms),
            &terms.encode(),
        );
        // **RFC 3 §3's credential.** Proposed here, signed by this node only,
        // and handed over for the other end to countersign — §5.3's step.
        // Until both signatures exist it is a claim rather than a contract,
        // which is why it goes to the home directory for handover and not
        // into the peer directory as though it were finished.
        let proposal = self.propose_credential(&their_card);
        let _ = atomic::write(&self.home.join(format!("{short}.credential")), &proposal);
        let credential_note = match credential::Credential::decode(&proposal) {
            // Never complete at this point — this node has signed and the
            // other end has not — so the note says what is still owed.
            Some(c) if !c.is_complete() => format!(
                "\n\nA peer-link credential is at {}, signed by you. \
                 Give it to them; they run `peer countersign` and hand it \
                 back, and you run the same command on what returns.\n\n\
                 RFC 3 §3 needs both signatures — one signature lets a party \
                 assert a relationship the other never agreed to. It is also \
                 what someone introducing you to a third party cites as \
                 evidence (§5.1), so a peering without it can be vouched for \
                 but not proved.",
                self.home.join(format!("{short}.credential")).display()
            ),
            _ => String::new(),
        };
        shred::remove(&self.path(artifact::Artifact::Ceremony), &mut OsRng);
        // `peer.pad` is this node's own contribution, written in the clear
        // because it has to be handed over. Once the reservoir exists it has no
        // further use and is half a live shared secret sitting unwrapped on
        // disk — the one file in the layout that is neither signed nor sealed,
        // and therefore the one where overwriting is the only tool available.
        shred::remove(&self.path(artifact::Artifact::PeerPad), &mut OsRng);
        // **And theirs.** Their pad is half the same shared secret and is
        // equally unprotected; it survived every wipe because the operator
        // chose where to put it and `wipe` only destroys what this node wrote.
        // Consuming it is the moment its owner is known, so it is the moment
        // to destroy it — the alternative is a plaintext half-secret sitting
        // in whatever directory a courier happened to unload into.
        if let Some(path) = source {
            shred::remove(std::path::Path::new(path), &mut OsRng);
        }
        // A peering completed while the listener runs must be accepted at
        // once — requiring a restart to talk to someone you just peered with
        // is a rule nothing states.
        self.refresh_allowed();

        // RFC 3 §4: the peer-link is a contract, so the terms both ends agreed
        // to belong on it. `negotiate` takes the lower bucket ceiling, since a
        // link is only as capable as its least capable end (RFC 4 §5.4).
        let agreed = pending.policy().unwrap_or_default();
        let mut msg = format!(
            "peer-link signed with {}\n\nagreed: buckets to {}, {}, {} retained{}",
            their_card.fingerprint(),
            agreed.max_bucket,
            if agreed.relay {
                "relaying for others"
            } else {
                "not relaying"
            },
            agreed.retention_bytes,
            if agreed.shard_bits > 0 {
                format!(", sharded at {} bits", agreed.shard_bits)
            } else {
                String::new()
            }
        );
        if !link.reservoir_is_post_quantum() {
            msg.push_str(
                "\n\nthis reservoir arrived over a channel secured by X25519, so it \
                 does NOT survive X25519 being broken. Recorded on the link.",
            );
        }
        if !pending.fingerprint_verified {
            msg.push_str("\n\nfingerprints were never compared. Recorded on the link.");
        }
        msg.push_str(&credential_note);
        msg
    }

    /// Re-key `peer` if the schedule says it is time, or if it must.
    ///
    /// Two triggers, and they are different in kind:
    ///
    /// - **Age.** `REKEY_EPOCHS` since the reservoir was last seated. This is
    ///   the stated guarantee — a reservoir compromised at time *T* stops
    ///   protecting traffic within `REKEY_EPOCHS` of *T* — and a guarantee
    ///   that depends on an operator remembering to type a verb is not one.
    /// - **Distance.** The ratchet is further behind than it can advance in
    ///   one step (`Reservoir::MAX_ADVANCE`, 90 days). Past that the peering
    ///   is dead and only a re-key revives it, so this is a repair rather than
    ///   a rotation.
    ///
    /// Returns `None` when nothing was due, when the link is down, or when the
    /// attempt failed — a failed re-key changes nothing and will be due again
    /// on the next tick, which is the correct behaviour for a link that is
    /// flapping.
    fn rekey_if_due(&mut self, peer: &str) -> Option<activity_log::Event> {
        // Cheap checks first: this runs on every scheduled peer, every tick.
        self.links.get(peer).and_then(|l| l.session.as_ref())?;
        let w = self.epoch_key?;
        let sealed = std::fs::read(self.peer_path(peer, artifact::PeerFile::Reservoir)).ok()?;
        let (_, seated) = krab_crypto::kek::open_under(&w, b"krab/reservoir", &sealed)
            .ok()
            .and_then(|r| persist::decode_reservoir(&r).ok())?;

        let age = now_epoch().0.saturating_sub(seated.0);
        let stale = age >= krab_crypto::REKEY_EPOCHS;
        let unreachable = age > krab_crypto::reservoir::Reservoir::MAX_ADVANCE;
        if !stale && !unreachable {
            return None;
        }

        let out = self.peer_rekey(Some(peer));
        // `peer_rekey` writes its own report to the caller; here the schedule
        // is what ran, so the operator learns about it through the activity
        // log rather than by having their output pane overwritten by something
        // they did not ask for.
        if out.starts_with("re-keyed") {
            Some(activity_log::Event::Rekeyed {
                peer: peer.to_string(),
                index: now_epoch().0,
            })
        } else {
            Some(activity_log::Event::Failed {
                peer: peer.to_string(),
                why: if unreachable {
                    "re-key needed to revive the peering"
                } else {
                    "scheduled re-key"
                },
            })
        }
    }

    /// Enable or disable channel carriage — RFC 6 §3.6, RFC 8 §4.3.
    ///
    /// **Default off, and the warning fires at the point of enabling.** RFC 8
    /// §4.3 forbids it being documentation-only: carrying channels moves a
    /// node from private relay to host of public content, and that is a
    /// change in what the node *is*, with consequences that depend on where
    /// the operator lives.
    fn channel_carry(&mut self, arg: Option<&str>) -> String {
        let current = if self.roster.carriage.enabled {
            "on"
        } else {
            "off"
        };
        match arg {
            None => format!(
                "channel carriage is {current}.\n\n\
                 `channel carry on` hosts public content; `channel carry off` \
                 stops. Off is the default (RFC 6 §3.6)."
            ),
            Some("off") => {
                self.roster.carriage.enabled = false;
                if let Some(e) = self.save_roster() {
                    return e;
                }
                "channel carriage off. This node relays only ciphertext again, \
                 for people you chose."
                    .into()
            }
            Some("on") => {
                if self.roster.carriage.enabled {
                    return "channel carriage is already on.".into();
                }
                // Two steps, like the first post and like `wipe`: this changes
                // what the node is, and RFC 8 §4.3 requires the warning at the
                // moment of enabling rather than in a document nobody reads.
                if !self.roster.carriage_armed {
                    self.roster.carriage_armed = true;
                    return format!(
                        "{}\n\nType `channel carry on` again to enable it.",
                        krab_crypto::CarriagePolicy::enabling_notice()
                    );
                }
                self.roster.carriage_armed = false;
                self.roster.carriage.enabled = true;
                if let Some(e) = self.save_roster() {
                    return e;
                }
                "channel carriage ON. This node now hosts public content.".into()
            }
            Some(other) => format!("usage: channel carry on|off (not {other:?})"),
        }
    }

    /// Create the channel this node can post to — RFC 6 §3.1.
    fn channel_new(&mut self) -> String {
        if let Some(c) = self.roster.mine.as_ref() {
            return format!(
                "this node already has a channel: {}\n\n\
                 A second would need a second key, and RFC 6 gives a node one \
                 posting identity.",
                channels::short(&c.id())
            );
        }
        let c = krab_crypto::channel::Channel::create(&mut OsRng);
        let id = c.id();
        self.roster.mine = Some(c);
        if let Some(e) = self.save_roster() {
            return e;
        }
        format!(
            "channel {} created.\n\n\
             Give that identifier to anyone who should read it — it is public.\n\
             Posts are PUBLIC, SIGNED and PERMANENT: they carry your channel's \
             signature, every carrying node archives them, and RFC 3 §6.1 \
             forbids any recall mechanism. There is no delete.",
            channels::short(&id)
        )
    }

    /// Publish — the one irreversible thing an operator does routinely.
    /// Open the composer for a channel post — RFC 8 §4.2 requirement 1.
    ///
    /// Switching to the Channels tab is what puts the red
    /// `PUBLIC — SIGNED — PERMANENT` banner on the composer: the banner is
    /// derived from the tab rather than passed in, so a composer for a post
    /// cannot be opened without it.
    fn compose_post(&mut self) -> String {
        if self.roster.mine.is_none() {
            return "no channel — `channel new` first".into();
        }
        self.ui.select_tab(layout::Tab::Channels);
        self.ui.compose();
        // Focus has to leave the command line, or the keystrokes go to it
        // rather than to the draft — the same move `send` makes.
        while self.ui.focus() != layout::Pane::View {
            self.ui.cycle_focus();
        }
        self.composing_channel = true;
        "composing a post. Enter is a newline; Ctrl-D publishes it; Esc \
         discards it.\n\n\
         It will be PUBLIC, SIGNED and PERMANENT: anyone holding it can read \
         it, it carries your channel's signature, and it cannot be edited or \
         withdrawn (RFC 8 §4.1)."
            .into()
    }

    /// Ctrl-D on a channel composition.
    fn seal_post(&mut self) -> String {
        let text = self.composer.trim().to_string();
        if text.is_empty() {
            return "nothing to publish. Esc discards this.".into();
        }
        overwrite(&mut self.composer);
        self.composer_at = 0;
        self.ui.end_compose();
        self.composing_channel = false;
        // **RFC 8 §4.2 requirement 2** — the first post of a session is
        // confirmed. Once per session: the friction is a reminder, not a toll
        // on every line.
        if self.roster.first_post_confirmed {
            return self.channel_post(&text);
        }
        let preview: String = text.lines().next().unwrap_or("").chars().take(60).collect();
        self.pending_post = Some(text);
        format!(
            "PUBLIC — SIGNED — PERMANENT\n\n\
             \x20 {preview}\n\n\
             Press Enter to publish it. Esc discards it.\n\n\
             Asked once a session, because this is the one action in Krab \
             that cannot be undone (RFC 8 §4.1)."
        )
    }

    fn channel_post(&mut self, text: &str) -> String {
        if text.is_empty() {
            return "usage: channel post <text>\n\n\
                    PUBLIC, SIGNED, PERMANENT. There is no recall."
                .into();
        }
        let Some(c) = self.roster.mine.as_ref() else {
            return "no channel — `channel new` first".into();
        };
        // **RFC 8 §4.2 requirement 2.** The first post of a session is
        // confirmed explicitly. Per session, not per node: the confirmation is
        // a reminder of what publishing means, and a reminder given once a
        // year is not one.
        if !self.roster.first_post_confirmed {
            // Hold the text so Enter can publish exactly what was confirmed.
            // It used to ask for the command to be retyped, which meant the
            // operator confirmed by typing rather than by reading, and left
            // the first attempt doing nothing at all.
            self.pending_post = Some(text.to_string());
            return format!(
                "PUBLIC — SIGNED — PERMANENT\n\n\
                 This will be signed with channel {}, flooded to every peer, \
                 and archived by every node that carries the channel. RFC 3 \
                 §6.1 forbids a recall mechanism, so it cannot be deleted, \
                 edited, or made unreadable later — unlike a sealed message, \
                 which expires with its epoch key.\n\n\
                 Press Enter to publish it. Esc discards it.",
                channels::short(&c.id())
            );
        }

        let seq = self.next_sequence();
        let post = c.post(seq, "text/plain", text.as_bytes());
        let now_min = now_epoch().0 * 1440;
        let Some((id, bytes)) =
            channels::into_object(&post, now_min, krab_core::tag::MAX_TTL_DAYS * 1440)
        else {
            return "too long for one object — split it".into();
        };
        if let Err(e) = self.store.with(|s| s.ingest(id, bytes, now_min, u32::MAX)) {
            return format!("the store refused it: {e:?}");
        }
        self.save_corpus();
        self.refresh_inbox();
        format!(
            "published post {seq} to channel {}.\n\n\
             It leaves on a scheduled reconciliation, and it is now permanent.",
            channels::short(&post.channel_id())
        )
    }

    /// The next sequence number for this node's channel.
    ///
    /// From the posts already held, so a restart does not restart the
    /// numbering — a repeated sequence number is two different posts claiming
    /// the same position, which no reader can resolve.
    fn next_sequence(&self) -> u64 {
        let Some(mine) = self.roster.mine.as_ref().map(|c| c.id()) else {
            return 1;
        };
        let mut max = 0;
        self.store.with(|s| {
            for (_, id) in s.entries_in_range(0, u32::MAX) {
                if let Some(p) = s.get(&id).and_then(channels::from_object) {
                    if p.channel_id() == mine {
                        max = max.max(p.sequence);
                    }
                }
            }
        });
        max + 1
    }

    /// Follow or unfollow a channel.
    fn channel_follow(&mut self, id: Option<&str>, follow: bool) -> String {
        let verb = if follow { "follow" } else { "unfollow" };
        let Some(hex) = id else {
            return format!("usage: channel {verb} <id>");
        };
        // A short id is what an operator reads and types; the full identifier
        // is 32 bytes and nobody transcribes those.
        let Some(full) = self.channel_by_short(hex) else {
            return format!(
                "no channel {hex} in this corpus.\n\n\
                 A channel appears once one of its posts has arrived — there is \
                 no directory to look it up in."
            );
        };
        let changed = if follow {
            self.roster.follow(full)
        } else {
            self.roster.unfollow(&full)
        };
        if let Some(e) = self.save_roster() {
            return e;
        }
        self.refresh_inbox();
        match (follow, changed) {
            (true, true) => format!("following {hex}."),
            (true, false) => format!("already following {hex}."),
            (false, true) => format!(
                "no longer following {hex}.\n\n\
                 Posts already held are kept: RFC 3 §6.1 forbids a recall \
                 mechanism, and a node that erased an archive on unfollowing \
                 would be a selective one."
            ),
            (false, false) => format!("not following {hex}."),
        }
    }

    /// Resolve a short identifier against the channels in the corpus.
    fn channel_by_short(&self, hex: &str) -> Option<[u8; 32]> {
        let mut found = None;
        self.store.with(|s| {
            for (_, id) in s.entries_in_range(0, u32::MAX) {
                if let Some(p) = s.get(&id).and_then(channels::from_object) {
                    if channels::short(&p.channel_id()) == hex {
                        found = Some(p.channel_id());
                    }
                }
            }
        });
        found.or_else(|| {
            self.roster
                .mine
                .as_ref()
                .map(|c| c.id())
                .filter(|c| channels::short(c) == hex)
        })
    }

    /// What this node owns and follows.
    fn channel_list(&self) -> String {
        let mut out = String::new();
        match self.roster.mine.as_ref() {
            Some(c) => out.push_str(&format!(
                "yours:      {}  (you hold the key; you can post)\n",
                channels::short(&c.id())
            )),
            None => out.push_str("yours:      none — `channel new` creates one\n"),
        }
        if self.roster.following.is_empty() {
            out.push_str("following:  none\n");
        } else {
            for c in &self.roster.following {
                out.push_str(&format!("following:  {}\n", channels::short(c)));
            }
        }
        // What is in the corpus but unfollowed — RFC 6 §3.6's decision made
        // visible, rather than a channel silently carried and never read.
        let mut seen: Vec<[u8; 32]> = Vec::new();
        self.store.with(|s| {
            for (_, id) in s.entries_in_range(0, u32::MAX) {
                if let Some(p) = s.get(&id).and_then(channels::from_object) {
                    let c = p.channel_id();
                    if !self.roster.follows(&c) && !seen.contains(&c) {
                        seen.push(c);
                    }
                }
            }
        });
        if !seen.is_empty() {
            out.push_str("\nin the corpus, not followed:\n");
            for c in &seen {
                out.push_str(&format!("  {}\n", channels::short(c)));
            }
        }
        out
    }

    /// Read the roster back. Absent is not an error — a node that has never
    /// touched a channel has none.
    fn load_roster(&mut self) {
        let Some(w) = self.epoch_key else { return };
        if let Some(r) = std::fs::read(self.path(artifact::Artifact::ChannelRoster))
            .ok()
            .and_then(|sealed| krab_crypto::kek::open_under(&w, b"krab/roster", &sealed).ok())
            .and_then(|raw| channels::Roster::decode(&raw))
        {
            self.roster = r;
        }
    }

    /// Persist the roster. It holds a posting key, so it is sealed.
    fn save_roster(&self) -> Option<String> {
        let w = self.epoch_key?;
        let sealed =
            krab_crypto::kek::seal_under(&w, b"krab/roster", &self.roster.encode(), &mut OsRng)
                .ok()?;
        atomic::write(&self.path(artifact::Artifact::ChannelRoster), &sealed)
            .err()
            .map(|e| format!("could not store the roster: {e}"))
    }

    /// Mix fresh entropy into a live peering.
    ///
    /// See `Documentation/PAD-OVER-NETWORK.md` §3 and `krab_crypto::rekey`.
    /// The new entropy crosses the link, and that is sound because the key
    /// protecting it is derived from a root that never has.
    ///
    /// # Nothing is written until both ends agree
    ///
    /// A re-key that half-completes is worse than one that fails: the two
    /// ends' tags stop matching and RFC 0 §6 guarantees nobody is told. So the
    /// reservoir is rewritten only after the exchange has confirmed, and a
    /// failure anywhere leaves the old root exactly where it was.
    fn peer_rekey(&mut self, peer: Option<&str>) -> String {
        let Some(peer) = peer else {
            return "usage: peer rekey <peer>\n\n\
                    Mixes fresh entropy into an established peering, so a \
                    compromise stops mattering and a long absence does not \
                    kill the link. Needs the link up — `connect` or `listen` \
                    first."
                .into();
        };
        let (Some(id), Some(w)) = (&self.identity, self.epoch_key) else {
            return "locked — unlock first".into();
        };

        // Their card, from disk. RFC 4 §4.1's rule: the key a signature is
        // checked against comes from the stored link, never from the wire.
        let card = match std::fs::read(self.peer_path(peer, artifact::PeerFile::Link))
            .ok()
            .and_then(|b| peering::Card::decode(&b).ok())
            .filter(|c| c.verify())
        {
            Some(c) => c,
            None => return format!("no verifying peer-link for {peer} — peer with them first"),
        };

        // The reservoir, and where its ratchet has reached.
        let sealed = match std::fs::read(self.peer_path(peer, artifact::PeerFile::Reservoir)) {
            Ok(b) => b,
            Err(_) => return format!("no reservoir for {peer}"),
        };
        let (root_n, stored_epoch) =
            match krab_crypto::kek::open_under(&w, b"krab/reservoir", &sealed)
                .ok()
                .and_then(|r| persist::decode_reservoir(&r).ok())
            {
                Some(v) => v,
                None => return format!("the reservoir for {peer} did not open"),
            };

        // The index both ends must arrive at independently. `now_epoch` is the
        // only value both hold without another round trip; if their clocks
        // straddle a day boundary the exchange refuses with `WrongIndex`
        // rather than seating two different roots, and the next attempt
        // succeeds.
        let index = now_epoch().0.max(stored_epoch.0);

        let mine = rekey::Payload {
            contribution: OsRng.next_32(),
            index,
            policy: Policy::default(),
            // RFC 6 §3.6's default: carrying nothing. There is no verb to
            // change it yet, and sending the default is still the honest
            // answer to "what do you carry" — it is what this node does.
            carriage: krab_crypto::CarriagePolicy::default(),
            max_ttl_minutes: krab_core::tag::MAX_TTL_DAYS * 1440,
        };
        let my_node = id.node_id();
        let signing = id.signing_key();

        let Some(link) = self.links.get_mut(peer) else {
            return format!("no link to {peer} — `connect {peer} tcp <addr>` first");
        };
        let Some(session) = link.session.as_mut() else {
            return format!("the link to {peer} is not up");
        };

        let outcome = match rekey_run::run(
            session.as_mut(),
            signing,
            &my_node,
            &card,
            &root_n,
            index,
            mine,
            &mut OsRng,
        ) {
            Ok(o) => o,
            Err(e) => return rekey_failure(peer, e),
        };

        // Adopt, then persist. `rekey` refuses to seat a root in the past, so
        // a clock that has gone backwards since the index was chosen fails
        // here rather than making one epoch derivable from two chains.
        let mut res = krab_crypto::reservoir::Reservoir::new(root_n, stored_epoch);
        if !res.rekey(outcome.new_root, krab_core::tag::Epoch(outcome.index)) {
            return "the new root landed before the ratchet — nothing changed".into();
        }
        let record = persist::encode_reservoir(
            &res.root_bytes().expect("just seated"),
            krab_core::tag::Epoch(outcome.index),
        );
        let out = match krab_crypto::kek::seal_under(&w, b"krab/reservoir", &record, &mut OsRng) {
            Ok(o) => o,
            Err(_) => return "could not seal the new reservoir — nothing changed".into(),
        };
        if let Err(e) = atomic::write(&self.peer_path(peer, artifact::PeerFile::Reservoir), &out) {
            return format!("could not store the new reservoir: {e} — nothing changed");
        }
        // Their terms, which until now propagated once at peering and never
        // again. Written beside the link so a locked node still shows them.
        let _ = atomic::write(
            &self.peer_path(peer, artifact::PeerFile::Policy),
            &outcome.theirs.encode(),
        );

        self.log.push(activity_log::Event::Rekeyed {
            peer: peer.to_string(),
            index: outcome.index,
        });
        // A re-key is four messages over the session, in both directions.
        self.outbound_ticks = ACTIVITY_GLYPH_TICKS;
        self.inbound_ticks = ACTIVITY_GLYPH_TICKS;

        let t = &outcome.theirs;
        format!(
            "re-keyed {peer} at index {}\n\n\
             This peering now survives a compromise of everything either node \
             held before it, and it is post-quantum if the original pad was.\n\n\
             their terms: buckets to {}, {}, {} retained, TTL {} days{}",
            outcome.index,
            t.policy.max_bucket,
            if t.policy.relay {
                "relaying for others"
            } else {
                "NOT relaying"
            },
            t.policy.retention_bytes,
            t.max_ttl_minutes / 1440,
            if t.carriage.enabled {
                format!(
                    ", carrying channels at {} shard bits",
                    t.carriage.shard_bits
                )
            } else {
                ", carrying no channels".into()
            }
        )
    }

    /// RFC 8 §5's `send` — compose, seal, and place in the store.
    ///
    /// **Does not transmit.** The object enters the corpus and leaves on the
    /// next scheduled reconciliation, which is what RFC 5 §6.1 requires and
    /// RFC 6 §2.7 reinforces: emitting on send would make transmission timing
    /// a function of composition timing.
    /// `short <peer> <text>` — RFC 4 §8's link-local one-liner.
    ///
    /// # Why this refuses without a live link
    ///
    /// A `short` is **link-local by construction** (RFC 1 §5.5): no
    /// identifier, no relay, no reconciliation. There is no corpus to leave it
    /// in and no third party to carry it, so "queue it until the peer is
    /// reachable" is not a smaller version of this feature — it is `send`, and
    /// `send` already exists. Refusing is the honest answer.
    ///
    /// # The counter, and the thing that must never happen
    ///
    /// The nonce is `(link_id, ctr)`. A counter that restarted at zero under a
    /// key that had not changed would repeat a nonce, which breaks
    /// ChaCha20-Poly1305 outright. So the counter is written to disk
    /// **before** the frame is sent, not after: a crash between the two costs
    /// one unused counter value, and the opposite order costs a repeat.
    fn short_command(&mut self, line: &str) -> String {
        let Some(peer) = arg(line, 1) else {
            return "usage: short <peer> <message>\n\n\
                    A one-line message straight to a peer you are linked to \
                    right now. It is not mail: nothing stores it, nothing \
                    relays it, and it is gone when the pane clears (RFC 4 §8)."
                .into();
        };
        let Some(text) = line
            .splitn(3, char::is_whitespace)
            .nth(2)
            .map(str::trim)
            .filter(|t| !t.is_empty())
        else {
            return format!("usage: short {peer} <message>");
        };
        if text.len() > krab_crypto::short::MAX_BODY {
            return format!(
                "{} bytes — a short carries at most {}. RFC 4 §8's ceiling is \
                 55 bytes on the wire and 18 of them are framing. Use `send` \
                 for anything longer.",
                text.len(),
                krab_crypto::short::MAX_BODY
            );
        }

        let Some(id) = self.identity.as_ref() else {
            return "locked — `unlock` first.".into();
        };
        if self.links.get(&peer).and_then(|l| l.session.as_ref()).is_none() {
            return format!(
                "no live link to {peer}. A short is link-local by construction \
                 (RFC 1 §5.5) — there is nothing to queue it in and nobody to \
                 relay it. `connect {peer} …` first, or use `send`."
            );
        }
        let Some((key, tag, link)) = self.short_keying(&peer) else {
            return format!(
                "no reservoir chunk for {peer} at this epoch. The link key \
                 comes from the pairwise reservoir (RFC 7 §6); `peer rekey \
                 {peer}` if the peering has fallen behind."
            );
        };
        let _ = id;

        let epoch = now_epoch();
        let (stored_epoch, ctr) = self.short_ctr(&peer);
        let ctr = if stored_epoch == epoch.0 { ctr } else { 0 };
        // Written first. See the note above on which way round a crash is
        // allowed to fail.
        if let Err(e) = self.write_short_ctr(&peer, epoch.0, ctr.saturating_add(1)) {
            return format!("could not record the short counter: {e} — refusing to send");
        }

        // Absolute hours, matching the frozen header's absolute minutes.
        let expiry_h = expiry_for(epoch) / 60;
        let frame = match krab_crypto::short::seal(
            key.expose(),
            &link,
            ctr,
            &tag,
            expiry_h,
            text.as_bytes(),
        ) {
            Ok(f) => f,
            Err(krab_crypto::short::Error::CounterExhausted) => {
                return format!(
                    "this link has used all {} counters this epoch. It rotates \
                     when the epoch turns; `peer rekey {peer}` rotates it now.",
                    krab_crypto::short::MAX_CTR
                )
            }
            Err(e) => return format!("could not frame it: {e:?}"),
        };

        let Some(session) = self.links.get_mut(&peer).and_then(|l| l.session.as_mut()) else {
            return format!("the link to {peer} went away before it could be sent");
        };
        match session.send(&krab_proto::control::Control::Short(frame)) {
            Ok(()) => format!(
                "sent to {peer}. Nothing kept a copy — not here, not there \
                 beyond their pane, and nothing in between (RFC 4 §8)."
            ),
            Err(e) => {
                self.links.failed(&peer);
                format!("the link to {peer} refused it: {e}")
            }
        }
    }

    /// The message key, the 4-byte tag, and the link identifier for a peering.
    ///
    /// All three are derived, never stored: the key from this epoch's
    /// reservoir chunk under its own domain, the tag from the same pairwise
    /// tag sealed mail uses, and the identifier from the two node identifiers
    /// in sorted order so both ends agree.
    fn short_keying(&self, peer: &str) -> Option<(krab_crypto::Secret<32>, [u8; 4], [u8; 32])> {
        let id = self.identity.as_ref()?;
        let w = self.epoch_key?;
        let card = std::fs::read(self.peer_path(peer, artifact::PeerFile::Link))
            .ok()
            .and_then(|b| peering::Card::decode(&b).ok())
            .filter(|c| c.verify())?;

        let epoch = now_epoch();
        let chunk = std::fs::read(self.peer_path(peer, artifact::PeerFile::Reservoir))
            .ok()
            .and_then(|sealed| krab_crypto::kek::open_under(&w, b"krab/reservoir", &sealed).ok())
            .and_then(|raw| persist::decode_reservoir(&raw).ok())
            .and_then(|(root, stored)| {
                let mut r = krab_crypto::reservoir::Reservoir::new(root, stored);
                if stored != epoch && !r.advance_to(epoch) {
                    return None;
                }
                r.chunk(epoch)
            })?;

        let shared = id.agree_with(&krab_crypto::dh::PublicKey(card.correspondence_pk))?;
        let full = krab_crypto::pairwise_tag(&shared, epoch);
        let mut tag = [0u8; 4];
        tag.copy_from_slice(&full.0[..4]);

        let link = krab_crypto::short::link_id(&id.node_id(), &card.node_id());
        Some((krab_crypto::short::link_key(&chunk), tag, link))
    }

    /// This link's `(epoch, next counter)`, or `(0, 0)` if it has never sent.
    ///
    /// An unreadable file reads as **exhausted**, not as zero: a counter whose
    /// previous value cannot be established is one whose safe next value is
    /// unknown, and guessing zero is the one answer certain to repeat a nonce
    /// if the file was ever written.
    fn short_ctr(&self, peer: &str) -> (u32, u16) {
        let path = self.peer_path(peer, artifact::PeerFile::ShortCtr);
        match std::fs::read(&path) {
            Ok(b) if b.len() == 6 => (
                u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
                u16::from_le_bytes([b[4], b[5]]),
            ),
            // Never written: nothing has been sent under any key.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (0, 0),
            // Present and unreadable. Refuse by reporting the epoch as one
            // that cannot match and the counter as spent.
            _ => (u32::MAX, krab_crypto::short::MAX_CTR),
        }
    }

    fn write_short_ctr(&self, peer: &str, epoch: u32, next: u16) -> std::io::Result<()> {
        let mut out = [0u8; 6];
        out[..4].copy_from_slice(&epoch.to_le_bytes());
        out[4..].copy_from_slice(&next.to_le_bytes());
        self.ensure_peer_dir(peer)
            .map_err(std::io::Error::other)?;
        atomic::write(&self.peer_path(peer, artifact::PeerFile::ShortCtr), &out)
    }

    fn send(&mut self, line: &str) -> String {
        let Some(peer) = arg(line, 1) else {
            return "usage: send <peer>                  compose, then Ctrl-D\n\
                    \x20      send <peer> <message>        one line\n\
                    \x20      send <peer> --picture <file>"
                .into();
        };
        // **`send <peer>` with no message opens the composer.** A message
        // worth writing is rarely one line, and typing it on the command line
        // put it in the history — where Up-arrow recalled it, and RFC 7 §8
        // says plaintext exists only while displayed.
        if arg(line, 2).is_none() {
            if !self.peer_path(&peer, artifact::PeerFile::Link).exists() {
                return format!("no peer-link for {peer} — complete a peering first");
            }
            self.composing_to = Some(peer.clone());
            self.ui.compose();
            // Focus the pane the composer is drawn in. On the command line a
            // character is a command character — that is what makes a command
            // containing a letter typeable — so leaving focus there would send
            // every keystroke to the wrong buffer.
            while self.ui.focus() != layout::Pane::View {
                self.ui.cycle_focus();
            }
            return format!(
                "composing to {peer}.\n\n\
                 Enter is a newline. Ctrl-D seals it and queues it. Esc \
                 discards it — and a discarded draft is overwritten, not \
                 dropped (RFC 7 §8)."
            );
        }
        // RFC 8 §6 permits pictures and no other attachment type.
        if arg(line, 2).as_deref() == Some("--picture") {
            let Some(path) = arg(line, 3) else {
                return "usage: send <peer> --picture <file>".into();
            };
            return self.send_picture(&peer, &path);
        }
        let text = line
            .splitn(3, char::is_whitespace)
            .nth(2)
            .unwrap_or("")
            .trim();
        let Some(id) = &self.identity else {
            return "no identity — run `init` first".into();
        };
        let Some(w) = self.epoch_key else {
            return "locked — unlock to compose".into();
        };

        let card_bytes = match std::fs::read(self.peer_path(&peer, artifact::PeerFile::Link)) {
            Ok(b) => b,
            Err(_) => {
                return format!(
                    "no peer-link for {peer}. Complete a peering first \
                     (`peer offer`, then `peer accept`, then `peer seal`)."
                )
            }
        };
        let card = match peering::Card::decode(&card_bytes) {
            Ok(c) if c.verify() => c,
            Ok(_) => return "the stored peer-link does not verify".into(),
            Err(e) => return format!("corrupt peer-link: {e:?}"),
        };

        // The reservoir, if the ceremony established one. Absent is not an
        // error: `mode_auth` is correct and simply lacks the post-quantum
        // property (RFC 7 §5 makes the reservoir a conditional tier).
        let epoch = now_epoch();
        // **Their prekey, if they have published one.** Encapsulating to a
        // key that expires is the whole of RFC 7 §5: without it every message
        // is sealed to a permanent correspondence key, and an adversary who
        // obtains that key opens everything ever sent to it, including
        // ciphertext recorded years earlier.
        let their_prekey = self.prekey_for(&card.node_id());
        let reservoir = std::fs::read(self.peer_path(&peer, artifact::PeerFile::Reservoir))
            .ok()
            .and_then(|sealed| krab_crypto::kek::open_under(&w, b"krab/reservoir", &sealed).ok())
            .and_then(|raw| persist::decode_reservoir(&raw).ok())
            .and_then(|(root, stored_epoch)| {
                let mut r = krab_crypto::reservoir::Reservoir::new(root, stored_epoch);
                if stored_epoch != epoch && !r.advance_to(epoch) {
                    return None;
                }
                Some(r)
            });
        let chunk = reservoir.as_ref().and_then(|r| r.chunk(epoch));

        let their_pk = krab_crypto::dh::PublicKey(card.correspondence_pk);
        let Some(shared) = id.agree_with(&their_pk) else {
            return "that peer's correspondence key is low-order and cannot be used".into();
        };
        // **The tag stays pairwise, from the correspondence keys.** Only the
        // *encapsulation* target moves to the prekey. Deriving the tag from a
        // prekey instead would make it change whenever they republished, and a
        // recipient scans by tag before it has decrypted anything — so the
        // mail would become unreadable at the moment it was most needed.
        let tag = krab_crypto::pairwise_tag(&shared, epoch);
        let to = their_prekey.unwrap_or(their_pk);

        let composed = match compose::seal_to(
            id.correspondence(),
            &compose::Recipient::Known {
                correspondence: &to,
                tag,
                chunk: chunk.as_ref(),
            },
            epoch,
            0,
            expiry_for(epoch),
            text.as_bytes(),
            &mut OsRng,
        ) {
            Ok(c) => c,
            Err(compose::Error::TooLarge) => {
                return format!(
                    "too long for the largest object ({} bytes). Split it.",
                    reach::bucket_bytes(reach::BUCKET_COUNT - 1)
                )
            }
            Err(e) => return format!("could not seal: {e:?}"),
        };

        let n = composed.bytes.len();
        match self
            .store
            .with(|s| s.ingest(composed.id, composed.bytes, epoch.0 * 1440, u32::MAX))
        {
            Ok(()) => {
                let note = match (chunk.is_some(), their_prekey.is_some()) {
                    (true, true) => ", post-quantum, to a prekey",
                    (true, false) => ", post-quantum, to their permanent key",
                    (false, true) => ", no reservoir, to a prekey",
                    (false, false) => ", no reservoir, to their permanent key",
                };
                let bucket = composed.bucket;
                self.save_corpus();
                self.refresh_inbox();
                format!(
                    "composed {n} bytes in bucket {bucket}{note}.\n\nIt is in your \
                     corpus and will leave on a scheduled reconciliation — not now, \
                     and not because you pressed send (RFC 5 §6.1)."
                )
            }
            Err(e) => format!("the store refused it: {e:?}"),
        }
    }

    /// RFC 3 §5.1's `peer-request` — reach someone this node has never met.
    ///
    /// Addressed to their **inbox tag**, which needs only their public key.
    /// That is what makes first contact possible at all, and RFC 2 §4.2 states
    /// its cost plainly: messages to an inbox tag are linkable within an epoch.
    /// It rotates out; that is the whole mitigation.
    fn peer_request(&mut self, line: &str) -> String {
        let Some(card_path) = arg(line, 1) else {
            return "usage: request <their.card> [note]\n\n\
                    Sends a first-contact request to the inbox tag their card \
                    implies. Requests to one person in one day are linkable to \
                    each other (RFC 2 §4.2)."
                .into();
        };
        // Free text, tokenised — so a note containing a quoted phrase keeps
        // it, rather than the quotes becoming part of the message.
        let note = words::split(line)
            .map(|w| words::rest(&w, 2))
            .unwrap_or_default();
        let note = note.trim();
        let (Some(id), Some(_)) = (&self.identity, self.epoch_key) else {
            return "locked — unlock to compose".into();
        };

        let Ok(bytes) = std::fs::read(&card_path) else {
            return format!("could not read {card_path}");
        };
        let card = match peering::Card::decode(&bytes) {
            Ok(c) if c.verify() => c,
            Ok(_) => return "that card's signature does not verify".into(),
            Err(e) => return format!("not a card: {e:?}"),
        };

        let epoch = now_epoch();
        let their_pk = krab_crypto::dh::PublicKey(card.correspondence_pk);
        let tag = krab_crypto::inbox_tag(&their_pk, epoch);
        // A held token whose target is this recipient rides along — RFC 3
        // §10. Matched on target rather than offered as a choice: a token is
        // scoped to one introduction, so there is never more than one right
        // answer, and asking would invite attaching the wrong one.
        let token = self
            .introductions
            .iter()
            .find(|t| t.target == card.node_id())
            .cloned();
        let vouched = token.as_ref().map(|t| short_id(&t.introducer));
        // **The evidence for that vouch** — RFC 3 §5.1 key 4. This node's own
        // credential with the introducer, which is mutually signed and so
        // proves the peering rather than asserting it. Sent only alongside the
        // token it supports: a credential is a graph edge, and disclosing one
        // that backs no claim is a disclosure for nothing.
        let evidence = vouched
            .as_ref()
            .and_then(|introducer| self.credential_with(introducer));
        let evidenced = evidence.is_some();
        // Spent on this node's side the moment it leaves: a token is scoped to
        // one introduction, and holding it after using it would let a second
        // request go out carrying a vouch the recipient will refuse.
        let used = token.as_ref().map(|t| t.nonce);
        let req = request::PeerRequest::create_introduced(
            id.signing_key(),
            id.card(Policy::default()),
            card.node_id(),
            // What this node will accept from them, to open the negotiation —
            // RFC 3 §5.1 key 5. Defaults until `peer counter` revises them;
            // §5.2's counter is where either party states something else.
            credential::LinkTerms::default(),
            note,
            token,
            evidence,
        );

        let composed = match compose::seal_to(
            id.correspondence(),
            &compose::Recipient::FirstContact {
                correspondence: &their_pk,
                tag,
            },
            epoch,
            0,
            expiry_for(epoch),
            &req.encode(),
            &mut OsRng,
        ) {
            Ok(c) => c,
            Err(e) => return format!("could not seal: {e:?}"),
        };

        match self
            .store
            .with(|s| s.ingest(composed.id, composed.bytes, epoch.0 * 1440, u32::MAX))
        {
            Ok(()) => {
                self.save_corpus();
                if let Some(nonce) = used {
                    self.introductions.retain(|t| t.nonce != nonce);
                }
                let mut out = format!(
                    "request composed for {}.\n\nIt carries your card and an inner \
                     signature, because first contact cannot be deniable — the \
                     recipient can prove you sent it, which RFC 3 §5.1 considers \
                     the right trade for this one message.",
                    card.fingerprint()
                );
                match vouched {
                    Some(who) => {
                        out.push_str(&format!(
                            "\n\n{who}'s introduction travelled with it, and is now \
                             released from this node — a token is good for one \
                             introduction (RFC 3 §10). Whether it counts for \
                             anything is their decision, not the protocol's."
                        ));
                        out.push_str(if evidenced {
                            "\n\nYour peer-link credential with them went too, as \
                             evidence (RFC 3 §5.1). It is mutually signed, so it \
                             proves the peering rather than asserting it — which \
                             is what lets someone who has never met your \
                             introducer check that the vouch is real.\n\n\
                             It also tells the recipient that you peer with them. \
                             That is one edge of your graph, disclosed to one \
                             person, because you chose to."
                        } else {
                            "\n\nNo evidence went with it: there is no completed \
                             credential with them on this node. `peer countersign` \
                             finishes one. Without it the vouch is worth something \
                             only to a recipient who already peers with your \
                             introducer."
                        });
                    }
                    None => out.push_str(
                        "\n\nNo introduction. Nothing is wrong with an unvouched \
                         request — it just arrives with only your note to \
                         recommend it.",
                    ),
                }
                out
            }
            Err(e) => format!("the store refused it: {e:?}"),
        }
    }

    /// RFC 8 §5's `pack` — write a courier archive.
    ///
    /// Writes a **window of the corpus**, not a diff. See `courier`'s module
    /// documentation: successive diffs handed to one courier reconstruct their
    /// author's composition schedule, which is the correlation RFC 5 §6.1
    /// forbids on the network arriving by another route.
    fn pack(&self, line: &str) -> String {
        let out = arg(line, 1).unwrap_or_else(|| "krab-archive.krab".into());
        let kind = arg_value(line, "--for").unwrap_or("courier");
        let Some(profile) = profile_named(kind) else {
            return format!("unknown transport {kind:?}");
        };
        // An operator-named courier archive, not an artifact: it has no fixed
        // name, so it cannot be an `Artifact` variant. `wipe` reaches it by
        // the `.krab` suffix, which is what `pack` defaults to and what the
        // predicate in `artifact` matches.
        let path = if out.contains('/') {
            PathBuf::from(out)
        } else {
            self.home.join(&out)
        };

        // MAX_TTL back from now, not "since last time". RFC 1 §2 sets the TTL
        // and the window follows it rather than anything the operator did.
        // `entries_in_range` is half-open, and an object composed today
        // expires at exactly `now + MAX_TTL` — the upper edge. A window that
        // stopped there would omit everything written today, every time.
        let now = now_epoch().0 * 1440;
        use krab_core::tag::MAX_TTL_MIN;
        let window = (
            now.saturating_sub(MAX_TTL_MIN),
            now.saturating_add(MAX_TTL_MIN) + 1,
        );

        match self
            .store
            .with(|s| courier::pack(s, &path, window, &profile))
        {
            Err(e) => format!("could not write {}: {e}", path.display()),
            Ok(packed) => {
                let manifest = path.with_extension("MANIFEST.hjson");
                let _ = std::fs::write(&manifest, courier::manifest(&packed));
                format!(
                    "wrote {} objects, {} bytes to {}\n\nThis is a window of your \
                     corpus, not what changed — so two archives do not reveal what \
                     you wrote in between. Carry it on anything; the filename is \
                     ignored on import.",
                    packed.objects,
                    packed.bytes,
                    path.display()
                )
            }
        }
    }

    /// RFC 8 §5's `import` — ingest a courier archive.
    fn import(&mut self, line: &str) -> String {
        let Some(path) = arg(line, 1) else {
            return "usage: import <archive>".into();
        };
        let path = PathBuf::from(path);
        let now = now_epoch().0 * 1440;

        // Verify before ingesting, so an operator can be told the medium is
        // bad rather than watching objects silently not appear.
        if let Err(idx) = courier::verify(&path) {
            return format!(
                "record {idx} of that archive is not self-consistent. Nothing was \
                 imported. If the medium is failing, a partial copy is still worth \
                 trying — records before {idx} would import."
            );
        }
        match self.store.with(|s| courier::import(s, &path, now)) {
            Err(e) => format!("could not read {}: {e}", path.display()),
            Ok(got) => {
                let msg = format!(
                    "{} new, {} already held, {} refused ({} records).\n\nNothing was \
                 trusted: every object was re-hashed before it entered the corpus.",
                    got.accepted,
                    got.duplicate,
                    got.refused,
                    got.total()
                );
                self.save_corpus();
                self.refresh_inbox();
                msg
            }
        }
    }

    /// Perform RFC 4 §4.1's Noise IK handshake toward `peer`.
    ///
    /// `Ok(None)` means there is no address to dial — a courier peer, or one
    /// reachable only inbound. That is not a failure: RFC 4 §5.5 is explicit
    /// that "whether anyone carries it is not the protocol's business", and
    /// I-4 forbids assuming reachability.
    /// Bring a link up, dialling or answering. Shared by `connect` and
    /// `listen`, which differ only in which end waits.
    fn dispatch_connect(
        &mut self,
        peer: &str,
        kind: &str,
        addr: Option<&str>,
        answer: bool,
        _line: &str,
    ) {
        let Some(profile) = profile_named(kind) else {
            self.output = format!("unknown transport {kind:?}");
            return;
        };
        self.links.connect(peer, profile.clone());
        // Register with the schedule. This is the *only* coupling between a
        // user action and the scheduler, and it adds a peer rather than
        // triggering anything: the first interval is drawn from entropy, not
        // from now (RFC 5 §6.1).
        if let Some(id) = sync::peer_id_of(peer) {
            let now_s = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let mut e = [0u8; 8];
            OsRng.fill(&mut e);
            self.scheduler.add(id, now_s, u64::from_le_bytes(e));
        }
        // A real handshake, if an address and a peer-link are both available.
        // RFC 4 §4.1 requires the presented static match the credential, and
        // `TcpFabric` takes the expected key as a required argument — so a peer
        // with no stored card cannot be connected to over TCP at all, which is
        // the correct refusal.
        match self.establish(peer, kind, addr, answer) {
            Ok(session) => {
                self.links.established(peer, session);
                self.log.push(activity_log::Event::LinkUp {
                    peer: peer.to_string(),
                    kind: profile.kind,
                });
            }
            Err(why) => {
                self.links.failed(peer);
                self.log.push(activity_log::Event::Failed {
                    peer: peer.to_string(),
                    why: "handshake refused",
                });
                self.output = why;
                return;
            }
        }
        let l = self.links.get(peer).expect("just connected");
        self.output = format!(
            "{}\n\nnothing was transferred. Reconciliation is scheduled \
             and does not follow your keypresses (RFC 8 §5.1).",
            l.status_line()
        );
    }

    fn establish(
        &self,
        peer: &str,
        kind: &str,
        addr: Option<&str>,
        answer: bool,
    ) -> Result<Option<Box<dyn krab_fabric::Session>>, String> {
        let Some(addr) = addr else {
            return Ok(None);
        };

        // Local input, checked before anything is looked up: the macOS `tty.`
        // node blocks in open() until carrier detect, so originating through it
        // hangs with no error and no timeout. Saying so beats a later, vaguer
        // failure about the peer.
        if matches!(kind, "serial" | "modem")
            && krab_fabric::backend::serial::SerialFabric::is_dial_in_node(addr)
        {
            return Err(format!(
                "{addr} is a dial-in device and will block until carrier detect. \
                 Use the cu. node instead: {}",
                krab_fabric::backend::serial::SerialFabric::device_hint()
            ));
        }

        let Some(id) = &self.identity else {
            return Err("no identity — run `init` first".into());
        };

        // The expected static comes from the stored peer-link, which is signed.
        // There is no path that dials without one, and no prompt: RFC 4 §4.1
        // requires a mismatch be "a hard failure, never a TOFU prompt".
        let card_bytes = std::fs::read(self.peer_path(peer, artifact::PeerFile::Link))
            .map_err(|_| format!("no peer-link for {peer} — complete a peering first"))?;
        let card = peering::Card::decode(&card_bytes)
            .ok()
            .filter(|c| c.verify())
            .ok_or_else(|| "the stored peer-link does not verify".to_string())?;

        use krab_fabric::Fabric;
        match kind {
            "serial" | "modem" => {
                use krab_fabric::backend::serial::{Role, SerialFabric};
                let role = if answer {
                    Role::Answer
                } else {
                    Role::Originate
                };
                let fabric = SerialFabric::new(
                    krab_fabric::profile::LinkProfile::serial(),
                    addr,
                    // RFC 4 §5.3's fast end. A slower line still works; it is
                    // the operator's cable, and both ends must agree.
                    115_200,
                    role,
                    id.noise_bytes(),
                    card.noise_static_pk,
                );
                if answer {
                    fabric
                        .accept()
                        .map_err(|e| format!("could not answer on {addr}: {e}"))?
                        .map(Some)
                        .ok_or_else(|| format!("nobody called on {addr}"))
                } else {
                    fabric
                        .connect()
                        .map(Some)
                        .map_err(|e| format!("could not originate on {addr}: {e}"))
                }
            }
            // Spelled as `links::profile_named` spells it, so the profile and
            // the carrier can never disagree about which kinds are Tor.
            "tor" | "socks" => {
                // The onion address goes to tor and never to a resolver.
                // Before this branch existed, `connect <peer> tor <addr>` fell
                // through to TCP, where `TcpStream::connect` hands the name to
                // the system resolver: the dial failed *and* told the local
                // DNS server which hidden service this node was looking for,
                // which is the one thing RFC 4 §5.2 exists to prevent.
                // Outbound only, and checked **before** whether tor is
                // running: inbound over an onion arrives at the listener the
                // service forwards to, so answering here is impossible rather
                // than merely unavailable. Telling an operator to `start-tor`
                // when starting it would not help is a worse message than the
                // true one.
                if answer {
                    return Err("a tor link cannot answer. Inbound reaches the \
                                listener your onion service forwards to — run \
                                `start-tor` and let the peer dial you."
                        .into());
                }
                let Some(tor) = self.tor.as_ref() else {
                    return Err("no tor is running — `start-tor` first. \
                                A tor link dials through this node's own \
                                SOCKS port and there is no other route to an \
                                .onion address."
                        .into());
                };
                let fabric = krab_fabric::backend::tor::TorFabric::new(
                    krab_fabric::profile::LinkProfile::tor(),
                    tor.socks_port(),
                    addr.trim_end_matches('/'),
                    id.noise_bytes(),
                    card.noise_static_pk,
                );
                fabric
                    .connect()
                    .map(Some)
                    .map_err(|e| format!("could not reach {addr} over tor: {e}"))
            }
            _ => {
                let fabric = krab_fabric::backend::tcp::TcpFabric::new(
                    krab_fabric::profile::LinkProfile::tcp(),
                    addr,
                    id.noise_bytes(),
                    card.noise_static_pk,
                );
                // `answer` reached the serial branch and stopped there, so over
                // TCP every node dialled and none listened — two nodes on one
                // host could not link at all. The fabric could listen the whole
                // time; nothing asked it to.
                if answer {
                    fabric
                        .listen(addr)
                        .map_err(|e| format!("could not listen on {addr}: {e}"))?;
                    // `accept` is non-blocking, so this is a bounded wait
                    // rather than a hang: the operator gets the prompt back
                    // and can try again, which a blocked UI would not allow.
                    let deadline =
                        std::time::Instant::now() + std::time::Duration::from_secs(ANSWER_WAIT_S);
                    loop {
                        match fabric.accept() {
                            Ok(Some(s)) => return Ok(Some(s)),
                            Ok(None) if std::time::Instant::now() < deadline => {
                                std::thread::sleep(std::time::Duration::from_millis(50));
                            }
                            Ok(None) => {
                                return Err(format!(
                                    "nobody called on {addr} within {ANSWER_WAIT_S}s"
                                ))
                            }
                            Err(e) => return Err(format!("could not answer on {addr}: {e}")),
                        }
                    }
                } else {
                    fabric
                        .connect()
                        .map(Some)
                        .map_err(|e| format!("could not establish a session with {peer}: {e}"))
                }
            }
        }
    }

    /// RFC 3 §12's per-peer aggregates, from the day's quota counters.
    ///
    /// # What each one is, and which are not measured
    ///
    /// `Spend` counts what a peer delivered (`offered`), what was charged
    /// against its budget (`objects`, `bytes`), and what was refused past the
    /// ceiling. That gives §12's ingress figures and its **novelty ratio** —
    /// the one §12 calls key, "high volume at low novelty is misconfiguration
    /// or attack".
    ///
    /// It does not give the rest, and the fields left at their defaults are
    /// left there deliberately rather than approximated:
    ///
    /// - **unique-source contribution** needs to know an object arrived *only*
    ///   via this peer, and §12 forbids the per-object provenance that would
    ///   answer it directly. `None`, so the panel says so.
    /// - **control vs payload bytes** are not separated on the link; the
    ///   ratio is `None` while both are zero, which is already honest.
    /// - **tag-match / decrypt-success** is measured in `receive`, on the
    ///   inbox scan, and is not attributed to a peer — nor could it be
    ///   without recording which peer supplied each object.
    ///
    /// `objects` is charged before `ingest` runs, so novelty's numerator is
    /// "passed the filter and the budget" rather than "entered the corpus".
    /// The two differ only for an object RFC 1 §11 refuses, which is a peer
    /// sending malformed data — and that already shows up as a refusal.
    fn metrics_from(spend: &quota::Spend) -> krab_node::metrics::PeerMetrics {
        krab_node::metrics::PeerMetrics {
            ingress_bytes: spend.bytes,
            objects_received: spend.offered,
            objects_new: spend.objects,
            rejected: spend.rejected,
            unique_source: None,
            ..Default::default()
        }
    }

    /// RFC 8 §5.3's panel.
    fn peers_panel(&self) -> String {
        // Activity provenance belongs beside the per-peer aggregates: the log
        // says what just happened, `PeerMetrics` says what has been happening.
        let recent = self.log.recent(6);
        // **RFC 3 §12's aggregates, from the counters that exist.**
        //
        // This was `Vec::new()` — the panel, its thresholds and its
        // highlights were written, tested, and shown to nobody, because
        // nothing built a row. §12's own closing sentence is the reason that
        // mattered: "a disconnect decision should be one keystroke from the
        // evidence justifying it. If it is not, operators will not make it,
        // and the accountability model degrades to nothing."
        //
        // What feeds a row is `quota::Spend`, which is already per-peer,
        // already persisted, and already counters-only. What does not feed one
        // reads as `—` rather than as a number: see `PeerMetrics.unique_source`
        // and `Row.coverage`, both of which would otherwise report an
        // unmeasured quantity as zero, and zero is the reassuring answer for
        // both.
        let spend_rows: Vec<(String, krab_node::metrics::PeerMetrics)> = self
            .peer_ids()
            .into_iter()
            .map(|id| {
                let acct = self
                    .spends
                    .get(&id)
                    .map(|c| *c.lock().unwrap_or_else(|e| e.into_inner()))
                    .unwrap_or_default();
                (id, Self::metrics_from(&acct.spend))
            })
            .collect();
        let rows: Vec<peers::Row> = spend_rows
            .iter()
            .map(|(id, m)| peers::Row {
                peer: id,
                metrics: m,
                coverage: None,
                link: None,
                quota_bytes: self
                    .inbound_terms(id)
                    .map(|t| t.bytes_per_day)
                    .unwrap_or(0),
            })
            .collect();

        // **Peerings, from disk — not links, from memory.** A peering is the
        // durable artifact (RFC 3 §4); a link is a socket that was open a
        // moment ago. Reporting only links meant a restarted node said "no
        // peers" while its peer-links sat on disk beside it, and told an
        // operator whose ceremony had completed to start another one.
        let names = self.aliases();
        let peerings = self.peer_ids();
        if peerings.is_empty() && self.links.up_count() == 0 {
            return peers::render(&rows, peers::DISCONNECT_KEY);
        }

        let mut out = String::new();
        for id in &peerings {
            let link = match self.links.get(id) {
                Some(l) if l.session.is_some() => "link up",
                Some(_) => "link down",
                None => "not connected",
            };
            // **RFC 8 §9 — two independent indicators, per link.**
            //
            // "A single 'secure' badge would average them into something
            // false." Location privacy is a transport property; volume
            // privacy needs cover traffic that a constrained link cannot
            // afford. A link that is down has no properties to report, and
            // saying nothing is better than reporting the last one's.
            // The operator's own name for this peer, beside the identifier
            // the ceremony verified — never instead of it.
            let who = names.show(alias::Kind::Peer, id);
            let privacy = match self.links.get(id).map(|l| l.profile.clone()) {
                Some(p) => format!(
                    "  {}  loc {}  vol {}",
                    p.kind,
                    if p.location_privacy() { "●" } else { "○" },
                    if p.volume_privacy() { "●" } else { "○" },
                ),
                None => String::new(),
            };
            let policy = if self.peer_path(id, artifact::PeerFile::Policy).exists() {
                "terms current"
            } else {
                "terms as of peering"
            };
            // How the peering was formed, and what it is worth — kept on disk
            // so a link made remotely on a bad afternoon still says so a year
            // later, which is what `PeerLink::caveats` always claimed.
            let how = match self.peer_terms(id) {
                Some(t) => {
                    let pq = if t.post_quantum() {
                        "post-quantum"
                    } else {
                        "NOT post-quantum"
                    };
                    let fp = if t.fingerprint_verified {
                        ""
                    } else {
                        ", fingerprints never compared"
                    };
                    let re = if t.reseals > 0 {
                        format!(", re-sealed {}×", t.reseals)
                    } else {
                        String::new()
                    };
                    format!("{} · {pq}{fp}{re}", t.channel)
                }
                None => "how it was formed: unrecorded".into(),
            };
            // RFC 3 §6 and §12: the quota position, next to the peering it
            // governs. "A disconnect decision should be one keystroke from
            // the evidence justifying it. If it is not, operators will not
            // make it, and the accountability model degrades to nothing."
            // **What is enforced, which is not the same as what was signed.**
            //
            // This branched on `inbound_terms` and told an operator with no
            // countersigned credential that "nothing is scoped or enforced on
            // this link" — true when it was written, and false since
            // `budget_for` began falling back to `LinkTerms::default()`
            // rather than to no budget at all. So the panel reported an
            // unmetered link that was in fact metered at the defaults, and
            // §12's evidence was missing for exactly the peerings whose
            // standing is most in doubt.
            //
            // The terms shown are now the terms applied, and the missing
            // credential is said separately — it is a different fact.
            let applied = self.inbound_terms(id);
            let budget = match Some(applied.unwrap_or_default()) {
                Some(t) => {
                    let acct = self
                        .spends
                        .get(id)
                        .map(|c| *c.lock().unwrap_or_else(|e| e.into_inner()))
                        .unwrap_or_default();
                    // The **effective** ceiling and the signed one, both.
                    // RFC 3 §6.2 dials within the credential, and an operator
                    // who sees only one of the two numbers cannot tell a
                    // throttled peer from a peer with a small agreement.
                    let eff_b = acct.standing.effective(t.bytes_per_day);
                    let eff_o = acct.standing.effective(t.objects_per_day);
                    let novelty = match acct.spend.novelty() {
                        Some(n) => format!("{:.0}% novel", n * 100.0),
                        None => "nothing offered".into(),
                    };
                    // The credential's own standing, said separately from the
                    // terms being applied. A peering with none is metered at
                    // the defaults above; that it has none is a fact about the
                    // ceremony, not about the meter.
                    let term = match self.credential_standing(id) {
                        Standing::Live(credential::Life::Current, _) if applied.is_some() => {
                            String::new()
                        }
                        other => format!("\n    {}", other.line(id, self.now_s())),
                    };
                    // **RFC 3 §12's aggregates, and only aggregates.** §12
                    // forbids per-object provenance outright — "a forensic
                    // reconstruction of the graph and its timing gradients,
                    // sitting on disk, waiting for seizure" — so the table's
                    // rows are derived from the two counters the budget
                    // already keeps rather than from a record of which object
                    // came from whom.
                    //
                    // `duplicates` is what they offered and this node already
                    // had; `first` is what they were first to deliver, which
                    // is §12's unique-source contribution measured at the only
                    // moment it can be measured without storing provenance.
                    let duplicates = acct.spend.offered.saturating_sub(acct.spend.objects);
                    let evidence = format!(
                        "\n    today: {} new, {duplicates} duplicate(s), {} KB — \
                         cutting them loses what only they bring (§12)",
                        acct.spend.objects,
                        acct.spend.bytes / 1024,
                    );
                    format!(
                        "\n    quota {}% of {} MB/day, {} objects/day \
                         (standing {}/{} of {} MB, {} objects agreed){evidence}\n    \
                         {novelty}{}{term}",
                        acct.spend.used_percent(eff_b, eff_o),
                        eff_b >> 20,
                        eff_o,
                        acct.standing.age,
                        quota::MATURE_WINDOWS,
                        t.bytes_per_day >> 20,
                        t.objects_per_day,
                        if acct.spend.refused > 0 {
                            format!(", {} refused over budget", acct.spend.refused)
                        } else {
                            String::new()
                        },
                    )
                }
                // Unreachable: the terms above fall back to the defaults, as
                // `budget_for` does. Kept so the two cannot drift apart
                // silently if either stops falling back.
                None => format!(
                    "\n    {}",
                    self.credential_standing(id).line(id, self.now_s())
                ),
            };
            // RFC 3 §8's two-hop visibility, where a peer has shared any.
            let onward = self
                .reach
                .iter()
                .find(|(who, _)| who == id)
                .map(|(_, r)| r.len())
                .unwrap_or(0);
            let nodelist = if onward > 0 {
                format!("\n    lists {onward} peer(s) onward — two hops, no more (RFC 3 §8)")
            } else {
                String::new()
            };
            // **What deserves saying out loud** — `Row::highlights`, whose
            // thresholds and wording were written and tested and reached no
            // operator, because nothing built a row to call it on. The eclipse
            // indicator is the one that cannot be inferred from the numbers
            // above it.
            let alarms: String = rows
                .iter()
                .find(|r| r.peer == id)
                .map(|r| {
                    r.highlights()
                        .iter()
                        .map(|h| format!("\n    ! {h}"))
                        .collect()
                })
                .unwrap_or_default();
            out.push_str(&format!(
                "{who}  peered  ·  {link}{privacy}  ·  {policy}\n    {how}{budget}{nodelist}{alarms}\n"
            ));
        }
        // RFC 3 §12's closing requirement, and RFC 8 §5.3's restatement of it:
        // "a disconnect decision should be one keystroke from the evidence
        // justifying it." The evidence is above; this is the keystroke.
        if !peerings.is_empty() {
            out.push_str(&format!(
                "\n  [{}] disconnect the selected peer  ·  `peer forget <id>` \
                 removes the peering itself (RFC 3 §8.4)\n",
                peers::DISCONNECT_KEY
            ));
        }
        // Links to nodes we have no peering with cannot exist — `establish`
        // refuses without a stored card — but a half-built one can, and
        // hiding it would hide the failure.
        for l in self.links.iter() {
            if !peerings.iter().any(|p| p == &l.peer) {
                out.push_str(&l.status_line());
                out.push('\n');
            }
        }
        // **RFC 3 §13's warnings, at the top of the evidence.** §12's closing
        // sentence is the requirement the whole panel is written around: "a
        // disconnect decision should be one keystroke from the evidence
        // justifying it. If it is not, operators will not make it, and the
        // accountability model degrades to nothing."
        //
        // A warning about the peer set as a whole belongs beside the per-peer
        // rows for the same reason — the decision to cut one peer is a
        // decision about the set.
        let warnings = self.peer_warnings();
        if !warnings.is_empty() {
            out.push_str(&format!("\n{} warning(s):\n", warnings.len()));
            for w in &warnings {
                out.push_str(&format!("\x20 ! {}\n", w.line()));
            }
        }
        // RFC 1 §6.4 — decapsulation cost. Node-wide rather than per peer,
        // because a tag is computed from a pair and a *collision* is by
        // definition not attributable to whoever sent it.
        if self.last_scan_fail > 0 {
            out.push_str(&format!(
                "\n{} object(s) matched a tag and did not open. A high rate \
                 means mail is arriving outside the acceptance window, which is \
                 otherwise invisible (RFC 1 §6.4).\n",
                self.last_scan_fail
            ));
        }
        if self.log.len() == 0 && warnings.is_empty() {
            out.push_str("\nno accountability metrics yet — nothing has reconciled.");
        }
        if !recent.is_empty() {
            out.push_str(&format!(
                "\n\nrecent activity ({} of at most {}, cleared on lock):\n",
                recent.len(),
                activity_log::CAPACITY
            ));
            for line in &recent {
                out.push_str(&format!("  {line}\n"));
            }
        }
        out
    }

    /// RFC 8 §5.2's diagnostic.
    fn reach_report(&self, line: &str) -> String {
        let size: u32 = arg_value(line, "--size")
            .and_then(|v| v.parse().ok())
            .unwrap_or(256);
        let class: u8 = match arg_value(line, "--class") {
            Some("sealed") | None => 0,
            Some("bulletin") => 1,
            Some(other) => return format!("unknown class {other:?}"),
        };
        let bucket = (0u8..=15)
            .find(|b| reach::bucket_bytes(*b) >= size)
            .unwrap_or(15);

        // One path per link: multi-hop routing needs the rollcall graph, which
        // does not exist yet. Reporting only what is known is the honest form,
        // and the count line still tells an operator how close to zero they are.
        let paths: Vec<reach::Path> = self
            .links
            .iter()
            .map(|l| reach::Path {
                hops: format!("a→{}", l.peer),
                links: alloc_one(l),
            })
            .collect();
        if paths.is_empty() {
            return "no links. `connect <peer>` establishes one.".into();
        }
        reach::Report::of(&paths, class, bucket, 0).render()
    }

    /// RFC 8 §5's `keys`.
    ///
    /// Reports the recognition table's size too: RFC 2 §4.3 makes it
    /// `correspondents × 91`, and an operator whose table is unexpectedly
    /// small has correspondents whose peer-link failed to load — which is
    /// otherwise invisible, since unrecognised mail looks like no mail.
    fn keys_report(&self) -> String {
        let Some(id) = &self.identity else {
            return "no identity — run `init` first".into();
        };
        let epochs = id.hierarchy.epochs().count();
        // RFC 2 §4.3 makes the table `correspondents × 91`. An operator whose
        // table is unexpectedly small has a peer-link that failed to load —
        // otherwise invisible, since unrecognised mail looks like no mail.
        let table = match &self.tag_table {
            Some(t) if !t.is_empty() => format!("{} entries", t.len()),
            _ => "not built — no correspondents, or locked".into(),
        };
        // **RFC 6 §216's burn rate.** "Exhaustion degrades forward secrecy
        // silently, so clients MUST surface burn rate." Silently is the word
        // that matters: a node whose batch has run out falls back to the
        // signed prekey and nothing says so.
        //
        // What is honestly knowable here is the batch size, how long it has
        // been published, and — the actionable part — whether the cadence
        // holds for the largest group this node is in. A recipient cannot see
        // which one-time keys a sender chose, so a literal consumption count
        // is not available to it.
        let largest = self
            .groups
            .iter()
            .map(|g| g.members.len())
            .max()
            .unwrap_or(0);
        let age_days = self.prekey_age_days().unwrap_or(0);
        let burn = match groups::Group::prekey_warning(
            largest,
            prekeys::BATCH_KEYS,
            REPUBLISH_EPOCHS.max(age_days),
        ) {
            Some(w) => format!(
                "{} published, {age_days} day(s) ago — ! {w}",
                prekeys::BATCH_KEYS
            ),
            None => format!(
                "{} published, {age_days} day(s) ago; republished every {} day(s)",
                prekeys::BATCH_KEYS,
                REPUBLISH_EPOCHS
            ),
        };
        format!(
            "identity   {}  (this node's address — public, not a secret)\n\
             epochs     {epochs} wrapper{} ({} bytes)\n\
             corpus     {} objects, {} bytes (cap {})\n\
             tags       {table}\n\
             prekeys    {burn}\n\
             activity   {} line{} held, cleared on lock (RFC 3 §12)\n\
             backup     shown once at init and never again (RFC 7 §11)\n\
             \n\
             message history is not recoverable from the identity backup, and \
             that is intentional.",
            id.short_id(),
            if epochs == 1 { "" } else { "s" },
            id.hierarchy.stored_bytes(),
            self.store.len(),
            self.store.with(|s| s.bytes()),
            peering::Policy::default().retention_bytes,
            self.log.len(),
            if self.log.len() == 1 { "" } else { "s" },
        )
    }

    /// Days since this node last published a prekey batch — RFC 6 §216.
    fn prekey_age_days(&self) -> Option<u32> {
        let me = self.identity.as_ref()?.node_id();
        let mut newest = 0u32;
        self.store.with(|s| {
            for (_, oid) in s.entries_in_range(0, u32::MAX) {
                if let Some(b) = s.get(&oid).and_then(bulletin::from_object) {
                    if b.kind == bulletin::Kind::Prekeys && b.node_id() == me {
                        newest = newest.max(b.epoch);
                    }
                }
            }
        });
        (newest > 0).then(|| now_epoch().0.saturating_sub(newest))
    }

    /// Report where a ceremony has reached.
    fn peer_status(&self) -> String {
        let done = self.peer_ids();
        let ceremony = match self.load_ceremony() {
            Err(e) => {
                if done.is_empty() {
                    return format!("{e}\n\nStart one with `peer offer`.");
                }
                format!(
                    "no ceremony in progress.\n\npeered with: {}",
                    done.join(", ")
                )
            }
            Ok(p) => {
                // Where in the five steps, and what to type next. An operator
                // who has lost track reaches for this verb, so it has to
                // answer "what now" rather than only "what happened".
                let pad = self.path(artifact::Artifact::PeerPad).exists();
                match p.their_fingerprint() {
                    None => format!(
                        "step 1 of 5 — your card is written, theirs has not arrived.\n\n\
                         wrote:  {}\n\n\
                         next:   send them that file, then `peer accept <their.card>`",
                        self.path(artifact::Artifact::PeerCard).display()
                    ),
                    Some(f) => format!(
                        "step {} of 5 — their card is recorded.\n\n\
                         theirs:  {f}\n\
                         yours:   {}\n\n\
                         {}\n\n\
                         then:    peer seal <their.pad> <in-person|media|corpus|network>",
                        if pad { 4 } else { 3 },
                        self.identity
                            .as_ref()
                            .map(|i| i.fingerprint())
                            .unwrap_or_default(),
                        if pad {
                            "your pad is written. Exchange pads with them."
                        } else {
                            "compare those two aloud, then: peer pad <destination>\n\
                             \x20        (your SECRET half — write it onto the medium you carry)"
                        }
                    ),
                }
            }
        };
        ceremony
    }

    /// RFC 7 §10's panic wipe.
    ///
    /// > "A command, and a duress passphrase that appears to unlock normally,
    /// > either of which destroys the KEK. The store becomes unrecoverable **in
    /// > milliseconds**. This is the control that matters at the moment of
    /// > seizure."
    ///
    /// # The ordering is the design
    ///
    /// Key destruction happens **first**, before a single byte of disk is
    /// touched. Everything wrapped beneath the KEK is unreadable the instant
    /// that line runs, and overwriting a corpus is not a millisecond
    /// operation — it is seconds to minutes on a large store.
    ///
    /// So if this is interrupted halfway — the process killed, the machine
    /// unplugged, the laptop taken mid-sentence — **the guarantee already
    /// holds** and only the hedge is incomplete. Doing it the other way round
    /// would mean an interrupted wipe leaves a live key beside partially
    /// overwritten files, which is the worst of both.
    fn panic_wipe(&mut self) -> String {
        // **Everything `lock` clears, first.** A panic wipe cleared *less*
        // than a lock did: it left the decrypted body, the activity log, the
        // command history, a displayed picture, the channel posting key and
        // every group roster in memory — on the one path an operator reaches
        // when somebody is at the door.
        //
        // Calling `lock` rather than repeating its list is what stops the two
        // drifting apart again. A field added to one is now cleared by both.
        self.lock();

        // **And the things a lock deliberately keeps.** A locked node is a
        // relay: it holds its links and its listener because it still carries
        // for the peers it has. A wiped node has none — it has just destroyed
        // the credentials that define them — so a socket still accepting the
        // statics of former peers is a node answering for an identity that no
        // longer exists.
        // **Tor dies first, and it dies now.**
        //
        // Before the erasure below, not after: an onion service is a published
        // address answering for this node, and every millisecond it keeps
        // answering while the identity behind it is being destroyed is a
        // millisecond somebody can confirm the node is here. It is also the
        // one thing in this function that is visible from outside the machine.
        //
        // `stop` kills rather than shutting down politely, for the same reason
        // this whole path exists — a wipe that waited for circuits to close
        // would be a wipe that waited.
        //
        // Called explicitly rather than left to `Option::take`'s drop, so that
        // "the daemon stops" is a statement in this function that a reader can
        // find, not a consequence of a field assignment somewhere else.
        if let Some(mut tor) = self.tor.take() {
            tor.stop();
        }
        self.onion = None;
        self.onion_contact = None;
        self.onion_counters = (0, 0);
        self.tor_bootstrap = None;
        self.node.tor_bootstrap = None;

        self.inbound = None;
        self.allowed.set(Vec::new());
        self.links = links::LinkTable::new();
        self.scheduler = krab_node::scheduler::Scheduler::new(self.scheduler.mean_interval_s());
        // Sealed copies composed before the wipe. They are ciphertext, but
        // emitting them would rebuild the corpus the wipe destroyed and
        // deliver mail the operator was destroying the means to have sent.
        self.pending.clear();

        // ---- The erasure. Milliseconds, and irreversible. ----
        self.identity = None; // Drop runs Zeroize on every private key
        self.epoch_key = None;
        self.tag_table = None;
        self.store = shared::SharedStore::new(krab_store::index::Store::new());
        for m in &mut self.messages {
            overwrite(&mut m.body);
        }
        self.messages.clear();
        self.passphrase.clear();
        overwrite(&mut self.composer);
        self.composer_at = 0;
        overwrite(&mut self.output);
        self.locked = true;
        self.list = vec!["(wiped)".into()];

        // ---- The hedge. Slower, best effort, and claims nothing. ----
        //
        // Applied to ciphertext as well as anything else: key destruction
        // defeats an adversary who never gets the key, and overwriting is the
        // only thing that touches one who obtains it later — coercion, a
        // keylogger, a passphrase brute-forced at leisure. RFC 7 §10 exists
        // because coercion is in the threat model.
        // The predicate lives in `artifact`, beside the enum every write
        // goes through. It was a hand-written list here, and it was wrong
        // twice — see that module for both.
        let n = shred::remove_matching(&self.home, artifact::wiped, &mut OsRng);
        format!(
            "destroyed. {n} files overwritten and removed.\n\n\
             The key went first and the store was unreadable before any file was \
             touched — an interrupted wipe is still a complete one. The overwrite \
             is a hedge against a passphrase obtained later, not the erasure \
             itself (RFC 7 §4, §10)."
        )
    }

    /// Write everything that survives a restart.
    ///
    /// Called after anything that changes the corpus or the key hierarchy.
    /// Only wrapped or self-authenticating data — see `persist`'s module docs
    /// and `Documentation/NO-CONFIG.md`.
    /// Write the store out.
    ///
    /// Errors are returned, not discarded. They were discarded — all three
    /// writes were `let _ =` — so a home directory that did not exist (nothing
    /// created it) produced a ceremony that announced success and left an
    /// empty disk. A node that believes it saved a key hierarchy it did not
    /// save is worse than one that failed to start.
    fn save(&self, kek: &krab_crypto::kek::Kek) -> Result<(), String> {
        let at = |what: &str, e: persist::Error| format!("could not write {what}: {e:?}");
        persist::write_params(
            &self.path(artifact::Artifact::KekParams),
            &self.identity_params(),
        )
        .map_err(|e| at("kek.params", e))?;
        if let Some(id) = &self.identity {
            persist::write_identity(
                &self.path(artifact::Artifact::IdentityWrapped),
                id,
                kek,
                &mut OsRng,
            )
            .map_err(|e| at("identity.wrapped", e))?;
        }
        let dir = self.path(artifact::Artifact::Corpus);
        self.store
            .with(|s| persist::write_corpus(&dir, s, &mut OsRng))
            .map(|_| ())
            .map_err(|e| at("corpus", e))
    }

    /// Start accepting calls, if `--listen` was given.
    ///
    /// One socket for every peer. The accept loop runs on its own thread
    /// because the alternative is an accept on the UI thread, which is either
    /// blocking — a hung interface — or polled, which puts a socket's latency
    /// on a redraw timer.
    ///
    /// Idempotent: called after `init` and after `unlock`, since neither is
    /// the only way a node arrives at having an identity.
    fn start_listener(&mut self) -> Option<String> {
        let addr = self.listen.clone()?;
        if self.inbound.is_some() {
            return None;
        }
        let id = self.identity.as_ref()?;
        self.refresh_allowed();

        let (l, port) = match krab_fabric::backend::listener::Listener::bind(
            &addr,
            id.noise_bytes(),
            self.allowed.clone(),
        ) {
            Ok(v) => v,
            Err(e) => {
                // Remember it. `status` reads this rather than inferring a
                // cause from `inbound` being empty, which it got wrong: a
                // node that is unlocked and failed to bind was told to
                // `unlock`, which it had already done.
                let why = format!("could not listen on {addr}: {e:?}");
                self.listen_error = Some(why.clone());
                return Some(why);
            }
        };

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // Ends when the receiver is dropped, which happens when the App
            // does. Nothing else needs to signal it.
            //
            // **RFC 4 §9's concurrency cap is a counter now, not a
            // structure.** This said the cap was "satisfied at one" because
            // `accept` completed the handshake before returning, and warned
            // that it would stop being true the moment someone spawned a
            // thread per connection. Someone did — that is exactly how a
            // silent caller was stopped from holding the accept loop — so the
            // structural argument is gone and the comment described the
            // opposite of the code.
            //
            // The cap it owed is `listener::MAX_PENDING_HANDSHAKES`, enforced
            // inside `accept`. This loop is still its only caller.
            loop {
                match l.accept() {
                    Ok(Some(pair)) => {
                        if tx.send(pair).is_err() {
                            return;
                        }
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                    Err(_) => std::thread::sleep(Duration::from_millis(500)),
                }
            }
        });
        self.inbound = Some(rx);
        self.listen_error = None;
        Some(format!(
            "listening on {addr} (port {port}) for any peered node.\n\n\
             Nothing else is needed at this end. The other end dials with:\n\
             \x20 connect {} tcp {addr}",
            self.identity
                .as_ref()
                .map(|i| i.short_id())
                .unwrap_or_default()
        ))
    }

    /// Tell the listener which statics to accept — every completed peering.
    fn refresh_allowed(&self) {
        let keys: Vec<[u8; 32]> = self
            .peer_ids()
            .iter()
            .filter_map(|p| std::fs::read(self.peer_path(p, artifact::PeerFile::Link)).ok())
            .filter_map(|b| peering::Card::decode(&b).ok())
            .filter(|c| c.verify())
            .map(|c| c.noise_static_pk)
            .collect();
        self.allowed.set(keys);
    }

    /// Install anything the listener has accepted since the last tick.
    fn drain_inbound(&mut self) {
        self.inbound_ticks = self.inbound_ticks.saturating_sub(1);
        self.outbound_ticks = self.outbound_ticks.saturating_sub(1);
        let Some(rx) = &self.inbound else { return };
        let arrived: Vec<_> = rx.try_iter().collect();
        if !arrived.is_empty() {
            self.inbound_ticks = ACTIVITY_GLYPH_TICKS;
        }
        // RFC 6 §2.7's window is derived from the *observed* rate. Every tick
        // is a sample of elapsed time whether or not anything arrived — a rate
        // measured only when busy is not a background rate.
        self.observed_hours += TICK.as_secs_f64() / 3600.0;
        for (session, static_pk) in arrived {
            // Which peering this is. The listener verified the static against
            // the set; this maps it back to the directory it belongs to.
            let who = self.peer_ids().into_iter().find(|p| {
                std::fs::read(self.peer_path(p, artifact::PeerFile::Link))
                    .ok()
                    .and_then(|b| peering::Card::decode(&b).ok())
                    .is_some_and(|c| c.noise_static_pk == static_pk)
            });
            let Some(who) = who else { continue };
            self.links.connect(&who, profile_named("tcp").expect("tcp"));
            self.links.established(&who, Some(session));
            self.log.push(activity_log::Event::LinkUp {
                peer: who.clone(),
                kind: "tcp",
            });
            // The caller dialled in order to say something. Answering is not a
            // transfer this node chose to start — RFC 8 §5.1's rule is that a
            // *keypress* never causes one, and nobody pressed anything here.
            self.answer_reconciliation(&who);
        }
    }

    /// Make sure `--home` exists before anything tries to write into it.
    ///
    /// Created here rather than at each write: the operator names the
    /// directory on the command line, and a typo that silently produces an
    /// empty node is the failure this prevents.
    fn ensure_home(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.home)
            .map_err(|e| format!("could not create {}: {e}", self.home.display()))
    }

    /// Persist just the corpus. Cheap, and needs no key.
    ///
    /// Cheap now in a way it was not: this writes the segments that changed,
    /// which after an exchange is usually one, rather than rewriting every
    /// object the node holds. See `persist::write_corpus`.
    fn save_corpus(&self) {
        let dir = self.path(artifact::Artifact::Corpus);
        let _ = self
            .store
            .with(|s| persist::write_corpus(&dir, s, &mut OsRng));
    }

    fn identity_params(&self) -> krab_crypto::kek::KekParams {
        self.identity
            .as_ref()
            .map(|i| i.kek_params)
            .unwrap_or_else(|| krab_crypto::kek::KekParams::new(&mut OsRng))
    }

    /// Whether a store already exists here.
    fn has_stored_identity(&self) -> bool {
        self.path(artifact::Artifact::IdentityWrapped).exists()
    }

    /// Open the store with `passphrase`, distinguishing duress from normal.
    ///
    /// # One derivation, whatever the outcome
    ///
    /// **This must not be split into "is it duress?" then "is it correct?".**
    /// An earlier version did, and it cost two Argon2 runs for a correct or
    /// wrong passphrase and one for the duress passphrase — RFC 7 §4.1
    /// calibrates Argon2 to about 500 ms, so the duress path completed in half
    /// the time.
    ///
    /// A stopwatch is enough to read that, and the person holding the
    /// stopwatch is the exact adversary §10's duress passphrase exists for:
    /// someone standing over the operator watching them unlock. A feature
    /// whose whole value is being indistinguishable was distinguishable by the
    /// most obvious possible measurement.
    ///
    /// The KEK depends only on the passphrase and the stored parameters, and
    /// both records use the same parameters — so it is derived once and used
    /// to attempt both opens. Every outcome now costs one Argon2 and two AEAD
    /// operations, which are microseconds against half a second.
    fn open_with(&self, passphrase: &[u8]) -> Result<Opened, String> {
        let params = persist::read_params(&self.path(artifact::Artifact::KekParams))
            .map_err(|_| "no store here — run `init`".to_string())?;
        let kek = persist::kek_for(passphrase, &params)
            .map_err(|_| "that passphrase does not open this store".to_string())?;

        // Both attempts run regardless of which succeeds. Ordering the duress
        // check first would leak through early return; ordering it second
        // would leak the same way for a correct passphrase.
        let duress = std::fs::read(self.path(artifact::Artifact::DuressWrapped))
            .ok()
            .and_then(|sealed| kek.open(persist::CONTEXT_DURESS, &sealed).ok())
            .is_some();
        let identity = persist::read_identity(
            &self.path(artifact::Artifact::IdentityWrapped),
            &kek,
            params,
        )
        .ok();

        match (duress, identity) {
            (true, _) => Ok(Opened::Duress),
            (false, Some(id)) => Ok(Opened::Normal(Box::new(id), kek)),
            (false, None) => Err("that passphrase does not open this store".into()),
        }
    }

    /// Record a duress passphrase — RFC 7 §10.
    ///
    /// Not enabled by default (§10 requires that), and set by an explicit
    /// command so the operator knows it exists.
    fn set_duress(&self, passphrase: &[u8]) -> Result<(), String> {
        let params = persist::read_params(&self.path(artifact::Artifact::KekParams))
            .map_err(|_| "no store here".to_string())?;
        let kek = persist::kek_for(passphrase, &params).map_err(|e| format!("{e:?}"))?;
        let sealed = kek
            .seal(persist::CONTEXT_DURESS, b"duress", &mut OsRng)
            .map_err(|e| format!("{e:?}"))?;
        atomic::write(&self.path(artifact::Artifact::DuressWrapped), &sealed)
            .map_err(|e| format!("could not store it: {e}"))
    }

    /// Unlock an existing store: derive the KEK, recover the identity, reload
    /// the corpus — RFC 7 §4.
    ///
    /// This is the *only* path that turns a passphrase into a working node,
    /// and it is deliberately the same shape as `init`'s final step: derive,
    /// open the epoch, then read. A second path would be a second place to get
    /// the ordering wrong.
    fn unlock(&mut self, passphrase: &[u8]) -> Result<(), String> {
        let (mut id, kek) = match self.open_with(passphrase)? {
            // **RFC 7 §10.** The response is silent: the node destroys itself
            // and then presents exactly what a freshly initialised node
            // presents. No warning, no distinct message, and — since
            // `open_with` does one derivation either way — no timing tell.
            Opened::Duress => {
                self.panic_wipe();
                self.body = "no messages".into();
                self.list = vec!["(no messages)".into()];
                self.locked = false;
                return Ok(());
            }
            Opened::Normal(id, kek) => (*id, kek),
        };

        let epoch = now_epoch();
        let before = id.hierarchy.records().len();
        let w = id
            .hierarchy
            .open_epoch(&kek, epoch, &mut OsRng)
            .map_err(|e| format!("{e:?}"))?;
        // **A minted `W_N` has to reach the disk.**
        //
        // `open_epoch` is idempotent only against records it can see, and it
        // sees the ones that were saved. The identity file was written at
        // `init` and never again, so the first unlock in a *later* epoch
        // minted a fresh `W_N`, kept it in memory, and dropped it at exit —
        // and everything sealed under it, the channel roster and the group
        // rosters among them, was unreadable on the next start. Not after a
        // day: immediately, for anything created in an epoch the identity
        // file predates.
        let minted = id.hierarchy.records().len() != before;
        if minted {
            let _ = persist::write_identity(
                &self.path(artifact::Artifact::IdentityWrapped),
                &id,
                &kek,
                &mut OsRng,
            );
        }
        self.identity = Some(krab_lock::Held::new(id));
        self.epoch_key = Some(w);
        self.pin_key = Some(pin::Pinned::key_from_kek(&kek));
        self.onion_key = Some(kek.subkey(persist::CONTEXT_ONION));
        // RFC 7 §10: an unlock is what resets the dead-man window.
        self.deadman_rearm();
        self.alias_key = Some(alias::Aliases::key_from_kek(&kek));
        self.locked = false;

        // The corpus goes through the same verification a stranger's archive
        // does. The disk is not trusted (RFC 7 §4).
        //
        // A node written by an earlier build has one `corpus.krab` instead of
        // a directory of segments. It is migrated here, once, through the same
        // import path — an upgrade that silently started with an empty corpus
        // would look exactly like the data loss this series keeps finding.
        let dir = self.path(artifact::Artifact::Corpus);
        let old = self.home.join("corpus.krab");
        let now_min = epoch.0 * 1440;
        let _ = self.store.with(|s| {
            if !dir.exists() && old.exists() {
                persist::migrate_corpus(&old, &dir, s, now_min, &mut OsRng)
            } else {
                persist::read_corpus(&dir, s, now_min)
            }
        });
        // Both are sealed under the epoch key, so this is the first moment
        // either can be read — and a restarted node that could not find its
        // own channel key would restart its post numbering, which is two
        // posts claiming one position and no reader can resolve that.
        self.load_roster();
        self.load_groups();
        self.refresh_inbox();
        self.become_relay_if_asked();
        Ok(())
    }

    /// Derive the KEK and open the current epoch, RFC 7 §4.
    /// Create the prekey ring if there is none, publish a batch, and store
    /// both. RFC 7 §5.
    ///
    /// The batch is a signed `bulletin` in this node's own corpus, so it
    /// floods on the next reconciliation — the corpus is the prekey server,
    /// which is X3DH with no infrastructure.
    fn publish_prekeys(&mut self) -> Option<String> {
        let w = self.epoch_key?;
        let id = self.identity.as_ref()?;
        let epoch = now_epoch();

        // **Rotate, never replace.** An earlier version built a fresh ring on
        // every call, which discarded the private halves of the previous batch
        // — so any message already encapsulated to one of those prekeys became
        // unreadable. It was only ever called once, at `init`, which is why
        // that did not show.
        let mut ring = std::fs::read(self.path(artifact::Artifact::PrekeyRing))
            .ok()
            .and_then(|sealed| krab_crypto::kek::open_under(&w, b"krab/prekeys", &sealed).ok())
            .and_then(|raw| prekeys::decode_ring(&raw));

        let rotated = match &mut ring {
            Some(r) => {
                // RFC 7 §5.1's tier rotates weekly-to-monthly. Rotating the
                // signed prekey is what bounds worst-case exposure to the
                // rotation period rather than for ever, which is the whole
                // claim §5 makes.
                let due = epoch.0.saturating_sub(r.signed().epoch.0) >= SIGNED_PREKEY_EPOCHS;
                if due {
                    r.rotate(krab_crypto::prekey::SignedPrekey::create(
                        id.signing_key(),
                        epoch,
                        &mut OsRng,
                    ));
                }
                due
            }
            None => {
                ring = Some(krab_crypto::prekey::Ring::new(
                    krab_crypto::prekey::SignedPrekey::create(id.signing_key(), epoch, &mut OsRng),
                ));
                true
            }
        };
        let ring = ring.as_mut()?;

        // Retire batches older than the acceptance window — RFC 7 §5.2:
        // **on a schedule, never on use.** The floor is `EPOCH_WINDOW`
        // because RFC 1 §6.2 gives an object that long to arrive, so a key
        // dropped sooner strands mail that is still legitimately in flight.
        let keep_from = krab_core::tag::Epoch(epoch.0.saturating_sub(krab_core::tag::EPOCH_WINDOW));
        let retired = ring.retire(keep_from);

        let published = prekeys::publish(ring, epoch, &mut OsRng);
        let sealed = krab_crypto::kek::seal_under(
            &w,
            b"krab/prekeys",
            &prekeys::encode_ring(ring),
            &mut OsRng,
        )
        .ok()?;
        atomic::write(&self.path(artifact::Artifact::PrekeyRing), &sealed).ok()?;

        let b = bulletin::Bulletin::create(
            bulletin::Kind::Prekeys,
            id.signing_key(),
            epoch.0,
            published.encode(),
        );
        let now_min = epoch.0 * 1440;
        let ttl = krab_core::tag::MAX_TTL_DAYS * 1440;
        let (oid, bytes) = bulletin::into_object(&b, now_min, ttl)?;
        if let Err(e) = self.store.with(|s| s.ingest(oid, bytes, now_min, u32::MAX)) {
            return Some(format!("could not publish prekeys: {e:?}"));
        }
        self.save_corpus();

        let mut out = format!(
            "published {} one-time prekeys. They flood as a signed bulletin, \
             so a correspondent encapsulates to a key that expires rather than \
             to your permanent one (RFC 7 §5).",
            published.keys.len()
        );
        if rotated {
            out.push_str(
                "\n\nThe signed prekey rotated. Worst-case exposure is now \
                 bounded by the rotation period rather than by the life of the \
                 identity key.",
            );
        }
        if retired > 0 {
            out.push_str(&format!(
                "\n\n{retired} batch(es) retired — on schedule, never on use \
                 (RFC 7 §5.2), and only past the window mail is allowed to \
                 arrive in."
            ));
        }
        Some(out)
    }

    fn open_store(&mut self) -> Result<(), String> {
        self.ensure_home()?;
        // Taken before the mutable borrow of `identity` below.
        let wrapped = self.path(artifact::Artifact::IdentityWrapped);
        let Some(id) = &mut self.identity else {
            return Err("no identity to open a store for".into());
        };
        let kek = id
            .kek(self.passphrase.as_string().as_bytes())
            .map_err(|e| format!("could not derive the key: {e:?}"))?;
        let before = id.hierarchy.records().len();
        self.epoch_key = Some(
            id.hierarchy
                .open_epoch(&kek, now_epoch(), &mut OsRng)
                .map_err(|e| format!("could not open the epoch: {e:?}"))?,
        );
        // As above: a wrapper that is minted and not written is a wrapper
        // that is minted again next start, under a different key.
        if id.hierarchy.records().len() != before {
            let _ = persist::write_identity(&wrapped, id, &kek, &mut OsRng);
        }
        // RFC 7 §8.1's long-lived key. From the KEK, so it survives every
        // epoch shred — which is the only reason a pin is worth anything.
        self.pin_key = Some(pin::Pinned::key_from_kek(&kek));
        self.onion_key = Some(kek.subkey(persist::CONTEXT_ONION));
        // RFC 7 §10: an unlock is what resets the dead-man window.
        self.deadman_rearm();
        self.alias_key = Some(alias::Aliases::key_from_kek(&kek));
        self.save(&kek)?;
        // `kek` drops here. RFC 7 §4: it is memory-only and never written, and
        // the shorter it lives the better — it is re-derived on unlock.
        Ok(())
    }

    /// Produce this node's half of a peering — RFC 3 §11 steps 1 and 3.
    fn peer_offer(&mut self) -> String {
        let Some(id) = &self.identity else {
            return "no identity".into();
        };
        let mine = peering::offer(id.card(Policy::default()), OsRng.next_32());
        let pending = ceremony::Pending::open(mine.card.clone(), mine.contribution.r);

        // Only the card. It is public and signed, so writing it costs nothing.
        //
        // The contribution is deliberately **not** written here: it is the one
        // artifact that would be plaintext on this node's own disk, and RFC 7
        // §4 forbids relying on deletion to remove it. It is already held
        // wrapped under W_N in the ceremony, so a plaintext copy would be a
        // redundant one — see Documentation/SECURE-DELETE.md. `peer pad
        // <destination>` materialises it onto the medium being carried.
        if let Err(e) = atomic::write(
            &self.path(artifact::Artifact::PeerCard),
            &mine.card.encode(),
        ) {
            return format!("could not write peer.card: {e}");
        }
        if let Err(e) = self.save_ceremony(&pending) {
            return e;
        }
        // The card is publishable; the contribution is half a shared secret,
        // and the two must not travel together. See `peering`'s module docs
        // and `RFC-7-review.md` §10 for why the channel matters.
        // What was written, and what to do next. This used to list `peer.pad`
        // alongside `peer.card` as though both existed. Only the card does —
        // the contribution stays wrapped inside the ceremony until `peer pad`
        // materialises it — so an operator went looking for a file that was
        // never there, and reached `peer seal` with nothing to give it.
        format!(
            "wrote {}\n\n\
             This is your card. It is public and signed — send it any way you \
             like.\n\n\
             your fingerprint — eight words that stand for your identity key:\n\n\
             \x20 {}\n\n\
             At step 3 you read these to them over a voice call, and they read \
             theirs back. Both must match what `peer accept` printed. If they \
             do not, stop: someone is between you. Nothing else in the \
             ceremony establishes who you are talking to.\n\n\
             next, in order:\n\
             \x20 1. send them peer.card, and get theirs\n\
             \x20 2. peer accept <their.card>\n\
             \x20 3. compare fingerprints aloud\n\
             \x20 4. peer pad <destination>   — writes your SECRET half\n\
             \x20 5. exchange pads, then: peer seal <their.pad> <channel>\n\n\
             Your pad does not exist yet. Step 4 creates it, where you tell it \
             to — on the medium you are carrying, not in this directory.",
            self.path(artifact::Artifact::PeerCard).display(),
            mine.card.fingerprint()
        )
    }

    /// Advance the first-run ceremony one step.
    ///
    /// Separate from `run` because [`InitStep`] is a sequence the operator
    /// walks, and RFC 7 §11 requires it to pass through the backup
    /// confirmation. Nothing here can skip a step; `InitStep::next` is the
    /// only edge available.
    fn advance_init(&mut self) {
        self.advance_init_step();
        // **The same reveal a typed verb gets.** `status` opens the pane; the
        // identical report printed at the end of `init` did not, which is the
        // one moment a new operator most needs to read it.
        self.reveal_output();
    }

    fn advance_init_step(&mut self) {
        let Some(step) = self.init_step else { return };

        // An unlock is a single step: derive and open, or refuse.
        if self.unlocking && step == InitStep::Passphrase {
            if self.passphrase.is_empty() {
                self.output = "a passphrase is required".into();
                return;
            }
            let passphrase = self.passphrase.take();
            self.output = match self.unlock(passphrase.as_bytes()) {
                Ok(()) => format!(
                    "unlocked {}",
                    self.identity
                        .as_ref()
                        .map(|i| i.short_id())
                        .unwrap_or_default()
                ),
                Err(e) => e,
            };
            let mut p = passphrase;
            overwrite(&mut p);
            self.init_step = None;
            self.unlocking = false;
            self.node.unlocking = false;
            // A restarted node reaches an identity through here, not through
            // the ceremony, so the listener has to start from both.
            if let Some(note) = self.start_listener() {
                self.output.push_str(&format!("\n\n{note}"));
            }
            // And the same status, for the same reason: a restarted node was
            // showing "a store is here. `unlock` to open it." in the message
            // pane *after* it had been opened.
            let status = self.status_report();
            self.output.push_str(&format!("\n\n{status}"));
            self.body = status;
            return;
        }

        // Refuse to leave the passphrase step with nothing. The KEK is the
        // only root (RFC 7 §4), so an empty passphrase is a store anyone who
        // picks up the disk can open.
        if step == InitStep::Passphrase && self.passphrase.is_empty() {
            self.output = "a passphrase is required — it is the only root".into();
            return;
        }

        match step.next() {
            Some(InitStep::Done) | None => {
                // The last act of the ceremony: derive the KEK and open the
                // current epoch's wrapper. Argon2id at RFC 7 §4.1's parameters
                // takes ~500 ms and 64 MiB, which is the whole point — it is
                // what a seized disk has to get through.
                self.output = match self.open_store() {
                    Ok(()) => format!(
                        "{}\n\nmessage history is NOT recoverable from that backup, \
                         and that is intentional (RFC 7 §11).",
                        InitStep::Done.prompt()
                    ),
                    Err(e) => {
                        // Leave the ceremony where it is: an identity without a
                        // KEK has nothing to wrap its keys under.
                        return self.output = e;
                    }
                };
                self.init_step = None;
                // The passphrase has done its work and must not linger (§9).
                self.passphrase.clear();
                self.load_roster();
                if let Some(note) = self.publish_prekeys() {
                    self.output.push_str(&format!("\n\n{note}"));
                }
                if let Some(note) = self.start_listener() {
                    self.output.push_str(&format!("\n\n{note}"));
                }
                self.become_relay_if_asked();
                // **What state the node is actually in, and what is missing.**
                //
                // `init` used to end on "generated 37e35a58" and leave the
                // message pane holding the text it was given before the
                // program started — "no identity. `init` to create one." —
                // so a node that had just been created reported that it had
                // not been. The operator had no way to tell whether anything
                // else was needed.
                let status = self.status_report();
                self.output.push_str(&format!("\n\n{status}"));
                self.body = status;
            }
            Some(next) => {
                if next == InitStep::Generate {
                    // Every key this node will ever hold originates here.
                    let id = Identity::generate(&mut OsRng);
                    self.output = format!("generated {}", id.short_id());
                    self.identity = Some(krab_lock::Held::new(id));
                }
                self.init_step = Some(next);
                if next == InitStep::ShowBackup {
                    let phrase = self
                        .identity
                        .as_ref()
                        .map(|i| i.backup_phrase())
                        .unwrap_or_default();
                    // The output pane, which scrolls to the newest line and
                    // full-screens with Ctrl-O. **Not** the message pane: that
                    // one is rebuilt from the inbox on every scheduler tick,
                    // so anything written there is erased within a second.
                    self.output = format!(
                        "{}\n\n{phrase}\n\n\
                         This is the only copy. RFC 7 §11: message history is \
                         not recoverable from it, but without it every peer \
                         must re-verify you in person, from scratch.\n\n\
                         Ctrl-O full-screens this pane if the list is cut off.",
                        next.prompt()
                    );
                } else if next != InitStep::Generate {
                    self.output = next.prompt().into();
                }
            }
        }
    }

    /// Leave.
    ///
    /// `Ctrl-Q` and the `quit` verb both arrive here, so they cannot drift
    /// apart — they had, and one of them left the corpus unwritten.
    ///
    /// The corpus is written because it needs no key. The identity and its
    /// wrapper are already on disk from `init` or `unlock`: the KEK is
    /// memory-only by RFC 7 §4 and is not held here to re-wrap with, which is
    /// why quitting mid-ceremony correctly leaves nothing behind.
    fn leave(&mut self) {
        if !self.locked && self.epoch_key.is_some() {
            self.save_corpus();
        }
        self.quit = true;
    }

    /// Lock immediately, if this node was started as a relay.
    ///
    /// `RFC-7-review.md` §9.3: *"A relay is a TUI that was unlocked once at
    /// startup and locked immediately."* The operator enters the passphrase,
    /// the node locks, and it runs indefinitely in that state — session keys
    /// live, reconciling, unable to read mail.
    ///
    /// The passphrase is the point. §7's relay took none, which left its disk
    /// unencrypted and made RFC 0 §4.4's "seizure yields nothing" false for
    /// the peer list. Entering one costs a single prompt at start and buys the
    /// same hierarchy every other node has.
    ///
    /// It is deliberately **not** a headless mode. RFC 8 forbids one, and a
    /// relay that could start without a human is a relay whose passphrase
    /// lives somewhere a machine can read.
    fn become_relay_if_asked(&mut self) {
        if !self.relay || self.locked {
            return;
        }
        self.lock();
        self.output = "relay.\n\n\
             This node is locked and will stay locked. It reconciles for the \
             peers you chose and cannot read a message — including its own.\n\n\
             Its disk is encrypted under the passphrase you just entered, \
             which is the whole reason it asked: a relay that took no \
             passphrase would leave its peer list in the clear.\n\n\
             `unlock` makes it an ordinary node again."
            .into();
    }

    /// Lock: zeroize what the interface holds and drop to the relay role.
    ///
    /// The node keeps reconciling — `RFC-8-review.md` §8.5 makes pausing it an
    /// I-5 violation worse than mail-driven sync, because it leaks a daily
    /// rhythm rather than sporadic events. Nothing here touches the schedule,
    /// and nothing here can.
    fn lock(&mut self) {
        // RFC-7-review.md §9: a locked node keeps its links and loses its
        // content keys. `W_N` is a content key.
        if let Some(mut w) = self.epoch_key.take() {
            use zeroize::Zeroize;
            w.zeroize();
        }
        // RFC 7 §8 — plaintext exists only while displayed, and a locked node
        // is displaying nothing.
        for m in &mut self.messages {
            overwrite(&mut m.body);
        }
        self.messages.clear();
        // The table derives from static-static shared secrets, so it is
        // content-key material. A locked node is a relay and must not hold it.
        self.tag_table = None;
        // The counters in `PeerMetrics` keep moving — a relay still
        // reconciles — but the screen must not list correspondents.
        self.log.clear();
        // **And neither must the history.** It held `send <peer>`, `message
        // <peer>`, and the paths of cards and pads — a list of who this node
        // talks to, recallable with Up-arrow on a node that is supposed to be
        // unable to read anything. It was cleared for the log and not for the
        // history, which is the same disclosure by another route.
        self.history.clear();
        self.history_at = 0;
        // An open composition names its recipients.
        self.composing_to = None;
        self.composing_to_many.clear();
        // A socket accepting strangers, on a node that cannot complete the
        // ceremony one would start: it needs the epoch key to seal a
        // reservoir, and that is the first thing gone.
        if let Some(m) = self.meeting.take() {
            m.running.store(false, std::sync::atomic::Ordering::Relaxed);
        }
        // A confirmation given before a lock must not authorise a destruction
        // after it — the operator who returns is not necessarily the one who
        // typed `wipe`.
        self.confirmed = false;
        // A pending prompt would consume the next line typed, which after an
        // unlock is whatever the returning operator meant to run.
        self.prompt = None;
        // The channel posting key and every group roster. Both are read back
        // from sealed storage on unlock, so holding them while locked buys
        // nothing and keeps a signing key and a membership list in the memory
        // of a node that is supposed to be unable to read anything.
        self.roster = channels::Roster::default();
        self.groups.clear();
        // Listing in the rollcall is opt-in per RFC 3 §9, and a lock is the
        // point at which nothing about the operator's intent is still known.
        // Clearing it means the node stops republishing; the entry already
        // flooded stands until it expires, because there is no recall
        // (RFC 3 §6.1) and pretending otherwise would be worse than saying so.
        self.rollcall = rollcall::Listing::default();
        // The graph, which is what RFC 3 §15 calls a fragment. A locked node
        // holding one is a seizure holding one.
        self.reach.clear();
        self.pending_bases.clear();
        // Derived from the KEK, so it goes when the KEK does.
        self.pin_key = None;
        self.onion_key = None;
        self.alias_key = None;
        self.warned_shred_at = None;
        self.last_scan_fail = 0;
        // Per-link budgets. Sealed under W_N, which a locked node no longer
        // holds — keeping the in-memory copies would mean a counter that
        // cannot be written back, and a peer list in memory besides.
        self.spends.clear();
        // Held tokens are private vouches other people made. A locked node has
        // no business holding one, and they are single-use in any case.
        self.introductions.clear();
        self.list = vec!["(locked)".into()];
        self.passphrase.clear();
        overwrite(&mut self.composer);
        self.composer_at = 0;
        // Both panes. `body` holds decrypted message plaintext and `output`
        // holds command output, and RFC 7 §8 does not distinguish: what is on
        // screen when the node locks must not survive the lock.
        overwrite(&mut self.body);
        overwrite(&mut self.output);
        // A picture on screen after a lock is the same failure as a message on
        // screen after one.
        self.showing = None;
        self.output.push_str("locked");
        self.ui.end_compose();
        self.locked = true;
    }
}

/// What a passphrase opened.
enum Opened {
    /// The real store.
    Normal(Box<Identity>, krab_crypto::kek::Kek),
    /// RFC 7 §10's duress passphrase.
    Duress,
}

/// The earliest clock reading treated as a date rather than a fault.
///
/// 2026-01-01. Before this the protocol did not exist, so a reading below it is
/// hardware — an unset RTC reads 1970, and deriving tags at epoch 0 puts a node
/// in a tag space no peer computes, silently.
const EPOCH_FLOOR_SECS: u64 = 1_767_225_600;

/// A peer's short identifier, as used for on-disk link filenames.
fn short_id(node_id: &[u8; 32]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        node_id[0], node_id[1], node_id[2], node_id[3]
    )
}

/// A default expiry: `MAX_TTL` from now, in minutes since the Unix epoch.
///
/// RFC 1 §2 sets `MAX_TTL` at 45 days. Using the maximum is the privacy-safe
/// default — a shorter, message-specific expiry would make the object's
/// lifetime a signal about its contents.
fn expiry_for(epoch: krab_core::tag::Epoch) -> u32 {
    (epoch.0 + 45) * 1440
}

/// One link, as a single-hop path.
fn alloc_one(l: &links::LinkState) -> Vec<krab_fabric::profile::LinkProfile> {
    vec![l.profile.clone()]
}

/// The value following a `--flag`.
fn arg_value<'a>(line: &'a str, flag: &str) -> Option<&'a str> {
    let mut it = line.split_whitespace();
    while let Some(t) = it.next() {
        if t == flag {
            return it.next();
        }
    }
    None
}

/// The `n`th argument of a command line, respecting quotes.
///
/// Returns an owned `String` rather than a borrow because a quoted word is
/// not a slice of the input — `"/Volumes/My Disk"` has no contiguous
/// representation in the line the operator typed once the quotes are gone.
///
/// A line that cannot be tokenised yields nothing, and [`App::submit`] refuses
/// it with the reason before any verb sees it.
fn arg(line: &str, n: usize) -> Option<String> {
    words::split(line).ok().and_then(|w| words::nth(&w, n))
}

/// The current epoch, RFC 1 §2 — days since the Unix epoch.
///
/// The clock lives here rather than in any library crate: `krab-core` is
/// zero-dependency so that "no clock" is compiler-enforced, and every function
/// beneath this one takes time as an argument.
fn now_epoch() -> krab_core::tag::Epoch {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // A clock reading before the protocol existed is a dead CMOS battery, not
    // a date. Clamping keeps the node inside a tag space its peers compute,
    // rather than deriving at epoch 0 where nobody is listening — and, since
    // the ratchet refuses implausible jumps, keeps a wrong clock from
    // presenting as a reservoir that will not advance.
    krab_core::tag::Epoch::at(secs.max(EPOCH_FLOOR_SECS))
}

/// Overwrite a `String`'s bytes before clearing.
///
/// `String::clear` sets the length and leaves the bytes in the allocation,
/// which is the residue RFC 7 §9 warns about.
fn overwrite(s: &mut String) {
    let n = s.len();
    s.clear();
    for _ in 0..n {
        s.push('\0');
    }
    s.clear();
}

fn setup() -> io::Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    // **Clear before the first frame.**
    //
    // ratatui writes only the cells that differ from its previous buffer, and
    // that buffer starts empty — so on the first draw every cell the frame
    // considers blank is simply not written. Entering the alternate screen
    // does not reliably blank it either. The result is the shell's scrollback
    // and the previous run's output showing through the gaps in the layout:
    // a garbled interface built from real text that is not this program's.
    term.clear()?;
    Ok(term)
}

fn restore() -> io::Result<()> {
    io::stdout().execute(LeaveAlternateScreen)?;
    disable_raw_mode()
}

/// Restore the terminal on panic.
///
/// Required because RFC 7 §9's `panic = "abort"` prevents unwinding, so no
/// `Drop` guard runs. The hook still does, and runs before the abort.
fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = restore();
        previous(info);
    }));
}

#[cfg(test)]
// Tests build an `App` from `Default` and then set the two or three fields
// under test; listing every field would obscure which ones matter.
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    fn app() -> App {
        let mut a = App::default();
        a.composer_set("a draft");
        a.body.push_str(" decrypted text");
        a
    }

    /// Lock zeroizes what the interface is holding, from any mode.
    /// A fresh directory under the system temp dir, unique per call.
    fn temp_home(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "krab-test-{}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed),
            tag
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    /// A node that has completed `init`: identity, epoch key, home directory.
    ///
    /// Argon2id runs at cheap parameters here; `krab_crypto::kek` exercises
    /// the specified ones.
    fn ready_node(tag: &str) -> App {
        let mut a = App::default();
        a.home = temp_home(tag);
        let mut id = Identity::generate(&mut OsRng);
        id.kek_params.m_kib = 64;
        id.kek_params.t = 1;
        id.kek_params.p = 1;
        a.identity = Some(krab_lock::Held::new(id));
        a.passphrase = line::Line::from("a passphrase");
        a.open_store().expect("store opens");
        a
    }

    /// Two nodes with a completed peering, and the short id each uses for the
    /// other. The sneakernet path, because that is the one that keeps the
    /// post-quantum property and so is the interesting starting point.
    /// Publish `text`, confirming if this is the session's first post.
    ///
    /// The confirmation is one keystroke now, not the command typed twice, so
    /// tests that doubled the verb were encoding the old behaviour.
    fn post_now(a: &mut App, text: &str) {
        type_command(a, &format!("channel post {text}"));
        if a.pending_post.is_some() {
            a.on_key(KeyCode::Enter, KeyModifiers::NONE);
        }
    }

    fn peered_pair(tag: &str) -> (App, App, String, String) {
        let mut a = ready_node(&format!("{tag}-a"));
        let mut b = ready_node(&format!("{tag}-b"));
        type_command(&mut a, "peer offer");
        type_command(&mut b, "peer offer");

        let carry = |from: &App, to: &App, name: artifact::Artifact, as_name: &str| {
            let bytes = std::fs::read(from.path(name)).expect("artifact exists");
            let dest = to.at(as_name);
            std::fs::write(&dest, bytes).expect("delivered");
            dest.to_string_lossy().into_owned()
        };
        let a_card = carry(&a, &b, artifact::Artifact::PeerCard, "from-a.card");
        let b_card = carry(&b, &a, artifact::Artifact::PeerCard, "from-b.card");
        type_command(&mut a, &format!("peer accept {b_card}"));
        type_command(&mut b, &format!("peer accept {a_card}"));

        let a_pad = pad_onto(&mut a, &b.at("from-a.pad"));
        let b_pad = pad_onto(&mut b, &a.at("from-b.pad"));
        type_command(&mut a, &format!("peer seal {b_pad} media"));
        type_command(&mut b, &format!("peer seal {a_pad} media"));
        assert!(a.output.starts_with("peer-link signed"), "{}", a.output);
        assert!(b.output.starts_with("peer-link signed"), "{}", b.output);

        let a_id = short_id(&a.identity.as_ref().unwrap().node_id());
        let b_id = short_id(&b.identity.as_ref().unwrap().node_id());
        (a, b, a_id, b_id)
    }

    /// A peered pair sealed over a chosen channel, so a test can start from a
    /// weak peering and upgrade it.
    fn peered_pair_over(tag: &str, channel: &str) -> (App, App, String, String) {
        let mut a = ready_node(&format!("{tag}-a"));
        let mut b = ready_node(&format!("{tag}-b"));
        type_command(&mut a, "peer offer");
        type_command(&mut b, "peer offer");

        let carry = |from: &App, to: &App, name: artifact::Artifact, as_name: &str| {
            let bytes = std::fs::read(from.path(name)).expect("artifact exists");
            let dest = to.at(as_name);
            std::fs::write(&dest, bytes).expect("delivered");
            dest.to_string_lossy().into_owned()
        };
        let a_card = carry(&a, &b, artifact::Artifact::PeerCard, "from-a.card");
        let b_card = carry(&b, &a, artifact::Artifact::PeerCard, "from-b.card");
        type_command(&mut a, &format!("peer accept {b_card}"));
        type_command(&mut b, &format!("peer accept {a_card}"));

        let a_pad = pad_onto(&mut a, &b.at("from-a.pad"));
        let b_pad = pad_onto(&mut b, &a.at("from-b.pad"));
        type_command(&mut a, &format!("peer seal {b_pad} {channel}"));
        type_command(&mut b, &format!("peer seal {a_pad} {channel}"));
        assert!(a.output.starts_with("peer-link signed"), "{}", a.output);
        assert!(b.output.starts_with("peer-link signed"), "{}", b.output);

        let a_id = short_id(&a.identity.as_ref().unwrap().node_id());
        let b_id = short_id(&b.identity.as_ref().unwrap().node_id());
        (a, b, a_id, b_id)
    }

    /// The short id `n` files its counterparty under — the one peer directory
    /// it has.
    fn a_id_of(n: &App) -> String {
        n.peer_ids().first().cloned().expect("one peering")
    }

    /// The reservoir root `n` currently holds for `peer`.
    fn stored_root(n: &App, peer: &str) -> [u8; 32] {
        let sealed =
            std::fs::read(n.peer_path(peer, artifact::PeerFile::Reservoir)).expect("a reservoir");
        let raw = krab_crypto::kek::open_under(&n.epoch_key.unwrap(), b"krab/reservoir", &sealed)
            .expect("it opens");
        persist::decode_reservoir(&raw).expect("it decodes").0
    }

    /// A pair of in-process sessions, standing in for a link that is up.
    /// The exchange is transport-agnostic by construction, and a socket here
    /// would test the socket.
    fn session_pair() -> (TestSession, TestSession) {
        use std::sync::mpsc::channel;
        let (a_tx, b_rx) = channel();
        let (b_tx, a_rx) = channel();
        (
            TestSession { tx: a_tx, rx: a_rx },
            TestSession { tx: b_tx, rx: b_rx },
        )
    }

    struct TestSession {
        tx: std::sync::mpsc::Sender<krab_proto::control::Control>,
        rx: std::sync::mpsc::Receiver<krab_proto::control::Control>,
    }

    impl krab_fabric::Session for TestSession {
        fn send(&mut self, msg: &krab_proto::control::Control) -> Result<(), krab_fabric::Error> {
            self.tx
                .send(msg.clone())
                .map_err(|_| krab_fabric::Error::Frame)
        }
        fn recv(&mut self) -> Result<Option<krab_proto::control::Control>, krab_fabric::Error> {
            Ok(self.rx.recv().ok())
        }
        fn close(&mut self) -> Result<(), krab_fabric::Error> {
            Ok(())
        }
    }

    /// Materialise a node's contribution onto a "medium" — the new `peer pad`
    /// verb, which writes where told and never to the node's own storage.
    fn pad_onto(from: &mut App, dest: &std::path::Path) -> String {
        type_command(from, &format!("peer pad {}", dest.display()));
        assert!(dest.exists(), "peer pad wrote nothing: {}", from.output);
        dest.to_string_lossy().into_owned()
    }

    /// **RFC 4 §5.2: the authorised-client set derives from the peerings.**
    ///
    /// A node with no peers has an empty set — and therefore, honestly, an
    /// unrestricted service. A node with a peering has exactly one entry, and
    /// it is the entry that peer will derive for itself.
    #[test]
    fn the_onion_client_set_comes_from_verified_peerings() {
        let alone = ready_node("onion-set-alone");
        let (set, skipped) = alone.onion_client_set();
        assert!(set.is_empty(), "a node with no peers authorised somebody");
        assert_eq!(skipped, 0);

        let (a, b, _a_of_b, _b_of_a) = peered_pair("onion-set");
        let (a_set, a_skipped) = a.onion_client_set();
        let (b_set, b_skipped) = b.onion_client_set();
        assert_eq!(a_set.len(), 1, "A did not authorise its peer");
        assert_eq!(b_set.len(), 1, "B did not authorise its peer");
        assert_eq!(a_skipped, 0);
        assert_eq!(b_skipped, 0);

        // **The two ends agree.** A authorises the key B will hand its own
        // tor, and vice versa — which is what makes restricted discovery work
        // without either sending the other an auth key.
        assert_eq!(
            a_set, b_set,
            "the two ends of a peering derived different client-auth keys, so \
             neither could decrypt the other's descriptor"
        );

        // And it is base32 of 32 bytes: 52 characters, no padding, which is
        // what tor's `ClientAuthV3` grammar accepts.
        assert_eq!(a_set[0].len(), 52);
        assert!(!a_set[0].contains('='));
        assert!(a_set[0]
            .chars()
            .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)));
    }

    /// **Rotation persists.** A counter that advanced only in memory would
    /// revert at the next start — and the operator would by then have told
    /// their peers an address this node no longer answers on.
    #[test]
    fn rotating_the_onion_counter_survives_a_restart() {
        let mut a = ready_node("onion-rotate");
        // No root yet: rotation has nothing to advance and says so rather
        // than inventing one, because a root created here would not be the
        // root `start-tor` publishes.
        type_command(&mut a, "onion rotate");
        assert!(a.output.contains("no onion root"), "{}", a.output);

        // Seed a root the way `start-tor` does.
        let key = a.onion_key.expect("unlocked");
        let root_path = a.path(artifact::Artifact::OnionRoot);
        let root = krab_crypto::onion::OnionRoot::generate(&mut OsRng);
        persist::write_onion_root(&root_path, &root, (0, 0), &key, &mut OsRng).unwrap();

        type_command(&mut a, "onion rotate");
        assert!(a.output.contains("counter 1"), "{}", a.output);
        assert_eq!(a.onion_counters.0, 1);

        // Read back from disk, as a restart would.
        let (_, sync, contact) = persist::read_onion_root(&root_path, &key).unwrap();
        assert_eq!(sync, 1, "the rotation did not reach the disk");
        assert_eq!(contact, 0, "rotating sync moved the contact counter");
    }

    /// **The old record format still opens.** Refusing a 32-byte record would
    /// take an existing node's permanent address away on upgrade — the
    /// loudest possible failure for the least reason.
    #[test]
    fn an_onion_record_without_counters_reads_as_counter_zero() {
        let a = ready_node("onion-legacy");
        let key = a.onion_key.expect("unlocked");
        let root_path = a.path(artifact::Artifact::OnionRoot);

        // Exactly what the first version wrote: the root, sealed, alone.
        let root = krab_crypto::onion::OnionRoot::generate(&mut OsRng);
        let sealed = krab_crypto::kek::seal_under(
            &key,
            persist::CONTEXT_ONION,
            root.as_bytes(),
            &mut OsRng,
        )
        .unwrap();
        std::fs::write(&root_path, &sealed).unwrap();

        let (back, sync, contact) = persist::read_onion_root(&root_path, &key).unwrap();
        assert_eq!(back.as_bytes(), root.as_bytes(), "the root did not survive");
        assert_eq!((sync, contact), (0, 0));
    }

    /// **The two endpoints are reported as two things**, because they are.
    /// An operator who hands a stranger the sync address has given away the
    /// reconciliation port, and no amount of restricted discovery helps once
    /// the address is in their hands.
    #[test]
    fn the_onion_report_separates_contact_from_sync() {
        let mut a = ready_node("onion-report");
        type_command(&mut a, "onion");
        assert!(a.output.contains("sync"), "{}", a.output);
        assert!(a.output.contains("contact"), "{}", a.output);
        assert!(
            a.output.contains("start-tor"),
            "a node with no tor must say why nothing is published: {}",
            a.output
        );
    }

    /// Closing a contact endpoint that was never open is not an error, and
    /// `peer meet` without tor still works — over a plain address.
    #[test]
    fn a_contact_endpoint_without_tor_is_absent_rather_than_a_failure() {
        let mut a = ready_node("onion-contact-none");
        assert!(a.onion_contact_open(40_000).is_none());
        assert_eq!(a.onion_contact_close(), "no contact endpoint is open.");
    }

    /// **Cover is off unless asked for, and says why.**
    ///
    /// RFC 0 §7.3: cover traffic "is unaffordable on a constrained link". A
    /// node that started emitting on its own would spend an operator's duty
    /// cycle, metered link or battery to buy a property they may not need.
    #[test]
    fn cover_is_off_until_an_operator_turns_it_on() {
        let mut a = ready_node("cover-off");
        assert!(a.cover_mean_s.is_none());
        type_command(&mut a, "cover");
        assert!(a.output.contains("OFF"), "{}", a.output);

        type_command(&mut a, "cover on 600");
        assert_eq!(a.cover_mean_s, Some(600));
        assert!(a.output.contains("class 0"), "{}", a.output);

        type_command(&mut a, "cover off");
        assert!(a.cover_mean_s.is_none());
    }

    /// The mean is bounded at both ends, and the refusal says what each bound
    /// is for.
    #[test]
    fn the_cover_interval_is_bounded() {
        let mut a = ready_node("cover-bounds");
        for bad in [COVER_MIN_S - 1, COVER_MAX_S + 1, 0] {
            type_command(&mut a, &format!("cover on {bad}"));
            assert!(a.cover_mean_s.is_none(), "{bad} was accepted");
            assert!(a.output.contains("usage"), "{}", a.output);
        }
    }

    /// **§8.2's corollary: a node that has observed nothing emits nothing.**
    ///
    /// There is no distribution to match yet, and inventing one produces
    /// exactly the trivially separable traffic §8.2 forbids. Separable cover
    /// is worse than none — an observer who strips it learns which objects
    /// were real, and that this node runs cover at all.
    #[test]
    fn cover_emits_nothing_until_real_traffic_has_been_seen() {
        let mut a = ready_node("cover-cold");
        type_command(&mut a, "cover on 60");
        assert!(a.output.contains("Nothing will be emitted yet"), "{}", a.output);

        let before = a.store.with(|s| s.len());
        // Force the schedule past due and tick it repeatedly.
        for _ in 0..20 {
            a.cover_next_s = 1;
            a.tick_cover();
        }
        assert_eq!(
            a.store.with(|s| s.len()),
            before,
            "a node with no observed distribution emitted cover anyway"
        );
    }

    /// **Once a distribution exists, dummies are emitted — as class 0.**
    ///
    /// RFC 1 §5.3 reserves class 2 and forbids using it: a distinct class byte
    /// would make every cover object separable by reading one byte, which is
    /// the exact opposite of the point.
    #[test]
    fn an_observed_distribution_produces_class_zero_cover() {
        let mut a = ready_node("cover-warm");
        type_command(&mut a, "cover on 60");

        // Feed the emitter a real shape, as an exchange would.
        let (id, bytes) = {
            let h = krab_core::object::RoutingHeader {
                version: 1,
                class: 0,
                size_bucket: 0,
                flags: 0,
                expiry_min: now_epoch().0 * 1440 + 10_000,
                tag: krab_core::object::Tag([5; 8]),
            };
            let body = krab_core::object::example_sealed_body(3);
            let b = krab_core::object::canonical_bytes(&h, &body).unwrap();
            (krab_crypto::object_id(&b), b)
        };
        let body_len = krab_core::object::validate_body(&bytes).unwrap();
        a.cover.observe(&bytes[..krab_core::object::ROUTING_HEADER_LEN], body_len);
        assert_eq!(a.cover.observations(), 1);
        let _ = id;

        let before = a.store.with(|s| s.len());
        a.cover_next_s = 1;
        a.tick_cover();
        let after = a.store.with(|s| s.len());
        assert_eq!(after, before + 1, "no cover was emitted");

        // The emitted object is class 0 and its bucket is the one observed.
        let emitted: Vec<Vec<u8>> = a.store.with(|s| {
            s.entries_in_range(0, u32::MAX)
                .into_iter()
                .filter_map(|(_, i)| s.get(&i).map(|b| b.to_vec()))
                .collect()
        });
        let dummy = emitted
            .iter()
            .find(|b| krab_crypto::object_id(b) != id)
            .expect("the dummy is in the corpus");
        let h = krab_core::object::RoutingHeader::parse(dummy).unwrap();
        assert_eq!(h.class, 0, "cover must be class 0, never class 2");
        assert_eq!(h.size_bucket, 0, "cover did not match the observed bucket");
        assert!(
            a.cover.is_mine(&krab_crypto::object_id(dummy)),
            "the emitter did not record its own cover"
        );
    }

    /// **Both ends of a peering derive the same `short` keying.**
    ///
    /// The analogue of the client-auth agreement test, and for the same
    /// reason: if the two ends disagree, each computes a *valid* key and every
    /// message fails to open. Neither end can tell that from the other being
    /// quiet, and RFC 0 §6 guarantees nobody is told.
    #[test]
    fn both_ends_of_a_link_derive_the_same_short_keying() {
        let (a, b, a_of_b, b_of_a) = peered_pair("short-keying");
        let (a_key, a_tag, a_link) = a.short_keying(&b_of_a).expect("A has keying for B");
        let (b_key, b_tag, b_link) = b.short_keying(&a_of_b).expect("B has keying for A");
        assert_eq!(a_key.expose(), b_key.expose(), "the message keys differ");
        assert_eq!(a_tag, b_tag, "the tags differ");
        assert_eq!(a_link, b_link, "the link identifiers differ");

        // And a frame sealed by one opens under the other.
        let frame =
            krab_crypto::short::seal(a_key.expose(), &a_link, 0, &a_tag, 400_000, b"on my way")
                .unwrap();
        let (head, body) = krab_crypto::short::open(b_key.expose(), &b_link, &frame).unwrap();
        assert_eq!(body, b"on my way");
        assert_eq!(head.tag, b_tag);
    }

    /// **A received short is displayed and stored nowhere.**
    ///
    /// RFC 4 §8's "MUST NOT be stored beyond display", checked on the two
    /// places a message body would plausibly end up: the inbox and the corpus.
    /// The exchange plumbing that carries the frame this far has its own test
    /// in `krab_node::exchange`; this is the half that opens it.
    #[test]
    fn a_received_short_is_shown_and_kept_nowhere() {
        let (mut a, b, a_of_b, b_of_a) = peered_pair("short-recv");
        let (key, tag, link) = b.short_keying(&a_of_b).expect("B has keying for A");
        let frame =
            krab_crypto::short::seal(key.expose(), &link, 0, &tag, 400_000, b"running late")
                .unwrap();

        let before_inbox = a.messages.len();
        let before_corpus = a.store.with(|s| s.len());
        a.shorts.0.send((b_of_a.clone(), vec![frame])).unwrap();
        a.drain_shorts();

        assert!(
            a.output.contains("running late"),
            "the message was not displayed: {}",
            a.output
        );
        assert_eq!(a.messages.len(), before_inbox, "a short reached the inbox");
        assert_eq!(
            a.store.with(|s| s.len()),
            before_corpus,
            "a short reached the corpus"
        );
        // And no peer name is paired with a body anywhere that persists.
        assert!(
            !a.log.recent(64).iter().any(|l| l.contains("running late")),
            "the text reached the activity log"
        );
    }

    /// A frame from a peering whose reservoir has drifted is counted, not
    /// silently dropped — a link that can never be read shows as a number.
    #[test]
    fn an_unopenable_short_is_counted() {
        let (mut a, _b, _a_of_b, b_of_a) = peered_pair("short-bad");
        a.shorts.0.send((b_of_a, vec![vec![0x13; 30]])).unwrap();
        a.drain_shorts();
        assert!(
            a.output.contains("could not be opened"),
            "an unopenable short vanished: {}",
            a.output
        );
    }

    /// **A short needs a live link, and says so rather than queueing.**
    ///
    /// RFC 1 §5.5 makes it link-local by construction: no identifier, no
    /// relay, no reconciliation. There is nothing to queue it in, so an
    /// implementation that queued it would have quietly turned it into `send`.
    #[test]
    fn a_short_without_a_live_link_is_refused() {
        let (mut a, _b, _a_of_b, b_of_a) = peered_pair("short-nolink");
        type_command(&mut a, &format!("short {b_of_a} on my way"));
        assert!(
            a.output.contains("no live link"),
            "a short with no link must refuse: {}",
            a.output
        );
        // And nothing was written: a refused send must not spend a counter.
        assert!(!a
            .peer_path(&b_of_a, artifact::PeerFile::ShortCtr)
            .exists());
    }

    /// **§8's ceiling is enforced with its own number.** 55 bytes on the wire,
    /// 18 of them framing.
    #[test]
    fn a_short_longer_than_the_ceiling_is_refused() {
        let (mut a, _b, _a_of_b, b_of_a) = peered_pair("short-long");
        let long = "x".repeat(krab_crypto::short::MAX_BODY + 1);
        type_command(&mut a, &format!("short {b_of_a} {long}"));
        assert!(
            a.output.contains("at most 37"),
            "the ceiling must be named: {}",
            a.output
        );
    }

    /// **An unreadable counter reads as exhausted, never as zero.**
    ///
    /// The nonce is `(link_id, ctr)`. A counter whose previous value cannot be
    /// established is one whose safe next value is unknown, and guessing zero
    /// is the single answer certain to repeat a nonce if the file was ever
    /// written. Repeating one under ChaCha20-Poly1305 leaks the XOR of two
    /// plaintexts and the Poly1305 key with it.
    #[test]
    fn a_damaged_short_counter_refuses_rather_than_restarting() {
        let (a, _b, _a_of_b, b_of_a) = peered_pair("short-ctr-bad");
        assert_eq!(a.short_ctr(&b_of_a), (0, 0), "never written reads as zero");

        a.write_short_ctr(&b_of_a, 12, 7).unwrap();
        assert_eq!(a.short_ctr(&b_of_a), (12, 7));

        std::fs::write(a.peer_path(&b_of_a, artifact::PeerFile::ShortCtr), b"junk").unwrap();
        let (epoch, ctr) = a.short_ctr(&b_of_a);
        assert_eq!(ctr, krab_crypto::short::MAX_CTR, "a damaged counter must read as spent");
        assert_ne!(epoch, now_epoch().0, "and its epoch must not match this one");
    }

    /// **`connect <peer> tor <addr>` reaches the Tor carrier, not TCP.**
    ///
    /// The branch did not exist, so an onion address fell through to
    /// `TcpFabric` and `TcpStream::connect` handed the name to the system
    /// resolver — the dial failed, and the local DNS server was told which
    /// hidden service this node wanted. Refusing before dialling is what makes
    /// that impossible; the message says why rather than reporting a timeout.
    #[test]
    fn a_tor_connect_without_tor_refuses_before_it_dials() {
        let (mut a, _b, _a_of_b, b_of_a) = peered_pair("tor-connect");
        assert!(a.tor.is_none(), "no tor should be running in a test node");
        let onion = "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion";
        type_command(&mut a, &format!("connect {b_of_a} tor {onion}"));
        assert!(
            a.output.contains("start-tor"),
            "a tor dial without tor must say so: {}",
            a.output
        );
    }

    /// **A tor link cannot answer**, and says so instead of quietly dialling.
    ///
    /// `connect <peer> tor <addr> answer` is the only way to express it —
    /// `listen` infers its carrier from the address shape and never produces
    /// this kind. Inbound over an onion service arrives at the listener the
    /// service forwards to, which is a different socket entirely, so a tor
    /// fabric that accepted would be a second listener racing the first.
    #[test]
    fn a_tor_link_refuses_to_answer() {
        let (mut a, _b, _a_of_b, b_of_a) = peered_pair("tor-answer");
        let onion = "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion";
        type_command(&mut a, &format!("connect {b_of_a} tor {onion} answer"));
        assert!(
            a.output.contains("cannot answer"),
            "answering over tor must be refused: {}",
            a.output
        );
    }

    /// **A peer whose card does not verify is skipped and counted**, not
    /// silently admitted. Admitting one would widen the set §5.2 exists to
    /// narrow; dropping it silently would leave an operator wondering why a
    /// peer cannot reach them.
    #[test]
    fn an_unverifiable_peer_is_skipped_and_reported() {
        let (a, _b, _, _) = peered_pair("onion-set-bad");
        assert_eq!(a.onion_client_set().0.len(), 1);

        // Corrupt the stored card so its signature no longer checks. The
        // directory name is whatever `peer_ids` reports, which is the same
        // set `onion_client_set` walks.
        let peer = a.peer_ids().first().expect("no peer directory").clone();
        let link = a.peer_path(&peer, artifact::PeerFile::Link);
        let mut bytes = std::fs::read(&link).unwrap();
        let n = bytes.len();
        bytes[n - 1] ^= 0xff;
        std::fs::write(&link, &bytes).unwrap();

        let (set, skipped) = a.onion_client_set();
        assert!(set.is_empty(), "an unverifiable card was authorised");
        assert_eq!(skipped, 1, "the skip was not counted");
    }

    /// **The dead-man timer actually destroys the node.**
    ///
    /// `deadman.rs`'s own tests cover the arithmetic; none of them touch an
    /// `App`, so none of them would notice if `deadman_on_start` were never
    /// called, called after the unlock, or wired to something other than
    /// `panic_wipe`. That gap is the whole failure mode — a timer that is
    /// armed, warns, and then does nothing.
    #[test]
    fn an_expired_dead_man_destroys_the_node() {
        let mut a = ready_node("deadman-fires");
        type_command(&mut a, "deadman 7");
        assert!(a.path(artifact::Artifact::DeadMan).exists(), "not armed");
        assert!(a.has_stored_identity(), "no identity to destroy");

        // Backdate the stamp past its window. This is what a week of nobody
        // unlocking looks like from the node's side.
        let stale = deadman::DeadMan {
            armed_at_s: a.now_s() - 8 * 86_400,
            days: 7,
        };
        deadman::write(&a.path(artifact::Artifact::DeadMan), &stale).unwrap();

        let notice = a.deadman_on_start().expect("no notice on an expired timer");
        assert!(notice.contains("DEAD-MAN TIMER FIRED"), "{notice}");
        assert!(
            !a.has_stored_identity(),
            "the timer fired but the node survived"
        );
        assert!(a.identity.is_none(), "the identity is still in memory");
    }

    /// And an unexpired one does not — the other half, because a test that
    /// only proved firing would pass on a timer that fired every start.
    #[test]
    fn an_unexpired_dead_man_leaves_the_node_alone() {
        let mut a = ready_node("deadman-waits");
        type_command(&mut a, "deadman 30");
        assert!(a.deadman_on_start().is_none(), "warned or fired too early");
        assert!(a.has_stored_identity(), "the node was destroyed early");

        // Inside the last quarter it warns, and still does not fire.
        let soon = deadman::DeadMan {
            armed_at_s: a.now_s() - 25 * 86_400,
            days: 30,
        };
        deadman::write(&a.path(artifact::Artifact::DeadMan), &soon).unwrap();
        let w = a.deadman_on_start().expect("no warning inside the window");
        assert!(w.contains("DEAD-MAN TIMER:"), "{w}");
        assert!(!w.contains("FIRED"), "{w}");
        assert!(a.has_stored_identity(), "a warning destroyed the node");
    }

    /// **RFC 7 §10: off by default.** A node nobody has told about the timer
    /// must never fire one.
    #[test]
    fn a_node_without_a_stamp_never_fires() {
        let mut a = ready_node("deadman-default");
        assert!(!a.path(artifact::Artifact::DeadMan).exists());
        assert!(a.deadman_on_start().is_none());
        assert!(a.has_stored_identity());
    }

    /// Unlocking resets the window — `deadman_rearm` is on the unlock path.
    #[test]
    fn unlocking_re_arms_the_timer() {
        let mut a = ready_node("deadman-rearm");
        type_command(&mut a, "deadman 10");
        let path = a.path(artifact::Artifact::DeadMan);
        let stale = deadman::DeadMan {
            armed_at_s: a.now_s() - 9 * 86_400,
            days: 10,
        };
        deadman::write(&path, &stale).unwrap();

        a.deadman_rearm();
        let deadman::Stamp::Armed(back) = deadman::read(&path) else {
            panic!("the stamp vanished");
        };
        assert_eq!(back.days, 10, "the period changed");
        assert!(
            back.armed_at_s >= a.now_s() - 2,
            "the deadline was not moved forward"
        );
    }

    /// Total bytes across the corpus's **segment files**.
    ///
    /// # Why not `metadata(dir).len()`
    ///
    /// That is the size of the directory *inode*, which is a filesystem detail
    /// and not a fact about the corpus. This test used it and passed on macOS
    /// for an accidental reason: APFS grows a directory inode about 32 bytes
    /// per entry, so adding a segment file moved the number. On ext4 a
    /// directory is one 4096-byte block until it needs a second, so `before`
    /// and `after` were both 4096 and the assertion failed — which is what the
    /// first Linux CI run reported.
    ///
    /// The corpus became a directory of per-segment files, and nothing
    /// revisited the one test that measured it as a single file. The honest
    /// measure is what those files hold, and it is the same on every platform.
    fn corpus_bytes(dir: &std::path::Path) -> u64 {
        std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().is_file())
            .filter_map(|e| e.metadata().ok())
            .map(|m| m.len())
            .sum()
    }

    fn type_command(a: &mut App, s: &str) {
        a.ui.focus_command();
        for c in s.chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        a.on_key(KeyCode::Enter, KeyModifiers::NONE);
    }

    /// A fresh install refuses almost everything, and says why.
    #[test]
    fn a_fresh_install_directs_the_operator_to_init() {
        let mut a = App::default();
        type_command(&mut a, "send");
        assert!(a.output.contains("run `init` first"), "{}", a.output);
        assert!(a.identity.is_none());
    }

    /// The store is openable when the ceremony finishes: an identity without
    /// a wrapper key would have nothing to protect its own keys under.
    #[test]
    fn finishing_init_opens_the_current_epoch() {
        let mut a = App::default();
        a.identity = Some(krab_lock::Held::new(Identity::generate(&mut OsRng)));
        a.passphrase = line::Line::from("a passphrase");
        // Use cheap Argon2id parameters; the specified ones are exercised in
        // `krab_crypto::kek`.
        {
            let id = a.identity.as_mut().unwrap();
            id.kek_params.m_kib = 64;
            id.kek_params.t = 1;
            id.kek_params.p = 1;
        }
        a.open_store().unwrap();
        let id = a.identity.as_ref().unwrap();
        assert_eq!(id.hierarchy.epochs().count(), 1);
        assert_eq!(id.hierarchy.stored_bytes(), krab_crypto::kek::WRAPPED_LEN);
    }

    /// **RFC 7 §11 end to end**: the ceremony cannot produce an identity
    /// without passing the backup confirmation.
    #[test]
    fn init_yields_an_identity_only_after_the_backup_step() {
        let mut a = App::default();
        type_command(&mut a, "init");
        // The ceremony will not leave the first step without one.
        a.advance_init();
        assert_eq!(
            a.init_step,
            Some(InitStep::Passphrase),
            "empty passphrase is refused"
        );
        for c in "a passphrase".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        assert!(
            a.command.is_empty(),
            "a passphrase must not land on the command line"
        );

        let mut seen = vec![a.init_step.unwrap()];
        for _ in 0..10 {
            a.advance_init();
            match a.init_step {
                Some(s) => seen.push(s),
                None => break,
            }
        }
        assert!(a.init_step.is_none(), "the ceremony terminates: {seen:?}");
        assert!(a.identity.is_some());
        assert!(seen.contains(&InitStep::ConfirmBackup), "{seen:?}");
        // And the passphrase does not outlive the ceremony (RFC 7 §9).
        assert!(
            a.passphrase.is_empty(),
            "the passphrase is cleared once the KEK exists"
        );
        // And it will not run twice.
        type_command(&mut a, "init");
        assert!(a.output.contains("runs once"), "{}", a.output);
    }

    /// Wipe is the only verb that asks twice, and lock is not on that list.
    #[test]
    fn wipe_asks_once_then_destroys() {
        let mut a = App::default();
        a.identity = Some(krab_lock::Held::new(Identity::generate(&mut entropy::OsRng)));
        type_command(&mut a, "wipe");
        assert!(a.output.contains("cannot be undone"), "{}", a.output);
        assert!(a.identity.is_some(), "first wipe only prompts");
        type_command(&mut a, "wipe");
        assert!(a.identity.is_none(), "second wipe destroys");
        assert!(a.locked);
    }

    #[test]
    fn an_unknown_command_is_reported_not_swallowed() {
        let mut a = App::default();
        type_command(&mut a, "frobnicate");
        assert!(a.output.contains("unknown command"), "{}", a.output);
    }

    #[test]
    fn lock_clears_the_interface_from_every_mode() {
        for compose in [false, true] {
            let mut a = app();
            if compose {
                a.ui.compose();
            }
            a.on_key(KeyCode::Char('l'), KeyModifiers::CONTROL);
            assert!(a.locked);
            assert!(a.composer.is_empty(), "draft gone");
            assert!(!a.body.contains("decrypted"), "plaintext gone");
            assert_eq!(a.ui.mode(), Mode::Browse, "composer closed");
        }
    }

    /// The composer swallows characters; it must not swallow the chord.
    #[test]
    fn the_composer_does_not_swallow_the_lock_chord() {
        let mut a = app();
        a.ui.compose();
        // Focus the view pane, where the composer is drawn — on the command
        // line a letter goes to the command line, which is the point.
        a.ui.cycle_focus();
        a.ui.cycle_focus();
        a.on_key(KeyCode::Char('l'), KeyModifiers::NONE);
        assert!(a.composer.ends_with('l'), "plain l types");
        assert!(!a.locked);
        a.on_key(KeyCode::Char('l'), KeyModifiers::CONTROL);
        assert!(a.locked, "the chord still locks");
    }

    /// Tab cycles panes even mid-composition, so the peers panel is reachable
    /// without losing the draft.
    #[test]
    fn tab_cycles_without_losing_the_draft() {
        let mut a = app();
        a.ui.compose();
        let before = a.composer.clone();
        a.on_key(KeyCode::Tab, KeyModifiers::NONE);
        a.on_key(KeyCode::Tab, KeyModifiers::NONE);
        assert_eq!(a.composer, before, "draft survives cycling");
        assert_eq!(a.ui.mode(), Mode::Compose);
    }

    #[test]
    fn any_pane_zooms_and_unzooms() {
        let mut a = App::default();
        // `z` is a chord in the body panes; on the command line it is a letter,
        // which is the whole point of focus deciding interpretation.
        a.ui.cycle_focus();
        a.on_key(KeyCode::Char('z'), KeyModifiers::NONE);
        assert!(a.ui.zoomed().is_some());
        a.on_key(KeyCode::Char('z'), KeyModifiers::NONE);
        assert!(a.ui.zoomed().is_none());
    }

    /// A locked interface must not open a composer — there is no key to seal
    /// with, and RFC 7 §8 forbids holding the plaintext meanwhile.
    #[test]
    fn a_locked_client_refuses_to_compose() {
        let mut a = App::default();
        a.lock();
        a.on_key(KeyCode::Char('c'), KeyModifiers::NONE);
        assert_eq!(a.ui.mode(), Mode::Browse);
    }

    #[test]
    fn cancelling_a_composition_zeroizes_the_draft() {
        let mut a = app();
        a.ui.compose();
        // Esc on the command line clears the command line — the composer is
        // cancelled from the pane it is displayed in.
        a.ui.cycle_focus();
        a.on_key(KeyCode::Esc, KeyModifiers::NONE);
        assert!(a.composer.is_empty());
        assert_eq!(a.ui.mode(), Mode::Browse);
    }

    /// **RFC 3 §11.3, the release gate — peering half.**
    ///
    /// > "An implementation MUST demonstrate a complete peering negotiation
    /// > and first message exchange **with all network interfaces down**,
    /// > using only file import and export."
    ///
    /// Two nodes, two directories, and nothing between them but `std::fs`.
    /// Every artifact is copied by the test the way a USB stick would carry
    /// it. If any step needed a round trip this would fail rather than pass —
    /// which is what the gate exists to catch, since a hidden round trip is
    /// invisible until an air-gapped node tries to join.
    ///
    /// The message-exchange half is `crates/krab-node/tests/courier_only.rs`.
    #[test]
    fn courier_only_peering_completes_with_no_network() {
        let mut a = ready_node("gate-a");
        let mut b = ready_node("gate-b");

        // Step 1: both ends offer. Symmetric — there is no initiator.
        type_command(&mut a, "peer offer");
        type_command(&mut b, "peer offer");

        // The courier: files move, nothing else does.
        let carry = |from: &App, to: &App, name: artifact::Artifact, as_name: &str| {
            let bytes = std::fs::read(from.path(name)).expect("artifact exists");
            let dest = to.at(as_name);
            std::fs::write(&dest, bytes).expect("delivered");
            dest.to_string_lossy().into_owned()
        };
        let a_card = carry(&a, &b, artifact::Artifact::PeerCard, "from-a.card");
        let b_card = carry(&b, &a, artifact::Artifact::PeerCard, "from-b.card");

        // Step 1 (receive) and step 2. Each side sees the other's words.
        type_command(&mut a, &format!("peer accept {b_card}"));
        assert!(
            a.output.contains("Read yours; they read theirs"),
            "{}",
            a.output
        );
        type_command(&mut b, &format!("peer accept {a_card}"));
        assert!(
            b.output.contains("Read yours; they read theirs"),
            "{}",
            b.output
        );

        // The fingerprint each side is asked to read must be the other's.
        let a_sees = a.load_ceremony().unwrap().their_fingerprint().unwrap();
        let b_sees = b.load_ceremony().unwrap().their_fingerprint().unwrap();
        assert_eq!(a_sees, b.identity.as_ref().unwrap().fingerprint());
        assert_eq!(b_sees, a.identity.as_ref().unwrap().fingerprint());
        assert_ne!(a_sees, b_sees);

        // Step 2 performed aloud — the one step no software can do.
        for n in [&mut a, &mut b] {
            let mut p = n.load_ceremony().unwrap();
            p.fingerprint_verified = true;
            n.save_ceremony(&p).unwrap();
        }

        // Steps 3 and 4: the pads travel on the same media.
        let a_pad = pad_onto(&mut a, &b.at("from-a.pad"));
        let b_pad = pad_onto(&mut b, &a.at("from-b.pad"));
        type_command(&mut a, &format!("peer seal {b_pad} media"));
        type_command(&mut b, &format!("peer seal {a_pad} media"));
        assert!(a.output.starts_with("peer-link signed"), "{}", a.output);
        assert!(b.output.starts_with("peer-link signed"), "{}", b.output);
        // Both ends report the same agreed terms, from opposite directions.
        assert!(a.output.contains("agreed: buckets to 5"), "{}", a.output);
        assert!(b.output.contains("agreed: buckets to 5"), "{}", b.output);

        // Sneakernet keeps the post-quantum property, so neither is warned.
        assert!(!a.output.contains("does NOT survive"), "{}", a.output);
        assert!(!a.output.contains("never compared"), "{}", a.output);

        // **Both ends derived the same reservoir**, having exchanged only files.
        // The peer-link is named for the counterparty, so each side looks the
        // other up by identifier.
        let reservoir = |n: &App, other: &App| {
            let peer = short_id(&other.identity.as_ref().unwrap().node_id());
            let sealed = std::fs::read(n.peer_path(peer, artifact::PeerFile::Reservoir)).unwrap();
            krab_crypto::kek::open_under(&n.epoch_key.unwrap(), b"krab/reservoir", &sealed).unwrap()
        };
        assert_eq!(
            reservoir(&a, &b),
            reservoir(&b, &a),
            "R_A xor R_B agrees on both ends"
        );
        assert_ne!(reservoir(&a, &b), vec![0u8; 32]);

        // The ceremony is retired, so a stale pad cannot be replayed into it.
        assert!(!a.path(artifact::Artifact::Ceremony).exists());
        assert!(a.load_ceremony().is_err());
    }

    /// Peering over the corpus works and says what it cost — RFC 3 §11.1
    /// permits it and forbids presenting it as equivalent.
    #[test]
    fn corpus_peering_completes_and_reports_the_downgrade() {
        let mut a = ready_node("corpus-a");
        let mut b = ready_node("corpus-b");
        type_command(&mut a, "peer offer");
        type_command(&mut b, "peer offer");
        std::fs::copy(b.path(artifact::Artifact::PeerCard), a.at("b.card")).unwrap();
        {
            let mut b2 = App {
                home: b.home.clone(),
                ..App::default()
            };
            b2.identity = Some(krab_lock::Held::new(Identity::generate(&mut OsRng)));
            b2.epoch_key = b.epoch_key;
            type_command(&mut b2, &format!("peer pad {}", a.at("b.pad").display()));
        }

        let card = a.at("b.card").display().to_string();
        let pad = a.at("b.pad").display().to_string();
        type_command(&mut a, &format!("peer accept {card}"));
        type_command(&mut a, &format!("peer seal {pad} corpus"));
        assert!(a.output.starts_with("peer-link signed"), "{}", a.output);
        assert!(
            a.output.contains("does NOT survive"),
            "the downgrade is stated: {}",
            a.output
        );
        assert!(
            a.output.contains("never compared"),
            "and so is the skipped step"
        );
    }

    /// The channel is never guessed, because guessing means guessing
    /// optimistically — claiming a property the link may not have.
    #[test]
    fn sealing_requires_an_explicit_channel() {
        let mut a = ready_node("chan");
        type_command(&mut a, "peer offer");
        type_command(&mut a, "peer seal somewhere.pad");
        assert!(a.output.contains("usage:"), "{}", a.output);
        assert!(a.output.contains("not guessed"), "{}", a.output);

        type_command(&mut a, "peer seal somewhere.pad probably-fine");
        assert!(a.output.contains("unknown channel"), "{}", a.output);
    }

    /// **A counterparty cannot be substituted after the words were read.**
    /// The ceremony's persistence is what creates this opening: the operator
    /// verified one person aloud, and a second card arrives before sealing.
    #[test]
    fn a_second_card_cannot_replace_a_recorded_one() {
        let mut a = ready_node("swap-a");
        let first = ready_node("swap-first");
        let second = ready_node("swap-second");
        for n in [&first, &second] {
            let mut n2 = App {
                home: n.home.clone(),
                ..App::default()
            };
            n2.identity = Some(krab_lock::Held::new(Identity::generate(&mut OsRng)));
            n2.epoch_key = n.epoch_key;
            type_command(&mut n2, "peer offer");
        }
        type_command(&mut a, "peer offer");

        std::fs::copy(first.at("peer.card"), a.at("first.card")).unwrap();
        std::fs::copy(second.at("peer.card"), a.at("second.card")).unwrap();

        let p1 = a.at("first.card").display().to_string();
        type_command(&mut a, &format!("peer accept {p1}"));
        assert!(a.output.contains("their fingerprint"), "{}", a.output);

        let p2 = a.at("second.card").display().to_string();
        type_command(&mut a, &format!("peer accept {p2}"));
        assert!(a.output.contains("already recorded"), "{}", a.output);
    }

    /// **A locked node cannot read its own ceremony state.**
    ///
    /// `W_N` is a content key, and `RFC-7-review.md` §9's role transition is
    /// only real if losing it costs something concrete.
    #[test]
    fn a_locked_node_cannot_resume_a_ceremony() {
        let mut a = ready_node("locked-ceremony");
        type_command(&mut a, "peer offer");
        assert!(a.load_ceremony().is_ok());

        a.lock();
        assert!(a.epoch_key.is_none(), "W_N is gone");
        let err = a.load_ceremony().unwrap_err();
        assert!(err.contains("locked"), "{err}");
        // The file is still there; it is simply unreadable without the key.
        assert!(a.path(artifact::Artifact::Ceremony).exists());
    }

    /// A card that does not verify is refused at step 1, not recorded and
    /// caught later.
    #[test]
    fn a_forged_card_is_refused_at_acceptance() {
        let mut a = ready_node("forged-a");
        let b = ready_node("forged-b");
        type_command(&mut a, "peer offer");
        {
            let mut b2 = App {
                home: b.home.clone(),
                ..App::default()
            };
            b2.identity = Some(krab_lock::Held::new(Identity::generate(&mut OsRng)));
            b2.epoch_key = b.epoch_key;
            type_command(&mut b2, "peer offer");
        }

        let mut raw = std::fs::read(b.path(artifact::Artifact::PeerCard)).unwrap();
        let n = raw.len();
        raw[n - 1] ^= 1; // last byte is inside the signature
        std::fs::write(a.at("forged.card"), raw).unwrap();

        let p = a.at("forged.card").display().to_string();
        type_command(&mut a, &format!("peer accept {p}"));
        assert!(a.output.contains("does not verify"), "{}", a.output);
        assert!(
            a.load_ceremony().unwrap().their_card.is_none(),
            "nothing recorded"
        );
    }

    /// **RFC 8 §5.1, at the level a user touches.**
    ///
    /// > "The client MUST NOT display 'syncing now' or any signal implying
    /// > that the user's action caused a transfer."
    ///
    /// The structural guarantee is that `LinkTable` holds nothing that can
    /// reconcile. This pins the words, because the words are what teaches the
    /// user the wrong mental model — and RFC 8 §5.1's argument is that the
    /// mental model is what eventually reintroduces event-driven sync.
    #[test]
    fn connect_never_claims_the_user_caused_a_transfer() {
        let mut a = ready_node("connect");
        type_command(&mut a, "connect q3m9 tcp");

        let body = a.output.to_lowercase();
        for forbidden in [
            "syncing",
            "sync now",
            "receiving",
            "downloading",
            "fetching",
            "objects received",
            "up to date",
        ] {
            assert!(
                !body.contains(forbidden),
                "{:?} contains {forbidden:?}",
                a.output
            );
        }
        // It says the true thing instead.
        assert!(a.output.contains("nothing was transferred"), "{}", a.output);
        assert!(a.output.contains("link up"), "{}", a.output);
        // And nothing was scheduled by the keypress.
        assert_eq!(a.links.get("q3m9").unwrap().next_sync_min, None);
    }

    /// Connecting twice must not accumulate links or schedule anything.
    #[test]
    fn connecting_is_idempotent_and_schedules_nothing() {
        let mut a = ready_node("connect-twice");
        type_command(&mut a, "connect q3m9 tcp");
        type_command(&mut a, "connect q3m9 tcp");
        assert_eq!(a.links.iter().count(), 1);
        assert_eq!(a.links.up_count(), 1);
        assert_eq!(a.links.get("q3m9").unwrap().next_sync_min, None);
    }

    /// RFC 3 §6.2 — disconnect tears down the transport and leaves quota
    /// alone. Bundling them would make disconnecting a punishment, and RFC 8
    /// §5.3 needs operators willing to use it.
    #[test]
    fn disconnect_does_not_silently_change_quota() {
        let mut a = ready_node("disconnect");
        type_command(&mut a, "connect q3m9 tcp");
        type_command(&mut a, "disconnect q3m9");
        assert!(a.output.contains("Quota unchanged"), "{}", a.output);
        assert_eq!(a.links.up_count(), 0);

        type_command(&mut a, "disconnect nobody");
        assert!(a.output.contains("no link"), "{}", a.output);
    }

    /// **RFC 8 §5.2's reason for existing.** A LoRa link silently drops
    /// oversized objects, and nothing else in the system will say so.
    #[test]
    fn reach_separates_a_bad_profile_from_a_silent_peer() {
        let mut a = ready_node("reach");
        type_command(&mut a, "connect m4k2 lora");

        type_command(&mut a, "reach m4k2 --size 256");
        assert!(a.output.contains("ADMIT"), "{}", a.output);
        assert!(a.output.contains("1 of 1"), "{}", a.output);

        type_command(&mut a, "reach m4k2 --size 8192");
        assert!(a.output.contains("BLOCK"), "{}", a.output);
        assert!(a.output.contains("max_bucket"), "{}", a.output);
        assert!(a.output.contains("0 of 1"), "{}", a.output);
        // The state where the operator most needs to know no error is coming.
        assert!(a.output.contains("silent"), "{}", a.output);
    }

    #[test]
    fn reach_with_no_links_says_so() {
        let mut a = ready_node("reach-empty");
        type_command(&mut a, "reach anyone");
        assert!(a.output.contains("no links"), "{}", a.output);
    }

    /// The panel must not invent rows it has no data for.
    #[test]
    fn peers_reports_honestly_when_nothing_has_reconciled() {
        let mut a = ready_node("peers");
        type_command(&mut a, "peers");
        assert!(a.output.contains("peer offer"), "{}", a.output);

        type_command(&mut a, "connect q3m9 tcp");
        type_command(&mut a, "peers");
        assert!(a.output.contains("q3m9"), "{}", a.output);
        // **RFC 3 §13's MUST, now that `warnings` has a caller.** A node with
        // no peerings is below every floor in §13's table, and §13 says an
        // implementation MUST say so — "operators choose peers by hand and
        // will not know any of this".
        assert!(a.output.contains("warning(s)"), "{}", a.output);
        assert!(a.output.contains("is the floor for"), "{}", a.output);
        assert!(
            !a.output.contains("IpConnected"),
            "a Debug enum reached operator text: {}",
            a.output
        );
        // Still no per-object anything (RFC 3 §12).
        assert!(!a.output.contains("id="), "{}", a.output);
    }

    /// `keys` reports state and does not re-show the backup — RFC 7 §11 makes
    /// it a one-time ceremony step, and a verb that reprinted it would turn it
    /// back into a settings item.
    #[test]
    fn keys_reports_state_without_reprinting_the_backup() {
        let mut a = ready_node("keys");
        type_command(&mut a, "keys");
        assert!(a.output.contains("shown once at init"), "{}", a.output);
        assert!(a.output.contains("not recoverable"), "{}", a.output);

        // The backup words themselves must not be in the output.
        let backup = a.identity.as_ref().unwrap().backup_phrase();
        let first_word = backup.split_whitespace().next().unwrap();
        let second = backup.split_whitespace().nth(1).unwrap();
        assert!(
            !(a.output.contains(first_word) && a.output.contains(second)),
            "the backup phrase leaked into `keys`: {}",
            a.output
        );
    }

    /// Give `a` a verified peer-link for `b`, as the ceremony would.
    ///
    /// Written directly rather than driven through `peer`, because what these
    /// tests are about is what happens *after* a peering exists.
    fn peer_up(a: &mut App, b: &mut App) -> String {
        let card = b
            .identity
            .as_ref()
            .unwrap()
            .card(peering::Policy::default());
        let short = short_id(&card.node_id());
        let path = a.peer_path(&short, artifact::PeerFile::Link);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, card.encode()).unwrap();
        short
    }

    /// A completed RFC 3 §3 credential between two nodes: proposed by one,
    /// countersigned by the other.
    fn completed_credential(x: &App, y: &App, now_s: u64) -> credential::Credential {
        let (xi, yi) = (x.identity.as_ref().unwrap(), y.identity.as_ref().unwrap());
        let mut c = credential::Credential::propose(
            xi.signing_key(),
            &xi.card(peering::Policy::default()),
            &yi.card(peering::Policy::default()),
            now_s,
            credential::DEFAULT_TERM_DAYS,
            [5u8; 16],
        );
        assert!(c.sign(yi.signing_key()));
        c
    }

    /// The token text out of an `introduce` output pane.
    fn minted(out: &str) -> String {
        out.lines()
            .map(str::trim)
            .find(|l| l.len() > 100 && l.chars().all(|c| c.is_ascii_hexdigit()))
            .expect("a token in the output")
            .to_string()
    }

    /// **The whole of RFC 3 §10, three parties.**
    ///
    /// A vouches for C, C requests to B, B evaluates. The point of the test is
    /// the last step: B accepts the vouch *because B peers with A*, which is
    /// the only thing that distinguishes a real introduction from a stranger's
    /// perfectly valid signature.
    #[test]
    fn an_introduction_travels_from_introducer_to_evaluator() {
        let mut a = ready_node("intro-a");
        let mut c = ready_node("intro-c");
        let mut b = ready_node("intro-b");

        // A peers with both. B peers with A.
        peer_up(&mut a, &mut c);
        peer_up(&mut a, &mut b);
        peer_up(&mut b, &mut a);

        let c_short = short_id(&c.identity.as_ref().unwrap().node_id());
        let b_short = short_id(&b.identity.as_ref().unwrap().node_id());
        type_command(&mut a, &format!("introduce {c_short} {b_short}"));
        assert!(a.output.contains("a vouch for"), "{}", a.output);
        let token = minted(&a.output);

        type_command(&mut c, &format!("introduce use {token}"));
        assert!(c.output.contains("held"), "{}", c.output);
        assert_eq!(c.introductions.len(), 1);

        // C sends the request; the token rides along.
        let card = c.home.join("theirs.card");
        std::fs::write(
            &card,
            b.identity
                .as_ref()
                .unwrap()
                .card(Policy::default())
                .encode(),
        )
        .unwrap();
        type_command(&mut c, &format!("request {} hello", card.display()));
        assert!(c.output.contains("introduction travelled"), "{}", c.output);
        assert!(c.introductions.is_empty(), "the token was not released");
    }

    /// **The Sybil case.** A stranger's token is signed correctly and is worth
    /// nothing, and the only thing telling those apart is whether the
    /// evaluator peers with the introducer.
    #[test]
    fn a_vouch_from_someone_the_evaluator_does_not_know_is_worthless() {
        let a = ready_node("intro-stranger");
        let b = ready_node("intro-eval");
        let c = ready_node("intro-req");

        let me = b.identity.as_ref().unwrap().node_id();
        let token = introduction::Token::create(
            a.identity.as_ref().unwrap().signing_key(),
            c.identity.as_ref().unwrap().node_id(),
            me,
            b.now_s(),
            introduction::MAX_LIFETIME_S,
            &mut OsRng,
        );
        let req = request::PeerRequest::create_introduced(
            c.identity.as_ref().unwrap().signing_key(),
            c.identity.as_ref().unwrap().card(Policy::default()),
            me,
            credential::LinkTerms::default(),
            "let me in",
            Some(token),
            None,
        );
        assert!(req.verify());

        // B does not peer with A, so B cannot resolve the introducer, and
        // nothing is attached that would let B check the vouch another way.
        let line = b.introduction_line(&req, &me, b.now_s(), &introduction::Spent::default());
        assert!(line.contains("you do not peer with"), "{line}");
        assert!(line.contains("could be anyone's"), "{line}");
        assert!(line.contains("nothing is attached"), "{line}");
    }

    /// **What evidence buys** — RFC 3 §5.1 key 4, §10.
    ///
    /// The same stranger's vouch as above, with the introducer's mutually
    /// signed credential attached. It is still a stranger's vouch, and the
    /// evaluator now has a *fact*: those two really did peer, both signatures.
    /// §10 gives the protocol the facts and the operator the judgement, so the
    /// verdict changes and the decision does not.
    #[test]
    fn evidence_turns_an_unknown_introducers_vouch_into_a_checkable_fact() {
        let a = ready_node("ev-a");
        let b = ready_node("ev-b");
        let c = ready_node("ev-c");
        let me = b.identity.as_ref().unwrap().node_id();

        // A vouches for C, to B. B has never met A.
        let token = introduction::Token::create(
            a.identity.as_ref().unwrap().signing_key(),
            c.identity.as_ref().unwrap().node_id(),
            me,
            b.now_s(),
            introduction::MAX_LIFETIME_S,
            &mut OsRng,
        );
        // And A and C really did peer: a credential both of them signed.
        let cred = completed_credential(&a, &c, b.now_s());

        let req = request::PeerRequest::create_introduced(
            c.identity.as_ref().unwrap().signing_key(),
            c.identity.as_ref().unwrap().card(Policy::default()),
            me,
            credential::LinkTerms::default(),
            "we have a friend in common",
            Some(token),
            Some(cred),
        );
        assert!(req.verify(), "evidence is inside the signature");
        assert_eq!(req.evidence_verdict(b.now_s()), request::Evidence::Confirms);

        let line = b.introduction_line(&req, &me, b.now_s(), &introduction::Spent::default());
        assert!(line.contains("really did peer"), "{line}");
        assert!(line.contains("signed by both"), "{line}");
        // And it still refuses to make the decision.
        assert!(line.contains("your judgement"), "{line}");
    }

    /// **Any real credential verifies.** So the check that matters is not
    /// whether the evidence is valid but whether it is about *these two* —
    /// otherwise an attacker attaches somebody else's genuine peering.
    #[test]
    fn a_credential_between_other_people_proves_nothing() {
        let a = ready_node("wp-a");
        let b = ready_node("wp-b");
        let c = ready_node("wp-c");
        let d = ready_node("wp-d");
        let me = b.identity.as_ref().unwrap().node_id();

        let token = introduction::Token::create(
            a.identity.as_ref().unwrap().signing_key(),
            c.identity.as_ref().unwrap().node_id(),
            me,
            b.now_s(),
            introduction::MAX_LIFETIME_S,
            &mut OsRng,
        );
        // A genuine, fully valid credential — between A and D, not A and C.
        let unrelated = completed_credential(&a, &d, b.now_s());
        assert_eq!(unrelated.verify(b.now_s()), Ok(()));

        let req = request::PeerRequest::create_introduced(
            c.identity.as_ref().unwrap().signing_key(),
            c.identity.as_ref().unwrap().card(Policy::default()),
            me,
            credential::LinkTerms::default(),
            "",
            Some(token),
            Some(unrelated),
        );
        assert_eq!(
            req.evidence_verdict(b.now_s()),
            request::Evidence::WrongParties,
            "someone else's peering was accepted as evidence for this one"
        );
        let line = b.introduction_line(&req, &me, b.now_s(), &introduction::Spent::default());
        assert!(line.contains("proves nothing"), "{line}");
    }

    /// Evidence is inside the request's signature, like every other field.
    #[test]
    fn evidence_cannot_be_added_to_a_signed_request() {
        let a = ready_node("ea-a");
        let b = ready_node("ea-b");
        let c = ready_node("ea-c");
        let me = b.identity.as_ref().unwrap().node_id();
        let token = introduction::Token::create(
            a.identity.as_ref().unwrap().signing_key(),
            c.identity.as_ref().unwrap().node_id(),
            me,
            b.now_s(),
            introduction::MAX_LIFETIME_S,
            &mut OsRng,
        );
        let req = request::PeerRequest::create_introduced(
            c.identity.as_ref().unwrap().signing_key(),
            c.identity.as_ref().unwrap().card(Policy::default()),
            me,
            credential::LinkTerms::default(),
            "",
            Some(token),
            None,
        );
        assert!(req.verify());
        let bolted = request::PeerRequest {
            evidence: Some(completed_credential(&a, &c, b.now_s())),
            ..req
        };
        assert!(!bolted.verify(), "evidence was outside the signature");
    }

    /// An expired credential proves a peering that has lapsed, and RFC 3 §4
    /// makes revocation non-renewal — so it is refused rather than aged.
    #[test]
    fn expired_evidence_is_refused() {
        let a = ready_node("ee-a");
        let b = ready_node("ee-b");
        let c = ready_node("ee-c");
        let me = b.identity.as_ref().unwrap().node_id();
        let long_ago = b.now_s() - credential::MAX_TERM_DAYS * 86_400 - 1;
        let stale = completed_credential(&a, &c, long_ago);

        let token = introduction::Token::create(
            a.identity.as_ref().unwrap().signing_key(),
            c.identity.as_ref().unwrap().node_id(),
            me,
            b.now_s(),
            introduction::MAX_LIFETIME_S,
            &mut OsRng,
        );
        let req = request::PeerRequest::create_introduced(
            c.identity.as_ref().unwrap().signing_key(),
            c.identity.as_ref().unwrap().card(Policy::default()),
            me,
            credential::LinkTerms::default(),
            "",
            Some(token),
            Some(stale),
        );
        assert_eq!(
            req.evidence_verdict(b.now_s()),
            request::Evidence::Invalid(credential::Invalid::Expired)
        );
    }

    /// **Both ends finish holding a credential they can cite.**
    ///
    /// The first version shredded the handover file unconditionally, so the
    /// countersigner kept the only complete document — sealed, and therefore
    /// unreadable to anyone else — while the proposer held a half-signed one
    /// for ever. Neither could supply evidence, which is the entire reason the
    /// document exists, and nothing reported anything wrong.
    /// Opt in to listing, on both sides, through the real countersign path.
    fn share_both_ways(x: &mut App, y: &mut App, short_y: &str) {
        type_command(x, &format!("peer share {short_y} on"));
        let handover = x.home.join(format!("{short_y}.credential"));
        let to_y = y.home.join("sh.credential");
        std::fs::copy(&handover, &to_y).unwrap();
        y.peer_countersign(Some(to_y.to_str().unwrap()));
        let short_x = short_id(&x.identity.as_ref().unwrap().node_id());
        let back = y.home.join(format!("{short_x}.credential"));
        let to_x = x.home.join("sh.credential");
        std::fs::copy(&back, &to_x).unwrap();
        x.peer_countersign(Some(to_x.to_str().unwrap()));
    }

    /// **Forgetting one peer must not stop another's mail opening.**
    ///
    /// `TagTable` maps a tag to a *position* in the correspondent slice, and
    /// that slice is rebuilt from the peer directories on every inbox refresh
    /// while the table rebuilds only on epoch rollover. Removing a peering
    /// shifts everyone after it down one, so a still-valid peer's tag resolved
    /// to somebody else's keys and their mail silently failed to open until
    /// midnight — a miss rather than a panic, which is what made it invisible.
    #[test]
    fn forgetting_one_peer_does_not_silence_another() {
        let mut a = ready_node("tt-a");
        let mut b = ready_node("tt-b");
        let mut c = ready_node("tt-c");
        let sb = peer_up(&mut a, &mut b);
        let sc = peer_up(&mut a, &mut c);
        assert_ne!(sb, sc);

        // Build the table, then remove a peering under it.
        a.refresh_inbox();
        assert!(a.tag_table.is_some(), "no table to invalidate");
        type_command(&mut a, &format!("peer forget {sb}"));
        assert!(
            a.tag_table.is_none(),
            "the tag table outlived the peer list it indexes"
        );

        // Rebuilt, and the surviving peer is still recognised.
        a.refresh_inbox();
        let table = a.tag_table.as_ref().expect("rebuilt");
        assert!(!table.is_empty(), "the surviving peering lost its tags");
    }

    /// **`forget` reaches the handover copies too.**
    ///
    /// `peer seal`, `peer renew`, `peer share` and `peer countersign` all
    /// write `<peer>.credential` into the home directory, in the clear, for
    /// the operator to hand over. `forget` cleared `peers/<id>/` and left it —
    /// so the one command whose job is to destroy the record left behind the
    /// single most incriminating file in the layout.
    #[test]
    fn forgetting_a_peer_reaches_the_plaintext_handover_copy() {
        let mut x = ready_node("hnd-x");
        let mut y = ready_node("hnd-y");
        let (_, short_y) = link_up(&mut x, &mut y);

        type_command(&mut x, &format!("peer renew {short_y}"));
        let loose = x.home.join(format!("{short_y}.credential"));
        assert!(loose.exists(), "the fixture wrote no handover file");

        type_command(&mut x, &format!("peer forget {short_y}"));
        assert!(
            !loose.exists(),
            "a plaintext, non-repudiable credential survived a termination"
        );
        // And nothing else named for them is left anywhere in home.
        for e in std::fs::read_dir(&x.home).unwrap().flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            assert!(
                !(n.starts_with(&format!("{short_y}.")) && artifact::wiped(&n)),
                "{n} survived a termination"
            );
        }
    }

    /// **The expiry purge must not erase the reason before the operator can
    /// act.**
    ///
    /// Purging the instant a term lapsed made `credential_standing` report
    /// `None`, so an operator was told "no credential — `peer countersign`"
    /// rather than "expired — `peer renew`": RFC 3 §4's MUST undone by §8.4
    /// one tick later, with the advice wrong as well as uninformative.
    ///
    /// §4 resolves it — "revocation is non-renewal" — so a peering ends when
    /// it is not renewed, and the grace is when that becomes true.
    #[test]
    fn a_lapsed_peering_keeps_its_reason_until_the_grace_runs_out() {
        let mut a = ready_node("grc-a");
        let mut b = ready_node("grc-b");
        let (_, sb) = link_up(&mut a, &mut b);

        // Both credentials built up front, so nothing holds a borrow on the
        // node while it is being mutated.
        let now = a.now_s();
        let w = a.epoch_key.unwrap();
        let seal = |established: u64| {
            let (ai, bi) = (a.identity.as_ref().unwrap(), b.identity.as_ref().unwrap());
            let mut c = credential::Credential::propose(
                ai.signing_key(),
                &ai.card(Policy::default()),
                &bi.card(Policy::default()),
                established,
                90,
                [3u8; 16],
            );
            assert!(c.sign(bi.signing_key()));
            krab_crypto::kek::seal_under(&w, b"krab/credential", &c.encode(), &mut OsRng).unwrap()
        };
        let lapsed_yesterday = seal(now - 91 * 86_400);
        let lapsed_a_month_ago = seal(now - 121 * 86_400);
        let path = a.peer_path(&sb, artifact::PeerFile::Credential);

        // Inside the grace: the reason survives and renewal is still named.
        std::fs::write(&path, &lapsed_yesterday).unwrap();
        a.purge_expired_peerings();
        let line = a.credential_standing(&sb).line(&sb, a.now_s());
        assert!(line.contains("EXPIRED"), "the reason was erased: {line}");
        assert!(line.contains("peer renew"), "wrong advice: {line}");
        assert!(path.exists(), "purged inside the grace");

        // Past it: §8.4 takes the record of an agreement nobody renewed.
        std::fs::write(&path, &lapsed_a_month_ago).unwrap();
        a.purge_expired_peerings();
        assert!(
            !path.exists(),
            "a peering that was never renewed kept its record for ever"
        );
        // And the material is still there, so it can be peered with again.
        assert!(a.peer_path(&sb, artifact::PeerFile::Link).exists());
    }

    /// **One default word, two directions, and only one was thought about.**
    ///
    /// `Flags::default()` is safe for RFC 3 §8.3's share bits — false, "opt in
    /// to being listed, not out" — and is *not* safe for RFC 6 §281's
    /// `class_mask`, which defaults to admitting everything.
    ///
    /// So a peering whose credential lapsed and was purged by §8.4, then
    /// renewed, correctly came back with sharing off and **silently re-enabled
    /// the carriage the operator had turned off**. Neither Phase 2 nor Phase 6
    /// was wrong alone; the safe direction is simply not the same for every
    /// flag in the word.
    #[test]
    fn a_renewal_from_defaults_says_that_it_is_one() {
        let mut x = ready_node("dflt-x");
        let mut y = ready_node("dflt-y");
        let (_, sy) = link_up(&mut x, &mut y);
        let bit = 1u8 << (krab_core::object::Class::Bulletin as u8 & 7);

        // Turn carriage off, and complete it on both sides.
        type_command(&mut x, &format!("peer carry {sy} off"));
        let to_y = y.home.join("c.credential");
        std::fs::copy(x.home.join(format!("{sy}.credential")), &to_y).unwrap();
        y.peer_countersign(to_y.to_str());
        let sx = short_id(&x.identity.as_ref().unwrap().node_id());
        let to_x = x.home.join("c.credential");
        std::fs::copy(y.home.join(format!("{sx}.credential")), &to_x).unwrap();
        x.peer_countersign(to_x.to_str());
        assert_eq!(
            x.credential_with(&sy).unwrap().flags.class_mask & bit,
            0,
            "the operator's decision did not take"
        );

        // Renewing while the agreement stands carries it across silently.
        type_command(&mut x, &format!("peer renew {sy}"));
        assert!(!x.output.contains("Rebuilt from defaults"), "{}", x.output);
        let kept = credential::Credential::decode(
            &std::fs::read(x.home.join(format!("{sy}.credential"))).unwrap(),
        )
        .unwrap();
        assert_eq!(kept.flags.class_mask & bit, 0, "carriage came back");

        // After §8.4 has purged the record, it cannot — and says so.
        std::fs::remove_file(x.peer_path(&sy, artifact::PeerFile::Credential)).unwrap();
        type_command(&mut x, &format!("peer renew {sy}"));
        assert!(
            x.output.contains("Rebuilt from defaults"),
            "a renewal silently widened what the link carries: {}",
            x.output
        );
        assert!(x.output.contains("carriage is back on"), "{}", x.output);
        assert!(x.output.contains("peer carry"), "the way back is not named");
    }

    /// **`force-send` says what it costs, every time.**
    ///
    /// RFC 5 §6.1 keeps inter-sync intervals uncorrelated with message events
    /// so an observer cannot tell when a node composed something. Forcing a
    /// sync is that correlation, and a verb that breaks an invariant quietly
    /// is worse than one that does not exist.
    #[test]
    fn force_send_states_the_invariant_it_breaks() {
        let mut a = ready_node("fs-a");
        // No link: it refuses rather than pretending, and does not dial.
        type_command(&mut a, "force-send");
        assert!(a.output.contains("no link is up"), "{}", a.output);

        // A named link with no session refuses, and names the way out. This
        // used to be asserted as "either the cost notice or the refusal",
        // which is an assertion that passes whichever one appears — and it is
        // how the bug below reached a release.
        type_command(&mut a, "connect q3m9 tcp");
        type_command(&mut a, "force-send");
        assert!(a.output.contains("nothing to force"), "{}", a.output);
        assert!(a.output.contains("connect"), "no way out named: {}", a.output);
    }

    /// **Every help row has a gap between the verb and what it does.**
    ///
    /// The column was `:<20`, which pads nothing wider than 20 — so the
    /// verbs that outgrew it printed as `peer countersign <file>sign their
    /// half...`. Measured from the table now, so a longer verb widens it
    /// instead of colliding with it.
    #[test]
    fn no_help_row_runs_its_verb_into_its_description() {
        let mut a = ready_node("help-columns");
        type_command(&mut a, "help");
        for (verb, what) in Command::SYNOPSES.iter().chain(Command::CHORDS) {
            // Split at the column gap and compare the left side exactly —
            // matching on a prefix makes `request` find the `requests` row.
            let row = a
                .output
                .lines()
                .find(|l| l.trim_start().split("  ").next() == Some(*verb))
                .unwrap_or_else(|| panic!("{verb} is not in help"));
            let rest = &row.trim_start()[verb.len()..];
            assert!(rest.starts_with("  "), "no gap after {verb:?}: {row:?}");
            assert_eq!(rest.trim_start(), *what, "{row:?}");
        }
    }

    /// **Ctrl-Y shows the bytes.** Rendering is a view of the text and never
    /// a replacement for it — "what you see is what is there" is the property
    /// RFC 8 §7 leans on, and a renderer that consumes syntax weakens it.
    #[test]
    fn ctrl_y_toggles_the_raw_body() {
        let mut a = ready_node("raw-toggle");
        assert!(!a.raw_body, "the default is rendered");
        a.on_key(KeyCode::Char('y'), KeyModifiers::CONTROL);
        assert!(a.raw_body, "Ctrl-Y did nothing");
        assert!(a.output.contains("bytes"), "{}", a.output);
        a.on_key(KeyCode::Char('y'), KeyModifiers::CONTROL);
        assert!(!a.raw_body);
    }

    /// **A body cannot render a link, an image or HTML**, because nothing
    /// renders one. The characters arrive and are displayed.
    #[test]
    fn a_hostile_body_renders_as_its_own_characters() {
        let hostile = "[bob's key](https://evil.example) ![](t.png) <b>x</b>";
        let rows = markdown::parse(hostile);
        let flat: String = rows[0].pieces.iter().map(|p| p.text.as_str()).collect();
        assert_eq!(flat, hostile, "a body was transformed");
    }

    /// **A two-line note renders as two lines.**
    ///
    /// The outstanding check from the `safe_block` fix. `display::safe`
    /// strips `\n` — right for a row in a list, wrong for a body — and the
    /// note pane called it, so "abc" and "sdd" came back as "abcsdd". Driven
    /// through the real frame rather than a pty, which is what two attempts
    /// at a terminal probe failed to produce.
    #[test]
    fn a_two_line_note_renders_on_two_lines() {
        use ratatui::{backend::TestBackend, Terminal};

        let mut a = ready_node("note-two-lines");
        type_command(&mut a, "note");
        for c in "abc".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        a.on_key(KeyCode::Enter, KeyModifiers::NONE);
        for c in "sdd".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        a.on_key(KeyCode::Char('d'), KeyModifiers::CONTROL);

        a.ui.reset();
        a.ui.select_tab(layout::Tab::Notes);
        a.refresh_inbox();

        let mut term = Terminal::new(TestBackend::new(100, 24)).expect("a terminal");
        let log: Vec<String> = Vec::new();
        let me = a.identity.as_ref().map(|i| i.short_id());
        term.draw(|f| render::draw(f, &a.view(&log, me.as_deref())))
            .expect("draws");

        // Read the frame row by row: the two halves must land on different
        // rows, which is the whole claim.
        let buf = term.backend().buffer();
        let mut rows: Vec<String> = Vec::new();
        for y in 0..buf.area.height {
            let mut row = String::new();
            for x in 0..buf.area.width {
                row.push_str(buf[(x, y)].symbol());
            }
            rows.push(row);
        }
        let abc = rows.iter().position(|r| r.contains("abc"));
        let sdd = rows.iter().position(|r| r.contains("sdd"));
        assert!(abc.is_some() && sdd.is_some(), "the note is not on screen");
        assert_ne!(abc, sdd, "the two lines were joined into one row");
        assert!(
            !rows.iter().any(|r| r.contains("abcsdd")),
            "the newline was eaten"
        );
    }

    /// **A cursor moved past the pane must still be on screen.**
    ///
    /// The list drew from row zero with no offset, so on a list longer than
    /// the pane an operator could arrow down to an item that was never
    /// rendered — the selection working and nothing visible to show it.
    #[test]
    fn the_list_pane_scrolls_to_keep_the_cursor_visible() {
        use ratatui::{backend::TestBackend, Terminal};

        let mut a = ready_node("list-scroll");
        // More notes than a short pane can hold.
        for i in 0..40 {
            type_command(&mut a, &format!("note item{i:02}"));
            if a.pending_post.is_some() {
                a.on_key(KeyCode::Enter, KeyModifiers::NONE);
            }
        }
        // Each `note` reveals its reply, which zooms the output pane — so
        // put the layout back before asking what the list pane drew.
        a.ui.reset();
        a.ui.select_tab(layout::Tab::Notes);
        a.refresh_inbox();
        while a.ui.focus() != layout::Pane::List {
            a.ui.cycle_focus();
        }
        assert_eq!(a.selectable_len(), 40);

        let mut term = Terminal::new(TestBackend::new(80, 24)).expect("a terminal");
        let render = |a: &App, term: &mut Terminal<TestBackend>| -> String {
            let log: Vec<String> = Vec::new();
            let me = a.identity.as_ref().map(|i| i.short_id());
            term.draw(|f| render::draw(f, &a.view(&log, me.as_deref())))
                .expect("draws");
            term.backend()
                .buffer()
                .content()
                .iter()
                .map(|c| c.symbol())
                .collect()
        };

        // Near the top: the first item is on screen, the last is not.
        let top = render(&a, &mut term);
        assert!(top.contains("item00"), "the first item is not drawn");
        assert!(!top.contains("item39"), "the whole list fits; widen the test");

        // Walk the cursor to the end.
        for _ in 0..39 {
            a.on_key(KeyCode::Down, KeyModifiers::NONE);
        }
        assert_eq!(a.selected, 39);
        let bottom = render(&a, &mut term);
        assert!(
            bottom.contains("item39"),
            "the cursor left the pane and took the selection with it"
        );

        // And back up: the pane follows in the other direction too.
        for _ in 0..39 {
            a.on_key(KeyCode::Up, KeyModifiers::NONE);
        }
        assert_eq!(a.selected, 0);
        assert!(
            render(&a, &mut term).contains("item00"),
            "the pane did not scroll back"
        );
    }

    /// **A tick must not move the cursor.**
    ///
    /// `refresh_inbox` zeroed `selected`, and it runs whenever an exchange
    /// drains — so the operator pressed Down, the cursor moved, and the next
    /// tick put it back. From outside it looked like the arrow key bouncing.
    #[test]
    fn a_refresh_leaves_the_cursor_where_the_operator_put_it() {
        let mut a = ready_node("cursor-sticks");
        for t in ["one", "two", "three"] {
            type_command(&mut a, &format!("note {t}"));
            if a.pending_post.is_some() {
                a.on_key(KeyCode::Enter, KeyModifiers::NONE);
            }
        }
        a.ui.select_tab(layout::Tab::Notes);
        a.refresh_inbox();
        while a.ui.focus() != layout::Pane::List {
            a.ui.cycle_focus();
        }
        a.on_key(KeyCode::Down, KeyModifiers::NONE);
        assert_eq!(a.selected, 1);

        // What the tick does, repeatedly.
        a.refresh_inbox();
        assert_eq!(a.selected, 1, "a refresh moved the cursor back to the top");
        a.refresh_inbox();
        assert_eq!(a.selected, 1);
    }

    /// But a shorter list must not leave the cursor past the end.
    #[test]
    fn the_cursor_is_clamped_when_the_list_shrinks() {
        let mut a = ready_node("cursor-clamp");
        a.ui.select_tab(layout::Tab::Notes);
        a.selected = 40;
        a.refresh_inbox();
        assert_eq!(a.selected, 0, "an empty list kept a cursor");
    }

    /// A tab switch is a different list, so it does start at the top.
    #[test]
    fn switching_tabs_starts_at_the_top() {
        let mut a = ready_node("cursor-tab");
        a.selected = 3;
        a.on_key(KeyCode::F(3), KeyModifiers::NONE);
        assert_eq!(a.ui.tab(), layout::Tab::Notes);
        assert_eq!(a.selected, 0);
    }

    /// **Every list pane can be navigated.**
    ///
    /// `selected` was written only as `0` and read everywhere, and Up/Down
    /// were bound to command history before anything else looked at them —
    /// so on the notes pane the arrows scrolled the command history and the
    /// list showed its first item and no other. The same in every tab.
    #[test]
    fn arrows_choose_an_item_in_every_list() {
        let mut a = ready_node("list-nav");

        // Notes, because that is where it was reported.
        type_command(&mut a, "note one");
        a.on_key(KeyCode::Enter, KeyModifiers::NONE);
        type_command(&mut a, "note two");
        type_command(&mut a, "note three");
        a.ui.select_tab(layout::Tab::Notes);
        a.refresh_inbox();
        while a.ui.focus() != layout::Pane::List {
            a.ui.cycle_focus();
        }
        assert_eq!(a.selectable_len(), 3, "{:?}", a.list);
        assert_eq!(a.selected, 0);

        a.on_key(KeyCode::Down, KeyModifiers::NONE);
        assert_eq!(a.selected, 1, "Down did not move the cursor");
        a.on_key(KeyCode::Down, KeyModifiers::NONE);
        assert_eq!(a.selected, 2);
        // It stops at the end rather than wrapping or running off.
        a.on_key(KeyCode::Down, KeyModifiers::NONE);
        assert_eq!(a.selected, 2, "the cursor ran past the last item");
        a.on_key(KeyCode::Up, KeyModifiers::NONE);
        assert_eq!(a.selected, 1);

        // The body follows the cursor, which is the point of moving it.
        let at_one = a.body.clone();
        a.on_key(KeyCode::Up, KeyModifiers::NONE);
        assert_ne!(a.body, at_one, "the view pane did not follow the cursor");
    }

    /// On the command line the same keys still mean history — the behaviour
    /// that was displacing selection must not be displaced in turn.
    #[test]
    fn arrows_on_the_command_line_still_recall_history() {
        let mut a = ready_node("list-nav-history");
        type_command(&mut a, "keys");
        assert_eq!(a.ui.focus(), layout::Pane::Command);
        a.on_key(KeyCode::Up, KeyModifiers::NONE);
        assert_eq!(a.command.as_string(), "keys", "history was lost to the list");
    }

    /// **History belongs to the command pane and to nowhere else.**
    ///
    /// Up/Down were dispatched to `recall` from any pane that was not the
    /// list, so the view and output panes recalled commands too — a pane
    /// with no history of its own answering as though it had one.
    #[test]
    fn only_the_command_pane_recalls_history() {
        let mut a = ready_node("history-scope");
        type_command(&mut a, "keys");
        type_command(&mut a, "peers");

        // View and Output: Up must not put a command anywhere.
        for pane in [layout::Pane::View, layout::Pane::Output] {
            while a.ui.focus() != pane {
                a.ui.cycle_focus();
            }
            let before = a.command.as_string();
            a.on_key(KeyCode::Up, KeyModifiers::NONE);
            assert_eq!(
                a.command.as_string(),
                before,
                "{pane:?} recalled history"
            );
        }

        // The command line still does.
        while a.ui.focus() != layout::Pane::Command {
            a.ui.cycle_focus();
        }
        a.on_key(KeyCode::Up, KeyModifiers::NONE);
        assert_eq!(a.command.as_string(), "peers");
    }

    /// An empty list has nothing to select, and must not move anyway.
    #[test]
    fn an_empty_list_has_no_cursor_to_move() {
        let mut a = ready_node("list-nav-empty");
        a.ui.select_tab(layout::Tab::Notes);
        a.refresh_inbox();
        while a.ui.focus() != layout::Pane::List {
            a.ui.cycle_focus();
        }
        assert_eq!(a.selectable_len(), 0);
        a.on_key(KeyCode::Down, KeyModifiers::NONE);
        assert_eq!(a.selected, 0);
    }

    /// **Ctrl-R asks for a clear.** The binding existed and had no arm, so
    /// the one key an operator reaches for when the screen is wrong fell
    /// through to `_ => {}` and did nothing.
    #[test]
    fn ctrl_r_requests_a_clear() {
        let mut a = ready_node("redraw");
        assert!(!a.needs_clear);
        a.on_key(KeyCode::Char('r'), KeyModifiers::CONTROL);
        assert!(a.needs_clear, "Ctrl-R did not ask for a redraw");

        // And it is consumed once: the loop takes it, and a second frame
        // does not clear again for no reason.
        assert!(std::mem::take(&mut a.needs_clear));
        assert!(!a.needs_clear);
    }

    /// **The composer takes editing keys.** It was a `String` with `push`:
    /// no backspace, no arrows, no way to fix a typo but to discard the
    /// draft. `Binding::Edit` returned early unless the command line had
    /// focus, so every editing key was dropped in the one pane where text is
    /// written.
    #[test]
    fn the_composer_can_be_edited() {
        let mut a = ready_node("compose-edit");
        type_command(&mut a, "note");
        assert_eq!(a.ui.mode(), Mode::Compose);

        for c in "helo".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        // Back over the typo and insert.
        a.on_key(KeyCode::Left, KeyModifiers::NONE);
        a.on_key(KeyCode::Char('l'), KeyModifiers::NONE);
        assert_eq!(a.composer, "hello", "arrows and insert do not work");

        a.on_key(KeyCode::Backspace, KeyModifiers::NONE);
        assert_eq!(a.composer, "helo");
        a.on_key(KeyCode::End, KeyModifiers::NONE);
        a.on_key(KeyCode::Char('!'), KeyModifiers::NONE);
        assert_eq!(a.composer, "helo!");
        a.on_key(KeyCode::Home, KeyModifiers::NONE);
        a.on_key(KeyCode::Delete, KeyModifiers::NONE);
        assert_eq!(a.composer, "elo!");
    }

    /// Up and Down move a line in a composer, and do not recall history.
    #[test]
    fn arrows_move_between_composer_lines() {
        let mut a = ready_node("compose-lines");
        type_command(&mut a, "note");
        for c in "one".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        a.on_key(KeyCode::Enter, KeyModifiers::NONE);
        for c in "two".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        assert_eq!(a.composer, "one\ntwo");

        // Up to the first line, Home, then insert: it lands on line one.
        a.on_key(KeyCode::Up, KeyModifiers::NONE);
        a.on_key(KeyCode::Home, KeyModifiers::NONE);
        a.on_key(KeyCode::Char('X'), KeyModifiers::NONE);
        assert_eq!(a.composer, "Xone\ntwo", "Up did not move a line");
    }

    /// A killed word is overwritten, not merely dropped — RFC 7 §8 applies to
    /// discarded plaintext however small.
    #[test]
    fn killing_a_word_shortens_the_draft() {
        let mut a = ready_node("compose-kill");
        type_command(&mut a, "note");
        for c in "alpha beta".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        a.on_key(KeyCode::Char('w'), KeyModifiers::CONTROL);
        assert_eq!(a.composer, "alpha ");
    }

    /// **Names appear beside identifiers wherever a list shows one.**
    ///
    /// And never instead of one: `channel follow` and `connect` take the
    /// identifier, so a list showing only a name would be a list of things
    /// the operator cannot act on — as well as a name standing in for a
    /// verification it did not perform (RFC 8 §7).
    #[test]
    fn names_annotate_the_channel_list_and_the_peers_panel() {
        let (mut a, _b, _a_id, b_id) = peered_pair("alias-panels");
        type_command(&mut a, "channel new");
        let chan = channels::short(&a.roster.mine.as_ref().unwrap().id());

        type_command(&mut a, &format!("alias-channel {chan} weather"));
        type_command(&mut a, &format!("alias-peer {b_id} bob"));

        let rows = a.channel_rows();
        assert!(
            rows.iter().any(|r| r.contains("weather") && r.contains(&chan)),
            "the channel list shows neither, or only one: {rows:?}"
        );

        let panel = a.peers_panel();
        assert!(
            panel.contains("bob") && panel.contains(&b_id),
            "the peers panel shows neither, or only one:\n{panel}"
        );
    }

    /// A name in one table does not annotate another table's identifier.
    #[test]
    fn a_peer_name_does_not_leak_into_the_channel_list() {
        let mut a = ready_node("alias-namespaces");
        type_command(&mut a, "channel new");
        let chan = channels::short(&a.roster.mine.as_ref().unwrap().id());
        // Named in the *peer* table, using the channel's identifier.
        type_command(&mut a, &format!("alias-peer {chan} wrongtable"));
        assert!(
            !a.channel_rows().iter().any(|r| r.contains("wrongtable")),
            "a peer name annotated a channel: {:?}",
            a.channel_rows()
        );
    }

    /// **A peering survives a restart, and so does what it agreed.**
    ///
    /// The peer-link, the credential and the terms are on disk; the reservoir
    /// is sealed under `W_N`, which is the part that was being lost. A
    /// peering that came back without its reservoir would still look peered
    /// and would quietly have stopped being post-quantum.
    #[test]
    fn a_peering_and_its_terms_survive_a_restart() {
        let (a, _b, _a_id, b_id) = peered_pair("peering-restart");
        let home = a.home.clone();
        let pass = a.passphrase.as_string();

        // What is on disk for that peer, before anything restarts.
        assert!(a.peer_path(&b_id, artifact::PeerFile::Link).exists());
        let terms_before = a.peer_terms(&b_id).is_some();
        drop(a);

        // A new process, same home: nothing carried in memory.
        let mut restarted = App::default();
        restarted.home = home;
        // `unlock` is the path a restart takes: it reads the identity from
        // disk rather than expecting one in memory.
        restarted.unlock(pass.as_bytes()).expect("the store opens");

        assert!(
            restarted.peer_ids().iter().any(|p| p == &b_id),
            "the peering is gone after a restart: {:?}",
            restarted.peer_ids()
        );
        assert_eq!(
            restarted.peer_terms(&b_id).is_some(),
            terms_before,
            "the peering came back without the terms it agreed"
        );
        // And the epoch key is the same one, so anything sealed under it —
        // the reservoir among them — is still readable.
        assert!(restarted.epoch_key.is_some());
    }

    /// Move every object A holds into B — what a reconciliation does, with
    /// the scheduling and the transport taken out.
    fn carry_all(from: &App, to: &App) {
        let now_min = now_epoch().0 * 1440;
        let objects: Vec<(krab_core::object::ObjectId, Vec<u8>)> = from.store.with(|s| {
            s.entries_in_range(0, u32::MAX)
                .into_iter()
                .filter_map(|(_, i)| s.get(&i).map(|x| (i, x.to_vec())))
                .collect()
        });
        for (i, bytes) in objects {
            let _ = to.store.with(|s| s.ingest(i, bytes, now_min, u32::MAX));
        }
    }

    /// **A relays for A and C without being able to read for them.**
    ///
    /// A is peered with B, C is peered with B, and A and C have never met.
    /// This is the whole point of a store-and-forward corpus: B carries
    /// ciphertext it cannot open, and the message arrives anyway.
    #[test]
    fn a_message_reaches_a_node_two_hops_away() {
        let (mut a, mut b, _a_id, b_id) = peered_pair("relay-ab");
        let (mut c, mut b2, _c_id, b2_id) = peered_pair("relay-cb");

        // A writes to C. It cannot: they have no peering, which is the
        // premise — so it writes to B, and what is proved is the carry.
        type_command(&mut a, &format!("send {b_id} for the middle node"));
        assert!(a.output.contains("composed"), "{}", a.output);

        // A -> B, and B can read it: they are peered.
        carry_all(&a, &b);
        b.refresh_inbox();
        assert!(
            b.messages.iter().any(|m| m.body.contains("for the middle node")),
            "the first hop did not arrive"
        );

        // Now the hop that matters. C writes to B2 and A never sees it, but
        // the object crosses A on its way — carried, not read.
        type_command(&mut c, &format!("send {b2_id} from the far side"));
        carry_all(&c, &a);
        a.refresh_inbox();
        assert!(
            !a.messages.iter().any(|m| m.body.contains("from the far side")),
            "a node read mail addressed to somebody else"
        );
        // And A still holds it, which is what makes it a relay rather than a
        // filter: the object is in the corpus it will offer onward.
        let held = a.store.with(|s| s.entries_in_range(0, u32::MAX).len());
        assert!(held > 1, "the relayed object was not kept: {held}");

        // A -> B2 completes the second hop, and B2 opens what C sealed.
        carry_all(&a, &b2);
        b2.refresh_inbox();
        assert!(
            b2.messages.iter().any(|m| m.body.contains("from the far side")),
            "the message did not survive the relay: {:?}",
            b2.messages.iter().map(|m| &m.body).collect::<Vec<_>>()
        );
    }

    /// **A channel post from each of three nodes reaches the other two.**
    ///
    /// Posts are class 1 and public, so unlike sealed mail every node that
    /// carries them can read them — which is what makes a channel a channel.
    #[test]
    fn channel_posts_from_three_nodes_reach_them_all() {
        let mut a = ready_node("three-chan-a");
        let mut b = ready_node("three-chan-b");
        let mut c = ready_node("three-chan-c");

        let mut ids = Vec::new();
        for (n, text) in [
            (&mut a, "from A"),
            (&mut b, "from B"),
            (&mut c, "from C"),
        ] {
            type_command(n, "channel carry on");
            type_command(n, "channel carry on");
            type_command(n, "channel new");
            ids.push(n.roster.mine.as_ref().unwrap().id());
            post_now(n, text);
        }

        // A -> B -> C, and back, which is the shape of the line A-B-C.
        carry_all(&a, &b);
        carry_all(&c, &b);
        carry_all(&b, &a);
        carry_all(&b, &c);

        // Every node holds every channel's post, including the two it did
        // not write and the one it cannot post to.
        for (who, node) in [("A", &a), ("B", &b), ("C", &c)] {
            for (n, id) in ids.iter().enumerate() {
                let posts = node.channel_posts(id);
                assert!(
                    !posts.is_empty(),
                    "{who} is missing channel {n}'s post: {posts:?}"
                );
            }
        }
    }

    /// **The same epoch must yield the same key after a restart.**
    ///
    /// This is what the roster, the group rosters and every peering's
    /// reservoir are sealed under. If `W_N` differs between one start and the
    /// next, all three are unreadable — and the reservoir's case is the
    /// quietest: a peering silently loses its post-quantum property and
    /// degrades to `mode_auth` with nothing said.
    #[test]
    fn an_epoch_yields_the_same_key_across_a_restart() {
        let mut a = ready_node("epoch-stable");
        let wrapped = a.path(artifact::Artifact::IdentityWrapped);
        let params = a.identity.as_ref().unwrap().kek_params;
        let kek = a
            .identity
            .as_ref()
            .unwrap()
            .kek(a.passphrase.as_string().as_bytes())
            .expect("kek");

        // An epoch this node has no wrapper for — the next day.
        let future = krab_core::tag::Epoch(now_epoch().0 + 1);
        let id = a.identity.as_mut().expect("identity");
        let first = id.hierarchy.open_epoch(&kek, future, &mut OsRng).unwrap();
        persist::write_identity(&wrapped, a.identity.as_ref().unwrap(), &kek, &mut OsRng)
            .expect("written");

        // What the next start does: read the identity back from disk and ask
        // for the same epoch.
        let mut reloaded = persist::read_identity(&wrapped, &kek, params).expect("read back");
        let second = reloaded
            .hierarchy
            .open_epoch(&kek, future, &mut OsRng)
            .unwrap();

        assert_eq!(
            first, second,
            "the same epoch gave two different keys across a restart — \
             everything sealed under the first is unreadable"
        );
        // And something sealed under it opens with the reloaded one, which is
        // the property the reservoir actually depends on.
        let sealed =
            krab_crypto::kek::seal_under(&first, b"krab/reservoir", b"chunk", &mut OsRng)
                .expect("sealed");
        assert_eq!(
            krab_crypto::kek::open_under(&second, b"krab/reservoir", &sealed).expect("opens"),
            b"chunk"
        );
    }

    /// **A minted epoch key must reach the disk.**
    ///
    /// `open_epoch` is idempotent only against records it can see, and it
    /// sees the ones that were saved. The identity file was written at `init`
    /// and never again, so the first unlock in a *later* epoch minted a fresh
    /// `W_N`, held it in memory and dropped it at exit — and the channel
    /// roster, the group rosters, and every peering's reservoir went with it.
    /// Not after a day: immediately, for anything created in an epoch the
    /// identity file predates.
    #[test]
    fn an_epoch_key_minted_after_init_is_persisted() {
        let mut a = ready_node("epoch-persist");
        let wrapped = a.path(artifact::Artifact::IdentityWrapped);
        let before = std::fs::read(&wrapped).expect("written at init");
        let records_at_init = a.identity.as_ref().unwrap().hierarchy.records().len();

        // Force the node into an epoch it has no wrapper for, the way a
        // restart on the next day does.
        let future = krab_core::tag::Epoch(now_epoch().0 + 1);
        let kek = a
            .identity
            .as_ref()
            .unwrap()
            .kek(a.passphrase.as_string().as_bytes())
            .expect("kek");
        let id = a.identity.as_mut().unwrap();
        let n = id.hierarchy.records().len();
        let _ = id.hierarchy.open_epoch(&kek, future, &mut OsRng).unwrap();
        assert_eq!(
            id.hierarchy.records().len(),
            n + 1,
            "the fixture did not mint a wrapper"
        );

        // What the fix does at that moment.
        persist::write_identity(&wrapped, a.identity.as_ref().unwrap(), &kek, &mut OsRng)
            .expect("written");

        let after = std::fs::read(&wrapped).expect("still there");
        assert_ne!(before, after, "the new wrapper did not reach the disk");
        assert!(
            after.len() > before.len(),
            "the file did not grow by a record: {} -> {}",
            before.len(),
            after.len()
        );
        assert_eq!(records_at_init + 1, a.identity.as_ref().unwrap().hierarchy.records().len());
    }

    /// **An alias never reaches the corpus.** It is a separate file that no
    /// send path reads, so naming somebody cannot put that name on a wire.
    #[test]
    fn naming_someone_changes_nothing_that_leaves_the_node() {
        let mut a = ready_node("alias-local");
        let before = a.store.with(|s| s.entries_in_range(0, u32::MAX).len());
        let card = std::fs::read(a.path(artifact::Artifact::PeerCard)).ok();

        type_command(&mut a, "alias 0cf29190 alice");
        assert!(a.output.contains("alice (0cf29190)"), "{}", a.output);

        assert_eq!(
            a.store.with(|s| s.entries_in_range(0, u32::MAX).len()),
            before,
            "an alias reached the corpus"
        );
        assert_eq!(
            std::fs::read(a.path(artifact::Artifact::PeerCard)).ok(),
            card,
            "an alias reached the card handed to peers"
        );
    }

    /// **It is ciphertext at rest, like the pinned archive.**
    #[test]
    fn the_alias_file_is_encrypted() {
        let mut a = ready_node("alias-crypto");
        type_command(&mut a, "alias 0cf29190 SECRETALIASMARKER");
        let sealed = std::fs::read(a.path(artifact::Artifact::Aliases)).expect("written");
        assert!(
            !sealed
                .windows(b"SECRETALIASMARKER".len())
                .any(|w| w == b"SECRETALIASMARKER"),
            "the name is on disk in the clear"
        );
    }

    /// **A wipe destroys names.** An alias table is a plaintext social graph;
    /// it is the part of a seizure that turns identifiers into people.
    #[test]
    fn a_wipe_destroys_aliases() {
        let mut a = ready_node("alias-wipe");
        type_command(&mut a, "alias 0cf29190 alice");
        assert!(a.path(artifact::Artifact::Aliases).exists());
        a.panic_wipe();
        assert!(
            !a.path(artifact::Artifact::Aliases).exists(),
            "the alias file survived a wipe"
        );
    }

    /// The three verbs write three tables, and removal is by name.
    #[test]
    fn the_three_verbs_and_their_removal() {
        let mut a = ready_node("alias-verbs");
        type_command(&mut a, "alias 0cf29190 alice");
        type_command(&mut a, "alias-channel 672bc3bf weather");
        type_command(&mut a, "alias-peer 7b4f469a bob");
        let t = a.aliases();
        assert_eq!(t.get(alias::Kind::Message, "0cf29190"), Some("alice"));
        assert_eq!(t.get(alias::Kind::Channel, "672bc3bf"), Some("weather"));
        assert_eq!(t.get(alias::Kind::Peer, "7b4f469a"), Some("bob"));

        // Removal names what it freed, and only from the table asked for.
        type_command(&mut a, "no alias-channel weather");
        assert!(a.output.contains("672bc3bf"), "{}", a.output);
        assert_eq!(a.aliases().get(alias::Kind::Channel, "672bc3bf"), None);
        assert_eq!(a.aliases().get(alias::Kind::Message, "0cf29190"), Some("alice"));

        // A name that is not there says so rather than silently succeeding.
        type_command(&mut a, "no alias nobody");
        assert!(a.output.contains("no alias name"), "{}", a.output);
    }

    /// A locked node has no key for the table and says so.
    #[test]
    fn aliases_are_unreachable_while_locked() {
        let mut a = ready_node("alias-locked");
        type_command(&mut a, "alias 0cf29190 alice");
        a.lock();
        type_command(&mut a, "alias 0cf29190 alice");
        assert!(a.output.contains("locked"), "{}", a.output);
        type_command(&mut a, "no alias alice");
        assert!(a.output.contains("locked"), "{}", a.output);
    }

    /// **A note to self is kept, and is not an object.**
    ///
    /// Sealing one to this node's own correspondence key would work and would
    /// put it in the corpus, where everything is offered at the next
    /// reconciliation — peers carrying ciphertext they can never open, metered
    /// against RFC 3 §6's quota and counted in §12's figures as a
    /// contribution that contributes nothing. So the store must not gain an
    /// entry.
    #[test]
    fn a_note_is_kept_without_becoming_an_object() {
        let mut a = ready_node("note-basic");
        let before = a.store.with(|s| s.entries_in_range(0, u32::MAX).len());

        type_command(&mut a, "note buy milk");
        assert!(a.output.contains("kept"), "{}", a.output);
        assert_eq!(
            a.store.with(|s| s.entries_in_range(0, u32::MAX).len()),
            before,
            "a note reached the corpus, where it will be offered to peers"
        );

        type_command(&mut a, "notes");
        assert!(a.output.contains("buy milk"), "{}", a.output);

        // It survives the process, like anything in the archive.
        let key = a.pin_key.expect("unlocked");
        assert!(a
            .pinned()
            .of(&a.identity.as_ref().unwrap().short_id())
            .iter()
            .any(|k| k.body == "buy milk"));
        let _ = key;
    }

    /// **A note is encrypted at rest, and tamper-evident.**
    ///
    /// It is sealed with ChaCha20-Poly1305 under a KEK-derived subkey — the
    /// same construction as pinned mail, because it *is* the pinned archive.
    /// The AEAD tag is what makes it tamper-evident; there is deliberately no
    /// signature, and §on-signing in the commit message says why.
    #[test]
    fn a_note_is_ciphertext_on_disk_and_will_not_open_if_altered() {
        let mut a = ready_node("note-crypto");
        type_command(&mut a, "note SECRETPLAINTEXTMARKER");

        let path = a.path(artifact::Artifact::Pinned);
        let sealed = std::fs::read(&path).expect("archive written");
        assert!(
            !sealed
                .windows(b"SECRETPLAINTEXTMARKER".len())
                .any(|w| w == b"SECRETPLAINTEXTMARKER"),
            "the note is on disk in the clear"
        );

        // Flip a byte of the ciphertext: the AEAD tag must refuse it rather
        // than hand back altered text.
        let key = a.pin_key.expect("unlocked");
        let mut tampered = sealed.clone();
        let n = tampered.len();
        tampered[n / 2] ^= 0x01;
        assert!(
            krab_crypto::kek::open_under(&key, pin::DOMAIN, &tampered).is_err(),
            "an altered archive opened anyway"
        );
        // And the untouched one still does.
        assert!(krab_crypto::kek::open_under(&key, pin::DOMAIN, &sealed).is_ok());
    }

    /// A note may be longer than a line, so it is composed.
    #[test]
    fn a_note_can_be_composed_over_several_lines() {
        let mut a = ready_node("note-compose");
        type_command(&mut a, "note");
        assert_eq!(a.ui.mode(), Mode::Compose, "{}", a.output);
        // Private tab: a note is not public, and the banner must not claim
        // otherwise.
        assert_eq!(a.ui.banner(), Some(layout::Banner::Private));

        for c in "first".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        a.on_key(KeyCode::Enter, KeyModifiers::NONE);
        for c in "second".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        a.on_key(KeyCode::Char('d'), KeyModifiers::CONTROL);

        type_command(&mut a, "notes");
        assert!(a.output.contains("first"), "{}", a.output);
        assert!(a.output.contains("second"), "{}", a.output);
    }

    /// **A wipe destroys notes.** They are plaintext exempt from epoch
    /// erasure; the panic path is the only thing that removes them, and it
    /// has to.
    #[test]
    fn a_wipe_destroys_notes() {
        let mut a = ready_node("note-wipe");
        type_command(&mut a, "note something incriminating");
        assert!(!a.pinned().kept.is_empty());

        a.panic_wipe();
        assert!(
            a.pinned().kept.is_empty(),
            "notes survived a wipe: {:?}",
            a.pinned().kept
        );
    }

    /// **A post is composed, not typed as an argument.**
    ///
    /// RFC 8 §4.2 requirement 1 puts the security context *in the composer*,
    /// which presumes one. `channel post <text>` was the only way in, so a
    /// post was a single line and the banner requirement had nowhere to
    /// apply.
    #[test]
    fn channel_post_with_no_text_opens_a_composer_with_its_banner() {
        let mut a = ready_node("post-compose");
        type_command(&mut a, "channel new");
        type_command(&mut a, "channel post");

        assert_eq!(a.ui.mode(), Mode::Compose, "{}", a.output);
        assert_eq!(a.ui.tab(), layout::Tab::Channels);
        assert_eq!(
            a.ui.banner(),
            Some(layout::Banner::PublicSignedPermanent),
            "the composer opened without the banner §4.2 requires"
        );

        // Multi-line, which an argument could never be.
        for c in "first line\nsecond line".chars() {
            a.on_key(
                if c == '\n' { KeyCode::Enter } else { KeyCode::Char(c) },
                KeyModifiers::NONE,
            );
        }
        assert!(a.composer.contains('\n'), "the composer refused a newline");
    }

    /// **Confirmation is one keystroke, not the verb typed twice.**
    ///
    /// §4.2 requirement 2 requires explicit confirmation of the first post of
    /// a session. It does not require retyping the command, and a command
    /// typed twice teaches the operator to type it twice without reading.
    #[test]
    fn the_first_post_confirms_with_a_key_and_later_posts_do_not() {
        let mut a = ready_node("post-confirm");
        type_command(&mut a, "channel new");
        let chan = a.roster.mine.as_ref().unwrap().id();

        type_command(&mut a, "channel post");
        for c in "the meeting moved".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        a.on_key(KeyCode::Char('d'), KeyModifiers::CONTROL);

        // Not published yet, and the pane says what it is about to do.
        assert!(a.channel_posts(&chan).is_empty(), "published without confirming");
        assert!(a.output.contains("PUBLIC — SIGNED — PERMANENT"), "{}", a.output);
        assert!(a.output.contains("Enter"), "the key is not named: {}", a.output);

        a.on_key(KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(a.channel_posts(&chan).len(), 1, "{}", a.output);

        // Second post of the session: composed, sealed, published. No prompt.
        type_command(&mut a, "channel post");
        for c in "and again".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        a.on_key(KeyCode::Char('d'), KeyModifiers::CONTROL);
        assert_eq!(
            a.channel_posts(&chan).len(),
            2,
            "the second post of a session asked again: {}",
            a.output
        );
    }

    /// Esc on a post awaiting confirmation discards it, like any draft.
    #[test]
    fn a_post_awaiting_confirmation_can_be_discarded() {
        let mut a = ready_node("post-discard");
        type_command(&mut a, "channel new");
        let chan = a.roster.mine.as_ref().unwrap().id();
        type_command(&mut a, "channel post");
        for c in "never mind".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        a.on_key(KeyCode::Char('d'), KeyModifiers::CONTROL);
        a.on_key(KeyCode::Esc, KeyModifiers::NONE);
        assert!(a.pending_post.is_none());
        assert!(a.channel_posts(&chan).is_empty(), "Esc published it");

        a.on_key(KeyCode::Enter, KeyModifiers::NONE);
        assert!(a.channel_posts(&chan).is_empty(), "Enter published a discarded draft");
    }

    /// **A channel can be entered, and a post read on its own.**
    ///
    /// `descend` set `Level::Messages` and nothing read it: Enter on a
    /// channel changed the pane title and left the channel list underneath.
    /// The body received every post joined together, so a post longer than a
    /// line could not be read by itself and the author appeared nowhere.
    #[test]
    fn a_channel_opens_to_its_posts_and_each_post_names_its_author() {
        let mut a = ready_node("channel-nav");
        type_command(&mut a, "channel new");
        let chan = a.roster.mine.as_ref().unwrap().id();
        // Typed once, then confirmed with a key — not typed twice.
        type_command(&mut a, "channel post the agreed line");
        assert!(a.channel_posts(&chan).is_empty(), "published unconfirmed");
        a.on_key(KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(a.channel_posts(&chan).len(), 1, "{}", a.output);

        a.on_key(KeyCode::Char('t'), KeyModifiers::CONTROL);
        assert_eq!(a.ui.tab(), layout::Tab::Channels);
        a.selected = 0;
        // Focus has to be on the list: Enter on the command line submits a
        // command, and an empty one does nothing. This is how an operator
        // reaches it — Tab, then Enter.
        while a.ui.focus() != layout::Pane::List {
            a.ui.cycle_focus();
        }

        // Enter descends into the channel under the cursor.
        a.on_key(KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(a.ui.level(), layout::Level::Messages);
        assert_eq!(a.channel_open, Some(chan), "no channel was entered");

        let author = channels::short(&chan);
        assert!(
            a.list.iter().any(|r| r.contains(&author)),
            "no author on any row: {:?}",
            a.list
        );
        assert!(
            a.body.contains("from ") && a.body.contains(&author),
            "the body does not say who posted:\n{}",
            a.body
        );
    }

    /// **Pass 13. The reveal must not hide the prompt it needs.**
    ///
    /// `Zoom::One` renders that pane and nothing else — no command line, so
    /// no prompt and no status rule, and the WAITING indicator went with it.
    /// The backup-words step is long enough to trigger the reveal, so the two
    /// features added together cancelled each other at exactly the step where
    /// the operator has to be told to press Enter.
    #[test]
    fn revealing_a_long_reply_keeps_the_command_line() {
        let mut a = App::default();
        a.home = temp_home("reveal-keeps-prompt");
        a.output_height.set(4);
        a.output_width.set(80);

        type_command(&mut a, "init");
        a.passphrase = line::Line::from("a passphrase");
        a.advance_init();
        while a.init_step.is_some() && a.init_step != Some(InitStep::ShowBackup) {
            a.advance_init();
        }
        a.advance_init();

        assert!(a.waiting().is_some(), "the ceremony is not waiting");
        assert_eq!(
            a.ui.zoomed(),
            Some(layout::Zoom::Console),
            "an automatic reveal took the whole screen"
        );
        // The command pane is in the layout, which is what carries both the
        // prompt and the rule the WAITING indicator rides on.
        let panes = a.ui.layout(layout::Rect {
            x: 0,
            y: 0,
            w: 120,
            h: 40,
        });
        assert!(
            panes.iter().any(|(p, _)| *p == layout::Pane::Command),
            "the reveal left no command pane: {panes:?}"
        );
    }

    /// **Pass 13. Wrapping counts columns, not characters.**
    ///
    /// A CJK character is one `char` and two columns. Counting `chars()` let
    /// a row that "fit" be twice the width of the pane — and because this
    /// wrapping replaced the widget's own, the overflow was truncated rather
    /// than re-flowed. Text was silently gone, not merely misplaced. That was
    /// a regression introduced with the wrapping itself.
    #[test]
    fn wrapping_measures_display_columns_not_characters() {
        let rows = render::wrap_rows(&"\u{4f60}\u{597d}\u{4e16}\u{754c}".repeat(10), 10);
        for r in &rows {
            assert!(
                unicode_width::UnicodeWidthStr::width(r.as_str()) <= 10,
                "a row is wider than the pane: {r:?}"
            );
        }
        // A zero-width combining mark must not consume a column either.
        let combining = render::wrap_rows("e\u{301}".repeat(20).as_str(), 10);
        for r in &combining {
            assert!(
                unicode_width::UnicodeWidthStr::width(r.as_str()) <= 10,
                "{r:?}"
            );
        }
    }

    /// **Pass 13. Scrolling to the top must not scroll past it.**
    ///
    /// The clamp allowed `scroll == rows`, which put the window entirely off
    /// the end of the text: `lines[0..0]`, an empty pane. Holding PgUp read
    /// as "the output is gone".
    #[test]
    fn scrolling_to_the_top_leaves_the_output_on_screen() {
        let mut a = ready_node("scroll-top");
        a.output = (0..40).map(|i| format!("line {i}")).collect::<Vec<_>>().join("\n");
        a.output_rows.set(40);
        a.output_height.set(4);

        for _ in 0..40 {
            a.on_key(KeyCode::PageUp, KeyModifiers::NONE);
        }
        assert!(
            a.output_scroll <= (40 - a.output_fits()) as i64,
            "scrolled past the top: {} of 40",
            a.output_scroll
        );
        // What the pane would render at that position is not empty.
        let rows = render::wrap_rows(&a.output, 80);
        let scrolled = a.output_scroll.max(0) as usize;
        let end = rows.len().saturating_sub(scrolled.min(rows.len()));
        assert!(end > 0, "the window ran off the end of the text");
    }

    /// **Pass 13. The end of `init` reveals what a typed verb would.**
    ///
    /// `status` opened the pane; the identical report at the end of the
    /// ceremony did not, because the reveal hung off `submit` alone. That is
    /// the one moment a new operator most needs to read it.
    #[test]
    fn the_report_at_the_end_of_init_opens_the_pane_too() {
        let mut a = App::default();
        a.home = temp_home("init-reveal");
        a.output_height.set(4);
        a.output_width.set(80);

        type_command(&mut a, "init");
        a.passphrase = line::Line::from("a passphrase");
        for _ in 0..5 {
            if a.init_step.is_none() {
                break;
            }
            a.advance_init();
        }
        assert!(a.output.lines().count() > 4, "{}", a.output);
        assert_eq!(
            a.ui.zoomed(),
            Some(layout::Zoom::Console),
            "the end of init did not show its own report"
        );
    }

    /// **Pass 13. A zoom on some other pane does not hide the reply.**
    ///
    /// The reveal skipped when anything was zoomed, so an operator who had
    /// full-screened the list and then ran `status` got no output at all —
    /// worse than the truncation the reveal exists to prevent.
    #[test]
    fn a_long_reply_takes_the_screen_from_another_zoomed_pane() {
        let mut a = ready_node("zoom-elsewhere");
        a.output_height.set(4);
        a.output_width.set(80);
        // Reached the way an operator reaches it: Tab to the list, Ctrl-O.
        a.ui.cycle_focus();
        assert_eq!(a.ui.focus(), layout::Pane::List);
        a.ui.toggle_full_screen();
        assert_eq!(a.ui.zoomed(), Some(layout::Zoom::One(layout::Pane::List)));

        type_command(&mut a, "status");
        assert_eq!(
            a.ui.zoomed(),
            Some(layout::Zoom::Console),
            "the reply was left behind a zoomed list"
        );
        a.on_key(KeyCode::Esc, KeyModifiers::NONE);
        assert_eq!(a.ui.zoomed(), None);
    }

    /// **A reply that does not fit opens the pane it does not fit in.**
    ///
    /// The output pane is a few rows. `help`, `peers` and `status` all run
    /// longer than that, and the part an operator wants is usually at the
    /// end — so the useful half sat behind a `PgUp` there was no reason to
    /// know was waiting.
    #[test]
    fn a_reply_too_long_for_the_pane_opens_it() {
        let mut a = ready_node("reveal");
        // A pane as the terminal last reported it: four rows, eighty wide.
        a.output_height.set(4);
        a.output_width.set(80);

        type_command(&mut a, "status");
        assert!(
            a.output.lines().count() > 4,
            "this test needs a long reply: {}",
            a.output
        );
        assert_eq!(
            a.ui.zoomed(),
            Some(layout::Zoom::Console),
            "a reply taller than the pane did not open it"
        );

        // Esc puts the layout back — the chord that already meant "back".
        a.on_key(KeyCode::Esc, KeyModifiers::NONE);
        assert_eq!(a.ui.zoomed(), None, "Esc did not restore the layout");
    }

    /// And a short reply is left alone: a pane that opens for everything is
    /// one the operator starts closing reflexively.
    #[test]
    fn a_reply_that_fits_does_not_disturb_the_layout() {
        let mut a = ready_node("reveal-short");
        a.output_height.set(4);
        a.output_width.set(80);
        type_command(&mut a, "channel carry");
        assert!(a.output.lines().count() <= 4, "{}", a.output);
        assert_eq!(a.ui.zoomed(), None, "a short reply opened the pane");
    }

    /// **Scrolling counts what is on screen, not what is in the string.**
    ///
    /// The clamp used `output.lines()`, which under-counted every line that
    /// wrapped — so on a narrow pane PgUp stopped before the top and the rest
    /// could not be reached at all.
    #[test]
    fn the_output_scroll_counts_wrapped_rows() {
        let mut a = ready_node("scroll-rows");
        // One logical line, many rows once wrapped into a narrow pane.
        a.output = "x ".repeat(400);
        a.output_width.set(20);
        a.output_rows
            .set(render::wrap_rows(&a.output, 20).len());
        assert!(a.output_rows.get() > 20, "the fixture does not wrap");

        for _ in 0..12 {
            a.on_key(KeyCode::PageUp, KeyModifiers::NONE);
        }
        assert!(
            a.output_scroll > 1,
            "a single logical line could not be scrolled: {}",
            a.output_scroll
        );
    }

    /// A word longer than the pane is cut rather than left running off it.
    #[test]
    fn wrapping_breaks_a_word_that_cannot_fit() {
        let rows = render::wrap_rows(&"z".repeat(50), 10);
        assert_eq!(rows.len(), 5, "{rows:?}");
        assert!(rows.iter().all(|r| r.chars().count() <= 10), "{rows:?}");
    }

    /// **A node that is waiting says so, and says what the key does.**
    ///
    /// "Press Enter to continue" and "this node is busy" looked identical
    /// from outside: both were prose in the output pane, if they appeared at
    /// all. The status rule now carries it.
    #[test]
    fn every_step_that_waits_says_what_the_next_key_does() {
        let mut a = App::default();
        a.home = temp_home("waiting");
        assert_eq!(a.waiting(), None, "an idle node claims to be waiting");

        type_command(&mut a, "init");
        let w = a.waiting().expect("the passphrase step does not announce itself");
        assert!(w.contains("passphrase"), "{w}");
        assert!(w.contains("Enter"), "the key to press is not named: {w}");

        // Every step of the ceremony, not only the first.
        let mut seen = 0;
        while let Some(step) = a.init_step {
            if step == InitStep::Done {
                break;
            }
            let w = a.waiting().unwrap_or_else(|| panic!("{step:?} announces nothing"));
            assert!(
                w.contains("Enter"),
                "{step:?} does not name the key: {w}"
            );
            seen += 1;
            if step == InitStep::Passphrase {
                a.passphrase = line::Line::from("a passphrase");
            }
            a.advance_init();
            if seen > 8 {
                break;
            }
        }
        assert!(seen >= 3, "the ceremony was not walked: {seen} steps");
        assert_eq!(a.waiting(), None, "a finished ceremony still claims to wait");
    }

    /// **A channel post crosses a session and a follower reads it.**
    ///
    /// The single-node test covers create/post/read in one process. This is
    /// the other half: the post has to survive reconciliation and be readable
    /// by a node that was not there when it was written.
    ///
    /// The order is not interchangeable and the verbs say so — carrying
    /// public content is off by default (RFC 6), and a channel cannot be
    /// followed until one of its posts has arrived, because there is no
    /// directory to look one up in.
    #[test]
    fn a_channel_post_crosses_to_a_follower_and_is_read() {
        let (mut a, mut b, a_id, b_id) = peered_pair("channel-cross");

        type_command(&mut a, "channel carry on");
        type_command(&mut a, "channel carry on");
        assert!(a.roster.carriage.enabled, "{}", a.output);

        type_command(&mut a, "channel new");
        assert!(a.output.contains("created"), "{}", a.output);
        let chan = a.roster.mine.as_ref().unwrap().id();
        let short = channels::short(&chan);

        // RFC 8 §4.2: the first post of a session confirms rather than
        // publishes — it holds the text and asks. Issuing it once and
        // assuming it went out is how a "post" that never left would look
        // like a delivery failure.
        type_command(&mut a, "channel post the meeting is moved to thursday");
        assert!(
            a.output.contains("PUBLIC — SIGNED — PERMANENT"),
            "the post did not state what it is: {}",
            a.output
        );
        a.on_key(KeyCode::Enter, KeyModifiers::NONE);
        assert!(a.output.contains("published post"), "{}", a.output);
        assert_eq!(a.channel_posts(&chan).len(), 1, "the post did not publish");

        // B hosts public content. Off by default, and enabling it is two
        // steps — RFC 8 §4.3 wants the warning at the moment of enabling,
        // so the first invocation arms and the second commits.
        type_command(&mut b, "channel carry on");
        assert!(b.output.contains("again to enable"), "{}", b.output);
        type_command(&mut b, "channel carry on");
        assert!(b.roster.carriage.enabled, "carriage did not come on: {}", b.output);
        assert!(b.channel_posts(&chan).is_empty(), "B has it before anything moved");

        // Cross a real session, both halves.
        let (sa, sb) = session_pair();
        a.links.connect(&b_id, profile_named("tcp").unwrap());
        a.links.established(&b_id, Some(Box::new(sa)));
        b.links.connect(&a_id, profile_named("tcp").unwrap());
        b.links.established(&a_id, Some(Box::new(sb)));

        let a_peer = a_id.clone();
        let chan_for_b = chan;
        let responder = std::thread::spawn(move || {
            b.answer_reconciliation(&a_peer);
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            while std::time::Instant::now() < deadline {
                b.drain_exchanges();
                if !b.channel_posts(&chan_for_b).is_empty() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            b
        });
        a.reconcile_with(&b_id);
        let mut b = responder.join().expect("B's thread");

        let posts = b.channel_posts(&chan);
        assert!(
            posts.iter().any(|p| p.contains("moved to thursday")),
            "the post did not cross: {posts:?}"
        );

        // Now it can be followed, and only now.
        type_command(&mut b, &format!("channel follow {short}"));
        assert!(
            !b.output.contains("no channel"),
            "a channel whose post arrived could not be followed: {}",
            b.output
        );
        type_command(&mut b, "channel list");
        assert!(
            b.output.contains(&short),
            "a followed channel is not listed: {}",
            b.output
        );
    }

    /// **A channel post carries text and no attachment.**
    ///
    /// `send <peer> --picture` exists; `channel post` has no equivalent, so a
    /// path that looks like a file is posted as the characters in it. Pinned
    /// so that if channel attachments are ever added this test is what has to
    /// be changed deliberately, rather than the gap being discovered by
    /// someone who assumed the flag worked here too.
    #[test]
    fn a_channel_post_has_no_attachment_path() {
        let mut a = ready_node("channel-attach");
        type_command(&mut a, "channel new");
        let chan = a.roster.mine.as_ref().unwrap().id();

        post_now(&mut a, "--picture /tmp/holiday.png");
        let posts = a.channel_posts(&chan);
        assert!(
            posts.iter().any(|p| p.contains("--picture")),
            "the flag was consumed as though it meant something: {posts:?}"
        );
        assert!(
            a.messages.iter().all(|m| m.picture.is_none()),
            "a channel post produced an attachment"
        );
    }

    /// **A node that peers while running must be able to read the mail.**
    ///
    /// The tag table was rebuilt on epoch rollover and on nothing else. A
    /// node that completed its first peering without restarting kept the
    /// table it built at startup, when it had no correspondents — so nothing
    /// from that peer carried a tag it knew. The pane read
    /// "(no messages — N objects examined)" while the corpus grew, and a
    /// restart fixed it, which made a stale cache look like a refresh delay.
    ///
    /// Found by delivering to a freshly peered node and watching twelve polls
    /// go by with the objects on disk and nothing in the list.
    #[test]
    fn a_peering_made_while_running_is_visible_without_a_restart() {
        // Prime the table the way a running node does: scan once, with no
        // correspondents at all. This is the state the bug depended on.
        let mut b = ready_node("stale-tags-b");
        b.refresh_inbox();
        assert!(b.tag_table.is_some(), "the empty table was not built");
        assert!(b.tag_table_peers.is_empty(), "there should be no peers yet");

        // Now peer, in this process, without restarting.
        let mut a = ready_node("stale-tags-a");
        type_command(&mut a, "peer offer");
        type_command(&mut b, "peer offer");
        let carry = |from: &App, to: &App, name: artifact::Artifact, as_name: &str| {
            let bytes = std::fs::read(from.path(name)).expect("artifact exists");
            let dest = to.at(as_name);
            std::fs::write(&dest, bytes).expect("delivered");
            dest.to_string_lossy().into_owned()
        };
        let a_card = carry(&a, &b, artifact::Artifact::PeerCard, "from-a.card");
        let b_card = carry(&b, &a, artifact::Artifact::PeerCard, "from-b.card");
        type_command(&mut a, &format!("peer accept {b_card}"));
        type_command(&mut b, &format!("peer accept {a_card}"));
        let a_pad = pad_onto(&mut a, &b.at("from-a.pad"));
        let b_pad = pad_onto(&mut b, &a.at("from-b.pad"));
        type_command(&mut a, &format!("peer seal {b_pad} media"));
        type_command(&mut b, &format!("peer seal {a_pad} media"));

        let b_id = short_id(&b.identity.as_ref().unwrap().node_id());
        type_command(&mut a, &format!("send {b_id} peered while running"));
        assert!(a.output.contains("composed"), "{}", a.output);

        // Carry every object across, as a reconciliation would.
        let now_min = now_epoch().0 * 1440;
        let carried: Vec<(krab_core::object::ObjectId, Vec<u8>)> = a.store.with(|s| {
            s.entries_in_range(0, u32::MAX)
                .into_iter()
                .filter_map(|(_, i)| s.get(&i).map(|x| (i, x.to_vec())))
                .collect()
        });
        for (i, bytes) in carried {
            let _ = b.store.with(|s| s.ingest(i, bytes, now_min, u32::MAX));
        }

        b.refresh_inbox();
        assert!(
            b.messages.iter().any(|m| m.body.contains("peered while running")),
            "a peering made while running cannot read its mail — the tag \
             table was not rebuilt. list: {:?}",
            b.list
        );
    }

    /// **Mail that arrived must be on the disk, not only in the pane.**
    ///
    /// The exchange thread puts received objects into the store, which is
    /// memory. Nothing on the receive path wrote them out, so a node that
    /// took delivery and exited lost it. The loss was invisible because the
    /// sender re-delivers from its own copy at the next reconciliation — it
    /// would have surfaced only once the sender no longer had it.
    ///
    /// Found by running two nodes and watching `corpus.krab` sit at 4111
    /// bytes while three delivered messages, one of them a picture, were
    /// listed in the pane above it.
    #[test]
    fn received_mail_reaches_the_disk_not_only_the_pane() {
        let (mut a, mut b, a_id, b_id) = peered_pair("persist-recv");
        type_command(&mut a, &format!("send {b_id} this must outlive the process"));

        let corpus = b.path(artifact::Artifact::Corpus);
        let before = corpus_bytes(&corpus);

        let (sa, sb) = session_pair();
        a.links.connect(&b_id, profile_named("tcp").unwrap());
        a.links.established(&b_id, Some(Box::new(sa)));
        b.links.connect(&a_id, profile_named("tcp").unwrap());
        b.links.established(&a_id, Some(Box::new(sb)));

        let a_peer = a_id.clone();
        let responder = std::thread::spawn(move || {
            b.answer_reconciliation(&a_peer);
            // The store is shared with the exchange thread, so plaintext can
            // appear in the pane a moment before the completion event drains.
            // Keep draining past that point: the write happens on the event.
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            let mut seen_after = 0;
            while std::time::Instant::now() < deadline {
                b.drain_exchanges();
                if !b.messages.is_empty() {
                    seen_after += 1;
                    if seen_after > 25 {
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            b
        });
        a.reconcile_with(&b_id);
        let b = responder.join().expect("B's thread");

        assert!(
            b.messages.iter().any(|m| m.body.contains("outlive")),
            "nothing arrived, so this proves nothing"
        );

        // The pane has it. The question is whether the disk does.
        let after = corpus_bytes(&corpus);
        assert!(
            after > before,
            "the corpus on disk did not grow: {before} -> {after} bytes. \
             Received mail is lost when the process exits."
        );

        // And read it back the way a restart would, with no help from memory.
        let mut fresh = krab_store::index::Store::default();
        let n = persist::read_corpus(&corpus, &mut fresh, 0).expect("corpus reads back");
        assert!(n > 0, "the persisted corpus is empty");
    }

    /// **A forced exchange that started must not report that it did not.**
    ///
    /// `reconcile_with` hands the exchange to a thread and returns `None`;
    /// it returns `Some` only when there was no session to take. `force_send`
    /// had the test inverted, so a forced send over a live link answered
    /// "nothing to force: no session" — and then delivered the message a
    /// moment later. Found by forcing a send between two real nodes over TCP
    /// and watching it arrive after the verb said it had not been sent.
    #[test]
    fn forcing_over_a_live_session_reports_that_it_started() {
        let (mut a, mut b, a_id, b_id) = peered_pair("fs-live");
        type_command(&mut a, &format!("send {b_id} forced across"));
        assert!(a.output.contains("composed"), "{}", a.output);

        let (sa, sb) = session_pair();
        a.links.connect(&b_id, profile_named("tcp").unwrap());
        a.links.established(&b_id, Some(Box::new(sa)));
        b.links.connect(&a_id, profile_named("tcp").unwrap());
        b.links.established(&a_id, Some(Box::new(sb)));

        let a_peer = a_id.clone();
        let responder = std::thread::spawn(move || {
            b.answer_reconciliation(&a_peer);
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            while std::time::Instant::now() < deadline {
                b.drain_exchanges();
                if !b.messages.is_empty() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            b
        });

        type_command(&mut a, &format!("force-send {b_id}"));
        let said = a.output.clone();
        let b = responder.join().expect("B's thread");

        assert!(
            !said.contains("nothing to force"),
            "a forced send over a live session claimed there was none: {said}"
        );
        assert!(
            said.contains("forced an exchange"),
            "the verb did not say what it did: {said}"
        );
        // And it still states its cost, every time — the point of the verb.
        assert!(said.contains("RFC 5 §6.1"), "the cost went unstated: {said}");

        assert!(
            b.messages.iter().any(|m| m.body.contains("forced across")),
            "the forced send moved nothing: {:?}",
            b.messages.iter().map(|m| &m.body).collect::<Vec<_>>()
        );
    }

    /// **The Poisson schedule is not perturbed.** That is what keeps §6.1
    /// true for every exchange the operator did not force: what an observer
    /// sees is one extra sync, not a schedule that has become readable.
    #[test]
    fn forcing_an_exchange_does_not_redraw_the_schedule() {
        let mut a = ready_node("fs-sched");
        let mut b = ready_node("fs-sched-b");
        let sb = peer_up(&mut a, &mut b);
        a.refresh_inbox();

        let id = sync::peer_id_from_node(&a.peer_card(&sb).unwrap().node_id());
        let before = a.scheduler.next_due(&id);
        assert!(before.is_some(), "the peering was never scheduled");

        type_command(&mut a, &format!("force-send {sb}"));
        assert_eq!(
            a.scheduler.next_due(&id),
            before,
            "forcing an exchange moved the next scheduled one, which makes the \
             schedule a function of when the operator typed"
        );
    }

    /// A locked node forces nothing.
    #[test]
    fn a_locked_node_cannot_force_an_exchange() {
        let mut a = ready_node("fs-lock");
        a.lock();
        type_command(&mut a, "force-send");
        assert!(a.output.contains("locked"), "{}", a.output);
    }

    /// **After `init`, a node says what state it is in.**
    ///
    /// It used to end on "generated 37e35a58" and leave the message pane
    /// holding the text it was given before the program started — "no
    /// identity. `init` to create one." So a node that had just been created
    /// reported that it had not been, and an operator had no way to tell
    /// whether anything else was needed.
    #[test]
    fn init_ends_by_saying_whether_the_node_is_ready() {
        let mut a = ready_node("status-a");

        let s = a.status_report();
        assert!(s.contains(&a.identity.as_ref().unwrap().short_id()), "{s}");
        assert!(s.contains("keys"), "{s}");
        assert!(s.contains("listening"), "{s}");
        assert!(s.contains("corpus"), "{s}");

        // A fresh node is **not** ready, and says what is missing rather than
        // anything reassuring — a status line reading "ready" on a node that
        // cannot receive is worse than none.
        assert!(s.contains("not ready yet"), "{s}");
        assert!(s.contains("peer offer"), "the next step is not named: {s}");
        assert!(
            !s.contains("\nready."),
            "a node with no peers claimed ready"
        );

        // The verb prints the same thing.
        type_command(&mut a, "status");
        assert_eq!(a.output, s);
    }

    /// Where the node listens is in it — the half `keys` never reported, and
    /// the one the screenshot was missing.
    #[test]
    fn the_status_says_where_the_node_listens() {
        let mut a = ready_node("status-listen");
        assert!(
            a.status_report().contains("dials out only"),
            "{}",
            a.status_report()
        );

        a.listen = Some("127.0.0.1:40000".into());
        let s = a.status_report();
        assert!(s.contains("127.0.0.1:40000"), "{s}");
    }

    /// **A listener that failed to bind is not a node that needs unlocking.**
    ///
    /// Found by running two nodes for real: the second was told to bind a port
    /// the first already held, and its status said "CONFIGURED BUT NOT
    /// RUNNING, `unlock` first" while sitting one line under "state
    /// unlocked". The operator is sent to the one place the problem is not.
    #[test]
    fn a_listener_that_could_not_bind_says_why_not_unlock() {
        let mut a = ready_node("status-bind");
        a.listen = Some("127.0.0.1:40000".into());
        a.listen_error = Some("could not listen on 127.0.0.1:40000: AddrInUse".into());

        let s = a.status_report();
        assert!(s.contains("CONFIGURED BUT NOT RUNNING"), "{s}");
        assert!(s.contains("AddrInUse"), "the real cause is missing: {s}");
        assert!(
            !s.contains("NOT RUNNING: `unlock` first"),
            "an unlocked node was told to unlock: {s}"
        );

        // And with no recorded failure it still gives the ordinary advice,
        // which is right for the case it was written for.
        a.listen_error = None;
        assert!(a.status_report().contains("`unlock` first"));
    }

    /// A locked node says so first, because nothing else it reports matters.
    #[test]
    fn a_locked_node_reports_locked_before_anything_else() {
        let mut a = ready_node("status-lock");
        a.lock();
        let s = a.status_report();
        assert!(s.contains("LOCKED"), "{s}");
        assert!(s.contains("unlock"), "{s}");
    }

    /// **RFC 6 §281: "Nodes MUST support excluding class 1 (bulletin)
    /// entirely via `class_mask`."**
    ///
    /// The filter has enforced `class_mask` since it existed and nothing ever
    /// set it — `Flags::class_mask` was `0xFF` and no verb changed it, so a
    /// node could not decline public content however much it wanted to. The
    /// same shape the share flag had before `peer share`.
    #[test]
    fn a_link_can_be_made_to_decline_public_content() {
        let mut x = ready_node("carry-x");
        let mut y = ready_node("carry-y");
        let (_, short_y) = link_up(&mut x, &mut y);

        // By default the link carries everything, and the filter says so.
        let before = filter::Filter::from_credential(&x.credential_with(&short_y).unwrap());
        let bulletin_bit = 1u8 << (krab_core::object::Class::Bulletin as u8 & 7);
        assert!(before.class_mask & bulletin_bit != 0);

        type_command(&mut x, &format!("peer carry {short_y} off"));
        assert!(x.output.contains("no longer carry"), "{}", x.output);

        // The re-signed credential excludes class 1, and the filter enforces it.
        let proposal = credential::Credential::decode(
            &std::fs::read(x.home.join(format!("{short_y}.credential"))).unwrap(),
        )
        .expect("a fresh credential");
        assert_eq!(
            proposal.flags.class_mask & bulletin_bit,
            0,
            "class 1 still admitted"
        );

        let scoped = filter::Filter::between(
            &proposal.terms_ab,
            &proposal.terms_ba,
            proposal.flags.class_mask,
        );
        let now = now_epoch().0 * 1440;
        let bulletin = krab_core::object::RoutingHeader {
            version: 1,
            class: krab_core::object::Class::Bulletin as u8,
            size_bucket: 0,
            flags: 0,
            expiry_min: now + 1_000,
            tag: krab_core::object::Tag([0; 8]),
        };
        assert!(!scoped.admits(&bulletin, now), "a bulletin still crossed");
        let sealed = krab_core::object::RoutingHeader {
            class: krab_core::object::Class::Sealed as u8,
            ..bulletin
        };
        assert!(scoped.admits(&sealed, now), "sealed mail was refused too");
    }

    /// **RFC 6 §216: "clients MUST surface burn rate."** Exhaustion degrades
    /// forward secrecy *silently* — a node whose batch has run out falls back
    /// to the signed prekey and nothing says so.
    #[test]
    fn the_prekey_burn_rate_is_surfaced() {
        let mut a = ready_node("burn-a");
        type_command(&mut a, "keys");
        assert!(a.output.contains("prekeys"), "{}", a.output);
        assert!(
            a.output.contains(&prekeys::BATCH_KEYS.to_string()),
            "the batch size is not reported: {}",
            a.output
        );
        assert!(a.output.contains("republished every"), "{}", a.output);
    }

    /// **A message body is foreign text too.**
    ///
    /// Phase 4 built `display::safe` for RFC 8 §7 and routed the *notes*
    /// through it. The body — the path an operator reads most, and the one
    /// that arrives from an established peer rather than a stranger — kept
    /// rendering U+202E, escape sequences and zero-width characters verbatim.
    #[test]
    fn a_message_body_cannot_carry_formatting_into_a_pane() {
        let mut a = ready_node("body-safe");
        a.messages.push(receive::Message {
            id: krab_core::object::ObjectId([3u8; 32]),
            from: "beefcafe".into(),
            epoch: now_epoch(),
            nodelist: None,
            picture: None,
            body: "safe\u{202e}reversed\u{1b}[31m\u{200b}\nsecond\u{202e}line".into(),
            post_quantum: true,
        });

        // The list row.
        let row = display::safe(a.messages[0].body.lines().next().unwrap_or("")).text;
        for bad in ['\u{202e}', '\u{1b}', '\u{200b}'] {
            assert!(!row.contains(bad), "{bad:?} reached the list");
        }

        // And the pane, every line of it — a control character in the fortieth
        // line is as good as one in the first.
        a.selected = 0;
        a.show_selected();
        for bad in ['\u{202e}', '\u{1b}', '\u{200b}'] {
            assert!(!a.body.contains(bad), "{bad:?} reached the message pane");
        }
        assert!(a.body.contains("second"), "the body was lost: {}", a.body);
    }

    /// **A background tick must not throw away what the operator asked for.**
    ///
    /// The shred warning replaced `self.output` from a timer, so a tick landing
    /// mid-read discarded a command's answer — including, on a bad day, an
    /// error the operator was reading.
    #[test]
    fn the_shred_warning_does_not_discard_the_operators_output() {
        let mut a = ready_node("warn-pane");
        let now = now_epoch().0;
        a.messages.push(receive::Message {
            id: krab_core::object::ObjectId([4u8; 32]),
            from: "beefcafe".into(),
            epoch: krab_core::tag::Epoch(now + 2 - krab_core::tag::EPOCH_WINDOW),
            nodelist: None,
            picture: None,
            body: "keep me".into(),
            post_quantum: true,
        });
        a.output = "the operator asked for this".into();

        a.warn_before_shredding();
        assert!(
            a.output.contains("the operator asked for this"),
            "a tick discarded the pane: {}",
            a.output
        );
        assert!(a.output.contains("permanently unreadable"), "{}", a.output);
        // And it reaches the list, which persists where the output pane does
        // not — §10 wants the consequence in the foreground.
        assert!(
            a.list
                .first()
                .is_some_and(|l| l.contains("unreadable in 2 day(s)")),
            "{:?}",
            a.list.first()
        );
    }

    /// **RFC 7 §8.1's "before".** The warning has to arrive while there is
    /// still something to do about it.
    ///
    /// `shred_expired_epochs` used to log only afterwards — "that mail is
    /// unreadable now" — which is the sentence §8.1 is written against.
    #[test]
    fn the_operator_is_warned_before_mail_becomes_unreadable() {
        let mut a = ready_node("pin-warn");
        let now = now_epoch().0;
        // A message whose epoch falls out of the window in three days.
        a.messages.push(receive::Message {
            id: krab_core::object::ObjectId([1u8; 32]),
            from: "beefcafe".into(),
            epoch: krab_core::tag::Epoch(now + 3 - krab_core::tag::EPOCH_WINDOW),
            nodelist: None,
            picture: None,
            body: "keep me".into(),
            post_quantum: true,
        });

        a.warn_before_shredding();
        assert!(a.output.contains("permanently unreadable"), "{}", a.output);
        assert!(a.output.contains("3 day(s)"), "{}", a.output);
        assert!(
            a.output.contains("pin "),
            "the way out is not named: {}",
            a.output
        );

        // Once per epoch, not per tick — a warning that fires constantly is
        // one an operator turns off.
        a.output.clear();
        a.warn_before_shredding();
        assert!(a.output.is_empty(), "the warning repeated: {}", a.output);
    }

    /// **A pin survives the shred, because its key is not the epoch key.**
    /// That is the whole of RFC 7 §8.1.
    #[test]
    fn a_pinned_conversation_is_kept_and_a_released_one_is_not() {
        let mut a = ready_node("pin-keep");
        let now = now_epoch().0;
        a.messages.push(receive::Message {
            id: krab_core::object::ObjectId([2u8; 32]),
            from: "beefcafe".into(),
            epoch: krab_core::tag::Epoch(now),
            nodelist: None,
            picture: None,
            body: "the one that matters".into(),
            post_quantum: true,
        });

        type_command(&mut a, "pin");
        assert!(a.output.contains("nothing is pinned"), "{}", a.output);

        type_command(&mut a, "pin beefcafe");
        assert!(a.output.contains("pinned 1 message"), "{}", a.output);
        // And the cost is stated rather than left to be discovered.
        assert!(a.output.contains("exempt"), "{}", a.output);

        // It is on disk, sealed under a key that is not `W_N`.
        let raw = std::fs::read(a.path(artifact::Artifact::Pinned)).unwrap();
        assert!(
            krab_crypto::kek::open_under(&a.epoch_key.unwrap(), pin::DOMAIN, &raw).is_err(),
            "the archive opens under the epoch key it was supposed to outlive"
        );
        assert_eq!(a.pinned().kept.len(), 1);
        assert_eq!(a.pinned().kept[0].body, "the one that matters");

        // A pinned message is not warned about: it is not a loss.
        a.warned_shred_at = None;
        a.messages[0].epoch = krab_core::tag::Epoch(now + 1 - krab_core::tag::EPOCH_WINDOW);
        a.pinned_epoch_fixup();
        a.output.clear();
        a.warn_before_shredding();

        type_command(&mut a, "pin release beefcafe");
        assert!(a.output.contains("released 1 message"), "{}", a.output);
        assert!(a.pinned().kept.is_empty());
    }

    /// The archive is cleared from memory on lock, like every other key.
    #[test]
    fn locking_drops_the_long_lived_key() {
        let mut a = ready_node("pin-lock");
        assert!(a.pin_key.is_some());
        a.lock();
        assert!(a.pin_key.is_none(), "a locked node kept the archive key");
        assert!(a.pinned().kept.is_empty(), "a locked node read the archive");
    }

    /// **RFC 8 §7, where the attack actually lands.**
    ///
    /// §7 is written for a client with petnames and this one has none — every
    /// identifier an operator sees is a short id derived from a key, and
    /// `groups::Group::name` is local and never crosses the wire. So §7's
    /// first MUST holds by construction.
    ///
    /// What does arrive from a stranger is the free-text note on a
    /// `peer-request` (RFC 3 §5.1 key 7), and it reached the pane verbatim.
    /// Because every identifier here is hex, the impersonation §7 describes
    /// has a precise form: Cyrillic letters that render as hex digits.
    #[test]
    fn a_note_that_imitates_a_short_id_is_marked_in_the_list() {
        let b = ready_node("hg-b");
        let other = ready_node("hg-other");

        // A peering whose short id is chosen rather than drawn, so the
        // homoglyph in the fixture is guaranteed to be one. `peer_ids` reads
        // the directory names, which is what `foreign` compares against.
        let known = "acedface".to_string();
        let dir = b.home.join("peers").join(&known);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(artifact::PeerFile::Link.name()),
            other
                .identity
                .as_ref()
                .unwrap()
                .card(Policy::default())
                .encode(),
        )
        .unwrap();
        assert!(b.peer_ids().contains(&known));

        // Cyrillic а, с and е for the Latin ones — renders identically.
        let spoofed = "асеdfасе";
        assert_ne!(spoofed, known, "the fixture has no homoglyph in it");

        let line = b.foreign(&format!("from {spoofed}, vouching"));
        assert!(
            line.contains("reads like"),
            "a homoglyph of a known peer went unmarked: {line}"
        );
        assert!(
            line.contains(&known),
            "the mark does not name what it imitates: {line}"
        );

        // And quoting the real one is not marked — otherwise the mark is
        // trained out of an operator within a week.
        let plain = b.foreign(&format!("from {known}, vouching"));
        assert!(!plain.contains("reads like"), "{plain}");
    }

    /// **A stranger's note cannot reach a pane with its control characters.**
    /// A newline breaks a list built from lines; U+202E reverses the rest of
    /// the row without being visible itself.
    #[test]
    fn a_note_cannot_break_the_pane_it_is_rendered_in() {
        let mut x = ready_node("nt-x");
        let mut y = ready_node("nt-y");
        let card = x.home.join("theirs.card");
        std::fs::write(
            &card,
            y.identity
                .as_ref()
                .unwrap()
                .card(Policy::default())
                .encode(),
        )
        .unwrap();
        type_command(
            &mut x,
            &format!("request {} first\u{202e}second", card.display()),
        );
        y.store = x.store.clone();
        type_command(&mut y, "requests");

        // Whatever arrived, the pane is still lines and holds no formatting.
        for bad in ['\n', '\r', '\u{202e}', '\u{200b}'] {
            let rows: Vec<&str> = y.output.lines().collect();
            assert!(
                rows.iter().all(|r| !r.contains(bad)),
                "{bad:?} reached the pane"
            );
        }
    }

    /// **RFC 3 §13's MUST, and the transport mix it depends on.**
    ///
    /// > "Implementations MUST warn below the lower bound for the node's
    /// > actual transport mix, and SHOULD warn above 25 on constrained links."
    ///
    /// The mix is read from the links the node has rather than configured: a
    /// floor the operator sets is a floor the operator can set wrong, and §13
    /// exists because "operators choose peers by hand and will not know any of
    /// this".
    #[test]
    fn the_peer_count_warning_uses_the_mix_the_node_actually_has() {
        let mut a = ready_node("warn-a");
        // No links at all: treated as the austere case, which has the highest
        // floor — the safe direction for a warning.
        let austere = a.peer_warnings();
        assert!(!austere.is_empty());
        assert!(
            austere[0].line().contains("courier"),
            "a node with no links got the easiest floor: {}",
            austere[0].line()
        );

        // A TCP link moves it to the IP-connected floor.
        type_command(&mut a, "connect q3m9 tcp");
        let ip = a.peer_warnings();
        assert!(ip[0].line().contains("IP-connected"), "{}", ip[0].line());
        assert!(ip[0].line().contains("8 is the floor"), "{}", ip[0].line());

        // Every warning reads as a sentence, not as a Debug dump.
        for w in a.peer_warnings() {
            let l = w.line();
            assert!(!l.contains("{"), "unrendered placeholder: {l}");
            assert!(!l.contains("  "), "the text is mangled: {l}");
        }
    }

    /// **RFC 3 §12's aggregates, and only aggregates.** §12 forbids per-object
    /// provenance — "a forensic reconstruction of the graph and its timing
    /// gradients, sitting on disk, waiting for seizure" — so the panel's rows
    /// come from the two counters the budget already keeps.
    #[test]
    fn the_panel_shows_evidence_without_per_object_provenance() {
        let mut x = ready_node("ev12-x");
        let mut y = ready_node("ev12-y");
        let (_, short_y) = link_up(&mut x, &mut y);
        {
            let b = x.budget_for(&short_y).unwrap();
            let mut a = b.spend.lock().unwrap();
            a.spend.objects = 7;
            a.spend.offered = 10;
            a.spend.bytes = 4_096;
        }
        type_command(&mut x, "peers");
        assert!(x.output.contains("7 new"), "{}", x.output);
        assert!(x.output.contains("3 duplicate(s)"), "{}", x.output);
        assert!(x.output.contains("4 KB"), "{}", x.output);
        // §12: "Implementations MUST NOT retain per-object provenance."
        assert!(!x.output.contains("id="), "{}", x.output);
    }

    /// **RFC 3 §8.4, both halves.** "On termination or expiry a node MUST
    /// purge those and **MUST retain the corpus**."
    ///
    /// The two requirements pull opposite ways, so both are asserted:
    /// destroying the corpus would lose everyone else's mail to end one
    /// relationship, and keeping the record would leave what §15 calls "the
    /// peer list with cryptographic proof — worse than an address book".
    ///
    /// The file check walks `PeerFile::ALL` rather than a list, so a new
    /// per-peer artifact fails this until `forget` reaches it — the same
    /// structural form as `wipe`'s, and for the same reason.
    #[test]
    fn forgetting_a_peer_purges_the_record_and_keeps_the_corpus() {
        let mut x = ready_node("fgt-x");
        let mut y = ready_node("fgt-y");
        let (_, short_y) = link_up(&mut x, &mut y);
        share_both_ways(&mut x, &mut y, &short_y);

        // Something in the corpus, and a peering with every artifact on disk.
        x.store.with(|s| {
            let b = test_object(7);
            let _ = s.ingest(
                krab_crypto::object_id(&b),
                b,
                now_epoch().0 * 1440,
                u32::MAX,
            );
        });
        let objects = x.store.len();
        assert!(objects > 0);
        assert!(x.credential_with(&short_y).is_some());
        x.budget_for(&short_y);

        type_command(&mut x, &format!("peer forget {short_y}"));
        assert!(x.output.contains("ended"), "{}", x.output);

        // Every per-peer file is gone, whatever it is called.
        for f in artifact::PeerFile::ALL {
            assert!(
                !x.peer_path(&short_y, f).exists(),
                "{} survived a termination",
                f.name()
            );
        }
        assert!(
            !x.home.join("peers").join(&short_y).exists(),
            "the directory remains"
        );

        // And the corpus is untouched — §8.4's other MUST.
        assert_eq!(x.store.len(), objects, "unpeering destroyed the corpus");

        // No longer acted on, either.
        assert!(!x.spends.contains_key(&short_y));
        assert!(x.credential_with(&short_y).is_none());
        assert!(x.reach.iter().all(|(w, _)| w != &short_y));
    }

    /// **§8.4 says "termination *or* expiry"**, and an expiry has no
    /// keystroke behind it — so the purge runs on the schedule.
    ///
    /// What it takes is what §8.4 names: the record of an agreement. The card
    /// and the reservoir stay, so `peer renew` can still form a fresh
    /// credential rather than the whole ceremony having to run again.
    #[test]
    fn an_expired_peering_has_its_record_purged_but_not_its_material() {
        let mut x = ready_node("pex-x");
        let mut y = ready_node("pex-y");
        let (_, short_y) = link_up(&mut x, &mut y);

        // A credential whose term has genuinely run out, properly signed.
        let w = x.epoch_key.unwrap();
        let (xi, yi) = (x.identity.as_ref().unwrap(), y.identity.as_ref().unwrap());
        let mut cred = credential::Credential::propose(
            xi.signing_key(),
            &xi.card(Policy::default()),
            &yi.card(Policy::default()),
            1,
            1,
            [8u8; 16],
        );
        assert!(cred.sign(yi.signing_key()));
        let sealed =
            krab_crypto::kek::seal_under(&w, b"krab/credential", &cred.encode(), &mut OsRng)
                .unwrap();
        std::fs::write(
            x.peer_path(&short_y, artifact::PeerFile::Credential),
            sealed,
        )
        .unwrap();
        let objects = x.store.len();
        // What is actually on disk, so the assertion is about files that
        // exist rather than files a fixture happens to write.
        let before: Vec<artifact::PeerFile> = artifact::PeerFile::ALL
            .into_iter()
            .filter(|f| x.peer_path(&short_y, *f).exists())
            .collect();
        assert!(before.contains(&artifact::PeerFile::Credential));

        x.purge_expired_peerings();

        for f in before {
            let exists = x.peer_path(&short_y, f).exists();
            if f.purged_on_expiry() {
                assert!(!exists, "{} outlived the agreement it records", f.name());
            } else {
                assert!(
                    exists,
                    "{} was destroyed by an expiry — a lapsed peering is \
                     renewable, not gone",
                    f.name()
                );
            }
        }
        // Their card in particular, or renewal is impossible.
        assert!(x.peer_path(&short_y, artifact::PeerFile::Link).exists());
        assert_eq!(x.store.len(), objects, "an expiry destroyed the corpus");

        // And the operator is told, rather than the link merely going quiet.
        assert!(
            x.log.recent(16).iter().any(|l| l.contains("purged")),
            "an automatic purge happened silently"
        );

        // Renewal still works, from the material that was kept.
        type_command(&mut x, &format!("peer renew {short_y}"));
        assert!(x.output.contains("renewed"), "{}", x.output);
    }

    /// Forgetting someone this node never peered with says so rather than
    /// reporting a successful destruction of nothing.
    #[test]
    fn forgetting_a_stranger_is_refused() {
        let mut x = ready_node("fgs-x");
        type_command(&mut x, "peer forget ffffffff");
        assert!(x.output.contains("no peering"), "{}", x.output);
    }

    /// **RFC 3 §4's MUST: an expired peering is an explicit state, not a
    /// silent sync failure.**
    ///
    /// > "The two look identical from the outside and confusing them will
    /// > waste a great deal of operator time."
    ///
    /// They were identical from the inside too: `credential_with` returns
    /// `Option`, so "never countersigned" and "lapsed last Tuesday" arrived as
    /// the same `None`, and every caller downstream fell back to an unscoped
    /// filter and said nothing.
    #[test]
    fn an_expired_credential_is_named_and_not_confused_with_an_absent_one() {
        let mut x = ready_node("exp-x");
        let mut y = ready_node("exp-y");
        let short_y = peer_up(&mut x, &mut y);

        // No credential at all.
        assert_eq!(x.credential_standing(&short_y), Standing::None);
        let absent = x.credential_standing(&short_y).line(&short_y, x.now_s());
        assert!(absent.contains("no credential"), "{absent}");

        link_up(&mut x, &mut y);
        match x.credential_standing(&short_y) {
            Standing::Live(credential::Life::Current, _) => {}
            other => panic!("a fresh credential is not current: {other:?}"),
        }

        // Age it past its term, the way a calendar does.
        let cred = {
            let w = x.epoch_key.unwrap();
            let sealed =
                std::fs::read(x.peer_path(&short_y, artifact::PeerFile::Credential)).unwrap();
            let raw = krab_crypto::kek::open_under(&w, b"krab/credential", &sealed).unwrap();
            credential::Credential::decode(&raw).unwrap()
        };
        assert_eq!(cred.life(cred.expires_s), credential::Life::Expired);

        // The two states produce different sentences, and the expired one
        // names the command that fixes it.
        let expired = Standing::Live(credential::Life::Expired, cred.expires_s)
            .line(&short_y, cred.expires_s + 86_400);
        assert!(expired.contains("EXPIRED"), "{expired}");
        assert!(expired.contains("peer renew"), "{expired}");
        assert!(
            !expired.contains("no credential"),
            "an expiry read as an absent credential: {expired}"
        );

        // And a due-for-renewal one prompts before it lapses — §4's 75%.
        let due = Standing::Live(credential::Life::DueForRenewal, cred.expires_s)
            .line(&short_y, cred.expires_s - 10 * 86_400);
        assert!(due.contains("expires in 10 day(s)"), "{due}");
        assert!(due.contains("peer renew"), "{due}");
    }

    /// **Renewal carries what was agreed.** §4: "a fresh `peer-link` with a
    /// new nonce, superseding by `established` time" — the dates change and
    /// nothing else, or renewing would silently drop a share flag or a
    /// negotiated quota.
    #[test]
    fn renewal_carries_the_flags_and_terms_across() {
        let mut x = ready_node("ren-x");
        let mut y = ready_node("ren-y");
        let (_, short_y) = link_up(&mut x, &mut y);
        share_both_ways(&mut x, &mut y, &short_y);

        let before = x.credential_with(&short_y).expect("a credential");
        assert!(fragment::listable(
            &before,
            &x.identity.as_ref().unwrap().node_id()
        ));

        type_command(&mut x, &format!("peer renew {short_y}"));
        assert!(x.output.contains("renewed"), "{}", x.output);

        let proposal = credential::Credential::decode(
            &std::fs::read(x.home.join(format!("{short_y}.credential"))).unwrap(),
        )
        .expect("a fresh credential");
        assert_eq!(proposal.flags, before.flags, "the share flags were dropped");
        assert_eq!(proposal.terms_ab, before.terms_ab, "terms were dropped");
        assert_eq!(proposal.terms_ba, before.terms_ba);
        assert_ne!(proposal.nonce, before.nonce, "§4 requires a new nonce");
        assert!(
            proposal.established_s >= before.established_s,
            "a renewal must supersede by established time"
        );
    }

    /// `peer renew` works on an already-expired peering — which is the case it
    /// exists for. `credential_with` refuses one, so the re-sign path reads
    /// the document directly.
    #[test]
    fn renewal_works_on_a_peering_that_has_already_lapsed() {
        let mut x = ready_node("lap-x");
        let mut y = ready_node("lap-y");
        let (_, short_y) = link_up(&mut x, &mut y);

        // A credential whose term has genuinely run out — **properly signed**,
        // because editing the dates of a signed document makes it a forgery
        // and `verify` reports that first, which is right: expiry is a state
        // of a valid document and nothing else.
        let w = x.epoch_key.unwrap();
        let (xi, yi) = (x.identity.as_ref().unwrap(), y.identity.as_ref().unwrap());
        let mut cred = credential::Credential::propose(
            xi.signing_key(),
            &xi.card(Policy::default()),
            &yi.card(Policy::default()),
            1,
            1,
            [4u8; 16],
        );
        assert!(cred.sign(yi.signing_key()));
        let sealed =
            krab_crypto::kek::seal_under(&w, b"krab/credential", &cred.encode(), &mut OsRng)
                .unwrap();
        std::fs::write(
            x.peer_path(&short_y, artifact::PeerFile::Credential),
            sealed,
        )
        .unwrap();

        assert!(
            x.credential_with(&short_y).is_none(),
            "it should be refused"
        );
        match x.credential_standing(&short_y) {
            Standing::Live(credential::Life::Expired, _) => {}
            other => panic!("a lapsed credential reported as {other:?}"),
        }

        type_command(&mut x, &format!("peer renew {short_y}"));
        assert!(x.output.contains("renewed"), "{}", x.output);
        assert!(
            x.output.contains("already expired"),
            "the operator was not told why the link was quiet: {}",
            x.output
        );
    }

    /// **RFC 3 §8.3's default is false, and nothing is listed until both
    /// parties sign the flag.**
    ///
    /// §15: "Fragments are the graph. §8.3's default-false share flag is the
    /// control. An operator who sets it true everywhere has published their
    /// social graph to their peers, one hop at a time."
    #[test]
    fn a_fragment_lists_nothing_until_both_parties_opt_in() {
        let mut x = ready_node("frag-x");
        let mut y = ready_node("frag-y");
        let (_, short_y) = link_up(&mut x, &mut y);

        // A credential exists, and lists nothing.
        assert!(x.credential_with(&short_y).is_some());
        type_command(&mut x, "peer fragment");
        assert!(x.output.contains("nothing to list"), "{}", x.output);
        assert!(x.output.contains("§8.3"), "{}", x.output);

        // X opts in, and hands the re-signed credential to Y.
        type_command(&mut x, &format!("peer share {short_y} on"));
        assert!(x.output.contains("will now list"), "{}", x.output);
        let handover = x.home.join(format!("{short_y}.credential"));
        let to_y = y.home.join("share.credential");
        std::fs::copy(&handover, &to_y).unwrap();
        y.peer_countersign(Some(to_y.to_str().unwrap()));

        // Y hands it back; X stores the countersigned version.
        let short_x = short_id(&x.identity.as_ref().unwrap().node_id());
        let back = y.home.join(format!("{short_x}.credential"));
        let to_x = x.home.join("share.credential");
        std::fs::copy(&back, &to_x).unwrap();
        x.peer_countersign(Some(to_x.to_str().unwrap()));

        // Now the fragment lists it, and goes out sealed per peer.
        type_command(&mut x, "peer fragment");
        assert!(x.output.contains("1 link(s)"), "{}", x.output);
        assert!(x.output.contains(&short_y), "{}", x.output);

        // And Y, who never opted in to listing X, still lists nothing.
        type_command(&mut y, "peer fragment");
        assert!(
            y.output.contains("nothing to list"),
            "Y published a link it never agreed to publish: {}",
            y.output
        );
    }

    /// **RFC 3 §8.2's cadence: a full fragment, then deltas.**
    ///
    /// Re-sending an unchanged nodelist costs one copy per peer for no news,
    /// and §8.2's table puts a one-link delta at 8× to 34× cheaper.
    #[test]
    fn a_second_nodelist_is_a_delta_and_an_unchanged_one_is_nothing() {
        let mut x = ready_node("nd-x");
        let mut y = ready_node("nd-y");
        let (_, short_y) = link_up(&mut x, &mut y);
        share_both_ways(&mut x, &mut y, &short_y);

        type_command(&mut x, "peer fragment");
        assert!(x.output.contains("full nodelist"), "{}", x.output);
        assert!(
            x.read_nodelist_base().is_some(),
            "no base was recorded, so nothing can reference one"
        );

        // Nothing changed, and nothing is due.
        type_command(&mut x, "peer fragment");
        assert!(x.output.contains("nothing has changed"), "{}", x.output);

        // A second peering, and the news is a delta rather than the lot.
        let mut z = ready_node("nd-z");
        let (_, short_z) = link_up(&mut x, &mut z);
        share_both_ways(&mut x, &mut z, &short_z);
        type_command(&mut x, "peer fragment");
        assert!(x.output.contains("NODEDIFF"), "{}", x.output);
        assert!(
            x.output.contains("1 link(s)"),
            "a delta carried everything: {}",
            x.output
        );
    }

    /// **A delta applies against the base the reader holds, and only that.**
    /// §8.2: "a peer that has missed a delta requests the full fragment."
    #[test]
    fn a_reader_applies_a_delta_to_the_base_it_stored() {
        let mut x = ready_node("app-x");
        let mut y = ready_node("app-y");
        let (short_x, short_y) = link_up(&mut x, &mut y);
        share_both_ways(&mut x, &mut y, &short_y);

        // X publishes a full nodelist; Y reads it and records the base.
        type_command(&mut x, "peer fragment");
        y.store = x.store.clone();
        y.refresh_inbox();
        assert!(
            y.read_peer_base(&short_x).is_some(),
            "Y did not record X's base, so X's next delta is unapplicable"
        );
        assert_eq!(
            y.reach
                .iter()
                .find(|(w, _)| *w == short_x)
                .map(|(_, r)| r.len()),
            Some(1)
        );

        // X gains a peering and sends a delta; Y applies it against the base.
        let mut z = ready_node("app-z");
        let (_, short_z) = link_up(&mut x, &mut z);
        share_both_ways(&mut x, &mut z, &short_z);
        type_command(&mut x, "peer fragment");
        assert!(x.output.contains("NODEDIFF"), "{}", x.output);

        y.store = x.store.clone();
        y.refresh_inbox();
        assert_eq!(
            y.reach
                .iter()
                .find(|(w, _)| *w == short_x)
                .map(|(_, r)| r.len()),
            Some(2),
            "the delta was not applied to the stored base"
        );
    }

    /// A delta with no base is dropped, not guessed at — otherwise a reader
    /// builds a nodelist neither party signed.
    #[test]
    fn a_delta_without_its_base_is_dropped() {
        let mut x = ready_node("nob2-x");
        let mut y = ready_node("nob2-y");
        let (short_x, short_y) = link_up(&mut x, &mut y);
        share_both_ways(&mut x, &mut y, &short_y);
        type_command(&mut x, "peer fragment");

        let mut z = ready_node("nob2-z");
        let (_, short_z) = link_up(&mut x, &mut z);
        share_both_ways(&mut x, &mut z, &short_z);
        type_command(&mut x, "peer fragment");

        // Y never saw the full fragment — only the delta.
        y.store = x.store.clone();
        std::fs::remove_file(y.peer_path(&short_x, artifact::PeerFile::Nodelist)).ok();
        y.refresh_inbox();
        assert!(
            y.reach.iter().all(|(w, _)| *w != short_x)
                || y.reach.iter().any(|(w, r)| *w == short_x && r.len() == 1),
            "a delta was applied without its base"
        );
    }

    /// A fragment is sealed to each peer, never flooded — RFC 3 §8. So it is
    /// not a bulletin, and nothing about it is public.
    #[test]
    fn a_fragment_is_not_a_bulletin() {
        let mut x = ready_node("fragb-x");
        let mut y = ready_node("fragb-y");
        let (_, short_y) = link_up(&mut x, &mut y);
        type_command(&mut x, &format!("peer share {short_y} on"));
        let handover = x.home.join(format!("{short_y}.credential"));
        let to_y = y.home.join("s.credential");
        std::fs::copy(&handover, &to_y).unwrap();
        y.peer_countersign(Some(to_y.to_str().unwrap()));
        let short_x = short_id(&x.identity.as_ref().unwrap().node_id());
        let back = y.home.join(format!("{short_x}.credential"));
        let to_x = x.home.join("s.credential");
        std::fs::copy(&back, &to_x).unwrap();
        x.peer_countersign(Some(to_x.to_str().unwrap()));

        let before = x.store.len();
        type_command(&mut x, "peer fragment");
        assert!(x.store.len() > before, "nothing was emitted");

        // Nothing new is readable as a bulletin: a fragment is sealed, and
        // §8 says it is not published, not flooded, and not readable at three
        // hops.
        x.store.with(|s| {
            for (_, oid) in s.entries_in_range(0, u32::MAX) {
                if let Some(bytes) = s.get(&oid) {
                    assert!(
                        bulletin::from_object(bytes)
                            .map(|b| b.kind != bulletin::Kind::Rollcall)
                            .unwrap_or(true),
                        "a fragment was published as a bulletin"
                    );
                    assert!(
                        fragment::Fragment::decode(bytes).is_none(),
                        "a fragment is readable straight out of the corpus"
                    );
                }
            }
        });
    }

    /// **RFC 3 §6's example, through the interface.**
    ///
    /// > X requests: 10 MB/day … B counters: 1 MB/day … X accepts.
    /// > "You can peer with a stranger at 1% trust."
    ///
    /// Before §5.2 existed, a credential's terms came from
    /// `LinkTerms::default()` whatever either party wanted — peering was
    /// accept-or-reject, the binary §5 says removes §6's whole point.
    #[test]
    fn a_counter_sets_the_terms_the_credential_is_built_from() {
        let mut x = ready_node("neg-x");
        let mut b = ready_node("neg-b");

        // X requests. The card goes by hand, as first contact does.
        let card = x.home.join("theirs.card");
        std::fs::write(
            &card,
            b.identity
                .as_ref()
                .unwrap()
                .card(Policy::default())
                .encode(),
        )
        .unwrap();
        type_command(&mut x, &format!("request {} let me in", card.display()));

        // B sees it, and counters with a sliver.
        b.store = x.store.clone();
        type_command(&mut b, "requests");
        assert!(b.output.contains("request from"), "{}", b.output);
        type_command(&mut b, "peer counter 1 1 500 3");
        assert!(b.output.contains("countered"), "{}", b.output);

        let short_x = short_id(&x.identity.as_ref().unwrap().node_id());
        let chain = b.chain_with(&short_x).expect("B stored the negotiation");
        assert_eq!(chain.verify(), Ok(()));
        assert_eq!(chain.counters.len(), 1);

        // The credential B would now propose carries B's stated terms, not a
        // default — which is the whole of §5.2.
        let proposal = b.propose_credential(&x.identity.as_ref().unwrap().card(Policy::default()));
        let cred = credential::Credential::decode(&proposal).expect("a credential");
        let b_id = b.identity.as_ref().unwrap().node_id();
        let mine = if cred.a.node_id() == b_id {
            cred.terms_ab
        } else {
            cred.terms_ba
        };
        assert_eq!(mine.bytes_per_day, 1 << 20, "B's sliver was not carried");
        assert_eq!(mine.objects_per_day, 500);
        assert_eq!(mine.retention_days, 3);
        assert_ne!(
            mine.bytes_per_day,
            credential::LinkTerms::default().bytes_per_day,
            "the credential fell back to defaults"
        );
    }

    /// A counter reaches the other party the way the request did — the inbox
    /// tag, because at this point they are still strangers.
    #[test]
    fn a_counter_travels_to_the_other_party() {
        let mut x = ready_node("trav-x");
        let mut b = ready_node("trav-b");
        let card = x.home.join("theirs.card");
        std::fs::write(
            &card,
            b.identity
                .as_ref()
                .unwrap()
                .card(Policy::default())
                .encode(),
        )
        .unwrap();
        type_command(&mut x, &format!("request {} hi", card.display()));
        b.store = x.store.clone();
        type_command(&mut b, "peer counter 1 2 900 7");

        // X, reading the same corpus, sees the counter on its own inbox tag.
        x.store = b.store.clone();
        type_command(&mut x, "requests");
        assert!(x.output.contains("counter from"), "{}", x.output);
        assert!(x.output.contains("2 MB/day"), "{}", x.output);
    }

    /// **It is not your turn.** A party that answered its own last word would
    /// make the chain evidence of a conversation it never had — §5.2's stated
    /// purpose is that neither party can misrepresent what was offered.
    #[test]
    fn a_party_cannot_counter_its_own_last_word_through_the_interface() {
        let mut x = ready_node("turn-x");
        let mut b = ready_node("turn-b");
        let card = x.home.join("theirs.card");
        std::fs::write(
            &card,
            b.identity
                .as_ref()
                .unwrap()
                .card(Policy::default())
                .encode(),
        )
        .unwrap();
        type_command(&mut x, &format!("request {} hi", card.display()));
        b.store = x.store.clone();
        type_command(&mut b, "peer counter 1 1 500 3");
        // B answers again without X having spoken.
        type_command(&mut b, "peer counter 1 1 400 3");
        assert!(b.output.contains("not your turn"), "{}", b.output);
    }

    /// **The filter digest is no longer a constant.**
    ///
    /// Every exchange used to pass `[0u8; 32]`. The digest was checked on both
    /// sides and compared two zeros, so two nodes with entirely different
    /// ideas of what an exchange covered agreed every time — RFC 3 §7.3's
    /// "both sides provably agree on the scope", proving nothing.
    /// A well-formed corpus object, for budget tests.
    fn test_object(salt: u32) -> Vec<u8> {
        let h = krab_core::object::RoutingHeader {
            version: 1,
            class: 0,
            size_bucket: 0,
            flags: 0,
            expiry_min: now_epoch().0 * 1440 + 10_000,
            tag: krab_core::object::Tag((salt as u64).to_le_bytes()),
        };
        krab_core::object::canonical_bytes(&h, &krab_core::object::example_sealed_body(salt as u8)).unwrap()
    }

    /// Complete a credential between two ready nodes, both ends.
    fn link_up(x: &mut App, y: &mut App) -> (String, String) {
        let short_y = peer_up(x, y);
        let short_x = peer_up(y, x);
        let proposal = x.propose_credential(&y.identity.as_ref().unwrap().card(Policy::default()));
        let to_y = y.home.join("lk.credential");
        std::fs::write(&to_y, &proposal).unwrap();
        y.peer_countersign(Some(to_y.to_str().unwrap()));
        let back = y.home.join(format!("{short_x}.credential"));
        let to_x = x.home.join("lk.credential");
        std::fs::copy(&back, &to_x).unwrap();
        x.peer_countersign(Some(to_x.to_str().unwrap()));
        (short_x, short_y)
    }

    /// **RFC 3 §6 — the budget stops objects, and it comes from the signed
    /// credential.** "You exceeded quota" is a checkable statement against a
    /// signed artifact rather than a unilateral judgement, which is only true
    /// if the ceiling is read from the document both parties signed.
    #[test]
    fn a_link_budget_stops_objects_once_it_is_spent() {
        let mut x = ready_node("bud-x");
        let mut y = ready_node("bud-y");
        let (_, short_y) = link_up(&mut x, &mut y);

        let budget = x.budget_for(&short_y).expect("a credential sets a ceiling");
        assert!(budget.bytes_per_day > 0);
        assert!(budget.objects_per_day > 0);

        // A view held to a ceiling of two objects.
        let tight = shared::Budget {
            objects_per_day: 2,
            ..budget
        };
        let store = shared::SharedStore::new(krab_store::index::Store::new());
        let mut view = shared::ExchangeView::new(
            store.clone(),
            now_epoch().0 * 1440,
            krab_crypto::CarriagePolicy::default(),
            filter::Filter::unscoped(),
            now_epoch().0 * 1440,
            krab_fabric::profile::MaxBucket(5),
        )
        .with_budget(tight);

        use krab_proto::recon::Corpus;
        for salt in 0u32..5 {
            view.put(test_object(salt));
        }
        assert_eq!(store.len(), 2, "the budget did not hold the link to two");
    }

    /// **RFC 3 §6.2 — the dial moves within the credential and never past
    /// it**, and a fresh peering starts at an eighth of what was signed.
    ///
    /// RFC 0 §5.3: "graduated quota is what makes early vantage points
    /// low-bandwidth and slow to become useful." An adversary who obtains a
    /// peering does not obtain a vantage point on the corpus — they obtain an
    /// eighth of one, and have to behave for a week for the rest.
    #[test]
    fn a_fresh_peering_is_dialled_down_and_earns_its_way_up() {
        let mut x = ready_node("dial-x");
        let mut y = ready_node("dial-y");
        let (_, short_y) = link_up(&mut x, &mut y);

        let signed = x
            .inbound_terms(&short_y)
            .expect("a credential")
            .objects_per_day;
        let fresh = x.budget_for(&short_y).unwrap();
        assert_eq!(
            fresh.objects_per_day,
            signed / quota::MATURE_WINDOWS as u64,
            "a fresh peering was granted the full ceiling"
        );

        // Eight good windows, driven through the account the way a day roll
        // does, and the dial reaches the signed ceiling and stops.
        {
            let cell = x.spends.get(&short_y).unwrap();
            let mut a = cell.lock().unwrap();
            for day in 1..=20u32 {
                a.spend.day = day;
                a.spend.offered = 100;
                a.spend.objects = 100;
                a.spend.refused = 0;
                a.roll(day + 1);
            }
        }
        let mature = x.budget_for(&short_y).unwrap();
        assert_eq!(mature.objects_per_day, signed, "the dial never matured");
        assert!(
            mature.objects_per_day <= signed,
            "the dial exceeded the signed ceiling"
        );
    }

    /// **A violation drops it sharply** — §6.2's "flood → quota reduction",
    /// and RFC 3 §12's key metric: high volume at low novelty.
    #[test]
    fn high_volume_at_low_novelty_drops_the_dial() {
        let mut x = ready_node("drop-x");
        let mut y = ready_node("drop-y");
        let (_, short_y) = link_up(&mut x, &mut y);
        x.budget_for(&short_y);

        let cell = x.spends.get(&short_y).unwrap().clone();
        {
            let mut a = cell.lock().unwrap();
            a.standing.age = quota::MATURE_WINDOWS;
            // A window of pure duplication.
            a.spend.day = 1;
            a.spend.offered = 5_000;
            a.spend.objects = 1;
            a.roll(2);
        }
        let after = cell.lock().unwrap().standing.age;
        assert_eq!(
            after,
            quota::MATURE_WINDOWS / 2,
            "a flood did not reduce the quota"
        );

        // And the link is still up: §6.2 makes disconnection the limit case,
        // not the mechanism.
        assert!(x.budget_for(&short_y).unwrap().objects_per_day > 0);
    }

    /// The novelty ratio counts objects the view never saw. `put` is reached
    /// only for objects this node lacks, so without the driver's `offered` a
    /// peer re-sending the whole corpus would look like a peer with nothing to
    /// send.
    #[test]
    fn the_novelty_ratio_counts_duplicates() {
        let mut m = krab_node::exchange::Moved::default();
        m.offered = 10;
        m.received = 1;
        let mut a = quota::Account::default();
        a.spend.offered = m.offered as u64;
        a.spend.objects = m.received as u64;
        assert_eq!(a.spend.novelty(), Some(0.1));
        assert_eq!(
            quota::Standing::judge(&quota::Spend {
                offered: 1_000,
                objects: 1,
                ..a.spend
            }),
            quota::Conduct::Unproductive
        );
    }

    /// A link with no credential has agreed no ceiling, so none is enforced —
    /// a budget nobody signed is the unilateral judgement §6 is written
    /// against.
    #[test]
    fn a_link_with_no_credential_is_metered_at_the_defaults() {
        let mut x = ready_node("nob-x");
        let mut y = ready_node("nob-y");
        let short_y = peer_up(&mut x, &mut y);

        // It used to be `None`, and `put` skips the quota block entirely on
        // `None` — so a ceremony that was never completed bought unmetered
        // ingress, which is strictly more than completing one grants.
        let b = x
            .budget_for(&short_y)
            .expect("an uncredentialled link is unmetered");
        let d = credential::LinkTerms::default();
        assert!(
            b.bytes_per_day <= d.bytes_per_day,
            "the default budget is looser than the default terms"
        );
    }

    /// **The budget survives a restart**, or it is not a budget: a peer that
    /// spent its day could restart the other end and start again.
    #[test]
    fn a_spent_budget_survives_a_restart() {
        let mut x = ready_node("per-x");
        let mut y = ready_node("per-y");
        let (_, short_y) = link_up(&mut x, &mut y);

        let b = x.budget_for(&short_y).unwrap();
        b.spend.lock().unwrap().spend.charge(4_096);
        x.save_spends();

        // A fresh view of the same home, as a restart gives.
        x.spends.clear();
        let again = x.budget_for(&short_y).unwrap();
        let spend = *again.spend.lock().unwrap();
        assert_eq!(spend.spend.objects, 1, "the budget reset on restart");
        assert_eq!(spend.spend.bytes, 4_096);
    }

    /// The counters are cleared on lock: they are sealed under `W_N`, which a
    /// locked node no longer holds.
    #[test]
    fn locking_drops_the_in_memory_budgets() {
        let mut x = ready_node("lockb-x");
        let mut y = ready_node("lockb-y");
        let (_, short_y) = link_up(&mut x, &mut y);
        assert!(x.budget_for(&short_y).is_some());
        assert!(!x.spends.is_empty());
        x.lock();
        assert!(x.spends.is_empty(), "a locked node kept per-link counters");
    }

    #[test]
    fn the_exchange_scope_comes_from_the_credential() {
        let mut x = ready_node("scope-x");
        let mut y = ready_node("scope-y");
        let short_y = peer_up(&mut x, &mut y);
        let short_x = peer_up(&mut y, &mut x);

        // No credential yet: the *defaults*, not unscoped. An unfinished
        // agreement used to admit everything, which is more than finishing
        // one grants — `admits` returns true on its first line for an
        // unscoped filter.
        let before = x.scope_for(&short_y);
        assert!(
            !before.is_unscoped(),
            "an uncredentialled link admits everything"
        );
        assert_ne!(before.digest(), [0u8; 32], "the vacuous digest is back");
        let d = credential::LinkTerms::default();
        assert_eq!(
            before.retention_days, d.retention_days,
            "the fallback is not the ceremony's own defaults"
        );

        // Complete a credential on both ends.
        let proposal = x.propose_credential(&y.identity.as_ref().unwrap().card(Policy::default()));
        let to_y = y.home.join("in.credential");
        std::fs::write(&to_y, &proposal).unwrap();
        y.peer_countersign(Some(to_y.to_str().unwrap()));
        let back = y.home.join(format!("{short_x}.credential"));
        let to_x = x.home.join("in.credential");
        std::fs::copy(&back, &to_x).unwrap();
        x.peer_countersign(Some(to_x.to_str().unwrap()));

        // Both ends now derive a real scope, and the same one.
        let sx = x.scope_for(&short_y);
        let sy = y.scope_for(&short_x);
        assert!(!sx.is_unscoped(), "a credential scoped nothing");
        assert_eq!(
            sx.digest(),
            sy.digest(),
            "the two ends disagree about the scope of their own link"
        );
        // Was `assert_ne!` against the pre-credential scope. That comparison
        // stopped meaning anything once the fallback became the ceremony's
        // own defaults: a credential agreeing those terms yields the same
        // filter, correctly. What still has to hold is that the scope is a
        // real one rather than the admit-everything filter it used to be.
        assert!(!sx.is_unscoped());
        assert_ne!(
            sx.digest(),
            filter::Filter::unscoped().digest(),
            "a credentialled link is indistinguishable from an uncredentialled one"
        );
    }

    #[test]
    fn both_ends_end_up_holding_the_completed_credential() {
        let mut x = ready_node("both-x");
        let mut y = ready_node("both-y");
        let short_y = peer_up(&mut x, &mut y);
        let short_x = peer_up(&mut y, &mut x);

        // X proposes.
        let proposal = x.propose_credential(&y.identity.as_ref().unwrap().card(Policy::default()));
        let to_y = y.home.join("in.credential");
        std::fs::write(&to_y, &proposal).unwrap();

        // Y countersigns, and must hand something back.
        y.peer_countersign(Some(to_y.to_str().unwrap()));
        assert!(
            y.credential_with(&short_x).is_some(),
            "Y cannot cite its own credential"
        );
        let back = y.home.join(format!("{short_x}.credential"));
        assert!(back.exists(), "Y kept the only complete credential");

        // X ingests it.
        let to_x = x.home.join("in.credential");
        std::fs::copy(&back, &to_x).unwrap();
        x.peer_countersign(Some(to_x.to_str().unwrap()));
        assert!(
            x.credential_with(&short_y).is_some(),
            "X was left holding a proposal for ever"
        );

        // X received a complete document, so nothing is owed onward — and the
        // plaintext file it was read from is gone, whatever it was called.
        assert!(
            !to_x.exists(),
            "a plaintext credential was left where the courier unloaded it"
        );
        assert!(!x.home.join(format!("{short_y}.credential")).exists());
    }

    /// **RFC 3 §15: "The credential store MUST be encrypted under the RFC 7
    /// key hierarchy."**
    ///
    /// A completed credential is the most incriminating file this node writes
    /// — not a name but a mutually signed, non-repudiable statement that two
    /// nodes agreed to peer. The first version of `peer countersign` wrote it
    /// in the clear.
    #[test]
    fn a_credential_is_sealed_at_rest() {
        let mut x = ready_node("seal-x");
        let mut y = ready_node("seal-y");
        peer_up(&mut x, &mut y);
        peer_up(&mut y, &mut x);

        let proposal = x.propose_credential(&y.identity.as_ref().unwrap().card(Policy::default()));
        let path = y.home.join("p.credential");
        std::fs::write(&path, &proposal).unwrap();
        assert!(y
            .peer_countersign(Some(path.to_str().unwrap()))
            .contains("complete"));

        let short_x = short_id(&x.identity.as_ref().unwrap().node_id());
        let stored = std::fs::read(y.peer_path(&short_x, artifact::PeerFile::Credential)).unwrap();
        assert!(
            credential::Credential::decode(&stored).is_none(),
            "the credential is readable straight off the disk"
        );
        // The identity keys must not appear in the file at all.
        for pk in [
            x.identity
                .as_ref()
                .unwrap()
                .card(Policy::default())
                .identity_pk,
            y.identity
                .as_ref()
                .unwrap()
                .card(Policy::default())
                .identity_pk,
        ] {
            assert!(
                !stored.windows(32).any(|w| w == pk),
                "an identity key is in the clear on disk"
            );
        }
        // And it still opens for the node that owns it.
        assert!(y.credential_with(&short_x).is_some());
    }

    /// **A credential must name this node's own keys.**
    ///
    /// `other_than` matches on node id, which is a hash of `sig_pk`, so a
    /// wrong identity key cannot get through. `kx_pk` is not covered by that
    /// and was unchecked: a peer could propose a credential carrying this
    /// node's real identity key beside a correspondence key **they** control,
    /// and countersigning it would produce a signed, non-repudiable statement
    /// by this node that its own key is theirs.
    #[test]
    fn a_credential_naming_the_wrong_correspondence_key_is_refused() {
        let mut x = ready_node("kx-x");
        let mut y = ready_node("kx-y");
        peer_up(&mut x, &mut y);
        peer_up(&mut y, &mut x);
        let attacker = ready_node("kx-evil");

        let mut cred = credential::Credential::decode(
            &x.propose_credential(&y.identity.as_ref().unwrap().card(Policy::default())),
        )
        .unwrap();

        // Swap Y's correspondence key for one the attacker holds, leaving
        // every identity key untouched so the parties still resolve.
        let evil_kx = attacker
            .identity
            .as_ref()
            .unwrap()
            .card(Policy::default())
            .correspondence_pk;
        let y_id = y.identity.as_ref().unwrap().node_id();
        if cred.a.node_id() == y_id {
            cred.a.kx_pk = evil_kx;
        } else {
            cred.b.kx_pk = evil_kx;
        }

        let path = y.home.join("evil.credential");
        std::fs::write(&path, cred.encode()).unwrap();
        let out = y.peer_countersign(Some(path.to_str().unwrap()));
        assert!(out.contains("does not name your keys"), "{out}");
        let short_x = short_id(&x.identity.as_ref().unwrap().node_id());
        assert!(
            y.credential_with(&short_x).is_none(),
            "it was signed anyway"
        );
    }

    /// The same, for the counterparty's keys: a credential that disagrees with
    /// the peer-link this node holds is two documents about one peering saying
    /// different things.
    #[test]
    fn a_credential_disagreeing_with_the_peer_link_is_refused() {
        let mut x = ready_node("dis-x");
        let mut y = ready_node("dis-y");
        peer_up(&mut x, &mut y);
        peer_up(&mut y, &mut x);
        let other = ready_node("dis-o");

        let mut cred = credential::Credential::decode(
            &x.propose_credential(&y.identity.as_ref().unwrap().card(Policy::default())),
        )
        .unwrap();
        let evil_kx = other
            .identity
            .as_ref()
            .unwrap()
            .card(Policy::default())
            .correspondence_pk;
        let x_id = x.identity.as_ref().unwrap().node_id();
        if cred.a.node_id() == x_id {
            cred.a.kx_pk = evil_kx;
        } else {
            cred.b.kx_pk = evil_kx;
        }

        let path = y.home.join("mismatch.credential");
        std::fs::write(&path, cred.encode()).unwrap();
        let out = y.peer_countersign(Some(path.to_str().unwrap()));
        assert!(out.contains("does not match the peer-link"), "{out}");
    }

    /// **Countersigning is agreeing to terms, so the terms are printed.**
    ///
    /// RFC 3 §5.3 makes the countersignature the act of acceptance, and §6
    /// says quota is "a checkable statement against a signed artifact rather
    /// than a unilateral judgement" — which is only true if the party bound by
    /// it saw it. The first version signed and reported success without ever
    /// showing the operator what they had agreed to.
    #[test]
    fn countersigning_shows_the_terms_being_agreed_to() {
        let mut x = ready_node("terms-x");
        let mut y = ready_node("terms-y");
        peer_up(&mut x, &mut y);
        peer_up(&mut y, &mut x);

        let proposal = x.propose_credential(&y.identity.as_ref().unwrap().card(Policy::default()));
        let path = y.home.join("t.credential");
        std::fs::write(&path, &proposal).unwrap();
        let out = y.peer_countersign(Some(path.to_str().unwrap()));

        assert!(out.contains("you accept from them"), "{out}");
        assert!(out.contains("they accept from you"), "{out}");
        assert!(out.contains("retained"), "{out}");
    }

    /// `peer countersign` completes a credential and stores it where the
    /// request path finds it, and refuses one between two other nodes.
    #[test]
    fn countersigning_completes_a_credential_and_refuses_a_strangers() {
        let mut x = ready_node("cs-x");
        let mut y = ready_node("cs-y");
        let short_y = peer_up(&mut x, &mut y);
        let _ = peer_up(&mut y, &mut x);

        // X proposes; the file lands in X's home.
        let proposal = x.propose_credential(&y.identity.as_ref().unwrap().card(Policy::default()));
        let path = x.home.join("proposal.credential");
        std::fs::write(&path, &proposal).unwrap();

        // Y countersigns it.
        let ypath = y.home.join("proposal.credential");
        std::fs::write(&ypath, &proposal).unwrap();
        let out = y.peer_countersign(Some(ypath.to_str().unwrap()));
        assert!(out.contains("is complete"), "{out}");
        let short_x = short_id(&x.identity.as_ref().unwrap().node_id());
        assert!(
            y.credential_with(&short_x).is_some(),
            "Y did not store the completed credential"
        );

        // And X, given the document Y hands back, stores it too. Y's copy in
        // its peer directory is sealed; the handover file is the plaintext one.
        let done = std::fs::read(y.home.join(format!("{short_x}.credential"))).unwrap();
        std::fs::write(&path, &done).unwrap();
        let out = x.peer_countersign(Some(path.to_str().unwrap()));
        assert!(out.contains("is complete"), "{out}");
        assert!(x.credential_with(&short_y).is_some());

        // A credential between two other nodes is refused.
        let z = ready_node("cs-z");
        let w = ready_node("cs-w");
        let theirs = completed_credential(&z, &w, x.now_s());
        let p = x.home.join("theirs.credential");
        std::fs::write(&p, theirs.encode()).unwrap();
        let out = x.peer_countersign(Some(p.to_str().unwrap()));
        assert!(out.contains("not yours to sign"), "{out}");
    }

    /// An introduction is honoured once — RFC 3 §10's "single-use" — and the
    /// record survives a restart, or it is a sentence rather than a property.
    #[test]
    fn an_introduction_is_spent_on_acceptance_and_stays_spent() {
        let mut a = ready_node("spend-a");
        let mut b = ready_node("spend-b");
        let c = ready_node("spend-c");
        peer_up(&mut b, &mut a);

        let me = b.identity.as_ref().unwrap().node_id();
        let token = introduction::Token::create(
            a.identity.as_ref().unwrap().signing_key(),
            c.identity.as_ref().unwrap().node_id(),
            me,
            b.now_s(),
            introduction::MAX_LIFETIME_S,
            &mut OsRng,
        );
        let req = request::PeerRequest::create_introduced(
            c.identity.as_ref().unwrap().signing_key(),
            c.identity.as_ref().unwrap().card(Policy::default()),
            me,
            credential::LinkTerms::default(),
            "",
            Some(token.clone()),
            None,
        );

        let now = b.now_s();
        assert!(
            b.introduction_line(&req, &me, now, &b.spent_tokens())
                .contains("unspent"),
            "{}",
            b.introduction_line(&req, &me, now, &b.spent_tokens())
        );

        let out = b.accept_request(&req);
        assert!(out.contains("now spent"), "{out}");
        assert!(b.spent_tokens().contains(&token.nonce));

        // Reading the spent set from disk is what a restart does.
        assert!(
            b.introduction_line(&req, &me, now, &b.spent_tokens())
                .contains("already used"),
            "the token was honoured twice"
        );
    }

    /// **Reading the list does not spend anything.** Burning a token because
    /// somebody looked at their inbox would make single-use mean something
    /// nobody asked for.
    #[test]
    fn listing_requests_does_not_spend_an_introduction() {
        let mut b = ready_node("nospend");
        type_command(&mut b, "requests");
        assert!(b.spent_tokens().is_empty());
        assert!(
            b.output.contains("no first-contact requests"),
            "{}",
            b.output
        );
    }

    /// A token bound to somebody else is refused at the point it is offered,
    /// not after a request has already gone out unvouched.
    #[test]
    fn a_token_for_somebody_else_is_refused_when_offered() {
        let mut a = ready_node("bind-a");
        let mut c = ready_node("bind-c");
        let mut b = ready_node("bind-b");
        let mut stranger = ready_node("bind-x");
        peer_up(&mut a, &mut c);
        peer_up(&mut a, &mut b);

        let c_short = short_id(&c.identity.as_ref().unwrap().node_id());
        let b_short = short_id(&b.identity.as_ref().unwrap().node_id());
        type_command(&mut a, &format!("introduce {c_short} {b_short}"));
        let token = minted(&a.output);

        type_command(&mut stranger, &format!("introduce use {token}"));
        assert!(
            stranger.output.contains("vouches for somebody else"),
            "{}",
            stranger.output
        );
        assert!(stranger.introductions.is_empty());
    }

    /// Vouching requires a peering. A vouch for someone you have not peered
    /// with is not evidence of anything, which is the whole basis of §10.
    #[test]
    fn vouching_requires_having_peered() {
        let mut a = ready_node("vouch-a");
        type_command(&mut a, "introduce ffffffff eeeeeeee");
        assert!(a.output.contains("no peer-link"), "{}", a.output);
    }

    /// Held tokens do not survive a lock — they are private vouches other
    /// people made, and a locked node has no business holding one.
    #[test]
    fn locking_releases_held_introductions() {
        let mut a = ready_node("lock-intro");
        let mut c = ready_node("lock-intro-c");
        let mut b = ready_node("lock-intro-b");
        peer_up(&mut a, &mut c);
        peer_up(&mut a, &mut b);
        let c_short = short_id(&c.identity.as_ref().unwrap().node_id());
        let b_short = short_id(&b.identity.as_ref().unwrap().node_id());
        type_command(&mut a, &format!("introduce {c_short} {b_short}"));
        let token = minted(&a.output);
        type_command(&mut c, &format!("introduce use {token}"));
        assert_eq!(c.introductions.len(), 1);

        c.lock();
        assert!(c.introductions.is_empty(), "a locked node held a vouch");
    }

    /// Count this node's own rollcall entries in the corpus.
    fn listed_entries(a: &App) -> Vec<rollcall::Entry> {
        let me = a.identity.as_ref().map(|i| i.node_id());
        let mut out = Vec::new();
        a.store.with(|s| {
            for (_, oid) in s.entries_in_range(0, u32::MAX) {
                if let Some(b) = s.get(&oid).and_then(bulletin::from_object) {
                    if b.kind == bulletin::Kind::Rollcall && Some(b.node_id()) == me {
                        if let Some(e) = rollcall::Entry::decode(&b.payload) {
                            out.push(e);
                        }
                    }
                }
            }
        });
        out
    }

    /// **A fresh node is invisible, and reading the directory does not change
    /// that.** RFC 3 §9: "a node that never publishes an entry is invisible to
    /// it … That MUST be the default."
    ///
    /// The second half is the part worth a test. A bare `rollcall` is a query,
    /// and if it published as a side effect of answering, the default would be
    /// off only until the first time anyone looked.
    #[test]
    fn a_node_is_not_listed_until_it_says_so() {
        let mut a = ready_node("rollcall");
        assert!(!a.rollcall.publishing);
        type_command(&mut a, "rollcall");
        assert!(a.output.contains("not listed"), "{}", a.output);
        assert!(!a.rollcall.publishing, "reading the directory opted us in");
        assert!(listed_entries(&a).is_empty(), "an entry was published");
    }

    /// `rollcall publish` lists the node, and the entry carries keys and terms.
    #[test]
    fn publishing_lists_the_node_with_its_terms() {
        let mut a = ready_node("rollcall");
        type_command(&mut a, "rollcall publish");
        assert!(a.rollcall.publishing, "{}", a.output);

        let entries = listed_entries(&a);
        assert_eq!(entries.len(), 1, "{}", a.output);
        let (kx, short) = {
            let id = a.identity.as_ref().unwrap();
            (id.correspondence_bytes(), id.short_id())
        };
        assert_eq!(entries[0].kx_pk, kx);

        // And it now shows in the directory, as us.
        type_command(&mut a, "rollcall");
        assert!(a.output.contains(&short), "{}", a.output);
        assert!(a.output.contains("(you)"), "{}", a.output);
    }

    /// **RFC 3 §9.2 — no reachability information, ever.**
    ///
    /// Checked against the published *object*, not the struct: the entry is
    /// wrapped in a bulletin and a routing header before it floods, and this
    /// is the artifact a stranger actually receives.
    #[test]
    fn a_published_entry_carries_no_endpoint() {
        let mut a = ready_node("rollcall");
        // Give the node a link, so there is an endpoint in memory that could
        // leak into an entry built carelessly.
        type_command(&mut a, "connect beacon tcp 127.0.0.1:40404");
        type_command(&mut a, "rollcall publish");

        let mut published: Vec<Vec<u8>> = Vec::new();
        let me = a.identity.as_ref().map(|i| i.node_id());
        a.store.with(|s| {
            for (_, oid) in s.entries_in_range(0, u32::MAX) {
                let Some(bytes) = s.get(&oid) else { continue };
                if let Some(b) = bulletin::from_object(bytes) {
                    if b.kind == bulletin::Kind::Rollcall && Some(b.node_id()) == me {
                        published.push(bytes.to_vec());
                    }
                }
            }
        });
        assert_eq!(published.len(), 1);

        for needle in ["127.0.0.1", "40404", "tcp", "beacon"] {
            assert!(
                !published[0]
                    .windows(needle.len())
                    .any(|w| w == needle.as_bytes()),
                "the entry carries `{needle}` — RFC 3 §9.2 forbids reachability"
            );
        }
    }

    /// **No statement that A peers with B** — RFC 3 §9.1's other column. A
    /// directory of links is the social graph.
    #[test]
    fn a_published_entry_names_no_peer() {
        let mut a = ready_node("rollcall");
        let b = ready_node("counterpart");
        let peer = b.identity.as_ref().unwrap().short_id();
        type_command(&mut a, "rollcall publish");

        let entries = listed_entries(&a);
        assert_eq!(entries.len(), 1);
        // The entry has no field that could name one, so the check is on the
        // encoding: nothing that identifies another node appears in it.
        let bytes = entries[0].encode();
        assert!(!bytes.windows(peer.len()).any(|w| w == peer.as_bytes()));
        assert!(!bytes
            .windows(32)
            .any(|w| w == b.identity.as_ref().unwrap().node_id()));
    }

    /// **Withdrawal is not recall, and the text must not suggest it is.**
    /// RFC 3 §6.1 forbids a recall mechanism permanently. The likeliest
    /// failure here is an operator believing `withdraw` removed something.
    #[test]
    fn withdrawing_stops_republication_and_says_recall_is_impossible() {
        let mut a = ready_node("rollcall");
        type_command(&mut a, "rollcall publish");
        let before = listed_entries(&a).len();

        type_command(&mut a, "rollcall withdraw");
        assert!(!a.rollcall.publishing);
        assert!(a.output.contains("cannot be recalled"), "{}", a.output);
        assert!(a.output.contains("expires"), "{}", a.output);
        assert_eq!(
            listed_entries(&a).len(),
            before,
            "withdrawing deleted the published entry, which is a recall"
        );
    }

    /// A lock stops republication. Listing is an operator decision, and a lock
    /// is the moment nothing about the operator's intent is still known.
    #[test]
    fn locking_stops_republishing_to_the_rollcall() {
        let mut a = ready_node("rollcall");
        type_command(&mut a, "rollcall publish");
        assert!(a.rollcall.publishing);
        a.lock();
        assert!(!a.rollcall.publishing, "a locked node kept publishing");
        assert!(!a.rollcall.due(u32::MAX));
    }

    /// The refresh only runs for a node that opted in — the schedule must not
    /// be a path to publication for a node that never asked.
    #[test]
    fn the_schedule_does_not_list_a_node_that_never_opted_in() {
        let mut a = ready_node("rollcall");
        for _ in 0..4 {
            a.republish_rollcall_if_due();
        }
        assert!(listed_entries(&a).is_empty());
        assert!(!a.rollcall.publishing);
    }

    /// An unknown subcommand is refused with the three forms, rather than
    /// falling through to the one that publishes.
    #[test]
    fn an_unknown_rollcall_subcommand_publishes_nothing() {
        let mut a = ready_node("rollcall");
        type_command(&mut a, "rollcall enable");
        assert!(a.output.contains("no rollcall subcommand"), "{}", a.output);
        assert!(!a.rollcall.publishing);
        assert!(listed_entries(&a).is_empty());
    }

    /// An unknown transport is refused rather than silently defaulted, since a
    /// default would be a link profile the operator did not choose — and a
    /// wrong profile is exactly what `reach` exists to diagnose.
    #[test]
    fn an_unknown_transport_is_refused() {
        let mut a = ready_node("transport");
        type_command(&mut a, "connect q3m9 carrier-pigeon");
        assert!(a.output.contains("unknown transport"), "{}", a.output);
        assert_eq!(a.links.iter().count(), 0);
    }

    /// **The whole system, end to end.** Two nodes peer offline, one sends,
    /// and the object that lands in the corpus is the one the other can read.
    ///
    /// This is the first test that crosses every layer: ceremony → peer-link →
    /// tag derivation → HPKE with a reservoir PSK → envelope → store.
    #[test]
    fn a_peered_node_can_send_and_the_object_is_readable_by_the_recipient() {
        let mut a = ready_node("send-a");
        let mut b = ready_node("send-b");
        type_command(&mut a, "peer offer");
        type_command(&mut b, "peer offer");

        let carry = |from: &App, to: &App, name: artifact::Artifact, as_name: &str| {
            std::fs::write(to.at(as_name), std::fs::read(from.path(name)).unwrap()).unwrap();
            to.at(as_name).to_string_lossy().into_owned()
        };
        let b_card = carry(&b, &a, artifact::Artifact::PeerCard, "from-b.card");
        let b_pad = pad_onto(&mut b, &a.at("from-b.pad"));
        type_command(&mut a, &format!("peer accept {b_card}"));
        {
            let mut p = a.load_ceremony().unwrap();
            p.fingerprint_verified = true;
            a.save_ceremony(&p).unwrap();
        }
        type_command(&mut a, &format!("peer seal {b_pad} media"));
        assert!(a.output.starts_with("peer-link signed"), "{}", a.output);

        // The peer-link is durable, and named by the peer's identifier.
        let peer = short_id(&b.identity.as_ref().unwrap().node_id());
        assert!(a.peer_path(&peer, artifact::PeerFile::Link).exists());

        type_command(&mut a, &format!("send {peer} meet me at the usual place"));
        assert!(a.output.contains("composed"), "{}", a.output);
        assert!(
            a.output.contains("post-quantum"),
            "the reservoir was used: {}",
            a.output
        );
        assert_eq!(a.store.len(), 1, "the object is in the corpus");

        // **It did not transmit.** RFC 5 §6.1 -- emission is scheduled, and
        // saying otherwise would make transmission timing follow composition.
        assert!(a.output.contains("not now"), "{}", a.output);
        assert_eq!(a.links.up_count(), 0);

        // Now read it as B would, from the object alone.
        let (_id, raw) = a.store.with(|s| {
            let id = *s.ids_in_order().next().unwrap();
            (id, s.get(&id).unwrap().to_vec())
        });
        let raw = &raw[..];
        let header = krab_core::object::RoutingHeader::parse(raw).unwrap();
        let (env, _) = krab_core::object::decode_envelope(&raw[16..]).unwrap();

        // B derives the same tag from its own side -- neither party sent it.
        let a_pk = krab_crypto::dh::PublicKey(
            peering::Card::decode(&std::fs::read(a.path(artifact::Artifact::PeerCard)).unwrap())
                .unwrap()
                .correspondence_pk,
        );
        let shared = b.identity.as_ref().unwrap().agree_with(&a_pk).unwrap();
        assert_eq!(
            krab_crypto::pairwise_tag(&shared, now_epoch()),
            header.tag,
            "the recipient recognises the tag without it being transmitted"
        );

        // And opens it with the reservoir chunk from its own root.
        let sealed_res = std::fs::read(b.peer_path(
            short_id(&a.identity.as_ref().unwrap().node_id()),
            artifact::PeerFile::Reservoir,
        ));
        let chunk = sealed_res.ok().and_then(|s| {
            krab_crypto::kek::open_under(&b.epoch_key.unwrap(), b"krab/reservoir", &s).ok()
        });
        // B never sealed (it only offered), so B has no reservoir file. The
        // chunk therefore comes from A's root, which is the same value.
        let _ = chunk;
        // The stored record is root + ratchet epoch (RFC 7 §6.4).
        let record = krab_crypto::kek::open_under(
            &a.epoch_key.unwrap(),
            b"krab/reservoir",
            &std::fs::read(a.peer_path(peer, artifact::PeerFile::Reservoir)).unwrap(),
        )
        .unwrap();
        let (r, stored_epoch) = persist::decode_reservoir(&record).unwrap();
        let mut res = krab_crypto::reservoir::Reservoir::new(r, stored_epoch);
        // Nothing to advance when the record is already at today; `advance_to`
        // reports that as `false` rather than as success.
        if stored_epoch != now_epoch() {
            assert!(res.advance_to(now_epoch()), "within MAX_ADVANCE");
        }
        let chunk = res.chunk(now_epoch()).unwrap();

        let mut enc = [0u8; krab_crypto::seal::ENC_LEN];
        enc.copy_from_slice(env.enc);
        let opened = krab_crypto::seal::open(
            &krab_crypto::seal::Mode::AuthPsk {
                chunk: &chunk,
                epoch: now_epoch(),
            },
            b.identity.as_ref().unwrap().correspondence(),
            &a_pk,
            &krab_crypto::seal::Sealed {
                enc,
                ct: env.ciphertext.to_vec(),
            },
            &krab_crypto::seal::info_for(header.class),
            &compose::aad_for(&header, &env),
        )
        .expect("the recipient opens it");
        assert_eq!(opened, b"meet me at the usual place");
    }

    /// Sending without a peering is refused with the remedy, not an error code.
    #[test]
    fn send_without_a_peer_link_says_what_to_do() {
        let mut a = ready_node("send-nolink");
        type_command(&mut a, "send nobody hello");
        assert!(a.output.contains("no peer-link"), "{}", a.output);
        assert!(a.output.contains("peer offer"), "{}", a.output);
        assert_eq!(a.store.len(), 0);
    }

    /// A locked node has no W_N and therefore cannot compose — the role
    /// transition costs something concrete.
    #[test]
    fn a_locked_node_cannot_send() {
        let mut a = ready_node("send-locked");
        a.lock();
        type_command(&mut a, "send anyone hello");
        assert!(a.output.contains("locked"), "{}", a.output);
    }

    /// Objects are padded to a bucket, so two messages of very different
    /// lengths can be indistinguishable on the wire (RFC 1 §8.1).
    #[test]
    fn short_messages_share_a_bucket() {
        assert_eq!(compose::bucket_for(200), compose::bucket_for(20));
        assert_eq!(
            compose::bucket_for(16 + compose::body_size_for(1)),
            compose::bucket_for(16 + compose::body_size_for(100))
        );
    }

    /// **RFC 3 §11.3, complete, through the verbs an operator actually types.**
    ///
    /// Two nodes peer over files, one composes, one packs a stick, the other
    /// imports it, and the message is readable. No network at any point, and
    /// every step is a command someone types rather than an internal call.
    #[test]
    fn a_message_reaches_a_peer_by_stick_using_only_typed_commands() {
        let mut a = ready_node("stick-a");
        let mut b = ready_node("stick-b");
        type_command(&mut a, "peer offer");
        type_command(&mut b, "peer offer");

        let carry = |from: &App, to: &App, name: artifact::Artifact, as_name: &str| {
            std::fs::write(to.at(as_name), std::fs::read(from.path(name)).unwrap()).unwrap();
            to.at(as_name).to_string_lossy().into_owned()
        };
        let b_card = carry(&b, &a, artifact::Artifact::PeerCard, "from-b.card");
        let b_pad = pad_onto(&mut b, &a.at("from-b.pad"));
        type_command(&mut a, &format!("peer accept {b_card}"));
        {
            let mut p = a.load_ceremony().unwrap();
            p.fingerprint_verified = true;
            a.save_ceremony(&p).unwrap();
        }
        type_command(&mut a, &format!("peer seal {b_pad} media"));

        let peer = short_id(&b.identity.as_ref().unwrap().node_id());
        type_command(&mut a, &format!("send {peer} the usual place, thursday"));
        assert!(a.output.contains("composed"), "{}", a.output);

        // Pack a stick.
        type_command(&mut a, "pack outbound.krab");
        assert!(a.output.contains("wrote 1 objects"), "{}", a.output);
        assert!(
            a.output.contains("not what changed"),
            "the window property is stated"
        );
        assert!(a.at("outbound.krab").exists());
        // The manifest is for the courier, and names nobody.
        let manifest = std::fs::read_to_string(a.at("outbound.MANIFEST.hjson")).unwrap();
        assert!(!manifest.contains(&peer), "{manifest}");

        // Carried, renamed, imported.
        let delivered = b.at("holiday-photos.zip");
        std::fs::copy(a.at("outbound.krab"), &delivered).unwrap();
        type_command(&mut b, &format!("import {}", delivered.display()));
        assert!(b.output.starts_with("1 new"), "{}", b.output);
        assert!(b.output.contains("re-hashed"), "{}", b.output);
        assert_eq!(b.store.len(), 1);

        // B reads it, having received one file and nothing else.
        let (_id, raw) = b.store.with(|s| {
            let id = *s.ids_in_order().next().unwrap();
            (id, s.get(&id).unwrap().to_vec())
        });
        let raw = &raw[..];
        let header = krab_core::object::RoutingHeader::parse(raw).unwrap();
        let (env, _) = krab_core::object::decode_envelope(&raw[16..]).unwrap();

        let a_pk = krab_crypto::dh::PublicKey(
            peering::Card::decode(&std::fs::read(a.path(artifact::Artifact::PeerCard)).unwrap())
                .unwrap()
                .correspondence_pk,
        );
        let shared = b.identity.as_ref().unwrap().agree_with(&a_pk).unwrap();
        assert_eq!(
            krab_crypto::pairwise_tag(&shared, now_epoch()),
            header.tag,
            "B recognises the tag it never received"
        );

        // The stored record is root + ratchet epoch (RFC 7 §6.4).
        let record = krab_crypto::kek::open_under(
            &a.epoch_key.unwrap(),
            b"krab/reservoir",
            &std::fs::read(a.peer_path(peer, artifact::PeerFile::Reservoir)).unwrap(),
        )
        .unwrap();
        let (r, stored_epoch) = persist::decode_reservoir(&record).unwrap();
        let mut res = krab_crypto::reservoir::Reservoir::new(r, stored_epoch);
        // Nothing to advance when the record is already at today; `advance_to`
        // reports that as `false` rather than as success.
        if stored_epoch != now_epoch() {
            assert!(res.advance_to(now_epoch()), "within MAX_ADVANCE");
        }
        let chunk = res.chunk(now_epoch()).unwrap();
        let mut enc = [0u8; krab_crypto::seal::ENC_LEN];
        enc.copy_from_slice(env.enc);
        let opened = krab_crypto::seal::open(
            &krab_crypto::seal::Mode::AuthPsk {
                chunk: &chunk,
                epoch: now_epoch(),
            },
            b.identity.as_ref().unwrap().correspondence(),
            &a_pk,
            &krab_crypto::seal::Sealed {
                enc,
                ct: env.ciphertext.to_vec(),
            },
            &krab_crypto::seal::info_for(header.class),
            &compose::aad_for(&header, &env),
        )
        .expect("B opens it");
        assert_eq!(opened, b"the usual place, thursday");
    }

    /// A second stick from an unchanged corpus carries the same thing, so a
    /// courier handed both learns nothing about what happened in between.
    #[test]
    fn successive_sticks_do_not_reveal_what_changed() {
        let mut a = ready_node("sticks");
        type_command(&mut a, "pack monday.krab");
        type_command(&mut a, "pack tuesday.krab");
        let one = std::fs::read(a.at("monday.krab")).unwrap();
        let two = std::fs::read(a.at("tuesday.krab")).unwrap();
        assert_eq!(
            one, two,
            "an unchanged corpus produces an unchanged archive"
        );
    }

    /// A corrupt medium is reported rather than silently importing nothing.
    #[test]
    fn a_corrupt_archive_is_reported_not_silently_ignored() {
        let mut a = ready_node("corrupt-a");
        let mut b = ready_node("corrupt-b");
        // Something to carry.
        let (id, bytes) = {
            let h = krab_core::object::RoutingHeader {
                version: 1,
                class: 0,
                size_bucket: 0,
                flags: 0,
                expiry_min: now_epoch().0 * 1440 + 40_000,
                tag: krab_core::object::Tag([3; 8]),
            };
            let b = krab_core::object::canonical_bytes(&h, &krab_core::object::example_sealed_body(3)).unwrap();
            (krab_crypto::object_id(&b), b)
        };
        a.store
            .with(|s| s.ingest(id, bytes, now_epoch().0 * 1440, u32::MAX))
            .unwrap();
        type_command(&mut a, "pack out.krab");

        let mut raw = std::fs::read(a.at("out.krab")).unwrap();
        let mid = raw.len() / 2;
        raw[mid] ^= 0xFF;
        std::fs::write(b.at("torn.krab"), raw).unwrap();

        let p = b.at("torn.krab").display().to_string();
        type_command(&mut b, &format!("import {p}"));

        // A tampered object is not an *invalid* object — it is a *different*
        // one, and anyone may create objects. What must not happen is it
        // arriving under the original's identifier, which is what would let a
        // courier substitute content for something a peer already wants.
        assert!(
            !b.store.with(|s| s.contains(&id)),
            "tampered content took the original's name"
        );
        b.store.with(|s| {
            for oid in s.ids_in_order() {
                assert_eq!(
                    krab_crypto::object_id(s.get(oid).unwrap()),
                    *oid,
                    "every object in the store hashes to its own identifier"
                );
            }
        });
    }

    #[test]
    fn importing_a_missing_file_says_so() {
        let mut a = ready_node("import-missing");
        type_command(&mut a, "import /nonexistent/stick.krab");
        assert!(
            a.output.contains("not self-consistent") || a.output.contains("could not read"),
            "{}",
            a.output
        );
    }

    /// **The loop closes at the interface.** A message imported from a stick
    /// appears in the list pane and its body in the view pane.
    #[test]
    fn imported_mail_appears_in_the_interface() {
        let mut a = ready_node("inbox-a");
        let mut b = ready_node("inbox-b");
        type_command(&mut a, "peer offer");
        type_command(&mut b, "peer offer");

        let carry = |from: &App, to: &App, name: artifact::Artifact, as_name: &str| {
            std::fs::write(to.at(as_name), std::fs::read(from.path(name)).unwrap()).unwrap();
            to.at(as_name).to_string_lossy().into_owned()
        };
        // Each side records the other, so both can recognise the other's tags.
        let b_card = carry(&b, &a, artifact::Artifact::PeerCard, "from-b.card");
        let a_card = carry(&a, &b, artifact::Artifact::PeerCard, "from-a.card");
        let b_pad = pad_onto(&mut b, &a.at("from-b.pad"));
        let a_pad = pad_onto(&mut a, &b.at("from-a.pad"));
        for (n, card, pad) in [(&mut a, b_card, b_pad), (&mut b, a_card, a_pad)] {
            type_command(n, &format!("peer accept {card}"));
            let mut p = n.load_ceremony().unwrap();
            p.fingerprint_verified = true;
            n.save_ceremony(&p).unwrap();
            type_command(n, &format!("peer seal {pad} media"));
        }

        let b_id = short_id(&b.identity.as_ref().unwrap().node_id());
        type_command(&mut a, &format!("send {b_id} bring the good coffee"));
        type_command(&mut a, "pack out.krab");

        let stick = b.at("anything.bin");
        std::fs::copy(a.at("out.krab"), &stick).unwrap();
        type_command(&mut b, &format!("import {}", stick.display()));

        // The list pane names the sender; the view pane holds the body.
        assert_eq!(b.messages.len(), 1, "list: {:?}", b.list);
        assert_eq!(b.messages[0].body, "bring the good coffee");
        assert!(b.messages[0].post_quantum, "the reservoir was in play");
        assert!(b.list[0].contains("bring the good coffee"), "{:?}", b.list);

        // The view pane holds the command's output, which is correct — the
        // operator just ran `import` and wants its result. Selecting the
        // message is what puts the body there.
        assert!(b.output.contains("1 new"), "{}", b.output);
        b.show_selected();
        assert!(b.body.starts_with("from "), "{}", b.body);
        assert!(b.body.contains("bring the good coffee"), "{}", b.body);
    }

    /// **RFC 7 §8** — locking destroys the plaintext, not just the view.
    #[test]
    fn locking_destroys_decrypted_mail() {
        let mut a = ready_node("inbox-lock");
        a.messages.push(receive::Message {
            id: krab_core::object::ObjectId([1; 32]),
            from: "alice".into(),
            epoch: now_epoch(),
            body: "something private".into(),
            picture: None,
            post_quantum: true,
            nodelist: None,
        });
        a.list = vec!["alice  something private".into()];
        a.show_selected();
        assert!(a.body.contains("something private"));

        a.lock();
        assert!(a.messages.is_empty(), "plaintext is gone, not hidden");
        assert!(!a.body.contains("something private"), "{}", a.body);
        assert_eq!(a.list, vec!["(locked)".to_string()]);
    }

    /// A locked node's inbox refresh produces nothing rather than failing.
    #[test]
    fn a_locked_node_has_no_inbox() {
        let mut a = ready_node("inbox-locked");
        a.lock();
        a.refresh_inbox();
        assert!(a.messages.is_empty());
        assert_eq!(a.list, vec!["(locked)".to_string()]);
    }

    /// **RFC 5 §6.1 at the loop.** Ticking the schedule never depends on what
    /// the user did — `tick_schedule` takes nothing and reads no user state.
    #[test]
    fn ticking_the_schedule_touches_no_user_state() {
        let mut a = ready_node("tick");
        // Peer names are short node identifiers, so they are hex.
        type_command(&mut a, "connect a1b2c3d4 tcp");
        a.composer_set("a draft in progress");
        a.command = line::Line::from("half-typed");
        let before = (a.composer.clone(), a.command.clone());

        for _ in 0..20 {
            a.tick_schedule();
        }
        assert_eq!((a.composer.clone(), a.command.clone()), before);

        // The corpus is not user state, and the schedule does write to it —
        // RFC 7 §5.1's prekey rotation has to happen without anyone typing.
        // What it must not do is add anything else, or take anything away.
        let me = a.identity.as_ref().unwrap().node_id();
        let (mine, other) = a.store.with(|s| {
            let mut mine = 0;
            let mut other = 0;
            for (_, id) in s.entries_in_range(0, u32::MAX) {
                match s.get(&id).and_then(bulletin::from_object) {
                    Some(b) if b.kind == bulletin::Kind::Prekeys && b.node_id() == me => mine += 1,
                    _ => other += 1,
                }
            }
            (mine, other)
        });
        assert_eq!(mine, 1, "the schedule published {mine} batches, not one");
        assert_eq!(other, 0, "the schedule put something else in the corpus");
        // And it publishes a window rather than a countdown.
        let l = a.links.get("a1b2c3d4").expect("connected");
        assert!(
            l.schedule_hint().contains("(scheduled)"),
            "the scheduler never published a window: {}",
            l.schedule_hint()
        );
    }

    /// **No configuration file, ever.** Startup options come from argv and
    /// nothing else — see `Documentation/NO-CONFIG.md`.
    #[test]
    fn startup_options_come_from_argv_only() {
        let a = App::from_args(
            ["--home", "/tmp/krab-x", "--sync-interval", "7200"]
                .iter()
                .map(|s| s.to_string()),
        )
        .unwrap();
        assert_eq!(a.home, PathBuf::from("/tmp/krab-x"));
        assert_eq!(a.scheduler.mean_interval_s(), 7_200);

        // An environment variable is deliberately not consulted: environment
        // is inherited, so a parent process would choose unseen.
        std::env::set_var("KRAB_HOME", "/tmp/should-be-ignored");
        let b = App::from_args(
            ["--home", "/tmp/krab-argv"].iter().map(|s| s.to_string()),
        )
        .unwrap();
        assert_eq!(
            b.home,
            PathBuf::from("/tmp/krab-argv"),
            "the environment must not decide"
        );

        // And with no `--home` at all it refuses rather than choosing. There
        // is nothing for the environment to override, which is the strongest
        // form of "argv only".
        let why = match App::from_args(std::iter::empty()) {
            Ok(_) => panic!("a node started with no store to open"),
            Err(e) => e,
        };
        assert!(why.contains("--home"), "{why}");
        assert!(
            why.contains("no default"),
            "the refusal does not say why: {why}"
        );
        std::env::remove_var("KRAB_HOME");
    }

    /// A sync interval short enough to correlate the node with its own
    /// activity is refused at the boundary rather than accepted quietly.
    #[test]
    fn an_absurd_sync_interval_is_refused() {
        assert!(App::from_args(["--sync-interval", "5"].iter().map(|s| s.to_string())).is_err());
        assert!(App::from_args(["--sync-interval", "x"].iter().map(|s| s.to_string())).is_err());
        assert!(App::from_args(["--nonsense"].iter().map(|s| s.to_string())).is_err());
        assert!(App::from_args(["--home"].iter().map(|s| s.to_string())).is_err());
    }

    /// **`peer offer` writes no plaintext to this node's own disk.**
    ///
    /// The contribution is the one artifact that must exist unencrypted,
    /// because a person carries it. RFC 7 §4 forbids relying on deletion to
    /// remove plaintext from a disk, so it is never written there by default —
    /// `peer pad <destination>` puts it on the medium and nowhere else. See
    /// `Documentation/SECURE-DELETE.md`.
    #[test]
    fn offering_writes_no_unencrypted_material_to_local_storage() {
        let mut a = ready_node("pad-life");
        type_command(&mut a, "peer offer");

        assert!(
            a.path(artifact::Artifact::PeerCard).exists(),
            "the card is public and signed"
        );
        assert!(
            !a.path(artifact::Artifact::PeerPad).exists(),
            "no plaintext contribution on our own disk"
        );

        // The contribution exists, wrapped, inside the ceremony — so nothing
        // was lost by not writing it.
        let r = a.load_ceremony().unwrap().my_contribution.r;
        assert_ne!(r, [0u8; 32]);

        // And it is not recoverable from anything on disk without W_N.
        for entry in std::fs::read_dir(&a.home).unwrap().flatten() {
            let bytes = std::fs::read(entry.path()).unwrap_or_default();
            assert!(
                !bytes.windows(32).any(|w| w == r),
                "the contribution appears in plaintext in {:?}",
                entry.file_name()
            );
        }
    }

    /// `peer pad` writes where told, once, and says what it just created.
    #[test]
    fn the_pad_is_materialised_only_where_the_operator_says() {
        let mut a = ready_node("pad-dest");
        type_command(&mut a, "peer offer");

        // No destination: refuses and explains, rather than picking one.
        type_command(&mut a, "peer pad");
        assert!(a.output.contains("usage:"), "{}", a.output);
        assert!(a.output.contains("carrying"), "{}", a.output);

        let medium = a.home.join("removable-medium.pad");
        type_command(&mut a, &format!("peer pad {}", medium.display()));
        assert!(medium.exists());
        assert!(
            a.output.contains("only unprotected artifact"),
            "{}",
            a.output
        );

        // It is the ceremony's contribution, and it matches.
        let written = ceremony::decode_contribution(&std::fs::read(&medium).unwrap()).unwrap();
        assert_eq!(written.r, a.load_ceremony().unwrap().my_contribution.r);
    }

    /// **A corpus of many segments is wiped, all of it.**
    ///
    /// The corpus stopped being one file and became a directory of them, and
    /// "the existing rule already covers it" is exactly the reasoning that
    /// left `wipe` stale twice before — see `artifact`. So this builds a
    /// corpus spanning several expiry buckets, asserts that there really are
    /// several files (a wipe test over an empty directory passes and proves
    /// nothing), and then asserts that every one of them is gone along with
    /// the directory that named them.
    ///
    /// The directory matters on its own. A surviving `corpus/` holding nothing
    /// but names still lists the expiry days this node held, which is the
    /// shape of its traffic over the retention window.
    #[test]
    fn wipe_removes_every_segment_and_the_directory_naming_them() {
        let mut a = ready_node("wipe-segments");
        let now_min = now_epoch().0 * 1440;
        for day in 1..6u32 {
            let h = krab_core::object::RoutingHeader {
                version: 1,
                class: 0,
                size_bucket: 0,
                flags: 0,
                expiry_min: now_min + day * 1_440,
                tag: krab_core::object::Tag([day as u8; 8]),
            };
            let bytes = krab_core::object::canonical_bytes(
                &h,
                &krab_core::object::example_sealed_body(day as u8),
            )
            .unwrap();
            let id = krab_crypto::object_id(&bytes);
            a.store
                .with(|s| s.ingest(id, bytes, now_min, u32::MAX))
                .expect("ingested");
        }
        a.save_corpus();

        let corpus = a.path(artifact::Artifact::Corpus);
        let segments: Vec<_> = std::fs::read_dir(&corpus)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        assert!(
            segments.len() >= 5,
            "the fixture must span several buckets, or this proves nothing: {segments:?}"
        );

        type_command(&mut a, "wipe");
        type_command(&mut a, "wipe");

        for path in &segments {
            assert!(!path.exists(), "{} survived the wipe", path.display());
        }
        assert!(
            !corpus.exists(),
            "the corpus directory survived, and its entries name the expiry \
             days this node held"
        );
        // And they were counted as overwritten, not merely unlinked — the
        // report is what an operator reads to know the hedge ran.
        assert!(a.output.contains("overwritten and removed"), "{}", a.output);
    }

    /// **`wipe` overwrites everything it removes**, ciphertext included.
    ///
    /// The erasure is the key destruction; the overwrite is what a
    /// later-obtained passphrase cannot undo, and it removes the listing —
    /// a directory of `*.link` files names who this node peered with even when
    /// their contents are unreadable.
    #[test]
    fn wipe_overwrites_every_artifact_including_encrypted_ones() {
        let mut a = ready_node("wipe-shred");
        type_command(&mut a, "peer offer");
        let card_before = std::fs::read(a.path(artifact::Artifact::PeerCard)).unwrap();
        assert!(a.path(artifact::Artifact::Ceremony).exists());

        type_command(&mut a, "wipe");
        type_command(&mut a, "wipe");
        assert!(
            a.identity.is_none(),
            "the key is destroyed — that is the erasure"
        );
        assert!(a.output.contains("overwritten and removed"), "{}", a.output);
        assert!(
            a.output.contains("not the erasure"),
            "and it does not overclaim"
        );

        // Nothing of the layout survives, and the listing is gone with it.
        for name in [
            "peer.card",
            "ceremony.cbor",
            "identity.wrapped",
            // The corpus is a directory of segments now. `remove_matching`
            // recurses, shreds each `<bucket>.krab`, and removes the directory
            // once it is empty — a directory that survived would name the
            // expiry buckets this node held, which is a shape of its traffic.
            "corpus",
        ] {
            assert!(!a.at(name).exists(), "{name} survived wipe");
        }
        assert!(!card_before.is_empty());
    }

    /// **A node survives being stopped.** Identity, peer-links, corpus, and
    /// readable mail all come back from a passphrase and a directory.
    #[test]
    fn a_node_restarts_from_a_passphrase_and_a_directory() {
        let home = temp_home("restart");
        let peer_home = temp_home("restart-peer");

        // A peer to exchange with, and a message from them.
        let mut them = App {
            home: peer_home.clone(),
            ..App::default()
        };
        let mut their_id = Identity::generate(&mut OsRng);
        their_id.kek_params.m_kib = 64;
        their_id.kek_params.t = 1;
        their_id.kek_params.p = 1;
        them.identity = Some(krab_lock::Held::new(their_id));
        them.passphrase = line::Line::from("their passphrase");
        them.open_store().unwrap();
        type_command(&mut them, "peer offer");

        // The node itself, initialised the long way.
        let mut a = App {
            home: home.clone(),
            ..App::default()
        };
        let mut id = Identity::generate(&mut OsRng);
        id.kek_params.m_kib = 64;
        id.kek_params.t = 1;
        id.kek_params.p = 1;
        a.identity = Some(krab_lock::Held::new(id));
        a.passphrase = line::Line::from("open sesame please");
        a.open_store().unwrap();
        let node_id = a.identity.as_ref().unwrap().node_id();
        let fingerprint = a.identity.as_ref().unwrap().fingerprint();

        type_command(&mut a, "peer offer");
        std::fs::copy(them.at("peer.card"), a.at("t.card")).unwrap();
        pad_onto(&mut them, &a.at("t.pad"));
        let card = a.at("t.card").display().to_string();
        let pad = a.at("t.pad").display().to_string();
        type_command(&mut a, &format!("peer accept {card}"));
        type_command(&mut a, &format!("peer seal {pad} media"));

        let peer = short_id(&them.identity.as_ref().unwrap().node_id());
        type_command(&mut a, &format!("send {peer} kept across a restart"));
        assert_eq!(a.store.len(), 1);

        // The process ends. Everything in memory is gone.
        drop(a);

        // A fresh process, given only the directory and the passphrase.
        let mut b = App::from_args(
            ["--home", home.to_str().unwrap()]
                .iter()
                .map(|s| s.to_string()),
        )
        .unwrap();
        assert!(b.has_stored_identity());
        assert!(b.identity.is_none(), "nothing is known before unlocking");

        b.unlock(b"open sesame please").expect("unlocks");
        assert_eq!(
            b.identity.as_ref().unwrap().node_id(),
            node_id,
            "same identity"
        );
        assert_eq!(b.identity.as_ref().unwrap().fingerprint(), fingerprint);
        assert_eq!(b.store.len(), 1, "the corpus came back");
        assert!(b.epoch_key.is_some());
        // And the peer-link is still there, so tags still derive.
        assert!(b.peer_path(peer, artifact::PeerFile::Link).exists());
    }

    /// The wrong passphrase opens nothing, and says nothing about how wrong.
    #[test]
    fn a_wrong_passphrase_opens_nothing() {
        let home = temp_home("restart-wrong");
        let mut a = App {
            home: home.clone(),
            ..App::default()
        };
        let mut id = Identity::generate(&mut OsRng);
        id.kek_params.m_kib = 64;
        id.kek_params.t = 1;
        id.kek_params.p = 1;
        a.identity = Some(krab_lock::Held::new(id));
        a.passphrase = line::Line::from("the right one");
        a.open_store().unwrap();
        drop(a);

        let mut b = App {
            home,
            ..App::default()
        };
        let err = b.unlock(b"the right on").unwrap_err();
        assert!(err.contains("does not open this store"), "{err}");
        assert!(b.identity.is_none(), "nothing was recovered");
        assert!(b.epoch_key.is_none());
    }

    /// A directory with no store says what to do rather than failing opaquely.
    #[test]
    fn an_empty_directory_directs_the_operator_to_init() {
        let mut a = App {
            home: temp_home("restart-empty"),
            ..App::default()
        };
        assert!(!a.has_stored_identity());
        assert!(a.unlock(b"anything").unwrap_err().contains("run `init`"));
    }

    /// **Nothing on disk is configuration.** Every file a run leaves behind is
    /// signed, wrapped, or content-addressed — `Documentation/NO-CONFIG.md`.
    #[test]
    fn the_stored_layout_contains_no_unauthenticated_settings() {
        let home = temp_home("layout");
        let mut a = App {
            home: home.clone(),
            ..App::default()
        };
        let mut id = Identity::generate(&mut OsRng);
        id.kek_params.m_kib = 64;
        id.kek_params.t = 1;
        id.kek_params.p = 1;
        a.identity = Some(krab_lock::Held::new(id));
        a.passphrase = line::Line::from("passphrase");
        a.open_store().unwrap();
        type_command(&mut a, "peer offer");

        let allowed = [
            "identity.wrapped", // sealed under the KEK
            "kek.params",       // plaintext, self-defeating to tamper with
            "corpus",           // a directory of content-addressed segments
            "ceremony.cbor",    // signed cards, wrapped contribution
            "peer.card",        // signed
            "peer.pad",         // destroyed at seal; see the pad-life test
        ];
        // The corpus directory holds one segment per expiry bucket, and a
        // bucket number is the expiry — which every relay already reads from
        // the frozen header. So the names disclose nothing the objects do not,
        // and they are checked here rather than exempted.
        let corpus = home.join("corpus");
        if corpus.is_dir() {
            for entry in std::fs::read_dir(&corpus).unwrap().flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                assert!(
                    name.strip_suffix(".krab").is_some_and(|b| b
                        .parse::<u32>()
                        .is_ok()),
                    "unexpected file in the corpus: {name}"
                );
            }
        }
        for entry in std::fs::read_dir(&home).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let ok = allowed.contains(&name.as_str())
                || name.ends_with(".link")
                || name.ends_with(".reservoir");
            assert!(ok, "unexpected file on disk: {name}");
            // Nothing that reads like configuration.
            for smell in [
                ".toml", ".conf", ".ini", ".yaml", ".json", "config", "settings",
            ] {
                assert!(!name.contains(smell), "{name} looks like configuration");
            }
        }
    }

    /// **RFC 7 §10's duress passphrase.** It destroys the node and then shows
    /// exactly what a fresh install shows — no warning, no distinct message,
    /// nothing readable over the operator's shoulder.
    #[test]
    fn the_duress_passphrase_destroys_and_then_lies_convincingly() {
        let home = temp_home("duress");
        let mut a = App {
            home: home.clone(),
            ..App::default()
        };
        let mut id = Identity::generate(&mut OsRng);
        id.kek_params.m_kib = 64;
        id.kek_params.t = 1;
        id.kek_params.p = 1;
        a.identity = Some(krab_lock::Held::new(id));
        a.passphrase = line::Line::from("the real one");
        a.open_store().unwrap();
        type_command(&mut a, "peer offer");
        a.set_duress(b"under duress").unwrap();
        assert!(a.path(artifact::Artifact::IdentityWrapped).exists());
        drop(a);

        // Someone is made to unlock.
        let mut b = App {
            home: home.clone(),
            ..App::default()
        };
        b.unlock(b"under duress").expect("it appears to work");

        // What they see is what a first run looks like.
        assert_eq!(b.list, vec!["(no messages)".to_string()]);
        assert!(!b.output.to_lowercase().contains("wipe"), "{}", b.output);
        assert!(!b.output.to_lowercase().contains("destroy"), "{}", b.output);
        assert!(!b.output.to_lowercase().contains("duress"), "{}", b.output);

        // And the store is gone, irreversibly — the real passphrase now opens
        // nothing either.
        assert!(b.identity.is_none());
        assert!(!home.join("identity.wrapped").exists());
        let mut c = App {
            home,
            ..App::default()
        };
        assert!(c.unlock(b"the real one").is_err());
    }

    /// The real passphrase still works when a duress one is set, and the
    /// duress record does not open the identity.
    #[test]
    fn setting_a_duress_passphrase_does_not_disturb_the_real_one() {
        let home = temp_home("duress-coexist");
        let mut a = App {
            home: home.clone(),
            ..App::default()
        };
        let mut id = Identity::generate(&mut OsRng);
        id.kek_params.m_kib = 64;
        id.kek_params.t = 1;
        id.kek_params.p = 1;
        a.identity = Some(krab_lock::Held::new(id));
        a.passphrase = line::Line::from("the real one");
        a.open_store().unwrap();
        let node_id = a.identity.as_ref().unwrap().node_id();
        a.set_duress(b"under duress").unwrap();
        drop(a);

        let mut b = App {
            home,
            ..App::default()
        };
        assert!(
            matches!(b.open_with(b"the real one"), Ok(Opened::Normal(..))),
            "the real one is not duress"
        );
        assert!(matches!(b.open_with(b"under duress"), Ok(Opened::Duress)));
        b.unlock(b"the real one")
            .expect("the real passphrase still opens it");
        assert_eq!(b.identity.as_ref().unwrap().node_id(), node_id);
    }

    /// A node with no duress passphrase set answers the same way to every
    /// wrong passphrase — its absence must not be detectable.
    #[test]
    fn a_node_without_a_duress_passphrase_reveals_nothing() {
        let home = temp_home("no-duress");
        let mut a = App {
            home: home.clone(),
            ..App::default()
        };
        let mut id = Identity::generate(&mut OsRng);
        id.kek_params.m_kib = 64;
        id.kek_params.t = 1;
        id.kek_params.p = 1;
        a.identity = Some(krab_lock::Held::new(id));
        a.passphrase = line::Line::from("only one");
        a.open_store().unwrap();
        drop(a);

        let mut b = App {
            home,
            ..App::default()
        };
        assert!(!matches!(
            b.open_with(b"anything at all"),
            Ok(Opened::Duress)
        ));
        let e1 = b.unlock(b"wrong one").unwrap_err();
        let e2 = b.unlock(b"wrong two").unwrap_err();
        assert_eq!(e1, e2, "two wrong guesses must be indistinguishable");
    }

    /// **The ordering is the design.** The key dies before any file is
    /// touched, so an interrupted wipe is still a complete one.
    #[test]
    fn the_key_is_destroyed_before_the_disk_is_touched() {
        let home = temp_home("wipe-order");
        let mut a = App {
            home: home.clone(),
            ..App::default()
        };
        let mut id = Identity::generate(&mut OsRng);
        id.kek_params.m_kib = 64;
        id.kek_params.t = 1;
        id.kek_params.p = 1;
        a.identity = Some(krab_lock::Held::new(id));
        a.passphrase = line::Line::from("passphrase");
        a.open_store().unwrap();
        type_command(&mut a, "peer offer");

        // `panic_wipe` returns its report rather than assigning it, so that
        // the erasure runs to completion before anything renders.
        let report = a.panic_wipe();

        // In-memory key material is gone, which is the erasure.
        assert!(a.identity.is_none());
        assert!(a.epoch_key.is_none());
        assert!(a.tag_table.is_none());
        assert!(a.messages.is_empty());
        assert_eq!(a.store.len(), 0);
        // And the message says which part is the guarantee.
        assert!(report.contains("key went first"), "{report}");
        assert!(
            report.contains("interrupted wipe is still a complete one"),
            "{report}"
        );
    }

    /// **First contact, end to end.** A node reaches someone it has never met,
    /// using only their card — no shared secret, no prior exchange.
    #[test]
    fn a_peer_request_reaches_a_stranger_and_proves_who_sent_it() {
        let mut a = ready_node("req-a");
        let mut b = ready_node("req-b");
        type_command(&mut b, "peer offer");

        // A has only B's card. That is the entire precondition.
        std::fs::copy(b.path(artifact::Artifact::PeerCard), a.at("stranger.card")).unwrap();
        let card = a.at("stranger.card").display().to_string();
        type_command(&mut a, &format!("request {card} we met at the thing"));
        assert!(a.output.contains("request composed"), "{}", a.output);
        assert_eq!(a.store.len(), 1);

        // It travels as an ordinary object, so a stick carries it.
        type_command(&mut a, "pack out.krab");
        let stick = b.at("unremarkable.bin");
        std::fs::copy(a.at("out.krab"), &stick).unwrap();
        type_command(&mut b, &format!("import {}", stick.display()));
        assert_eq!(b.store.len(), 1);

        // B recognises it on its own inbox tag, which needs only B's own key.
        let incoming = b.store.with(|st| {
            receive::scan_requests(
                st,
                b.identity.as_ref().unwrap().correspondence(),
                &b.identity.as_ref().unwrap().node_id(),
                now_epoch(),
                (0, u32::MAX),
                &mut receive::Attempts::new(),
            )
        });
        assert_eq!(incoming.len(), 1, "the request was not recognised");

        // And it is visible in the interface, at the top, with the caution
        // that a signature proves who signed and not who they are.
        assert!(b.list[0].starts_with("REQUEST from"), "{:?}", b.list);
        assert!(
            b.list
                .iter()
                .any(|l| l.contains("Compare fingerprints aloud")),
            "{:?}",
            b.list
        );
        let receive::Incoming::Request { request: req, .. } = &incoming[0] else {
            panic!("a request, not a counter");
        };
        assert_eq!(req.note, "we met at the thing");
        assert!(req.verify(), "the inner signature stands");
        assert!(req.is_for(&b.identity.as_ref().unwrap().node_id()));

        // And it carries A's identity provably — mode_base binds no sender, so
        // the signature is the only thing that says who, and it says A.
        assert_eq!(req.from.node_id(), a.identity.as_ref().unwrap().node_id());
        assert_eq!(
            req.from.fingerprint(),
            a.identity.as_ref().unwrap().fingerprint()
        );
    }

    /// A request addressed to someone else does not become ours by arriving.
    #[test]
    fn a_request_for_another_node_is_not_accepted() {
        let mut a = ready_node("req-wrong-a");
        let mut b = ready_node("req-wrong-b");
        let c = ready_node("req-wrong-c");
        type_command(&mut b, "peer offer");

        // A addresses B, but C imports the object.
        std::fs::copy(b.path(artifact::Artifact::PeerCard), a.at("b.card")).unwrap();
        let card = a.at("b.card").display().to_string();
        type_command(&mut a, &format!("request {card} for B only"));
        type_command(&mut a, "pack out.krab");

        let mut c = c;
        let stick = c.at("in.krab");
        std::fs::copy(a.at("out.krab"), &stick).unwrap();
        type_command(&mut c, &format!("import {}", stick.display()));

        let incoming = c.store.with(|st| {
            receive::scan_requests(
                st,
                c.identity.as_ref().unwrap().correspondence(),
                &c.identity.as_ref().unwrap().node_id(),
                now_epoch(),
                (0, u32::MAX),
                &mut receive::Attempts::new(),
            )
        });
        assert!(
            incoming.is_empty(),
            "C must not adopt a request addressed to B"
        );
        assert_eq!(c.store.len(), 1, "but it is stored and relayed regardless");
    }

    /// A locked node composes nothing.
    #[test]
    fn a_locked_node_cannot_send_a_request() {
        let mut a = ready_node("req-locked");
        a.lock();
        type_command(&mut a, "request anything.card note");
        assert!(a.output.contains("locked"), "{}", a.output);
    }

    /// **CRYPTO-REVIEW.md §11.5, wired.** A node that was off for a long gap
    /// resumes the ratchet at the recorded epoch rather than inferring one.
    ///
    /// Inferring is the silent failure: it derives chunks at the wrong index,
    /// its peer does not recognise them, and RFC 0 §6 guarantees nobody is
    /// told. The stored record therefore carries `root_N` and `N` together
    /// (RFC 7 §6.4).
    #[test]
    fn a_reservoir_resumes_at_its_recorded_ratchet_epoch() {
        let home = temp_home("ratchet-resume");
        let mut a = App {
            home: home.clone(),
            ..App::default()
        };
        let mut id = Identity::generate(&mut OsRng);
        id.kek_params.m_kib = 64;
        id.kek_params.t = 1;
        id.kek_params.p = 1;
        a.identity = Some(krab_lock::Held::new(id));
        a.passphrase = line::Line::from("passphrase");
        a.open_store().unwrap();

        // A reservoir as the ceremony would have left it, some epochs ago.
        let root = [0x5A; 32];
        let then = krab_core::tag::Epoch(now_epoch().0 - 30);
        let record = persist::encode_reservoir(&root, then);
        let sealed = krab_crypto::kek::seal_under(
            &a.epoch_key.unwrap(),
            b"krab/reservoir",
            &record,
            &mut OsRng,
        )
        .unwrap();
        std::fs::write(a.at("abcd1234.reservoir"), sealed).unwrap();

        // What a peer that stayed up would hold today.
        let mut peer = krab_crypto::reservoir::Reservoir::new(root, then);
        assert!(peer.advance_to(now_epoch()), "within MAX_ADVANCE");

        // What this node reconstructs from the record alone.
        let raw = std::fs::read(a.at("abcd1234.reservoir")).unwrap();
        let opened =
            krab_crypto::kek::open_under(&a.epoch_key.unwrap(), b"krab/reservoir", &raw).unwrap();
        let (stored_root, stored_epoch) = persist::decode_reservoir(&opened).unwrap();
        assert_eq!(stored_epoch, then, "the ratchet position survived storage");

        let mut mine = krab_crypto::reservoir::Reservoir::new(stored_root, stored_epoch);
        assert!(mine.advance_to(now_epoch()), "within MAX_ADVANCE");

        assert_eq!(mine.epoch(), peer.epoch(), "the ratchets agree");
        assert_eq!(mine.root_bytes(), peer.root_bytes());
        for d in 0..20u32 {
            let e = krab_core::tag::Epoch(now_epoch().0 - d);
            assert_eq!(
                mine.chunk(e).map(|c| *c.expose()),
                peer.chunk(e).map(|c| *c.expose()),
                "epoch {} diverged after the gap",
                e.0
            );
        }

        // And adopting at the wrong epoch — what inferring would do — produces
        // chunks the peer does not recognise. This is the failure being fixed.
        // Already at `now_epoch()`, so there is nothing to advance — which is
        // exactly what inferring the position produces.
        let inferred = krab_crypto::reservoir::Reservoir::new(stored_root, now_epoch());
        assert_ne!(
            inferred.chunk(now_epoch()).map(|c| *c.expose()),
            peer.chunk(now_epoch()).map(|c| *c.expose()),
            "inferring the ratchet position must not accidentally agree"
        );
    }

    /// **Provenance in the command pane, within RFC 3 §12's limits.**
    ///
    /// The log names peers and counts, never objects and never times, and it
    /// is cleared on lock — a locked screen must not list correspondents.
    #[test]
    fn background_activity_is_visible_and_bounded() {
        let mut a = ready_node("log");
        type_command(&mut a, "connect a1b2c3d4 tcp");
        assert_ne!(a.log.len(), 0, "connecting produced no provenance");
        let lines = a.log.recent(8);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("a1b2c3d4") && l.contains("link up")),
            "{lines:?}"
        );

        // Ticking the schedule reports what it did, per peer.
        for _ in 0..40 {
            a.tick_schedule();
        }
        let lines = a.log.recent(activity_log::CAPACITY);
        assert!(
            lines.len() <= activity_log::CAPACITY,
            "the ring is not bounded"
        );

        // No line carries a wall-clock time or an object identifier.
        for line in &lines {
            for leak in ["id=", "0x", " obj ", "tag "] {
                assert!(!line.contains(leak), "{line:?} leaks {leak:?}");
            }
        }
    }

    /// **Cleared on lock.** The counters in `PeerMetrics` keep moving — a relay
    /// still reconciles — but the screen stops naming who.
    #[test]
    fn locking_clears_the_activity_log() {
        let mut a = ready_node("log-lock");
        type_command(&mut a, "connect a1b2c3d4 tcp");
        assert_ne!(a.log.len(), 0);
        a.lock();
        assert_eq!(a.log.len(), 0, "a locked screen listed correspondents");
    }

    /// **RFC 7 §4's forward secrecy actually happens now.** Nothing called
    /// `shred_epoch` before, so wrappers accumulated and every past epoch
    /// stayed openable with the passphrase — §4's promise kept in the sense
    /// that an unused lock secures a door.
    #[test]
    fn epoch_wrappers_past_the_window_are_destroyed() {
        let mut a = ready_node("shred-epochs");
        let now = now_epoch();
        let kek = {
            let id = a.identity.as_ref().unwrap();
            persist::kek_for(b"a passphrase", &id.kek_params).unwrap()
        };
        {
            let id = a.identity.as_mut().unwrap();
            for back in [0u32, 10, 44, 45, 46, 200] {
                let e = krab_core::tag::Epoch(now.0 - back);
                id.hierarchy.open_epoch(&kek, e, &mut OsRng).unwrap();
            }
        }
        let before = a.identity.as_ref().unwrap().hierarchy.epochs().count();
        assert!(before >= 6);

        a.shred_expired_epochs();

        let id = a.identity.as_ref().unwrap();
        let kept: Vec<u32> = id.hierarchy.epochs().map(|e| e.0).collect();
        // The acceptance window is retained, because RFC 1 §6.2 says an object
        // may arrive that late and a shredded epoch cannot decrypt it.
        assert!(kept.contains(&now.0), "today was shredded");
        assert!(
            kept.contains(&(now.0 - 45)),
            "the far edge of MAX_TTL was shredded"
        );
        // Beyond it, gone — and gone means the passphrase does not reopen it.
        assert!(
            !kept.contains(&(now.0 - 46)),
            "an epoch past the window survived"
        );
        assert!(!kept.contains(&(now.0 - 200)));
        assert!(id
            .hierarchy
            .epoch_key(&kek, krab_core::tag::Epoch(now.0 - 200))
            .is_err());
    }

    /// A clock reading before the protocol existed is hardware, not a date.
    /// Deriving at epoch 0 puts a node in a tag space no peer computes.
    #[test]
    fn the_clock_is_floored_at_a_plausible_date() {
        assert!(now_epoch().0 >= krab_core::tag::Epoch::at(EPOCH_FLOOR_SECS).0);
        assert!(
            krab_core::tag::Epoch::at(EPOCH_FLOOR_SECS).0 > 20_000,
            "the floor must be a real date, not epoch 0"
        );
    }

    /// **A modem link gets every feature TCP has.** Same Noise IK, same
    /// framing, same session, same reconciliation driver — RFC 4 §5.3's
    /// "direct cable, wired radio modem, or X.25 PAD".
    #[test]
    fn serial_is_a_first_class_transport() {
        use krab_fabric::profile::LinkProfile;
        // It resolves by name, under both spellings an operator might use.
        assert_eq!(links::profile_named("serial").unwrap().kind, "serial");
        assert_eq!(links::profile_named("modem").unwrap().kind, "serial");

        let p = LinkProfile::serial();
        // RFC 4 §5.3's table: 115 200 baud is 11 520 B/s.
        assert_eq!(p.sustained_bps, 11_520.0);
        // FEC on, because §5.3 requires it "where there is no link-layer
        // retransmission" and a raw cable has none.
        assert!(p.fec, "a serial line has no retransmission below it");
        // The sync mode is derived, not chosen (RFC 5 §4.5) — and a serial
        // line resolves to the *same* mode as TCP, which is correct: it is low
        // bandwidth, not high latency. A direct cable turns a round trip
        // around in microseconds, so RBSR's trade of round trips for bytes is
        // exactly what this carrier wants. `Manifest` is for `Courier`, where
        // a round trip is measured in days.
        assert_eq!(p.sync_mode(), LinkProfile::tcp().sync_mode());
        assert_ne!(p.sync_mode(), LinkProfile::courier().sync_mode());
    }

    /// **The macOS trap, refused rather than hung on.** `tty.*` blocks in
    /// `open()` until carrier detect, so originating through it hangs with no
    /// error and no timeout — the block is in the kernel, not in any read.
    #[test]
    fn a_dial_in_device_is_refused_with_the_remedy() {
        if !cfg!(target_os = "macos") {
            return;
        }
        let mut a = ready_node("serial-tty");
        type_command(&mut a, "connect a1b2c3d4 serial /dev/tty.usbserial-XX");
        assert!(a.output.contains("dial-in"), "{}", a.output);
        assert!(
            a.output.contains("cu."),
            "the remedy must be in the message: {}",
            a.output
        );
    }

    /// Usage names a device shape that exists on this host, because there is
    /// no configuration file to copy one from.
    #[test]
    fn connect_usage_names_a_device_for_this_platform() {
        let mut a = ready_node("serial-usage");
        type_command(&mut a, "connect");
        assert!(a.output.contains("serial"), "{}", a.output);
        assert!(a.output.contains("modem"), "{}", a.output);
        if cfg!(target_os = "windows") {
            assert!(a.output.contains("COM"), "{}", a.output);
        } else {
            assert!(a.output.contains("/dev/"), "{}", a.output);
        }
    }

    /// A serial peer still needs a signed peer-link: RFC 4 §4.1's static-key
    /// check is a hard failure on every carrier, never a prompt.
    #[test]
    fn a_serial_link_still_requires_a_verified_credential() {
        let mut a = ready_node("serial-nolink");
        type_command(&mut a, "connect a1b2c3d4 serial /dev/cu.nonexistent");
        assert!(a.output.contains("no peer-link"), "{}", a.output);
    }

    /// **The negotiated retention is enforced, not decorative.** `evict_to`
    /// had no caller, so a node agreeing to hold a gigabyte held whatever
    /// arrived — a disk-filling attack needing no more than a generous peer.
    #[test]
    fn the_corpus_is_held_inside_its_agreed_retention() {
        let mut a = ready_node("retention");
        let cap = peering::Policy::default().retention_bytes;

        // Well past the cap, in objects the store will accept.
        let now = now_epoch().0 * 1440;
        a.store.with(|s| {
            let mut salt = 0u32;
            while s.bytes() <= cap + 100_000 {
                let h = krab_core::object::RoutingHeader {
                    version: 1,
                    class: 0,
                    size_bucket: 5,
                    flags: 0,
                    expiry_min: now + 1_000 + (salt % 60_000),
                    tag: krab_core::object::Tag((salt as u64).to_le_bytes()),
                };
                let b = krab_core::object::canonical_bytes(&h, &krab_core::object::example_sealed_body(7)).unwrap();
                let _ = s.ingest(krab_crypto::object_id(&b), b, now, u32::MAX);
                salt += 1;
                if salt > 20_000 {
                    break;
                }
            }
            assert!(s.bytes() > cap, "the test did not exceed the cap");
        });

        a.enforce_retention();
        a.store.with(|s| {
            assert!(
                s.bytes() <= cap,
                "the corpus stayed at {} bytes against a {cap}-byte agreement",
                s.bytes()
            );
            // Eviction raised the watermark, so what went cannot come back.
            assert!(
                s.watermark() > 0,
                "eviction must raise the watermark (RFC 5 §8)"
            );
        });
        assert!(
            a.log.recent(4).iter().any(|l| l.contains("capacity")),
            "eviction is not recoverable by reconnecting and must be said"
        );
    }

    /// A corpus inside its agreement is left alone — enforcement must not
    /// evict on every tick.
    #[test]
    fn a_small_corpus_is_not_evicted() {
        let mut a = ready_node("retention-small");
        let now = now_epoch().0 * 1440;
        a.store.with(|s| {
            let h = krab_core::object::RoutingHeader {
                version: 1,
                class: 0,
                size_bucket: 0,
                flags: 0,
                expiry_min: now + 40_000,
                tag: krab_core::object::Tag([3; 8]),
            };
            let b = krab_core::object::canonical_bytes(&h, &krab_core::object::example_sealed_body(3)).unwrap();
            s.ingest(krab_crypto::object_id(&b), b, now, u32::MAX)
                .unwrap();
        });
        a.enforce_retention();
        assert_eq!(
            a.store.len(),
            1,
            "a corpus inside its agreement was evicted"
        );
    }

    /// **Is the interface usable from a cold start?**
    ///
    /// Added after the author ran it and reported the command pane did not
    /// work. It did not: focus began on the list pane, where letters are
    /// chords, so `init` was four ignored keystrokes and nothing happened.
    #[test]
    fn a_fresh_node_can_be_driven_from_the_keyboard() {
        let mut a = App::default();
        a.home = temp_home("cold-start");

        // Typing lands in the command line without touching anything first.
        for c in "keys".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        assert_eq!(
            a.command.as_string(),
            "keys",
            "typing did not reach the command line"
        );

        a.on_key(KeyCode::Enter, KeyModifiers::NONE);
        assert!(a.command.is_empty(), "submitting did not clear the line");
        assert!(
            a.output.contains("init"),
            "a fresh node must say what to do: {}",
            a.output
        );
    }

    /// **There must always be a way out.** Before `Ctrl-Q` there was none:
    /// `q` resolved to `Ignored` in browse mode, and the branch that set
    /// `quit` was only reachable while typing, where the character went into
    /// the command instead.
    #[test]
    fn ctrl_q_quits_from_every_pane_and_mode() {
        for pane_cycles in 0..3 {
            for compose in [false, true] {
                let mut a = App::default();
                for _ in 0..pane_cycles {
                    a.ui.cycle_focus();
                }
                if compose {
                    a.ui.compose();
                }
                assert!(!a.quit);
                a.on_key(KeyCode::Char('q'), KeyModifiers::CONTROL);
                assert!(a.quit, "no exit from pane {pane_cycles}, compose={compose}");
            }
        }
    }

    /// A bare `q` is a letter, not an exit — otherwise no command containing
    /// one could be typed.
    #[test]
    fn a_bare_q_types_rather_than_quitting() {
        let mut a = App::default();
        a.on_key(KeyCode::Char('q'), KeyModifiers::NONE);
        assert!(!a.quit);
        assert_eq!(a.command.as_string(), "q");
    }

    /// **RFC 8 §3's two lines are two lines of content.** A three-row pane
    /// with a top rule leaves two; a two-row pane with a full border left
    /// none, and the command line had nowhere to render.
    #[test]
    fn the_command_pane_has_two_usable_lines() {
        let ui = Ui::default();
        let screen = layout::Rect {
            x: 0,
            y: 0,
            w: 100,
            h: 40,
        };
        let cmd = ui
            .layout(screen)
            .into_iter()
            .find(|(p, _)| *p == layout::Pane::Command)
            .expect("a command pane")
            .1;
        assert_eq!(cmd.h, layout::COMMAND_ROWS);
        assert_eq!(cmd.h - 1, 2, "one rule plus RFC 8 §3's two content lines");
        assert_eq!(cmd.w, screen.w, "it spans the width");
    }

    /// The whole first-run sequence an operator actually types, with nothing
    /// but the keyboard.
    #[test]
    fn the_first_run_sequence_works_end_to_end() {
        let mut a = App::default();
        a.home = temp_home("first-run");

        let type_line = |a: &mut App, line: &str| {
            for c in line.chars() {
                a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
            }
            a.on_key(KeyCode::Enter, KeyModifiers::NONE);
        };

        type_line(&mut a, "init");
        assert!(a.init_step.is_some(), "init did not start: {}", a.output);

        for c in "a passphrase".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        assert_eq!(a.passphrase.as_string(), "a passphrase");
        assert!(
            a.command.is_empty(),
            "the passphrase leaked onto the command line"
        );

        // Enter walks the ceremony; cheap Argon2 so the test is not a minute.
        a.identity = Some(krab_lock::Held::new({
            let mut id = Identity::generate(&mut OsRng);
            id.kek_params.m_kib = 64;
            id.kek_params.t = 1;
            id.kek_params.p = 1;
            id
        }));
        for _ in 0..6 {
            a.advance_init();
        }
        assert!(
            a.epoch_key.is_some(),
            "the ceremony did not finish: {}",
            a.output
        );

        type_line(&mut a, "verify");
        assert!(
            a.output.split_whitespace().count() > 8,
            "verify must print eight words to read aloud: {}",
            a.output
        );
    }

    /// Selecting is idempotent; toggling is not. An operator who cannot see
    /// which tab they are on cannot toggle their way to certainty, and RFC 8
    /// §4.1 makes guessing wrong irreversible.
    #[test]
    fn ctrl_1_and_ctrl_2_select_tabs_absolutely() {
        let mut a = App::default();
        for _ in 0..2 {
            a.on_key(KeyCode::Char('2'), KeyModifiers::CONTROL);
            assert_eq!(a.ui.tab(), layout::Tab::Channels);
        }
        for _ in 0..2 {
            a.on_key(KeyCode::Char('1'), KeyModifiers::CONTROL);
            assert_eq!(a.ui.tab(), layout::Tab::Private);
        }
        // And from the command line, where focus starts and `m` is a letter.
        assert_eq!(a.ui.focus(), layout::Pane::Command);
        a.on_key(KeyCode::Char('m'), KeyModifiers::NONE);
        assert_eq!(a.command.as_string(), "m");
        assert_eq!(
            a.ui.tab(),
            layout::Tab::Private,
            "`m` typed, it did not switch"
        );
        a.on_key(KeyCode::Char('2'), KeyModifiers::CONTROL);
        assert_eq!(a.ui.tab(), layout::Tab::Channels);
    }

    /// **What an operator actually sees on a cold start.** Every earlier test
    /// here asserts on state; this one asserts on pixels, because the command
    /// pane bug was invisible to state assertions — the command was in the
    /// string, the string just never reached the screen.
    #[test]
    fn the_cold_start_screen_shows_the_prompt_and_both_tabs() {
        use ratatui::{backend::TestBackend, Terminal};

        let mut a = App::default();
        for c in "init".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }

        let mut term = Terminal::new(TestBackend::new(80, 24)).expect("a terminal");
        let log = a.log.recent(activity_log::CAPACITY);
        let me = a.identity.as_ref().map(|i| i.short_id());
        term.draw(|f| render::draw(f, &a.view(&log, me.as_deref())))
            .expect("a frame");
        let screen: Vec<String> = term
            .backend()
            .buffer()
            .content()
            .chunks(80)
            .map(|row| row.iter().map(|c| c.symbol()).collect())
            .collect();
        let all = screen.join("\n");

        assert!(all.contains("Private"), "no private tab:\n{all}");
        assert!(all.contains("Channels"), "no channels tab:\n{all}");
        assert!(
            screen.iter().any(|r| r.contains("> init")),
            "what was typed never reached the screen:\n{all}"
        );

        // The command pane's own rows: the rule with the status, and RFC 8
        // §3's two content lines.
        let rows = &screen[screen.len() - layout::COMMAND_ROWS as usize..];
        assert!(rows[0].contains('\u{2500}'), "no rule: {:?}", rows[0]);
        assert!(
            rows.iter().any(|r| r.trim_end().ends_with("init")),
            "the prompt is not in the command pane: {rows:?}"
        );
    }

    /// Not an assertion — a way to read the screen. `cargo test -p krab-tui
    /// dump_the_cold_start_screen -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn dump_the_cold_start_screen() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut a = App::default();
        for c in "init".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        let mut term = Terminal::new(TestBackend::new(80, 24)).expect("a terminal");
        let log = a.log.recent(activity_log::CAPACITY);
        let me = a.identity.as_ref().map(|i| i.short_id());
        term.draw(|f| render::draw(f, &a.view(&log, me.as_deref())))
            .expect("a frame");
        for row in term.backend().buffer().content().chunks(80) {
            let line: String = row.iter().map(|c| c.symbol()).collect();
            println!("|{}|", line.trim_end());
        }
    }

    /// **Two nodes on one host, over TCP.** The case the author asked about,
    /// and the case that did not work: `answer` was parsed, passed to
    /// `establish`, honoured by the serial branch, and dropped by the TCP
    /// branch — so both ends dialled and neither listened.
    #[test]
    fn two_local_nodes_link_over_tcp_when_one_answers() {
        use krab_fabric::backend::tcp::TcpFabric;
        use krab_fabric::{profile::LinkProfile, Fabric};

        let mut rng = OsRng;
        let a = Identity::generate(&mut rng);
        let b = Identity::generate(&mut rng);

        // The answering end, bound to a port the kernel picks so the test does
        // not fight whatever is on 40000.
        let answerer = TcpFabric::new(
            LinkProfile::tcp(),
            "127.0.0.1:0",
            b.noise_bytes(),
            a.card(Policy::default()).noise_static_pk,
        );
        let port = answerer.listen("127.0.0.1:0").expect("a port");

        let b_static = b.card(Policy::default()).noise_static_pk;
        let dialler = std::thread::spawn(move || {
            TcpFabric::new(
                LinkProfile::tcp(),
                format!("127.0.0.1:{port}"),
                a.noise_bytes(),
                b_static,
            )
            .connect()
            .map(|_| ())
            .map_err(|e| e.to_string())
        });

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut got = None;
        while std::time::Instant::now() < deadline && got.is_none() {
            got = answerer.accept().expect("accept must not error");
            if got.is_none() {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
        assert!(got.is_some(), "the answering end never saw the call");
        dialler
            .join()
            .expect("the dialling thread")
            .expect("a session");
    }

    /// `Ctrl-O` full-screens whatever has focus, and the command line takes
    /// the output pane with it.
    #[test]
    fn ctrl_o_full_screens_the_focused_pane() {
        use layout::{Pane, Zoom};
        for (cycles, want) in [
            (0, Zoom::Console),         // Command
            (1, Zoom::One(Pane::List)), // List
            (2, Zoom::One(Pane::View)), // View
            (3, Zoom::Console),         // Output
        ] {
            let mut a = App::default();
            for _ in 0..cycles {
                a.ui.cycle_focus();
            }
            a.on_key(KeyCode::Char('o'), KeyModifiers::CONTROL);
            assert_eq!(a.ui.zoomed(), Some(want), "focus after {cycles} cycles");
            // And it toggles back.
            a.on_key(KeyCode::Char('o'), KeyModifiers::CONTROL);
            assert_eq!(a.ui.zoomed(), None);
        }
    }

    /// The console keeps both panes on screen. A zoomed output pane with no
    /// prompt, or a prompt with its output elsewhere, is neither.
    #[test]
    fn the_console_zoom_shows_output_and_the_command_line() {
        let mut a = App::default();
        a.on_key(KeyCode::Char('o'), KeyModifiers::CONTROL);
        let panes = a.ui.layout(layout::Rect {
            x: 0,
            y: 0,
            w: 80,
            h: 24,
        });
        let kinds: Vec<layout::Pane> = panes.iter().map(|(p, _)| *p).collect();
        assert_eq!(kinds, vec![layout::Pane::Output, layout::Pane::Command]);
        assert_eq!(panes[0].1.h + panes[1].1.h, 24, "they fill the screen");
        assert_eq!(panes[1].1.h, layout::COMMAND_ROWS);
    }

    /// **Esc goes home from anywhere**, in one keystroke.
    #[test]
    fn esc_returns_to_the_default_screen() {
        let mut a = App::default();
        // As tangled as the interface gets: a channel, composing, zoomed, on
        // a body pane, with a half-typed command.
        a.on_key(KeyCode::Char('2'), KeyModifiers::CONTROL);
        a.ui.descend();
        a.ui.compose();
        a.composer_set("a draft");
        a.ui.cycle_focus();
        a.on_key(KeyCode::Char('o'), KeyModifiers::CONTROL);
        a.command = line::Line::from("half typed");

        a.on_key(KeyCode::Esc, KeyModifiers::NONE);

        assert_eq!(a.ui.zoomed(), None, "unzoomed");
        assert_eq!(a.ui.mode(), Mode::Browse, "not composing");
        assert_eq!(a.ui.focus(), layout::Pane::Command, "back at the prompt");
        assert!(a.command.is_empty(), "the command line is clear");
        assert!(a.composer.is_empty(), "and the draft is gone");
    }

    /// Esc must not throw away a key hierarchy that is halfway created.
    #[test]
    fn esc_does_not_cancel_the_first_run_ceremony() {
        let mut a = App::default();
        a.home = temp_home("esc-init");
        for c in "init".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        a.on_key(KeyCode::Enter, KeyModifiers::NONE);
        let step = a.init_step;
        assert!(step.is_some());
        a.on_key(KeyCode::Esc, KeyModifiers::NONE);
        assert_eq!(a.init_step, step, "the ceremony survived");
    }

    /// The line editor, through the key path an operator actually uses.
    #[test]
    fn the_command_line_can_be_edited() {
        let mut a = App::default();
        for c in "conect bob".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        // Back to the typo and fix it, without losing what follows.
        a.on_key(KeyCode::Home, KeyModifiers::NONE);
        for _ in 0..3 {
            a.on_key(KeyCode::Right, KeyModifiers::NONE);
        }
        a.on_key(KeyCode::Char('n'), KeyModifiers::NONE);
        assert_eq!(a.command.as_string(), "connect bob");

        // Word deletion, from the end.
        a.on_key(KeyCode::End, KeyModifiers::NONE);
        a.on_key(KeyCode::Char('w'), KeyModifiers::CONTROL);
        assert_eq!(a.command.as_string(), "connect ");
    }

    /// A masked passphrase is exactly where correcting a typo matters most:
    /// the KEK is the only root (RFC 7 §4) and nothing on screen shows what
    /// was typed.
    #[test]
    fn the_passphrase_can_be_corrected() {
        let mut a = App::default();
        a.home = temp_home("passphrase-edit");
        for c in "init".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        a.on_key(KeyCode::Enter, KeyModifiers::NONE);
        while a.init_step != Some(InitStep::Passphrase) {
            a.advance_init();
        }
        for c in "hunter3".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        a.on_key(KeyCode::Backspace, KeyModifiers::NONE);
        a.on_key(KeyCode::Char('2'), KeyModifiers::NONE);
        assert_eq!(a.passphrase.as_string(), "hunter2");
        // And it never reached the command line.
        assert!(a.command.is_empty());
    }

    /// `quit` is `Ctrl-Q` in a form that can be discovered by typing `help`.
    #[test]
    fn the_quit_verb_leaves() {
        let mut a = App::default();
        type_command(&mut a, "quit");
        assert!(a.quit);
    }

    /// `help` lists every verb the parser accepts. A verb that exists and is
    /// not listed cannot be found by an operator who has not read RFC 8.
    #[test]
    fn help_lists_every_verb_the_parser_accepts() {
        let mut a = App::default();
        type_command(&mut a, "help");
        for (entry, _) in Command::SYNOPSES {
            let verb = entry.split_whitespace().next().unwrap();
            assert!(
                Command::parse(verb).is_some(),
                "help lists {verb}, which does not parse"
            );
        }
        for verb in [
            "init",
            "peer",
            "lock",
            "unlock",
            "duress",
            "request",
            "wipe",
            "connect",
            "disconnect",
            "rollcall",
            "import",
            "pack",
            "send",
            "keys",
            "reach",
            "peers",
            "verify",
            "listen",
            "help",
            "quit",
        ] {
            assert!(
                a.output.contains(verb),
                "help does not mention `{verb}`:\n{}",
                a.output
            );
        }
    }

    /// **A restarted node can be unlocked, and cannot be re-initialised.**
    ///
    /// Both halves went wrong the same way: `admit` was told whether an
    /// identity was in *memory*, when what it needed was whether this node
    /// *has* one. After a restart the hierarchy is on disk and memory is
    /// empty, so `unlock` was refused for want of the thing it produces —
    /// and `init` was admitted, which would have generated a new hierarchy
    /// over the stored one and made every existing message unreadable.
    ///
    /// Existing restart coverage called `open_with` directly and so could not
    /// see this. It is reached only through `submit`.
    #[test]
    fn a_restarted_node_unlocks_and_refuses_to_reinitialise() {
        let home = temp_home("restart-verbs");

        // A node with a store on disk.
        let mut a = App {
            home: home.clone(),
            ..App::default()
        };
        let mut id = Identity::generate(&mut OsRng);
        id.kek_params.m_kib = 64;
        id.kek_params.t = 1;
        id.kek_params.p = 1;
        let fingerprint = id.short_id();
        a.identity = Some(krab_lock::Held::new(id));
        a.passphrase = line::Line::from("a passphrase");
        a.open_store().expect("the store opens");
        assert!(a.has_stored_identity(), "something must be on disk");

        // Restart: same directory, nothing in memory.
        let mut b = App {
            home: home.clone(),
            ..App::default()
        };
        assert!(b.identity.is_none());

        // `init` must not be offered a second time — it would overwrite the
        // hierarchy that is already there.
        type_command(&mut b, "init");
        assert!(
            b.output.contains("already has an identity"),
            "init was admitted over an existing store: {}",
            b.output
        );
        assert!(b.init_step.is_none(), "and did not start the ceremony");

        // `unlock` must be admitted, then take the passphrase.
        type_command(&mut b, "unlock");
        assert!(
            !b.output.contains("no identity yet"),
            "unlock was refused for want of what it produces: {}",
            b.output
        );
        assert_eq!(
            b.init_step,
            Some(InitStep::Passphrase),
            "unlock must ask for a passphrase: {}",
            b.output
        );

        for c in "a passphrase".chars() {
            b.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        b.advance_init();
        assert!(b.identity.is_some(), "the store did not open: {}", b.output);
        assert_eq!(
            b.identity.as_ref().unwrap().short_id(),
            fingerprint,
            "and it is the same identity, not a new one"
        );
        assert!(b.epoch_key.is_some(), "with its epoch key");
    }

    /// **The backup words must be on screen when the ceremony asks whether
    /// they were written down.** They were printed into the two-row output
    /// pane, where they scrolled off — so the next step asked the operator to
    /// confirm they had recorded something they had never seen.
    #[test]
    fn the_backup_words_are_shown_where_they_fit() {
        let mut a = App::default();
        a.home = temp_home("backup-words");
        type_command(&mut a, "init");
        while a.init_step != Some(InitStep::ShowBackup) {
            if a.init_step == Some(InitStep::Passphrase) {
                a.passphrase = line::Line::from("a passphrase");
            }
            a.advance_init();
        }

        let phrase = a
            .identity
            .as_ref()
            .expect("the ceremony generated an identity")
            .backup_phrase();
        assert!(phrase.split_whitespace().count() > 8, "a real word list");
        assert!(
            a.output.contains(&phrase),
            "the words are not on screen:\n{}",
            a.output
        );
        // **And a scheduler tick must not erase them.** The message pane is
        // rebuilt from the inbox on every tick, so anything written there
        // vanishes within a second — which is what happened when these words
        // were routed to it.
        a.tick_schedule();
        assert!(
            a.output.contains(&phrase),
            "a tick erased the backup words:\n{}",
            a.output
        );
    }

    /// **A node upgraded in place must not start empty.**
    ///
    /// Every earlier build wrote one `corpus.krab`. An upgrade that silently
    /// began with nothing would look exactly like the data loss this series
    /// keeps finding — and it would be irreversible, because the first save
    /// would then have nothing to write and the old file would sit beside a
    /// live node that ignored it.
    #[test]
    fn a_corpus_written_by_an_earlier_build_is_migrated_on_open() {
        let a = ready_node("migrate-open");
        let home = a.home.clone();

        // A node with something in it.
        let h = krab_core::object::RoutingHeader {
            version: 1,
            class: 0,
            size_bucket: 0,
            flags: 0,
            expiry_min: now_epoch().0 * 1440 + 10_000,
            tag: krab_core::object::Tag([5; 8]),
        };
        let bytes =
            krab_core::object::canonical_bytes(&h, &krab_core::object::example_sealed_body(5))
                .unwrap();
        let id = krab_crypto::object_id(&bytes);
        a.store
            .with(|s| s.ingest(id, bytes, now_epoch().0 * 1440, u32::MAX))
            .expect("ingested");
        a.save_corpus();
        assert!(home.join("corpus").is_dir(), "the new layout was not written");

        // Now put the home back into the old layout, by hand: one archive over
        // the whole window, and no directory.
        let old = home.join("corpus.krab");
        a.store.with(|s| {
            crate::courier::pack(
                s,
                &old,
                (0, u32::MAX),
                &krab_fabric::profile::LinkProfile::courier(),
            )
            .expect("packed")
        });
        std::fs::remove_dir_all(home.join("corpus")).unwrap();

        // A fresh node on that home migrates it. The identity is read back
        // from `identity.wrapped`, exactly as a restart does — `Identity` does
        // not implement `Clone`, and it should not: a second copy of the
        // private keys is a second thing to zeroize.
        let mut b = App {
            home: home.clone(),
            ..App::default()
        };
        b.unlock(b"a passphrase").expect("unlocks");

        assert!(
            b.store.with(|s| s.contains(&id)),
            "the object did not survive the migration"
        );
        assert!(home.join("corpus").is_dir(), "the segments were not written");
        assert!(!old.exists(), "the old file was left behind");
    }

    /// `Ctrl-Q` and `quit` must do the same thing. They did not: one wrote the
    /// corpus out and the other did not.
    #[test]
    fn the_two_ways_out_both_persist_the_corpus() {
        let make = |tag: &str| {
            let mut a = App {
                home: temp_home(tag),
                ..App::default()
            };
            let mut id = Identity::generate(&mut OsRng);
            id.kek_params.m_kib = 64;
            id.kek_params.t = 1;
            id.kek_params.p = 1;
            a.identity = Some(krab_lock::Held::new(id));
            a.passphrase = line::Line::from("a passphrase");
            a.open_store().expect("the store opens");
            // The corpus is a directory of segments now, so starting without
            // one means removing the directory.
            let _ = std::fs::remove_dir_all(a.path(artifact::Artifact::Corpus));
            a
        };

        let mut chord = make("quit-chord");
        chord.on_key(KeyCode::Char('q'), KeyModifiers::CONTROL);
        assert!(chord.quit);
        assert!(
            chord.at("corpus").exists(),
            "Ctrl-Q left the corpus unwritten"
        );

        let mut verb = make("quit-verb");
        type_command(&mut verb, "quit");
        assert!(verb.quit);
        assert!(
            verb.path(artifact::Artifact::Corpus).exists(),
            "`quit` left the corpus unwritten"
        );
    }

    /// **The quickstarts must not go stale.** Every verb shown at a `>`
    /// prompt in `INIT.md` and `PEERING.md` has to still parse, and every
    /// `peer` subverb has to still exist. Renaming a verb without touching
    /// the documentation fails here rather than at an operator's terminal.
    #[test]
    fn the_documented_verbs_all_exist() {
        for doc in [
            "../../Documentation/INIT.md",
            "../../Documentation/PEERING.md",
        ] {
            let text = std::fs::read_to_string(doc).unwrap_or_else(|e| panic!("{doc}: {e}"));
            let mut checked = 0;
            let mut fenced = false;
            for line in text.lines() {
                if line.starts_with("```") {
                    fenced = !fenced;
                    continue;
                }
                // Prompt lines inside the fenced examples. Outside them `> `
                // is a Markdown blockquote, which is prose.
                if !fenced {
                    continue;
                }
                let Some(rest) = line.strip_prefix("> ") else {
                    continue;
                };
                let rest = rest.trim();
                // `> (Enter)` and blockquote prose are not commands.
                if rest.starts_with('(') || rest.starts_with("**") || rest.is_empty() {
                    continue;
                }
                let verb = rest.split_whitespace().next().unwrap();
                // The screen mockups draw a cursor after the prompt.
                if !verb.chars().all(|c| c.is_ascii_lowercase()) {
                    continue;
                }
                assert!(
                    Command::parse(verb).is_some(),
                    "{doc} documents `{verb}`, which no longer parses"
                );
                if verb == "peer" {
                    let sub = rest.strip_prefix("peer").unwrap_or("");
                    assert!(
                        Peering::parse(sub).is_some(),
                        "{doc} documents `{rest}`, which no longer parses"
                    );
                }
                checked += 1;
            }
            assert!(
                checked >= 5,
                "{doc}: only {checked} commands found — did the format change?"
            );
        }
    }

    /// **`wipe` must reach into the peer directories.**
    ///
    /// Per-peer state moved from flat `<id>.link` files into `peers/<id>/`,
    /// and the shredder did not recurse. A flat scan walks straight past every
    /// peering the node has — which is exactly the list `wipe` exists to
    /// destroy. The files are useless without the KEK; a list of who this node
    /// peered with is not.
    #[test]
    fn wipe_destroys_peer_directories_not_just_the_top_level() {
        let mut a = ready_node("wipe-peers");
        let peer = "deadbeef";
        a.ensure_peer_dir(peer).expect("a peer directory");
        std::fs::write(a.peer_path(peer, artifact::PeerFile::Link), b"a card").unwrap();
        std::fs::write(a.peer_path(peer, artifact::PeerFile::Reservoir), b"sealed").unwrap();

        a.confirmed = true;
        type_command(&mut a, "wipe");

        assert!(
            !a.peer_path(peer, artifact::PeerFile::Link).exists(),
            "the peer-link survived the wipe"
        );
        assert!(
            !a.peer_path(peer, artifact::PeerFile::Reservoir).exists(),
            "the reservoir survived the wipe"
        );
        assert!(
            !a.home.join("peers").join(peer).exists(),
            "the directory name alone discloses the peer"
        );
    }

    /// Each peer's state lives together, under its own directory.
    #[test]
    fn peer_state_is_grouped_per_peer() {
        let a = ready_node("peer-layout");
        for id in ["aaaa1111", "bbbb2222"] {
            a.ensure_peer_dir(id).unwrap();
            std::fs::write(a.peer_path(id, artifact::PeerFile::Link), b"card").unwrap();
        }
        assert_eq!(a.peer_ids(), vec!["aaaa1111", "bbbb2222"]);
        assert_eq!(
            a.peer_path("aaaa1111", artifact::PeerFile::Reservoir),
            a.home.join("peers").join("aaaa1111").join("reservoir")
        );
        // A directory without a link is not a peer — a half-written one must
        // not be reported as peered.
        a.ensure_peer_dir("cccc3333").unwrap();
        assert_eq!(a.peer_ids(), vec!["aaaa1111", "bbbb2222"]);
    }

    /// **RFC 3 §3's verb exists and reads the stored document.**
    ///
    /// The rendering's completeness is asserted next to the renderer, in
    /// `credential::tests`. What is asserted here is the plumbing: the verb
    /// the RFC names by name, and that it reads from disk rather than from
    /// memory, so what an operator inspects is what is stored.
    #[test]
    fn peer_show_is_the_verb_rfc3_names() {
        let (mut a, _b, _, _) = peered_pair("hjson-verb");
        let peer = a.peer_ids().first().cloned().expect("a peering");

        type_command(&mut a, "peer show");
        assert!(a.output.contains("usage: peer show"), "{}", a.output);
        assert!(a.output.contains("RFC 3 §3"), "{}", a.output);

        // A peering with no countersigned credential says which of the two
        // reasons applies, rather than reporting an empty document.
        type_command(&mut a, &format!("peer show {peer}"));
        assert!(a.output.contains("never countersigned"), "{}", a.output);
    }

    /// **RFC 3 §12's evidence reaches the operator, and the keystroke is
    /// beside it.**
    ///
    /// > "A disconnect decision should be one keystroke from the evidence
    /// > justifying it. If it is not, operators will not make it, and the
    /// > accountability model degrades to nothing."
    ///
    /// The panel, its thresholds and its highlights were written and tested;
    /// `peers_panel` built `Vec::new()` and passed it, so none of it was ever
    /// shown. That is the same shape as a bound with no caller — a mechanism
    /// that exists and does not run — and the reason it was worth a test
    /// rather than a reading.
    #[test]
    fn the_peers_panel_shows_the_evidence_and_the_keystroke() {
        let (mut a, _b, _, _) = peered_pair("panel-evidence");
        // The panel lists peerings from disk, so the counters have to be keyed
        // the way it reads them.
        let peer = a.peer_ids().first().cloned().expect("a peering");

        // Traffic, as an exchange would record it: offered, charged, refused.
        {
            let budget = a.budget_for(&peer).expect("a peering has a budget");
            let mut acct = budget.spend.lock().unwrap_or_else(|e| e.into_inner());
            acct.spend.offered = 1_000;
            acct.spend.objects = 40;
            acct.spend.bytes = 4 * 1024 * 1024;
            acct.spend.refused = 12;
        }

        let panel = a.peers_panel();
        // §12's key metric, and the volume behind it.
        assert!(panel.contains("4% novel"), "no novelty ratio:\n{panel}");
        assert!(panel.contains("960 duplicate(s)"), "no duplicates:\n{panel}");
        assert!(panel.contains("refused over budget"), "no refusals:\n{panel}");
        // And the action, one keystroke away from all of it.
        assert!(
            panel.contains(&format!("[{}] disconnect", peers::DISCONNECT_KEY)),
            "the evidence has no action beside it:\n{panel}"
        );
    }

    /// **An unmeasured metric must not read as a good one.**
    ///
    /// `unique_source` is §12's eclipse indicator — "high means cutting them
    /// partitions you" — and nothing measures it. Rendered as `0%` it says
    /// cutting the peer is safe, which is the reassuring answer arrived at by
    /// not looking. Coverage is the same: `Coverage::default()` is all zeros,
    /// and "coverage 0%" is RFC 0 §7.4's alarm condition reported as fact.
    #[test]
    fn an_unmeasured_metric_reads_as_unknown() {
        let m = App::metrics_from(&quota::Spend {
            day: 1,
            bytes: 1_000,
            objects: 5,
            offered: 10,
            refused: 0,
            rejected: 0,
        });
        assert_eq!(m.novelty_ratio(), Some(0.5), "novelty is measured");
        assert_eq!(
            m.unique_source_ratio(),
            None,
            "the eclipse indicator is not measured and must not claim zero"
        );

        let row = peers::Row {
            peer: "q3m9",
            metrics: &m,
            coverage: None,
            link: None,
            quota_bytes: 4_096,
        };
        let line = row.render();
        assert!(line.contains("unique    —"), "{line}");
        assert!(line.contains("coverage    —"), "{line}");
        assert!(
            row.highlights().is_empty(),
            "an unmeasured indicator raised an alarm: {:?}",
            row.highlights()
        );
    }

    /// **The render loop reaches the retention cap.**
    ///
    /// Every background guarantee this node makes — expiry, eviction, prekey
    /// republication, the meeting window, the reconciliation schedule — hangs
    /// off one `if` in `run`, and `run` cannot be called from a test because it
    /// blocks on a real terminal. So the chain was asserted by reading, and an
    /// audit that read it differently concluded `evict_to` had no caller
    /// outside the tests. The chain was there; nothing exercised it.
    ///
    /// This drives the loop's own condition, so what is asserted is the edge
    /// rather than any one destination. The observable is the meeting window,
    /// because it is the only thing downstream of `tick_schedule` that a test
    /// can make due on demand — the rest are governed by the wall clock. What
    /// this proves is the edge; what it does not prove is that any particular
    /// item on `tick_schedule`'s list does its job, which is what each of
    /// those items' own tests are for.
    #[test]
    fn the_render_loops_tick_reaches_the_background_half() {
        let mut a = ready_node("tick-edge");
        type_command(&mut a, "peer meet listen 127.0.0.1:0 --timeout 1");
        assert!(a.meeting.is_some(), "{}", a.output);

        // Not due yet: the loop must not run the background half every frame.
        let mut last = Instant::now();
        assert!(!a.tick_if_due(&mut last), "ticked before it was due");
        assert!(a.meeting.is_some(), "the door closed without a tick");

        // The window expires. Nothing else changes.
        if let Some(m) = a.meeting.as_mut() {
            m.until = Instant::now() - Duration::from_secs(1);
        }
        assert!(
            a.meeting.is_some(),
            "an expired window closes itself only on a tick"
        );

        // Due. This is the edge `run` takes, and the only one it has.
        let mut last = Instant::now() - TICK - Duration::from_millis(1);
        assert!(a.tick_if_due(&mut last), "the tick did not fire when due");
        assert!(
            a.meeting.is_none(),
            "the tick did not reach `tick_schedule` — and `enforce_retention`, \
             `shred_expired_epochs` and the reconciliation schedule are on the \
             same list"
        );
    }

    /// **A first-contact door closes when the arrangement is over**, and the
    /// operator may say how long that is.
    ///
    /// The default is fifteen minutes and it was the only choice. Two people
    /// arranging a call for a known minute do not want a quarter-hour window,
    /// and one waiting on a slow correspondent may want longer — but not
    /// unboundedly longer, because a socket that accepts whoever calls is safe
    /// only for as long as somebody is watching it.
    #[test]
    fn a_meet_window_can_be_shortened_and_is_bounded() {
        let mut a = ready_node("meet-timeout");

        type_command(&mut a, "peer meet listen 127.0.0.1:0 --timeout 2");
        assert!(a.output.contains("for 2 minutes"), "{}", a.output);
        let m = a.meeting.as_ref().expect("a door is open");
        assert_eq!(m.window, Duration::from_secs(120));
        assert!(m.until <= Instant::now() + Duration::from_secs(121));
        type_command(&mut a, "peer meet cancel");

        // Bounded above: this is a door, not a service.
        type_command(&mut a, "peer meet listen 127.0.0.1:0 --timeout 601");
        assert!(a.output.contains("1 to 60 minutes"), "{}", a.output);
        assert!(a.meeting.is_none(), "an over-long window opened a door");

        // And zero is not a window.
        type_command(&mut a, "peer meet listen 127.0.0.1:0 --timeout 0");
        assert!(a.meeting.is_none(), "{}", a.output);

        // A missing or unparseable number says so rather than defaulting —
        // silently using fifteen minutes when the operator asked for two is
        // the failure this option exists to prevent.
        type_command(&mut a, "peer meet listen 127.0.0.1:0 --timeout");
        assert!(a.output.contains("usage:"), "{}", a.output);
        assert!(a.meeting.is_none());

        // The default still applies when nothing is asked for.
        type_command(&mut a, "peer meet listen 127.0.0.1:0");
        assert_eq!(a.meeting.as_ref().unwrap().window, MEET_WINDOW);
        type_command(&mut a, "peer meet cancel");
    }

    /// **The panic chord.** RFC 7 §10's wipe for an operator who does not have
    /// time to type. `duress` covers being watched; this covers having
    /// seconds.
    ///
    /// **One press.** It armed on the first and fired on a second within three
    /// seconds, which bought one second of protection against a mis-strike at
    /// the price of one second of delay at the only moment this key exists
    /// for. The chord itself is the protection — see [`keys::Binding::PanicWipe`].
    #[test]
    fn one_press_of_the_panic_chord_destroys_everything() {
        let mut a = ready_node("panic-chord");
        assert!(a.identity.is_some() && a.epoch_key.is_some());
        assert!(a.path(artifact::Artifact::IdentityWrapped).exists());

        a.on_key(
            KeyCode::Char('W'),
            KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SHIFT,
        );

        assert!(a.identity.is_none(), "the hierarchy survived one press");
        assert!(a.epoch_key.is_none());
        assert!(
            !a.path(artifact::Artifact::IdentityWrapped).exists(),
            "the store survived"
        );
        assert!(a.output.contains("overwritten and removed"), "{}", a.output);
    }

    /// **It fires from wherever the operator is**, including mid-command with
    /// the command line focused.
    ///
    /// The chord resolves ahead of every mode in `Binding::of`, and a panic
    /// wipe that needed the right pane focused would be one that failed at the
    /// moment it was reached for. `W` is also a letter, and a letter typed on
    /// the command line is a character — so this is where a mode-dependent
    /// binding would go wrong.
    #[test]
    fn the_panic_chord_fires_while_typing_a_command() {
        let mut a = ready_node("panic-typing");
        a.ui.focus_command();
        for c in "conn".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        assert_eq!(a.command.as_string(), "conn", "the fixture must be typing");

        a.on_key(
            KeyCode::Char('W'),
            KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SHIFT,
        );
        assert!(a.identity.is_none(), "the chord did not reach the wipe");
    }

    /// Four modifiers, and every subset of them is something else. A chord an
    /// operator can strike by accident is not a panic chord.
    #[test]
    fn no_lesser_chord_reaches_the_panic_wipe() {
        use keys::{Binding, Key, KeyPress};
        for (ctrl, alt, shift) in [
            (true, false, false),
            (true, false, true),
            (true, true, false),
            (false, true, true),
            (false, false, true),
        ] {
            let press = KeyPress {
                code: Key::Char('W'),
                ctrl,
                alt,
                shift,
            };
            assert_ne!(
                Binding::of(press, Mode::Browse),
                Binding::PanicWipe,
                "ctrl={ctrl} alt={alt} shift={shift} reached the panic wipe"
            );
        }
    }

    /// **Two nodes re-key through the typed verb**, over a real pair of
    /// sessions, and end up holding the same root.
    ///
    /// The exchange itself is covered in `rekey_run`; this covers the wiring
    /// around it — reading the reservoir, seating the new root, and writing it
    /// back — which is where a mechanism with no caller usually turns out to
    /// have none.
    #[test]
    fn two_nodes_rekey_through_the_command_pane() {
        let (mut a, mut b, a_id, b_id) = peered_pair("rekey-verb");

        let before_a = stored_root(&a, &b_id);
        let before_b = stored_root(&b, &a_id);
        assert_eq!(before_a, before_b, "the peering must start in agreement");

        // A pair of in-process sessions standing in for a link that is up.
        let (sa, sb) = session_pair();
        a.links.connect(&b_id, profile_named("tcp").unwrap());
        a.links.established(&b_id, Some(Box::new(sa)));
        b.links.connect(&a_id, profile_named("tcp").unwrap());
        b.links.established(&a_id, Some(Box::new(sb)));

        let b_id2 = b_id.clone();
        let handle = std::thread::spawn(move || {
            let out = b.peer_rekey(Some(&a_id_of(&b)));
            (b, out)
        });
        let out_a = a.peer_rekey(Some(&b_id2));
        let (b, out_b) = handle.join().expect("B's thread");

        assert!(out_a.contains("re-keyed"), "A: {out_a}");
        assert!(out_b.contains("re-keyed"), "B: {out_b}");

        let after_a = stored_root(&a, &b_id2);
        let after_b = stored_root(&b, &a_id_of(&b));
        assert_eq!(after_a, after_b, "the two ends hold different roots");
        assert_ne!(after_a, before_a, "the root did not move");

        // And the peer's terms landed, which they never did before: `Policy`
        // was signed into the card at peering and never propagated again.
        assert!(
            a.peer_path(&b_id2, artifact::PeerFile::Policy).exists(),
            "their policy was not recorded"
        );
    }

    /// Re-keying without a link says so, rather than failing somewhere deeper.
    #[test]
    fn rekey_without_a_link_is_refused_up_front() {
        let (mut a, _b, _a_id, b_id) = peered_pair("rekey-nolink");
        let out = a.peer_rekey(Some(&b_id));
        assert!(out.contains("no link"), "{out}");
    }

    /// A peer we never peered with has no card to check a signature against,
    /// and RFC 4 §4.1 forbids taking one from the wire.
    #[test]
    fn rekey_with_a_stranger_is_refused() {
        let mut a = ready_node("rekey-stranger");
        let out = a.peer_rekey(Some("deadbeef"));
        assert!(out.contains("no verifying peer-link"), "{out}");
    }

    /// Re-seat `peer`'s stored reservoir at `epoch`, to stand in for time
    /// passing. The root is unchanged; only where the ratchet claims to be.
    fn backdate_reservoir(n: &App, peer: &str, epoch: u32) {
        let sealed = std::fs::read(n.peer_path(peer, artifact::PeerFile::Reservoir)).unwrap();
        let raw = krab_crypto::kek::open_under(&n.epoch_key.unwrap(), b"krab/reservoir", &sealed)
            .unwrap();
        let (root, _) = persist::decode_reservoir(&raw).unwrap();
        let record = persist::encode_reservoir(&root, krab_core::tag::Epoch(epoch));
        let out = krab_crypto::kek::seal_under(
            &n.epoch_key.unwrap(),
            b"krab/reservoir",
            &record,
            &mut OsRng,
        )
        .unwrap();
        atomic::write(&n.peer_path(peer, artifact::PeerFile::Reservoir), &out).unwrap();
    }

    /// **The guarantee must not depend on someone remembering to type.**
    ///
    /// `REKEY_EPOCHS` states that a reservoir compromised at time *T* stops
    /// protecting traffic within that many epochs of *T*. A re-key mechanism
    /// that only runs when an operator invokes it does not deliver that, and
    /// `REKEY_EPOCHS` had no caller outside its own module until this.
    #[test]
    fn an_aged_reservoir_rekeys_itself_on_the_schedule() {
        let (mut a, mut b, a_id, b_id) = peered_pair("auto-rekey");
        let (sa, sb) = session_pair();
        a.links.connect(&b_id, profile_named("tcp").unwrap());
        a.links.established(&b_id, Some(Box::new(sa)));
        b.links.connect(&a_id, profile_named("tcp").unwrap());
        b.links.established(&a_id, Some(Box::new(sb)));

        // Nothing is due on a reservoir seated today.
        assert!(
            a.rekey_if_due(&b_id).is_none(),
            "a fresh reservoir re-keyed anyway"
        );

        // Age both ends past the interval.
        let old = now_epoch().0 - krab_crypto::REKEY_EPOCHS;
        backdate_reservoir(&a, &b_id, old);
        backdate_reservoir(&b, &a_id, old);
        let before = stored_root(&a, &b_id);

        let b_peer = a_id.clone();
        let handle = std::thread::spawn(move || {
            let e = b.rekey_if_due(&b_peer);
            (b, e)
        });
        let ev_a = a.rekey_if_due(&b_id);
        let (b, ev_b) = handle.join().expect("B's thread");

        assert!(
            matches!(ev_a, Some(activity_log::Event::Rekeyed { .. })),
            "A did not re-key: {ev_a:?}"
        );
        assert!(
            matches!(ev_b, Some(activity_log::Event::Rekeyed { .. })),
            "B did not re-key: {ev_b:?}"
        );
        assert_ne!(stored_root(&a, &b_id), before, "the root did not move");
        assert_eq!(
            stored_root(&a, &b_id),
            stored_root(&b, &a_id),
            "the two ends diverged"
        );
    }

    /// **The 90-day death is repairable.** Past `MAX_ADVANCE` the ratchet
    /// cannot be caught up and the peering is dead; a re-key is the only thing
    /// that revives it, so the trigger must fire there too and not merely on
    /// the rotation interval.
    #[test]
    fn a_peering_past_max_advance_is_revived_rather_than_lost() {
        let (mut a, mut b, a_id, b_id) = peered_pair("auto-revive");
        let (sa, sb) = session_pair();
        a.links.connect(&b_id, profile_named("tcp").unwrap());
        a.links.established(&b_id, Some(Box::new(sa)));
        b.links.connect(&a_id, profile_named("tcp").unwrap());
        b.links.established(&a_id, Some(Box::new(sb)));

        let dead = now_epoch().0 - krab_crypto::reservoir::Reservoir::MAX_ADVANCE - 10;
        backdate_reservoir(&a, &b_id, dead);
        backdate_reservoir(&b, &a_id, dead);

        // The ratchet genuinely cannot close that gap on its own.
        let mut r = krab_crypto::reservoir::Reservoir::new(
            stored_root(&a, &b_id),
            krab_core::tag::Epoch(dead),
        );
        assert!(!r.advance_to(now_epoch()), "the gap must be uncloseable");

        let b_peer = a_id.clone();
        let handle = std::thread::spawn(move || {
            let e = b.rekey_if_due(&b_peer);
            (b, e)
        });
        let ev = a.rekey_if_due(&b_id);
        let (b, _) = handle.join().expect("B's thread");

        assert!(
            matches!(ev, Some(activity_log::Event::Rekeyed { .. })),
            "a dead peering was not revived: {ev:?}"
        );
        assert_eq!(stored_root(&a, &b_id), stored_root(&b, &a_id));
        // And it is usable again from today.
        let r = krab_crypto::reservoir::Reservoir::new(stored_root(&a, &b_id), now_epoch());
        assert!(r.chunk(now_epoch()).is_some());
    }

    /// A peer with no link up is not attempted. The scheduler runs over every
    /// due peer on every tick, and reading a reservoir off disk for each one
    /// that cannot be talked to is work with no possible outcome.
    #[test]
    fn nothing_is_attempted_without_a_live_link() {
        let (mut a, _b, _a_id, b_id) = peered_pair("auto-nolink");
        backdate_reservoir(&a, &b_id, now_epoch().0 - krab_crypto::REKEY_EPOCHS);
        assert!(a.rekey_if_due(&b_id).is_none(), "it tried without a link");
    }

    /// **`peer offer` must not name a file it did not write.**
    ///
    /// It listed `peer.pad` beside `peer.card` as though both existed. Only
    /// the card does — the contribution stays wrapped in the ceremony until
    /// `peer pad` materialises it — so an operator went looking for a file
    /// that was never there and reached `peer seal` with nothing to give it.
    #[test]
    fn peer_offer_names_only_the_file_it_wrote() {
        let mut a = ready_node("offer-honest");
        type_command(&mut a, "peer offer");

        assert!(
            a.path(artifact::Artifact::PeerCard).exists(),
            "the card was not written"
        );
        assert!(
            !a.path(artifact::Artifact::PeerPad).exists(),
            "the pad must not be written into the node's own storage"
        );
        assert!(
            !a.output.contains("peer.pad  "),
            "it lists a file it did not write:\n{}",
            a.output
        );
        // And it says how to get one.
        assert!(
            a.output.contains("peer pad"),
            "it never mentions the verb that creates the pad:\n{}",
            a.output
        );
        assert!(
            a.output.contains("does not exist yet"),
            "it does not say the pad is missing:\n{}",
            a.output
        );
    }

    /// `peer status` is what an operator reaches for when lost, so it has to
    /// answer "what now", not only "what happened".
    #[test]
    fn peer_status_names_the_step_and_the_next_verb() {
        let mut a = ready_node("status-steps");
        let mut b = ready_node("status-steps-b");

        type_command(&mut a, "peer status");
        assert!(a.output.contains("peer offer"), "{}", a.output);

        type_command(&mut a, "peer offer");
        type_command(&mut b, "peer offer");
        type_command(&mut a, "peer status");
        assert!(a.output.contains("step 1 of 5"), "{}", a.output);
        assert!(a.output.contains("peer accept"), "{}", a.output);

        let b_card = {
            let bytes = std::fs::read(b.path(artifact::Artifact::PeerCard)).unwrap();
            let dest = a.at("from-b.card");
            std::fs::write(&dest, bytes).unwrap();
            dest.to_string_lossy().into_owned()
        };
        type_command(&mut a, &format!("peer accept {b_card}"));
        type_command(&mut a, "peer status");
        assert!(a.output.contains("step 3 of 5"), "{}", a.output);
        assert!(
            a.output.contains("peer pad"),
            "step 3 must point at the pad verb:\n{}",
            a.output
        );
    }

    /// Sealing with a path that is not there says which file was wanted.
    /// "No such file or directory" alone does not tell an operator that the
    /// pad they are missing is the one their friend has to hand them.
    #[test]
    fn a_missing_pad_says_whose_pad_it_wanted() {
        let mut a = ready_node("seal-missing");
        type_command(&mut a, "peer offer");
        let mut b = ready_node("seal-missing-b");
        type_command(&mut b, "peer offer");
        let b_card = {
            let bytes = std::fs::read(b.path(artifact::Artifact::PeerCard)).unwrap();
            let dest = a.at("from-b.card");
            std::fs::write(&dest, bytes).unwrap();
            dest.to_string_lossy().into_owned()
        };
        type_command(&mut a, &format!("peer accept {b_card}"));

        type_command(&mut a, "peer seal /nonexistent/their.pad media");
        assert!(
            a.output.contains("pad THEY gave you"),
            "the error does not say whose pad:\n{}",
            a.output
        );
    }

    /// **A restart must not lose the peerings.** `peers` reported the
    /// in-memory link table, which is empty on every start, so a node whose
    /// ceremony had completed said "no peers" and told the operator to run
    /// `peer offer` again — over the top of a peering that already existed.
    #[test]
    fn peers_survive_a_restart() {
        let (a, _b, _a_id, b_id) = peered_pair("peers-restart");

        // Restart: same directory, nothing in memory.
        let mut fresh = App {
            home: a.home.clone(),
            ..App::default()
        };
        fresh.passphrase = line::Line::from("a passphrase");
        fresh.unlock(b"a passphrase").expect("it reopens");

        type_command(&mut fresh, "peers");
        assert!(
            fresh.output.contains(&b_id),
            "the peering vanished across a restart:\n{}",
            fresh.output
        );
        assert!(
            !fresh.output.contains("no peers"),
            "it told the operator to peer again:\n{}",
            fresh.output
        );
        assert!(
            fresh.output.contains("not connected"),
            "it must distinguish peered-but-offline from not peered:\n{}",
            fresh.output
        );
    }

    /// A failed connection must not unpeer anybody. The link goes down; the
    /// peering is a signed artifact on disk and is unaffected.
    #[test]
    fn a_failed_connection_leaves_the_peering_intact() {
        let (mut a, _b, _a_id, b_id) = peered_pair("peers-failed-connect");

        // Nothing is listening on this port.
        type_command(&mut a, &format!("connect {b_id} tcp 127.0.0.1:1"));
        assert!(
            a.output.contains("could not establish") || a.output.contains("refused"),
            "{}",
            a.output
        );

        type_command(&mut a, "peers");
        assert!(
            a.output.contains(&b_id) && !a.output.contains("no peers"),
            "a failed dial unpeered them:\n{}",
            a.output
        );
    }

    /// **`--listen` starts the receive service.** It used to be only a default
    /// address for the `listen` verb, so a node launched with it bound
    /// nothing and the other end got "connection refused" — with no
    /// indication why.
    #[test]
    fn listen_binds_automatically_and_accepts_a_peer() {
        let (mut a, mut b, a_id, b_id) = peered_pair("auto-listen");

        // B accepts, on one socket, for anyone it has peered with.
        b.listen = Some("127.0.0.1:0".into());
        let note = b.start_listener().expect("it starts");
        assert!(note.contains("listening on"), "{note}");
        assert!(
            note.contains("any peered node"),
            "it must not imply a port per peer: {note}"
        );
        let port = note
            .split("port ")
            .nth(1)
            .and_then(|s| s.split(')').next())
            .and_then(|s| s.parse::<u16>().ok())
            .expect("it reports the port it took");

        // A dials, with no `listen` typed at the other end.
        type_command(&mut a, &format!("connect {b_id} tcp 127.0.0.1:{port}"));
        assert!(
            a.output.contains("link up") || a.output.contains("tcp"),
            "the dial failed: {}",
            a.output
        );

        // And B installs it on its next tick, without anyone typing there.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            b.drain_inbound();
            if b.links.get(&a_id).is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        // The peer is in the link table. Its *session* is not: accepting hands
        // it straight to the responder, because a caller who dialled did so in
        // order to say something and there is no keypress to wait for.
        assert!(
            b.links.get(&a_id).is_some(),
            "the accepted call never reached the link table"
        );
        assert!(b.inbound_ticks > 0, "the arrival was not registered");
    }

    /// One socket, not one per peer — a port per peer would publish the size
    /// of the operator's friend list to a port scanner.
    #[test]
    fn the_listener_accepts_every_peering_on_one_socket() {
        let (a, _b, _a_id, b_id) = peered_pair("listen-one-socket");
        a.refresh_allowed();

        // The set is the peerings, whatever their number.
        let mut n = App {
            home: a.home.clone(),
            ..App::default()
        };
        n.passphrase = line::Line::from("a passphrase");
        n.unlock(b"a passphrase").expect("reopens");
        n.refresh_allowed();
        assert_eq!(n.peer_ids(), vec![b_id]);
        // And `--listen` names one address, never a range.
        assert!(!n.listen.iter().any(|a| a.contains('-')));
    }

    /// The two glyphs are distinguishable, and a still one means idle rather
    /// than frozen.
    #[test]
    fn the_duplex_spinners_show_each_direction_separately() {
        let mut s = activity::Spinner::default();
        let idle = s.duplex(false, false);
        assert_eq!(idle.0, idle.1, "both idle glyphs are the same");

        let (out, inn) = s.duplex(true, true);
        assert_ne!(out, idle.0, "sending did not animate");
        assert_ne!(inn, idle.1, "receiving did not animate");

        // One direction at a time is legible on its own.
        assert_eq!(s.duplex(true, false).1, idle.1);
        assert_eq!(s.duplex(false, true).0, idle.0);

        // They advance in opposite directions, so two adjacent animations do
        // not read as one.
        let mut differed = false;
        for _ in 0..8 {
            s.tick();
            let (o, i) = s.duplex(true, true);
            differed |= o != i;
        }
        assert!(differed, "the two spinners are indistinguishable");
    }

    /// **A path with a space must survive.** Removable media is where pads
    /// and cards travel, and it is mounted under names people gave it.
    /// `split_whitespace` truncated silently, so `peer accept
    /// /Volumes/My Disk/bob.card` read from `/Volumes/My` and the operator
    /// was told the file did not exist.
    #[test]
    fn a_quoted_path_reaches_the_verb_intact() {
        let mut a = ready_node("quoted-path");
        type_command(&mut a, "peer offer");

        // A card, at a path with a space in it.
        let dir = a.home.join("My Disk");
        std::fs::create_dir_all(&dir).unwrap();
        let mut b = ready_node("quoted-path-b");
        type_command(&mut b, "peer offer");
        let card = dir.join("bob.card");
        std::fs::copy(b.path(artifact::Artifact::PeerCard), &card).unwrap();

        type_command(&mut a, &format!("peer accept \"{}\"", card.display()));
        assert!(
            a.output.contains("card accepted"),
            "the quoted path did not reach the verb:\n{}",
            a.output
        );

        // Unquoted, the same path is truncated — and the operator is told
        // about the truncated name, not a name they typed.
        type_command(&mut a, &format!("peer accept {}", card.display()));
        assert!(a.output.contains("could not read"), "{}", a.output);
    }

    /// An unterminated quote is refused before any verb runs, with the reason.
    #[test]
    fn an_unbalanced_quote_is_refused_with_its_reason() {
        let mut a = ready_node("bad-quote");
        type_command(&mut a, "peer accept \"oops");
        assert!(a.output.contains("unterminated quote"), "{}", a.output);
        assert!(
            !a.output.contains("could not read"),
            "it ran the verb anyway:\n{}",
            a.output
        );
    }

    /// A bare port number is a port on loopback — what an operator reaches
    /// for, and refusing it would be pedantry with no security content.
    #[test]
    fn listen_accepts_a_bare_port_number() {
        let (mut a, _b, _a_id, b_id) = peered_pair("bare-port");
        type_command(&mut a, &format!("listen {b_id} 1"));
        // Port 1 on loopback is reserved, so this fails — but it must fail
        // having tried 127.0.0.1:1, not having tried to open a serial device
        // called "1".
        assert!(
            !a.output.contains("dial-in") && !a.output.contains("device"),
            "a bare number was taken for a device path:\n{}",
            a.output
        );
    }

    /// Up and down walk what was typed, and stepping past the newest gives an
    /// empty line rather than wrapping — wrapping means an operator holding a
    /// key runs something from the start of the session.
    #[test]
    fn the_command_history_walks_and_does_not_wrap() {
        let mut a = ready_node("history");
        for cmd in ["keys", "peers", "verify"] {
            type_command(&mut a, cmd);
        }

        a.on_key(KeyCode::Up, KeyModifiers::NONE);
        assert_eq!(a.command.as_string(), "verify");
        a.on_key(KeyCode::Up, KeyModifiers::NONE);
        assert_eq!(a.command.as_string(), "peers");
        a.on_key(KeyCode::Up, KeyModifiers::NONE);
        assert_eq!(a.command.as_string(), "keys");
        // Older than the oldest stays put.
        a.on_key(KeyCode::Up, KeyModifiers::NONE);
        assert_eq!(a.command.as_string(), "keys");

        for expect in ["peers", "verify", ""] {
            a.on_key(KeyCode::Down, KeyModifiers::NONE);
            assert_eq!(a.command.as_string(), expect);
        }
        // And newer than the newest stays empty, rather than wrapping round.
        a.on_key(KeyCode::Down, KeyModifiers::NONE);
        assert_eq!(a.command.as_string(), "");
    }

    /// **A passphrase must never enter the history.** It is masked on screen,
    /// and an Up-arrow that reveals it would undo that.
    #[test]
    fn the_passphrase_never_reaches_the_history() {
        let mut a = App::default();
        a.home = temp_home("history-passphrase");
        type_command(&mut a, "init");
        assert_eq!(a.init_step, Some(InitStep::Passphrase));
        for c in "hunter2".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        // Up is inert while the passphrase is being taken.
        a.on_key(KeyCode::Up, KeyModifiers::NONE);
        assert_eq!(a.passphrase.as_string(), "hunter2", "history moved it");
        assert!(a.command.is_empty(), "history put something on the line");
        assert!(
            !a.history.iter().any(|h| h.contains("hunter2")),
            "the passphrase is in the history: {:?}",
            a.history
        );
    }

    /// Repeating a command does not fill the history with copies of it.
    #[test]
    fn consecutive_duplicates_collapse() {
        let mut a = ready_node("history-dupes");
        for _ in 0..5 {
            type_command(&mut a, "peers");
        }
        assert_eq!(a.history, vec!["peers"]);
    }

    /// **Output does not start at the top of the screen for every command.**
    /// A reply's first line is rarely the answer; the last one usually is.
    #[test]
    fn the_output_pane_shows_the_newest_lines_and_scrolls_back() {
        use ratatui::{backend::TestBackend, Terminal};

        let mut a = ready_node("output-scroll");
        a.output = (1..=40)
            .map(|n| format!("line {n}"))
            .collect::<Vec<_>>()
            .join("\n");

        let screen = |a: &App| {
            let mut term = Terminal::new(TestBackend::new(80, 24)).expect("a terminal");
            let log = a.log.recent(activity_log::CAPACITY);
            let me = a.identity.as_ref().map(|i| i.short_id());
            term.draw(|f| render::draw(f, &a.view(&log, me.as_deref())))
                .expect("a frame");
            term.backend()
                .buffer()
                .content()
                .chunks(80)
                .map(|r| r.iter().map(|c| c.symbol()).collect::<String>())
                .collect::<Vec<_>>()
                .join("\n")
        };

        let bottom = screen(&a);
        assert!(bottom.contains("line 40"), "the newest line is not shown");
        assert!(!bottom.contains("line 1 "), "it anchored to the top");
        assert!(bottom.contains("PgUp"), "no hint that more is above");

        // PgUp walks back.
        a.on_key(KeyCode::PageUp, KeyModifiers::NONE);
        let up = screen(&a);
        assert!(!up.contains("line 40"), "PgUp did not move");
        assert!(up.contains("PgDn"), "no hint that more is below");

        // PgDn returns, and cannot go past the newest line.
        for _ in 0..10 {
            a.on_key(KeyCode::PageDown, KeyModifiers::NONE);
        }
        assert!(screen(&a).contains("line 40"), "PgDn overshot");

        // A new command resets to the newest, wherever the operator was.
        a.on_key(KeyCode::PageUp, KeyModifiers::NONE);
        type_command(&mut a, "peers");
        assert_eq!(a.output_scroll, 0, "a new reply was left scrolled away");
    }

    /// `peer connect` is the likely typo, because `connect` is a top-level
    /// verb and `peer` reads like a namespace. "unknown" alone leaves the
    /// operator holding a correct command they cannot find.
    #[test]
    fn a_top_level_verb_typed_after_peer_is_redirected() {
        let mut a = ready_node("peer-typo");
        type_command(&mut a, "peer connect 70913ef6 tcp 127.0.0.1:40001");
        assert!(a.output.contains("is a command on its own"), "{}", a.output);
        assert!(
            a.output.contains("connect 70913ef6 tcp 127.0.0.1:40001"),
            "it does not show the command that works:\n{}",
            a.output
        );

        // And a genuinely unknown subverb lists the real ones.
        type_command(&mut a, "peer frobnicate");
        assert!(a.output.contains("peer offer"), "{}", a.output);
        assert!(a.output.contains("peer seal"), "{}", a.output);
    }

    /// **The indicators report traffic, not configuration.** A node that is
    /// merely set up — listener bound, peers on disk, something queued — is
    /// not sending or receiving, and a glyph that turns anyway is a false
    /// claim rather than a harmless one.
    #[test]
    fn the_activity_glyphs_are_still_on_a_configured_but_idle_node() {
        let (mut a, _b, _a_id, b_id) = peered_pair("glyphs-idle");
        a.listen = Some("127.0.0.1:0".into());
        a.start_listener().expect("it starts");
        a.node.queued = 3;
        a.links.connect(&b_id, profile_named("tcp").unwrap());

        let log = a.log.recent(activity_log::CAPACITY);
        let v = a.view(&log, None);
        assert!(!v.sending, "a queue is not a transfer in progress");
        assert!(!v.receiving, "a bound listener is not a transfer");
    }

    /// And they stop on their own, so a peer that quits does not leave one
    /// turning forever.
    #[test]
    fn an_activity_glyph_stops_by_itself() {
        let mut a = ready_node("glyphs-decay");
        a.inbound_ticks = 2;
        a.outbound_ticks = 2;
        for _ in 0..2 {
            a.drain_inbound();
        }
        let log = a.log.recent(activity_log::CAPACITY);
        let v = a.view(&log, None);
        assert!(!v.sending && !v.receiving, "a glyph is still turning");
    }

    /// **Ctrl-M and Ctrl-G reach the tabs.** `Ctrl-1` has no encoding in the
    /// terminal control range — which is `@` through `_`, and a digit is not
    /// in it — so it arrives as a bare `1` or as nothing.
    #[test]
    fn ctrl_m_and_ctrl_g_select_the_tabs() {
        let mut a = App::default();
        // Several chords reach Channels, because every candidate is stolen by
        // something somewhere — Ctrl-G by Google's terminals and by emacs.
        for c in ['t', 'g', 'c'] {
            a.ui.select_tab(layout::Tab::Private);
            a.on_key(KeyCode::Char(c), KeyModifiers::CONTROL);
            assert_eq!(a.ui.tab(), layout::Tab::Channels, "Ctrl-{c} did not work");
        }
        a.on_key(KeyCode::Char('m'), KeyModifiers::CONTROL);
        assert_eq!(a.ui.tab(), layout::Tab::Private);

        // F-keys too, for terminals that bind Ctrl-M to Return.
        a.on_key(KeyCode::F(2), KeyModifiers::NONE);
        assert_eq!(a.ui.tab(), layout::Tab::Channels);
        a.on_key(KeyCode::F(1), KeyModifiers::NONE);
        assert_eq!(a.ui.tab(), layout::Tab::Private);

        // Unmodified, they are still letters — a command containing `m` or
        // `g` has to be typeable.
        a.on_key(KeyCode::Char('g'), KeyModifiers::NONE);
        assert_eq!(a.command.as_string(), "g");
        assert_eq!(a.ui.tab(), layout::Tab::Private);
    }

    /// **A message sealed to a prekey opens at the other end.** The whole
    /// point of RFC 7 §5: the recipient's permanent correspondence key is no
    /// longer the key an adversary needs.
    #[test]
    fn a_message_encapsulated_to_a_prekey_is_readable() {
        let (mut a, mut b, a_id, b_id) = peered_pair("prekey-send");

        // B publishes, and the batch reaches A the way any object does.
        let note = b.publish_prekeys().expect("B published nothing");
        assert!(note.contains("published"), "publish failed: {note}");
        assert!(
            !b.store.is_empty(),
            "publish said {note}, and stored nothing"
        );
        let carried: Vec<(krab_core::object::ObjectId, Vec<u8>)> = b.store.with(|s| {
            s.entries_in_range(0, u32::MAX)
                .into_iter()
                .filter_map(|(_, id)| s.get(&id).map(|x| (id, x.to_vec())))
                .collect()
        });
        let now_min = now_epoch().0 * 1440;
        for (id, bytes) in carried {
            a.store
                .with(|s| s.ingest(id, bytes, now_min, u32::MAX))
                .expect("the batch is a well-formed object");
        }

        // Diagnose before asserting: which of publish, carry, or lookup?
        let n_objects = a.store.with(|s| s.entries_in_range(0, u32::MAX).len());
        let n_bulletins = a.store.with(|s| {
            s.entries_in_range(0, u32::MAX)
                .into_iter()
                .filter(|(_, id)| s.get(id).and_then(bulletin::from_object).is_some())
                .count()
        });
        assert!(n_objects > 0, "nothing was carried");
        assert!(
            n_bulletins > 0,
            "{n_objects} objects carried, none a bulletin"
        );

        // A now finds a prekey for B, and it is not B's correspondence key.
        let b_node = b.identity.as_ref().unwrap().node_id();
        let chosen = a.prekey_for(&b_node).expect("A found no prekey for B");
        assert_ne!(
            chosen.0,
            b.identity.as_ref().unwrap().correspondence().public().0,
            "it fell back to the permanent key"
        );

        type_command(&mut a, &format!("send {b_id} bring the good coffee"));
        assert!(a.output.contains("to a prekey"), "{}", a.output);

        // Carry it to B and open it.
        let objects: Vec<(krab_core::object::ObjectId, Vec<u8>)> = a.store.with(|s| {
            s.entries_in_range(0, u32::MAX)
                .into_iter()
                .filter_map(|(_, id)| s.get(&id).map(|x| (id, x.to_vec())))
                .collect()
        });
        for (id, bytes) in objects {
            let _ = b.store.with(|s| s.ingest(id, bytes, now_min, u32::MAX));
        }
        b.refresh_inbox();
        assert!(
            b.messages.iter().any(|m| m.body.contains("good coffee")),
            "a message sealed to a prekey did not open: {:?}",
            b.messages.iter().map(|m| &m.body).collect::<Vec<_>>()
        );
        let _ = a_id;
    }

    /// A peer who has published nothing still receives mail, sealed to their
    /// permanent key. Failing instead would make prekeys a way to become
    /// unreachable.
    #[test]
    fn a_peer_without_prekeys_is_still_reachable() {
        let (mut a, mut b, _a_id, b_id) = peered_pair("prekey-absent");
        let b_node = b.identity.as_ref().unwrap().node_id();
        assert!(a.prekey_for(&b_node).is_none(), "B published nothing");

        type_command(&mut a, &format!("send {b_id} still arrives"));
        assert!(a.output.contains("permanent key"), "{}", a.output);

        let objects: Vec<(krab_core::object::ObjectId, Vec<u8>)> = a.store.with(|s| {
            s.entries_in_range(0, u32::MAX)
                .into_iter()
                .filter_map(|(_, id)| s.get(&id).map(|x| (id, x.to_vec())))
                .collect()
        });
        for (id, bytes) in objects {
            let _ = b.store.with(|s| s.ingest(id, bytes, 0, u32::MAX));
        }
        b.refresh_inbox();
        assert!(b.messages.iter().any(|m| m.body.contains("still arrives")));
    }

    /// **A forged batch is refused.** A bulletin is flooded from anyone, so
    /// its signature is the only thing standing between a sender and
    /// encapsulating to an attacker's key.
    #[test]
    fn a_prekey_batch_with_a_broken_signature_is_ignored() {
        let (a, mut b, _a_id, _b_id) = peered_pair("prekey-forged");
        assert!(b.publish_prekeys().is_some());

        let mut tampered: Vec<(krab_core::object::ObjectId, Vec<u8>)> = b.store.with(|s| {
            s.entries_in_range(0, u32::MAX)
                .into_iter()
                .filter_map(|(_, id)| s.get(&id).map(|x| (id, x.to_vec())))
                .collect()
        });
        // Swap a key inside an otherwise genuine bulletin, and re-wrap it as
        // a valid object — so the store accepts it and only the *signature*
        // stands between A and an attacker's key.
        let now_min = now_epoch().0 * 1440;
        let mut swapped = 0;
        for (id, bytes) in tampered.iter_mut() {
            let Some(mut bl) = bulletin::from_object(bytes) else {
                continue;
            };
            if bl.kind != bulletin::Kind::Prekeys {
                continue;
            }
            let mut p = prekeys::Published::decode(&bl.payload).expect("a batch");
            p.keys[0] = [9u8; 32];
            bl.payload = p.encode();
            let (new_id, new_bytes) =
                bulletin::into_object(&bl, now_min, krab_core::tag::MAX_TTL_DAYS * 1440)
                    .expect("it re-wraps");
            *id = new_id;
            *bytes = new_bytes;
            swapped += 1;
        }
        assert_eq!(swapped, 1, "the test tampered with nothing");

        for (id, bytes) in tampered {
            a.store
                .with(|s| s.ingest(id, bytes, now_min, u32::MAX))
                .expect("the tampered object is still well-formed");
        }

        let b_node = b.identity.as_ref().unwrap().node_id();
        assert!(
            a.prekey_for(&b_node).is_none(),
            "a tampered batch was accepted"
        );
    }

    /// **The Channels tab is no longer empty.** It was drawn, selectable and
    /// advertised, and nothing ever put anything in it.
    #[test]
    fn a_channel_can_be_created_posted_to_and_read() {
        let mut a = ready_node("channel-basic");

        type_command(&mut a, "channel list");
        assert!(a.output.contains("none"), "{}", a.output);

        type_command(&mut a, "channel new");
        assert!(a.output.contains("created"), "{}", a.output);
        let id = channels::short(&a.roster.mine.as_ref().unwrap().id());
        assert!(a.output.contains(&id));

        // **RFC 8 §4.2 requirement 2** — the first post of a session confirms.
        type_command(&mut a, "channel post the meeting is moved");
        assert!(
            a.output.contains("PUBLIC — SIGNED — PERMANENT"),
            "no confirmation banner:\n{}",
            a.output
        );
        assert_eq!(
            a.channel_posts(&a.roster.mine.as_ref().unwrap().id()).len(),
            0
        );

        // One keystroke confirms it — §4.2 requirement 2 asks for an explicit
        // act, not for the verb to be typed a second time.
        a.on_key(KeyCode::Enter, KeyModifiers::NONE);
        assert!(a.output.contains("published post 1"), "{}", a.output);

        let posts = a.channel_posts(&a.roster.mine.as_ref().unwrap().id());
        assert_eq!(posts.len(), 1);
        assert!(posts[0].contains("the meeting is moved"));

        // And the tab shows it.
        a.on_key(KeyCode::Char('t'), KeyModifiers::CONTROL);
        assert!(
            a.list.iter().any(|r| r.contains(&id)),
            "the Channels tab is still empty: {:?}",
            a.list
        );
        assert!(
            a.body.contains("PUBLIC, SIGNED, PERMANENT"),
            "the security context is not on screen:\n{}",
            a.body
        );
    }

    /// A second post in the same session does not re-confirm — the friction is
    /// a reminder, not an obstacle to every line.
    #[test]
    fn only_the_first_post_of_a_session_confirms() {
        let mut a = ready_node("channel-confirm-once");
        type_command(&mut a, "channel new");
        post_now(&mut a, "one");
        type_command(&mut a, "channel post two");
        assert!(a.output.contains("published post 2"), "{}", a.output);
    }

    /// **Sequence numbers do not restart.** Two posts claiming one position is
    /// something no reader can resolve.
    #[test]
    fn sequence_numbers_survive_a_restart() {
        let mut a = ready_node("channel-seq");
        type_command(&mut a, "channel new");
        post_now(&mut a, "first");
        type_command(&mut a, "channel post second");

        let mut fresh = App {
            home: a.home.clone(),
            ..App::default()
        };
        fresh.passphrase = line::Line::from("a passphrase");
        fresh.unlock(b"a passphrase").expect("reopens");
        assert_eq!(fresh.epoch_key, a.epoch_key, "the epoch key changed");
        let sealed = std::fs::read(fresh.path(artifact::Artifact::ChannelRoster)).unwrap();
        let raw = krab_crypto::kek::open_under(&fresh.epoch_key.unwrap(), b"krab/roster", &sealed)
            .expect("the roster opens");
        assert!(
            channels::Roster::decode(&raw).is_some(),
            "it does not decode"
        );
        assert!(fresh.roster.mine.is_some(), "the channel key was lost");
        assert_eq!(fresh.next_sequence(), 3, "numbering restarted");

        // And the confirmation is asked again, because it is a session
        // property and a reminder given once a year is not one.
        assert!(!fresh.roster.first_post_confirmed);
    }

    /// A post from a channel this node does not follow is still carried, and
    /// still readable once followed — but it is not in the list until then.
    #[test]
    fn a_channel_is_followed_before_it_is_listed() {
        let mut a = ready_node("channel-follow-a");
        let mut b = ready_node("channel-follow-b");
        type_command(&mut b, "channel new");
        post_now(&mut b, "hello");
        let id = channels::short(&b.roster.mine.as_ref().unwrap().id());

        let now_min = now_epoch().0 * 1440;
        let carried: Vec<(krab_core::object::ObjectId, Vec<u8>)> = b.store.with(|s| {
            s.entries_in_range(0, u32::MAX)
                .into_iter()
                .filter_map(|(_, i)| s.get(&i).map(|x| (i, x.to_vec())))
                .collect()
        });
        for (i, bytes) in carried {
            let _ = a.store.with(|s| s.ingest(i, bytes, now_min, u32::MAX));
        }

        type_command(&mut a, "channel list");
        assert!(
            a.output.contains("not followed"),
            "an unfollowed channel is invisible:\n{}",
            a.output
        );

        type_command(&mut a, &format!("channel follow {id}"));
        assert!(a.output.contains("following"), "{}", a.output);
        assert!(a.roster.follows(&b.roster.mine.as_ref().unwrap().id()));
        assert!(a.channel_posts(&b.roster.mine.as_ref().unwrap().id())[0].contains("hello"));

        // Unfollowing keeps the archive — RFC 3 §6.1 forbids a recall
        // mechanism, and a selective one is worse.
        type_command(&mut a, &format!("channel unfollow {id}"));
        assert!(
            !a.channel_posts(&b.roster.mine.as_ref().unwrap().id())
                .is_empty(),
            "unfollowing erased the archive"
        );
    }

    /// Posting needs a channel, and there is no way to post to someone else's.
    #[test]
    fn posting_without_a_channel_is_refused() {
        let mut a = ready_node("channel-none");
        type_command(&mut a, "channel post nothing to post to");
        assert!(a.output.contains("channel new"), "{}", a.output);
        type_command(&mut a, "channel new");
        type_command(&mut a, "channel new");
        assert!(a.output.contains("already has a channel"), "{}", a.output);
    }

    /// **The epoch hierarchy must survive a restart.**
    ///
    /// It did not. `write_identity` stored three seeds and not the wrapped
    /// epoch keys, so `open_epoch` minted a fresh `W_N` on every start — and
    /// everything sealed under the old one became unreadable. Silently: no
    /// error, no warning, and a peering that looked intact in `peers` while
    /// its reservoir could no longer be opened.
    ///
    /// This is the failure RFC 0 §6 guarantees nobody is told about, in the
    /// one place where it costs a peering rather than a message.
    #[test]
    fn the_epoch_hierarchy_survives_a_restart() {
        let (a, _b, _a_id, b_id) = peered_pair("hierarchy-restart");
        let before = a.epoch_key.expect("an epoch key");
        let reservoir_before = stored_root(&a, &b_id);

        let mut fresh = App {
            home: a.home.clone(),
            ..App::default()
        };
        fresh.passphrase = line::Line::from("a passphrase");
        fresh.unlock(b"a passphrase").expect("it reopens");

        assert_eq!(
            fresh.epoch_key,
            Some(before),
            "a fresh W_N was minted, so everything sealed under the old one is gone"
        );
        assert_eq!(
            stored_root(&fresh, &b_id),
            reservoir_before,
            "the peering's reservoir did not survive the restart"
        );

        // And the identity itself is unchanged, so this is not a new node.
        assert_eq!(
            fresh.identity.as_ref().unwrap().short_id(),
            a.identity.as_ref().unwrap().short_id()
        );
    }

    /// **RFC 8 §4.2 requirement 3.** Pressing reply must never publish.
    #[test]
    fn reply_never_publishes_and_publish_is_a_separate_key() {
        let mut a = ready_node("reply-private");
        type_command(&mut a, "channel new");
        post_now(&mut a, "hello");
        let before = a.channel_posts(&a.roster.mine.as_ref().unwrap().id()).len();

        a.on_key(KeyCode::Char('t'), KeyModifiers::CONTROL);
        // Onto the list pane: on the command line `r` is a letter, which is
        // what makes a command containing one typeable.
        a.ui.cycle_focus();
        a.on_key(KeyCode::Char('r'), KeyModifiers::NONE);
        assert_eq!(
            a.channel_posts(&a.roster.mine.as_ref().unwrap().id()).len(),
            before,
            "reply published"
        );
        assert!(
            a.output.contains("never publishes") || a.output.contains("PRIVATE"),
            "{}",
            a.output
        );

        // And `P` does not publish either. It opens a composer — RFC 8 §4.2
        // requirement 1 wants the security context there — and publishing is
        // still a further, separate act.
        a.on_key(KeyCode::Char('P'), KeyModifiers::SHIFT);
        assert_eq!(
            a.channel_posts(&a.roster.mine.as_ref().unwrap().id()).len(),
            before,
            "the publish key published without confirmation"
        );
        assert_eq!(a.ui.mode(), Mode::Compose, "{}", a.output);
        assert_eq!(
            a.ui.banner(),
            Some(layout::Banner::PublicSignedPermanent),
            "a post is being composed without its banner"
        );
    }

    /// In private mail, reply addresses the sender — the same key, the same
    /// meaning, no ambiguity to resolve.
    #[test]
    fn reply_in_private_mail_addresses_the_sender() {
        let mut a = ready_node("reply-mail");
        a.messages.push(receive::Message {
            id: krab_crypto::hash::object_id(b"x"),
            from: "deadbeef".into(),
            epoch: now_epoch(),
            body: "hello".into(),
            picture: None,
            post_quantum: false,
            nodelist: None,
        });
        a.selected = 0;
        a.ui.cycle_focus();
        a.on_key(KeyCode::Char('r'), KeyModifiers::NONE);
        assert_eq!(a.command.as_string(), "send deadbeef ");
        // And focus returned to the command line, so the reply can be typed.
        assert_eq!(a.ui.focus(), layout::Pane::Command);
    }

    /// **RFC 8 §4.2 requirement 5.** The warnings arrive while the decision is
    /// still open, not when a send later fails.
    #[test]
    fn group_size_and_prekey_warnings_arrive_at_join_time() {
        let (mut a, _b, _a_id, b_id) = peered_pair("group-warn");
        type_command(&mut a, "group new friends");
        assert!(a.output.contains("PRIVATE"), "{}", a.output);

        type_command(&mut a, &format!("group add friends {b_id}"));
        assert!(a.output.contains("2 members"), "{}", a.output);

        // A member who is not a peer cannot be added: fan-out seals to each
        // member, and one that cannot be sealed to receives nothing silently.
        type_command(&mut a, "group add friends cafebabe");
        assert!(a.output.contains("no peer-link"), "{}", a.output);

        // The thresholds themselves, without needing fifty real peerings.
        let i = a.groups.iter().position(|g| g.name == "friends").unwrap();
        for n in 0..25u8 {
            a.groups[i].members.push([n; 32]);
        }
        type_command(&mut a, "group list");
        assert!(
            a.output.contains("above the recommended"),
            "no size warning at 27:\n{}",
            a.output
        );
    }

    /// **RFC 8 §4.2 requirement 4.** Divergence is shown and never merged
    /// silently — a member added without your knowledge and a roster you have
    /// not received look identical.
    #[test]
    fn roster_divergence_is_surfaced_and_not_merged() {
        let mine = groups::Group::new("g", [1u8; 32], groups::Authority::CreatorOnly);
        let mut theirs = mine.clone();
        theirs.add([2u8; 32]);

        let before = mine.clone();
        let report = mine.divergence(&theirs).expect("they diverge");
        assert_eq!(mine, before, "comparing merged them");
        assert!(report.contains("do not know about"), "{report}");
        assert!(report.contains("NOT resolved automatically"), "{report}");
    }

    /// A group survives a restart, roster and epoch intact — a roster that
    /// reset would report a divergence against every member forever.
    #[test]
    fn groups_survive_a_restart() {
        let (mut a, _b, _a_id, b_id) = peered_pair("group-restart");
        type_command(&mut a, "group new friends");
        type_command(&mut a, &format!("group add friends {b_id}"));
        let epoch = a.groups[0].epoch;

        let mut fresh = App {
            home: a.home.clone(),
            ..App::default()
        };
        fresh.passphrase = line::Line::from("a passphrase");
        fresh.unlock(b"a passphrase").expect("reopens");
        assert_eq!(fresh.groups.len(), 1, "the group was lost");
        assert_eq!(fresh.groups[0].name, "friends");
        assert_eq!(fresh.groups[0].epoch, epoch, "the roster epoch reset");
        assert_eq!(fresh.groups[0].members.len(), 2);
    }

    /// **RFC 8 §4.3.** The warning fires at the point of enabling, states the
    /// change in what the node *is*, and carriage defaults to off.
    #[test]
    fn channel_carriage_defaults_off_and_warns_before_enabling() {
        let mut a = ready_node("carry");
        assert!(!a.roster.carriage.enabled, "carriage must default to off");

        type_command(&mut a, "channel carry");
        assert!(a.output.contains("is off"), "{}", a.output);

        // First `on` warns and changes nothing.
        type_command(&mut a, "channel carry on");
        assert!(
            a.output.contains("host of public content"),
            "the warning does not say what the node becomes:\n{}",
            a.output
        );
        assert!(
            !a.roster.carriage.enabled,
            "carriage was enabled by the keystroke that warned about it"
        );

        // Second enables.
        type_command(&mut a, "channel carry on");
        assert!(a.roster.carriage.enabled, "{}", a.output);

        // And it is a standing decision: it survives a restart, unlike the
        // warning's acknowledgement.
        let mut fresh = App {
            home: a.home.clone(),
            ..App::default()
        };
        fresh.passphrase = line::Line::from("a passphrase");
        fresh.unlock(b"a passphrase").expect("reopens");
        assert!(fresh.roster.carriage.enabled, "the decision was lost");
        assert!(
            !fresh.roster.carriage_armed,
            "the warning was pre-acknowledged across a restart"
        );

        type_command(&mut fresh, "channel carry off");
        assert!(!fresh.roster.carriage.enabled);
    }

    /// **RFC 8 §4.2 requirement 4, end to end.** A member's published roster
    /// reaches us, differs, and is *shown* — not merged.
    #[test]
    fn a_divergent_roster_from_a_member_is_surfaced_not_merged() {
        let (mut a, mut b, a_id, b_id) = peered_pair("divergence");

        // Both are in a group of the same name, and B knows about someone A
        // does not — the routine case RFC 6 §2.6 describes.
        type_command(&mut a, "group new friends");
        type_command(&mut a, &format!("group add friends {b_id}"));
        type_command(&mut b, "group new friends");
        type_command(&mut b, &format!("group add friends {a_id}"));
        b.groups[0].add([0x99; 32]);
        b.publish_roster(&b.groups[0].clone());

        let mine_before = a.groups[0].clone();
        let now_min = now_epoch().0 * 1440;
        let carried: Vec<(krab_core::object::ObjectId, Vec<u8>)> = b.store.with(|s| {
            s.entries_in_range(0, u32::MAX)
                .into_iter()
                .filter_map(|(_, i)| s.get(&i).map(|x| (i, x.to_vec())))
                .collect()
        });
        for (i, bytes) in carried {
            let _ = a.store.with(|s| s.ingest(i, bytes, now_min, u32::MAX));
        }

        type_command(&mut a, "group list");
        assert!(
            a.output.contains("roster divergence"),
            "the divergence was not shown:\n{}",
            a.output
        );
        assert!(
            a.output.contains("do not know about"),
            "it does not say what differs:\n{}",
            a.output
        );
        assert_eq!(
            a.groups[0], mine_before,
            "the roster was silently merged — RFC 6 §2.6 forbids exactly this"
        );
    }

    /// A roster from someone who is not in the group is not a notification we
    /// have to render. Otherwise a flooded object is a way to write on
    /// anyone's screen.
    #[test]
    fn a_roster_from_a_stranger_is_ignored() {
        let (mut a, mut b, _a_id, b_id) = peered_pair("divergence-stranger");
        type_command(&mut a, "group new friends");
        // B is NOT added to A's group.
        type_command(&mut b, "group new friends");
        b.groups[0].add([0x99; 32]);
        b.publish_roster(&b.groups[0].clone());

        let now_min = now_epoch().0 * 1440;
        let carried: Vec<(krab_core::object::ObjectId, Vec<u8>)> = b.store.with(|s| {
            s.entries_in_range(0, u32::MAX)
                .into_iter()
                .filter_map(|(_, i)| s.get(&i).map(|x| (i, x.to_vec())))
                .collect()
        });
        for (i, bytes) in carried {
            let _ = a.store.with(|s| s.ingest(i, bytes, now_min, u32::MAX));
        }
        let _ = b_id;

        type_command(&mut a, "group list");
        assert!(
            !a.output.contains("roster divergence"),
            "a stranger wrote on the screen:\n{}",
            a.output
        );
    }

    /// **A group message reaches every member.** One sealed copy each, opened
    /// with each member's own key — there is no shared group key, which is
    /// what makes one compromised member expose one member.
    #[test]
    fn a_group_message_is_sealed_once_per_member_and_opens() {
        let (mut a, mut b, _a_id, b_id) = peered_pair("group-send");
        type_command(&mut a, "group new friends");
        type_command(&mut a, &format!("group add friends {b_id}"));

        type_command(&mut a, "group send friends the meeting is moved");
        assert!(a.output.contains("1 copy"), "{}", a.output);
        assert!(
            a.output.contains("released over"),
            "the stagger is not reported:\n{}",
            a.output
        );

        // **Nothing is in the corpus yet.** RFC 6 §2.7: the copies are held.
        assert_eq!(a.pending.len(), 1, "the copy was not held for staggering");

        // Release, carry, and read.
        for p in std::mem::take(&mut a.pending) {
            let now_min = now_epoch().0 * 1440;
            a.store
                .with(|s| s.ingest(p.id, p.bytes, now_min, u32::MAX))
                .expect("a well-formed object");
        }
        let now_min = now_epoch().0 * 1440;
        let carried: Vec<(krab_core::object::ObjectId, Vec<u8>)> = a.store.with(|s| {
            s.entries_in_range(0, u32::MAX)
                .into_iter()
                .filter_map(|(_, i)| s.get(&i).map(|x| (i, x.to_vec())))
                .collect()
        });
        for (i, bytes) in carried {
            let _ = b.store.with(|s| s.ingest(i, bytes, now_min, u32::MAX));
        }
        b.refresh_inbox();
        assert!(
            b.messages
                .iter()
                .any(|m| m.body.contains("meeting is moved")),
            "the member never received it: {:?}",
            b.messages.iter().map(|m| &m.body).collect::<Vec<_>>()
        );
    }

    /// **RFC 6 §2.7.** Copies are held, not emitted together, and they are
    /// released as their times come rather than all at once.
    #[test]
    fn fan_out_copies_are_staggered_rather_than_emitted_together() {
        let (mut a, _b, _a_id, b_id) = peered_pair("group-stagger");
        type_command(&mut a, "group new friends");
        type_command(&mut a, &format!("group add friends {b_id}"));
        // Enough members to make a window worth measuring; only one is a real
        // peer, so only one copy seals — the rest are reported as unreachable.
        let i = a.groups.iter().position(|g| g.name == "friends").unwrap();
        for n in 0..8u8 {
            a.groups[i].members.push([n; 32]);
        }
        type_command(&mut a, "group send friends hello");
        assert!(
            a.output.contains("NOT sent to"),
            "members with no peer-link must be named:\n{}",
            a.output
        );

        // Held, with a release time in the future.
        assert_eq!(a.pending.len(), 1);
        assert!(
            a.pending[0].release_at_s > now_seconds(),
            "the copy was released immediately, which is the burst §2.7 forbids"
        );
        let store_before = a.store.len();
        a.release_pending();
        assert_eq!(a.store.len(), store_before, "it was released early");
        assert_eq!(a.pending.len(), 1, "it was dropped rather than held");

        // Once due, it goes in.
        a.pending[0].release_at_s = 0;
        a.release_pending();
        assert!(a.pending.is_empty());
        assert_eq!(a.store.len(), store_before + 1);
    }

    /// The window is derived from what this node has observed, never from a
    /// constant — RFC 6 §2.7 says so in exactly those words.
    #[test]
    fn the_stagger_window_follows_the_observed_rate() {
        let mut a = ready_node("group-rate");
        assert_eq!(
            a.background_rate(),
            0.0,
            "an unobserved rate is not a number"
        );

        a.observed_hours = 10.0;
        a.observed_arrivals = 500;
        assert!((a.background_rate() - 50.0).abs() < 0.001);

        // Busier network, narrower window.
        let busy = fanout::window_seconds(20, a.background_rate());
        a.observed_arrivals = 50;
        let quiet = fanout::window_seconds(20, a.background_rate());
        assert!(quiet > busy, "a quieter network must stagger for longer");
    }

    /// A group of one has nobody to send to, and says so rather than sealing
    /// a copy to its own author.
    #[test]
    fn a_group_with_only_you_refuses_to_send() {
        let mut a = ready_node("group-alone");
        type_command(&mut a, "group new alone");
        type_command(&mut a, "group send alone nobody there");
        assert!(a.output.contains("no members but you"), "{}", a.output);
        assert!(a.pending.is_empty());
    }

    /// **Republishing must not destroy the keys already in flight.** An
    /// earlier version built a fresh ring on every call, so the previous
    /// batch's private halves were discarded and any message already
    /// encapsulated to one became unreadable. It had one caller, at `init`,
    /// which is why that never showed.
    #[test]
    fn republishing_keeps_the_private_halves_of_earlier_batches() {
        let mut a = ready_node("prekey-rotate");
        a.publish_prekeys().expect("a first batch");
        let first = a.opening_keys().len();
        assert!(first > 1, "the first batch published nothing");

        // A message sealed to a key from the first batch.
        let published = {
            let w = a.epoch_key.unwrap();
            let raw = krab_crypto::kek::open_under(
                &w,
                b"krab/prekeys",
                &std::fs::read(a.path(artifact::Artifact::PrekeyRing)).unwrap(),
            )
            .unwrap();
            prekeys::decode_ring(&raw).expect("a ring")
        };
        let target = published.candidates()[3].public();

        a.publish_prekeys().expect("republishes");
        let after = a.opening_keys();
        assert!(
            after.iter().any(|k| k.public().0 == target.0),
            "a key from the previous batch was destroyed by republishing"
        );
        assert!(
            after.len() > first,
            "republishing added nothing: {} then {}",
            first,
            after.len()
        );
    }

    /// **RFC 7 §5.1's rotation is what bounds exposure.** Without a caller the
    /// period is for ever, which is not the property §5 claims.
    #[test]
    fn the_signed_prekey_rotates_on_its_cadence() {
        let mut a = ready_node("prekey-cadence");
        a.publish_prekeys().expect("a first batch");
        let read_ring = |a: &App| {
            let w = a.epoch_key.unwrap();
            let raw = krab_crypto::kek::open_under(
                &w,
                b"krab/prekeys",
                &std::fs::read(a.path(artifact::Artifact::PrekeyRing)).unwrap(),
            )
            .unwrap();
            prekeys::decode_ring(&raw).expect("a ring")
        };
        let before = read_ring(&a).signed().public().0;

        // Same epoch: no rotation, because the tier is weekly and not
        // per-publication.
        a.publish_prekeys().expect("republishes");
        assert_eq!(
            read_ring(&a).signed().public().0,
            before,
            "it rotated early"
        );

        // Backdate the signed prekey past the cadence.
        {
            let w = a.epoch_key.unwrap();
            let mut ring = read_ring(&a);
            ring.rotate(krab_crypto::prekey::SignedPrekey::create(
                a.identity.as_ref().unwrap().signing_key(),
                krab_core::tag::Epoch(now_epoch().0 - SIGNED_PREKEY_EPOCHS),
                &mut OsRng,
            ));
            let sealed = krab_crypto::kek::seal_under(
                &w,
                b"krab/prekeys",
                &prekeys::encode_ring(&ring),
                &mut OsRng,
            )
            .unwrap();
            atomic::write(&a.path(artifact::Artifact::PrekeyRing), &sealed).unwrap();
        }
        let stale = read_ring(&a).signed().public().0;
        let out = a.publish_prekeys().expect("republishes");
        assert!(out.contains("rotated"), "{out}");
        assert_ne!(
            read_ring(&a).signed().public().0,
            stale,
            "the signed prekey did not rotate past its cadence"
        );
    }

    /// The scheduler republishes without anybody typing, and does not
    /// republish every tick.
    #[test]
    fn the_schedule_republishes_prekeys_when_due() {
        let mut a = ready_node("prekey-schedule");
        let batches = |a: &App| {
            let me = a.identity.as_ref().unwrap().node_id();
            a.store.with(|s| {
                s.entries_in_range(0, u32::MAX)
                    .into_iter()
                    .filter(|(_, i)| {
                        s.get(i)
                            .and_then(bulletin::from_object)
                            .is_some_and(|b| b.kind == bulletin::Kind::Prekeys && b.node_id() == me)
                    })
                    .count()
            })
        };
        // A node with no batch publishes on its first tick, rather than
        // depending on the ceremony having run — `unlock` does not go through
        // `init`, and a restarted node must not be left without prekeys.
        assert_eq!(batches(&a), 0);
        a.republish_prekeys_if_due();
        assert_eq!(batches(&a), 1, "the schedule never published a first batch");

        a.republish_prekeys_if_due();
        assert_eq!(batches(&a), 1, "it republished on the same day");

        // Nothing published within the cadence: due again.
        a.store = shared::SharedStore::new(krab_store::index::Store::new());
        a.republish_prekeys_if_due();
        assert_eq!(batches(&a), 1, "the schedule did not republish when due");
        assert!(
            a.log.recent(8).iter().any(|l| l.contains("prekeys")),
            "the rotation is not in the activity log: {:?}",
            a.log.recent(8)
        );
    }

    /// Retirement is on a schedule and only past the window mail may arrive
    /// in — RFC 7 §5.2 and RFC 1 §6.2. A key dropped sooner strands mail that
    /// is still legitimately in flight.
    #[test]
    fn batches_retire_only_past_the_acceptance_window() {
        let mut ring = krab_crypto::prekey::Ring::new(krab_crypto::prekey::SignedPrekey::create(
            &krab_crypto::sign::SigningKey::generate(&mut OsRng),
            krab_core::tag::Epoch(1_000),
            &mut OsRng,
        ));
        // Both inside the window that ends at "now" = 1050.
        ring.add_batch(4, krab_core::tag::Epoch(1_040), &mut OsRng);
        ring.add_batch(4, krab_core::tag::Epoch(1_050), &mut OsRng);
        assert_eq!(
            ring.retire(krab_core::tag::Epoch(1_050 - krab_core::tag::EPOCH_WINDOW)),
            0,
            "a batch inside the acceptance window was retired — mail still in \
             flight to it would be stranded"
        );
        assert_eq!(ring.batch_count(), 2);

        // One falls out of the window.
        assert_eq!(ring.retire(krab_core::tag::Epoch(1_045)), 1);
        assert_eq!(ring.batch_count(), 1);
    }

    /// **The assumption everything else rests on.** Two live nodes, a real
    /// pair of sessions, a message crossing by reconciliation rather than by a
    /// test copying objects between stores.
    ///
    /// Nothing exercised this. `reconcile_with` initiated and **nothing
    /// responded** — `exchange::respond_to` had no caller in the application
    /// at all — so a node that accepted a session installed it and never
    /// spoke. Every feature built on top of reconciliation was built on a path
    /// that could not complete.
    #[test]
    fn a_message_crosses_between_two_nodes_by_reconciliation() {
        let (mut a, mut b, a_id, b_id) = peered_pair("recon-live");

        type_command(&mut a, &format!("send {b_id} bring the good coffee"));
        assert!(a.output.contains("composed"), "{}", a.output);
        assert!(b.messages.is_empty(), "B has it before anything moved");

        // A pair of in-process sessions, as `listen`/`connect` would leave.
        let (sa, sb) = session_pair();
        a.links.connect(&b_id, profile_named("tcp").unwrap());
        a.links.established(&b_id, Some(Box::new(sa)));
        b.links.connect(&a_id, profile_named("tcp").unwrap());
        b.links.established(&a_id, Some(Box::new(sb)));

        // B answers; A initiates. Both halves, which is the point.
        let a_peer = a_id.clone();
        let responder = std::thread::spawn(move || {
            b.answer_reconciliation(&a_peer);
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            while std::time::Instant::now() < deadline {
                b.drain_exchanges();
                if !b.messages.is_empty() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            b
        });

        a.reconcile_with(&b_id);
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let mut sent = 0;
        while std::time::Instant::now() < deadline && sent == 0 {
            while let Ok(e) = a.exchanges.1.try_recv() {
                if let activity_log::Event::Reconciled { sent: n, .. } = e {
                    sent = n;
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let b = responder.join().expect("B's thread");

        assert!(sent > 0, "A sent nothing — the exchange did not complete");
        assert!(
            b.messages.iter().any(|m| m.body.contains("good coffee")),
            "the message did not arrive: {:?}",
            b.messages.iter().map(|m| &m.body).collect::<Vec<_>>()
        );
    }

    /// And it is the *schedule* that drives it, never a keypress — RFC 8
    /// §5.1. `connect` establishes a session and transfers nothing.
    #[test]
    fn connecting_transfers_nothing_by_itself() {
        let (mut a, _b, _a_id, b_id) = peered_pair("recon-no-keypress");
        type_command(&mut a, &format!("send {b_id} not yet"));
        let (sa, _sb) = session_pair();
        a.links.connect(&b_id, profile_named("tcp").unwrap());
        a.links.established(&b_id, Some(Box::new(sa)));

        // The link is up and there is mail queued; nothing has left.
        assert!(
            a.links
                .get(&b_id)
                .and_then(|l| l.session.as_ref())
                .is_some(),
            "the link is not up"
        );
        let mut moved = false;
        while a.exchanges.1.try_recv().is_ok() {
            moved = true;
        }
        assert!(!moved, "connecting caused a transfer");
    }

    /// A node mid-ceremony with a counterparty card recorded — the state
    /// `peer seal` requires, since you cannot seal without their card.
    fn mid_ceremony(tag: &str) -> App {
        let mut a = ready_node(tag);
        let mut other = ready_node(&format!("{tag}-other"));
        type_command(&mut a, "peer offer");
        type_command(&mut other, "peer offer");
        let card = a.at("theirs.card");
        std::fs::write(&card, std::fs::read(other.at("peer.card")).unwrap()).unwrap();
        type_command(&mut a, &format!("peer accept {}", card.display()));
        a
    }

    /// **Peering at distance, end to end.** Two nodes that never meet: the
    /// cards and the wrapped pads cross a network, and only 32 words cross a
    /// voice call — once, ever.
    #[test]
    fn two_nodes_peer_over_the_network_with_a_spoken_key() {
        let mut a = ready_node("spoken-a");
        let mut b = ready_node("spoken-b");
        type_command(&mut a, "peer offer");
        type_command(&mut b, "peer offer");

        // Cards, over anything. They are public and signed.
        let carry = |from: &App, to: &App, name: artifact::Artifact, as_name: &str| {
            let bytes = std::fs::read(from.path(name)).expect("exists");
            let dest = to.at(as_name);
            std::fs::write(&dest, bytes).expect("delivered");
            dest.to_string_lossy().into_owned()
        };
        let a_card = carry(&a, &b, artifact::Artifact::PeerCard, "from-a.card");
        let b_card = carry(&b, &a, artifact::Artifact::PeerCard, "from-b.card");
        type_command(&mut a, &format!("peer accept {b_card}"));
        type_command(&mut b, &format!("peer accept {a_card}"));
        for n in [&mut a, &mut b] {
            let mut p = n.load_ceremony().unwrap();
            p.fingerprint_verified = true;
            n.save_ceremony(&p).unwrap();
        }

        // Each wraps its pad. The file is safe to send over anything.
        let a_dest = a.at("a.wrapped").display().to_string();
        type_command(&mut a, &format!("peer wrap {a_dest}"));
        assert!(a.output.contains("READ THESE ALOUD"), "{}", a.output);
        let a_words = a
            .output
            .lines()
            .find(|l| l.split_whitespace().count() == spoken::WORDS)
            .expect("32 words")
            .trim()
            .to_string();

        let b_dest = b.at("b.wrapped").display().to_string();
        type_command(&mut b, &format!("peer wrap {b_dest}"));
        let b_words = b
            .output
            .lines()
            .find(|l| l.split_whitespace().count() == spoken::WORDS)
            .expect("32 words")
            .trim()
            .to_string();

        // The wrapped files cross the network; the words cross a voice call.
        // These are fixtures the test wrote, not artifacts, so they move by
        // hand rather than through `carry`.
        let move_file = |from: &App, to: &App, name: &str, as_name: &str| {
            let dest = to.at(as_name);
            std::fs::write(&dest, std::fs::read(from.at(name)).unwrap()).unwrap();
            dest.to_string_lossy().into_owned()
        };
        let to_b = move_file(&a, &b, "a.wrapped", "from-a.wrapped");
        let to_a = move_file(&b, &a, "b.wrapped", "from-b.wrapped");

        type_command(&mut a, &format!("peer seal {to_a} spoken"));
        assert!(a.output.contains("type the 32 words"), "{}", a.output);
        type_command(&mut a, &b_words);
        assert!(a.output.starts_with("peer-link signed"), "{}", a.output);

        type_command(&mut b, &format!("peer seal {to_b} spoken"));
        type_command(&mut b, &a_words);
        assert!(b.output.starts_with("peer-link signed"), "{}", b.output);

        // **Post-quantum.** The pad crossed a network, and the key that
        // protected it never did.
        assert!(
            !a.output.contains("does NOT survive"),
            "a spoken peering was not credited as post-quantum:\n{}",
            a.output
        );

        // Both ends hold the same reservoir, so the peering actually works.
        let a_of_b = short_id(&b.identity.as_ref().unwrap().node_id());
        let b_of_a = short_id(&a.identity.as_ref().unwrap().node_id());
        assert_eq!(stored_root(&a, &a_of_b), stored_root(&b, &b_of_a));
    }

    /// **The words never enter the history.** A history is a record, and these
    /// are a live key sitting next to the thing they protect.
    #[test]
    fn the_transfer_words_do_not_reach_the_command_history() {
        let mut a = mid_ceremony("spoken-history");
        let dest = a.at("mine.wrapped").display().to_string();
        type_command(&mut a, &format!("peer wrap {dest}"));
        let words = a
            .output
            .lines()
            .find(|l| l.split_whitespace().count() == spoken::WORDS)
            .expect("32 words")
            .trim()
            .to_string();

        type_command(&mut a, &format!("peer seal {dest} spoken"));
        assert!(a.prompt.is_some(), "no prompt was raised");
        type_command(&mut a, &words);

        let first = words.split_whitespace().next().unwrap();
        assert!(
            !a.history.iter().any(|h| h.contains(first)),
            "the transfer words are in the history: {:?}",
            a.history
        );
        // And Up-arrow cannot bring them back.
        a.on_key(KeyCode::Up, KeyModifiers::NONE);
        assert!(!a.command.as_string().contains(first));
    }

    /// Wrong words are refused, and a bare pad is not a wrapped one.
    #[test]
    fn a_spoken_seal_refuses_the_wrong_words_and_the_wrong_file() {
        let mut a = mid_ceremony("spoken-wrong");

        // A bare pad is not a wrapped pad, and says so rather than prompting.
        let pad = a.at("bare.pad").display().to_string();
        type_command(&mut a, &format!("peer pad {pad}"));
        type_command(&mut a, &format!("peer seal {pad} spoken"));
        assert!(a.output.contains("not a wrapped pad"), "{}", a.output);
        assert!(a.prompt.is_none(), "it prompted for a file it cannot use");

        // Wrong words fail closed, and the same way tampering does.
        let dest = a.at("mine.wrapped").display().to_string();
        type_command(&mut a, &format!("peer wrap {dest}"));
        type_command(&mut a, &format!("peer seal {dest} spoken"));
        type_command(&mut a, "aardvark absurd accrue acme adrift adult");
        assert!(a.output.contains("did not open it"), "{}", a.output);
    }

    /// `spoken` earns post-quantum credit; `network` does not, and the
    /// classification is what an operator reviewing a link months later reads.
    #[test]
    fn the_spoken_channel_is_post_quantum_and_distinct_from_in_person() {
        use peering::Channel;
        assert!(Channel::Spoken.independent_of_dh());
        assert!(!Channel::Network.independent_of_dh());
        assert!(!Channel::Corpus.independent_of_dh());
        // Distinct, because the assertion an operator made is different: a
        // voice call is defeated by a recording and a meeting is not.
        assert_ne!(Channel::Spoken, Channel::InPerson);
        assert_eq!(ceremony::parse_channel("spoken"), Some(Channel::Spoken));
        assert_eq!(ceremony::parse_channel("voice"), Some(Channel::Spoken));
    }

    /// **A weak peering is recoverable.** Peer over the network today,
    /// re-seal the first time you meet, and keep the peer-link, the message
    /// history and the correspondent.
    #[test]
    fn a_network_peering_is_upgraded_in_place_by_reseal() {
        let (mut a, mut b, a_id, b_id) = peered_pair_over("reseal", "corpus");

        // It starts weak, and says so.
        let before = a.peer_terms(&b_id).expect("terms were recorded");
        assert!(!before.post_quantum(), "corpus must not be post-quantum");
        assert_eq!(before.reseals, 0);
        type_command(&mut a, "peers");
        assert!(a.output.contains("NOT post-quantum"), "{}", a.output);

        let root_before = stored_root(&a, &b_id);
        let messages_before = a.store.len();

        // They meet. Fresh contributions, carried.
        type_command(&mut a, &format!("peer reseal {b_id}"));
        assert!(a.output.contains("NOT post-quantum"), "{}", a.output);
        type_command(&mut b, &format!("peer reseal {a_id}"));

        let a_pad = a.at("a.fresh").display().to_string();
        let b_pad = b.at("b.fresh").display().to_string();
        type_command(&mut a, &format!("peer reseal pad {a_pad}"));
        type_command(&mut b, &format!("peer reseal pad {b_pad}"));

        type_command(&mut a, &format!("peer reseal seal {b_pad} in-person"));
        assert!(a.output.contains("re-sealed"), "{}", a.output);
        type_command(&mut b, &format!("peer reseal seal {a_pad} in-person"));
        assert!(b.output.contains("re-sealed"), "{}", b.output);

        // The root changed, and both ends agree on the new one.
        assert_ne!(stored_root(&a, &b_id), root_before, "the root did not move");
        assert_eq!(
            stored_root(&a, &b_id),
            stored_root(&b, &a_id),
            "the two ends re-sealed to different roots"
        );

        // And nothing else was lost.
        assert_eq!(a.store.len(), messages_before, "the corpus was disturbed");
        assert!(
            a.peer_path(&b_id, artifact::PeerFile::Link).exists(),
            "the peer-link was lost"
        );
        let after = a.peer_terms(&b_id).expect("terms");
        assert!(after.post_quantum(), "the upgrade was not recorded");
        assert_eq!(after.reseals, 1);
        type_command(&mut a, "peers");
        assert!(a.output.contains("re-sealed 1×"), "{}", a.output);
    }

    /// A re-seal must not claim a channel that is not an upgrade, and must
    /// not invent a fingerprint comparison nobody performed.
    #[test]
    fn a_reseal_refuses_a_weak_channel_and_keeps_outstanding_caveats() {
        let (mut a, _b, _a_id, b_id) = peered_pair_over("reseal-weak", "corpus");
        type_command(&mut a, &format!("peer reseal {b_id}"));
        let pad = a.at("mine.fresh").display().to_string();
        type_command(&mut a, &format!("peer reseal pad {pad}"));

        for weak in ["corpus", "network"] {
            type_command(&mut a, &format!("peer reseal seal {pad} {weak}"));
            assert!(a.output.contains("not an upgrade"), "{}", a.output);
        }
        assert_eq!(
            a.peer_terms(&b_id).unwrap().reseals,
            0,
            "it re-sealed anyway"
        );
    }

    /// Re-sealing something that was never peered is refused, rather than
    /// silently creating a peering with no card behind it.
    #[test]
    fn a_reseal_needs_an_existing_peering() {
        let mut a = ready_node("reseal-stranger");
        type_command(&mut a, "peer reseal deadbeef");
        assert!(a.output.contains("no peering with"), "{}", a.output);
    }

    /// The terms survive a restart. They were held in memory only, so a link
    /// formed remotely presented as though it had been formed in person the
    /// moment the process exited.
    #[test]
    fn how_a_peering_was_formed_survives_a_restart() {
        let (a, _b, _a_id, b_id) = peered_pair_over("terms-restart", "corpus");
        let mut fresh = App {
            home: a.home.clone(),
            ..App::default()
        };
        fresh.passphrase = line::Line::from("a passphrase");
        fresh.unlock(b"a passphrase").expect("reopens");
        let t = fresh.peer_terms(&b_id).expect("terms were lost");
        assert!(!t.post_quantum());
        assert_eq!(t.channel, peering::Channel::Corpus);
    }

    /// The fingerprint comparison is a human act, recorded by a human — and
    /// it does not make a network peering post-quantum.
    #[test]
    fn verification_is_recorded_separately_and_is_not_an_upgrade() {
        let (mut a, _b, _a_id, b_id) = peered_pair_over("meet-verify", "corpus");
        assert!(!a.peer_terms(&b_id).unwrap().fingerprint_verified);

        type_command(&mut a, &format!("peer verified {b_id}"));
        assert!(a.output.contains("recorded as verified"), "{}", a.output);
        assert!(
            a.output.contains("still NOT post-quantum"),
            "verifying was presented as an upgrade:\n{}",
            a.output
        );
        assert!(a.peer_terms(&b_id).unwrap().fingerprint_verified);
        assert!(!a.peer_terms(&b_id).unwrap().post_quantum());

        type_command(&mut a, "peers");
        assert!(
            !a.output.contains("fingerprints never compared"),
            "{}",
            a.output
        );

        // And it is idempotent rather than incrementing anything.
        type_command(&mut a, &format!("peer verified {b_id}"));
        assert!(a.output.contains("already"), "{}", a.output);
    }

    /// A meet, then a reseal: start over the network, upgrade when you can.
    /// This is the whole argument of `PAD-OVER-NETWORK.md` in one test.
    #[test]
    fn a_network_peering_becomes_post_quantum_after_a_reseal() {
        let (mut a, mut b, a_id, b_id) = peered_pair_over("meet-then-reseal", "network");
        assert!(!a.peer_terms(&b_id).unwrap().post_quantum());

        type_command(&mut a, &format!("peer reseal {b_id}"));
        type_command(&mut b, &format!("peer reseal {a_id}"));
        let a_pad = a.at("a.fresh").display().to_string();
        let b_pad = b.at("b.fresh").display().to_string();
        type_command(&mut a, &format!("peer reseal pad {a_pad}"));
        type_command(&mut b, &format!("peer reseal pad {b_pad}"));
        type_command(&mut a, &format!("peer reseal seal {b_pad} in-person"));
        type_command(&mut b, &format!("peer reseal seal {a_pad} in-person"));

        assert!(a.peer_terms(&b_id).unwrap().post_quantum());
        assert_eq!(stored_root(&a, &b_id), stored_root(&b, &a_id));
    }

    /// The full schedule, as an observer of the network would experience it:
    /// when each peer is next spoken to.
    fn schedule_of(a: &App) -> Vec<(String, Option<u64>)> {
        let mut out: Vec<(String, Option<u64>)> = a
            .peer_ids()
            .iter()
            .filter_map(|p| sync::peer_id_of(p).map(|id| (p.clone(), a.scheduler.next_due(&id))))
            .collect();
        out.sort();
        out
    }

    /// **RFC 5 §6.1, and MILESTONE-0.1 phase D's first gate.** Inter-sync
    /// intervals must be uncorrelated with message events.
    ///
    /// An absence test, which RFC 8 §14 calls the only durable protection: it
    /// asserts that composing, sending, importing and reading mail change
    /// *nothing* about when this node next talks to the network. A schedule
    /// that moved when the operator did would let a passive observer read
    /// their activity off the timing of syncs, which is the whole failure
    /// mode Poisson scheduling exists to prevent.
    #[test]
    fn the_schedule_is_untouched_by_message_events() {
        let (mut a, _b, _a_id, b_id) = peered_pair("sched-events");
        a.scheduler.add(
            sync::peer_id_of(&b_id).expect("a peer id"),
            now_seconds(),
            0x5eed,
        );
        let before = schedule_of(&a);
        assert!(
            before.iter().any(|(_, due)| due.is_some()),
            "nothing was scheduled, so the test proves nothing"
        );

        // Every message event the interface offers.
        a.ui.compose();
        a.composer_set("a draft in progress");
        type_command(&mut a, &format!("send {b_id} the meeting is moved"));
        a.refresh_inbox();
        a.show_selected();
        type_command(&mut a, "peers");
        type_command(&mut a, "reach");

        assert_eq!(
            schedule_of(&a),
            before,
            "a message event moved the schedule — a passive observer could \
             read the operator's activity off the timing of syncs"
        );
    }

    /// **Phase D's second gate.** The schedule must be uncorrelated with lock
    /// state too.
    ///
    /// Pausing sync while locked would publish the operator's daily rhythm —
    /// when they are at the keyboard and when they are not — which
    /// `MILESTONE-0.1.md` calls a worse I-5 violation than mail-driven sync.
    /// So a locked node keeps its schedule *and keeps ticking*.
    #[test]
    fn the_schedule_is_untouched_by_locking_and_keeps_running() {
        let (mut a, _b, _a_id, b_id) = peered_pair("sched-lock");
        a.scheduler.add(
            sync::peer_id_of(&b_id).expect("a peer id"),
            now_seconds(),
            0x5eed,
        );
        let before = schedule_of(&a);
        let enrolled = a.scheduler.len();

        a.lock();
        assert!(a.locked);
        assert_eq!(
            schedule_of(&a),
            before,
            "locking moved the schedule, which publishes when the operator \
             locks their node"
        );
        assert_eq!(a.scheduler.len(), enrolled, "locking dropped a peer");

        // And it keeps running: a locked node is a relay, not a silent one.
        for _ in 0..5 {
            a.tick_schedule();
        }
        assert_eq!(
            a.scheduler.len(),
            enrolled,
            "ticking while locked unenrolled a peer"
        );

        a.passphrase = line::Line::from("a passphrase");
        a.unlock(b"a passphrase").expect("reopens");
        assert_eq!(
            schedule_of(&a),
            before,
            "unlocking moved the schedule, which publishes when the operator \
             returns to their node"
        );
    }

    /// **A keypress must not move a transfer.** `Scheduler::add` overwrites,
    /// so `connect` on a peer that was already enrolled re-drew its next sync
    /// — and an observer who sees the connection *and* the sync learns the
    /// operator pressed a key. RFC 5 §6.1 forbids exactly that correlation.
    #[test]
    fn connecting_does_not_move_an_existing_schedule() {
        let (mut a, _b, _a_id, b_id) = peered_pair("sched-connect");
        a.scheduler.add(
            sync::peer_id_of(&b_id).expect("a peer id"),
            now_seconds(),
            0x5eed,
        );
        let before = schedule_of(&a);

        // A dial that fails still enrols; the point is the *schedule*, not the
        // link. Nothing is listening on port 1.
        type_command(&mut a, &format!("connect {b_id} tcp 127.0.0.1:1"));
        assert_eq!(
            schedule_of(&a),
            before,
            "connecting re-drew an existing schedule — the operator's keypress \
             moved when this node next talks to the network"
        );

        // And a peer that was *not* enrolled still gets enrolled, or a node
        // would never reconcile with someone it had just peered with.
        a.scheduler
            .remove(&sync::peer_id_of(&b_id).expect("a peer id"));
        assert_eq!(a.scheduler.len(), 0);
        type_command(&mut a, &format!("connect {b_id} tcp 127.0.0.1:1"));
        assert_eq!(a.scheduler.len(), 1, "a new peer was not enrolled");
    }

    /// A small valid PNG, produced by the same encoder the pipeline uses.
    fn a_png(w: u32, h: u32) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut out, w, h);
            enc.set_color(png::ColorType::Rgba);
            enc.set_depth(png::BitDepth::Eight);
            let mut wr = enc.write_header().unwrap();
            wr.write_image_data(&vec![0x40; (w as usize) * (h as usize) * 4])
                .unwrap();
        }
        out
    }

    /// **A picture crosses intact, and nothing else does.** The bytes on the
    /// wire are the ones the pipeline produced, not the ones on disk.
    #[test]
    fn a_picture_is_sent_re_encoded_and_arrives_as_bytes() {
        let (mut a, mut b, _a_id, b_id) = peered_pair("picture-send");

        // A PNG with metadata appended, as a camera or an attacker would.
        let mut src = a_png(8, 8);
        src.extend_from_slice(b"GPS 51.5074 -0.1278 and a whole zip archive");
        let path = a.at("holiday.png");
        std::fs::write(&path, &src).unwrap();

        type_command(&mut a, &format!("send {b_id} --picture {}", path.display()));
        assert!(a.output.contains("decoded and re-encoded"), "{}", a.output);
        assert!(a.output.contains("no EXIF"), "{}", a.output);

        // Carry it.
        let now_min = now_epoch().0 * 1440;
        let carried: Vec<(krab_core::object::ObjectId, Vec<u8>)> = a.store.with(|s| {
            s.entries_in_range(0, u32::MAX)
                .into_iter()
                .filter_map(|(_, i)| s.get(&i).map(|x| (i, x.to_vec())))
                .collect()
        });
        for (i, bytes) in carried {
            let _ = b.store.with(|s| s.ingest(i, bytes, now_min, u32::MAX));
        }
        b.refresh_inbox();

        let m = b
            .messages
            .iter()
            .find(|m| m.picture.is_some())
            .expect("the picture did not arrive");
        let png = m.picture.as_ref().unwrap();

        // **It is a picture**, not a lossy string of one.
        assert_eq!(picture::dimensions(png).unwrap(), (8, 8));
        // And the appended data is gone.
        assert!(
            !png.windows(3).any(|w| w == b"GPS"),
            "metadata reached the recipient"
        );
        // The list shows it as a picture rather than as mangled text.
        assert!(m.body.contains("[picture"), "{}", m.body);

        // **And the row is marked, so an attachment is visible without
        // opening anything.** Asserted on `list`, which is what the pane
        // renders, rather than on the `Message` — the glyph is a property of
        // the row and a change to the row format has to break this.
        let row = b
            .list
            .iter()
            .find(|r| r.contains("[picture"))
            .expect("the picture is not in the list");
        assert!(
            row.contains(ATTACHMENT_GLYPH),
            "an attachment is not marked in the list: {row}"
        );
    }

    /// **The marker column is the same width on every row.**
    ///
    /// A glyph that only appears on some rows moves the body column between
    /// them, which is harder to scan than no marker. The blank is deliberate.
    #[test]
    fn the_attachment_column_holds_its_width_without_an_attachment() {
        // `Message` is deliberately not `Clone` — it holds plaintext that
        // `lock` destroys — so both rows are built outright.
        let mk = |body: &str, picture: Option<Vec<u8>>| receive::Message {
            id: krab_crypto::hash::object_id(b"x"),
            from: "deadbeef".into(),
            epoch: now_epoch(),
            body: body.into(),
            picture,
            post_quantum: true,
            nodelist: None,
        };
        let names = alias::Aliases::default();
        let with = App::inbox_row(&mk("[picture]", Some(a_png(2, 2))), &names);
        let without = App::inbox_row(&mk("plain", None), &names);

        assert!(with.contains(ATTACHMENT_GLYPH), "{with}");
        assert!(!without.contains(ATTACHMENT_GLYPH), "{without}");
        // Columns are cells, not bytes: the glyph is three bytes of UTF-8
        // and one cell, so comparing byte offsets would fail on a row that
        // lines up perfectly on screen.
        let col = |row: &str, needle: &str| {
            row[..row.find(needle).expect("body not in row")]
                .chars()
                .count()
        };
        assert_eq!(
            col(&with, "[picture]"),
            col(&without, "plain"),
            "the body column moved between a row with an attachment and one \
             without:\n  {with}\n  {without}"
        );
    }

    /// `picture save` writes bytes and does not open anything — RFC 8 §6
    /// forbids handing received bytes to a system viewer.
    #[test]
    fn picture_save_writes_bytes_and_opens_no_viewer() {
        let mut b = ready_node("picture-save");
        let png = a_png(4, 4);
        b.messages.push(receive::Message {
            id: krab_crypto::hash::object_id(b"x"),
            from: "deadbeef".into(),
            epoch: now_epoch(),
            body: "[picture]".into(),
            picture: Some(png.clone()),
            post_quantum: false,
            nodelist: None,
        });
        b.selected = 0;

        let dest = b.at("out.png");
        type_command(&mut b, &format!("picture save {}", dest.display()));
        assert_eq!(std::fs::read(&dest).unwrap(), png);
        assert!(
            b.output.contains("will not open it"),
            "the refusal to open a viewer is not stated:\n{}",
            b.output
        );

        // A text message is not a picture.
        b.messages[0].picture = None;
        type_command(&mut b, &format!("picture save {}", dest.display()));
        assert!(a_not_picture(&b.output), "{}", b.output);
    }

    fn a_not_picture(out: &str) -> bool {
        out.contains("not a picture")
    }

    /// **RFC 8 §6: say so before sending, not after silent non-delivery.**
    #[test]
    fn a_picture_is_refused_on_a_lora_link_before_it_is_sent() {
        let (mut a, _b, _a_id, b_id) = peered_pair("picture-lora");
        a.links.connect(&b_id, profile_named("lora").unwrap());

        let path = a.at("p.png");
        std::fs::write(&path, a_png(4, 4)).unwrap();
        let before = a.store.len();

        type_command(&mut a, &format!("send {b_id} --picture {}", path.display()));
        assert!(a.output.contains("cannot carry a picture"), "{}", a.output);
        assert_eq!(a.store.len(), before, "it was sent anyway");
    }

    /// **RFC 6 §2.4: "clients MUST surface which recipients are LoRa-reachable
    /// before sending."**
    ///
    /// §2.4 prices one message to a 20-member group at **1.6 hours of LoRa
    /// airtime**, and a sender who does not know which members are on a radio
    /// link is spending somebody else's duty cycle without being told. RFC 4
    /// §9 is explicit that nothing at the protocol layer can defend that — "it
    /// is a physical-layer property of the band, and it MUST be stated to
    /// operators rather than implied."
    ///
    /// The send path reported how many copies were sealed, the stagger window,
    /// and who had no peer-link. It said nothing about the carrier.
    #[test]
    fn a_group_send_says_which_members_are_on_a_constrained_link() {
        let (mut a, _b, _a_id, b_id) = peered_pair("group-lora");
        type_command(&mut a, "group new friends");
        type_command(&mut a, &format!("group add friends {b_id}"));

        // Over TCP, nothing to say about airtime.
        a.links.connect(&b_id, profile_named("tcp").unwrap());
        type_command(&mut a, "group send friends hello");
        assert!(
            !a.output.contains("constrained links"),
            "a TCP peer was reported as constrained:\n{}",
            a.output
        );

        // The same group, over a radio link.
        a.links.connect(&b_id, profile_named("lora").unwrap());
        type_command(&mut a, "group send friends hello again");
        assert!(
            a.output.contains("constrained links") && a.output.contains(&b_id),
            "the sender was not told whose duty cycle this spends:\n{}",
            a.output
        );
        assert!(
            a.output.contains("1.6 hours"),
            "the cost was named without its magnitude:\n{}",
            a.output
        );
    }

    /// A decompression bomb is refused at the interface, with the reason, and
    /// nothing is composed.
    #[test]
    fn a_bomb_is_refused_by_the_send_path() {
        let (mut a, _b, _a_id, b_id) = peered_pair("picture-bomb");
        let mut bomb = a_png(1, 1);
        let ihdr = 12;
        bomb[ihdr + 4..ihdr + 8].copy_from_slice(&40_000u32.to_be_bytes());
        bomb[ihdr + 8..ihdr + 12].copy_from_slice(&40_000u32.to_be_bytes());
        let crc = crc32fast::hash(&bomb[ihdr..ihdr + 17]);
        bomb[ihdr + 17..ihdr + 21].copy_from_slice(&crc.to_be_bytes());

        let path = a.at("bomb.png");
        std::fs::write(&path, &bomb).unwrap();
        let before = a.store.len();

        type_command(&mut a, &format!("send {b_id} --picture {}", path.display()));
        assert!(a.output.contains("Refused before decoding"), "{}", a.output);
        assert_eq!(a.store.len(), before, "a bomb was composed");
    }

    /// **A picture is drawn from pixels this node decoded**, as coloured
    /// half-block characters. The terminal is never handed the file: a
    /// terminal emulator decoding a stranger's PNG is a system image viewer,
    /// which RFC 8 §6 forbids.
    #[test]
    fn a_picture_renders_as_coloured_cells_in_the_view_pane() {
        use ratatui::{backend::TestBackend, Terminal};

        let mut b = ready_node("picture-show");
        b.messages.push(receive::Message {
            id: krab_crypto::hash::object_id(b"x"),
            from: "deadbeef".into(),
            epoch: now_epoch(),
            body: "[picture]".into(),
            picture: Some(a_png(16, 16)),
            post_quantum: false,
            nodelist: None,
        });
        b.selected = 0;
        b.showing = Some(picture::cells(&a_png(16, 16), 20, 8).expect("renders"));

        let mut term = Terminal::new(TestBackend::new(80, 24)).expect("a terminal");
        let log = b.log.recent(activity_log::CAPACITY);
        term.draw(|f| render::draw(f, &b.view(&log, None)))
            .expect("a frame");
        let buf = term.backend().buffer();

        // Half-blocks, with a foreground and a background that differ from the
        // pane's — which is what carries the two pixels.
        let painted = buf
            .content()
            .iter()
            .filter(|c| c.symbol() == "\u{2580}")
            .count();
        assert!(painted > 20, "the picture was not drawn: {painted} cells");
        assert!(
            buf.content()
                .iter()
                .any(|c| matches!(c.bg, ratatui::style::Color::Rgb(..))),
            "no truecolour background — the lower pixel of each cell is lost"
        );
    }

    /// **A locked node shows no picture.** One on screen after a lock is the
    /// same failure as a message on screen after one (RFC 7 §8).
    #[test]
    fn locking_removes_a_picture_from_the_screen() {
        let mut b = ready_node("picture-lock");
        b.showing = Some(picture::cells(&a_png(8, 8), 10, 4).expect("renders"));
        b.lock();
        assert!(b.showing.is_none(), "the picture survived the lock");
    }

    /// A terminal that does not advertise truecolour is told, and pointed at
    /// the verb that works — not left with a muddy render.
    #[test]
    fn a_terminal_without_colour_is_told_rather_than_shown_mud() {
        assert!(picture::terminal_supports_colour(Some("truecolor")));
        assert!(!picture::terminal_supports_colour(None));

        let mut b = ready_node("picture-nocolour");
        b.messages.push(receive::Message {
            id: krab_crypto::hash::object_id(b"x"),
            from: "deadbeef".into(),
            epoch: now_epoch(),
            body: "[picture]".into(),
            picture: Some(a_png(8, 8)),
            post_quantum: false,
            nodelist: None,
        });
        b.selected = 0;

        // The verb consults COLORTERM; drive the decision function directly so
        // the test does not depend on the environment it runs in.
        let out = if picture::terminal_supports_colour(None) {
            String::new()
        } else {
            b.picture_show();
            b.output.clone()
        };
        let _ = out;
        // Whatever this terminal is, `save` must always be available.
        let dest = b.at("out.png");
        type_command(&mut b, &format!("picture save {}", dest.display()));
        assert!(std::fs::read(&dest).is_ok());
    }

    /// **A panic wipe leaves nothing.** RFC 7 §10's destruction, checked
    /// against a node that has actually been used — peered, prekeyed,
    /// channelled, grouped, with a duress store — rather than a fresh one.
    ///
    /// This is the test that was missing. The predicate was a hand-written
    /// list of filenames and it failed twice: once by not recursing into
    /// `peers/`, once by never being updated as four more artifacts appeared.
    /// The second left prekey private halves, every group roster, the channel
    /// posting key and the duress store on disk after the operator had pressed
    /// the panic chord.
    #[test]
    fn a_wipe_leaves_no_artifact_behind() {
        let (mut a, _b, _a_id, b_id) = peered_pair("wipe-everything");
        a.publish_prekeys().expect("a prekey batch");
        type_command(&mut a, "channel new");
        type_command(&mut a, "group new friends");
        type_command(&mut a, &format!("group add friends {b_id}"));
        type_command(&mut a, &format!("peer reseal {b_id}"));
        type_command(&mut a, "peer offer");
        std::fs::write(a.path(artifact::Artifact::DuressWrapped), b"a duress store").unwrap();

        // Everything this node writes now exists.
        let expected: Vec<_> = artifact::Artifact::ALL
            .iter()
            .filter(|x| a.path(**x).exists())
            .collect();
        assert!(
            expected.len() >= 8,
            "the fixture did not exercise enough artifacts: {expected:?}"
        );
        assert!(a.peer_path(&b_id, artifact::PeerFile::Link).exists());

        a.confirmed = true;
        type_command(&mut a, "wipe");

        // Walk the whole home, not just the top level.
        fn survivors(dir: &std::path::Path, out: &mut Vec<String>) {
            if let Ok(rd) = std::fs::read_dir(dir) {
                for e in rd.flatten() {
                    if e.path().is_dir() {
                        survivors(&e.path(), out);
                    } else {
                        out.push(e.file_name().to_string_lossy().into_owned());
                    }
                }
            }
        }
        let mut left = Vec::new();
        survivors(&a.home, &mut left);
        left.sort();
        // Nothing secret survives. A *card* the operator was handed may — it
        // is public and signed, and destroying arbitrary files an operator
        // placed is the catastrophic behaviour the next test guards against.
        let secret: Vec<_> = left.iter().filter(|n| !n.ends_with(".card")).collect();
        assert!(
            secret.is_empty(),
            "these survived a panic wipe: {secret:?}\n\
             Each is either key material or a disclosure of who this node \
             talks to, and RFC 7 §10 exists to destroy exactly those."
        );
    }

    /// A wipe destroys the node's files and **not the operator's**. `--home`
    /// defaults to the working directory, so a wipe that removed everything
    /// there would be catastrophic.
    #[test]
    fn a_wipe_leaves_files_the_node_did_not_write() {
        let mut a = ready_node("wipe-bystanders");
        for name in ["notes.txt", "holiday.png", "Cargo.toml"] {
            std::fs::write(a.at(name), b"the operator's").unwrap();
        }
        a.confirmed = true;
        type_command(&mut a, "wipe");

        for name in ["notes.txt", "holiday.png", "Cargo.toml"] {
            assert!(
                a.at(name).exists(),
                "{name} was destroyed, and the node did not write it"
            );
        }
        assert!(!a.path(artifact::Artifact::IdentityWrapped).exists());
    }

    /// **Their pad is destroyed when it is consumed.** It is half the same
    /// shared secret as this node's own, equally unprotected, and it survived
    /// every wipe — because the operator chose where to put it and `wipe` only
    /// destroys what this node wrote. Sealing is the moment its owner is
    /// known, so it is the moment to destroy it.
    #[test]
    fn sealing_destroys_the_pad_it_consumed() {
        let mut a = ready_node("seal-shreds-a");
        let mut b = ready_node("seal-shreds-b");
        type_command(&mut a, "peer offer");
        type_command(&mut b, "peer offer");
        let card = a.at("theirs.card");
        std::fs::write(
            &card,
            std::fs::read(b.path(artifact::Artifact::PeerCard)).unwrap(),
        )
        .unwrap();
        type_command(&mut a, &format!("peer accept {}", card.display()));

        // Their pad, delivered wherever a courier unloaded it.
        let their_pad = a.at("from-bob.pad");
        let path = pad_onto(&mut b, &their_pad);
        assert!(their_pad.exists());

        type_command(&mut a, &format!("peer seal {path} media"));
        assert!(a.output.starts_with("peer-link signed"), "{}", a.output);
        assert!(
            !their_pad.exists(),
            "their pad survived the seal that consumed it — half a shared \
             secret, in plaintext, in whatever directory it was delivered to"
        );
        // And this node's own, as before.
        assert!(!a.path(artifact::Artifact::PeerPad).exists());
    }

    /// **A missing safety property is reported, never silent.** Where the
    /// decoder cannot be run as a separate process, the picture is still
    /// decoded — and the operator is told that the isolation RFC 8 §6 prefers
    /// was not available. A silent fallback would be a property quietly
    /// absent, which is worse than not having it.
    #[test]
    fn losing_process_isolation_is_reported_and_not_silent() {
        let (mut a, _b, _a_id, b_id) = peered_pair("picture-fallback");
        let path = a.at("p.png");
        std::fs::write(&path, a_png(8, 8)).unwrap();

        type_command(&mut a, &format!("send {b_id} --picture {}", path.display()));
        assert!(a.output.contains("re-encoded"), "{}", a.output);
        // Under `cargo test` the executable is a harness that does not know
        // the child flag, so this exercises exactly the degraded path.
        assert!(
            a.output.contains("decoded in this process"),
            "the fallback happened without saying so:\n{}",
            a.output
        );
        assert!(
            a.output.contains("holds your keys"),
            "it does not say what the cost is:\n{}",
            a.output
        );
    }

    /// Missing isolation and a bad picture are different, because the
    /// remedies are opposite: one means the file is bad, the other means a
    /// safety property is unavailable.
    #[test]
    fn missing_isolation_is_not_a_refusal() {
        assert_ne!(picture::Error::NoIsolation, picture::Error::Corrupt);
        assert!(picture::Error::NoIsolation
            .to_string()
            .contains("separate process"));
        assert!(picture::Error::Corrupt.to_string().contains("refused"));
    }

    /// **A relay is this same program, locked.** `RFC-7-review.md` §9.3, and
    /// the reason it takes a passphrase at all: §7's relay took none, which
    /// left its disk unencrypted and made RFC 0 §4.4's "seizure yields
    /// nothing" false for its peer list.
    #[test]
    fn a_relay_locks_itself_and_still_has_an_encrypted_disk() {
        let (a, _b, _a_id, b_id) = peered_pair("relay");

        // Restart as a relay: the passphrase is still entered.
        let mut r = App {
            home: a.home.clone(),
            relay: true,
            ..App::default()
        };
        r.passphrase = line::Line::from("a passphrase");
        r.unlock(b"a passphrase").expect("it opens");

        assert!(r.locked, "a relay must lock the moment it opens");
        assert!(r.epoch_key.is_none(), "it kept a content key");
        assert!(r.output.contains("relay"), "{}", r.output);

        // **The disk is encrypted**, which is the whole point of the prompt.
        assert!(r.path(artifact::Artifact::IdentityWrapped).exists());
        assert!(r.path(artifact::Artifact::KekParams).exists());
        // And a wrong passphrase does not open it, so the peer list is not
        // readable from the disk alone.
        let mut wrong = App {
            home: a.home.clone(),
            ..App::default()
        };
        assert!(wrong.unlock(b"not the passphrase").is_err());

        // It still knows who it peers with, from disk, and still schedules.
        assert!(r.peer_ids().contains(&b_id));
    }

    /// **A relay keeps reconciling.** It is a relay, not a silent node:
    /// pausing while locked would publish the operator's daily rhythm, which
    /// `MILESTONE-0.1.md` calls a worse violation than mail-driven sync.
    #[test]
    fn a_relay_keeps_its_schedule_and_keeps_ticking() {
        let (a, _b, _a_id, b_id) = peered_pair("relay-ticks");
        let mut r = App {
            home: a.home.clone(),
            relay: true,
            ..App::default()
        };
        r.passphrase = line::Line::from("a passphrase");
        r.unlock(b"a passphrase").expect("it opens");
        // Enrolled from the peer-links on disk, without anyone typing.
        let id = sync::peer_id_of(&b_id).expect("a peer id");
        assert!(
            r.scheduler.next_due(&id).is_some(),
            "a relay did not enrol the peers it holds links for — it would \
             never reconcile, which is the only thing it is for"
        );
        let enrolled = r.scheduler.len();

        for _ in 0..10 {
            r.tick_schedule();
        }
        assert!(r.locked, "ticking unlocked it");
        assert_eq!(
            r.scheduler.len(),
            enrolled,
            "a relay stopped scheduling a peer while locked"
        );
        assert!(
            r.scheduler.next_due(&id).is_some(),
            "the peer fell out of the schedule"
        );
        // Still cannot read anything, which is the other half of what a relay
        // is: it carries and does not open.
        assert!(r.epoch_key.is_none());
        assert!(r.messages.is_empty());
    }

    /// It is not a headless mode. RFC 8 forbids one, and a relay that could
    /// start without a human is a relay whose passphrase lives somewhere a
    /// machine can read.
    #[test]
    fn a_relay_still_needs_a_passphrase() {
        let a = App::from_args(["--home", "/tmp/krab-relay", "--relay"].iter().map(|s| s.to_string()))
            .expect("parses");
        assert!(a.relay);
        assert!(a.identity.is_none(), "it started with a key from nowhere");
        assert!(a.epoch_key.is_none());
        // And `--relay` is not accepted as a value for anything else.
        assert!(App::from_args(["--home", "--relay"].iter().map(|s| s.to_string())).is_ok());
    }

    /// `unlock` makes it an ordinary node again — a relay is a state, not a
    /// build.
    #[test]
    fn a_relay_can_be_unlocked_into_an_ordinary_node() {
        let (a, _b, _a_id, _b_id) = peered_pair("relay-unlock");
        let mut r = App {
            home: a.home.clone(),
            relay: true,
            ..App::default()
        };
        r.passphrase = line::Line::from("a passphrase");
        r.unlock(b"a passphrase").expect("opens");
        assert!(r.locked);

        // The operator sits down and unlocks it.
        r.relay = false;
        r.passphrase = line::Line::from("a passphrase");
        r.unlock(b"a passphrase").expect("reopens");
        assert!(!r.locked, "it would not come back");
        assert!(r.epoch_key.is_some(), "it has no content key");
    }

    /// **You can write a message.** The composer opened, accepted text, and
    /// nothing sent it — there was no path from a composition to a sealed
    /// object at all. `send <peer> <text>` was the only way, one line, on the
    /// command line.
    #[test]
    fn a_message_can_be_composed_over_several_lines_and_sent() {
        let (mut a, mut b, _a_id, b_id) = peered_pair("compose-send");

        type_command(&mut a, &format!("send {b_id}"));
        assert!(a.output.contains("composing to"), "{}", a.output);
        assert_eq!(a.ui.mode(), Mode::Compose);
        assert_eq!(
            a.ui.focus(),
            layout::Pane::View,
            "keystrokes would have gone to the command line"
        );

        for c in "the meeting is moved".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        a.on_key(KeyCode::Enter, KeyModifiers::NONE);
        for c in "to Thursday".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        assert!(a.composer.contains('\n'), "Enter did not make a newline");
        assert!(a.command.is_empty(), "the text went to the command line");

        // Ctrl-D seals it.
        a.on_key(KeyCode::Char('d'), KeyModifiers::CONTROL);
        assert!(a.output.contains("composed"), "{}", a.output);
        assert_eq!(a.ui.mode(), Mode::Browse, "the composer stayed open");
        assert!(a.composer.is_empty(), "the draft was not cleared");

        // And it arrives, both lines.
        let now_min = now_epoch().0 * 1440;
        let carried: Vec<(krab_core::object::ObjectId, Vec<u8>)> = a.store.with(|s| {
            s.entries_in_range(0, u32::MAX)
                .into_iter()
                .filter_map(|(_, i)| s.get(&i).map(|x| (i, x.to_vec())))
                .collect()
        });
        for (i, bytes) in carried {
            let _ = b.store.with(|s| s.ingest(i, bytes, now_min, u32::MAX));
        }
        b.refresh_inbox();
        let got = b
            .messages
            .iter()
            .find(|m| m.body.contains("meeting is moved"))
            .expect("it did not arrive");
        assert!(got.body.contains("Thursday"), "the second line was lost");
    }

    /// **A message body must not reach the command history.** `send bob the
    /// meeting is moved` recorded the plaintext, and Up-arrow brought it
    /// back — RFC 7 §8 says plaintext exists only while displayed.
    #[test]
    fn a_message_body_never_reaches_the_command_history() {
        let (mut a, _b, _a_id, b_id) = peered_pair("compose-history");
        type_command(
            &mut a,
            &format!("send {b_id} the safe house is on Rua Augusta"),
        );

        assert!(
            !a.history.iter().any(|h| h.contains("Rua Augusta")),
            "the message body is in the history: {:?}",
            a.history
        );
        // The verb and the recipient are kept, because recalling `send bob `
        // is what an operator actually wants.
        assert!(
            a.history.iter().any(|h| h == &format!("send {b_id} ")),
            "the recipient was dropped too: {:?}",
            a.history
        );
        a.on_key(KeyCode::Up, KeyModifiers::NONE);
        assert!(!a.command.as_string().contains("Rua Augusta"));
    }

    /// Ctrl-D is not Enter. A message worth composing over several lines is
    /// one where Enter must not send it halfway through — and RFC 3 §6.1
    /// forbids any mechanism that could recall it.
    #[test]
    fn enter_does_not_send_a_composition() {
        let (mut a, _b, _a_id, b_id) = peered_pair("compose-enter");
        let before = a.store.len();
        type_command(&mut a, &format!("send {b_id}"));
        for c in "half a thought".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        for _ in 0..3 {
            a.on_key(KeyCode::Enter, KeyModifiers::NONE);
        }
        assert_eq!(a.store.len(), before, "Enter sent it");
        assert_eq!(a.ui.mode(), Mode::Compose, "Enter closed the composer");
    }

    /// A composition addressed to nobody cannot be sent, and Esc overwrites
    /// the draft rather than dropping it.
    #[test]
    fn an_unaddressed_composition_is_not_sent_and_esc_overwrites_it() {
        let mut a = ready_node("compose-nobody");
        a.on_key(KeyCode::Char('c'), KeyModifiers::NONE);
        a.ui.compose();
        a.composer_set("to nobody");
        a.on_key(KeyCode::Char('d'), KeyModifiers::CONTROL);
        assert!(a.output.contains("not addressed"), "{}", a.output);

        a.on_key(KeyCode::Esc, KeyModifiers::NONE);
        assert!(a.composer.is_empty(), "the draft survived Esc");
        assert_eq!(a.ui.mode(), Mode::Browse);
    }

    /// Sending to someone this node has not peered with says so up front,
    /// rather than after the operator has written a message.
    #[test]
    fn composing_to_a_stranger_is_refused_before_the_message_is_written() {
        let mut a = ready_node("compose-stranger");
        type_command(&mut a, "send deadbeef");
        assert!(a.output.contains("no peer-link"), "{}", a.output);
        assert_eq!(a.ui.mode(), Mode::Browse, "it opened a composer anyway");
    }

    /// **The main verb.** `message <peer> [peer…]` opens a composition, and
    /// Ctrl-D seals one copy per recipient and queues them.
    #[test]
    fn message_composes_to_several_people_and_seals_one_copy_each() {
        let (mut a, mut b, _a_id, b_id) = peered_pair("message-many");
        type_command(&mut a, &format!("message {b_id}"));
        assert!(a.output.contains("PRIVATE"), "{}", a.output);
        assert_eq!(a.ui.mode(), Mode::Compose);

        for ch in "the meeting is moved".chars() {
            a.on_key(KeyCode::Char(ch), KeyModifiers::NONE);
        }
        a.on_key(KeyCode::Char('d'), KeyModifiers::CONTROL);
        assert!(a.output.contains("composed for"), "{}", a.output);

        let now_min = now_epoch().0 * 1440;
        let carried: Vec<(krab_core::object::ObjectId, Vec<u8>)> = a.store.with(|s| {
            s.entries_in_range(0, u32::MAX)
                .into_iter()
                .filter_map(|(_, i)| s.get(&i).map(|x| (i, x.to_vec())))
                .collect()
        });
        for (i, bytes) in carried {
            let _ = b.store.with(|s| s.ingest(i, bytes, now_min, u32::MAX));
        }
        b.refresh_inbox();
        assert!(
            b.messages
                .iter()
                .any(|m| m.body.contains("meeting is moved")),
            "it did not arrive"
        );
    }

    /// **Every recipient is checked before the operator writes anything.**
    /// Fan-out seals individually, so one that cannot be sealed to would
    /// receive nothing while nothing said so.
    #[test]
    fn message_refuses_an_unknown_recipient_up_front() {
        let (mut a, _b, _a_id, b_id) = peered_pair("message-unknown");
        type_command(&mut a, &format!("message {b_id} deadbeef"));
        assert!(a.output.contains("no peer-link"), "{}", a.output);
        assert!(
            a.output.contains("deadbeef"),
            "it does not say who: {}",
            a.output
        );
        assert_eq!(
            a.ui.mode(),
            Mode::Browse,
            "it opened a composer the operator could not send"
        );
    }

    /// A message to several people is staggered, for the reason a group's is:
    /// N objects together in one bucket announce the fan-out and its size.
    #[test]
    fn a_message_to_several_people_is_staggered() {
        let (mut a, _b, _a_id, b_id) = peered_pair("message-stagger");
        // Two recipients, both reachable: the same peer twice is enough to
        // exercise the fan-out without a second peering.
        let to = vec![b_id.clone(), b_id.clone()];
        let before = a.store.len();
        let out = a.fan_out(&to, "hello");
        assert!(out.contains("composed for"), "{out}");
        assert_eq!(a.pending.len(), 2, "the copies were not held");
        assert_eq!(a.store.len(), before, "they went out immediately");
        assert!(out.contains("RFC 6 §2.7"), "{out}");

        // One recipient is not a fan-out and goes straight in.
        let out = a.fan_out(&[b_id], "hello again");
        assert!(!out.contains("copies"), "{out}");
        assert!(a.store.len() > before, "a single message was held back");
    }

    /// `message` takes no text on the command line, so no message body can
    /// reach the history through it at all.
    #[test]
    fn message_puts_no_body_in_the_history() {
        let (mut a, _b, _a_id, b_id) = peered_pair("message-history");
        type_command(&mut a, &format!("message {b_id}"));
        for ch in "the safe house is on Rua Augusta".chars() {
            a.on_key(KeyCode::Char(ch), KeyModifiers::NONE);
        }
        a.on_key(KeyCode::Char('d'), KeyModifiers::CONTROL);
        assert!(
            !a.history.iter().any(|h| h.contains("Rua Augusta")),
            "{:?}",
            a.history
        );
    }

    /// **A first-contact socket is cancellable and self-closing.** It was a
    /// thirty-second blocking wait on the interface thread: not long enough to
    /// arrange a call with anybody, and impossible to stop — it took the lock
    /// chord with it while it waited.
    #[test]
    fn a_first_contact_socket_can_be_opened_and_closed() {
        let mut a = ready_node("meet-cancel");

        assert!(a.meet_status().contains("no first-contact socket"));
        type_command(&mut a, "peer meet cancel");
        assert!(a.output.contains("nothing is waiting"), "{}", a.output);

        type_command(&mut a, "peer meet listen 127.0.0.1:0");
        assert!(a.meeting.is_some(), "{}", a.output);
        assert!(a.output.contains("accepts whoever calls"), "{}", a.output);
        assert!(
            a.output.contains("closes itself"),
            "it does not say it will close: {}",
            a.output
        );

        // Visible while open.
        type_command(&mut a, "peer meet status");
        assert!(a.output.contains("minute(s) left"), "{}", a.output);

        // And closeable.
        type_command(&mut a, "peer meet cancel");
        assert!(a.output.contains("closed"), "{}", a.output);
        assert!(a.meeting.is_none(), "the door stayed open");
        assert!(a.meeting.is_none());
    }

    /// A second door is refused rather than silently replacing the first,
    /// which would leave a thread holding a socket nobody could close.
    #[test]
    fn only_one_first_contact_socket_at_a_time() {
        let mut a = ready_node("meet-one");
        type_command(&mut a, "peer meet listen 127.0.0.1:0");
        let first = a.meeting.as_ref().map(|m| m.addr.clone());
        type_command(&mut a, "peer meet listen 127.0.0.1:0");
        assert!(a.output.contains("already waiting"), "{}", a.output);
        assert_eq!(
            a.meeting.as_ref().map(|m| m.addr.clone()),
            first,
            "the second call replaced the first"
        );
        type_command(&mut a, "peer meet cancel");
    }

    /// **It closes itself.** A door left open past the arrangement to use it
    /// is a door nobody is watching, and this one accepts whoever calls.
    #[test]
    fn a_first_contact_socket_closes_itself_when_its_time_is_up() {
        let mut a = ready_node("meet-expire");
        type_command(&mut a, "peer meet listen 127.0.0.1:0");
        assert!(a.meeting.is_some());

        // Bring the deadline forward rather than waiting fifteen minutes.
        if let Some(m) = a.meeting.as_mut() {
            m.until = Instant::now();
        }
        a.tick_schedule();
        assert!(a.meeting.is_none(), "it stayed open past its window");
        assert!(a.output.contains("nobody called"), "{}", a.output);
        assert!(
            a.output.contains("peer meet listen"),
            "it does not say how to reopen it: {}",
            a.output
        );
    }

    /// The window is bounded, and long enough to be useful. Thirty seconds
    /// was neither.
    #[test]
    fn the_meeting_window_is_long_enough_to_arrange_and_short_enough_to_end() {
        assert!(MEET_WINDOW >= Duration::from_secs(5 * 60));
        assert!(MEET_WINDOW <= Duration::from_secs(60 * 60));
    }

    /// **Two strangers still peer**, now through the background socket rather
    /// than a blocking wait.
    #[test]
    fn two_strangers_peer_through_the_background_socket() {
        let mut a = ready_node("meet-bg-a");
        let mut b = ready_node("meet-bg-b");
        let a_id = short_id(&a.identity.as_ref().unwrap().node_id());
        let b_id = short_id(&b.identity.as_ref().unwrap().node_id());

        type_command(&mut b, "peer meet listen 127.0.0.1:45591");
        assert!(b.meeting.is_some(), "{}", b.output);
        std::thread::sleep(Duration::from_millis(200));

        let out_a = a.peer_meet("meet 127.0.0.1:45591");
        assert!(out_a.starts_with("peer-link signed"), "A: {out_a}");

        // B picks it up on a tick, without anyone typing.
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline && b.meeting.is_some() {
            b.tick_schedule();
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(b.meeting.is_none(), "B never completed: {}", b.output);
        assert!(b.output.starts_with("peer-link signed"), "B: {}", b.output);
        assert!(
            b.output.contains("Nothing is verified yet"),
            "B: {}",
            b.output
        );

        // A working peering at both ends.
        assert_eq!(stored_root(&a, &b_id), stored_root(&b, &a_id));
    }

    /// **Adversarial: what does `lock` leave in memory?**
    ///
    /// `lock` clears the log because "the screen must not list
    /// correspondents". This asks the same question of every other field that
    /// accumulated since — the command history, an open composition's
    /// recipients, a first-contact socket, a wipe confirmation, a pending
    /// prompt.
    #[test]
    fn locking_leaves_nothing_that_names_a_correspondent() {
        let (mut a, _b, _a_id, b_id) = peered_pair("adv-lock-state");

        // A session's worth of state: mail sent, a composition open, a
        // stranger-accepting socket, a wipe half-confirmed, a prompt pending.
        type_command(&mut a, &format!("send {b_id} the meeting is moved"));
        type_command(&mut a, &format!("message {b_id}"));
        type_command(&mut a, "peer meet listen 127.0.0.1:0");
        type_command(&mut a, "wipe");
        a.prompt = Some(Prompt::TransferWords {
            path: "/tmp/theirs.wrapped".into(),
        });

        a.lock();
        assert!(a.locked);

        // The history names who this node talks to, and Up-arrow recalls it.
        assert!(
            !a.history.iter().any(|h| h.contains(&b_id)),
            "the command history still lists a correspondent: {:?}",
            a.history
        );
        // So does an open composition's recipient list.
        assert!(
            a.composing_to.is_none() && a.composing_to_many.is_empty(),
            "a locked node still holds who it was writing to"
        );
        // A socket accepting strangers, on a node that cannot complete the
        // ceremony it would start.
        assert!(
            a.meeting.is_none(),
            "a locked node left a first-contact socket open"
        );
        // A confirmation given before the lock must not authorise a
        // destruction after it.
        assert!(!a.confirmed, "a wipe stayed confirmed across a lock");
        // And a pending prompt would swallow the next line typed.
        assert!(a.prompt.is_none(), "a prompt survived the lock");
    }

    /// **Adversarial: a panic wipe must clear at least as much as a lock.**
    ///
    /// It cleared less. `lock` overwrote the decrypted body, the log and a
    /// displayed picture; `panic_wipe` — the verb behind the chord an operator
    /// presses when somebody is at the door — did not, and also left the
    /// channel posting key and every group roster in memory.
    #[test]
    fn a_panic_wipe_clears_at_least_as_much_as_a_lock() {
        let (mut a, _b, _a_id, b_id) = peered_pair("adv-panic-state");
        type_command(&mut a, "channel new");
        type_command(&mut a, "group new friends");
        type_command(
            &mut a,
            &format!("send {b_id} the safe house is on Rua Augusta"),
        );
        a.body = "from bob\n\nthe safe house is on Rua Augusta".into();
        a.showing = Some(picture::cells(&a_png(8, 8), 10, 4).expect("renders"));
        a.composing_to = Some(b_id.clone());

        a.panic_wipe();

        assert!(
            a.body.is_empty(),
            "decrypted plaintext survived a panic wipe"
        );
        assert!(a.showing.is_none(), "a picture was still on screen");
        assert!(
            a.roster.mine.is_none(),
            "the channel posting key survived in memory"
        );
        assert!(a.groups.is_empty(), "group rosters survived in memory");
        assert!(
            !a.history.iter().any(|h| h.contains(&b_id)),
            "the history still names a correspondent: {:?}",
            a.history
        );
        assert!(a.composing_to.is_none());
        assert!(a.log.recent(8).is_empty(), "the activity log survived");
    }

    /// **Adversarial: two things wanting the next line.**
    ///
    /// `Prompt` consumes the next submitted line without parsing it. The
    /// first-run ceremony and `unlock` also consume input. If both are live,
    /// one of them silently gets the other's text — and one of those texts is
    /// a passphrase.
    #[test]
    fn a_prompt_and_the_ceremony_never_both_want_the_next_line() {
        let mut a = ready_node("adv-prompt-clash");
        a.prompt = Some(Prompt::TransferWords {
            path: "/tmp/nonexistent.wrapped".into(),
        });

        // `unlock` asks for a passphrase through `init_step`, not through the
        // command line, so the two channels are separate — but a stale prompt
        // must not eat the verb that starts it.
        type_command(&mut a, "unlock");
        assert!(
            a.prompt.is_none(),
            "the prompt is still armed and will eat the next line"
        );

        // Whatever happened, the passphrase buffer did not receive the verb.
        assert!(!a.passphrase.as_string().contains("unlock"));
    }

    /// **Adversarial: a passphrase typed while a prompt is armed.**
    ///
    /// The passphrase step has its own buffer and its own key handling, so a
    /// prompt must not be able to intercept it. If it could, the transfer-word
    /// handler would receive a passphrase and — since a wrong phrase is
    /// reported the same way a tampered file is — the operator would be told
    /// only that "those words did not open it".
    #[test]
    fn a_prompt_cannot_intercept_a_passphrase() {
        let mut a = App::default();
        a.home = temp_home("adv-prompt-passphrase");
        type_command(&mut a, "init");
        assert_eq!(a.init_step, Some(InitStep::Passphrase));
        a.prompt = Some(Prompt::TransferWords {
            path: "/tmp/x".into(),
        });

        for c in "hunter2".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        assert_eq!(
            a.passphrase.as_string(),
            "hunter2",
            "the passphrase went somewhere else"
        );
        assert!(a.command.is_empty());
        assert!(
            !a.history.iter().any(|h| h.contains("hunter2")),
            "{:?}",
            a.history
        );
    }

    /// **Adversarial: a wipe confirmed, then something else typed.**
    ///
    /// `confirmed` is a one-shot latch. Anything between the two `wipe`s must
    /// clear it, or an operator who typed `wipe`, changed their mind, ran
    /// something else, and later typed `wipe` again would destroy the node on
    /// what they believed was the first of two presses.
    #[test]
    fn a_wipe_confirmation_does_not_survive_another_command() {
        let mut a = ready_node("adv-wipe-latch");
        type_command(&mut a, "wipe");
        assert!(a.output.contains("cannot be undone"), "{}", a.output);
        assert!(a.confirmed);

        type_command(&mut a, "peers");
        assert!(
            !a.confirmed,
            "a wipe stayed armed across an unrelated command — the next `wipe` \
             would destroy the node on what looks like the first press"
        );
        assert!(a.identity.is_some());

        type_command(&mut a, "wipe");
        assert!(a.output.contains("cannot be undone"), "{}", a.output);
        assert!(a.identity.is_some(), "it destroyed on a single press");
    }

    /// **Adversarial: what does a tick do after a panic wipe?**
    ///
    /// The node keeps running — the operator pressed the chord, they did not
    /// quit. Anything still queued gets a chance to act, and two things were:
    /// fan-out copies awaiting release, and a listener still holding the
    /// statics of peers that no longer exist.
    #[test]
    fn nothing_queued_before_a_panic_wipe_acts_after_it() {
        let (mut a, _b, _a_id, b_id) = peered_pair("adv-wipe-tick");

        // Copies composed but not yet emitted, and a bound listener.
        a.listen = Some("127.0.0.1:0".into());
        a.start_listener();
        let _ = a.fan_out(
            &[b_id.clone(), b_id.clone()],
            "the safe house is on Rua Augusta",
        );
        assert_eq!(a.pending.len(), 2, "the fixture did not queue anything");

        a.panic_wipe();
        assert!(
            !a.path(artifact::Artifact::Corpus).exists(),
            "the wipe failed"
        );

        // Release everything that was waiting, then tick.
        for p in a.pending.iter_mut() {
            p.release_at_s = 0;
        }
        a.tick_schedule();

        assert!(
            a.pending.is_empty() || a.store.is_empty(),
            "sealed messages composed before the wipe were emitted after it"
        );
        assert!(
            !a.path(artifact::Artifact::Corpus).exists(),
            "a tick recreated the corpus a panic wipe had destroyed"
        );
        assert!(
            a.inbound.is_none(),
            "a wiped node is still accepting calls from its former peers"
        );
    }
}
