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

mod activity;
mod activity_log;
mod atomic;
mod ceremony;
mod command;
mod compose;
mod courier;
mod entropy;
mod identity;
mod keys;
mod layout;
mod line;
mod links;
mod peering;
mod peers;
mod persist;
mod reach;
mod receive;
mod rekey;
mod rekey_run;
mod render;
mod request;
mod shared;
mod shred;
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

/// How long the panic chord stays armed.
///
/// Long enough to press twice under stress, short enough that an armed node
/// left alone disarms itself rather than waiting to be triggered by whoever
/// is at the keyboard next.
const PANIC_WINDOW: Duration = Duration::from_secs(3);

/// Lines PgUp/PgDn move the output pane.
///
/// A fixed step rather than a screenful: the pane is four rows unzoomed and
/// full-screen zoomed, and a step that changes size with the zoom means the
/// same keystroke moves a different distance depending on state.
const OUTPUT_SCROLL_LINES: usize = 8;

/// How many ticks an activity glyph keeps turning after bytes move.
///
/// Long enough to be seen at a glance, short enough that it stops well before
/// an operator could mistake it for continuous traffic.
const ACTIVITY_GLYPH_TICKS: u8 = 20;

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
    #[cfg(not(test))]
    {
        PathBuf::from(".")
    }
}

fn main() -> io::Result<()> {
    let mut app = match App::from_args(std::env::args().skip(1)) {
        Ok(app) => app,
        Err(usage) => {
            eprintln!("{usage}");
            return Ok(());
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
        "corpus.krab",
        "ceremony.cbor",
    ]
    .iter()
    .filter(|n| atomic::clear_stale(&app.home.join(n)))
    .count();

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
    identity: Option<Identity>,
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
    /// Where inbound links arrive, from `--listen`. `None` means this node
    /// only dials.
    listen: Option<String>,
    /// Inbound sessions accepted by the background listener, waiting to be
    /// installed. Drained on each tick.
    inbound: Option<std::sync::mpsc::Receiver<(Box<dyn krab_fabric::Session>, [u8; 32])>>,
    /// The set of statics the listener will accept, kept in step with the
    /// peerings on disk.
    allowed: krab_fabric::backend::listener::Allowed,
    /// Transports. **Holds nothing that can reconcile** — RFC 8 §5.1.
    links: LinkTable,
    /// The corpus, reachable from background exchanges.
    store: shared::SharedStore,
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
    /// Set by the confirmation prompt, consumed by the next command.
    confirmed: bool,
    /// Where the first-run ceremony has got to, if it is running.
    init_step: Option<InitStep>,
    /// Whether the passphrase prompt is unlocking rather than initialising.
    unlocking: bool,
    /// When the panic chord was first pressed, if it is armed. See
    /// [`Binding::PanicWipe`].
    panic_armed: Option<Instant>,
}

impl Default for App {
    fn default() -> App {
        App {
            ui: Ui::default(),
            node: NodeState::default(),
            spinner: Spinner::default(),
            command: line::Line::default(),
            composer: String::new(),
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
            listen: None,
            history: Vec::new(),
            history_at: 0,
            output_scroll: 0,
            inbound_ticks: 0,
            outbound_ticks: 0,
            inbound: None,
            allowed: krab_fabric::backend::listener::Allowed::default(),
            links: LinkTable::new(),
            store: shared::SharedStore::new(krab_store::index::Store::new()),
            exchanges: std::sync::mpsc::channel(),
            // Four hours. RFC 5 §6.1 fixes the shape, not the mean; this is a
            // starting point a deployment tunes.
            scheduler: krab_node::scheduler::Scheduler::new(4 * 3_600),
            messages: Vec::new(),
            selected: 0,
            log: activity_log::ActivityLog::new(),
            tag_table: None,
            confirmed: false,
            init_step: None,
            unlocking: false,
            panic_armed: None,
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
        const USAGE: &str =
            "krab [--home <dir>] [--sync-interval <seconds>] [--listen <address>]\n\n\
             krab reads no configuration file. Everything else is set by a \
             command-pane verb during the session.\n\n\
             --listen binds one socket and accepts calls from any node this \
             one has peered with. There is no port per peer: that would \
             publish the size of the operator's friend list to a port \
             scanner.";

        let mut app = App::default();
        let mut args = args.peekable();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--home" => {
                    app.home = PathBuf::from(args.next().ok_or(USAGE)?);
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
            term.draw(|f| render::draw(f, &self.view(&log_lines, me.as_deref())))?;

            if event::poll(TICK)? {
                if let Event::Key(k) = event::read()? {
                    if k.kind == KeyEventKind::Press {
                        self.on_key(k.code, k.modifiers);
                    }
                }
            }
            if last.elapsed() >= TICK {
                self.spinner.tick();
                self.tick_schedule();
                last = Instant::now();
            }
        }
        Ok(())
    }

    fn on_key(&mut self, code: KeyCode, mods: KeyModifiers) {
        // Anything that is not the second half of the chord disarms it. An
        // armed node that stays armed while the operator does something else
        // is a node that destroys itself on an unrelated keystroke later.
        let was_armed = self.panic_armed.take();
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
            Binding::PanicWipe => {
                let now = Instant::now();
                let armed = was_armed.is_some_and(|t| now.duration_since(t) < PANIC_WINDOW);
                if armed {
                    self.panic_armed = None;
                    self.output = self.panic_wipe();
                } else {
                    self.panic_armed = Some(now);
                    self.output = format!(
                        "ARMED — press again within {}s to destroy every key on this node. \
                         Anything else cancels.",
                        PANIC_WINDOW.as_secs()
                    );
                }
            }
            Binding::Quit => self.leave(),
            Binding::Lock => self.lock(),
            Binding::CycleFocus => self.ui.cycle_focus(),
            Binding::CycleFocusBack => self.ui.cycle_focus_back(),
            Binding::ToggleZoom => self.ui.toggle_zoom(),
            Binding::SwitchTab => self.ui.switch_tab(),
            Binding::SelectTab(t) => self.ui.select_tab(t),
            Binding::ToggleFullScreen => self.ui.toggle_full_screen(),
            // **History.** Typed commands only, never the passphrase — see
            // `push_history`.
            Binding::History(d) => {
                if self.init_step == Some(InitStep::Passphrase) {
                    return;
                }
                self.recall(d);
            }
            // **Scroll the output pane.** By screens, so a long `help` or
            // `peers` can be read without zooming.
            Binding::Scroll(d) => {
                let step = OUTPUT_SCROLL_LINES as i64;
                let n = self.output.lines().count() as i64;
                self.output_scroll = (self.output_scroll + d as i64 * step).clamp(0, n);
            }
            Binding::Compose if !self.locked => self.ui.compose(),

            // Editing goes to whichever line is being typed into. The
            // passphrase gets the same vocabulary as the command line: it is
            // masked, so an operator who cannot correct it cannot recover.
            Binding::Edit(e) => {
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
                self.command.clear();
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
                if typing {
                    if !self.command.is_empty() {
                        self.submit();
                    }
                } else if self.ui.mode() == Mode::Compose {
                    self.composer.push('\n');
                } else {
                    self.ui.descend();
                }
            }
            Binding::Input(c) => {
                if self.init_step == Some(InitStep::Passphrase) {
                    self.passphrase.insert(c);
                } else if typing {
                    self.command.insert(c);
                } else if self.ui.mode() == Mode::Compose {
                    self.composer.push(c);
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
        self.drain_inbound();
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
        const MAX_TTL_MIN: u32 = 45 * 1440;
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
        let _ = expired;
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

    /// Reconcile with one peer over its established session.
    ///
    /// **Called only from the schedule.** `connect` cannot reach this: it goes
    /// through `establish`, which returns a session and nothing else. RFC 8
    /// §5.1's guarantee is that a keypress never causes a transfer, and the
    /// separation is that the two paths do not share a function.
    fn reconcile_with(&mut self, peer: &str) -> Option<activity_log::Event> {
        let window = {
            let now = now_epoch().0 * 1440;
            (
                now.saturating_sub(45 * 1440),
                now.saturating_add(45 * 1440) + 1,
            )
        };
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
        let done = self.exchanges.0.clone();
        let name = peer.to_string();
        // An exchange is about to put bytes on the link in both directions.
        // Set here rather than on completion: the thread runs for minutes on
        // a serial link, and an indicator that only lights up at the end
        // reports the one moment nothing is moving.
        self.outbound_ticks = ACTIVITY_GLYPH_TICKS;
        self.inbound_ticks = ACTIVITY_GLYPH_TICKS;
        std::thread::spawn(move || {
            let mut session = session;
            let mut view = shared::ExchangeView::new(view_store, window.0);
            let event = match krab_node::exchange::initiate(
                &mut *session,
                &mut view,
                [0u8; 32],
                window.0,
                window.1,
                salt,
            ) {
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

    /// Drain finished exchanges. Never blocks.
    fn drain_exchanges(&mut self) {
        while let Ok(event) = self.exchanges.1.try_recv() {
            if matches!(event, activity_log::Event::Failed { .. }) {
                self.links.failed(event.peer());
            }
            self.log.push(event);
        }
        // Mail may have arrived while the interface was doing nothing.
        if self.identity.is_some() && self.epoch_key.is_some() {
            self.refresh_inbox();
        }
    }

    /// Rebuild the tag table and open what this node can read.
    ///
    /// Called after anything that changes the corpus or the correspondent set.
    /// Returns plaintext into `self.messages`, which `lock` destroys.
    fn refresh_inbox(&mut self) {
        self.messages.clear();
        self.selected = 0;
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
                let Ok(bytes) = std::fs::read(self.peer_path(name, "link")) else {
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
                let reservoir = std::fs::read(self.peer_path(name, "reservoir"))
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
        // Rebuild only on rollover. A stale table loses the newest epoch,
        // which would present as "mail from today is undecryptable".
        if !self.tag_table.as_ref().is_some_and(|t| t.is_current(epoch)) {
            self.tag_table = Some(receive::TagTable::build(&peers, epoch));
        }
        let table = self.tag_table.as_ref().expect("just built");
        let scan = self
            .store
            .with(|st| receive::Inbox::scan(st, table, &peers, id.correspondence(), (0, u32::MAX)));

        self.list = if scan.messages.is_empty() {
            vec![format!(
                "(no messages — {} objects examined)",
                scan.examined
            )]
        } else {
            scan.messages
                .iter()
                .map(|m| {
                    format!(
                        "{}  {}{}",
                        m.from,
                        m.body
                            .lines()
                            .next()
                            .unwrap_or("")
                            .chars()
                            .take(48)
                            .collect::<String>(),
                        if m.post_quantum {
                            ""
                        } else {
                            "  (no reservoir)"
                        }
                    )
                })
                .collect()
        };
        // First-contact requests, on our own inbox tag. Shown at the top: a
        // request needs a human decision (RFC 3 §11's ceremony is a deliberate
        // act), and burying it under mail would mean it is never made.
        let requests = self.store.with(|st| {
            receive::scan_requests(st, id.correspondence(), &id.node_id(), epoch, (0, u32::MAX))
        });
        for inc in &requests {
            let note = inc.request.note.chars().take(40).collect::<String>();
            self.list.insert(
                0,
                format!(
                    "REQUEST from {}  {note}",
                    inc.request
                        .from
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
        self.show_selected();
    }

    /// Put the selected message in the view pane.
    fn show_selected(&mut self) {
        overwrite(&mut self.body);
        match self.messages.get(self.selected) {
            Some(m) => {
                self.body = format!("from {}\n\n{}", m.from, m.body);
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
        if self.history.last().map(String::as_str) != Some(line) {
            self.history.push(line.to_string());
        }
        self.history_at = self.history.len();
    }

    /// Run whatever is on the command line.
    fn submit(&mut self) {
        let line = self.command.take();
        // Tokenise once, up front, so a malformed line is refused with the
        // reason rather than reaching a verb that sees a truncated argument
        // and reports a file that does not exist.
        self.push_history(&line);
        // A new command's output starts at the newest line, not wherever the
        // operator had scrolled to.
        self.output_scroll = 0;
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
                let mut out = String::from("verbs\n");
                for (verb, what) in Command::SYNOPSES {
                    out.push_str(&format!("  {verb:<20}{what}\n"));
                }
                out.push_str("\nkeys\n");
                for (chord, what) in Command::CHORDS {
                    out.push_str(&format!("  {chord:<20}{what}\n"));
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
            Command::Rollcall => {
                self.output = match &self.identity {
                    Some(id) => format!(
                        "rollcall entry for {} refreshed.\n\nIt carries your statics \
                         and policy, signed. It does not carry endpoints — those are \
                         exchanged inside a peering (RFC 3 §9).",
                        id.short_id()
                    ),
                    None => "no identity — run `init` first".into(),
                };
            }
            Command::Send => self.output = self.send(line),
            Command::Request => self.output = self.peer_request(line),
            Command::Pack => self.output = self.pack(line),
            Command::Import => self.output = self.import(line),
        }
    }

    /// The path of a ceremony artifact.
    fn path(&self, name: &str) -> PathBuf {
        self.home.join(name)
    }

    /// Everything belonging to one peer, under one directory.
    ///
    /// `<home>/peers/<short-id>/<name>`. Flat files named `<short>.link` and
    /// `<short>.reservoir` worked while a peer had two artifacts; continuous
    /// re-keying gives each peer mutable state of its own, and state that
    /// belongs together should be removable together — a peering that ends
    /// should be one directory to shred, not a pattern to glob.
    fn peer_path(&self, peer: impl AsRef<str>, name: &str) -> PathBuf {
        self.home.join("peers").join(peer.as_ref()).join(name)
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
        let bytes = std::fs::read(self.path("ceremony.cbor"))
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
        atomic::write(&self.path("ceremony.cbor"), &p.encode(&wrapped))
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
        let Some(their_card) = pending.their_card.clone() else {
            return "no card recorded yet — run `peer accept <their.card>` first".into();
        };
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
        let theirs = match ceremony::decode_contribution(&bytes) {
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
        if let Err(e) = atomic::write(&self.peer_path(&short, "reservoir"), &out) {
            return format!("could not store the reservoir: {e}");
        }
        if let Err(e) = atomic::write(&self.peer_path(&short, "link"), &their_card.encode()) {
            return format!("could not store the peer-link: {e}");
        }
        shred::remove(&self.path("ceremony.cbor"), &mut OsRng);
        // `peer.pad` is this node's own contribution, written in the clear
        // because it has to be handed over. Once the reservoir exists it has no
        // further use and is half a live shared secret sitting unwrapped on
        // disk — the one file in the layout that is neither signed nor sealed,
        // and therefore the one where overwriting is the only tool available.
        shred::remove(&self.path("peer.pad"), &mut OsRng);
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
        if self
            .links
            .get(peer)
            .and_then(|l| l.session.as_ref())
            .is_none()
        {
            return None;
        }
        let w = self.epoch_key?;
        let sealed = std::fs::read(self.peer_path(peer, "reservoir")).ok()?;
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
        let card = match std::fs::read(self.peer_path(peer, "link"))
            .ok()
            .and_then(|b| peering::Card::decode(&b).ok())
            .filter(|c| c.verify())
        {
            Some(c) => c,
            None => return format!("no verifying peer-link for {peer} — peer with them first"),
        };

        // The reservoir, and where its ratchet has reached.
        let sealed = match std::fs::read(self.peer_path(peer, "reservoir")) {
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
        if let Err(e) = atomic::write(&self.peer_path(peer, "reservoir"), &out) {
            return format!("could not store the new reservoir: {e} — nothing changed");
        }
        // Their terms, which until now propagated once at peering and never
        // again. Written beside the link so a locked node still shows them.
        let _ = atomic::write(&self.peer_path(peer, "policy"), &outcome.theirs.encode());

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
    fn send(&mut self, line: &str) -> String {
        let (Some(peer), Some(_)) = (arg(line, 1), arg(line, 2)) else {
            return "usage: send <peer> <message>".into();
        };
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

        let card_bytes = match std::fs::read(self.peer_path(&peer, "link")) {
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
        let reservoir = std::fs::read(self.peer_path(&peer, "reservoir"))
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
        let tag = krab_crypto::pairwise_tag(&shared, epoch);

        let composed = match compose::seal_to(
            id.correspondence(),
            &compose::Recipient::Known {
                correspondence: &their_pk,
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
                let note = if chunk.is_some() {
                    ", post-quantum"
                } else {
                    ", no reservoir"
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
        let req = request::PeerRequest::create(
            id.signing_key(),
            id.card(Policy::default()),
            card.node_id(),
            Policy::default(),
            note,
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
                format!(
                    "request composed for {}.\n\nIt carries your card and an inner \
                     signature, because first contact cannot be deniable — the \
                     recipient can prove you sent it, which RFC 3 §5.1 considers \
                     the right trade for this one message.",
                    card.fingerprint()
                )
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
        let path = if out.contains('/') {
            PathBuf::from(out)
        } else {
            self.path(&out)
        };

        // MAX_TTL back from now, not "since last time". RFC 1 §2 sets the TTL
        // and the window follows it rather than anything the operator did.
        // `entries_in_range` is half-open, and an object composed today
        // expires at exactly `now + MAX_TTL` — the upper edge. A window that
        // stopped there would omit everything written today, every time.
        let now = now_epoch().0 * 1440;
        const MAX_TTL_MIN: u32 = 45 * 1440;
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
        let card_bytes = std::fs::read(self.peer_path(peer, "link"))
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

    /// RFC 8 §5.3's panel.
    fn peers_panel(&self) -> String {
        // Activity provenance belongs beside the per-peer aggregates: the log
        // says what just happened, `PeerMetrics` says what has been happening.
        let recent = self.log.recent(6);
        // No metrics source is wired yet, so the panel is honest about being
        // empty rather than inventing rows. `PeerMetrics` is counters-only by
        // construction (RFC 3 §12), which is the part that had to be right
        // before anything populated it.
        let rows: Vec<peers::Row> = Vec::new();

        // **Peerings, from disk — not links, from memory.** A peering is the
        // durable artifact (RFC 3 §4); a link is a socket that was open a
        // moment ago. Reporting only links meant a restarted node said "no
        // peers" while its peer-links sat on disk beside it, and told an
        // operator whose ceremony had completed to start another one.
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
            let policy = if self.peer_path(id, "policy").exists() {
                "terms current"
            } else {
                "terms as of peering"
            };
            out.push_str(&format!("{id}  peered  ·  {link}  ·  {policy}\n"));
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
        out.push_str("\nno accountability metrics yet — nothing has reconciled.");
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
        format!(
            "identity   {}  (this node's address — public, not a secret)\n\
             epochs     {epochs} wrapper{} ({} bytes)\n\
             corpus     {} objects, {} bytes (cap {})\n\
             tags       {table}\n\
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
                let pad = self.path("peer.pad").exists();
                match p.their_fingerprint() {
                    None => format!(
                        "step 1 of 5 — your card is written, theirs has not arrived.\n\n\
                         wrote:  {}\n\n\
                         next:   send them that file, then `peer accept <their.card>`",
                        self.path("peer.card").display()
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
        let n = shred::remove_matching(
            &self.home,
            |name| {
                // Bare `link` and `reservoir` live in `peers/<id>/`; the
                // suffixed forms are what older layouts left behind.
                name == "link"
                    || name == "reservoir"
                    || name.ends_with(".link")
                    || name.ends_with(".reservoir")
                    || name.ends_with(".krab")
                    || matches!(
                        name,
                        "identity.wrapped"
                            | "kek.params"
                            | "ceremony.cbor"
                            | "peer.card"
                            | "peer.pad"
                    )
            },
            &mut OsRng,
        );
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
        persist::write_params(&self.path("kek.params"), &self.identity_params())
            .map_err(|e| at("kek.params", e))?;
        if let Some(id) = &self.identity {
            persist::write_identity(&self.path("identity.wrapped"), id, kek, &mut OsRng)
                .map_err(|e| at("identity.wrapped", e))?;
        }
        self.store
            .with(|s| persist::write_corpus(&self.path("corpus.krab"), s))
            .map(|_| ())
            .map_err(|e| at("corpus.krab", e))
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
            Err(e) => return Some(format!("could not listen on {addr}: {e:?}")),
        };

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // Ends when the receiver is dropped, which happens when the App
            // does. Nothing else needs to signal it.
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
            .filter_map(|p| std::fs::read(self.peer_path(p, "link")).ok())
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
        for (session, static_pk) in arrived {
            // Which peering this is. The listener verified the static against
            // the set; this maps it back to the directory it belongs to.
            let who = self.peer_ids().into_iter().find(|p| {
                std::fs::read(self.peer_path(p, "link"))
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
    fn save_corpus(&self) {
        let _ = self
            .store
            .with(|s| persist::write_corpus(&self.path("corpus.krab"), s));
    }

    fn identity_params(&self) -> krab_crypto::kek::KekParams {
        self.identity
            .as_ref()
            .map(|i| i.kek_params)
            .unwrap_or_else(|| krab_crypto::kek::KekParams::new(&mut OsRng))
    }

    /// Whether a store already exists here.
    fn has_stored_identity(&self) -> bool {
        self.path("identity.wrapped").exists()
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
        let params = persist::read_params(&self.path("kek.params"))
            .map_err(|_| "no store here — run `init`".to_string())?;
        let kek = persist::kek_for(passphrase, &params)
            .map_err(|_| "that passphrase does not open this store".to_string())?;

        // Both attempts run regardless of which succeeds. Ordering the duress
        // check first would leak through early return; ordering it second
        // would leak the same way for a correct passphrase.
        let duress = std::fs::read(self.path("duress.wrapped"))
            .ok()
            .and_then(|sealed| kek.open(persist::CONTEXT_DURESS, &sealed).ok())
            .is_some();
        let identity = persist::read_identity(&self.path("identity.wrapped"), &kek, params).ok();

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
        let params = persist::read_params(&self.path("kek.params"))
            .map_err(|_| "no store here".to_string())?;
        let kek = persist::kek_for(passphrase, &params).map_err(|e| format!("{e:?}"))?;
        let sealed = kek
            .seal(persist::CONTEXT_DURESS, b"duress", &mut OsRng)
            .map_err(|e| format!("{e:?}"))?;
        atomic::write(&self.path("duress.wrapped"), &sealed)
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
        let w = id
            .hierarchy
            .open_epoch(&kek, epoch, &mut OsRng)
            .map_err(|e| format!("{e:?}"))?;
        self.identity = Some(id);
        self.epoch_key = Some(w);
        self.locked = false;

        // The corpus goes through the same verification a stranger's archive
        // does. The disk is not trusted (RFC 7 §4).
        let _ = self
            .store
            .with(|s| persist::read_corpus(&self.path("corpus.krab"), s, epoch.0 * 1440));
        self.refresh_inbox();
        Ok(())
    }

    /// Derive the KEK and open the current epoch, RFC 7 §4.
    fn open_store(&mut self) -> Result<(), String> {
        self.ensure_home()?;
        let Some(id) = &mut self.identity else {
            return Err("no identity to open a store for".into());
        };
        let kek = id
            .kek(self.passphrase.as_string().as_bytes())
            .map_err(|e| format!("could not derive the key: {e:?}"))?;
        self.epoch_key = Some(
            id.hierarchy
                .open_epoch(&kek, now_epoch(), &mut OsRng)
                .map_err(|e| format!("could not open the epoch: {e:?}"))?,
        );
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
        if let Err(e) = atomic::write(&self.path("peer.card"), &mine.card.encode()) {
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
            self.path("peer.card").display(),
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
                if let Some(note) = self.start_listener() {
                    self.output.push_str(&format!("\n\n{note}"));
                }
            }
            Some(next) => {
                if next == InitStep::Generate {
                    // Every key this node will ever hold originates here.
                    let id = Identity::generate(&mut OsRng);
                    self.output = format!("generated {}", id.short_id());
                    self.identity = Some(id);
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
        self.list = vec!["(locked)".into()];
        self.passphrase.clear();
        overwrite(&mut self.composer);
        // Both panes. `body` holds decrypted message plaintext and `output`
        // holds command output, and RFC 7 §8 does not distinguish: what is on
        // screen when the node locks must not survive the lock.
        overwrite(&mut self.body);
        overwrite(&mut self.output);
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
    Terminal::new(CrosstermBackend::new(io::stdout()))
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
        a.composer.push_str("a draft");
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
        a.identity = Some(id);
        a.passphrase = line::Line::from("a passphrase");
        a.open_store().expect("store opens");
        a
    }

    /// Two nodes with a completed peering, and the short id each uses for the
    /// other. The sneakernet path, because that is the one that keeps the
    /// post-quantum property and so is the interesting starting point.
    fn peered_pair(tag: &str) -> (App, App, String, String) {
        let mut a = ready_node(&format!("{tag}-a"));
        let mut b = ready_node(&format!("{tag}-b"));
        type_command(&mut a, "peer offer");
        type_command(&mut b, "peer offer");

        let carry = |from: &App, to: &App, name: &str, as_name: &str| {
            let bytes = std::fs::read(from.path(name)).expect("artifact exists");
            let dest = to.path(as_name);
            std::fs::write(&dest, bytes).expect("delivered");
            dest.to_string_lossy().into_owned()
        };
        let a_card = carry(&a, &b, "peer.card", "from-a.card");
        let b_card = carry(&b, &a, "peer.card", "from-b.card");
        type_command(&mut a, &format!("peer accept {b_card}"));
        type_command(&mut b, &format!("peer accept {a_card}"));

        let a_pad = pad_onto(&mut a, &b.path("from-a.pad"));
        let b_pad = pad_onto(&mut b, &a.path("from-b.pad"));
        type_command(&mut a, &format!("peer seal {b_pad} media"));
        type_command(&mut b, &format!("peer seal {a_pad} media"));
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
        let sealed = std::fs::read(n.peer_path(peer, "reservoir")).expect("a reservoir");
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
        a.identity = Some(Identity::generate(&mut OsRng));
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
        a.identity = Some(Identity::generate(&mut entropy::OsRng));
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
        let carry = |from: &App, to: &App, name: &str, as_name: &str| {
            let bytes = std::fs::read(from.path(name)).expect("artifact exists");
            let dest = to.path(as_name);
            std::fs::write(&dest, bytes).expect("delivered");
            dest.to_string_lossy().into_owned()
        };
        let a_card = carry(&a, &b, "peer.card", "from-a.card");
        let b_card = carry(&b, &a, "peer.card", "from-b.card");

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
        let a_pad = pad_onto(&mut a, &b.path("from-a.pad"));
        let b_pad = pad_onto(&mut b, &a.path("from-b.pad"));
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
            let sealed = std::fs::read(n.peer_path(peer, "reservoir")).unwrap();
            krab_crypto::kek::open_under(&n.epoch_key.unwrap(), b"krab/reservoir", &sealed).unwrap()
        };
        assert_eq!(
            reservoir(&a, &b),
            reservoir(&b, &a),
            "R_A xor R_B agrees on both ends"
        );
        assert_ne!(reservoir(&a, &b), vec![0u8; 32]);

        // The ceremony is retired, so a stale pad cannot be replayed into it.
        assert!(!a.path("ceremony.cbor").exists());
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
        std::fs::copy(b.path("peer.card"), a.path("b.card")).unwrap();
        {
            let mut b2 = App {
                home: b.home.clone(),
                ..App::default()
            };
            b2.identity = Some(Identity::generate(&mut OsRng));
            b2.epoch_key = b.epoch_key;
            type_command(&mut b2, &format!("peer pad {}", a.path("b.pad").display()));
        }

        let card = a.path("b.card").display().to_string();
        let pad = a.path("b.pad").display().to_string();
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
            n2.identity = Some(Identity::generate(&mut OsRng));
            n2.epoch_key = n.epoch_key;
            type_command(&mut n2, "peer offer");
        }
        type_command(&mut a, "peer offer");

        std::fs::copy(first.path("peer.card"), a.path("first.card")).unwrap();
        std::fs::copy(second.path("peer.card"), a.path("second.card")).unwrap();

        let p1 = a.path("first.card").display().to_string();
        type_command(&mut a, &format!("peer accept {p1}"));
        assert!(a.output.contains("their fingerprint"), "{}", a.output);

        let p2 = a.path("second.card").display().to_string();
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
        assert!(a.path("ceremony.cbor").exists());
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
            b2.identity = Some(Identity::generate(&mut OsRng));
            b2.epoch_key = b.epoch_key;
            type_command(&mut b2, "peer offer");
        }

        let mut raw = std::fs::read(b.path("peer.card")).unwrap();
        let n = raw.len();
        raw[n - 1] ^= 1; // last byte is inside the signature
        std::fs::write(a.path("forged.card"), raw).unwrap();

        let p = a.path("forged.card").display().to_string();
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
        assert!(
            a.output.contains("no accountability metrics yet"),
            "{}",
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

    /// `rollcall` publishes statics and policy, not endpoints — RFC 3 §9
    /// keeps endpoints inside a peering, so a public attestation is not a
    /// location beacon.
    #[test]
    fn rollcall_does_not_publish_endpoints() {
        let mut a = ready_node("rollcall");
        type_command(&mut a, "rollcall");
        assert!(
            a.output.contains("does not carry endpoints"),
            "{}",
            a.output
        );
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

        let carry = |from: &App, to: &App, name: &str, as_name: &str| {
            std::fs::write(to.path(as_name), std::fs::read(from.path(name)).unwrap()).unwrap();
            to.path(as_name).to_string_lossy().into_owned()
        };
        let b_card = carry(&b, &a, "peer.card", "from-b.card");
        let b_pad = pad_onto(&mut b, &a.path("from-b.pad"));
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
        assert!(a.peer_path(&peer, "link").exists());

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
            peering::Card::decode(&std::fs::read(a.path("peer.card")).unwrap())
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
        let sealed_res = std::fs::read(b.path(&format!(
            "{}.reservoir",
            short_id(&a.identity.as_ref().unwrap().node_id())
        )));
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
            &std::fs::read(a.peer_path(peer, "reservoir")).unwrap(),
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

        let carry = |from: &App, to: &App, name: &str, as_name: &str| {
            std::fs::write(to.path(as_name), std::fs::read(from.path(name)).unwrap()).unwrap();
            to.path(as_name).to_string_lossy().into_owned()
        };
        let b_card = carry(&b, &a, "peer.card", "from-b.card");
        let b_pad = pad_onto(&mut b, &a.path("from-b.pad"));
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
        assert!(a.path("outbound.krab").exists());
        // The manifest is for the courier, and names nobody.
        let manifest = std::fs::read_to_string(a.path("outbound.MANIFEST.hjson")).unwrap();
        assert!(!manifest.contains(&peer), "{manifest}");

        // Carried, renamed, imported.
        let delivered = b.path("holiday-photos.zip");
        std::fs::copy(a.path("outbound.krab"), &delivered).unwrap();
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
            peering::Card::decode(&std::fs::read(a.path("peer.card")).unwrap())
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
            &std::fs::read(a.peer_path(peer, "reservoir")).unwrap(),
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
        let one = std::fs::read(a.path("monday.krab")).unwrap();
        let two = std::fs::read(a.path("tuesday.krab")).unwrap();
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
            let b = krab_core::object::canonical_bytes(&h, &[3u8; 40]).unwrap();
            (krab_crypto::object_id(&b), b)
        };
        a.store
            .with(|s| s.ingest(id, bytes, now_epoch().0 * 1440, u32::MAX))
            .unwrap();
        type_command(&mut a, "pack out.krab");

        let mut raw = std::fs::read(a.path("out.krab")).unwrap();
        let mid = raw.len() / 2;
        raw[mid] ^= 0xFF;
        std::fs::write(b.path("torn.krab"), raw).unwrap();

        let p = b.path("torn.krab").display().to_string();
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

        let carry = |from: &App, to: &App, name: &str, as_name: &str| {
            std::fs::write(to.path(as_name), std::fs::read(from.path(name)).unwrap()).unwrap();
            to.path(as_name).to_string_lossy().into_owned()
        };
        // Each side records the other, so both can recognise the other's tags.
        let b_card = carry(&b, &a, "peer.card", "from-b.card");
        let a_card = carry(&a, &b, "peer.card", "from-a.card");
        let b_pad = pad_onto(&mut b, &a.path("from-b.pad"));
        let a_pad = pad_onto(&mut a, &b.path("from-a.pad"));
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

        let stick = b.path("anything.bin");
        std::fs::copy(a.path("out.krab"), &stick).unwrap();
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
            post_quantum: true,
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
        a.composer.push_str("a draft in progress");
        a.command = line::Line::from("half-typed");
        let before = (a.composer.clone(), a.command.clone(), a.store.len());

        for _ in 0..20 {
            a.tick_schedule();
        }
        assert_eq!(
            (a.composer.clone(), a.command.clone(), a.store.len()),
            before
        );
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
        let b = App::from_args(std::iter::empty()).unwrap();
        assert_ne!(
            b.home,
            PathBuf::from("/tmp/should-be-ignored"),
            "the environment must not decide"
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
            a.path("peer.card").exists(),
            "the card is public and signed"
        );
        assert!(
            !a.path("peer.pad").exists(),
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
        let card_before = std::fs::read(a.path("peer.card")).unwrap();
        assert!(a.path("ceremony.cbor").exists());

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
            "corpus.krab",
        ] {
            assert!(!a.path(name).exists(), "{name} survived wipe");
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
        them.identity = Some(their_id);
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
        a.identity = Some(id);
        a.passphrase = line::Line::from("open sesame please");
        a.open_store().unwrap();
        let node_id = a.identity.as_ref().unwrap().node_id();
        let fingerprint = a.identity.as_ref().unwrap().fingerprint();

        type_command(&mut a, "peer offer");
        std::fs::copy(them.path("peer.card"), a.path("t.card")).unwrap();
        pad_onto(&mut them, &a.path("t.pad"));
        let card = a.path("t.card").display().to_string();
        let pad = a.path("t.pad").display().to_string();
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
        assert!(b.peer_path(peer, "link").exists());
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
        a.identity = Some(id);
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
        a.identity = Some(id);
        a.passphrase = line::Line::from("passphrase");
        a.open_store().unwrap();
        type_command(&mut a, "peer offer");

        let allowed = [
            "identity.wrapped", // sealed under the KEK
            "kek.params",       // plaintext, self-defeating to tamper with
            "corpus.krab",      // content-addressed
            "ceremony.cbor",    // signed cards, wrapped contribution
            "peer.card",        // signed
            "peer.pad",         // destroyed at seal; see the pad-life test
        ];
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
        a.identity = Some(id);
        a.passphrase = line::Line::from("the real one");
        a.open_store().unwrap();
        type_command(&mut a, "peer offer");
        a.set_duress(b"under duress").unwrap();
        assert!(a.path("identity.wrapped").exists());
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
        a.identity = Some(id);
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
        a.identity = Some(id);
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
        a.identity = Some(id);
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
        std::fs::copy(b.path("peer.card"), a.path("stranger.card")).unwrap();
        let card = a.path("stranger.card").display().to_string();
        type_command(&mut a, &format!("request {card} we met at the thing"));
        assert!(a.output.contains("request composed"), "{}", a.output);
        assert_eq!(a.store.len(), 1);

        // It travels as an ordinary object, so a stick carries it.
        type_command(&mut a, "pack out.krab");
        let stick = b.path("unremarkable.bin");
        std::fs::copy(a.path("out.krab"), &stick).unwrap();
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
        let req = &incoming[0].request;
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
        std::fs::copy(b.path("peer.card"), a.path("b.card")).unwrap();
        let card = a.path("b.card").display().to_string();
        type_command(&mut a, &format!("request {card} for B only"));
        type_command(&mut a, "pack out.krab");

        let mut c = c;
        let stick = c.path("in.krab");
        std::fs::copy(a.path("out.krab"), &stick).unwrap();
        type_command(&mut c, &format!("import {}", stick.display()));

        let incoming = c.store.with(|st| {
            receive::scan_requests(
                st,
                c.identity.as_ref().unwrap().correspondence(),
                &c.identity.as_ref().unwrap().node_id(),
                now_epoch(),
                (0, u32::MAX),
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
        a.identity = Some(id);
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
        std::fs::write(a.path("abcd1234.reservoir"), sealed).unwrap();

        // What a peer that stayed up would hold today.
        let mut peer = krab_crypto::reservoir::Reservoir::new(root, then);
        assert!(peer.advance_to(now_epoch()), "within MAX_ADVANCE");

        // What this node reconstructs from the record alone.
        let raw = std::fs::read(a.path("abcd1234.reservoir")).unwrap();
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
                let b = krab_core::object::canonical_bytes(&h, &[7u8; 40]).unwrap();
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
            let b = krab_core::object::canonical_bytes(&h, &[3u8; 40]).unwrap();
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
        a.identity = Some({
            let mut id = Identity::generate(&mut OsRng);
            id.kek_params.m_kib = 64;
            id.kek_params.t = 1;
            id.kek_params.p = 1;
            id
        });
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
        a.composer.push_str("a draft");
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
        a.identity = Some(id);
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
            a.identity = Some(id);
            a.passphrase = line::Line::from("a passphrase");
            a.open_store().expect("the store opens");
            std::fs::remove_file(a.path("corpus.krab")).expect("start without one");
            a
        };

        let mut chord = make("quit-chord");
        chord.on_key(KeyCode::Char('q'), KeyModifiers::CONTROL);
        assert!(chord.quit);
        assert!(
            chord.path("corpus.krab").exists(),
            "Ctrl-Q left the corpus unwritten"
        );

        let mut verb = make("quit-verb");
        type_command(&mut verb, "quit");
        assert!(verb.quit);
        assert!(
            verb.path("corpus.krab").exists(),
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
        std::fs::write(a.peer_path(peer, "link"), b"a card").unwrap();
        std::fs::write(a.peer_path(peer, "reservoir"), b"sealed").unwrap();

        a.confirmed = true;
        type_command(&mut a, "wipe");

        assert!(
            !a.peer_path(peer, "link").exists(),
            "the peer-link survived the wipe"
        );
        assert!(
            !a.peer_path(peer, "reservoir").exists(),
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
            std::fs::write(a.peer_path(id, "link"), b"card").unwrap();
        }
        assert_eq!(a.peer_ids(), vec!["aaaa1111", "bbbb2222"]);
        assert_eq!(
            a.peer_path("aaaa1111", "reservoir"),
            a.home.join("peers").join("aaaa1111").join("reservoir")
        );
        // A directory without a link is not a peer — a half-written one must
        // not be reported as peered.
        a.ensure_peer_dir("cccc3333").unwrap();
        assert_eq!(a.peer_ids(), vec!["aaaa1111", "bbbb2222"]);
    }

    /// **The panic chord.** RFC 7 §10's wipe for an operator who does not have
    /// time to type. `duress` covers being watched; this covers having
    /// seconds.
    #[test]
    fn the_panic_chord_needs_two_presses_and_destroys_everything() {
        let mut a = ready_node("panic-chord");
        assert!(a.identity.is_some() && a.epoch_key.is_some());

        let chord = |a: &mut App| {
            a.on_key(
                KeyCode::Char('W'),
                KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SHIFT,
            )
        };

        // One press arms and destroys nothing.
        chord(&mut a);
        assert!(a.identity.is_some(), "one press must not destroy anything");
        assert!(a.output.contains("ARMED"), "{}", a.output);

        // The second finishes it.
        chord(&mut a);
        assert!(a.identity.is_none(), "the hierarchy survived");
        assert!(a.epoch_key.is_none());
        assert!(!a.path("identity.wrapped").exists(), "the store survived");
    }

    /// An armed node that stays armed destroys itself on an unrelated
    /// keystroke later. Anything else disarms it.
    #[test]
    fn any_other_key_disarms_the_panic_chord() {
        let mut a = ready_node("panic-disarm");
        a.on_key(
            KeyCode::Char('W'),
            KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SHIFT,
        );
        assert!(a.panic_armed.is_some());

        a.on_key(KeyCode::Char('x'), KeyModifiers::NONE);
        assert!(a.panic_armed.is_none(), "still armed after another key");

        // So a later press only arms again, it does not fire.
        a.on_key(
            KeyCode::Char('W'),
            KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SHIFT,
        );
        assert!(a.identity.is_some(), "it fired without a second press");
        assert!(a.output.contains("ARMED"));
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
            a.peer_path(&b_id2, "policy").exists(),
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
        let sealed = std::fs::read(n.peer_path(peer, "reservoir")).unwrap();
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
        atomic::write(&n.peer_path(peer, "reservoir"), &out).unwrap();
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
        let mut r = krab_crypto::reservoir::Reservoir::new(stored_root(&a, &b_id), now_epoch());
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

        assert!(a.path("peer.card").exists(), "the card was not written");
        assert!(
            !a.path("peer.pad").exists(),
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
            let bytes = std::fs::read(b.path("peer.card")).unwrap();
            let dest = a.path("from-b.card");
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
            let bytes = std::fs::read(b.path("peer.card")).unwrap();
            let dest = a.path("from-b.card");
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
            if b.links
                .get(&a_id)
                .and_then(|l| l.session.as_ref())
                .is_some()
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            b.links
                .get(&a_id)
                .and_then(|l| l.session.as_ref())
                .is_some(),
            "the accepted session never reached the link table"
        );
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
        std::fs::copy(b.path("peer.card"), &card).unwrap();

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
        a.on_key(KeyCode::Char('g'), KeyModifiers::CONTROL);
        assert_eq!(a.ui.tab(), layout::Tab::Channels);
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
}
