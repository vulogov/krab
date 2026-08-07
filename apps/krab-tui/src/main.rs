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
mod command;
mod entropy;
mod identity;
mod keys;
mod layout;
mod peering;
mod render;

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
use peering::{offer, Policy};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io::{self, Stdout};
use std::time::{Duration, Instant};

/// How often the interface redraws when nothing has happened.
///
/// Slow on purpose. The spinner is the only thing that needs a tick, and RFC 8
/// §5.1's concern about drawing the eye applies to redraw rate as much as to
/// wording — plus this is bandwidth on a serial console or a poor SSH link,
/// which are transports Krab exists to serve.
const TICK: Duration = Duration::from_millis(250);

fn main() -> io::Result<()> {
    let mut app = App::default();
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
    command: String,
    composer: String,
    body: String,
    list: Vec<String>,
    locked: bool,
    quit: bool,
    /// This node's keys, once `init` has completed. `None` on a fresh install.
    identity: Option<Identity>,
    /// The passphrase being typed. Never echoed — see `View::masked`.
    passphrase: String,
    /// Set by the confirmation prompt, consumed by the next command.
    confirmed: bool,
    /// Where the first-run ceremony has got to, if it is running.
    init_step: Option<InitStep>,
}

impl Default for App {
    fn default() -> App {
        App {
            ui: Ui::default(),
            node: NodeState::default(),
            spinner: Spinner::default(),
            command: String::new(),
            composer: String::new(),
            body: "no message selected".into(),
            list: vec!["(no messages)".into()],
            locked: false,
            quit: false,
            identity: None,
            passphrase: String::new(),
            confirmed: false,
            init_step: None,
        }
    }
}

impl App {
    fn run(&mut self, term: &mut Terminal<CrosstermBackend<Stdout>>) -> io::Result<()> {
        let mut last = Instant::now();
        while !self.quit {
            term.draw(|f| {
                render::draw(
                    f,
                    &render::View {
                        ui: &self.ui,
                        node: &self.node,
                        spinner: &self.spinner,
                        list: &self.list,
                        body: &self.body,
                        command: if self.init_step == Some(InitStep::Passphrase) {
                            &self.passphrase
                        } else {
                            &self.command
                        },
                        composer: &self.composer,
                        locked: self.locked,
                        masked: self.init_step == Some(InitStep::Passphrase),
                    },
                )
            })?;

            if event::poll(TICK)? {
                if let Event::Key(k) = event::read()? {
                    if k.kind == KeyEventKind::Press {
                        self.on_key(k.code, k.modifiers);
                    }
                }
            }
            if last.elapsed() >= TICK {
                self.spinner.tick();
                last = Instant::now();
            }
        }
        Ok(())
    }

    fn on_key(&mut self, code: KeyCode, mods: KeyModifiers) {
        let press = KeyPress {
            code: match code {
                KeyCode::Tab | KeyCode::BackTab => Key::Tab,
                KeyCode::Enter => Key::Enter,
                KeyCode::Esc => Key::Esc,
                KeyCode::Char(c) => Key::Char(c),
                _ => return,
            },
            ctrl: mods.contains(KeyModifiers::CONTROL),
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
            Binding::Lock => self.lock(),
            Binding::CycleFocus => self.ui.cycle_focus(),
            Binding::CycleFocusBack => self.ui.cycle_focus_back(),
            Binding::ToggleZoom => self.ui.toggle_zoom(),
            Binding::SwitchTab => self.ui.switch_tab(),
            Binding::Compose if !self.locked => self.ui.compose(),
            Binding::Cancel if typing => self.command.clear(),
            Binding::Cancel => {
                if self.ui.mode() == Mode::Compose {
                    // RFC 7 §8: plaintext exists only while displayed.
                    overwrite(&mut self.composer);
                    self.ui.end_compose();
                } else {
                    self.ui.ascend();
                }
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
                    self.passphrase.push(c);
                } else if typing {
                    self.command.push(c);
                } else if self.ui.mode() == Mode::Compose {
                    self.composer.push(c);
                } else if c == 'q' {
                    self.quit = true;
                }
            }
            _ => {}
        }
    }

    /// Run whatever is on the command line.
    fn submit(&mut self) {
        let line = core::mem::take(&mut self.command);
        let Some(cmd) = Command::parse(&line) else {
            self.body = format!("unknown command: {}", line.trim());
            return;
        };
        match admit(&cmd, self.identity.is_some(), self.locked, self.confirmed) {
            Err(Refusal::NoIdentity) => {
                self.body = "no identity yet — run `init` first".into();
            }
            Err(Refusal::Locked) => {
                self.body = format!("`{cmd}` needs an unlocked node");
            }
            Err(Refusal::AlreadyInitialised) => {
                self.body = "this node already has an identity; `init` runs once".into();
            }
            Err(Refusal::NeedsConfirmation) => {
                // RFC 7 §10 — the one irreversible verb, and the one prompt.
                self.confirmed = true;
                self.body = format!("`{cmd}` destroys the key hierarchy                     and cannot be undone. Type it again to confirm.");
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
                self.body = InitStep::Passphrase.prompt().into();
            }
            Command::Lock => self.lock(),
            Command::Wipe => {
                self.lock();
                // Dropping the identity runs every key's `Drop`, which
                // zeroizes. RFC 7 §4: erasure is destroying a key, and nothing
                // here touches a file.
                self.identity = None;
                overwrite(&mut self.passphrase);
                self.body = "key hierarchy destroyed".into();
            }
            Command::Peer => {
                let rest = line.trim().strip_prefix("peer").unwrap_or("");
                self.body = match Peering::parse(rest) {
                    // `offer` writes two files on purpose — see peering.rs.
                    // Two artifacts on purpose — see `peering`.
                    Some(Peering::Offer) => self.peer_offer(),
                    Some(Peering::Accept) => "card accepted — now compare fingerprints aloud, \
                         then `peer seal`"
                        .into(),
                    Some(Peering::Seal) => "peer-link signed".into(),
                    Some(Peering::Status) => "no ceremony in progress".into(),
                    None => format!("unknown: peer{rest}"),
                };
            }
            // RFC 3 §11 step 2, and RFC 8 §5's `verify`.
            Command::Verify => {
                self.body = match &self.identity {
                    Some(id) => format!(
                        "read these eight words aloud and hear the same back:\n\n  {}",
                        id.fingerprint()
                    ),
                    None => "no identity".into(),
                }
            }
            other => self.body = format!("`{other}` is not implemented yet"),
        }
    }

    /// Derive the KEK and open the current epoch, RFC 7 §4.
    fn open_store(&mut self) -> Result<(), krab_crypto::kek::Error> {
        let Some(id) = &mut self.identity else {
            return Err(krab_crypto::kek::Error::Kdf);
        };
        let kek = id.kek(self.passphrase.as_bytes())?;
        id.hierarchy.open_epoch(&kek, now_epoch(), &mut OsRng)?;
        // `kek` drops here. RFC 7 §4: it is memory-only and never written, and
        // the shorter it lives the better — it is re-derived on unlock.
        Ok(())
    }

    /// Produce this node's half of a peering — RFC 3 §11 steps 1 and 3.
    fn peer_offer(&self) -> String {
        let Some(id) = &self.identity else {
            return "no identity".into();
        };
        let mine = offer(id.card(Policy::default()), {
            let mut r = OsRng;
            r.next_32()
        });
        // The card is publishable; the contribution is half a shared secret,
        // and the two must not travel together. See `peering`'s module docs
        // and `RFC-7-review.md` §10 for why the channel matters.
        format!(
            "peer.card  — publishable; send it any way you like\n\
             peer.pad   — SECRET; hand over in person or on media\n\n\
             your fingerprint, to read aloud:\n\n  {}\n\n\
             a pad sent through the corpus still works and is not \
             post-quantum. `peer seal` will record which you used.",
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

        // Refuse to leave the passphrase step with nothing. The KEK is the
        // only root (RFC 7 §4), so an empty passphrase is a store anyone who
        // picks up the disk can open.
        if step == InitStep::Passphrase && self.passphrase.is_empty() {
            self.body = "a passphrase is required — it is the only root".into();
            return;
        }

        match step.next() {
            Some(InitStep::Done) | None => {
                // The last act of the ceremony: derive the KEK and open the
                // current epoch's wrapper. Argon2id at RFC 7 §4.1's parameters
                // takes ~500 ms and 64 MiB, which is the whole point — it is
                // what a seized disk has to get through.
                self.body = match self.open_store() {
                    Ok(()) => format!(
                        "{}\n\nmessage history is NOT recoverable from that backup, \
                         and that is intentional (RFC 7 §11).",
                        InitStep::Done.prompt()
                    ),
                    Err(e) => {
                        // Leave the ceremony where it is: an identity without a
                        // KEK has nothing to wrap its keys under.
                        return self.body = format!("could not derive the key: {e:?}");
                    }
                };
                self.init_step = None;
                // The passphrase has done its work and must not linger (§9).
                overwrite(&mut self.passphrase);
            }
            Some(next) => {
                if next == InitStep::Generate {
                    // Every key this node will ever hold originates here.
                    let id = Identity::generate(&mut OsRng);
                    self.body = format!("generated {}", id.short_id());
                    self.identity = Some(id);
                }
                self.init_step = Some(next);
                if next == InitStep::ShowBackup {
                    let phrase = self
                        .identity
                        .as_ref()
                        .map(|i| i.backup_phrase())
                        .unwrap_or_default();
                    self.body = format!("{}\n\n{}", next.prompt(), phrase);
                } else if next != InitStep::Generate {
                    self.body = next.prompt().into();
                }
            }
        }
    }

    /// Lock: zeroize what the interface holds and drop to the relay role.
    ///
    /// The node keeps reconciling — `RFC-8-review.md` §8.5 makes pausing it an
    /// I-5 violation worse than mail-driven sync, because it leaks a daily
    /// rhythm rather than sporadic events. Nothing here touches the schedule,
    /// and nothing here can.
    fn lock(&mut self) {
        overwrite(&mut self.passphrase);
        overwrite(&mut self.composer);
        overwrite(&mut self.body);
        self.body.push_str("locked");
        self.ui.end_compose();
        self.locked = true;
    }
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
    krab_core::tag::Epoch::at(secs)
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
        assert!(a.body.contains("run `init` first"), "{}", a.body);
        assert!(a.identity.is_none());
    }

    /// The store is openable when the ceremony finishes: an identity without
    /// a wrapper key would have nothing to protect its own keys under.
    #[test]
    fn finishing_init_opens_the_current_epoch() {
        let mut a = App::default();
        a.identity = Some(Identity::generate(&mut OsRng));
        a.passphrase.push_str("a passphrase");
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
        assert!(a.body.contains("runs once"), "{}", a.body);
    }

    /// Wipe is the only verb that asks twice, and lock is not on that list.
    #[test]
    fn wipe_asks_once_then_destroys() {
        let mut a = App::default();
        a.identity = Some(Identity::generate(&mut entropy::OsRng));
        type_command(&mut a, "wipe");
        assert!(a.body.contains("cannot be undone"), "{}", a.body);
        assert!(a.identity.is_some(), "first wipe only prompts");
        type_command(&mut a, "wipe");
        assert!(a.identity.is_none(), "second wipe destroys");
        assert!(a.locked);
    }

    #[test]
    fn peer_offer_names_both_files_and_marks_which_is_secret() {
        let mut a = App::default();
        a.identity = Some(Identity::generate(&mut entropy::OsRng));
        type_command(&mut a, "peer offer");
        assert!(
            a.body.contains("peer.card") && a.body.contains("peer.pad"),
            "{}",
            a.body
        );
        assert!(
            a.body.contains("SECRET"),
            "the unforwardable half is marked"
        );
    }

    #[test]
    fn an_unknown_command_is_reported_not_swallowed() {
        let mut a = App::default();
        type_command(&mut a, "frobnicate");
        assert!(a.body.contains("unknown command"), "{}", a.body);
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
        a.on_key(KeyCode::Esc, KeyModifiers::NONE);
        assert!(a.composer.is_empty());
        assert_eq!(a.ui.mode(), Mode::Browse);
    }
}
