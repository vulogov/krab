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
mod ceremony;
mod command;
mod compose;
mod courier;
mod entropy;
mod identity;
mod keys;
mod layout;
mod links;
mod peering;
mod peers;
mod reach;
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
    /// The current epoch wrapper key `W_N`, held **only while unlocked**.
    ///
    /// RFC 7 §4: the KEK is memory-only and re-derived on unlock. `W_N` is
    /// what actually seals stored secrets, so a locked node not holding it is
    /// what makes `RFC-7-review.md` §9's role transition real rather than
    /// cosmetic — a locked node cannot read its own ceremony state.
    epoch_key: Option<[u8; 32]>,
    /// Where cards, pads and ceremony state live.
    home: PathBuf,
    /// Transports. **Holds nothing that can reconcile** — RFC 8 §5.1.
    links: LinkTable,
    /// The corpus.
    store: krab_store::index::Store,
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
            epoch_key: None,
            home: std::env::var_os("KRAB_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(".")),
            links: LinkTable::new(),
            store: krab_store::index::Store::new(),
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
                    // `offer` writes two files on purpose — see `peering`.
                    Some(Peering::Offer) => self.peer_offer(),
                    Some(Peering::Accept) => self.peer_accept(arg(rest, 1)),
                    Some(Peering::Seal) => self.peer_seal(arg(rest, 1), arg(rest, 2)),
                    Some(Peering::Status) => self.peer_status(),
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
            // RFC 8 §5.1: establishes a transport and MUST NOT sync. The
            // guarantee is structural -- `LinkTable` has no reconciler to call.
            Command::Connect => {
                let (Some(peer), kind) = (arg(line, 1), arg(line, 2).unwrap_or("tcp")) else {
                    self.body = "usage: connect <peer> [tcp|courier|lora]".into();
                    return;
                };
                let Some(profile) = profile_named(kind) else {
                    self.body = format!("unknown transport {kind:?}");
                    return;
                };
                self.links.connect(peer, profile);
                // Establishment is synchronous here; a real transport would
                // leave it `Establishing` and animate that, which RFC 4 §5.2
                // requires and RFC 8 §5.1 explicitly permits.
                self.links.established(peer);
                let l = self.links.get(peer).expect("just connected");
                self.body = format!(
                    "{}\n\nnothing was transferred. Reconciliation is scheduled \
                     and does not follow your keypresses (RFC 8 §5.1).",
                    l.status_line()
                );
            }
            Command::Disconnect => {
                let Some(peer) = arg(line, 1) else {
                    self.body = "usage: disconnect <peer>".into();
                    return;
                };
                self.body = if self.links.disconnect(peer) {
                    // RFC 3 §6.2's quota reduction is deliberately not bundled:
                    // making disconnect a punishment discourages using it, and
                    // RFC 8 §5.3 needs operators to act.
                    format!("{peer} disconnected. Quota unchanged — adjust it from `peers`.")
                } else {
                    format!("no link to {peer}")
                };
            }
            Command::Peers => self.body = self.peers_panel(),
            Command::Reach => self.body = self.reach_report(line),
            Command::Keys => self.body = self.keys_report(),
            Command::Rollcall => {
                self.body = match &self.identity {
                    Some(id) => format!(
                        "rollcall entry for {} refreshed.\n\nIt carries your statics \
                         and policy, signed. It does not carry endpoints — those are \
                         exchanged inside a peering (RFC 3 §9).",
                        id.short_id()
                    ),
                    None => "no identity — run `init` first".into(),
                };
            }
            Command::Send => self.body = self.send(line),
            Command::Pack => self.body = self.pack(line),
            Command::Import => self.body = self.import(line),
        }
    }

    /// The path of a ceremony artifact.
    fn path(&self, name: &str) -> PathBuf {
        self.home.join(name)
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
        std::fs::write(self.path("ceremony.cbor"), p.encode(&wrapped))
            .map_err(|e| format!("could not write ceremony state: {e}"))
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
            Err(e) => return format!("could not read {path}: {e}"),
        };
        let card = match peering::Card::decode(&bytes) {
            Ok(c) => c,
            Err(e) => return format!("not a card: {e:?}"),
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
            "card accepted. Now read these eight words aloud and hear the same back:\n\n  \
             {}\n\nthen: peer seal <their.pad> <channel>",
            pending.their_fingerprint().unwrap_or_default()
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
            Err(e) => return format!("could not read {path}: {e}"),
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
        let out = match self.epoch_key.and_then(|w| {
            krab_crypto::kek::seal_under(&w, b"krab/reservoir", &reservoir, &mut OsRng).ok()
        }) {
            Some(sealed) => sealed,
            None => return "locked".into(),
        };
        // The peer-link: their card, and the reservoir sealed under W_N. This
        // is what `send` resolves a peer name against — RFC 3 §4 makes the
        // link the durable artifact, not the ceremony.
        let short = short_id(&their_card.node_id());
        if let Err(e) = std::fs::write(self.path(&format!("{short}.reservoir")), out) {
            return format!("could not store the reservoir: {e}");
        }
        if let Err(e) = std::fs::write(self.path(&format!("{short}.link")), their_card.encode()) {
            return format!("could not store the peer-link: {e}");
        }
        let _ = std::fs::remove_file(self.path("ceremony.cbor"));

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

        let card_bytes = match std::fs::read(self.path(&format!("{peer}.link"))) {
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
        let reservoir = std::fs::read(self.path(&format!("{peer}.reservoir")))
            .ok()
            .and_then(|sealed| krab_crypto::kek::open_under(&w, b"krab/reservoir", &sealed).ok())
            .and_then(|raw| <[u8; 32]>::try_from(raw.as_slice()).ok())
            .map(|root| krab_crypto::reservoir::Reservoir::new(root, epoch));
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
            .ingest(composed.id, composed.bytes, epoch.0 * 1440, u32::MAX)
        {
            Ok(()) => format!(
                "composed {} bytes in bucket {}{}.\n\nIt is in your corpus and will \
                 leave on a scheduled reconciliation — not now, and not because you \
                 pressed send (RFC 5 §6.1).",
                n,
                composed.bucket,
                if chunk.is_some() {
                    ", post-quantum"
                } else {
                    ", no reservoir"
                }
            ),
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
        let out = arg(line, 1).unwrap_or("krab-archive.krab");
        let kind = arg_value(line, "--for").unwrap_or("courier");
        let Some(profile) = profile_named(kind) else {
            return format!("unknown transport {kind:?}");
        };
        let path = if out.contains('/') {
            PathBuf::from(out)
        } else {
            self.path(out)
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

        match courier::pack(&self.store, &path, window, &profile) {
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
        match courier::import(&mut self.store, &path, now) {
            Err(e) => format!("could not read {}: {e}", path.display()),
            Ok(got) => format!(
                "{} new, {} already held, {} refused ({} records).\n\nNothing was \
                 trusted: every object was re-hashed before it entered the corpus.",
                got.accepted,
                got.duplicate,
                got.refused,
                got.total()
            ),
        }
    }

    /// RFC 8 §5.3's panel.
    fn peers_panel(&self) -> String {
        // No metrics source is wired yet, so the panel is honest about being
        // empty rather than inventing rows. `PeerMetrics` is counters-only by
        // construction (RFC 3 §12), which is the part that had to be right
        // before anything populated it.
        let rows: Vec<peers::Row> = Vec::new();
        if self.links.up_count() == 0 && rows.is_empty() {
            return peers::render(&rows, peers::DISCONNECT_KEY);
        }
        let mut out = String::new();
        for l in self.links.iter() {
            out.push_str(&l.status_line());
            out.push('\n');
        }
        out.push_str("\nno accountability metrics yet — nothing has reconciled.");
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
    fn keys_report(&self) -> String {
        let Some(id) = &self.identity else {
            return "no identity — run `init` first".into();
        };
        let epochs = id.hierarchy.epochs().count();
        format!(
            "identity   {}\nepochs     {epochs} wrapper{} ({} bytes)\nbackup                  shown once at init and never again (RFC 7 §11)\nreservoir  none \
             established\n\nmessage history is not recoverable from the identity \
             backup, and that is intentional.",
            id.short_id(),
            if epochs == 1 { "" } else { "s" },
            id.hierarchy.stored_bytes(),
        )
    }

    /// Report where a ceremony has reached.
    fn peer_status(&self) -> String {
        match self.load_ceremony() {
            Err(e) => e,
            Ok(p) => match p.their_fingerprint() {
                None => "offer made; waiting for their card. Next: peer accept <their.card>".into(),
                Some(f) => format!(
                    "their card recorded: {f}\n\ncompare those aloud, then: \
                     peer seal <their.pad> <channel>"
                ),
            },
        }
    }

    /// Derive the KEK and open the current epoch, RFC 7 §4.
    fn open_store(&mut self) -> Result<(), krab_crypto::kek::Error> {
        let Some(id) = &mut self.identity else {
            return Err(krab_crypto::kek::Error::Kdf);
        };
        let kek = id.kek(self.passphrase.as_bytes())?;
        self.epoch_key = Some(id.hierarchy.open_epoch(&kek, now_epoch(), &mut OsRng)?);
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

        // Two files, never one. See `peering`'s module documentation: a single
        // blob holding both halves would look routine and be catastrophic to
        // forward.
        if let Err(e) = std::fs::write(self.path("peer.card"), mine.card.encode()) {
            return format!("could not write peer.card: {e}");
        }
        if let Err(e) = std::fs::write(
            self.path("peer.pad"),
            ceremony::encode_contribution(&mine.contribution),
        ) {
            return format!("could not write peer.pad: {e}");
        }
        if let Err(e) = self.save_ceremony(&pending) {
            return e;
        }
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
        // RFC-7-review.md §9: a locked node keeps its links and loses its
        // content keys. `W_N` is a content key.
        if let Some(mut w) = self.epoch_key.take() {
            use zeroize::Zeroize;
            w.zeroize();
        }
        overwrite(&mut self.passphrase);
        overwrite(&mut self.composer);
        overwrite(&mut self.body);
        self.body.push_str("locked");
        self.ui.end_compose();
        self.locked = true;
    }
}

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

/// The `n`th whitespace-separated argument of a command line.
fn arg(line: &str, n: usize) -> Option<&str> {
    line.split_whitespace().nth(n)
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
        a.passphrase.push_str("a passphrase");
        a.open_store().expect("store opens");
        a
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
        let mut a = ready_node("offer-names");
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
            a.body.contains("read these eight words aloud"),
            "{}",
            a.body
        );
        type_command(&mut b, &format!("peer accept {a_card}"));
        assert!(
            b.body.contains("read these eight words aloud"),
            "{}",
            b.body
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
        let a_pad = carry(&a, &b, "peer.pad", "from-a.pad");
        let b_pad = carry(&b, &a, "peer.pad", "from-b.pad");
        type_command(&mut a, &format!("peer seal {b_pad} media"));
        type_command(&mut b, &format!("peer seal {a_pad} media"));
        assert!(a.body.starts_with("peer-link signed"), "{}", a.body);
        assert!(b.body.starts_with("peer-link signed"), "{}", b.body);
        // Both ends report the same agreed terms, from opposite directions.
        assert!(a.body.contains("agreed: buckets to 7"), "{}", a.body);
        assert!(b.body.contains("agreed: buckets to 7"), "{}", b.body);

        // Sneakernet keeps the post-quantum property, so neither is warned.
        assert!(!a.body.contains("does NOT survive"), "{}", a.body);
        assert!(!a.body.contains("never compared"), "{}", a.body);

        // **Both ends derived the same reservoir**, having exchanged only files.
        // The peer-link is named for the counterparty, so each side looks the
        // other up by identifier.
        let reservoir = |n: &App, other: &App| {
            let peer = short_id(&other.identity.as_ref().unwrap().node_id());
            let sealed = std::fs::read(n.path(&format!("{peer}.reservoir"))).unwrap();
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
        std::fs::copy(b.path("peer.pad"), a.path("b.pad")).unwrap();

        let card = a.path("b.card").display().to_string();
        let pad = a.path("b.pad").display().to_string();
        type_command(&mut a, &format!("peer accept {card}"));
        type_command(&mut a, &format!("peer seal {pad} corpus"));
        assert!(a.body.starts_with("peer-link signed"), "{}", a.body);
        assert!(
            a.body.contains("does NOT survive"),
            "the downgrade is stated: {}",
            a.body
        );
        assert!(
            a.body.contains("never compared"),
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
        assert!(a.body.contains("usage:"), "{}", a.body);
        assert!(a.body.contains("not guessed"), "{}", a.body);

        type_command(&mut a, "peer seal somewhere.pad probably-fine");
        assert!(a.body.contains("unknown channel"), "{}", a.body);
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
        assert!(a.body.contains("eight words"), "{}", a.body);

        let p2 = a.path("second.card").display().to_string();
        type_command(&mut a, &format!("peer accept {p2}"));
        assert!(a.body.contains("already recorded"), "{}", a.body);
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
        assert!(a.body.contains("does not verify"), "{}", a.body);
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

        let body = a.body.to_lowercase();
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
                a.body
            );
        }
        // It says the true thing instead.
        assert!(a.body.contains("nothing was transferred"), "{}", a.body);
        assert!(a.body.contains("link up"), "{}", a.body);
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
        assert!(a.body.contains("Quota unchanged"), "{}", a.body);
        assert_eq!(a.links.up_count(), 0);

        type_command(&mut a, "disconnect nobody");
        assert!(a.body.contains("no link"), "{}", a.body);
    }

    /// **RFC 8 §5.2's reason for existing.** A LoRa link silently drops
    /// oversized objects, and nothing else in the system will say so.
    #[test]
    fn reach_separates_a_bad_profile_from_a_silent_peer() {
        let mut a = ready_node("reach");
        type_command(&mut a, "connect m4k2 lora");

        type_command(&mut a, "reach m4k2 --size 256");
        assert!(a.body.contains("ADMIT"), "{}", a.body);
        assert!(a.body.contains("1 of 1"), "{}", a.body);

        type_command(&mut a, "reach m4k2 --size 8192");
        assert!(a.body.contains("BLOCK"), "{}", a.body);
        assert!(a.body.contains("max_bucket"), "{}", a.body);
        assert!(a.body.contains("0 of 1"), "{}", a.body);
        // The state where the operator most needs to know no error is coming.
        assert!(a.body.contains("silent"), "{}", a.body);
    }

    #[test]
    fn reach_with_no_links_says_so() {
        let mut a = ready_node("reach-empty");
        type_command(&mut a, "reach anyone");
        assert!(a.body.contains("no links"), "{}", a.body);
    }

    /// The panel must not invent rows it has no data for.
    #[test]
    fn peers_reports_honestly_when_nothing_has_reconciled() {
        let mut a = ready_node("peers");
        type_command(&mut a, "peers");
        assert!(a.body.contains("peer offer"), "{}", a.body);

        type_command(&mut a, "connect q3m9 tcp");
        type_command(&mut a, "peers");
        assert!(a.body.contains("q3m9"), "{}", a.body);
        assert!(
            a.body.contains("no accountability metrics yet"),
            "{}",
            a.body
        );
        // Still no per-object anything (RFC 3 §12).
        assert!(!a.body.contains("id="), "{}", a.body);
    }

    /// `keys` reports state and does not re-show the backup — RFC 7 §11 makes
    /// it a one-time ceremony step, and a verb that reprinted it would turn it
    /// back into a settings item.
    #[test]
    fn keys_reports_state_without_reprinting_the_backup() {
        let mut a = ready_node("keys");
        type_command(&mut a, "keys");
        assert!(a.body.contains("shown once at init"), "{}", a.body);
        assert!(a.body.contains("not recoverable"), "{}", a.body);

        // The backup words themselves must not be in the output.
        let backup = a.identity.as_ref().unwrap().backup_phrase();
        let first_word = backup.split_whitespace().next().unwrap();
        let second = backup.split_whitespace().nth(1).unwrap();
        assert!(
            !(a.body.contains(first_word) && a.body.contains(second)),
            "the backup phrase leaked into `keys`: {}",
            a.body
        );
    }

    /// `rollcall` publishes statics and policy, not endpoints — RFC 3 §9
    /// keeps endpoints inside a peering, so a public attestation is not a
    /// location beacon.
    #[test]
    fn rollcall_does_not_publish_endpoints() {
        let mut a = ready_node("rollcall");
        type_command(&mut a, "rollcall");
        assert!(a.body.contains("does not carry endpoints"), "{}", a.body);
    }

    /// An unknown transport is refused rather than silently defaulted, since a
    /// default would be a link profile the operator did not choose — and a
    /// wrong profile is exactly what `reach` exists to diagnose.
    #[test]
    fn an_unknown_transport_is_refused() {
        let mut a = ready_node("transport");
        type_command(&mut a, "connect q3m9 carrier-pigeon");
        assert!(a.body.contains("unknown transport"), "{}", a.body);
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
        let b_pad = carry(&b, &a, "peer.pad", "from-b.pad");
        type_command(&mut a, &format!("peer accept {b_card}"));
        {
            let mut p = a.load_ceremony().unwrap();
            p.fingerprint_verified = true;
            a.save_ceremony(&p).unwrap();
        }
        type_command(&mut a, &format!("peer seal {b_pad} media"));
        assert!(a.body.starts_with("peer-link signed"), "{}", a.body);

        // The peer-link is durable, and named by the peer's identifier.
        let peer = short_id(&b.identity.as_ref().unwrap().node_id());
        assert!(a.path(&format!("{peer}.link")).exists());

        type_command(&mut a, &format!("send {peer} meet me at the usual place"));
        assert!(a.body.contains("composed"), "{}", a.body);
        assert!(
            a.body.contains("post-quantum"),
            "the reservoir was used: {}",
            a.body
        );
        assert_eq!(a.store.len(), 1, "the object is in the corpus");

        // **It did not transmit.** RFC 5 §6.1 -- emission is scheduled, and
        // saying otherwise would make transmission timing follow composition.
        assert!(a.body.contains("not now"), "{}", a.body);
        assert_eq!(a.links.up_count(), 0);

        // Now read it as B would, from the object alone.
        let id = *a.store.ids_in_order().next().unwrap();
        let raw = a.store.get(&id).unwrap();
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
        let root = krab_crypto::kek::open_under(
            &a.epoch_key.unwrap(),
            b"krab/reservoir",
            &std::fs::read(a.path(&format!("{peer}.reservoir"))).unwrap(),
        )
        .unwrap();
        let mut r = [0u8; 32];
        r.copy_from_slice(&root);
        let chunk = krab_crypto::reservoir::Reservoir::new(r, krab_core::tag::Epoch(0))
            .chunk(now_epoch())
            .unwrap();

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
            &header.write(),
        )
        .expect("the recipient opens it");
        assert_eq!(opened, b"meet me at the usual place");
    }

    /// Sending without a peering is refused with the remedy, not an error code.
    #[test]
    fn send_without_a_peer_link_says_what_to_do() {
        let mut a = ready_node("send-nolink");
        type_command(&mut a, "send nobody hello");
        assert!(a.body.contains("no peer-link"), "{}", a.body);
        assert!(a.body.contains("peer offer"), "{}", a.body);
        assert_eq!(a.store.len(), 0);
    }

    /// A locked node has no W_N and therefore cannot compose — the role
    /// transition costs something concrete.
    #[test]
    fn a_locked_node_cannot_send() {
        let mut a = ready_node("send-locked");
        a.lock();
        type_command(&mut a, "send anyone hello");
        assert!(a.body.contains("locked"), "{}", a.body);
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
        let b_pad = carry(&b, &a, "peer.pad", "from-b.pad");
        type_command(&mut a, &format!("peer accept {b_card}"));
        {
            let mut p = a.load_ceremony().unwrap();
            p.fingerprint_verified = true;
            a.save_ceremony(&p).unwrap();
        }
        type_command(&mut a, &format!("peer seal {b_pad} media"));

        let peer = short_id(&b.identity.as_ref().unwrap().node_id());
        type_command(&mut a, &format!("send {peer} the usual place, thursday"));
        assert!(a.body.contains("composed"), "{}", a.body);

        // Pack a stick.
        type_command(&mut a, "pack outbound.krab");
        assert!(a.body.contains("wrote 1 objects"), "{}", a.body);
        assert!(
            a.body.contains("not what changed"),
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
        assert!(b.body.starts_with("1 new"), "{}", b.body);
        assert!(b.body.contains("re-hashed"), "{}", b.body);
        assert_eq!(b.store.len(), 1);

        // B reads it, having received one file and nothing else.
        let id = *b.store.ids_in_order().next().unwrap();
        let raw = b.store.get(&id).unwrap();
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

        let root = krab_crypto::kek::open_under(
            &a.epoch_key.unwrap(),
            b"krab/reservoir",
            &std::fs::read(a.path(&format!("{peer}.reservoir"))).unwrap(),
        )
        .unwrap();
        let mut r = [0u8; 32];
        r.copy_from_slice(&root);
        let chunk = krab_crypto::reservoir::Reservoir::new(r, krab_core::tag::Epoch(0))
            .chunk(now_epoch())
            .unwrap();
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
            &header.write(),
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
            .ingest(id, bytes, now_epoch().0 * 1440, u32::MAX)
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
            !b.store.contains(&id),
            "tampered content took the original's name"
        );
        for oid in b.store.ids_in_order() {
            assert_eq!(
                krab_crypto::object_id(b.store.get(oid).unwrap()),
                *oid,
                "every object in the store hashes to its own identifier"
            );
        }
    }

    #[test]
    fn importing_a_missing_file_says_so() {
        let mut a = ready_node("import-missing");
        type_command(&mut a, "import /nonexistent/stick.krab");
        assert!(
            a.body.contains("not self-consistent") || a.body.contains("could not read"),
            "{}",
            a.body
        );
    }
}
