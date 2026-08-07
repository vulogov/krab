//! The command pane's verbs, RFC 8 §5 — and four it does not list.
//!
//! # A gap in RFC 8 §5
//!
//! The published set is `connect`, `disconnect`, `rollcall`, `import`, `pack`,
//! `send`, `keys`, `reach`, `peers`, `verify`. **None of them creates an
//! identity.** `keys` reports prekey burn rate, reservoir state and identity
//! backup status — it reads a hierarchy that something else must have made.
//!
//! So a fresh install has no verb that makes it usable, and three further
//! operations the series requires have no verb either:
//!
//! | missing | required by |
//! |---|---|
//! | [`Command::Init`] | RFC 3 §2 identity, RFC 7 §4 KEK, **RFC 7 §11 backup at creation** |
//! | [`Command::Peer`] | RFC 3 §11's ceremony — `pack`/`import` are its transport, not its driver |
//! | [`Command::Lock`] | `RFC-7-review.md` §9; `Ctrl-L` exists, but a verb is discoverable |
//! | [`Command::Wipe`] | RFC 7 §10's panic wipe, which §5 omits entirely |
//!
//! # Why `init` is a ceremony and not `keygen`
//!
//! RFC 7 §11:
//!
//! > "The identity key MUST be backed up offline at creation, **as part of the
//! > setup ceremony rather than a settings-menu item.** The moment someone
//! > needs a backup is the moment they can no longer create one."
//!
//! A verb called `keygen` produces bytes and returns. A verb that produces
//! bytes and returns will have its backup step skipped, because skipping it
//! costs nothing until the day it costs everything. [`Init`](Command::Init)
//! therefore cannot reach [`InitStep::Done`] without passing through
//! [`InitStep::ConfirmBackup`], and a test asserts it.
//!
//! # Why there is no `padgen`
//!
//! A reservoir is `R_A ⊕ R_B` (RFC 7 §6.2) — it does not exist until both
//! parties have contributed, and the author's position is that initial
//! exchange is manual with no automatic path. A standalone `padgen` would
//! produce `R_A`, which is a **half** that looks like a pad, and inviting
//! someone to use one is inviting the failure the XOR exists to prevent.
//!
//! Contribution generation is therefore a step inside [`Command::Peer`], where
//! it cannot be mistaken for a finished artifact.

use core::fmt;

/// A verb typed into the command pane.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Command {
    /// **Not in RFC 8 §5.** First-run ceremony: identity, Noise static,
    /// correspondence key, first prekey batch, KEK — and the mandatory backup.
    Init,
    /// **Not in RFC 8 §5.** Drive RFC 3 §11's peering ceremony, including the
    /// reservoir contribution exchange.
    Peer,
    /// **Not in RFC 8 §5.** Lock now. The `Ctrl-L` chord's discoverable form.
    Lock,
    /// **Not in RFC 8 §5.** Set a duress passphrase (RFC 7 §10).
    Duress,
    /// **Not in RFC 8 §5.** Re-derive the KEK and reopen the store.
    ///
    /// §5 has no way to *create* an identity and no way to *reopen* one, which
    /// together mean a node that has been restarted has no listed verb that
    /// makes it usable again.
    Unlock,
    /// **Not in RFC 8 §5.** RFC 7 §10's panic wipe: destroy the KEK.
    Wipe,
    /// Establish a transport. Does **not** trigger a reconciliation.
    Connect,
    /// Tear down a transport.
    Disconnect,
    /// Publish or refresh this node's self-attestation.
    Rollcall,
    /// Ingest a courier archive.
    Import,
    /// Write a courier archive.
    Pack,
    /// Compose and emit.
    Send,
    /// Prekey burn rate, reservoir state, identity backup status.
    Keys,
    /// Path admission diagnostic.
    Reach,
    /// Per-peer accountability panel.
    Peers,
    /// Fingerprint word list for out-of-band comparison.
    Verify,
}

impl Command {
    /// Parse a verb.
    pub fn parse(s: &str) -> Option<Command> {
        Some(match s.split_whitespace().next()? {
            "init" => Command::Init,
            "peer" => Command::Peer,
            "lock" => Command::Lock,
            "unlock" => Command::Unlock,
            "duress" => Command::Duress,
            "wipe" => Command::Wipe,
            "connect" => Command::Connect,
            "disconnect" => Command::Disconnect,
            "rollcall" => Command::Rollcall,
            "import" => Command::Import,
            "pack" => Command::Pack,
            "send" => Command::Send,
            "keys" => Command::Keys,
            "reach" => Command::Reach,
            "peers" => Command::Peers,
            "verify" => Command::Verify,
            _ => return None,
        })
    }

    /// Whether this verb needs an identity to exist first.
    ///
    /// A fresh install can only `init`, `lock`, `wipe`, or ask for `keys` —
    /// everything else needs a key hierarchy that does not exist yet, and
    /// failing at the point of use is worse than refusing up front.
    pub fn needs_identity(&self) -> bool {
        !matches!(
            self,
            Command::Init | Command::Lock | Command::Wipe | Command::Keys
        )
    }

    /// Whether this verb needs the node unlocked.
    ///
    /// A locked node is a relay: it reconciles and cannot read. Commands that
    /// touch message content or key material are refused; `peers`, `reach` and
    /// `connect` are not, because a relay still has links to manage.
    pub fn needs_unlocked(&self) -> bool {
        matches!(
            self,
            Command::Send
                | Command::Peer
                | Command::Init
                | Command::Keys
                | Command::Verify
                | Command::Duress
        )
    }

    /// Whether this verb destroys something irreversibly.
    ///
    /// Exactly one does. Lock is **not** in this list: it is reversible with a
    /// passphrase, and RFC 7 §10 makes the case that a confirmation at the
    /// moment of seizure is the wrong shape. Wipe is not reversible by
    /// anything, so it is the one place a prompt earns its friction.
    pub fn is_destructive(&self) -> bool {
        matches!(self, Command::Wipe)
    }
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Command::Init => "init",
            Command::Peer => "peer",
            Command::Lock => "lock",
            Command::Unlock => "unlock",
            Command::Duress => "duress",
            Command::Wipe => "wipe",
            Command::Connect => "connect",
            Command::Disconnect => "disconnect",
            Command::Rollcall => "rollcall",
            Command::Import => "import",
            Command::Pack => "pack",
            Command::Send => "send",
            Command::Keys => "keys",
            Command::Reach => "reach",
            Command::Peers => "peers",
            Command::Verify => "verify",
        };
        f.write_str(s)
    }
}

/// What `peer` is being asked to do — RFC 3 §11's four steps, as two
/// symmetric halves each end performs.
///
/// Both ends run `offer` and both run `accept`. There is no initiator and no
/// responder in the trust step, because there is no asymmetry to exploit:
/// that is what friend-to-friend means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peering {
    /// Emit this node's public card and open a ceremony.
    ///
    /// The card only. The reservoir contribution is materialised separately by
    /// [`Peering::Pad`], because it is the one artifact that would be plaintext
    /// on this node's own disk and RFC 7 §4 forbids relying on deletion to
    /// remove it — see `Documentation/SECURE-DELETE.md`.
    Offer,
    /// Write the reservoir contribution to a destination the operator names.
    ///
    /// Separate from [`Peering::Offer`] on purpose: the two artifacts have
    /// different channel requirements *and* different storage requirements, and
    /// a single command producing both invites leaving one behind.
    Pad,
    /// Ingest the peer's card. Displays the fingerprint word list for RFC 3
    /// §11 step 2, which the operator must then read aloud.
    Accept,
    /// Ingest the peer's contribution and sign the peer-link, recording how it
    /// arrived and therefore what the reservoir is actually worth.
    Seal,
    /// Show the state of an in-progress ceremony.
    Status,
}

impl Peering {
    /// Parse the subverb. Bare `peer` reports status rather than guessing.
    pub fn parse(rest: &str) -> Option<Peering> {
        Some(match rest.split_whitespace().next().unwrap_or("status") {
            "offer" => Peering::Offer,
            "pad" => Peering::Pad,
            "accept" => Peering::Accept,
            "seal" => Peering::Seal,
            "status" => Peering::Status,
            _ => return None,
        })
    }
}

/// Steps of the first-run ceremony.
///
/// Ordered, and [`InitStep::Done`] is reachable only through
/// [`InitStep::ConfirmBackup`] — which is the whole point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InitStep {
    /// Choose a passphrase. RFC 7 §4 derives the KEK from it via Argon2id.
    Passphrase,
    /// Generate identity (Ed25519), Noise static and correspondence keys
    /// (X25519), and the first prekey batch.
    Generate,
    /// Display the 64-byte identity backup as a word list to write down.
    ///
    /// RFC 7 §11: "printable as a word list on paper, or written to the same
    /// removable media holding the online copy."
    ShowBackup,
    /// **The step that cannot be skipped.** The operator confirms the backup
    /// is recorded, and RFC 7 §11 makes clear why: message history is
    /// explicitly unrecoverable, so losing identity means every peer must
    /// re-verify out of band, in person, from scratch.
    ConfirmBackup,
    /// Complete.
    Done,
}

impl InitStep {
    /// The next step, or `None` at the end.
    pub fn next(self) -> Option<InitStep> {
        Some(match self {
            InitStep::Passphrase => InitStep::Generate,
            InitStep::Generate => InitStep::ShowBackup,
            InitStep::ShowBackup => InitStep::ConfirmBackup,
            InitStep::ConfirmBackup => InitStep::Done,
            InitStep::Done => return None,
        })
    }

    /// What to tell the operator.
    pub fn prompt(&self) -> &'static str {
        match self {
            InitStep::Passphrase => "choose a passphrase — it is the only root",
            InitStep::Generate => "generating identity and first prekeys",
            InitStep::ShowBackup => "write these words down, offline, now",
            InitStep::ConfirmBackup => "confirm you recorded them — this cannot be shown again",
            InitStep::Done => "ready",
        }
    }
}

/// Why a command was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// No identity yet; run `init`.
    NoIdentity,
    /// The node is locked.
    Locked,
    /// Already initialised. `init` is once.
    AlreadyInitialised,
    /// Destructive, and unconfirmed.
    NeedsConfirmation,
}

/// Whether a command may run.
pub fn admit(
    cmd: &Command,
    has_identity: bool,
    locked: bool,
    confirmed: bool,
) -> Result<(), Refusal> {
    if *cmd == Command::Init && has_identity {
        return Err(Refusal::AlreadyInitialised);
    }
    if cmd.needs_identity() && !has_identity {
        return Err(Refusal::NoIdentity);
    }
    if cmd.needs_unlocked() && locked {
        return Err(Refusal::Locked);
    }
    if cmd.is_destructive() && !confirmed {
        return Err(Refusal::NeedsConfirmation);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8 §5's ten verbs all parse, and so do the four it omits.
    #[test]
    fn every_verb_parses_and_round_trips() {
        let all = [
            Command::Init,
            Command::Peer,
            Command::Lock,
            Command::Unlock,
            Command::Duress,
            Command::Wipe,
            Command::Connect,
            Command::Disconnect,
            Command::Rollcall,
            Command::Import,
            Command::Pack,
            Command::Send,
            Command::Keys,
            Command::Reach,
            Command::Peers,
            Command::Verify,
        ];
        for c in &all {
            assert_eq!(Command::parse(&c.to_string()).as_ref(), Some(c));
        }
        assert_eq!(Command::parse("nonsense"), None);
        assert_eq!(Command::parse(""), None);
        // Arguments are ignored by the verb parser.
        assert_eq!(
            Command::parse("reach q3m9 --size 4096"),
            Some(Command::Reach)
        );
    }

    /// **A fresh install can barely do anything, and that is correct.**
    #[test]
    fn a_fresh_install_admits_only_init_and_a_few_safe_verbs() {
        let admitted: Vec<Command> = [
            Command::Init,
            Command::Lock,
            Command::Keys,
            Command::Send,
            Command::Connect,
            Command::Peers,
            Command::Peer,
        ]
        .into_iter()
        .filter(|c| admit(c, false, false, false).is_ok())
        .collect();
        assert_eq!(admitted, vec![Command::Init, Command::Lock, Command::Keys]);

        // And the refusal names the reason rather than failing later.
        assert_eq!(
            admit(&Command::Send, false, false, false),
            Err(Refusal::NoIdentity)
        );
    }

    /// **RFC 7 §11's requirement, enforced by the state machine.**
    ///
    /// The ceremony cannot reach `Done` without passing `ConfirmBackup`. This
    /// is the test that fails if someone makes backup a settings item.
    #[test]
    fn init_cannot_complete_without_the_backup_confirmation() {
        let mut step = InitStep::Passphrase;
        let mut path = vec![step];
        while let Some(next) = step.next() {
            step = next;
            path.push(step);
        }
        assert_eq!(
            path,
            vec![
                InitStep::Passphrase,
                InitStep::Generate,
                InitStep::ShowBackup,
                InitStep::ConfirmBackup,
                InitStep::Done,
            ]
        );
        // There is no edge that skips it: `Done` has exactly one predecessor.
        assert_eq!(InitStep::ShowBackup.next(), Some(InitStep::ConfirmBackup));
        assert_eq!(InitStep::ConfirmBackup.next(), Some(InitStep::Done));
    }

    #[test]
    fn peer_subverbs_parse_and_bare_peer_does_nothing_destructive() {
        assert_eq!(Peering::parse("offer"), Some(Peering::Offer));
        assert_eq!(Peering::parse("accept alice.card"), Some(Peering::Accept));
        assert_eq!(Peering::parse("seal alice.pad"), Some(Peering::Seal));
        // A bare `peer` reports rather than guessing which half was meant.
        assert_eq!(Peering::parse(""), Some(Peering::Status));
        assert_eq!(Peering::parse("  "), Some(Peering::Status));
        assert_eq!(Peering::parse("nonsense"), None);
    }

    #[test]
    fn init_runs_once() {
        assert!(admit(&Command::Init, false, false, false).is_ok());
        assert_eq!(
            admit(&Command::Init, true, false, false),
            Err(Refusal::AlreadyInitialised)
        );
    }

    /// A locked node is a relay: it keeps its links and loses its content.
    #[test]
    fn a_locked_node_manages_links_but_not_messages() {
        for c in [
            Command::Peers,
            Command::Reach,
            Command::Connect,
            Command::Pack,
        ] {
            assert!(admit(&c, true, true, false).is_ok(), "{c} is link work");
        }
        for c in [Command::Send, Command::Keys, Command::Verify, Command::Peer] {
            assert_eq!(
                admit(&c, true, true, false),
                Err(Refusal::Locked),
                "{c} needs content"
            );
        }
    }

    /// **Exactly one command is destructive, and lock is not it.**
    ///
    /// Lock is reversible with a passphrase, and RFC 7 §10 argues a prompt at
    /// the moment of seizure is the wrong shape. Wipe is reversible by
    /// nothing, so it is the one place friction is earned.
    #[test]
    fn only_wipe_asks_for_confirmation() {
        assert!(
            admit(&Command::Lock, true, false, false).is_ok(),
            "lock never prompts"
        );
        assert_eq!(
            admit(&Command::Wipe, true, false, false),
            Err(Refusal::NeedsConfirmation)
        );
        assert!(admit(&Command::Wipe, true, false, true).is_ok());

        // And wipe works on a node with no identity and on a locked one --
        // both are states where an operator might most need it.
        assert!(admit(&Command::Wipe, false, true, true).is_ok());
    }
}
