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
    /// **Not in RFC 8 §5.** The dead-man timer — RFC 7 §10.
    ///
    /// `deadman <days>` arms it, `deadman off` disarms, bare `deadman` reports.
    ///
    /// §10 requires it be discoverable and not on by default. It is a verb
    /// like any other, listed in `help`, and absent until typed.
    DeadMan,
    /// **Not in RFC 8 §5.** Start this node's own `tor` — RFC 4 §5.2.
    ///
    /// `start-tor [absolute-path-to-tor]`. With no argument, whatever `tor` is
    /// on `PATH`; with one, exactly that binary, which is the answer for an
    /// operator who does not trust `PATH`.
    ///
    /// Launches the daemon on arguments alone — no `torrc`, per
    /// `NO-CONFIG.md` — and publishes this node's derived onion address, so
    /// that afterwards the node can both be reached and reach out.
    StartTor,
    /// **Not in RFC 8 §5.** Stop the `tor` this node started.
    ///
    /// The address is derived, so stopping and starting gets the same one
    /// back. A panic wipe also stops it, immediately and without this verb.
    StopTor,
    /// **Not in RFC 8 §5.** Keep a conversation past the retention window —
    /// RFC 8 §10, RFC 7 §8.1.
    ///
    /// "Pinning is a conscious act; the default is forgetting."
    Pin,
    /// A note to yourself — never leaves this node.
    Note,
    /// Name a correspondent, locally.
    Alias,
    /// Name a channel, locally.
    AliasChannel,
    /// Name a peer, locally.
    AliasPeer,
    /// Remove a local name: `no alias <name>`.
    No,
    /// **Not in RFC 8 §5.** Write a received picture to a file — RFC 8 §6.
    ///
    /// Writes bytes and stops. RFC 8 §6 forbids passing received bytes to a
    /// system image viewer, so this program does not open one — not with a
    /// flag, not with a setting.
    Picture,
    /// **Not in RFC 8 §5.** Groups — RFC 6 §2.
    ///
    /// A closed roster with fan-out. The opposite security model from a
    /// channel, presented in the same interface, which RFC 6 §5 names as the
    /// worst failure the system can produce.
    Group,
    /// **Not in RFC 8 §5.** Channels — RFC 6.
    ///
    /// §5's verbs are all about private mail. Channels are the other half of
    /// the interface and had no verb at all, which is why the tab rendered an
    /// empty pane.
    Channel,
    /// **Not in RFC 8 §5.** Leave. The `Ctrl-Q` chord's discoverable form,
    /// the same way `lock` is `Ctrl-L`'s.
    Quit,
    /// **Not in RFC 8 §5.** Wait for an inbound link on a named address.
    ///
    /// §5 has `connect`, which dials. Nothing in it answers — so of two nodes
    /// both would dial and neither would listen, and a pair on one host could
    /// not link at all. A bind address is not a dial address and must not be
    /// spelled like one.
    Listen,
    /// **Not in RFC 8 §5, and against the grain of RFC 5 §6.1.** Reconcile
    /// with a peer now, rather than when the schedule says.
    ///
    /// §6.1 requires inter-sync intervals be uncorrelated with message
    /// events, and this is that correlation by construction: an observer
    /// watching the link sees a sync that followed a composition. It exists
    /// because testing a two-node setup otherwise means waiting on a Poisson
    /// draw, and because an operator who needs something to go now will
    /// otherwise restart the process to get it — which leaks the same thing
    /// and tells them less.
    ///
    /// It does **not** perturb the schedule. The forced exchange is extra, so
    /// scheduled syncs stay uncorrelated and §6.1 still holds for everything
    /// this verb did not cause.
    ForceSend,
    /// **Not in RFC 8 §5.** Whether this node is ready to operate, and what
    /// is missing if it is not.
    ///
    /// §5 has `keys`, `peers` and `reach`, each answering one question well.
    /// None answers "can I use this yet", which is the question an operator
    /// has on the screen after `init` and cannot get from a verb that reports
    /// one subsystem.
    Status,
    /// **Not in RFC 8 §5.** Every verb, listed. §5 assumes an operator who
    /// has read it; an operator running a node for the first time has an
    /// empty screen and a prompt, and no way to find out what to type.
    Help,
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
    /// **Not in RFC 8 §5.** Send a first-contact `peer-request` (RFC 3 §5.1).
    ///
    /// §5 has `pack` and `import` — the transport of a ceremony — but no verb
    /// that *initiates* one with someone not yet met.
    Request,
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
    /// Mint or present an introduction token — RFC 3 §10.
    Introduce,
    /// First-contact requests waiting on this node's inbox tag.
    Requests,
    /// Ingest a courier archive.
    Import,
    /// Write a courier archive.
    Pack,
    /// **Not in RFC 8 §5.** Compose a sealed message to one or more people.
    ///
    /// The verb this program is for. Opens the composer addressed to everyone
    /// named; `Ctrl-D` seals one copy per recipient and queues them; `Esc`
    /// discards the draft.
    ///
    /// Separate from [`Command::Send`], which takes its text on the command
    /// line — that is for one line to one person, and a command line is the
    /// wrong place for a message: it has a history.
    Message,
    /// Compose and emit — one line, on the command line.
    Send,
    /// The onion endpoints — RFC 4 §5.2's rotation and RFC 3 §9.2's
    /// contact/sync separation.
    Onion,
    /// Replace the correspondence key — RFC 2 §9's rotation.
    ///
    /// Destructive, and in a way `wipe` is not: `wipe` destroys this node,
    /// while this destroys **the ability of every correspondent to reach it**
    /// until they are given the new card, and loses whatever was in flight.
    Rotate,
    /// What this node's peers think the time is — RFC 2 §5.1.
    ///
    /// A report and never a setting: the repair for a divergence is the system
    /// clock, which is not Krab's to change.
    Clock,
    /// Cover traffic — RFC 1 §5.3's Poisson dummies.
    ///
    /// Off by default and discoverable, like the dead-man timer: it costs
    /// bandwidth an operator may not have, and RFC 8 §4.3 says a setting with
    /// consequences is stated rather than assumed.
    Cover,
    /// One line straight down a live link — RFC 4 §8's `short`.
    ///
    /// Not mail. It is not stored, not relayed, and not reconciled, so it
    /// needs the peer to be linked *now*. Separate from [`Command::Send`]
    /// because the two differ in what they promise, not in how long the text
    /// is: `send` will get there eventually, and this either goes now or does
    /// not go.
    Short,
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
    /// Every verb.
    ///
    /// Used by the two tests that keep it complete and correct. Not read by
    /// the program itself, which is why `#[allow(dead_code)]` is here rather
    /// than the constant being deleted: the list's job is to fail a test, and
    /// a list that must be *used* to be kept would be back where it started.
    #[allow(dead_code)]
    ///
    /// **Exhaustive, and a test says so.** `Command` is `#[non_exhaustive]`
    /// for callers outside this crate, which means nothing inside it fails
    /// when a variant is added — the hand-written list this replaced had drifted
    /// to 19 of 26 without anything noticing. `every_variant_is_in_all` closes
    /// that: it matches on `Command` exhaustively, so a new variant does not
    /// compile until it appears here.
    pub const ALL: [Command; 42] = [
        Command::Pin,
        Command::Note,
        Command::Alias,
        Command::AliasChannel,
        Command::AliasPeer,
        Command::No,
        Command::Picture,
        Command::Group,
        Command::Channel,
        Command::Quit,
        Command::Listen,
        Command::ForceSend,
        Command::Status,
        Command::Help,
        Command::Init,
        Command::Peer,
        Command::Lock,
        Command::Duress,
        Command::Request,
        Command::Unlock,
        Command::Wipe,
        Command::StartTor,
        Command::StopTor,
        Command::DeadMan,
        Command::Connect,
        Command::Disconnect,
        Command::Rollcall,
        Command::Introduce,
        Command::Requests,
        Command::Import,
        Command::Pack,
        Command::Message,
        Command::Send,
        Command::Short,
        Command::Cover,
        Command::Onion,
        Command::Clock,
        Command::Rotate,
        Command::Keys,
        Command::Reach,
        Command::Peers,
        Command::Verify,
    ];

    /// Parse a verb.
    pub fn parse(s: &str) -> Option<Command> {
        Some(match s.split_whitespace().next()? {
            "init" => Command::Init,
            "peer" => Command::Peer,
            "lock" => Command::Lock,
            "unlock" => Command::Unlock,
            "duress" => Command::Duress,
            "request" => Command::Request,
            "wipe" => Command::Wipe,
            "start-tor" => Command::StartTor,
            "stop-tor" => Command::StopTor,
            "deadman" => Command::DeadMan,
            "connect" => Command::Connect,
            "disconnect" => Command::Disconnect,
            "rollcall" => Command::Rollcall,
            "introduce" => Command::Introduce,
            "requests" => Command::Requests,
            "import" => Command::Import,
            "pack" => Command::Pack,
            "send" => Command::Send,
            "short" => Command::Short,
            "cover" => Command::Cover,
            "onion" => Command::Onion,
            "clock" => Command::Clock,
            "rotate" => Command::Rotate,
            "message" | "msg" => Command::Message,
            "keys" => Command::Keys,
            "reach" => Command::Reach,
            "peers" => Command::Peers,
            "verify" => Command::Verify,
            "listen" => Command::Listen,
            "quit" | "exit" => Command::Quit,
            "channel" | "chan" => Command::Channel,
            "group" => Command::Group,
            "pin" => Command::Pin,
            "note" | "notes" => Command::Note,
            "alias" | "aliases" => Command::Alias,
            "alias-channel" => Command::AliasChannel,
            "alias-peer" => Command::AliasPeer,
            "no" => Command::No,
            "picture" | "pic" => Command::Picture,
            "force-send" => Command::ForceSend,
            "status" => Command::Status,
            "help" | "?" => Command::Help,
            _ => return None,
        })
    }

    /// Every verb, with what it is for. The order is the order an operator
    /// meets them: set the node up, find a peer, exchange, inspect, and the
    /// two that end things.
    pub const SYNOPSES: &'static [(&'static str, &'static str)] = &[
        ("init", "create this node's key hierarchy — run once, first"),
        (
            "alias <short id> <name>",
            "name a correspondent, locally — never sent, never imported",
        ),
        (
            "alias-channel <id> <name>",
            "name a channel, locally",
        ),
        (
            "alias-peer <id> <name>",
            "name a peer, locally",
        ),
        (
            "no alias <name>",
            "remove a local name; also `no alias-channel`, `no alias-peer`",
        ),
        (
            "note [text]",
            "a note to yourself — never leaves this node; no text opens a composer",
        ),
        ("keys", "show what key material exists"),
        ("verify", "print this node's fingerprint, to read aloud"),
        (
            "peer offer",
            "start a peering — writes a card to send to the other end",
        ),
        ("peer accept <file>", "take in the card they sent you"),
        (
            "peer seal",
            "finish the peering once both cards are exchanged",
        ),
        (
            "peer forget <peer>",
            "end a peering and destroy its record — the corpus is kept (RFC 3 §8.4)",
        ),
        (
            "peer renew <peer>",
            "fresh credential before the term ends — there is no revocation list",
        ),
        (
            "peer share <peer> on|off",
            "opt in to listing them in your nodelist — off by default (RFC 3 §8.3)",
        ),
        (
            "peer carry <peer> on|off",
            "whether this link carries public content at all (RFC 6 §281)",
        ),
        (
            "peer fragment",
            "send your nodelist to each peer, individually (RFC 3 §8)",
        ),
        (
            "peer counter <n> <MB/day> <objects> <days>",
            "answer a request with your own terms (RFC 3 §5.2)",
        ),
        (
            "peer countersign <file>",
            "sign their half of the peer-link credential — RFC 3 §3 needs both",
        ),
        (
            "peer pad",
            "generate a one-time pad for a sneakernet peering",
        ),
        ("peer status", "how far along each peering is"),
        (
            "peer show <peer>",
            "the peer-link itself, as HJSON — RFC 3 §3. Not a summary: the \
             document, so an altered term is visible",
        ),
        (
            "peer rekey <peer>",
            "mix fresh entropy into a live peering — needs a link up",
        ),
        ("peers", "who this node is peered with"),
        (
            "listen <peer> [addr]",
            "wait for that peer to call — e.g. listen bob 127.0.0.1:40000",
        ),
        (
            "connect <peer> tcp <addr>",
            "dial that peer — e.g. connect alice 127.0.0.1:40000",
        ),
        ("disconnect", "close the link"),
        ("reach", "what this node can reach, and how far"),
        (
            "rollcall [publish|withdraw]",
            "the public directory — listing yourself is opt-in (RFC 3 §9)",
        ),
        (
            "introduce <peer> <to>",
            "vouch for someone, once, privately (RFC 3 §10)",
        ),
        ("requests", "first-contact requests waiting for you"),
        (
            "pin <peer> | pin release <peer> | pin",
            "keep a conversation past the retention window — the default is forgetting",
        ),
        (
            "message <peer> [peer…]",
            "compose to one or more people; Ctrl-D seals and queues",
        ),
        ("send <peer> <text>", "one line to one person"),
        (
            "short <peer> <text>",
            "one line down a live link — not stored, not relayed",
        ),
        ("cover on <seconds> | off", "Poisson dummy traffic — RFC 1 §5.3"),
        (
            "onion [rotate]",
            "the two onion endpoints, and rotating the sync one",
        ),
        ("clock", "what your peers think the time is — RFC 2 §5.1"),
        (
            "rotate",
            "new correspondence key — LOSES MAIL IN FLIGHT, RFC 2 §9",
        ),
        ("request", "ask a peer for an object by name"),
        ("pack <file>", "write queued objects out for a courier"),
        ("import <file>", "take in what a courier brought"),
        ("lock", "lock the node now"),
        ("unlock", "unlock it"),
        ("duress", "unlock under coercion — opens the duress corpus"),
        (
            "wipe",
            "destroy the key hierarchy — irreversible, asks twice",
        ),
        (
            "status",
            "whether this node is ready to operate, and what is missing",
        ),
        (
            "force-send [peer]",
            "reconcile now instead of on the schedule — leaks that you just sent",
        ),
        ("help", "this list"),
        ("quit", "leave — the same as Ctrl-Q"),
        ("channel new", "create a channel you can post to"),
        (
            "channel post <text>",
            "PUBLIC, SIGNED, PERMANENT — cannot be recalled",
        ),
        ("channel follow <id>", "read a channel"),
        ("channel unfollow <id>", "stop reading it"),
        ("channel list", "channels you own or follow"),
        (
            "group new <name>",
            "a closed roster — sealed per member, PRIVATE",
        ),
        (
            "group add <name> <peer>",
            "add a member; warns above 25, refuses above 50",
        ),
        ("group remove <name> <peer>", "remove a member"),
        ("group list", "groups, their rosters and their epochs"),
        (
            "send <peer> --picture <file>",
            "decoded and re-encoded; EXIF is stripped",
        ),
        ("picture save <file>", "write the selected picture out"),
        (
            "start-tor [binary]",
            "launch this node's own tor — no config file, RFC 4 §5.2",
        ),
        ("stop-tor", "stop it; the onion addresses go with it"),
        (
            "deadman <days> | off",
            "wipe if this node is not unlocked in time — RFC 7 §10",
        ),
    ];

    /// The chords, which are not typed and so are not in [`Self::SYNOPSES`].
    pub const CHORDS: &'static [(&'static str, &'static str)] = &[
        ("Ctrl-Q", "quit"),
        ("Ctrl-L", "lock immediately"),
        (
            "Ctrl-Alt-Shift-W",
            "PANIC — destroys every key on this node at once. No confirmation, \
             no second press, no undo.",
        ),
        (
            "Ctrl-M / Ctrl-T",
            "messages / channels. F1/F2, Ctrl-1/Ctrl-2, Alt-M/Alt-C also work",
        ),
        ("Tab", "move between panes"),
        (
            "z",
            "zoom the focused pane (for output longer than two lines)",
        ),
    ];

    /// Whether this verb needs an identity to exist first.
    ///
    /// A fresh install can only `init`, `lock`, `wipe`, or ask for `keys` —
    /// everything else needs a key hierarchy that does not exist yet, and
    /// failing at the point of use is worse than refusing up front.
    pub fn needs_identity(&self) -> bool {
        !matches!(
            self,
            Command::Init
                | Command::Lock
                | Command::Wipe
                | Command::Keys
                | Command::Help
                | Command::Quit
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
                | Command::Short
                | Command::Rotate
                | Command::Onion
                | Command::Peer
                | Command::Init
                | Command::Keys
                | Command::Verify
                | Command::Duress
                | Command::Request
        )
    }

    /// Whether this verb destroys something irreversibly.
    ///
    /// Exactly one does. Lock is **not** in this list: it is reversible with a
    /// passphrase, and RFC 7 §10 makes the case that a confirmation at the
    /// moment of seizure is the wrong shape. Wipe is not reversible by
    /// anything, so it is the one place a prompt earns its friction.
    /// Whether this verb destroys something irreversibly.
    ///
    /// Two now. `wipe` destroys this node; `rotate` destroys every
    /// correspondent's ability to reach it until they hold the new card, and
    /// loses whatever was in flight under the old key — RFC 2 §9's "messages
    /// in flight under the old key are lost", which "on a courier route may be
    /// weeks of traffic". Neither is undone by a passphrase, which is the line
    /// `lock` sits on the other side of.
    pub fn is_destructive(&self) -> bool {
        matches!(self, Command::Wipe | Command::Rotate)
    }

    /// What typing this verb a second time will do, for the confirmation.
    ///
    /// Per verb, because a single sentence covering both would have to be
    /// vague enough to cover both — and the whole value of a confirmation is
    /// that it names the specific loss.
    pub fn destroys(&self) -> &'static str {
        match self {
            Command::Wipe => "destroys the key hierarchy and cannot be undone",
            Command::Rotate => {
                "replaces your correspondence key: mail already in flight to you \
                 is lost for good, and no correspondent can reach you until they \
                 have your new card (RFC 2 §9)"
            }
            _ => "cannot be undone",
        }
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
            Command::Request => "request",
            Command::Wipe => "wipe",
            Command::StartTor => "start-tor",
            Command::StopTor => "stop-tor",
            Command::DeadMan => "deadman",
            Command::Connect => "connect",
            Command::Disconnect => "disconnect",
            Command::Rollcall => "rollcall",
            Command::Introduce => "introduce",
            Command::Requests => "requests",
            Command::Import => "import",
            Command::Pack => "pack",
            Command::Send => "send",
            Command::Short => "short",
            Command::Cover => "cover",
            Command::Onion => "onion",
            Command::Clock => "clock",
            Command::Rotate => "rotate",
            Command::Message => "message",
            Command::Keys => "keys",
            Command::Reach => "reach",
            Command::Peers => "peers",
            Command::Verify => "verify",
            Command::Listen => "listen",
            Command::Quit => "quit",
            Command::Channel => "channel",
            Command::Group => "group",
            Command::Pin => "pin",
            Command::Note => "note",
            Command::Alias => "alias",
            Command::AliasChannel => "alias-channel",
            Command::AliasPeer => "alias-peer",
            Command::No => "no",
            Command::Picture => "picture",
            Command::ForceSend => "force-send",
            Command::Status => "status",
            Command::Help => "help",
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
    /// Wrap the contribution under a spoken transfer key — `crate::spoken`.
    ///
    /// The route for two people who cannot meet. The wrapped file crosses any
    /// network; the 32-word key crosses a voice call, once ever.
    Wrap,
    /// First contact over a live link — the whole ceremony in one exchange.
    ///
    /// The route for two people who can reach each other on a network and
    /// nowhere else. Not post-quantum, and not authenticated until the
    /// fingerprints are compared: `peer reseal` repairs the first and
    /// `peer verified` records the second.
    Meet,
    /// Record that the fingerprints were compared aloud and matched.
    ///
    /// Separate from `meet` because it is a *human* act performed elsewhere.
    /// A ceremony that recorded it automatically would be recording that
    /// something happened which it cannot observe.
    Verified,
    /// Render a peering's credential as HJSON — RFC 3 §3.
    ///
    /// > "Implementations MUST render any credential as HJSON on request
    /// > (`krab peer show`), and that rendering is what an operator
    /// > inspects."
    ///
    /// The verb the RFC names, because the RFC names it: an operator told to
    /// run `peer show` by a document should find `peer show`.
    Show,
    /// Upgrade a peering's channel classification in place.
    ///
    /// A weak peering is recoverable rather than permanent: start on
    /// `network` today, `reseal` when you next meet, and keep the peer-link
    /// and the message history throughout.
    Reseal,
    /// Ingest the peer's card. Displays the fingerprint word list for RFC 3
    /// §11 step 2, which the operator must then read aloud.
    Accept,
    /// Ingest the peer's contribution and sign the peer-link, recording how it
    /// arrived and therefore what the reservoir is actually worth.
    Seal,
    /// End a peering and purge its record — RFC 3 §8.4.
    ///
    /// "Unpeering should remove the relationship record, not merely stop the
    /// conversation." The corpus is retained, which §8.4 makes an equal MUST:
    /// objects are content-addressed and unattributed, so they are unaffected
    /// by who this node peers with.
    Forget,
    /// Renew a peering's credential — RFC 3 §4.
    ///
    /// "Renewal is a fresh `peer-link` with a new nonce, superseding by
    /// `established` time." Revocation is non-renewal, so this is the only
    /// thing that keeps a peering alive past its term.
    Renew,
    /// Opt in to listing a peer in nodelist fragments — RFC 3 §8.3.
    ///
    /// "Default MUST be false — opt in to being listed, not out." Setting it
    /// re-signs the credential, because the flag is inside both signatures so
    /// that "neither party can unilaterally expose the other".
    Share,
    /// Whether a link carries public content — RFC 6 §281.
    Carry,
    /// Publish a nodelist fragment to every peer — RFC 3 §8.
    Fragment,
    /// Counter a peer-request or a counter — RFC 3 §5.2.
    ///
    /// "The counter-offer is the step that matters. Without it, peering is
    /// accept-or-reject and therefore binary: friend or stranger."
    Counter,
    /// Countersign the peer's `peer-link` credential — RFC 3 §3, §5.3.
    ///
    /// The second signature. Until it exists the document is a proposal: §3 is
    /// explicit that "a singly-signed document lets one party assert a
    /// relationship the other never agreed to", and the credential is cited as
    /// evidence by §5.1, so a claim is not good enough.
    Countersign,
    /// Show the state of an in-progress ceremony.
    Status,
    /// Mix fresh entropy into an established peering — `krab_crypto::rekey`.
    ///
    /// Needs a live link, because the two ends must agree before either
    /// adopts anything. Not part of RFC 3 §11's ceremony: that establishes a
    /// reservoir, and this is what keeps one alive.
    Rekey,
}

impl Peering {
    /// Parse the subverb. Bare `peer` reports status rather than guessing.
    pub fn parse(rest: &str) -> Option<Peering> {
        Some(match rest.split_whitespace().next().unwrap_or("status") {
            "offer" => Peering::Offer,
            "pad" => Peering::Pad,
            "wrap" => Peering::Wrap,
            "meet" => Peering::Meet,
            "verified" => Peering::Verified,
            "show" => Peering::Show,
            "reseal" => Peering::Reseal,
            "accept" => Peering::Accept,
            "seal" => Peering::Seal,
            "forget" => Peering::Forget,
            "renew" => Peering::Renew,
            "share" => Peering::Share,
            "carry" => Peering::Carry,
            "fragment" => Peering::Fragment,
            "counter" => Peering::Counter,
            "countersign" => Peering::Countersign,
            "status" => Peering::Status,
            "rekey" => Peering::Rekey,
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

    /// **Every verb this parser accepts appears in `help`.**
    ///
    /// RFC 7 §10 is the sharp case: "both MUST be discoverable" — the panic
    /// wipe *and* the dead-man timer. `deadman` was built, parsed, dispatched,
    /// documented in its own module and tested, and was **not in this list**,
    /// so `help` had never heard of it. A safety feature nobody can find is
    /// not a safety feature, and RFC 8 §4.3's whole argument is that a
    /// consequential setting must be stated rather than assumed.
    ///
    /// `start-tor` and `stop-tor` were missing the same way and for the same
    /// reason: three verbs added in one pass, none of them added here.
    ///
    /// Canonical spellings only — [`Command::to_string`] gives those, so the
    /// short forms (`msg`, `pic`, `chan`, `exit`) are deliberately not
    /// required to appear. A synonym that is not advertised is a convenience;
    /// a verb that is not advertised does not exist.
    #[test]
    fn every_verb_is_in_help() {
        let listed: Vec<&str> = Command::SYNOPSES
            .iter()
            .filter_map(|(verb, _)| verb.split_whitespace().next())
            .collect();
        let missing: Vec<String> = Command::ALL
            .iter()
            .map(|c| c.to_string())
            .filter(|v| !listed.contains(&v.as_str()))
            .collect();
        assert!(
            missing.is_empty(),
            "these verbs work and `help` does not mention them: {missing:?}"
        );
    }

    /// **`ALL` is complete.** The match is exhaustive, so a variant added to
    /// the enum fails to compile here until it is added to `ALL` too — which
    /// is the only way a list like that stays true. `#[non_exhaustive]` makes
    /// the wildcard necessary for outside callers and useless as a guard, so
    /// the guard lives in this crate where the match can be total.
    #[test]
    fn every_variant_is_in_all() {
        for c in Command::ALL {
            match c {
                Command::Short => {}
                Command::Cover => {}
                Command::Onion => {}
                Command::Clock => {}
                Command::Rotate => {}
                Command::Pin => {}
                Command::Note => {}
                Command::Alias => {}
                Command::AliasChannel => {}
                Command::AliasPeer => {}
                Command::No => {}
                Command::Picture => {}
                Command::Group => {}
                Command::Channel => {}
                Command::Quit => {}
                Command::Listen => {}
                Command::ForceSend => {}
                Command::Status => {}
                Command::Help => {}
                Command::Init => {}
                Command::Peer => {}
                Command::Lock => {}
                Command::Duress => {}
                Command::Request => {}
                Command::Unlock => {}
                Command::Wipe => {}
                Command::StartTor => {}
                Command::StopTor => {}
                Command::DeadMan => {}
                Command::Connect => {}
                Command::Disconnect => {}
                Command::Rollcall => {}
                Command::Introduce => {}
                Command::Requests => {}
                Command::Import => {}
                Command::Pack => {}
                Command::Message => {}
                Command::Send => {}
                Command::Keys => {}
                Command::Reach => {}
                Command::Peers => {}
                Command::Verify => {}
            }
        }
        assert_eq!(Command::ALL.len(), 42);
    }

    /// **Every verb round-trips.** RFC 8 §5's ten, and the sixteen it omits.
    ///
    /// The list below was hand-written and had gone stale: it covered 19 of
    /// 26 verbs, and `Command` is `#[non_exhaustive]`, so adding one failed
    /// nothing. All seven missing ones happened to round-trip, so there was no
    /// live defect — but that is luck, and this codebase's recurring failure
    /// is a rule enforced only over what existed when it was written
    /// (`artifact.rs`, `.gitignore`, `wipe`). `ALL` is now the list, and
    /// `every_variant_is_in_all` is what keeps it complete.
    #[test]
    fn every_verb_parses_and_round_trips() {
        for c in Command::ALL {
            assert_eq!(
                Command::parse(&c.to_string()).as_ref(),
                Some(&c),
                "{c} does not survive to_string -> parse"
            );
        }
        let all = [
            Command::Init,
            Command::Peer,
            Command::Lock,
            Command::Unlock,
            Command::Duress,
            Command::Request,
            Command::Wipe,
            Command::Connect,
            Command::Disconnect,
            Command::Rollcall,
            Command::Introduce,
            Command::Requests,
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
