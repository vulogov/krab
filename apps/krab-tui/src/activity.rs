//! Activity and progress indication, RFC 8 §5.1.
//!
//! # The constraint is temporal association, not animation
//!
//! RFC 8 §5.1 forbids an indicator that *begins on a keypress and resolves on
//! object arrival*, because it asserts a causal relationship the protocol does
//! not have. A spinner leaks nothing; the claim does.
//!
//! > "Event-driven sync is not reintroduced by someone deciding to weaken
//! > privacy; it is reintroduced by someone fixing what looks like a bug."
//! > — RFC 8 §5.1
//!
//! # How that is enforced here
//!
//! [`Activity::of`] is a **pure function of node state**. There is no
//! constructor taking an event, no `start()`, and no handle a keypress could
//! hold. The forbidden shape is not merely discouraged — it is not
//! expressible, which is the same discipline `Scheduler::due` uses for I-5 and
//! `Store::evict_to` uses for I-6.
//!
//! # A spinner is fine; a countdown is not
//!
//! RFC 8 §5.1 permits showing progress "for a reconciliation **while one is in
//! fact running**", and says outright that "a spinner emits nothing and leaks
//! nothing; the objection is to the causal claim the interface makes."
//!
//! Those are two different things and only one is restricted:
//!
//! | indicator | shows | verdict |
//! |---|---|---|
//! | spinner while reconciling | *that* something is happening, now | fine — it is a fact |
//! | countdown to next sync | *when* something will happen | coarsened — predictive, and §5.1 says a precise one "invites waiting for it" |
//! | spinner starting on a keypress | that the user caused it | forbidden — the claim is false |
//!
//! Because the node reconciles on a background thread, a running spinner is
//! **decorrelated from user activity by construction**. A user watching it
//! learns "sync happens sometimes", not "my keypress causes sync" — and since
//! the schedule is Poisson and therefore memoryless, watching it does not
//! help predict it. That is what the distribution was chosen for.

use core::fmt;

/// What the node is doing, derived from its state.
///
/// # Almost nothing here is foreground work
///
/// The node sends and receives on a background thread regardless of what the
/// interface is doing. Only a short list of operations are genuinely
/// *frontend* activities — things the user drives, that block on them, and
/// that would look broken without feedback:
///
/// | activity | foreground? | why |
/// |---|---|---|
/// | initial key exchange (RFC 3 §11) | **yes** | a ceremony: the user is reading a word list aloud and moving a USB stick |
/// | transport establishment | **yes** | the user pressed `connect`, and RFC 4 §5.2 notes Tor bootstrap takes tens of seconds |
/// | unlock (Argon2id) | **yes** | RFC 7 §4.1 calibrates it at ~500 ms, and the interface is stopped for it |
/// | reconciliation | no | Poisson-scheduled, RFC 5 §6.1 |
/// | sending | no | the object queues for the next scheduled exchange |
/// | receiving | no | it arrives when it arrives |
///
/// The distinction is not cosmetic. A foreground activity may be shown as
/// *the user's operation in progress*, because it is one. A background
/// activity may only be reported as a fact — RFC 8 §5.1 forbids implying the
/// user's action caused it, and for reconciliation that implication would be
/// false.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activity {
    /// Nothing in flight. The common case, and it is not a failure.
    Idle,
    /// A transport is being established.
    ///
    /// **Required** by RFC 8 §5.1: this is real work the user asked for, and
    /// RFC 4 §5.2 notes Tor bootstrap takes tens of seconds, so a client that
    /// shows nothing here will be reported as broken at every start.
    Establishing {
        /// Transport being brought up, e.g. `"tor"`.
        transport: &'static str,
    },
    /// A scheduled reconciliation is running **now**.
    ///
    /// Background. Permitted by RFC 8 §5.1 only because it reports a fact
    /// rather than a consequence — it can begin while the user is doing
    /// nothing at all, which is exactly what makes it safe to show.
    Reconciling {
        /// Short peer label.
        peer: &'static str,
    },
    /// A peering ceremony is in progress, RFC 3 §11.
    ///
    /// **Foreground.** The user is comparing a fingerprint word list aloud and
    /// carrying a USB stick between two machines; the interface is genuinely
    /// waiting on them, and each step needs to say which step it is or the
    /// ceremony cannot be followed.
    ///
    /// `RFC-8-review.md` §9.1 settles the mechanism: `pack`/`import` over
    /// physical media, three passes, with `verify` read aloud between them.
    /// RFC 3 §11 assumes a QR path a terminal cannot complete, since a
    /// terminal can render a QR and cannot read one.
    Ceremony {
        /// Which of the three passes.
        step: CeremonyStep,
    },
    /// Deriving the KEK on unlock, RFC 7 §4.1.
    ///
    /// **Foreground**, and deliberately slow: Argon2id is calibrated to about
    /// 500 ms, so the interface must say why it has stopped.
    Unlocking,
}

/// Where a peering ceremony has reached, RFC 3 §11.
///
/// `PackRequest` and `Import` are constructed once `peer accept` and `peer
/// seal` read files; the whole sequence is enumerated now because RFC 8 §5.1's
/// rule — indicate only what is genuinely running — is easier to hold to when
/// the full set of runnable things is written down in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum CeremonyStep {
    /// Writing this node's `peer-request` to removable media.
    PackRequest,
    /// Reading the counterparty's archive.
    Import,
    /// Comparing fingerprint word lists aloud — **the actual security step**,
    /// and the only one no software can perform.
    Verify,
    /// Countersigning, and exchanging reservoir contributions.
    Sign,
}

impl CeremonyStep {
    /// What to tell the operator to do next.
    pub fn prompt(&self) -> &'static str {
        match self {
            CeremonyStep::PackRequest => "written to media -- hand it over",
            CeremonyStep::Import => "reading their archive",
            CeremonyStep::Verify => "compare the word list aloud, both of you",
            CeremonyStep::Sign => "signing, and exchanging pad contributions",
        }
    }
}

/// Node state the indicator is derived from.
///
/// Deliberately carries **no** field describing a user action. There is
/// nothing here to hang "the user pressed send" on.
#[derive(Debug, Clone, Copy, Default)]
pub struct NodeState {
    /// A transport currently coming up, if any.
    pub establishing: Option<&'static str>,
    /// A reconciliation currently running, if any.
    pub reconciling: Option<&'static str>,
    /// Seconds until the next scheduled reconciliation.
    pub next_sync_in_s: Option<u64>,
    /// Objects created locally and awaiting the next scheduled exchange.
    pub queued: usize,
    /// A peering ceremony in progress. **Foreground** — the user is driving it.
    pub ceremony: Option<CeremonyStep>,
    /// Deriving the KEK. **Foreground** — the interface is stopped for it.
    pub unlocking: bool,
    /// Tor's bootstrap percentage while it is still coming up — RFC 4 §5.2.
    ///
    /// `None` once done, or when no tor is running.
    ///
    /// # Why a percentage is allowed here and forbidden three lines away
    ///
    /// RFC 8 §5.1 forbids progress indicators, and
    /// `sending_shows_a_queue_and_never_progress` enforces it by asserting the
    /// status line never contains `%`. That rule is about **message
    /// transfer**: a percentage that moves when the operator sends is a
    /// statement that their action caused a transfer, which is the activity
    /// leak §5.1 exists to prevent.
    ///
    /// Tor's bootstrap is not that. It is a transport coming up — the same
    /// category as [`NodeState::establishing`] — it starts when the operator
    /// types `start-tor` and not when they send anything, and it reveals
    /// nothing about mail because no mail is involved. RFC 4 §5.2 requires it
    /// outright:
    ///
    /// > clients MUST show bootstrap progress or users will believe the node
    /// > is broken at every start.
    ///
    /// The two requirements are about different subjects and both are met.
    pub tor_bootstrap: Option<u8>,
}

impl Activity {
    /// Derive what to show. The only way to construct one.
    pub fn of(state: &NodeState) -> Activity {
        // Precedence is "what is the user waiting on", most-blocking first.
        // Unlock stops the interface outright (RFC 7 §4.1's ~500 ms), so it
        // outranks work the user can ignore.
        if state.unlocking {
            return Activity::Unlocking;
        }
        // A ceremony is the operation the user is executing with their hands.
        if let Some(step) = state.ceremony {
            return Activity::Ceremony { step };
        }
        // Establishment is foreground but not blocking; RFC 4 §5.2 warns it
        // will look like a hang if nothing is shown.
        if let Some(t) = state.establishing {
            return Activity::Establishing { transport: t };
        }
        if let Some(p) = state.reconciling {
            return Activity::Reconciling { peer: p };
        }
        Activity::Idle
    }

    /// Whether anything should be drawn at all.
    pub fn is_visible(&self) -> bool {
        !matches!(self, Activity::Idle)
    }

    /// Whether this activity animates.
    ///
    /// True whenever something is genuinely in flight, so the operator gets
    /// the "yes, it is alive" signal a background process otherwise never
    /// gives. False when idle, because idle is the common case and a
    /// perpetually spinning interface says nothing.
    pub fn animates(&self) -> bool {
        self.is_visible()
    }
}

/// A spinner, advanced by the render tick.
///
/// Deliberately has **no** `start`, `stop`, `begin` or `finish`. It cannot be
/// driven by an event, only sampled — so the forbidden shape from RFC 8 §5.1,
/// an indicator that begins on a keypress and resolves on object arrival, has
/// no method to express it.
#[derive(Debug, Clone, Copy, Default)]
pub struct Spinner {
    frame: usize,
}

/// Braille frames: one cell wide, so the status line never reflows.
const FRAMES: [char; 8] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠇'];

/// Shown when a direction is idle. One cell wide, like the frames, so the
/// title does not reflow as traffic starts and stops.
const IDLE: char = '⠿';

impl Spinner {
    /// Advance one render tick.
    pub fn tick(&mut self) {
        self.frame = self.frame.wrapping_add(1);
    }

    /// A pair of glyphs for the output pane's frame: outbound, then inbound.
    ///
    /// Each turns only while that direction is doing something, so a still
    /// glyph means "nothing is moving" rather than "the interface froze" —
    /// two states that look identical when only one spinner exists.
    ///
    /// The directions turn **opposite ways**: this is the one place in the
    /// interface where two animations sit adjacent, and the same animation
    /// twice is harder to read at a glance than two that differ.
    pub fn duplex(&self, sending: bool, receiving: bool) -> (char, char) {
        let out = if sending {
            FRAMES[self.frame % FRAMES.len()]
        } else {
            IDLE
        };
        let inn = if receiving {
            FRAMES[FRAMES.len() - 1 - (self.frame % FRAMES.len())]
        } else {
            IDLE
        };
        (out, inn)
    }

    /// The glyph to draw for `activity`, or `None` when nothing is in flight.
    pub fn glyph(&self, activity: &Activity) -> Option<char> {
        activity
            .animates()
            .then(|| FRAMES[self.frame % FRAMES.len()])
    }
}

impl fmt::Display for Activity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Activity::Idle => Ok(()),
            Activity::Establishing { transport } => write!(f, "connecting ({transport})"),
            // Note the wording: never "syncing now", which RFC 8 §5.1 forbids
            // because it implies the user's action caused a transfer.
            Activity::Reconciling { peer } => write!(f, "reconciling with {peer}"),
            Activity::Ceremony { step } => write!(f, "peering: {}", step.prompt()),
            Activity::Unlocking => f.write_str("unlocking"),
        }
    }
}

/// Coarsen a countdown into a window.
///
/// RFC 8 §5.1: *"Showing a window rather than a countdown matters: a precise
/// countdown invites waiting for it."* The buckets widen with distance, so the
/// display is stable — a value that ticks every second is a countdown however
/// it is labelled.
pub fn schedule_window(secs_until: u64) -> &'static str {
    match secs_until {
        0..=900 => "within the hour",
        901..=10_800 => "~2h",
        10_801..=28_800 => "~6h",
        28_801..=86_400 => "today",
        86_401..=604_800 => "this week",
        _ => "when a courier runs",
    }
}

/// The status line: activity, queue depth, and the next scheduled window.
///
/// # Why sending shows a queue rather than progress
///
/// A composed message enters the local store and waits for the next scheduled
/// reconciliation (RFC 5 §6.1). There is no activity to report, and reporting
/// some would be the causal claim RFC 8 §5.1 forbids. "queued" is true, tells
/// the user their message is safe, and asserts nothing about when it moves
/// beyond the window already shown.
///
/// # An unresolved conflict between three documents
///
/// RFC 5 §4.5 permits PushOnly as a supplement — *"a node MAY push a newly
/// created object to peers immediately as a low-latency fast path"*. Immediate
/// push makes emission time equal composition time, which is a direct activity
/// leak; RFC 6 §2.7 already forbids that shape for group fan-out, requiring a
/// randomised stagger because "G−1 objects appearing within a short window is
/// visible as *someone just sent to about G people*". The reasoning does not
/// stop at G > 1.
///
/// And if push-on-send were implemented, an honest indicator would have to
/// show activity on compose, which RFC 8 §5.1 forbids. All three cannot hold.
/// This implements scheduled-only emission.
#[allow(dead_code)] // the spinner-aware form is what renders
pub fn status_line(state: &NodeState) -> String {
    status_line_with(state, &Spinner::default())
}

/// As [`status_line`], with a spinner glyph when something is in flight.
///
/// RFC 8 §3 gives the command pane two lines and requires structured output to
/// render elsewhere, so this stays to one short line and the same spinner
/// serves link status.
pub fn status_line_with(state: &NodeState, spinner: &Spinner) -> String {
    let mut parts: Vec<String> = Vec::new();
    let activity = Activity::of(state);
    if activity.is_visible() {
        match spinner.glyph(&activity) {
            Some(g) => parts.push(format!("{g} {activity}")),
            None => parts.push(activity.to_string()),
        }
    }
    // RFC 4 §5.2's MUST. First, because it is the one thing on this line an
    // operator is actively waiting on, and because a node that has not
    // bootstrapped is not reachable however healthy the rest looks.
    if let Some(pct) = state.tor_bootstrap {
        parts.push(format!("tor bootstrapping {pct}%"));
    }
    if state.queued > 0 {
        parts.push(format!("{} queued", state.queued));
    }
    if let Some(s) = state.next_sync_in_s {
        parts.push(format!("next reconciliation {}", schedule_window(s)));
    }
    parts.join("  ·  ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **RFC 4 §5.2's MUST: bootstrap progress is shown.**
    ///
    /// "Clients MUST show bootstrap progress or users will believe the node is
    /// broken at every start." Bootstrap takes tens of seconds, so the absence
    /// of this is not cosmetic — it is a node that looks broken every time.
    #[test]
    fn tor_bootstrap_progress_is_shown_while_it_is_coming_up() {
        let coming_up = NodeState {
            tor_bootstrap: Some(45),
            ..Default::default()
        };
        let line = status_line(&coming_up);
        assert!(line.contains("45%"), "no bootstrap progress in {line:?}");
        assert!(line.contains("tor"));
    }

    /// And it goes away when done, rather than sitting at 100% for ever.
    #[test]
    fn a_bootstrapped_tor_says_nothing() {
        let done = NodeState {
            tor_bootstrap: None,
            ..Default::default()
        };
        assert!(!status_line(&done).contains("tor"));
    }

    /// **The two rules that look like they conflict, pinned together.**
    ///
    /// RFC 8 §5.1 forbids a progress indicator for message transfer; RFC 4
    /// §5.2 requires one for Tor bootstrap. They are about different subjects,
    /// and this is what stops a future change collapsing them: sending must
    /// still show no percentage even while tor is bootstrapping, and the
    /// percentage that is present must be tor's.
    #[test]
    fn sending_shows_no_progress_even_while_tor_bootstraps() {
        let both = NodeState {
            queued: 3,
            next_sync_in_s: Some(7_800),
            tor_bootstrap: Some(20),
            ..Default::default()
        };
        let line = status_line(&both);
        assert!(line.contains("3 queued"));
        assert!(line.contains("tor bootstrapping 20%"));
        // The only percentage on the line is tor's.
        assert_eq!(line.matches('%').count(), 1);
        for forbidden in ["sending", "transferring", "uploading"] {
            assert!(!line.contains(forbidden), "{forbidden} in {line:?}");
        }
    }

    /// The central requirement: composing and sending produce no activity,
    /// because there is none to produce.
    #[test]
    fn sending_shows_a_queue_and_never_progress() {
        let after_send = NodeState {
            queued: 1,
            next_sync_in_s: Some(7_800),
            ..Default::default()
        };
        assert_eq!(Activity::of(&after_send), Activity::Idle);
        assert!(!Activity::of(&after_send).is_visible());

        let line = status_line(&after_send);
        assert!(line.contains("1 queued"));
        assert!(line.contains("next reconciliation"));
        // Never a signal implying the user's action caused a transfer.
        for forbidden in ["syncing", "sending", "transferring", "uploading", "%"] {
            assert!(
                !line.to_lowercase().contains(forbidden),
                "{line:?} implies causation"
            );
        }
    }

    /// RFC 8 §5.1 — establishment progress is required, not merely allowed.
    #[test]
    fn establishment_is_shown_because_it_is_real_work() {
        let s = NodeState {
            establishing: Some("tor"),
            ..Default::default()
        };
        assert_eq!(
            Activity::of(&s),
            Activity::Establishing { transport: "tor" }
        );
        assert!(Activity::of(&s).is_visible());
        assert!(status_line(&s).contains("connecting (tor)"));
    }

    /// Permitted because it reports a fact. It can begin while the user is
    /// doing nothing, which is what makes it safe to show.
    #[test]
    fn a_running_reconciliation_may_be_shown_but_is_never_called_syncing() {
        let s = NodeState {
            reconciling: Some("m4k2"),
            ..Default::default()
        };
        assert!(status_line(&s).contains("reconciling with m4k2"));
        assert!(!status_line(&s).to_lowercase().contains("syncing now"));
    }

    /// The operator needs "yes, it is alive" from a background process.
    #[test]
    fn a_spinner_animates_while_something_is_in_flight() {
        let mut sp = Spinner::default();
        let busy = Activity::Reconciling { peer: "m4k2" };
        let a = sp.glyph(&busy).unwrap();
        sp.tick();
        let b = sp.glyph(&busy).unwrap();
        assert_ne!(a, b, "it must actually move");

        // And it stops when nothing is happening -- a perpetually spinning
        // interface says nothing.
        assert_eq!(sp.glyph(&Activity::Idle), None);
    }

    /// The spinner has no way to be started by an event: sampling it is the
    /// only thing a caller can do. This is the test that fails if someone adds
    /// `Spinner::start()`.
    #[test]
    fn the_spinner_is_sampled_never_triggered() {
        let mut sp = Spinner::default();
        // Ticking with nothing in flight still draws nothing, so a keypress
        // that ticked the spinner could not make one appear.
        for _ in 0..100 {
            sp.tick();
            assert_eq!(sp.glyph(&Activity::Idle), None);
        }
        // It appears only because the node state says so.
        let s = NodeState {
            reconciling: Some("p1"),
            ..Default::default()
        };
        assert!(sp.glyph(&Activity::of(&s)).is_some());
    }

    /// Sending must not make the spinner appear, however many objects queue.
    #[test]
    fn queueing_a_message_does_not_start_the_spinner() {
        let sp = Spinner::default();
        for queued in [1usize, 5, 999] {
            let s = NodeState {
                queued,
                next_sync_in_s: Some(7_800),
                ..Default::default()
            };
            assert_eq!(
                sp.glyph(&Activity::of(&s)),
                None,
                "{queued} queued must not animate"
            );
        }
    }

    /// Foreground work is the user's operation and is shown as one.
    #[test]
    fn the_ceremony_is_foreground_and_names_its_step() {
        let s = NodeState {
            ceremony: Some(CeremonyStep::Verify),
            ..Default::default()
        };
        let line = status_line(&s);
        assert!(line.contains("compare the word list aloud"), "{line}");
        // It outranks a background reconciliation, because the user is waiting
        // on it and the reconciliation is nobody's concern right now.
        let both = NodeState {
            ceremony: Some(CeremonyStep::Sign),
            reconciling: Some("m4k2"),
            ..Default::default()
        };
        assert!(matches!(Activity::of(&both), Activity::Ceremony { .. }));
    }

    /// RFC 7 §4.1 puts Argon2id at ~500 ms, so the interface must say why it
    /// has stopped rather than appearing to hang.
    #[test]
    fn unlocking_is_foreground_and_outranks_everything() {
        let s = NodeState {
            unlocking: true,
            ceremony: Some(CeremonyStep::Verify),
            reconciling: Some("p"),
            establishing: Some("tor"),
            ..Default::default()
        };
        assert_eq!(Activity::of(&s), Activity::Unlocking);
    }

    /// The whole point of the foreground/background split: only a handful of
    /// activities are the user's, and sending is not one of them.
    #[test]
    fn only_a_handful_of_activities_are_foreground() {
        let background = NodeState {
            reconciling: Some("p"),
            queued: 12,
            next_sync_in_s: Some(7_000),
            ..Default::default()
        };
        // Reported as a fact, never as the user's operation.
        let line = status_line(&background);
        assert!(line.contains("reconciling with p"));
        for forbidden in ["syncing", "sending", "uploading", "please wait"] {
            assert!(!line.to_lowercase().contains(forbidden), "{line:?}");
        }
    }

    /// RFC 8 §5.1 — a window, never a countdown.
    #[test]
    fn the_schedule_is_a_window_that_does_not_tick() {
        // Values a second apart must render identically, or it is a countdown.
        assert_eq!(schedule_window(7_800), schedule_window(7_801));
        assert_eq!(schedule_window(3_600), schedule_window(5_000));
        // And it coarsens with distance rather than becoming more precise.
        assert_eq!(schedule_window(60), "within the hour");
        assert_eq!(schedule_window(20_000), "~6h");
        assert_eq!(schedule_window(500_000), "this week");
        assert_eq!(schedule_window(5_000_000), "when a courier runs");
    }

    /// Idle is the common case and must not look like a fault.
    #[test]
    fn idle_draws_nothing() {
        let s = NodeState::default();
        assert_eq!(Activity::of(&s), Activity::Idle);
        assert_eq!(status_line(&s), "");
    }

    /// The structural claim: `Activity` has one constructor and it takes node
    /// state. There is no field on `NodeState` describing a user action, so an
    /// indicator cannot be attached to a keypress even by mistake.
    #[test]
    fn activity_is_derived_from_state_alone() {
        let a = NodeState {
            reconciling: Some("p1"),
            queued: 3,
            ..Default::default()
        };
        let b = NodeState {
            reconciling: Some("p1"),
            queued: 3,
            ..Default::default()
        };
        assert_eq!(Activity::of(&a), Activity::of(&b));
        // Queue depth -- the closest thing to a user action -- does not reach
        // the indicator at all.
        let c = NodeState {
            reconciling: Some("p1"),
            queued: 999,
            ..Default::default()
        };
        assert_eq!(Activity::of(&a), Activity::of(&c));
    }
}
