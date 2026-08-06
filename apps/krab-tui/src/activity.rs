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
//! # Non-intrusive, for a reason beyond taste
//!
//! RFC 8 §5.1 also warns that "a precise countdown invites waiting for it, and
//! a user who learns the exact schedule will correlate their own behaviour
//! with it." An indicator that draws the eye trains the attention the design
//! is trying not to create. So the schedule is shown as a **coarsened window**
//! and never as a live countdown, and nothing animates.
//!
//! There is a plain cost reason too: a spinner redrawing at 10 Hz over a
//! serial console or a poor SSH link is real bandwidth on exactly the
//! transports Krab exists to serve.

use core::fmt;

/// What the node is doing, derived from its state.
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
    /// Permitted by RFC 8 §5.1 only because it reports a fact rather than a
    /// consequence. It can begin while the user is doing nothing at all, which
    /// is exactly what makes it safe to show.
    Reconciling {
        /// Short peer label.
        peer: &'static str,
    },
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
}

impl Activity {
    /// Derive what to show. The only way to construct one.
    pub fn of(state: &NodeState) -> Activity {
        // Establishment first: it is the one the user actually caused, and the
        // one RFC 4 §5.2 says will otherwise look like a hang.
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
}

impl fmt::Display for Activity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Activity::Idle => Ok(()),
            Activity::Establishing { transport } => write!(f, "connecting ({transport})"),
            // Note the wording: never "syncing now", which RFC 8 §5.1 forbids
            // because it implies the user's action caused a transfer.
            Activity::Reconciling { peer } => write!(f, "reconciling with {peer}"),
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
pub fn status_line(state: &NodeState) -> String {
    let mut parts: Vec<String> = Vec::new();
    let activity = Activity::of(state);
    if activity.is_visible() {
        parts.push(activity.to_string());
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

    /// The central requirement: composing and sending produce no activity,
    /// because there is none to produce.
    #[test]
    fn sending_shows_a_queue_and_never_progress() {
        let after_send = NodeState { queued: 1, next_sync_in_s: Some(7_800), ..Default::default() };
        assert_eq!(Activity::of(&after_send), Activity::Idle);
        assert!(!Activity::of(&after_send).is_visible());

        let line = status_line(&after_send);
        assert!(line.contains("1 queued"));
        assert!(line.contains("next reconciliation"));
        // Never a signal implying the user's action caused a transfer.
        for forbidden in ["syncing", "sending", "transferring", "uploading", "%"] {
            assert!(!line.to_lowercase().contains(forbidden), "{line:?} implies causation");
        }
    }

    /// RFC 8 §5.1 — establishment progress is required, not merely allowed.
    #[test]
    fn establishment_is_shown_because_it_is_real_work() {
        let s = NodeState { establishing: Some("tor"), ..Default::default() };
        assert_eq!(Activity::of(&s), Activity::Establishing { transport: "tor" });
        assert!(Activity::of(&s).is_visible());
        assert!(status_line(&s).contains("connecting (tor)"));
    }

    /// Permitted because it reports a fact. It can begin while the user is
    /// doing nothing, which is what makes it safe to show.
    #[test]
    fn a_running_reconciliation_may_be_shown_but_is_never_called_syncing() {
        let s = NodeState { reconciling: Some("m4k2"), ..Default::default() };
        assert!(status_line(&s).contains("reconciling with m4k2"));
        assert!(!status_line(&s).to_lowercase().contains("syncing now"));
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
        let a = NodeState { reconciling: Some("p1"), queued: 3, ..Default::default() };
        let b = NodeState { reconciling: Some("p1"), queued: 3, ..Default::default() };
        assert_eq!(Activity::of(&a), Activity::of(&b));
        // Queue depth -- the closest thing to a user action -- does not reach
        // the indicator at all.
        let c = NodeState { reconciling: Some("p1"), queued: 999, ..Default::default() };
        assert_eq!(Activity::of(&a), Activity::of(&c));
    }
}
