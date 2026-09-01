//! Transports, and the schedule the user is not allowed to trigger.
//!
//! # `connect` does not sync, and cannot
//!
//! RFC 8 §5.1 is unusually direct about the failure mode:
//!
//! > "**This will be reported as a bug.** Users press a button and nothing
//! > appears to happen."
//!
//! And about why it must be resisted anyway: if a keypress produces an
//! indicator that resolves into "12 objects received", the user learns that
//! pressing the key causes transfer. It does not — a scheduled reconciliation
//! happened to fire. Two things then follow. The user starts pressing it when
//! expecting mail or after sending, clustering keypresses around their real
//! activity; and the mental model becomes load-bearing, so *"make the button do
//! what it appears to do"* becomes very hard to refuse.
//!
//! > "Event-driven sync is not reintroduced by someone deciding to weaken
//! > privacy; it is reintroduced by someone fixing what looks like a bug."
//!
//! So this module holds no reference to anything that can reconcile.
//! [`LinkTable::connect`] establishes a transport and returns a
//! [`LinkState`]; there is no path from a keypress to a sync because the type
//! that handles keypresses has nothing to call. A future contributor "fixing"
//! the bug has to add a dependency, not flip a flag.
//!
//! # Windows, not countdowns
//!
//! RFC 8 §5.1 again: "a precise countdown invites waiting for it, and a user
//! who learns the exact schedule will correlate their own behaviour with it."
//!
//! [`LinkState::schedule_hint`] therefore coarsens. `~2h10m` in the RFC's own
//! example is illustrative of format, not of precision — this rounds to the
//! coarser of 10% or 10 minutes, so the number moves in steps a person cannot
//! use to plan around.

use krab_fabric::profile::LinkProfile;
use std::collections::BTreeMap;
use std::fmt;

/// Where a transport has got to.
///
/// RFC 4 §5.2 requires progress for establishment, so these are the states an
/// operator is entitled to watch. Reconciliation is deliberately absent: it is
/// not a transport state and does not belong on this axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // `Failed` awaits a real Fabric -- see the variant.
pub enum Transport {
    /// No transport.
    Down,
    /// Handshake, Tor bootstrap, or LoRa session setup in progress.
    ///
    /// **This is the one thing `connect` may animate.** It is real work caused
    /// by the keypress, so indicating it makes a true claim.
    Establishing,
    /// Established and idle.
    Up,
    /// Establishment failed.
    ///
    /// Constructed once a real `Fabric` is wired: `Fabric::connect` is where
    /// an unreachable peer surfaces, and a courier link deliberately never
    /// reports one (RFC 4 §5.5 — "whether anyone carries it is not the
    /// protocol's business").
    Failed,
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Transport::Down => "down",
            Transport::Establishing => "establishing",
            Transport::Up => "up",
            Transport::Failed => "failed",
        })
    }
}

/// One peer's link.
pub struct LinkState {
    /// The established session, if the transport is up.
    ///
    /// **Held open across reconciliation cycles.** RFC 4 §4.1: a handshake is
    /// ~3 minutes of LoRa airtime, so constrained links "MUST hold sessions
    /// open ... and SHOULD treat session teardown as expensive". Nothing here
    /// closes on idle.
    ///
    /// A session can carry bytes; it cannot reconcile. The driver is
    /// `krab_node::exchange`, and this module does not depend on it — which is
    /// what keeps RFC 8 §5.1's guarantee structural rather than a convention.
    pub session: Option<Box<dyn krab_fabric::Session + 'static>>,
    /// Short peer identifier, as displayed.
    pub peer: String,
    /// What this link can carry.
    pub profile: LinkProfile,
    /// Transport state.
    pub transport: Transport,
    /// Minutes until the next scheduled reconciliation, from the scheduler.
    ///
    /// `None` when nothing is scheduled. **Never displayed raw** — see
    /// [`LinkState::schedule_hint`].
    pub next_sync_min: Option<u64>,
}

impl LinkState {
    /// The scheduled window, coarsened.
    ///
    /// Deliberately imprecise, and the imprecision is the feature. RFC 8 §5.1:
    /// showing a window rather than a countdown "matters: a precise countdown
    /// invites waiting for it".
    ///
    /// Always says "(scheduled)", because the one thing the operator must take
    /// away is that this did not happen because they asked.
    pub fn schedule_hint(&self) -> String {
        let Some(min) = self.next_sync_min else {
            return "no reconciliation scheduled".into();
        };
        // A **fixed** grid, chosen by magnitude. Deriving the step from the
        // value itself moves the grid as the value drifts, which is how a
        // coarsened display leaks a countdown anyway: successive readings land
        // on different boundaries and the differences are informative.
        let step = match min {
            0..=59 => 15,
            60..=359 => 30,
            _ => 60,
        };
        let rounded = (((min + step / 2) / step) * step).max(step);
        if rounded >= 60 {
            let (h, m) = (rounded / 60, rounded % 60);
            if m == 0 {
                format!("next reconciliation ~{h}h (scheduled)")
            } else {
                format!("next reconciliation ~{h}h{m:02}m (scheduled)")
            }
        } else {
            format!("next reconciliation ~{}m (scheduled)", rounded.max(step))
        }
    }

    /// RFC 8 §5.1's suggested status line.
    pub fn status_line(&self) -> String {
        format!(
            "peer {}  ·  link {} ({})  ·  {}",
            self.peer,
            self.transport,
            self.profile.kind,
            self.schedule_hint()
        )
    }
}

/// Every link this node holds.
///
/// **Holds no reconciler by construction.** See the module documentation.
#[derive(Default)]
pub struct LinkTable {
    links: BTreeMap<String, LinkState>,
}

impl LinkTable {
    /// An empty table.
    pub fn new() -> LinkTable {
        LinkTable {
            links: BTreeMap::new(),
        }
    }

    /// Establish a transport toward `peer` — RFC 8 §5's `connect`.
    ///
    /// Establishes a transport and **nothing else**. There is no reconcile
    /// call here and no way to add one without giving this module a dependency
    /// it does not have.
    /// Begin establishing a link to `peer` over `profile`.
    ///
    /// # The profile is adopted, and it used to be ignored
    ///
    /// This was `or_insert_with`, so a second `connect` to a peer that already
    /// had a link kept the **first** profile and discarded the one passed in.
    /// `connect <peer> lora <addr>` after `connect <peer> tcp <addr>` therefore
    /// reported success and left the node believing the peer was still on TCP
    /// — which decides the sync mode (RFC 5 §4.1), the object ceiling (RFC 4
    /// §5.4 and §9), the session deadline, and what the peers panel tells the
    /// operator about location privacy. Every one of those would have been
    /// answered for a carrier the link no longer used.
    ///
    /// The session is deliberately kept. A profile is a description of the
    /// carrier; an open socket is a fact about the world, and dropping it here
    /// would make a re-`connect` tear down a working exchange.
    pub fn connect(&mut self, peer: &str, profile: LinkProfile) -> &LinkState {
        let entry = self
            .links
            .entry(peer.to_string())
            .or_insert_with(|| LinkState {
                peer: peer.to_string(),
                profile: profile.clone(),
                transport: Transport::Down,
                next_sync_min: None,
                session: None,
            });
        entry.profile = profile;
        entry.transport = Transport::Establishing;
        entry
    }

    /// Mark establishment complete, adopting the session.
    pub fn established(
        &mut self,
        peer: &str,
        session: Option<Box<dyn krab_fabric::Session + 'static>>,
    ) {
        if let Some(l) = self.links.get_mut(peer) {
            l.transport = Transport::Up;
            l.session = session;
        }
    }

    /// Mark establishment as having failed.
    pub fn failed(&mut self, peer: &str) {
        if let Some(l) = self.links.get_mut(peer) {
            l.transport = Transport::Failed;
            l.session = None;
        }
    }

    /// Take the session for a peer whose transport is up.
    ///
    /// Moves it out rather than lending it: an exchange runs on another thread
    /// and cannot borrow from the link table. A peer with an exchange in flight
    /// therefore has no session here, which is also what stops two overlapping
    /// exchanges on one link.
    pub fn take_session(&mut self, peer: &str) -> Option<Box<dyn krab_fabric::Session + 'static>> {
        let l = self.links.get_mut(peer)?;
        if l.transport != Transport::Up {
            return None;
        }
        l.session.take()
    }

    /// Tear a link down — RFC 8 §5's `disconnect`.
    ///
    /// Returns whether a link was there. RFC 3 §6.2's quota reduction is a
    /// separate decision an operator makes from the peers panel; conflating
    /// them would make disconnecting a punishment and discourage it.
    pub fn disconnect(&mut self, peer: &str) -> bool {
        match self.links.get_mut(peer) {
            Some(l) => {
                l.transport = Transport::Down;
                if let Some(mut s) = l.session.take() {
                    let _ = s.close();
                }
                true
            }
            None => false,
        }
    }

    /// Record the scheduler's next window for a peer.
    ///
    /// Called by `krab_node::scheduler`, which is not yet driving this loop.
    /// Present now because the *direction* matters: the scheduler pushes a
    /// window in, and no command pulls one out. A command that could ask
    /// "when is the next sync" would be one refactor away from "sync now".
    ///
    /// Called by the scheduler, never by a command. The signature takes minutes
    /// rather than a closure precisely so a caller cannot pass "now".
    pub fn set_next_sync(&mut self, peer: &str, minutes: u64) {
        if let Some(l) = self.links.get_mut(peer) {
            l.next_sync_min = Some(minutes);
        }
    }

    /// One peer's link.
    pub fn get(&self, peer: &str) -> Option<&LinkState> {
        self.links.get(peer)
    }

    /// A link, mutably — for a verb that needs to talk on its session.
    pub fn get_mut(&mut self, peer: &str) -> Option<&mut LinkState> {
        self.links.get_mut(peer)
    }

    /// Every link, in stable order.
    pub fn iter(&self) -> impl Iterator<Item = &LinkState> {
        self.links.values()
    }

    /// Every peer name, for joining against the scheduler.
    pub fn peer_names(&self) -> Vec<String> {
        self.links.keys().cloned().collect()
    }

    /// Links currently up.
    pub fn up_count(&self) -> usize {
        self.links
            .values()
            .filter(|l| l.transport == Transport::Up)
            .count()
    }
}

/// Resolve a transport name to a profile.
pub fn profile_named(kind: &str) -> Option<LinkProfile> {
    Some(match kind {
        "tcp" => LinkProfile::tcp(),
        // RFC 4 §5.2. `socks` is accepted as a synonym because the cargo
        // feature and `location_privacy` have both spelled it that way since
        // before either did anything, and an operator who typed it would
        // otherwise get "unknown link kind" for a transport that exists.
        "tor" | "socks" => LinkProfile::tor(),
        "serial" | "modem" => LinkProfile::serial(),
        "courier" => LinkProfile::courier(),
        "lora" => LinkProfile::lora_sf10(),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use krab_fabric::profile::LatencyClass;

    fn table() -> LinkTable {
        let mut t = LinkTable::new();
        t.connect("q3m9", LinkProfile::tcp());
        t.established("q3m9", None);
        t
    }

    /// **RFC 8 §5.1.** Connecting establishes a transport and moves nothing
    /// else. The structural guarantee is that this module cannot reconcile —
    /// this test pins the observable half.
    #[test]
    fn connect_establishes_a_transport_and_schedules_nothing() {
        let mut t = LinkTable::new();
        let l = t.connect("q3m9", LinkProfile::tcp());
        assert_eq!(l.transport, Transport::Establishing);
        assert_eq!(l.next_sync_min, None, "connecting must not schedule a sync");
        assert!(l.schedule_hint().contains("no reconciliation scheduled"));
    }

    /// The status line must never imply the user caused a transfer.
    #[test]
    fn no_status_line_claims_the_user_caused_a_transfer() {
        let mut t = table();
        t.set_next_sync("q3m9", 130);
        let line = t.get("q3m9").unwrap().status_line();
        assert!(line.contains("(scheduled)"), "{line}");
        for forbidden in [
            "syncing",
            "receiving",
            "downloading",
            "now",
            "objects received",
        ] {
            assert!(
                !line.to_lowercase().contains(forbidden),
                "{line:?} implies the keypress caused transfer via {forbidden:?}"
            );
        }
    }

    /// **Windows, not countdowns.** Successive glances a minute apart must not
    /// yield a usable countdown, or a user will time their behaviour to it.
    #[test]
    fn the_schedule_is_coarse_enough_not_to_be_a_countdown() {
        let mut t = table();
        let mut distinct = std::collections::BTreeSet::new();
        for min in 120..140 {
            t.set_next_sync("q3m9", min);
            distinct.insert(t.get("q3m9").unwrap().schedule_hint());
        }
        assert!(
            distinct.len() <= 3,
            "20 minutes of drift produced {} distinct readings: {distinct:?}",
            distinct.len()
        );
    }

    /// And it stays coarse at short horizons, where a countdown would be most
    /// tempting to watch.
    #[test]
    fn short_horizons_are_coarsened_too() {
        let mut t = table();
        let mut distinct = std::collections::BTreeSet::new();
        for min in 1..20 {
            t.set_next_sync("q3m9", min);
            distinct.insert(t.get("q3m9").unwrap().schedule_hint());
        }
        assert!(distinct.len() <= 2, "{distinct:?}");
    }

    #[test]
    fn disconnect_reports_whether_there_was_a_link() {
        let mut t = table();
        assert!(t.disconnect("q3m9"));
        assert_eq!(t.get("q3m9").unwrap().transport, Transport::Down);
        assert!(!t.disconnect("nobody"));
        assert_eq!(t.up_count(), 0);
    }

    /// Establishment is the one thing `connect` may indicate, because it is
    /// real work the keypress actually caused (RFC 4 §5.2).
    #[test]
    fn establishment_is_a_distinct_observable_state() {
        let mut t = LinkTable::new();
        t.connect("m4k2", LinkProfile::lora_sf10());
        assert_eq!(t.get("m4k2").unwrap().transport, Transport::Establishing);
        t.established("m4k2", None);
        assert_eq!(t.get("m4k2").unwrap().transport, Transport::Up);
    }

    #[test]
    fn transports_resolve_by_name() {
        assert_eq!(profile_named("tcp").unwrap().kind, LinkProfile::tcp().kind);
        assert_eq!(
            profile_named("lora").unwrap().kind,
            LinkProfile::lora_sf10().kind
        );
        assert!(profile_named("carrier-pigeon").is_none());
    }

    /// A courier link's schedule is meaningless in minutes, and saying so is
    /// better than rendering "~0m".
    #[test]
    fn a_link_with_no_schedule_says_so_rather_than_showing_zero() {
        let mut t = LinkTable::new();
        t.connect("post", LinkProfile::courier());
        let hint = t.get("post").unwrap().schedule_hint();
        assert!(!hint.contains("~0"), "{hint}");
        assert!(hint.contains("no reconciliation scheduled"));
    }

    /// Latency class drives sync mode; it is derived, never configured
    /// (RFC 5 §4.5).
    #[test]
    fn sync_mode_follows_the_link_not_a_setting() {
        assert_eq!(LinkProfile::tcp().latency_class, LatencyClass::Interactive);
        assert_ne!(
            LinkProfile::tcp().sync_mode(),
            LinkProfile::courier().sync_mode(),
            "a courier link must not choose a multi-round protocol"
        );
    }
}
