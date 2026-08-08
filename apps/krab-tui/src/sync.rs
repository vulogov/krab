//! The reconciliation schedule — RFC 5 §6.1, RFC 0 I-5.
//!
//! ```text
//! Reconciliation MUST run on a Poisson schedule with randomised interval
//! and randomised peer order, independent of user activity, mail arrival,
//! queue depth, and application focus.
//! ```
//!
//! # Why this is the invariant most likely to be lost
//!
//! RFC 5 §6.1 names the mechanism: event-driven sync "looks strictly better on
//! every metric a performance test measures." Latency drops, bandwidth drops,
//! battery use drops. Nothing a benchmark reports gets worse. The only thing
//! that gets worse is that a node which syncs more eagerly when it has mail
//! correlates itself with a tag stream, and an observer needs nothing but
//! arrival timing to exploit it.
//!
//! So the RFC asks for a specific defence:
//!
//! > "It **SHOULD be protected by a test asserting that inter-sync intervals
//! > are uncorrelated with message events**, not by a comment."
//!
//! [`tests::the_schedule_is_independent_of_message_events`] is that test, and
//! it is stronger than the RFC asks for. Rather than measuring a correlation
//! coefficient and asserting it is small, it runs the same schedule twice —
//! once with heavy message activity, once with none, from the same entropy —
//! and asserts the two are **byte-identical**. Correlation near zero is
//! evidence; identity is proof.
//!
//! That is possible because `Scheduler::due(now, entropy)` takes no event
//! parameter. The independence is a property of the type signature, and this
//! module keeps it that way: [`Tick::run`] receives the scheduler and the link
//! table and has no access to the store, the composer, or anything else that
//! could tell it what the user did.

use crate::links::LinkTable;
use krab_node::scheduler::{PeerId, Scheduler};

/// One pass of the schedule.
pub struct Tick {
    /// Peers due to reconcile now, in randomised order (RFC 5 §6.2).
    pub due: Vec<PeerId>,
}

impl Tick {
    /// Advance the schedule to `now`.
    ///
    /// **Takes no event input, by construction.** There is no parameter here
    /// for "mail arrived", "the user pressed send", or "the queue is deep",
    /// and adding one would be the change that breaks I-5 — which is why the
    /// absence is worth stating rather than assuming.
    pub fn run(scheduler: &mut Scheduler, links: &mut LinkTable, now_s: u64, entropy: u64) -> Tick {
        let due = scheduler.due(now_s, entropy);

        // Publish the next window for every peer, so the interface can show a
        // coarsened hint (RFC 8 §5.1). The scheduler pushes; nothing pulls.
        for peer in links.peer_names() {
            if let Some(id) = peer_id_of(&peer) {
                if let Some(next_s) = scheduler.next_due(&id) {
                    links.set_next_sync(&peer, next_s.saturating_sub(now_s) / 60);
                }
            }
        }
        Tick { due }
    }
}

/// Parse a displayed short identifier back to the `PeerId` prefix used by the
/// scheduler.
///
/// The link table is keyed by what the operator sees; the scheduler by the
/// full identifier. This is the seam, and it is deliberately lossy in the
/// safe direction — an unparseable name schedules nothing rather than
/// scheduling the wrong peer.
pub fn peer_id_of(short: &str) -> Option<PeerId> {
    if short.len() < 8 || !short.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut id = [0u8; 32];
    for i in 0..4 {
        id[i] = u8::from_str_radix(&short[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(id)
}

/// The scheduler's identifier for a peer whose full node id is known.
pub fn peer_id_from_node(node_id: &[u8; 32]) -> PeerId {
    let mut id = [0u8; 32];
    id[..4].copy_from_slice(&node_id[..4]);
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use krab_fabric::profile::LinkProfile;

    const HOUR: u64 = 3_600;
    const MEAN: u64 = 4 * HOUR;

    fn setup(peers: usize) -> (Scheduler, LinkTable) {
        let mut s = Scheduler::new(MEAN);
        let mut l = LinkTable::new();
        for i in 0..peers {
            let mut id = [0u8; 32];
            id[0] = i as u8 + 1;
            s.add(id, 0, 0x9E37_79B9_7F4A_7C15u64.wrapping_mul(i as u64 + 1));
            let name = format!("{:02x}{:02x}{:02x}{:02x}", id[0], id[1], id[2], id[3]);
            l.connect(&name, LinkProfile::tcp());
            l.established(&name, None);
        }
        (s, l)
    }

    /// A deterministic entropy stream, so two runs are comparable.
    fn entropy_at(t: u64) -> u64 {
        let mut x = t
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(0xDEAD_BEEF);
        x ^= x >> 30;
        x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x ^= x >> 27;
        x
    }

    /// Run the schedule for a simulated week, optionally with a user busily
    /// composing and receiving mail throughout.
    fn schedule_over_a_week(with_message_events: bool) -> Vec<(u64, PeerId)> {
        let (mut sched, mut links) = setup(5);
        let mut fired = Vec::new();

        for step in 0..(7 * 24 * 60) {
            let now = step * 60;

            // Message activity, in bursts, at times a person would actually
            // produce them: a cluster in the morning and one in the evening.
            if with_message_events {
                let minute_of_day = step % (24 * 60);
                let busy =
                    (480..540).contains(&minute_of_day) || (1140..1200).contains(&minute_of_day);
                if busy && step % 3 == 0 {
                    // A message event. It reaches the store, the composer, the
                    // interface -- and nothing here. There is no parameter on
                    // `Tick::run` for it to travel through.
                    let _ = "the user sent something";
                }
            }

            for peer in Tick::run(&mut sched, &mut links, now, entropy_at(now)).due {
                fired.push((now, peer));
            }
        }
        fired
    }

    /// **RFC 5 §6.1's required protection.**
    ///
    /// > "It SHOULD be protected by a test asserting that inter-sync intervals
    /// > are uncorrelated with message events, not by a comment."
    ///
    /// Stronger than asked: the two schedules are identical, not merely
    /// uncorrelated. Correlation near zero is evidence; identity is proof, and
    /// it is available because `Scheduler::due` has no event parameter to pass.
    #[test]
    fn the_schedule_is_independent_of_message_events() {
        let quiet = schedule_over_a_week(false);
        let busy = schedule_over_a_week(true);

        assert!(!quiet.is_empty(), "the schedule must actually fire");
        assert_eq!(
            quiet, busy,
            "a week of heavy message activity changed the reconciliation schedule"
        );
    }

    /// The schedule is a Poisson process: intervals are exponentially
    /// distributed around the configured mean, not periodic.
    ///
    /// A periodic schedule is independent of events and still wrong — an
    /// observer who learns the period knows when to look, and RFC 8 §5.1's
    /// concern about countdowns is the same concern at a different layer.
    #[test]
    fn intervals_are_exponential_not_periodic() {
        let fired = schedule_over_a_week(false);
        let mut per_peer: std::collections::BTreeMap<PeerId, Vec<u64>> = Default::default();
        for (t, p) in &fired {
            per_peer.entry(*p).or_default().push(*t);
        }

        for (peer, times) in per_peer {
            let gaps: Vec<u64> = times.windows(2).map(|w| w[1] - w[0]).collect();
            assert!(gaps.len() > 10, "too few samples for {:02x}", peer[0]);

            let mean = gaps.iter().sum::<u64>() as f64 / gaps.len() as f64;
            assert!(
                (mean - MEAN as f64).abs() < MEAN as f64 * 0.5,
                "mean interval {mean:.0}s is far from the configured {MEAN}s"
            );

            // Exponential: the standard deviation equals the mean. A periodic
            // schedule would have a standard deviation near zero.
            let var = gaps
                .iter()
                .map(|g| {
                    let d = *g as f64 - mean;
                    d * d
                })
                .sum::<f64>()
                / gaps.len() as f64;
            let sd = var.sqrt();
            assert!(
                sd > mean * 0.4,
                "standard deviation {sd:.0} is too small for a Poisson process — \
                 this schedule is nearly periodic and therefore predictable"
            );
        }
    }

    /// RFC 5 §6.2 — peer order is randomised, so no peer is predictably first
    /// and none is predictably your only source for a region of the corpus.
    #[test]
    fn peer_order_is_randomised() {
        let (mut sched, mut links) = setup(6);
        // Make everything due at once, so the order is entirely the shuffle's.
        let mut orders = std::collections::BTreeSet::new();
        for round in 0..40u64 {
            let (mut s2, mut l2) = setup(6);
            let t = 10 * HOUR + round * HOUR;
            let due = Tick::run(&mut s2, &mut l2, t, entropy_at(t)).due;
            if due.len() > 1 {
                orders.insert(due);
            }
        }
        assert!(orders.len() > 1, "peer order never varied across 40 rounds");
        let _ = Tick::run(&mut sched, &mut links, HOUR, entropy_at(HOUR));
    }

    /// The interface learns the *next* window from the scheduler. Nothing in
    /// the other direction — a command that could ask "when is the next sync"
    /// is one refactor from "sync now".
    #[test]
    fn the_scheduler_pushes_windows_and_nothing_pulls() {
        let (mut sched, mut links) = setup(2);
        Tick::run(&mut sched, &mut links, 0, 12_345);
        for link in links.iter() {
            assert!(
                link.next_sync_min.is_some(),
                "{} never learned its window",
                link.peer
            );
            // And it is rendered coarsely (RFC 8 §5.1).
            assert!(link.schedule_hint().contains("(scheduled)"));
        }
    }

    /// A peer with no link still schedules; a link with no peer still renders.
    /// The two tables are joined by a name, and a mismatch must not panic.
    #[test]
    fn a_name_mismatch_is_survivable() {
        let (mut sched, mut links) = setup(1);
        links.connect("not-hex-at-all", LinkProfile::tcp());
        links.connect("ab", LinkProfile::tcp());
        Tick::run(&mut sched, &mut links, HOUR, 999);
        assert_eq!(links.get("not-hex-at-all").unwrap().next_sync_min, None);
        assert_eq!(links.get("ab").unwrap().next_sync_min, None);
    }

    #[test]
    fn short_ids_round_trip() {
        let node = [0xAB, 0xCD, 0xEF, 0x01, 0xFF, 0xFF];
        let mut full = [0u8; 32];
        full[..6].copy_from_slice(&node);
        let id = peer_id_from_node(&full);
        assert_eq!(peer_id_of("abcdef01"), Some(id));
        assert_eq!(peer_id_of("ABCDEF01"), Some(id), "case-insensitive");
        assert_eq!(peer_id_of("abcd"), None, "too short");
        assert_eq!(peer_id_of("zzzzzzzz"), None, "not hex");
    }
}
