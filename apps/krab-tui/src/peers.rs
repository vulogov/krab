//! The peers panel — RFC 8 §5.3, RFC 3 §12.
//!
//! # Aggregates only, and the reason is a seizure
//!
//! RFC 8 §5.3: per-object provenance is forbidden, "because arrival timestamps
//! and per-object attribution reconstruct the graph and its timing gradients on
//! disk for a seizing adversary."
//!
//! So the constraint is not about what the panel *displays*. It is about what
//! the node *keeps*. A panel that renders aggregates from a per-object log has
//! satisfied nothing — the log is the artifact that gets seized.
//!
//! [`krab_node::metrics::PeerMetrics`] is counters only, with no vector to
//! append to and no timestamp field. This module renders those counters and
//! cannot do otherwise, because there is nothing else to render.
//!
//! # Two rows that are worth more than the rest
//!
//! RFC 8 §5.3 singles them out, "rather than burial in a table":
//!
//! - **unique-source contribution** is the eclipse indicator, and is invisible
//!   otherwise. A peer supplying objects nobody else supplies is either a
//!   well-connected friend or the only thing you can see, and those look
//!   identical until you ask.
//! - **overhead share above 50% on a non-constrained link** indicates
//!   misconfiguration (RFC 5 §10).
//!
//! [`Row::highlights`] surfaces both without the operator having to read a
//! table and know what to look for.
//!
//! # Disconnect is one keystroke
//!
//! ```text
//! The disconnect action MUST be reachable with one keystroke from the peers panel.
//! ```
//!
//! *(RFC 8 §5.3, derived from RFC 3 §12.)* "If it is not, operators will not
//! act, and quota as an accountability mechanism degrades to nothing." The
//! binding is [`DISCONNECT_KEY`] and a test asserts it is a bare key with no
//! modifier.

use crate::links::LinkState;
use krab_node::metrics::{Coverage, PeerMetrics};

/// The one keystroke RFC 8 §5.3 requires. Bare, no modifier.
pub const DISCONNECT_KEY: char = 'd';

/// What the panel says about one peer, beyond the raw counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Highlight {
    /// This peer supplies objects no other peer does.
    ///
    /// The eclipse indicator. Not an accusation — a well-connected friend
    /// looks the same — but it is the only place the question is askable.
    EclipseRisk(u8),
    /// Control traffic exceeds half the bytes, on a link with room.
    ///
    /// RFC 5 §10. On a constrained link this is expected and not reported.
    OverheadHigh(u8),
    /// Tag matches that failed to decrypt.
    ///
    /// RFC 1 §6.2's window is the usual cause: an object arrived inside its
    /// TTL but outside the epochs this node computed tags for, so it is
    /// stored and undecryptable, permanently and silently.
    DecryptFailures(u8),
}

impl core::fmt::Display for Highlight {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Highlight::EclipseRisk(p) => write!(
                f,
                "{p}% of what this peer sends reaches you from nowhere else — \
                 if this is most of your corpus you are seeing what they choose"
            ),
            Highlight::OverheadHigh(p) => write!(
                f,
                "{p}% of bytes are control traffic on an unconstrained link — \
                 likely misconfiguration (RFC 5 §10)"
            ),
            Highlight::DecryptFailures(p) => write!(
                f,
                "{p}% of tag matches did not decrypt — objects are being stored \
                 that can never be read"
            ),
        }
    }
}

/// One peer's row.
pub struct Row<'a> {
    /// Short peer identifier.
    pub peer: &'a str,
    /// Counters. **No per-object history exists to pass here.**
    pub metrics: &'a PeerMetrics,
    /// Corpus coverage by age.
    pub coverage: &'a Coverage,
    /// Transport state, or `None` if there is no link.
    pub link: Option<&'a LinkState>,
    /// Ingress quota in bytes, for the against-quota figure.
    pub quota_bytes: u64,
}

impl Row<'_> {
    /// Ingress as a percentage of quota (RFC 3 §6).
    pub fn quota_used(&self) -> f64 {
        if self.quota_bytes == 0 {
            return 0.0;
        }
        100.0 * self.metrics.ingress_bytes as f64 / self.quota_bytes as f64
    }

    /// What deserves saying out loud about this peer.
    ///
    /// Thresholds are conservative on purpose: a panel that cries wolf is a
    /// panel operators stop reading, and RFC 8 §5.3's whole concern is that
    /// they will not act.
    pub fn highlights(&self) -> Vec<Highlight> {
        let mut out = Vec::new();
        let pct = |x: f64| (x * 100.0).round() as u8;

        if let Some(r) = self.metrics.unique_source_ratio() {
            if r > 0.5 {
                out.push(Highlight::EclipseRisk(pct(r)));
            }
        }
        if let Some(r) = self.metrics.overhead_share() {
            // "on a non-constrained link" — a courier or LoRa link is expected
            // to spend a large share on control, and flagging it would train
            // operators to ignore the row.
            let constrained = self
                .link
                .map(|l| l.profile.metered || l.profile.sustained_bps < 10_000.0)
                .unwrap_or(false);
            if r > 0.5 && !constrained {
                out.push(Highlight::OverheadHigh(pct(r)));
            }
        }
        if let Some(r) = self.metrics.decrypt_failure_ratio() {
            if r > 0.05 {
                out.push(Highlight::DecryptFailures(pct(r)));
            }
        }
        out
    }

    /// The row, rendered.
    pub fn render(&self) -> String {
        let link = match self.link {
            Some(l) => format!("{} ({})", l.transport, l.profile.kind),
            None => "no link".into(),
        };
        let f = |o: Option<f64>| {
            o.map(|v| format!("{:.0}%", v * 100.0))
                .unwrap_or("—".into())
        };

        let mut s = format!(
            "{:<8} {:<20} quota {:>5.1}%  novelty {:>4}  unique {:>4}  \
             overhead {:>4}  coverage {:>4.0}%",
            self.peer,
            link,
            self.quota_used(),
            f(self.metrics.novelty_ratio()),
            f(self.metrics.unique_source_ratio()),
            f(self.metrics.overhead_share()),
            self.coverage.mean() * 100.0,
        );
        for h in self.highlights() {
            s.push_str(&format!("\n         ! {h}"));
        }
        s
    }
}

/// The panel.
pub fn render(rows: &[Row], key: char) -> String {
    if rows.is_empty() {
        return "no peers. `peer offer` starts a ceremony (RFC 3 §11).".into();
    }
    let mut out = String::new();
    for r in rows {
        out.push_str(&r.render());
        out.push('\n');
    }
    // RFC 8 §5.3: the disconnect action MUST be one keystroke from here.
    out.push_str(&format!("\n  [{key}] disconnect the selected peer"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::links::{LinkTable, Transport};
    use krab_fabric::profile::LinkProfile;

    fn metrics() -> PeerMetrics {
        PeerMetrics {
            ingress_bytes: 5_000_000,
            objects_received: 1_000,
            objects_new: 400,
            unique_source: 100,
            control_bytes: 10_000,
            payload_bytes: 990_000,
            tag_match_decrypt_ok: 100,
            tag_match_decrypt_fail: 0,
            rejected: 0,
        }
    }

    fn coverage() -> Coverage {
        Coverage { by_age: [0.9; 8] }
    }

    fn table() -> LinkTable {
        let mut t = LinkTable::new();
        t.connect("q3m9", LinkProfile::tcp());
        t.established("q3m9", None);
        t
    }

    /// **RFC 8 §5.3's one-keystroke requirement**, asserted rather than
    /// assumed. A modifier would make it two.
    #[test]
    fn disconnect_is_a_bare_single_keystroke() {
        assert!(DISCONNECT_KEY.is_ascii_alphabetic());
        let t = table();
        let m = metrics();
        let c = coverage();
        let rows = [Row {
            peer: "q3m9",
            metrics: &m,
            coverage: &c,
            link: t.get("q3m9"),
            quota_bytes: 10_000_000,
        }];
        let panel = render(&rows, DISCONNECT_KEY);
        assert!(
            panel.contains(&format!("[{DISCONNECT_KEY}] disconnect")),
            "{panel}"
        );
    }

    /// **The eclipse indicator.** RFC 8 §5.3 asks for it to be surfaced rather
    /// than buried, because it is invisible otherwise.
    #[test]
    fn a_peer_supplying_most_of_your_corpus_alone_is_flagged() {
        let mut m = metrics();
        m.unique_source = 900;
        m.objects_received = 1_000;
        let c = coverage();
        let t = table();
        let row = Row {
            peer: "q3m9",
            metrics: &m,
            coverage: &c,
            link: t.get("q3m9"),
            quota_bytes: 10_000_000,
        };
        let hs = row.highlights();
        assert!(
            matches!(hs.first(), Some(Highlight::EclipseRisk(_))),
            "{hs:?}"
        );
        // And the text explains the consequence, not just the number.
        assert!(
            row.render().contains("what they choose"),
            "{}",
            row.render()
        );
    }

    /// A well-shared corpus produces no eclipse warning — a panel that always
    /// warns is a panel nobody reads.
    #[test]
    fn a_normal_peer_is_not_flagged() {
        let m = metrics();
        let c = coverage();
        let t = table();
        let row = Row {
            peer: "q3m9",
            metrics: &m,
            coverage: &c,
            link: t.get("q3m9"),
            quota_bytes: 10_000_000,
        };
        assert!(row.highlights().is_empty(), "{:?}", row.highlights());
    }

    /// **RFC 5 §10** — high overhead on an unconstrained link is
    /// misconfiguration. On a constrained one it is expected, and flagging it
    /// would train operators to ignore the row.
    #[test]
    fn overhead_is_flagged_only_where_it_indicates_misconfiguration() {
        let mut m = metrics();
        m.control_bytes = 900_000;
        m.payload_bytes = 100_000;
        let c = coverage();

        let mut fast = LinkTable::new();
        fast.connect("q3m9", LinkProfile::tcp());
        let flagged = Row {
            peer: "q3m9",
            metrics: &m,
            coverage: &c,
            link: fast.get("q3m9"),
            quota_bytes: 10_000_000,
        };
        assert!(
            flagged
                .highlights()
                .iter()
                .any(|h| matches!(h, Highlight::OverheadHigh(_))),
            "{:?}",
            flagged.highlights()
        );

        let mut slow = LinkTable::new();
        slow.connect("m4k2", LinkProfile::lora_sf10());
        let quiet = Row {
            peer: "m4k2",
            metrics: &m,
            coverage: &c,
            link: slow.get("m4k2"),
            quota_bytes: 10_000_000,
        };
        assert!(
            !quiet
                .highlights()
                .iter()
                .any(|h| matches!(h, Highlight::OverheadHigh(_))),
            "a constrained link spends bytes on control by design"
        );
    }

    /// Tag matches that never decrypt mean objects are stored that can never
    /// be read — RFC 1 §6.2's window, and it is otherwise silent.
    #[test]
    fn undecryptable_arrivals_are_surfaced() {
        let mut m = metrics();
        m.tag_match_decrypt_ok = 90;
        m.tag_match_decrypt_fail = 10;
        let c = coverage();
        let t = table();
        let row = Row {
            peer: "q3m9",
            metrics: &m,
            coverage: &c,
            link: t.get("q3m9"),
            quota_bytes: 10_000_000,
        };
        assert!(row
            .highlights()
            .iter()
            .any(|h| matches!(h, Highlight::DecryptFailures(_))));
        assert!(row.render().contains("can never be read"));
    }

    /// **RFC 3 §12** — nothing per-object reaches the panel, because the
    /// counters have no per-object data in them to begin with. This test pins
    /// the rendered surface; the structural guarantee is `PeerMetrics`'s shape.
    #[test]
    fn the_panel_shows_no_per_object_provenance_or_timestamps() {
        let m = metrics();
        let c = coverage();
        let t = table();
        let row = Row {
            peer: "q3m9",
            metrics: &m,
            coverage: &c,
            link: t.get("q3m9"),
            quota_bytes: 10_000_000,
        };
        let text = row.render();
        for leak in ["object ", "arrived at", "T00:", "id=", "20260"] {
            assert!(!text.contains(leak), "{text:?} leaks {leak:?}");
        }
    }

    #[test]
    fn quota_use_is_a_percentage_of_the_quota() {
        let m = metrics();
        let c = coverage();
        let row = Row {
            peer: "x",
            metrics: &m,
            coverage: &c,
            link: None,
            quota_bytes: 10_000_000,
        };
        assert!((row.quota_used() - 50.0).abs() < 0.01);

        // A zero quota must not divide by zero.
        let row0 = Row {
            quota_bytes: 0,
            ..row
        };
        assert_eq!(row0.quota_used(), 0.0);
    }

    #[test]
    fn an_empty_panel_says_what_to_do_next() {
        let text = render(&[], DISCONNECT_KEY);
        assert!(text.contains("peer offer"), "{text}");
    }

    /// A peer with no link renders rather than panicking — the usual state
    /// after a disconnect, and the panel is where reconnecting starts.
    #[test]
    fn a_peer_with_no_link_still_renders() {
        let m = metrics();
        let c = coverage();
        let row = Row {
            peer: "gone",
            metrics: &m,
            coverage: &c,
            link: None,
            quota_bytes: 1_000,
        };
        assert!(row.render().contains("no link"));
    }

    #[test]
    fn transport_state_appears_in_the_row() {
        let mut t = table();
        t.disconnect("q3m9");
        let m = metrics();
        let c = coverage();
        let row = Row {
            peer: "q3m9",
            metrics: &m,
            coverage: &c,
            link: t.get("q3m9"),
            quota_bytes: 1_000,
        };
        assert!(row.render().contains(&Transport::Down.to_string()));
    }
}
