//! Operator warnings, RFC 0 §8.2 and RFC 8 §9.2.
//!
//! Operators choose peers by hand and will not know any of the thresholds.

use crate::metrics::Coverage;

/// The node's dominant transport mix, which sets the thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMix {
    /// Mostly IP or Tor.
    IpConnected,
    /// Mixed.
    Mixed,
    /// Courier- or radio-dominated.
    Austere,
}

impl TransportMix {
    /// Minimum peers for this mix.
    ///
    /// # Three documents, three tables
    ///
    /// `RFC-8-review.md` §2 found RFC 0 §8.2, RFC 3 §13 and RFC 8 §9.2 giving
    /// different numbers, and RFC 8 is the one that renders a warning:
    ///
    /// ```text
    ///                 IP      mixed   austere
    ///   RFC 0 §8.2    6-8     8       12+
    ///   RFC 3 §13     8-20    12-20   12-25
    ///   RFC 8 §9.2    6-8     8-12    12+
    /// ```
    ///
    /// These take **RFC 3 §13's**, the most conservative, because SIM-1 §3
    /// postdates RFC 0 §8.2 and found degree 12 is what closes the holdings
    /// leak under austere transport — an argument RFC 0 §8.2 predates and
    /// RFC 8 §9.2 declines to make. Warning too eagerly costs an operator a
    /// message; warning too late costs them the property.
    ///
    /// This should collapse to one table in one document.
    pub fn min_peers(&self) -> usize {
        match self {
            TransportMix::IpConnected => 8,
            TransportMix::Mixed => 12,
            TransportMix::Austere => 12,
        }
    }

    /// Minimum TTL in days (SIM-0 §4).
    pub fn min_ttl_days(&self) -> u32 {
        match self {
            TransportMix::IpConnected => 7,
            TransportMix::Mixed => 14,
            TransportMix::Austere => 30,
        }
    }
}

/// Upper bound on peers for a constrained link (RFC 3 §8.1).
///
/// Nodelist propagation is O(P²): at 50 peers a full fragment costs about 58
/// LoRa reconciliations, roughly two weeks of airtime for one publication.
pub const MAX_PEERS_CONSTRAINED: usize = 25;

/// Something the operator needs to be told.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Warning {
    /// Below the peer threshold for this transport mix.
    ///
    /// **This is a privacy warning, not an availability one.** SIM-1 §3
    /// measured an origin attack from holdings and cleartext object age
    /// putting the true sender in the top 10 of 500 for **12.45%** of messages
    /// at degree 8 under austere transport — 6.2× chance — against **3.40%**
    /// at degree 12. Under-provisioning is measurably deanonymising, and the
    /// warning text must say so rather than citing delivery.
    PeerCountLow {
        /// Peers currently held.
        have: usize,
        /// Minimum for the measured mix.
        want: usize,
        /// The mix that set the threshold.
        mix: TransportMix,
    },
    /// Above the constrained-link ceiling; nodelist propagation is O(P²).
    PeerCountHighForConstrainedLink {
        /// Peers currently held.
        have: usize,
    },
    /// TTL below the minimum for this mix (SIM-0 §4).
    TtlLow {
        /// Configured TTL, days.
        have: u32,
        /// Minimum for the mix.
        want: u32,
    },
    /// Coverage is a steep ramp rather than flat, so possession is evidence.
    CoverageRamped {
        /// Fraction of the youngest age bucket held.
        youngest: f64,
        /// The misleading aggregate.
        mean: f64,
    },
    /// A link admits so little of the traffic distribution that it is inert.
    ///
    /// The SIM-0 audit found a 512-byte gate against a 500-byte floor
    /// admitting **0.16%** of objects in the simulator, and **0%** under RFC 1's
    /// real encoding — LoRa was not slow, it was absent, for five sweeps.
    LinkEffectivelyInert {
        /// Peer this link reaches.
        peer: String,
        /// Fraction of recent objects the link admits.
        admitted: f64,
    },
}

impl TransportMix {
    /// How to name this mix to an operator.
    ///
    /// `Debug` leaked into operator text once — "the floor for a IpConnected
    /// deployment" — which is the shape of every enum that reaches an
    /// interface without being asked how it should read.
    pub fn describe(&self) -> &'static str {
        match self {
            TransportMix::IpConnected => "an IP-connected",
            TransportMix::Mixed => "a mixed",
            TransportMix::Austere => "a courier- or radio-dominated",
        }
    }
}

impl Warning {
    /// One line for an operator, saying what to do about it.
    ///
    /// **The reason this module had no callers.** It computed five warnings
    /// and rendered none, so wiring it into an interface meant writing the
    /// prose there — which is where the reasoning stops travelling with
    /// the threshold it came from. RFC 3 §13: "operators choose peers by
    /// hand and will not know any of this."
    pub fn line(&self) -> String {
        match self {
            Warning::PeerCountLow { have, want, mix } => format!(
                "only {have} peer(s); {want} is the floor for {} deployment. A privacy warning before an availability one — SIM-1 §3 measures holdings-based identification getting sharply worse below it.",
                mix.describe()
            ),
            Warning::PeerCountHighForConstrainedLink { have } => format!(
                "{have} peers on a constrained link. RFC 3 §8.1 makes nodelist cost O(P²) — at fifty peers one publication is about 58 LoRa reconciliations."
            ),
            Warning::TtlLow { have, want } => format!(
                "objects get {have} day(s) to arrive and this deployment needs {want}. Mail will expire in transit, silently, because RFC 0 §6 makes delivery failure silent by design."
            ),
            Warning::CoverageRamped { youngest, mean } => format!(
                "coverage is a ramp, not a level: {:.0}% of the youngest objects against {:.0}% overall. Propagation is not completing within TTL, so holding a young object identifies you — SIM-1 §2's 37% headline concealed exactly this.",
                youngest * 100.0,
                mean * 100.0
            ),
            Warning::LinkEffectivelyInert { .. } => "a link cannot carry what its filter admits — it is configured to move nothing. Widen the filter, or accept that this peer is unreachable.".into(),
        }
    }
}

/// Evaluate the operator warnings for a node.
pub fn evaluate(
    peers: usize,
    mix: TransportMix,
    ttl_days: u32,
    coverage: Coverage,
    has_constrained_link: bool,
) -> Vec<Warning> {
    let mut out = Vec::new();
    let want = mix.min_peers();
    if peers < want {
        out.push(Warning::PeerCountLow {
            have: peers,
            want,
            mix,
        });
    }
    if has_constrained_link && peers > MAX_PEERS_CONSTRAINED {
        out.push(Warning::PeerCountHighForConstrainedLink { have: peers });
    }
    if ttl_days < mix.min_ttl_days() {
        out.push(Warning::TtlLow {
            have: ttl_days,
            want: mix.min_ttl_days(),
        });
    }
    if coverage.is_ramped() {
        out.push(Warning::CoverageRamped {
            youngest: coverage.youngest(),
            mean: coverage.mean(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flat() -> Coverage {
        Coverage { by_age: [0.97; 8] }
    }

    #[test]
    fn a_well_provisioned_node_is_quiet() {
        assert!(evaluate(12, TransportMix::Mixed, 14, flat(), false).is_empty());
    }

    /// SIM-0 §5 — degree 4 is a cliff even on good transport.
    #[test]
    fn warns_below_the_threshold_for_the_actual_mix() {
        let w = evaluate(4, TransportMix::IpConnected, 7, flat(), false);
        assert_eq!(
            w,
            vec![Warning::PeerCountLow {
                have: 4,
                want: 8,
                mix: TransportMix::IpConnected
            }]
        );
        // Austere needs more, so 8 peers is fine on IP and not on austere.
        assert!(evaluate(8, TransportMix::IpConnected, 7, flat(), false).is_empty());
        assert!(!evaluate(8, TransportMix::Austere, 30, flat(), false).is_empty());
    }

    /// RFC 3 §8.1 — nodelist propagation is O(P²).
    #[test]
    fn warns_above_the_constrained_ceiling_only_on_constrained_links() {
        assert!(evaluate(50, TransportMix::Mixed, 14, flat(), false)
            .iter()
            .all(|w| !matches!(w, Warning::PeerCountHighForConstrainedLink { .. })));
        assert!(evaluate(50, TransportMix::Mixed, 14, flat(), true)
            .iter()
            .any(|w| matches!(w, Warning::PeerCountHighForConstrainedLink { .. })));
    }

    /// SIM-0 §4 — TTL is decisive under austere transport and irrelevant on IP.
    #[test]
    fn ttl_threshold_follows_the_mix() {
        assert!(evaluate(12, TransportMix::IpConnected, 7, flat(), false).is_empty());
        assert!(evaluate(12, TransportMix::Austere, 14, flat(), false)
            .iter()
            .any(|w| matches!(w, Warning::TtlLow { want: 30, .. })));
    }

    /// SIM-1 §2 — the ramp is the warning, not the aggregate.
    #[test]
    fn warns_on_a_ramped_coverage_profile() {
        let austere = Coverage {
            by_age: [0.03, 0.06, 0.12, 0.26, 0.41, 0.56, 0.71, 0.82],
        };
        let w = evaluate(12, TransportMix::Austere, 30, austere, false);
        match w
            .iter()
            .find(|w| matches!(w, Warning::CoverageRamped { .. }))
        {
            Some(Warning::CoverageRamped { youngest, mean }) => {
                assert_eq!(*youngest, 0.03);
                assert!((mean - 0.37).abs() < 0.02, "the headline the ramp conceals");
            }
            _ => panic!("a 3%-to-82% ramp must be surfaced"),
        }
    }
}
