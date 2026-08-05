//! Sync loop and per-peer metrics (RFC 5).

/// Per-peer accounting, surfaced in the client's `peers` panel (RFC 8).
#[derive(Debug, Default, Clone)]
pub struct PeerMetrics {
    /// Bytes received from this peer.
    pub ingress_bytes: u64,
    /// Fraction of received objects that were new. A peer whose novelty ratio
    /// collapses is dropping traffic, which is how the one censorship attack
    /// available to a relay becomes visible (RFC 0 §5.4).
    pub novelty_ratio: f64,
    /// Duplicate arrivals.
    pub duplicates: u64,
    /// Objects for which this peer was the only source.
    pub unique_contribution: u64,
}

/// Warning conditions the client MUST surface (RFC 0 §8.2, SIM-0 §5).
///
/// Operators choose peers by hand and will not know these thresholds.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Warning {
    /// Peer count is below the minimum for the node's actual transport mix.
    /// SIM-0 §5: 6–8 peers on IP transport, 12+ where courier or radio
    /// dominates. Degree 4 is a cliff even on good transport.
    PeerCountLow {
        /// Current peer count.
        have: usize,
        /// Minimum for the measured transport mix.
        want: usize,
    },
    /// TTL is below the minimum for the node's actual transport mix.
    /// SIM-0 §4: 7 d on IP, 14 d mixed, 21–30 d courier- or radio-dominated.
    TtlLow {
        /// Configured TTL, days.
        have: u64,
        /// Minimum for the measured transport mix, days.
        want: u64,
    },
    /// Coverage has fallen into the regime where possession becomes evidence
    /// (RFC 0 §7.4). Report the age profile, not only the scalar: the SIM-0
    /// audit found a 37% aggregate concealing a 3%–82% ramp across object age.
    CoverageWeak {
        /// Coverage by age bucket, youngest first.
        by_age: Vec<f64>,
    },
    /// A link's size gate admits so little of the traffic distribution that it
    /// is effectively inert. See the SIM-0 audit: a 512 B gate against a
    /// 500 B–8 KB distribution admitted 0.16% of objects.
    LinkEffectivelyInert {
        /// Peer this link reaches.
        peer: String,
        /// Fraction of recent objects the link admits.
        admitted_fraction: f64,
    },
    /// A link cannot sustain flood replication at the current network size,
    /// regardless of object size. Its useful role is targeted traffic under a
    /// narrow filter.
    LinkCannotFlood {
        /// Peer this link reaches.
        peer: String,
        /// Sustained capacity, bytes/day.
        capacity: f64,
        /// Required ingress at current network size, bytes/day.
        required: f64,
    },
}
