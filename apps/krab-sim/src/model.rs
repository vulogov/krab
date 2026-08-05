//! Simulation model: configuration, transports, objects, node state.

use crate::graph::Topology;

pub const HOUR: u64 = 3_600;
pub const DAY: u64 = 86_400;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkKind {
    Tcp,
    Lora,
    Courier,
}

impl LinkKind {
    pub fn name(&self) -> &'static str {
        match self {
            LinkKind::Tcp => "tcp",
            LinkKind::Lora => "lora",
            LinkKind::Courier => "courier",
        }
    }

    /// Mean interval between reconciliation attempts on this link.
    pub fn sync_mean(&self) -> f64 {
        match self {
            // Poisson-scheduled, deliberately not event-driven: sync timing
            // must not correlate with user activity or mail arrival.
            LinkKind::Tcp => (4 * HOUR) as f64,
            LinkKind::Lora => (6 * HOUR) as f64,
            // A courier journey. Weekly is optimistic for a real one.
            LinkKind::Courier => (7 * DAY) as f64,
        }
    }

    pub fn latency_s(&self) -> f64 {
        match self {
            // Tor circuit round trip dominates; direct IP would be far lower.
            LinkKind::Tcp => 3.0,
            LinkKind::Lora => 10.0,
            // Someone physically carries the media.
            LinkKind::Courier => (3 * DAY) as f64,
        }
    }

    /// Bytes movable per reconciliation.
    pub fn capacity_bytes(&self) -> u64 {
        match self {
            // Not the binding constraint at these volumes.
            LinkKind::Tcp => 1 << 30,
            // EU868 SF10 under a 1% duty cycle sustains order-of 1 B/s.
            // Over a 6h window that is ~21 KB. This is the number that
            // decides whether LoRa can carry anything useful at all.
            LinkKind::Lora => (0.85 * (6 * HOUR) as f64) as u64,
            // A USB stick. Effectively unbounded; latency is the cost.
            LinkKind::Courier => 64 << 30,
        }
    }

    /// Per-link object size gate. Objects above this never cross.
    pub fn max_object(&self) -> u32 {
        match self {
            LinkKind::Tcp => 512 * 1024,
            // Fragmentation is mandatory below this; anything larger is
            // filtered at the sender rather than wasting airtime.
            // Overridable via KRAB_LORA_GATE for the audit experiment that
            // asks what LoRa would carry if fragmentation were free.
            LinkKind::Lora => {
                static G: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
                *G.get_or_init(|| {
                    std::env::var("KRAB_LORA_GATE").ok().and_then(|v| v.parse().ok()).unwrap_or(512)
                })
            }
            LinkKind::Courier => 512 * 1024,
        }
    }
}

#[derive(Clone, Copy)]
pub struct Link {
    pub a: u32,
    pub b: u32,
    pub kind: LinkKind,
}

#[derive(Clone, Copy)]
pub struct Object {
    pub size: u32,
    pub created: u64,
    pub origin: u32,
    pub dest: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestModel {
    /// Recipient uniform over the whole network. Pessimistic: real traffic
    /// is not uniform, and uniform destinations require global convergence.
    Uniform,
    /// Recipient drawn from within `social_hops` of the sender. Closer to
    /// how a friend-to-friend network is actually used.
    Social,
}

#[derive(Clone)]
pub struct Config {
    pub topo: Topology,
    pub n: usize,
    pub degree: usize,
    pub rewire: f64,

    /// Fractions must sum to 1.0.
    pub mix_tcp: f64,
    pub mix_lora: f64,
    pub mix_courier: f64,

    pub ttl: u64,
    pub horizon: u64,

    /// Messages originated per node per day.
    pub rate_per_day: f64,
    pub dest: DestModel,
    pub social_hops: usize,

    /// Alternating renewal process for node availability. Courier links are
    /// unaffected: physical media does not require the node to be up.
    pub uptime: f64,
    pub mean_session_up: f64,

    pub seeds: u64,
    pub quiet: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            topo: Topology::WattsStrogatz,
            n: 500,
            degree: 8,
            rewire: 0.10,
            mix_tcp: 0.70,
            mix_lora: 0.15,
            mix_courier: 0.15,
            ttl: 14 * DAY,
            horizon: 42 * DAY,
            rate_per_day: 2.0,
            dest: DestModel::Social,
            social_hops: 3,
            uptime: 0.85,
            mean_session_up: (12 * HOUR) as f64,
            seeds: 5,
            quiet: false,
        }
    }
}

/// Fixed-width bitset over object indices. One per node: the node's corpus.
/// Reconciliation is `mine & !theirs` restricted to the live window, which is
/// a handful of word operations rather than a set difference over IDs.
#[derive(Clone)]
pub struct BitSet {
    pub w: Vec<u64>,
}

impl BitSet {
    pub fn new(bits: usize) -> BitSet {
        BitSet { w: vec![0u64; (bits + 63) / 64] }
    }
    #[inline]
    pub fn set(&mut self, i: usize) {
        self.w[i >> 6] |= 1u64 << (i & 63);
    }
    #[inline]
    pub fn get(&self, i: usize) -> bool {
        self.w[i >> 6] >> (i & 63) & 1 == 1
    }
    /// Population count over a word range.
    pub fn count_range(&self, lo_word: usize, hi_word: usize) -> u64 {
        self.w[lo_word..hi_word].iter().map(|x| x.count_ones() as u64).sum()
    }
}
