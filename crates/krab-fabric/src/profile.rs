//! Link profiles (RFC 4).

use krab_proto::recon::Mode;

/// Latency class, which selects reconciliation strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LatencyClass {
    /// Milliseconds to seconds.
    Interactive,
    /// Seconds to minutes.
    Delayed,
    /// Hours to days. Zero-round-trip algorithms only.
    Sneakernet,
}

/// Static description of what a link can carry.
#[derive(Debug, Clone)]
pub struct LinkProfile {
    /// Maximum transmission unit, bytes.
    pub mtu: u32,
    /// Sustained throughput, bits per second, after duty-cycle derating.
    pub sustained_bps: u32,
    /// Regulatory duty cycle, as a fraction. `1.0` where unrestricted.
    pub duty_cycle: f64,
    /// Latency class.
    pub latency_class: LatencyClass,
    /// Whether the carrier bills by byte.
    pub metered: bool,
    /// Per-link object size gate.
    ///
    /// # SIM-0 audit
    ///
    /// A size gate below the bulk of the traffic distribution does not slow a
    /// link, it disables it. SIM-0 paired a 512 B LoRa gate with a traffic
    /// model whose smallest object was 500 B and measured LoRa as a
    /// participating transport for five sweeps before anyone noticed it was
    /// carrying 0.16% of objects. `admitted_fraction` exists so this is
    /// visible rather than inferred.
    pub max_object_size: u32,
    /// Reconciliation strategy for this link.
    pub sync_mode: Mode,
    /// Whether text armor is applied (text-only carriers).
    pub armor: bool,
    /// Whether forward error correction is applied.
    pub fec: bool,
}

impl LinkProfile {
    /// Sustained bytes per day after duty-cycle derating.
    ///
    /// Compare against the flood ingress requirement before calling a link a
    /// corpus-replication transport. Per the SIM-0 audit an EU868 SF10 LoRa
    /// link sustains ~73 KB/day against a ~31 MB/day requirement at n=500 —
    /// about 2% of one peer-share, falling linearly as the network grows.
    /// Such a link can carry targeted traffic under a narrow filter; it
    /// cannot participate in flood replication at any object size.
    pub fn bytes_per_day(&self) -> f64 {
        self.sustained_bps as f64 * self.duty_cycle * 86_400.0 / 8.0
    }

    /// Whether this link can plausibly sustain flood replication given a
    /// required daily ingress. Advisory, and intended to drive a client
    /// warning rather than a silent policy decision.
    pub fn can_flood(&self, required_bytes_per_day: f64) -> bool {
        self.bytes_per_day() >= required_bytes_per_day
    }
}
