//! `LinkProfile`, RFC 4 §3.
//!
//! Every transport-specific decision is data, not code.

use krab_proto::recon::Mode;

/// RFC 4 §3. Selects the reconciliation strategy, and RFC 5 §4.1 makes the
/// mapping normative rather than a preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LatencyClass {
    /// Milliseconds to seconds. IP, Tor.
    Interactive,
    /// Seconds to minutes. Serial, LoRa.
    Batch,
    /// Hours to days. Exactly one round trip is available.
    Courier,
}

impl LatencyClass {
    /// The reconciliation strategy this class requires.
    ///
    /// SIM-1 §1 measured both failure modes, and neither is a degradation:
    /// a full manifest **starves 98.3%** of LoRa reconciliations, and RBSR
    /// **collapses austere delivery from 95.8% to 33.0%** because four descent
    /// levels cost four courier round trips of three days each.
    ///
    /// So this is a function, not a setting. `RFC-4-review.md` §1 found that
    /// RFC 4 §3 places `sync_mode` and `latency_class` on the *local* side of
    /// the credential line, which cannot hold: reconciliation is two-party, and
    /// if one end runs `Manifest` while the other runs `Rbsr` they do not
    /// reconcile at all. Deriving the mode removes half the disagreement;
    /// carrying `latency_class` in the signed credential removes the rest, and
    /// that is a change RFC 3 §3 key 9 still needs.
    pub fn sync_mode(&self) -> Mode {
        match self {
            LatencyClass::Interactive | LatencyClass::Batch => Mode::Rbsr,
            LatencyClass::Courier => Mode::Manifest,
        }
    }
}

/// Size buckets a link admits, RFC 4 §3.
///
/// **A bucket index, never a byte count.** RFC 4 §3: "a byte gate that falls
/// between buckets — 512 bytes, say — admits nothing above the 256-byte bucket
/// while appearing to admit more." Expressing it as an index makes that class
/// of error unrepresentable, and it is exactly the error the SIM-0 audit found
/// in the simulator's own LoRa model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxBucket(pub u8);

impl MaxBucket {
    /// Largest object size this link admits, bytes.
    pub fn bytes(&self) -> u32 {
        krab_core::object::BUCKETS[(self.0 as usize).min(krab_core::object::BUCKETS.len() - 1)]
    }
    /// Whether an object of `size_bucket` crosses.
    pub fn admits(&self, size_bucket: u8) -> bool {
        size_bucket <= self.0
    }
}

/// Static description of what a link can carry, RFC 4 §3.
#[derive(Debug, Clone)]
pub struct LinkProfile {
    /// Human-facing transport name.
    pub kind: &'static str,
    /// Sustained throughput after duty-cycle derating, bytes/second.
    pub sustained_bps: f64,
    /// Regulatory duty cycle as a fraction; `1.0` where unrestricted.
    pub duty_cycle: f64,
    /// Selects `sync_mode`.
    pub latency_class: LatencyClass,
    /// Whether the carrier bills by byte.
    pub metered: bool,
    /// Largest bucket admitted.
    pub max_bucket: MaxBucket,
    /// Shard width, RFC 2 §6. `0` means no sharding.
    pub shard_k: u8,
    /// Object classes admitted, by class byte.
    pub class_mask: u16,
    /// Text-only carriers need armor; it sits outside the identifier (RFC 1 §3).
    pub armor: bool,
    /// Forward error correction; likewise outside the identifier.
    pub fec: bool,
}

impl LinkProfile {
    /// The strategy this link must use.
    pub fn sync_mode(&self) -> Mode {
        self.latency_class.sync_mode()
    }

    /// Sustained bytes per day.
    pub fn bytes_per_day(&self) -> f64 {
        self.sustained_bps * 86_400.0
    }

    /// Whether this link can sustain flood replication at a required ingress.
    ///
    /// RFC 4 §5.4 and SIM-1 §1: a LoRa link supplies about **2% of one
    /// peer-share** at n=500 and falls linearly with network size. A profile
    /// that cannot flood is not broken — it is a targeted-traffic link, and it
    /// must carry a narrow `shard_k` and `class_mask` or it is misconfigured by
    /// construction.
    pub fn can_flood(&self, required_bytes_per_day: f64) -> bool {
        self.bytes_per_day() >= required_bytes_per_day
    }

    /// **RFC 8 §9 — whether this link provides LOCATION privacy.**
    ///
    /// A transport property, per RFC 4 §10: a Tor link with restricted
    /// discovery has it, plain IP does not. A courier has it in the sense
    /// that matters — there is no network observation of where the operator
    /// is — and so does a directly-wired serial line, which reveals a
    /// location only to someone already standing at it.
    ///
    /// LoRa does not: a transmission is direction-findable, which is a
    /// physical-layer property no protocol can undo (RFC 4 §11).
    pub fn location_privacy(&self) -> bool {
        matches!(self.kind, "socks" | "tor" | "courier" | "serial")
    }

    /// **RFC 8 §9 — whether this link provides VOLUME privacy.**
    ///
    /// RFC 0 §7.3: volume privacy requires cover traffic, and cover traffic
    /// is unaffordable on a constrained link. So this is not a property a
    /// deployment chooses — some links structurally cannot have it.
    ///
    /// A courier has it trivially: an observer sees a person, not a byte
    /// count per correspondent. A metered or duty-cycled link cannot afford
    /// the cover that would provide it.
    pub fn volume_privacy(&self) -> bool {
        if self.kind == "courier" {
            return true;
        }
        // Cover traffic has to be affordable to exist. A duty cycle below one
        // is a regulatory ceiling on airtime, and a metered link bills it.
        !self.metered && self.duty_cycle >= 1.0
    }

    /// A plain TCP link. RFC 4 §5.1.
    pub fn tcp() -> LinkProfile {
        LinkProfile {
            kind: "tcp",
            sustained_bps: 1_000_000.0,
            duty_cycle: 1.0,
            latency_class: LatencyClass::Interactive,
            metered: false,
            max_bucket: MaxBucket(5),
            shard_k: 0,
            class_mask: u16::MAX,
            armor: false,
            fec: false,
        }
    }

    /// A serial line at 115 200 baud — RFC 4 §5.3.
    ///
    /// "A direct cable, a wired radio modem, or an X.25 PAD are all serviceable
    /// links, and serial is the natural carrier for a physically isolated but
    /// co-located pair." 11 520 B/s moves §5.3's 447 MB corpus in about
    /// eleven hours.
    ///
    /// `Batch` rather than `Interactive`, which still resolves to `Rbsr` — and
    /// that is right, though not for the reason it first appears.
    ///
    /// A serial line is **low bandwidth, not high latency**: a direct cable
    /// turns a round trip around in microseconds and moves 11 520 bytes a
    /// second. RBSR trades round trips for bytes by binary-searching the
    /// divergence, which is exactly the trade this carrier wants. `Manifest`
    /// would send the whole filtered set and is the right answer only where a
    /// round trip is measured in days, which is what `Courier` means.
    ///
    /// `Batch` rather than `Interactive` therefore records the throughput, not
    /// a different protocol: RFC 5 §4.5's mapping is by round-trip cost, and
    /// this carrier shares TCP's.
    ///
    /// `fec` is on. RFC 4 §5.3: "FEC SHOULD be enabled where there is no
    /// link-layer retransmission." A raw cable has none — a modem with V.42
    /// does, and an operator who knows they have it may turn this off.
    ///
    /// `armor` is off, because the common case is an 8-bit-clean line. §5.3
    /// requires it "where the carrier is text-only", which is an X.25 PAD or a
    /// radio link with a text-only modem, and is the operator's call.
    pub fn serial() -> LinkProfile {
        LinkProfile {
            kind: "serial",
            sustained_bps: 11_520.0,
            duty_cycle: 1.0,
            latency_class: LatencyClass::Batch,
            metered: false,
            max_bucket: MaxBucket(5),
            shard_k: 0,
            class_mask: u16::MAX,
            armor: false,
            fec: true,
        }
    }

    /// A courier. RFC 4 §5.5 — capacity never binds, human latency always does.
    pub fn courier() -> LinkProfile {
        LinkProfile {
            kind: "courier",
            sustained_bps: 1_000_000.0,
            duty_cycle: 1.0,
            latency_class: LatencyClass::Courier,
            metered: false,
            max_bucket: MaxBucket(5),
            shard_k: 0,
            class_mask: u16::MAX,
            armor: false,
            fec: false,
        }
    }

    /// EU868 SF10 at a 1% duty cycle. RFC 4 §5.4.
    ///
    /// `max_bucket` is **1**, not 5: RFC 4 §5.4 caps LoRa at the 1024-byte
    /// bucket for SF7–SF10, because a 4096-byte object costs 1.9 hours of
    /// airtime once fragmentation and RaptorQ repair are counted.
    pub fn lora_sf10() -> LinkProfile {
        LinkProfile {
            kind: "lora",
            sustained_bps: 0.83,
            duty_cycle: 0.01,
            latency_class: LatencyClass::Batch,
            metered: false,
            max_bucket: MaxBucket(1),
            shard_k: 5,
            class_mask: u16::MAX,
            armor: false,
            fec: true,
        }
    }
}

#[cfg(test)]
mod privacy_tests {
    use super::*;

    /// **RFC 8 §9 — two independent indicators, never averaged.**
    ///
    /// "A single 'secure' badge would average them into something false."
    /// The test that matters is that some link has one and not the other; if
    /// every profile agreed on both, one indicator would do and the RFC
    /// would not have asked for two.
    #[test]
    fn the_two_privacy_properties_are_independent() {
        let tcp = LinkProfile::tcp();
        let lora = LinkProfile::lora_sf10();
        let courier = LinkProfile::courier();

        // Plain TCP: an observer sees where you are, but the link can afford
        // cover traffic.
        assert!(!tcp.location_privacy(), "plain TCP hides location");
        assert!(tcp.volume_privacy(), "TCP cannot afford cover");

        // LoRa: direction-findable, and too constrained for cover. Neither.
        assert!(!lora.location_privacy());
        assert!(!lora.volume_privacy());

        // A courier: both, and for reasons no network property explains.
        assert!(courier.location_privacy());
        assert!(courier.volume_privacy());

        // The point of two indicators: at least one link differs on them.
        assert_ne!(
            tcp.location_privacy(),
            tcp.volume_privacy(),
            "if no profile ever differs, one badge would have done"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SIM-1 §1's measured requirement, as a function rather than a setting.
    #[test]
    fn sync_mode_is_derived_from_latency_class() {
        assert_eq!(LatencyClass::Interactive.sync_mode(), Mode::Rbsr);
        assert_eq!(LatencyClass::Batch.sync_mode(), Mode::Rbsr);
        // A courier exchange has exactly one round trip available.
        assert_eq!(LatencyClass::Courier.sync_mode(), Mode::Manifest);
        assert_eq!(LinkProfile::courier().sync_mode(), Mode::Manifest);
        assert_eq!(LinkProfile::lora_sf10().sync_mode(), Mode::Rbsr);
    }

    /// RFC 4 §3 — a byte gate falling between buckets admits nothing above the
    /// bucket below it, while appearing to admit more. An index cannot.
    #[test]
    fn max_bucket_is_an_index_so_a_between_buckets_gate_is_unrepresentable() {
        let lora = LinkProfile::lora_sf10();
        assert_eq!(
            lora.max_bucket.bytes(),
            1_024,
            "RFC 4 §5.4 caps SF7-SF10 here"
        );
        assert!(lora.max_bucket.admits(0), "256-byte objects cross");
        assert!(lora.max_bucket.admits(1), "1024-byte objects cross");
        assert!(!lora.max_bucket.admits(2), "4096-byte objects do not");
    }

    /// RFC 4 §5.4 and SIM-1 §1 from a different direction.
    #[test]
    fn lora_cannot_flood_at_any_realistic_network_size() {
        let lora = LinkProfile::lora_sf10();
        // 0.83 B/s sustained is ~72 KB/day.
        assert!((71_000.0..73_000.0).contains(&lora.bytes_per_day()));
        // SIM-0 §2 measured 31 MB/day of ingress at n=500.
        assert!(!lora.can_flood(31_000_000.0));
        assert!(LinkProfile::tcp().can_flood(31_000_000.0));
    }
}
