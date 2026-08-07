//! Per-peer accountability metrics, RFC 3 §12 and RFC 5 §10.
//!
//! # Aggregates only, and it is the type that enforces it
//!
//! RFC 3 §12:
//!
//! > "Implementations MUST NOT retain per-object provenance: arrival
//! > timestamps and per-object attribution are a forensic reconstruction of
//! > the graph and its timing gradients, sitting on disk, waiting for seizure.
//! > Rolling counters lose nothing operationally."
//!
//! [`PeerMetrics`] therefore holds **counters and nothing else**. There is no
//! map keyed by object identifier, no timestamp vector, and no field an
//! object's provenance could be written into. Adding per-object attribution
//! would mean adding a field, which is a visible change rather than a quiet
//! one — the same discipline `Store::evict_to` uses for I-6 and `Scheduler`
//! uses for I-5.

/// Rolling counters for one peer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerMetrics {
    /// Bytes received in the window.
    pub ingress_bytes: u64,
    /// Objects received.
    pub objects_received: u64,
    /// Of those, how many were new.
    pub objects_new: u64,
    /// Objects that arrived from this peer and no other.
    pub unique_source: u64,
    /// Control-message bytes, for the overhead share.
    pub control_bytes: u64,
    /// Payload bytes.
    pub payload_bytes: u64,
    /// Objects whose tag matched but which failed to decrypt.
    pub tag_match_decrypt_fail: u64,
    /// Objects whose tag matched and which decrypted.
    pub tag_match_decrypt_ok: u64,
    /// Ingests refused, per RFC 1 §11.
    pub rejected: u64,
}

impl PeerMetrics {
    /// Fraction of received objects that were not already held.
    ///
    /// RFC 5 §10 calls this the key metric: **high volume at low novelty is
    /// misconfiguration or attack**. It is also the one signal that makes
    /// RFC 0 §5.4's censorship case visible — a relay dropping everything is
    /// possible, and shows up here.
    pub fn novelty_ratio(&self) -> Option<f64> {
        (self.objects_received > 0).then(|| self.objects_new as f64 / self.objects_received as f64)
    }

    /// Objects that arrived **only** via this peer.
    ///
    /// RFC 5 §10: the eclipse indicator, and invisible without it. A high
    /// value means cutting this peer partitions you, which is exactly what an
    /// eclipse attempt engineers.
    pub fn unique_source_ratio(&self) -> Option<f64> {
        (self.objects_received > 0)
            .then(|| self.unique_source as f64 / self.objects_received as f64)
    }

    /// Reconciliation bytes as a share of all bytes on this link.
    ///
    /// RFC 5 §10: **above 50% on a non-constrained link indicates
    /// misconfiguration.** On LoRa it is expected to be high — SIM-1 §1
    /// measured 68–83% even when correctly configured — which is why the
    /// threshold is conditioned on the link rather than absolute.
    pub fn overhead_share(&self) -> Option<f64> {
        let total = self.control_bytes + self.payload_bytes;
        (total > 0).then(|| self.control_bytes as f64 / total as f64)
    }

    /// Tag matches that failed to decrypt, as a share.
    ///
    /// RFC 1 §6.4 and RFC 2 §7.4: an adversary who learns a tag can flood
    /// objects bearing it, forcing decapsulation work for free. A high ratio
    /// here is unambiguous and SHOULD feed quota reduction.
    pub fn decrypt_failure_ratio(&self) -> Option<f64> {
        let total = self.tag_match_decrypt_fail + self.tag_match_decrypt_ok;
        (total > 0).then(|| self.tag_match_decrypt_fail as f64 / total as f64)
    }
}

/// Coverage as an **age profile**, not a scalar.
///
/// SIM-1 §2 found a single percentage actively misleading: under austere
/// transport a 37% aggregate concealed a **3%-to-82% ramp** across object age,
/// because propagation takes longer than TTL and a node holds a ramp rather
/// than a corpus. The mean describes no node's actual holding probability for
/// any object.
///
/// `RFC-8-review.md` §3 found RFC 8 §5.3 lists coverage among a dozen
/// aggregates without requiring the profile. This type makes the scalar
/// derived from the profile rather than the other way round, so the profile
/// cannot be dropped without removing the field it is computed from.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Coverage {
    /// Fraction held per age bucket, youngest first.
    pub by_age: [f64; 8],
}

impl Coverage {
    /// The aggregate, derived from the profile.
    pub fn mean(&self) -> f64 {
        self.by_age.iter().sum::<f64>() / self.by_age.len() as f64
    }

    /// The youngest bucket — where an object is most identifying.
    ///
    /// SIM-1 §3: holding probability is a steep function of age, and age is
    /// readable from the cleartext `expiry` field. A node holding a young
    /// object is one of few that do, which is what makes differential-holdings
    /// analysis work at all.
    pub fn youngest(&self) -> f64 {
        self.by_age[0]
    }

    /// Whether the profile is steep enough to be worth surfacing.
    ///
    /// A flat profile means propagation completes within TTL and RFC 0 §7.4's
    /// possession argument holds. A steep one means it does not.
    pub fn is_ramped(&self) -> bool {
        let oldest = self.by_age[self.by_age.len() - 1];
        oldest - self.youngest() > 0.25
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratios_are_none_before_any_traffic() {
        let m = PeerMetrics::default();
        assert_eq!(m.novelty_ratio(), None);
        assert_eq!(m.overhead_share(), None);
        assert_eq!(m.unique_source_ratio(), None);
        assert_eq!(m.decrypt_failure_ratio(), None);
    }

    /// RFC 5 §10 — high volume at low novelty is misconfiguration or attack.
    #[test]
    fn novelty_ratio_exposes_a_peer_sending_what_we_have() {
        let m = PeerMetrics {
            objects_received: 1_000,
            objects_new: 3,
            ..Default::default()
        };
        assert!(m.novelty_ratio().unwrap() < 0.01);
    }

    /// RFC 5 §10's eclipse indicator.
    #[test]
    fn unique_source_ratio_exposes_an_eclipse() {
        let m = PeerMetrics {
            objects_received: 500,
            unique_source: 480,
            ..Default::default()
        };
        assert!(
            m.unique_source_ratio().unwrap() > 0.9,
            "cutting this peer partitions us"
        );
    }

    /// SIM-1 §1 measured 68-83% overhead on a correctly configured LoRa link,
    /// so the 50% threshold is conditioned on the link, not absolute.
    #[test]
    fn overhead_share_is_high_on_lora_by_design() {
        let lora = PeerMetrics {
            control_bytes: 17_200,
            payload_bytes: 1_300,
            ..Default::default()
        };
        assert!(lora.overhead_share().unwrap() > 0.9);
        let tcp = PeerMetrics {
            control_bytes: 100,
            payload_bytes: 100_000,
            ..Default::default()
        };
        assert!(tcp.overhead_share().unwrap() < 0.5);
    }

    /// SIM-1 §2 — the scalar conceals the ramp, so it is derived from it.
    #[test]
    fn coverage_scalar_is_derived_from_the_profile() {
        // SIM-1 §2's measured austere profile.
        let austere = Coverage {
            by_age: [0.03, 0.06, 0.12, 0.26, 0.41, 0.56, 0.71, 0.82],
        };
        assert!((austere.mean() - 0.37).abs() < 0.02, "the 37% headline");
        assert_eq!(austere.youngest(), 0.03, "and what it conceals");
        assert!(
            austere.is_ramped(),
            "propagation does not complete within TTL"
        );

        // SIM-1 §2's mixed profile: flat after the youngest bucket.
        let mixed = Coverage {
            by_age: [0.76, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0],
        };
        assert!(!mixed.is_ramped(), "possession implies nothing here");
        assert!(mixed.mean() > 0.95);
    }
}
