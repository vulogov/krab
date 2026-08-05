//! RFC 4 transport arithmetic: Noise handshake, framing, LoRa, serial, courier.
//!
//! # Two senses of "airtime"
//!
//! RFC 4's fragmentation tables report duty-cycle-limited *elapsed* time — 8
//! fragments at SF10 is 4.9 s of transmission but 8.2 minutes of wall clock at
//! a 1% duty cycle. Its `krab-sizes/transport` output reports the handshake in
//! raw transmission time instead (1.50 s), while §4.1's prose calls the same
//! handshake "approximately 3 minutes of airtime", which is the elapsed
//! figure. Both quantities are computed here and named distinctly.

/// Noise IK message sizes, RFC 4 §4.1.
pub const NOISE_MSG1: usize = 96;
pub const NOISE_MSG2: usize = 48;
pub const NOISE_HANDSHAKE: usize = NOISE_MSG1 + NOISE_MSG2;

/// Length prefix plus Noise transport tag, RFC 4 §4.2.
pub const FRAME_OVERHEAD: usize = 4 + 16;
/// Maximum Noise transport message, including its tag.
pub const NOISE_MAX_FRAME: usize = 65_535;

/// Fragment header on a constrained link, RFC 4 §5.4.
pub const FRAG_HEADER: usize = 6;
/// RaptorQ repair overhead, RFC 4 §5.4.
pub const FEC_OVERHEAD: f64 = 0.20;

/// One LoRa spreading-factor configuration, EU868 / 125 kHz / CR 4/5.
#[derive(Clone, Copy)]
pub struct Lora {
    pub sf: u8,
    pub payload: usize,
    /// Time on air for a full payload, milliseconds.
    pub toa_ms: f64,
    /// Regulatory duty cycle as a fraction.
    pub duty: f64,
}

pub const LORA: [Lora; 6] = [
    Lora { sf: 7, payload: 222, toa_ms: 348.4, duty: 0.01 },
    Lora { sf: 8, payload: 222, toa_ms: 614.9, duty: 0.01 },
    Lora { sf: 9, payload: 115, toa_ms: 615.4, duty: 0.01 },
    Lora { sf: 10, payload: 51, toa_ms: 616.4, duty: 0.01 },
    Lora { sf: 11, payload: 51, toa_ms: 1_314.8, duty: 0.01 },
    Lora { sf: 12, payload: 51, toa_ms: 2_465.8, duty: 0.01 },
];

impl Lora {
    /// Sustained throughput after duty-cycle derating, bytes/second.
    pub fn sustained_bps(&self) -> f64 {
        self.payload as f64 / (self.toa_ms / 1000.0 / self.duty)
    }
    pub fn mb_day(&self) -> f64 {
        self.sustained_bps() * 86_400.0 / 1e6
    }
    /// Fragments needed for `bytes`, before repair symbols.
    pub fn fragments(&self, bytes: usize) -> usize {
        bytes.div_ceil(self.payload - FRAG_HEADER)
    }
    /// Fragments including RaptorQ repair.
    pub fn fragments_fec(&self, bytes: usize) -> usize {
        (self.fragments(bytes) as f64 * (1.0 + FEC_OVERHEAD)).ceil() as usize
    }
    /// Wall-clock seconds to move `bytes`, duty cycle included. This is what
    /// RFC 4's fragmentation tables report.
    pub fn elapsed_s(&self, bytes: usize) -> f64 {
        self.fragments_fec(bytes) as f64 * self.toa_ms / 1000.0 / self.duty
    }
    /// Seconds actually transmitting, duty cycle excluded.
    pub fn transmit_s(&self, bytes: usize) -> f64 {
        self.fragments_fec(bytes) as f64 * self.toa_ms / 1000.0
    }
}

/// Frames needed to carry `bytes` under RFC 4 §4.2's framing.
pub fn frames(bytes: usize) -> usize {
    bytes.div_ceil(NOISE_MAX_FRAME - FRAME_OVERHEAD + 16)
}

/// Total framing overhead for `bytes`.
pub fn framing_overhead(bytes: usize) -> usize {
    frames(bytes) * FRAME_OVERHEAD
}

/// Hours to move `bytes` over a serial link at `baud` (8N1: 10 bits/byte).
pub fn serial_hours(bytes: usize, baud: u32) -> f64 {
    bytes as f64 / (baud as f64 / 10.0) / 3600.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(got: f64, want: f64, rel: f64) -> bool {
        (got - want).abs() / want.abs() < rel
    }

    #[test]
    fn noise_handshake_matches_rfc4() {
        assert_eq!(NOISE_MSG1, 96);
        assert_eq!(NOISE_MSG2, 48);
        assert_eq!(NOISE_HANDSHAKE, 144);
    }

    /// RFC 4 §4.2's framing table.
    #[test]
    fn framing_table_matches_rfc4() {
        for (bucket, f, over, pct) in [
            (256usize, 1usize, 20usize, 7.81f64),
            (1_024, 1, 20, 1.95),
            (4_096, 1, 20, 0.488),
            (16_384, 1, 20, 0.122),
            (65_536, 2, 40, 0.061),
            (262_144, 5, 100, 0.038),
        ] {
            assert_eq!(frames(bucket), f, "frames for {bucket}");
            assert_eq!(framing_overhead(bucket), over, "overhead for {bucket}");
            assert!(close(100.0 * over as f64 / bucket as f64, pct, 0.01), "pct for {bucket}");
        }
    }

    /// RFC 4 §5.4's LoRa table.
    #[test]
    fn lora_table_matches_rfc4() {
        for (i, (bps, mb)) in [
            (6.37f64, 0.5505f64),
            (3.61, 0.3119),
            (1.87, 0.1614),
            (0.83, 0.0715),
            (0.39, 0.0335),
            (0.21, 0.0179),
        ]
        .iter()
        .enumerate()
        {
            // RFC 4 gives sustained rates to two significant figures, so SF12's
            // 0.2068 prints as "0.21" — 1.5% off on its own.
            assert!(close(LORA[i].sustained_bps(), *bps, 0.02), "SF{}", LORA[i].sf);
            assert!(close(LORA[i].mb_day(), *mb, 0.01), "SF{} MB/day", LORA[i].sf);
        }
        // "SF7 is 7.7x faster than SF10".
        assert!(close(LORA[0].sustained_bps() / LORA[3].sustained_bps(), 7.7, 0.01));
    }

    /// RFC 4 §5.4's fragmentation table — the "airtime" column is elapsed
    /// wall-clock under the duty cycle, not transmission time.
    #[test]
    fn fragmentation_table_matches_rfc4() {
        let sf = |n: u8| LORA.iter().find(|l| l.sf == n).unwrap();
        // (bucket, SF, fragments, with FEC, elapsed)
        for (bucket, s, frag, fec, secs) in [
            (256usize, 7u8, 2usize, 3usize, 104.5f64),
            (256, 10, 6, 8, 493.1),
            (1_024, 7, 5, 6, 209.0),
            (1_024, 10, 23, 28, 1_725.9),
            (4_096, 7, 19, 23, 801.3),
            (4_096, 10, 92, 111, 6_842.0),
        ] {
            let l = sf(s);
            assert_eq!(l.fragments(bucket), frag, "{bucket}B SF{s} fragments");
            assert_eq!(l.fragments_fec(bucket), fec, "{bucket}B SF{s} with FEC");
            assert!(close(l.elapsed_s(bucket), secs, 0.01), "{bucket}B SF{s} elapsed");
        }
    }

    /// §4.1 calls the handshake "approximately 3 minutes of airtime" while
    /// RFC 4's computed output reports 1.50 s for the same handshake. The two
    /// differ by the duty cycle, and only the elapsed figure is what a link
    /// actually costs. Exact values depend on packetisation assumptions RFC 4
    /// does not state, so only the relationship is pinned here.
    #[test]
    fn handshake_has_two_defensible_durations() {
        let sf10 = LORA[3];
        let transmit = sf10.transmit_s(NOISE_HANDSHAKE);
        let elapsed = sf10.elapsed_s(NOISE_HANDSHAKE);
        assert!(close(elapsed / transmit, 1.0 / sf10.duty, 1e-9), "duty-cycle ratio");
        // §4.1's "approximately 3 minutes" is the right order for elapsed;
        // a raw-transmission figure of ~1.5 s is not what the link costs.
        assert!((1.0..6.0).contains(&(elapsed / 60.0)), "elapsed {:.1} min", elapsed / 60.0);
        assert!(transmit < 5.0, "transmit {transmit:.1} s");
    }

    /// RFC 4 §5.3's serial table.
    #[test]
    fn serial_table_matches_rfc4() {
        const CORPUS: usize = 447_000_000; // SIM-0 §2, n=500
        for (baud, hours) in [(9_600u32, 129.3f64), (19_200, 64.7), (57_600, 21.6), (115_200, 10.8)]
        {
            assert!(close(serial_hours(CORPUS, baud), hours, 0.01), "{baud} baud");
        }
    }

    /// RFC 4 §5.4 caps LoRa at bucket 1024 for SF7–SF10. That is tighter than
    /// `RFC-4-blocking-items.md` §1.3 proposed, and the reason is fragmentation
    /// plus FEC, which the gate document's simpler model omitted.
    #[test]
    fn fragmentation_overhead_explains_the_tighter_cap() {
        let sf10 = LORA[3];
        // A 1024-byte object costs 28 fragments of 51 bytes on the wire.
        let on_air = sf10.fragments_fec(1_024) * sf10.payload;
        assert_eq!(on_air, 1_428);
        // 39% more than the object itself, which the gate document ignored.
        assert!(close(on_air as f64 / 1_024.0, 1.39, 0.01));
        // So the daily object count is lower than the gate document computed.
        let budget = sf10.sustained_bps() * 86_400.0;
        let objects = budget / on_air as f64;
        assert!((50.0..53.0).contains(&objects), "{objects:.1} objects/day");
    }
}
