//! Poisson sync scheduler (I-5).
//!
//! All peers are visited on a Poisson schedule with randomised order and
//! interval. There is deliberately no way to trigger a sync from user
//! activity: RFC 0 §5.3's intersection attack works precisely by correlating
//! eager syncing with having mail, and no decryption is needed to run it.

/// Schedules reconciliation attempts without reference to user activity.
#[derive(Debug)]
pub struct Scheduler {
    /// Mean interval between attempts per link, seconds.
    pub mean_interval: u64,
}

impl Scheduler {
    /// Next attempt time for a link, drawn from an exponential distribution.
    ///
    /// `now` and `entropy` are arguments rather than ambient reads, so the
    /// scheduler is replayable under the simulator and the fuzzer.
    pub fn next_attempt(&self, now: u64, entropy: u64) -> u64 {
        // Exponential inverse-CDF over a uniform drawn from `entropy`.
        let u = (entropy >> 11) as f64 / (1u64 << 53) as f64;
        let u = if u <= 0.0 { f64::MIN_POSITIVE } else { u };
        now + (-(u.ln()) * self.mean_interval as f64) as u64
    }
}
