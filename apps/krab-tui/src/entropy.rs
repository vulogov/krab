//! The operating system's generator.
//!
//! `krab-crypto` takes randomness as an argument and has no platform
//! dependency (see `krab_crypto::rng`), so **this file is the only place in
//! the workspace that names an entropy source**. Every key the node ever holds
//! traces back through here.
//!
//! That concentration is the point. "Where does this key's entropy come from?"
//! has exactly one answer, checkable by reading one screen, rather than an
//! answer per call site that has to be re-established at every review.

use krab_crypto::rng::Rng;

/// `getrandom`, which is the platform CSPRNG: `getrandom(2)` on Linux,
/// `getentropy(2)` on macOS and the BSDs, `BCryptGenRandom` on Windows.
pub struct OsRng;

impl Rng for OsRng {
    /// # Panics
    ///
    /// If the platform generator fails.
    ///
    /// This is deliberate, and it is the one place in the TUI where a panic is
    /// the correct response. A failure here means the OS could not produce
    /// entropy; the alternatives are to continue with a degraded source, which
    /// silently produces guessable keys that look identical to good ones, or to
    /// surface an error the caller may ignore. Neither is acceptable for
    /// material that protects everything else.
    ///
    /// RFC 7 §9's `panic = "abort"` then applies, so no core dump follows —
    /// and `install_panic_hook` in `main.rs` restores the terminal first, so
    /// the operator sees the message rather than a wedged shell.
    fn fill(&mut self, out: &mut [u8]) {
        getrandom::getrandom(out).expect("the operating system could not provide entropy");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_os_generator_produces_distinct_nonzero_values() {
        let mut r = OsRng;
        let a = r.next_32();
        let b = r.next_32();
        assert_ne!(a, b, "two draws must not coincide");
        assert_ne!(a, [0u8; 32]);
    }

    /// A generator that fails to fill part of its output would leave stale or
    /// zero bytes in a key, which is the failure that looks like success.
    #[test]
    fn every_byte_of_a_large_draw_gets_written() {
        let mut r = OsRng;
        let mut buf = [0u8; 4096];
        r.fill(&mut buf);
        let zeros = buf.iter().filter(|&&b| b == 0).count();
        // ~16 expected in 4 KiB; 200 would mean a large unwritten region.
        assert!(
            zeros < 200,
            "{zeros} zero bytes suggests an unfilled buffer"
        );
    }
}
