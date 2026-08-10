//! Randomness, as an argument.
//!
//! `krab-core` is zero-dependency so that "no I/O, no clock, no ambient
//! randomness" is enforced by the compiler rather than by review. This crate
//! needs randomness — key generation is not a pure function — but it keeps the
//! same posture one level up: **nothing here reaches for an entropy source.**
//! A caller passes one in.
//!
//! This is the shape `Scheduler::due(now, entropy)` already uses (RFC 0 I-5),
//! and it buys the same three things:
//!
//! - Every keygen path is reproducible under test with a fixed generator, so
//!   the wire formats have stable vectors (RFC 1 §12).
//! - The audit question "where does this key's entropy come from?" has one
//!   answer per binary rather than one per call site.
//! - The crate stays `no_std` with no `getrandom`, so nothing downstream of
//!   `krab-core` acquires a platform dependency.
//!
//! The OS generator lives in the application crate, which is the only part of
//! the system that has an OS.

/// A source of cryptographically secure random bytes.
///
/// # Implementor's obligation
///
/// This trait cannot enforce its own security property, and the type system
/// will not save an implementor who gets it wrong. An implementation MUST draw
/// from a cryptographically secure generator seeded by the operating system.
///
/// The failure is silent and total: keys from a weak generator are guessable,
/// every downstream property fails at once, and nothing observable changes.
/// RFC 7 §6.2's `reservoir = R_A ⊕ R_B` exists precisely because one end's
/// generator may be backdoored — but that only covers the reservoir, and only
/// when the *other* end is sound.
pub trait Rng {
    /// Fill `out` entirely with random bytes.
    fn fill(&mut self, out: &mut [u8]);

    /// A fresh 32-byte secret.
    fn next_32(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        self.fill(&mut b);
        b
    }
}

/// A mutable borrow of a generator is a generator.
///
/// Needed so a `&mut dyn Rng` can be passed to anything taking `impl Rng` —
/// which is what a recursive walk needs, since recursing with a generic
/// closure re-instantiates the function at each reference depth without end.
impl<R: Rng + ?Sized> Rng for &mut R {
    fn fill(&mut self, out: &mut [u8]) {
        (**self).fill(out)
    }
}

/// A deterministic generator, for tests and for nothing else.
///
/// ChaCha8, seeded explicitly. It is exported rather than hidden behind
/// `#[cfg(test)]` because the simulator and the test-vector generator both
/// need reproducible keys, and a second copy of this would be worse.
///
/// # Never use this for real keys
///
/// The name is deliberately hostile. Every value it produces follows from the
/// seed, so a peering conducted with one is a peering with no secrets in it.
#[derive(Clone)]
pub struct NotRandom {
    state: [u32; 16],
    buf: [u8; 64],
    used: usize,
}

impl NotRandom {
    /// A generator fixed by `seed`.
    pub fn seeded(seed: u64) -> NotRandom {
        let mut state = [0u32; 16];
        // "expand 32-byte k"
        state[0] = 0x6170_7865;
        state[1] = 0x3320_646e;
        state[2] = 0x7962_2d32;
        state[3] = 0x6b20_6574;
        state[4] = seed as u32;
        state[5] = (seed >> 32) as u32;
        NotRandom {
            state,
            buf: [0; 64],
            used: 64,
        }
    }

    // The index is shared between the working state and the original state,
    // which is exactly what the ChaCha feed-forward step is.
    #[allow(clippy::needless_range_loop)]
    fn block(&mut self) {
        let mut x = self.state;
        for _ in 0..4 {
            quarter(&mut x, 0, 4, 8, 12);
            quarter(&mut x, 1, 5, 9, 13);
            quarter(&mut x, 2, 6, 10, 14);
            quarter(&mut x, 3, 7, 11, 15);
            quarter(&mut x, 0, 5, 10, 15);
            quarter(&mut x, 1, 6, 11, 12);
            quarter(&mut x, 2, 7, 8, 13);
            quarter(&mut x, 3, 4, 9, 14);
        }
        for i in 0..16 {
            let w = x[i].wrapping_add(self.state[i]);
            self.buf[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        self.state[12] = self.state[12].wrapping_add(1);
        if self.state[12] == 0 {
            self.state[13] = self.state[13].wrapping_add(1);
        }
        self.used = 0;
    }
}

fn quarter(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}

impl Rng for NotRandom {
    fn fill(&mut self, out: &mut [u8]) {
        for byte in out.iter_mut() {
            if self.used == 64 {
                self.block();
            }
            *byte = self.buf[self.used];
            self.used += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn the_test_generator_is_reproducible() {
        assert_eq!(
            NotRandom::seeded(7).next_32(),
            NotRandom::seeded(7).next_32()
        );
        assert_ne!(
            NotRandom::seeded(7).next_32(),
            NotRandom::seeded(8).next_32()
        );
    }

    #[test]
    fn it_does_not_repeat_within_a_stream() {
        let mut r = NotRandom::seeded(1);
        let (a, b, c) = (r.next_32(), r.next_32(), r.next_32());
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    /// Fills that straddle the 64-byte block boundary must be continuous --
    /// a generator that restarts or repeats at a block edge would silently
    /// produce correlated key material.
    #[test]
    fn output_is_continuous_across_block_boundaries() {
        let mut a = NotRandom::seeded(42);
        let mut whole = vec![0u8; 200];
        a.fill(&mut whole);

        let mut b = NotRandom::seeded(42);
        let mut piecewise = vec![0u8; 200];
        for chunk in [0..7, 7..64, 64..65, 65..130, 130..200] {
            b.fill(&mut piecewise[chunk]);
        }
        assert_eq!(whole, piecewise, "chunking must not change the stream");
    }

    #[test]
    fn it_produces_something_other_than_zeros() {
        let mut r = NotRandom::seeded(0);
        let mut b = [0u8; 64];
        r.fill(&mut b);
        assert!(b.iter().any(|&x| x != 0));
    }
}
