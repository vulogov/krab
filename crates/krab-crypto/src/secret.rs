//! Secret material that erases itself.
//!
//! RFC 7 §9's memory hygiene, and the mechanism RFC 7 §4's crypto-shredding
//! rests on: *"forward secrecy is achieved by destroying keys, never by
//! overwriting data"* (RFC 0 I-7). Destroying a key means the bytes are gone
//! from memory, which the compiler will otherwise happily optimise away.
//!
//! # The honest limit
//!
//! RFC 7 §9.1: **Rust cannot guarantee a secret was never copied.** Moves,
//! reallocation and compiler optimisation may leave residue that zeroizing
//! never sees. `Secret` is a fixed-size array precisely so it does not
//! reallocate — RFC 7 §9 requires "fixed-size arrays rather than `Vec`, since
//! growth reallocates and leaves the previous contents behind" — but a move
//! still copies. This reduces exposure; it does not eliminate it.

use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A fixed-size secret, zeroized on drop.
///
/// `Debug` prints nothing: RFC 7 §9 requires that `Debug` implementations on
/// key types print nothing, because a key in a log line survives every other
/// precaution in the series.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
    /// Wrap `bytes`.
    pub fn new(bytes: [u8; N]) -> Secret<N> {
        Secret(bytes)
    }

    /// Borrow the material.
    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }

    /// Destroy it now, without waiting for the drop.
    ///
    /// This is the whole of a crypto-shred at any tier: RFC 7 §10 describes
    /// panic wipe and the dead-man timer as "a 32-byte overwrite" each, and
    /// this is that overwrite.
    pub fn destroy(&mut self) {
        self.0.zeroize();
    }

    /// Whether the material is all zero — destroyed, or never set.
    pub fn is_destroyed(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl<const N: usize> fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret<{N}>(..)")
    }
}

/// A 32-byte key — the width of every root in RFC 7 §4's hierarchy.
pub type Key = Secret<32>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destroy_clears_the_material() {
        let mut k = Key::new([0xAB; 32]);
        assert!(!k.is_destroyed());
        assert_eq!(k.expose()[0], 0xAB);
        k.destroy();
        assert!(k.is_destroyed());
        assert_eq!(k.expose(), &[0u8; 32]);
    }

    /// RFC 7 §9 — a key in a log line survives every other precaution.
    #[test]
    fn debug_prints_no_material() {
        let k = Key::new([0xAB; 32]);
        let s = alloc::format!("{k:?}");
        assert!(!s.contains("171") && !s.contains("ab") && !s.contains("AB"));
        assert_eq!(s, "Secret<32>(..)");
    }
}
