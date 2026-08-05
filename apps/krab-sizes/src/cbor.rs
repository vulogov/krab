//! Encoded lengths under the RFC 1 §4.3 deterministic CBOR profile.
//!
//! Only lengths are computed, never bytes. The profile is restrictive enough
//! that an item's length is a pure function of its type and magnitude:
//! shortest-form integers, definite lengths only, no floats, no tags.
//!
//! That restrictiveness is the point. An encoding where size depends on
//! encoder choices could not be used to freeze a parameter table.

/// Length of a CBOR head carrying argument `v` (major type included).
///
/// RFC 8949 §4.2.1 requires shortest form, so this is total.
const fn head(v: u64) -> usize {
    match v {
        0..=23 => 1,
        24..=0xFF => 2,
        0x100..=0xFFFF => 3,
        0x1_0000..=0xFFFF_FFFF => 5,
        _ => 9,
    }
}

/// Encoded length of an unsigned integer.
pub const fn uint(v: u64) -> usize {
    head(v)
}

/// Encoded length of a byte string of `n` bytes.
pub const fn bstr(n: usize) -> usize {
    head(n as u64) + n
}

/// Encoded length of a text string of `n` bytes.
pub const fn tstr(n: usize) -> usize {
    head(n as u64) + n
}

/// Encoded length of a map head with `n` entries.
pub const fn map(n: usize) -> usize {
    head(n as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_boundaries() {
        // The boundaries are where a parameter table silently gains a byte,
        // so they are worth pinning.
        assert_eq!(uint(23), 1);
        assert_eq!(uint(24), 2);
        assert_eq!(uint(255), 2);
        assert_eq!(uint(256), 3);
        assert_eq!(uint(65_535), 3);
        assert_eq!(uint(65_536), 5);
        assert_eq!(uint(0xFFFF_FFFF), 5);
        assert_eq!(uint(0x1_0000_0000), 9);
    }

    #[test]
    fn strings_carry_their_head() {
        assert_eq!(bstr(0), 1);
        assert_eq!(bstr(23), 24);
        assert_eq!(bstr(32), 34);
        assert_eq!(tstr(10), 11);
        assert_eq!(bstr(65_536), 65_541);
    }
}
