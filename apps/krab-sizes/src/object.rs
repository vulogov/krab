//! Object size model, from RFC 1 §4, §6, §7 and §8.

use crate::cbor;

/// RFC 1 §4.1. Fixed-width binary, never CBOR.
pub const ROUTING_HEADER: usize = 16;

/// RFC 1 §6.1: AEAD tag, ChaCha20-Poly1305.
pub const AEAD_TAG: usize = 16;

/// X25519 public key, and the DHKEM encapsulation under suite 0x0001.
pub const X25519: usize = 32;

/// ML-KEM-768 ciphertext (FIPS 203). Suite 0x0002 encapsulates
/// X25519 ‖ ML-KEM-768, so the hybrid encapsulation is the sum.
pub const MLKEM768_CT: usize = 1088;

/// Ed25519 signature, RFC 1 §7 key 7.
pub const ED25519_SIG: usize = 64;

/// RFC 1 §2.
pub const MAX_OBJECT: usize = 262_144;

/// RFC 1 §8.1.
pub const BUCKETS: [usize; 6] = [256, 1_024, 4_096, 16_384, 65_536, 262_144];

/// Magnitudes that decide a CBOR head width, and therefore object size.
///
/// These are not free parameters — they are what the field actually holds at
/// the time of writing, and the head width is stable across the protocol's
/// plausible lifetime. `epoch` is days since the Unix epoch (3-byte head from
/// 2170 to the year 2149); `created` is minutes since the Unix epoch (5-byte
/// head until the year 10136, which is where RFC 1 §4.1 puts the u32 ceiling).
#[derive(Clone, Copy)]
pub struct Magnitudes {
    pub epoch: u64,
    pub created_min: u64,
}

impl Default for Magnitudes {
    fn default() -> Self {
        // 2026-08-05, give or take. Any value in the same head class gives
        // identical sizes, which is the property that matters.
        Magnitudes { epoch: 20_671, created_min: 29_766_240 }
    }
}

/// Which HPKE suite, and therefore how large the encapsulation is.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    /// 0x0001 — DHKEM(X25519, HKDF-SHA256).
    Classical,
    /// 0x0002 — X25519 + ML-KEM-768 hybrid.
    Hybrid,
}

impl Suite {
    pub fn enc_len(&self) -> usize {
        match self {
            Suite::Classical => X25519,
            Suite::Hybrid => X25519 + MLKEM768_CT,
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Suite::Classical => "0x0001 X25519",
            Suite::Hybrid => "0x0002 X25519+ML-KEM-768",
        }
    }
}

/// RFC 1 §7. Inner plaintext, `mode_auth` (no signature, no node identifier).
///
/// Keys 0,1,2,3,4,5,6 — version, address, sender kx key, epoch base, created,
/// content type, body.
pub fn inner_plaintext(addr: usize, ctype: usize, body: usize, m: Magnitudes) -> usize {
    cbor::map(7)
        + 1 + cbor::uint(1)             // 0: inner version
        + 1 + cbor::tstr(addr)          // 1: recipient address
        + 1 + cbor::bstr(X25519)        // 2: sender X25519 public key
        + 1 + cbor::uint(m.epoch)       // 3: sender epoch base
        + 1 + cbor::uint(m.created_min) // 4: created
        + 1 + cbor::tstr(ctype)         // 5: content type
        + 1 + cbor::bstr(body)          // 6: body
}

/// As above but `mode_base`: adds the Ed25519 signature and sender node id,
/// which `mode_auth` gets for free from the KEM (RFC 1 §6.2).
pub fn inner_plaintext_base(addr: usize, ctype: usize, body: usize, m: Magnitudes) -> usize {
    inner_plaintext(addr, ctype, body, m) - cbor::map(7) + cbor::map(9)
        + 1 + cbor::bstr(ED25519_SIG)   // 7: signature
        + 1 + cbor::bstr(32)            // 8: sender node identifier
}

/// RFC 1 §4.2. Envelope body for `sealed`, keys 0..5.
///
/// `admission` (key 3) is emitted as a zero-length byte string. RFC 1 does not
/// state whether a v1 encoder must emit it empty or omit it, and the choice
/// changes the identifier — see Documentation/RFC-1-review.md §3. Emitting it
/// is the reading that matches RFC 1's own published byte counts.
pub fn envelope(enc: usize, ct: usize, m: Magnitudes) -> usize {
    cbor::map(6)
        + 1 + cbor::uint(m.epoch)  // 0: tag epoch
        + 1 + cbor::uint(1)        // 1: tag mode
        + 1 + cbor::uint(1)        // 2: HPKE suite
        + 1 + cbor::bstr(0)        // 3: admission, reserved
        + 1 + cbor::bstr(enc)      // 4: HPKE encapsulated key
        + 1 + cbor::bstr(ct)       // 5: ciphertext ‖ AEAD tag
}

/// A fully described sealed object.
#[derive(Clone, Copy)]
pub struct Sealed {
    pub body: usize,
    pub plaintext: usize,
    pub ciphertext: usize,
    pub on_wire: usize,
    pub bucket: Option<usize>,
}

/// Compute a sealed object end to end, per RFC 1 §3's layering.
pub fn sealed(
    body: usize,
    addr: usize,
    ctype: usize,
    suite: Suite,
    m: Magnitudes,
) -> Sealed {
    let plaintext = inner_plaintext(addr, ctype, body, m);
    let ciphertext = plaintext + AEAD_TAG;
    let on_wire = ROUTING_HEADER + envelope(suite.enc_len(), ciphertext, m);
    Sealed { body, plaintext, ciphertext, on_wire, bucket: bucket_for(on_wire) }
}

/// Smallest bucket that fits, or `None` if the object exceeds `MAX_OBJECT`.
pub fn bucket_for(on_wire: usize) -> Option<usize> {
    BUCKETS.iter().copied().find(|&b| on_wire <= b)
}

/// Largest body that still fits `bucket`, by binary search over `sealed`.
///
/// Searched rather than solved: the relationship is monotone but not
/// continuous, because a CBOR head gains a byte at 24, 256 and 65 536, and
/// those steps land inside the bucket ranges.
pub fn max_body_for(bucket: usize, addr: usize, ctype: usize, suite: Suite, m: Magnitudes)
    -> Option<usize>
{
    if sealed(0, addr, ctype, suite, m).on_wire > bucket {
        return None;
    }
    let (mut lo, mut hi) = (0usize, bucket);
    while lo < hi {
        let mid = (lo + hi + 1) / 2;
        if sealed(mid, addr, ctype, suite, m).on_wire <= bucket {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    Some(lo)
}

#[cfg(test)]
mod tests {
    use super::*;

    const M: Magnitudes = Magnitudes { epoch: 20_671, created_min: 29_766_240 };
    // RFC 1 §7.2's worked example: "dst=<16 hex>" is 20 characters.
    const ADDR: usize = 20;
    // "text/plain"
    const CTYPE: usize = 10;

    #[test]
    fn envelope_with_empty_ciphertext_is_48() {
        assert_eq!(envelope(X25519, 0, M), 48);
    }

    #[test]
    fn inner_plaintext_empty_body_is_84() {
        assert_eq!(inner_plaintext(ADDR, CTYPE, 0, M), 84);
    }

    /// RFC 1's realistic-message table, reproduced exactly.
    #[test]
    fn realistic_messages_match_rfc1() {
        // (body, plaintext, ciphertext, on_wire, bucket)
        let want = [
            (0usize, 84usize, 100usize, 165usize, 256usize),
            (64, 149, 165, 230, 256),
            (280, 366, 382, 448, 1_024),
            (1_200, 1_286, 1_302, 1_368, 4_096),
            (4_000, 4_086, 4_102, 4_168, 16_384),
            (20_000, 20_086, 20_102, 20_168, 65_536),
            (120_000, 120_088, 120_104, 120_172, 262_144),
        ];
        for (body, pt, ct, wire, bucket) in want {
            let s = sealed(body, ADDR, CTYPE, Suite::Classical, M);
            assert_eq!(s.plaintext, pt, "plaintext for body {body}");
            assert_eq!(s.ciphertext, ct, "ciphertext for body {body}");
            assert_eq!(s.on_wire, wire, "on-wire for body {body}");
            assert_eq!(s.bucket, Some(bucket), "bucket for body {body}");
        }
    }

    /// RFC 1 §8.1's bucket table, reproduced exactly.
    #[test]
    fn bucket_capacities_match_rfc1() {
        let want = [
            (256usize, 90usize),
            (1_024, 856),
            (4_096, 3_928),
            (16_384, 16_216),
            (65_536, 65_368),
            (262_144, 261_972),
        ];
        for (bucket, max_body) in want {
            assert_eq!(
                max_body_for(bucket, ADDR, CTYPE, Suite::Classical, M),
                Some(max_body),
                "max body for bucket {bucket}"
            );
            // And one byte more must not fit.
            assert!(
                sealed(max_body + 1, ADDR, CTYPE, Suite::Classical, M).on_wire > bucket,
                "bucket {bucket} should not admit {} bytes",
                max_body + 1
            );
        }
    }

    /// RFC 1 §6.5's post-quantum comparison.
    #[test]
    fn hybrid_suite_matches_rfc1() {
        let s = sealed(280, ADDR, CTYPE, Suite::Hybrid, M);
        assert_eq!(s.on_wire, 1_537);
        assert_eq!(s.bucket, Some(4_096));
    }

    #[test]
    fn mode_base_costs_a_signature_and_a_node_id() {
        let auth = inner_plaintext(ADDR, CTYPE, 0, M);
        let base = inner_plaintext_base(ADDR, CTYPE, 0, M);
        // 64-byte signature + 32-byte node id, each with a key byte and a
        // two-byte CBOR head.
        assert_eq!(base - auth, (1 + 2 + ED25519_SIG) + (1 + 2 + 32));
    }

    #[test]
    fn nothing_exceeds_max_object() {
        assert_eq!(bucket_for(MAX_OBJECT), Some(MAX_OBJECT));
        assert_eq!(bucket_for(MAX_OBJECT + 1), None);
    }
}
