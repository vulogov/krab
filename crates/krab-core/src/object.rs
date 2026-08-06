//! Object identity and the frozen routing header.
//!
//! # Layer model (RFC 0 §4.1)
//!
//! ```text
//! link frame → [armor] → [FEC] → OBJECT (CBOR)
//!                                  envelope (public)
//!                                  payload: HPKE sealed
//! ```
//!
//! Object identity is fixed **before** any transport codec is applied. Armor
//! and forward error correction are properties of a link, not of an object,
//! and MUST NOT participate in the identifier. This is what permits a gateway
//! to transcode between an IP link and a LoRa link without fracturing the
//! corpus.
//!
//! # I-1, content addressing
//!
//! `id = H(canonical_bytes)`. Objects are immutable. Duplicate suppression,
//! loop suppression, and replay resistance all follow from this and need no
//! additional mechanism.

use crate::Error;

/// The frozen routing header (RFC 0 §10.1, plan blocking item B2).
///
/// Nodes go offline for months and return by courier. There is never a flag
/// day. These four fields MUST be parseable by every version of Krab forever;
/// a relay encountering an unknown object version MUST route, filter, and
/// expire from this header alone and forward the remainder as opaque bytes.
///
/// Nothing may be added to this struct after RFC 1 reaches Draft.
///
/// # Privacy note (SIM-0 audit, Documentation/SIM-0-audit.md §2)
///
/// `expiry` discloses object age to every relay. Under partial coverage the
/// probability that a node holds an object is a steep function of that age,
/// so this field is what makes differential-holdings analysis tractable.
/// The interaction is unresolved and is called out in the audit; it must be
/// settled before this header is frozen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutingHeader {
    /// Object format version.
    pub version: u16,
    /// Absolute expiry, seconds since the Unix epoch. Absolute rather than
    /// relative so that a courier-delivered object cannot be resurrected by
    /// restarting its clock (RFC 5, expiry resurrection).
    pub expiry: u64,
    /// Per-epoch unlinkable destination tag (RFC 2).
    pub tag: Tag,
    /// Payload size in bytes, for filtering before transfer.
    pub size: u32,
}

/// Per-epoch unlinkable destination identifier.
///
/// # I-2, namespace separation
///
/// Node identifiers and message destination tags are disjoint namespaces. A
/// node identifier MUST NOT appear in a tag position, and a `Tag` MUST NOT
/// appear in a beacon, a nodelist fragment, a routing header outside this
/// field, or a log line. The newtype exists to make that separation checkable
/// rather than conventional; it deliberately does not implement `Display`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag(
    /// Width is blocking item B3 and is not settled.
    pub [u8; 32],
);

/// Content-addressed object identifier, `H(canonical_bytes)`.
///
/// Width is blocking item B3 (32 B full vs 16 B truncated in ranges) and is
/// not settled; the choice drives manifest size, which per the SIM-0 audit is
/// the binding constraint on constrained links.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObjectId(pub [u8; 32]);

/// Object classes (RFC 1). Per-class size, crypto, and relay rules differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Sealed point-to-point message.
    Sealed,
    /// Link-local short form; cannot be relayed by construction.
    Short,
    /// Public, signed, permanent. Channels and rollcall entries.
    Bulletin,
    /// Signed nodelist fragment, encrypted individually to each peer.
    Nodelist,
    /// Liveness and capability beacon. Carries coverage (RFC 0 §7.4).
    Presence,
    /// Cover traffic.
    Cover,
}

/// Wire length of the frozen routing header, RFC 1 §4.1.
pub const ROUTING_HEADER_LEN: usize = 16;

/// Size buckets, RFC 1 §8.1. `size_bucket` in the header indexes this.
pub const BUCKETS: [u32; 6] = [256, 1_024, 4_096, 16_384, 65_536, 262_144];

/// `flags` bit 0 — link-local; the object is not relayed beyond this link.
pub const FLAG_LINK_LOCAL: u8 = 1 << 0;
/// `flags` bit 1 — no-relay.
pub const FLAG_NO_RELAY: u8 = 1 << 1;
/// Bits 2–7 are reserved and MUST be zero (RFC 1 §10).
const FLAG_RESERVED: u8 = !(FLAG_LINK_LOCAL | FLAG_NO_RELAY);

impl RoutingHeader {
    /// Parse the frozen routing header from the head of an encoded object.
    ///
    /// **This is the one parse that must never change behaviour across
    /// versions.** RFC 1 §10 requires a relay encountering an unknown `ver` to
    /// route, filter, and expire from these sixteen bytes alone and forward
    /// the remainder opaquely — so this function deliberately does *not*
    /// validate `ver`. Rejecting an unknown version here would partition the
    /// network at the first protocol revision, permanently, because the nodes
    /// that would bridge it are the ones offline for a month.
    ///
    /// What it does validate is what is frozen for all versions: the reserved
    /// flag bits are zero, and `size_bucket` indexes a defined bucket.
    pub fn parse(bytes: &[u8]) -> Result<RoutingHeader, Error> {
        if bytes.len() < ROUTING_HEADER_LEN {
            return Err(Error::Malformed);
        }
        let flags = bytes[3];
        if flags & FLAG_RESERVED != 0 {
            return Err(Error::UnknownEnvelopeKey);
        }
        let size_bucket = bytes[2];
        if size_bucket as usize >= BUCKETS.len() {
            return Err(Error::Malformed);
        }
        let mut tag = [0u8; 32];
        tag[..8].copy_from_slice(&bytes[8..16]);
        Ok(RoutingHeader {
            version: bytes[0] as u16,
            expiry: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as u64 * 60,
            tag: Tag(tag),
            size: BUCKETS[size_bucket as usize],
        })
    }

    /// The class byte, read without interpreting it.
    ///
    /// Returned raw because the class enumeration is per-version: a relay
    /// filters on the byte and must not require it to be one it knows.
    pub fn class_byte(bytes: &[u8]) -> Result<u8, Error> {
        bytes.get(1).copied().ok_or(Error::Malformed)
    }

    /// Whether the object is link-local and MUST NOT be relayed.
    pub fn is_link_local(bytes: &[u8]) -> Result<bool, Error> {
        Ok(bytes.get(3).copied().ok_or(Error::Malformed)? & FLAG_LINK_LOCAL != 0)
    }

    /// Smallest bucket that fits `on_wire`, or `None` above `MAX_OBJECT`.
    pub fn bucket_for(on_wire: u32) -> Option<(u8, u32)> {
        BUCKETS.iter().position(|&b| on_wire <= b).map(|i| (i as u8, BUCKETS[i]))
    }
}

/// Compute `id = H(DOMAIN || object)`.
///
/// # Blocked
///
/// Not implemented, and deliberately not guessed. The identifier covers the
/// whole object *including its padding* (RFC 1 §3, §4), and **RFC 1 does not
/// specify what the padding bytes contain.** Two conforming implementations
/// that pad with zeros and with random bytes compute different identifiers for
/// identical plaintext, which fractures the corpus along implementation lines
/// with no repair possible once objects exist.
///
/// See `Documentation/CRYPTO-REVIEW.md` §4. One sentence in RFC 1 §8 unblocks
/// this; writing it here instead would establish the answer by accident, which
/// is exactly what a frozen format must not allow.
pub fn object_id(_canonical_bytes: &[u8]) -> Result<ObjectId, Error> {
    Err(Error::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(ver: u8, class: u8, bucket: u8, flags: u8, expiry_min: u32, tag: [u8; 8]) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0] = ver;
        b[1] = class;
        b[2] = bucket;
        b[3] = flags;
        b[4..8].copy_from_slice(&expiry_min.to_le_bytes());
        b[8..16].copy_from_slice(&tag);
        b
    }

    #[test]
    fn parses_the_frozen_layout() {
        let b = hdr(1, 0, 2, FLAG_LINK_LOCAL, 29_766_240, [9; 8]);
        let h = RoutingHeader::parse(&b).unwrap();
        assert_eq!(h.version, 1);
        assert_eq!(h.size, 4_096);
        // expiry_min is minutes; the struct carries seconds.
        assert_eq!(h.expiry, 29_766_240 * 60);
        assert_eq!(&h.tag.0[..8], &[9u8; 8]);
        assert_eq!(RoutingHeader::class_byte(&b).unwrap(), 0);
        assert!(RoutingHeader::is_link_local(&b).unwrap());
    }

    /// RFC 1 §10: a relay MUST route, filter and expire an unknown version
    /// from the header alone. Rejecting it here would partition the network.
    #[test]
    fn accepts_unknown_versions() {
        for ver in [0u8, 2, 7, 255] {
            let b = hdr(ver, 0, 0, 0, 1, [0; 8]);
            let h = RoutingHeader::parse(&b).expect("unknown version must still parse");
            assert_eq!(h.version, ver as u16);
        }
    }

    /// RFC 1 §10: reserved flag bits MUST be zero on emission and are checked
    /// here because they are frozen for all versions.
    #[test]
    fn rejects_reserved_flag_bits() {
        for bit in 2..8 {
            let b = hdr(1, 0, 0, 1 << bit, 1, [0; 8]);
            assert_eq!(RoutingHeader::parse(&b), Err(Error::UnknownEnvelopeKey), "bit {bit}");
        }
        // Both defined bits together are fine.
        let b = hdr(1, 0, 0, FLAG_LINK_LOCAL | FLAG_NO_RELAY, 1, [0; 8]);
        assert!(RoutingHeader::parse(&b).is_ok());
    }

    #[test]
    fn rejects_undefined_size_buckets() {
        for bucket in 6u8..=255 {
            let b = hdr(1, 0, bucket, 0, 1, [0; 8]);
            assert_eq!(RoutingHeader::parse(&b), Err(Error::Malformed), "bucket {bucket}");
        }
    }

    #[test]
    fn rejects_short_input() {
        for n in 0..ROUTING_HEADER_LEN {
            assert_eq!(RoutingHeader::parse(&[0u8; 16][..n]), Err(Error::Malformed), "len {n}");
        }
    }

    /// Bucket selection must agree with krab-sizes, which reproduces RFC 1
    /// §8.1's published table.
    #[test]
    fn bucket_selection_matches_rfc1() {
        assert_eq!(RoutingHeader::bucket_for(1), Some((0, 256)));
        assert_eq!(RoutingHeader::bucket_for(256), Some((0, 256)));
        assert_eq!(RoutingHeader::bucket_for(257), Some((1, 1_024)));
        assert_eq!(RoutingHeader::bucket_for(262_144), Some((5, 262_144)));
        assert_eq!(RoutingHeader::bucket_for(262_145), None);
    }

    /// Never panic on arbitrary input — RFC 0 §9 reaches this pre-auth.
    #[test]
    fn never_panics_on_arbitrary_input() {
        for a in 0u16..=255 {
            let mut b = [0u8; 16];
            for i in 0..16 {
                b[i] = a as u8;
            }
            let _ = RoutingHeader::parse(&b);
            let _ = RoutingHeader::class_byte(&b);
            let _ = RoutingHeader::is_link_local(&b);
        }
        for n in 0..40 {
            let v = alloc::vec![0xABu8; n];
            let _ = RoutingHeader::parse(&v);
        }
    }

    /// The identifier is blocked, and the test records why so a future change
    /// to make it "work" fails loudly.
    #[test]
    fn object_id_is_blocked_on_the_padding_ambiguity() {
        assert_eq!(object_id(b"anything"), Err(Error::Malformed));
    }
}
