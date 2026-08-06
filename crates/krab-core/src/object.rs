//! Object identity and the frozen routing header.
//!
//! # Layer model (RFC 1 §3)
//!
//! ```text
//! plaintext → [compress] → inner CBOR → HPKE seal
//!           → ROUTING_HEADER ‖ BODY → pad to bucket
//!           ────────── id = BLAKE3(domain ‖ object) ──────────
//!           → [FEC] → [armor] → link frame
//! ```
//!
//! Object identity is fixed **before** any transport codec is applied. Armor
//! and forward error correction are properties of a link, not of an object,
//! and MUST NOT participate in the identifier. That is what permits a gateway
//! to transcode between an IP link and a LoRa link without fracturing the
//! corpus.
//!
//! # Where the hash is
//!
//! This crate assembles canonical bytes and never hashes them: `krab-core` is
//! zero-dependency so its no-I/O, no-clock, no-ambient-randomness invariant
//! stays compiler-enforced. [`canonical_bytes`] produces the exact byte string
//! the identifier is taken over; `krab_crypto::object_id` takes it.

use crate::cbor;
use crate::Error;
use alloc::vec::Vec;

/// Wire length of the frozen routing header, RFC 1 §4.1.
pub const ROUTING_HEADER_LEN: usize = 16;

/// Size buckets, RFC 1 §8.1. `size_bucket` indexes this.
pub const BUCKETS: [u32; 6] = [256, 1_024, 4_096, 16_384, 65_536, 262_144];

/// RFC 1 §2. Equal to the largest bucket.
pub const MAX_OBJECT: u32 = 262_144;

/// `flags` bit 0 — link-local; not relayed beyond this link.
pub const FLAG_LINK_LOCAL: u8 = 1 << 0;
/// `flags` bit 1 — no-relay.
pub const FLAG_NO_RELAY: u8 = 1 << 1;
/// Bits 2–7 are reserved and MUST be zero (RFC 1 §10).
const FLAG_RESERVED: u8 = !(FLAG_LINK_LOCAL | FLAG_NO_RELAY);

/// Per-epoch unlinkable destination identifier, 8 bytes (RFC 1 §4.1, RFC 2 §4).
///
/// # I-2, namespace separation
///
/// Node identifiers and destination tags are disjoint namespaces. A node
/// identifier MUST NOT appear in a tag position, and a `Tag` MUST NOT appear in
/// a beacon, a nodelist fragment, a rollcall entry, or a log line. The newtype
/// makes that separation checkable rather than conventional, and deliberately
/// implements neither `Display` nor `Debug` in a form that prints the bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tag(pub [u8; 8]);

impl core::fmt::Debug for Tag {
    /// Prints nothing. A tag in a log line is exactly what I-2 forbids.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Tag(..)")
    }
}

/// Content-addressed object identifier: BLAKE3-256, 32 bytes (RFC 1 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObjectId(pub [u8; 32]);

impl ObjectId {
    /// The 12-byte prefix used in manifests (RFC 1 §9.3).
    ///
    /// Valid **only** inside an agreed reconciliation range. RFC 5 §3.1
    /// forbids it in a routing header, in stored structures, or in any request
    /// outside an established session.
    pub fn truncated(&self) -> [u8; 12] {
        let mut t = [0u8; 12];
        t.copy_from_slice(&self.0[..12]);
        t
    }
}

/// Object classes, RFC 1 §5. The enumeration is in the frozen header, so
/// additions are permanent and expensive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Class {
    /// The normal message: sealed, deniably authenticated, relayed.
    Sealed = 0,
    /// Public, signed, not encrypted. Channels, prekey batches, rollcall.
    Bulletin = 1,
    /// Reserved and unused in v1 — RFC 1 §5.3 requires cover traffic to use
    /// `Sealed`, so that it is indistinguishable. The value exists only so no
    /// future version assigns it a meaning that would make cover separable.
    ReservedCover = 2,
    /// Link-local short form. Not a corpus object; RFC 4 §8 frames it.
    Short = 3,
}

impl Class {
    /// Interpret a class byte for a *known* version.
    ///
    /// Returns `None` for anything else. A relay MUST NOT require this to
    /// succeed — RFC 1 §10 has it filter on the raw byte.
    pub fn from_byte(b: u8) -> Option<Class> {
        match b {
            0 => Some(Class::Sealed),
            1 => Some(Class::Bulletin),
            2 => Some(Class::ReservedCover),
            3 => Some(Class::Short),
            _ => None,
        }
    }
}

/// The frozen routing header, RFC 1 §4.1. Fixed-width binary, little-endian.
///
/// **Every version of Krab, for the lifetime of the protocol, MUST be able to
/// parse these sixteen bytes.** Nothing may be added.
///
/// # Privacy note
///
/// `expiry_min` discloses object age to every relay. Under partial coverage the
/// probability a node holds an object is a steep function of age (SIM-1 §2), so
/// this field is what makes differential-holdings analysis tractable. SIM-1 §3
/// measured the resulting attack and found it a symptom of under-provisioning
/// rather than of the field; the mitigation is peer count and TTL, not the
/// header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutingHeader {
    /// Object format version.
    pub version: u8,
    /// Class byte, uninterpreted. See [`Class::from_byte`].
    pub class: u8,
    /// Index into [`BUCKETS`].
    pub size_bucket: u8,
    /// Bits 0 and 1 defined; 2–7 reserved and zero.
    pub flags: u8,
    /// Absolute expiry, **minutes** since the Unix epoch. Absolute so a
    /// courier-delivered object cannot be resurrected by restarting a clock.
    pub expiry_min: u32,
    /// Destination tag.
    pub tag: Tag,
}

impl RoutingHeader {
    /// Parse the frozen header from the head of an encoded object.
    ///
    /// **This is the one parse that must never change behaviour across
    /// versions.** RFC 1 §10 requires a relay encountering an unknown `version`
    /// to route, filter and expire from these bytes alone and forward the rest
    /// opaquely, so this deliberately does *not* validate `version` or `class`.
    /// Rejecting an unknown version here would partition the network at the
    /// first protocol revision, permanently — the nodes that would bridge the
    /// partition are the ones offline for a month.
    ///
    /// It validates only what is frozen for all versions: reserved flag bits
    /// are zero, and `size_bucket` indexes a defined bucket.
    pub fn parse(bytes: &[u8]) -> Result<RoutingHeader, Error> {
        if bytes.len() < ROUTING_HEADER_LEN {
            return Err(Error::Malformed);
        }
        if bytes[3] & FLAG_RESERVED != 0 {
            return Err(Error::Malformed);
        }
        if bytes[2] as usize >= BUCKETS.len() {
            return Err(Error::Malformed);
        }
        let mut tag = [0u8; 8];
        tag.copy_from_slice(&bytes[8..16]);
        Ok(RoutingHeader {
            version: bytes[0],
            class: bytes[1],
            size_bucket: bytes[2],
            flags: bytes[3],
            expiry_min: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            tag: Tag(tag),
        })
    }

    /// Serialise to the sixteen frozen bytes.
    pub fn write(&self) -> [u8; ROUTING_HEADER_LEN] {
        let mut b = [0u8; ROUTING_HEADER_LEN];
        b[0] = self.version;
        b[1] = self.class;
        b[2] = self.size_bucket;
        b[3] = self.flags;
        b[4..8].copy_from_slice(&self.expiry_min.to_le_bytes());
        b[8..16].copy_from_slice(&self.tag.0);
        b
    }

    /// Declared object size in bytes.
    pub fn bucket_size(&self) -> u32 {
        BUCKETS[self.size_bucket as usize]
    }

    /// Absolute expiry in seconds since the Unix epoch.
    pub fn expiry_secs(&self) -> u64 {
        self.expiry_min as u64 * 60
    }

    /// Whether the object is link-local and MUST NOT be relayed.
    pub fn is_link_local(&self) -> bool {
        self.flags & FLAG_LINK_LOCAL != 0
    }

    /// Smallest bucket index that fits `on_wire`, or `None` above [`MAX_OBJECT`].
    pub fn bucket_for(on_wire: u32) -> Option<u8> {
        BUCKETS.iter().position(|&b| on_wire <= b).map(|i| i as u8)
    }
}

/// Assemble the exact byte string the identifier is taken over.
///
/// `ROUTING_HEADER ‖ BODY`, zero-padded to the declared bucket (RFC 1 §3, §8.1).
///
/// # Padding
///
/// RFC 1 §8.1: **padding MUST be zero bytes.** The identifier covers it, so an
/// unspecified fill would let two conforming encoders compute different
/// identifiers for identical plaintext. Zero is chosen over random because
/// padding sits outside the AEAD's AAD and is protected only by the identifier
/// — a fixed value makes the invariant checkable on ingest, where a random one
/// is indistinguishable from corruption. [`verify_padding`] is that check.
pub fn canonical_bytes(header: &RoutingHeader, body: &[u8]) -> Result<Vec<u8>, Error> {
    let bucket = header.bucket_size() as usize;
    let used = ROUTING_HEADER_LEN + body.len();
    if used > bucket {
        return Err(Error::Malformed);
    }
    let mut out = Vec::with_capacity(bucket);
    out.extend_from_slice(&header.write());
    out.extend_from_slice(body);
    out.resize(bucket, 0);
    Ok(out)
}

/// Check RFC 1 §11 rule 1 and §8.1's padding rule on ingest.
///
/// The object's length must equal its declared bucket, and every byte after
/// the body must be zero. `body_len` is what the body decoder consumed.
pub fn verify_padding(bytes: &[u8], body_len: usize) -> Result<(), Error> {
    let header = RoutingHeader::parse(bytes)?;
    if bytes.len() != header.bucket_size() as usize {
        return Err(Error::Malformed);
    }
    let used = ROUTING_HEADER_LEN + body_len;
    if used > bytes.len() {
        return Err(Error::Malformed);
    }
    if bytes[used..].iter().any(|&b| b != 0) {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// A decoded `sealed` envelope body, RFC 1 §4.2.
///
/// Key 3 (`admission`) is absent by construction: RFC 1 §4.2 requires a v1
/// encoder not to emit it and a v1 decoder to reject it if present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope<'a> {
    /// Key 0 — tag epoch.
    pub epoch: u64,
    /// Key 1 — tag mode: 0 pairwise, 1 inbox.
    pub tag_mode: u64,
    /// Key 2 — HPKE suite identifier.
    pub suite: u64,
    /// Key 4 — HPKE encapsulated key.
    pub enc: &'a [u8],
    /// Key 5 — ciphertext ‖ AEAD tag.
    pub ciphertext: &'a [u8],
}

/// Envelope body keys, RFC 1 §4.2.
mod key {
    pub const EPOCH: u64 = 0;
    pub const TAG_MODE: u64 = 1;
    pub const SUITE: u64 = 2;
    pub const ADMISSION: u64 = 3;
    pub const ENC: u64 = 4;
    pub const CIPHERTEXT: u64 = 5;
}

impl Envelope<'_> {
    /// Encode to deterministic CBOR. Five keys, ascending, key 3 omitted.
    pub fn write(&self) -> Vec<u8> {
        let mut w = cbor::Writer::new();
        w.map(5)
            .uint(key::EPOCH)
            .uint(self.epoch)
            .uint(key::TAG_MODE)
            .uint(self.tag_mode)
            .uint(key::SUITE)
            .uint(self.suite)
            .uint(key::ENC)
            .bstr(self.enc)
            .uint(key::CIPHERTEXT)
            .bstr(self.ciphertext);
        w.finish()
    }
}

/// Decode a `sealed` envelope body from `bytes`.
///
/// Returns the envelope and the number of bytes consumed, so the caller can
/// check padding with [`verify_padding`].
///
/// Enforces RFC 1 §4.3's "unknown keys in a body of a known version MUST be
/// rejected" — an object that cannot be fully validated must not enter the
/// store, because the identifier covers bytes the receiver did not understand
/// and that is a malleability surface.
pub fn decode_envelope(bytes: &[u8]) -> Result<(Envelope<'_>, usize), Error> {
    let mut r = cbor::Reader::new(bytes);
    let mut m = r.map().map_err(|_| Error::Malformed)?;
    let (mut epoch, mut tag_mode, mut suite) = (None, None, None);
    let (mut enc, mut ct) = (None, None);

    while let Some(k) = m.key().map_err(|_| Error::Malformed)? {
        let v = m.value().map_err(|_| Error::Malformed)?;
        match (k, v) {
            (key::EPOCH, cbor::Item::Uint(x)) => epoch = Some(x),
            (key::TAG_MODE, cbor::Item::Uint(x)) => tag_mode = Some(x),
            (key::SUITE, cbor::Item::Uint(x)) => suite = Some(x),
            (key::ENC, cbor::Item::Bstr(x)) => enc = Some(x),
            (key::CIPHERTEXT, cbor::Item::Bstr(x)) => ct = Some(x),
            // RFC 1 §4.2: reserved means absent, not present-and-empty.
            (key::ADMISSION, _) => return Err(Error::UnknownEnvelopeKey),
            // RFC 1 §4.3: unknown keys in a known version are rejected.
            _ => return Err(Error::UnknownEnvelopeKey),
        }
    }
    let consumed = bytes.len() - r.remaining();
    Ok((
        Envelope {
            epoch: epoch.ok_or(Error::Malformed)?,
            tag_mode: tag_mode.ok_or(Error::Malformed)?,
            suite: suite.ok_or(Error::Malformed)?,
            enc: enc.ok_or(Error::Malformed)?,
            ciphertext: ct.ok_or(Error::Malformed)?,
        },
        consumed,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr() -> RoutingHeader {
        RoutingHeader {
            version: 1,
            class: Class::Sealed as u8,
            size_bucket: 1,
            flags: 0,
            expiry_min: 29_766_240,
            tag: Tag([7; 8]),
        }
    }

    #[test]
    fn header_round_trips_the_frozen_layout() {
        let h = hdr();
        let parsed = RoutingHeader::parse(&h.write()).unwrap();
        assert_eq!(parsed, h);
        assert_eq!(parsed.bucket_size(), 1_024);
        assert_eq!(parsed.expiry_secs(), 29_766_240 * 60);
    }

    /// RFC 1 §10: a relay MUST route, filter and expire an unknown version
    /// from the header alone. Rejecting it here would partition the network.
    #[test]
    fn accepts_unknown_versions_and_classes() {
        for v in [0u8, 2, 200, 255] {
            let mut h = hdr();
            h.version = v;
            assert_eq!(RoutingHeader::parse(&h.write()).unwrap().version, v);
        }
        for c in [4u8, 99, 255] {
            let mut h = hdr();
            h.class = c;
            let p = RoutingHeader::parse(&h.write()).unwrap();
            assert_eq!(p.class, c);
            assert_eq!(Class::from_byte(c), None, "unknown class must not resolve");
        }
    }

    #[test]
    fn rejects_reserved_flag_bits_and_undefined_buckets() {
        for bit in 2..8 {
            let mut b = hdr().write();
            b[3] = 1 << bit;
            assert_eq!(RoutingHeader::parse(&b), Err(Error::Malformed), "bit {bit}");
        }
        for bucket in 6u8..=255 {
            let mut b = hdr().write();
            b[2] = bucket;
            assert_eq!(RoutingHeader::parse(&b), Err(Error::Malformed), "bucket {bucket}");
        }
    }

    #[test]
    fn bucket_selection_matches_rfc1() {
        assert_eq!(RoutingHeader::bucket_for(1), Some(0));
        assert_eq!(RoutingHeader::bucket_for(256), Some(0));
        assert_eq!(RoutingHeader::bucket_for(257), Some(1));
        assert_eq!(RoutingHeader::bucket_for(MAX_OBJECT), Some(5));
        assert_eq!(RoutingHeader::bucket_for(MAX_OBJECT + 1), None);
    }

    #[test]
    fn envelope_round_trips_with_admission_absent() {
        let e = Envelope { epoch: 20_671, tag_mode: 0, suite: 1, enc: &[9; 32], ciphertext: &[1; 40] };
        let body = e.write();
        let (back, consumed) = decode_envelope(&body).unwrap();
        assert_eq!(back, e);
        assert_eq!(consumed, body.len());
        // krab-sizes computes 13 + b(enc) + b(ct) for the envelope; check the
        // published constant for an empty ciphertext holds here too.
        let empty = Envelope { epoch: 20_671, tag_mode: 0, suite: 1, enc: &[0; 32], ciphertext: &[] };
        assert_eq!(empty.write().len(), 46, "RFC 1 §4.2 with key 3 absent");
    }

    /// RFC 1 §4.2 — reserved means absent, not present-and-empty.
    #[test]
    fn rejects_a_present_admission_key() {
        let mut w = cbor::Writer::new();
        w.map(6)
            .uint(0)
            .uint(1)
            .uint(1)
            .uint(0)
            .uint(2)
            .uint(1)
            .uint(3)
            .bstr(&[]) // admission, present and empty
            .uint(4)
            .bstr(&[0; 32])
            .uint(5)
            .bstr(&[1]);
        assert_eq!(decode_envelope(&w.finish()), Err(Error::UnknownEnvelopeKey));
    }

    /// RFC 1 §4.3 — unknown keys in a known version are rejected, because the
    /// identifier covers bytes the receiver did not understand.
    #[test]
    fn rejects_unknown_envelope_keys() {
        let mut w = cbor::Writer::new();
        w.map(6)
            .uint(0)
            .uint(1)
            .uint(1)
            .uint(0)
            .uint(2)
            .uint(1)
            .uint(4)
            .bstr(&[0; 32])
            .uint(5)
            .bstr(&[1])
            .uint(9)
            .uint(0); // unknown
        assert_eq!(decode_envelope(&w.finish()), Err(Error::UnknownEnvelopeKey));
    }

    #[test]
    fn rejects_an_envelope_missing_a_required_key() {
        let mut w = cbor::Writer::new();
        w.map(2).uint(0).uint(1).uint(1).uint(0);
        assert_eq!(decode_envelope(&w.finish()), Err(Error::Malformed));
    }

    /// RFC 1 §8.1 — padding MUST be zero, and it is checkable on ingest.
    #[test]
    fn canonical_bytes_pads_with_zeros_and_verifies() {
        let h = hdr();
        let e = Envelope { epoch: 1, tag_mode: 0, suite: 1, enc: &[0; 32], ciphertext: &[7; 64] };
        let body = e.write();
        let obj = canonical_bytes(&h, &body).unwrap();

        assert_eq!(obj.len(), 1_024);
        assert!(obj[ROUTING_HEADER_LEN + body.len()..].iter().all(|&b| b == 0));
        assert_eq!(verify_padding(&obj, body.len()), Ok(()));

        // A single non-zero padding byte is rejected.
        let mut tampered = obj.clone();
        let last = tampered.len() - 1;
        tampered[last] = 1;
        assert_eq!(verify_padding(&tampered, body.len()), Err(Error::Malformed));
    }

    #[test]
    fn canonical_bytes_rejects_a_body_that_overflows_its_bucket() {
        let mut h = hdr();
        h.size_bucket = 0; // 256
        assert_eq!(canonical_bytes(&h, &[0u8; 300]), Err(Error::Malformed));
    }

    /// The whole pipeline agrees with krab-sizes' bucket table: a 64-byte body
    /// lands in the 256 bucket, matching RFC 1's published realistic-message row.
    #[test]
    fn a_64_byte_message_lands_in_the_256_bucket() {
        // krab-sizes: body 64 -> ciphertext 165 -> on-wire 228 -> bucket 256.
        let e = Envelope { epoch: 20_671, tag_mode: 0, suite: 1, enc: &[0; 32], ciphertext: &[0; 165] };
        let on_wire = ROUTING_HEADER_LEN + e.write().len();
        assert_eq!(on_wire, 228, "matches RFC 1 §8.1 with key 3 absent");
        assert_eq!(RoutingHeader::bucket_for(on_wire as u32), Some(0));
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        for n in 0..40usize {
            let v = alloc::vec![0xABu8; n];
            let _ = RoutingHeader::parse(&v);
            let _ = decode_envelope(&v);
            let _ = verify_padding(&v, n / 2);
        }
        for a in 0u16..=255 {
            let v = alloc::vec![a as u8; 20];
            let _ = RoutingHeader::parse(&v);
            let _ = decode_envelope(&v);
        }
    }
}
