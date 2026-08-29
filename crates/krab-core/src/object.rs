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

/// Truncated identifier width, RFC 1 §9.3 — manifests only.
///
/// **16 bytes, raised from 12.** At 12 bytes a targeted 2⁴⁸ grind is
/// affordable, and §9.3's stated consequence — "one object not transferred on
/// one link, recoverable through another peer" — was wrong. `wanted()` filters
/// on `has(truncated)`, so a node holding *any* object with a colliding prefix
/// stops asking for the target, from every peer, permanently. The failure is
/// not bounded to a link and is not recoverable; it is silent suppression of
/// one chosen object, and RFC 0 §6 guarantees nobody is told.
///
/// 16 bytes puts the grind at 2⁶⁴ and the accidental rate in a 500 000-object
/// corpus near 2⁻²⁵. §9.3's own table prices the change at 8.0 MB → 10.0 MB
/// for that corpus — 25% of a manifest RFC 5 already scopes to a filtered set.
pub const TRUNC_LEN: usize = 16;

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
    pub fn truncated(&self) -> [u8; TRUNC_LEN] {
        let mut t = [0u8; TRUNC_LEN];
        t.copy_from_slice(&self.0[..TRUNC_LEN]);
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

/// A minimal well-formed `sealed` body, distinct per `salt`.
///
/// For callers that need an object whose body is *valid* and whose content
/// does not matter — every fixture that used to write forty arbitrary bytes.
/// Until RFC 1 §11 I4 was enforced those bytes were ingestible; now they are
/// not, correctly, and a dozen hand-rolled replacements would be a dozen
/// chances to write a body that is almost canonical and to blame the check
/// for the rejection.
///
/// Nothing in it is secret and nothing is encrypted: it is a shape, not a
/// message. It exists here rather than in each test module because the shape
/// is RFC 1 §4.2's and this is where §4.2 lives.
pub fn example_sealed_body(salt: u8) -> Vec<u8> {
    Envelope {
        epoch: 1,
        tag_mode: 0,
        suite: 1,
        enc: &[salt; 32],
        ciphertext: &[salt; 16],
    }
    .write()
}

/// The most nesting a v1 body may contain.
///
/// **Derived, and slack.** Every body RFC 1 §4.2 and RFC 6 define is a flat
/// map of scalars, so one level is what is used. The bound exists because
/// [`validate_body`] runs on pre-authentication input: a body of `[[[[…`
/// nests as deep as it is long, and an object may be 262 128 bytes.
const MAX_BODY_DEPTH: usize = 8;

/// Validate a body and report how many bytes it occupies — RFC 1 §11 **I4**,
/// and the length **I1** needs.
///
/// # Why these two checks are one function
///
/// I1 requires the padding after the body to be zero, and nothing knows where
/// the body ends without decoding it — which is I4. So neither could be done
/// without the other, and for a long time neither was done at all: `ingest`
/// checked that an object's *length* equalled its declared bucket and stopped
/// there, with a comment explaining that `body_len` was not available. Both
/// were missing together because they are one check wearing two numbers.
///
/// §11's own note is what this costs when it is skipped: *"the identifier
/// covers the padding, so a non-zero pad is a covert channel that every relay
/// carries until expiry, believing it ordinary."* The same is true of a body
/// with an unknown key, or one encoded non-canonically — bytes inside the
/// identifier that the receiver did not understand and relayed anyway.
///
/// # What each class gets
///
/// `sealed` and `cover` bodies are §4.2's five-key envelope, so
/// [`decode_envelope`] checks the key set exactly: unknown keys are refused
/// and key 3 is refused *because* it is reserved. That is all of I4.
///
/// A `bulletin` body's key set is RFC 6's, not RFC 1's, and this layer does
/// not know it — RFC 1 §3 makes the store handle opaque objects on purpose.
/// What is checked here is I4's first clause in full: the body is exactly one
/// deterministic CBOR map, every rule of §4.3 enforced, and nothing after it
/// but padding. Its key *set* is checked where the format is known, in
/// `bulletin::from_object` and `channels::from_object`, both of which refuse a
/// map whose keys are not the ones they expect. That split is stated rather
/// than implied, and it is the residue of the check, not a waiver of it.
///
/// `short` is refused outright: RFC 1 §5 makes it link-local and framed by
/// RFC 4 §8, so it is not a corpus object and there is no ingest path for one.
pub fn validate_body(bytes: &[u8]) -> Result<usize, Error> {
    let header = RoutingHeader::parse(bytes)?;
    let class = Class::from_byte(header.class).ok_or(Error::Malformed)?;
    let body = bytes.get(ROUTING_HEADER_LEN..).ok_or(Error::Malformed)?;
    match class {
        Class::Sealed | Class::ReservedCover => decode_envelope(body).map(|(_, n)| n),
        Class::Bulletin => walk_body(body),
        Class::Short => Err(Error::Malformed),
    }
}

/// One frame of [`walk_body`]'s explicit stack.
enum Frame {
    /// Items still owed by an open array.
    Array(usize),
    /// Items still owed by an open map — two per pair — and the last key seen.
    ///
    /// An even count means a key comes next, which is how §4.3 rule 3's
    /// ascending-key requirement is enforced without a second reader.
    Map { owed: usize, last: Option<u64> },
}

/// Walk exactly one deterministic CBOR map and return the bytes it spans.
///
/// Iterative rather than recursive: this is pre-authentication input, and a
/// deeply nested body would otherwise choose this program's stack depth.
/// Nothing is allocated against a declared count either — the counts are only
/// counted down, so a truncated body fails on the first item that is not
/// there, exactly as `Control::parse` does one layer up.
fn walk_body(body: &[u8]) -> Result<usize, Error> {
    let mut r = cbor::Reader::new(body);
    let Ok(cbor::Item::Map(n)) = r.item() else {
        // Every v1 body is a map. Requiring it makes the body's extent one
        // item rather than "as many items as happen to fit before the
        // padding", which is what makes the padding check below meaningful.
        return Err(Error::Malformed);
    };
    let mut stack = alloc::vec![Frame::Map {
        owed: n.checked_mul(2).ok_or(Error::Malformed)?,
        last: None,
    }];

    while let Some(frame) = stack.last_mut() {
        let expect_key = match frame {
            Frame::Array(0) | Frame::Map { owed: 0, .. } => {
                stack.pop();
                continue;
            }
            Frame::Array(left) => {
                *left -= 1;
                false
            }
            Frame::Map { owed, .. } => {
                *owed -= 1;
                // Decremented already, so an *odd* remainder means the item
                // just claimed was the key of its pair.
                *owed % 2 == 1
            }
        };
        // Every §4.3 rule the reader already owns — shortest form, definite
        // lengths, no floats, no tags — is enforced here by asking it.
        let item = r.item().map_err(|_| Error::Malformed)?;
        if expect_key {
            let cbor::Item::Uint(k) = item else {
                // §4.3 rule 3: map keys are unsigned integers.
                return Err(Error::Malformed);
            };
            let Some(Frame::Map { last, .. }) = stack.last_mut() else {
                unreachable!("the frame was a map a line ago")
            };
            // Ascending, no duplicates — `<=` catches both.
            if last.is_some_and(|p| k <= p) {
                return Err(Error::Malformed);
            }
            *last = Some(k);
            continue;
        }
        let child = match item {
            cbor::Item::Array(n) => Some(Frame::Array(n)),
            cbor::Item::Map(n) => Some(Frame::Map {
                owed: n.checked_mul(2).ok_or(Error::Malformed)?,
                last: None,
            }),
            _ => None,
        };
        if let Some(child) = child {
            if stack.len() >= MAX_BODY_DEPTH {
                return Err(Error::Malformed);
            }
            stack.push(child);
        }
    }
    Ok(body.len() - r.remaining())
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
    /// The AAD prefix — RFC 1 §6.1's "deterministic CBOR of the body with key
    /// 5 omitted".
    ///
    /// A four-key map: epoch, tag mode, suite, and the encapsulated key. This
    /// is what makes §6.1's claim true that the AAD "binds expiry, tag, class,
    /// **epoch, and suite**" — the header alone binds only the first three.
    ///
    /// Note key 4 is included, so this cannot be built before encapsulation.
    /// RFC 9180's `Encap` does not take the AAD, so the two-phase HPKE API
    /// resolves the ordering; a single-shot call cannot.
    pub fn aad_prefix(epoch: u64, tag_mode: u64, suite: u64, enc: &[u8]) -> Vec<u8> {
        let mut w = cbor::Writer::new();
        w.map(4)
            .uint(key::EPOCH)
            .uint(epoch)
            .uint(key::TAG_MODE)
            .uint(tag_mode)
            .uint(key::SUITE)
            .uint(suite)
            .uint(key::ENC)
            .bstr(enc);
        w.finish()
    }

    /// This envelope's AAD prefix.
    pub fn aad(&self) -> Vec<u8> {
        Envelope::aad_prefix(self.epoch, self.tag_mode, self.suite, self.enc)
    }

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
            assert_eq!(
                RoutingHeader::parse(&b),
                Err(Error::Malformed),
                "bucket {bucket}"
            );
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
        let e = Envelope {
            epoch: 20_671,
            tag_mode: 0,
            suite: 1,
            enc: &[9; 32],
            ciphertext: &[1; 40],
        };
        let body = e.write();
        let (back, consumed) = decode_envelope(&body).unwrap();
        assert_eq!(back, e);
        assert_eq!(consumed, body.len());
        // krab-sizes computes 13 + b(enc) + b(ct) for the envelope; check the
        // published constant for an empty ciphertext holds here too.
        let empty = Envelope {
            epoch: 20_671,
            tag_mode: 0,
            suite: 1,
            enc: &[0; 32],
            ciphertext: &[],
        };
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
        let e = Envelope {
            epoch: 1,
            tag_mode: 0,
            suite: 1,
            enc: &[0; 32],
            ciphertext: &[7; 64],
        };
        let body = e.write();
        let obj = canonical_bytes(&h, &body).unwrap();

        assert_eq!(obj.len(), 1_024);
        assert!(obj[ROUTING_HEADER_LEN + body.len()..]
            .iter()
            .all(|&b| b == 0));
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
        let e = Envelope {
            epoch: 20_671,
            tag_mode: 0,
            suite: 1,
            enc: &[0; 32],
            ciphertext: &[0; 165],
        };
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
