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

/// Parse the frozen routing header from the head of an encoded object.
///
/// This is the one parse that must never change behaviour across versions.
pub fn parse_routing_header(_bytes: &[u8]) -> Result<RoutingHeader, Error> {
    // Awaiting RFC 1 §B2. Deliberately unimplemented rather than guessed: the
    // encoding is frozen permanently and must not be established by accident.
    Err(Error::Malformed)
}

/// Compute `id = H(DOMAIN || deterministic_cbor(object))`.
pub fn object_id(_canonical_bytes: &[u8]) -> Result<ObjectId, Error> {
    // Awaiting RFC 1: hash choice and domain string are frozen into every
    // identifier that will ever exist.
    Err(Error::Malformed)
}
