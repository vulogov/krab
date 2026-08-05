//! Peering, credentials, and accountability (RFC 3).
//!
//! # Admission control
//!
//! The peering relationship *is* the admission control. There is no
//! proof-of-work because a vantage point costs a social relationship rather
//! than a virtual machine: an adversary wanting 500 observation points needs
//! 500 people to agree (RFC 0 §5.2).
//!
//! # Expiry replaces revocation
//!
//! Peer links expire and are re-signed. Revocation is non-renewal. There will
//! be no CRL — a permanent design decision, not a deferral.

/// A bilateral peering relationship, evidenced by a mutually signed,
/// expiring credential.
#[derive(Debug, Clone)]
pub struct PeerLink {
    /// Credential expiry, Unix seconds. Typically 60–90 days.
    pub expires: u64,
    /// Per-direction byte and object budget.
    pub quota: Quota,
    /// Per-direction floor commitment on history kept available. Distinct
    /// from an object's expiry, and detectable in breach.
    pub retention: u64,
    /// Whether this node's nodelist fragment may be shared onward. Default
    /// false: a list of links is the social graph.
    pub share: bool,
}

/// The per-link budget: the continuous trust dial and the sole admission
/// control mechanism.
///
/// New peers start at minimal quota and grow on observed behaviour.
/// Misbehaviour is quota reduction; disconnection is the limit case, not the
/// first response. Graduated quota is what makes early vantage points
/// low-bandwidth and slow to become useful (RFC 0 §5.3).
#[derive(Debug, Clone, Copy, Default)]
pub struct Quota {
    /// Bytes per day accepted from this peer.
    pub bytes_per_day: u64,
    /// Objects per day accepted from this peer.
    pub objects_per_day: u64,
}

/// The peering negotiation triple (RFC 3).
///
/// All three are static signed documents chained by hash. There is no
/// interactive handshake, which is what allows the flow to complete over a
/// courier link with the network down — an outstanding verification item in
/// RFC 0 §9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Negotiation {
    /// Initial request.
    Request,
    /// Counter-offer, chained to the request by hash.
    Counter,
    /// Mutually signed credential.
    Link,
}
