//! Krab cryptographic primitives.
//!
//! **This is the only crate in the workspace with third-party dependencies.**
//! That is deliberate: it localises the audit surface and RFC 0 §9's
//! reproducible-builds argument to a single boundary, and it keeps `krab-core`
//! literally zero-dependency so its no-I/O, no-clock, no-ambient-randomness
//! invariant stays compiler-enforced rather than reviewed.
//!
//! Every dependency here supports `no_std`, so nothing downstream of
//! `krab-core` undermines its posture.
//!
//! # Status
//!
//! Hashing and content addressing are implemented. Sealing, tag derivation and
//! signatures are not — see `Documentation/MILESTONE-0.1.md` §2 phase B, and
//! `Documentation/CRYPTO-REVIEW.md` for the three findings that shape them:
//!
//! - **§1, critical and open.** RFC 7 §6's reservoir derives one message key
//!   per (pair, epoch) rather than per message. Not implemented; the
//!   recommended `mode_auth_psk` construction needs no format change. RFC 7 §5
//!   makes the reservoir a *conditional* tier, so this does not block v1.
//! - **§2.** Ed25519 verification MUST be strict — canonical `S`, canonical
//!   encodings, small-order `A` rejected — or malleability defeats RFC 0 I-1's
//!   duplicate suppression and one signature amplifies without bound.
//! - **§3.** RFC 1 §6.2 feeds the raw X25519 output to `HKDF-Expand` as a PRK,
//!   skipping Extract, against RFC 5869 §3.3. That will be implemented **as
//!   frozen**, with the deviation marked: doing it the safer way would fork
//!   the tag space from the specification. Low-order rejection is additive and
//!   will be applied.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

pub mod hash;
pub mod secret;

pub use hash::{channel_id, channel_tag, node_id, object_id, Fingerprint};
pub use secret::{Key, Secret};
