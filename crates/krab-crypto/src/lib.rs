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
//! # Randomness is an argument
//!
//! Nothing here reaches for an entropy source; a caller passes one in via
//! [`rng::Rng`]. That keeps `krab-core`'s no-ambient-randomness posture intact
//! one level up, makes every keygen path reproducible under test, and means
//! this crate needs no `getrandom` and therefore no platform. The OS generator
//! lives in the application crate, which is the only part of the system that
//! has an OS.
//!
//! # Status
//!
//! Implemented: hashing and content addressing, Ed25519 identity ([`sign`]),
//! X25519 agreement ([`dh`]), tag derivation ([`kdf`]), and the Argon2id key
//! hierarchy ([`kek`]).
//!
//! Not implemented: HPKE sealing and the reservoir, both blocked on
//! `CRYPTO-REVIEW.md` §1 below. See `Documentation/MILESTONE-0.1.md` §2 phase
//! B. The three findings that shape this crate:
//!
//! - **§1, critical and open.** RFC 7 §6's reservoir derives one message key
//!   per (pair, epoch) rather than per message. Not implemented; the
//!   recommended `mode_auth_psk` construction needs no format change. RFC 7 §5
//!   makes the reservoir a *conditional* tier, so this does not block v1.
//! - **§2.** Ed25519 verification MUST be strict — canonical `S`, canonical
//!   encodings, small-order `A` rejected — or malleability defeats RFC 0 I-1's
//!   duplicate suppression and one signature amplifies without bound.
//! - **§3.** RFC 1 §6.2 feeds the raw X25519 output to `HKDF-Expand` as a PRK,
//!   skipping Extract, against RFC 5869 §3.3. Implemented **as frozen** in
//!   [`kdf`], with the deviation marked: doing it the safer way would fork the
//!   tag space and fail silently, since RFC 0 §6 makes delivery failure silent
//!   by design. Low-order rejection is additive and **is** applied, in
//!   [`dh::agree`].

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

pub mod dh;
pub mod hash;
pub mod kdf;
pub mod kek;
pub mod rng;
pub mod secret;
pub mod sign;
pub mod words;

pub use dh::{agree, PublicKey, SecretKey, Shared};
pub use hash::{channel_id, channel_tag, node_id, object_id, Fingerprint};
pub use kdf::{inbox_tag, pairwise_tag, pairwise_window};
pub use kek::{Hierarchy, Kek, KekParams};
pub use rng::Rng;
pub use sign::{Sig, SigningKey, VerifyingKey};
pub use words::phrase;
pub use secret::{Key, Secret};
