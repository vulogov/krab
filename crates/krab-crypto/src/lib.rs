//! Krab cryptographic primitives.
//!
//! **This crate owns the workspace's object-layer cryptography** — everything
//! that protects message content, identity and tags.
//!
//! It is not the *only* crate with cryptographic dependencies: `krab-fabric`
//! owns the link layer, because RFC 4 §4.1's Noise IK resolves older major
//! versions of three primitives than RFC 1 §6.1's suite requires and no
//! combination satisfies both. Two boundaries, both named, in
//! `Documentation/CRYPTO-BOUNDARIES.md`. A third would mean there is no
//! boundary, only a habit.
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
//! X25519 agreement ([`dh`]), tag derivation ([`kdf`]), the Argon2id key
//! hierarchy ([`kek`]), three-tier [`prekey`]s, the epoch-chunked
//! [`reservoir`], single-author [`channel`]s, and HPKE [`seal`]ing.
//!
//! **[`seal`] implements the construction `CRYPTO-REVIEW.md` §1 recommends,
//! not RFC 7 §6 as written** — §6 marks its own derivation defective and says
//! it MUST NOT be implemented. RFC 7 §6 needs amending to match; RFC 1 stays
//! frozen, because §6.1's suite space already accommodates it.
//!
//! # One copy of each primitive, *within this crate*
//!
//! Every version in `Cargo.toml` is pinned to whatever `hpke` resolves to. Two
//! copies inside this crate would mean one implementation deriving tags and a
//! different one running the KEM, which is a genuine hazard rather than a
//! bookkeeping one.
//!
//! `cargo tree -p krab-crypto | grep curve25519` must show exactly one version.
//! If it ever shows two, that is a regression.
//!
//! The three findings that shape this crate:
//!
//! - **§1, critical.** RFC 7 §6's reservoir derives one message key per (pair,
//!   epoch) rather than per message, because `tag` is constant for a pair
//!   across an epoch and `chunk_N` is constant by definition. **Fixed here**
//!   by supplying the chunk as an HPKE PSK under `mode_auth_psk` with the
//!   epoch as `psk_id`, so the ephemeral makes the schedule per-message while
//!   the PSK carries the post-quantum property. There is deliberately no
//!   `message_key` function anywhere in this crate — the safe construction and
//!   the defective one would differ only by which function you called.
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

pub mod channel;
pub mod dh;
pub mod hash;
pub mod kdf;
pub mod kek;
pub mod prekey;
pub mod rekey;
pub mod reservoir;
pub mod rng;
pub mod seal;
pub mod secret;
pub mod sign;
pub mod words;

pub use channel::{CarriagePolicy, Channel, Post};
pub use dh::{agree, PublicKey, SecretKey, Shared};
pub use hash::{channel_id, channel_tag, node_id, object_id, Fingerprint};
pub use kdf::{inbox_tag, pairwise_tag, pairwise_window};
pub use kek::{Hierarchy, Kek, KekParams};
pub use prekey::{index_for, PrekeyBatch, Ring, SignedPrekey};
pub use rekey::{carrier_key, confirm_tag, next_root, REKEY_EPOCHS};
pub use reservoir::{Chunk, Reservoir};
pub use rng::Rng;
pub use seal::{info_for, open, seal, Sealed};
pub use secret::{Key, Secret};
pub use sign::{Sig, SigningKey, VerifyingKey};
pub use words::phrase;
