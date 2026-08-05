//! Crypto-shredding key hierarchy (RFC 7).
//!
//! ```text
//! passphrase → Argon2id → KEK (memory only, mlock'd)
//!                          └─ epoch wrapper keys
//!                              └─ everything else
//! ```
//!
//! # I-7
//!
//! Erasure is destruction of the epoch wrapper key, never an overwrite of the
//! data it protected. Every forward-secrecy claim in the series depends on
//! this, because overwrite-based deletion is not reliable on SSDs.
//!
//! Key hierarchy is organised by access frequency: identity (offline, rotated
//! quarterly) → Noise static → prekeys → reservoir chunks. The identity key
//! signs only and never decrypts, so its compromise exposes no historical
//! traffic.

/// Epoch wrapper key. Dropping this renders the epoch's data unreadable.
///
/// Deliberately carries no `Clone`: a key that can be duplicated is a key
/// whose destruction cannot be reasoned about.
#[derive(Debug)]
pub struct EpochKey {
    /// Epoch this key wraps.
    pub epoch: u64,
}

/// The key hierarchy for one node.
#[derive(Debug, Default)]
pub struct Hierarchy {
    /// Live epoch wrapper keys, oldest first.
    pub epochs: Vec<EpochKey>,
}

impl Hierarchy {
    /// Shred every epoch at or before `epoch`, making that data permanently
    /// unreadable including this node's own archive.
    ///
    /// That the node's own history becomes unreadable is the intended
    /// behaviour, not a side effect: it is the only real form of message
    /// expiry (RFC 7). A deliberate "pin" action is the supported escape.
    pub fn shred_through(&mut self, epoch: u64) -> usize {
        let before = self.epochs.len();
        self.epochs.retain(|k| k.epoch > epoch);
        before - self.epochs.len()
    }
}
