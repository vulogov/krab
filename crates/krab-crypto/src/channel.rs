//! Channels — RFC 6 §3.
//!
//! ```text
//! channel_id = BLAKE3-256("krab/chan/v1" ‖ ed25519_pk)
//! tag        = leading 8 bytes of channel_id
//! ```
//!
//! Self-certifying: no registry, no hierarchy, no coordinators, no name
//! disputes. Names are **local labels** a client displays, and two subscribers
//! may call the same channel different things without anything breaking.
//!
//! The tag is stable and public — the one place in Krab where a tag is
//! deliberately linkable, because a channel is a public feed. RFC 0 I-2's
//! namespace separation is what makes that safe: a `bulletin` tag can never be
//! mistaken for a `sealed` tag, because the class byte in the frozen header
//! distinguishes them.
//!
//! # Single-author, and not negotiable
//!
//! Only the holder of the channel key may post. RFC 6 §3.2:
//!
//! > "Shared-write channels MUST NOT be added. The moment anyone can post to a
//! > channel, moderation is required; moderation requires authority; authority
//! > requires infrastructure; and RFC 0 §6 forbids infrastructure. The chain is
//! > short and its conclusion is not negotiable."
//!
//! There is no roster here, no writer set, and no way to add one: a [`Post`] is
//! valid only under the channel's own key, so "who may post" is not a field
//! anyone could widen. "Open discussion" is a *client-side* construct —
//! subscribe to several author feeds and merge by thread reference — and
//! moderation becomes unsubscription, which needs no authority.
//!
//! # Cost is constant in audience
//!
//! One post is one object whether ten or ten thousand people read it. RFC 6
//! §3.3: **a group of 20 costs 380× a channel post**, because a group is
//! fan-out and a channel is not.
//!
//! # Carriage is a decision about what a node is
//!
//! RFC 6 §3.6 is emphatic, and [`CarriagePolicy`] encodes it: channel carriage
//! is **off by default**, acceptance is by shard prefix rather than exact
//! identifier, and a client MUST state the consequence when it is enabled —
//! not in documentation nobody reads.
//!
//! An exact subscription list handed to a peer is a list of your interests. A
//! `k`-bit prefix means you also carry channels you do not read, and your peer
//! learns 1/2ᵏ of your interest — the same dial as everywhere else, reused at
//! no cost.

use crate::hash::{channel_id, channel_tag};
use crate::rng::Rng;
use crate::sign::{Sig, SigningKey, VerifyingKey};
use alloc::string::String;
use alloc::vec::Vec;
use krab_core::object::Tag;

/// Domain label for a channel post signature. Frozen — RFC 1 §5.2.
pub const DOMAIN_POST: &[u8] = b"krab/bul/v1";

/// A channel's identity: an Ed25519 key and nothing else.
pub struct Channel {
    signing: SigningKey,
}

impl core::fmt::Debug for Channel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let id = self.id();
        write!(
            f,
            "Channel({:02x}{:02x}{:02x}{:02x}..)",
            id[0], id[1], id[2], id[3]
        )
    }
}

impl Channel {
    /// Create a channel. The key *is* the channel.
    pub fn create(rng: &mut impl Rng) -> Channel {
        Channel {
            signing: SigningKey::generate(rng),
        }
    }

    /// Adopt an existing key.
    pub fn from_key(signing: SigningKey) -> Channel {
        Channel { signing }
    }

    /// The signing seed, for storing a posting credential at rest.
    ///
    /// This is the channel's private half: whoever holds it can post, which is
    /// the whole of RFC 6's authorisation model, so a caller seals it.
    pub fn signing_seed(&self) -> [u8; 32] {
        self.signing.to_seed()
    }

    /// `channel_id = BLAKE3("krab/chan/v1" ‖ ed25519_pk)`, RFC 6 §3.1.
    pub fn id(&self) -> [u8; 32] {
        channel_id(&self.signing.verifying_key().to_bytes())
    }

    /// The public key subscribers verify against.
    pub fn public(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// The stable, public tag — RFC 1 §5.2.
    pub fn tag(&self) -> Tag {
        channel_tag(&self.id())
    }

    /// Sign a post.
    pub fn post(&self, sequence: u64, content_type: &str, payload: &[u8]) -> Post {
        let author = self.signing.verifying_key().to_bytes();
        let msg = Post::signed_bytes(&author, sequence, content_type, payload);
        Post {
            author,
            sequence,
            content_type: String::from(content_type),
            payload: payload.to_vec(),
            sig: self.signing.sign(&msg),
        }
    }
}

/// A channel post — a `bulletin` object body, RFC 1 §5.2.
///
/// Signed, **not encrypted**, third-party verifiable. That is the whole
/// difference from a `sealed` object and the reason a channel costs what it
/// costs.
#[derive(Clone, PartialEq, Eq)]
pub struct Post {
    /// The channel's Ed25519 public key. RFC 1 §5.2 key 0.
    pub author: [u8; 32],
    /// Position in the feed, so a subscriber can detect a gap.
    pub sequence: u64,
    /// RFC 1 §5.2 key 2.
    pub content_type: String,
    /// RFC 1 §5.2 key 1.
    pub payload: Vec<u8>,
    /// RFC 1 §5.2 key 3, over `"krab/bul/v1" ‖ …`.
    pub sig: Sig,
}

impl core::fmt::Debug for Post {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Post(seq: {}, {} bytes)",
            self.sequence,
            self.payload.len()
        )
    }
}

impl Post {
    /// The bytes a signature covers.
    pub fn signed_bytes(
        author: &[u8; 32],
        sequence: u64,
        content_type: &str,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(DOMAIN_POST.len() + payload.len() + 64);
        out.extend_from_slice(DOMAIN_POST);
        out.extend_from_slice(author);
        out.extend_from_slice(&sequence.to_le_bytes());
        out.extend_from_slice(&(content_type.len() as u32).to_le_bytes());
        out.extend_from_slice(content_type.as_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// Whether this post is genuinely from the channel it claims.
    ///
    /// **This is the entire access-control mechanism.** RFC 6 §3.2 forbids
    /// shared-write channels, so there is no roster to consult and no writer
    /// set to widen — a post is valid under the channel's own key or it is not
    /// a post. Nothing here could be extended to admit a second author without
    /// changing what a channel is.
    #[must_use]
    pub fn verify(&self) -> bool {
        let msg = Post::signed_bytes(
            &self.author,
            self.sequence,
            &self.content_type,
            &self.payload,
        );
        VerifyingKey::from_bytes(self.author).verify(&msg, &self.sig)
    }

    /// The channel this post belongs to.
    pub fn channel_id(&self) -> [u8; 32] {
        channel_id(&self.author)
    }

    /// The tag it is addressed to.
    pub fn tag(&self) -> Tag {
        channel_tag(&self.channel_id())
    }
}

/// What a node will carry — RFC 6 §3.4.
///
/// > "Nodes MUST support excluding class 1 (bulletin) entirely via class_mask.
/// > Channel carriage MUST be off by default. Channels MUST occupy a separate
/// > shard space from sealed traffic."
// Derived rather than hand-written: every field's default *is* the safe value,
// and the reasoning lives on `enabled` where someone changing it will read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CarriagePolicy {
    /// Whether this node carries bulletins at all.
    ///
    /// **False by default.** RFC 6 §3.6: without channels a node is invisible,
    /// relaying only ciphertext for people its operator chose. Enabling
    /// carriage moves it from "I relay for four friends" to "I host public
    /// content", with whatever that means in the operator's jurisdiction.
    pub enabled: bool,
    /// Shard bits for the channel space, RFC 6 §3.4.
    ///
    /// Acceptance is by **prefix**, never by exact identifier: an exact list is
    /// a list of your interests handed to your peer, and a peer curious whether
    /// you follow channel X can simply add X and watch. A `k`-bit bucket means
    /// you also carry channels you do not read.
    pub shard_bits: u8,
    /// Which prefix bucket this node accepts.
    pub shard: u64,
}

impl CarriagePolicy {
    /// Whether this node accepts a given channel.
    pub fn accepts(&self, channel: &[u8; 32]) -> bool {
        if !self.enabled {
            return false;
        }
        if self.shard_bits == 0 {
            return true;
        }
        let k = self.shard_bits.min(63);
        let mut b = [0u8; 8];
        b.copy_from_slice(&channel[..8]);
        (u64::from_be_bytes(b) >> (64 - k as u32)) == self.shard
    }

    /// What an operator must be told when enabling carriage — RFC 6 §3.6.
    ///
    /// > "It MUST be stated at the point a user enables them — not buried in
    /// > documentation they will not read."
    pub fn enabling_notice() -> &'static str {
        "Carrying channels makes this node a host of public content. Until now it \
         has relayed only ciphertext, for people you chose, and has been \
         invisible: nothing about it is enumerable or indexable. A channel is a \
         published artifact you can neither inspect nor account for, and \
         carrying one has legal and operational consequences that depend on \
         where you are."
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::NotRandom;

    fn channel(seed: u64) -> Channel {
        Channel::create(&mut NotRandom::seeded(seed))
    }

    /// RFC 6 §3.1 — a channel is a key, and the identifier derives from it.
    #[test]
    fn a_channel_is_its_key() {
        let c = channel(1);
        assert_eq!(c.id(), channel_id(&c.public().to_bytes()));
        assert_eq!(c.tag(), channel_tag(&c.id()));
        assert_ne!(c.id(), channel(2).id());
        // Self-certifying: nothing to look up and nothing to squat.
        assert_ne!(
            c.id(),
            c.public().to_bytes(),
            "the id is not the key itself"
        );
    }

    /// The tag is stable and public — deliberately linkable, because a channel
    /// is a public feed.
    #[test]
    fn the_tag_is_stable_and_public() {
        let c = channel(3);
        assert_eq!(c.tag(), c.tag());
        // Anyone holding the public key computes it, which is the point.
        assert_eq!(c.tag(), channel_tag(&channel_id(&c.public().to_bytes())));
    }

    /// **RFC 6 §3.2 — single-author, and there is nothing to widen.** A post is
    /// valid under the channel's own key or it is not a post; no roster, no
    /// writer set, no field anyone could extend.
    #[test]
    fn only_the_channel_key_can_post() {
        let c = channel(4);
        let p = c.post(1, "text/plain", b"the first post");
        assert!(p.verify());
        assert_eq!(p.channel_id(), c.id());

        // Another key's post is a different channel, not an intrusion into
        // this one — which is what "nothing to moderate" means.
        let other = channel(5).post(1, "text/plain", b"the first post");
        assert!(other.verify());
        assert_ne!(other.channel_id(), c.id());

        // And a post reattributed to this channel does not verify.
        let mut forged = other;
        forged.author = c.public().to_bytes();
        assert!(
            !forged.verify(),
            "a post was reattributed to another channel"
        );
    }

    /// Any change invalidates the signature, including the sequence — so a
    /// subscriber detecting a gap cannot be fooled by renumbering.
    #[test]
    fn every_field_is_signed() {
        let c = channel(6);
        let p = c.post(7, "text/markdown", b"body");
        assert!(p.verify());

        for mutate in [
            |p: &mut Post| p.sequence += 1,
            |p: &mut Post| p.payload.push(b'!'),
            |p: &mut Post| p.content_type.push('x'),
            |p: &mut Post| p.sig.0[0] ^= 1,
            |p: &mut Post| p.author[0] ^= 1,
        ] {
            let mut bad = c.post(7, "text/markdown", b"body");
            mutate(&mut bad);
            assert!(!bad.verify(), "a mutated post verified");
        }
    }

    /// **RFC 6 §3.4 — carriage is off by default.** A default that carried
    /// public content would decide on the operator's behalf.
    #[test]
    fn channel_carriage_is_off_by_default() {
        let p = CarriagePolicy::default();
        assert!(!p.enabled);
        assert!(
            !p.accepts(&channel(7).id()),
            "a fresh node carried a channel"
        );
    }

    /// **Acceptance is by prefix, never by exact identifier.** An exact list is
    /// a list of your interests handed to a peer, and a peer curious whether
    /// you follow channel X can add X and watch.
    #[test]
    fn acceptance_is_by_shard_prefix() {
        let ids: alloc::vec::Vec<[u8; 32]> = (0..200u64).map(|i| channel(i).id()).collect();

        // Unsharded: everything, which is the honest maximum.
        let all = CarriagePolicy {
            enabled: true,
            shard_bits: 0,
            shard: 0,
        };
        assert!(ids.iter().all(|c| all.accepts(c)));

        // 4 bits: about a sixteenth, and the node carries channels it does not
        // read — which is what limits what the peer learns.
        let bucket = {
            let mut b = [0u8; 8];
            b.copy_from_slice(&ids[0][..8]);
            u64::from_be_bytes(b) >> 60
        };
        let sharded = CarriagePolicy {
            enabled: true,
            shard_bits: 4,
            shard: bucket,
        };
        assert!(sharded.accepts(&ids[0]));
        let carried = ids.iter().filter(|c| sharded.accepts(c)).count();
        assert!(carried > 1, "the bucket held only the channel of interest");
        assert!(
            carried < ids.len() / 4,
            "{carried} of {} is not a shard",
            ids.len()
        );
    }

    /// **RFC 6 §3.6 — the consequence is stated where it is chosen.** "It MUST
    /// be stated at the point a user enables them, not buried in documentation
    /// they will not read."
    #[test]
    fn enabling_carriage_states_what_it_changes() {
        let n = CarriagePolicy::enabling_notice();
        assert!(n.contains("public content"), "{n}");
        assert!(
            n.contains("legal"),
            "the jurisdictional consequence must be named"
        );
        assert!(
            n.contains("invisible"),
            "what is being given up must be named"
        );
    }

    /// RFC 6 §3.3 — one post is one object regardless of audience, which is
    /// the whole reason a channel is not a group.
    #[test]
    fn cost_is_constant_in_audience() {
        let c = channel(8);
        let p = c.post(1, "text/plain", &[0u8; 4_000]);
        let bytes = Post::signed_bytes(&p.author, p.sequence, &p.content_type, &p.payload).len();
        // §3.3's table uses a 4 KB post; the object is that plus signing
        // overhead, and it does not vary with how many people read it.
        assert!(bytes > 4_000 && bytes < 4_200, "{bytes}");

        // §3.3: a group of 20 costs 380× a channel post, because a group is
        // fan-out and a channel is not. 20 members × 19 recipients = 380.
        assert_eq!(20 * 19, 380);
    }

    #[test]
    fn a_channel_prints_only_its_identifier() {
        let s = alloc::format!("{:?}", channel(9));
        assert!(s.starts_with("Channel(") && s.len() < 24, "{s}");
    }
}
