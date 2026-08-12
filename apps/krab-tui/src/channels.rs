//! Channels — RFC 6, and the interface requirements in RFC 8 §4.
//!
//! A channel is a signing keypair. Its identifier is the hash of its public
//! key, its tag is derived from that identifier, and a post is signed by the
//! channel key rather than by the author's identity key. So the channel *is*
//! the credential: whoever holds the key can post, and nobody else can.
//!
//! # Why posts are not wrapped in a [`crate::bulletin::Bulletin`]
//!
//! A `Bulletin` exists to attach an identity signature to a payload that has
//! none. A `Post` already carries one, made with the channel key, and
//! `Post::tag()` already says where it belongs. Wrapping would add a second
//! signature that means something different from the first — "this node's
//! operator vouches for this" — which is a claim RFC 6 never asks for and
//! which would attach a real identity to every post that passed through.
//!
//! Both are `Class::Bulletin` objects. The class says public-and-signed; it
//! does not say by whom.
//!
//! # The part that is irreversible
//!
//! RFC 8 §4.1 makes a mistaken channel post **the highest-severity item in
//! the design**. It is signed, flooded, archived by every carrying node, and
//! RFC 3 §6.1 forbids any recall mechanism — permanently, because a recall
//! mechanism is a censorship mechanism and cannot be made selective. Unlike a
//! sealed message it does not become unreadable when an epoch key is erased,
//! because there is no epoch key.
//!
//! Every other mistake in Krab is recoverable or expires. This one is neither,
//! which is why [`Roster::first_post_confirmed`] exists and why it resets.

use krab_core::cbor;
use krab_core::object::{Class, ObjectId, RoutingHeader, ROUTING_HEADER_LEN};
use krab_crypto::channel::{Channel, Post};

/// Wrap a post as a corpus object.
///
/// Same shape as [`crate::bulletin::into_object`] and for the same reason: a
/// payload is not an object until it has a routing header, and a store that
/// rejects it as malformed looks identical to one that accepted it if the
/// error is discarded.
pub fn into_object(p: &Post, now_min: u32, ttl_min: u32) -> Option<(ObjectId, Vec<u8>)> {
    let body = encode_post(p);
    let bucket = RoutingHeader::bucket_for((ROUTING_HEADER_LEN + body.len()) as u32)?;
    let header = RoutingHeader {
        version: 1,
        class: Class::Bulletin as u8,
        size_bucket: bucket,
        flags: 0,
        expiry_min: now_min.saturating_add(ttl_min),
        // The channel's own tag, so a node carrying that channel finds it the
        // same way it finds anything else — and a node not carrying it never
        // has to decode the body to know that.
        tag: p.tag(),
    };
    let total = krab_core::object::BUCKETS[bucket as usize] as usize;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&header.write());
    out.extend_from_slice(&body);
    out.resize(total, 0);
    Some((krab_crypto::hash::object_id(&out), out))
}

/// Read a post back out, or `None` if it is not a **verifying** one.
///
/// Verification is inside this function so a caller cannot act on an
/// unauthenticated post by forgetting to check. A post arrives by flooding
/// from anyone.
pub fn from_object(bytes: &[u8]) -> Option<Post> {
    let header = RoutingHeader::parse(bytes).ok()?;
    if header.class != Class::Bulletin as u8 {
        return None;
    }
    let p = decode_post(&bytes[ROUTING_HEADER_LEN..])?;
    p.verify().then_some(p)
}

/// Deterministic CBOR — RFC 1 §4.3.
pub fn encode_post(p: &Post) -> Vec<u8> {
    let mut w = cbor::Writer::new();
    w.map(5)
        .uint(1)
        .bstr(&p.author)
        .uint(2)
        .uint(p.sequence)
        .uint(3)
        .tstr(&p.content_type)
        .uint(4)
        .bstr(&p.payload)
        .uint(5)
        .bstr(&p.sig.0);
    w.finish()
}

/// Decode. **Pre-authentication input.**
pub fn decode_post(bytes: &[u8]) -> Option<Post> {
    let mut r = cbor::Reader::new(bytes);
    let mut m = r.map().ok()?;
    if m.left() != 5 {
        return None;
    }
    let author = bstr_at(&mut m, 1)?.try_into().ok()?;
    let sequence = uint_at(&mut m, 2)?;
    let content_type = tstr_at(&mut m, 3)?.to_string();
    // A content type is a label, not a document. Anything longer is either a
    // mistake or an attempt to make readers carry a payload in a field they
    // will render without thinking.
    if content_type.len() > 64 {
        return None;
    }
    let payload = bstr_at(&mut m, 4)?.to_vec();
    let sig: [u8; 64] = bstr_at(&mut m, 5)?.try_into().ok()?;
    Some(Post {
        author,
        sequence,
        content_type,
        payload,
        sig: krab_crypto::sign::Sig(sig),
    })
}

/// Which channels this node follows, and the one it can post to.
///
/// **Single-author.** RFC 6's channel is a keypair, so "can post" means
/// "holds the key". A multi-author channel would be a shared secret with the
/// properties of a shared secret, and RFC 6 §3 does not describe one.
#[derive(Default)]
pub struct Roster {
    /// Channels being read, by identifier.
    pub following: Vec<[u8; 32]>,
    /// The channel this node owns, if it has made one.
    pub mine: Option<Channel>,
    /// **RFC 8 §4.2 requirement 2.** Whether the operator has confirmed a
    /// channel post this session.
    ///
    /// Per *session*, not per node: it resets on lock and on restart, because
    /// the confirmation is a reminder of what publishing means and a reminder
    /// given once a year is not one.
    pub first_post_confirmed: bool,
}

impl Roster {
    /// Follow a channel. Idempotent — following twice is not two channels.
    pub fn follow(&mut self, id: [u8; 32]) -> bool {
        if self.following.contains(&id) {
            return false;
        }
        self.following.push(id);
        true
    }

    /// Stop following. Returns whether anything changed.
    ///
    /// **This does not remove posts already held.** RFC 3 §6.1 forbids a
    /// recall mechanism, and a node that erased a channel's archive on
    /// unfollowing would be one — a selective one, which is worse.
    pub fn unfollow(&mut self, id: &[u8; 32]) -> bool {
        let before = self.following.len();
        self.following.retain(|c| c != id);
        self.following.len() != before
    }

    /// Whether a post belongs to a channel this node is reading.
    pub fn follows(&self, id: &[u8; 32]) -> bool {
        self.following.contains(id) || self.mine.as_ref().is_some_and(|c| c.id() == *id)
    }

    /// Encode for storage. The channel *secret* is included, so a caller
    /// seals this — it is a posting credential.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = cbor::Writer::new();
        let mut flat = Vec::with_capacity(self.following.len() * 32);
        for c in &self.following {
            flat.extend_from_slice(c);
        }
        let mine = self
            .mine
            .as_ref()
            .map(|c| c.signing_seed())
            .unwrap_or([0u8; 32]);
        w.map(3)
            .uint(1)
            .bstr(&flat)
            .uint(2)
            .bool(self.mine.is_some())
            .uint(3)
            .bstr(&mine);
        w.finish()
    }

    /// Decode. `first_post_confirmed` is deliberately **not** stored: it is a
    /// session property, and restoring it would mean a node that restarted
    /// never asked again.
    pub fn decode(bytes: &[u8]) -> Option<Roster> {
        let mut r = cbor::Reader::new(bytes);
        let mut m = r.map().ok()?;
        if m.left() != 3 {
            return None;
        }
        let flat = bstr_at(&mut m, 1)?;
        if flat.len() % 32 != 0 || flat.len() / 32 > 4096 {
            return None;
        }
        let following = flat
            .chunks_exact(32)
            .map(|c| c.try_into().expect("32 bytes"))
            .collect();
        let has_mine = bool_at(&mut m, 2)?;
        let seed: [u8; 32] = bstr_at(&mut m, 3)?.try_into().ok()?;
        Some(Roster {
            following,
            mine: has_mine
                .then(|| Channel::from_key(krab_crypto::sign::SigningKey::from_seed(&seed))),
            first_post_confirmed: false,
        })
    }
}

fn at<'a>(m: &mut cbor::MapReader<'a, '_>, k: u64) -> Option<cbor::Item<'a>> {
    (m.key().ok()?? == k).then_some(())?;
    m.value().ok()
}

fn uint_at(m: &mut cbor::MapReader, k: u64) -> Option<u64> {
    match at(m, k)? {
        cbor::Item::Uint(v) => Some(v),
        _ => None,
    }
}

fn bool_at(m: &mut cbor::MapReader, k: u64) -> Option<bool> {
    match at(m, k)? {
        cbor::Item::Bool(v) => Some(v),
        _ => None,
    }
}

fn bstr_at<'a>(m: &mut cbor::MapReader<'a, '_>, k: u64) -> Option<&'a [u8]> {
    match at(m, k)? {
        cbor::Item::Bstr(b) => Some(b),
        _ => None,
    }
}

fn tstr_at<'a>(m: &mut cbor::MapReader<'a, '_>, k: u64) -> Option<&'a str> {
    match at(m, k)? {
        cbor::Item::Tstr(s) => Some(s),
        _ => None,
    }
}

/// A channel identifier, as an operator types and reads it.
pub fn short(id: &[u8; 32]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}", id[0], id[1], id[2], id[3])
}

#[cfg(test)]
mod tests {
    use super::*;
    use krab_crypto::rng::NotRandom;

    fn channel(seed: u64) -> Channel {
        Channel::create(&mut NotRandom::seeded(seed))
    }

    #[test]
    fn a_post_wraps_into_an_object_and_back() {
        let c = channel(1);
        let p = c.post(1, "text/plain", b"the meeting is moved");
        let (id, bytes) = into_object(&p, 1_000, 64_800).expect("it wraps");

        let header = RoutingHeader::parse(&bytes).expect("a header");
        assert_eq!(header.class, Class::Bulletin as u8);
        assert_eq!(header.tag, p.tag(), "not addressed to the channel");
        assert_eq!(id, krab_crypto::hash::object_id(&bytes));
        assert_eq!(
            bytes.len(),
            krab_core::object::BUCKETS[header.size_bucket as usize] as usize,
            "not padded to its bucket"
        );
        assert_eq!(from_object(&bytes), Some(p));
    }

    /// A post arrives by flooding from anyone, so an unverifying one must not
    /// be readable by forgetting to check.
    #[test]
    fn a_tampered_post_yields_nothing() {
        let c = channel(1);
        let p = c.post(1, "text/plain", b"original");
        let (_, mut bytes) = into_object(&p, 0, 100).expect("it wraps");
        bytes[ROUTING_HEADER_LEN + 30] ^= 0xff;
        assert_eq!(from_object(&bytes), None);
    }

    /// Only the key holder can post to a channel. That is the whole of RFC 6's
    /// authorisation model.
    #[test]
    fn a_post_signed_by_another_channel_does_not_verify_as_this_one() {
        let a = channel(1);
        let b = channel(2);
        let mut forged = a.post(1, "text/plain", b"not mine");
        let theirs = b.post(1, "text/plain", b"not mine");
        forged.sig = theirs.sig;
        assert!(!forged.verify());
        assert_ne!(a.id(), b.id());
    }

    /// Following is idempotent, and unfollowing does not erase history —
    /// RFC 3 §6.1 forbids a recall mechanism, and a selective one is worse.
    #[test]
    fn the_roster_follows_and_unfollows() {
        let mut r = Roster::default();
        let id = channel(1).id();
        assert!(r.follow(id));
        assert!(!r.follow(id), "following twice made two channels");
        assert!(r.follows(&id));
        assert!(r.unfollow(&id));
        assert!(!r.unfollow(&id));
        assert!(!r.follows(&id));
    }

    /// A node's own channel is one it follows without saying so.
    #[test]
    fn the_owned_channel_is_always_followed() {
        let c = channel(1);
        let id = c.id();
        let r = Roster {
            mine: Some(c),
            ..Default::default()
        };
        assert!(r.follows(&id));
    }

    #[test]
    fn a_roster_round_trips_including_the_posting_key() {
        let c = channel(1);
        let id = c.id();
        let r = Roster {
            following: vec![[7u8; 32], [8u8; 32]],
            mine: Some(c),
            first_post_confirmed: true,
        };
        let back = Roster::decode(&r.encode()).expect("decodes");
        assert_eq!(back.following, r.following);
        assert_eq!(back.mine.as_ref().map(|c| c.id()), Some(id));
        assert!(
            !back.first_post_confirmed,
            "the confirmation survived a restart — RFC 8 §4.2 wants it asked again"
        );
    }

    /// Nothing an attacker floods causes a panic, and nothing absurd is
    /// allocated on a declared count.
    #[test]
    fn malformed_input_is_refused_without_panicking() {
        assert_eq!(decode_post(&[]), None);
        assert!(Roster::decode(&[]).is_none());
        assert!(from_object(&[]).is_none());

        let c = channel(1);
        let good = encode_post(&c.post(1, "text/plain", b"x"));
        for cut in 0..good.len() {
            let _ = decode_post(&good[..cut]);
        }
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0xff;
            if let Some(p) = decode_post(&bad) {
                assert!(!p.verify() || p == decode_post(&good).unwrap());
            }
        }
    }

    /// A content type is a label. A reader that renders it must not be handed
    /// a document in that field.
    #[test]
    fn an_enormous_content_type_is_refused() {
        let c = channel(1);
        let p = c.post(1, &"x".repeat(65), b"payload");
        assert_eq!(decode_post(&encode_post(&p)), None);
    }
}
