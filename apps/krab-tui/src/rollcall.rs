//! The public rollcall — RFC 3 §9.
//!
//! > "The optional public tier. **Opt-in; a node that never publishes an entry
//! > is invisible to it and reachable only through hand-exchanged
//! > credentials.** That MUST be the default."
//!
//! There is no coordinator, no hierarchy and no hosted file. "The rollcall" is
//! the set of live self-attestations sitting in the corpus, and it works for
//! the same reason prekey batches and channels do: a `Class::Bulletin` object
//! is public, signed and flooded, so a directory needs no server to host it.
//!
//! # A directory of nodes, never of links
//!
//! RFC 3 §9.1 draws the line the whole tier rests on:
//!
//! > "A directory of *nodes* is a public key directory. A directory of *links*
//! > is the social graph. The first is safe; the second undoes the design."
//!
//! So an entry carries what a stranger needs in order to *offer* a peering —
//! keys, and the terms under which an offer would be worth making — and
//! nothing that says who this node already talks to.
//!
//! [`Entry`] is that rule as a type. It has no field for a peer-link, for a
//! peer count, for an operator name, or for free text, so publishing one is
//! not a matter of remembering to leave them out. `artifact::Artifact` exists
//! for the same reason and after two failures of the same shape: a rule
//! enforced by a list is a rule enforced only over what was on the list when
//! someone last thought about it.
//!
//! # And no endpoints, ever
//!
//! RFC 3 §9.2 is separate from §9.1 and stricter: an entry carries **no
//! reachability information at all**. Not an address, not a port, not a
//! transport name, not an onion.
//!
//! This is not a mitigation of the stable-network-pseudonym problem, it
//! removes it: there is nothing to correlate across appearances. Peer-requests
//! travel through the corpus (RFC 3 §5.1), so nothing about being reachable is
//! needed in order to *be reached*, and endpoints are exchanged inside the
//! signed credential afterwards, with the counterparty alone.
//!
//! It buys a second property that is easy to undervalue: the peering flow is
//! byte-identical for a node on fibre, a node on LoRa, and a node reachable
//! only by courier. **No transport-specific path exists in the most
//! security-sensitive part of the protocol** — so there is no branch there to
//! get wrong, and no way to tell those three nodes apart by watching one.
//!
//! # Withdrawal is expiry, because recall is censorship
//!
//! There is no unpublish. RFC 3 §6.1 forbids a recall mechanism permanently,
//! on the grounds that a recall mechanism is a censorship mechanism and cannot
//! be made selective. An entry therefore carries a short TTL — [`TTL_MINUTES`]
//! — and withdrawing means declining to republish, after which it is gone
//! within a week by the same rule that removes everything else.
//!
//! Stale entries vanish with no revocation mechanism, which is the property
//! the short TTL is bought for.
//!
//! # Coverage is permitted and is not published
//!
//! RFC 3 §9.1 lists coverage (RFC 0 §7.4) among what an entry *may* carry.
//! This omits it, deliberately, for two reasons that point the same way.
//!
//! A single coverage percentage is **misleading**, and this codebase already
//! says so: `krab_node::metrics::Coverage` is an eight-bucket age profile
//! rather than a scalar because SIM-1 §2 measured a 37% aggregate concealing a
//! 3%-to-82% ramp — "the mean describes no node's actual holding probability
//! for any object". Publishing the scalar would reintroduce exactly the figure
//! that type was built to prevent anyone quoting.
//!
//! Publishing the *profile* instead would be worse. Eight fractions are a
//! strong fingerprint, and a rollcall entry is the one artifact this node
//! deliberately hands to strangers: it is what an observer would use to decide
//! which observed corpus belongs to which listed key. §9.1's "may" is doing
//! real work, and the answer here is no.
//!
//! The watermark is published because §9.1 permits it *and* because a peer
//! genuinely needs it before offering — it is the difference between a node
//! that can close their gap and one that cannot. One coarse number for a
//! decision that would otherwise be made blind is a trade worth making; a
//! holdings profile for no decision at all is not.

use krab_core::cbor;

/// How long an entry lives — RFC 3 §9.1's "expiring in ~7 days".
///
/// Short on purpose. It is what makes a stale entry disappear on its own, and
/// it is the only withdrawal mechanism there is.
pub const TTL_MINUTES: u32 = 7 * 1_440;

/// Republish this many minutes before expiry.
///
/// An entry that is republished only once it has already lapsed leaves the
/// node briefly absent from the directory for no reason. Two days of overlap
/// costs one extra object a week.
pub const REPUBLISH_BEFORE: u32 = 2 * 1_440;

/// A self-signed rollcall entry — RFC 3 §9.1.
///
/// # What is not here, and why it is not here
///
/// The author's `sig_pk` is the enclosing [`crate::bulletin::Bulletin`]'s
/// `author` field, and the node id is derived from it, so neither is repeated.
///
/// Everything RFC 3 §9.1's right-hand column forbids is absent by
/// construction: no peer-link, no peer count, no statement that this node
/// peers with anyone, no operator identity, no free text, no address. A future
/// field that would carry any of them has to be added here, in a type whose
/// whole documented purpose is that it does not have one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The correspondence key — RFC 1 §6.1.
    ///
    /// What a stranger encapsulates to when sending the peer-request that
    /// starts a peering. Publishing it is the point of the tier.
    pub kx_pk: [u8; 32],
    /// Largest size bucket accepted, as an **index** into RFC 1 §8.1's ladder.
    ///
    /// Never a byte count: RFC 4 §3's gate-between-buckets error is
    /// unrepresentable when the value is an index, and this one travels
    /// between implementations that cannot ask each other what they meant.
    pub max_bucket: u8,
    /// Shard bits — RFC 2 §6. Zero means no sharding.
    pub shard_bits: u8,
    /// Whether this node relays for others.
    ///
    /// A capability, not a link: it says what this node does for strangers,
    /// which is exactly what a stranger deciding whether to offer needs.
    pub relay: bool,
    /// The corpus watermark — the oldest expiry still held (RFC 5 §3).
    ///
    /// Published so a peer can tell *before* offering whether this node could
    /// close its gap at all. Permitted explicitly by §9.1.
    pub watermark: u32,
}

impl Entry {
    /// Encode for a bulletin payload. Deterministic CBOR — RFC 1 §4.3.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = cbor::Writer::new();
        w.map(5)
            .uint(1)
            .bstr(&self.kx_pk)
            .uint(2)
            .uint(self.max_bucket as u64)
            .uint(3)
            .uint(self.shard_bits as u64)
            .uint(4)
            .uint(u64::from(self.relay))
            .uint(5)
            .uint(self.watermark as u64);
        w.finish()
    }

    /// Decode.
    ///
    /// **Pre-authentication input.** A rollcall entry arrives by flooding from
    /// anyone at all — that is more true here than for any other bulletin,
    /// since the tier's entire purpose is being read by strangers. Nothing
    /// here allocates on a declared count or trusts a declared length.
    ///
    /// Out-of-range values are refused rather than clamped. A `max_bucket`
    /// naming no bucket is a term two implementations could read differently,
    /// and silently repairing it would hide a peer that disagrees with this
    /// one about the ladder.
    pub fn decode(bytes: &[u8]) -> Option<Entry> {
        let mut r = cbor::Reader::new(bytes);
        let mut m = r.map().ok()?;
        if m.left() != 5 {
            return None;
        }
        let kx_pk: [u8; 32] = bstr_at(&mut m, 1)?.try_into().ok()?;
        let max_bucket = u8::try_from(uint_at(&mut m, 2)?).ok()?;
        let shard_bits = u8::try_from(uint_at(&mut m, 3)?).ok()?;
        let relay = match uint_at(&mut m, 4)? {
            0 => false,
            1 => true,
            // Not a boolean. Anything else is a peer encoding something this
            // version does not know it is agreeing to.
            _ => return None,
        };
        let watermark = u32::try_from(uint_at(&mut m, 5)?).ok()?;

        if max_bucket as usize >= krab_core::object::BUCKETS.len() {
            return None;
        }
        Some(Entry {
            kx_pk,
            max_bucket,
            shard_bits,
            relay,
            watermark,
        })
    }

    /// One line, for the directory listing.
    pub fn summary(&self) -> String {
        format!(
            "{relay}, buckets to {bytes} B, {shard}, holds back to minute {wm}",
            relay = if self.relay { "relays" } else { "leaf" },
            bytes = krab_core::object::BUCKETS[self.max_bucket as usize],
            shard = if self.shard_bits == 0 {
                "unsharded".to_string()
            } else {
                format!("1/{} shard", 1u32 << self.shard_bits)
            },
            wm = self.watermark,
        )
    }
}

/// Whether this node publishes an entry.
///
/// **`false` is the default and RFC 3 §9 requires that it be**, so this is a
/// plain `bool` with a `Default` rather than anything cleverer: the failure to
/// avoid is a node that ends up listed without its operator having said so,
/// and every mechanism that could produce it starts with a default that is not
/// this one.
///
/// `NO-CONFIG.md` matters here too. There is no settings file that could carry
/// an opt-in across a restart unnoticed — publishing is a command the operator
/// types, and a node that is restarted and never told to publish does not.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Listing {
    /// Whether `rollcall publish` has been run in this session.
    pub publishing: bool,
    /// The epoch of the entry last published, if any.
    pub last_epoch: Option<u32>,
}

impl Listing {
    /// Whether an entry should be published now.
    ///
    /// Only ever true once the operator has opted in. The second condition is
    /// the refresh: an entry expires after [`TTL_MINUTES`], so it is renewed
    /// [`REPUBLISH_BEFORE`] minutes ahead of that rather than after it lapses.
    pub fn due(&self, now_min: u32) -> bool {
        if !self.publishing {
            return false;
        }
        match self.last_epoch {
            None => true,
            Some(e) => {
                let published_at = e.saturating_mul(1_440);
                now_min.saturating_sub(published_at) >= TTL_MINUTES - REPUBLISH_BEFORE
            }
        }
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

fn bstr_at<'a>(m: &mut cbor::MapReader<'a, '_>, k: u64) -> Option<&'a [u8]> {
    match at(m, k)? {
        cbor::Item::Bstr(b) => Some(b),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bulletin::{self, Bulletin, Kind};
    use krab_crypto::rng::NotRandom;
    use krab_crypto::sign::SigningKey;

    fn entry() -> Entry {
        Entry {
            kx_pk: [7u8; 32],
            max_bucket: 5,
            shard_bits: 0,
            relay: true,
            watermark: 29_766_000,
        }
    }

    #[test]
    fn an_entry_round_trips() {
        let e = entry();
        assert_eq!(Entry::decode(&e.encode()), Some(e));
    }

    /// **The entry carries no reachability information** — RFC 3 §9.2.
    ///
    /// Encoded and searched for the bytes of every kind of endpoint this
    /// codebase can produce. The type has no field to hold one, so this cannot
    /// fail today; it is here for the revision that adds a field and does not
    /// re-read §9.2, which is how every other omission in this tree happened.
    #[test]
    fn nothing_reachable_survives_into_the_encoding() {
        let e = entry();
        let bytes = e.encode();
        for endpoint in [
            "127.0.0.1:40000",
            "10.0.0.1",
            "example.onion",
            "/dev/ttyUSB0",
            "tcp",
            "lora",
        ] {
            assert!(
                !bytes
                    .windows(endpoint.len())
                    .any(|w| w == endpoint.as_bytes()),
                "an endpoint reached the encoding: {endpoint}"
            );
        }
        // And the whole payload is small enough that there is nowhere for one
        // to hide: six fixed fields, one of which is a 32-byte key.
        assert!(bytes.len() < 64, "the payload grew: {} bytes", bytes.len());
    }

    /// **Opt-in is the default, and RFC 3 §9 says it MUST be.**
    #[test]
    fn a_fresh_node_publishes_nothing() {
        let l = Listing::default();
        assert!(!l.publishing);
        assert!(!l.due(0), "a node nobody opted in for is listed");
        assert!(!l.due(u32::MAX), "and time alone does not opt it in");
    }

    /// Once opted in, an entry is published and then refreshed **before** it
    /// lapses — an entry renewed after expiry leaves a gap for no reason.
    #[test]
    fn an_opted_in_node_republishes_before_it_expires() {
        let mut l = Listing {
            publishing: true,
            last_epoch: None,
        };
        assert!(l.due(0), "the first publication is due immediately");

        let day = 20_671u32; // an ordinary epoch
        l.last_epoch = Some(day);
        let published_at = day * 1_440;
        assert!(!l.due(published_at), "republished on the spot");
        assert!(!l.due(published_at + 4 * 1_440), "too early");
        assert!(
            l.due(published_at + (TTL_MINUTES - REPUBLISH_BEFORE)),
            "not renewed before it lapses"
        );
        assert!(l.due(published_at + TTL_MINUTES), "and certainly by expiry");
    }

    /// Withdrawal stops republication. There is no recall — RFC 3 §6.1 — so
    /// the published entry stands until it expires, and the code must not
    /// pretend otherwise by, say, clearing `last_epoch`.
    #[test]
    fn withdrawing_stops_republication_without_recalling_anything() {
        let l = Listing {
            publishing: false,
            last_epoch: Some(20_671),
        };
        assert!(!l.due(u32::MAX));
        assert_eq!(
            l.last_epoch,
            Some(20_671),
            "the record of what is out there"
        );
    }

    /// **RFC 3 §9.1 says 153 bytes "computed". This produces 160.**
    ///
    /// Pinned rather than reconciled, because it cannot be reconciled: §9.1
    /// gives the number and not the field list it came from, so there is no
    /// way to tell whether 153 omits the watermark, packs the capability bits
    /// differently, or assumed a shorter signature envelope.
    /// `krab_sizes::creds`'s own header says the same of RFC 3 §3's credential
    /// figures — "cannot be recomputed from the document … taken here as
    /// stated inputs".
    ///
    /// This is `AMENDMENTS.md`'s recurring shape: a figure that reads as
    /// normative, that two implementations can satisfy differently, and where
    /// neither would ever discover the disagreement — a rollcall entry is
    /// self-describing CBOR, so a peer reads a 160-byte one perfectly well and
    /// nothing anywhere reports a size mismatch.
    ///
    /// So the test asserts what this implementation emits. If a future change
    /// alters it, that is a decision someone makes here rather than a drift
    /// nobody sees.
    #[test]
    fn the_entry_is_the_size_this_implementation_says_it_is() {
        let k = SigningKey::generate(&mut NotRandom::seeded(1));
        let b = Bulletin::create(Kind::Rollcall, &k, 20_671, entry().encode());
        assert_eq!(entry().encode().len(), 48, "the payload");
        assert_eq!(
            b.encode().len(),
            160,
            "the signed entry — RFC 3 §9.1 states 153, underivably"
        );
        // And it fits an object comfortably, which is the property that
        // actually matters: an entry that needed splitting could not flood as
        // one bulletin, and §9 describes no way to split one.
        let (_, obj) = bulletin::into_object(&b, 0, TTL_MINUTES).expect("wraps");
        assert_eq!(obj.len(), 256, "the smallest bucket that holds it");
    }

    /// An entry is a bulletin like any other, and its signature is checked
    /// against the author's key by `from_object` before a reader sees it.
    #[test]
    fn an_entry_travels_as_a_signed_bulletin() {
        let k = SigningKey::generate(&mut NotRandom::seeded(1));
        let e = entry();
        let b = Bulletin::create(Kind::Rollcall, &k, 20_671, e.encode());
        let (_, bytes) = bulletin::into_object(&b, 20_671 * 1_440, TTL_MINUTES).expect("wraps");

        let back = bulletin::from_object(&bytes).expect("verifies");
        assert_eq!(back.kind, Kind::Rollcall);
        assert_eq!(Entry::decode(&back.payload), Some(e));

        // ~7 days, per §9.1.
        let h = krab_core::object::RoutingHeader::parse(&bytes).expect("header");
        assert_eq!(h.expiry_min, 20_671 * 1_440 + 7 * 1_440);
    }

    /// **A rollcall signature must not verify as any other kind.** Without a
    /// distinct domain, an entry could be replayed as a channel post by the
    /// same author, or a post as an entry — and an entry is the one bulletin
    /// strangers are invited to act on.
    #[test]
    fn a_rollcall_signature_does_not_verify_as_another_kind() {
        let k = SigningKey::generate(&mut NotRandom::seeded(1));
        let real = Bulletin::create(Kind::Rollcall, &k, 20_671, entry().encode());
        assert!(real.verify());
        for kind in [Kind::Prekeys, Kind::Post, Kind::Roster] {
            let forged = Bulletin {
                kind,
                ..real.clone()
            };
            assert!(!forged.verify(), "{kind:?} accepted a rollcall signature");
        }
    }

    /// Flooded from anyone. Nothing here may panic, and nothing out of range
    /// may be quietly repaired into something plausible.
    #[test]
    fn malformed_entries_are_refused_without_panicking() {
        assert_eq!(Entry::decode(&[]), None);
        assert_eq!(Entry::decode(&[0xa5]), None);
        let mut runaway = vec![0xa5, 0x01, 0x5a];
        runaway.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(Entry::decode(&runaway), None);

        let good = entry().encode();
        for cut in 0..good.len() {
            let _ = Entry::decode(&good[..cut]);
        }
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0xff;
            let _ = Entry::decode(&bad);
        }
    }

    /// A `max_bucket` naming no bucket is refused, not clamped — the same
    /// error `Policy::default` documents, in a field that travels between
    /// implementations which cannot ask each other what they meant.
    #[test]
    fn a_bucket_index_naming_no_bucket_is_refused() {
        let mut e = entry();
        e.max_bucket = krab_core::object::BUCKETS.len() as u8;
        assert_eq!(Entry::decode(&e.encode()), None);

        e.max_bucket = (krab_core::object::BUCKETS.len() - 1) as u8;
        assert!(Entry::decode(&e.encode()).is_some());
    }

    /// `relay` is a boolean on the wire. A third value would be a peer
    /// encoding a capability this version does not know it is agreeing to.
    #[test]
    fn a_relay_flag_that_is_not_a_boolean_is_refused() {
        let mut w = cbor::Writer::new();
        w.map(5)
            .uint(1)
            .bstr(&[7u8; 32])
            .uint(2)
            .uint(5)
            .uint(3)
            .uint(0)
            .uint(4)
            .uint(2)
            .uint(5)
            .uint(29_766_000);
        assert_eq!(Entry::decode(&w.finish()), None);
    }

    /// The summary names the terms a stranger is deciding on, and says nothing
    /// about who this node peers with — there is nothing in the type that
    /// could.
    #[test]
    fn the_summary_describes_terms_and_not_relationships() {
        let s = entry().summary();
        assert!(s.contains("relays"), "{s}");
        assert!(s.contains("unsharded"), "{s}");
        let leaf = Entry {
            relay: false,
            shard_bits: 3,
            ..entry()
        };
        assert!(leaf.summary().contains("leaf"));
        assert!(leaf.summary().contains("1/8 shard"));
    }
}
