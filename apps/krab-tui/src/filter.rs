//! The reconciliation filter — RFC 3 §7.3, RFC 5.
//!
//! ```text
//! filter = shard_mask ∩ size_cap ∩ class_mask ∩ retention_window
//! ```
//!
//! > "All four derive from the signed credential, so **both sides provably
//! > agree on the scope**. Reconciliation is scoped to the filter (RFC 5);
//! > anything else produces phantom divergence that recurs every cycle,
//! > permanently."
//!
//! # What was there before
//!
//! Every exchange passed `filter_digest = [0u8; 32]`.
//!
//! The digest was *checked* — `accept_manifest` refuses a mismatch, and so
//! does the RBSR descent — so the machinery worked correctly and compared two
//! constants. Two nodes with entirely different ideas of what an exchange
//! covered would agree, every time, because neither was saying anything.
//!
//! That was not an oversight so much as a dependency: §7.3 derives all four
//! components from the signed credential, and until RFC 3 §3's credential
//! existed there was nothing to derive them from. Now there is.
//!
//! # Both ends compute the same digest, or they do not reconcile
//!
//! A filter has to be a property of the **link**, not of either end, or the
//! two sides compute different digests and every exchange fails. So each
//! component is reduced to the value both parties can honour:
//!
//! | component | reduction | why |
//! |---|---|---|
//! | `shard_bits` | **larger** of the two | a shard mask narrows; the narrower end cannot serve what it does not hold |
//! | `max_bucket` | **smaller** | "a link is only as capable as its least capable end" (RFC 4 §5.4) |
//! | `class_mask` | the credential's, directly | one field, and both signed it |
//! | `retention_days` | **smaller** | a floor commitment neither end can exceed on the other's behalf |
//!
//! Three of the four are per-direction in the credential and are reduced here;
//! the fourth is already shared. None of it depends on who is initiating,
//! which is what makes the digests match.
//!
//! # A node with no credential does not reconcile with one that has it
//!
//! [`Filter::unscoped`] has its own digest, distinct from any real filter and
//! from zero. So a peering that has not completed `peer countersign` no longer
//! reconciles with one that has.
//!
//! That is a deliberate, breaking behaviour and it is the correct reading of
//! §7.3: a node citing a credential and a node citing nothing **do not agree
//! on the scope**, and the digest exists to say so before rows are trusted.
//! The alternative — falling back to zero — would restore exactly the vacuous
//! check this module was written to remove, and would do it silently.
//!
//! The repair is one command on each side.

use crate::credential::{Credential, LinkTerms};
use krab_core::cbor::Writer;
use krab_core::object::RoutingHeader;

/// Domain for the filter digest. Frozen.
pub const DOMAIN: &[u8] = b"krab/filter/v1";

/// The agreed scope of an exchange — RFC 3 §7.3's four components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Filter {
    /// RFC 2 §6. Zero means no sharding.
    pub shard_bits: u8,
    /// The largest size bucket that crosses, as an **index** into RFC 1
    /// §8.1's ladder — never a byte count, per RFC 4 §3.
    pub max_bucket: u8,
    /// Object classes admitted, one bit per class.
    pub class_mask: u8,
    /// How many days of history the link covers — RFC 3 §7.
    pub retention_days: u32,
}

impl Filter {
    /// The filter a credential implies.
    ///
    /// Direction-independent by construction: every reduction is symmetric in
    /// the two ends, so both compute the same value and therefore the same
    /// digest without exchanging anything.
    pub fn from_credential(c: &Credential) -> Filter {
        Filter::between(&c.terms_ab, &c.terms_ba, c.flags.class_mask)
    }

    /// The reduction, exposed so a test can drive it without a signature.
    pub fn between(a: &LinkTerms, b: &LinkTerms, class_mask: u8) -> Filter {
        Filter {
            // A shard mask narrows. The end holding 1/2^k cannot serve
            // outside it, so the link covers the narrower of the two.
            shard_bits: a.policy.shard_bits.max(b.policy.shard_bits),
            max_bucket: a.policy.max_bucket.min(b.policy.max_bucket),
            class_mask,
            retention_days: a.retention_days.min(b.retention_days),
        }
    }

    /// The scope of a link with no credential.
    ///
    /// **Not zero.** Zero is what every exchange sent before this module
    /// existed, and a fallback to it would quietly restore the check that
    /// compared two constants. This is a distinct value that means "no agreed
    /// scope", so a node holding it and a node holding a real filter refuse
    /// each other rather than agreeing by accident.
    pub fn unscoped() -> Filter {
        Filter {
            shard_bits: 0,
            max_bucket: u8::MAX,
            class_mask: 0xFF,
            retention_days: 0,
        }
    }

    /// Whether this filter is the unscoped one.
    pub fn is_unscoped(&self) -> bool {
        *self == Filter::unscoped()
    }

    /// The digest both sides compare — RFC 5's `Manifest` field.
    ///
    /// Domain-separated, like every other hash in the series, so a filter
    /// digest can never coincide with an object identifier or a node id.
    pub fn digest(&self) -> [u8; 32] {
        let mut w = Writer::new();
        w.map(4)
            .uint(1)
            .uint(self.shard_bits as u64)
            .uint(2)
            .uint(self.max_bucket as u64)
            .uint(3)
            .uint(self.class_mask as u64)
            .uint(4)
            .uint(self.retention_days as u64);
        krab_crypto::hash::domain_hash(DOMAIN, &w.finish())
    }

    /// Whether an object is inside the agreed scope.
    ///
    /// **The digest is agreement; this is enforcement.** They are separate on
    /// purpose: a peer that agrees to a filter and then offers rows outside it
    /// is not caught by a matching digest, and RFC 3 §6.1's whole model is
    /// that a peer is held to what it signed rather than trusted to honour it.
    pub fn admits(&self, header: &RoutingHeader, now_min: u32) -> bool {
        if self.is_unscoped() {
            return true;
        }
        if header.size_bucket > self.max_bucket {
            return false;
        }
        if self.class_mask & (1u8 << (header.class & 7)) == 0 {
            return false;
        }
        // The retention window, evaluated against the object rather than
        // against arrival: RFC 3 §7 makes it "a duration evaluated against
        // object creation time, so it is stable under the clock drift a
        // courier network will have."
        if self.retention_days > 0 {
            let horizon = now_min.saturating_add(self.retention_days.saturating_mul(1_440));
            if header.expiry_min > horizon {
                return false;
            }
        }
        // Sharding is over the tag, RFC 2 §6: the low `k` bits select which
        // fraction of the corpus this link carries.
        if self.shard_bits > 0 {
            let k = self.shard_bits.min(63);
            let tag = u64::from_le_bytes(header.tag.0);
            if tag & ((1u64 << k) - 1) != 0 {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::Credential;
    use crate::identity::Identity;
    use crate::peering::Policy;
    use krab_core::object::Tag;
    use krab_crypto::rng::NotRandom;

    const NOW: u64 = 1_800_000_000;
    const NOW_MIN: u32 = 29_766_000;

    fn terms(shard: u8, bucket: u8, days: u32) -> LinkTerms {
        LinkTerms {
            policy: Policy {
                shard_bits: shard,
                max_bucket: bucket,
                ..Policy::default()
            },
            retention_days: days,
            ..LinkTerms::default()
        }
    }

    fn header(class: u8, bucket: u8, expiry: u32, tag: u64) -> RoutingHeader {
        RoutingHeader {
            version: 1,
            class,
            size_bucket: bucket,
            flags: 0,
            expiry_min: expiry,
            tag: Tag(tag.to_le_bytes()),
        }
    }

    /// **Both ends compute the same digest**, whichever way the credential was
    /// assembled. If this fails, every exchange fails and the symptom is "the
    /// exchange did not complete".
    #[test]
    fn the_digest_does_not_depend_on_direction() {
        let a = terms(2, 5, 30);
        let b = terms(0, 3, 45);
        assert_eq!(
            Filter::between(&a, &b, 0xFF),
            Filter::between(&b, &a, 0xFF),
            "the reduction is not symmetric"
        );
        assert_eq!(
            Filter::between(&a, &b, 0xFF).digest(),
            Filter::between(&b, &a, 0xFF).digest()
        );
    }

    /// Each component reduces to what both ends can honour — RFC 3 §7.3.
    #[test]
    fn each_component_reduces_to_what_both_ends_can_honour() {
        let f = Filter::between(&terms(2, 5, 30), &terms(0, 3, 45), 0x0F);
        assert_eq!(f.shard_bits, 2, "the narrower shard governs");
        assert_eq!(f.max_bucket, 3, "the least capable end governs");
        assert_eq!(f.retention_days, 30, "the shorter floor governs");
        assert_eq!(f.class_mask, 0x0F);
    }

    /// **The unscoped filter is not zero.** A fallback to the old constant
    /// would restore a check that compared two constants, silently.
    #[test]
    fn an_unscoped_filter_is_distinguishable_from_everything() {
        let unscoped = Filter::unscoped();
        assert_ne!(unscoped.digest(), [0u8; 32]);
        assert!(unscoped.is_unscoped());

        let real = Filter::between(&terms(0, 5, 45), &terms(0, 5, 45), 0xFF);
        assert!(!real.is_unscoped());
        assert_ne!(
            real.digest(),
            unscoped.digest(),
            "a credentialled node and an uncredentialled one must not agree"
        );
    }

    /// Different filters, different digests — every component participates.
    #[test]
    fn every_component_changes_the_digest() {
        let base = Filter::between(&terms(1, 4, 20), &terms(1, 4, 20), 0xFF);
        for other in [
            Filter {
                shard_bits: 2,
                ..base
            },
            Filter {
                max_bucket: 3,
                ..base
            },
            Filter {
                class_mask: 0x0F,
                ..base
            },
            Filter {
                retention_days: 19,
                ..base
            },
        ] {
            assert_ne!(base.digest(), other.digest(), "{other:?} shares a digest");
        }
    }

    /// **Agreement is not enforcement.** A peer that signed a filter and then
    /// offers rows outside it is not caught by a matching digest.
    #[test]
    fn the_filter_admits_only_what_was_agreed() {
        let f = Filter {
            shard_bits: 0,
            max_bucket: 3,
            class_mask: 0b0000_0011,
            retention_days: 10,
        };
        assert!(f.admits(&header(0, 3, NOW_MIN + 1_000, 0), NOW_MIN));
        assert!(
            !f.admits(&header(0, 4, NOW_MIN + 1_000, 0), NOW_MIN),
            "bucket"
        );
        assert!(
            !f.admits(&header(3, 3, NOW_MIN + 1_000, 0), NOW_MIN),
            "class"
        );
        assert!(
            !f.admits(&header(0, 3, NOW_MIN + 11 * 1_440, 0), NOW_MIN),
            "beyond the retention window"
        );
    }

    /// Sharding selects a fraction of the corpus by tag — RFC 2 §6.
    #[test]
    fn sharding_selects_a_fraction_by_tag() {
        let f = Filter {
            shard_bits: 2,
            max_bucket: 5,
            class_mask: 0xFF,
            retention_days: 45,
        };
        let admitted = (0u64..64)
            .filter(|t| f.admits(&header(0, 0, NOW_MIN + 10, *t), NOW_MIN))
            .count();
        assert_eq!(admitted, 16, "a 2-bit shard is one quarter");
    }

    /// The unscoped filter admits everything, which is what "no agreed scope"
    /// has to mean for a link that has not got one yet.
    #[test]
    fn an_unscoped_filter_admits_everything() {
        let f = Filter::unscoped();
        for class in 0u8..4 {
            for bucket in 0u8..6 {
                assert!(f.admits(&header(class, bucket, u32::MAX, 7), NOW_MIN));
            }
        }
    }

    /// A real credential produces a real filter, and two nodes reading the
    /// same credential produce the same digest.
    #[test]
    fn a_credential_yields_a_filter_both_ends_agree_on() {
        let x = Identity::generate(&mut NotRandom::seeded(1));
        let y = Identity::generate(&mut NotRandom::seeded(2));
        let mut c = Credential::propose(
            x.signing_key(),
            &x.card(Policy::default()),
            &y.card(Policy::default()),
            NOW,
            crate::credential::DEFAULT_TERM_DAYS,
            [4u8; 16],
        );
        assert!(c.sign(y.signing_key()));

        let f = Filter::from_credential(&c);
        assert!(!f.is_unscoped(), "a credential must scope something");
        assert_eq!(f.retention_days, krab_core::tag::MAX_TTL_DAYS);

        // Decoded on the far end, the same document gives the same digest.
        let back = Credential::decode(&c.encode()).expect("decodes");
        assert_eq!(Filter::from_credential(&back).digest(), f.digest());
    }
}
