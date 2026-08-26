//! `reach` — the path admission diagnostic, RFC 8 §5.2.
//!
//! > "Under partial coverage (RFC 0 §7.4) delivery failure is silent and a
//! > misconfigured link profile is indistinguishable from a peer ignoring you.
//! > `reach` is the only tool that separates them."
//!
//! That sentence is the whole justification. Krab has no delivery receipts and
//! no error path — RFC 0 §6 makes failure silent by design — so an operator
//! whose messages are not arriving has exactly two hypotheses and, without
//! this, no way to tell them apart. One is a five-second fix and the other is
//! a social problem.
//!
//! # Why it reports every path, including the ones that work
//!
//! The count line matters as much as the failures. "1 of 3 known paths admit
//! this message" tells an operator something "BLOCK: lora max_bucket 256" does
//! not: whether they are one misconfiguration away from no delivery at all.
//!
//! # It never says the message will arrive
//!
//! Admission is not delivery. A path that admits a message may still be a peer
//! who is offline for a month, and RFC 0 §6 means nobody will be told. The
//! verdict is `Admit`, not `Ok`, for that reason.

use krab_core::object::BUCKETS;
use krab_fabric::profile::LinkProfile;
use std::fmt;

/// Why a path will not carry a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    /// The object's size bucket exceeds the link's ceiling (RFC 4 §5.4).
    Bucket {
        /// The link's ceiling, in bytes.
        limit: u32,
        /// What the object needs, in bytes.
        needed: u32,
    },
    /// The link's shard mask excludes this tag (RFC 2 §6).
    Shard {
        /// Shard bits in force.
        k: u8,
        /// The tag's shard.
        shard: u64,
    },
    /// The link does not carry this object class (RFC 1 §4.1).
    Class(u8),
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Block::Bucket { limit, needed } => {
                write!(f, "max_bucket {limit} < {needed}")
            }
            Block::Shard { k, shard } => {
                write!(f, "shard mask {k} bits excludes 0x{shard:02X}")
            }
            Block::Class(c) => write!(f, "class {c} not carried"),
        }
    }
}

/// What a path does with a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The path will carry it.
    ///
    /// Named `Admit` rather than `Ok` on purpose: admission is not delivery,
    /// and a verb that reported "OK" would be making a promise the protocol
    /// explicitly does not make.
    Admit,
    /// The path will not.
    Block(Block),
}

/// One candidate path.
pub struct Path {
    /// Hops, as displayed — `a→b→q3m9`.
    pub hops: String,
    /// The profile of each link along it.
    pub links: Vec<LinkProfile>,
}

impl Path {
    /// Whether this path admits a message.
    ///
    /// A path is admitted only if **every** link admits it. The first blocking
    /// link is reported, because that is the one to fix.
    pub fn admits(&self, class: u8, size_bucket: u8, shard: u64) -> Verdict {
        for link in &self.links {
            if !link.max_bucket.admits(size_bucket) {
                return Verdict::Block(Block::Bucket {
                    limit: link.max_bucket.bytes(),
                    needed: bucket_bytes(size_bucket),
                });
            }
            if link.class_mask & (1u16 << class.min(15)) == 0 {
                return Verdict::Block(Block::Class(class));
            }
            if link.shard_k > 0 {
                let width = 1u64 << link.shard_k;
                if !shard.is_multiple_of(width) {
                    return Verdict::Block(Block::Shard {
                        k: link.shard_k,
                        shard,
                    });
                }
            }
        }
        Verdict::Admit
    }

    /// Rough transit estimate, seconds, summed over hops.
    pub fn estimate_secs(&self, size_bucket: u8) -> f64 {
        let bytes = bucket_bytes(size_bucket) as f64;
        self.links
            .iter()
            .map(|l| bytes / (l.sustained_bps / 8.0).max(1.0) / l.duty_cycle.max(0.01))
            .sum()
    }
}

/// Bytes in a size bucket, RFC 1 §8.1.
///
/// Six buckets in ×4 steps, not a doubling ladder — `krab_core` is the
/// authority and this defers to it rather than restating the numbers. An
/// earlier revision of this function invented `256·2ⁿ`, which agreed with the
/// real ladder at buckets 0 and 1 and diverged after; every object above 1 KB
/// would have been mis-sized, and the tests that only exercised small objects
/// passed.
pub fn bucket_bytes(bucket: u8) -> u32 {
    let i = (bucket as usize).min(BUCKETS.len() - 1);
    BUCKETS[i]
}

/// The number of buckets, RFC 1 §8.1.
pub const BUCKET_COUNT: u8 = BUCKETS.len() as u8;

/// The report `reach` prints.
pub struct Report {
    /// Every known path and what it does.
    pub paths: Vec<(String, Verdict, f64)>,
}

impl Report {
    /// Evaluate every path.
    pub fn of(paths: &[Path], class: u8, size_bucket: u8, shard: u64) -> Report {
        Report {
            paths: paths
                .iter()
                .map(|p| {
                    (
                        p.hops.clone(),
                        p.admits(class, size_bucket, shard),
                        p.estimate_secs(size_bucket),
                    )
                })
                .collect(),
        }
    }

    /// How many paths admit the message.
    pub fn admitting(&self) -> usize {
        self.paths
            .iter()
            .filter(|(_, v, _)| *v == Verdict::Admit)
            .count()
    }

    /// RFC 8 §5.2's rendering.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for (hops, verdict, est) in &self.paths {
            match verdict {
                Verdict::Admit => {
                    out.push_str(&format!("  via {hops:<16} ADMIT   est. {est:.0}s\n"));
                }
                Verdict::Block(b) => {
                    out.push_str(&format!("  via {hops:<16} BLOCK   {b}\n"));
                }
            }
        }
        out.push_str(&format!(
            "  {} of {} known paths admit this message",
            self.admitting(),
            self.paths.len()
        ));
        if self.admitting() == 0 && !self.paths.is_empty() {
            // The case the verb exists for. Say what it means, not just that
            // the number is zero.
            out.push_str(
                "\n\n  Nothing will carry this. Delivery failure is silent \
                 (RFC 0 §6), so no error will ever appear.",
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use krab_fabric::profile::MaxBucket;

    fn tcp_path(hops: &str) -> Path {
        Path {
            hops: hops.into(),
            links: vec![LinkProfile::tcp(), LinkProfile::tcp()],
        }
    }

    /// RFC 1 §8.1's ladder, deferred to `krab_core` rather than restated.
    #[test]
    fn bucket_sizes_follow_rfc1() {
        assert_eq!(bucket_bytes(0), 256);
        assert_eq!(bucket_bytes(1), 1_024);
        assert_eq!(bucket_bytes(2), 4_096);
        assert_eq!(bucket_bytes(5), 262_144);
        assert_eq!(BUCKET_COUNT, 6);
        // Out-of-range saturates rather than panicking or overflowing.
        assert_eq!(bucket_bytes(255), 262_144);
    }

    /// **The case the verb exists for.** A LoRa hop silently drops anything
    /// over its ceiling, and nothing else in the system will say so.
    #[test]
    fn a_constrained_hop_blocks_and_names_itself() {
        let p = Path {
            hops: "a→c→q3m9".into(),
            links: vec![LinkProfile::tcp(), LinkProfile::lora_sf10()],
        };
        // Bucket 2 is 4 096 bytes on RFC 1 §8.1's ×4 ladder.
        match p.admits(0, 2, 0) {
            Verdict::Block(Block::Bucket { limit, needed }) => {
                assert!(limit < needed, "{limit} should be below {needed}");
                assert_eq!(needed, 4_096);
            }
            other => panic!("expected a bucket block, got {other:?}"),
        }
        // And the same path carries a small object.
        assert_eq!(p.admits(0, 0, 0), Verdict::Admit);
    }

    /// A path is only as capable as its least capable hop.
    #[test]
    fn one_bad_hop_blocks_the_whole_path() {
        let good = tcp_path("a→b→q3m9");
        assert_eq!(good.admits(0, 2, 0), Verdict::Admit);

        let mut mixed = tcp_path("a→b→q3m9");
        mixed.links.push(LinkProfile::lora_sf10());
        assert_ne!(mixed.admits(0, 2, 0), Verdict::Admit);
    }

    /// RFC 2 §6 — a shard mask excludes traffic, and an operator who set `k`
    /// for load reasons needs to see that it is why nothing arrives.
    #[test]
    fn a_shard_mask_blocks_and_says_which_bits() {
        let mut link = LinkProfile::tcp();
        link.shard_k = 4;
        let p = Path {
            hops: "a→d→…".into(),
            links: vec![link],
        };
        match p.admits(0, 0, 0x3A) {
            Verdict::Block(Block::Shard { k, shard }) => {
                assert_eq!(k, 4);
                assert_eq!(shard, 0x3A);
            }
            other => panic!("expected a shard block, got {other:?}"),
        }
        // A tag inside the shard passes.
        assert_eq!(p.admits(0, 0, 0), Verdict::Admit);
    }

    #[test]
    fn a_class_the_link_does_not_carry_blocks() {
        let mut link = LinkProfile::tcp();
        link.class_mask = 0b0001; // class 0 only
        let p = Path {
            hops: "a→e".into(),
            links: vec![link],
        };
        assert_eq!(p.admits(0, 0, 0), Verdict::Admit);
        assert_eq!(p.admits(1, 0, 0), Verdict::Block(Block::Class(1)));
    }

    /// **The count line is the point.** RFC 8 §5.2's example ends with
    /// "1 of 3", which tells an operator how close they are to nothing.
    #[test]
    fn the_report_counts_admitting_paths() {
        let mut lora = tcp_path("a→c→q3m9");
        lora.links[1] = LinkProfile::lora_sf10();
        let paths = vec![tcp_path("a→b→q3m9"), lora, tcp_path("a→d→q3m9")];
        let r = Report::of(&paths, 0, 2, 0);
        assert_eq!(r.admitting(), 2);
        let text = r.render();
        assert!(text.contains("2 of 3 known paths admit"), "{text}");
        assert!(text.contains("BLOCK"), "{text}");
        assert!(text.contains("ADMIT"), "{text}");
    }

    /// **Zero admitting paths gets an explanation, not just a zero.** This is
    /// the state where the operator most needs to know that no error is coming.
    #[test]
    fn no_admitting_path_explains_that_failure_will_be_silent() {
        let mut p = tcp_path("a→c→q3m9");
        p.links[1] = LinkProfile::lora_sf10();
        let r = Report::of(&[p], 0, 5, 0);
        assert_eq!(r.admitting(), 0);
        let text = r.render();
        assert!(text.contains("0 of 1"), "{text}");
        assert!(
            text.contains("silent"),
            "the operator must learn no error is coming: {text}"
        );
    }

    /// The verdict is `ADMIT`, never `OK`: admission is not delivery, and the
    /// protocol makes no delivery promise.
    #[test]
    fn the_report_never_promises_delivery() {
        let r = Report::of(&[tcp_path("a→b")], 0, 0, 0);
        let text = r.render();
        assert!(text.contains("ADMIT"));
        for promise in ["will arrive", "delivered", "guaranteed", " OK "] {
            assert!(
                !text.contains(promise),
                "{text:?} promises delivery via {promise:?}"
            );
        }
    }

    #[test]
    fn an_empty_path_set_does_not_panic_or_mislead() {
        let r = Report::of(&[], 0, 0, 0);
        assert_eq!(r.admitting(), 0);
        let text = r.render();
        assert!(text.contains("0 of 0"), "{text}");
        assert!(
            !text.contains("silent"),
            "no paths is not the same as all blocked"
        );
    }

    #[test]
    fn a_slow_link_estimates_longer_than_a_fast_one() {
        let fast = tcp_path("a→b");
        let slow = Path {
            hops: "a→c".into(),
            links: vec![LinkProfile::lora_sf10()],
        };
        assert!(slow.estimate_secs(0) > fast.estimate_secs(0));
    }

    #[test]
    fn max_bucket_admits_up_to_its_ceiling() {
        let b = MaxBucket(2);
        assert!(b.admits(0) && b.admits(2));
        assert!(!b.admits(3));
    }
}
