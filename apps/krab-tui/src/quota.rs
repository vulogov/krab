//! Per-link byte and object budgets — RFC 3 §6.
//!
//! > "This is the central mechanism of this document."
//!
//! # Why a budget and not attribution
//!
//! RFC 0 §5 requires that message origination be unattributable, so a peer
//! **cannot** distinguish "this node is relaying the corpus, as designed" from
//! "this node is flooding" by inspecting traffic. §6.1 draws the only
//! conclusion available:
//!
//! > "Accountability is therefore a **byte and object budget on the link**,
//! > regardless of who originated anything. Exceed it and you are throttled,
//! > then reduced, then cut. You then allocate your own budget between your
//! > traffic and your relaying, which creates back-pressure that propagates
//! > outward through the graph without anyone learning anything."
//!
//! So this counts bytes and objects arriving on a link and nothing else. It
//! does not know who sent what, when any particular object arrived, or what
//! any of them were — §12 forbids per-object provenance outright, because
//! "arrival timestamps and per-object attribution are a forensic
//! reconstruction of the graph and its timing gradients, sitting on disk,
//! waiting for seizure."
//!
//! Two counters and a day number. That is the whole record.
//!
//! # Why it is stored
//!
//! A budget that resets when the process restarts is not a budget. It is also
//! not much of a leak: the pair `(bytes, objects, day)` says how much crossed
//! a link this window and nothing about what or from whom.
//!
//! It is sealed under `W_N` anyway, and shredded by `wipe`, because it is
//! *per peer* — the file's existence names a peering, which is the disclosure
//! RFC 3 §8.4 says to purge on termination.
//!
//! # Disconnection is the limit case, not the mechanism
//!
//! §6.2: "Quota SHOULD drift upward toward an operator-set ceiling while
//! behaviour is good, and drop sharply on violation … **Continuous,
//! proportionate, reversible**, and it does not require a human awake at
//! 03:00."
//!
//! Exceeding a budget stops objects being accepted for the rest of the window.
//! It does not close the session, drop the peering, or raise anything the
//! operator has to answer. RFC 0 I-4 makes an unreachable peer normal; a
//! throttled one is normaller still.

use krab_core::cbor::{Item, Reader, Writer};

/// A day, as whole days since the Unix epoch.
///
/// The window RFC 3 §6 measures against. Whole days rather than a rolling
/// window because a rolling one needs timestamps to roll, and timestamps per
/// arrival are what §12 forbids.
pub fn day_of(now_s: u64) -> u32 {
    (now_s / 86_400) as u32
}

/// What has crossed a link today.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Spend {
    /// The day these counters are for. A different day resets them.
    pub day: u32,
    /// Bytes accepted from the peer.
    pub bytes: u64,
    /// Objects accepted from the peer.
    pub objects: u64,
}

impl Spend {
    /// Roll into `day` if the counters are for an earlier one.
    ///
    /// **Only forward.** A peer whose clock — or whose lying — puts the day
    /// in the past must not reset a budget it has already spent; nothing here
    /// takes a day number from the wire, but the guard costs one comparison
    /// and removes the question.
    pub fn roll(&mut self, day: u32) {
        if day > self.day {
            *self = Spend {
                day,
                bytes: 0,
                objects: 0,
            };
        }
    }

    /// Whether one more object of `len` bytes is within budget.
    pub fn admits(&self, len: usize, bytes_per_day: u64, objects_per_day: u64) -> bool {
        self.objects < objects_per_day && self.bytes.saturating_add(len as u64) <= bytes_per_day
    }

    /// Record an accepted object.
    pub fn charge(&mut self, len: usize) {
        self.bytes = self.bytes.saturating_add(len as u64);
        self.objects = self.objects.saturating_add(1);
    }

    /// How much of the budget is gone, as a percentage, for the operator
    /// panel. Saturates at 100 rather than reporting an overspend that cannot
    /// happen.
    pub fn used_percent(&self, bytes_per_day: u64, objects_per_day: u64) -> u8 {
        let by_bytes = pct(self.bytes, bytes_per_day);
        let by_objects = pct(self.objects, objects_per_day);
        by_bytes.max(by_objects)
    }

    /// Deterministic CBOR, for sealed storage.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.map(3)
            .uint(1)
            .uint(self.day as u64)
            .uint(2)
            .uint(self.bytes)
            .uint(3)
            .uint(self.objects);
        w.finish()
    }

    /// Decode. This is the node's own storage, but a corrupt file must not
    /// panic and must not read as **less** spent than was stored — so anything
    /// malformed yields nothing, and the caller starts a fresh window rather
    /// than an emptied one.
    pub fn decode(bytes: &[u8]) -> Option<Spend> {
        let mut r = Reader::new(bytes);
        let mut m = r.map().ok()?;
        if m.left() != 3 {
            return None;
        }
        let day = match (m.key().ok()??, m.value().ok()?) {
            (1, Item::Uint(v)) => u32::try_from(v).ok()?,
            _ => return None,
        };
        let b = match (m.key().ok()??, m.value().ok()?) {
            (2, Item::Uint(v)) => v,
            _ => return None,
        };
        let o = match (m.key().ok()??, m.value().ok()?) {
            (3, Item::Uint(v)) => v,
            _ => return None,
        };
        Some(Spend {
            day,
            bytes: b,
            objects: o,
        })
    }
}

fn pct(spent: u64, ceiling: u64) -> u8 {
    if ceiling == 0 {
        return 100;
    }
    ((spent.saturating_mul(100) / ceiling).min(100)) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 86_400;
    const NOW: u64 = 1_800_000_000;

    #[test]
    fn a_budget_admits_until_it_is_spent() {
        let mut s = Spend {
            day: day_of(NOW),
            ..Spend::default()
        };
        assert!(s.admits(100, 1_000, 10));
        for _ in 0..10 {
            assert!(s.admits(100, 1_000, 10));
            s.charge(100);
        }
        assert_eq!(s.bytes, 1_000);
        assert_eq!(s.objects, 10);
        assert!(!s.admits(1, 1_000, 10), "the budget did not stop anything");
    }

    /// Either ceiling stops it. §6.1 names both, and a byte budget alone lets
    /// a peer spend a link on a million empty objects.
    #[test]
    fn either_ceiling_stops_it() {
        let by_objects = Spend {
            day: 0,
            bytes: 0,
            objects: 10,
        };
        assert!(!by_objects.admits(1, u64::MAX, 10));

        let by_bytes = Spend {
            day: 0,
            bytes: 1_000,
            objects: 0,
        };
        assert!(!by_bytes.admits(1, 1_000, u64::MAX));
    }

    /// An object that would cross the ceiling is refused whole. Half an object
    /// is not a thing the corpus can hold.
    #[test]
    fn an_object_that_would_overshoot_is_refused_whole() {
        let s = Spend {
            day: 0,
            bytes: 900,
            objects: 0,
        };
        assert!(!s.admits(101, 1_000, u64::MAX));
        assert!(s.admits(100, 1_000, u64::MAX));
    }

    /// The window rolls, and **only forward**.
    #[test]
    fn the_window_rolls_forward_and_never_back() {
        let mut s = Spend {
            day: day_of(NOW),
            bytes: 999,
            objects: 9,
        };
        s.roll(day_of(NOW));
        assert_eq!(s.bytes, 999, "the same day reset the counters");

        s.roll(day_of(NOW) - 1);
        assert_eq!(s.bytes, 999, "an earlier day reset a spent budget");

        s.roll(day_of(NOW + DAY));
        assert_eq!(s.bytes, 0);
        assert_eq!(s.objects, 0);
        assert_eq!(s.day, day_of(NOW + DAY));
    }

    /// The stored record survives a restart, or a budget is not a budget.
    #[test]
    fn the_record_round_trips() {
        let s = Spend {
            day: 20_671,
            bytes: 12_345,
            objects: 67,
        };
        assert_eq!(Spend::decode(&s.encode()), Some(s));
    }

    /// A corrupt record reads as nothing rather than as an emptied budget —
    /// the caller starts a fresh window, which is the safe direction only
    /// because it cannot be reached by a peer.
    #[test]
    fn a_corrupt_record_is_refused_rather_than_read_as_empty() {
        assert_eq!(Spend::decode(&[]), None);
        assert_eq!(Spend::decode(&[0xa3]), None);
        let good = Spend {
            day: 1,
            bytes: 2,
            objects: 3,
        }
        .encode();
        for cut in 0..good.len() {
            assert_ne!(
                Spend::decode(&good[..cut]),
                Some(Spend {
                    day: 1,
                    bytes: 2,
                    objects: 3
                })
            );
        }
    }

    /// The operator panel reads a percentage, and it is the *worse* of the two
    /// ceilings — a link at 5% of its bytes and 99% of its objects is at 99%.
    #[test]
    fn the_percentage_reports_the_worse_ceiling() {
        let s = Spend {
            day: 0,
            bytes: 50,
            objects: 99,
        };
        assert_eq!(s.used_percent(1_000, 100), 99);
        assert_eq!(
            Spend::default().used_percent(0, 0),
            100,
            "a zero ceiling is fully spent, not divided by zero"
        );
    }

    /// Days are whole days since the epoch — the window §6 measures against.
    #[test]
    fn a_day_is_a_whole_day() {
        assert_eq!(day_of(0), 0);
        assert_eq!(day_of(DAY - 1), 0);
        assert_eq!(day_of(DAY), 1);
        assert_eq!(day_of(NOW + DAY) - day_of(NOW), 1);
    }
}
