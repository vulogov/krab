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
    /// Objects the peer delivered, accepted or not — RFC 3 §12.
    ///
    /// The denominator of the novelty ratio. §12 calls it "the key metric:
    /// high volume at low novelty is misconfiguration or attack."
    pub offered: u64,
    /// Objects refused because the budget was spent.
    ///
    /// A peer that keeps sending past its ceiling is exceeding what it signed,
    /// which is the other violation signal. Distinct from a duplicate: this is
    /// volume the link agreed not to carry.
    pub refused: u64,
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
                ..Spend::default()
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
        w.map(5)
            .uint(1)
            .uint(self.day as u64)
            .uint(2)
            .uint(self.bytes)
            .uint(3)
            .uint(self.objects)
            .uint(4)
            .uint(self.offered)
            .uint(5)
            .uint(self.refused);
        w.finish()
    }

    /// Decode. This is the node's own storage, but a corrupt file must not
    /// panic and must not read as **less** spent than was stored — so anything
    /// malformed yields nothing, and the caller starts a fresh window rather
    /// than an emptied one.
    pub fn decode(bytes: &[u8]) -> Option<Spend> {
        let mut r = Reader::new(bytes);
        let mut m = r.map().ok()?;
        if m.left() != 5 {
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
        let off = match (m.key().ok()??, m.value().ok()?) {
            (4, Item::Uint(v)) => v,
            _ => return None,
        };
        let ref_ = match (m.key().ok()??, m.value().ok()?) {
            (5, Item::Uint(v)) => v,
            _ => return None,
        };
        Some(Spend {
            day,
            bytes: b,
            objects: o,
            offered: off,
            refused: ref_,
        })
    }

    /// The novelty ratio — RFC 3 §12.
    ///
    /// `None` when nothing was offered: a peer with nothing to give has no
    /// novelty ratio, and reporting one as zero would read as the worst
    /// possible behaviour rather than as no evidence.
    pub fn novelty(&self) -> Option<f64> {
        (self.offered > 0).then(|| self.objects as f64 / self.offered as f64)
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
            ..Spend::default()
        };
        assert!(!by_objects.admits(1, u64::MAX, 10));

        let by_bytes = Spend {
            day: 0,
            bytes: 1_000,
            objects: 0,
            ..Spend::default()
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
            ..Spend::default()
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
            ..Spend::default()
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
            ..Spend::default()
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
            ..Spend::default()
        }
        .encode();
        for cut in 0..good.len() {
            assert_ne!(
                Spend::decode(&good[..cut]),
                Some(Spend {
                    day: 1,
                    bytes: 2,
                    objects: 3,
                    ..Spend::default()
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
            ..Spend::default()
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

/// Graduated standing on a link — RFC 3 §6.2, RFC 0 §5.3.
///
/// # Adjustment moves *within* the credential, never beyond it
///
/// §6.2's last sentence is the architecture: "Adjustment within the
/// credential's negotiated ceiling requires no re-signing; raising the ceiling
/// does."
///
/// So the signed document is a **ceiling** and this is a local dial beneath
/// it. A node can throttle a peer without either party re-signing anything,
/// and cannot grant more than was agreed without going back to the ceremony.
/// That is what makes automatic adjustment safe to run unattended: the worst
/// it can do is refuse traffic it was entitled to refuse.
///
/// # The shape is SIM-2's, deliberately
///
/// `graduated_quota_makes_a_fresh_vantage_point_slow_to_become_useful` in
/// `krab-node/tests/sim2.rs` measures RFC 0 §5.3's claim — that a fresh
/// vantage point is slow to become useful — against `BASE × min(age, 8)`.
/// Linear growth over eight windows.
///
/// This implements that curve rather than a different one. A simulation
/// measuring a model the code does not implement is the exact failure SIM-2
/// was written to remove; if the growth here were exponential, or capped at a
/// different age, the measured anti-Sybil property would be about a system
/// nobody runs.
///
/// # New peers start low, and that is the point
///
/// RFC 0 §5.3, via `krab_node::peering::Quota`: "New peers start at minimal
/// quota and grow on observed behaviour … Graduated quota is what makes early
/// vantage points low-bandwidth and slow to become useful."
///
/// An adversary who acquires a peering does not acquire a vantage point on the
/// corpus; they acquire one eighth of one, and have to behave for a week to
/// get the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Standing {
    /// Good windows observed, capped at [`MATURE_WINDOWS`].
    ///
    /// Starts at 1, not 0: a peering that admitted nothing at all would look
    /// to the operator exactly like a broken link, and RFC 0 §6 makes failure
    /// silent enough already.
    pub age: u32,
}

/// Windows of good behaviour after which quota stops growing — SIM-2's
/// `MATURE`.
pub const MATURE_WINDOWS: u32 = 8;

impl Default for Standing {
    fn default() -> Standing {
        Standing { age: 1 }
    }
}

/// What a closing window said about a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conduct {
    /// Nothing happened. Neither evidence nor a reason to move the dial.
    Quiet,
    /// Within budget, and novel enough to be worth carrying.
    Good,
    /// Kept sending past the ceiling it agreed to.
    Overspent,
    /// High volume at low novelty — RFC 3 §12's key metric.
    Unproductive,
}

/// Objects offered below which novelty is not evidence.
///
/// §6.1 warns that "a flood is indistinguishable from a well-connected peer
/// relaying a busy region", so a handful of duplicates must not read as an
/// attack. **Chosen, not derived** — the RFC gives no figure.
pub const NOVELTY_FLOOR_VOLUME: u64 = 64;

/// Novelty below which a high-volume window counts against a peer. Chosen.
pub const LOW_NOVELTY: f64 = 0.10;

impl Standing {
    /// The effective ceiling: a fraction of what the credential permits.
    pub fn effective(&self, ceiling: u64) -> u64 {
        let age = self.age.clamp(1, MATURE_WINDOWS) as u64;
        // Rounded up, so the smallest possible ceiling still admits something.
        // A quota of zero is disconnection, and §6.2 makes disconnection the
        // limit case rather than something a dial reaches on its own.
        ceiling
            .saturating_mul(age)
            .div_ceil(MATURE_WINDOWS as u64)
            .max(1)
    }

    /// Read a closing window.
    pub fn judge(spend: &Spend) -> Conduct {
        if spend.refused > 0 {
            return Conduct::Overspent;
        }
        if spend.offered >= NOVELTY_FLOOR_VOLUME {
            if let Some(n) = spend.novelty() {
                if n < LOW_NOVELTY {
                    return Conduct::Unproductive;
                }
            }
        }
        if spend.offered == 0 {
            return Conduct::Quiet;
        }
        Conduct::Good
    }

    /// Apply a window's verdict — §6.2's "drift upward … drop sharply".
    ///
    /// Recovery costs exactly what the drop saved: halving the age halves the
    /// quota, and climbing back takes as many good windows as were lost. That
    /// is §6.2's "continuous, proportionate, reversible" as arithmetic rather
    /// than as an intention.
    ///
    /// A quiet window moves nothing. A peer with nothing to send is not
    /// behaving well or badly, and rewarding silence would grow the quota of
    /// the pure observer §15 calls a harvester.
    pub fn settle(&mut self, conduct: Conduct) {
        match conduct {
            Conduct::Quiet => {}
            Conduct::Good => self.age = (self.age + 1).min(MATURE_WINDOWS),
            // Sharply, and to a floor of one rather than to nothing.
            Conduct::Overspent | Conduct::Unproductive => self.age = (self.age / 2).max(1),
        }
    }

    /// Deterministic CBOR, for sealed storage.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.map(1).uint(1).uint(self.age as u64);
        w.finish()
    }

    /// Decode. A corrupt record reads as a **fresh** standing, not a mature
    /// one: the safe direction for a value that decides how much a peer may
    /// send is the one that lets them send less.
    pub fn decode(bytes: &[u8]) -> Option<Standing> {
        let mut r = Reader::new(bytes);
        let mut m = r.map().ok()?;
        if m.left() != 1 {
            return None;
        }
        let age = match (m.key().ok()??, m.value().ok()?) {
            (1, Item::Uint(v)) => u32::try_from(v).ok()?,
            _ => return None,
        };
        Some(Standing {
            age: age.clamp(1, MATURE_WINDOWS),
        })
    }
}

/// A link's whole quota position: this window's spend and its standing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Account {
    /// What has crossed this window.
    pub spend: Spend,
    /// How far up the dial this peer has climbed.
    pub standing: Standing,
}

impl Account {
    /// Roll into `day`, settling the window that just closed.
    ///
    /// **Settlement happens here and nowhere else.** A window is judged when
    /// it ends, which is the only moment its totals are final — judging
    /// mid-window would let a peer that started badly be punished for a window
    /// it went on to spend well.
    ///
    /// Returns the verdict, so a caller can tell the operator. `None` when the
    /// window has not closed.
    pub fn roll(&mut self, day: u32) -> Option<Conduct> {
        if day <= self.spend.day {
            return None;
        }
        // A first window on a fresh account has nothing to judge: `day` starts
        // at zero, and the object of settling is the window that ran.
        let verdict = (self.spend.day > 0).then(|| Standing::judge(&self.spend));
        if let Some(v) = verdict {
            self.standing.settle(v);
        }
        self.spend.roll(day);
        verdict
    }

    /// Deterministic CBOR, for sealed storage.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.map(2)
            .uint(1)
            .bstr(&self.spend.encode())
            .uint(2)
            .bstr(&self.standing.encode());
        w.finish()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Option<Account> {
        let mut r = Reader::new(bytes);
        let mut m = r.map().ok()?;
        if m.left() != 2 {
            return None;
        }
        let spend = match (m.key().ok()??, m.value().ok()?) {
            (1, Item::Bstr(b)) => Spend::decode(b)?,
            _ => return None,
        };
        let standing = match (m.key().ok()??, m.value().ok()?) {
            (2, Item::Bstr(b)) => Standing::decode(b)?,
            _ => return None,
        };
        Some(Account { spend, standing })
    }
}

#[cfg(test)]
mod adjust_tests {
    use super::*;

    /// **The curve is SIM-2's.** `graduated_quota_…` measures RFC 0 §5.3's
    /// anti-Sybil claim against `BASE × min(age, 8)`. If this diverges, the
    /// simulation measures a system nobody runs — the exact failure SIM-2 was
    /// written to remove.
    #[test]
    fn the_growth_curve_matches_the_one_sim2_measures() {
        let ceiling = 8_000u64;
        let base = ceiling / MATURE_WINDOWS as u64;
        for age in 1..=MATURE_WINDOWS {
            let s = Standing { age };
            assert_eq!(
                s.effective(ceiling),
                base * age as u64,
                "age {age} is off the measured curve"
            );
        }
        // And it stops there.
        assert_eq!(
            Standing {
                age: MATURE_WINDOWS + 5
            }
            .effective(ceiling),
            ceiling
        );
    }

    /// **A fresh peering starts at one eighth.** RFC 0 §5.3: an adversary who
    /// acquires a peering acquires an eighth of a vantage point, and must
    /// behave for a week for the rest.
    #[test]
    fn a_fresh_peering_starts_low_and_takes_a_week_to_mature() {
        let ceiling = 800u64;
        let mut s = Standing::default();
        assert_eq!(s.effective(ceiling), 100);

        let mut windows = 0;
        while s.effective(ceiling) < ceiling {
            s.settle(Conduct::Good);
            windows += 1;
            assert!(windows <= 16, "maturity is unreachable");
        }
        assert_eq!(windows, MATURE_WINDOWS - 1);
    }

    /// **Never above the credential.** §6.2: adjustment within the negotiated
    /// ceiling needs no re-signing; raising the ceiling does. So the dial
    /// cannot raise it.
    #[test]
    fn the_dial_never_exceeds_the_signed_ceiling() {
        for age in 0..100u32 {
            assert!(Standing { age }.effective(1_000) <= 1_000);
        }
    }

    /// And never to nothing: a quota of zero is disconnection, which §6.2
    /// makes the limit case rather than something a dial reaches by itself.
    #[test]
    fn the_dial_never_reaches_zero() {
        let mut s = Standing::default();
        for _ in 0..50 {
            s.settle(Conduct::Overspent);
        }
        assert_eq!(s.age, 1);
        assert!(s.effective(1) >= 1);
        assert!(s.effective(0) >= 1);
    }

    /// **Drop sharply, recover proportionately** — §6.2's "continuous,
    /// proportionate, reversible". Recovery costs what the drop saved.
    #[test]
    fn a_violation_halves_the_dial_and_recovery_costs_what_it_saved() {
        let mut s = Standing {
            age: MATURE_WINDOWS,
        };
        s.settle(Conduct::Overspent);
        assert_eq!(s.age, MATURE_WINDOWS / 2, "the drop was not sharp");

        let mut back = 0;
        while s.age < MATURE_WINDOWS {
            s.settle(Conduct::Good);
            back += 1;
        }
        assert_eq!(back, MATURE_WINDOWS / 2, "recovery was not proportionate");
    }

    /// Exceeding the agreed ceiling is a violation, whatever else was true.
    #[test]
    fn sending_past_the_ceiling_counts_against_a_peer() {
        let spend = Spend {
            day: 1,
            bytes: 100,
            objects: 100,
            offered: 200,
            refused: 1,
        };
        assert_eq!(Standing::judge(&spend), Conduct::Overspent);
    }

    /// **High volume at low novelty** — §12's key metric.
    #[test]
    fn high_volume_at_low_novelty_counts_against_a_peer() {
        let spend = Spend {
            day: 1,
            bytes: 0,
            objects: 1,
            offered: 1_000,
            refused: 0,
        };
        assert_eq!(Standing::judge(&spend), Conduct::Unproductive);
    }

    /// **But low novelty at low volume does not.** §6.1: "a flood is
    /// indistinguishable from a well-connected peer relaying a busy region",
    /// so a handful of duplicates is not evidence of anything.
    #[test]
    fn a_few_duplicates_are_not_an_attack() {
        let spend = Spend {
            day: 1,
            bytes: 0,
            objects: 0,
            offered: NOVELTY_FLOOR_VOLUME - 1,
            refused: 0,
        };
        assert_eq!(Standing::judge(&spend), Conduct::Good);
    }

    /// **Silence moves nothing.** A peer with nothing to send is neither
    /// behaving well nor badly, and rewarding silence would grow the quota of
    /// the pure observer RFC 3 §15 calls a harvester.
    #[test]
    fn a_quiet_window_does_not_reward_a_harvester() {
        let quiet = Spend {
            day: 1,
            ..Spend::default()
        };
        assert_eq!(Standing::judge(&quiet), Conduct::Quiet);

        let mut s = Standing::default();
        for _ in 0..20 {
            s.settle(Conduct::Quiet);
        }
        assert_eq!(s.age, 1, "silence matured a peering");
    }

    /// Settlement happens when a window closes, and once.
    #[test]
    fn a_window_is_settled_when_it_closes_and_not_before() {
        let mut a = Account {
            spend: Spend {
                day: 100,
                bytes: 10,
                objects: 10,
                offered: 10,
                refused: 0,
            },
            standing: Standing::default(),
        };
        assert_eq!(a.roll(100), None, "settled mid-window");
        assert_eq!(a.standing.age, 1);

        assert_eq!(a.roll(101), Some(Conduct::Good));
        assert_eq!(a.standing.age, 2);
        assert_eq!(a.spend.offered, 0, "the window did not reset");

        // And a second roll on the same day changes nothing.
        assert_eq!(a.roll(101), None);
        assert_eq!(a.standing.age, 2);
    }

    /// The account survives a restart, standing included — a dial that
    /// resets is a dial an adversary resets by waiting.
    #[test]
    fn an_account_round_trips() {
        let a = Account {
            spend: Spend {
                day: 20_671,
                bytes: 1,
                objects: 2,
                offered: 3,
                refused: 4,
            },
            standing: Standing { age: 5 },
        };
        assert_eq!(Account::decode(&a.encode()), Some(a));
    }

    /// A corrupt standing reads as fresh, never as mature: the safe direction
    /// for a value deciding how much a peer may send is the one that lets them
    /// send less.
    #[test]
    fn a_corrupt_standing_reads_as_fresh() {
        assert_eq!(Standing::decode(&[]), None);
        let mut w = Writer::new();
        w.map(1).uint(1).uint(9_999);
        assert_eq!(
            Standing::decode(&w.finish()),
            Some(Standing {
                age: MATURE_WINDOWS
            }),
            "an out-of-range age is clamped, not trusted"
        );
    }
}
