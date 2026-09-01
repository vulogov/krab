//! The dead-man timer — RFC 7 §10.
//!
//! ```text
//! **Dead-man timer.** Wipe if not unlocked within N days. Useful for a node
//! its operator may not be able to return to, and it degrades safely: the
//! corpus is replicated elsewhere, so wiping costs nobody anything.
//!
//! Neither MUST be enabled by default. Both MUST be discoverable, and the
//! dead-man timer MUST warn well before it fires.
//! ```
//!
//! Three requirements, and each is met by a specific thing below: **not
//! default** is the absence of the file ([`DeadMan::read`] returning `None`),
//! **discoverable** is the `deadman` verb appearing in `help` like any other,
//! and **warns well before** is [`DeadMan::warning`] with
//! [`WARN_FRACTION`].
//!
//! # The stamp is in the clear, and that is the hard part
//!
//! Everything else this node stores is sealed under the KEK. This is not, and
//! it cannot be: **the timer's whole purpose is to fire when nobody has
//! unlocked the node**, so the deadline has to be legible to a process that
//! does not have the passphrase. A deadline sealed under the KEK could only be
//! read after an unlock, which is precisely the event that cancels it. It
//! would be a timer that fires only when it is not needed.
//!
//! So the file is two integers in the clear, and the disclosure is real: an
//! adversary holding the disk learns that a dead-man is armed and when it
//! expires. That is worth stating plainly rather than burying, because it
//! cuts both ways — it also tells them that waiting is expensive, which is
//! not obviously to their advantage.
//!
//! What the stamp deliberately does **not** contain: any identifier, any peer,
//! any count, any indication of what the node holds. Two integers is the whole
//! file, so what leaks is the existence of a policy and not a fact about the
//! operator's correspondence.
//!
//! # Why this cannot be a config file
//!
//! `NO-CONFIG.md` forbids configuration files because they "may be lost,
//! spoofed, faked, leaked". This is state rather than configuration — it is
//! written by the node when an operator arms the timer, and rewritten by the
//! node at every unlock — but the objection still bites in one direction:
//! **an attacker who can write this file can bring the deadline forward and
//! destroy the node.**
//!
//! That is not a new power. Anyone who can write into the node's home can
//! already delete `identity.wrapped`, which destroys it just as thoroughly and
//! faster. The stamp adds no capability an attacker did not have; it is
//! recorded here so the next reader does not have to work that out.
//!
//! The *other* direction is the one that matters and is closed: an attacker
//! cannot push the deadline **back** to keep a node alive that its operator
//! meant to die, because [`DeadMan::expired`] compares against a wall clock
//! and a forward-dated stamp only shortens the window it takes to fire.

use krab_core::cbor::{Item, Reader, Writer};
use std::path::Path;

/// Seconds in a day.
const DAY: u64 = 86_400;

/// The shortest timer an operator may set.
///
/// A timer shorter than a day is one that fires while somebody is on holiday
/// for a long weekend, and the failure is unrecoverable. RFC 7 §10's use case
/// is "a node its operator may not be able to return to", which is a scale of
/// days at minimum.
pub const MIN_DAYS: u32 = 1;

/// The longest.
///
/// Not a safety limit — a bound that keeps the arithmetic in range and stops
/// a typo like `deadman 100000` reading as "effectively never" while looking
/// armed. Ten years.
pub const MAX_DAYS: u32 = 3_650;

/// How much of the window is left when warning starts.
///
/// §10 says "well before it fires" without a number. A quarter of the window
/// is the reading taken here: on a 30-day timer that is a week of warnings,
/// and on a 4-day timer it is a day — both long enough to act on, and both
/// proportional to a period the operator chose.
///
/// A fixed number of days would be wrong at one end or the other: three days'
/// notice on a 4-day timer is noise, and three days' notice on a year-long
/// timer is not "well before".
pub const WARN_FRACTION: u64 = 4;

/// An armed dead-man timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeadMan {
    /// When the timer was last reset — armed, or unlocked.
    pub armed_at_s: u64,
    /// How many days of silence fire it.
    pub days: u32,
}

impl DeadMan {
    /// Arm, or re-arm, at `now_s`.
    ///
    /// `days` outside [`MIN_DAYS`]..=[`MAX_DAYS`] is refused rather than
    /// clamped: clamping would arm a timer with a period the operator did not
    /// ask for, and this is a control that destroys the node.
    pub fn new(now_s: u64, days: u32) -> Result<DeadMan, String> {
        if !(MIN_DAYS..=MAX_DAYS).contains(&days) {
            return Err(format!(
                "a dead-man timer must be between {MIN_DAYS} and {MAX_DAYS} days"
            ));
        }
        Ok(DeadMan {
            armed_at_s: now_s,
            days,
        })
    }

    /// When it fires.
    pub fn deadline_s(&self) -> u64 {
        // `days` is bounded by `MAX_DAYS`, so this cannot overflow a `u64`
        // for any `armed_at_s` a wall clock produces. Saturating anyway: an
        // absurd clock should not panic a node.
        self.armed_at_s.saturating_add(self.days as u64 * DAY)
    }

    /// Whether the node should be destroyed now.
    ///
    /// # A clock moved backwards does not fire it
    ///
    /// `now_s` before `armed_at_s` means the machine's clock went back — a
    /// timezone mishap, a dead RTC battery, an NTP correction. That is not
    /// evidence the operator has gone, and destroying a node over it would be
    /// the worst possible false positive. The comparison is one-directional
    /// for that reason.
    pub fn expired(&self, now_s: u64) -> bool {
        now_s >= self.deadline_s()
    }

    /// Seconds remaining, saturating at zero.
    pub fn remaining_s(&self, now_s: u64) -> u64 {
        self.deadline_s().saturating_sub(now_s)
    }

    /// The warning to show, if it is time to warn — RFC 7 §10's MUST.
    ///
    /// `None` when there is more than [`WARN_FRACTION`] of the window left.
    pub fn warning(&self, now_s: u64) -> Option<String> {
        let window = self.days as u64 * DAY;
        let left = self.remaining_s(now_s);
        if left > window / WARN_FRACTION {
            return None;
        }
        let days = left / DAY;
        let hours = (left % DAY) / 3_600;
        let when = if left == 0 {
            "now".to_string()
        } else if days > 0 {
            format!("in {days}d {hours}h")
        } else if hours > 0 {
            format!("in {hours}h")
        } else {
            format!("in {}m", (left % 3_600) / 60)
        };
        Some(format!(
            "DEAD-MAN TIMER: this node destroys itself {when} unless it is \
             unlocked. Unlocking resets it to {} days.",
            self.days
        ))
    }

    /// Encode. Two integers, and nothing else — see the module note.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.map(2);
        w.uint(1).uint(self.armed_at_s);
        w.uint(2).uint(self.days as u64);
        w.finish()
    }

    /// Decode, or `None` if the file is not a stamp this version wrote.
    ///
    /// A malformed stamp reads as **absent**, not as expired. The other
    /// reading would let a corrupt byte destroy a node, which is the wrong
    /// direction for an unrecoverable action — and the operator is told,
    /// because [`read`] reports it.
    pub fn decode(bytes: &[u8]) -> Option<DeadMan> {
        let mut r = Reader::new(bytes);
        let mut m = r.map().ok()?;
        let (mut armed, mut days) = (None, None);
        while let Some(key) = m.key().ok()? {
            match (key, m.value().ok()?) {
                (1, Item::Uint(v)) => armed = Some(v),
                (2, Item::Uint(v)) => days = u32::try_from(v).ok(),
                _ => {}
            }
        }
        let days = days?;
        if !(MIN_DAYS..=MAX_DAYS).contains(&days) {
            return None;
        }
        Some(DeadMan {
            armed_at_s: armed?,
            days,
        })
    }
}

/// What was on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stamp {
    /// No timer. **The default**, per RFC 7 §10's "MUST NOT be enabled by
    /// default" — which is met by the file's absence rather than by a flag
    /// inside it, so there is no state in which a stamp exists and means off.
    Absent,
    /// A timer, armed.
    Armed(DeadMan),
    /// A file that is not a stamp. Treated as absent and reported.
    Unreadable,
}

/// Read the stamp beside the node.
pub fn read(path: &Path) -> Stamp {
    match std::fs::read(path) {
        Err(_) => Stamp::Absent,
        Ok(bytes) => match DeadMan::decode(&bytes) {
            Some(d) => Stamp::Armed(d),
            None => Stamp::Unreadable,
        },
    }
}

/// Write the stamp.
pub fn write(path: &Path, d: &DeadMan) -> std::io::Result<()> {
    crate::atomic::write(path, &d.encode())
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_700_000_000;

    #[test]
    fn a_timer_round_trips() {
        let d = DeadMan::new(T0, 30).unwrap();
        assert_eq!(DeadMan::decode(&d.encode()), Some(d));
    }

    /// **RFC 7 §10: not enabled by default.** No file, no timer — and there is
    /// no encoding of "armed but off", so it cannot be on by accident.
    #[test]
    fn absent_means_off() {
        let dir = std::env::temp_dir().join(format!("krab-dm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(read(&dir.join("nothing.stamp")), Stamp::Absent);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn it_fires_after_its_window_and_not_before() {
        let d = DeadMan::new(T0, 7).unwrap();
        assert!(!d.expired(T0));
        assert!(!d.expired(T0 + 7 * DAY - 1));
        assert!(d.expired(T0 + 7 * DAY));
        assert!(d.expired(T0 + 700 * DAY));
    }

    /// **A clock that went backwards must not fire it.**
    ///
    /// A dead RTC battery or a timezone mishap is not evidence the operator
    /// has gone, and this action is unrecoverable. The worst false positive
    /// the module can have, so it is pinned.
    #[test]
    fn a_backwards_clock_does_not_fire_it() {
        let d = DeadMan::new(T0, 7).unwrap();
        assert!(!d.expired(T0 - 400 * DAY));
        assert!(!d.expired(0));
        // And "remaining" grows rather than saturating to zero — the safe
        // direction. A clock at the epoch reports the whole distance to the
        // deadline, which is far more than the window, so nothing fires.
        assert_eq!(d.remaining_s(0), T0 + 7 * DAY);
        assert!(d.warning(0).is_none(), "a backwards clock must not warn");
    }

    /// **RFC 7 §10's MUST: it warns well before it fires**, and the notice is
    /// proportional to the window the operator chose.
    #[test]
    fn it_warns_well_before_firing() {
        let d = DeadMan::new(T0, 40).unwrap();
        // Most of the way through the window: nothing yet.
        assert!(d.warning(T0).is_none());
        assert!(d.warning(T0 + 29 * DAY).is_none());
        // Inside the last quarter — ten days, which is "well before".
        let w = d.warning(T0 + 31 * DAY).expect("no warning inside the window");
        assert!(w.contains("DEAD-MAN"));
        assert!(w.contains("unlock"), "the remedy must be in the warning: {w}");
        // And it still warns at the moment it fires.
        assert!(d.warning(T0 + 40 * DAY).is_some());
    }

    /// The notice scales with the period rather than being a fixed number of
    /// days — three days' notice is noise on a 4-day timer and negligible on
    /// a yearly one.
    #[test]
    fn the_warning_window_is_proportional() {
        let short = DeadMan::new(T0, 4).unwrap();
        let long = DeadMan::new(T0, 365).unwrap();
        // One day left of four: warning. One day left of 365: warning too.
        assert!(short.warning(T0 + 3 * DAY).is_some());
        assert!(long.warning(T0 + 364 * DAY).is_some());
        // A quarter of 365 days is 91.25, so the warning starts with about 91
        // days left. 85 days left warns; 100 does not.
        assert!(long.warning(T0 + 280 * DAY).is_some(), "85 days left");
        assert!(long.warning(T0 + 265 * DAY).is_none(), "100 days left");
    }

    /// **A malformed stamp reads as absent, never as expired.** A corrupt byte
    /// must not destroy a node.
    #[test]
    fn a_corrupt_stamp_does_not_destroy_the_node() {
        assert_eq!(DeadMan::decode(b""), None);
        assert_eq!(DeadMan::decode(b"not cbor at all"), None);
        assert_eq!(DeadMan::decode(&[0xff; 40]), None);
        // A well-formed map with an absurd period is refused too, rather than
        // clamped into something that fires.
        let mut w = Writer::new();
        w.map(2);
        w.uint(1).uint(T0);
        w.uint(2).uint(9_999_999);
        assert_eq!(DeadMan::decode(&w.finish()), None);
    }

    /// A period outside the bounds is refused rather than clamped: clamping
    /// arms a timer the operator did not ask for, and this one destroys the
    /// node.
    #[test]
    fn an_out_of_range_period_is_refused() {
        assert!(DeadMan::new(T0, 0).is_err());
        assert!(DeadMan::new(T0, MAX_DAYS + 1).is_err());
        assert!(DeadMan::new(T0, MIN_DAYS).is_ok());
        assert!(DeadMan::new(T0, MAX_DAYS).is_ok());
    }

    /// Unlocking resets the window — that is what "wipe if **not unlocked**
    /// within N days" means.
    #[test]
    fn re_arming_moves_the_deadline() {
        let d = DeadMan::new(T0, 10).unwrap();
        let later = DeadMan::new(T0 + 9 * DAY, 10).unwrap();
        assert!(!later.expired(T0 + 10 * DAY), "an unlock did not reset it");
        assert_eq!(later.deadline_s(), T0 + 19 * DAY);
        assert!(d.expired(T0 + 10 * DAY));
    }

    /// The stamp carries two integers and nothing that identifies anybody.
    ///
    /// It is the one file this node writes in the clear, so what is *not* in
    /// it is a security property rather than a detail.
    #[test]
    fn the_stamp_is_two_integers() {
        let d = DeadMan::new(T0, 30).unwrap();
        let bytes = d.encode();
        assert!(bytes.len() < 24, "stamp is {} bytes", bytes.len());
        let mut r = Reader::new(&bytes);
        let mut m = r.map().unwrap();
        let mut keys = Vec::new();
        while let Some(k) = m.key().unwrap() {
            keys.push(k);
            let _ = m.value().unwrap();
        }
        assert_eq!(keys, vec![1, 2], "the stamp gained a field");
    }
}
