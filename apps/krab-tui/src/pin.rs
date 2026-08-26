//! Pinning — RFC 8 §10, RFC 7 §8.1.
//!
//! > "Some users want a permanent archive. Provide an explicit **pin** action
//! > that re-encrypts a selected conversation under a long-lived key, so
//! > retention is a conscious act rather than the default.
//! >
//! > Implementations **MUST make the consequence visible before the retention
//! > window elapses**: mail older than the window becomes unreadable, and a
//! > user who discovers this afterwards has lost something irrecoverably."
//!
//! # This was already running
//!
//! `shred_expired_epochs` drops epoch keys older than `EPOCH_WINDOW` on the
//! schedule, and logged:
//!
//! ```text
//! epochs shredded — that mail is unreadable now
//! ```
//!
//! *Now*. After. Which is the sentence §8.1 is written against, and the loss
//! is real: an epoch key is gone, the objects remain, and nothing anywhere can
//! open them again. RFC 8 §10 calls that "the only genuine form of message
//! expiry" — it is the point, not a defect — but the operator has to be able
//! to see it coming.
//!
//! # The long-lived key
//!
//! A pin is only worth something if its key outlives the epoch. So it is
//! derived from the **KEK**, which is a function of the passphrase and nothing
//! else, rather than from `W_N`, which is a function of the epoch:
//!
//! ```text
//! pin_key = BLAKE3-256("krab/pin/v1" ‖ kek)
//! ```
//!
//! Held in memory beside `epoch_key`, re-derived on unlock, and cleared on
//! lock. It never touches disk — RFC 7 §4's rule for the KEK applies to
//! anything derived from it.
//!
//! # What pinning costs, stated plainly
//!
//! A pinned conversation is **exempt from the erasure everything else gets**.
//! That is the request, and it is also the whole of the risk: RFC 7 §8's
//! erasure is what makes a seized disk stop being a transcript, and every pin
//! is a hole in it.
//!
//! So the default is forgetting, the action is explicit, and
//! [`Pinned::warning`] says how much has been made permanent rather than
//! letting an archive accumulate quietly.

use krab_core::cbor::{Item, Reader, Writer};

/// Domain for the long-lived key. Frozen.
pub const DOMAIN: &[u8] = b"krab/pin/v1";

/// Days before an epoch is shredded at which the operator is warned.
///
/// RFC 7 §8.1 says "before", not how long before. A week is enough to act on
/// a courier link, which is the deployment with the least room, and short
/// enough that the warning still means something when it appears.
pub const WARN_DAYS: u32 = 7;

/// The most conversations that may be pinned.
///
/// Every pin is a hole in RFC 7 §8's erasure. A bound is not a security
/// property — an operator can pin, unpin and pin again — but an archive that
/// grows without anyone deciding to grow it is how "the default is forgetting"
/// stops being true.
pub const MAX_PINNED: usize = 64;

/// One kept message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    /// Who it was from, as a short id.
    pub from: String,
    /// The epoch it arrived in — kept so the archive can say what it saved.
    pub epoch: u32,
    /// The plaintext.
    pub body: String,
}

/// A node's pinned archive.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pinned {
    /// Kept messages, oldest first.
    pub kept: Vec<Kept>,
}

impl Pinned {
    /// Derive the long-lived key from the KEK.
    ///
    /// **Not from `W_N`.** A pin whose key is the epoch key is unreadable
    /// exactly when it was supposed to be readable, which is the one thing a
    /// pin must not be.
    pub fn key_from_kek(kek: &krab_crypto::kek::Kek) -> [u8; 32] {
        kek.subkey(DOMAIN)
    }

    /// Keep a conversation. Returns how many messages were added.
    ///
    /// Idempotent per message: pinning the same conversation twice does not
    /// double it, because an operator who is unsure whether it worked will
    /// run it again.
    pub fn keep(&mut self, msgs: &[Kept]) -> usize {
        let mut added = 0;
        for m in msgs {
            if self.kept.len() >= MAX_PINNED {
                break;
            }
            if self.kept.iter().any(|k| k == m) {
                continue;
            }
            self.kept.push(m.clone());
            added += 1;
        }
        added
    }

    /// Forget a pinned conversation. Returns how many went.
    pub fn release(&mut self, from: &str) -> usize {
        let before = self.kept.len();
        self.kept.retain(|k| k.from != from);
        before - self.kept.len()
    }

    /// Everything kept from one correspondent.
    pub fn of(&self, from: &str) -> Vec<&Kept> {
        self.kept.iter().filter(|k| k.from == from).collect()
    }

    /// What to tell the operator about the archive they have built.
    ///
    /// Empty when nothing is pinned: the default is forgetting, and a node
    /// that keeps nothing has nothing to answer for.
    pub fn warning(&self) -> Option<String> {
        if self.kept.is_empty() {
            return None;
        }
        let mut who: Vec<&str> = self.kept.iter().map(|k| k.from.as_str()).collect();
        who.sort_unstable();
        who.dedup();
        Some(format!(
            "{} message(s) from {} correspondent(s) are pinned, and are exempt \
             from the epoch erasure everything else gets. That erasure is what \
             stops a seized disk being a transcript (RFC 7 §8); each pin is a \
             hole in it. `pin release <peer>` closes one.",
            self.kept.len(),
            who.len()
        ))
    }

    /// Deterministic CBOR, for sealed storage.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let mut flat = Vec::new();
        for k in &self.kept {
            let mut e = Writer::new();
            e.map(3)
                .uint(1)
                .tstr(&k.from)
                .uint(2)
                .uint(k.epoch as u64)
                .uint(3)
                .tstr(&k.body);
            let b = e.finish();
            let mut n = Writer::new();
            n.uint(b.len() as u64);
            flat.extend_from_slice(&n.finish());
            flat.extend_from_slice(&b);
        }
        w.map(2)
            .uint(1)
            .uint(self.kept.len() as u64)
            .uint(2)
            .bstr(&flat);
        w.finish()
    }

    /// Decode. This is the node's own archive, but a corrupt file must not
    /// panic and must not read as a **shorter** archive than was stored —
    /// silently dropping a pinned message is the loss the pin existed to
    /// prevent.
    pub fn decode(bytes: &[u8]) -> Option<Pinned> {
        let mut r = Reader::new(bytes);
        let mut m = r.map().ok()?;
        if m.left() != 2 {
            return None;
        }
        let declared = match at(&mut m, 1)? {
            Item::Uint(v) => usize::try_from(v).ok()?,
            _ => return None,
        };
        if declared > MAX_PINNED {
            return None;
        }
        let flat = match at(&mut m, 2)? {
            Item::Bstr(b) => b,
            _ => return None,
        };
        let mut kept = Vec::new();
        let mut rest = flat;
        while !rest.is_empty() {
            if kept.len() >= MAX_PINNED {
                return None;
            }
            let mut rr = Reader::new(rest);
            let len = match rr.item().ok()? {
                Item::Uint(v) => usize::try_from(v).ok()?,
                _ => return None,
            };
            let consumed = rest.len() - rr.remaining();
            let body = rest.get(consumed..consumed.checked_add(len)?)?;
            kept.push(one(body)?);
            rest = &rest[consumed + len..];
        }
        // A count that disagrees with what is present describes a different
        // archive from the one that arrived.
        (kept.len() == declared).then_some(Pinned { kept })
    }
}

fn one(bytes: &[u8]) -> Option<Kept> {
    let mut r = Reader::new(bytes);
    let mut m = r.map().ok()?;
    if m.left() != 3 {
        return None;
    }
    let from = match at(&mut m, 1)? {
        Item::Tstr(t) => t.to_string(),
        _ => return None,
    };
    let epoch = match at(&mut m, 2)? {
        Item::Uint(v) => u32::try_from(v).ok()?,
        _ => return None,
    };
    let body = match at(&mut m, 3)? {
        Item::Tstr(t) => t.to_string(),
        _ => return None,
    };
    Some(Kept { from, epoch, body })
}

fn at<'a>(m: &mut krab_core::cbor::MapReader<'a, '_>, k: u64) -> Option<Item<'a>> {
    (m.key().ok()?? == k).then_some(())?;
    m.value().ok()
}

/// How many days until the epoch holding `epoch` falls out of the window and
/// its key is shredded — RFC 7 §8.1's "before".
///
/// `None` once it already has: there is nothing left to warn about, and saying
/// "0 days" about mail that is already unreadable is the *after* §8.1 objects
/// to, dressed as a warning.
pub fn days_until_unreadable(epoch: u32, now: u32) -> Option<u32> {
    let shred_at = epoch.checked_add(krab_core::tag::EPOCH_WINDOW)?;
    shred_at.checked_sub(now).filter(|d| *d > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kept(from: &str, epoch: u32) -> Kept {
        Kept {
            from: from.into(),
            epoch,
            body: format!("message from {from}"),
        }
    }

    /// **The key outlives the epoch, because that is the whole point.**
    /// A pin whose key is `W_N` is unreadable exactly when it was supposed to
    /// be readable.
    #[test]
    fn the_pin_key_is_a_function_of_the_kek_and_nothing_else() {
        use krab_crypto::kek::{Kek, KekParams};
        use krab_crypto::rng::NotRandom;
        let mut p = KekParams::new(&mut NotRandom::seeded(1));
        p.m_kib = 64;
        p.t = 1;
        p.p = 1;
        let one = Kek::derive(b"a passphrase", &p).unwrap();
        let two = Kek::derive(b"another", &p).unwrap();

        assert_eq!(Pinned::key_from_kek(&one), Pinned::key_from_kek(&one));
        assert_ne!(Pinned::key_from_kek(&one), Pinned::key_from_kek(&two));
        // Domain-separated: a subkey for a different purpose is unrelated.
        assert_ne!(Pinned::key_from_kek(&one), one.subkey(b"krab/other/v1"));
    }

    /// **RFC 7 §8.1's "before".** The warning has to arrive while there is
    /// still something to do about it.
    #[test]
    fn the_warning_comes_before_the_window_elapses() {
        let window = krab_core::tag::EPOCH_WINDOW;
        let arrived = 20_000u32;
        // Fresh mail: the whole window left.
        assert_eq!(days_until_unreadable(arrived, arrived), Some(window));
        // A week from the edge — inside `WARN_DAYS`.
        let soon = arrived + window - WARN_DAYS;
        assert_eq!(days_until_unreadable(arrived, soon), Some(WARN_DAYS));
        assert!(days_until_unreadable(arrived, soon).unwrap() <= WARN_DAYS);
        // And once it is gone there is nothing to warn about — saying
        // "0 days" about unreadable mail is the *after* §8.1 objects to.
        assert_eq!(days_until_unreadable(arrived, arrived + window), None);
        assert_eq!(days_until_unreadable(arrived, arrived + window + 99), None);
    }

    /// Pinning twice does not double the archive: an operator unsure whether
    /// it worked will run it again.
    #[test]
    fn pinning_is_idempotent() {
        let mut p = Pinned::default();
        let msgs = vec![kept("alice", 1), kept("alice", 2)];
        assert_eq!(p.keep(&msgs), 2);
        assert_eq!(p.keep(&msgs), 0, "the archive doubled");
        assert_eq!(p.kept.len(), 2);
    }

    /// Releasing takes one correspondent and leaves the rest.
    #[test]
    fn releasing_closes_one_hole_and_not_the_others() {
        let mut p = Pinned::default();
        p.keep(&[kept("alice", 1), kept("bob", 1), kept("alice", 2)]);
        assert_eq!(p.release("alice"), 2);
        assert_eq!(p.kept.len(), 1);
        assert_eq!(p.of("bob").len(), 1);
        assert_eq!(p.release("nobody"), 0);
    }

    /// **Every pin is a hole in RFC 7 §8's erasure, and the operator is told
    /// so.** The default is forgetting; an archive that grows without anyone
    /// deciding to grow it is how that stops being true.
    #[test]
    fn an_archive_says_what_it_costs() {
        let mut p = Pinned::default();
        assert_eq!(
            p.warning(),
            None,
            "a node keeping nothing has nothing to say"
        );

        p.keep(&[kept("alice", 1), kept("alice", 2), kept("bob", 1)]);
        let w = p.warning().expect("an archive says so");
        assert!(w.contains("3 message(s)"), "{w}");
        assert!(w.contains("2 correspondent(s)"), "{w}");
        assert!(w.contains("exempt"), "{w}");
        assert!(w.contains("pin release"), "the way out is not named: {w}");
    }

    /// Bounded, so an archive cannot grow past a size anyone decided on.
    #[test]
    fn the_archive_is_bounded() {
        let mut p = Pinned::default();
        let many: Vec<Kept> = (0..MAX_PINNED as u32 + 10).map(|i| kept("a", i)).collect();
        assert_eq!(p.keep(&many), MAX_PINNED);
        assert_eq!(p.kept.len(), MAX_PINNED);
    }

    /// The archive survives a restart, and a corrupt one reads as nothing
    /// rather than as a shorter archive — silently dropping a pinned message
    /// is the loss the pin existed to prevent.
    #[test]
    fn an_archive_round_trips_and_a_corrupt_one_is_refused() {
        let mut p = Pinned::default();
        p.keep(&[kept("alice", 1), kept("bob", 2)]);
        assert_eq!(Pinned::decode(&p.encode()), Some(p.clone()));

        assert_eq!(Pinned::decode(&[]), None);
        let good = p.encode();
        for cut in 0..good.len() {
            let back = Pinned::decode(&good[..cut]);
            assert!(
                back.is_none() || back.as_ref() == Some(&p),
                "a truncated archive read as a shorter one"
            );
        }

        // A count that disagrees with what is present.
        let mut w = Writer::new();
        w.map(2).uint(1).uint(9).uint(2).bstr(&[]);
        assert_eq!(Pinned::decode(&w.finish()), None);
    }

    /// Text arriving from a correspondent goes in verbatim; nothing here may
    /// panic on it.
    #[test]
    fn arbitrary_bodies_survive() {
        let mut p = Pinned::default();
        for body in ["", "🙂", "\u{202e}reversed", &"x".repeat(4096)] {
            p.kept.push(Kept {
                from: "a".into(),
                epoch: 1,
                body: body.to_string(),
            });
        }
        let back = Pinned::decode(&p.encode()).expect("decodes");
        assert_eq!(back, p);
    }
}
