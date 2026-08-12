//! Groups — RFC 6 §2, and the two interface requirements that need a roster.
//!
//! A group is a **closed roster with fan-out**: a message is sealed once per
//! member, to that member. There is no shared group key, so one compromised
//! member exposes one member — which is the whole reason to pay `(G−1)×` for
//! it.
//!
//! # This is the opposite security model from a channel
//!
//! | | group | channel |
//! |---|---|---|
//! | audience | closed roster | anyone, permanently |
//! | confidentiality | sealed per member | none, signed only |
//! | cost | `(G−1)×` | constant |
//! | roster | exists, and diverges | none to diverge |
//!
//! RFC 6 §5 names the failure this creates: *"A user who believes they are in
//! a private group while posting to a public channel is the worst failure this
//! system can produce."* Both appear in one interface as "a list of messages".
//!
//! # Divergence is guaranteed, not exceptional
//!
//! RFC 6 §2.6: Alice believes the group is {A,B,C}; Bob added D last week and
//! Alice has not received that message. With courier latency and no global
//! ordering this is routine.
//!
//! ```text
//! epoch      increments on every membership change
//! change     an ordinary signed group message
//! merge      on receiving a higher epoch, adopt that roster
//! ```
//!
//! **and it MUST be surfaced rather than resolved.** A member added without
//! your knowledge and a roster you have not yet synchronised are
//! indistinguishable, so an interface that smooths it over has hidden exactly
//! the event that distinguishes an attack from latency. That is why silent
//! merge is forbidden rather than discouraged.

use krab_core::cbor;

/// Who may change the roster. **Recorded at creation and never changed.**
///
/// RFC 6 §2.6: a change to the authority model is indistinguishable from a
/// compromise of it, so there is no operation that alters this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Authority {
    /// Only the creator may add or remove.
    CreatorOnly = 1,
    /// Any member may.
    AnyMember = 2,
}

impl Authority {
    fn from_byte(b: u8) -> Option<Authority> {
        match b {
            1 => Some(Authority::CreatorOnly),
            2 => Some(Authority::AnyMember),
            _ => None,
        }
    }
}

/// Above this, RFC 6 §2.4 requires a warning.
///
/// Not a comfort number: at fifty members fan-out is paying `49×` to
/// compartmentalise a secret fifty people already share, and the realistic
/// disclosure path is a person rather than a cryptanalyst. Above 25 the
/// correct mechanism is a channel, which costs 380× less at G=20.
pub const WARN_ABOVE: usize = 25;

/// Above this, RFC 6 §2.4 requires a **refusal**.
pub const REFUSE_ABOVE: usize = 50;

/// A group as this node understands it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// Operator-chosen name. Local only — it is not in any signature, so two
    /// members may call one group different things and neither is wrong.
    pub name: String,
    /// Roster epoch. Increments on every membership change.
    pub epoch: u64,
    /// Member node ids, sorted, so two nodes with the same membership produce
    /// the same roster regardless of the order they learned it.
    pub members: Vec<[u8; 32]>,
    /// Fixed at creation.
    pub authority: Authority,
}

/// What to tell the operator before they commit to a membership change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SizeVerdict {
    /// Below the threshold; nothing to say.
    Fine,
    /// RFC 6 §2.4 — above 25.
    Warn(String),
    /// RFC 6 §2.4 — above 50. **The operation does not proceed.**
    Refuse(String),
}

impl Group {
    /// A new group with one member: its creator.
    pub fn new(name: &str, creator: [u8; 32], authority: Authority) -> Group {
        Group {
            name: name.to_string(),
            epoch: 1,
            members: vec![creator],
            authority,
        }
    }

    /// Whether a roster of this size is allowed, and what to say about it.
    ///
    /// **Evaluated at join time, not at failure time** — RFC 6 §5 requirement
    /// 5. A warning that arrives when a send fails arrives after the operator
    /// has already told people they are in the group.
    pub fn size_verdict(size: usize) -> SizeVerdict {
        if size > REFUSE_ABOVE {
            return SizeVerdict::Refuse(format!(
                "a group of {size} exceeds the limit of {REFUSE_ABOVE} (RFC 6 §2.4).\n\n\
                 Fan-out seals one copy per member, so this costs {}× a single \
                 message — to compartmentalise a secret {size} people already \
                 share. Use a channel: constant cost, and it does not grow with \
                 the audience.",
                size.saturating_sub(1)
            ));
        }
        if size > WARN_ABOVE {
            return SizeVerdict::Warn(format!(
                "a group of {size} is above the recommended {WARN_ABOVE} (RFC 6 §2.4).\n\n\
                 Each message is sealed {}× over. Above this size the realistic \
                 disclosure path is a person, not a cryptanalyst, so the \
                 compartmentalisation is buying very little.",
                size.saturating_sub(1)
            ));
        }
        SizeVerdict::Fine
    }

    /// Prekey adequacy for a group this size — RFC 6 §2.8, RFC 7 §5.3.
    ///
    /// A member receives `G−1` messages per round, so membership dominates
    /// prekey consumption. Returns a warning when the node's current batch
    /// cannot cover `days` at that rate.
    ///
    /// **Surfaced at join, not at exhaustion.** Running out degrades forward
    /// secrecy *silently* — the sender falls back to the signed prekey and
    /// nothing fails — which is precisely why it cannot be left to be
    /// discovered.
    pub fn prekey_warning(size: usize, batch_keys: usize, days: u32) -> Option<String> {
        // RFC 6 §2.8's table is two messages per member per day.
        let received_per_day = (size.saturating_sub(1) as u32) * 2;
        if received_per_day == 0 {
            return None;
        }
        let needed = krab_crypto::prekey::PrekeyBatch::size_for(received_per_day, days);
        if needed <= batch_keys {
            return None;
        }
        Some(format!(
            "at {size} members you would receive about {received_per_day} messages a day, \
             which needs {needed} one-time prekeys to cover {days} days. This node \
             publishes {batch_keys}.\n\n\
             Exhaustion does not fail — it falls back to the signed prekey and \
             quietly weakens forward secrecy (RFC 6 §2.8). Republish weekly, or \
             keep the group smaller."
        ))
    }

    /// Add a member. Returns the verdict; the roster is unchanged on `Refuse`.
    pub fn add(&mut self, who: [u8; 32]) -> SizeVerdict {
        if self.members.contains(&who) {
            return SizeVerdict::Fine;
        }
        let verdict = Self::size_verdict(self.members.len() + 1);
        if matches!(verdict, SizeVerdict::Refuse(_)) {
            return verdict;
        }
        self.members.push(who);
        self.members.sort();
        self.epoch += 1;
        verdict
    }

    /// Remove a member.
    pub fn remove(&mut self, who: &[u8; 32]) -> bool {
        let before = self.members.len();
        self.members.retain(|m| m != who);
        if self.members.len() != before {
            self.epoch += 1;
            return true;
        }
        false
    }

    /// Compare an incoming roster against this one — RFC 6 §2.6.
    ///
    /// **Returns a description, and changes nothing.** Merging is the caller's
    /// deliberate act, because silent convergence hides the one event a user
    /// needs to see.
    pub fn divergence(&self, theirs: &Group) -> Option<String> {
        if theirs.epoch == self.epoch && theirs.members == self.members {
            return None;
        }
        let unknown: Vec<_> = theirs
            .members
            .iter()
            .filter(|m| !self.members.contains(m))
            .collect();
        let missing: Vec<_> = self
            .members
            .iter()
            .filter(|m| !theirs.members.contains(m))
            .collect();

        let mut out = format!(
            "roster divergence in \"{}\": they are at epoch {}, you are at {}.\n",
            self.name, theirs.epoch, self.epoch
        );
        if !unknown.is_empty() {
            out.push_str(&format!(
                "\n{} member(s) you do not know about:\n",
                unknown.len()
            ));
            for m in &unknown {
                out.push_str(&format!("  {}\n", short(m)));
            }
        }
        if !missing.is_empty() {
            out.push_str(&format!(
                "\n{} member(s) they do not have:\n",
                missing.len()
            ));
            for m in &missing {
                out.push_str(&format!("  {}\n", short(m)));
            }
        }
        out.push_str(
            "\nThis is NOT resolved automatically. A member added without your \
             knowledge and a roster you have not yet received look identical, and \
             smoothing that over would hide the difference (RFC 6 §2.6). \
             `group merge <name>` adopts theirs, deliberately.",
        );
        Some(out)
    }

    /// Deterministic CBOR — RFC 1 §4.3.
    pub fn encode(&self) -> Vec<u8> {
        let mut flat = Vec::with_capacity(self.members.len() * 32);
        for m in &self.members {
            flat.extend_from_slice(m);
        }
        let mut w = cbor::Writer::new();
        w.map(4)
            .uint(1)
            .tstr(&self.name)
            .uint(2)
            .uint(self.epoch)
            .uint(3)
            .bstr(&flat)
            .uint(4)
            .uint(self.authority as u64);
        w.finish()
    }

    /// Decode. A roster arrives from a peer, so nothing here allocates on a
    /// declared count or accepts a size the rules forbid.
    pub fn decode(bytes: &[u8]) -> Option<Group> {
        let mut r = cbor::Reader::new(bytes);
        let mut m = r.map().ok()?;
        if m.left() != 4 {
            return None;
        }
        let name = tstr_at(&mut m, 1)?.to_string();
        if name.len() > 64 {
            return None;
        }
        let epoch = uint_at(&mut m, 2)?;
        let flat = bstr_at(&mut m, 3)?;
        if flat.len() % 32 != 0 {
            return None;
        }
        // A roster above the hard limit is one this node would refuse to
        // build, so it is one it refuses to adopt.
        if flat.len() / 32 > REFUSE_ABOVE {
            return None;
        }
        let mut members: Vec<[u8; 32]> = flat
            .chunks_exact(32)
            .map(|c| c.try_into().expect("32 bytes"))
            .collect();
        members.sort();
        members.dedup();
        let authority = Authority::from_byte(u8::try_from(uint_at(&mut m, 4)?).ok()?)?;
        Some(Group {
            name,
            epoch,
            members,
            authority,
        })
    }
}

/// A member identifier, as an operator reads it.
pub fn short(id: &[u8; 32]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}", id[0], id[1], id[2], id[3])
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

fn tstr_at<'a>(m: &mut cbor::MapReader<'a, '_>, k: u64) -> Option<&'a str> {
    match at(m, k)? {
        cbor::Item::Tstr(s) => Some(s),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn group_of(n: usize) -> Group {
        let mut g = Group::new("test", member(0), Authority::CreatorOnly);
        for i in 1..n {
            g.members.push(member(i as u8));
        }
        g.members.sort();
        g
    }

    /// **RFC 6 §2.4's thresholds, at join time.** Above 25 warn; above 50
    /// refuse. A warning that arrives when a send fails arrives after the
    /// operator has already told people they are in the group.
    #[test]
    fn size_warns_above_twenty_five_and_refuses_above_fifty() {
        assert_eq!(Group::size_verdict(1), SizeVerdict::Fine);
        assert_eq!(Group::size_verdict(WARN_ABOVE), SizeVerdict::Fine);
        assert!(matches!(
            Group::size_verdict(WARN_ABOVE + 1),
            SizeVerdict::Warn(_)
        ));
        assert!(matches!(
            Group::size_verdict(REFUSE_ABOVE),
            SizeVerdict::Warn(_)
        ));
        assert!(matches!(
            Group::size_verdict(REFUSE_ABOVE + 1),
            SizeVerdict::Refuse(_)
        ));
    }

    /// A refusal changes nothing. A roster that grew past the limit and then
    /// reported a refusal would have already done the thing it refused.
    #[test]
    fn a_refused_addition_leaves_the_roster_untouched() {
        let mut g = group_of(REFUSE_ABOVE + 1);
        let before = g.clone();
        assert!(matches!(g.add(member(200)), SizeVerdict::Refuse(_)));
        assert_eq!(g, before, "the refused member was added anyway");
    }

    /// Adding advances the epoch; adding the same member twice does not, since
    /// nothing changed and a spurious epoch bump is a spurious divergence at
    /// every other member.
    #[test]
    fn the_epoch_tracks_real_membership_changes() {
        let mut g = Group::new("g", member(0), Authority::AnyMember);
        assert_eq!(g.epoch, 1);
        g.add(member(1));
        assert_eq!(g.epoch, 2);
        g.add(member(1));
        assert_eq!(g.epoch, 2, "re-adding a member moved the epoch");
        assert!(g.remove(&member(1)));
        assert_eq!(g.epoch, 3);
        assert!(!g.remove(&member(1)));
        assert_eq!(g.epoch, 3);
    }

    /// **RFC 6 §2.6.** Divergence is described, never resolved — and the
    /// description says what is different, because "out of sync" alone gives
    /// an operator no way to tell an attack from latency.
    #[test]
    fn divergence_is_reported_in_detail_and_changes_nothing() {
        let mine = group_of(3);
        let mut theirs = mine.clone();
        theirs.add(member(99));

        let before = mine.clone();
        let report = mine.divergence(&theirs).expect("they diverge");
        assert_eq!(mine, before, "comparing changed the roster");

        assert!(report.contains("epoch"), "{report}");
        assert!(
            report.contains("1 member(s) you do not know about"),
            "{report}"
        );
        assert!(report.contains(&short(&member(99))), "{report}");
        assert!(
            report.contains("NOT resolved automatically"),
            "silent merge is not ruled out in the text: {report}"
        );
    }

    /// Divergence in the other direction is reported too — a member *they*
    /// have not got is equally a difference, and equally invisible otherwise.
    #[test]
    fn a_member_they_lack_is_also_a_divergence() {
        let mut mine = group_of(3);
        mine.add(member(99));
        let theirs = group_of(3);
        let report = mine.divergence(&theirs).expect("they diverge");
        assert!(report.contains("1 member(s) they do not have"), "{report}");
    }

    /// Identical rosters at identical epochs are not a divergence, or every
    /// message would raise one and the warning would stop meaning anything.
    #[test]
    fn identical_rosters_do_not_diverge() {
        let g = group_of(4);
        assert_eq!(g.divergence(&g.clone()), None);
    }

    /// **RFC 6 §2.8.** Group size dominates prekey consumption, and
    /// exhaustion degrades forward secrecy *silently* — so it is surfaced at
    /// join rather than discovered.
    #[test]
    fn prekey_adequacy_is_reported_at_join_time() {
        // A pair burns almost nothing.
        assert_eq!(Group::prekey_warning(2, 64, 7), None);
        // A large group over a month does not fit a small batch.
        let warn = Group::prekey_warning(20, 64, 30).expect("20 members must warn");
        assert!(warn.contains("one-time prekeys"), "{warn}");
        assert!(
            warn.contains("weakens forward secrecy") || warn.contains("forward secrecy"),
            "the consequence is not stated: {warn}"
        );
        // A node alone in a group receives nothing.
        assert_eq!(Group::prekey_warning(1, 8, 30), None);
    }

    #[test]
    fn a_group_round_trips() {
        let g = group_of(5);
        assert_eq!(Group::decode(&g.encode()), Some(g));
    }

    /// A roster this node would refuse to build is one it refuses to adopt,
    /// and nothing arriving from a peer causes a panic.
    #[test]
    fn malformed_or_oversized_rosters_are_refused() {
        assert_eq!(Group::decode(&[]), None);
        let big = group_of(REFUSE_ABOVE + 1);
        assert_eq!(
            Group::decode(&big.encode()),
            None,
            "a roster above the hard limit was adopted"
        );

        let good = group_of(3).encode();
        for cut in 0..good.len() {
            let _ = Group::decode(&good[..cut]);
        }
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0xff;
            let _ = Group::decode(&bad);
        }
    }

    /// Membership order must not depend on the order it was learned, or two
    /// members with the same roster would report a divergence forever.
    #[test]
    fn rosters_are_order_independent() {
        let mut a = Group::new("g", member(3), Authority::AnyMember);
        a.add(member(1));
        a.add(member(2));
        let mut b = Group::new("g", member(3), Authority::AnyMember);
        b.add(member(2));
        b.add(member(1));
        assert_eq!(a.members, b.members);
        assert_eq!(a.divergence(&b), None);
    }
}
