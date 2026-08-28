//! Local names for identifiers — never transmitted, never imported.
//!
//! # What an alias is allowed to be
//!
//! An identifier in Krab is a key. `0cf29190` is not memorable and is not
//! meant to be: RFC 8 §7 requires a fingerprint beside every display name
//! precisely because a *name* is the part an attacker would choose. So an
//! alias here is written by this operator, for this operator, and:
//!
//! - **it is never transmitted.** Nothing puts one in an object, a card, a
//!   rollcall entry or a nodelist fragment. It is a separate file that the
//!   send path does not read.
//! - **it is never imported.** There is no verb that takes a name from a
//!   peer. If there were, it would be the attacker-controlled display name
//!   that §7 exists to defend against, arriving through the front door.
//! - **it annotates and never replaces.** [`Aliases::show`] renders
//!   `alice (0cf29190)`, always both. An alias that replaced the identifier
//!   would become a trust signal it has not earned — "it says alice, so it is
//!   alice" — when the only thing establishing who is on the other end is the
//!   fingerprint comparison in RFC 3 §11 step 2.
//!
//! # And what it costs
//!
//! An alias table is a plaintext social graph. Encrypted at rest it is no
//! worse than the peer list beside it; what it changes is the harm from a
//! seizure of an *unlocked* node, which currently yields pseudonymous short
//! ids and would then yield "mum", "lawyer", "source". That is why it is
//! sealed under the KEK and destroyed by the same paths as the pinned
//! archive rather than merely being a file in the home directory.

use std::collections::BTreeMap;

/// Sealing domain, distinct from every other artifact's.
pub const DOMAIN: &[u8] = b"krab/alias/v1";

/// Longest alias kept. Long enough for a name, short enough that one cannot
/// be used to push an identifier off the end of a row.
pub const MAX_ALIAS: usize = 32;

/// Most aliases held, per table. A bound because the file is written from
/// typed input and an unbounded one is unbounded plaintext at rest.
pub const MAX_ALIASES: usize = 512;

/// Which table an alias belongs to.
///
/// Three, not one. A channel identifier and a node identifier are different
/// namespaces, and a name meaning one thing in each is ordinary rather than a
/// conflict — `weather` the channel and `weather` the peer who runs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `alias <short id> <name>` — for addressing private mail.
    Message,
    /// `alias-channel <channel id> <name>`.
    Channel,
    /// `alias-peer <peer id> <name>`.
    Peer,
}

impl Kind {
    fn tag(self) -> u8 {
        match self {
            Kind::Message => 0,
            Kind::Channel => 1,
            Kind::Peer => 2,
        }
    }

    fn of(tag: u8) -> Option<Kind> {
        match tag {
            0 => Some(Kind::Message),
            1 => Some(Kind::Channel),
            2 => Some(Kind::Peer),
            _ => None,
        }
    }

    /// The verb that writes this table, for messages that name it.
    pub fn verb(self) -> &'static str {
        match self {
            Kind::Message => "alias",
            Kind::Channel => "alias-channel",
            Kind::Peer => "alias-peer",
        }
    }
}

/// Why an alias was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// Longer than [`MAX_ALIAS`].
    TooLong,
    /// Empty, or nothing left after sanitising.
    Empty,
    /// The table is full.
    Full,
    /// It looks like a short id, which would make the annotation ambiguous.
    LooksLikeAnIdentifier,
}

/// The three tables.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Aliases {
    message: BTreeMap<String, String>,
    channel: BTreeMap<String, String>,
    peer: BTreeMap<String, String>,
}

impl Aliases {
    /// Derive the long-lived key from the KEK.
    pub fn key_from_kek(kek: &krab_crypto::kek::Kek) -> [u8; 32] {
        kek.subkey(DOMAIN)
    }

    fn table(&self, k: Kind) -> &BTreeMap<String, String> {
        match k {
            Kind::Message => &self.message,
            Kind::Channel => &self.channel,
            Kind::Peer => &self.peer,
        }
    }

    fn table_mut(&mut self, k: Kind) -> &mut BTreeMap<String, String> {
        match k {
            Kind::Message => &mut self.message,
            Kind::Channel => &mut self.channel,
            Kind::Peer => &mut self.peer,
        }
    }

    /// Name `id` in table `k`.
    ///
    /// The name is sanitised the way any other displayed text is — an alias
    /// is typed rather than received, but it can be pasted, and RFC 8 §7's
    /// rule is about what reaches the screen rather than about where it came
    /// from.
    pub fn set(&mut self, k: Kind, id: &str, name: &str) -> Result<(), Refused> {
        let clean = crate::display::safe(name).text.trim().to_string();
        if clean.is_empty() {
            return Err(Refused::Empty);
        }
        if clean.chars().count() > MAX_ALIAS {
            return Err(Refused::TooLong);
        }
        // **An alias must not look like an identifier.** `show` renders
        // `name (id)`; a name that is itself eight hex characters makes that
        // unreadable, and a name equal to *another* peer's short id is a
        // deliberate confusion this can simply refuse.
        if clean.len() == 8 && clean.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Refused::LooksLikeAnIdentifier);
        }
        let t = self.table_mut(k);
        if !t.contains_key(id) && t.len() >= MAX_ALIASES {
            return Err(Refused::Full);
        }
        t.insert(id.to_string(), clean);
        Ok(())
    }

    /// Forget the name for `id`. `true` if there was one.
    ///
    /// Removal is by *name* in the interface — `no alias <name>` — so this
    /// exists for the tests and for a caller that has the identifier.
    #[cfg(test)]
    pub fn clear(&mut self, k: Kind, id: &str) -> bool {
        self.table_mut(k).remove(id).is_some()
    }

    /// Forget by name rather than by identifier — `no alias <name>`.
    ///
    /// Returns the identifier it was on, so the operator is told what they
    /// just un-named: "removed alice (0cf29190)" rather than "removed", which
    /// on a mistyped name would be a silent no-op that looked like success.
    pub fn clear_by_name(&mut self, k: Kind, name: &str) -> Option<String> {
        let id = self
            .table(k)
            .iter()
            .find(|(_, v)| v.as_str() == name)
            .map(|(id, _)| id.clone())?;
        if let Some(v) = self.table_mut(k).get_mut(&id) {
            crate::overwrite(v);
        }
        self.table_mut(k).remove(&id);
        Some(id)
    }

    /// The name for `id`, if any.
    pub fn get(&self, k: Kind, id: &str) -> Option<&str> {
        self.table(k).get(id).map(String::as_str)
    }

    /// Every pair in one table, for listing.
    pub fn all(&self, k: Kind) -> Vec<(&str, &str)> {
        self.table(k)
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect()
    }

    /// How `id` is shown to the operator.
    ///
    /// **Both, always.** The identifier is what the node actually uses and
    /// what a fingerprint comparison established; the alias is a convenience
    /// this operator wrote. Rendering the alias alone would let a name stand
    /// in for a verification it did not perform.
    pub fn show(&self, k: Kind, id: &str) -> String {
        match self.get(k, id) {
            Some(name) => format!("{name} ({id})"),
            None => id.to_string(),
        }
    }

    /// Total names held, across the three tables.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.message.len() + self.channel.len() + self.peer.len()
    }

    /// Whether anything is named.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Serialise. A local file, so the framing is explicit rather than CBOR:
    /// nothing else reads it and it never reaches a wire.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for k in [Kind::Message, Kind::Channel, Kind::Peer] {
            for (id, name) in self.table(k) {
                out.push(k.tag());
                out.push(id.len().min(255) as u8);
                out.extend_from_slice(&id.as_bytes()[..id.len().min(255)]);
                out.push(name.len().min(255) as u8);
                out.extend_from_slice(&name.as_bytes()[..name.len().min(255)]);
            }
        }
        out
    }

    /// Parse. Anything malformed yields what was read so far rather than an
    /// error: a truncated alias file should cost names, not the session.
    pub fn decode(bytes: &[u8]) -> Aliases {
        let mut out = Aliases::default();
        let mut i = 0usize;
        while i + 2 <= bytes.len() {
            let Some(kind) = Kind::of(bytes[i]) else {
                break;
            };
            let id_len = bytes[i + 1] as usize;
            let id_at = i + 2;
            if id_at + id_len >= bytes.len() {
                break;
            }
            let name_len = bytes[id_at + id_len] as usize;
            let name_at = id_at + id_len + 1;
            if name_at + name_len > bytes.len() {
                break;
            }
            let (Ok(id), Ok(name)) = (
                std::str::from_utf8(&bytes[id_at..id_at + id_len]),
                std::str::from_utf8(&bytes[name_at..name_at + name_len]),
            ) else {
                break;
            };
            out.table_mut(kind).insert(id.to_string(), name.to_string());
            i = name_at + name_len;
        }
        out
    }

    /// Overwrite every name in place — RFC 7 §9.
    ///
    /// **Not called in production, deliberately.** The table is never held
    /// across calls: it is read from disk, changed, sealed and dropped within
    /// one verb, and `save_aliases` zeroes the encoded plaintext it produced.
    /// There is no long-lived copy for this to reach. It exists so that if
    /// one is ever introduced, the wipe for it is already written.
    #[cfg(test)]
    pub fn overwrite(&mut self) {
        for k in [Kind::Message, Kind::Channel, Kind::Peer] {
            let t = self.table_mut(k);
            let keys: Vec<String> = t.keys().cloned().collect();
            for key in keys {
                if let Some(v) = t.get_mut(&key) {
                    crate::overwrite(v);
                }
            }
            t.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_annotates_and_never_replaces() {
        let mut a = Aliases::default();
        a.set(Kind::Message, "0cf29190", "alice").unwrap();
        // Both, always: the identifier is what was verified, the name is a
        // convenience this operator wrote.
        assert_eq!(a.show(Kind::Message, "0cf29190"), "alice (0cf29190)");
        // And an unnamed identifier is itself, not blank.
        assert_eq!(a.show(Kind::Message, "deadbeef"), "deadbeef");
    }

    /// The three tables are separate namespaces, as asked.
    #[test]
    fn the_tables_do_not_leak_into_each_other() {
        let mut a = Aliases::default();
        a.set(Kind::Channel, "672bc3bf", "weather").unwrap();
        assert_eq!(a.get(Kind::Channel, "672bc3bf"), Some("weather"));
        assert_eq!(a.get(Kind::Message, "672bc3bf"), None);
        assert_eq!(a.get(Kind::Peer, "672bc3bf"), None);

        // The same name in two namespaces is ordinary, not a conflict.
        a.set(Kind::Peer, "672bc3bf", "weather").unwrap();
        assert_eq!(a.get(Kind::Peer, "672bc3bf"), Some("weather"));
    }

    /// A name that looks like an identifier makes `show` unreadable and could
    /// be another peer's id — refused rather than rendered.
    #[test]
    fn a_name_may_not_impersonate_an_identifier() {
        let mut a = Aliases::default();
        assert_eq!(
            a.set(Kind::Message, "0cf29190", "deadbeef"),
            Err(Refused::LooksLikeAnIdentifier)
        );
        // Not hex, so ordinary.
        a.set(Kind::Message, "0cf29190", "deadbeefs").unwrap();
    }

    #[test]
    fn names_are_sanitised_bounded_and_countable() {
        let mut a = Aliases::default();
        // RFC 8 §7 is about what reaches the screen, not where it came from.
        a.set(Kind::Message, "id1", "al\u{202e}ice").unwrap();
        assert_eq!(a.get(Kind::Message, "id1"), Some("alice"));

        assert_eq!(a.set(Kind::Message, "id2", ""), Err(Refused::Empty));
        assert_eq!(
            a.set(Kind::Message, "id3", &"x".repeat(MAX_ALIAS + 1)),
            Err(Refused::TooLong)
        );
        assert_eq!(a.len(), 1);
        assert!(a.clear(Kind::Message, "id1"));
        assert!(a.is_empty());
    }

    #[test]
    fn a_table_is_bounded() {
        let mut a = Aliases::default();
        for i in 0..MAX_ALIASES {
            a.set(Kind::Message, &format!("id{i}"), &format!("n{i}")).unwrap();
        }
        assert_eq!(a.set(Kind::Message, "one-more", "nope"), Err(Refused::Full));
        // Renaming something already named still works when full.
        a.set(Kind::Message, "id0", "renamed").unwrap();
    }

    #[test]
    fn it_round_trips_and_survives_truncation() {
        let mut a = Aliases::default();
        a.set(Kind::Message, "0cf29190", "alice").unwrap();
        a.set(Kind::Channel, "672bc3bf", "weather").unwrap();
        a.set(Kind::Peer, "7b4f469a", "bob").unwrap();
        let bytes = a.encode();
        assert_eq!(Aliases::decode(&bytes), a);

        // A truncated file costs names, not the session.
        let cut = Aliases::decode(&bytes[..bytes.len() / 2]);
        assert!(cut.len() < a.len());
    }

    /// Removal is by name, and says which identifier it freed.
    #[test]
    fn a_name_can_be_removed_by_name() {
        let mut a = Aliases::default();
        a.set(Kind::Message, "0cf29190", "alice").unwrap();
        assert_eq!(a.clear_by_name(Kind::Message, "nobody"), None);
        assert_eq!(
            a.clear_by_name(Kind::Message, "alice"),
            Some("0cf29190".to_string())
        );
        assert!(a.is_empty());
        // And only from the table asked for.
        a.set(Kind::Peer, "id", "bob").unwrap();
        assert_eq!(a.clear_by_name(Kind::Channel, "bob"), None);
        assert_eq!(a.get(Kind::Peer, "id"), Some("bob"));
    }

    #[test]
    fn overwrite_empties_every_table() {
        let mut a = Aliases::default();
        a.set(Kind::Message, "id", "alice").unwrap();
        a.set(Kind::Channel, "ch", "weather").unwrap();
        a.set(Kind::Peer, "pr", "bob").unwrap();
        a.overwrite();
        assert!(a.is_empty());
    }
}
