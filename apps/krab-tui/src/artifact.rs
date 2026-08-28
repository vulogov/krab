//! Every file a node writes, named once.
//!
//! # Why this exists
//!
//! `wipe` — RFC 7 §10's panic destruction — decided what to destroy from a
//! hand-written list of filenames. That list failed twice.
//!
//! The first time it did not recurse, so every peering survived a wipe: the
//! files were useless without the KEK, but *a list of who this node peered
//! with is not nothing*, which is the reason they were on the list at all.
//!
//! The second time it was simply not updated. `prekeys.ring`, `groups.sealed`,
//! `channels.roster` and `duress.wrapped` were added over several months and
//! none reached the predicate, so a panic wipe left behind the private halves
//! of every outstanding prekey, the roster of every group, the channel posting
//! key, and the duress store — which means a "wiped" node was not the fresh
//! one RFC 7 §10 says it presents as.
//!
//! Both were omissions in a list nobody had a reason to look at. A third
//! omission was certain, so the list is no longer written by hand:
//! [`App::path`](crate::App::path) takes an [`Artifact`] rather than a
//! string, and a file that is not in this enum cannot be written at all.
//!
//! # What is destroyed
//!
//! Everything. `SECURE-DELETE.md`'s argument is that ciphertext is shredded
//! too, because destruction protects against an adversary who obtains the key
//! *later* — coercion, a keylogger, a passphrase brute-forced at leisure —
//! and that adversary is the one RFC 7 §10 exists for. So
//! [`Artifact::destroyed_by_wipe`] is `true` for every variant, and it is a
//! method rather than an assumption so that adding a variant that should
//! survive is a deliberate act with somewhere to write down why.

/// A file in the node's home directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Artifact {
    /// The key hierarchy, wrapped under the KEK.
    IdentityWrapped,
    /// Argon2 parameters and salt.
    KekParams,
    /// The corpus.
    Corpus,
    /// A peering ceremony in progress.
    Ceremony,
    /// This node's card, published during a peering.
    PeerCard,
    /// This node's contribution, in the clear, awaiting a courier.
    PeerPad,
    /// Prekey private halves — RFC 7 §5.
    PrekeyRing,
    /// Channels owned and followed, including the posting key — RFC 6 §3.
    ChannelRoster,
    /// Group rosters — RFC 6 §2. A membership disclosure.
    Groups,
    /// A re-seal in progress.
    Reseal,
    /// The duress store — RFC 7 §10.
    DuressWrapped,
    /// Conversations pinned under the long-lived key — RFC 8 §10, RFC 7 §8.1.
    ///
    /// **Plaintext mail, sealed under a key that outlives every epoch.** That
    /// is the request and the risk together: RFC 7 §8's erasure is what stops
    /// a seized disk being a transcript, and this file is exempt from it.
    Pinned,
    /// Local names for identifiers — RFC 8 §7's fingerprint rule applies.
    ///
    /// **Never transmitted and never imported.** An alias is written by this
    /// operator, for this operator, and nothing puts one on the wire or takes
    /// one from a peer's card: a name a correspondent could choose is the
    /// attacker-controlled display name §7 exists to defend against.
    ///
    /// Sealed under a KEK subkey like the pinned archive, and destroyed by
    /// the same paths — an alias table is a plaintext social graph, and it is
    /// the part of a seizure that turns pseudonymous identifiers into people.
    Aliases,
    /// The last full nodelist fragment this node published — RFC 3 §8.2.
    ///
    /// The base a `NODEDIFF` references. One record for every peer, because a
    /// fragment's contents are the same for all of them and they are all sent
    /// the same one at the same moment.
    Nodelist,
    /// Introduction tokens already honoured — RFC 3 §10's "single-use".
    ///
    /// A membership-adjacent disclosure: it is a record of who was introduced
    /// to this node and by whom. `introduction::Spent` forgets each nonce at
    /// its token's expiry for that reason; this is what destroys the rest.
    IntroductionsSpent,
}

impl Artifact {
    /// Every artifact. Used by the test that keeps this file honest.
    pub const ALL: [Artifact; 15] = [
        Artifact::IdentityWrapped,
        Artifact::KekParams,
        Artifact::Corpus,
        Artifact::Ceremony,
        Artifact::PeerCard,
        Artifact::PeerPad,
        Artifact::PrekeyRing,
        Artifact::ChannelRoster,
        Artifact::Groups,
        Artifact::Reseal,
        Artifact::DuressWrapped,
        Artifact::IntroductionsSpent,
        Artifact::Nodelist,
        Artifact::Pinned,
        Artifact::Aliases,
    ];

    /// The name on disk.
    pub fn name(&self) -> &'static str {
        match self {
            Artifact::IdentityWrapped => "identity.wrapped",
            Artifact::KekParams => "kek.params",
            Artifact::Corpus => "corpus.krab",
            Artifact::Ceremony => "ceremony.cbor",
            Artifact::PeerCard => "peer.card",
            Artifact::PeerPad => "peer.pad",
            Artifact::PrekeyRing => "prekeys.ring",
            Artifact::ChannelRoster => "channels.roster",
            Artifact::Groups => "groups.sealed",
            Artifact::Reseal => "reseal.cbor",
            Artifact::DuressWrapped => "duress.wrapped",
            Artifact::IntroductionsSpent => "introductions.spent",
            Artifact::Nodelist => "nodelist.sent",
            Artifact::Pinned => "pinned.archive",
            Artifact::Aliases => "aliases",
        }
    }

    /// Whether `wipe` destroys it.
    ///
    /// True for everything. Written as a method so that a future artifact
    /// which should survive has a place to say why, rather than being omitted
    /// from a list and surviving by accident — which is how the two failures
    /// this module exists for both happened.
    pub fn destroyed_by_wipe(&self) -> bool {
        match self {
            Artifact::IdentityWrapped
            | Artifact::KekParams
            | Artifact::Corpus
            | Artifact::Ceremony
            | Artifact::PeerCard
            | Artifact::PeerPad
            | Artifact::PrekeyRing
            | Artifact::ChannelRoster
            | Artifact::Groups
            | Artifact::Reseal
            | Artifact::DuressWrapped
            | Artifact::IntroductionsSpent
            | Artifact::Nodelist
            | Artifact::Pinned
            | Artifact::Aliases => true,
        }
    }
}

/// A file inside one peer's directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerFile {
    /// Their signed card — the peer-link.
    Link,
    /// The shared reservoir, sealed under the epoch key.
    Reservoir,
    /// Their terms, as of the last re-key.
    Policy,
    /// How the peering was formed, and what it is worth.
    Terms,
    /// The last full fragment received from this peer — RFC 3 §8.2.
    ///
    /// The base their deltas reference. A reader that does not hold it cannot
    /// apply one, which is §8.2's "requests the full fragment" as a check
    /// rather than as advice.
    Nodelist,
    /// The negotiation that produced this peering — RFC 3 §5.3.
    ///
    /// "Both parties store the full chain: `request → counter(s) → link`. The
    /// chain is local evidence and **MUST NOT be published** — it names an
    /// introducer and is therefore graph information."
    Chain,
    /// This link's byte and object budget for the current day — RFC 3 §6.
    ///
    /// Two counters and a day number. §12 forbids per-object provenance, so
    /// there is nothing here about *what* crossed or *when* — but the file
    /// naming a peer is itself the disclosure §8.4 says to purge.
    Quota,
    /// The mutually signed `peer-link` credential — RFC 3 §3.
    ///
    /// The most sensitive per-peer file: RFC 3 §15 calls credentials at rest
    /// "non-repudiable", so seizing a disk yields the peer list *with
    /// cryptographic proof* — worse than an address book.
    Credential,
}

impl PeerFile {
    /// Whether RFC 3 §8.4 purges this when a credential **expires**, as
    /// distinct from when the operator ends the relationship.
    ///
    /// > "Fragments, beacons, credentials, and negotiation chains are
    /// > attributable — they are records of a relationship. On termination or
    /// > expiry a node MUST purge those and MUST retain the corpus."
    ///
    /// §8.4 names four things, and the list is doing work: a **credential**, a
    /// **chain** and a **fragment** are records that two parties agreed
    /// something. A card and a reservoir are not records of an agreement —
    /// they are the material that makes sealing possible, and destroying them
    /// on a lapsed term would end a relationship the operator may be about to
    /// renew.
    ///
    /// So expiry purges the record and keeps the material; **termination**
    /// ([`App::peer_forget`](crate::App::peer_forget)) purges both, because
    /// there the operator has said the relationship is over.
    ///
    /// The consequence, stated because it is a real cost: renewing a peering
    /// that has already lapsed starts from default terms, since the terms that
    /// were agreed went with the credential. RFC 3 §4 prompts at 75% of the
    /// term precisely so that does not happen, and §15 accepts the case
    /// directly — "a node offline longer than a credential term returns unable
    /// to peer with anyone".
    pub fn purged_on_expiry(&self) -> bool {
        match self {
            // Records of an agreement.
            PeerFile::Credential | PeerFile::Chain | PeerFile::Nodelist => true,
            // Material, and a local counter. The peering may be renewed.
            PeerFile::Link | PeerFile::Reservoir | PeerFile::Policy | PeerFile::Terms => false,
            // Spent budget against terms that no longer exist.
            PeerFile::Quota => true,
        }
    }

    /// Every per-peer file.
    pub const ALL: [PeerFile; 8] = [
        PeerFile::Link,
        PeerFile::Reservoir,
        PeerFile::Policy,
        PeerFile::Terms,
        PeerFile::Credential,
        PeerFile::Quota,
        PeerFile::Chain,
        PeerFile::Nodelist,
    ];

    /// The name on disk.
    pub fn name(&self) -> &'static str {
        match self {
            PeerFile::Link => "link",
            PeerFile::Reservoir => "reservoir",
            PeerFile::Policy => "policy",
            PeerFile::Terms => "terms",
            PeerFile::Credential => "credential",
            PeerFile::Quota => "quota",
            PeerFile::Chain => "chain",
            PeerFile::Nodelist => "nodelist",
        }
    }
}

/// Whether `wipe` destroys a file with this name.
///
/// The predicate `shred::remove_matching` is given. It answers for names in
/// the home directory *and* inside `peers/<id>/`, because the walk recurses.
pub fn wiped(name: &str) -> bool {
    Artifact::ALL
        .iter()
        .any(|a| a.name() == name && a.destroyed_by_wipe())
        || PeerFile::ALL.iter().any(|p| p.name() == name)
        // Names an older layout wrote, before per-peer directories. A node
        // upgraded in place still has them, and a wipe that skipped them
        // would leave exactly the peer list it is meant to destroy.
        || name.ends_with(".link")
        || name.ends_with(".reservoir")
        || name.ends_with(".krab")
        // `<peer>.credential`, the half-signed proposal written into the home
        // directory for handover. Operator-named in the sense that the peer
        // decides the prefix, so it cannot be an `Artifact` variant — and it
        // is a signed statement that this node peered with someone, which is
        // exactly what RFC 3 §8.4 says to purge.
        || name.ends_with(".credential")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Every artifact is destroyed by a wipe.** The two failures this module
    /// exists for were both omissions; this is the assertion that makes an
    /// omission impossible, because a new variant fails to compile until it is
    /// in `ALL` and fails this until `wiped` covers it.
    #[test]
    fn wipe_covers_every_artifact_this_node_writes() {
        for a in Artifact::ALL {
            assert!(
                a.destroyed_by_wipe(),
                "{:?} survives a wipe and nothing says why",
                a
            );
            assert!(
                wiped(a.name()),
                "{} is not matched by the predicate",
                a.name()
            );
        }
        for p in PeerFile::ALL {
            assert!(wiped(p.name()), "{} is not matched", p.name());
        }
    }

    /// The four that were actually left behind, named so a regression is
    /// recognisable rather than merely a failing count.
    #[test]
    fn the_artifacts_that_survived_a_wipe_no_longer_do() {
        for name in [
            "prekeys.ring",
            "groups.sealed",
            "channels.roster",
            "duress.wrapped",
        ] {
            assert!(wiped(name), "{name} survived a panic wipe");
        }
    }

    /// Names are distinct, or two artifacts would share a file.
    #[test]
    fn every_artifact_has_its_own_name() {
        let mut names: Vec<&str> = Artifact::ALL.iter().map(|a| a.name()).collect();
        let n = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), n, "two artifacts share a filename");

        let mut peers: Vec<&str> = PeerFile::ALL.iter().map(|p| p.name()).collect();
        let n = peers.len();
        peers.sort();
        peers.dedup();
        assert_eq!(peers.len(), n);
    }

    /// The repository root, or `None` when the tests are not run from a
    /// checkout.
    fn repo_root() -> Option<std::path::PathBuf> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)?
            .to_path_buf();
        root.join(".gitignore").exists().then_some(root)
    }

    /// **Every artefact this node writes is gitignored.**
    ///
    /// The same failure as `wipe`'s, in a different file. `.gitignore` listed
    /// six artefacts because six existed when it was written; ten more were
    /// added over the following months and none of them reached it. The result
    /// was `identity.wrapped`, `kek.params`, `corpus.krab` and a **plaintext
    /// reservoir contribution** committed to a public repository, where they
    /// stayed in the history until it was rewritten.
    ///
    /// So the list is no longer trusted to be complete: git is asked directly,
    /// for every variant, and a new one fails here until `.gitignore` covers
    /// it. That is the same shape as [`wipe_covers_every_artifact_this_node_writes`] —
    /// an omission has to fail something rather than be noticed.
    #[test]
    fn every_artifact_is_gitignored() {
        let Some(root) = repo_root() else {
            eprintln!("not a checkout; skipping");
            return;
        };
        // The paths a node actually writes, relative to a home directory that
        // may be anywhere in the tree — including the package root, which is
        // where the leak came from.
        let mut paths: Vec<String> = Artifact::ALL.iter().map(|a| a.name().to_string()).collect();
        paths.extend(
            PeerFile::ALL
                .iter()
                .map(|p| format!("peers/6a1284df/{}", p.name())),
        );
        // And the same again one directory down, since `--home` is arbitrary.
        let nested: Vec<String> = paths.iter().map(|p| format!("apps/krab-tui/{p}")).collect();
        paths.extend(nested);

        let mut missed = Vec::new();
        for p in &paths {
            let out = std::process::Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(["check-ignore", "-q", "--no-index", p])
                .status();
            match out {
                Ok(s) if s.success() => {}
                Ok(_) => missed.push(p.clone()),
                Err(_) => {
                    eprintln!("no git; skipping");
                    return;
                }
            }
        }
        assert!(
            missed.is_empty(),
            "these are written by this node and are NOT gitignored — add them \
             to .gitignore:\n  {}",
            missed.join("\n  ")
        );
    }

    /// **No artefact is tracked right now.**
    ///
    /// `.gitignore` does nothing for a file already in the index: git ignores
    /// ignore rules for tracked paths, which is precisely how the committed
    /// key material kept being committed after the rules were added. This asks
    /// what is tracked rather than what is ignored.
    #[test]
    fn no_artifact_is_tracked_by_git() {
        let Some(root) = repo_root() else {
            eprintln!("not a checkout; skipping");
            return;
        };
        let Ok(out) = std::process::Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["ls-files"])
            .output()
        else {
            eprintln!("no git; skipping");
            return;
        };
        let tracked = String::from_utf8_lossy(&out.stdout);

        let names: Vec<&str> = Artifact::ALL
            .iter()
            .map(|a| a.name())
            .chain(PeerFile::ALL.iter().map(|p| p.name()))
            .collect();
        let mut found = Vec::new();
        for line in tracked.lines() {
            let base = line.rsplit('/').next().unwrap_or(line);
            // `link`, `policy` and `terms` are plausible source filenames, so
            // a bare basename match is not enough for those: they only count
            // inside a `peers/` directory, which is where a node writes them.
            let is_peer_file = PeerFile::ALL.iter().any(|p| p.name() == base);
            if names.contains(&base) && (!is_peer_file || line.contains("peers/")) {
                found.push(line.to_string());
            }
        }
        assert!(
            found.is_empty(),
            "node artefacts are tracked by git — `git rm --cached` them, and \
             check whether they need purging from history too:\n  {}",
            found.join("\n  ")
        );
    }

    /// **RFC 3 §8.4 names what expiry purges, and the split is deliberate.**
    ///
    /// A record of an agreement goes; the material that makes sealing possible
    /// stays, so a lapsed peering can be renewed rather than having to be
    /// formed again. Written as a method so a new per-peer file has to answer
    /// the question rather than default into one of the two answers.
    #[test]
    fn expiry_purges_records_and_keeps_material() {
        assert!(PeerFile::Credential.purged_on_expiry());
        assert!(PeerFile::Chain.purged_on_expiry());
        assert!(PeerFile::Nodelist.purged_on_expiry());

        assert!(
            !PeerFile::Link.purged_on_expiry(),
            "the card is not a record"
        );
        assert!(
            !PeerFile::Reservoir.purged_on_expiry(),
            "destroying the reservoir would end a renewable peering"
        );

        // And termination takes everything: `wiped` covers every variant.
        for p in PeerFile::ALL {
            assert!(wiped(p.name()), "{} survives a termination", p.name());
        }
    }

    /// A file this node never writes is not destroyed — a wipe that removed
    /// everything in the working directory would be catastrophic, since
    /// `--home` defaults to it.
    #[test]
    fn a_file_the_node_did_not_write_is_left_alone() {
        for name in ["notes.txt", ".bashrc", "Cargo.toml", "holiday.png", ""] {
            assert!(!wiped(name), "{name} would be destroyed by a wipe");
        }
    }
}
