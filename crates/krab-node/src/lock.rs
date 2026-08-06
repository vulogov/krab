//! Lock: the runtime transition between mailbox and relay.
//!
//! `Documentation/RFC-7-review.md` §9. Krab has no headless mode, so an
//! always-on TUI holding decryption keys is RFC 0 §5.1's "endpoint seizure,
//! powered on" case standing by default. Lock is the control that bridges it,
//! and RFC 7 §7 already contains the shape:
//!
//! > **A locked TUI is a relay. An unlocked TUI is a mailbox.**
//!
//! # It is a memory operation, not a disk-hierarchy split
//!
//! The disk hierarchy is unchanged — one root, the passphrase, exactly as
//! RFC 7 §4 draws it. Credentials were unwrapped at startup and are *already
//! in memory*, so lock does not need to read anything; it needs to decline to
//! wipe part of what it already holds.
//!
//! ```text
//! on lock   zeroize   tag precomputation table, prekey privates,
//!                     reservoir chunks, plaintext, composer buffer, the KEK
//!           retain    Noise static, peer credentials, corpus working key,
//!                     live session state
//! ```
//!
//! An earlier draft of this design proposed a second on-disk root with its own
//! device secret, which would have pulled in an OS keychain or a TPM. It
//! solved a problem that does not exist.
//!
//! # A relay is this, at startup
//!
//! RFC 7 §7 currently says a relay takes *no passphrase*, which leaves its disk
//! unencrypted and makes RFC 0 §4.4's "seizure yields nothing" false for the
//! peer list. Under this model a relay is a TUI **unlocked once at startup and
//! locked immediately** — so its disk is encrypted like any other node's, at
//! the cost of one prompt.

use krab_crypto::Key;

/// What a node can do right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Unlocked. Full key hierarchy; can read its own mail.
    Mailbox,
    /// Locked. Session keys only; reconciles, and cannot recognise its own
    /// traffic. RFC 0 §4.4's relay, demonstrated rather than asserted.
    Relay,
}

/// Material destroyed on lock.
///
/// The tag precomputation table is the reason this exists. RFC 2 §9 calls it
/// *"the single most valuable artifact on a seized running node"* — it maps
/// tags to correspondents, which is precisely the correlation the whole design
/// prevents everyone else from making.
#[derive(Debug)]
pub struct ContentKeys {
    /// Root of RFC 7 §4's hierarchy, derived from the passphrase.
    pub kek: Key,
    /// Tag → correspondent. RFC 2 §4.3 sizes it at 4 550 entries for 50
    /// correspondents at ±45, rebuilt in about 6.8 ms.
    pub tag_table_len: usize,
    /// One-time prekey private halves.
    pub prekeys: usize,
    /// Reservoir chunks, per peer.
    pub reservoir_chunks: usize,
}

/// Material retained across lock.
///
/// Everything reconciliation needs, and nothing that reads mail. That is what
/// makes a locked node a relay rather than a stopped one.
#[derive(Debug)]
pub struct LinkKeys {
    /// Answers a Noise IK handshake (RFC 4 §4.1).
    pub noise_static: Key,
    /// Verifies an initiator's static key and derives RFC 5 §2's filter.
    pub credentials: usize,
}

/// A node's live key state.
#[derive(Debug)]
pub struct Session {
    link: LinkKeys,
    content: Option<ContentKeys>,
    /// Plaintext currently displayed, and the composer buffer.
    plaintext: Vec<u8>,
    composer: String,
}

impl Session {
    /// An unlocked session.
    pub fn unlocked(link: LinkKeys, content: ContentKeys) -> Session {
        Session { link, content: Some(content), plaintext: Vec::new(), composer: String::new() }
    }

    /// Current role.
    pub fn role(&self) -> Role {
        if self.content.is_some() {
            Role::Mailbox
        } else {
            Role::Relay
        }
    }

    /// Whether the node can read its own mail.
    pub fn can_decrypt(&self) -> bool {
        self.content.is_some()
    }

    /// Whether the node can answer a handshake and reconcile.
    ///
    /// **Always true.** Lock never takes this away, which is the entire point:
    /// RFC-8-review.md §8.5 makes pausing reconciliation while locked an I-5
    /// violation worse than mail-driven sync, because it leaks a *daily
    /// rhythm* rather than sporadic events.
    pub fn can_reconcile(&self) -> bool {
        !self.link.noise_static.is_destroyed()
    }

    /// Displayed plaintext, present only while unlocked.
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    /// The composer buffer.
    pub fn composer(&self) -> &str {
        &self.composer
    }

    /// Decrypt into the view. RFC 8 §2.2 — plaintext exists only while shown.
    pub fn show(&mut self, bytes: Vec<u8>) -> Result<(), Locked> {
        if self.content.is_none() {
            return Err(Locked);
        }
        self.plaintext = bytes;
        Ok(())
    }

    /// Type into the composer.
    pub fn compose(&mut self, s: &str) -> Result<(), Locked> {
        if self.content.is_none() {
            return Err(Locked);
        }
        self.composer.push_str(s);
        Ok(())
    }

    /// **Lock immediately.**
    ///
    /// No confirmation and no grace period: lock is used when someone walks
    /// into the room. Returns the number of secrets destroyed.
    ///
    /// The composer buffer is zeroized with everything else, so a draft is
    /// lost. RFC 7 §8 forbids storing plaintext and there is no unproblematic
    /// place to put it — sealing it to self would put unsent text in the
    /// corpus, with an identifier and a TTL. `RFC-8-review.md` §8.6 records
    /// that as the one open question in the lock design.
    pub fn lock(&mut self) -> usize {
        let mut destroyed = 0;
        if let Some(mut c) = self.content.take() {
            c.kek.destroy();
            destroyed = 1 + c.tag_table_len + c.prekeys + c.reservoir_chunks;
        }
        self.plaintext.iter_mut().for_each(|b| *b = 0);
        self.plaintext.clear();
        // Overwrite before clearing: `String::clear` sets the length and
        // leaves the bytes, which is the residue RFC 7 §9 warns about.
        unsafe_free_overwrite(&mut self.composer);
        destroyed
    }

    /// Unlock with re-derived content material.
    ///
    /// The caller performs Argon2id — RFC 7 §4.1 calibrates it at ~500 ms,
    /// which is the right cost for this operation.
    pub fn unlock(&mut self, content: ContentKeys) {
        self.content = Some(content);
    }
}

/// Overwrite a `String`'s bytes before clearing it.
///
/// Named to be conspicuous. `String::clear` sets the length to zero and leaves
/// the allocation intact, so the plaintext stays in the heap until something
/// happens to reuse it — exactly the residue RFC 7 §9.1 concedes Rust cannot
/// fully prevent, but this part is preventable.
fn unsafe_free_overwrite(s: &mut String) {
    let n = s.len();
    s.clear();
    s.reserve(n);
    for _ in 0..n {
        s.push('\0');
    }
    s.clear();
}

/// The operation needs content keys and the node is locked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Locked;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::Scheduler;

    fn session() -> Session {
        Session::unlocked(
            LinkKeys { noise_static: Key::new([1; 32]), credentials: 8 },
            ContentKeys {
                kek: Key::new([2; 32]),
                tag_table_len: 4_550,
                prekeys: 256,
                reservoir_chunks: 45,
            },
        )
    }

    #[test]
    fn lock_is_immediate_and_total() {
        let mut s = session();
        s.show(vec![0xAB; 200]).unwrap();
        s.compose("a draft nobody will see again").unwrap();
        assert_eq!(s.role(), Role::Mailbox);

        let destroyed = s.lock();

        assert_eq!(s.role(), Role::Relay);
        assert!(!s.can_decrypt());
        assert!(s.plaintext().is_empty(), "displayed plaintext zeroized");
        assert!(s.composer().is_empty(), "composer zeroized -- the draft is gone");
        assert_eq!(destroyed, 1 + 4_550 + 256 + 45);
    }

    /// The whole point: a locked node keeps relaying.
    #[test]
    fn a_locked_node_still_reconciles() {
        let mut s = session();
        s.lock();
        assert!(s.can_reconcile(), "session keys retained -- this is the relay role");
        assert!(!s.can_decrypt(), "and it cannot read its own mail");
    }

    /// RFC 0 §4.4 *asserts* a relay holds no message decryption keys. A locked
    /// TUI demonstrates it, in the process that was a mailbox a moment ago.
    #[test]
    fn a_locked_node_cannot_recognise_its_own_mail() {
        let mut s = session();
        s.lock();
        // The tag table went with the content tier, so nothing maps a tag to a
        // correspondent. Attempting to decrypt is refused outright.
        assert_eq!(s.show(vec![1, 2, 3]), Err(Locked));
        assert_eq!(s.compose("x"), Err(Locked));
    }

    #[test]
    fn unlock_restores_the_mailbox_role() {
        let mut s = session();
        s.lock();
        s.unlock(ContentKeys {
            kek: Key::new([3; 32]),
            tag_table_len: 4_550,
            prekeys: 256,
            reservoir_chunks: 45,
        });
        assert_eq!(s.role(), Role::Mailbox);
        assert!(s.show(vec![9; 10]).is_ok());
    }

    /// **The second I-5 absence test**, which `RFC-8-review.md` §8.5 argues is
    /// the cheaper of the two to get wrong.
    ///
    /// Pausing sync while locked reads as a battery optimisation and would
    /// publish the operator's daily presence schedule to every peer — worse
    /// than mail-driven sync, because it leaks a rhythm rather than events.
    ///
    /// It is structurally impossible here: `Scheduler` has no lock parameter,
    /// and `Session` has no scheduler. Neither can reach the other, so the
    /// test asserts the schedule is byte-identical across a run that locks and
    /// one that does not.
    #[test]
    fn locking_does_not_alter_the_schedule() {
        let run = |lock_at: Option<u64>| {
            let mut sched = Scheduler::new(600);
            let mut sess = session();
            for n in 1..=4u8 {
                sched.add([n; 32], 0, 0xFEED ^ n as u64);
            }
            let mut fired = Vec::new();
            for t in (0..20_000u64).step_by(60) {
                if Some(t) == lock_at {
                    sess.lock();
                }
                fired.extend(sched.due(t, 0xBEEF ^ t));
            }
            (fired, sess.role())
        };

        let (never, r1) = run(None);
        let (early, r2) = run(Some(600));
        let (late, r3) = run(Some(9_960)); // must land on the 60-second step

        assert_eq!(never, early, "locking early must not change the schedule");
        assert_eq!(never, late, "nor locking late");
        assert!(!never.is_empty(), "and the schedule must actually fire");
        assert_eq!(r1, Role::Mailbox);
        assert_eq!(r2, Role::Relay);
        assert_eq!(r3, Role::Relay);
    }

    /// Locking twice is safe — the panic-wipe path may fire on an already
    /// locked node, and RFC 7 §10 makes it a command a user can press.
    #[test]
    fn lock_is_idempotent() {
        let mut s = session();
        assert!(s.lock() > 0);
        assert_eq!(s.lock(), 0, "nothing left to destroy");
        assert_eq!(s.role(), Role::Relay);
        assert!(s.can_reconcile());
    }
}
