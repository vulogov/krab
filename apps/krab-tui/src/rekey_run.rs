//! Driving a re-key over a live session.
//!
//! Separate from [`crate::rekey`], which is the payload, and from
//! `krab_crypto::rekey`, which is the derivation. This is the part that talks,
//! and it is written against [`krab_fabric::Session`] rather than against a
//! socket so that both ends can be run in one test.
//!
//! # Symmetric, with no initiator
//!
//! Both ends send, then both receive, then both confirm. There is no role
//! negotiation because there is nothing to negotiate: contributions are
//! ordered by node id (`krab_crypto::rekey`), so the two ends derive the same
//! root regardless of who spoke first.
//!
//! What *is* asymmetric is who calls first, and that is a transport question
//! already answered by `listen`/`connect`.
//!
//! # Why it confirms
//!
//! A re-key that half-completes is worse than one that fails. One end adopts
//! `root_{n+1}`, the other keeps `root_n`, and from that moment every tag
//! silently fails to match — RFC 0 §6's guarantee that nobody is told.
//!
//! So neither end adopts anything until both have proved they derived the same
//! root. The confirmation is an HKDF output, not a hash of the root: it is
//! published over the session, and a hash of a live key is a head start on
//! that key for anyone recording.

use crate::peering::Card;
use crate::rekey::Payload;
use krab_crypto::dh;
use krab_crypto::rekey as core_rekey;
use krab_crypto::rng::Rng;
use krab_crypto::sign::{Sig, SigningKey};
use krab_fabric::Session;
use krab_proto::control::Control;

/// Domain separation for the signature over a re-key payload.
///
/// Without it, a signature made here would verify against any other structure
/// this identity key signs — RFC 3 §8's finding, which cost a credential its
/// domain prefix.
pub const SIG_DOMAIN: &[u8] = b"krab/rekey/payload/v1";

/// The bytes a re-key signature actually covers.
///
/// The domain goes in front of the body, the same shape every other signed
/// document in the series uses (`peering::DOMAIN_CARD`). Signing the bare body
/// would let a signature made here verify against any other structure this
/// identity key signs — RFC 3 §8's finding.
fn domained(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIG_DOMAIN.len() + body.len());
    out.extend_from_slice(SIG_DOMAIN);
    out.extend_from_slice(body);
    out
}

/// What went wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The transport failed.
    Link,
    /// The peer sent something other than the expected message.
    Protocol,
    /// The sealed payload did not open under the carrier key.
    ///
    /// Means the two ends disagree about `root_n` — usually because one has
    /// already re-keyed and the other has not.
    Undecipherable,
    /// The signature over the payload did not verify.
    ///
    /// An adversary holding the reservoir can produce the sealing key but not
    /// this. Keeping the two separate is the reason both layers exist.
    Forged,
    /// The peer derived a different root.
    Diverged,
    /// The peer is re-keying to an index we are not.
    WrongIndex,
}

/// The outcome of a completed re-key.
pub struct Outcome {
    /// `root_{n+1}`. Adopt with `Reservoir::rekey`.
    pub new_root: [u8; 32],
    /// The index it corresponds to.
    pub index: u32,
    /// What the peer says its terms now are.
    pub theirs: Payload,
}

/// Run one re-key to completion.
///
/// `root_n` is the current reservoir root; `index` is the index being produced
/// (`n+1`). `their_card` supplies the identity key the peer's signature is
/// checked against — **from the stored peer-link**, never from the wire, which
/// is the same rule RFC 4 §4.1 applies to the Noise static.
///
/// Nothing is adopted here. The caller writes the reservoir, so that a failure
/// between deriving and persisting leaves the old root in place rather than a
/// root only one end holds.
#[allow(clippy::too_many_arguments)]
pub fn run(
    session: &mut dyn Session,
    signing: &SigningKey,
    my_node: &[u8; 32],
    their_card: &Card,
    root_n: &[u8; 32],
    index: u32,
    mine: Payload,
    rng: &mut impl Rng,
) -> Result<Outcome, Error> {
    let carrier = core_rekey::carrier_key(root_n, index);

    // Our half. The ephemeral is fresh per re-key: reusing one would mean the
    // DH output repeats, and a repeated DH output cannot heal a compromise.
    let eph = dh::SecretKey::generate(rng);
    let body = mine.encode();
    let sig = signing.sign(&domained(&body));
    let mut signed = Vec::with_capacity(body.len() + 64);
    signed.extend_from_slice(&sig.0);
    signed.extend_from_slice(&body);
    let sealed = krab_crypto::kek::seal_under(carrier.expose(), SIG_DOMAIN, &signed, rng)
        .map_err(|_| Error::Undecipherable)?;

    session
        .send(&Control::Rekey {
            index,
            sealed,
            ephemeral: eph.public().0,
        })
        .map_err(|_| Error::Link)?;

    // Their half.
    let (their_sealed, their_eph) = match session.recv().map_err(|_| Error::Link)? {
        Some(Control::Rekey {
            index: i,
            sealed,
            ephemeral,
        }) => {
            if i != index {
                return Err(Error::WrongIndex);
            }
            (sealed, ephemeral)
        }
        _ => return Err(Error::Protocol),
    };

    let opened = krab_crypto::kek::open_under(carrier.expose(), SIG_DOMAIN, &their_sealed)
        .map_err(|_| Error::Undecipherable)?;
    if opened.len() < 64 {
        return Err(Error::Protocol);
    }
    let (sig_bytes, body_bytes) = opened.split_at(64);

    // Signature before parse. A payload that has not been authenticated is
    // attacker-chosen input, and the cheapest way to keep a parser out of an
    // attacker's reach is not to run it.
    let their_vk = krab_crypto::sign::VerifyingKey::from_bytes(their_card.identity_pk);
    let their_sig = Sig(sig_bytes.try_into().expect("64 bytes, just checked"));
    if !their_vk.verify(&domained(body_bytes), &their_sig) {
        return Err(Error::Forged);
    }
    let theirs = Payload::decode(body_bytes).ok_or(Error::Protocol)?;
    if theirs.index != index {
        return Err(Error::WrongIndex);
    }

    // The healing half.
    let shared = dh::agree(&eph, &dh::PublicKey(their_eph)).ok_or(Error::Protocol)?;
    let new_root = core_rekey::next_root(
        root_n,
        shared.as_bytes(),
        (
            my_node,
            &krab_crypto::secret::Secret::new(mine.contribution),
        ),
        (
            &their_card.node_id(),
            &krab_crypto::secret::Secret::new(theirs.contribution),
        ),
        index,
    );

    // Confirm before either end adopts.
    let confirm = core_rekey::confirm_tag(&new_root, index);
    session
        .send(&Control::RekeyAck { index, confirm })
        .map_err(|_| Error::Link)?;
    match session.recv().map_err(|_| Error::Link)? {
        Some(Control::RekeyAck {
            index: i,
            confirm: theirs_confirm,
        }) => {
            if i != index {
                return Err(Error::WrongIndex);
            }
            // Constant time is not required — this value is public by
            // construction — but diverging here is the failure that would
            // otherwise be silent, so it is checked rather than assumed.
            if theirs_confirm != confirm {
                return Err(Error::Diverged);
            }
        }
        _ => return Err(Error::Protocol),
    }

    Ok(Outcome {
        new_root,
        index,
        theirs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::peering::Policy;
    use krab_crypto::channel::CarriagePolicy;
    use krab_crypto::rng::NotRandom;
    use std::sync::mpsc::{channel, Receiver, Sender};

    /// A session that is one half of a pair, so both ends can run in one test.
    struct Pipe {
        tx: Sender<Control>,
        rx: Receiver<Control>,
        /// Drop everything sent, to model a link that dies mid-exchange.
        deaf: bool,
    }

    impl Session for Pipe {
        fn send(&mut self, msg: &Control) -> Result<(), krab_fabric::Error> {
            if self.deaf {
                return Err(krab_fabric::Error::Frame);
            }
            self.tx
                .send(msg.clone())
                .map_err(|_| krab_fabric::Error::Frame)
        }
        fn recv(&mut self) -> Result<Option<Control>, krab_fabric::Error> {
            Ok(self.rx.recv().ok())
        }
        fn close(&mut self) -> Result<(), krab_fabric::Error> {
            Ok(())
        }
    }

    fn pair() -> (Pipe, Pipe) {
        let (a_tx, b_rx) = channel();
        let (b_tx, a_rx) = channel();
        (
            Pipe {
                tx: a_tx,
                rx: a_rx,
                deaf: false,
            },
            Pipe {
                tx: b_tx,
                rx: b_rx,
                deaf: false,
            },
        )
    }

    fn payload(seed: u8, index: u32) -> Payload {
        Payload {
            contribution: [seed; 32],
            index,
            policy: Policy::default(),
            carriage: CarriagePolicy::default(),
            max_ttl_minutes: 64_800,
        }
    }

    /// Both ends run the same code and arrive at the same root, with no role
    /// negotiation anywhere in it.
    #[test]
    fn two_ends_rekey_to_the_same_root() {
        let mut ra = NotRandom::seeded(1);
        let mut rb = NotRandom::seeded(2);
        let a = Identity::generate(&mut ra);
        let b = Identity::generate(&mut rb);
        let (card_a, card_b) = (a.card(Policy::default()), b.card(Policy::default()));
        let root = [5u8; 32];
        let (mut pa, mut pb) = pair();

        let (a_node, b_node) = (a.node_id(), b.node_id());
        let a_sign = a.signing_key();
        let out_b = std::thread::spawn(move || {
            let mut rb2 = NotRandom::seeded(20);
            run(
                &mut pb,
                b.signing_key(),
                &b_node,
                &card_a,
                &root,
                7,
                payload(0xbb, 7),
                &mut rb2,
            )
            .map(|o| (o.new_root, o.theirs))
        });

        let mut ra2 = NotRandom::seeded(10);
        let out_a = run(
            &mut pa,
            a_sign,
            &a_node,
            &card_b,
            &root,
            7,
            payload(0xaa, 7),
            &mut ra2,
        )
        .expect("A completes");
        let (b_root, b_theirs) = out_b.join().unwrap().expect("B completes");

        assert_eq!(
            out_a.new_root, b_root,
            "the two ends derived different roots"
        );
        assert_ne!(out_a.new_root, root, "the root did not move");
        assert_eq!(out_a.theirs.contribution, [0xbb; 32]);
        assert_eq!(b_theirs.contribution, [0xaa; 32]);
    }

    /// **A forged payload is refused.** An adversary who read the disk holds
    /// the reservoir, and therefore the carrier key — so sealing alone would
    /// let them steer the next root to a value they know, defeating the very
    /// compromise `dh` exists to heal.
    #[test]
    fn a_payload_sealed_by_the_right_key_but_signed_by_the_wrong_one_is_refused() {
        let mut r1 = NotRandom::seeded(1);
        let mut r2 = NotRandom::seeded(2);
        let mut r3 = NotRandom::seeded(3);
        let a = Identity::generate(&mut r1);
        let b = Identity::generate(&mut r2);
        let impostor = Identity::generate(&mut r3);
        let root = [5u8; 32];
        let (mut pa, mut pb) = pair();

        // The impostor has the reservoir and seals correctly — but signs with
        // their own identity key.
        let b_card = b.card(Policy::default());
        let a_node = a.node_id();
        let a_card = a.card(Policy::default());
        let a_sign = a.signing_key();
        let imp = std::thread::spawn(move || {
            let mut rr = NotRandom::seeded(30);
            let _ = run(
                &mut pb,
                impostor.signing_key(),
                &impostor.node_id(),
                &a_card,
                &root,
                7,
                payload(0xcc, 7),
                &mut rr,
            );
        });

        let mut ra = NotRandom::seeded(10);
        let got = run(
            &mut pa,
            a_sign,
            &a_node,
            &b_card,
            &root,
            7,
            payload(0xaa, 7),
            &mut ra,
        );
        // Drop our end before joining. We refused without acknowledging, so
        // the impostor is still waiting for one — and it waits on a channel
        // whose sender lives inside `pa`. This is the shape of the two
        // deadlocks the exchange protocol has already produced once each
        // (`ADVERSARIAL-PASS.md`); here it is only the test.
        drop(pa);
        let _ = imp.join();
        assert_eq!(got.err(), Some(Error::Forged), "an impostor re-keyed us");
    }

    /// Ends that disagree about `root_n` cannot open each other's payloads.
    /// This is the "one end already re-keyed" case, and it must be a clean
    /// refusal rather than two nodes deriving different roots.
    #[test]
    fn ends_that_disagree_about_the_old_root_refuse() {
        let mut r1 = NotRandom::seeded(1);
        let mut r2 = NotRandom::seeded(2);
        let a = Identity::generate(&mut r1);
        let b = Identity::generate(&mut r2);
        let b_card = b.card(Policy::default());
        let a_card = a.card(Policy::default());
        let (mut pa, mut pb) = pair();

        let b_node = b.node_id();
        let handle = std::thread::spawn(move || {
            let mut rr = NotRandom::seeded(20);
            run(
                &mut pb,
                b.signing_key(),
                &b_node,
                &a_card,
                &[6u8; 32], // a different root
                7,
                payload(0xbb, 7),
                &mut rr,
            )
            .err()
        });

        let mut ra = NotRandom::seeded(10);
        let got = run(
            &mut pa,
            a.signing_key(),
            &a.node_id(),
            &b_card,
            &[5u8; 32],
            7,
            payload(0xaa, 7),
            &mut ra,
        );
        let _ = handle.join();
        assert_eq!(got.err(), Some(Error::Undecipherable));
    }

    /// A link that dies mid-exchange leaves an error, not a half-adopted root.
    /// The caller persists nothing on `Err`, which is why `run` adopts
    /// nothing itself.
    #[test]
    fn a_dead_link_fails_without_producing_a_root() {
        let mut r1 = NotRandom::seeded(1);
        let mut r2 = NotRandom::seeded(2);
        let a = Identity::generate(&mut r1);
        let b = Identity::generate(&mut r2);
        let (mut pa, _pb) = pair();
        pa.deaf = true;

        let mut ra = NotRandom::seeded(10);
        let got = run(
            &mut pa,
            a.signing_key(),
            &a.node_id(),
            &b.card(Policy::default()),
            &[5u8; 32],
            7,
            payload(0xaa, 7),
            &mut ra,
        );
        assert_eq!(got.err(), Some(Error::Link));
    }

    /// Two ends re-keying to different indices must not proceed. Their roots
    /// would be seated at different epochs, which is the same silent
    /// divergence by another route.
    #[test]
    fn a_mismatched_index_is_refused() {
        let mut r1 = NotRandom::seeded(1);
        let mut r2 = NotRandom::seeded(2);
        let a = Identity::generate(&mut r1);
        let b = Identity::generate(&mut r2);
        let b_card = b.card(Policy::default());
        let a_card = a.card(Policy::default());
        let (mut pa, mut pb) = pair();

        let b_node = b.node_id();
        let handle = std::thread::spawn(move || {
            let mut rr = NotRandom::seeded(20);
            run(
                &mut pb,
                b.signing_key(),
                &b_node,
                &a_card,
                &[5u8; 32],
                8, // a different index
                payload(0xbb, 8),
                &mut rr,
            )
            .err()
        });

        let mut ra = NotRandom::seeded(10);
        let got = run(
            &mut pa,
            a.signing_key(),
            &a.node_id(),
            &b_card,
            &[5u8; 32],
            7,
            payload(0xaa, 7),
            &mut ra,
        );
        let _ = handle.join();
        assert!(
            matches!(
                got.err(),
                Some(Error::WrongIndex) | Some(Error::Undecipherable)
            ),
            "a mismatched index was accepted"
        );
    }
}
