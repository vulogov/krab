//! First contact over a live link — RFC 3 §11's ceremony, without the files.
//!
//! Two nodes that have never met exchange a card and a contribution over one
//! session. `PAD-OVER-NETWORK.md` §1's argument is why this exists: a protocol
//! that offers no network route does not prevent network transfer, it exports
//! it to `scp` and a shared drive, where it is unauthenticated, unlogged,
//! leaves copies, and where the peering records nothing at all.
//!
//! # What this is worth, exactly
//!
//! `Channel::Network`. **Not post-quantum.** The session is Noise XX over
//! X25519, so an adversary who records it and later breaks X25519 recovers the
//! contribution and therefore the reservoir. That is not a defect in the
//! implementation; it is the property being traded away, and `peer reseal`
//! exists so the trade is reversible.
//!
//! # And it is not authenticated until the fingerprints match
//!
//! XX tells each end *a* static key the other holds. It does not say whose:
//! an active attacker completes two handshakes and relays. Every operational
//! guarantee therefore rests on RFC 3 §11 step 2 — the fingerprint read aloud
//! — exactly as it does when a card arrives by email. What the session changes
//! is only how the bytes travelled.
//!
//! So this module deliberately **does not** mark the peering verified. It
//! prints both fingerprints and stops.
//!
//! # Symmetric, with no initiator
//!
//! Both ends send a card, then both read one; both send a contribution, then
//! both read one. Who dialled is a transport question already answered before
//! this runs, and making it a protocol role would be a second thing to keep
//! consistent.

use crate::peering::{Card, Contribution};
use krab_crypto::rng::Rng;
use krab_fabric::Session;
use krab_proto::control::Control;

/// Why a first contact stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The transport failed.
    Link,
    /// The peer sent something other than the step expected.
    Protocol,
    /// The card's signature does not verify under its own identity key.
    ///
    /// A hard failure. RFC 4 §4.1's rule about never prompting applies to
    /// anything claiming to be a credential, not only to a Noise static.
    BadCard,
    /// The card's Noise static is not the key that completed the handshake.
    ///
    /// Someone is relaying: the card describes one node and the session was
    /// established with another.
    KeyMismatch,
}

/// What one end learned.
pub struct Outcome {
    /// Their signed card.
    pub card: Card,
    /// Their reservoir contribution.
    pub contribution: Contribution,
}

/// Run first contact to completion over `session`.
///
/// `session_static` is the Noise static the far end actually presented. The
/// card's `noise_static_pk` must equal it — otherwise the card belongs to
/// somebody other than whoever is on the wire, which is what a relay looks
/// like from here.
pub fn run(
    session: &mut dyn Session,
    my_card: &Card,
    my_contribution: &Contribution,
    session_static: &[u8; 32],
) -> Result<Outcome, Error> {
    session
        .send(&Control::Card(my_card.encode()))
        .map_err(|_| Error::Link)?;

    let their_card = match session.recv().map_err(|_| Error::Link)? {
        Some(Control::Card(b)) => Card::decode(&b).map_err(|_| Error::BadCard)?,
        _ => return Err(Error::Protocol),
    };
    // Signature before anything else is done with it.
    if !their_card.verify() {
        return Err(Error::BadCard);
    }
    // And the card must describe the node on the other end of this session.
    // Without this, an attacker relays a genuine card from someone else and
    // the operator compares a fingerprint that belongs to the wrong person.
    if &their_card.noise_static_pk != session_static {
        return Err(Error::KeyMismatch);
    }

    session
        .send(&Control::Contribution(
            crate::ceremony::encode_contribution(my_contribution),
        ))
        .map_err(|_| Error::Link)?;

    let contribution = match session.recv().map_err(|_| Error::Link)? {
        Some(Control::Contribution(b)) => {
            crate::ceremony::decode_contribution(&b).map_err(|_| Error::Protocol)?
        }
        _ => return Err(Error::Protocol),
    };

    Ok(Outcome {
        card: their_card,
        contribution,
    })
}

/// A card and contribution for this node, for one first contact.
pub fn offer(card: Card, rng: &mut impl Rng) -> (Card, Contribution) {
    (card, Contribution { r: rng.next_32() })
}

/// The warning that must accompany a peering formed this way.
///
/// Separate from the mechanism so it is one thing to review rather than a
/// format string in a dispatcher.
pub fn caveat(theirs: &str, mine: &str) -> String {
    format!(
        "first contact complete, over the network.\n\n\
         their fingerprint:\n\n\x20 {theirs}\n\n\
         yours, for them to check:\n\n\x20 {mine}\n\n\
         **Nothing is verified yet.** The link proved the far end holds a key; \
         it did not prove whose. An attacker in the middle completes two \
         handshakes and relays, and would show you a fingerprint you have no \
         reason to doubt.\n\n\
         Call them. Read yours; they read theirs. Both must match.\n\n\
         This peering is NOT post-quantum: the contribution crossed a channel \
         secured by X25519, so an adversary recording it today and breaking \
         X25519 later recovers it. That is repairable without redoing the \
         peering — `peer reseal` the first time you meet or get a voice call.\n\n\
         when the fingerprints match:  peer verified <peer>",
        theirs = theirs,
        mine = mine
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::peering::Policy;
    use krab_crypto::rng::NotRandom;
    use std::sync::mpsc::{channel, Receiver, Sender};

    struct Pipe {
        tx: Sender<Control>,
        rx: Receiver<Control>,
    }

    impl Session for Pipe {
        fn send(&mut self, msg: &Control) -> Result<(), krab_fabric::Error> {
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
        (Pipe { tx: a_tx, rx: a_rx }, Pipe { tx: b_tx, rx: b_rx })
    }

    fn node(seed: u64) -> Identity {
        Identity::generate(&mut NotRandom::seeded(seed))
    }

    /// Both ends learn the other's card and contribution in one exchange.
    #[test]
    fn two_strangers_exchange_a_card_and_a_contribution() {
        let a = node(1);
        let b = node(2);
        let (a_card, a_contrib) = offer(a.card(Policy::default()), &mut NotRandom::seeded(10));
        let (b_card, b_contrib) = offer(b.card(Policy::default()), &mut NotRandom::seeded(20));
        let (a_static, b_static) = (a_card.noise_static_pk, b_card.noise_static_pk);
        let (mut pa, mut pb) = pair();

        let bc = b_card.clone();
        let br = crate::peering::Contribution { r: b_contrib.r };
        let handle = std::thread::spawn(move || {
            run(&mut pb, &bc, &br, &a_static).map(|o| (o.card, o.contribution))
        });
        let out_a = run(&mut pa, &a_card, &a_contrib, &b_static).expect("A completes");
        let (their_a_card, their_a_contrib) = handle.join().unwrap().expect("B completes");

        assert_eq!(out_a.card.node_id(), b_card.node_id());
        assert_eq!(their_a_card.node_id(), a_card.node_id());
        assert_eq!(out_a.contribution.r, b_contrib.r);
        assert_eq!(their_a_contrib.r, a_contrib.r);
    }

    /// **A card that does not match the session's key is a relay.** The
    /// attacker forwards a genuine card belonging to someone else, and the
    /// operator compares a fingerprint for the wrong person.
    #[test]
    fn a_card_that_does_not_match_the_session_key_is_refused() {
        let a = node(1);
        let b = node(2);
        let stranger = node(3);
        let (a_card, a_contrib) = offer(a.card(Policy::default()), &mut NotRandom::seeded(10));
        let (b_card, b_contrib) = offer(b.card(Policy::default()), &mut NotRandom::seeded(20));
        let (mut pa, mut pb) = pair();

        // A expects the session to belong to `stranger`, and B sends B's card.
        let expect = stranger.card(Policy::default()).noise_static_pk;
        let a_static = a_card.noise_static_pk;
        let handle = std::thread::spawn(move || {
            let _ = run(&mut pb, &b_card, &b_contrib, &a_static);
        });
        let got = run(&mut pa, &a_card, &a_contrib, &expect);
        drop(pa);
        let _ = handle.join();
        assert_eq!(got.err(), Some(Error::KeyMismatch));
    }

    /// An unsigned or corrupt card is refused before anything is done with it.
    #[test]
    fn a_card_that_does_not_verify_is_refused() {
        let a = node(1);
        let b = node(2);
        let (a_card, a_contrib) = offer(a.card(Policy::default()), &mut NotRandom::seeded(10));
        let mut forged = b.card(Policy::default());
        forged.policy.relay = !forged.policy.relay; // outside the signature now
        let b_static = forged.noise_static_pk;
        let (mut pa, mut pb) = pair();

        let handle = std::thread::spawn(move || {
            let _ = pb.send(&Control::Card(forged.encode()));
            let _ = pb.recv();
        });
        let got = run(&mut pa, &a_card, &a_contrib, &b_static);
        let _ = handle.join();
        assert_eq!(got.err(), Some(Error::BadCard));
    }

    /// A link that dies mid-ceremony leaves an error, not a half-peering.
    #[test]
    fn a_dead_link_fails_without_producing_an_outcome() {
        let a = node(1);
        let (a_card, a_contrib) = offer(a.card(Policy::default()), &mut NotRandom::seeded(10));
        let (mut pa, pb) = pair();
        drop(pb);
        let got = run(&mut pa, &a_card, &a_contrib, &[0u8; 32]);
        assert!(got.is_err());
    }

    /// **The text must not let an operator think this is finished.** The
    /// likeliest failure is treating a completed exchange as a verified
    /// peering, and the only thing standing against that is what is printed.
    #[test]
    fn the_caveat_says_it_is_neither_verified_nor_post_quantum() {
        let out = caveat("their words", "my words");
        assert!(out.contains("Nothing is verified yet"), "{out}");
        assert!(out.contains("relays"), "{out}");
        assert!(out.contains("NOT post-quantum"), "{out}");
        assert!(
            out.contains("peer reseal"),
            "the repair is not named: {out}"
        );
        assert!(out.contains("their words") && out.contains("my words"));
    }
}
