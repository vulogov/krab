//! A peering ceremony that survives a restart — RFC 3 §11.
//!
//! The ceremony is four steps and **the gap between them is measured in days**,
//! not milliseconds. A sneakernet peering means writing a card and a
//! contribution to a USB stick, posting it, and waiting; RFC 7 §6.2 calls this
//! "two courier legs". Nothing about that fits in one process lifetime, so the
//! half-finished state is a stored artifact rather than a field on `App`.
//!
//! # What is stored, and how
//!
//! | | secret | at rest |
//! |---|---|---|
//! | my card | no | plain |
//! | their card | no | plain |
//! | **my contribution `R_A`** | **yes** | wrapped under `W_N` |
//! | how their pad arrived | no | plain |
//!
//! The contribution is half a shared secret, so it is wrapped under the epoch
//! key (RFC 7 §4) like anything else. That has a consequence worth stating: a
//! ceremony left open across an epoch boundary whose wrapper has since been
//! shredded **cannot be resumed**. That is correct — the alternative is a
//! long-lived secret exempt from the shredding schedule, which is the exception
//! that makes the schedule meaningless.
//!
//! # Why the arrival channel is recorded here and not asked later
//!
//! `RFC-7-review.md` §10: a contribution that arrived over the corpus yields a
//! reservoir with no post-quantum property. The node cannot observe how a file
//! reached it, so the operator states it at `peer seal` — while they still
//! remember. Asking at first use, weeks later, would get a guess.

use crate::peering::{Card, Channel, Contribution, Policy};
use krab_core::cbor::{Error as CborError, Item, Reader, Writer};

/// A peering in progress.
///
/// `Debug` prints the counterparty and the step reached, never the
/// contribution — RFC 7 §9. `Contribution`'s own `Debug` redacts, but a
/// derived impl on the container would still print the cards, and the point of
/// writing it out is that the redaction is deliberate rather than inherited.
pub struct Pending {
    /// The card handed over at step 1.
    pub my_card: Card,
    /// `R_A`. Wrapped when stored.
    pub my_contribution: Contribution,
    /// Their card, once accepted at step 1.
    pub their_card: Option<Card>,
    /// Whether the operator has confirmed step 2.
    pub fingerprint_verified: bool,
}

/// What went wrong loading or advancing a ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The counterparty's card does not verify under its own identity key.
    BadCard,
    /// Their card is already recorded, and it is not this one.
    ///
    /// Two different cards for one ceremony means either a mistake or an
    /// attempt to substitute a counterparty after the fingerprints were read.
    CounterpartyChanged,
}

// Deliberately only two variants. A malformed file surfaces as a `CborError`
// from `decode`, and "step 2 was skipped" is not an error at all — RFC 3 §11.1
// permits remote peering, so it is a `Caveat` recorded on the link rather than
// a refusal. An error enum listing conditions nothing constructs invites a
// caller to handle one that cannot happen.

impl core::fmt::Debug for Pending {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Pending(counterparty: {}, verified: {})",
            match &self.their_card {
                Some(c) => c.fingerprint(),
                None => "none".into(),
            },
            self.fingerprint_verified
        )
    }
}

impl Pending {
    /// Begin a ceremony.
    pub fn open(my_card: Card, r: [u8; 32]) -> Pending {
        Pending {
            my_card,
            my_contribution: Contribution { r },
            their_card: None,
            fingerprint_verified: false,
        }
    }

    /// Record the counterparty's card — step 1.
    ///
    /// Verifies the signature here rather than at parse, and refuses to
    /// silently replace a card already recorded.
    pub fn accept_card(&mut self, card: Card) -> Result<(), Error> {
        if !card.verify() {
            return Err(Error::BadCard);
        }
        match &self.their_card {
            Some(existing) if *existing != card => Err(Error::CounterpartyChanged),
            Some(_) => Ok(()),
            None => {
                self.their_card = Some(card);
                Ok(())
            }
        }
    }

    /// The words to read aloud — step 2. `None` until a card is accepted.
    pub fn their_fingerprint(&self) -> Option<String> {
        self.their_card.as_ref().map(|c| c.fingerprint())
    }

    /// The negotiated policy, once both cards are present.
    pub fn policy(&self) -> Option<Policy> {
        self.their_card
            .as_ref()
            .map(|c| self.my_card.policy.negotiate(&c.policy))
    }

    /// Deterministic CBOR, with the contribution supplied already wrapped.
    ///
    /// `wrapped_contribution` is what the caller got from the epoch key. This
    /// function does not wrap, because it has no business holding a KEK.
    pub fn encode(&self, wrapped_contribution: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        w.map(4);
        w.uint(1).bstr(&self.my_card.encode());
        w.uint(2).bstr(wrapped_contribution);
        w.uint(3).bstr(
            &self
                .their_card
                .as_ref()
                .map(|c| c.encode())
                .unwrap_or_default(),
        );
        w.uint(4).bool(self.fingerprint_verified);
        w.finish()
    }

    /// Decode, given the caller has already unwrapped the contribution.
    ///
    /// Returns the still-wrapped contribution bytes alongside the rest, so the
    /// caller can unwrap with the epoch key it holds.
    pub fn decode(bytes: &[u8]) -> Result<(PendingParts, Vec<u8>), CborError> {
        let mut r = Reader::new(bytes);
        let mut m = r.map()?;
        let (mut mine, mut wrapped, mut theirs, mut verified) = (None, Vec::new(), None, false);
        while let Some(key) = m.key()? {
            match (key, m.value()?) {
                (1, Item::Bstr(b)) => mine = Some(Card::decode(b)?),
                (2, Item::Bstr(b)) => wrapped = b.to_vec(),
                (3, Item::Bstr(b)) => {
                    theirs = if b.is_empty() {
                        None
                    } else {
                        Some(Card::decode(b)?)
                    }
                }
                (4, Item::Bool(v)) => verified = v,
                _ => return Err(CborError::Malformed),
            }
        }
        let my_card = mine.ok_or(CborError::Truncated)?;
        Ok((
            PendingParts {
                my_card,
                their_card: theirs,
                fingerprint_verified: verified,
            },
            wrapped,
        ))
    }
}

/// Everything a stored ceremony holds except the wrapped contribution.
pub struct PendingParts {
    /// The card handed over at step 1.
    pub my_card: Card,
    /// Their card, if step 1 has completed.
    pub their_card: Option<Card>,
    /// Whether step 2 is done.
    pub fingerprint_verified: bool,
}

impl PendingParts {
    /// Reassemble once the contribution is unwrapped.
    pub fn with_contribution(self, r: [u8; 32]) -> Pending {
        Pending {
            my_card: self.my_card,
            my_contribution: Contribution { r },
            their_card: self.their_card,
            fingerprint_verified: self.fingerprint_verified,
        }
    }
}

/// A contribution as it travels: 32 bytes, framed, and nothing else.
///
/// No signature and no identifier. Signing it would let an observer confirm
/// which pair a captured pad belongs to, and RFC 7 §6.2's value depends on the
/// pad being unattributable as well as secret.
pub fn encode_contribution(c: &Contribution) -> Vec<u8> {
    let mut w = Writer::new();
    w.map(1);
    w.uint(1).bstr(&c.r);
    w.finish()
}

/// Decode a contribution.
pub fn decode_contribution(bytes: &[u8]) -> Result<Contribution, CborError> {
    let mut r = Reader::new(bytes);
    let mut m = r.map()?;
    let mut out = None;
    while let Some(key) = m.key()? {
        match (key, m.value()?) {
            (1, Item::Bstr(b)) if b.len() == 32 => {
                let mut v = [0u8; 32];
                v.copy_from_slice(b);
                out = Some(Contribution { r: v });
            }
            _ => return Err(CborError::Malformed),
        }
    }
    out.ok_or(CborError::Truncated)
}

/// Parse the `--channel` argument of `peer seal`.
///
/// There is no default. The node cannot observe how a file arrived, and
/// guessing would mean guessing in the optimistic direction — recording a
/// post-quantum property the link may not have.
pub fn parse_channel(arg: &str) -> Option<Channel> {
    Some(match arg {
        "in-person" | "person" => Channel::InPerson,
        "media" | "usb" | "sneakernet" => Channel::RemovableMedia,
        "corpus" => Channel::Corpus,
        "network" | "net" => Channel::Network,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use krab_crypto::rng::NotRandom;
    use krab_crypto::sign::SigningKey;

    fn card(seed: u8) -> Card {
        let k = SigningKey::generate(&mut NotRandom::seeded(seed as u64));
        Card::create(
            &k,
            [seed.wrapping_add(1); 32],
            [seed.wrapping_add(2); 32],
            Policy::default(),
        )
    }

    #[test]
    fn a_ceremony_survives_the_round_trip_to_storage() {
        let mut p = Pending::open(card(1), [0xAB; 32]);
        p.accept_card(card(2)).unwrap();
        p.fingerprint_verified = true;

        // The caller wraps; this layer never sees a key.
        let wrapped = b"pretend-this-is-wrapped".to_vec();
        let (parts, back_wrapped) = Pending::decode(&p.encode(&wrapped)).unwrap();
        assert_eq!(back_wrapped, wrapped);

        let restored = parts.with_contribution([0xAB; 32]);
        assert_eq!(restored.my_card, p.my_card);
        assert_eq!(restored.their_card, p.their_card);
        assert!(restored.fingerprint_verified);
        assert_eq!(restored.my_contribution.r, [0xAB; 32]);
    }

    /// The common case: offer written, machine rebooted, card arrives a week
    /// later. Step 1 must still be pending rather than lost.
    #[test]
    fn a_ceremony_stored_before_step_one_resumes_with_no_counterparty() {
        let p = Pending::open(card(1), [0x01; 32]);
        let (parts, _) = Pending::decode(&p.encode(b"w")).unwrap();
        assert!(parts.their_card.is_none());
        assert!(!parts.fingerprint_verified);

        let mut resumed = parts.with_contribution([0x01; 32]);
        assert!(resumed.their_fingerprint().is_none());
        resumed.accept_card(card(2)).unwrap();
        assert!(resumed.their_fingerprint().is_some());
    }

    /// A forged card is refused at step 1 rather than recorded and caught later.
    #[test]
    fn a_card_that_does_not_verify_is_refused() {
        let mut p = Pending::open(card(1), [0; 32]);
        let mut forged = card(2);
        forged.policy.retention_bytes = 1;
        assert_eq!(p.accept_card(forged), Err(Error::BadCard));
        assert!(p.their_card.is_none(), "nothing is recorded");
    }

    /// **Substituting a counterparty after the fingerprints were read** is the
    /// attack the ceremony's persistence creates: the operator verified one
    /// person aloud, and a second card arrives before sealing.
    #[test]
    fn the_counterparty_cannot_be_swapped_mid_ceremony() {
        let mut p = Pending::open(card(1), [0; 32]);
        p.accept_card(card(2)).unwrap();
        p.fingerprint_verified = true;

        assert_eq!(p.accept_card(card(3)), Err(Error::CounterpartyChanged));
        assert_eq!(p.their_card, Some(card(2)), "the verified card stands");
        // Re-accepting the same card is fine -- a resend is not an attack.
        assert_eq!(p.accept_card(card(2)), Ok(()));
    }

    /// The contribution must not reach a log through the container.
    #[test]
    fn a_pending_ceremony_prints_no_secret() {
        let mut p = Pending::open(card(1), [0xDE; 32]);
        let s = format!("{p:?}");
        assert!(s.contains("none"), "{s}");
        assert!(!s.contains("de") && !s.contains("222"), "{s}");
        p.accept_card(card(2)).unwrap();
        assert!(format!("{p:?}").contains(&p.their_fingerprint().unwrap()));
    }

    #[test]
    fn a_contribution_round_trips_and_carries_nothing_else() {
        let c = Contribution { r: [0x5A; 32] };
        let bytes = encode_contribution(&c);
        assert_eq!(decode_contribution(&bytes).unwrap().r, c.r);
        // No identity, no signature: 32 bytes plus minimal framing.
        assert!(bytes.len() < 40, "{} bytes", bytes.len());
    }

    #[test]
    fn malformed_input_is_rejected_without_panicking() {
        let bytes = Pending::open(card(1), [0; 32]).encode(b"w");
        for n in 0..bytes.len() {
            let _ = Pending::decode(&bytes[..n]);
        }
        assert!(decode_contribution(&[]).is_err());
        assert!(decode_contribution(&[0xff, 0x00]).is_err());
    }

    /// The channel must be stated. Every spelling an operator might reach for
    /// maps to the right one, and an unrecognised word is refused rather than
    /// defaulted -- a default would guess optimistically.
    #[test]
    fn the_channel_argument_has_no_default() {
        assert_eq!(parse_channel("in-person"), Some(Channel::InPerson));
        assert_eq!(parse_channel("usb"), Some(Channel::RemovableMedia));
        assert_eq!(parse_channel("sneakernet"), Some(Channel::RemovableMedia));
        assert_eq!(parse_channel("corpus"), Some(Channel::Corpus));
        assert_eq!(parse_channel("net"), Some(Channel::Network));
        assert_eq!(parse_channel(""), None);
        assert_eq!(parse_channel("probably-fine"), None);

        // And the two that matter differ in exactly the property at stake.
        assert!(parse_channel("usb").unwrap().independent_of_dh());
        assert!(!parse_channel("corpus").unwrap().independent_of_dh());
    }

    #[test]
    fn the_negotiated_policy_takes_the_lower_ceiling() {
        let mut p = Pending::open(card(1), [0; 32]);
        assert!(p.policy().is_none(), "not until both cards are present");
        let mut theirs = card(2);
        // Re-sign with a lower ceiling so the card still verifies.
        let k = SigningKey::generate(&mut NotRandom::seeded(2));
        theirs = Card::create(
            &k,
            theirs.noise_static_pk,
            theirs.correspondence_pk,
            Policy {
                max_bucket: 2,
                ..Policy::default()
            },
        );
        p.accept_card(theirs).unwrap();
        assert_eq!(p.policy().unwrap().max_bucket, 2);
    }
}
