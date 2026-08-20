//! Moving a pad over a network without giving up the reservoir's purpose.
//!
//! `Documentation/PAD-OVER-NETWORK.md` §3. Two people who cannot meet still
//! need one secret established out of band, and that requirement is
//! information-theoretic rather than a design choice: for a root to be
//! post-quantum secret, some component must have full entropy and must never
//! have crossed a channel the adversary records.
//!
//! But the requirement is **once**, not every time. So the out-of-band channel
//! is narrowed to the smallest thing a person can carry across it: thirty-two
//! words, read aloud on a voice call, one time ever per peer. Everything after
//! that — including the pad itself — travels over the network.
//!
//! ```text
//! transfer_key  ← CSPRNG(32)              shown as 32 words
//! salt          ← CSPRNG(16)
//! k             ← Argon2id(words, salt)   RFC 7 §4.1's parameters
//! wrapped       ← AEAD(k, DOMAIN, contribution)
//! ```
//!
//! # Why not a PAKE
//!
//! CPace, SPAKE2 and OPAQUE are the textbook answer to bootstrapping from a
//! shared secret, and every standard one is Diffie–Hellman based — so they
//! fail exactly the adversary the reservoir exists for. **A PAKE here would
//! look stronger and be weaker.** It is the first thing a reviewer proposes,
//! which is why it is written down.
//!
//! # Why Krab generates the key
//!
//! An operator-chosen phrase is guessable, and an offline dictionary attack
//! against the recorded ciphertext then recovers the pad — silently, with the
//! peering appearing to have succeeded. There is no verb that accepts a
//! chosen transfer phrase.
//!
//! # Why thirty-two
//!
//! The word alphabet is 256 words at even positions and 256 at odd, so each
//! word carries exactly 8 bits: 32 words is 256 bits. Position-dependent
//! alphabets make a transposition *audible* — swapped words land in the wrong
//! alphabet and `words::parse` rejects them rather than silently producing a
//! different key.
//!
//! # What this is not
//!
//! It is not equal to meeting. It rests on a voice channel, which is a real
//! thing and a lesser one: a synthesised voice defeats it, and a **recorded**
//! call defeats it completely — the transfer key is the whole protection, so a
//! spoken key over a recorded call is `network`, not `spoken`.

use krab_core::cbor;
use krab_crypto::kek::{Kek, KekParams};
use krab_crypto::rng::Rng;

/// Domain for the AEAD over a wrapped contribution.
pub const DOMAIN: &[u8] = b"krab/pad/spoken/v1";

/// Words in a transfer key. 8 bits each — see the module note on why 32.
pub const WORDS: usize = 32;

/// A pad wrapped for transport, and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wrapped {
    /// Argon2 parameters and salt for deriving the key from the words.
    pub params: KekParams,
    /// The sealed contribution.
    pub sealed: Vec<u8>,
}

/// Wrap `contribution` under a fresh transfer key.
///
/// Returns the wrapped form and the words to read aloud. The key itself is
/// not returned: it exists to be spoken and then forgotten, and a caller that
/// held it would be a caller that could store it.
pub fn wrap(contribution: &[u8], rng: &mut impl Rng) -> Option<(Wrapped, String)> {
    let key = rng.next_32();
    let phrase = krab_crypto::words::phrase(&key);
    let params = KekParams::new(rng);
    // Argon2 over 256 bits is redundant and is here anyway: it costs one
    // `unlock`, and it is the only thing standing between a future shorter
    // phrase and an offline attack. A construction that is safe only because
    // of a parameter chosen elsewhere is the pattern `AMENDMENTS.md` keeps
    // finding.
    let kek = Kek::derive(phrase.as_bytes(), &params).ok()?;
    let sealed = kek.seal(DOMAIN, contribution, rng).ok()?;
    Some((Wrapped { params, sealed }, phrase))
}

/// Unwrap using the words the other end read aloud.
///
/// `None` covers both a wrong phrase and a tampered file, deliberately: an
/// operator's remedy is the same either way, and distinguishing them would
/// tell someone who intercepted the file which of their guesses was closer.
pub fn unwrap(w: &Wrapped, phrase: &str) -> Option<Vec<u8>> {
    // Parsed first, so a mistyped word fails as a *word* rather than as a
    // decryption. `words::parse` rejects a word from the wrong alphabet, which
    // is what makes a transposition detectable rather than merely wrong.
    let bytes = krab_crypto::words::parse(phrase)?;
    if bytes.len() != 32 {
        return None;
    }
    let kek = Kek::derive(krab_crypto::words::phrase(&bytes).as_bytes(), &w.params).ok()?;
    kek.open(DOMAIN, &w.sealed).ok()
}

impl Wrapped {
    /// Deterministic CBOR — RFC 1 §4.3.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = cbor::Writer::new();
        w.map(5)
            .uint(1)
            .uint(self.params.m_kib as u64)
            .uint(2)
            .uint(self.params.t as u64)
            .uint(3)
            .uint(self.params.p as u64)
            .uint(4)
            .bstr(&self.params.salt)
            .uint(5)
            .bstr(&self.sealed);
        w.finish()
    }

    /// Decode. This file crosses a network from someone who may not be the
    /// peer, so nothing here allocates on a declared count.
    pub fn decode(bytes: &[u8]) -> Option<Wrapped> {
        let mut r = cbor::Reader::new(bytes);
        let mut m = r.map().ok()?;
        if m.left() != 5 {
            return None;
        }
        let m_kib = u32::try_from(uint_at(&mut m, 1)?).ok()?;
        let t = u32::try_from(uint_at(&mut m, 2)?).ok()?;
        let p = u32::try_from(uint_at(&mut m, 3)?).ok()?;
        // An attacker-chosen Argon2 cost is a denial of service against the
        // machine that opens it. RFC 7 §4.1's parameters are the ceiling.
        if m_kib > 1_048_576 || t > 16 || p > 16 || m_kib == 0 || t == 0 || p == 0 {
            return None;
        }
        let salt: [u8; 16] = bstr_at(&mut m, 4)?.try_into().ok()?;
        let sealed = bstr_at(&mut m, 5)?.to_vec();
        Some(Wrapped {
            params: KekParams { m_kib, t, p, salt },
            sealed,
        })
    }
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

/// What `peer wrap` prints. Separate from the mechanism so the warnings are
/// one thing to review rather than a format string in a dispatcher.
pub fn instructions(dest: &str, phrase: &str) -> String {
    format!(
        "wrote {dest}\n\n\
         That file is safe to send over anything — email, chat, a shared \
         drive. It is useless without the words below.\n\n\
         READ THESE ALOUD, on a live voice call, and nowhere else:\n\n  {phrase}\n\n\
         They are used once and never again.\n\n\
         \x20 - Do NOT type them into chat \"so they can copy them\". That puts \
         the key on the same recorded channel as the file, and the peering \
         silently becomes no better than `network` while the interface still \
         says `spoken`.\n\
         \x20 - If the call is recorded, this is worth nothing — the words are \
         the whole protection.\n\
         \x20 - A voice can be synthesised. Ask them something only they would \
         know, that is not in any message either of you has sent.\n\n\
         They finish with:  peer seal <the file you sent> spoken"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use krab_crypto::rng::NotRandom;

    fn cheap(w: &mut Wrapped) {
        // Argon2 at RFC 7 §4.1's parameters is half a second per call; these
        // tests are about the construction, not the cost.
        w.params.m_kib = 64;
        w.params.t = 1;
        w.params.p = 1;
    }

    fn wrapped(contribution: &[u8], seed: u64) -> (Wrapped, String) {
        let mut rng = NotRandom::seeded(seed);
        let key = rng.next_32();
        let phrase = krab_crypto::words::phrase(&key);
        let mut params = KekParams::new(&mut rng);
        params.m_kib = 64;
        params.t = 1;
        params.p = 1;
        let kek = Kek::derive(phrase.as_bytes(), &params).unwrap();
        let sealed = kek.seal(DOMAIN, contribution, &mut rng).unwrap();
        (Wrapped { params, sealed }, phrase)
    }

    #[test]
    fn a_wrapped_pad_opens_with_its_words_and_no_others() {
        let (w, phrase) = wrapped(b"half a shared secret", 1);
        assert_eq!(
            unwrap(&w, &phrase).as_deref(),
            Some(&b"half a shared secret"[..])
        );

        let (_, other) = wrapped(b"x", 2);
        assert_eq!(unwrap(&w, &other), None, "another phrase opened it");
    }

    /// **Thirty-two words, 256 bits.** The alphabet carries 8 bits a word, so
    /// a shorter phrase is a weaker key and the count is the guarantee.
    #[test]
    fn the_phrase_is_thirty_two_words() {
        let (_, phrase) = wrapped(b"x", 3);
        assert_eq!(phrase.split_whitespace().count(), WORDS);
    }

    /// **A transposition is audible and detectable.** Even and odd positions
    /// draw from different alphabets, so two swapped words land in the wrong
    /// one and are rejected rather than producing a different key.
    #[test]
    fn two_swapped_words_are_refused_rather_than_producing_another_key() {
        let (w, phrase) = wrapped(b"secret", 4);
        let mut words: Vec<&str> = phrase.split_whitespace().collect();
        words.swap(0, 1);
        let swapped = words.join(" ");
        assert_ne!(swapped, phrase);
        assert_eq!(
            unwrap(&w, &swapped),
            None,
            "a transposition silently produced a different key"
        );
    }

    /// A tampered file and a wrong phrase are indistinguishable. The
    /// operator's remedy is the same, and telling them apart would tell an
    /// interceptor which guess was closer.
    #[test]
    fn tampering_fails_the_same_way_a_wrong_phrase_does() {
        let (mut w, phrase) = wrapped(b"secret", 5);
        w.sealed[4] ^= 0xff;
        assert_eq!(unwrap(&w, &phrase), None);
    }

    #[test]
    fn a_wrapped_pad_round_trips_through_a_file() {
        let (w, _) = wrapped(b"secret", 6);
        assert_eq!(Wrapped::decode(&w.encode()), Some(w));
    }

    /// **An attacker-chosen Argon2 cost is a denial of service** against the
    /// machine that opens the file, which is the one place this format is
    /// read from something a stranger may have written.
    #[test]
    fn an_absurd_work_factor_is_refused() {
        let (w, _) = wrapped(b"x", 7);
        for (m, t, p) in [
            (u32::MAX, 1, 1),
            (64, u32::MAX, 1),
            (64, 1, u32::MAX),
            (0, 1, 1),
            (64, 0, 1),
            (64, 1, 0),
        ] {
            let mut bad = w.clone();
            bad.params.m_kib = m;
            bad.params.t = t;
            bad.params.p = p;
            assert_eq!(
                Wrapped::decode(&bad.encode()),
                None,
                "accepted m={m} t={t} p={p}"
            );
        }
    }

    /// Nothing a stranger can write causes a panic.
    #[test]
    fn malformed_input_is_refused_without_panicking() {
        assert_eq!(Wrapped::decode(&[]), None);
        let (w, _) = wrapped(b"secret", 8);
        let good = w.encode();
        for cut in 0..good.len() {
            let _ = Wrapped::decode(&good[..cut]);
        }
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0xff;
            let _ = Wrapped::decode(&bad);
        }
        // And nonsense phrases.
        for p in ["", "not words at all", "a b c"] {
            assert_eq!(unwrap(&w, p), None);
        }
    }

    /// The warnings an operator must see are in the text, not in a document.
    /// The likeliest failure is pasting the words into chat, which downgrades
    /// the peering invisibly.
    #[test]
    fn the_instructions_state_how_this_fails() {
        let out = instructions("/tmp/alice.wrapped", "word word");
        assert!(out.contains("READ THESE ALOUD"), "{out}");
        assert!(out.contains("Do NOT type them into chat"), "{out}");
        assert!(out.contains("recorded"), "{out}");
        assert!(out.contains("synthesised"), "{out}");
        assert!(out.contains("peer seal"), "the next step is missing: {out}");
    }

    /// Real parameters, once, so the cheap ones used elsewhere are not the
    /// only thing exercised.
    #[test]
    fn it_works_at_the_real_work_factor() {
        let mut rng = NotRandom::seeded(9);
        let (w, phrase) = wrap(b"half a shared secret", &mut rng).expect("wraps");
        assert_eq!(phrase.split_whitespace().count(), WORDS);
        assert_eq!(
            unwrap(&w, &phrase).as_deref(),
            Some(&b"half a shared secret"[..])
        );
        let _ = cheap;
    }
}
