//! `short` framing — RFC 4 §8.
//!
//! ```text
//! [1B ver<<4|class][4B tag][3B expiry_h][2B ctr][N body][8B truncated MAC]
//! = 18 + N bytes;  N ≤ 37 at a 55-byte ceiling
//! ```
//!
//! > Keyed from the pairwise reservoir in the credential (RFC 7 §6). Nonce
//! > from `(link_id, ctr)`. A `short` message MUST NOT be forwarded, MUST NOT
//! > be stored beyond display, and MUST NOT enter reconciliation.
//!
//! RFC 1 §5.5 defers the encoding to here, "because `short` is a transport
//! message and not a corpus object: no identifier, no relay, no
//! reconciliation".
//!
//! # The three prohibitions are structural, not remembered
//!
//! A `short` message never becomes a [`krab_core::object`]: [`open`] returns
//! bytes and a [`Short`] header, and there is no constructor anywhere that
//! turns one into something the store will accept. It has **no object
//! identifier** — nothing to reconcile *by* — so RBSR and the manifest cannot
//! carry it even if someone tried. That is what makes "MUST NOT enter
//! reconciliation" a property of the type rather than a rule someone has to
//! keep remembering.
//!
//! "MUST NOT be stored beyond display" is the caller's to honour, and the one
//! this module cannot enforce. It is stated at every entry point.
//!
//! # The 64-bit MAC, restated as §8 requires
//!
//! > A 64-bit truncated MAC is defensible only because the link is pairwise,
//! > mutually authenticated, and low-volume. Implementations MUST restate this
//! > in their security documentation rather than treating it as settled by
//! > citation.
//!
//! So, plainly: **an 8-byte tag gives an online forger a 2⁻⁶⁴ chance per
//! attempt.** That is not a comfortable margin by modern standards — a 128-bit
//! tag is the default for good reason — and it is accepted here only because
//! all three of §8's conditions hold and each is load-bearing:
//!
//! - **Pairwise.** There is exactly one other party who could be forging, and
//!   they already share the key, so forgery gains them nothing they cannot do
//!   honestly.
//! - **Mutually authenticated.** A forger has to be inside an established
//!   Noise session (RFC 4 §4.1) to deliver an attempt at all. An off-path
//!   attacker gets no attempts, not merely unlikely ones.
//! - **Low-volume.** [`MAX_CTR`] caps a key at 65 535 messages, so an attacker
//!   who somehow gets on-path cannot grind: they get one attempt per message
//!   the link would carry anyway, and the epoch rotates the key underneath
//!   them (RFC 7 §6).
//!
//! **If any of those stops being true, this framing stops being defensible.**
//! In particular it must never be used on a broadcast link, a channel, or
//! anything a third party can inject into. `Documentation/SECURE-DELETE.md`
//! carries this same paragraph, because §8 asks for it in the security
//! documentation and a module comment is not that.
//!
//! # Nonce, and the counter that must not wrap
//!
//! `nonce = BLAKE3(link_id)[..10] ‖ u16_le(ctr)`.
//!
//! Ten bytes bind the nonce to the link and two carry the counter, which is
//! the `(link_id, ctr)` §8 asks for. **A repeated nonce under one key breaks
//! ChaCha20-Poly1305 catastrophically** — it leaks the XOR of two plaintexts
//! and, worse, the Poly1305 key — so [`seal`] refuses at [`MAX_CTR`] rather
//! than wrapping. Refusing is the only safe direction: a wrap is silent and
//! its consequence is total.
//!
//! The reservoir rotating per epoch (RFC 7 §6) means a key rarely lives long
//! enough to approach the cap. The refusal is for the case where it does.

use alloc::vec::Vec;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use krab_core::object::Class;

/// `1B ver<<4|class` + `4B tag` + `3B expiry_h` + `2B ctr`.
pub const HEADER: usize = 10;
/// The truncated MAC — RFC 4 §8's 64 bits.
pub const MAC: usize = 8;
/// Everything that is not body.
pub const OVERHEAD: usize = HEADER + MAC;
/// The largest body at §8's 55-byte ceiling.
pub const MAX_BODY: usize = 37;
/// §8's ceiling.
pub const MAX_MESSAGE: usize = OVERHEAD + MAX_BODY;
/// The last counter value a key may use. See the module note on nonces.
pub const MAX_CTR: u16 = u16::MAX - 1;

/// The protocol version this framing carries, in the high nibble.
const VERSION: u8 = krab_core::object::VERSION;

/// What went wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Body longer than [`MAX_BODY`], or a message outside the size bounds.
    TooLong,
    /// The message is shorter than [`OVERHEAD`].
    TooShort,
    /// Version or class byte is not a `short` of this version.
    NotShort,
    /// The MAC did not check. **Not distinguished from any other failure to a
    /// caller who might time it** — there is one error for a bad tag and it
    /// carries nothing about which byte differed.
    Mac,
    /// The counter reached [`MAX_CTR`]. The link must rotate its key rather
    /// than wrap the nonce.
    CounterExhausted,
}

/// A parsed `short` header. The body is returned separately by [`open`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Short {
    /// Destination tag, truncated to 4 bytes — RFC 4 §8's field.
    pub tag: [u8; 4],
    /// Expiry, in hours. Three bytes on the wire.
    pub expiry_h: u32,
    /// Per-link counter, and half the nonce.
    pub ctr: u16,
}

/// Derive the AEAD nonce from `(link_id, ctr)` — RFC 4 §8.
fn nonce(link_id: &[u8], ctr: u16) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..10].copy_from_slice(&blake3::hash(link_id).as_bytes()[..10]);
    n[10..].copy_from_slice(&ctr.to_le_bytes());
    n
}

/// The 10-byte header, which is also the AEAD's associated data.
///
/// Authenticating the header is what stops an attacker editing the expiry or
/// the tag of a message they cannot read — the fields are in the clear, so
/// without this they would be malleable.
///
/// `expiry_h` is written **little-endian**, like every other integer in this
/// codebase (RFC 2 §4.1's `u32_le`). §8 does not say, and a three-byte field
/// has no convention to fall back on; this is the choice, recorded because a
/// second implementation choosing the other way would produce messages that
/// authenticate and then expire at the wrong time.
fn header(tag: &[u8; 4], expiry_h: u32, ctr: u16) -> [u8; HEADER] {
    let mut h = [0u8; HEADER];
    h[0] = (VERSION << 4) | Class::Short as u8;
    h[1..5].copy_from_slice(tag);
    let e = expiry_h.to_le_bytes();
    h[5..8].copy_from_slice(&e[..3]);
    h[8..10].copy_from_slice(&ctr.to_le_bytes());
    h
}

/// Frame and seal one `short` message.
///
/// `key` comes from the pairwise reservoir (RFC 7 §6); `link_id` is the
/// link's identifier, and together with `ctr` it makes the nonce.
///
/// **The result MUST NOT be forwarded and MUST NOT be stored beyond display**
/// — RFC 4 §8. Nothing here can enforce the second; it is the caller's.
pub fn seal(
    key: &[u8; 32],
    link_id: &[u8],
    ctr: u16,
    tag: &[u8; 4],
    expiry_h: u32,
    body: &[u8],
) -> Result<Vec<u8>, Error> {
    if body.len() > MAX_BODY {
        return Err(Error::TooLong);
    }
    if ctr >= MAX_CTR {
        return Err(Error::CounterExhausted);
    }
    // Three bytes on the wire, so a larger value would be silently truncated
    // into a message that expires at the wrong time.
    if expiry_h > 0x00FF_FFFF {
        return Err(Error::TooLong);
    }

    let head = header(tag, expiry_h, ctr);
    let cipher = ChaCha20Poly1305::new(key.into());
    let n = nonce(link_id, ctr);
    // `encrypt` returns `ciphertext ‖ tag16`.
    let sealed = cipher
        .encrypt(
            (&n).into(),
            Payload {
                msg: body,
                aad: &head,
            },
        )
        .map_err(|_| Error::TooLong)?;

    let mut out = Vec::with_capacity(OVERHEAD + body.len());
    out.extend_from_slice(&head);
    out.extend_from_slice(&sealed[..body.len()]);
    // **Truncated to 8 bytes** — RFC 4 §8, and the module note argues it.
    out.extend_from_slice(&sealed[body.len()..body.len() + MAC]);
    Ok(out)
}

/// Verify and open one `short` message.
///
/// Returns the header and the plaintext. **The plaintext MUST NOT be stored
/// beyond display** — RFC 4 §8.
pub fn open(key: &[u8; 32], link_id: &[u8], msg: &[u8]) -> Result<(Short, Vec<u8>), Error> {
    if msg.len() < OVERHEAD {
        return Err(Error::TooShort);
    }
    if msg.len() > MAX_MESSAGE {
        return Err(Error::TooLong);
    }
    let head: [u8; HEADER] = msg[..HEADER].try_into().map_err(|_| Error::TooShort)?;
    if head[0] != (VERSION << 4) | Class::Short as u8 {
        return Err(Error::NotShort);
    }
    let tag = [head[1], head[2], head[3], head[4]];
    let expiry_h = u32::from_le_bytes([head[5], head[6], head[7], 0]);
    let ctr = u16::from_le_bytes([head[8], head[9]]);

    let ct = &msg[HEADER..msg.len() - MAC];
    let mac = &msg[msg.len() - MAC..];
    let n = nonce(link_id, ctr);
    let cipher = ChaCha20Poly1305::new(key.into());

    // **Verifying a truncated tag takes two passes, and this is why.**
    //
    // The AEAD's `decrypt` wants the whole 16-byte Poly1305 tag and only eight
    // of them were transmitted, so the authentic tag has to be *recomputed*
    // rather than supplied. There is no API here that verifies a partial tag,
    // and inventing one by reaching into the primitive would put a second
    // Poly1305 in the tree.
    //
    // Pass one: ChaCha20 is a stream cipher, so encrypting the ciphertext with
    // the same nonce XORs the same keystream and yields the plaintext. The tag
    // this call returns is computed over the plaintext, which is not the one
    // wanted, so it is dropped.
    let p = cipher
        .encrypt(
            (&n).into(),
            Payload {
                msg: ct,
                aad: &head,
            },
        )
        .map_err(|_| Error::Mac)?;
    let plain = p[..ct.len()].to_vec();

    // Pass two: encrypting the recovered plaintext reproduces the ciphertext
    // and returns the tag actually computed over it — the one to compare.
    let c = cipher
        .encrypt(
            (&n).into(),
            Payload {
                msg: &plain,
                aad: &head,
            },
        )
        .map_err(|_| Error::Mac)?;
    let full = &c[ct.len()..];

    // Constant time: no early exit, and the result is one bit either way. A
    // comparison that returned at the first differing byte would leak how much
    // of a forged tag was right, which is exactly the grind an 8-byte tag
    // cannot afford.
    let mut diff = 0u8;
    for i in 0..MAC {
        diff |= full[i] ^ mac[i];
    }
    if diff != 0 {
        return Err(Error::Mac);
    }

    Ok((
        Short {
            tag,
            expiry_h,
            ctr,
        },
        plain,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const KEY: [u8; 32] = [9u8; 32];
    const LINK: &[u8] = b"link-abc";
    const TAG: [u8; 4] = [1, 2, 3, 4];

    #[test]
    fn a_message_round_trips() {
        let msg = seal(&KEY, LINK, 7, &TAG, 1234, b"hello").unwrap();
        let (h, body) = open(&KEY, LINK, &msg).unwrap();
        assert_eq!(body, b"hello");
        assert_eq!(h.tag, TAG);
        assert_eq!(h.expiry_h, 1234);
        assert_eq!(h.ctr, 7);
    }

    /// **RFC 4 §8's size law**: `18 + N`, and 55 bytes at `N = 37`.
    #[test]
    fn the_wire_size_is_eighteen_plus_the_body() {
        for n in [0usize, 1, 20, MAX_BODY] {
            let msg = seal(&KEY, LINK, 1, &TAG, 9, &vec![0xAB; n]).unwrap();
            assert_eq!(msg.len(), OVERHEAD + n, "body {n}");
        }
        let full = seal(&KEY, LINK, 1, &TAG, 9, &[0; MAX_BODY]).unwrap();
        assert_eq!(full.len(), 55, "§8's ceiling");
        assert_eq!(MAX_MESSAGE, 55);
        assert_eq!(OVERHEAD, 18);
    }

    /// A body past the ceiling is refused, not truncated into a message that
    /// says something else.
    #[test]
    fn an_oversized_body_is_refused() {
        assert_eq!(
            seal(&KEY, LINK, 1, &TAG, 9, &[0; MAX_BODY + 1]),
            Err(Error::TooLong)
        );
    }

    /// The first byte is `ver<<4|class`, and the class is `Short`.
    #[test]
    fn the_version_and_class_are_in_the_first_byte() {
        let msg = seal(&KEY, LINK, 1, &TAG, 9, b"x").unwrap();
        assert_eq!(msg[0] >> 4, VERSION);
        assert_eq!(msg[0] & 0x0f, Class::Short as u8);
        assert_eq!(msg[0] & 0x0f, 3);
    }

    /// **The MAC is 8 bytes and it actually authenticates.** Every single-bit
    /// flip anywhere in the message must be caught — the header included,
    /// because those fields travel in the clear and would otherwise be
    /// malleable.
    #[test]
    fn every_flipped_bit_is_caught() {
        let msg = seal(&KEY, LINK, 3, &TAG, 500, b"payload!").unwrap();
        for i in 0..msg.len() {
            for bit in [0x01u8, 0x80] {
                let mut bad = msg.clone();
                bad[i] ^= bit;
                if bad == msg {
                    continue;
                }
                let got = open(&KEY, LINK, &bad);
                assert!(
                    got.is_err(),
                    "byte {i} bit {bit:#x} was not caught: {got:?}"
                );
            }
        }
    }

    /// The header is associated data, so editing the expiry of a message you
    /// cannot read still fails — this is the specific case the loop above
    /// covers generally, pinned on its own because it is the interesting one.
    #[test]
    fn the_clear_text_header_is_authenticated() {
        let msg = seal(&KEY, LINK, 3, &TAG, 500, b"payload!").unwrap();
        let mut forged = msg.clone();
        forged[5] = forged[5].wrapping_add(1); // expiry_h
        assert_eq!(open(&KEY, LINK, &forged), Err(Error::Mac));

        let mut retagged = msg.clone();
        retagged[1] ^= 0xff; // destination tag
        assert_eq!(open(&KEY, LINK, &retagged), Err(Error::Mac));
    }

    /// A different key, or a different link, does not open it. The link is in
    /// the nonce, so a message replayed onto another link fails.
    #[test]
    fn the_key_and_the_link_both_matter() {
        let msg = seal(&KEY, LINK, 3, &TAG, 9, b"secret").unwrap();
        assert_eq!(open(&[8u8; 32], LINK, &msg), Err(Error::Mac));
        assert_eq!(open(&KEY, b"another-link", &msg), Err(Error::Mac));
    }

    /// **The counter must not wrap.** A repeated nonce under one key leaks the
    /// Poly1305 key, so `seal` refuses rather than rolling over.
    #[test]
    fn the_counter_refuses_to_wrap() {
        assert!(seal(&KEY, LINK, MAX_CTR - 1, &TAG, 9, b"ok").is_ok());
        assert_eq!(
            seal(&KEY, LINK, MAX_CTR, &TAG, 9, b"no"),
            Err(Error::CounterExhausted)
        );
        assert_eq!(
            seal(&KEY, LINK, u16::MAX, &TAG, 9, b"no"),
            Err(Error::CounterExhausted)
        );
    }

    /// Two counters give two different nonces, so identical plaintexts do not
    /// produce identical ciphertexts.
    #[test]
    fn the_counter_changes_the_ciphertext() {
        let a = seal(&KEY, LINK, 1, &TAG, 9, b"same").unwrap();
        let b = seal(&KEY, LINK, 2, &TAG, 9, b"same").unwrap();
        assert_ne!(a[HEADER..], b[HEADER..], "nonce reuse across counters");
    }

    /// Truncated and overlong messages are refused before any crypto runs.
    #[test]
    fn malformed_lengths_are_refused() {
        assert_eq!(open(&KEY, LINK, &[]), Err(Error::TooShort));
        assert_eq!(open(&KEY, LINK, &[0u8; OVERHEAD - 1]), Err(Error::TooShort));
        assert_eq!(
            open(&KEY, LINK, &[0u8; MAX_MESSAGE + 1]),
            Err(Error::TooLong)
        );
    }

    /// A message of another class or version is not a `short`, and says so
    /// rather than failing as a bad MAC.
    #[test]
    fn another_class_is_not_a_short() {
        let mut msg = seal(&KEY, LINK, 1, &TAG, 9, b"x").unwrap();
        msg[0] = (VERSION << 4) | Class::Sealed as u8;
        assert_eq!(open(&KEY, LINK, &msg), Err(Error::NotShort));
        msg[0] = (2 << 4) | Class::Short as u8;
        assert_eq!(open(&KEY, LINK, &msg), Err(Error::NotShort));
    }

    /// An expiry that does not fit three bytes is refused rather than silently
    /// truncated into a message that expires at the wrong time.
    #[test]
    fn an_unrepresentable_expiry_is_refused() {
        assert!(seal(&KEY, LINK, 1, &TAG, 0x00FF_FFFF, b"x").is_ok());
        assert_eq!(
            seal(&KEY, LINK, 1, &TAG, 0x0100_0000, b"x"),
            Err(Error::TooLong)
        );
    }

    /// An empty body is legal — `18 + 0`.
    #[test]
    fn an_empty_body_is_legal() {
        let msg = seal(&KEY, LINK, 1, &TAG, 9, b"").unwrap();
        assert_eq!(msg.len(), OVERHEAD);
        let (_, body) = open(&KEY, LINK, &msg).unwrap();
        assert!(body.is_empty());
    }
}
