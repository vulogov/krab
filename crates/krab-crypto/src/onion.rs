//! Onion service key derivation — RFC 4 §5.2.
//!
//! ```text
//! The onion service key MUST NOT be derived from, or equal to, the node
//! identity key.
//! ```
//!
//! §5.2 gives three reasons, and they are the reason this module is separate
//! from everything in `identity`:
//!
//! 1. it would **weld network location to identity permanently**, undoing the
//!    endpoint-free rollcall of RFC 3 §9.2;
//! 2. reusing an Ed25519 key across the Krab protocol and the hidden-service
//!    protocol is **textbook cross-protocol exposure**;
//! 3. it would make **onion rotation impossible** without changing identity.
//!
//! And the permitted construction:
//!
//! ```text
//! Where operators want one secret to back up, the service key SHOULD be
//! derived through a KDF with a distinct domain string and a rotatable epoch
//! counter.
//! ```
//!
//! That is exactly what this is: [`OnionRoot`] is the one secret, `DOMAIN` is
//! the distinct domain string, and [`Counter`] is the rotatable epoch counter.
//!
//! # Why the root is its own secret and not the KEK
//!
//! A permanent address wants a root that survives everything except a
//! deliberate rotation. The KEK does not: it is derived from the passphrase
//! (RFC 7 §4), so deriving the onion key from it would silently change the
//! node's address every time an operator changed their passphrase — a
//! network-visible consequence of an action that has nothing to do with the
//! network, and one nothing would warn them about.
//!
//! So [`OnionRoot`] is 32 random bytes made once at init and sealed under the
//! KEK beside the identity. Rekeying reseals it unchanged; the address holds.
//!
//! # Why the address is permanent
//!
//! Tor's `ADD_ONION` accepts either `NEW:ED25519-V3`, where tor generates a key
//! and the address changes at every start, or `ED25519-V3:<key>`, where the
//! caller supplies one and the address is a pure function of it. Krab supplies
//! one. The consequence is that a peer's stored `.onion` keeps working across
//! restarts, reinstalls and machine moves, and that **no onion key is ever
//! written to disk** — tor is handed it over the control port and never asked
//! to persist it.
//!
//! # The expanded-key format, which is the part that is easy to get wrong
//!
//! `ED25519-V3` does **not** take a 32-byte seed. It takes the 64-byte
//! *expanded* secret key: `SHA-512(seed)`, with the standard Ed25519 clamping
//! applied to the first half. The first 32 bytes are the scalar, the second 32
//! are the nonce prefix. Handing tor a raw seed produces a key that is
//! accepted, wrong, and gives a different address than any other Ed25519
//! implementation would derive from the same seed.

use alloc::string::String;
use alloc::vec::Vec;
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The distinct domain string RFC 4 §5.2 asks for.
///
/// It must not collide with any other label in this crate, which
/// `krab-node/tests/domain_separation.rs` enforces across the workspace
/// (RFC 3 §3).
pub const DOMAIN: &[u8] = b"krab/onion/v1";

/// The distinct domain string for the **contact** endpoint — RFC 3 §9.2.
///
/// A separate domain, not merely a separate counter. Sharing `DOMAIN` and
/// distinguishing the two endpoints by counter alone would mean the contact
/// address at counter *n* is byte-identical to the sync address at counter
/// *n* — so rotating the contact endpoint onto a counter the sync endpoint had
/// used would publish the sync address, unrestricted, to anyone. The
/// separation §9.2 asks for would collapse silently and at exactly the moment
/// an operator did the thing §9.2 calls "freely rotatable".
pub const DOMAIN_CONTACT: &[u8] = b"krab/onion-contact/v1";

/// Which of RFC 3 §9.2's two endpoints a key is for.
///
/// > "Where endpoints are exchanged, implementations SHOULD separate a
/// > **contact endpoint** (accepts only peer-requests, freely rotatable) from
/// > a **sync endpoint** (never published, protected by Tor restricted
/// > discovery where applicable — RFC 4)."
///
/// The two differ in three ways at once and all three are load-bearing: a
/// different key, a different discovery regime, and a different thing
/// listening behind them. This type carries the first; RFC 4 §5.2's
/// `ClientAuthV3` carries the second; and the port each is mapped to carries
/// the third.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    /// Never published, restricted discovery, reconciliation behind it.
    Sync,
    /// Handed out to a stranger for one peering, unrestricted, with only the
    /// first-contact listener behind it.
    Contact,
}

impl Endpoint {
    /// The domain string this endpoint derives under.
    pub fn domain(&self) -> &'static [u8] {
        match self {
            Endpoint::Sync => DOMAIN,
            Endpoint::Contact => DOMAIN_CONTACT,
        }
    }
}

/// The rotatable epoch counter of RFC 4 §5.2.
///
/// Not a time epoch. It advances only when an operator rotates the address,
/// which is why it is a distinct type from [`krab_core::tag::Epoch`] — the two
/// are both "counters that go into a KDF" and confusing them would rotate a
/// node's onion address every fifteen minutes.
pub type Counter = u32;

/// The one secret an operator backs up, from which every onion key follows.
///
/// Sealed under the KEK beside the identity, and never equal to or derived
/// from it — RFC 4 §5.2's MUST.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OnionRoot([u8; 32]);

impl OnionRoot {
    /// Wrap 32 bytes that came from the system RNG.
    pub fn from_bytes(b: [u8; 32]) -> OnionRoot {
        OnionRoot(b)
    }

    /// The bytes, for sealing under the KEK.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Generate a fresh root.
    ///
    /// Takes this crate's [`crate::rng::Rng`] rather than `rand_core`'s trait,
    /// so that the one place a node's onion identity comes into existence uses
    /// the same entropy source as every other secret here.
    pub fn generate(rng: &mut impl crate::rng::Rng) -> OnionRoot {
        OnionRoot(rng.next_32())
    }
}

/// Prints nothing — RFC 7 §9.
impl core::fmt::Debug for OnionRoot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OnionRoot(<redacted>)")
    }
}

/// A 64-byte Ed25519 expanded secret key, in the form `ADD_ONION` wants.
///
/// Zeroized on drop. [`ExpandedKey::to_base64`] is the only way out, and the
/// string it returns is the caller's to erase — `TorProcess` overwrites it
/// after the control command is written.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ExpandedKey([u8; 64]);

impl ExpandedKey {
    /// The blob, base64 as the control protocol requires.
    pub fn to_base64(&self) -> String {
        base64(&self.0)
    }

    /// The raw expanded key, for tests and vectors.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Prints nothing — RFC 7 §9.
impl core::fmt::Debug for ExpandedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ExpandedKey(<redacted>)")
    }
}

/// Derive the onion service key for `counter`.
///
/// `seed = BLAKE3-derive-key(DOMAIN ‖ u32_le(counter), root)`, then the
/// Ed25519 expansion `SHA-512(seed)` with clamping.
///
/// # Why BLAKE3 here and HKDF-SHA256 in [`crate::kdf`]
///
/// [`crate::kdf`] is HKDF-SHA256 because RFC 1 §6.1 froze the suite's KDF and
/// tags must interoperate byte for byte with every other implementation. This
/// derivation interoperates with **nothing** — the output is consumed by the
/// local tor and never appears on the Krab wire — so it is free to use the
/// hash the rest of the codebase uses, and `blake3::derive_key` is a
/// purpose-built KDF whose context string is exactly the domain separation
/// §5.2 asks for.
///
/// The counter is little-endian, matching every other counter in this
/// codebase (RFC 2 §4.1's `u32_le`).
pub fn service_key(root: &OnionRoot, counter: Counter) -> ExpandedKey {
    endpoint_key(root, Endpoint::Sync, counter)
}

/// Derive the onion service key for one endpoint at one counter.
///
/// The general form of [`service_key`], which is the `Sync` case. Both
/// endpoints come from the same [`OnionRoot`] — one secret to back up, as
/// §5.2 asks — and are separated by domain string rather than by counter, for
/// the reason [`DOMAIN_CONTACT`] gives.
pub fn endpoint_key(root: &OnionRoot, endpoint: Endpoint, counter: Counter) -> ExpandedKey {
    let domain = endpoint.domain();
    // `derive_key` takes the context as `&str`, and both parts are ours.
    let mut context = Vec::with_capacity(domain.len() + 4);
    context.extend_from_slice(domain);
    context.extend_from_slice(&counter.to_le_bytes());
    // The context is not required to be UTF-8 by BLAKE3's construction, but
    // the safe API insists, so it is hex-encoded rather than lossily
    // converted — a lossy conversion would map distinct counters onto the same
    // context and silently give two rotations the same address.
    let context = hex(&context);

    let mut seed = [0u8; 32];
    seed.copy_from_slice(blake3::derive_key(&context, root.as_bytes()).as_slice());

    // The Ed25519 expansion. `SHA-512(seed)`, clamp the scalar half.
    let mut expanded = [0u8; 64];
    expanded.copy_from_slice(&Sha512::digest(seed));
    seed.zeroize();

    // Standard Ed25519 clamping: clear the low three bits, clear the top bit,
    // set the second-highest. Omitting it produces a key tor accepts and every
    // other implementation disagrees with.
    expanded[0] &= 248;
    expanded[31] &= 127;
    expanded[31] |= 64;

    ExpandedKey(expanded)
}

/// The domain string for restricted-discovery client authentication.
///
/// **Not in any RFC.** RFC 4 §5.2 requires that "the authorised-client set
/// derives directly from the node's signed credentials" and does not say how.
/// This is the construction chosen here, and because two implementations that
/// derive it differently will silently fail to reach each other, it is
/// recorded in `Documentation/RFC-ERRATA.md` rather than left implicit.
pub const DOMAIN_CLIENT_AUTH: &[u8] = b"krab/onion-client-auth/v1";

/// A restricted-discovery client-auth keypair — RFC 4 §5.2.
///
/// Zeroized on drop. The secret half goes to *this node's* tor when it is the
/// client; the public half goes into the service's `ClientAuthV3` list when it
/// is the server. Both sides derive the same pair, which is what makes the two
/// roles agree without another exchange.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ClientAuth {
    secret: [u8; 32],
    public: [u8; 32],
}

impl ClientAuth {
    /// The x25519 public key, base32 — what `ClientAuthV3=` wants.
    pub fn public_base32(&self) -> String {
        base32(&self.public)
    }

    /// The x25519 private key, base32 — what `ONION_CLIENT_AUTH_ADD` wants.
    ///
    /// Returns a `String` the caller must erase. Every caller here overwrites
    /// it once the control command is written.
    pub fn secret_base32(&self) -> String {
        base32(&self.secret)
    }

    /// The x25519 private key, **base64** — what `ONION_CLIENT_AUTH_ADD` wants.
    ///
    /// # The two encodings are different, and that is tor's grammar
    ///
    /// The service publishes the public half with
    /// `ADD_ONION … ClientAuthV3=<base32>`, and the client registers the
    /// private half with `ONION_CLIENT_AUTH_ADD <addr> x25519:<base64>`. Same
    /// key type, same protocol, two encodings — so a single `to_string` used
    /// for both halves produces a service nobody can reach and a client tor
    /// refuses, and the two failures look nothing alike.
    ///
    /// Both are spelled out here, next to each other, so the asymmetry is a
    /// property of the type rather than something a caller has to remember at
    /// the point of use.
    pub fn secret_base64(&self) -> String {
        base64(&self.secret)
    }

    /// The raw public half, for tests and vectors.
    pub fn public_bytes(&self) -> &[u8; 32] {
        &self.public
    }
}

/// Prints nothing — RFC 7 §9.
impl core::fmt::Debug for ClientAuth {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ClientAuth(<redacted>)")
    }
}

/// Derive the restricted-discovery keypair for one peering.
///
/// ```text
/// sk = clamp(BLAKE3-derive-key("krab/onion-client-auth/v1", S))
/// pk = X25519(sk, basepoint)
/// ```
///
/// where `S` is the static-static X25519 agreement between the two nodes'
/// credential keys — [`crate::dh::agree`], the same value RFC 1 §6.2's tags
/// come from.
///
/// # Why derived and not the credential's own key
///
/// The obvious shortcut is to hand tor the peer's existing Noise static key:
/// it is already x25519 and already in the credential. That is exactly the
/// mistake RFC 4 §5.2 forbids one paragraph earlier — "reusing an Ed25519 key
/// across the Krab protocol and the hidden-service protocol is textbook
/// cross-protocol exposure". The argument does not depend on which key or
/// which direction, so the key is derived instead.
///
/// Reusing `S` itself for two derivations is not the same thing: `S` is
/// secret input to a KDF under a distinct domain string, which is the pattern
/// RFC 4 §5.2 explicitly permits for the service key. Nothing about the tag
/// derivation is recoverable from this output, or the reverse.
///
/// # Why both sides get the whole pair
///
/// X25519 agreement is symmetric, so the service and the client compute the
/// same `sk`. That is what removes the extra exchange: neither has to send the
/// other an auth key, and the set is a pure function of who has peered with
/// whom — which is "derives directly from the node's signed credentials",
/// read literally.
///
/// The service knowing the client's private half is not a weakness worth
/// closing. The key exists so the service can decide who may decrypt its
/// descriptor; a service that abuses it can only impersonate a client to
/// itself. Between *different* peers the values are unrelated, because each
/// derives from a different `S`.
pub fn client_auth(shared: &crate::dh::Shared) -> ClientAuth {
    let context = hex(DOMAIN_CLIENT_AUTH);
    let mut secret = [0u8; 32];
    secret.copy_from_slice(blake3::derive_key(&context, shared.as_bytes()).as_slice());

    // x25519-dalek clamps internally on use, but the *stored* bytes are what
    // is handed to tor — and tor clamps on use too, so an unclamped scalar
    // here would be clamped by tor into a key whose public half is the one
    // computed below only by luck. Clamping before deriving the public half
    // makes the two agree by construction.
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;

    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret));
    ClientAuth {
        secret,
        public: public.to_bytes(),
    }
}

/// RFC 4648 base32, upper-case, **unpadded** — tor's control protocol format.
///
/// Padding would be rejected: tor's `ClientAuthV3` grammar takes the bare
/// 52-character encoding of 32 bytes, and `=` is not in it.
fn base32(bytes: &[u8]) -> String {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(A[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(A[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Lower-case hex.
fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 0x0f) as usize] as char);
    }
    s
}

/// Standard base64 with padding — RFC 4648 §4.
///
/// Twenty lines rather than a dependency. The control protocol needs one
/// encoder and one alphabet, and a crate for that would be a fourth party in
/// the path between the KEK and the onion address.
fn base64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            A[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    fn root() -> OnionRoot {
        OnionRoot::from_bytes([7u8; 32])
    }

    /// **The address is permanent.** Same root and counter, same key, for ever
    /// — which is the whole reason the key is supplied to tor rather than
    /// generated by it.
    #[test]
    fn the_same_root_and_counter_give_the_same_key() {
        let a = service_key(&root(), 0);
        let b = service_key(&root(), 0);
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_eq!(a.to_base64(), b.to_base64());
    }

    /// **RFC 4 §5.2's rotation.** Bumping the counter gives a different key,
    /// and therefore a different address, from the same backed-up secret.
    #[test]
    fn the_counter_rotates_the_address() {
        let zero = service_key(&root(), 0);
        let one = service_key(&root(), 1);
        assert_ne!(zero.as_bytes(), one.as_bytes());
        // And it is not merely the counter appearing in the output somewhere:
        // every byte should differ from a KDF, so a trivial overlap would show
        // up as a long shared prefix.
        let shared = zero
            .as_bytes()
            .iter()
            .zip(one.as_bytes())
            .take_while(|(a, b)| a == b)
            .count();
        assert!(
            shared < 8,
            "{shared} leading bytes shared between rotations"
        );
    }

    /// A different root gives a different key — the derivation actually
    /// depends on the secret, rather than on the domain string alone.
    #[test]
    fn the_root_is_load_bearing() {
        let a = service_key(&OnionRoot::from_bytes([1u8; 32]), 0);
        let b = service_key(&OnionRoot::from_bytes([2u8; 32]), 0);
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    /// **The clamping is applied.** Without it tor accepts the key and derives
    /// a different address than any other Ed25519 implementation would — a
    /// failure that looks like "my peers cannot reach me" and nothing else.
    #[test]
    fn the_scalar_half_is_clamped() {
        for counter in 0..16 {
            let k = service_key(&root(), counter);
            let b = k.as_bytes();
            assert_eq!(b[0] & 0b0000_0111, 0, "low three bits must be clear");
            assert_eq!(b[31] & 0b1000_0000, 0, "top bit must be clear");
            assert_eq!(b[31] & 0b0100_0000, 0b0100_0000, "bit 62 must be set");
        }
    }

    /// The key is 64 bytes, not 32 — `ED25519-V3` takes the expanded form.
    #[test]
    fn the_key_is_the_expanded_form() {
        let k = service_key(&root(), 0);
        assert_eq!(k.as_bytes().len(), 64);
        // 64 bytes is 88 base64 characters with padding.
        assert_eq!(k.to_base64().len(), 88);
        assert!(k.to_base64().ends_with('='));
    }

    /// Neither type says anything about its contents — RFC 7 §9.
    #[test]
    fn debug_prints_nothing() {
        let r = root();
        let k = service_key(&r, 0);
        assert_eq!(format!("{r:?}"), "OnionRoot(<redacted>)");
        assert_eq!(format!("{k:?}"), "ExpandedKey(<redacted>)");
    }

    /// Base64 against RFC 4648 §10's published vectors, including both
    /// padding cases — a wrong encoder would be rejected by tor with a message
    /// about the key rather than about the encoding.
    #[test]
    fn base64_matches_rfc4648() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    /// **Both sides of a peering derive the same client-auth pair.** That is
    /// what removes the extra exchange — the service computes the public half
    /// for its `ClientAuthV3` list, the client computes the private half for
    /// its own tor, and neither sends the other anything.
    #[test]
    fn both_ends_of_a_peering_agree_on_the_client_auth_key() {
        use crate::dh;
        let a = dh::SecretKey::from_bytes([11u8; 32]);
        let b = dh::SecretKey::from_bytes([22u8; 32]);
        let (pa, pb) = (a.public(), b.public());

        let from_a = client_auth(&dh::agree(&a, &pb).unwrap());
        let from_b = client_auth(&dh::agree(&b, &pa).unwrap());

        assert_eq!(from_a.public_base32(), from_b.public_base32());
        assert_eq!(from_a.secret_base32(), from_b.secret_base32());
    }

    /// **Different peers get unrelated keys.** If they did not, one peer's
    /// authorisation would decrypt another's descriptor, and restricted
    /// discovery would restrict nothing.
    #[test]
    fn different_peerings_give_unrelated_keys() {
        use crate::dh;
        let me = dh::SecretKey::from_bytes([1u8; 32]);
        let p1 = dh::SecretKey::from_bytes([2u8; 32]);
        let p2 = dh::SecretKey::from_bytes([3u8; 32]);

        let k1 = client_auth(&dh::agree(&me, &p1.public()).unwrap());
        let k2 = client_auth(&dh::agree(&me, &p2.public()).unwrap());
        assert_ne!(k1.public_base32(), k2.public_base32());
        assert_ne!(k1.public_bytes(), k2.public_bytes());
    }

    /// **The client-auth key is not the credential's key.** RFC 4 §5.2 forbids
    /// reusing a protocol key in the hidden-service protocol, and the obvious
    /// shortcut — handing tor the peer's Noise static — is exactly that.
    #[test]
    fn the_client_auth_key_is_not_a_credential_key() {
        use crate::dh;
        let me = dh::SecretKey::from_bytes([5u8; 32]);
        let them = dh::SecretKey::from_bytes([6u8; 32]);
        let shared = dh::agree(&me, &them.public()).unwrap();
        let k = client_auth(&shared);

        assert_ne!(k.public_bytes(), &me.public().0);
        assert_ne!(k.public_bytes(), &them.public().0);
        // Nor the raw agreement itself.
        assert_ne!(k.public_bytes(), shared.as_bytes());
    }

    /// The scalar is clamped before the public half is derived, so tor's own
    /// clamping cannot produce a key whose public half differs from the one
    /// advertised.
    #[test]
    fn the_client_auth_scalar_is_clamped() {
        use crate::dh;
        for seed in 0..8u8 {
            let a = dh::SecretKey::from_bytes([seed; 32]);
            let b = dh::SecretKey::from_bytes([seed.wrapping_add(50); 32]);
            let k = client_auth(&dh::agree(&a, &b.public()).unwrap());
            assert_eq!(k.secret[0] & 0b0000_0111, 0);
            assert_eq!(k.secret[31] & 0b1000_0000, 0);
            assert_eq!(k.secret[31] & 0b0100_0000, 0b0100_0000);
        }
    }

    /// Neither half is printed — RFC 7 §9.
    #[test]
    fn client_auth_debug_prints_nothing() {
        use crate::dh;
        let a = dh::SecretKey::from_bytes([7u8; 32]);
        let b = dh::SecretKey::from_bytes([8u8; 32]);
        let k = client_auth(&dh::agree(&a, &b.public()).unwrap());
        assert_eq!(format!("{k:?}"), "ClientAuth(<redacted>)");
    }

    /// Base32 against RFC 4648 §10's vectors, upper-case and **unpadded** —
    /// tor's `ClientAuthV3` grammar has no `=` in it.
    #[test]
    fn base32_matches_rfc4648_without_padding() {
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(b"fo"), "MZXQ");
        assert_eq!(base32(b"foo"), "MZXW6");
        assert_eq!(base32(b"foob"), "MZXW6YQ");
        assert_eq!(base32(b"fooba"), "MZXW6YTB");
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        // 32 bytes is 52 characters, which is the length tor expects.
        assert_eq!(base32(&[0u8; 32]).len(), 52);
        assert!(!base32(&[0u8; 32]).contains('='));
    }

    /// Hex is lower-case and fixed-width — the control protocol's
    /// `AUTHENTICATE` rejects anything else.
    #[test]
    fn hex_is_lowercase_and_padded() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(hex(&[]), "");
    }

    /// **The counter cannot collide through the context string.**
    ///
    /// The context is hex-encoded because `blake3::derive_key` demands `&str`
    /// and a lossy UTF-8 conversion would map distinct counter bytes onto the
    /// same replacement character — giving two rotations the same address,
    /// silently. This is the test that would fail if someone simplified the
    /// hex away.
    #[test]
    fn every_counter_gives_a_distinct_context() {
        // `no_std`: a sorted `Vec` stands in for a `HashSet`.
        let mut seen: Vec<[u8; 64]> = Vec::new();
        // Counters whose little-endian bytes are not valid UTF-8, which is
        // where a lossy conversion collapses them together.
        for c in [0x80u32, 0x81, 0xff, 0xfe, 0x8080, 0xffff, u32::MAX] {
            let k = service_key(&root(), c);
            assert!(!seen.contains(k.as_bytes()), "counter {c:#x} collided");
            seen.push(*k.as_bytes());
        }
    }

    /// **The two endpoints never share an address, at any counter.**
    ///
    /// Separating them by counter alone would make the contact address at
    /// counter *n* identical to the sync address at counter *n* — so rotating
    /// the contact endpoint onto a counter the sync endpoint had used would
    /// publish the sync address unrestricted, which is the one thing RFC 3
    /// §9.2 exists to prevent. It would happen silently, and at exactly the
    /// moment an operator did what §9.2 calls "freely rotatable".
    #[test]
    fn a_contact_key_never_equals_a_sync_key() {
        let root = OnionRoot::from_bytes([7; 32]);
        let mut seen = alloc::collections::BTreeSet::new();
        for counter in 0..8u32 {
            for endpoint in [Endpoint::Sync, Endpoint::Contact] {
                let key = endpoint_key(&root, endpoint, counter);
                assert!(
                    seen.insert(*key.as_bytes()),
                    "{endpoint:?} at counter {counter} collided with an earlier key"
                );
            }
        }
        assert_eq!(seen.len(), 16);
    }

    /// `service_key` is the sync endpoint, unchanged. Peers hold addresses
    /// derived by it, so this is the compatibility check: if it ever stops
    /// meaning `Endpoint::Sync`, every stored `.onion` breaks at once.
    #[test]
    fn service_key_is_the_sync_endpoint() {
        let root = OnionRoot::from_bytes([3; 32]);
        for counter in [0u32, 1, 4_000_000_000] {
            assert_eq!(
                service_key(&root, counter).as_bytes(),
                endpoint_key(&root, Endpoint::Sync, counter).as_bytes()
            );
        }
    }

    /// Rotation actually rotates: the counter changes the key, and the old
    /// one is still derivable from the same root — which is what lets an
    /// operator roll back a rotation they regret.
    #[test]
    fn rotating_the_counter_changes_the_address_and_is_reversible() {
        let root = OnionRoot::from_bytes([11; 32]);
        let before = *service_key(&root, 4).as_bytes();
        let after = *service_key(&root, 5).as_bytes();
        assert_ne!(before, after);
        assert_eq!(
            *service_key(&root, 4).as_bytes(),
            before,
            "not reproducible"
        );
    }

    /// **The two halves are encoded the way tor asks for each.**
    ///
    /// `ClientAuthV3=` takes base32 and `ONION_CLIENT_AUTH_ADD` takes base64,
    /// for the same key type in the same protocol. Using one encoding for both
    /// gives a service nobody can reach and a client tor refuses, and neither
    /// failure names the other.
    #[test]
    fn the_client_auth_halves_use_the_encodings_tor_asks_for() {
        let a = crate::dh::SecretKey::from_bytes([9u8; 32]);
        let b = crate::dh::SecretKey::from_bytes([21u8; 32]);
        let shared = crate::dh::agree(&a, &b.public()).expect("agreement");
        let auth = client_auth(&shared);

        // base32 of 32 bytes: 52 characters, unpadded, RFC 4648 alphabet.
        let pk = auth.public_base32();
        assert_eq!(pk.len(), 52);
        assert!(!pk.contains('='));
        assert!(pk
            .chars()
            .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)));

        // base64 of 32 bytes: 44 characters with one pad.
        let sk = auth.secret_base64();
        assert_eq!(sk.len(), 44, "not base64: {sk}");
        assert!(
            sk.ends_with('='),
            "base64 of 32 bytes ends in one pad: {sk}"
        );
        assert_ne!(sk, auth.secret_base32(), "the two encodings collapsed");
    }
}
