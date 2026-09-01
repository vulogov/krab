//! This node's key hierarchy — what `init` creates.
//!
//! Three keypairs, deliberately not one:
//!
//! | key | purpose | why separate |
//! |---|---|---|
//! | Ed25519 identity | `node_id`, card signatures (RFC 3 §2) | signing, not agreement |
//! | X25519 Noise static | transport authentication (RFC 4 §4.1) | a *network* identity |
//! | X25519 correspondence | pairwise tag derivation (RFC 2 §4.1) | a *tag* namespace |
//!
//! Collapsing the two X25519 keys into one would tie the address a node is
//! reachable at to the tags its mail carries, and RFC 2 §2's I-2 keeps those
//! namespaces disjoint precisely so that observing a link tells an adversary
//! nothing about which tags to watch.
//!
//! # The 64-byte backup, and an inference
//!
//! RFC 7 §11 says "the backup is 64 bytes" without enumerating them. Two
//! 32-byte seeds is the only reading that fits, and the pair has to be the
//! identity seed and the **correspondence** seed:
//!
//! - Without the identity seed, every peer must re-verify out of band — the
//!   loss §11 names explicitly.
//! - Without the correspondence seed, no pairwise tag with any existing peer
//!   can be derived, so the identity survives and addresses nobody. Recovering
//!   requires a fresh ceremony with every peer, which is the same cost.
//!
//! The Noise static is deliberately **not** in the backup. It is a link key; a
//! restored node republishes a card and peers learn the new one. Including it
//! would cost 32 bytes of the operator's handwriting for no recovery value.
//!
//! §11 should say which 64 bytes. An implementation that backed up the
//! identity keypair as private ‖ public would also produce 64 bytes, restore
//! cleanly, pass every test — and lose every correspondent.

use crate::peering::{Card, Policy};
use krab_crypto::dh::SecretKey;
use krab_crypto::kek::{Hierarchy, Kek, KekParams};
use krab_crypto::rng::Rng;
use krab_crypto::sign::SigningKey;
use krab_crypto::words;
use std::fmt;
use zeroize::Zeroize;

/// Everything `init` generates.
pub struct Identity {
    signing: SigningKey,
    noise: SecretKey,
    correspondence: SecretKey,
    /// Argon2id parameters and salt, stored (RFC 7 §4.1).
    pub kek_params: KekParams,
    /// Epoch wrapper keys.
    pub hierarchy: Hierarchy,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The identifier is public; nothing else here is.
        write!(f, "Identity({})", self.short_id())
    }
}

impl Identity {
    /// Generate a complete hierarchy.
    ///
    /// Randomness is an argument — the OS generator is `crate::entropy::OsRng`,
    /// and it is named in exactly one place in the workspace.
    pub fn generate(rng: &mut impl Rng) -> Identity {
        Identity {
            signing: SigningKey::generate(rng),
            noise: SecretKey::generate(rng),
            correspondence: SecretKey::generate(rng),
            kek_params: KekParams::new(rng),
            hierarchy: Hierarchy::new(),
        }
    }

    /// Replace the correspondence key — RFC 2 §9's rotation.
    ///
    /// > Static-static ECDH is the structural weakness. Pairwise tags derive
    /// > from a stable shared secret, so compromise of either long-term X25519
    /// > key retroactively links every message between that pair across the
    /// > entire retained corpus… Rotation is the only remedy.
    ///
    /// **Only the correspondence key moves.** The Ed25519 identity stays, so
    /// `node_id` stays, so every peer still knows who this is and every
    /// signature ever made still verifies. Rotating the identity key instead
    /// would not be rotation, it would be becoming a different node — and RFC
    /// 3 §9.2's rollcall, RFC 6's channels and every stored peer-link are all
    /// keyed on `node_id`.
    ///
    /// The Noise static is left alone for the same reason it is separate in
    /// the first place (see this module's table): it is a *transport*
    /// identity, and rotating it would break every configured link address
    /// without touching the correlation §9 is about.
    ///
    /// # What this cannot undo
    ///
    /// The old key's shared secrets are gone with it, so **mail in flight
    /// under the old tags can never be opened** — §9's "messages in flight
    /// under the old key are lost", which "on a courier route may be weeks of
    /// traffic". The caller must have said so before calling this.
    pub fn rotate_correspondence(&mut self, rng: &mut impl Rng) {
        // The old secret is dropped here. `x25519_dalek::StaticSecret` is
        // built with the `zeroize` feature (see `krab-crypto/Cargo.toml`), so
        // the assignment overwrites it rather than leaving it on the heap —
        // which is the whole point of rotating and would be undone by a
        // residue RFC 7 §9 warns about.
        self.correspondence = SecretKey::generate(rng);
    }

    /// `node_id`, RFC 3 §2.
    pub fn node_id(&self) -> [u8; 32] {
        self.signing.node_id()
    }

    /// The spoken fingerprint — first 8 bytes as words (RFC 3 §2).
    pub fn fingerprint(&self) -> String {
        words::phrase(&self.node_id()[..8])
    }

    /// A short hex form, for a status line where eight words will not fit.
    pub fn short_id(&self) -> String {
        let id = self.node_id();
        format!("{:02x}{:02x}{:02x}{:02x}", id[0], id[1], id[2], id[3])
    }

    /// The 64-byte offline backup, as words (RFC 7 §11).
    ///
    /// # This is the only time it can be produced
    ///
    /// Not because the bytes vanish, but because §11 requires the backup be
    /// made at creation and the ceremony is what enforces it. Showing it again
    /// later on request would turn a one-time ceremony into a settings item,
    /// which is the exact failure §11 legislates against.
    pub fn backup_phrase(&self) -> String {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.signing.to_seed());
        bytes[32..].copy_from_slice(&self.correspondence.to_bytes());
        let out = words::phrase(&bytes);
        // The array is a stack copy of two secrets. It does not outlive this
        // call, but leaving it intact is exactly the residue RFC 7 §9 warns
        // about — and a plain loop here is one the optimiser may delete, since
        // nothing reads the buffer afterwards. `zeroize` writes volatilely.
        bytes.zeroize();
        out
    }

    /// Derive the KEK from a passphrase, RFC 7 §4.1.
    pub fn kek(&self, passphrase: &[u8]) -> Result<Kek, krab_crypto::kek::Error> {
        Kek::derive(passphrase, &self.kek_params)
    }

    /// Reconstruct from stored seeds — see `crate::persist`.
    pub fn from_parts(
        signing_seed: &[u8; 32],
        noise: [u8; 32],
        correspondence: [u8; 32],
        kek_params: KekParams,
    ) -> Identity {
        Identity {
            signing: SigningKey::from_seed(signing_seed),
            noise: SecretKey::from_bytes(noise),
            correspondence: SecretKey::from_bytes(correspondence),
            kek_params,
            hierarchy: Hierarchy::new(),
        }
    }

    /// The Ed25519 seed, for wrapping. Never for display.
    pub fn signing_seed(&self) -> [u8; 32] {
        self.signing.to_seed()
    }

    /// The Noise static, for wrapping.
    pub fn noise_bytes(&self) -> [u8; 32] {
        self.noise.to_bytes()
    }

    /// The correspondence key, for wrapping.
    pub fn correspondence_bytes(&self) -> [u8; 32] {
        self.correspondence.to_bytes()
    }

    /// This node's signing key, for the inner signature a `peer-request`
    /// carries (RFC 3 §5.1).
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    /// This node's correspondence key, for sealing.
    pub fn correspondence(&self) -> &SecretKey {
        &self.correspondence
    }

    /// Static-static agreement with a correspondent, for tag derivation.
    ///
    /// `None` if their key is low-order — `CRYPTO-REVIEW.md` §3. A caller that
    /// treated that as "use zeros" would derive a tag the attacker also knows.
    pub fn agree_with(
        &self,
        their_correspondence: &krab_crypto::dh::PublicKey,
    ) -> Option<krab_crypto::dh::Shared> {
        krab_crypto::dh::agree(&self.correspondence, their_correspondence)
    }

    /// Build this node's signed card — RFC 3 §11 step 1.
    pub fn card(&self, policy: Policy) -> Card {
        Card::create(
            &self.signing,
            self.noise.public().0,
            self.correspondence.public().0,
            policy,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use krab_crypto::rng::NotRandom;

    fn id(seed: u64) -> Identity {
        Identity::generate(&mut NotRandom::seeded(seed))
    }

    /// The three keypairs must be independent: deriving one from another would
    /// collapse RFC 2 §2's I-2 namespace separation.
    #[test]
    fn the_three_keys_are_independent() {
        let i = id(1);
        let card = i.card(Policy::default());
        assert_ne!(card.identity_pk, card.noise_static_pk);
        assert_ne!(card.identity_pk, card.correspondence_pk);
        assert_ne!(
            card.noise_static_pk, card.correspondence_pk,
            "a shared X25519 key would tie network location to tag namespace"
        );
    }

    #[test]
    fn a_generated_identity_produces_a_card_that_verifies() {
        let i = id(2);
        let card = i.card(Policy::default());
        assert!(card.verify());
        assert_eq!(card.node_id(), i.node_id());
        assert_eq!(card.fingerprint(), i.fingerprint());
    }

    /// RFC 7 §11 — 64 bytes, and they must be the two seeds that matter.
    #[test]
    fn the_backup_is_sixty_four_bytes_of_the_two_recoverable_secrets() {
        let i = id(3);
        let phrase = i.backup_phrase();
        assert_eq!(
            phrase.split_whitespace().count(),
            64,
            "RFC 7 §11 — 64 bytes"
        );

        let bytes = krab_crypto::words::parse(&phrase).unwrap();
        assert_eq!(&bytes[..32], &i.signing.to_seed(), "identity seed");
        assert_eq!(
            &bytes[32..],
            &i.correspondence.to_bytes(),
            "correspondence seed"
        );
        // The Noise static is a link key and is deliberately absent.
        assert_ne!(&bytes[32..], &i.noise.to_bytes());
    }

    /// A backup that restored the identity but not the correspondence key
    /// would address nobody — the failure the module documentation describes.
    #[test]
    fn the_backup_restores_tag_derivation_not_just_the_name() {
        let i = id(4);
        let bytes = krab_crypto::words::parse(&i.backup_phrase()).unwrap();

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[..32]);
        let mut corr = [0u8; 32];
        corr.copy_from_slice(&bytes[32..]);

        let restored_signing = SigningKey::from_seed(&seed);
        let restored_corr = SecretKey::from_bytes(corr);
        assert_eq!(restored_signing.node_id(), i.node_id(), "same identity");
        assert_eq!(
            restored_corr.public(),
            i.correspondence.public(),
            "and the same tags with every existing peer"
        );
    }

    #[test]
    fn distinct_identities_have_distinct_fingerprints() {
        assert_ne!(id(5).fingerprint(), id(6).fingerprint());
        assert_eq!(id(5).fingerprint().split_whitespace().count(), 8);
    }

    #[test]
    fn the_kek_derives_from_the_stored_parameters() {
        let mut rng = NotRandom::seeded(7);
        let mut i = Identity::generate(&mut rng);
        i.kek_params.m_kib = 64;
        i.kek_params.t = 1;
        i.kek_params.p = 1;
        assert!(i.kek(b"passphrase").is_ok());
    }

    #[test]
    fn an_identity_prints_only_its_identifier() {
        let i = id(8);
        let s = format!("{i:?}");
        assert!(s.starts_with("Identity(") && s.len() < 32, "{s}");
    }

    /// The backup phrase is derived, not stored: asking twice yields the same
    /// words, and no buffer is retained between calls.
    #[test]
    fn the_backup_phrase_is_reproducible_and_unretained() {
        let i = id(9);
        assert_eq!(i.backup_phrase(), i.backup_phrase());
    }
}
