# Krab — Cryptographic Composition Review

    Subject:  RFC 1, RFC 2, RFC 4 §4/§8, RFC 7 — the composition, not the primitives
    Scope:    specification review against the documents as written
    Status:   NOT a substitute for external professional review

---

## 0. What this is, and what it is not

RFC 0 §9 requires external cryptographic review before release, and RFC 1 §13
states the reason precisely: the primitives are standard and well-reviewed;
the *arrangement* of them is novel, and arrangement is where subtle breaks
live. That requirement should stand. This document does not discharge it.

**What this review is.** One reviewer reading the specifications for
composition errors: key reuse, domain separation, malleability, primitive
misuse, and mismatches between a stated security property and the mechanism
said to provide it.

**What it is not.** No formal analysis, no proofs, no symbolic model, no
implementation review, no side-channel analysis, and no cryptanalysis of any
primitive. A single reviewer without tooling finds a different and smaller
class of problem than a funded review by people who do this professionally.

**How to read the severities.** *Critical* means the specification as written
admits a construction that breaks confidentiality or integrity. *High* means a
concrete attack exists against a stated property. *Medium* means a deviation
from a standard's explicit requirement with no known attack. Anything I could
not decide is listed in §9 rather than guessed at.

Findings 1 and 2 should be resolved regardless of what external review later
concludes.

---

## 1. CRITICAL — the reservoir derives one message key per epoch, not per message

> **Implementation status, 2026-08-07.** §1.2's recommended construction is
> implemented in `crates/krab-crypto/src/seal.rs` and the defective derivation
> is not. There is no `message_key` function anywhere in `krab-crypto`, so the
> defect cannot be reached by calling the wrong thing.
>
> **The finding remains open against RFC 7 §6**, which still specifies the
> defective derivation. Drop-in replacement text is in
> `Documentation/RFC-7-section-6-proposed.md`, which closes this finding and
> `RFC-7-review.md` §§10–11 in one edit — all three land in §6. Until §6 is amended, an implementation following it
> literally and this one will not interoperate. That is the safer direction:
> §6 as written reuses one key for every message a pair exchanges in a day.
>
> Demonstrated by `two_messages_in_one_epoch_do_not_share_a_key`, which holds
> constant everything §6's derivation takes as input — same chunk, same tag,
> same epoch, same plaintext — and shows the ciphertexts differ.

RFC 7 §6:

```
reservoir → chunk_N  (32 bytes, one per epoch)
            msg_key = HKDF(chunk_N, "krab/msg/v1" ‖ tag)
```

RFC 7 §6.1 justifies the absence of a counter:

> "No offsets, no counters, no consumption state. The tag is already in the
> envelope, already unlinkable, **already unique per message**."
> "**Two-time-pad reuse is structurally impossible**, not merely prevented."

**The tag is not unique per message.** RFC 1 §6.2 derives it as
`tag_e = HKDF-Expand(S, "krab/tag/v1" ‖ u32_le(epoch), 8)` where `S` is the
static-static X25519 shared secret — constant per pair. The only varying input
is the epoch. RFC 2 §4.3 confirms the consequence from the receiving side: the
precomputation table holds `correspondents × (2W+1)` entries, i.e. **exactly
one tag per correspondent per epoch**.

It has to be that way. A per-message tag could not be precomputed, and
precomputation is what makes recognition-before-decryption work.

Therefore, for a fixed pair in a fixed epoch, `chunk_N` is constant and `tag`
is constant, so **`msg_key` is constant across every message that pair
exchanges that day.**

If `msg_key` keys ChaCha20-Poly1305 with a fixed or implicit nonce, the
consequences are the textbook ones:

- two ciphertexts XOR to the XOR of their plaintexts — confidentiality gone
  for all reservoir-protected traffic between that pair, that epoch
- Poly1305's one-time key is reused, which yields the authentication key and
  therefore **arbitrary forgery** under that `msg_key`

The claim in §6.1 is not merely unsupported; the mechanism it describes
guarantees the condition it says is impossible.

### 1.1 The specification admits a safe reading, and does not require it

RFC 7 §5 lists the reservoir as a forward-secrecy tier "where a reservoir
exists," and RFC 1 §6.5 makes it the primary post-quantum strategy. Neither
says whether a reservoir-protected object *replaces* HPKE or *feeds* it. Under
the replacing reading, §1 above is a complete break. Under a feeding reading —
`chunk_N` supplied as an HPKE PSK — HPKE's per-message ephemeral `skE` enters
the key schedule and there is no reuse.

An ambiguity that admits a catastrophic reading is itself the defect.

### 1.2 Recommended construction

Use **HPKE `mode_auth_psk`** (RFC 9180 §5.1.4) with `chunk_N` as the PSK and
the tag's epoch as `psk_id`:

```
mode_auth_psk:
  shared_secret = KDF( DH(skE, pkR) ‖ DH(skS, pkR) )
  key_schedule( shared_secret, info, psk = chunk_N, psk_id = epoch )
```

This is the construction the design already wants and does not name:

- **per-message keys** — `skE` is fresh, so §1's reuse cannot arise
- **post-quantum** — a quantum adversary who breaks both DH values still
  faces the PSK, which is exactly RFC 1 §6.5's goal at RFC 1 §6.5's cost
  (zero per-message bytes)
- **forward secrecy at epoch granularity** — destroying `chunk_N` destroys the
  key schedule, which is RFC 7 §3's mechanism unchanged
- **deniability preserved** — `mode_auth` semantics are retained
- **no format change** — RFC 1 §4.2 key 2 is the suite identifier and RFC 1
  §6.1 reserves the suite space; a `mode_auth_psk` suite is a new value, not a
  new field. RFC 1 stays frozen.

If instead the reservoir is meant to stand alone, then a per-message nonce is
mandatory and must be carried in the envelope. RFC 1 §4.2 key 4 holds the HPKE
encapsulation, which a reservoir-only object does not need — so the frozen
format can carry a 32-byte random nonce there without modification. This works
but is strictly worse than `mode_auth_psk`, because it discards the ephemeral
DH and with it any protection if a chunk leaks.

**Either way, RFC 7 §6.1's "unique per message" sentence must be deleted, and
the reason the construction is safe must be stated as the ephemeral or the
nonce — never as the tag.**

---

## 2. HIGH — Ed25519 malleability defeats duplicate suppression

RFC 0 I-1 makes duplicate suppression, loop suppression, and replay resistance
all follow from content addressing, and RFC 1 §4 makes the identifier cover the
whole object.

Ed25519 signatures are malleable in the standard encoding: given a valid
`(R, S)`, the value `S + L` (and, in most encodings, several non-canonical
point encodings of `R`) verifies under a naive verifier. RFC 8032 §5.1.7
requires `S < L`; many library defaults do not enforce it, and RFC 1 does not
require it.

Applied to a `bulletin` (RFC 1 §5.2), whose signature sits in body key 3:

1. take any valid bulletin — a channel post, a prekey batch, a rollcall entry
2. malleate the signature
3. the object is byte-different, so its identifier differs
4. it verifies, so every node accepts and stores it
5. duplicate suppression does not fire, because the identifiers differ

**This is unbounded amplification from a single valid signature**, against a
corpus every node replicates for the full TTL, with no decryption required and
no key material needed. Quota (RFC 3 §6) bounds the rate but not the ratio: an
adversary spends one object of quota and the network stores many.

It also silently breaks RFC 6 §3.1's "a channel is a key" model — a subscriber
sees several distinct valid posts where the author made one.

**Fix.** RFC 1 §11 must add a validation step:

```
Ed25519 verification MUST be strict:
  S MUST be canonical (S < L); non-canonical S MUST be rejected.
  R and A MUST be canonical point encodings; non-canonical encodings MUST be rejected.
  Small-order A MUST be rejected.
```

This is `ed25519-dalek`'s `verify_strict` and equivalents elsewhere. It is a
validation rule, not an encoding change, so RFC 1 remains frozen — the same
argument RFC 7 §13 used for its erratum.

The same rule applies to `peer-link` signatures (RFC 3 §3), which reach the
corpus inside nodelist fragments.

---

## 3. HIGH — raw X25519 output is used as an HKDF PRK, and low-order points are unchecked

RFC 1 §6.2:

```
S      = X25519(sk_sender, pk_recipient)
tag_e  = HKDF-Expand(S, "krab/tag/v1" ‖ u32_le(epoch), 8)
```

Two problems.

**HKDF-Extract is skipped.** RFC 5869 §3.3 requires Extract when the input
keying material is not uniformly random, and RFC 7748 §6.1 states that the
X25519 output must be passed through a KDF before use. A curve point's
x-coordinate is not a uniform 256-bit string. Feeding it directly as an
HMAC key is precisely what Extract exists to prevent. There is no known attack
on HMAC-SHA256 with a structured key, so this is a standards deviation rather
than a break — but it is the kind of deviation that external review exists to
catch, and the fix costs one HMAC call:

```
PRK   = HKDF-Extract(salt = "krab/tag/v1", IKM = S)
tag_e = HKDF-Expand(PRK, u32_le(epoch), 8)
```

**Low-order points are not rejected.** RFC 7748 §6.1 permits an all-zero
output check; RFC 9180 mandates it inside HPKE. Krab's tag derivation calls
X25519 *outside* HPKE, so the check must be mandated separately, and RFC 1 does
not mandate it.

The concrete attack is on credential exchange. If a peer supplies a low-order
point as its `kx_pk` in a `peer-link` (RFC 3 §3), then `S = 0` for every
counterparty, and **every sender derives the same, publicly computable tag** to
that peer. Tag unlinkability is gone for that relationship, and an observer can
enumerate all traffic to it. RFC 3 §11's ceremony compares fingerprints, which
does not validate curve membership or order.

**Fix.** RFC 3 credential validation MUST reject `kx_pk` values that are
low-order or otherwise invalid X25519 public keys, and RFC 1 §6.2 MUST require
aborting if the X25519 output is all-zero.

---

## 4. HIGH — padding content is unspecified, and it is inside the identifier

RFC 1 §3 pads to a size bucket *before* the identifier is computed, and §4
makes the identifier cover the whole object. RFC 1 §8 never says what the
padding bytes contain.

Two implementations that pad with zeros and with random bytes produce
**different identifiers for identical plaintext**. The corpus fractures along
implementation lines: duplicate suppression fails, reconciliation never
converges on the difference, and there is no way to repair it afterwards
because RFC 1 is frozen.

This is the same defect class as the `admission` key ambiguity in
`RFC-1-review.md` §3, and it has the same one-sentence fix. **Padding MUST be
zero bytes.**

A secondary consideration argues the same way: random padding is
indistinguishable from ciphertext to an observer, but it is also unauthenticated
by the AEAD — it sits outside the AAD (RFC 1 §6.1 covers header and body-minus-
ciphertext) and is protected only by the identifier. Zero padding makes the
invariant checkable on ingest.

---

## 5. MEDIUM — `short` has no counter-exhaustion rule

RFC 4 §8:

```
[1B ver<<4|class][4B tag][3B expiry_h][2B ctr][N body][8B truncated MAC]
nonce from (link_id, ctr)
```

`ctr` is 16 bits: 65 536 values. The key comes from the pairwise reservoir.
RFC 4 §8 does not say what happens when `ctr` wraps.

If the key is a reservoir chunk and chunks rotate per epoch, wrap requires
65 536 `short` messages in one day on one link — implausible at SIM-0's
2 messages/day, but not impossible for automated traffic, and "implausible" is
not a security argument. On wrap with an unchanged key, the nonce repeats and
the stream cipher's keystream repeats.

**Fix.** State it: a node MUST refuse to emit a `short` message when `ctr`
would wrap within the current key's lifetime, and MUST rekey instead.

Separately, the 8-byte truncated Poly1305 tag deserves a note. Truncated
Poly1305 has no standard security analysis, unlike truncated HMAC (RFC 2104
§5). 2⁻⁶⁴ per forgery attempt on a pairwise authenticated low-volume link is
defensible, and RFC 4 §8 says so — but "defensible by argument" and "covered
by an analysis" are different, and this is worth putting in front of external
review explicitly rather than leaving as a citation.

---

## 6. MEDIUM — the inbox tag misuses HKDF-Expand

RFC 1 §6.2 and RFC 2 §4.2:

```
inbox_e = HKDF-Expand(pk_recipient, "krab/inbox/v1" ‖ u32_le(epoch), 8)
```

`HKDF-Expand`'s first argument is a pseudorandom key. Here it is a public
X25519 key — non-secret and non-uniform. The output is publicly computable,
which is intended (RFC 2 §4.2 says so plainly), so nothing is broken.

The objection is that the construction *reads* as a KDF over secret material.
An implementer or reviewer encountering `HKDF-Expand(key, ...)` reasonably
assumes the output is secret, and here it is the opposite. A plain hash states
the intent:

```
inbox_e = BLAKE3("krab/inbox/v1" ‖ pk_recipient ‖ u32_le(epoch))[0..8]
```

Same properties, same cost, and no implied secrecy. Krab already uses BLAKE3
for identifiers and node identifiers, so this removes a primitive from the
inbox path rather than adding one.

---

## 7. MEDIUM — only inbox tags are rate-capped, but pairwise tags are floodable too

RFC 1 §6.4, RFC 2 §7.4 and RFC 7 §13.3 all cap **inbox-tagged** decapsulation
attempts. The reasoning is that inbox mode has no sender to index by and
therefore needs exhaustive search.

But the flooding attack does not depend on exhaustive search. An adversary who
*observes* a pairwise tag — which is public, in the frozen header, for the
whole epoch (§1) — can mint unlimited objects bearing it. Each is a distinct
object with a distinct identifier, so RFC 2 §7.4's failed-`(id, epoch)` cache
never hits. Each costs the recipient a decapsulation against every live prekey
batch: three, per RFC 7 §5.5.

At RFC 7 §5.5's 100 µs, that is 0.3 ms per object — cheaper than the inbox
case, but unbounded rather than capped, and the objects also consume storage
for the full TTL.

Quota (RFC 3 §6) is the real bound and it is adequate. The finding is that the
documents cap the *cheaper* case and leave the *common* one to a mechanism
they do not cross-reference. **RFC 2 §7.4 should cap tag-matched decapsulation
generally, not inbox-tagged specifically**, and should say that quota is the
outer bound.

---

## 8. Observations, not findings

**Domain string reused at two levels.** RFC 6 §3.1 sets
`channel_id = BLAKE3("krab/chan/v1" ‖ ed25519_pk)`, and RFC 1 §5.2 sets the
bulletin tag to `BLAKE3("krab/chan/v1" ‖ channel_id)[0..8]` — the same label at
both levels. Not exploitable, since the inputs differ in length and type, but
distinct labels cost nothing and the convention elsewhere in Krab is one label
per purpose.

**Reservoir XOR establishment is order-sensitive.** RFC 7 §6.2 says
`reservoir = R_A ⊕ R_B` means "a backdoored or broken RNG on one end does not
compromise it." That holds for the stated threat — a broken RNG — in either
position. It does not hold against a *malicious* party who goes second, who
can choose `R_B = R_A ⊕ desired` and fix the result entirely. Since a malicious
counterparty already knows the shared reservoir, the practical impact is
small; the claim should nonetheless be narrowed to the RNG threat it actually
covers, or a commit-then-reveal added.

**The negotiation chain is retained non-repudiable graph evidence.** RFC 3
§5.1 uses `mode_base` with an inner Ed25519 signature, so a `peer-request` is a
signed, non-repudiable statement that a specific node sought contact. RFC 3
§5.3 requires both parties to *retain the full chain* as local evidence, which
deliberately exempts it from RFC 7's crypto-shredding. RFC 3 §8.4 purges it on
termination, which is right — but for the life of the relationship each party
holds cryptographic proof of the other's approach. That is a coherent choice
and it sits in tension with RFC 3 §15's own observation that credentials at
rest are "worse than an address book." Worth stating in RFC 3 §15 rather than
leaving to be discovered.

**Argon2id parameters versus the weakest device.** RFC 7 §4.1 fixes
m=64 MiB, t=3, p=4 *and* says implementations SHOULD calibrate to ~500 ms on
target hardware. Those instructions conflict. Since RFC 7 §7 puts constrained
nodes in the relay role — no decryption keys, no passphrase — the fixed
parameters are probably right and the calibration sentence is the one to
remove.

---

## 9. What I could not determine

Listed rather than guessed:

- **Whether the reservoir replaces or feeds HPKE** (§1.1). The specification
  does not say, and the answer changes §1 from critical to non-existent.
- **Whether `msg_key` is used with an explicit nonce.** RFC 7 §6 shows none.
  If an implementation supplies one from somewhere unstated, §1 changes.
- **Whether the AEAD nonce for reservoir-sealed objects is specified anywhere.**
  I did not find it in RFC 1, 2 or 7.
- **The `short` key derivation.** RFC 4 §8 says "keyed from the pairwise
  reservoir"; RFC 7 §6.4 says reservoir material never appears in the
  credential. The derivation path is not written down.
- **Whether prekey private keys are erased on epoch rollover or on batch
  retirement.** RFC 7 §5.2 says schedule-based deletion; RFC 7 §4 wraps them
  under epoch keys. Those imply different lifetimes.

---

## 10. Recommendation

Resolve findings 1 through 4 before any release, and independently of external
review — 1 and 4 because they are specification defects with known fixes that
cost nothing, 2 and 3 because they have concrete attacks against stated
properties.

Then obtain external review anyway. RFC 1 §13 is right that composition is
where subtle breaks live, and the findings above are the ones visible to a
careful reading. They are not evidence that no others exist; if anything, four
findings of this severity in a first pass argues the opposite.

The most useful thing that could be prepared for such a review is RFC 1 §12's
test vectors. A reviewer given executable vectors for tag derivation, the AAD
construction, both HPKE modes, and the reservoir path will find in an afternoon
what prose review does not surface at all — and §9's five undetermined items
would all have been answered by a vector.
