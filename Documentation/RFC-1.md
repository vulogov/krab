# RFC 1 — Object Format and Cryptography

    Number:      1
    Title:       Object Format and Cryptography
    Status:      Draft
    Repository:  https://github.com/vulogov/krab
    Author:      Vladimir Ulogov
    Requires:    RFC 0, SIM-0
    Grounded by: krab-sizes (reference encoder; all byte counts computed)

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be
interpreted as described in RFC 2119.

---

## 1. Scope and permanence

**This document cannot be revised.** Once objects exist in a corpus, their
identifiers are derived from the encoding specified here, and a change to
the encoding changes every identifier. Nodes go offline for months and
return by courier; there is never a flag day (RFC 0 §10.1).

Everything defined here is therefore frozen for the lifetime of the
protocol. Extension happens through the version field and the mechanism in
§10, never through revision.

Every byte count in this document was computed by the reference encoder in
`krab-sizes`, not estimated.

---

## 2. Parameter table

Normative constants. All are inside the identifier hash or determine an
interoperability boundary.

| parameter | value | rationale |
|---|---|---|
| `PROTO` | `"krab"` | domain-separation prefix; permanent |
| `VERSION` | `1` | |
| identifier | BLAKE3-256, 32 bytes | |
| truncated identifier | 12 bytes (96 bits) | manifests only, §9.3 |
| `EPOCH` | 86 400 s (1 day) | §6.2 |
| `EPOCH_WINDOW` | ±45 epochs | = `MAX_TTL` / `EPOCH`; §6.2 |
| `MAX_TTL` | 45 days | RFC 0 §8.2 requires ≥ 30 |
| `MAX_OBJECT` | 262 144 bytes | |
| size buckets | 256, 1K, 4K, 16K, 64K, 256K | §8 |
| default shard `k` | 0 bits | §5.4 |
| clock skew tolerance | ±6 h | §7.4 |
| HPKE suite (v1) | `0x0001` | §6.1 |

---

## 3. Layering

```
plaintext
  → [compress]                       optional, BEFORE encryption
  → inner CBOR
  → HPKE seal, AAD = header ‖ body-without-ciphertext
  → assemble: ROUTING_HEADER ‖ BODY
  → pad to size bucket
  ────────────── id = BLAKE3(domain ‖ object) ──────────────
  ────────────── object is now immutable ───────────────────
  → [FEC]                            per-link, outside the identifier
  → [armor]                          per-link, outside the identifier
  → link frame                       RFC 4
```

**Forward error correction and armor MUST NOT participate in the object
identifier.** They are properties of a link. This is what allows a gateway
to transcode between an IP link and a LoRa link without fracturing the
corpus, and it is the invariant most likely to be broken by a later
optimisation.

**Compression MUST precede encryption and padding.** Compressing ciphertext
achieves nothing; leaking compressed length through observable size builds
a CRIME-style oracle. Padding to buckets bounds that leak to bucket
granularity but does not eliminate it — see §8.2.

---

## 4. Object

```
OBJECT = ROUTING_HEADER (16 bytes, fixed) ‖ BODY (deterministic CBOR)
```

```
id = BLAKE3-256( "krab/obj/v1" ‖ OBJECT )
```

The identifier covers the entire object including the routing header.
An object with any byte altered is a different object.

### 4.1 Routing header (frozen forever)

Fixed-width binary, little-endian. **Every version of Krab, for the
lifetime of the protocol, MUST be able to parse these 16 bytes.**

```
offset  size  field         notes
     0     1  ver           protocol version; 1 in this document
     1     1  class         §5
     2     1  size_bucket   index into §8; 0..5
     3     1  flags         bit0 link_local, bit1 no_relay, bits2-7 reserved MBZ
     4     4  expiry_min    absolute, minutes since Unix epoch (u32 LE)
     8     8  tag           destination tag (§6.2)
    16
```

A fixed binary struct rather than the first few CBOR keys: "parseable
forever" is a guarantee about bytes, and it is far easier to make about a
struct than about a map whose encoding rules might themselves be extended.

`expiry_min` at minute granularity in a `u32` runs to the year 10136.

Everything a relay needs is here: route (`tag`), filter (`class`,
`size_bucket`, `flags`), expire (`expiry_min`), validate (`ver`).
Per RFC 0 I-3, nothing else may be added.

### 4.2 Body

Deterministic CBOR map, integer keys, for `sealed` and `cover` classes:

| key | type | field |
|---|---|---|
| 0 | uint | tag epoch |
| 1 | uint | tag mode: 0 pairwise, 1 inbox |
| 2 | uint | HPKE suite identifier |
| 3 | bstr | admission — reserved, empty in v1 |
| 4 | bstr | HPKE encapsulated key |
| 5 | bstr | ciphertext ‖ AEAD tag |

Key 3 is reserved because RFC 0 removes proof-of-work as unnecessary under
friend-to-friend peering — but it is inside the identifier hash, so a rate
token could never be added later. Deployments accepting traffic from
low-trust peers may want one.

**The HPKE suite is public and this is unavoidable.** A recipient cannot
decapsulate without knowing the suite. Suite diversity is therefore a
fingerprint, and deployments SHOULD converge on a single suite.

### 4.3 Deterministic encoding

RFC 8949 §4.2.1 core deterministic encoding, plus:

1. Integers in shortest form.
2. Definite lengths only. Indefinite-length items MUST be rejected.
3. Map keys are unsigned integers, ascending, no duplicates.
4. **No floating-point values anywhere.** NaN and negative-zero
   canonicalisation is a defect source and Krab has no need for floats.
5. No tags, no `undefined`, no `simple` values other than `false`/`true`.

**Unknown keys in a body of a known version MUST be rejected.** An object
that cannot be fully validated must not enter the store; anything else is
a malleability surface, since the identifier covers bytes the receiver did
not understand.

Unknown keys in the *inner plaintext* MUST be ignored. That is the entire
forward-compatibility budget, and it is safe because inner content does
not affect identity.

---

## 5. Classes

| id | class | sealed | signed | relayed | notes |
|---|---|---|---|---|---|
| 0 | `sealed` | yes | inner (deniable) | yes | the normal message |
| 1 | `bulletin` | **no** | outer (non-repudiable) | yes | channels, prekey batches, rollcall |
| 2 | `cover` | yes | — | yes | Poisson dummies |
| 3 | `short` | pairwise | MAC | **never** | §5.5; not a corpus object |

Four classes, deliberately. `class` sits in the frozen header, so the
enumeration is permanent and additions are expensive.

`presence` and `nodelist` are **not** classes. They are `sealed` objects
with `link_local` set and a specific inner content type. Adding classes
for them would spend permanent header space on what is a payload
distinction.

### 5.1 `sealed`

§6. Recipient determined by tag, content by HPKE, authentication deniable
by default.

### 5.2 `bulletin`

Public, signed, not encrypted — the point is third-party verifiability.
Body differs:

| key | type | field |
|---|---|---|
| 0 | bstr | signer Ed25519 public key (32) |
| 1 | bstr | payload |
| 2 | tstr | content type |
| 3 | bstr | Ed25519 signature (64) over `"krab/bul/v1" ‖ header ‖ body-without-key-3` |

`tag` for a bulletin is the leading 8 bytes of `BLAKE3("krab/chan/v1" ‖
channel_id)` — stable, public, and by design linkable, since a channel is
a public feed. **This is the one place where a tag is not unlinkable**, and
it is why RFC 0 I-2's namespace separation matters: a bulletin tag must
never be confused with a `sealed` tag.

Bulletins carry a real risk of unbounded corpus growth (RFC 0 §6, RFC 6).
Nodes MUST support excluding class 1 entirely via `class_mask`.

### 5.3 `cover`

Poisson-emitted dummies. Body is a `sealed` body whose ciphertext is
indistinguishable random bytes. Tag is drawn uniformly at random.

Cover objects MUST be indistinguishable from `sealed` objects to any party
other than the emitter — which means they MUST use class 0, not class 2.

*Class 2 is therefore reserved and unused in v1.* It exists in the
enumeration only so that no future version assigns it a meaning that would
make cover traffic distinguishable. Emitters track their own cover objects
locally.

### 5.4 Shard

`shard = leading k bits of tag`. `k` is a **link** parameter, not an object
property, so it appears nowhere in the object. Default 0.

SIM-0 (RFC 0 §8.3) shows ingress grows linearly with network size at
~0.063 MB/day per node per node, making sharding mandatory above roughly
n = 5 000. Since the shard derives from the tag, which is already in the
frozen header, **no header change is needed to enable sharding later.**
This was the reason for placing the tag in the header rather than the body.

### 5.5 `short` — not a corpus object

At a 55-byte ceiling there is no room for a 32-byte KEM encapsulation.
That is arithmetic, not a design choice, so `short` uses the pairwise key
already established in the peer credential.

The consequence is that it is **link-local by construction**: it cannot be
relayed, has no identifier, does not enter the corpus, and does not
participate in reconciliation. It is a transport-level message. Framing is
specified in RFC 4.

```
[1B ver<<4|class][4B tag][3B expiry_h][2B ctr][N body][8B truncated MAC]
= 18 + N bytes;  N ≤ 37 at a 55-byte ceiling
```

Nonce derives from `(link_id, ctr)`. A 64-bit truncated MAC is defensible
only because the link is pairwise, mutually authenticated, and low-volume;
this MUST be restated in the security considerations of any implementation.

Corpus objects still cross LoRa links, via fragmentation (§8.3). `short`
is an optimisation for neighbour-to-neighbour traffic, not the mechanism
by which LoRa participates in the network.

---

## 6. Cryptography

### 6.1 Suites

| id | KEM | KDF | AEAD | status |
|---|---|---|---|---|
| `0x0001` | DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | ChaCha20-Poly1305 | v1, mandatory |
| `0x0002` | X25519 + ML-KEM-768 hybrid | HKDF-SHA256 | ChaCha20-Poly1305 | reserved, §6.5 |

HPKE per RFC 9180.

```
info = "krab/v1/" ‖ class
aad  = ROUTING_HEADER ‖ deterministic_cbor(body with key 5 omitted)
```

The AAD binds expiry, tag, class, epoch, and suite. A relay that mutates
the expiry to force indefinite storage produces something undecryptable —
and since expiry is also inside the identifier, the object is also no
longer the object it claims to be. Tampering is doubly dead.

### 6.2 Modes and tag derivation

Tag mode determines HPKE mode. This coupling is normative:

| tag mode | recipient knows sender | HPKE mode | authentication |
|---|---|---|---|
| 0 pairwise | yes | `mode_auth` | deniable |
| 1 inbox | no | `mode_base` | inner Ed25519 signature |

`mode_auth` folds the sender's static key into the KEM, so the recipient —
and only the recipient — can verify origin. A third party holding the
ciphertext and both public keys learns nothing. It also saves the 64 bytes
an inner signature would cost.

`mode_auth` is impossible for first contact because decapsulation requires
the sender's static public key as an input, which the recipient does not
have. First contact therefore uses `mode_base` with the sender's identity
and signature inside the plaintext. This is a reasonable place for the
deniability boundary: a first-contact message is the one you are most
likely to want to be able to prove later.

**Pairwise tag:**
```
S      = X25519(sk_sender, pk_recipient)          static-static, stable per pair
tag_e  = HKDF-Expand(S, "krab/tag/v1" ‖ u32(epoch), 8)
```

Unlinkable across epochs and across senders. The recipient precomputes
`correspondents × EPOCH_WINDOW` tags into a lookup table — for 50
correspondents and a ±45 window, 4 550 entries.

**Inbox tag:**
```
inbox_e = HKDF-Expand(pk_recipient, "krab/inbox/v1" ‖ u32(epoch), 8)
```

Computable by anyone holding the recipient's public key, so messages to it
are linkable *within* an epoch. It rotates out. This is a real and bounded
cost, accepted because first contact is inherently less private than
established correspondence, and because hiding the tradeoff would be
worse than stating it.

`EPOCH` is 86 400 s.

**`EPOCH_WINDOW` MUST be at least `MAX_TTL / EPOCH`, and is therefore ±45.**

The bound is `MAX_TTL`, not observed latency. An object may be delivered at
any point inside the TTL this document declares valid, so it may arrive up to
45 epochs after the epoch its tag was derived from. A recipient whose window
is narrower simply never computed that tag: §11 accepts the object, the store
keeps it, and it is undecryptable. Nothing surfaces this, because RFC 0 §6
makes delivery failure silent by design.

An earlier draft of this section derived the window from measured delivery
latency — SIM-0's p99 of 382 hours (16 days) under austere transport — and set
±30 with ±45 advised for courier-dominated deployments. That was wrong twice
over. A p99 is not a bound; SIM-0's own 45-day-TTL austere run puts p99 at
441.9 hours with a tail beyond it. And the deployments that need the widest
window are precisely the ones whose nodes are offline for the periods it must
cover, so making the correct value the non-default was the wrong way round.

The cost of the correct value is negligible and is the reason there is no
tradeoff to weigh: 50 correspondents at ±30 is 3 050 precomputed tags, at ±45
it is 4 550. One-off HKDF work on a table that is already being built.

`EPOCH_WINDOW` is the one row of §2 that is not inside the identifier hash, so
unlike the rest of this document it constrains implementations rather than
identity. A deployment MAY widen it. It MUST NOT narrow it below
`MAX_TTL / EPOCH`.

### 6.3 Key selection carries no hint

**The envelope MUST NOT indicate which recipient key was used.** Prekeys
are published as signed `bulletin` objects, so a prekey identifier would
be a direct pointer into a public document naming the recipient — undoing
the tag scheme entirely. Tier, rotation epoch, and exhaustion state leak
similarly and are equally forbidden.

Selection is two-stage. The tag performs gross selection publicly and
unlinkably, narrowing the candidate set from the corpus to the objects
actually addressed to this recipient. Key selection then happens with
information only the recipient has:

- **Baseline:** constant-time trial decapsulation across all outstanding
  private keys. Implementations MUST attempt the full set and MUST NOT
  stop at first success; early exit leaks index position, which correlates
  with prekey consumption and is a volume signal.
- **Optimisation:** senders SHOULD select prekey index
  `i = H("krab/pkidx/v1" ‖ sender_id ‖ batch_id) mod N`. The recipient,
  who knows the sender from the matched tag, computes the same `i`. This
  is not available in inbox mode.

### 6.4 Denial of service on trial decapsulation

An adversary who learns a current tag can flood objects bearing it,
forcing full constant-time trial decapsulation at roughly 10 ms per object
for zero cost. Implementations MUST cache failed `(id, epoch)` pairs so a
replayed object costs one lookup, and SHOULD cap decapsulation attempts
per epoch per peer. A high tag-match / low decrypt-success ratio is an
unambiguous signal and SHOULD feed quota reduction (RFC 3).

### 6.5 Post-quantum: measured, not assumed

The corpus is public, archived by every node, and nothing compels an
adversarial relay to evict (RFC 0 §7.6). It is a textbook
harvest-now-decrypt-later target.

The naive answer — hybrid KEM per message — costs more than expected:

| | classical `0x0001` | hybrid `0x0002` |
|---|---|---|
| floor for a sealed object | 150 B | **1 239 B** |
| padded bucket | 256 B | **4 096 B** |
| a 280-byte message | 448 B → 1 KB bucket | 1 537 B → **4 KB bucket** |
| LoRa airtime, one small message | ~5 min | **~1.3 h** |

This is not "+1.1 KB per message". For short traffic it is a **16× corpus
inflation** and it makes LoRa links effectively unusable.

**Therefore the epoch-chunked key reservoir (RFC 7) is Krab's primary
post-quantum strategy, not a secondary one.**

> **⚠ Dependency notice.** RFC 7 §6's reservoir key derivation carries an open
> critical defect — it derives one message key per (pair, epoch) rather than
> per message. This section's post-quantum claim depends on that mechanism, so
> the claim is **contingent until RFC 7 §6 is fixed.** The recommended fix
> (HPKE `mode_auth_psk` with the chunk as PSK) requires no change to this
> document: RFC 1 §6.1's suite space accommodates it and RFC 1 remains frozen.
> See `CRYPTO-REVIEW.md` §1. A reservoir established
once — by physical exchange or by a single hybrid KEM — yields
post-quantum security at *zero* per-message overhead, because message keys
derive symmetrically from reservoir material.

Suite `0x0002` therefore exists for correspondents with no reservoir. It
MUST be selectable per message, MUST NOT be a deployment-wide default, and
SHOULD NOT be used on constrained links.

---

## 7. Inner plaintext

Deterministic CBOR map:

| key | type | field | notes |
|---|---|---|---|
| 0 | uint | inner version | |
| 1 | tstr | full recipient address | `<key>=<value>;` form |
| 2 | bstr | sender X25519 public key (32) | reply material; MAY be omitted, §7.2 |
| 3 | uint | sender's current epoch base | |
| 4 | uint | created, minutes since Unix epoch | |
| 5 | tstr | content type | |
| 6 | bstr | body | |
| 7 | bstr | Ed25519 signature (64) | **only** in `mode_base` |
| 8 | bstr | sender node identifier (32) | only in `mode_base` |
| 9 | map | group block | RFC 6 |

### 7.1 No SURBs are required

Keys 2 and 3 let the recipient derive the sender's tag directly, so a
reply is an ordinary object. Mixminion's hardest problem — anonymous
reply blocks — does not exist in a flood-delivery design. Krab is
genuinely simpler than the mixnet literature here, and the reason is worth
recording.

### 7.2 Address canonicalisation is low-stakes

The `<key>=<value>;` address lives entirely inside the ciphertext and
therefore does not participate in the identifier hash. It needs
canonicalisation rules for *matching and display*, not for cryptographic
agreement — a considerably lower bar than an envelope field would face.

In pairwise mode the recipient derived the tag from a specific
correspondent's key and therefore already holds key 2. Senders MAY omit
it, saving 34 bytes — which matters only in the 256-byte bucket, where it
raises usable body from 90 to 124 bytes (§8.1).

---

## 8. Size

### 8.1 Buckets

Objects are padded to the next bucket. Without this, size alone
fingerprints content type — a 180-byte object is a beacon, a 40 KB one a
picture.

| bucket | max body | padding overhead |
|---|---|---|
| 256 | 90 B | 64.8 % |
| 1 024 | 856 B | 16.4 % |
| 4 096 | 3 928 B | 4.1 % |
| 16 384 | 16 216 B | 1.0 % |
| 65 536 | 65 368 B | 0.3 % |
| 262 144 | 261 972 B | 0.1 % |

The floor for a sealed object is **150 bytes**, so the 256-byte bucket is
inefficient by construction. This is accepted: the alternative is a
smaller bucket that no object can occupy.

### 8.2 Padding bounds the compression oracle; it does not close it

A highly compressible message may land in a lower bucket than an
incompressible one of the same plaintext length. Padding reduces the leak
to bucket granularity. Traffic where this matters SHOULD pad to a fixed
bucket regardless of content, and `cover` traffic MUST match the bucket
distribution of real traffic or it is trivially separable.

### 8.3 LoRa

EU868 SF10 under a 1 % duty cycle, ~0.85 B/s sustained, 51-byte payload:

| bucket | frames | airtime |
|---|---|---|
| 256 | 6 | ~5 min |
| 1 024 | 21 | ~20 min |
| 4 096 | 81 | ~1.3 h |

Objects above the link's `max_object_size` are filtered **at the sender**
(RFC 4). Receiver-side rejection wastes the scarcest resource in the
system and creates invisible partitions.

---

## 9. Identifiers

### 9.1 Canonical

32-byte BLAKE3, as §4.

### 9.2 Display

First 8 bytes, base32 (Crockford), grouped in fours. Implementations MUST
show a fingerprint alongside any display name in list views — channel and
node identifiers are keys and cannot be spoofed, but display names are
attacker-controlled, and a Cyrillic homoglyph defeats the strongest
cryptographic guarantee in the system with a font.

### 9.3 Truncated, within a scoped range

Manifest entries carry `(expiry_min, id[0..12])` = 16 bytes.

| corpus | 8 B id | 12 B id | 16 B id | 32 B id |
|---|---|---|---|---|
| 10 000 | 0.1 MB | 0.2 MB | 0.2 MB | 0.4 MB |
| 100 000 | 1.2 MB | 1.6 MB | 2.0 MB | 3.6 MB |
| 500 000 | 6.0 MB | 8.0 MB | 10.0 MB | 18.0 MB |

12 bytes is normative. 8 bytes admits a 2³² birthday grind; 12 bytes
raises that to 2⁴⁸, and the consequence of a collision is bounded — one
object not transferred on one link, recoverable through another peer.

**Truncated identifiers are valid only inside a reconciliation range that
both parties have already agreed on.** They MUST NOT appear in a routing
header, a `WANT` outside a session, or any stored structure.

A manifest is proportional to the **filtered** set, not the corpus
(RFC 5). This is what makes manifest exchange survivable on LoRa: the
size gate that makes LoRa slow also makes its eligible set small. Whether
it is survivable in fact is the open question RFC 0 §9 assigns to SIM-1.

---

## 10. Forward compatibility

There is never a flag day. RFC 0 §10.1 is normative here:

- A relay encountering `ver` it does not know MUST route, filter, and
  expire from the 16-byte routing header alone, and MUST store and forward
  the remaining bytes opaquely. This is safe because the identifier covers
  the whole object; an unparsed object cannot be tampered with undetected.
- A recipient encountering an unknown `ver` reports that a newer client is
  required.
- Within a known `ver`, unknown body keys MUST be rejected (§4.3).
- Unknown *inner* keys MUST be ignored.
- Reserved header bits MUST be zero on emission and MUST be ignored on
  receipt.

Without opaque relay of unknown versions, the first protocol revision
partitions the network along version lines and the partition is permanent,
because the nodes that would bridge it are the ones offline for a month.

---

## 11. Validation on ingest

A receiver MUST reject an object unless all hold:

1. Length ≤ `MAX_OBJECT` and equal to the declared `size_bucket`.
2. `expiry_min` > now − skew, and ≤ now + `MAX_TTL` + skew.
3. `class` known for this `ver`; reserved flag bits zero.
4. Body parses as deterministic CBOR with no unknown keys (known `ver`).
5. Recomputed identifier matches the identifier it was offered under.
6. Not already present, and not in the expired-tombstone set.

Rejection MUST be silent to the peer beyond ordinary flow control, and
MUST be counted per peer as a quota signal (RFC 3).

Check 2 is what prevents a relay extending TTL to force indefinite
storage, and check 6 is what prevents expiry resurrection — a returning
courier node re-injecting objects the network already evicted.

---

## 12. Test vectors

RFC 1 MUST NOT reach Final without machine-checkable vectors covering, at
minimum: canonical encoding of each class; identifier derivation;
pairwise and inbox tag derivation across an epoch boundary; AAD
construction; `mode_auth` and `mode_base` seal/open; each padding bucket
boundary; and every rejection case in §11.

Two independent implementations MUST agree on every vector before the
status changes. For a format that cannot be revised, vectors are the
specification; the prose is commentary.

---

## 13. Security considerations

**Composition, not primitives, is the risk.** BLAKE3, X25519,
ChaCha20-Poly1305, HPKE, and Ed25519 are all standard and well-reviewed.
The tag derivation, the mode/tag-mode coupling, the AAD construction, and
the reservoir interaction in RFC 7 are novel *arrangements* of them. That
is exactly the category where subtle breaks live. External cryptographic
review is required before any release (RFC 0 §9).

**Deniability is a default, not a guarantee.** `mode_auth` gives deniable
authentication against a third party holding ciphertext and public keys.
It does not defend against a recipient who is compromised, coerced, or
lying, and it does not survive the sender's own device.

**Static-static ECDH for tags.** Pairwise tag derivation uses a stable
shared secret. Compromise of either long-term X25519 key retroactively
links every message between that pair — not their contents, which are
protected by prekeys and the reservoir, but the *fact and timing* of
correspondence, across the entire retained corpus. Recipients concerned
about this should rotate their kx key, accepting that it invalidates
precomputed tags on both sides.

**The 8-byte tag** admits accidental collision across a large corpus.
Consequence is a spurious trial decapsulation, not a disclosure. Adversarial
collision is cheap (2³²) and can be used to force decapsulation work; §6.4
is the mitigation.

**Coverage conditions the privacy claim.** RFC 0 §7.4. Nothing in this
document changes it.

---

## 14. References

- RFC 2119 — requirement keywords
- RFC 8949 §4.2.1 — deterministic CBOR encoding
- RFC 9180 — Hybrid Public Key Encryption
- RFC 7748 — X25519
- RFC 8032 — Ed25519
- RFC 8439 — ChaCha20-Poly1305
- FIPS 203 — ML-KEM
- BLAKE3 specification
- RFC 6330 — RaptorQ
- KRAB RFC 0 — Architecture and Threat Model
- KRAB SIM-0 — Corpus Convergence Measurements
- `krab-sizes` — reference encoder; source of every byte count here
