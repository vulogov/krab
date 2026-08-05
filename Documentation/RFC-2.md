# RFC 2 — Addressing and Tag Derivation

    Number:      2
    Title:       Addressing and Tag Derivation
    Status:      Draft
    Repository:  https://github.com/vulogov/krab
    Author:      Vladimir Ulogov
    Requires:    RFC 0, RFC 1
    Grounded by: krab-sizes/tags, krab-sizes/prekeys (all figures computed)
    Errata:      RFC 7 §5.3, RFC 6 §2.8 — see §8

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be
interpreted as described in RFC 2119.

---

## 1. Scope

RFC 1 fixes the wire encoding of the tag. This document specifies how tags
are derived, how a recipient recognises one, how the shard dial works, how
a sender selects a recipient key without saying so, and the operational
consequences of each.

Addressing in Krab is the mechanism that makes a public, fully replicated
corpus survivable. A relay must be able to route and filter an object
without learning anything about who it is for. Every design decision here
follows from that.

---

## 2. Namespace separation

**RFC 0 I-2, restated normatively because it is the invariant most easily
violated by a well-intentioned feature.**

Krab has two identifier namespaces and they are disjoint:

| namespace | derived from | stability | visibility |
|---|---|---|---|
| **node identifier** | `BLAKE3("krab/node/v1" ‖ ed25519_pk)` | permanent | public within the peer set |
| **destination tag** | per-epoch KDF output | rotates every epoch | public to everyone, unlinkable |

```
A node identifier MUST NOT appear in a tag position.
A destination tag MUST NOT appear in:
  - a presence beacon
  - a nodelist fragment
  - a rollcall entry
  - a routing or transport header outside the object envelope
  - any log line, metric label, or diagnostic output
```

The failure mode is concrete. A presence beacon carrying a destination tag
alongside a timestamp publishes an identifier, a time, and a network
location together — which is a tracking beacon, and it undoes the tag
scheme completely for the cost of one convenient field. Presence beacons
carry a node identifier, which is already known to the peers they are
scoped to (RFC 3 §8).

Channel tags (RFC 1 §5.2) are the single deliberate exception: stable,
public, and linkable by design, because a channel is a public feed. They
are distinguished by `class`, which is in the frozen routing header, so
they can never be confused with a `sealed` tag.

---

## 3. Address grammar

The full recipient address lives **inside the ciphertext** (RFC 1 §7) and
therefore does not participate in the object identifier. It needs
canonicalisation for matching and display, not for cryptographic
agreement — a considerably lower bar than an envelope field would face.

```
address    = attribute *( ";" attribute ) [ ";" ]
attribute  = key "=" value
key        = 1*32 ( %x61-7A / %x30-39 / "-" )      ; lowercase, digits, hyphen
value      = 1*128 VCHAR-except-";"-and-"="
```

Canonical form, for comparison and hashing:

1. Keys lowercased.
2. Attributes sorted by key, ascending byte order.
3. Duplicate keys: **reject the address.** Do not silently take the first
   or last; ambiguity in an address is a security defect.
4. No whitespace anywhere. Leading or trailing whitespace is a rejection,
   not something to trim.
5. Trailing `;` optional on the wire, present in canonical form.

The minimal address is `dst=<destination identifier>`.

**Unknown keys MUST be preserved and ignored**, not stripped. A recipient
may route internally on keys a sender's version did not define, and
stripping them destroys information the recipient needed.

A small registry of defined keys is frozen in this document. Additions
require a new RFC.

| key | meaning |
|---|---|
| `dst` | destination identifier at the recipient |
| `kind` | recipient-side routing hint |
| `grp` | group identifier, where the address is a group member |

The registry is deliberately short. The ancestor of this grammar is X.400
O/R addressing, whose unbounded attribute extensibility became unbounded
ambiguity. Krab keeps the mechanism and refuses the extensibility.

---

## 4. Tag derivation

A tag is **8 bytes** and appears in the frozen routing header. The
recipient must recognise it *before* decrypting, so it cannot depend on
any per-message ephemeral.

### 4.1 Pairwise — established correspondents

```
S      = X25519(sk_sender, pk_recipient)              static-static
tag_e  = HKDF-Expand(S, "krab/tag/v1" ‖ u32_le(epoch), 8)
```

Unlinkable across epochs and across senders. `S` is stable per pair, so
the ECDH is computed once and cached; only the HKDF pass repeats.

### 4.2 Inbox — first contact

```
inbox_e = HKDF-Expand(pk_recipient, "krab/inbox/v1" ‖ u32_le(epoch), 8)
```

Computable by anyone holding the recipient's public key, so messages to it
are linkable **within** an epoch. It rotates out.

This is a real cost, accepted rather than hidden. First contact is
inherently less private than established correspondence: the sender does
not yet have a relationship to protect, and pretending otherwise would
require machinery that buys nothing. Inbox mode is used for `peer-request`
(RFC 3 §5.1) and nothing else.

Inbox mode forces `mode_base` HPKE, because `mode_auth` decapsulation
requires the sender's static public key as an input and the recipient does
not have it. The coupling in RFC 1 §6.2 is therefore not a policy choice
but a consequence.

### 4.3 Recognition

The recipient precomputes a lookup table of `correspondents × (2W+1)`
tags, where `W` is the epoch acceptance window.

| correspondents | window | entries | table | ECDH (once) | HKDF (per rollover) |
|---|---|---|---|---|---|
| 25 | ±30 | 1 525 | 18 KB | 1.5 ms | 2.3 ms |
| 50 | ±30 | 3 050 | 37 KB | 3.0 ms | 4.6 ms |
| 50 | ±45 | 4 550 | 55 KB | 3.0 ms | 6.8 ms |
| 200 | ±30 | 12 200 | 146 KB | 12.0 ms | 18.3 ms |
| 500 | ±45 | 45 500 | 546 KB | 30.0 ms | 68.2 ms |

Recognition is a hash lookup. **Precomputation is not a constraint at any
plausible scale** — even 500 correspondents at a ±45 window is half a
megabyte and 68 ms to rebuild.

Table entries MUST be zeroized on drop and are covered by RFC 7 §9's
memory-locking requirement; the table is a map from tag to correspondent,
which is exactly the correlation the design exists to prevent.

### 4.4 False matches are negligible

A tag is 64 bits, so an unrelated object matches the table with
probability `corpus × entries / 2⁶⁴`:

| corpus | entries | P(≥1 false match) |
|---|---|---|
| 100 000 | 1 525 | 8.3 × 10⁻¹² |
| 500 000 | 1 525 | 4.1 × 10⁻¹¹ |
| 500 000 | 22 750 | 6.2 × 10⁻¹⁰ |

A false match costs one wasted decapsulation, not a disclosure.

**Adversarial collision is different and is cheap** — 2³² work for a
birthday collision in a 64-bit space, and an adversary who has simply
*observed* one of your tags needs no work at all. Both force decapsulation
work rather than revealing anything. §6 is the mitigation.

---

## 5. Epoch window

`EPOCH` is 86 400 s (RFC 1 §2). The acceptance window `W` must exceed
maximum delivery latency, or messages arrive after the key that would
recognise them has been retired.

SIM-0 measured austere-transport delivery latency at p50 170.6 h and
p99 382.5 h (15.9 days):

| window | covers | vs measured p99 | table growth |
|---|---|---|---|
| ±7 | 7 d | 0.4× | 0.2× |
| ±14 | 14 d | 0.9× | 0.5× |
| **±30** | 30 d | **1.9×** | 1.0× |
| ±45 | 45 d | 2.8× | 1.5× |

```
W MUST default to ±30 epochs.
Courier-dominated deployments SHOULD use ±45.
W MUST NOT be below ±14 — that fails to cover the measured p99.
```

The window is also the **exposure window** for reservoir chunks and prekey
batches (RFC 7 §12): every retained epoch is a decryptable epoch. Courier
deployments buy delivery reliability with a longer exposure window, and
the two cannot be tuned independently. This is the central operational
tradeoff in Krab's key handling and it should be stated to operators
directly, not left implicit in a constants table.

### 5.1 Clock

Tag epochs are derived from absolute time, so a node with a wrong clock
computes wrong tags and silently receives nothing.

```
Implementations MUST accept objects whose epoch falls within W of local time.
Implementations MUST NOT emit objects when the median-of-peers time estimate
diverges from the local clock by more than the skew tolerance (±6 h, RFC 1 §2).
```

Emitting with a bad clock poisons other nodes' stores with wrong expiry,
and that damage cannot be undone. Receiving with a bad clock only hurts
the node itself. The asymmetry justifies the asymmetric requirement.

The corpus is itself a clock: objects carry creation timestamps from many
independent senders, and a running median over recently received objects
from multiple peers is a serviceable sanity check requiring no
infrastructure.

---

## 6. Shard

```
shard = leading k bits of tag
```

`k` is a **link** parameter (RFC 3 §7.3), not an object property. It
appears nowhere in the object, which is why enabling sharding later
requires no format change — the reason the tag was placed in the frozen
routing header rather than the body.

| k | corpus share | anonymity set | ingress at n=10 000 |
|---|---|---|---|
| 0 | 100% | 100% | 625 MB/day |
| 2 | 25% | 25% | 156 MB/day |
| 4 | 6.25% | 6.25% | 39 MB/day |
| 6 | 1.56% | 1.56% | 9.8 MB/day |
| 8 | 0.39% | 0.39% | 2.4 MB/day |

**The two columns are the same number.** `k` bits of shard reduce every
node's load by 2ᵏ and reduce the recipient's anonymity set by exactly the
same factor. There is no configuration in which sharding is free, and the
dial should be presented to operators in those terms.

Sizing rule, from SIM-0's measured 0.063 MB/day per node per node against
a target ingress `T`:

```
k = ceil( log2( 0.063 × n / T ) )
```

At a 50 MB/day target: `k=4` at n=10 000, `k=7` at n=100 000. RFC 0 §8.3's
requirement that sharding be mandatory above n≈5 000 corresponds to `k≥2`.

A node's shard selection is visible to its peers, who are people it chose
(RFC 0 §7.4). This is what makes selective subscription safe in Krab where
it was not safe in open networks — and it is why §6's dial and RFC 6
§3.4's channel prefix bucketing use the same mechanism.

---

## 7. Prekey selection

### 7.1 Nothing in the envelope

**The envelope MUST NOT indicate which recipient key was used** — not the
index, not the tier, not the rotation epoch, not exhaustion state.

Prekeys are published as signed `bulletin` objects, so any key hint is a
pointer into a public document naming the recipient. It would undo the tag
scheme with one field.

### 7.2 Deterministic index

```
i = H("krab/pkidx/v1" ‖ sender_id ‖ batch_id) mod N
```

The recipient knows the sender from the matched tag and computes the same
`i`. RFC 7 §13 makes this mandatory: exhaustive search across a 512-key
batch at 200 tag-matched objects costs 30.7 seconds against 0.06 seconds
indexed.

Not available in inbox mode, which has no known sender. Inbox-tagged
objects therefore require exhaustive search and MUST be rate-capped per
peer per epoch (§7.4).

### 7.3 The consequence: batches are sized by correspondents, not messages

**A sender draws the same index for every message within a batch period.**
Prekeys are therefore consumed by *distinct correspondents*, not by
message volume.

Collisions among `S` senders are `S²/2N`. They do not affect lookup — the
recipient computes `i` from the known sender — but they mean a prekey is
shared, which forces schedule-based deletion rather than delete-on-use
(RFC 7 §5.2).

Sizing for ≤10% of senders sharing an index:

```
N ≥ 5 × correspondents
```

| correspondents | batch | expected shared | wire | bucket |
|---|---|---|---|---|
| 10 | 64 | 0.8 | 2 168 B | 4 K |
| 25 | 128 | 2.4 | 4 216 B | 16 K |
| 50 | 256 | 4.9 | 8 312 B | 16 K |
| 100 | 512 | 9.8 | 16 504 B | 64 K |
| 200 | 1 024 | 19.5 | 32 888 B | 64 K |

Batch identity is mixed into the hash, so each republication reshuffles
the mapping and a collision does not persist across batches.

### 7.4 Decapsulation rate limiting

An adversary who observes a current tag can flood objects bearing it,
forcing decapsulation work at no cost. Per RFC 1 §6.4 and RFC 7 §13:

```
Implementations MUST cache failed (id, epoch) pairs so a replay costs one lookup.
Implementations MUST cap inbox-tagged decapsulation attempts per peer per epoch.
Implementations MUST attempt all live batches in constant time and MUST NOT
  stop at first success.
```

A high tag-match / low decrypt-success ratio is unambiguous and SHOULD
feed quota reduction (RFC 3 §12).

---

## 8. Errata

### 8.1 RFC 7 §5.3 and RFC 6 §2.8 — prekey batch sizing

Both size batches by **messages received × republish interval**. That
model assumes random prekey selection. RFC 7 §13 subsequently made
deterministic indexing mandatory, under which a sender draws one index per
batch regardless of how many messages it sends — so the correct driver is
**distinct correspondents** (§7.3).

Corrected sizes:

| scenario | published | corrected | shrink |
|---|---|---|---|
| solo, 5 msg/day, 30 d | 256 | 64 | 4× |
| group of 20, 7 d | 512 | 128 | 4× |
| group of 50, 7 d | 2 048 | 256 | 8× |
| group of 50, 30 d | **8 192** | **256** | **32×** |
| busy node, 100 msg/day | 8 192 | 512 | 16× |

Consequences:

1. **The `MAX_OBJECT` ceiling on republish cadence is removed.** RFC 7
   §5.3 concluded that a node receiving 100 messages/day could not
   republish monthly because the batch would exceed `MAX_OBJECT`; RFC 6
   §2.8 repeated it for 50-member groups. Under the corrected model a
   50-member group needs a 256-key batch of 8 312 bytes. The constraint
   does not exist.
2. **"Members of large groups MUST republish weekly" is withdrawn.**
   Group size drives correspondent count linearly, not message volume
   quadratically, so cadence is a policy choice again.
3. **Forward-secrecy granularity is unchanged.** It was already the batch
   period (RFC 7 §5.2), for the same underlying reason. Nothing weakens.
4. **RFC 7 §5.4 stands unchanged.** Even a 64-key batch is 2 168 bytes
   against LoRa's 512-byte gate, so prekey forward secrecy remains
   unavailable on constrained links and the reservoir remains the only
   mechanism there.

No wire format changes. RFC 1 remains frozen.

---

## 9. Security considerations

**Static-static ECDH is the structural weakness.** Pairwise tags derive
from a stable shared secret, so compromise of either long-term X25519 key
retroactively links every message between that pair across the entire
retained corpus — not contents, which prekeys and the reservoir protect,
but the *fact and timing* of correspondence.

Rotation is the only remedy. It costs almost nothing locally (12 ms of
ECDH at 200 correspondents) and a great deal socially: every
correspondent must learn the new key before they can address you, and
messages in flight under the old key are lost. Implementations SHOULD make
rotation available and MUST warn about in-flight loss, which on a courier
route may be weeks of traffic.

**The precomputation table is the correlation.** It maps tags to
correspondents — precisely what the design prevents everyone else from
doing. It is the single most valuable artifact on a seized running node
and MUST be treated as key material under RFC 7 §9, never paged, never
logged, never persisted.

**Inbox mode is linkable within an epoch, by design.** Anyone holding a
recipient's public key can compute their inbox tag and enumerate messages
sent to it during the current epoch. This is why inbox mode is restricted
to `peer-request` and why §7.4 rate-caps it.

**The epoch window is exposure, not just tolerance.** §5. Lengthening it
to accommodate courier latency lengthens the period during which retained
keys can decrypt.

**Shard selection leaks proportionally and irreducibly.** §6. There is no
value of `k` that reduces load without reducing the anonymity set by the
identical factor.

**Address canonicalisation rejects rather than repairs.** Duplicate keys
and stray whitespace are rejections. Any implementation that normalises
instead has created two addresses that compare equal and hash
differently, which is the beginning of a confusion attack.

---

## 10. References

- KRAB RFC 0 — Architecture and Threat Model
- KRAB RFC 1 — Object Format and Cryptography
- KRAB RFC 3 — Peering, Credentials, and Accountability
- KRAB RFC 6 — Groups and Channels
- KRAB RFC 7 — Key Custody and Erasure
- KRAB SIM-0 — Corpus Convergence Measurements
- `krab-sizes/tags`, `krab-sizes/prekeys` — reference calculators
- RFC 5869 — HKDF
- RFC 7748 — X25519
- RFC 9180 — HPKE
- ITU-T X.400 — O/R addressing (cautionary prior art, §3)
