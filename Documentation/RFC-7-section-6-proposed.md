# RFC 7 §6 — proposed replacement text

Drop-in replacement for §6 through §6.4. Closes three findings, all of which
land in this one section:

| finding | what it fixes |
|---|---|
| `CRYPTO-REVIEW.md` §1 (critical) | `msg_key` derivation reuses one key per (pair, epoch) |
| `RFC-7-review.md` §10 | no channel rule, so the post-quantum property can be silently void |
| `RFC-7-review.md` §11 | `reservoir → chunk_N` is drawn as an arrow, never defined |

Implemented in `crates/krab-crypto/src/{reservoir,seal}.rs`. The implementation
follows **this** text, not the current §6 — so until this is adopted, a
conforming implementation and Krab's own will not interoperate. That is the
safer direction to fail in: §6 as written reuses one key for every message a
pair exchanges in a day.

Changes are marked ▲. Everything unmarked is the existing text, preserved.

---

## 6. The epoch-chunked reservoir

A shared secret between two peers, partitioned by epoch, from which message
keys derive symmetrically.

▲ **Chunk derivation** — previously an unlabelled arrow:

```
chunk_N = HKDF(reservoir, "krab/chunk/v1" ‖ u32_le(N), 32)
```

using the KDF of the suite in force (RFC 1 §6.1), with full HKDF — Extract
then Expand. Extract is used here, unlike RFC 1 §6.2's tag derivation: a
reservoir root is not a curve point and no existing tag space derives from it,
so there is no namespace to fork and no reason to inherit that compromise.

▲ **Message keys** — the previous derivation is withdrawn. `chunk_N` is not a
message key and MUST NOT be used as one:

```
Sealing with a reservoir uses HPKE mode_auth_psk (RFC 9180 §5.1.4):

  psk     = chunk_N
  psk_id  = u32_le(N)
  skS     = sender's correspondence key
  pkR     = recipient's correspondence key
  info    = "krab/v1/" ‖ class          (RFC 1 §6.1)
  aad     = ROUTING_HEADER ‖ deterministic_cbor(body without key 5)
```

Three properties hold together, and no two of them are separable:

- **Per-message keys.** The ephemeral `skE` enters the key schedule, so two
  messages in one epoch derive different keys.
- **Post-quantum.** The PSK is symmetric and established out of band, so an
  adversary who breaks X25519 from a recording still lacks it.
- **Deniability and forward secrecy, unchanged.** `mode_auth` authenticates to
  the recipient alone, and §4's shredding still bounds exposure at epoch
  granularity.

RFC 1 §6.1's suite space accommodates this, so **RFC 1 remains frozen.**

> ▲ **What was wrong.** The withdrawn derivation was
> `msg_key = HKDF(chunk_N, "krab/msg/v1" ‖ tag)`. `tag` is constant for a pair
> across an epoch (RFC 1 §6.2, RFC 2 §4.3) and `chunk_N` is constant by
> definition, so `msg_key` was constant for every message that pair exchanged
> that day. Nothing per-message entered the derivation. This is recorded rather
> than deleted because the error is not obvious from the formula — it requires
> knowing that `tag` does not vary per message, which is stated two documents
> away.

At the close of epoch N plus a grace window, **`chunk_N` is destroyed** (§4).
Every message of that epoch becomes permanently undecryptable — by anyone,
including the participants.

### 6.1 Why this shape

The naive one-time pad consumes key material equal to message volume and
requires both parties to track a consumption offset — which cannot be kept in
sync across a network that delivers out of order, duplicates, and loses. Reuse
of an offset is catastrophic.

Deriving instead of consuming removes all of it:

- ▲ **No offsets, no counters, no consumption state.** Per-message variation
  comes from HPKE's ephemeral, not from anything either party must track.
  *(Previously this bullet claimed the tag supplied uniqueness. It does not —
  the tag is unique per (pair, epoch), not per message. That claim was the
  origin of the defect above.)*
- ▲ **Two-time-pad reuse is prevented by the ephemeral**, not by the tag. Under
  `mode_auth_psk` a repeated `skE` would be required to repeat a key, and
  RFC 9180's key schedule makes that a KEM-level failure rather than a protocol
  one.
- **Out-of-order delivery is free** within an epoch and grace window.
- **The epoch number is the same one used for tag derivation and key erasure.**
  One clock, one counter, three mechanisms.

And the material required collapses:

| | one peer-year at 50 msg/day |
|---|---|
| raw pad | 74.8 MB |
| **reservoir** | **11.7 KB** |

**6 400× smaller.** A year of forward-secret, post-quantum messaging with one
peer costs under 12 KB. Twenty-five peers at 45-epoch retention is 36 KB total.
This fits in a credential exchange, a QR sequence, or a single LoRa
reconciliation.

The tradeoff is granularity: compromising an unexpired chunk exposes that
epoch's traffic with that peer. That is the same granularity §5.2 already
accepted for prekeys, so nothing worsens. Finer granularity is available by
enlarging chunks and sub-partitioning by hour, at negligible size cost.

### 6.2 Establishment

**Physical exchange** is the gold standard, and both parties MUST contribute:

```
reservoir = R_A ⊕ R_B
```

A brings `R_A`, B returns `R_B`, both XOR. Neither party's generator alone
determines the result, so a backdoored or broken RNG on one end does not
compromise it. Two courier legs — already the request/response pattern, so
structurally free.

▲ **Channel independence.** The XOR addresses a bad generator. It does not
address a bad channel, and the following is a separate requirement:

```
A contribution MUST reach its destination over a channel whose
confidentiality does not depend on the asymmetric cryptography the reservoir
is intended to outlive. In-person exchange and physically transported
removable media satisfy this. The corpus and any live link do not.

Where no such channel is available, a peering MAY still be completed. The
implementation MUST record that the reservoir on that link provides no
post-quantum property, and MUST surface this wherever the link is displayed.
```

Such a reservoir keeps its RNG-independence and its forward secrecy under §4
shredding. It loses only store-now-decrypt-later resistance — which is the
property §6 exists to provide, so the loss is total with respect to this
section's purpose.

> ▲ **Why this needs saying.** RFC 3 §11.1 permits "the same documents flow
> through the corpus" for remote peering and qualifies it only as to
> fingerprint comparison. Read literally that covers the contribution. If it
> does, an adversary recording the exchange and breaking X25519 later recovers
> both halves, hence the root, hence every chunk, for the life of the peering —
> and nothing observes anything wrong, because the link functions perfectly.
>
> The mistake is the *diligent* one. Wrapping a secret in the peer's public key
> is correct everywhere else in this series, and an implementer who does it here
> has done something that looks like care. Same bytes, same ceremony, same
> successful link; only the threat model changed, and threat models do not raise
> exceptions.
>
> RFC 3 §11.1 should be amended to distinguish its two artifacts: step 1 through
> the corpus is fine, step 3 through the corpus is the downgrade above.

RFC 1 §6.5 shows per-message hybrid KEM costs a 16× corpus inflation on short
traffic. A **single** hybrid exchange seeding a multi-year reservoir amortises
that to nothing. This is why the reservoir is Krab's primary post-quantum
strategy and suite `0x0002` is the fallback for correspondents without one.

### 6.3 Ratchet on contact

```
reservoir_{n+1} = HKDF(reservoir_n ‖ DH(fresh ephemerals))
```

Hybrid logic applied over time: if the DH is broken later, the original
physical entropy still protects; if the reservoir leaks, the fresh DH still
protects. **It fails only if both fail.**

Peers SHOULD top up from fresh material on every courier exchange — the media
is already moving and entropy is free — so the reservoir strengthens with
contact rather than aging into a static shared secret on two disks.

▲ A ratchet step does **not** restore the post-quantum property to a reservoir
established over a dependent channel: `DH(fresh ephemerals)` is the very
primitive at issue. A link recorded as non-post-quantum under §6.2 stays so
until a contribution is exchanged over an independent channel.

### 6.4 Establishment belongs to the ceremony

Reservoir exchange is step 3 of the peering ceremony (RFC 3 §11), not a separate
operation someone might skip. The `peer-link` records the reservoir identifier
and current epoch; **the material itself MUST NOT appear in the credential.**

▲ Steps 2 and 3 may be separated by days when the ceremony is conducted by
courier, and an implementation holding a part-finished ceremony MUST NOT accept
a second, differing card for it. Otherwise a counterparty can be substituted
*after* the fingerprint comparison the operator remembers performing — §11
describes the ceremony as "one event", and for a sneakernet peering it
demonstrably is not.

---

## What this does not change

- **RFC 1 stays frozen.** §6.1's suite space already permits `mode_auth_psk`;
  no wire format, identifier, or tag derivation changes.
- **§5's tiering is unaffected.** The reservoir remains a conditional tier, so
  a deployment without one is still conformant and still gets `mode_auth`.
- **§4's shredding is unaffected.** Chunk destruction is unchanged; only the
  derivation that produces a chunk, and what a chunk is then used for, are
  specified differently.
