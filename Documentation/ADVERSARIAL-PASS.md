# Adversarial pass — 2026-08-08

A deliberate attempt to break the implementation, rather than a re-read of it.
Commissioned because external review will not happen (see
`RFC-0-section-9-proposed.md`), and conducted with the method that has actually
produced findings in this project: pick a claim, ask what would have to be true
for it to be false, and go looking.

**Four findings. Two fixed here, two open.** The first is the most serious
thing found in the project so far, because it defeats a feature under precisely
the threat model that feature exists for.

---

## 1. CRITICAL — the duress passphrase was timing-distinguishable · **FIXED**

RFC 7 §10's duress passphrase "appears to unlock normally". Its entire value is
being indistinguishable from the real one to someone watching.

`unlock` checked duress first and returned early on a match:

| passphrase | Argon2 runs | wall clock |
|---|---|---|
| **duress** | **1** | **~500 ms** |
| correct | 2 | ~1 000 ms |
| wrong | 2 | ~1 000 ms |

RFC 7 §4.1 calibrates Argon2id to "approximately 500 ms on target hardware", so
the duress path completed in **half the time of every other outcome**.

**A stopwatch is enough to read that**, and the person holding the stopwatch is
exactly the adversary §10 describes: someone standing over the operator
watching them unlock. The feature announced itself by finishing early.

This is worse than a side channel in the usual sense. It needs no equipment, no
repetition, and no statistical analysis — one observation of one unlock, by
someone with no technical skill, distinguishes "they wiped it" from "they
complied".

**Fix.** The KEK depends only on the passphrase and the stored parameters, and
both the duress record and the identity record use the same parameters. So it
is derived **once** and used to attempt both opens, with the branch taken on
the results rather than on the way to them. Every outcome now costs one Argon2
and two AEAD operations — microseconds against half a second.

`open_with` carries the reasoning at the call site, because the obvious
refactor is to split it back into two predicates.

## 2. The exchange loop was unbounded · **FIXED**

`initiate` and `respond_to` looped until the peer said `Done`. A peer that
never says it keeps the loop running: every object is checked and most are
rejected, but the session never ends and the thread never returns.

RFC 3 §6's quota is the durable answer to volume and does not solve this — it
is a **per-window budget**, not a per-session one, so it bounds how much a peer
may give in a day and says nothing about how long one conversation may last.

**Fix.** `MAX_MESSAGES` bounds a session at 64k messages. Reaching it is not an
error: the exchange ends, the schedule fires again later, and a peer with more
to give gives it then. That is the same shape as every other limit here —
RFC 5's reconciliation is designed to be resumable, so ending early costs
nothing.

## 3. OPEN — truncated identifiers permit a targeted liveness attack

`TRUNC` is 12 bytes. Reconciliation addresses objects by truncated identifier:
`Want([u8; 12])`, and the responder serves via `Corpus::get(&[u8; 12])`.

96 bits gives a birthday bound near 2⁴⁸, which is reachable. An attacker who
grinds an object colliding with a *specific* target's truncated identifier can,
whenever that object is requested, answer with the collision instead.

**This is not a content-substitution attack.** RFC 1 §11's I5 is checked on
ingest, so the collision is stored under its own full identifier and the
requester still lacks the target. Confidentiality and integrity hold.

**It is a liveness attack, and it is targeted.** The requester asks again next
cycle, receives the collision again, and never obtains the object — while every
check passes and RFC 0 §6 guarantees nothing is reported. One specific message
can be suppressed indefinitely by one relay on the path.

The cost is 2⁴⁸ work *per target object*, which is expensive for bulk
suppression and affordable for a single message someone cares about.

**Not fixed, because the fix is a format change.** Options, in order of my
preference:

1. **Serve the full identifier alongside the object** and have the requester
   drop a response whose full identifier is not one it asked for. Costs 20
   bytes per delivered object; detects the attack rather than preventing it,
   which is enough — the requester can then ask a different peer.
2. Widen `TRUNC` to 16 bytes, moving the bound to 2⁶⁴. Costs 4 bytes per
   manifest row, and RFC 1 §9.3's row size is a published figure.
3. Accept it, and document the bound.

RFC 1 §9.3 sizes the manifest row and RFC 5 §4.4 assumes truncation, so this
crosses two frozen documents and should be decided rather than patched.

## 4. OPEN — the tombstone set grows without bound

`Store::tombstones` is a `BTreeSet<ObjectId>` that is inserted into on expiry
and on eviction, and **never pruned** — there is no `remove` or `retain` on it
anywhere.

RFC 5 §8 needs tombstones so a returning courier node cannot re-inject what the
network evicted. But an entry is only useful while some peer might still offer
that object, which is bounded by `MAX_TTL`: after 45 days past its expiry,
nobody holds it and no honest peer will offer it.

At 32 bytes per entry and SIM-0's corpus rates, a long-lived node accumulates
tombstones indefinitely — memory that only grows, on a node RFC 4 §5.4
contemplates running on constrained hardware.

**Not fixed, because the retention period is a protocol decision.** The obvious
answer is to drop a tombstone once `now > expiry + MAX_TTL`, which needs RFC 5
§8 to say so. Note this is the same defect pattern the series has already been
bitten by four times: a retention parameter that should be a function of the
declared guarantee (`MAX_TTL`) and is instead unspecified.

---

## What this pass did not cover

Stated because a review's silence is otherwise read as a clean bill.

- **The primitives themselves.** Ed25519, X25519, ChaCha20-Poly1305, HKDF,
  Argon2id, BLAKE3, HPKE and Noise are used, not analysed. RFC 1 §13 is right
  that "composition, not primitives, is the risk" — but that is an argument for
  where to spend review effort, not a claim that the primitives were reviewed.
- **Side channels other than the one in §1.** No cache-timing analysis, no
  power analysis, no attempt at differential timing on tag lookup or HPKE
  rejection. §1 was found because it was half a second wide.
- **The dependency supply chain.** `hpke`, `snow`, `dalek`, `argon2` and their
  transitive graph are trusted as published. RFC 0 §9's reproducible-builds
  argument addresses the binary, not the sources.
- **Concurrency.** The node is single-threaded except for the responder path;
  no interleaving analysis was done.
- **The formats under a fuzzer.** Decoders are tested against truncation at
  every offset and against flipped bytes, which is not fuzzing.

## Method note

All four findings came from the same question applied to a different claim:
*"what would have to be true for this sentence to be false?"* — §1 from "appears
to unlock normally", §2 from "the session ends", §3 from "an identifier names
its content", §4 from "erasure is destroying a key".

That is a method, and it is repeatable by someone who is not me. It is also the
method that found the reservoir ratchet defect (`CRYPTO-REVIEW.md` §11.2), and
in each case the sentence had been written by me and believed by me until it
was attacked. **That is the argument for external review, restated as evidence
rather than as principle.**
