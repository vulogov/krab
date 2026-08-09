# Adversarial pass — 2026-08-08

A deliberate attempt to break the implementation, rather than a re-read of it.
Commissioned because external review will not happen (see
`RFC-0-section-9-proposed.md`), and conducted with the method that has actually
produced findings in this project: pick a claim, ask what would have to be true
for it to be false, and go looking.

**Four findings, all now fixed.** Two were fixed when this was written; the
remaining two are fixed below, and investigating one of them showed the
finding had been understated. The first is the most serious
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

## 3. Truncated identifiers permitted targeted, permanent suppression · **FIXED**

`TRUNC` is 12 bytes. Reconciliation addresses objects by truncated identifier:
`Want([u8; 12])`, and the responder serves via `Corpus::get(&[u8; 12])`.

96 bits gives a birthday bound near 2⁴⁸, which is reachable. An attacker who
grinds an object colliding with a *specific* target's truncated identifier can,
whenever that object is requested, answer with the collision instead.

**This is not content substitution.** RFC 1 §11's I5 is checked on ingest, so
the collision is stored under its own full identifier. Confidentiality and
integrity hold.

**It was worse than first described, and worse than RFC 1 §9.3 claimed.** §9.3
justified 12 bytes on the grounds that "the consequence of a collision is
bounded — one object not transferred on one link, recoverable through another
peer." Tracing it showed that sentence to be false.

`recon::wanted` asks for what it lacks by testing the *truncated* identifier
against what it holds. A node that accepts the collision therefore holds
something with that prefix, `has(trunc)` returns true, and it **stops asking
for the target — from every peer, permanently.** Not one link, and not
recoverable. RFC 0 §6 guarantees it is never told.

So a 2⁴⁸ grind against one chosen object bought permanent silent suppression of
that object at that node. My first write-up said "asks again next cycle", which
was wrong in the direction that made it sound survivable.

**Fix.** `TRUNC` widened to 16 bytes: grind at 2⁶⁴, accidental rate in a
500 000-object corpus near 2⁻²⁵. The manifest row goes from 16 to 20 bytes
packed, which §9.3's own table prices at 8.0 MB → 10.0 MB for that corpus.

The width is now set where a grind is *infeasible* rather than where the damage
is tolerable, because the damage cannot be bounded by the protocol: the
requester never learns the full identifier, so it cannot distinguish the
collision from the target. The serve-the-full-identifier option I ranked first
does not work for the same reason — the requester has nothing to compare
against.

RFC 1 §9.3 is amended, including a note recording that its original
justification was wrong and why.

## 4. The tombstone set grew without bound · **FIXED**

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

**Fix.** `Store::prune_tombstones` drops entries past `expiry + MAX_TTL`, and
RFC 5 §8 now requires it. Past that horizon no honest peer holds the object and
a dishonest one gains nothing by offering it, because RFC 1 §11's I2 rejects an
expired object regardless.

The set now stores `(expiry, id)` rather than `id` alone, since an identifier
does not reveal when its object expired. Eviction and expiry work by segment,
so the bucket's upper edge is used as the bound — keeping a tombstone slightly
longer than needed, which is the safe direction.

This was the fifth instance of one pattern: a retention parameter that should
be a function of the declared guarantee (`MAX_TTL`) and was instead
unspecified. RFC 1 §6.2, RFC 7 §12 and §5.2, RFC 2 §5, and now RFC 5 §8.

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
