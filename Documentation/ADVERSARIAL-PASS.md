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

---

# Second pass — 2026-08-09 · axis: **time**

The first pass attacked *claims in sentences*. This one attacks a different
thing: **time**, because Krab takes time as an argument everywhere by design —
`Scheduler::due(now, entropy)`, `Store::ingest(.., now_min, ..)`,
`Epoch::at(unix_secs)` — and there is exactly one place it reads a clock. That
asymmetry is worth pressing on.

**Four findings, all fixed. Two are severe, and one was introduced by the fix
in `CRYPTO-REVIEW.md` §11.**

## 5. CRITICAL — a wrong clock permanently destroyed the reservoir · **FIXED**

The epoch ratchet is irreversible by design: that is what makes §6's
destruction claim true. `advance_to` capped its *iteration count* at 4×365 so a
wild value could not spin, and advanced up to that many steps otherwise.

So a clock reading ten years ahead — an NTP correction, a restored VM snapshot,
a dead CMOS battery, a typed date — ratcheted **1 460 epochs**, destroyed every
intermediate root on the way, and landed at neither the old epoch nor the
requested one. The peer stayed where it was.

**The reservoir was then permanently desynchronised with every correspondent,
with no way back**, because the ratchet cannot rewind. An ordinary hardware
fault became irreversible key loss, and the node would report nothing: chunks
simply stopped matching, and RFC 0 §6 guarantees silence.

This was **introduced by the ratchet added to fix `CRYPTO-REVIEW.md` §11.2**.
The static root it replaced had no such failure — a wrong clock derived a wrong
chunk and a right clock derived a right one, recoverably. Making destruction
real made a clock fault destructive, and that consequence was not considered
when the fix was made.

**Fix.** `advance_to` now **refuses** an advance beyond `MAX_ADVANCE`
(2 × `EPOCH_WINDOW`) and changes nothing at all — returning `bool` rather than
silently doing part of the work. A node offline longer than `MAX_TTL` has
already lost the mail it missed, so advancing further serves nothing, and every
value beyond it is likelier to be a wrong clock than a long absence.

The principle, stated in the module: **an irreversible operation must not run
on unvalidated input, and a system clock is unvalidated input.**

## 6. SEVERE — epoch keys were never shredded · **FIXED**

`Hierarchy::shred_epoch` and `shred_before` existed, were tested, and **had no
caller anywhere in the application.**

RFC 7 §4's entire promise is that destroying `W_N` makes an epoch unreadable
"regardless of what the flash controller did with the underlying blocks". An
implementation that never destroys one keeps that promise in the sense that an
unused lock secures a door. Every past epoch remained openable with the
passphrase, indefinitely, and the wrapper set grew without bound.

Every part of the mechanism was correct and tested. Nothing invoked it.

**Fix.** `shred_expired_epochs` runs on the schedule tick, retaining
`EPOCH_WINDOW` — because RFC 1 §6.2 says an object may arrive that late and a
shredded epoch cannot decrypt it. Erasure lags rotation by exactly the
acceptance window rather than by a chosen number, which is the rule this series
has violated five times (§4 above).

The test asserts what matters: after shredding, the correct passphrase does not
reopen the epoch.

## 7. A clock before the protocol existed was treated as a date · **FIXED**

`now_epoch` used `unwrap_or(0)`, and an unset RTC reads 1970. A node with a
dead battery derived tags at epoch 0 — a tag space no peer computes — and
appeared to work: it composed, stored, packed and reconciled, and nothing it
sent was ever recognised.

**Fix.** Clamped to 2026-01-01. A reading below that is hardware, not a date.

## 8. Reservoir use degrades silently on a refused advance · **checked, adequate**

Raised and dismissed. If the ratchet cannot reach the current epoch the
reservoir is dropped and sealing falls back to `mode_auth` — losing the
post-quantum property.

That is correct behaviour (RFC 7 §5 makes the reservoir a conditional tier) and
it is **not** silent: `send` reports `", post-quantum"` or `", no reservoir"` on
every message. Recorded because the check is the finding — a degradation that
reports itself is a different thing from one that does not, and the difference
is one line.

## What this pass suggests about the last one

Finding 5 exists because of a fix made three days earlier, and finding 6 is a
tested mechanism with no caller. Neither is the kind of defect the first pass's
method finds: attacking a *sentence* does not surface a function nobody calls,
and it does not surface a consequence created by the previous fix.

**The axes are not interchangeable, and running one does not reduce the yield
of the next.** Two passes have now produced eight findings, three of them
severe, and the second pass found the more serious pair. That is not evidence
that the code is bad; it is evidence about how much a single reviewer with one
method misses, which is the argument `RFC-0-section-9-proposed.md` makes.

Axes not yet run: concurrency, resource exhaustion, partial-write and
crash-consistency, and the decoders under an actual fuzzer.

---

# Third pass — 2026-08-09 · axis: **fuzzing the decoders**

`cargo-fuzz` against the four hostile-input surfaces. Setup and results in
`fuzz/README.md`; this is the finding.

**One finding, severe, found in under sixteen thousand executions.**

## 9. CRITICAL — a 40-byte frame killed the node · **FIXED**

`Control::parse` pre-sized its collections from the array length the input
declared:

```rust
let n = arr(&mut r)?;
let mut ids = Vec::with_capacity(n);   // n is attacker-controlled
```

A CBOR array head with an 8-byte length declares up to 2⁶⁴ elements. In a
46-byte message, `Vec::with_capacity` multiplied that by the element size and
overflowed, panicking inside the allocator.

**RFC 7 §9 sets `panic = "abort"`** so a core dump cannot carry key material.
So this was not a caught error: the process died. Any peer past the Noise
handshake could kill a node with one small frame, repeatedly, and anyone at all
could do it through a courier archive — `read_archive` reaches the same parser
with no handshake.

### The rule existed one layer up

RFC 4 §9 states it and `frame::read` obeys it:

> "The length is validated **before** any allocation. RFC 4 §9 requires it, and
> a four-byte header claiming four gigabytes is the cheapest attack there is."

The frame layer checks its length against `MAX_FRAME` before allocating. The
message layer, decoding the body that check protected, allocated on a *nested*
declared count with no check at all. The defence was implemented where it was
written down and not where the same reasoning applied.

That is worth more than the bug: **a rule stated once, in the section about the
layer where someone happened to think of it.** RFC 4 §9 should say it applies
to every length in every decoder, not to frames.

### Fix

The three collection arms build with `Vec::new` and push. That removes the
attacker's control over the allocation entirely — a truncated body fails on the
first missing element and the vector never grows past what the buffer actually
contained. Capping capacity against the remaining bytes would also work and is
one arithmetic mistake away from the same bug.

The crash input is carried verbatim in a unit test, so the regression is caught
by `cargo test` rather than depending on nightly or on anyone remembering to
fuzz.

## What this says about the previous passes

`Control::parse` was already tested against truncation at every offset and
against flipped bytes. Both of those mutate *valid* messages. Neither
constructs a message that is structurally valid and semantically absurd — an
array header promising 2⁶⁰ items — because a human writing tests starts from
something that works and damages it.

**A fuzzer starts from nothing and has no idea what is supposed to work.** That
is the whole of the difference, and it took 15 694 executions.

Three passes, nine findings, four severe. Each axis found what the previous
ones structurally could not: sentences, then time, then a machine that does not
know what the code is for.

---

# Fourth and fifth passes — 2026-08-09 · axes: **concurrency** and **crash-consistency**

Run together because both concern what happens when something interrupts —
another thread, or a power cut. **Two findings, both severe, both fixed.**

## 10. SEVERE — reconciliation froze the interface, taking the lock chord with it · **FIXED**

`tick_schedule` ran inside the render loop, between `event::poll` calls, and
called `reconcile_with` — which does blocking socket I/O.

So an exchange froze the interface for its whole duration. On a serial link at
RFC 4 §5.3's 11 520 B/s that is **minutes** for a few megabytes, and during it:

- no keystroke is processed,
- nothing redraws,
- and **`Ctrl-L` does not lock**, which is the one keystroke an operator might
  need urgently and the reason `RFC-7-review.md` §9 exists.

A peer trickling bytes could hold the interface hostage deliberately. The
exchange loop is bounded at 64k *messages* (§2 above), not by time, so a slow
peer is bounded only by patience.

It also contradicted a stated requirement directly:

> "As TUI is client and 'server in background', send/receive shall be in
> background regardless frontend user activity."

**Fix.** Exchanges run on their own thread and report back over a channel
drained on tick. `Session` gained a `Send` bound, `SimSession` moved from
`Rc<RefCell<…>>` to `Arc<Mutex<…>>`, and `LinkTable::take_session` moves the
session out rather than lending it — which also prevents two overlapping
exchanges on one link.

### The trap, which is most of the work

Moving the exchange to a thread is half the fix. The obvious next step is to
hand that thread a `MutexGuard` on the corpus for the duration — and that
**rebuilds the freeze through the lock**. The interface then blocks on `lock()`
instead of on `recv()`, for exactly as long, with an identical symptom and a
less obvious cause.

`SharedStore` therefore locks **per `Corpus` operation** and never across one.
The exchange holds no lock while waiting on a socket.

What that admits is stated rather than left to be rediscovered: two calls are
not a consistent pair. `count` and `entries` may disagree by whatever landed
between them. That is safe here because RBSR converges as a fixed point rather
than in a single pass — an interleaved write costs a wasted descent, not a
wrong answer — and it would not be safe for a protocol needing a snapshot.

A test asserting the *stronger* property failed, which is how the distinction
got written down. The test now asserts what is actually guaranteed: each single
call is internally consistent, and one explicit lock gives a consistent pair.

## 11. SEVERE — a crash during any save could destroy the identity · **FIXED**

Every persistent write used `std::fs::write`, which truncates and then writes.
Between those steps the file is empty; after a partial write it holds a prefix.
There was no `fsync` and no atomic rename anywhere — 29 write sites, zero
durable.

For most files that is an inconvenience. For `identity.wrapped` it is
permanent identity loss, and RFC 7 §11 is explicit:

> "Losing identity means every peer must re-verify out of band, in person, from
> scratch."

The identity is rewritten on `init` and on any operation touching the key
hierarchy, so the window is every save rather than a rare one. §11 prescribes
an offline backup *for* identity loss — it did not anticipate that a routine
write was among the ways to cause it, and an operator who took the backup and
then lost the file to a power cut would be recovering from the implementation
rather than from a disaster.

**Fix.** `atomic::write`: write to `<path>.tmp`, `fsync` it, `rename` over the
target, `fsync` the directory. A crash at any point leaves either the old file
or the new one.

The directory sync is the step usually missed: syncing the file makes the
*contents* durable and leaves the *directory entry pointing at them* possibly
not, so a crash can undo the rename and orphan the temporary.

The temporary sits beside the target rather than in a system temp directory,
because `rename` is only atomic within a filesystem and a cross-device rename
degrades to copy-and-delete — which is the non-atomic write being avoided.

### One place that deliberately is not atomic

`peer pad` writes the reservoir contribution to removable media. An atomic
write leaves a `.tmp` on failure, and here that file is **the plaintext
contribution** under a name nothing cleans up, on a medium the operator is
about to carry away. A partial write is visibly partial and the pad is
regenerable from the ceremony, so the plain form is safer. Recorded at the call
site, because it looks like an oversight.

## Running total

Five axes, eleven findings, six severe:

| axis | findings | severe |
|---|---|---|
| sentences | 4 | 2 |
| time | 4 | 2 |
| fuzzing | 1 | 1 |
| portability | 2 | 0 |
| concurrency + crash-consistency | 2 | 2 |

No axis has come back empty, and no axis has found what another would have.
Finding 10 was a stated requirement violated in code; finding 11 was a class of
bug nothing else looks for. Neither is reachable by reading the code for
correctness — one needs the requirement in hand, the other needs someone to ask
"what if this stops halfway?"

---

# Sixth pass — 2026-08-10 · axis: **resource exhaustion**

What a hostile or merely generous peer can make this node spend. **Four
findings, three severe, all fixed** — and the first two are the same bug seen
from two sides.

## 12. CRITICAL — reconciliation broke entirely above ~3 000 objects · **FIXED**

`MAX_PER_EXCHANGE` was 4 096 by choice. A manifest is one `Control::Manifest`
and therefore one frame, capped at `MAX_FRAME` (65 535 bytes), and a row costs
22 bytes as CBOR. 4 096 rows is about 90 KB.

**So a manifest of a full window could not be sent.** A node holding more than
~3 000 objects in the reconciliation range produced a message that failed to
frame, the session died, and the operator saw "session ended" — for every peer,
every time, permanently.

RFC 1 §9.3's own table sizes corpora at 10 000, 100 000 and 500 000 objects.
The limit sat below the smallest figure the design contemplates, and nothing
reached it: SIM-2 used 900 objects, the courier gate used five, and every unit
test a handful.

**Fix.** `MAX_PER_EXCHANGE` is now derived from `MAX_FRAME` and the row cost,
with a test that encodes a maximal manifest and frames it. A constant that must
satisfy an arithmetic relationship should be computed from the relationship.

## 13. CRITICAL — a corpus above one manifest never converged · **FIXED**

Underneath the first, and worse. `entries(lo, hi).take(N)` returns `(expiry,
id)` order, so truncating takes **the same first N rows every round**. The tail
is never advertised, the corpus converges on a prefix, and it stops.

Not slowly — permanently. Measured directly: a 3 773-object corpus shipped
2 973 objects in the first exchange and **zero in every exchange after**, across
forty rounds.

Truncation reads like graceful degradation. It is silent, total, and looks
identical to a peer having nothing new.

**Fix.** `advertised_range` bisects the window on expiry — the ordering both
sides share without coordination (RFC 5 §4.4) — and picks a sub-range that
fits, varying with a per-exchange salt. The responder chooses its own sub-range
salted by the initiator's rows, so both directions advance without either
keeping state.

Three things had to be right, and each was wrong first:

- **Descend into a populated half.** A blind bisection of a `(0, u32::MAX)`
  window walks into empty space, terminating on a range with no rows —
  advertising nothing, for ever.
- **Spend a salt bit only on a free choice.** Consuming one per step exhausts
  the salt during the ~20 forced halvings needed to reach the band where
  expiries live, after which every salt picks the same range.
- **The responder must not mirror the initiator's span.** Doing so offers only
  the overlap, so anything it holds outside never ships in that direction. That
  version passed the large-corpus test and broke a 40-object one.

## 14. SEVERE — the negotiated retention was decorative · **FIXED**

`Store::evict_to` existed, was tested, and **had no caller** outside tests and
SIM-2. `Policy::retention_bytes` is negotiated in the peer-link and signed by
both parties; nothing enforced it. A node agreeing to hold a gigabyte held
whatever arrived, which on a fast link is a disk-filling attack requiring no
more than a generous peer.

This is the third instance of one shape: **a correct, tested mechanism with no
caller** — after `shred_epoch` (§6) and alongside it. Coverage measures whether
a function works, never whether anything calls it.

**Fix.** `enforce_retention` runs on the tick. Expiry first, then tombstone
pruning, then eviction if still over — dropping what is already dead is free,
where evicting what is live raises the watermark and costs the network a copy.

## 15. Quadratic lookups, one of them a regression I introduced · **FIXED**

- `has_truncated` scanned the whole index per call, and `recon::wanted` calls it
  once per manifest row: `O(rows × corpus)`, about nine million truncations for
  a 3 000-row manifest against a 3 000-object corpus, and quadratic after that.
  Now a `BTreeMap<[u8; 16], ObjectId>`, maintained on insert **and on removal** —
  a stale entry would make the store claim an object it dropped, which is the
  same silent suppression §3 was fixed to prevent, arrived at from the other
  side.
- Tombstone membership was `O(t)` per ingest. It had been `O(log t)` until I
  changed the set to `(expiry, id)` pairs two passes ago to permit pruning.
  Now a `BTreeMap<ObjectId, u32>`: membership is checked on every ingest and
  pruning runs once a tick, so the lookup must be logarithmic and the scan may
  be linear — the reverse of what the pair-set gave.

## Running total

Six axes, fifteen findings, nine severe. The two worst in this pass were
reachable only by asking what happens **at scale**, and every test in the
project had used a corpus three orders of magnitude below the design's own
smallest tabulated size.

That is the lesson worth keeping: the tests were not wrong, they were small.
A property that holds for five objects and fails for five thousand is invisible
to every one of them.

---

## Pass 7 — overlapping operator state

**Axis.** Every previous pass looked at one subsystem under stress. This one
looks at the *interaction* of state that accumulated across many sessions:
prompts, an open composition, a background socket accepting strangers, queued
fan-out copies, a wipe confirmation, a displayed picture.

**Method.** Enumerate every field of `App`, then ask of each: does `lock`
clear it, does `panic_wipe` clear it, and should it? `lock` carries the rule
in its own comment — *"the screen must not list correspondents"* — so that
rule was applied to fields written long after it.

Three findings, all severe, all the same shape: a rule stated in one place and
enforced only over the fields that existed when it was written.

### 7.1 The command history survived a lock

`lock` cleared the activity log because it names correspondents. The command
history names them too — `send b73a4d8c`, `message b73a4d8c`, the paths of
cards and pads — and Up-arrow recalled it on a node that is supposed to be
unable to read anything.

Alongside it: an open composition's recipient list, a first-contact socket
still accepting strangers, a `wipe` still confirmed, and a pending `Prompt`
that would consume whatever the returning operator typed next.

### 7.2 A panic wipe cleared *less* than a lock

The verb behind the chord an operator presses when somebody is at the door
left the decrypted body, the activity log, a displayed picture, the channel
posting key and every group roster in memory. `lock` cleared the first three;
nothing cleared the last two.

**The fix is structural.** `panic_wipe` now calls `lock` rather than repeating
its list, so a field added to one is cleared by both. The two had drifted
apart precisely because they were two lists.

### 7.3 A wiped node kept answering for an identity it had destroyed

A lock deliberately keeps links and the listener: a locked node is a relay and
still carries for its peers. A *wiped* node has no peers — it has just
destroyed the credentials that define them — and it was still accepting calls
from their statics, still scheduling reconciliations with them, and still
holding sealed copies whose release would have rebuilt the corpus the wipe
destroyed.

### What did not fail

Three probes found nothing, and are kept as tests because a negative result
about a security property is worth as much as a positive one:

- a `Prompt` cannot intercept a passphrase — the passphrase step has its own
  buffer and its own key handling
- a stale prompt does not eat the verb that starts an unlock
- a `wipe` confirmation does not survive an unrelated command

### The pattern, again

Every finding in this pass is a rule that was true when written and silently
stopped being true as fields were added around it. That is the same shape as
`wipe`'s filename list (twice), `respond_to` with no caller, and the epoch
hierarchy that was never persisted.

The durable fixes have all been the same: make the rule structural rather than
enumerated. `Artifact` for the disk, `panic_wipe → lock` for memory. Where a
list is unavoidable, a test that walks it and fails on omission.

---

## Pass 8 — the credential, and the newest surface

Run against everything added since Pass 7: the RBSR session driver, the `sim`
backend's blocking semantics, rollcall, introduction tokens, RFC 3 §3's
credential, and `evidence`. Four of those decode input from strangers, and one
is a wire protocol that had never existed before.

**Five findings, all in the newest code, four of them in the same command.**
That concentration is itself the result: `peer countersign` was two days old
and had been written, reviewed and tested by the same person in one sitting.

### 1. Credentials were stored in the clear — a MUST violation

RFC 3 §15:

> "**Credentials at rest are non-repudiable.** Seizing a disk yields the peer
> list *with cryptographic proof* — worse than an address book. The credential
> store **MUST be encrypted under the RFC 7 key hierarchy.**"

`peer countersign` wrote `peers/<id>/credential` as plaintext CBOR. Every other
sensitive per-peer file is sealed under `W_N`; this one, the only file in the
layout that is *cryptographic proof* of a relationship rather than an assertion
of one, was not.

Sealed under `W_N` with domain `krab/credential`. A locked node can no longer
read its own credentials, which is the intended consequence — §15 calls holding
them in memory "mitigation, not a fix".

The test asserts the identity keys do not appear anywhere in the stored bytes,
rather than asserting the file is "encrypted", because the second is not a
property anything can check.

### 2. Countersigning did not check that the document named this node's keys

`other_than` resolves a party by node id, which is `BLAKE3(sig_pk)`, so a wrong
identity key could not get through. **`kx_pk` was covered by nothing.**

A peer could propose a credential carrying this node's real identity key beside
a correspondence key *they* control. Countersigning it produced a mutually
signed — and per §15 non-repudiable — statement by this node that its own
correspondence key was the attacker's.

Nothing reads `kx_pk` out of a credential today, which made it latent rather
than live. It does not stay latent: RFC 3 §9.2 makes the credential the place
contact details are exchanged, and §3 keys 1 and 2 carry `{sig_pk, kx_pk}`
precisely so a reader can use them. The first code to do so would have been
encapsulating to an attacker.

Both parties' entries are now checked against the cards this node holds.

### 3. Countersigning agreed to terms the operator never saw

RFC 3 §5.3 makes the countersignature the act of acceptance, and §6 says quota
is "a checkable statement against a signed artifact rather than a unilateral
judgement" — which is only true if the party bound by it saw it.

The command signed and reported success without printing the terms. A peer
could propose one byte of retention and the operator would agree to it blind.
Both directions are now printed before the confirmation.

### 4. Only one side ever ended up with a credential

The countersigner sealed the completed document into its peer directory and
shredded the handover copy unconditionally. So the proposer was left holding a
half-signed proposal for ever, and the countersigner held the only complete
one — sealed, and therefore unreadable to anyone else.

Neither could cite it as evidence, which is the entire reason the document
exists. Nothing reported anything wrong: `credential_with` returned `None` and
a request simply went out unevidenced.

Found by a test written for finding 1, which is the argument for writing tests
that drive the whole flow rather than the unit under repair.

### 4b. And the fix to it was wrong, for a reason worth keeping

`Credential::sign` returned `true` for re-signing a slot it had already filled.
So the proposer, handed the completed document back, believed it had just
countersigned — and wrote out *another* plaintext handover copy, in the home
directory of a node that owed nobody one.

`sign` now reports whether it **added** a signature. Two falses: not a party,
and already signed.

The related half: destruction was keyed off a conventional filename
(`<peer>.credential`) rather than the path the operator actually passed, so a
credential delivered as `incoming.dat` was sealed into the peer directory and
also left in the clear wherever the courier unloaded it. `peer seal` had made
exactly this mistake with the counterparty's pad and had already been fixed;
the new code did not inherit the fix.

### 5. `Command::ALL` did not exist, and the list standing in for it had drifted

`every_verb_parses_and_round_trips` walked a hand-written array covering **19
of 26** verbs. `Command` is `#[non_exhaustive]`, so adding a variant failed
nothing.

All seven missing verbs happened to round-trip, so there was no live defect.
That is luck. `Command::ALL` is now the list, and `every_variant_is_in_all`
matches on it exhaustively, so a new variant does not compile until it is
there.

`peer countersign` was also missing from `help`, while `peer seal` had just
started telling operators to run it.

### What did not fail

- **The RBSR descent terminates against a hostile peer.** `resolved` grows only
  through leaves, leaves are produced only while `rounds <= RBSR_MAX_ROUNDS`,
  and a batch is bounded by `MAX_FRAME`. The initiator's drain loop is nested
  inside the outer loop but breaks it immediately, so it is not
  `MAX_MESSAGES²`.
- **`Control::Range` allocates nothing on a declared count.**
- **Evidence discloses no edge the token had not already disclosed.** A token
  is signed by the introducer and names the requester, so a recipient learns
  those two know each other from the token alone. Evidence adds proof, not the
  fact — which is why it can ride along without a separate consent step.
- **The rollcall entry still carries no endpoint**, checked against the
  published object rather than the struct.

### The pattern, again, and where it moved

Findings 2, 4, 4b and 5 are the same shape as every previous pass: a rule
enforced only over what existed when it was written. Finding 4b is the sharpest
version yet — `peer seal` had already made the filename mistake and already
been fixed, and the new command reproduced it anyway, because the fix lived in
`peer seal` rather than anywhere a second caller would meet it.

Findings 1 and 3 are a different shape, and new: **a MUST read, understood,
and then not carried into the code that needed it.** Both §15 and §5.3 are
quoted in the module that violated them. Reading the specification is not the
step that fails; connecting a sentence in it to the four lines that had to
change is.

No structural fix suggests itself for that one. What the pass can do is keep
finding them, which is the argument for running it after every feature rather
than before every release.

---

## Pass 9 — the credential's five dependants

Run against everything built on RFC 3 §3's credential: the filter (§7.3), quota
(§6, §6.2), the negotiation chain (§5.2), nodelist fragments (§8), and
`NODEDIFF` (§8.2). About 2 500 lines, all written in the days before the pass.

**Two findings, and the first is the worst thing shipped in this series.**

### 1. Every credentialled link silently refused every object

`ExchangeView` was given `window.0` as its `now_min` — the exchange's *lower*
bound, `now` minus the 45-day window. That is correct for `ingest`, which is
what the field was added for: passing the window's start makes the whole window
admissible.

RFC 3 §7's retention horizon was then computed from the same field:

```text
horizon = now_min + retention_days × 1440
```

With `now_min` 45 days stale and the default 45-day retention, the horizon
landed exactly on **now** — and every object, whose expiry is by definition in
the future, failed `header.expiry_min > horizon`.

So a link with a completed credential accepted nothing. Not an error: the
exchange completed, reported success, and moved zero objects. RFC 0 §6 makes
delivery failure silent by design, so the symptom would have been "that peer
stopped receiving anything" with both nodes reporting healthy reconciliations —
and it would have appeared exactly when an operator did the thing the last five
commits were written to encourage.

The shape is new to this series: **one field holding two meanings of "now"**,
one of which was wrong. Neither meaning is unreasonable, and nothing in the
name distinguished them. `retention_now_min` is now separate, and a test in
`shared.rs` puts an ordinary object through a scoped view.

Found by reading the call sites of a value rather than the logic that used it.
The logic is right; it was fed the wrong number.

### 2. Two artifacts under one sealing domain

`Artifact::Nodelist` (this node's published base) and `PeerFile::Nodelist` (a
peer's, per peer) were both sealed under `krab/nodelist`. A ciphertext from
either therefore opens as the other.

The exploit is weak — an attacker who can write the home directory but not read
it could swap them, and `Delta::apply`'s base-hash and author checks refuse the
result — but those checks are downstream of a decryption that should never have
succeeded, and "a later check catches it" is not what a domain is for. Split to
`krab/nodelist` and `krab/nodelist/peer`.

### Found while wiring, not while auditing

Two more were caught in the same session by writing the NODEDIFF wiring, and
belong to the same pass:

- **The fragment read path could never have worked.** `Message.body` is
  `String::from_utf8_lossy`, and a fragment is 32-byte keys and 64-byte
  signatures, so `Fragment::decode(body.as_bytes())` decoded a string of
  U+FFFD. The picture path had solved this exact problem, in the same function,
  and the new code did not reuse it.
- **Two rows for one peer.** An older full fragment stays in the corpus after
  its delta arrives, so both opened on one scan and each pushed a reach entry.
  A reader taking the first got whichever the scan reached.

### What did not fail

- `Account::roll` judges the closing window before resetting it, so a
  settlement never reads counters it has already cleared.
- `Standing::effective` saturates: a peer countering with `u64::MAX` quota
  moves nothing, and in any case states only its own ceiling.
- The negotiation chain refuses a stranger, a party answering itself, a counter
  moved onto another negotiation, and a declared count that disagrees with what
  arrived.
- `listable` resolves the share direction from the author for both fragments
  and deltas, so a delta cannot smuggle a link a fragment would refuse.
- `lock` clears all five new in-memory fields, and `panic_wipe` still routes
  through `lock`.

### The pattern

Findings 1 and the two wiring defects are all **a value or a solved problem
that existed nearby and was not reused**: the window bound was reused where it
should not have been, and the picture path was not reused where it should have
been. Passes 7 and 8 found rules enforced over stale field lists; this one
found the opposite failure, which no enumeration would have caught.

What did catch it was asking, of a value used in a new place, *which of its
meanings applies here* — and the answer being "neither, exactly".

---

## Pass 10 — the three phases, and a phase undoing another

Run against Phases 1–3: RFC 3 §4's expiry state, §8.4's purge, §13's warnings
and §12's panel. **Three findings**, and the middle one is a shape no previous
pass produced.

### 1. `peer forget` left the file it exists to destroy

`peer seal`, `peer renew`, `peer share` and `peer countersign` all write
`<peer>.credential` into the home directory, **in the clear**, for the operator
to hand over. `forget` cleared `peers/<id>/` and stopped.

So the one command whose whole purpose is RFC 3 §8.4's "remove the relationship
record" left behind the single most incriminating file in the layout: a
mutually signed and, per §15, non-repudiable statement that these two agreed to
peer — sitting unencrypted in the working directory, after the operator had
been told the peering was ended and the files shredded.

`forget` now shreds anything in the home directory named for that peer which
`artifact::wiped` recognises.

### 2. Phase 2 undid Phase 1, one tick later

Phase 1 existed for §4's `MUST`: an expired peering must be an explicit state,
"rather than as a silent sync failure — the two look identical from the outside
and confusing them will waste a great deal of operator time."

Phase 2 purged the credential the moment its term lapsed. `credential_standing`
then found nothing, so the operator was told:

```
no credential — nothing is scoped or enforced on this link.
`peer countersign` completes one
```

instead of:

```
**EXPIRED** 3 day(s) ago — this link will not reconcile until it is
renewed. `peer renew <peer>`
```

The reason was destroyed along with the record, and the remaining advice was
**wrong** as well as uninformative: `peer countersign` does nothing for a
peering with no proposal outstanding.

Two `MUST`s from the same document, in sections that never mention each other,
where satisfying the second cancels the first. §4 resolves it and neither
section says so: "revocation is non-renewal" — a peering ends when it is *not
renewed*, not the instant its term runs out. So there is a fortnight's grace in
which the state stays reportable and renewable, and §8.4's purge fires when
declining has actually become true.

**This is the first finding in ten passes where two pieces of correct work
combined into an incorrect whole.** Neither phase was wrong on its own, and
neither review would have caught it: Phase 1's tests pass, Phase 2's tests pass,
and the defect lives in the sentence between them.

### 3. Forgetting one peer silenced another

`TagTable` maps a tag to a **position** in the correspondent slice. That slice
is rebuilt from the peer directories on every inbox refresh; the table rebuilds
only on epoch rollover.

So removing a peering shifted every correspondent after it down one, and a
still-valid peer's tag resolved to somebody else's keys. Decryption failed, and
`correspondents.get(idx)` made that a **miss rather than a panic** — so mail
from an untouched peering simply stopped opening, with nothing reported, until
midnight.

An operator ending one relationship would have watched a different one go
quiet, on the same day, and had no reason to connect the two. `forget` now
invalidates the table.

### What did not fail

- `forget` retains the corpus (§8.4's other `MUST`), asserted alongside the
  purge because the two pull opposite ways.
- The expiry purge takes records and leaves material, so a lapsed peering is
  renewable rather than gone.
- `PeerFile::purged_on_expiry` is a method, so a new per-peer file has to
  answer the question rather than defaulting into an answer.
- §12's aggregates are derived from the budget's two counters and store no
  per-object provenance.
- `Warning::line` renders every variant; a test refuses an unrendered
  placeholder, which is how `Debug` reached operator text in the first place.

### The pattern, and what it changes about the passes

Passes 7 and 8 found rules enforced over stale lists. Pass 9 found a value
reused where it did not fit. **Pass 10 found an interaction** — two correct
features that are wrong together — and that is the first one where reviewing
either change alone was guaranteed not to find it.

Findings 1 and 3 share it in a smaller way: both are a *new* operation failing
to reach state that a *previous* feature owns. The handover file belongs to
Phase 1's renewal path; the tag table belongs to the inbox. Neither was in
front of anyone writing Phase 2.

The practical consequence is that a pass over a phase is not enough. A pass has
to be over the phase **and everything the phase now touches**, which is the
larger and less comfortable question.

---

## Pass 11 — Phases 4 and 5, and the path a feature did not reach

Run against `display` (RFC 8 §7) and `pin` (RFC 8 §10, RFC 7 §8.1), under
Pass 10's rule: the phase **and everything the phase now touches**.

**Two findings, both of them the shape Pass 10 named.**

### 1. The sanitiser was applied to the notes and not to the mail

Phase 4 built `display::safe` because attacker-chosen text reached a pane
verbatim, and applied it to the operator note on a `peer-request` and a
`peer-counter`.

It did not apply it to `Message::body`.

That is the path an operator reads most, and the one that carries text from an
**established peer** rather than a stranger — so the list row and the message
pane both rendered U+202E, ANSI escape sequences and zero-width characters
exactly as they arrived. The list used `.lines().next()`, which happens to
handle a newline and nothing else, and that partial defence is probably why it
looked done.

Both paths now go through `display::safe`, the pane line by line — a control
character in the fortieth line is as good as one in the first.

The uncomfortable part: Phase 4 was *about* this. It found the notes by asking
where attacker-controlled text reaches a list, and answered with two of the
three places. A feature written to close a class of hole left the largest
instance of that class open.

### 2. A background tick threw away what the operator asked for

`warn_before_shredding` set `self.output`, and it is called from
`shred_expired_epochs`, which is called from `tick_schedule` — a timer.

So a tick landing mid-read replaced the answer to whatever command had just
been run, including an error the operator was in the middle of reading. RFC 8
§10 wants the consequence in the foreground, and taking the foreground away
from the operator is not the same thing.

The warning now goes into the message list, which persists where the output
pane does not, and is **appended** to any output already there rather than
replacing it.

### What did not fail

- The pin key is a subkey of the KEK, and a test confirms the archive does not
  open under `W_N` — which is the one thing that would make a pin worthless.
- `pin_key` is derived at both unlock sites and cleared on lock, along with
  `warned_shred_at`.
- The archive refuses a declared count that disagrees with what is present, and
  a truncated file reads as nothing rather than as a shorter archive.
- `confusable_with_known` still refuses to flag an exact quotation, so the mark
  does not fire on ordinary text.
- Pinning is idempotent and bounded.

### The pattern, holding

Pass 10 found two correct phases wrong together and concluded that a pass has
to cover everything a phase touches. Both findings here are that, one layer
in: a **new mechanism not reaching a path an older feature owns**.

`display::safe` is a rule about foreign text; `Message::body` is foreign text
that predates it. `self.output` is the interface's, and Phase 5 wrote to it
from a timer without asking what else writes there.

Neither is found by reading the new code, because the new code is correct. They
are found by asking, of every new rule, **what else is already in its scope** —
and of every new writer, **who else owns what it writes to**.

---

## Pass 12 — Phase 6, and a default word with two directions

Run against Phase 6 — `peer carry`, the burn-rate report — and against what it
touches: `resign_credential`, which Phases 1 and 4 also own, and `Flags`, which
Phase 2 purges.

**One finding, and it is Pass 10's shape again with a sharper point.**

### A renewal silently re-enabled what the operator had turned off

`Flags::default()` holds two things that are not alike:

```rust
a_shares_b: false,      // RFC 3 §8.3 — "opt in to being listed, not out"
b_shares_a: false,
class_mask: 0xFF,       // RFC 6 §281 — admits everything
```

The share bits default to the safe direction and `class_mask` defaults to the
unsafe one, and nothing anywhere had asked whether those were the same
question.

They meet in `resign_credential`. It carries the previous credential's flags
across, so `peer renew` changes the dates and nothing else — but when RFC 3
§8.4 has purged the credential after a lapse, there is nothing to carry, and
the fresh one takes the defaults. Sharing correctly comes back **off**.
Carriage comes back **on**, undoing a decision the operator made and signed,
with nothing said.

Measured, not reasoned:

```text
after carry off, mask admits bulletins: false
after purge+renew,  admits bulletins: true
after purge+renew,  shares peer:      false
```

Neither phase is wrong alone. Phase 2 purges the record because §8.4 says
`MUST`. Phase 6 defaults the mask to `0xFF` because a fresh peering that
refused prekey batches and rollcall entries could not discover anyone. The
defect is that "start from defaults" is safe for one field of a word and not
for another, and the word was treated as one thing.

`resign_credential` now reports whether it started from an agreement or from
defaults, and a renewal that could not carry anything across says so and names
what to check. The default is not changed: an initial credential that excluded
class 1 would break peering discovery for everyone in order to protect a
decision nobody had made yet.

### What did not fail

- `peer carry` goes through the one re-signing path, so the share flags and the
  negotiated terms survive a carriage change and vice versa.
- The mask is not per direction, which is right: a link carrying bulletins one
  way is still moving them.
- `Class::Bulletin as u8 & 7` and `filter::admits`'s `1u8 << (class & 7)` agree
  on which bit is which.
- The burn-rate report claims only what a recipient can know. A node cannot see
  which one-time keys a sender chose, and no consumption count is invented.

### The pattern

Passes 10 and 11 found new work not reaching what older work owns. This one is
narrower and worse: **a single value whose safe direction differs field by
field**, where reading either phase alone gives the right answer and reading
them together gives the wrong one.

The question that finds it is not "what does this touch" but "what does this
*default to*, and is that the safe direction **for each thing it defaults**".
A struct's `Default` is a set of decisions wearing one name.
