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

---

## Pass 13 — 2026-08-28 · axis: **the bounds themselves**

Run against the question the previous twelve passes kept answering by
accident: *this value is bounded — by what, and is the bound reachable from
the code that is actually compiled?* Not "is there a check" but "does the
check run".

**Twelve findings, four severe.** Recorded before the work rather than after
it, because three of the four severe ones compose into one attack and fixing
them piecemeal would lose the chain. Finding 1's network path was fixed while
this was being written; everything else here is open.

### 1. SEVERE — RFC 1 §11's I2 is dead code · **partly fixed**

`Store::ingest` takes a TTL ceiling:

```rust
pub fn ingest(&mut self, id: ObjectId, bytes: Vec<u8>, now_min: u32, max_ttl_min: u32)
```

and enforces it at `index.rs:182`, under a comment that states the whole
purpose of the check:

```rust
// RFC 1 §11 check 2 — this is what stops a relay extending TTL to
// force indefinite storage.
if expiry > now_min.saturating_add(max_ttl_min) {
    return Err(Reject::TooFarFuture);
}
```

Every call site outside a test passes `u32::MAX`:

```text
apps/krab-tui/src/shared.rs:299     ← the network path
apps/krab-tui/src/persist.rs:415,444
apps/krab-tui/src/receive.rs:705,888
```

`MAX_TTL` exists only as a constant in `index.rs`'s own test module. So the
saturating add always reaches `u32::MAX`, the comparison is always false, and
`Reject::TooFarFuture` has never fired in a running node.

Measured. An object declaring `expiry_min = u32::MAX - 10_000` — about eight
thousand years out — ingests, and `expire(now)` returns zero for it forever.

**The storage cost is the small half.** `evict_to` is oldest-first, and it
finds the oldest by `self.segments.keys().next()`:

```rust
let Some(&oldest) = self.segments.keys().next() else { break };
```

Buckets are days. The operator's mail sits near bucket 29 000; an object with
a far-future expiry sits near bucket 2 982 616. Under capacity pressure the
node therefore evicts **every real object first** and keeps the injected ones,
and each eviction raises `min_expiry_min`, so `Reject::BelowWatermark`
permanently blocks re-fetching what was dropped. RFC 5 §8's resurrection
defence, applied to the wrong objects, makes the loss unrecoverable by
reconnecting — which is exactly what `enforce_retention`'s own log line warns
the operator about.

The bound that was missing is not missing. `enforce_retention` declared
`const MAX_TTL_MIN: u32 = 45 * 1440` and passed it to `prune_tombstones` on
the next line. Five lines away, the same tick, the same function.

**A fix for the network path landed in the working tree while this was being
written, and is not committed.** `MAX_TTL_MIN` now lives in `krab_core::tag`
beside `MAX_TTL_DAYS`, the two function-local copies are gone, and
`ExchangeView::put` passes it. That is the right shape: it closes the
reachable attack, and it closes finding 2 with it by making the top bucket
unreachable. It is recorded here as reported rather than as verified — this
pass measured the defect, not the repair.

Three call sites still pass `u32::MAX`, and they are not all the same
question:

- `courier.rs:161` — **untrusted.** A courier archive is input from a medium
  a stranger may have written; it takes the same ceiling as the socket.
- `main.rs` and `receive.rs` — this node's own objects, composed locally.
  Harmless today, and each is one edit away from not being, because nothing
  distinguishes them from the two above at the call site.
- `node.rs:81` — **worse than `u32::MAX`, and the reason to look at these one
  by one.** `StoreView::put` is `krab-node`'s reference `Corpus`
  implementation, and it derives *now* from the object being ingested:

  ```rust
  self.0.ingest(id, bytes, h.expiry_min.saturating_sub(1), u32::MAX);
  ```

  With `now_min` taken from the expiry, `expiry <= now_min` is false for every
  object and `expiry > now_min + max_ttl` is false for every object. Both of
  I2's time checks are vacuous by construction, so an already-expired object
  ingests as readily as a far-future one. Nothing in the interface uses
  `StoreView` — the TUI has its own `ExchangeView` — so this is a trap rather
  than a live path, sitting in the implementation a second client would copy.

### 2. SEVERE — the top bucket overflows the expiry arithmetic · **latent**

Reachable only through finding 1, which is why it survived six passes, and
closed by finding 1's fix rather than by anything here. The arithmetic is
still wrong; what changed is that nothing can reach a bucket high enough to
overflow it. Recorded because the next caller to pass a wider ceiling reopens
it, and because the release-mode symptom is the one worth recognising.

`bucket_of(u32::MAX)` is 2 982 616, and both `expire` and `evict_to` compute a
bucket's upper edge the same way:

```rust
(b + 1) * crate::segment::BUCKET_MINUTES        // index.rs:340, 349, 383, 389
```

`2_982_617 × 1_440` is 4 294 968 480. `u32::MAX` is 4 294 967 295.

Measured, both profiles, from one ingested object:

```text
debug   — panicked at index.rs:340: attempt to multiply with overflow
release — wraps to 1185
```

The debug case is a remote peer crashing the node with one object in one
frame. The release case is worse, because it is quiet. 1 185 is less than
`now_min`, so the far-future segment is unlinked as if it had already expired
— and the next line keeps its index entry, because the comparison there is
against the expiry rather than the bucket:

```rust
self.index.retain(|(e, _), _| *e > now_min);    // u32::MAX > now_min
```

`index` and `segments` now disagree, and the two halves of the reconciliation
interface read different ones:

| method | reads | sees the phantom |
|---|---|---|
| `count_in_range`, `entries_in_range`, `len` | `self.index` | yes |
| `range_fingerprint` | `self.segments` | no |

So the node's own count and fingerprint disagree about the same range, and its
manifest advertises an identifier `get()` cannot serve. The peer `Want`s it,
receives nothing, and asks again next session. Every session. `rebuild_index`
repairs it, which means the symptom is a node that reconciles correctly until
it has been up long enough to hit `expire`, and then never converges again
until it is restarted.

### 3. SEVERE — control messages are free, and answering them is not · **open**

RFC 3 §6 is "the central mechanism of this document", and `ExchangeView::put`
implements it faithfully — for objects. `Range` is not an object. It is never
charged, and `MAX_MESSAGES` permits 65 536 of them in one session.

Measured against a 100 000-object corpus, for the 1 600 rows that fit in one
64 KB frame:

```text
stored 100000
1600 count_in_range   over 100000 objects: 210.678708ms
1600 range_fingerprint over 100000 objects:  7.920745042s
```

`recon::respond` calls `describe` — which is one of each — once per offered
range, and up to `RBSR_BRANCH` times more in the descend arm. Eight seconds of
a core for 64 KB of upload, on a session bounded only at 65 536 messages.

Two avoidable scans produce it. `count_in_range` and `entries_in_range` filter
`self.index.keys()` although `index` is a `BTreeMap<(u32, ObjectId), _>` whose
ordering is exactly the one being filtered on — `.range()` is available and
unused. And `range_fingerprint` computes

```rust
let whole = b > lo_b && b < hi_b;
```

which is never true when `lo_b == hi_b`, so a range narrower than a day always
takes the per-identifier edge-bucket scan with a `locate()` lookup for each.
The attacker chooses the range width, so the attacker chooses which branch.

The pattern is the one Pass 6 named and did not finish: a property that holds
for five objects and fails for a hundred thousand. Pass 6 measured the corpus
against convergence. Nothing had measured it against a peer choosing the
question.

### 4. SEVERE — both link bounds default to "unlimited" · **open**

```rust
fn scope_for(&self, peer: &str) -> filter::Filter {
    self.credential_with(peer)
        .map(|c| filter::Filter::from_credential(&c))
        .unwrap_or_else(filter::Filter::unscoped)
}

fn budget_for(&mut self, peer: &str) -> Option<shared::Budget> {
    let terms = self.inbound_terms(peer)?;      // None without a credential
    …
}
```

`Filter::admits` returns `true` on its first line for an unscoped filter, and
`put` skips the quota block entirely when `budget` is `None`. So a peering
whose credential ceremony was never completed reconciles with no retention
horizon, no class mask, no shard, and no byte or object budget.

That is the configuration finding 1 needs. The two mechanisms RFC 3 builds to
bound a link both degrade to *unlimited* in the absence of the artifact that
configures them, when the whole argument of §6 is that you peer with a
stranger at 1% trust.

**And a credential does not reliably restore the horizon either.**
`Filter::admits` skips the retention check entirely when `retention_days` is
zero:

```rust
if self.retention_days > 0 {
    let horizon = now_min.saturating_add(self.retention_days.saturating_mul(1_440));
    if header.expiry_min > horizon { return false; }
}
```

while `Filter::between` derives the field as `a.min(b)`, on the stated
reasoning that a floor commitment is the narrower of the two. Zero is the
narrowest number and the widest policy. One reader treats it as "the tightest
commitment either side offered"; the other treats it as "no commitment at
all", and no code anywhere reconciles them. A negotiated credential naming
zero days is a filter that admits every expiry there is.

Pass 12's closing question, applied one level up from a struct field:
**what does this default to, and is that the safe direction.** Pass 12 asked
it of `Flags::default()`. Nobody had asked it of `Option::None`, and nobody
had asked it of a zero that two functions read in opposite directions.

### 5. `display::safe_block` is quadratic · **open**

`out.chars().count()` is evaluated once per appended character, against a
bound of `MAX_BLOCK = 512 * 1024`:

```rust
if out.chars().count() >= MAX_BLOCK {      // display.rs:164
```

Measured, release build:

```text
   1000 chars ->  94.791µs
  10000 chars ->   3.776ms
  50000 chars ->  55.317ms
 100000 chars -> 148.499ms
 262144 chars ->   1.0027s      ← the largest body an object can carry
```

`show_selected` runs it on the interface thread, so arrow-keying onto a
hostile message freezes the interface for a second — and Pass 4 established
what that costs: a frozen interface takes the lock chord with it, which is the
one keystroke an operator might need urgently. The module's own bound is the
attack surface: 512 KiB was chosen so that "no message this protocol can
carry hits it", and the cost of walking to it was never priced.

`a_block_is_still_bounded` accounts for about four seconds of the test suite
and has been paying for this in every run since it was written.

### 6. Invisible characters walk past both halves of RFC 8 §7 · **open**

`is_dangerous` removes the C0 controls, U+202A–202E, U+2066–2069,
U+200B–200F, U+FEFF and U+2061–2064. `skeleton` filters on the same predicate,
so anything `is_dangerous` misses is carried into the confusable comparison
intact.

Measured — for each of these, `safe()` reports `removed == 0` and
`confusable_with_known` returns `None` against a known short id of
`0797c2c1`:

```text
SOFT HYPHEN          U+00AD
ARABIC LETTER MARK   U+061C     ← a bidi control, and not in the two ranges above
HANGUL FILLER        U+3164
TAG LATIN SMALL A    U+E0041
VARIATION SELECTOR-1 U+FE00
```

The control holds: `pay 0797с2c1 now` with a Cyrillic `с` *is* flagged. So the
mechanism works and is walked around, which is the worse of the two outcomes.

No homoglyph is needed. A soft hyphen inside an otherwise exact short id
renders as nothing — ratatui drops U+00AD, U+061C and U+3164 before they reach
the terminal — and changes the skeleton, so the note reads as the identifier
and is not marked. The module states its **confusables table** is a subset and
says what that costs. It does not state that its **removal set** is one, and
the removal set is what the skeleton depends on.

The fix is not a longer list. `char::is_control` is category Cc; what this
wants is Cc, Cf, Cn, Zl and Zp — a predicate rather than an enumeration, with
the enumeration kept only for the ranges a predicate would miss.

### 7. One body path skips the sanitiser · **open**

In `show_selected`, the post-detail branch sanitises:

```rust
display::safe_block(text).text                  // main.rs:5808
```

and the channel-overview branch, twenty lines below, does not:

```rust
posts.join("\n")                                // main.rs:5825
```

`channel_posts` builds those from `String::from_utf8_lossy(&p.payload)` —
signed, but written by somebody else. Not escape injection: ratatui 0.29 drops
Cc characters before the backend prints, which I verified rather than assumed.
But U+200D and U+2028 survive into the buffer, and everything in finding 6
survives everywhere.

Found while reading for something else: `channel_posts` scans the entire
corpus and decodes every object in it on **every keystroke** that moves the
list cursor.

### 8. The picture decoder's parent trusts one number it says it does not · **open**

`cells_isolated` checks the child's framing, under a comment that is exactly
right about why:

```rust
// The parent checks the child's arithmetic. A compromised child is not
// bound by anything inside it, so its framing is input like any other.
if n.saturating_mul(w).saturating_mul(6) != out.len() - 8 {
    return Err(Error::Corrupt);
}
let mut grid = Vec::with_capacity(n);
```

`n = u32::MAX, w = 0` satisfies it — `0 == 0` — for an eight-byte reply. The
`with_capacity` that follows is over a 24-byte element and asks for about
100 GB. The saturating multiplications were added so the check could not
overflow; nothing bounds `n` when the product is zero for the other reason.

### 9. A truncated length prefix reads as a clean close · **open**

`frame::read` and `read_bytes` map `UnexpectedEof` on the four-byte length to
`Ok(None)`, which is the value that means "the peer finished". One to three
bytes then a cut connection is indistinguishable from a polite goodbye. RFC 0
I-4 makes an unreachable peer normal, which is the argument for not escalating
— it is not an argument for the two being the same value.

### 10. `Control::parse` is malleable · **open**

The outer array length is read and never reconciled against what the opcode
consumed, and `Reader::is_done` is never checked, so trailing bytes inside a
frame parse cleanly. Control messages are never hashed, stored or relayed, so
nothing rests on their canonicity today — but `write(parse(x)) != x` is a
property RFC 4 §5.5 will need the moment an archive is signed.

Separately, `u32::try_from(v)? as u16` truncates for both fields that use it:
a `Hello` declaring version 65 536 parses as version 1's, and a `Bye` with
reason 65 536 reads as reason 0.

### 11. The workspace's only `unsafe` is UB, and it is in a test · **open**

`apps/krab-tui/src/line.rs:294` reads `Vec::spare_capacity_mut()` as
initialised `char` to assert that `take()` overwrote the passphrase. Reading
uninitialised memory is UB, and an arbitrary bit pattern is not a valid
`char`, so the assertion is not sound evidence for the thing it is checking —
a compiler entitled to assume validity is entitled to fold the check away.
The property is worth testing; the observation has to be made through
initialised memory.

`apps/krab-tui` is also the only crate in the workspace without
`#![forbid(unsafe_code)]`, which is why this compiles at all.

### 12. A file that cannot exist on Windows is tracked · **open**

A zero-byte file named `` .num()).unwrap_or(0);|X| `` — a shell redirection
that got away — has been in the tree since ce22d72. `|` is not a legal
filename character on Windows, so `git clone` fails there outright. RFC 0 §9's
argument is that a user must be able to verify the binary without trusting the
author; a checkout that fails on a major platform is the first step of that
failing.

### What did not fail

- **The CBOR reader.** It borrows throughout, allocates nothing, checks every
  declared length against the input rather than trusting it, and enforces all
  five of RFC 1 §4.3's rules including the ones a general library would not.
  I tried to find a length it would trust and could not.
- **`frame::read`'s bound.** `MAX_FRAME` is checked before the allocation, in
  both the control and the raw path, which is the rule finding 9 in Pass 3 was
  about. It held.
- **The picture decoder's isolation.** A separate process, a 20-second kill,
  a 64 MB output cap, and a fallback that is reported rather than silent.
  Finding 8 is one arithmetic gap in an otherwise complete boundary.
- **`transcode`'s pixel cap.** Taken from the header before any decoder
  allocates, then re-checked against what the decoder actually produced, which
  is the check that closes the gap the first one leaves.
- **Constant-time comparison where it is load-bearing.** `noise.rs` uses
  `subtle::ConstantTimeEq` for the key check. The one non-constant comparison
  I found, `rekey_run.rs:200`, is over a value both ends derive from the same
  root inside an already-authenticated session.
- **`chunks_exact` everywhere**, with a `% 32 != 0` rejection in front of each
  of the three sites, so a trailing partial chunk is refused rather than
  silently dropped.
- **The build.** Clean `clippy` across the workspace with `--all-targets`,
  clean `cargo test --workspace --release`, and `#![forbid(unsafe_code)]` on
  all six library crates.

### The pattern

Passes 7 through 12 found new work not reaching what older work owned. This
one is a different shape, and it is the one a reader is least likely to catch:
**every finding here is a bound that exists, is documented, is correct, and
does not run.**

I2's ceiling is implemented and every caller disables it. The quota is
implemented and does not cover the message class that costs the most to
answer. The filter is implemented and returns `true` on its first line for the
configuration an attacker would choose. The sanitiser is implemented and its
removal set is narrower than the check that depends on it. In every case the
code that would have to be read to see the defect is not the code the comment
is attached to.

That is why grepping for the check finds nothing. The question that finds
these is not "is this bounded" — the answer is always yes, in writing, next to
the bound. It is **"who supplies the bound, and what do they actually pass"**,
which is a call-site question rather than a definition question, and none of
the twelve previous passes had asked one.

Two of the four severe findings compose: 1 makes 2 reachable, and 4 makes 1
reachable from the network. A pass that had found any one of them alone would
have priced it as a nuisance.

---

## Pass 14 — 2026-08-29 · axis: **the frame ceiling**

RFC 4 §4.2 gives every link one hard number: a frame is at most 65 535 bytes.
`frame::write` enforces it, and its doc comment is emphatic about validating
before allocating. This pass asked the mirror-image question, which no previous
pass had: **not "is the input bounded" but "is the output".**

Every finding below is a message this node builds and cannot send.

Baseline before starting: `cargo test --workspace` 780 passing, `cargo clippy
--workspace --all-targets --all-features` clean, `#![forbid(unsafe_code)]`
intact on all six library crates.

### 1. CRITICAL — two of the six size buckets cannot be put on a link · **open**

RFC 1 §8.1's bucket ladder and RFC 4 §4.2's frame ceiling were never compared.

```text
bucket 0 (    256 B object) -> Control::Obj =     261 B  frame::write = ok
bucket 1 (   1024 B object) -> Control::Obj =    1029 B  frame::write = ok
bucket 2 (   4096 B object) -> Control::Obj =    4101 B  frame::write = ok
bucket 3 (  16384 B object) -> Control::Obj =   16389 B  frame::write = ok
bucket 4 (  65536 B object) -> Control::Obj =   65543 B  frame::write = REFUSED
bucket 5 ( 262144 B object) -> Control::Obj =  262151 B  frame::write = REFUSED
```

Bucket 4 misses by **eight bytes** — the CBOR array head, the opcode and the
byte-string head. `MAX_OBJECT` is 262 144 and equals the largest bucket, so a
third of the defined object sizes are unreachable over any live link. The same
ceiling binds twice: `StreamSession::send` hands the plaintext to
`noise.write_message`, and a Noise transport message has the identical 65 535
ceiling, so removing the check in `frame.rs` would not help.

**These objects are routinely created.** `picture.rs` shrinks an image until it
fits `MAX_OBJECT` — bucket 5, by construction — and `compose::bucket_for`
searches all six buckets. Any picture over roughly 16 KiB lands in a bucket that
cannot be transferred.

The runtime consequence is not a dropped object. `serve_wants` is

```rust
session.send(&Control::Obj(bytes))?;        // exchange.rs:584
```

so the `Err(Error::Frame)` propagates out of the exchange and **ends the
session**. The peer asked for the object, gets nothing, and asks again next
session — every session, for as long as the object is held. One legal picture
in the corpus permanently breaks reconciliation with every peer on every live
link, and RFC 0 §6 guarantees nobody is told.

A hostile peer does not need to compose one: it needs to get one object into
the corpus, which is what the protocol is for.

The courier path is the exception, and by accident rather than design —
`courier.rs:117` writes `if session.send(...).is_ok()`, so an archive skips the
object instead of dying. The two paths disagree about whether an unsendable
object is fatal, and neither chose.

### 2. SEVERE — the RBSR arm's manifest has no cap · **open**

Pass 6 finding 13 was "a corpus above one manifest never converged", and the fix
was `.take(MAX_PER_EXCHANGE)`. It was applied to the two manifest-mode sends,
at `exchange.rs:215` and `exchange.rs:297`. **The RBSR arm has a third send and
did not get one:**

```rust
if !answer.list.is_empty() {
    session.send(&Control::Manifest {
        filter_digest,
        entries: answer.list,          // exchange.rs:487 — no `.take`
    })?;
}
```

`respond` fills `answer.list` from `local.entries(r.lo, r.hi)` for every range
it resolves as a leaf, and nothing bounds the total across ranges. Measured, two
peers holding disjoint halves of the same window:

```text
n= 10000  round 4: Manifest frame =   110 039 B   <-- over
n= 20000  round 4: Manifest frame =   220 039 B   <-- over
n= 50000  round 4: Manifest frame =   550 039 B   <-- over
n=100000  round 4: Manifest frame = 1 100 041 B   <-- over
```

It breaks at about **10 000 objects** — below the smallest corpus RFC 1 §9.3's
own table sizes, and the same threshold class Pass 6 already paid for once.

### 3. SEVERE — the RBSR descent list has no cap either · **open**

The other send in the same arm:

```rust
session.send(&Control::Range(out))?;   // exchange.rs:505 — no cap
```

Each offered range that differs and is not a leaf contributes `RBSR_BRANCH` = 16
described sub-ranges, and `respond` iterates every offered range. Same two
peers:

```text
n= 10000  round 3:   801 ranges, Range frame =  36 051 B
n= 20000  round 3:  1376 ranges, Range frame =  61 925 B
n= 30000  round 3:  1760 ranges, Range frame =  79 205 B   <-- over
n=100000  round 3:  2928 ranges, Range frame = 131 765 B   <-- over
```

Breaks between 20 000 and 30 000 objects. `RBSR_MAX_ROUNDS` bounds the number of
rounds and says nothing about the size of one.

Note what findings 2 and 3 mean together: for any corpus over ~10 000 objects,
**RBSR mode cannot complete a descent** — and `LatencyClass::Interactive` and
`Batch` both select it, which is every TCP and Tor link.

### 4. Why 780 tests and thirteen passes did not see any of this · **root cause**

`SimSession::send` never serialises the message:

```rust
w.a_to_b.push_back(msg.clone());       // backend/sim.rs:119
```

It moves a `Control` between two `VecDeque`s. There is no encoding step, so
there is no length, so **`MAX_FRAME` does not exist on the simulated
transport.** SIM-2, the convergence measurements, and every test that drives
the real reconciliation state machine run over this backend. The state machine
has never once been exercised against the one constraint every real link has.

Demonstrated directly:

```text
Obj(bucket 4)          65543 B on the wire | sim backend: accepts | real framing: REFUSES
Manifest(5000 rows)   110039 B on the wire | sim backend: accepts | real framing: REFUSES
```

`CourierSession::send` and `StreamSession::send` both go through the framing
and would have caught all three. Neither is what the tests drive at scale.

This is the first finding in fourteen passes that is a property of the *test
harness* rather than of the code under test, and it is why the three above
could survive a suite that is otherwise thorough enough to have caught them
individually.

### 5. SEVERE — one silent socket denies all inbound peering · **open**

`Listener::accept` completes the Noise handshake inline, and the comment says
so deliberately:

```rust
// **RFC 4 §12's concurrency cap, satisfied at one.** This loop is the only
// caller of `accept`, and `accept` completes the handshake before returning
// — so there is never more than one in-progress handshake, against the SHOULD
// of four. That is a structural property, not a counter.
```

It satisfies a cap of four by never exceeding one, which also means a single
handshake is the only handshake. An earlier fix added `HANDSHAKE_TIMEOUT_S` =
10 to stop a silent caller holding the loop "for good" — but bounding it at ten
seconds does not close the attack, it prices it.

An unauthenticated attacker connects and sends nothing. The accept loop spends
ten seconds on that socket; every real peer waits in the TCP backlog and gives
up at its own end. Keeping one connection in flight — about **one connection
every ten seconds, from one socket, with no data sent** — denies inbound
peering completely and indefinitely. There is no cost to the attacker and
nothing in the activity log, because a failed handshake is deliberately
reported as `Ok(None)`.

The cap RFC 4 §12 asks for is a *bound* on concurrency, not the absence of it.
Satisfying it structurally at one is what makes the loop a single point of
serialisation.

### What did not fail

- **`krab-core::cbor`.** Non-allocating, non-recursive, borrows throughout. A
  declared length can only fail to fit the input. All five §4.3 rules enforced
  where they are claimed.
- **`walk_body`.** Iterative with `MAX_BODY_DEPTH` = 8 and `checked_mul` on
  every map count — pre-authentication nesting cannot choose the stack depth.
- **`Store::ingest`.** All six of RFC 1 §11's checks present and in the order
  §11 requires, I5 first and unconditional.
- **`frame::read_len`.** Pass 13 finding 9 fixed: a partial header is now
  `Err(Frame)` rather than a clean close.
- **`Control::parse`.** Pass 13 finding 10 fixed: the outer array length is
  checked against `Control::arity`, so the encoding is no longer malleable.
- **`fold_range`.** Pass 13 finding 3's two scans fixed — `BTreeMap::range`
  and maintained segment aggregates, with the `intact` test corrected. The
  early return makes the `hi_min - 1` underflow unreachable.
- **`bucket_end`.** Pass 13 finding 2 fixed: returns `u64`, and `bucket_start`
  saturates. The top-bucket overflow is gone.
- **The workspace's `unsafe`.** Pass 13 finding 11 fixed; nothing outside
  `lock.rs`'s deliberately-named overwrite remains.
- **`NotRandom`.** Reachable only from test modules. `OsRng` fails closed
  rather than degrading.
- **`RoutingHeader::parse`.** Validates `size_bucket` against `BUCKETS.len()`
  before anything indexes it.

### The pattern

Pass 13 ended on "who supplies the bound, and what do they actually pass" — a
call-site question. This pass is the same question asked in the other
direction, and it turns out nobody had asked it at all: **every bound in the
system is written as a check on what arrives.** `frame::read` validates before
allocating. `Control::parse` pushes rather than pre-sizing. `ingest` runs six
checks. The receive path is genuinely hardened.

The send path has one check, in `frame::write`, and it is the last thing that
happens. Nothing upstream of it knows the number exists. `respond` builds a
response of whatever size the corpus implies; `serve_wants` sends whatever
`get` returned; `compose` picks whatever bucket the plaintext needs. Each is
correct in isolation and none is reconciled with 65 535.

Findings 1, 2 and 3 are one defect wearing three hats, and finding 4 is why it
was invisible: **the simulator models a transport with no frame.** A test
harness that omits the single constraint the layer exists to impose will
validate a state machine that cannot run anywhere.

Finding 5 is separate and is the older shape — a bound satisfied so
structurally that the structure became the vulnerability.
