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
