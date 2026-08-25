# Milestone 0.1 — Implementation Plan

    Branch:   0.1
    Status:   A–E done. F: two of three gates met; RFC 1 §12's needs a second
              implementation that will not exist, and **0.1 ships with it
              unmet** — the decision and its cost are in §2.2.2.
              Last checked against the tree 2026-08-24.
    Scope:    a message from A to B, over sim, TCP and courier, with lock
              — plus what §5 records as having grown past that

---

## 1. The critical path is clear

An earlier version of this document listed five blockers and implied the work
was gated on them. Re-checking against RFC 7 §5, that was wrong:

| tier | status |
|---|---|
| three-tier prekeys + crypto-shredding | **mandatory in v1** |
| epoch-chunked reservoir | "where a reservoir exists" |

**The reservoir is conditional, so `CRYPTO-REVIEW.md` §1's critical defect does
not block v1 messaging.** It blocks the post-quantum position (RFC 1 §6.5), and
that is serious, but it is not on the path to a working message.

Re-checking the other three the same way:

| item | actually blocking? |
|---|---|
| padding content | **resolved** — zero bytes, RFC 1 §8.1 |
| `admission` presence | **resolved** — absent, RFC 1 §4.2 |
| Ed25519 strictness | no — strict is the safe default; relaxing later is a relaxation |
| X25519 Extract | no — implement RFC 1 §6.2 **exactly as frozen** and mark the deviation |
| low-order rejection | no — additive validation, safe to add unilaterally |
| reservoir construction | no — conditional tier, deferred |

So **nothing blocks the build.** Two of the three crypto findings are safe
defaults an implementation should take anyway; the third is a question about
amending a frozen document, which is a different decision from whether to
write code.

Where a decision was taken unilaterally, the code says so and a test pins it,
so reversing costs an edit rather than an archaeology exercise.

---

## 2. Phases

Ordered by dependency, not by interest. Each phase is independently testable.

### A — foundations · no decisions needed

| crate | work |
|---|---|
| `krab-crypto` | `object_id`, `node_id`, `channel_id`; additive fingerprints for RBSR |
| `krab-core` | filter types (RFC 5 §2) |
| `krab-store` | TTL-bucketed segments, rebuildable index, oldest-first uniform eviction, tombstones, `min_expiry` watermark |
| `krab-proto` | all 8 opcodes, manifest mode, RBSR descent, session state machine |
| — | fuzz targets for the CBOR parser and the state machine (RFC 0 §9) |

`krab-core`'s CBOR and routing header are **done**. The property RFC 0 §9 asks
for — *for any two stores and any filter, reconciliation converges to the
filtered union in bounded rounds under reordering and duplication* — is the
acceptance test for this phase.

### B — cryptography · three defaults taken, all marked

| work | decision taken |
|---|---|
| tag derivation | **as RFC 1 §6.2 is frozen** — `HKDF-Expand(S, …)` with no Extract. Deviation from RFC 5869 §3.3 marked in code |
| X25519 validation | **reject low-order points and all-zero outputs** — additive, RFC 7748 §6.1 |
| Ed25519 verification | **strict** — canonical `S`, canonical encodings, small-order `A` rejected |
| HPKE | `mode_auth` and `mode_base` per RFC 1 §6.1–6.2; suite `0x0001` only |
| prekeys | three-tier, deterministic index per RFC 2 §7.2, sized by correspondents per RFC 2 §7.3 |
| reservoir | **built after all** — see §2.1. `CRYPTO-REVIEW.md` §1 said defer; the post-quantum position was worth more than the deferral |

### C — transport

`Fabric` and `Session` traits, `LinkProfile`, Noise IK over length-delimited
framing. Backends in this order:

1. **sim** — first, because RFC 4 §5.6 makes it the testing seam and everything
   after this is easier with it
2. **courier** — second, because RFC 3 §11.3 is a release gate and the archive
   is the control-message sequence with round trips removed. Building it early
   forces the `Fabric` boundary to be honest
3. **tcp** — third
4. socks/serial — later

### D — node

Poisson scheduler, sync loop, peer metrics, the operator warnings, and **lock**.

Lock per `RFC-7-review.md` §9: one disk root, a memory-residency split.

```
zeroize on lock   tag precomputation table, prekey privates,
                  reservoir chunks, plaintext, composer buffer, the KEK
retain on lock    Noise static, peer credentials, corpus working key,
                  live session state
```

Two tests are the point of this phase, both asserting the *absence* of
behaviour, which RFC 8 §14 identifies as the only durable protection:

- inter-sync intervals are uncorrelated with message events (RFC 5 §6.1)
- **and with lock state** — pausing sync while locked would publish the
  operator's daily rhythm, a worse I-5 violation than mail-driven sync

### E — TUI

ratatui shell: two tabs, 40/60 panes, two-line command pane, zoom. The lock
chord, reachable from every mode including mid-composition. Commands in RFC 8
§5 order. Picture pipeline per RFC 8 §6 — decode, cap pixels before allocating,
re-encode, never hand bytes to a system viewer.

A relay is this same binary, unlocked once at startup and locked immediately
(`RFC-7-review.md` §9.3).

### F — gates

- RFC 1 §12 test vectors, and two implementations agreeing on them
- RFC 3 §11.3: full peering and first message with all interfaces down
- SIM-2 against the implementations through the `sim` backend, not against a
  third model

Status in §2.2.

---

## 2.1 Where the build actually is

This section exists because §5 below was wrong for several months and nobody
noticed. It listed groups, channels and the reservoir as 0.2 while all three
were being built and tested, which means the document that defines the
milestone stopped describing it. A plan that is not checked against the tree is
not a plan, so the check is written down here.

| phase | state | where |
|---|---|---|
| A — foundations | **done** | RFC 0 §9's property is `recon.rs`: converges in both modes, under reordering, under duplication, and through RBSR descent. Fuzz targets exist for CBOR, control frames, objects and ingest |
| B — cryptography | **done, and past its scope** | all four decisions taken and pinned. The reservoir was to be deferred and was built |
| C — transport | **done, and past its scope** | `sim`, `courier`, `tcp` as planned; `socks` (Tor) and `serial` were "later" and exist. Both sync modes now run over a session — see §2.2.1 for how long only one did |
| D — node | **done** | Poisson scheduler, sync loop, peer metrics, lock. Both absence-tests hold: intervals uncorrelated with message events *and* with lock state |
| E — TUI | **done, and past its scope** | shell, chords, zoom, commands, picture pipeline with an out-of-process decoder. Relay mode present |
| F — gates | **two of three met**, the third unmeetable | §2.2 |

Built although §5 called it 0.2: **groups** (`groups.rs`), **channels**
(`channels.rs`), the **reservoir** (`krab-crypto/src/reservoir.rs`), **Tor** via
the `socks` backend, and a serial backend against which the LoRa profile is
modelled.

**Rollcall** and **introduction tokens** were the last two listed as absent and
are both now built — `rollcall.rs` with `bulletin::Kind::Rollcall`, and
`introduction.rs` with `introduce` and `requests`.

Nothing from §5 remains absent. Every feature the plan deferred to 0.2 exists.

## 2.2 Gate status

| gate | state |
|---|---|
| RFC 1 §12 vectors | **unmet, and 0.1 ships anyway — see §2.2.2.** The vectors exist and are checked every run; the second implementation does not and will not exist |
| RFC 3 §11.3, all interfaces down | **met.** `courier_only_peering_completes_with_no_network` drives offer, accept, pad and seal by file copy with no socket; `courier_only.rs` carries a sealed first message across with no round trip |
| SIM-2 through the `sim` backend | **met.** All four items measure the real `Store`, `recon` and `Node`, and `sim2.rs` now drives every reconciliation through `SimFabric` — two halves, two threads, real opcodes — rather than calling `recon::reconcile` on two corpora it holds at once |

### 2.2.2 0.1 ships with the first gate unmet

RFC 1 §12:

> "Two independent implementations MUST agree on every vector before the status
> changes. **For a format that cannot be revised, vectors are the
> specification; the prose is commentary.**"

There is one implementation and there will not be a second. **0.1 ships with
this gate unmet.** That is a decision, recorded here so nobody has to infer it
from an empty checkbox.

What that costs is specific, and it is not "the vectors are untested". It is
that nothing has yet checked this implementation's *reading* of RFC 1. A second
implementation is valuable because it is a second reader: where §6.2 can be
read two ways, two independent readers find out and one does not. Everything
below reduces the surface where that matters; none of it removes it.

**What exists in place of the second implementation:**

- The vectors cover all seven categories §12 enumerates, and are regenerated
  and compared on every test run, so drift fails the suite.
- Every derived value is published **beside the inputs it came from** — the
  literal HKDF `info` bytes, both private keys and the agreed secret, the full
  canonical preimage of each identifier, the header's fields next to its
  encoding. A reader holding RFC 1 can check the constructions by hand.
- `Documentation/vectors/check.py` recomputes all of it in standard-library
  Python, sharing no code with the implementation. It anchors its **own**
  X25519 against RFC 7748 §5.2 and §6.1 and its own HKDF-Expand against
  RFC 5869 §A.1 before checking anything.
- Two tests keep that honest: one runs the checker against the committed file,
  one mutates the file four ways — including writing an epoch big-endian — and
  requires each mutation to be rejected.
- The file marks each block **external**, **derivable** or **drift**, so its
  status is legible rather than uniform.

**What none of that catches.** `check.py` was written by the same author from
the same reading of §6.2. A misreading is reproduced there rather than caught,
and the two agreeing would look like evidence while being none. It is said in
the module header, in the vector file, and in the checker's own output, so the
gate's status cannot be mistaken by someone reading any one of them.

It has already paid for itself once: on its first run it disagreed with the
vector file's own comment about the routing header's byte order, and the
comment was what was wrong.

**What a second implementer inherits.** Not a pass, and not a claim of one —
a file where a disagreement can be *localised*. A failing line comes with the
inputs that produced it, so the answer is "we differ on the epoch's byte
order", not "we differ".

**To change this**, RFC 1 §12 needs a second implementation from a different
reader. Until then this gate stays unmet, and the status line at the top of
this document says so.

### 2.2.1 What the third gate was hiding

Worth recording, because "the test takes a shortcut" turned out to be the
smaller half of it. Routing SIM-2 through the backend the gate names surfaced
two defects that the shortcut had made unreachable:

1. **`SimSession::recv` returned `None` for a momentarily empty queue.**
   `Session::recv` reserves `None` for *"the peer is finished"*, and both
   exchange drivers break on it. A reconciliation over this backend therefore
   ended at the first gap and reported however many objects had crossed by
   then — not an error, a **plausible smaller number**.

2. **Nothing spoke RBSR over a session.** Opcodes 5 and 6 were defined, framed
   and fuzzed, and no driver sent them. `recon::reconcile` implements the
   descent between two corpora it holds simultaneously, which is the algorithm
   but not the protocol. So a link whose `LinkProfile` says `Rbsr` — every TCP
   and LoRa link, per RFC 5 §4.5 — spoke Manifest, and the module said so in
   its own header without that being enough to get it fixed.

Both are closed: `exchange::{initiate_rbsr, respond_rbsr}` drive the descent
over a session, and the TUI now selects the mode from the link's profile
instead of always passing Manifest.

The pattern is §5.1's again. A gate that could not be met was recorded as
unmet, in a milestone file, next to a module header that named the same gap —
and the accurate record was not what closed it. Running the thing was.

---

## 3. What each phase needs that does not exist yet

| phase | needs | from |
|---|---|---|
| A | nothing | — |
| B | nothing to start; the Extract question decides whether B's tags are final | RFC 1 §6.2 amendment or not |
| C | `latency_class` in the credential | RFC 3 §3 key 9 (`RFC-4-review.md` §1) |
| C | per-class shard masks | RFC 5 filter (`RFC-6-review.md` §1) |
| D | draft-on-lock policy | `RFC-7-review.md` §8.6 — discard, seal-to-self, or a short-lived key |
| D | lock chord binding | judgement; default proposed below |
| F | RFC 5's SIM-1 extension | not in the repository (`RFC-5-review.md`) |

None of these blocks starting its phase. Each blocks *finishing* it.

### 3.1 Proposed lock chord

One motion, available from every mode including inside the composer, and
survivable on a terminal that swallows exotic modifiers.

```
Ctrl-L        lock immediately
              redraw moves to Ctrl-R
```

Rejected: a two-key chord. Lock is used when someone walks into the room, and
"immediately" was the author's word. A confirmation prompt is likewise wrong —
it converts a security action into a dialogue at the moment least suited to
one. The cost is a lost draft, which is §8.6's open question and not solvable
by adding a keystroke.

---

## 4. Decisions taken unilaterally, and how to reverse them

Each is a safe default, marked in code, pinned by a test.

| decision | reverse by |
|---|---|
| Ed25519 strict verification | relaxing a check; no data migration |
| low-order X25519 rejection | removing a check; no data migration |
| tag derivation without Extract | **changes every tag** — this is the one with a migration cost, which is why it follows the frozen text rather than the safer construction |
| `Ctrl-L` for lock | configuration |

The third is worth stating plainly: implementing RFC 1 §6.2 as written is the
*conservative* choice for interoperability and the *unsafe* choice against
RFC 5869 §3.3. Doing it the other way round would silently fork the tag space
from the specification. If §6.2 is to be amended, it should be amended before
any object exists.

---

## 5. What 0.1 is not

**This section previously said:** *"No groups, no channels, no rollcall, no
introduction tokens, no reservoir, no LoRa, no Tor. Those are 0.2."* By the
time anyone re-read it, five of those seven were built. It is corrected rather
than deleted, because the way it went wrong is the more useful record.

What is actually absent from 0.1:

Nothing from §5's list, and nothing from RFC 3.

Nothing is built-and-unwired. §8.2's `NODEDIFF` was, for one commit, and is
recorded here because that state is worth naming rather than discovering:
`peer fragment` now sends a full fragment weekly and a delta between, and a
reader applies one against the base it stored or drops it.

Rollcall cost nothing that was not already there: `Class::Bulletin` carried
channels and prekey batches, so RFC 3 §9's whole public tier came to one
payload type, a fourth signing domain and a command. That is the shape the
design predicted, and some evidence the bulletin abstraction is the right one.

Introduction tokens cost more, and the extra was never the tokens. RFC 3 §5.1
puts one at `peer-request` key 6, which was occupied — see `AMENDMENTS.md` #8 —
and evaluating one needs a node that can *see* an inbound request, which none
could: `receive::scan_requests` existed, was tested, and had no caller in the
application. A node could send a first-contact request and never observe one
arriving.

Then §5.1's `evidence` field turned out to rest on a document that did not
exist at all. **RFC 3 §3's mutually signed `peer-link` credential was never
built**: a completed peering stored the counterparty's card, which carries one
signature — theirs — and §3 is explicit that "a singly-signed document lets one
party assert a relationship the other never agreed to … which matters because
these propagate one hop (§8) and are cited as evidence (§5.1)". Sending a card
as evidence would have shipped exactly the forgeable claim §3 forbids.

So `credential.rs` builds §3: both signatures, canonical party order, §4's
60–90 day term with the 180-day ceiling enforced rather than warned about, and
§8.3's share bits defaulting to false. `peer seal` proposes one and `peer
countersign` completes it. `AMENDMENTS.md` #9 records that §3 never says which
party is A, which two implementations must agree on or neither can verify the
other.

None of the three would have surfaced without something needing them. That is
the argument for building the last feature on the list rather than declaring it
optional.

### 5.1 The scope argument, and what happened to it

The original reasoning was sound: *each one multiplies the surface that has to
be right, and nothing here is right until F's test vectors say so.* The
vectors landed; the deferred features were then built anyway, one at a time,
each for a local reason that was good on its own — the reservoir because the
post-quantum position was worth more than the deferral, Tor because RFC 4
specifies it and the backend seam already existed, groups and channels because
RFC 8 §4.2's interface requirements needed something to be an interface *to*.

None of those decisions is being reversed here. What is being recorded is that
the scope grew by accretion and the document did not, so for a stretch nothing
in the repository stated what the milestone contained. That failure has the
same shape as the two `wipe` defects in `artifact.rs` and the third in
`ADVERSARIAL-PASS.md` §7: **a rule written once, and thereafter enforced only
over the things that existed when it was written.** It is the most common
defect in this codebase by a wide margin, and it is now visible in the plan as
well as in the code.

The mitigation is the same as the one that worked for `wipe`: not more
diligence, but a place where an omission fails something. §2.1's inventory is
that place — it names what is built against what was planned, so the next
divergence has to be written down to be missed.
