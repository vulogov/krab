# RFC 1 — Blocking Item Status

    Status:      Working document, not an RFC
    Purpose:     the gate on RFC 1 reaching Draft
    Grounding:   SIM-0-results.md, SIM-0-audit.md, SIM-1-results.md

RFC 1 freezes the object format permanently. The RFC series plan §1 states it
MUST NOT reach Draft until blocking items **B2** (frozen routing header) and
**B3** (parameter table) are settled.

This document tracks exactly which rows are settled, on what evidence, and
what would settle the rest. It exists so that nothing reaches Draft on a
number nobody measured — which is the failure mode SIM-0's audit found in
RFC 0 §8.

Nothing here is normative. When a row is settled it moves into RFC 1 proper.

---

## B0 — Project name

**Settled: `krab`.**

Appears in cryptographic domain-separation strings and in the link frame
magic; frozen permanently once objects exist. Implemented as
`krab_core::DOMAIN`.

---

## B2 — Frozen routing header

**Fields settled: `version`, `expiry`, `tag`, `size`. Nothing else.**

A relay encountering an unknown object version MUST route, filter, and expire
from these four alone, and MUST store and forward the remainder as opaque
bytes. Within a known version, unknown envelope keys MUST be rejected.

### The `expiry` resolution question — resolved

The SIM-0 audit raised this as a deadline item: `expiry` discloses object age
to every relay, and under partial coverage the probability a node holds an
object is a steep function of age, so a permanently-cleartext `expiry` is what
makes differential-holdings analysis tractable.

SIM-1 §3 measured the resulting attack. Using only holdings and cleartext age,
a maximum-likelihood attack over 500 candidate origins:

| deployment | top-10 hit rate (chance 2.0%) |
|---|---|
| mixed or all-TCP, 1–50 vantage points | never beats chance |
| austere, degree 8, TTL 14 d — below SIM-0 guidance | 12.45% at k=25 |
| austere, degree 12 + TTL 30 d — at guidance | 2.50% at k=25 |

**Decision: keep `expiry` at useful resolution.** The leak is a symptom of
under-provisioning rather than of the field, it vanishes when the deployment
meets SIM-0's own peer-count and TTL guidance, and the same age information is
available to any long-lived observer regardless. The mitigation belongs in
provisioning guidance and client warnings (RFC 0 §8.2), not in the header.

Still to specify: the encoding and its unit. Absolute seconds since the Unix
epoch is assumed throughout the simulator and by RFC 5's expiry-resurrection
rule, but the width is unchosen.

**Open:** encoding of all four fields, and the exact byte layout. This is the
remaining work for B2 and it is specification, not measurement.

---

## B3 — Parameter table

| parameter | status | value | grounding |
|---|---|---|---|
| identifier length | **settled** | 32 B | SIM-1 §2 |
| `MAX_TTL` | **settled** | ≥ 30 d, admit 45 d | SIM-0 §4, SIM-1 §3 |
| default shard `k` | **settled** | 0 in v1, field mandatory | SIM-0 §7 |
| epoch length | **open** | — | unmeasured |
| max object size | **open — conflict** | 64 KB proposed | see below |
| size buckets | **open** | — | unmeasured |
| clock skew tolerance | **open** | — | unmeasured |

### Identifier length — settled at 32 B

B3 offered 32 B full versus 16 B truncated within ranges, on the grounds that
identifier length drives manifest size. SIM-1 §2 measured both against the
alternative lever:

- truncating 32 B → 8 B cuts full-manifest overhead **3.3×**
- switching full manifest → RBSR cuts it **80×**, after which identifier
  length is worth 1.4×

The algorithm dominates the identifier by more than an order of magnitude, so
there is no bandwidth reason to weaken content addressing — which I-1 makes
duplicate suppression, loop suppression, and replay resistance rest on.
Truncation remains available later as a range-local encoding detail inside
RBSR, where it is a wire choice rather than a property of the identifier.

### `MAX_TTL` — settled at ≥ 30 days

SIM-0 §4: austere transport delivers 21.3% at 3 days, 95.8% at 14, and 100% at
30. SIM-1 §3 adds a second reason — 30-day TTL is also part of what closes the
holdings leak. SIM-0 measured to 45 days without incident, so admitting 45 is
free.

### Default shard `k` — settled at 0, field mandatory

SIM-0 §7: sharding is mandatory above roughly n = 5 000. The field is inside
the identifier hash and cannot be added later, so it MUST be present in v1
even shipping `k = 0` everywhere.

### Max object size — open, and it conflicts with the traffic model

B3 proposes 64 KB. SIM-0's traffic model generates pictures of 50–500 KB
behind a 512 KB gate, so every published storage and ingress figure describes
a network carrying objects RFC 1 would forbid, at up to 8× the cap
(audit §6).

Byte volume is unaffected, so the storage figures stand. Object *count* is
not: fragmenting pictures to 64 KB raises live object count roughly 1.4×, and
object count is the basis for manifest sizing.

**To settle:** re-run SIM-1's `recon` and `idlen` sweeps with the traffic model
capped at the chosen maximum and fragmentation on (`--sim1`). This is a
half-hour of simulator time, not new code — `--frag` already implements
store-and-forward fragmentation. It should be done before the number is
frozen, because manifest cost is what the identifier-length decision above was
weighed against.

### Epoch length — open, and the hardest

24 h versus 7 d. Sneakernet pushes long, unlinkability pushes short. One clock
and one counter shared by tag derivation, key erasure, and the reservoir
(RFC 0 §11), so the choice is not local to RFC 2.

Nothing in SIM-0 or SIM-1 bears on this. It needs its own measurement: the
acceptance window's interaction with courier latency is simulable with the
existing engine, since SIM-0 already measures the courier latency distribution
(p99 406 h ≈ 17 days under all-courier, 382 h under austere). A 24 h epoch
against a 17-day tail means late-arriving objects land many epochs out.

**To settle:** measure the fraction of delivered objects arriving outside a
candidate acceptance window, per transport mix. The latency percentiles needed
are already in `sim-0-runs/sweeps.txt`; this may not need new simulation at
all, only analysis.

### Size buckets — open

256 / 1K / 4K / 16K / 64K proposed, for size-fingerprint resistance. Interacts
with max object size above and with the LoRa gate: SIM-1 showed a size gate
below the bulk of the traffic distribution disables a link rather than slowing
it (audit §1), and bucket boundaries determine which objects land either side
of a gate.

**To settle:** needs an adversary model for size fingerprinting, which neither
SIM-0 nor SIM-1 has. Candidate for SIM-2.

### Clock skew tolerance — open

± hours, for courier and air-gapped nodes. Interacts with absolute `expiry`
and with the epoch acceptance window. Unmeasured.

---

## Findings from SIM-1 that RFC 1 does not own but must not lose

These change other documents. Recorded here so they are not dropped while
RFC 1 is in progress.

1. **`sync_mode` has no safe default** (SIM-1 §1). A full manifest starves
   98.3% of LoRa reconciliations; RBSR collapses austere delivery from 95.8%
   to 33.0%. RFC 5 must select per `LinkProfile` from `latency_class`, and
   must forbid a full manifest larger than the link's per-window capacity.
2. **Uniform eviction makes the holding set deterministic, not
   uninformative** (SIM-1 §4). RFC 0 §7.4 and SIM-0 §6 both currently claim
   the opposite. A capped node holds exactly the newest N megabytes, so
   storage cap plus object age determines its holdings exactly.
3. **Eviction needs a negotiated age watermark** (SIM-1 §4) or capacity
   pressure becomes a permanent re-fetch loop costing up to 68% extra ingress.
   Belongs in RFC 5's filter, negotiated through RFC 3's retention floor.
4. **RFC 0 §3's restated premise is over-corrected** (audit §2). Full
   replication holds wherever a deployment meets its transport mix's minimum
   peer count and TTL.
5. **RFC 0 §8.1's transport-mix table must state that LoRa edges were inert**
   (audit §1), and §8.2's "courier/radio-dominated" row must be renamed
   courier-dominated. Radio remains unmeasured.

---

## Gate

RFC 1 may reach Draft when:

- [x] B0 settled
- [x] B2 field set settled
- [ ] B2 encoding and byte layout specified
- [x] B3 identifier length
- [x] B3 `MAX_TTL`
- [x] B3 default shard `k`
- [ ] B3 max object size — blocked on the re-run above
- [ ] B3 epoch length — blocked on the acceptance-window analysis
- [ ] B3 size buckets — blocked on a size-fingerprinting adversary model
- [ ] B3 clock skew tolerance
- [ ] External cryptographic review of the composition, not the primitives

The last item is the one the RFC series plan §4 calls out as most important:
the primitives are all standard, the composition is novel, and composition is
where subtle breaks live. It is not something to self-certify.
