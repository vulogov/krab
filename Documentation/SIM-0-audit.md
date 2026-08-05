# SIM-0 — Audit

    Subject:     SIM-0 corpus convergence measurements
    Status:      Complete
    Method:      source review of apps/krab-sim, plus instrumented re-runs
    Raw output:  Documentation/sim-0-runs/sweeps.txt

---

## Summary

Every figure published in `SIM-0-results.md` reproduces exactly from the
source in `apps/krab-sim`. The simulator is faithful to its documentation and
the documentation is faithful to the simulator.

The problem is what three of the columns mean.

1. **LoRa edges carried 0.16% of objects.** A 512 B size gate met a traffic
   distribution whose smallest object is 500 B. Every "LoRa" figure in the
   series describes a network with inert radio links.
2. **The 37.2% coverage headline is a propagation ramp caught mid-flight, not
   a steady-state holding fraction.** Restricted to objects that have had time
   to propagate, the same run measures **76.4%**. Under every configuration
   that meets SIM-0's own minimum-peer and minimum-TTL guidance, settled
   coverage is **100%**.
3. **`storeMB` and `rxMB/d` are p99-across-nodes of a peak-over-time**, not
   means. This fully explains the 1.6× discrepancy between the coverage and
   storage columns.

There is also a live bug (§4) that the LoRa gate was accidentally masking.

Findings 1 and 2 change normative text in RFC 0. Finding 2 changes it in both
directions: the restated premise in RFC 0 §3 is over-corrected, while a new
and sharper privacy problem appears in its place.

## Reproducing

    cargo build --release -p krab-sim
    ./target/release/krab-sim --diag --sweep mix
    KRAB_LORA_GATE=8000 ./target/release/krab-sim --diag --sweep mix

`--diag` and `KRAB_LORA_GATE` were added by this audit. `--diag` reports the
quantities the standard table conflates; it changes no existing output.
Full captured output for all sweeps is in `sim-0-runs/sweeps.txt`.

---

## 1. LoRa links were inert in every published figure

`model.rs` gates LoRa at **512 bytes**. `sim.rs` draws text objects uniformly
from **[500, 8000)** and pictures from [50 000, 500 000). Only 13 of 7500
byte-values in the text range clear the gate, so:

> **0.16% of objects were eligible to cross a LoRa edge**, in every sweep, at
> every parameter setting.

The simulator already computes this as `RunResult::lora_gated_objects`. It is
never read — `cargo build` emits `field is never read`, which is why five
sweeps were published without anyone noticing.

The consequence is that the transport-mix table does not say what it appears
to say:

| published as | actually simulated |
|---|---|
| `tcp+lora` 0.85 / 0.15 / 0 | all-TCP with 15% of edges inert |
| `mixed` 0.70 / 0.15 / 0.15 | 70 TCP / 15 courier / **15 inert** |
| `austere` 0.20 / 0.30 / 0.50 | 20 TCP / 50 courier / **30 inert** |

The austere degree sweep corroborates this independently. At degree 4 under
austere transport, P(a node has no TCP edge) = 0.8⁴ = 41%, and removing the
inert LoRa edges leaves an effective degree of 2.8 — which is why that row
collapses to courier-only performance (56.7% delivery, 1.8% coverage). At
degree 12, 0.8¹² = 6.9% and delivery recovers to 100%. The published "degree
cliff" is a TCP-edge lottery.

### What fragmentation would buy

Raising the gate bounds the benefit of the fragmentation that SIM-0 §9 lists
as unmodelled:

| LoRa gate | austere delivery | coverage | settled coverage |
|---|---|---|---|
| 512 B (published) | 95.8% | 37.2% | 76.4% |
| 8 KB — all text passes | 98.7% | 41.9% | 83.4% |
| 512 KB — everything passes | 97.5% | 38.7% | 79.0% |

Free fragmentation of text is worth **+2.9pp delivery**. That is the ceiling,
and it is modest.

### The capacity arithmetic makes the size gate secondary

The gate was never the binding constraint. From the model's own parameters:

```
LoRa sustained     0.85 B/s × 6 h  = 18.4 KB per sync
                   × 4 syncs/day   = 73 KB/day per link

Required ingress   n=500           = 31 MB/day per node
                   ÷ degree 8      = 3.9 MB/day per peer-share
```

> **A LoRa link supplies ~2% of one peer-share of the flood at n=500, falling
> linearly with network size** — 0.06% at n=2000.

No object size fixes this. LoRa cannot participate in corpus flooding at any
useful scale. RFC 4 already states "no corpus flooding" for LoRa; RFC 0 §8.1
nevertheless presents it as a participating transport in a mix table where it
was inert, and RFC 0 §8.2's guidance for "courier- or radio-dominated"
deployments is grounded only in the courier half.

**Normative consequences.**

- RFC 0 §8.1's mix table MUST state that LoRa edges were inert, or the rows
  MUST be re-measured with a representative gate.
- RFC 0 §8.2's "courier/radio-dominated" row MUST be renamed
  courier-dominated. Radio is unmeasured.
- `shard_filter` and `class_mask` cannot be optional on a LoRa `LinkProfile`.
  They are the only thing that makes such a link mean anything, and this is a
  design conclusion rather than a tuning one.
- The RFC series plan §4 item *"LoRa links are viable at all"* is **not**
  grounded by SIM-0 and must not cite it.

---

## 2. Coverage: the published column measures a ramp, not a holding fraction

`coverage_mean` is computed at `t = horizon` over the live window
`[horizon − TTL, horizon]`. That window includes objects created moments
before the measurement, which cannot have propagated anywhere.

Under IP transport this is negligible: median latency 7.3 h against a 336 h
window, so ~2% of the window is too fresh to count. Under austere transport
median latency is 170.6 h — **more than half the live window is younger than
the median delivery time.** The published figure is a mean over a propagation
ramp.

Two candidate explanations were tested and rejected. The boundary-word
overcount in `count_range` is real but negligible (37.0% exact vs 37.2%
published). Byte-weighting changes nothing (37.4%). The age profile is the
whole effect:

```
austere, TTL 14 d, degree 8 — coverage by object age (youngest → oldest):
    3%    6%   12%   26%   41%   56%   71%   82%
mixed, same run:
   76%  100%  100%  100%  100%  100%  100%  100%
```

Restricted to objects with at least 0.75 × TTL to propagate, the austere run
measures **76.4%**, not 37.2%.

### This over-corrects RFC 0 §3, and under-states a different problem

Settled coverage across every sweep:

| configuration | published coverage | settled coverage |
|---|---|---|
| mixed, n = 100 … 2000 | 98.8% → 96.1% | **100.0% at every n** |
| all topologies (ws / ba / rr) | 97.2–98.3% | **100.0%** |
| all destination models | 97.2% | **100.0%** |
| austere, degree 8, TTL 14 d | 37.2% | 76.4% |
| austere, degree 12 | 85.7% | **100.0%** |
| austere, TTL 21 d | 56.8% | 97.4% |
| austere, TTL 30 d | 69.6% | 99.9% |

Two things follow.

**RFC 0 §3's restated premise is too pessimistic.** Full replication does
hold — wherever the deployment meets SIM-0's *own* minimum guidance. The
37.2% headline comes from austere transport at 14-day TTL and degree 8, and
SIM-0 §4 and §5 independently recommend 21–30 days and 12+ peers for exactly
that transport mix. The figure measures an under-provisioned deployment, and
its coverage is low because the corpus is still in flight, not because it
converges to a third. The apparent coverage decay with network size
(97.1% → 96.1% from n=500 to n=2000) is likewise not decay: settled coverage
is 100.0% at both.

Suggested restatement, replacing RFC 0 §3:

> Full replication holds in any deployment meeting the minimum peer count and
> TTL for its transport mix. Below those thresholds the corpus does not fail
> to converge — it converges more slowly than TTL, so nodes hold a
> propagation ramp rather than a corpus. Delivery is the requirement;
> replication is what a correctly provisioned deployment gets.

**But the age gradient is a real and previously unnamed privacy problem, and
it does not go away at 100% coverage.** Even in the best mixed configuration,
the youngest age bucket sits at 68–86%. Under austere transport it is 3%.
Holding probability is a steep function of object age in every configuration
measured.

Object age is not secret. Blocking item B2 freezes `expiry` into the
permanently-cleartext routing header, so every relay can compute it for every
object it sees. An adversary therefore knows that a one-day-old object under
austere transport is held by ~3% of nodes — so a holder is one of roughly
fifteen out of five hundred, and is likely close to the injection point.

That is RFC 0 §5.3's first-seen gradient attack, recovered from holdings
alone, with no arrival timestamps and no decryption.

**Normative consequences.**

- RFC 0 §7.4 MUST be rewritten around the age gradient rather than around a
  scalar coverage threshold. The scalar is a mean over a distribution whose
  *shape* is the actual attack surface.
- Coverage reported in `presence` capability fields MUST be an age profile,
  not a single number. A scalar is not merely lossy here, it is misleading:
  37% describes no node's actual holding probability for any object.
- The interaction between B2's frozen `expiry` field and holdings analysis
  MUST be resolved **before RFC 1 freezes the header**, because it cannot be
  revised afterwards. Coarsening expiry into buckets is the obvious lever and
  costs nothing structurally, but it must be decided now.
- RFC 0 §8.2's client warnings gain force: under-provisioning is what puts a
  deployment in the weak regime, so the warnings are a privacy control, not
  an availability convenience.

---

## 3. `storeMB` and `rxMB/d` are p99 of a peak, under mean-sounding names

`main.rs` passes `store_p99` and `rx_p99` into the table; the p50 values are
computed and emitted to JSON but never displayed. Worse, the underlying
`peak_bytes` is a **maximum over roughly fourteen time samples**, so the
column is a p99-across-nodes of a peak-over-time — a double maximum.

This fully accounts for the discrepancy between the coverage and storage
columns, which agree to ~1% under good transport and diverge by 1.6× under
austere transport:

| factor | ratio |
|---|---|
| p99 across nodes instead of mean (273.3 / 195.5) | 1.40× |
| peak over time instead of at-horizon (195.5 / 170.5) | 1.15× |
| **product** | **1.60×** |

SIM-0 §2 compares the 447 MB figure against an analytic estimate of 438 MB
and calls it a match. It is comparing a p99 to a mean; that they agree is a
consequence of good transport compressing the distribution, not a validation.

Under good transport the spread is ~0.4%, so RFC 0 §8.3's scale table and the
`ingress ≈ 0.063 MB/day per node per node` law survive unchanged. They are
p99 laws wearing mean labels, which is the conservative direction — but the
labels should say so.

**Normative consequence.** RFC 0 §8.3 and SIM-0 §7 MUST label these columns
p99. An operator sizing storage from a column labelled "live corpus" is
sizing for the 99th-percentile node's high-water mark, which is correct
practice but should be a decision rather than an accident.

---

## 4. Head-of-line blocking in the capacity check

`sim.rs` breaks out of the transfer loop when an object does not fit the
remaining capacity:

```rust
if bytes + sz > cap { break 'words; }
```

It is `break`, not `continue`. Objects are visited in index order, which is
creation order, which is oldest-first. So a single oversized object at the
head of the difference set halts the entire transfer — and halts it again on
every subsequent sync, permanently, because the ordering is stable.

This is visible in the gate sweep in §1: gate = 512 KB scores *worse* than
gate = 8 KB (38.7% vs 41.9% coverage, 97.5% vs 98.7% delivery). Admitting
pictures lets them wedge the link. Adding capability made the system worse,
which is the signature of a blocking bug rather than a capacity limit.

The 512 B gate was masking this by filtering every large object out before
the loop ever saw it. TCP and courier never hit it because their caps are
1 GB and 64 GB.

**Consequence.** This is a simulator bug and does not affect the published
figures, which all ran with the masking gate. It matters because RFC 5 will
implement this same oldest-first-under-capacity loop for real, and fragment
reassembly will put genuinely oversized units at the head of the queue.
Whatever RFC 5 specifies MUST skip and continue rather than halt, and SIM-1
MUST NOT inherit this loop unchanged.

---

## 5. Minor

- **Argument parser reads a value before matching the flag.** `parse()` calls
  `need(i, &a)` unconditionally at the top of the loop, so any bare flag
  (`--quiet`, and now `--diag`) fails with usage text if it is the last
  argument. Documented in the crate README; worth fixing.
- **`lora_gated_objects` is computed and never read.** Wiring it into the
  default output would have surfaced §1 immediately. `--diag` now reports it.
- **Seed values are not published.** SIM-0 §11 claims byte-identical output
  for a given configuration, which holds, but a reader cannot confirm which
  seeds produced the tables without reading `aggregate()` (they are
  `1..=seeds`). State them.
- **Failed seeds are averaged over silently.** `aggregate()` drops seeds whose
  thread returns `None` or panics and divides by the survivors. The `runs`
  column does surface this, so it is honest — but it is easy to miss, and
  under the workspace's `panic = "abort"` profile a panicking seed now aborts
  the process instead.
- **B1 scope.** The RFC series plan asks for 10 000 nodes; SIM-0 measured to
  2 000 and extrapolated. RFC 0 §8.3 marks the extrapolated rows honestly.

---

## 6. Conflict with blocking item B3

The RFC series plan sets **maximum object size at 64 KB** (B3). SIM-0's
traffic model generates pictures of 50–500 KB behind a 512 KB gate, so it
carries objects that RFC 1 would forbid, at up to 8× the cap.

Byte volume is unaffected, so the storage and ingress figures stand. Object
*count* does not: fragmenting pictures to 64 KB raises live object count by
roughly 1.4× (90% text unchanged, 10% pictures becoming ~5 fragments each).

Object count is precisely the basis for manifest sizing, which is the thing
SIM-1 exists to measure. So the plan's §4 item *"corpus size is manageable at
target scale — checked against SIM-0 traffic model"* does not currently
check: the traffic model and the parameter table disagree.

---

## 7. What this implies for SIM-1

> **Resolved.** SIM-1 has since been run against all four priorities below;
> results are in [`SIM-1-results.md`](SIM-1-results.md). The manifest
> arithmetic in this section proved pessimistic in one respect — RFC 5 scopes
> reconciliation to the agreed filter, so the shipped 512 B LoRa gate yields a
> 1.2 KB manifest rather than 448 KB. Once the filter widens to admit ordinary
> text, a full manifest starves 98.3% of LoRa reconciliations, which is the
> failure this section anticipated.

SIM-1's manifest question is now partly answerable by arithmetic, and the
answer is bad enough to be worth stating before building anything:

```
n = 500, TTL 14 d          ≈ 14 000 live objects
full manifest @ 32 B/id    ≈ 448 KB
                           ≈ 24× a single LoRa sync window
                           ≈  6× a LoRa link's entire daily budget
with B3's 64 KB object cap ≈ 627 KB
```

A full manifest cannot cross a LoRa link at n = 500 by more than an order of
magnitude. Combined with §1's capacity result, the question SIM-1 should ask
is not "do manifests fit on LoRa" but "what is a LoRa link for" — which is
RFC 4 and RFC 5 filter design, not a measurement.

Revised priorities for SIM-1, in order:

1. **Reconciliation overhead**, as SIM-0 §9 says — but scoped to identifier
   length and manifest encoding, since those are B3 decisions with a frozen
   deadline.
2. **The adversary model for holdings analysis.** SIM-0 §6 defers the
   coverage threshold to SIM-1. The age gradient in §2 says the threshold is
   the wrong question; the quantity to measure is how much an adversary's
   posterior over injection point sharpens given holdings plus the cleartext
   `expiry`. That has a frozen-header deadline too.
3. Capacity-pressure eviction, which SIM-0 §9 notes will reduce coverage
   further, and which interacts directly with I-6.
4. Fragmentation — but as a fix for §4's blocking bug, not as a way to
   rescue LoRa throughput.

---

## Appendix: changes made to `krab-sim`

Additive only. No existing output path was modified, and all published
figures reproduce byte-identically under the workspace build.

| change | file | purpose |
|---|---|---|
| `cov_exact`, `cov_bytes`, `cov_settled`, `cov_by_age` | `sim.rs` | separate the quantities `coverage_mean` conflates |
| `store_mb_mean`, `rx_mb_day_mean` | `sim.rs` | expose the mean alongside the published p99 |
| `lora_eligible` | `sim.rs` | surface the previously unread gate statistic |
| `--diag` output | `main.rs` | report the above |
| `KRAB_LORA_GATE` env override | `model.rs` | bound the value of fragmentation |
