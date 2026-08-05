# SIM-1 — Reconciliation Overhead and Holdings Analysis

    Status:      Complete
    Simulator:   apps/krab-sim, SIM-1 features behind flags
    Raw output:  Documentation/sim-1-runs/sweeps.txt
    Requires:    SIM-0, and the corrections in SIM-0-audit.md

SIM-0 named reconciliation overhead its most significant omission. RFC 0 §7.4
deferred to SIM-1 the coverage threshold below which possession becomes
evidence. The SIM-0 audit added a third item with the same deadline: an age
gradient in holdings, readable from the cleartext `expiry` field that blocking
item B2 freezes permanently.

This document answers all three. All are decidable before RFC 1 freezes.

SIM-1 is implemented as flagged extensions to `krab-sim` rather than a
separate program, so every result below is measured on the *same* network, with
the same seeds and the same generators, as the SIM-0 figure it is compared
against. With no flags, `krab-sim` reproduces SIM-0 byte-identically; that is
the regression check.

---

## Summary

1. **The two constrained transports demand opposite reconciliation
   strategies, and each choice is catastrophic on the other link.** A full
   manifest starves 98.3% of LoRa reconciliations. RBSR collapses austere
   delivery from 95.8% to 33.0%, because each descent level costs a courier
   round trip of three days each way. RFC 5 must select per `LinkProfile`,
   and neither default is safe.

2. **Blocking item B3's identifier-length question is dominated by the
   sync-mode question.** Truncating identifiers from 32 B to 8 B cuts full
   manifest overhead 3.3× — but RBSR cuts it 80×, and under RBSR the
   identifier length is nearly irrelevant. Krab can keep 32-byte identifiers
   and full collision resistance; it should buy bandwidth with the algorithm,
   not with the hash.

3. **The holdings leak is a symptom of under-provisioning, not an inherent
   property.** Under any transport mix meeting SIM-0's own minimum peer count
   and TTL, a maximum-likelihood origin attack does not beat chance. Under
   austere transport *below* that guidance it beats chance by 2–8×.
   Provisioning to the guidance closes it.

4. **Capacity-pressure eviction inverts the age gradient and makes the
   holding set fully determined.** This is the most consequential finding, and
   it is not in any current document. It also raises ingress by up to 68%
   through a re-fetch loop.

---

## 1. Reconciliation overhead

SIM-0 treated manifest exchange as free. SIM-1 charges it against the same
per-sync capacity as payload, for both strategies RFC 5 contemplates:

- **Full** — each side names every identifier it holds within the filter.
  One round trip. Cost is linear in corpus size.
- **RBSR** — descend a `b`-ary fingerprint tree over `(expiry, id)`, pruning
  ranges that agree. Cost is linear in the *difference*, but costs
  `ceil(log_b m)` round trips.

### At the shipped LoRa filter width, SIM-0's conclusions survive

| mix | mode | delivery | LoRa ctl% | courier ctl% | TCP ctl% |
|---|---|---|---|---|---|
| all-tcp | full | 100.0% | — | — | 28.6% |
| all-tcp | rbsr | 100.0% | — | — | 0.34% |
| mixed | full | 100.0% | 94.9% | 18.6% | 21.8% |
| mixed | rbsr | 100.0% | 95.0% | 0.2% | 0.27% |
| courier-heavy | full | 100.0% | 93.5% | 10.0% | 16.5% |
| courier-heavy | rbsr | 99.4% | 93.7% | 0.2% | 0.22% |
| austere | full | 95.8% | 89.6% | 0.4% | 5.6% |
| austere | rbsr | **33.0%** | 90.3% | 0.1% | 0.48% |

Charging overhead does not move the SIM-0 delivery figures under a full
manifest. That is not a vindication of the omission — it is a consequence of
the 512 B LoRa gate admitting 0.16% of objects (audit §1). Reconciliation is
correctly scoped to the filter, so a filter that admits almost nothing yields
a manifest of almost nothing: 1.2 KB against an 18.4 KB window.

Even so, **90–95% of every byte a LoRa link carries is control traffic.** The
link moves 0.1 KB of payload per reconciliation.

### With the filter widened, a full manifest starves the link outright

The realistic case once fragmentation exists — LoRa admits ordinary text:

| mix | mode | LoRa ctl% | LoRa ctl KB/sync | LoRa payload KB/sync | **starved** |
|---|---|---|---|---|---|
| mixed | full | 99.0% | 18.1 | 0.2 | **98.3%** |
| mixed | rbsr | 34.0% | 6.8 | 13.3 | 0.3% |
| courier-heavy | full | 98.5% | 18.1 | 0.3 | **97.8%** |
| courier-heavy | rbsr | 43.4% | 8.4 | 11.0 | 3.6% |
| austere | full | 93.0% | 17.2 | 1.3 | **89.4%** |
| austere | rbsr | 60.5% | 11.3 | 7.4 | 40.3% |

*Starved* is the share of reconciliations in which control traffic consumed
the entire window and no payload moved at all — the failure SIM-0 could not
see. RFC 0 §9 predicted it in words; this measures it.

RBSR raises useful LoRa throughput from 0.2 KB to 13.3 KB per sync, a **66×
improvement**, and eliminates starvation.

### But RBSR destroys courier links

The same table's first block: austere delivery falls from **95.8% to 33.0%**
under RBSR. With ~14 000 live objects and `b = 16`, the descent is four
levels; a courier round trip is three days each way, so one reconciliation
takes 21 days against a 14-day TTL. The objects expire in flight.

This is a genuine conflict, not a tuning preference:

> **LoRa requires RBSR. Courier forbids it.** Both are constrained links, and
> the correct choice for one is catastrophic on the other.

**Normative consequences.**

- RFC 5's `sync_mode` MUST be a per-`LinkProfile` property with no global
  default, and the profile MUST derive it from `latency_class` rather than
  from bandwidth alone. A link that is both slow and high-latency has no good
  option and should be told so.
- RFC 5's existing rule — "courier and high-latency mode: full manifest, one
  round trip, zero-round-trip algorithms only" — is correct and now has a
  number behind it.
- The corresponding rule for constrained-bandwidth links is missing and must
  be added: a full manifest MUST NOT be used where the manifest for the
  agreed filter exceeds the per-window capacity. Clients can compute this
  from the filter and `LinkProfile` before ever attempting a sync.

---

## 2. Identifier length (blocking item B3)

B3 offers 32 B full versus 16 B truncated within ranges, on the grounds that
identifier length drives manifest size. It does — but only under a full
manifest:

| mode | id length | LoRa ctl% | courier ctl% | TCP ctl% |
|---|---|---|---|---|
| full | 32 B | 94.9% | 18.6% | 21.76% |
| full | 16 B | 90.4% | 10.2% | 12.21% |
| full | 8 B | 82.4% | 5.4% | 6.50% |
| rbsr | 32 B | 95.0% | 0.2% | 0.27% |
| rbsr | 16 B | 95.0% | 0.2% | 0.22% |
| rbsr | 8 B | 95.0% | 0.2% | 0.19% |

Truncating 32 B → 8 B buys 3.3× on TCP control overhead. Switching full → RBSR
buys **80×**, and once on RBSR the identifier length is worth 1.4×.

> **B3 recommendation: keep 32-byte identifiers.** Manifest size is not a good
> reason to weaken collision resistance, because the algorithm choice dominates
> it by more than an order of magnitude. Truncation remains available later as
> a range-local encoding optimisation inside RBSR, where it is a wire detail
> rather than a property of the identifier.

This matters beyond bandwidth: a truncated identifier is a weaker binding
between an object and its content, and content addressing is what I-1 makes
duplicate suppression, loop suppression, and replay resistance rest on.

---

## 3. Holdings analysis and the origin attack (blocking item B2)

RFC 0 §7.4 asks for the coverage threshold below which differential holdings
analysis becomes practical. The SIM-0 audit argued the threshold is the wrong
question, because holding probability is a steep function of object *age* and
age is public. SIM-1 measures the leak directly.

**Method.** Place `k` adversary vantage points in the peer graph. At the
horizon, for every live object, record which vantage points hold it and the
object's age — nothing else. No arrival timestamps, no decryption. Calibrate
`P(hold | hop distance from origin, age bucket)` on half the corpus, then run a
maximum-likelihood attack over all `n` candidate origins on the other half.
Report the true origin's mid-rank percentile and how often it lands in the
adversary's top 10 of 500. Chance is 50% and 2.0%.

### Under well-provisioned transport there is no leak

```
mixed 70/15/15 — P(hold | hops), by age bucket, youngest first
  bucket 0   95%  96%  87%  78%  78%  77%  73%  65%
  bucket 1   95%  99% 100% 100% 100% 100% 100%  99%
  bucket 2+  ... flat at 100% ...
```

Only the youngest bucket carries any gradient, and the attack cannot exploit
it:

| vantage points | mixed rank p50 | mixed top-10 | all-tcp top-10 |
|---|---|---|---|
| 1 | 53.6% | 0.18% | 0.18% |
| 5 | 48.8% | 1.91% | 1.87% |
| 25 | 48.5% | 2.33% | 2.21% |
| 50 | 48.6% | 2.23% | 2.12% |

Chance is 50% and 2.0%. **The possession argument holds exactly as RFC 0
claims it does.**

### Under austere transport the gradient is steep and exploitable

```
austere 20/30/50 — P(hold | hops), by age bucket, youngest first
  bucket 0   95%  41%  16%   4%   2%   1%   1%   1%
  bucket 1   95%  51%  21%  10%   6%   3%   1%   2%
  bucket 3   96%  75%  49%  27%  20%  20%  21%  32%
  bucket 5   95%  93%  74%  54%  49%  48%  47%  47%
  bucket 7   93%  99%  94%  82%  77%  77%  79%  74%
```

Every bucket decays monotonically with hop distance from the origin. The
attack scales with vantage count:

| vantage points | rank p50 | top-10 | vs chance |
|---|---|---|---|
| 1 | 42.8% | 4.35% | 2.2× |
| 5 | 36.2% | 6.26% | 3.1× |
| 10 | 29.8% | 7.99% | 4.0× |
| 25 | 20.1% | 12.45% | 6.2× |
| 50 | 14.4% | 16.33% | 8.2× |

With fifty vantage points — a tenth of the network, and by RFC 0 §5.2 the
price is fifty social relationships — the adversary places the true injection
point in its top ten of five hundred for **16.3% of all messages**, from
holdings and public age alone.

Choosing hubs rather than random peers does not help much (13.5% at k=50
versus 16.3%): what the attack needs is spread, not centrality.

### Provisioning to SIM-0's own guidance closes it

SIM-0 §4 and §5 recommend 21–30 day TTL and 12+ peers for courier- or
radio-dominated transport. The austere runs above use 14 days and degree 8 —
below that guidance on both axes. Correcting either:

| austere configuration, 25 vantage points | rank p50 | top-10 | vs chance |
|---|---|---|---|
| degree 8, TTL 14 d — below guidance | 20.1% | 12.45% | 6.2× |
| degree 12 — minimum peers | 45.7% | 3.40% | 1.7× |
| TTL 30 d — minimum TTL | 34.9% | 6.67% | 3.3× |
| degree 12 + TTL 30 d | **48.0%** | **2.50%** | **1.25×** |

> **Answer to RFC 0 §7.4.** There is no universal coverage threshold. The leak
> is a function of whether propagation completes within TTL. Where it does,
> holdings are uninformative and the possession argument is sound. Where it
> does not, holdings leak the injection point in proportion to how far short
> the deployment falls — and peer count is the stronger lever, closing most of
> the gap on its own.

**Normative consequences.**

- RFC 0 §8.2's client warnings are **privacy controls**, not availability
  conveniences. An operator below the peer-count threshold for their transport
  mix is measurably more deanonymisable, not merely slower. The warning text
  must say so.
- RFC 0 §7.4 should be rewritten around propagation-completes-within-TTL
  rather than a coverage number, and should cite the table above.
- The `presence` beacon's coverage field should carry the age profile, since
  the scalar cannot distinguish the safe regime from the leaking one.
- **B2 is not blocked by this.** Coarsening `expiry` in the frozen header
  would blunt the attack's age input, but the same information is available
  from any long-lived observer, and the leak vanishes under correct
  provisioning. Freezing `expiry` at useful resolution is defensible; the
  mitigation belongs in provisioning guidance, not in the header. This is a
  decision RFC 1 can now make on evidence.

---

## 4. Capacity-pressure eviction inverts everything

SIM-0 §9 noted that real nodes evict early and that this would reduce coverage
further. It does — but the interesting effect is not the magnitude.

| storage cap | delivery | coverage | settled coverage | ingress MB/day |
|---|---|---|---|---|
| none | 100.0% | 97.2% | 100.0% | 31.20 |
| 450 MB | 100.0% | 97.2% | 100.0% | 31.21 |
| 300 MB | 100.0% | 69.4% | 0.3% | 42.44 |
| 200 MB | 100.0% | 46.2% | 0.0% | 47.91 |
| 100 MB | 100.0% | 23.2% | 0.0% | **52.38** |

Two things happen, neither of them in any current document.

### The age gradient inverts

```
cover by age, youngest bucket first
  cap=none    76% 100% 100% 100% 100% 100% 100% 100%
  cap=300MB   76% 100% 100% 100% 100%  76%   1%   0%
  cap=100MB   76% 100%  10%   0%   0%   0%   0%   0%
```

Uniform oldest-first eviction (I-6) means a capped node holds exactly the
newest N megabytes and nothing else. Without a cap, holding a *young* object
is evidence. With a cap, holding an *old* object is evidence. The direction of
the leak is set by a local configuration parameter.

> **I-6 does not make the holding set uninformative. It makes it a
> deterministic function of the node's storage capacity and the object's age,
> both of which an adversary can learn.**

This is a genuine gap in RFC 0 §7.4 and SIM-0 §6, both of which treat uniform
oldest-first eviction as the *protection*. It is the protection against
policy-driven holding sets — a node must not choose what to keep by shard or
size — but it is not protection against holdings analysis, because
"deterministic" and "uninformative" are different properties. A `presence`
beacon carrying coverage discloses the cap, and the cap discloses the holding
set exactly.

### Eviction causes a re-fetch loop

Ingress rises from 31.2 to 52.4 MB/day at a 100 MB cap — **+68%** — while
delivery stays at 100%. A node evicts an object; its peer still holds it and
offers it again; the node re-accepts, and evicts again. Nothing in the current
design breaks the cycle. The tighter the cap, the more the link spends
re-transferring objects the node has already decided it cannot keep.

**Normative consequences.**

- RFC 5 needs an eviction watermark analogous to its `min_expiry` tombstone
  rule: a node MUST be able to tell a peer "do not offer me objects older
  than X" as part of the agreed filter. Without it, capacity pressure converts
  directly into wasted bandwidth on the links least able to afford it.
- The retention floor in the RFC 3 credential is the natural place to
  negotiate this, since both sides must agree or the filter is not provably
  shared (RFC 5).
- RFC 0 §7.4 must state that uniform eviction makes the holding set
  deterministic rather than uninformative, and that a node's storage cap is
  therefore sensitive in a way its coverage figure alone does not convey.

---

## 5. What SIM-1 still does not model

- **No adversary in the transport layer.** Vantage points observe honestly;
  they do not lie, withhold, or eclipse. Delivery figures remain upper bounds.
- **No quota enforcement or back-pressure.** RFC 3's graduated quota is the
  primary defence against the vantage-acquisition attack in §3, and its effect
  on that attack is unmeasured.
- **RBSR is modelled analytically**, not implemented: cost is derived from
  corpus and difference size rather than from a real fingerprint tree. The
  round-trip count is the load-bearing term and is right; the byte constant is
  approximate.
- **Fragmentation is store-and-forward but lossless.** Fragments never arrive
  out of order or partially, and there is no reassembly timeout.
- **Eviction runs at sample points**, every two days, not continuously.
- **Uniform TTL and no sharding**, both inherited from SIM-0.

---

## 6. Findings that change the design

1. **`sync_mode` is per-link and has no safe default.** LoRa requires RBSR;
   courier forbids it. RFC 5 must derive it from `latency_class`, and must
   forbid a full manifest whose size exceeds the link's window.
2. **Keep 32-byte identifiers (B3).** Sync-mode choice dominates identifier
   length by 80× to 3.3×. Do not weaken content addressing to save manifest
   bytes.
3. **The holdings leak is under-provisioning, not a coverage threshold**
   (RFC 0 §7.4). It vanishes at 12 peers and 30-day TTL under austere
   transport. Client warnings are privacy controls.
4. **`expiry` can stay in the frozen header at useful resolution (B2)**, on
   the evidence in §3. This unblocks RFC 1.
5. **Uniform eviction makes holdings deterministic, not uninformative.** A
   node's storage cap plus object age determines its holding set exactly.
   RFC 0 §7.4 and SIM-0 §6 both currently claim the opposite.
6. **Eviction needs a negotiated age watermark** or capacity pressure becomes
   a permanent re-fetch loop costing up to 68% extra ingress.

---

## 7. Reproducing

```
cargo build --release -p krab-sim

# reconciliation overhead
./target/release/krab-sim --recon --sweep recon
KRAB_LORA_GATE=8000 ./target/release/krab-sim --recon --sweep recon

# identifier length (B3)
./target/release/krab-sim --recon --sweep idlen

# holdings analysis (B2)
./target/release/krab-sim --adv --tcp 0.2 --lora 0.3 --courier 0.5 --sweep adversary
./target/release/krab-sim --adv --sweep adversary-mix

# does provisioning close the leak?
./target/release/krab-sim --adv --adversary 25 --tcp 0.2 --lora 0.3 --courier 0.5 \
    --degree 12 --ttl 30 --horizon 90

# capacity-pressure eviction
./target/release/krab-sim --diag --sweep cap

# SIM-0 regression: must reproduce SIM-0-results.md byte-identically
./target/release/krab-sim --sweep mix
```

Captured output for every run is in
[`sim-1-runs/sweeps.txt`](sim-1-runs/sweeps.txt).
