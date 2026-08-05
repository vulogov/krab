# SIM-0 — Corpus Convergence Measurements

Grounding document for the Krab RFC series. RFC 0 cites this; no RFC may
assert a convergence, delivery, or storage claim not measured here.

Simulator: `krab-sim`, zero external dependencies, deterministic per seed.
All figures are means over 5 independent seeds unless noted.

> **Audit notice.** Every figure below reproduces exactly from
> `apps/krab-sim`. Three of the columns nevertheless do not mean what their
> names suggest, and one headline conclusion (§6) is drawn from a metric
> artifact. Read [`SIM-0-audit.md`](SIM-0-audit.md) before citing anything
> here. In short: LoRa edges carried 0.16% of objects in every run; the 37.2%
> coverage figure is a propagation ramp measured mid-flight, and settled
> coverage in the same run is 76.4%; and `storeMB`/`rxMB/d` are
> p99-across-nodes of a peak-over-time rather than means.

---

## Summary

**The architecture works, but the premise needs restating.**

Under IP-connected transport the network converges comfortably: 100%
delivery, median latency ~7 hours, and near-complete corpus replication.
TTL and topology barely matter.

Under courier- and radio-dominated transport, delivery still largely works
but **full-corpus replication does not**. At 20% TCP / 30% LoRa / 50%
courier with a 14-day TTL, 95.8% of messages arrive — while the average
node holds only **37%** of the live corpus, and the bottom decile holds
15%.

Delivery and convergence are separate properties. The design has been
written as though full replication were a guarantee. It is an emergent
property of well-connected IP networks, not an invariant. This has a
privacy consequence (§5) that is not currently accounted for anywhere in
the design.

---

## 1. Model

Discrete-event, integer seconds. Objects are content-addressed, uniform
TTL, sorted by creation so expiry is a prefix of the index space;
reconciliation is a bitmap difference over the live window.

| transport | sync interval | latency | capacity/sync | object gate |
|---|---|---|---|---|
| TCP (over Tor) | 4 h | 3 s | unbounded | 512 KB |
| LoRa (EU868 SF10, 1% duty) | 6 h | 10 s | ~18 KB | 512 B |
| Courier | 7 d | 3 d | unbounded | 512 KB |

LoRa capacity derives from the duty-cycle arithmetic: ~0.85 B/s sustained,
so a 6-hour window moves about 18 KB. Objects above 512 B are gated at the
sender and never cross a LoRa edge.

Traffic: 2 messages/node/day. 90% text (0.5–8 KB), 10% pictures (50–500 KB).
Node availability is an alternating renewal process at 85% uptime, 12-hour
mean sessions. Courier links do not require either endpoint online.

Baseline: Watts–Strogatz, n=500, degree 8, rewire 0.10, TTL 14 d,
horizon 42 d, 70/15/15 transport mix, social destinations within 3 hops.

Only objects created before `horizon − TTL` are scored, so every measured
message had a full lifetime in which to arrive.

> **Audit note.** The 512 B LoRa gate and the 500 B floor of the text size
> distribution collide: 0.16% of objects were eligible to cross a LoRa edge.
> LoRa is inert in every table below. See audit §1.

---

## 2. Baseline

```
delivery   lat50h  lat90h  lat99h   coverage  cover_p10   storeMB   rxMB/day
  100.0%      7.3    12.7    18.6      97.2%      96.4%     447.0      31.2
```

Corpus size matches the analytic estimate (500 nodes × 2/day × 14 d ×
31 KB mean ≈ 438 MB), which is a useful check that the model is not
inventing traffic.

> **Audit note.** This compares a p99-across-nodes of a peak-over-time
> against a mean. See audit §3.

---

## 3. Transport mix — the binding constraint

TTL 14 d, degree 8.

| mix | delivery | lat p50 | lat p99 | coverage | cover p10 | store MB |
|---|---|---|---|---|---|---|
| all TCP | 100.0% | 4.9 h | 14.1 h | 98.2% | 97.7% | 449 |
| TCP + LoRa | 100.0% | 5.9 h | 15.8 h | 97.8% | 97.2% | 448 |
| mixed (70/15/15) | 100.0% | 7.3 h | 18.6 h | 97.2% | 96.4% | 447 |
| courier-heavy (50/20/30) | 100.0% | 11.6 h | 60.5 h | 95.3% | 94.3% | 442 |
| austere (20/30/50) | 95.8% | 170.6 h | 382.5 h | **37.2%** | **15.4%** | 273 |
| all courier | 52.5% | 311.5 h | 406.3 h | **1.8%** | 1.3% | 18 |

Transport mix dominates every other parameter. Topology, destination model,
and network size are all second-order by comparison.

**All-courier does not work.** 52.5% delivery and 1.8% coverage: a network
reachable only by physical media, at weekly exchange intervals, cannot
sustain flood replication. A courier-only node must be a leaf attached to
at least one better-connected peer, not a participant in a courier-only
component. This should be a stated deployment constraint.

---

## 4. TTL

TTL is **irrelevant to delivery** under IP-rich transport and **decisive**
under austere transport. Two sweeps, same everything else:

| TTL | delivery (mixed) | delivery (austere) | store MB (mixed) |
|---|---|---|---|
| 3 d | 100.0% | 21.3% | 94 |
| 7 d | 100.0% | 57.7% | 225 |
| 14 d | 100.0% | 95.8% | 447 |
| 21 d | 100.0% | 99.9% | 673 |
| 30 d | 100.0% | 100.0% | 954 |
| 45 d | 100.0% | 100.0% | 1419 |

Storage is linear in TTL; delivery is a step function whose knee sits where
TTL crosses the network's mixing time.

**Normative consequence.** TTL must be a deployment parameter, not a
protocol constant, and `MAX_TTL` must be generous enough to admit 30 days.
Suggested guidance for RFC 1's parameter table:

- IP-connected deployments: 7 days is sufficient; 3 days is viable.
- Mixed deployments: 14 days.
- Courier- or radio-dominated: **21–30 days minimum.**

The earlier working assumption that "TTL must exceed mixing time by a wide
margin" is confirmed, but only for the austere case. On IP transport it
over-provisions storage by 4–10× for no delivery benefit.

---

## 5. Peer count

| degree | delivery (mixed) | lat p99 (mixed) | delivery (austere) | coverage (austere) |
|---|---|---|---|---|
| 4 | 99.6% | 159.7 h | 56.7% | 1.8% |
| 6 | 100.0% | 26.3 h | 72.4% | 8.5% |
| 8 | 100.0% | 18.6 h | 95.8% | 37.2% |
| 12 | 100.0% | 14.3 h | 100.0% | 85.7% |
| 16 | 100.0% | 12.5 h | 100.0% | 93.5% |
| 20 | 100.0% | 11.5 h | 100.0% | 96.2% |

**Degree 4 is a cliff even on good transport** — tail latency is 8.6× worse
than at degree 8 while median barely moves, which is the signature of a few
nodes sitting behind a single fragile path.

**Minimum peer count is transport-dependent**, and this belongs in operator
guidance:

- IP-connected: 6–8 peers.
- Courier/radio-dominated: **12+ peers.** Degree 12 restores 100% delivery
  and cuts median latency from 170 h to 30 h.

Since operators choose peers by hand and will not naturally know this, the
client should warn below the threshold for its actual transport mix. This
is a concrete requirement for RFC 8's `peers` panel.

> **Audit note.** The austere degree cliff is a TCP-edge lottery: with LoRa
> edges inert, 41% of degree-4 nodes have no TCP edge at all. See audit §1.

---

## 6. Coverage is a privacy parameter, not just availability

The design's privacy argument for full replication is that *possession
implies nothing, because everyone holds everything*. That argument is
load-bearing: it is why a relay cannot be asked who a message was for.

At 97% coverage it holds. **At 37% coverage it does not.** If a node holds
roughly a third of the live corpus, the fact that it holds a particular
object is evidence, and differential holdings analysis across several nodes
recovers signal that full replication was supposed to destroy.

This is not currently accounted for anywhere in the design. Consequences:

1. **Coverage must be measured and surfaced.** A node whose coverage falls
   below a threshold is in a weaker privacy position than the RFC claims,
   and it cannot currently tell. Add coverage to the `peers` panel and to
   the `presence` beacon's capability fields.
2. **The threat model in RFC 0 must be conditioned on coverage**, not
   stated unconditionally.
3. **Uniform oldest-first eviction becomes more important, not less.** When
   coverage is partial, *which* objects a node holds is the whole question,
   and a policy-driven holding set is an oracle.

Suggested threshold for further work: characterise the coverage below which
differential analysis becomes practical. SIM-0 can measure coverage; it
cannot answer that question, which needs an adversary model.

> **Audit note — this section's central figure is an artifact.** 37.2% is a
> mean over a propagation ramp measured at the horizon; settled coverage in
> the same run is 76.4%, and is 100% in every configuration meeting SIM-0's
> own minimum peer count and TTL. The conclusion survives in a sharper and
> more durable form: holding probability is a steep function of object *age*
> in every configuration, including the fully-converged ones, and age is
> readable from the cleartext `expiry` field that blocking item B2 freezes
> permanently. See audit §2 — it carries a deadline.

---

## 7. Scale

Watts–Strogatz, degree 8, mixed transport, 3 seeds.

| n | delivery | lat p50 | coverage | store MB | ingress MB/day |
|---|---|---|---|---|---|
| 100 | 100.0% | 5.5 h | 98.8% | 95 | 6.2 |
| 250 | 100.0% | 6.8 h | 97.9% | 232 | 16.1 |
| 500 | 100.0% | 7.4 h | 97.1% | 447 | 31.3 |
| 1 000 | 100.0% | 7.9 h | 96.6% | 893 | 63.0 |
| 2 000 | 100.0% | 8.3 h | 96.1% | 1 749 | 125.2 |

Latency grows logarithmically — the small-world property holding as
expected. **Storage and ingress grow linearly**, and that is the
quantitative confirmation of the flooding cost problem:

```
ingress ≈ 0.063 MB/day per node, per node in the network
```

Extrapolating at 2 messages/node/day:

| n | ingress/node/day | live corpus |
|---|---|---|
| 5 000 | ~310 MB | ~4.4 GB |
| 10 000 | ~625 MB | ~8.8 GB |
| 100 000 | ~6.2 GB | ~88 GB |

A node's cost grows with the network's popularity rather than with its own
usage — growth is punished. **Sharding is not optional above roughly
n = 5 000**, and the shard field must therefore be present in v1's envelope
even if v1 ships with k = 0 everywhere.

> **Audit note.** The apparent coverage decay with scale (98.8% → 96.1%) is
> not decay: settled coverage is 100.0% at every n from 100 to 2 000. The
> `store MB` and `ingress` columns are p99, not means. See audit §2, §3.

---

## 8. Second-order parameters

**Topology** barely matters: Watts–Strogatz 100%/7.3 h, Barabási–Albert
100%/5.3 h, random-regular 100%/6.3 h. Scale-free hubs help latency
slightly and are not required.

**Destination model** barely matters: social h=2 gives 4.6 h median,
uniform gives 9.9 h, both at 100% delivery. Expected — under flooding,
everyone receives everything regardless of who the message was for. Note
this also means the simulation cannot distinguish routing quality; that
would need a non-flooding variant.

---

## 9. What SIM-0 does not model

Interpretation limits. Each of these is a candidate for SIM-1:

- **No adversary.** No lying peers, eclipse attempts, or flooding attacks.
  Delivery figures are upper bounds.
- **No quota enforcement or back-pressure.** Links transfer up to capacity
  with no accounting.
- **No capacity-pressure eviction.** Nodes are assumed to hold everything
  within TTL. Real nodes will evict early, which reduces coverage further.
- **Reconciliation overhead is not counted** — manifest exchange bytes are
  free here. On a LoRa link where capacity is ~18 KB per sync, a full
  manifest is not free and may dominate. **This is the most significant
  omission** and should be the first addition.
- **No fragmentation.** LoRa-oversized objects are dropped rather than
  split; fragmentation would raise LoRa's contribution.
- **Couriers never miss a journey** and require no human.
- **Uniform TTL** across all objects.

> **Audit note.** The fragmentation bullet understates its own item: with the
> shipped gate, LoRa carried 0.16% of objects, so fragmentation is not an
> improvement to LoRa's contribution but a precondition for it being nonzero.
> Even so, capacity caps the benefit at +2.9pp delivery — a LoRa link
> supplies ~2% of one peer-share of the flood. See audit §1.

---

## 10. Findings that change the design

1. **Restate the premise.** "Every node eventually holds the entire corpus"
   is false under austere transport. Delivery is the requirement; full
   replication is a property of well-connected deployments. RFC 0's
   framing needs to change.
2. **Coverage is a privacy parameter** (§6) and must be measured, surfaced,
   and written into the threat model's preconditions.
3. **TTL and minimum peer count are transport-dependent** and belong in
   operator guidance, with client warnings, not just in a constants table.
4. **All-courier components do not work.** State as a deployment constraint.
5. **Sharding is mandatory above ~5 000 nodes**, so the envelope shard field
   must ship in v1.
6. **Reconciliation overhead on constrained links is unmeasured** and is the
   most likely place for the current design to be wrong.

> **Audit note.** Finding 1 is over-corrected — see audit §2 for a suggested
> replacement. Finding 2 holds but should be restated around the age
> gradient rather than a coverage threshold. Findings 3–6 stand.

---

## 11. Reproducing

```
cargo build --release -p krab-sim
./target/release/krab-sim                      # baseline
./target/release/krab-sim --sweep mix          # transport mix
./target/release/krab-sim --sweep ttl --tcp 0.2 --lora 0.3 --courier 0.5
./target/release/krab-sim --sweep degree --tcp 0.2 --lora 0.3 --courier 0.5
./target/release/krab-sim --sweep scale --seeds 3
./target/release/krab-sim --json results.json
```

Output is byte-identical across invocations for a given configuration.
Ordered containers are used throughout the generators specifically to keep
it that way: hash-set iteration order is randomised per process and would
otherwise perturb the RNG stream, making published figures unreproducible.

Seeds are `1..=--seeds`. The `--sweep ttl` and `--sweep degree` commands
above reproduce only the austere column of §4 and §5; drop the mix overrides
for the mixed column. Captured output for every sweep, with audit
diagnostics, is in [`sim-0-runs/sweeps.txt`](sim-0-runs/sweeps.txt).
