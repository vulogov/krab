# SIM-2 — measurements against the implementation

`crates/krab-node/tests/sim2.rs`. Run with:

```
cargo test -p krab-node --test sim2 -- --nocapture
```

`MILESTONE-0.1.md` §2 phase F requires SIM-2 run "against the implementations
through the `sim` backend, **not against a third model**." Everything here
drives `krab_store::Store`, `krab_proto::recon` and `krab_node::StoreView` —
the same adapter the node itself uses. `StoreView` was made public for this
reason; a second adapter written for the simulator would have been the third
model the requirement rules out.

## Item 1 — graduated quota versus vantage acquisition (RFC 3 gate §3)

RFC 0 §5.3 claims graduated quota "means early vantage points are low-bandwidth
and slow to become useful." `RFC-3-blocking-items.md` records that the claim
"is currently ungrounded" and that SIM-1 §5 listed quota as explicitly
unmodelled — "the primary defence against the attack was absent from the
measurement of it."

**Result.** 900-object corpus, 12 rounds, ingress capped per round and growing
with peering age to a ceiling at 8 rounds:

| joined at round | holds | share of corpus | share of an established peer's holdings |
|---|---|---|---|
| 0 | 408 / 900 | 45.3% | 100% |
| 4 | 216 / 900 | 24.0% | 53% |
| 8 | 60 / 900 | 6.7% | 15% |
| 11 | 6 / 900 | 0.7% | **1.5%** |

**A vantage point acquired one round before measurement holds 1.5% of what an
established peer holds.** The gradient is steep and monotone in peering age.

RFC 0 §5.3's claim is now grounded, with the caveat that the shape depends on
the quota schedule, which is a deployment dial (RFC 3 §6) rather than a
protocol constant. What the measurement establishes is that the *mechanism*
works — holdings track peering age — not that any particular schedule is
sufficient.

### The first attempt was wrong, and how it was wrong matters

Measured **without** quota, every node converges to the whole corpus and a
single vantage point sees 100% of it. That is not a bug: Krab floods, and full
replication is the design.

It does mean the obvious framing — "how much can an adversary see?" — is the
wrong question. An adversary does not need a vantage point to obtain
ciphertext. `without_quota_every_vantage_point_sees_everything` is kept as a
test precisely to record this: it is the state SIM-1 §5 was in, and it shows
that an unquota'd measurement of vantage acquisition measures nothing.

**This file supports no deanonymisation claim.** RFC 8 §494 is explicit that
one "requires a SIM-2 with an adversary model", and there is no adversary model
here — only honest peers whose holdings are being counted.

## Item 2 — fan-out (RFC 6 gate §3)

RFC 6 §1 asks for group cost measured rather than multiplied.

| members | objects | bytes |
|---|---|---|
| 4 | 4 | 1 024 |
| 12 | 12 | 3 072 |
| 40 | 40 | 10 240 |

**Linear in members at composition, and free thereafter.** RFC 6 §2.7 forbids
per-recipient push, so replication is ordinary corpus replication: a relay
carrying the objects does not know they are related, and the cost does not
scale with group size a second time. RFC 6 §1's concern was a multiplier hiding
somewhere; there is not one.

## Item 3 — RBSR against a real fingerprint tree (RFC 5 §5)

Neither SIM-0 nor SIM-1 ran the state machine, so convergence was a property of
the model rather than of the code.

**Result.** Three seeds, two 400-object corpora drawn from a 600-object space,
converge in **under 20 rounds** in every case, with equal range fingerprints
over the whole window — equal counts alone would not prove equal contents.

`manifest_and_rbsr_reach_the_same_corpus` additionally checks that the mode does
not change the result. RFC 5 §4.5 derives the mode from latency class rather
than configuring it, so both must be correct: a courier link has no choice.

## Item 4 — capacity-pressure eviction with the watermark (RFC 5 §3, §8)

**Result.** An 800-object corpus evicted to half its bytes retains 120 objects
and raises its watermark to 29 767 680 minutes. A peer still holding all 800
then attempts to give them back, and **nothing below the watermark returns**.

That is the property RFC 5 §8 needs: without it a returning courier node
re-injects a corpus the network already dropped, and eviction never converges.
`the_watermark_only_rises` pins the monotonicity a node would otherwise use to
re-admit its own evictions.

## What SIM-2 does not cover

- **No adversary model**, therefore no anonymity or deanonymisation figure.
- **The quota schedule is a dial**, not a measured optimum. The measurement
  shows the mechanism has the claimed shape; choosing the numbers is RFC 3 §6.
- **No network model.** Latency, churn and partition are SIM-0's and SIM-1's
  domain and remain unmodelled against the implementation.
- **`krab-sim` is unchanged.** It stays zero-dependency so SIM-0 and SIM-1
  reproduce offline, which is the reason SIM-2 lives elsewhere.
