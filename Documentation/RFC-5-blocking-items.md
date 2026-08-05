# RFC 5 — Blocking Item Status

    Status:      Working document, not an RFC
    Purpose:     the gate on RFC 5 reaching Draft
    Grounding:   SIM-0, SIM-1, RFC 1/2/3/4/6/7, rfc-5-runs/
    Depends on:  RFC 1, RFC 4

RFC 5 is the last document in the series and the one carrying the most
inherited requirements — six other documents have deferred something to it.

It is also the only one whose central decision was already measured before it
was written. SIM-1 §1 established that reconciliation strategy has no safe
default; §1 below turns that into a procedure a `LinkProfile` can evaluate.

Reproduce with `rfc-5-runs/sync-mode.py`.

---

## 1. `sync_mode` is decidable, not configurable

Two independent feasibility tests, each computable from a `LinkProfile` and
the filtered corpus size.

### 1.1 A full manifest must fit the per-sync window

Both sides name what they hold, at RFC 1 §9.3's 16 bytes per entry:

| link | window | manifest at m=14 000 | fits | max m |
|---|---|---|---|---|
| TCP over Tor | 1 GB | 448 KB | yes | 33 million |
| **LoRa SF10** | **18 KB** | **448 KB** | **no** | **562** |
| courier | 64 GB | 448 KB | yes | 2 billion |

A LoRa link can name **562 objects** per sync window. The live corpus at n=500
is 14 000, so a full manifest is 25× over.

Shard filtering can close that, at a price RFC 2 §6 already quantified:

```
LoRa needs shard k >= 5 for a full manifest to fit at n=500
k = 5 leaves a 3.12% anonymity set
```

So the choice on a LoRa link is RBSR, or a full manifest bought with a
thirty-fold reduction in the recipient's anonymity set. That is not a tuning
decision.

### 1.2 RBSR must fit the round-trip budget

Descent depth at `b=16`, `m=14 000` is **4 rounds**:

| link | RTT | 4 rounds | vs TTL | verdict |
|---|---|---|---|---|
| TCP over Tor | 6 s | 24 s | 0.0% | ok |
| LoRa SF10 | 20 s | 80 s | 0.0% | ok |
| **courier** | **6 d** | **24 d** | **171%** | **no** |

A courier reconciliation would take 24 days against a 14-day TTL. The objects
expire mid-descent — which is SIM-1 §1's measured collapse from 95.8% to
33.0% delivery, arrived at from the other direction.

### 1.3 The procedure

```
full_manifest_feasible  =  2 * m * ENTRY <= window
rbsr_feasible           =  depth(m) * 2 * latency << TTL

both        -> Rbsr        (97x cheaper in control bytes)
manifest only -> Manifest
rbsr only     -> Rbsr
neither       -> the link cannot reconcile; say so
```

The fourth case is the one worth specifying deliberately. A link that is both
narrow and high-latency has no working strategy, and the client should report
that at configuration time rather than after a fortnight of silence.

**This also settles `RFC-4-review.md` §1.** `sync_mode` cannot be a local
`LinkProfile` field, because both sides must evaluate the same procedure on
the same inputs — which requires `latency_class` and the filter to come from
the signed credential. RFC 5 owns the procedure; RFC 3 must carry its inputs.

---

## 2. Bloom filters fail on exactly the wrong nodes

The plan rules them out because false positives fail in the message-loss
direction. That is right, and the shape of the failure is sharper than the
statement:

| peers | p = 1% | p = 0.1% |
|---|---|---|
| **1** | **1.0 × 10⁻²** | 1.0 × 10⁻³ |
| 4 | 1.0 × 10⁻⁸ | 1.0 × 10⁻¹² |
| 12 | 1.0 × 10⁻²⁴ | 1.0 × 10⁻³⁶ |

`P(object never delivered) = p^peers`. A false positive means the sender
believes the receiver already holds the object, so it is never offered — a
silent permanent loss, not a delay.

**The loss concentrates entirely on low-degree nodes**, which SIM-0 §5 already
identifies as the population where delivery is worst (degree 4 is a cliff even
on good transport). A leaf node with one peer loses 1% of its mail
permanently at p=1%, while a degree-12 node loses nothing measurable.

An optimisation whose error rate is inversely proportional to how well-served
a node already is should be recorded as rejected with the reason, so it is not
reintroduced by someone measuring only the average case.

---

## 3. The eviction watermark, sized

`RFC-3-review.md` §3 and SIM-1 §4: retention is a *promise*, not a capacity.
Under pressure they diverge and the re-fetch loop costs **+68% ingress**.

```
effective_retention = min(promised_retention, cap / daily_ingress)
```

At SIM-0's 31 MB/day at n=500:

| storage cap | days actually held | honours a 30-day promise? |
|---|---|---|
| 100 MB | 3.2 | no |
| 300 MB | 9.7 | no |
| 450 MB | 14.5 | no |
| 1 GB | 32.3 | yes |

**A node must provision roughly 1 GB to honour a 30-day retention promise at
n=500**, and that scales linearly with network size (SIM-0 §7). RFC 3's
credential lets a node promise what it cannot deliver, and nothing detects it
until the peer notices missing objects it supplied.

RFC 5's filter is where this is fixed:

- the filter MUST carry an effective retention floor, not the promised one
- a node MUST recompute it as capacity or network size changes, and
  renegotiate rather than silently breach
- RFC 3 §7's retention field SHOULD be validated against provisioned capacity
  at credential-signing time, so the promise is refused rather than broken

---

## 4. Inherited requirements

Each of these was deferred to RFC 5 by a document already at Draft.

| requirement | from | what it needs |
|---|---|---|
| skip-and-continue on capacity exhaustion | SIM-0 audit §4 | a transfer MUST skip an object that does not fit and continue, never abandon. `break` wedges a link permanently on its oldest oversized object |
| per-class shard masks | RFC 6 §3.4, RFC 2 gate §2.2 | the filter must be `(class, shard_prefix)` pairs; RFC 6's channel-interest bucketing cannot be expressed otherwise |
| `sync_mode` derived from signed inputs | RFC 4 review §1 | §1.3 above |
| LoRa profile MUST use RBSR | SIM-1 §1, RFC 4 review §3 | §1 above |
| filter derives from the credential | RFC 3 §7.3 | else phantom divergence recurs permanently |
| expiry resurrection | RFC 1 §11 check 6 | tombstones and a `min_expiry` watermark, so a returning courier node cannot re-inject expired objects |
| novelty ratio, unique-source contribution | RFC 3 §12 | the metrics RFC 3's quota decisions consume |
| Poisson partner rotation | RFC 0 I-5 | never event-driven; RFC 0 §5.3 names this the invariant most likely to be lost to a battery optimisation |

---

## 5. Open, with no grounding

- **RBSR is modelled analytically, never implemented.** SIM-1 §5 says so: cost
  is derived from corpus and difference size rather than from a fingerprint
  tree. The round-trip count is the load-bearing term and is right; the byte
  constant is approximate. RFC 5 specifies a real algorithm and should expect
  the constant to move.
- **Additive composable fingerprints** are named in the plan and unspecified.
  The construction determines whether range probes can be cached across
  reconciliations, which is what decides whether depth-4 descent costs four
  round trips every time or only on first contact.
- **The `min_expiry` watermark's interaction with clock skew** (RFC 2 §5.1,
  ±6 h) is unexamined. A node whose clock is fast evicts early and re-requests.
- **Fan-out is unmodelled** (RFC 6 review §3): 19 correlated objects per
  message changes both manifest size and the difference set, and no
  measurement covers it.

---

## 6. Gate

RFC 5 may reach Draft when:

- [x] `sync_mode` decision procedure derived — §1
- [x] Bloom rejection quantified — §2
- [x] effective retention sized — §3
- [ ] the four-case procedure, including "cannot reconcile", specified
- [ ] per-class shard masking specified
- [ ] skip-and-continue specified
- [ ] additive fingerprint construction chosen
- [ ] tombstone and `min_expiry` semantics specified
- [ ] RBSR implemented and SIM-2 re-run against a real fingerprint tree

---

## 7. Series status

RFC 5 is the last document. With it at Draft the series is complete in outline,
and what remains is global rather than per-document:

- **RFC 0 has accumulated eleven corrections** across the reviews — the
  sharding threshold (RFC 6 review §2), peer counts (RFC 3 review §5), the
  restated premise (SIM-0 audit §2), the epoch/erasure conflation (RFC 7 gate
  §1), the RFC 2 roadmap entry, and the errata process RFC 7 §13 used without
  one existing.
- **One rule would have prevented four findings**: acceptance and retention
  parameters MUST be functions of the declared guarantee, never of a measured
  percentile. RFC 1 §6.2, RFC 7 §12 and §5.2, and RFC 2 §5 each got this wrong
  independently.
- **SIM-2** now has four items: quota versus vantage acquisition (RFC 3 gate
  §3), fan-out (RFC 6 gate §3), a real RBSR implementation (§5 above), and
  capacity-pressure eviction with the watermark from §3.
- **No RFC has reached Final**, and none should before RFC 1 §12's test vectors
  exist, two implementations agree on them, and the external cryptographic
  review RFC 0 §9 requires has happened.
