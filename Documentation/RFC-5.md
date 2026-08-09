# RFC 5 — Synchronisation

    Number:      5
    Title:       Synchronisation
    Status:      Draft
    Repository:  https://github.com/vulogov/krab
    Author:      Vladimir Ulogov
    Requires:    RFC 0, RFC 1, RFC 3, RFC 4
    Grounded by: SIM-0, SIM-1 (all figures measured)
    Errata:      RFC 3 §7.3 — see §11

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be
interpreted as described in RFC 2119.

---

## 1. Scope

Two nodes hold overlapping sets of immutable, content-addressed objects.
Reconciliation determines what each is missing and transfers it. This
document specifies the filter that bounds the exercise, the control
protocol, the choice of algorithm per transport, the storage layout that
makes it cheap, and the scheduling discipline that keeps it from leaking.

**Reconciliation overhead is charged against the same link capacity as the
payload.** SIM-0 ignored this. SIM-1 measured it, and the result changed
both the algorithm choice and a claim in RFC 3.

---

## 2. The filter

```
filter = shard_mask ∩ max_bucket ∩ class_mask ∩ retention_window
```

All four derive from the signed `peer-link` credential (RFC 3 §3, RFC 4
§3), so **both sides provably agree on the scope without negotiating it.**

```
Reconciliation MUST be scoped to the filter.
```

An unscoped exchange makes each side permanently believe the other is
missing objects it will never accept, so the same phantom divergence
recurs every cycle, forever. It is the same failure mode as a replication
protocol whose replicas disagree on configuration, arrived at from the
other direction.

Filter-scoping is necessary. **It is not sufficient on constrained links**
— see §4.3 and §11.

---

## 3. Control protocol

Control messages are **not objects**: never stored, never hashed, never
relayed, never assigned an identifier. Deterministic CBOR arrays with a
leading opcode, carried over the RFC 4 §4 framing.

| op | message | payload |
|---|---|---|
| 0 | `HELLO` | version, node id, capabilities, watermark, filter digest |
| 1 | `MANIFEST` | filter digest, `[(expiry, id[0..12]), …]` |
| 2 | `WANT` | `[id[0..12], …]` |
| 3 | `OBJ` | object bytes |
| 4 | `DONE` | direction complete |
| 5 | `RANGE` | `[(lo, hi, fingerprint, count), …]` |
| 6 | `RANGE_DONE` | |
| 7 | `BYE` | reason |

`HELLO` carries a **filter digest** — a hash of the four filter components
as derived from the credential. A mismatch is a hard error, not a
negotiation: it means the two sides hold different credentials, and
proceeding would produce exactly the phantom divergence §2 exists to
prevent.

**`watermark`** is the oldest expiry the sender still holds. A peer that
has been offline longer than the sender's retention learns immediately
that this exchange cannot close its gap, and can stop rather than burning
a full cycle to discover it. On a LoRa link this is the difference between
a viable protocol and an unusable one.

### 3.1 Truncated identifiers

`MANIFEST` and `WANT` carry 12-byte identifier prefixes (RFC 1 §9.3),
valid **only within the agreed filter scope**. They MUST NOT appear in a
routing header, in stored structures, or in any request outside an
established session.

---

## 4. Modes

### 4.1 Assignment is per transport, and the intuition is backwards

```
IP / Tor        → RBSR
LoRa / serial   → Manifest
Courier         → Manifest
PushOnly        → MUST NOT be used
```

SIM-1 measured per-transport assignment as optimal on every axis in every
transport mix: equal delivery to the best single mode, with 32× lower
global overhead than all-manifest (0.2% against 6.5%) and the lower LoRa
overhead of the two negotiating modes.

**RBSR is not the sophisticated upgrade to manifest exchange.** It is the
correct choice in one regime and the wrong choice in the other, and the
regimes are exactly IP and constrained links.

| mixed transport | delivery | overhead | LoRa overhead |
|---|---|---|---|
| all manifest | 100.0% | 6.5% | 82.5% |
| all RBSR | 100.0% | 0.1% | 92.0% |
| all push | **46.2%** | 0% | 0% (44% waste) |
| **per-transport** | **100.0%** | **0.2%** | **82.5%** |

Under austere transport the gap widens sharply: all-RBSR delivers **64.8%**
against manifest's 95.8%.

### 4.2 Why RBSR loses where it was expected to win

RBSR's advantage is asymptotic — `O(d log n)` against `O(n)` — and requires
`n` to be large.

**§2's filter already made `n` small.** In the regime where the manifest is
supposedly too expensive, it is in fact cheap, and RBSR's *fixed* costs
dominate:

- Range descriptors cost `rounds × branch × 44 B` and that floor does not
  shrink with the set.
- RBSR still transmits the symmetric difference's identifiers, so it pays
  the manifest's marginal cost regardless.
- `log₁₆(n/32)` round trips, each two link latencies. Minutes on LoRa;
  days on courier.

The two modes are **complements, not competitors**: RBSR where the filtered
set is large and round trips cheap, manifest where the set is small and
round trips expensive.

### 4.3 Manifest

```
A → B:  HELLO
B → A:  HELLO
A → B:  MANIFEST(A's filtered set)
B → A:  WANT(ids B lacks) ‖ MANIFEST(B's filtered set)
A → B:  OBJ… ‖ WANT(ids A lacks)
B → A:  OBJ… ‖ DONE
```

One round trip, both directions. Cost is `filtered_set × 16 B`.

**Manifest mode is mandatory on any link whose `latency_class` is
`Courier`.** A courier exchange has exactly one round trip available;
anything requiring more cannot complete, and the archive is the protocol
written to a file with the round trips removed (RFC 4 §5.5).

### 4.4 RBSR

Ordering is `(expiry, id)` — identical on both sides with no coordination,
because expiry is absolute and inside the identifier hash.

Fingerprints MUST be **additively composable**: `Σ H(id) mod 2²⁵⁶`.
Addition, not XOR: XOR is malleable and an adversary can craft identifiers
that cancel. Composability is what allows a range fingerprint to be read
from a prefix-sum index in `O(1)` rather than rescanning.

```
A → B: RANGE[(lo, hi, fingerprint, count)]
B, per range:
    fingerprint matches   → omit
    count ≤ 32            → MANIFEST for that range
    otherwise             → split into 16 sub-ranges by relative
                            cardinality, return each with its fingerprint
repeat until every range is matched or listed
```

Implementations MUST cap round trips (SHOULD be 8) and fall back to
manifest mode on exceeding it. An adversarial peer can otherwise
manufacture divergence patterns that never converge.

### 4.5 PushOnly is disqualified

Zero overhead is not free. Without negotiation a sender cannot know what
the peer holds:

| | mixed | austere |
|---|---|---|
| delivery | 46.2% | 17.8% |
| wasted bytes | 44.0% | 21.0% |

```
PushOnly MUST NOT be used as a link's sync mode.
```

It remains valid as a *supplement*: a node MAY push a newly created object
to peers immediately as a low-latency fast path, provided scheduled
reconciliation remains the correctness guarantee (§6.2).

### 4.6 Bloom filters are excluded

A false positive means "the peer already has this," so the object is not
sent and is silently lost. **The failure is in the message-loss
direction.** Recorded here so it is not reintroduced as an optimisation;
the bandwidth saving is real and the failure mode is unacceptable.

---

## 5. Constrained links

Even correctly configured, **68–83% of LoRa capacity is reconciliation
rather than payload.** At SF10's 72 KB/day (RFC 4 §5.4), a LoRa link
delivers roughly 12–23 KB/day of messages.

```
LoRa is viable as a MINORITY transport and as a last hop.
Deployments MUST NOT rely on LoRa as a majority transport:
at 60% LoRa edges, delivery is 28.3% under every mode.
Implementations SHOULD warn when LoRa exceeds 30% of a node's links.
```

Two mitigations, specified as OPTIONAL because SIM-1 did not measure them:

**Asymmetric cadence.** Manifest cost is per-exchange, so reconciling half
as often on a constrained link roughly halves the overhead share at the
cost of latency. Implementations SHOULD lengthen the mean interval on
links whose `latency_class` is not `Interactive`.

**Delta manifests.** Send only entries changed since the last exchange
with this peer, with a periodic full manifest — structurally identical to
RFC 3 §8.2's `NODEDIFF`, which achieved 8–34× there. Requires per-peer
last-exchange state and a full-manifest fallback when a delta is missed.

---

## 6. Scheduling

### 6.1 Never event-driven

```
Reconciliation MUST run on a Poisson schedule with randomised interval
and randomised peer order, independent of user activity, mail arrival,
queue depth, and application focus.
```

RFC 0 I-5. A node that syncs more eagerly when it has mail correlates
itself with a tag stream without any decryption occurring, and an observer
needs only arrival timing to exploit it.

This is the invariant most likely to be destroyed by a later optimisation,
because event-driven sync looks strictly better on every metric a
performance test measures. **It SHOULD be protected by a test asserting
that inter-sync intervals are uncorrelated with message events**, not by a
comment.

`connect` establishes a transport; it does not trigger a reconciliation
(RFC 8).

### 6.2 Partner rotation

Sync with all peers on schedule, randomised in order and interval. No
single peer should be predictably your only source for any region of the
corpus — that is the eclipse condition, and it is invisible without the
unique-source-contribution metric (RFC 3 §12).

Reconciliation is the correctness guarantee. Any low-latency push path is
best-effort and bounded by it.

---

## 7. Storage

Objects are immutable and expire in bulk, so a general-purpose key-value
store is the wrong shape.

```
segments/
  <expiry_bucket>.dat     append-only; all objects expiring in this bucket
index                     (expiry, id) → (segment, offset, len)
                          per-bucket (count, fingerprint) aggregates
tombstones                short-lived, §8
```

Eviction is `unlink()` of a whole segment: no compaction, no tombstone
sweep, no fragmentation, no write amplification. Courier export is a copy
of whole segment files.

**The index MUST be fully rebuildable from the segments by one scan.**
Corruption is then recoverable and the index can be redesigned without
migrating data — worth a great deal over a project's life.

Per-bucket `(count, fingerprint)` aggregates in a Fenwick or segment tree
give the `O(1)` range summary RBSR requires. Neither a plain key-value
store nor a relational index provides this without a scan, and it is the
single storage property the algorithm depends on.

Pure-Rust ordered stores (redb and equivalents) are appropriate for the
index. The segments need no library.

---

## 8. Expiry, tombstones, and resurrection

A node returning by courier holds objects the network evicted weeks ago.
Without suppression it re-injects them, its peers accept them, and the
corpus never quiets.

```
Expiry is absolute and derived from the object (RFC 1 §4.1).
A receiver MUST reject any object whose expiry has passed (RFC 1 §11).
A node MUST maintain a tombstone set of recently expired identifiers,
  retained for at least the clock skew tolerance plus one sync interval.
A node MUST maintain a min_expiry watermark below which nothing is accepted.
```

The watermark is also what `HELLO` advertises (§3), so a peer can detect
an unbridgeable gap before spending capacity on it.

---


**Tombstones MUST be bounded.** A tombstone is useful only while some peer
might still hold the object, and `MAX_TTL` bounds that: past
`expiry + MAX_TTL` no honest peer holds it, and a dishonest one gains nothing
by offering it because RFC 1 §11's I2 rejects an expired object regardless.

An implementation MUST drop tombstones past that horizon. Without it the set
only grows — every expiry and every eviction inserts and nothing removes — on
a node RFC 4 §5.4 expects to run on constrained hardware.


## 9. Eviction under pressure

TTL handles the normal case. When storage fills before TTL:

```
Eviction MUST be oldest-first and uniform across shards.
Eviction policy MUST NOT depend on any property of an object other
than its age.
```

RFC 0 I-6. Every intuitive alternative is an oracle: evicting "least
likely to be mine" reveals that the node profiled it; evicting by shard
distance reveals the node's shard; evicting by source peer reveals
topology.

RFC 0 §7.4 makes this more important, not less: under partial coverage,
*which* objects a node holds is the entire question, and a policy-driven
holding set is directly readable by differential analysis. Declared
retention (RFC 3 §7.1) is what removes the inference; uniform eviction is
what keeps the residual clean.

---

## 10. Metrics

Per peer, windowed, aggregates only — RFC 3 §12 forbids per-object
provenance. Reconciliation contributes:

| metric | reads as |
|---|---|
| overhead share | reconciliation bytes ÷ total link bytes. Above 50% on a non-constrained link indicates misconfiguration |
| novelty ratio | objects received that were not already held |
| duplicate arrivals | over-connection here, under-connection elsewhere |
| unique-source contribution | the eclipse indicator |
| filter digest mismatches | credential drift, or an attempt to widen scope |
| RBSR round-trip count | rising counts mean divergence is not localising |
| watermark gap | peers whose retention cannot close this node's gap |

---

## 11. Erratum to RFC 3 §7.3

RFC 3 §7.3 presents filter-scoping as what makes reconciliation tractable
on constrained links. SIM-1 measured it: filter-scoping reduces LoRa
overhead from 100% to 68%.

**Necessary, not sufficient.** The corrected claim:

> Filter-scoping is required for convergence — an unscoped exchange
> produces permanent phantom divergence. It substantially reduces overhead
> on constrained links but does not make them cheap: 68–83% of LoRa
> capacity remains reconciliation rather than payload.

RFC 0 §9 lists "reconciliation overhead is affordable on constrained
links" as outstanding. The measured answer is **qualified**: affordable on
IP, dominant but survivable with LoRa as a minority transport, and
disqualifying where LoRa is the majority (§5).

No format or credential change is implied.

---

## 12. Security considerations

**A peer can lie about its fingerprints or its manifest**, hiding objects
from you. No reconciliation protocol prevents this. Partner diversity
(§6.2) and unique-source contribution (§10) are the defences, and they are
detection rather than prevention.

**RBSR round trips are an amplification vector.** A peer can manufacture
divergence patterns that fail to localise, costing round trips at no cost
to itself. §4.4's cap and fallback are the mitigation, and rising round
counts are a quota signal.

**Manifests reveal holdings to the peer**, which under partial coverage is
more information than under full coverage (RFC 0 §7.4). Filter-scoping
bounds the disclosure to what the link could carry anyway; declared
retention (RFC 3 §7.1) removes the inference from the remainder.

**Truncated identifiers are scope-bound.** §3.1. A 12-byte prefix is safe
because the agreed range already bounds the candidate set; outside that
range it is a 2⁴⁸ grinding target.

**Sync timing is the leak that survives all encryption.** §6.1. Everything
else in Krab protects content and recipients; scheduling protects the fact
that you are doing anything at all, and it is protected only by
discipline.

---

## 13. References

- KRAB RFC 0 — Architecture and Threat Model
- KRAB RFC 1 — Object Format and Cryptography
- KRAB RFC 3 — Peering, Credentials, and Accountability
- KRAB RFC 4 — Transport and Link Profiles
- KRAB SIM-0 — Corpus Convergence Measurements
- KRAB SIM-1 — Reconciliation Overhead Measurements
- Meyer, A. — range-based set reconciliation
- Negentropy / NIP-77 — RBSR in practice
- Bitcoin Erlay, minisketch — PinSketch set reconciliation (evaluated:
  requires a difference estimate and fails catastrophically when wrong)
- RFC 3977, NNTP — `IHAVE`/`SENDME`, the manifest exchange's ancestor
