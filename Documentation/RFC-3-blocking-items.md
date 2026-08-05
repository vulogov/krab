# RFC 3 — Blocking Item Status

    Status:      Working document, not an RFC
    Purpose:     the gate on RFC 3 reaching Draft
    Grounding:   SIM-0-results.md, SIM-0-audit.md, SIM-1-results.md, RFC-1.md
    Depends on:  RFC 0

RFC 3 specifies peering, credentials, and accountability. The series plan §7
puts it immediately after RFC 1 because "the negotiation triple is the most
under-specified piece and everything social depends on it."

Unlike RFC 1, **RFC 3 is revisable** — the credential format is not inside the
object identifier hash. That lowers the stakes on getting it right first time,
but it does not lower them on the two items below that are load-bearing for
other documents' claims.

This document tracks what RFC 3 must settle, what is already grounded, and
where the measurements do not exist yet.

---

## 1. Settled by measurement

### Credential expiry SHOULD be 90 days, not 60

The series plan proposes "expiry (60–90 d)" without choosing. The negotiation
triple is three signed static documents chained by hash —

```
peer-request  ->  peer-counter  ->  peer-link
```

— which is exactly three one-way legs. Over SIM-0's courier model (Poisson
journeys at a 7-day mean interval, 3-day transit; the wait is exponential and
therefore memoryless, so the expected wait is the full 7 days, not half of
it):

```
mean  30.0 d     p50  27.7 d     p90  46.2 d     p99  68.3 d
```

Against the two candidate expiries:

| credential expiry | establishment, mean | at p90 | renewal lead time | settled life | P(negotiation outlives a full term) |
|---|---|---|---|---|---|
| 60 d | 50.0 % | 77.0 % | ≥ 46 d | **14 d** | **2.44 %** |
| 90 d | 33.3 % | 51.4 % | ≥ 46 d | 44 d | 0.07 % |

Two consequences.

**At 60 days, roughly one courier peering attempt in forty cannot complete at
all** — the negotiation takes longer than the term of the credential it is
negotiating. RFC 0 §6 makes failure silent, so both operators simply see
nothing happen, repeatedly, with no signal distinguishing "still in flight"
from "structurally impossible."

**At 60 days a courier link spends 77 % of its life renewing.** Since
revocation is non-renewal (RFC 3's permanent design decision), renewal is not
a background task — it is the mechanism by which the link continues to exist.
A link that must begin renewing 46 days into a 60-day term is continuously
renegotiating.

At 90 days both problems become tolerable: 0.07 % structural failure, and 44
days of settled life against a 46-day renewal lead.

> **Recommendation: `CREDENTIAL_EXPIRY` = 90 days, and RFC 3 MUST state a
> renewal lead time derived from the peer's slowest transport rather than a
> fixed fraction of the term.** A 46-day lead is right for courier and absurd
> for TCP.

Reproduce with `rfc-3-runs/peering-latency.py`. This is analytic: RFC 0 §9
still lists "the peering flow completes over courier alone" as an outstanding
end-to-end test with the network down. The computation sizes that test, it
does not discharge it.

### The negotiation must carry its own validity, separate from the credential

Implied by the above and not currently specified. If `peer-request` and
`peer-counter` carry no expiry, they are replayable indefinitely; if they
carry the credential's expiry, the 2.44 % case above becomes a silent failure
mode. The negotiation window is a distinct parameter and RFC 3 must name it.

---

## 2. Inherited requirements — other documents depend on RFC 3 for these

### The retention floor must be able to express an eviction watermark

SIM-1 §4 found that capacity-pressure eviction drives a re-fetch loop: a node
evicts an object, its peer still holds it and offers it again, the node
re-accepts and evicts again. Ingress rose **68 %** at a 100 MB cap while
delivery stayed at 100 % — pure waste, concentrated on the links least able to
afford it.

The fix is a negotiated "do not offer me objects older than X" in the agreed
filter. RFC 5 owns the filter, but the filter must be derivable from the
signed credential so both sides provably agree (RFC 5's phantom-divergence
rule). **The retention floor in RFC 3's credential is the field that has to
carry it**, and it therefore needs to be a two-sided, per-direction commitment
rather than a one-sided promise.

### `transports` must determine `latency_class`, not just reachability

SIM-1 §1 found that reconciliation strategy has no safe default: a full
manifest starves 98.3 % of LoRa reconciliations, while RBSR collapses austere
delivery from 95.8 % to 33.0 % because each fingerprint-tree descent level
costs a courier round trip. RFC 5 must select per link from `latency_class`.

`latency_class` lives in RFC 4's `LinkProfile`, but the credential's
`transports` field is what tells a peer which profile applies before any
connection exists. If `transports` records only "reachable by X" and not the
latency class, RFC 5 cannot make its choice from signed data, and a peer could
induce the catastrophic strategy by misdeclaring.

### Quota is the sink for three separate abuse signals

RFC 1 and RFC 0 route accountability signals here without RFC 3 having defined
how they combine:

| signal | source | what it indicates |
|---|---|---|
| ingest rejection rate | RFC 1 §11 | malformed or hostile objects |
| tag-match / decrypt-success ratio | RFC 1 §6.4 | forced trial-decapsulation DoS |
| novelty ratio collapse | RFC 5 metrics, RFC 0 §5.4 | a relay dropping traffic |

RFC 3 must specify how these feed the quota dial, and in particular whether
quota reduction is reversible — the plan says "misbehaviour is quota
reduction, not disconnection," which only works if recovery is possible.

---

## 3. Open, with no grounding

### Graduated quota versus vantage acquisition — the important gap

SIM-1 §3 measured the attack RFC 3's graduated quota is supposed to blunt. An
adversary using only holdings and cleartext object age, under austere
transport below SIM-0's provisioning guidance:

| vantage points | true origin in top 10 of 500 | vs chance |
|---|---|---|
| 1 | 4.35 % | 2.2× |
| 25 | 12.45 % | 6.2× |
| 50 | 16.33 % | 8.2× |

SIM-1 §5 lists quota enforcement as explicitly unmodelled, so **the primary
defence against the attack was absent from the measurement of it.** RFC 0 §5.3
claims graduated quota "means early vantage points are low-bandwidth and slow
to become useful," and that claim is currently ungrounded.

It is also testable: a low-quota vantage point holds less of the corpus, which
directly weakens the holdings signal the attack depends on. Whether it weakens
it enough is a number nobody has.

**This is the SIM-2 item, and it should gate RFC 3 reaching Draft** — not
because RFC 3 cannot be written without it, but because RFC 3 will assert the
defence, and asserting an unmeasured defence is the failure the SIM-0 audit
was written about.

### Unmeasured, lower priority

- **Introduction token economics.** Private, single-use, expiring, bound to
  the requester's key. No measurement bears on the expiry or on how many a
  node should issue.
- **Nodelist fragment growth.** Two-hop visibility with `NODEDIFF`-style
  deltas. Fragment size and churn are computable from a degree distribution
  but have not been computed.
- **Rollcall corpus cost.** Self-published `bulletin` entries are class 1
  objects, and RFC 1 §5.2 already warns bulletins risk unbounded corpus
  growth. Rollcall's contribution is unestimated.
- **Handshake DoS caps.** RFC 4 owns the Noise slowloris defence, but
  concurrent-handshake limits interact with the quota dial.

---

## 4. Permanent decisions to restate, not re-litigate

RFC 3 should carry these explicitly because they will be proposed again:

- **Expiry replaces revocation.** No CRL, no revocation objects, no
  propagation. Non-renewal is the mechanism.
- **No public reputation or endorsement score.** Visible reputation
  concentrates into hubs; hubs become chokepoints, compulsion targets, and
  single points of failure (RFC 0 §6).
- **A list of *links* MUST NOT be published.** That is the social graph.
  Node self-attestations MAY be.
- **Bootstrap cost is a security property.** Joining requires knowing a
  participant. It is not a gap to close.

---

## 5. Gate

RFC 3 may reach Draft when:

- [x] credential expiry chosen on evidence — 90 d, §1
- [ ] renewal lead time specified per transport, not as a fixed fraction
- [ ] negotiation validity window named, separate from credential expiry
- [ ] retention floor specified as a two-sided per-direction commitment that
      RFC 5's filter can consume as an eviction watermark
- [ ] `transports` specified to carry latency class, not just reachability
- [ ] quota signal combination and reversibility specified
- [ ] SIM-2: graduated quota measured against vantage acquisition
- [ ] end-to-end peering test over courier with the network down (RFC 0 §9)

The last two are the ones that cannot be written around.
