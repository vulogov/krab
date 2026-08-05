# RFC 7 — Review

    Subject:  RFC 7, Key Custody and Erasure, Status: Draft
    Method:   cross-check against RFC 0, RFC 1, RFC 3, SIM-0, SIM-1, apps/krab-sizes
    Verdict:  one recurring defect, one cross-document contradiction, three gaps

RFC 7 is revisable — nothing in it is inside the object identifier hash. Its
§13 erratum to RFC 1 is the strongest piece of work in the series so far and
is treated as such below.

## Every figure verifies

`apps/krab-sizes` gained a `keys` module deriving RFC 7's arithmetic from the
constants RFC 7 states (32 B chunks, 60 B wrapped records, 100 µs per X25519
decapsulation, 416 B credentials from RFC 3). All four tables reproduce
exactly on the first run:

- reservoir sizing at 30/45/60/90 epochs, per peer and at 25 peers, and the
  11 680 B peer-year
- §6.1's headline — raw pad 74 752 000 B against reservoir 11 680 B, exactly
  **6 400×**
- §5.3's six batch rows: needed, batch, wire, bucket, including 8 192 keys
  exceeding `MAX_OBJECT` at 262 264 B
- §5.5's decapsulation costs, both columns, and the 200-object figures
  (30.7 s / 122.9 s / 0.06 s)
- §2.1's footprint, line by line, totalling 82 732 B

One constant is **recovered rather than derived**: the prekey batch wire size
is `32·N + 120`, and RFC 7 does not decompose the 120. A `bulletin` body per
RFC 1 §5.2 does not obviously account for it. Same class as RFC 3's fragment
wrapper and RFC 1's floor — the number is self-consistent across all six rows,
but a reader cannot check it.

---

## 1. Recurring defect — retention is still anchored to latency, not to `MAX_TTL`

This is the third appearance of one mistake, and the first two are already
fixed in this repository.

RFC 7 states its retention rules against measured behaviour:

> §12: "The grace window … must exceed maximum delivery latency"
> §5.2: "Retire a batch at expiry plus a grace window of roughly 2× maximum
> delivery latency"

But the protocol's guarantee is not a latency percentile. RFC 1 §11 check 2
accepts any object whose `expiry_min` is within `MAX_TTL` — 45 days — and
RFC 1 §6.2 (as corrected here) requires computing tags across that whole span.
Against SIM-0's measured tails:

| | latency | 1× | 2× | `MAX_TTL` |
|---|---|---|---|---|
| austere p99 | 15.9 d | 15.9 d | 31.9 d | **45 d** |
| all-courier p99 | 16.9 d | 16.9 d | 33.9 d | **45 d** |

**Both rules under-provision.** A chunk erased at 1× or 2× maximum observed
latency is destroyed while objects it decrypts are still valid, still
in flight, and still being offered by peers. The recipient accepts the object
under §11, stores it, and cannot read it — the exact failure the `EPOCH_WINDOW`
fix removed from RFC 1, reintroduced one layer down.

RFC 7's own arithmetic already uses the right number: §2.1 computes the
footprint at 45-epoch retention, and the reservoir table offers 45 as a row.
**The number is right and the rule that generates it is wrong**, which is the
dangerous combination — it works today and breaks silently the first time
`MAX_TTL` moves or an implementer follows §12 literally.

The pattern is worth naming, because it has now cost three findings: *a
retention parameter in this series must be derived from the protocol's
declared guarantee, never from measured behaviour.* Measured behaviour is
what the guarantee is chosen to cover, not a substitute for it.

**Fix.** State both as expressions:

- chunk retention `≥ MAX_TTL / EPOCH` (45 epochs)
- prekey batch retirement `≥ MAX_TTL` after the batch stops being a selection
  candidate

and add the resulting exposure floor to §12 plainly: a seizure costs 45 days,
whatever the epoch length.

---

## 2. Contradiction — §5.4's LoRa conclusion assumes a gate RFC 1 does not

§5.4 concludes that **no prekey batch can cross a LoRa link**, and builds a
significant design consequence on it: "the reservoir is the only
forward-secrecy mechanism available on constrained links."

The table uses a 512-byte LoRa object gate. But RFC 1 §8.3 tabulates LoRa
airtime for the 256, 1 024 and **4 096**-byte buckets — so RFC 1 plainly
expects LoRa to carry objects eight times that gate. At RFC 1's gate:

```
batch  64:  2 168 B -> 4 096 bucket   crosses at a 4096 B gate
batch 128:  4 216 B -> 16 384 bucket  does not
```

A 64-key batch fits. At 5 received messages/day that is 13 days of keys, and
one republication costs 4 096 B against a LoRa link's ~73 KB/day budget
(SIM-1 §1) — about 5% of one day. Workable.

So §5.4's conclusion inverts depending on a number the two documents disagree
about. This is the same 512-byte gate the SIM-0 audit flagged as pathological:
paired against SIM-0's traffic model it admitted **0.16%** of objects, making
LoRa inert rather than slow.

The design consequence survives in weakened form — prekey FS on LoRa is
limited to small batches and therefore to low-traffic correspondents, which is
a real constraint — but "structurally unavailable" is too strong, and the
reservoir's claim to being the *only* mechanism does not hold.

**Fix.** RFC 4 must pin one LoRa `max_object_size` and both documents must
cite it. Until then §5.4 should state its gate assumption explicitly.

---

## 3. §13's erratum is correct, and the mechanism deserves recording

RFC 7 §13 upgrades RFC 1 §6.3's deterministic prekey indexing from SHOULD to
MUST, on measurement: exhaustive search across a 512-key batch at 200
tag-matched objects costs **30.7 s**, and 2 048 keys costs **122.9 s**, against
0.06 s with indexing. All four figures reproduce.

The reasoning is right, and the refinement in §13.3 is better than RFC 1's own
text: inbox-mode objects have no sender to index by, so they genuinely require
exhaustive search — which localises RFC 1 §6.4's decapsulation DoS to inbox
mode specifically, rather than to all traffic. RFC 1 states it more broadly
than necessary.

The argument that RFC 1 stays frozen is sound. RFC 1 §1 freezes the
*encoding*; a requirement level is not an encoding, and no wire bytes change.

**Process gap, worth closing now that it has been used once.** The series has
no defined errata mechanism — RFC 0 §10's roadmap and §10.1's
forward-compatibility rules describe versioning, not corrections to frozen
prose. Since RFC 1 cannot be revised and will accumulate more of these, RFC 0
should say where errata live and how a reader of RFC 1 discovers that §6.3 has
been superseded. A reader who finds RFC 1 alone currently gets the weaker
requirement with no pointer.

---

## 4. Gap — remote reservoir establishment is unspecified

§6.2 permits network establishment and requires a hybrid KEM for it. §6.4 then
says establishment "is step 3 of the peering ceremony (RFC 3 §11), not a
separate operation someone might skip."

RFC 3 §11 is the **in-person** ceremony. RFC 3 §11.1 covers remote peering and
never mentions reservoirs. So the path most correspondents will actually take
is described by neither document: §6.4 binds establishment to a ceremony that
remote peers do not perform, and §6.2's network path has no specified carrier,
ordering, or relationship to the negotiation triple.

This matters more than a normal gap because of RFC 1 §6.5, which is frozen and
declares the reservoir Krab's *primary* post-quantum strategy. If the reservoir
is only reliably established in person, that claim holds for a minority of
correspondents.

The economics argue for making the network path primary: one hybrid-KEM
establishment costs a single 4 096 B object against a 3 072 B per-message
surcharge, so it repays after **1.33 messages** and is 75× cheaper at a hundred.

**Fix.** Specify reservoir establishment as a fourth document in RFC 3 §5's
chain, or as a defined follow-up object, so it has the same courier-safe
static-document property as the rest of peering.

---

## 5. Gap — "under 100 KB" is batch-dependent, and §9 rests on it

§2.1's 82 732 B total assumes a 1 024-key batch. §9's `mlock` requirement is
justified by that total being "under 100 KB."

At the largest batch §5.3 permits without exceeding `MAX_OBJECT` — 2 048 keys,
which §5.3's own table prescribes for a node receiving 100 messages/day — the
prekey privates double to 65 536 B and the footprint reaches **115 500 B**.
Still small, but past the stated bound, and a high-traffic node is exactly the
one under memory pressure.

**Fix.** State the footprint as a function of batch size, and set the
`RLIMIT_MEMLOCK` requirement against the largest permitted batch rather than
the assumed one. §9 already requires failing loudly when locking is
unavailable, which is right — this just needs the ceiling computed correctly.

---

## 6. Minor

- **Dead-man timer sizing (§10) is still untied to deployment.** §10 requires
  a warning before firing but does not relate N to the offline periods RFC 3
  §15 anticipates for courier nodes — which are the population most likely to
  trip it accidentally, and the population least able to recover.
- **§6.2's physical-exchange framing.** Keeping `R_A ⊕ R_B` as the gold
  standard is right, and the rationale — neither party's RNG alone determines
  the result — is a good argument that the plan did not make. It sits awkwardly
  against §4 above, where the network path needs to be routine.
- **§12's honesty is a strength worth preserving.** "Krab does not have
  per-message forward secrecy and should not claim it," and §9.1's admission
  that Rust cannot guarantee a secret was never copied, are the kind of stated
  limits that make the rest credible.

---

## 7. Consistency items this review does not close

Carried from `RFC-7-blocking-items.md`; RFC 7 does not address them and they
belong to other documents:

- **RFC 0 §11** still defines the epoch as one period shared by tag derivation
  and key erasure. §1 above shows erasure lags rotation by `MAX_TTL / EPOCH`.
- **RFC 0 §7.5** bounds pre-forward-secrecy exposure by the signed-prekey
  rotation period; with §1's floor the binding constraint is
  `max(rotation period, MAX_TTL)`.
- **Prekey burn under group fan-out** is now partly computed — §5.3 covers
  received-message rate, and correctly identifies group membership as the
  driver — but RFC 3 §14's per-device multiplier is not folded in. A
  three-device operator in a 20-person group receives 3× the fan-out.
