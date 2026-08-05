# RFC 2 — Review

    Subject:  RFC 2, Addressing and Tag Derivation, Status: Draft
    Method:   cross-check against RFC 0/1/3/6/7, SIM-0, apps/krab-sizes
    Verdict:  one direct contradiction of a frozen document; the erratum is right

RFC 2 arrives with an erratum that corrects two documents already at Draft,
and the erratum is sound — §2 below verifies it and withdraws a finding this
repository made against RFC 6. It also contradicts RFC 1's frozen normative
text in §5, which is the more serious problem.

## Every figure verifies

`apps/krab-sizes` gained a `tags` module. All four tables reproduce exactly —
the precomputation table across six configurations and all four columns, the
false-match probabilities, the shard dial, and §7.3's collision figures. 36
tests now pass across RFC 1, 2, 3, 6 and 7.

One inconsistency: §4.3 costs a static-static X25519 at 60 µs, while RFC 7
§5.5 costs an X25519 decapsulation at 100 µs. Both are plausible — a raw ECDH
is cheaper than a full decapsulation — but the two documents should say which
operation they mean.

---

## 1. Contradiction — §5 requires a window RFC 1 forbids

RFC 2 §5:

> `W MUST default to ±30 epochs.`
> `W MUST NOT be below ±14 — that fails to cover the measured p99.`

RFC 1 §2 and §6.2, as they stand in this repository:

> `EPOCH_WINDOW` = **±45 epochs**, = `MAX_TTL / EPOCH`
> "**`EPOCH_WINDOW` MUST be at least `MAX_TTL / EPOCH`, and is therefore ±45.**
> … A deployment MAY widen it. It MUST NOT narrow it below `MAX_TTL / EPOCH`."

**RFC 2's default is below RFC 1's floor, and RFC 2's stated minimum is a
third of it.** RFC 1 is the frozen document.

The reasoning is the same one this series has now made four times: §5's table
compares each candidate window against **measured p99 delivery latency** and
has no `MAX_TTL` column. Had it, ±30 against a 45-day guarantee would have
been visibly short. RFC 1 §6.2's own corrected text says why the anchor is
wrong — a p99 is not a bound, and the protocol's guarantee is `MAX_TTL`, which
RFC 1 §11 check 2 accepts unconditionally.

The failure is concrete and silent: an object created at epoch *E*, delivered
at day 40 — legal under RFC 1 §11 — arrives at a recipient running ±30 who
never computed `tag_E`. §11 accepts the object, the store keeps it, and it is
undecryptable.

**Fix.** Delete §5's requirement block and defer to RFC 1 §6.2. If RFC 2 wants
to keep the table, add a `MAX_TTL` column so the floor is visible. The table
is otherwise useful — the "table growth" column is exactly the cost RFC 1's
±45 imposes, and it is 1.5×, which is 55 KB at 50 correspondents.

This is the fourth occurrence: RFC 1 §6.2 originally, RFC 7 §12 and §5.2, and
now RFC 2 §5. The pattern has cost four findings and is worth an explicit rule
in RFC 0: *any retention or acceptance parameter MUST be expressed as a
function of the protocol's declared guarantee, never of a measured percentile.*

---

## 2. The erratum is correct, and it withdraws a finding of ours

§8.1 corrects RFC 7 §5.3 and RFC 6 §2.8. Both sized prekey batches by messages
received × republish interval. That is right only under *random* prekey
selection — and RFC 7 §13 made deterministic indexing mandatory, under which
`i = H(sender ‖ batch) mod N` is fixed per sender per batch. A sender sending
one message and a sender sending a thousand consume the same single index.

The driver is therefore distinct correspondents, and every consequence follows:

| scenario | published | corrected | shrink |
|---|---|---|---|
| group of 50, monthly | **8 192 — "impossible"** | **256** | **32×** |
| busy node, 100 msg/day | 8 192 | 512 | 16× |

All five rows reproduce, as does the collision model `S²/2N` and the `N ≥ 5S`
rule that holds sharing at ≤10%.

**This withdraws a finding from `RFC-6-blocking-items.md` §2 and
`RFC-6-review.md`.** Both stated that a 50-person group makes monthly prekey
republication *structurally impossible* because the batch would exceed
`MAX_OBJECT`. Under the corrected model that group needs a 256-key batch of
8 312 bytes, which fits the 16 K bucket. The constraint does not exist, and
neither does the "MUST republish weekly" requirement RFC 6 §2.8 derived from
it. The claim was arithmetic built on the wrong model, and both RFC 7 §5.3 and
this repository's review propagated it.

§8.1's four consequences are each checked and each holds. In particular
point 3 is right for a subtle reason worth stating: forward-secrecy
granularity does not weaken, because RFC 7 §5.2's "delete on schedule, never
on use" already retains every prekey in a live batch. Random selection would
have spread messages across more keys, but a store compromise takes the whole
batch either way, so the granularity was already the batch period.

Point 4 is also right and worth noting for its restraint: the erratum does not
rescue LoRa. Even a 64-key batch is 2 168 B against the 512 B gate.

---

## 3. Gap — the tag table is key material and is missing from RFC 7's footprint

§9 states plainly that the precomputation table "is the single most valuable
artifact on a seized running node and MUST be treated as key material under
RFC 7 §9, never paged, never logged, never persisted." That is correct.

RFC 7 §2.1's footprint does not include it, and RFC 7 §9's `mlock` requirement
is justified by that footprint being "under 100 KB":

| configuration | tag table | + RFC 7 footprint |
|---|---|---|
| RFC 7 §2.1 as published | — | 82.7 KB |
| 50 correspondents, ±45 | 54.6 KB | **137 KB** |
| 200 correspondents, ±30 | 146.4 KB | **229 KB** |
| 500 correspondents, ±45 | 546.0 KB | **629 KB** |

At RFC 1's mandatory ±45 and 50 correspondents — an ordinary node — the table
alone is two-thirds of everything RFC 7 counted. The "under 100 KB" claim
fails, and it was already failing for a second reason (`RFC-7-review.md` §5,
where a 2 048-key batch takes the footprint to 115 KB).

`mlock` remains entirely practical at these sizes; what needs correcting is
the number RFC 7 §9 cites as its justification and the `RLIMIT_MEMLOCK`
headroom implementations are told to check.

---

## 4. Gaps — two of the three items RFC 2 was opened for are unaddressed

`RFC-2-blocking-items.md` identified three findings with no addressing home.
RFC 2 addresses one.

**The inbox-tag counting leak (§2.1 of the gate document) is understated.**
RFC 2 §9 says "anyone holding a recipient's public key can compute their inbox
tag and enumerate messages sent to it **during the current epoch**." The scope
is larger. RFC 3 §9.1 publishes `kx_pk` in a rollcall entry, which is a
`bulletin` object that persists for its TTL and indefinitely on any archival
relay — the adversary RFC 0 §7.6 says exists. Such an adversary computes every
past epoch's inbox tag and counts inbound peering attempts across all history,
not the current epoch.

RFC 2 §4.2's framing — "a real cost, accepted rather than hidden" — is the
right posture, but the cost stated is smaller than the cost incurred. RFC 3
§9.1 also still lists `kx_pk` under "may be published" with no mention of the
consequence.

**Per-class shard masks (§2.2) are not specified.** §6 covers the shard dial
well, including the observation that load reduction and anonymity-set
reduction are the same number — which is the sharpest statement of that
tradeoff anywhere in the series. But RFC 6 §3.4's requirement that channels
occupy a separate shard space still has no mechanism: a node's mail shard mask
and its channel shard mask must differ, and §6 describes a single `k` applied
to the tag. Either RFC 2 adds per-class masking or RFC 6 §3.4 must be amended.

**The inbox decapsulation cap (§2.3) is still unsized.** §7.4 requires
implementations to "cap inbox-tagged decapsulation attempts per peer per
epoch" and gives no number — the same wording RFC 7 §13.3 used. RFC 7 §5.5's
measured costs make a CPU-budget derivation straightforward, and RFC 2 is the
document that should do it.

---

## 5. What RFC 2 got right

- **§5.1 grounds the clock skew tolerance that `RFC-1-review.md` §5 flagged as
  the one parameter with no basis.** The asymmetry — receive permissively,
  emit conservatively, because a bad clock on emission poisons other nodes'
  stores irreversibly — is a good argument, and "the corpus is itself a clock"
  is a mechanism requiring no infrastructure. This closes a real gap.
- **§2's concrete failure mode** for namespace separation: a presence beacon
  carrying a tag beside a timestamp is a tracking beacon. Naming the specific
  well-intentioned feature that would break the invariant is more useful than
  restating the invariant.
- **§6's "the two columns are the same number."** Load reduction and
  anonymity-set reduction are identical, so there is no free configuration.
- **§3's rejection-over-repair rule** for address canonicalisation, and the
  X.400 citation as cautionary prior art rather than as precedent.
- **§9's honesty about static-static ECDH** — rotation costs 12 ms locally and
  a great deal socially, and in-flight messages are lost, which on a courier
  route is weeks of traffic.

---

## 6. Consistency items

- **RFC 1 §6.2 and RFC 2 §5** — direct contradiction on `EPOCH_WINDOW`. §1.
- **RFC 7 §2.1 and §9** — footprint omits the tag table; the "under 100 KB"
  justification fails twice over. §3.
- **RFC 6 §2.8 and RFC 7 §5.3** — superseded by §8.1's erratum; both should
  carry a pointer, since a reader finding either alone gets the wrong model.
- **RFC 3 §9.1** — must disclose that publishing `kx_pk` makes inbound
  first-contact volume permanently countable. §4.
- **RFC 0 §10** — roadmap should now show RFC 2 as required *by* RFC 5 and
  RFC 6 rather than the reverse, which is how it has actually turned out.
- **RFC 0** — should carry the general rule from §1: acceptance and retention
  parameters are functions of declared guarantees, not of measured
  percentiles.
