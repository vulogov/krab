# Documentation

> ## ⚠ Open critical defect
>
> **RFC 7 §6's reservoir key derivation MUST NOT be implemented as written.**
> It derives one message key per (pair, epoch) rather than per message, which
> is keystream reuse and Poly1305 one-time-key recovery. Marked in place in
> `RFC-7.md` §6 and §6.1, with the dependency noted in `RFC-1.md` §6.5.
> Recommended fix — HPKE `mode_auth_psk` with the chunk as PSK — needs no
> format change. Full analysis in [`CRYPTO-REVIEW.md`](CRYPTO-REVIEW.md) §1.

Grounding documents for the Krab RFC series. No RFC may assert a
convergence, delivery, or storage claim that is not measured here.

## SIM-0 — corpus convergence

| document | what it is |
|---|---|
| [`SIM-0-results.md`](SIM-0-results.md) | the measurements RFC 0 §8 cites, annotated where the audit contradicts them |
| [`SIM-0-audit.md`](SIM-0-audit.md) | source review and instrumented re-runs; **read before citing any figure** |
| [`sim-0-runs/sweeps.txt`](sim-0-runs/sweeps.txt) | captured output for every sweep, with audit diagnostics |

## SIM-1 — reconciliation overhead and holdings analysis

| document | what it is |
|---|---|
| [`SIM-1-results.md`](SIM-1-results.md) | answers SIM-0's largest omission and the two questions RFC 0 deferred |
| [`sim-1-runs/sweeps.txt`](sim-1-runs/sweeps.txt) | captured output for every SIM-1 run |

SIM-1 is implemented as flagged extensions to the same simulator, so every
figure is measured on the same network, seeds, and generators as the SIM-0
figure it is compared against. With no flags `krab-sim` reproduces SIM-0
byte-identically, which is the regression check.

Headline findings:

- **LoRa requires RBSR; courier forbids it.** A full manifest starves 98.3% of
  LoRa reconciliations; RBSR collapses austere delivery from 95.8% to 33.0%
  because each descent level costs a three-day courier round trip. RFC 5's
  `sync_mode` has no safe default.
- **Keep 32-byte identifiers (B3).** Sync-mode choice dominates identifier
  length by 80× against 3.3×, so there is no bandwidth reason to weaken
  content addressing.
- **The holdings leak is under-provisioning, not a coverage threshold.** It
  beats chance by up to 8× under austere transport below SIM-0's own peer and
  TTL guidance, and vanishes at degree 12 with a 30-day TTL. **B2 is
  unblocked**: `expiry` can stay in the frozen header at useful resolution.
- **Uniform eviction makes the holding set deterministic, not
  uninformative** — a node's storage cap plus object age determines it
  exactly, and the age gradient inverts under a cap. RFC 0 §7.4 and SIM-0 §6
  currently claim the opposite. Eviction also drives a re-fetch loop costing
  up to 68% extra ingress.

The simulator itself is [`apps/krab-sim`](../apps/krab-sim). It has no
dependencies, internal or external, so any reviewer can rebuild and re-run it
offline with nothing to vendor-trust:

    cargo build --release -p krab-sim
    ./target/release/krab-sim --diag --sweep mix

### Standing corrections

Three columns in `SIM-0-results.md` do not mean what their names suggest, and
one headline conclusion rests on a metric artifact:

- **LoRa edges carried 0.16% of objects** in every published run — a 512 B
  size gate against a traffic distribution whose floor is 500 B. No figure in
  the series measures radio transport. Capacity arithmetic says a LoRa link
  supplies ~2% of one peer-share of the flood regardless of object size.
- **The 37.2% coverage headline is a propagation ramp**, not a steady-state
  holding fraction. Settled coverage in the same run is 76.4%, and is 100% in
  every configuration meeting SIM-0's own minimum peer count and TTL. The
  durable finding is different and sharper: holding probability is a steep
  function of object *age* in every configuration, and age is readable from
  the cleartext `expiry` field that blocking item B2 freezes permanently.
- **`storeMB` and `rxMB/d` are p99-across-nodes of a peak-over-time**, not
  means.

Two of these carried a deadline against RFC 1's frozen routing header. SIM-1
resolves both — see `SIM-1-results.md` §3 and §6.

## RFC 1

| document | what it is |
|---|---|
| [`RFC-1.md`](RFC-1.md) | the object format and cryptography, Status: Draft |
| [`RFC-1-review.md`](RFC-1-review.md) | cross-check against SIM-0, SIM-1 and `krab-sizes`; **read before Draft becomes Final** |
| [`RFC-1-blocking-items.md`](RFC-1-blocking-items.md) | the gate document that preceded the Draft; records which rows were settled on what evidence |

RFC 1 freezes the object format permanently — it closes every open B3 row.
All 54 of its published byte counts are reproduced exactly by
[`apps/krab-sizes`](../apps/krab-sizes), which derives the size model
independently from §4.2/§6/§7 and gates on it:

    cargo run --release -p krab-sizes -- --check

The review finds one blocking defect, now fixed, and four items worth
resolving before Final:

- ~~**`EPOCH_WINDOW` (±30 epochs) is smaller than `MAX_TTL` (45 days).**~~
  **Fixed** — an object delivered inside its declared TTL could arrive up to
  45 epochs after creation, leaving 15 epochs' worth silently undecryptable.
  §2 and §6.2 now set ±45 with the bound stated as `MAX_TTL / EPOCH`.
- **§9.3 defers to SIM-1, which is complete and disagrees.** Manifest exchange
  is survivable on LoRa only at a filter width that makes the link useless;
  at the width §8.3 itself assumes, a full manifest starves 98.3% of
  reconciliations.
- **Key 3 `admission` has ambiguous presence** and sits inside the identifier
  hash — two conforming implementations could compute different identifiers
  for identical content.
- **`MAX_OBJECT` leaves 5.3% of the modelled traffic unrepresentable**, with
  no object-level chunking specified.
- **Clock skew ±6 h is the one parameter with no grounding.**

## RFC 3

| document | what it is |
|---|---|
| [`RFC-3.md`](RFC-3.md) | peering, credentials, and accountability, Status: Draft |
| [`RFC-3-review.md`](RFC-3-review.md) | cross-check against SIM-0, SIM-1, RFC 0/1 and `krab-sizes` |
| [`RFC-3-blocking-items.md`](RFC-3-blocking-items.md) | the gate document that preceded the Draft |
| [`rfc-3-runs/peering-latency.py`](rfc-3-runs/peering-latency.py) | negotiation completion over the corpus |

RFC 3 is revisable — the credential format is not inside the identifier hash —
so nothing in it is irreversible the way RFC 1's findings were. §8.1 and §8.2
reproduce exactly in `krab-sizes` from `fragment(P) = 220 + 416·P`, and the
§13 cap of 25 peers is confirmed load-bearing: a weekly fragment publication
fits in a week of LoRa airtime at 25 peers (3.7 d) and not at 50 (14.6 d).

The review's leading findings:

- **Composition defect.** RFC 1 §6.2 derives the inbox tag from the
  recipient's public key; RFC 3 §5.1 sends peer-requests there as flooded
  corpus objects; RFC 3 §9.1 publishes that key in the rollcall. So anyone can
  compute a listed node's inbox tag and **count its inbound peering attempts,
  per epoch, permanently** — RFC 0 §7.6 means archival relays never forget.
  Neither document is wrong alone. A separate rotating contact key fixes it.
- **12.1% of austere peering negotiations are silently lost.** Each of the
  three legs is a corpus delivery, and delivery rates compound: 0.958³ = 87.9%.
  RFC 3 specifies no retry, though a `peer-request` is idempotent and three
  attempts would take the loss to 0.18%.
- **Retention is a promise, not a capacity**, so SIM-1 §4's +68% re-fetch loop
  survives §7.3's otherwise-correct filter mechanism.
- **`transports` carries endpoints but not latency class**, so RFC 5 cannot
  pick `sync_mode` from signed data — and picking wrong costs 98.3% starved
  LoRa reconciliations or 33% austere delivery.
- **§13's peer counts contradict RFC 0 §8.2.** RFC 3 is the correct one;
  RFC 0 should be updated.

## RFC 7

| document | what it is |
|---|---|
| [`RFC-7.md`](RFC-7.md) | key custody and erasure, Status: Draft |
| [`RFC-7-review.md`](RFC-7-review.md) | cross-check against RFC 0/1/3, SIM-0/1 and `krab-sizes` |
| [`RFC-7-blocking-items.md`](RFC-7-blocking-items.md) | the gate document that preceded the Draft |
| [`rfc-7-runs/reservoir.py`](rfc-7-runs/reservoir.py) | reservoir sizing and post-quantum economics |

RFC 7 became load-bearing when RFC 1 froze: **RFC 1 §6.5 names the
epoch-chunked reservoir Krab's *primary* post-quantum strategy.** Every figure
RFC 7 publishes reproduces exactly in `krab-sizes/keys` — the reservoir table,
the 6 400× pad comparison, all six batch rows, the decapsulation costs, and
the 82 732 B footprint line by line.

- **§13's erratum is the strongest work in the series.** It upgrades RFC 1
  §6.3's deterministic prekey indexing from SHOULD to MUST on measurement
  (30.7 s against 0.06 s), and correctly narrows RFC 1 §6.4's DoS surface to
  inbox mode, which has no sender to index by. The series has no defined
  errata process, though — now that one has been used, RFC 0 should say where
  errata live.
- **Retention is still anchored to latency rather than to `MAX_TTL`** — third
  occurrence of one defect. §12 and §5.2 size grace windows at 1× and 2×
  maximum delivery latency (15.9 d and 31.9 d against SIM-0's austere p99),
  both short of the 45-day guarantee RFC 1 §11 actually makes. §2.1's
  arithmetic already uses 45; the rule that generates it does not.
- **§5.4's "no prekey batch can cross a LoRa link" assumes a 512-byte gate
  that RFC 1 §8.3 contradicts** by tabulating airtime to the 4 096-byte
  bucket. At RFC 1's gate a 64-key batch does cross, so the reservoir is not
  the *only* forward-secrecy mechanism on constrained links.
- **Remote reservoir establishment is unspecified.** §6.4 binds it to RFC 3
  §11's in-person ceremony; RFC 3 §11.1's remote path never mentions it.

## RFC 6

| document | what it is |
|---|---|
| [`RFC-6.md`](RFC-6.md) | groups and channels, Status: Draft |
| [`RFC-6-review.md`](RFC-6-review.md) | cross-check against RFC 0/1/3/7, SIM-0 and `krab-sizes` |
| [`RFC-6-blocking-items.md`](RFC-6-blocking-items.md) | the gate document that preceded the Draft |
| [`rfc-6-runs/fanout.py`](rfc-6-runs/fanout.py) | fan-out cost: sharding threshold and prekey burn |

Groups are fan-out, channels are flood: opposite security models *and*
opposite cost classes, quadratic against constant. §4's crossover table makes
the choice arithmetic rather than preference, which is the clearest organising
idea in the series. All five of RFC 6's tables reproduce in `krab-sizes`.

- **§3.4's "channels MUST occupy a separate shard space" does not follow from
  RFC 1.** Shard derives from the tag, and a bulletin's tag is BLAKE3-derived
  over the same uniformly-distributed space as sealed tags — there is no
  separate space to occupy. The intent needs a **per-class shard mask**, which
  is RFC 5's filter design and is specified nowhere.
- **§2.3 reports one group against the whole baseline (3% at G=20), not a
  network that uses groups.** Systemically the multiplier is **19×**, which
  moves RFC 0 §8.3's sharding threshold from ~4 900 nodes to **~260**. RFC 6
  is the document that invalidates that threshold and does not say so.
- **§2.7's stagger rests on an asserted 10% detection threshold**, and its
  latency cost is worst in small networks — 2.5 days for a 50-member group at
  n=100, before propagation even starts.
- **Neither SIM-0 nor SIM-1 models fan-out**, so its interaction with
  eviction, holdings analysis and manifest size is unexamined.

## RFC 2

| document | what it is |
|---|---|
| [`RFC-2.md`](RFC-2.md) | addressing and tag derivation, Status: Draft |
| [`RFC-2-review.md`](RFC-2-review.md) | cross-check against RFC 0/1/3/6/7, SIM-0 and `krab-sizes` |
| [`RFC-2-blocking-items.md`](RFC-2-blocking-items.md) | the gate document; asked whether RFC 2 should exist |
| [`rfc-2-runs/inbox-leak.txt`](rfc-2-runs/inbox-leak.txt) | why rotating a published contact key does not close the counting leak |

RFC 1 had absorbed five of RFC 2's seven original items, so the gate document
asked whether RFC 2 should exist at all. The Draft answers by repopulating it —
and by carrying an erratum that corrects two documents already at Draft.

- **§8.1's erratum is right, and it withdraws a finding of ours.** Prekey
  batches are sized by *distinct correspondents*, not messages received:
  deterministic indexing (RFC 7 §13) fixes one index per sender per batch, so a
  sender's message volume is irrelevant. A 50-person group needs 256 keys, not
  8 192. **The `MAX_OBJECT` ceiling does not exist**, and neither does RFC 6
  §2.8's "MUST republish weekly" — nor this repository's claim that monthly
  republication was structurally impossible.
- **§5 contradicts RFC 1, which is frozen.** RFC 2 sets `W` to ±30 by default
  and permits ±14; RFC 1 §6.2 requires `W ≥ MAX_TTL / EPOCH` = **±45** and
  forbids narrowing. §5's table has no `MAX_TTL` column, which is how it
  happened — the **fourth** occurrence of anchoring a retention parameter to a
  measured percentile instead of the declared guarantee.
- **The tag table is key material and is missing from RFC 7's footprint.**
  RFC 2 §9 says so explicitly; at 50 correspondents and RFC 1's mandatory ±45
  it is 54.6 KB against the 82.7 KB RFC 7 §2.1 counted, so RFC 7 §9's "under
  100 KB" `mlock` justification fails.
- **§5.1 closes a real gap** — it grounds the ±6 h clock skew that RFC 1's
  review flagged as the one parameter with no basis, using the corpus itself
  as a clock.

## RFC 4

| document | what it is |
|---|---|
| [`RFC-4.md`](RFC-4.md) | transport and link profiles, Status: Draft |
| [`RFC-4-review.md`](RFC-4-review.md) | cross-check against RFC 0/1/3/5/6/7, SIM-0/1 and `krab-sizes` |
| [`RFC-4-blocking-items.md`](RFC-4-blocking-items.md) | the gate document that preceded the Draft |
| [`rfc-4-runs/lora-gate.py`](rfc-4-runs/lora-gate.py) | the gate analysis, now superseded by RFC 4 §5.4 |

RFC 4 settles the LoRa gate four documents had been assuming differently, and
settles it better than the gate document did. All five of its tables reproduce
in `krab-sizes`.

- **RFC 4's cap supersedes ours.** The gate document recommended 4 096 B;
  RFC 4 §5.4 caps at bucket **1 024** for SF7–SF10, correctly — our model
  omitted fragmentation and FEC, which add 39% on the wire and put a 4 096-byte
  object at 1.9 hours. §3's treatment of `max_bucket` as a *bucket index
  rather than a byte count* reaches our finding independently and states it
  better: a 512-byte gate "admits nothing above the 256-byte bucket while
  appearing to admit more."
- **`sync_mode` cannot be a local field.** §3 puts it and `latency_class` on
  the local side of the credential line. Reconciliation is two-party: if one
  end runs `Manifest` and the other `Rbsr` they do not reconcile at all, and
  SIM-1 §1 measured the cost of picking wrong at 98.3% starved or 33% delivery.
  A peer can induce either by misdeclaring.
- **§5.4 defers to SIM-1, which is complete** — and SIM-1's answer is a
  `LinkProfile` requirement RFC 4 owns: a LoRa profile MUST use RBSR.
- **The cap's coverage cost is unstated.** At bucket 1 024 a LoRa peer can
  receive **4.8%** of realistic text traffic; at 4 096 it would be 45.7%.

## RFC 5

| document | what it is |
|---|---|
| [`RFC-5.md`](RFC-5.md) | synchronisation, Status: Draft |
| [`RFC-5-review.md`](RFC-5-review.md) | cross-check; **RFC 5's grounding is not in this repository** |
| [`RFC-5-blocking-items.md`](RFC-5-blocking-items.md) | the gate document that preceded the Draft |
| [`rfc-5-runs/sync-mode.py`](rfc-5-runs/sync-mode.py) | the `sync_mode` decision procedure |

RFC 5 completes the series. §4.2 is its strongest section: RBSR is the wrong
algorithm exactly where it was expected to win, because §2's filter already
made `n` small, so RBSR's fixed costs dominate. The two modes are complements.

Its figures cite `ovhd%`/`waste%` columns and a `PushOnly` mode that do not
exist in `apps/krab-sim`, and where the two overlap they disagree — this
repository's SIM-1 measures austere all-RBSR delivery at **33.0%** against
RFC 5's 64.8%. The conclusion survives either number; the figure should not be
cited until the extension is committed.

## Cryptographic review

| document | what it is |
|---|---|
| [`CRYPTO-REVIEW.md`](CRYPTO-REVIEW.md) | composition review of RFC 1, 2, 4 and 7 — **not a substitute for external review** |

RFC 0 §9 requires external cryptographic review and that requirement stands.
This is one reviewer reading for composition errors, with no formal analysis
and no tooling. Four findings warrant fixing regardless of what external
review later concludes:

- **CRITICAL — the reservoir derives one message key per epoch, not per
  message.** RFC 7 §6.1 justifies having no counter on the grounds that the tag
  is "already unique per message." It is not: RFC 1 §6.2 derives it from a
  static-static secret and the epoch, and RFC 2 §4.3's precomputation table
  confirms one tag per correspondent per epoch. So `msg_key` is constant for a
  pair for a day. Recommended fix is HPKE `mode_auth_psk` with the chunk as
  PSK — per-message keys, post-quantum, epoch-granular forward secrecy, and no
  format change.
- **HIGH — Ed25519 malleability defeats duplicate suppression.** Malleating a
  bulletin's signature yields a byte-different object with a different
  identifier that still verifies, so one valid signature amplifies into
  unbounded distinct objects every node stores. Strict verification fixes it.
- **HIGH — raw X25519 output is used as an HKDF PRK without Extract**, and
  low-order points are not rejected. A peer publishing a low-order `kx_pk`
  makes every sender derive the same publicly computable tag.
- **HIGH — padding content is unspecified and sits inside the identifier**,
  so two conforming implementations produce different identifiers for
  identical plaintext.

## RFC 8

| document | what it is |
|---|---|
| [`RFC-8.md`](RFC-8.md) | client behaviour, Status: Draft |
| [`RFC-8-review.md`](RFC-8-review.md) | cross-check against RFC 0–7, SIM-0 and SIM-1 |

RFC 8 completes the series. **§1.1 is a genuine contribution**: it marks every
requirement *derived* or *judgement*, and states that a "MUST" on a judgement
requirement means the author believes the failure mode warrants it *despite the
absence of evidence*. That discipline would benefit the other seven documents
retroactively.

- **§9.2 declines to state a result that was measured.** It says no simulation
  has measured an origin attack against degree; SIM-1 §3 measured exactly that,
  and found degree 8 at 6.2× chance against degree 12 at 1.7×. The caution is
  admirable but costly — the warning text will cite delivery problems where the
  measured position is that under-provisioning is *measurably deanonymising*.
  This is the series' first **under**-claim.
- **Peer-count guidance is now three-way split** — RFC 0 §8.2, RFC 3 §13 and
  RFC 8 §9.2 all differ, and RFC 8 is the one that renders a number to an
  operator.
- **§5.3 lists coverage without requiring the age profile** SIM-1 §2 found
  necessary; a 37% scalar concealed a 3–82% ramp.
- **§6's re-encoding is what makes RFC 1's `MAX_OBJECT` enforceable** — an
  upward dependency neither document states.

## Not yet here

RFC 0 and the RFC series plan are not in this directory.
