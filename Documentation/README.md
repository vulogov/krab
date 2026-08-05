# Documentation

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

## Not yet here

RFC 0 and the RFC series plan are not in this directory.
