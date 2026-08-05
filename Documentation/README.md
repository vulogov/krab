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
All of its byte counts verify against `krab-sizes`. The review finds one
blocking defect and four items worth resolving before Final:

- **`EPOCH_WINDOW` (±30 epochs) is smaller than `MAX_TTL` (45 days).** An
  object delivered inside its declared TTL can arrive up to 45 epochs after
  creation, so 15 epochs' worth is undecryptable — silently. `EPOCH_WINDOW`
  is not inside the identifier hash, so this one is still cheap to fix.
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

## Not yet here

RFC 0 and the RFC series plan are not in this directory.
