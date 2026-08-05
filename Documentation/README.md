# Documentation

Grounding documents for the Krab RFC series. No RFC may assert a
convergence, delivery, or storage claim that is not measured here.

## SIM-0 — corpus convergence

| document | what it is |
|---|---|
| [`SIM-0-results.md`](SIM-0-results.md) | the measurements RFC 0 §8 cites, annotated where the audit contradicts them |
| [`SIM-0-audit.md`](SIM-0-audit.md) | source review and instrumented re-runs; **read before citing any figure** |
| [`sim-0-runs/sweeps.txt`](sim-0-runs/sweeps.txt) | captured output for every sweep, with audit diagnostics |

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

Two of these carry a deadline: they must be resolved before RFC 1 freezes the
routing header, because it cannot be revised afterwards.

## Not yet here

RFC 0 and the RFC series plan are not in this directory. Neither is SIM-1,
whose revised scope is proposed in audit §7.
