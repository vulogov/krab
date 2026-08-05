# krab-sim — SIM-0

Corpus convergence simulator for the Krab store-and-forward messaging
network. Answers the question the architecture rests on: does a message
reach its recipient, within TTL, across a sparse hand-built peer graph
whose edges include day-latency couriers and duty-cycle-limited radio?

Results and their interpretation live in
[`Documentation/SIM-0-results.md`](../../Documentation/SIM-0-results.md).
**Read [`Documentation/SIM-0-audit.md`](../../Documentation/SIM-0-audit.md)
before citing any figure** — three of the published columns do not mean what
their names suggest.

## Dependencies

None, external or internal. PRNG (xoshiro256++), argument parsing and JSON
output are in-tree. SIM-0 grounds normative claims in the RFC series, so
anyone checking those claims must be able to rebuild and re-run it offline,
on any toolchain, with nothing to vendor-trust. Builds on Rust 1.75+.

It does not depend on `krab-core` either, so that a change to the
implementation cannot silently move a published measurement.

## Build and run

    cargo build --release -p krab-sim
    ./target/release/krab-sim --help

    ./target/release/krab-sim                       # baseline
    ./target/release/krab-sim --sweep mix           # transport mix
    ./target/release/krab-sim --sweep ttl
    ./target/release/krab-sim --sweep degree
    ./target/release/krab-sim --sweep scale
    ./target/release/krab-sim --sweep topo
    ./target/release/krab-sim --sweep dest
    ./target/release/krab-sim --json results.json

Sweeps compose with overrides, e.g. TTL under austere transport:

    ./target/release/krab-sim --sweep ttl --tcp 0.2 --lora 0.3 --courier 0.5

## Reproducibility

Output is byte-identical across invocations for a given configuration.
Ordered containers are used in the graph generators specifically to
preserve this: hash-set iteration order is randomised per process and
would otherwise perturb the RNG stream.

The workspace release profile sets `panic = "abort"` (an RFC 7 requirement
for the binaries that hold key material). Seeds run on separate threads, so a
panicking seed now aborts the process rather than being dropped from the
average — the preferable failure mode for a measurement tool, but a change
from the standalone build. Either way the `runs` column reports how many
seeds actually contributed to a row; a value below `--seeds` means the figures
were averaged over fewer runs than requested.

## Audit flags

Added while auditing the published figures. See `SIM-0-audit.md`.

    --diag                     report the metrics the standard table conflates:
                               exact vs byte-weighted vs settled coverage,
                               coverage by object age, mean alongside p99 for
                               store and ingress, and LoRa-eligible fraction

    KRAB_LORA_GATE=<bytes>     override the LoRa per-object size gate
                               (default 512). Bounds what fragmentation could
                               buy, given that the shipped gate admits 0.16%
                               of the traffic distribution

Bare flags cannot be the final argument — the parser reads a value before
matching the flag name. Put `--diag` and `--quiet` ahead of the last valued
option.

## Layout

    src/rng.rs     xoshiro256++ / SplitMix64
    src/graph.rs   Watts-Strogatz, Barabasi-Albert, random-regular
    src/model.rs   config, transports, objects, bitset corpus
    src/sim.rs     discrete-event engine, reconciliation, metrics
    src/main.rs    CLI, sweeps, aggregation, output

## Metrics

  delivery   fraction of messages reaching their destination within TTL
  latNNh     delivery latency percentiles, hours
  cover      mean fraction of the live corpus a node holds, **at the horizon**.
             Under slow transport this is dominated by objects too young to
             have propagated — use `--diag` for the age profile
  cover10    same, 10th percentile across nodes
  storeMB    **p99 across nodes** of the per-node **peak over time** of live
             corpus bytes. Not a mean, despite reading like one
  rxMB/d     **p99 across nodes** of ingress per node per day
