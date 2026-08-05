# Krab

Friend-to-friend, store-and-forward messaging over any transport.

Nodes exchange an encrypted, content-addressed object corpus over whatever
carrier is available — IP, Tor, LoRa, serial, X.25, or a hand-carried USB
stick — with peers chosen individually, out of band, by their operators.

There is no discovery, no directory, no bootstrap server, no proof-of-work,
and no infrastructure of any kind. Admission control is the peering
relationship itself.

Messages are sealed to the recipient's public key and addressed by a
per-epoch unlinkable tag. Relays cannot read a message, determine its
recipient, or identify its sender.

**Krab is FidoNet with modern cryptography.** From FidoNet it takes the
peering model: a hand-maintained peer list, bilateral accountability,
store-and-forward over intermittent links, flood distribution with duplicate
suppression. From Bitmessage it takes the privacy model: an encrypted corpus
every node holds, so possession of an object implies nothing about its
recipient. From neither does it take the scaling assumptions.

## Status

**Planning.** This repository is a scaffold. No RFC in the series is
normative until it reaches Draft and its dependencies are satisfied, and
RFC 1 — the document that freezes the object format permanently — is not
there yet. Nothing here is stable and no wire format exists.

What *is* done is SIM-0, the convergence measurement the whole architecture
rests on, together with an audit of it. See [`Documentation/`](Documentation).

## What Krab is not

Not a replacement for Signal, Matrix, or email. It is slower by orders of
magnitude, cannot be joined without knowing a participant, and makes no
delivery guarantee. It is appropriate where those costs buy something:
operation without infrastructure, resistance to mass passive collection,
resistance to Sybil-based vantage acquisition, and the ability to carry
traffic across links no conventional messenger can use.

It offers no resistance to a global passive adversary. That is out of scope,
explicitly.

## Layout

The split between crates is by dependency direction and is load-bearing
rather than cosmetic — it is what makes deterministic testing, fuzzing, and
headless operation possible.

```
crates/
  krab-core      object format, crypto, tags, filters.
                 no_std, so no I/O, no clock, and no ambient randomness are
                 reachable — the invariant is enforced by the compiler
  krab-store     TTL-bucketed segments, rebuildable index,
                 crypto-shredding key hierarchy
  krab-proto     control messages, reconciliation state machine.
                 pure; property-test and fuzz target
  krab-fabric    Fabric trait and backends: tcp, socks(tor), serial,
                 courier, sim
  krab-node      scheduler, sync loop, key management, peering
  krab           public library facade

apps/
  krab-tui       the TUI application; builds the `krab` binary
  krab-sim       SIM-0 convergence simulator; no dependencies at all
```

## Build

    cargo build --release

    ./target/release/krab                        # TUI (scaffold)
    ./target/release/krab-sim --diag --sweep mix # SIM-0

## Documentation

- [`Documentation/SIM-0-results.md`](Documentation/SIM-0-results.md) — the
  convergence measurements RFC 0 cites
- [`Documentation/SIM-0-audit.md`](Documentation/SIM-0-audit.md) — audit of
  those measurements. Three published columns do not mean what their names
  suggest; read this before citing any figure

## Licence

MIT. See [LICENSE](LICENSE).
