# Fuzzing

```
cargo +nightly fuzz run cbor     # the CBOR reader (RFC 1 §4.3)
cargo +nightly fuzz run object   # header, envelope, padding (RFC 1 §4, §8.1)
cargo +nightly fuzz run control  # the wire protocol (RFC 4 §4.2, RFC 5)
cargo +nightly fuzz run ingest   # RFC 1 §11's I1-I6 postconditions
cargo +nightly fuzz run picture fuzz/corpus/picture fuzz/seeds/picture
```

**`picture` needs its seeds, and the difference is not marginal.** `corpus/` is
gitignored, so a fresh checkout starts a target with nothing — and for the
image parsers that means almost every input dies on the magic bytes before
reaching a decoder. Measured: 972 covered blocks unseeded, **3 373 with the
seeds**, on the same target and the same machine. The seeds are seven small
real images in `seeds/picture/`, checked in because they are the difference
between fuzzing two image parsers and fuzzing two magic-byte comparisons.

`fuzz` is excluded from the workspace: `cargo fuzz` builds under nightly with
sanitiser flags, and the workspace release profile sets `panic = "abort"` per
RFC 7 §9 — which would hide the panics fuzzing exists to find. This crate
unwinds deliberately.

## First run — 2026-08-09

| target | executions | result |
|---|---|---|
| `cbor` | 110 622 746 | clean |
| `object` | 94 821 250 | clean |
| `control` | 15 694 | **crash** — see below |
| `ingest` | 8 558 621 | clean |

The `control` crash is written up in `Documentation/ADVERSARIAL-PASS.md` §9. It
was found in **under sixteen thousand executions**, against decoders already
tested at every truncation offset and against single-byte flips — which is the
argument for fuzzing over hand-written robustness tests, made concretely.

After the fix, `control` ran 37 668 225 executions clean.

## In CI — 2026-09-01

The `fuzz` job in `.github/workflows/ci.yml` runs all five targets nightly, 30
minutes each, on the schedule rather than on pushes. A fuzz run short enough to
block a merge is a fuzz run too short to find anything.

**"Run it for hours" has a ceiling, and it is not the binding constraint.** A
GitHub-hosted job is capped at six hours and the cap cannot be raised. But
thirty minutes a night beats one long run, because the corpus carries forward:
the job caches `fuzz/corpus/<target>` between runs, so each night starts where
the last one stopped rather than re-deriving the same inputs. Without that
cache the numbers below would repeat every night for ever.

`-timeout=25` makes a single slow input a finding rather than a lost run, and
a crash is uploaded as an artifact — a crashing input nobody kept is a crash
nobody can reproduce.

## `picture` — 2026-09-01

RFC 8 §6's pipeline: two third-party parsers, on bytes a peer chose, which the
module's own comment calls "historically the richest source of remote code
execution". It is the largest attack surface in the system and it had **no
target** — not by oversight but by structure. `picture` was a module of the
interface *binary*, and `cargo fuzz` cannot depend on a binary crate.

`krab-picture` is that module as a library, and it is the substantive part of
this change; the target is what it bought.

| run | corpus | executions | coverage | result |
|---|---|---|---|---|
| unseeded | empty | 6 243 897 | 972 blocks | clean |
| unseeded, continued | discovered | 5 840 921 | 972 blocks | clean |
| **seeded** | 7 real images | 325 679 | **3 373 blocks** | clean |

The seeded run is three and a half times the coverage at a fiftieth of the
execution rate, which is the shape to expect: the earlier runs were fast
because they were rejecting, and the last one is slow because it is decoding,
downscaling and re-encoding. **Twelve million fast executions found less than
three hundred thousand slow ones reached**, which is the argument for checking
seeds in rather than trusting a target's run count.

What the target asserts beyond "did not crash" is the postcondition RFC 8 §6
actually requires: the output is a PNG this implementation produced, within
`MAX_OBJECT` and `MAX_PIXELS`, no larger than the input declared, and **not
containing the input**. A `transcode` that passed attacker bytes through would
satisfy every crash test and defeat the requirement entirely.

## What the targets check beyond "does not panic"

Absence of a crash is the weak claim. Each target asserts a property:

- **`object`** — a parsed `RoutingHeader` must re-`write` to the bytes it came
  from. RFC 1 §10 makes those 16 bytes permanent and readable by every future
  version, so a parser that accepts something its encoder cannot reproduce has
  a wider input language than the format. It also checks that
  `decode_envelope` never reports consuming more than it was given.
- **`control`** — `parse ∘ write ∘ parse` must be identity. A decoder that
  accepts what its encoder cannot produce is the same defect one layer up.
- **`ingest`** — the *postcondition*, not the checks: whatever the input, every
  object in the store hashes to its own identifier (I5), is exactly its
  declared bucket (I1), has a known version and class (I3), and has not
  expired (I2). Three of those six checks were absent at various points and
  nothing failed, so asserting the outcome is worth more than asserting the
  path.
- **`cbor`** — map traversal must terminate, and a length claim must not
  outrun the buffer.

## What fuzzing here cannot see

- **Wrongly accepted input.** RFC 1 §4.3 forbids indefinite lengths, floats,
  tags, non-canonical integers and out-of-order map keys. A reader that
  silently *accepted* one would pass every target here — nothing crashes.
  Catching that needs a differential oracle or a second implementation, which
  is RFC 1 §12's requirement and is unmet.
- **Semantic wrongness.** An object that decodes correctly to the wrong
  meaning is invisible.
- **The crypto.** Sealing, tags and the ratchet are not fuzz targets; their
  inputs are keys and epochs rather than attacker bytes.

## Corpus

`fuzz/corpus/` is not committed. It is machine-specific, regenerable, and
large; the artifacts that mattered are reproduced as unit tests instead —
`a_huge_declared_array_does_not_allocate` in `krab-proto` carries the crash
input verbatim, so the regression is checked by `cargo test` and does not
depend on nightly or on anyone remembering to fuzz.
