# Fuzzing

```
cargo +nightly fuzz run cbor     # the CBOR reader (RFC 1 §4.3)
cargo +nightly fuzz run object   # header, envelope, padding (RFC 1 §4, §8.1)
cargo +nightly fuzz run control  # the wire protocol (RFC 4 §4.2, RFC 5)
cargo +nightly fuzz run ingest   # RFC 1 §11's I1–I6 postconditions
```

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
