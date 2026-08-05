# krab-sizes — RFC 1 reference size encoder

Computes every byte count the Krab object format implies, from the format
[RFC 1](../../Documentation/RFC-1.md) specifies.

RFC 1 cannot be revised, and it cites this tool for every figure it publishes.
A reviewer must therefore be able to check the document against arithmetic
rather than against assertion.

## Dependencies

None, external or internal. Rebuild and re-run offline, on any toolchain, with
nothing to vendor-trust — the same rule `krab-sim` follows.

It does not depend on `krab-core` either. This computes what RFC 1
*specifies*; `krab-core` implements it. Keeping them independent is what makes
a disagreement between the two a finding rather than a tautology.

## Build and run

    cargo build --release -p krab-sizes
    ./target/release/krab-sizes             # the full size budget
    ./target/release/krab-sizes --check     # verify RFC 1's published figures

`--check` exits non-zero on any disagreement, so it works as a CI gate against
RFC 1 drifting from its own arithmetic. The same figures are pinned as unit
tests:

    cargo test -p krab-sizes

## What it models

Lengths, not bytes. RFC 1 §4.3's deterministic CBOR profile — shortest-form
integers, definite lengths only, no floats, no tags — makes an item's encoded
length a pure function of its type and magnitude. That restrictiveness is
precisely what allows a parameter table to be frozen, and it is why a size
model can be exact rather than approximate.

    src/cbor.rs     encoded lengths under the RFC 1 §4.3 profile
    src/object.rs   routing header, envelope, inner plaintext, buckets
    src/main.rs     CLI, the size budget, and --check

Magnitudes that decide a CBOR head width — the tag epoch, the `created`
timestamp — are constants rather than free parameters. They are what the
fields actually hold, and their head widths are stable for the protocol's
plausible lifetime: the epoch counter stays three bytes until 2149, and
`created` in minutes stays five bytes until the year 10136, which is where
RFC 1 §4.1's `u32` ceiling sits anyway.

## Known divergence from RFC 1's prose

`krab-sizes` computes a **135-byte** minimum sealed object where RFC 1 §8.1
cites 150, and **1 224** where §6.5 cites 1 239 — a 15-byte delta in both
cases. RFC 1's floor assumes 17 bytes of encoded address and content type; a
strictly minimal object has both empty. RFC 1 does not state the composition.

Both values land in the 256-byte bucket, so §8.1's conclusion that the
smallest bucket is inefficient by construction holds either way. Recorded in
[`RFC-1-review.md`](../../Documentation/RFC-1-review.md).
