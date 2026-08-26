# Reproducible builds

```
./build-reproducible.sh            # build, print the hash
./build-reproducible.sh --verify   # build twice from two paths, compare
```

RFC 0 §9:

> "A user who cannot verify the binary matches the source is trusting the
> author personally, which is the trust relationship this design exists to
> avoid."

That verification requires two builds of one source to produce the same bytes —
on different machines, in different directories, by different people. As of
`RFC-0-section-9-proposed.md` this is the **only verifiable claim** the review
section makes, external review being unavailable, which raises rather than
lowers its importance.

**Verified reproducible** on `aarch64-apple-darwin`, rustc 1.94.1: two builds
from two directories, byte-identical.

| date | tree | hash |
|---|---|---|
| 2026-08-10 | pre-0.1 | — |
| 2026-08-26 | **0.1.0** | `ef82f172c6c72cec4fc467278db0b944b2e596dbfc700832fc945c6d01c0aa7c` |

Re-run for the release rather than carried forward: three weeks of work sat
between the two dates, and a reproducibility claim that is not re-checked is a
claim about a tree nobody is shipping.

## What makes it work

**The toolchain is pinned** (`rust-toolchain.toml`). rustc's codegen, inlining
and standard library all change between releases, so two people on "stable"
build different binaries and neither can tell whether the difference is the
compiler or the code. Bump it deliberately, in its own commit, so a diff in the
artefact has a diff in the repository to point at.

**`Cargo.lock` is committed and `--locked` is passed.** Without it, a
dependency published since the lock was written is picked up silently and the
build is reproducible only until somebody else's release.

**Paths are remapped.** This is the dominant source of divergence in Rust:
panic messages, debug info and `file!()` all embed the build directory. Left
alone, the same source built in two places differs — and a released binary
carries the author's directory layout, which is its own small disclosure.

**Incremental compilation is off.** It caches per-machine state that changes
codegen unit boundaries, so an incremental build and a clean one differ.

**The linker's build identifier is suppressed** — `-no_uuid` on Mach-O,
`--build-id=none` on ELF. Neither is derived from the content.

## Three things that were wrong first, and how each failed

Recorded because each looked correct and none announced itself.

**`trim-paths` is not stable in 1.94.1.** It is Cargo's own answer to path
embedding and would be the right mechanism; it needs nightly, and RFC 0 §9's
argument is that verification must not be made harder. So the remapping is
applied by the script, which computes prefixes from the checkout. A
`--remap-path-prefix` in `.cargo/config.toml` cannot substitute: it would have
to name one machine's directory and would do nothing on anyone else's —
silently, which is the worst way for a reproducibility measure to fail.

**`RUSTFLAGS` takes precedence over `target.<triple>.rustflags`.** Setting both
discards the config entirely. The first version set the remapping in
`RUSTFLAGS` and the linker flag in the config, and the linker flag never
applied — the build succeeded, the hashes differed, and nothing said why.

**Flags reach build scripts unless `--target` is passed explicitly.** Without
it Cargo does not separate host units from target units. A build-script
executable linked without a UUID will not load: dyld refuses it with "missing
LC_UUID load command", and the build dies inside `curve25519-dalek`.

## What this does not establish

- **Only the host platform is verified.** Linux and Windows use different
  linkers with their own stamps. `--verify` should be run on each platform a
  release ships for, and its result recorded here.
- **The toolchain itself is trusted.** A reproducible build proves the binary
  follows from the source *and this compiler*. Bootstrapping trust in rustc is
  a separate problem this does not touch.
- **The dependencies are trusted as published.** `Cargo.lock` pins versions and
  hashes; it says nothing about what is in them.
- **Reproducibility is not review.** It establishes that a binary matches a
  source everyone can read. Whether the source is correct is
  `CRYPTO-REVIEW.md` and `ADVERSARIAL-PASS.md`, and those are self-review.
