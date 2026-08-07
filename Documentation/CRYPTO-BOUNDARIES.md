# Cryptographic boundaries

The workspace has **two** crates with third-party cryptographic dependencies,
not one. This document exists because the original design claimed one, and the
change is a weakening that should be visible rather than discovered.

| crate | domain | what a compromise costs |
|---|---|---|
| `krab-crypto` | object layer | message content, identity, tags |
| `krab-fabric` | link layer | who talked to whom, when, how much |

Everything else in the workspace is zero-dependency or depends only on these.

## Why it is two

RFC 4 §4.1 specifies Noise IK for transports. `snow` is the Rust implementation
and it resolves **older major versions** of three primitives than `hpke`
requires for RFC 1 §6.1's suite:

```
                snow        krab-crypto (via hpke)
curve25519      4.1.3       5.0.0
chacha20poly1305 0.10.1     0.11.0
sha2            0.10.9      0.11.0
```

No combination satisfies both. A binary linking Noise and HPKE therefore
contains two implementations of X25519, of ChaCha20-Poly1305, and of SHA-256.

The alternatives were considered and rejected:

- **Downgrade `krab-crypto`.** Not available — `hpke` 0.14 requires the newer
  set, and there is no older `hpke` that takes the older one.
- **Hand-implement Noise IK** over `krab-crypto`'s primitives. About 200 lines,
  and official test vectors exist. Rejected because a hand-rolled handshake is
  precisely what this project's own review standard says to refuse, and the
  duplication is a smaller risk than a bespoke key schedule.
- **Wait.** Indefinite, and it blocks a release gate.

## Why two boundaries is tolerable, and where it is not

**Tolerable**, because they are genuinely different trust domains. A link-layer
compromise yields traffic analysis: who connected, when, how much passed. An
object-layer compromise yields content. The two are audited separately by
anyone doing this properly, so "one boundary" was always somewhat aspirational
— the boundary that mattered was *zero crypto outside these crates*, and that
still holds.

Both duplicated implementations are also **dalek**, differing by major version
rather than by author or design. That is materially different from linking two
independent X25519s with different clamping and low-order behaviour.

**Not tolerable if it grows.** The rule going forward:

> A crate may take a cryptographic dependency only if it is `krab-crypto` or
> `krab-fabric`. A third would mean the workspace has no boundary at all, only
> a habit.

## What this costs RFC 0 §9

RFC 0 §9 argues for reproducible builds on the grounds that "a user who cannot
verify the binary matches the source is trusting the author personally." That
argument is unaffected — reproducibility does not care how many copies of a
primitive are linked.

What *is* affected is the review surface: an auditor now reads two X25519
implementations rather than one. That is a real cost, it is roughly a day of
someone's attention, and it is stated here so nobody discovers it during an
audit and wonders what else was not mentioned.

## The check

```
cargo tree -p krab-crypto | grep curve25519    # must show exactly one version
cargo tree -p krab-fabric | grep curve25519    # may show two: snow's and ours
```

If `krab-crypto` ever shows two, that is a regression against the rule above
and not an acceptable state.
