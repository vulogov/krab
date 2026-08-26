# Changelog

## 0.1.0 — 2026-08-26

First release. A message from A to B, over sim, TCP, Tor, serial or a
hand-carried stick, with lock.

### What it does

- **Objects and cryptography** (RFC 1). Deterministic CBOR, content-addressed
  objects, HPKE with `mode_auth` and `mode_base`, per-epoch unlinkable tags,
  six size buckets with zero padding.
- **Peering** (RFC 3). The ceremony, mutually signed `peer-link` credentials,
  negotiated terms with counter-offers, quota that drifts on behaviour,
  introduction tokens, the public rollcall, nodelist fragments with
  `NODEDIFF`, and unpeering that purges the record and keeps the corpus.
- **Transports** (RFC 4). `sim`, `courier`, `tcp`, `socks` (Tor) and `serial`,
  behind one `Fabric`/`Session` seam, with Noise IK for known peers and XX for
  first contact.
- **Reconciliation** (RFC 5). Manifest and RBSR, both over a session, scoped by
  a filter derived from the signed credential.
- **Groups and channels** (RFC 6), with fan-out staggered over a window derived
  from the observed arrival rate.
- **Key custody** (RFC 7). Three-tier prekeys, the epoch-chunked reservoir,
  hybrid re-key, lock, duress, panic wipe, secure delete, and pinning for mail
  that must outlive its epoch.
- **Interface** (RFC 8). Two tabs, chords from every mode, out-of-process
  picture decoding, and confusable detection on text this node did not write.

### Release gates — RFC 0 §9, `MILESTONE-0.1.md` §2.2

| gate | state |
|---|---|
| RFC 3 §11.3 — full peering and first message with all interfaces down | **met** |
| SIM-2 through the `sim` backend, not a third model | **met** |
| RFC 1 §12 — test vectors, two implementations agreeing | **UNMET. Shipping anyway.** |

**The third gate is not met and will not be.** §12 requires two independent
implementations to agree on the vectors before RFC 1 reaches Final, and there
is one. A second written by the same author agrees with the first whether or
not either is right, which would look like evidence while being none.

What stands in its place, and what it is worth, is in `MILESTONE-0.1.md`
§2.2.2. In short: the vectors cover all seven categories §12 names and are
checked on every test run; every derived value is published beside the inputs
it came from, so the constructions can be checked by hand; and
`Documentation/vectors/check.py` recomputes them in standard-library Python,
anchoring its own X25519 against RFC 7748 and its HKDF against RFC 5869 before
checking anything.

None of that is a second reader. **RFC 1 does not reach Final on this release.**

### Verification

- 1013 tests, `cargo clippy` clean across the workspace.
- Reproducible on `aarch64-apple-darwin`, rustc 1.94.1, re-verified against
  this tree — `Documentation/REPRODUCIBLE-BUILDS.md`.
- Twelve adversarial passes, recorded in `Documentation/ADVERSARIAL-PASS.md`,
  including what each one found *after* the code had shipped.

### Known limitations, stated rather than discovered

- **Coverage is not measured.** `metrics::Coverage` has no production
  constructor, so RFC 3 §13's ramp warning cannot fire. The other three §13
  warnings do.
- **A pin is a hole in the erasure.** RFC 7 §8's epoch erasure is what stops a
  seized disk being a transcript; pinned mail is exempt by design, and `pin`
  reports how much.
- **A renewal after a lapse starts from defaults.** RFC 3 §8.4 purges the
  agreement, so a `peer carry` or `peer share` decision does not survive one —
  the renewal says so and names what to check.
- **An introduction token cannot cross a courier's worst case.** Fourteen days
  against a 45-day TTL, because a token that lived long enough would be the
  durable credential RFC 3 §10 exists to avoid.
- **Only the host platform's reproducibility is verified.** Linux and Windows
  use different linkers with their own stamps.

### Open amendments against the frozen RFCs

Nine findings, in `Documentation/AMENDMENTS.md`. Six adopted; three open:

- **#7** — RFC 3 §9.1 states a rollcall entry is "153 bytes computed" and gives
  no field list to compute it from. This produces 160.
- **#8** — RFC 3 §5.1 numbers keys 0–7 and never numbers the signature it
  requires.
- **#9** — RFC 3 §3 does not say which party is A, and both ends must agree or
  neither can verify the other.

Each was found by implementing the paragraph, and each is a place two
implementations could diverge without either noticing.
