# RFC 5 — Review

    Subject:  RFC 5, Synchronisation, Status: Draft
    Method:   cross-check against SIM-0, SIM-1, RFC 0/1/3/4/6/7
    Verdict:  conclusions sound; the grounding is not in this repository

RFC 5 is the last document. Its §4.1 finding — that per-transport assignment
beats every uniform choice, and that RBSR is the wrong algorithm exactly where
it was expected to win — is the right conclusion and matches SIM-1 §1's
direction. §4.2's explanation of *why* is the best thing in the document:
filter-scoping already made `n` small, so RBSR's fixed costs dominate in the
regime where its asymptotic advantage was supposed to pay.

## The figures cannot be reproduced here

RFC 5 cites `ovhd%`, `loraOvhd%` and `waste%` columns, and a `PushOnly` mode.
None exists in `apps/krab-sim`. The numbers come from a SIM-1 extension that is
not in the repository, so unlike every other Draft in this series **RFC 5's
grounding cannot be checked** — the same gap the SIM-0 audit was written about,
and the same one `krab-sizes` closed for RFC 1, 3, 6 and 7.

Where the two overlap they disagree:

| | this repository's SIM-1 | RFC 5 §4.1 |
|---|---|---|
| austere, all-RBSR delivery | **33.0%** | **64.8%** |

Both cannot be right. The likely cause is the round-trip model: this
repository charges `latency × (2·rounds − 1)`, and a different descent depth or
a cached-fingerprint assumption would move the figure a long way. The
qualitative conclusion — RBSR is disqualifying under courier-heavy transport —
survives either number, but the specific figure should not be cited until the
extension is committed.

The same applies to §5's "at 60% LoRa edges, delivery is 28.3% under every
mode" and §4.5's PushOnly table.

**Recommendation.** Commit the SIM-1 extension as `apps/krab-sim` flags
alongside `--recon` and `--adv`, and re-run. It is the last unreproducible
grounding in the series.

## Findings

**§4.1's mode assignment contradicts §1's own decision procedure for serial.**
The assignment table puts `LoRa / serial → Manifest`. Serial at 115 200 baud is
11 520 B/s (RFC 4 §5.3) with millisecond latency — `Interactive` by any
reading, and `RFC-5-blocking-items.md` §1's two feasibility tests both pass, so
RBSR wins on bytes. Grouping serial with LoRa follows the *bandwidth* intuition
that §4.2 correctly warns against; the discriminator is round-trip cost, and
serial's is negligible. **Assignment should key on `latency_class`, not on a
transport list.**

**§8's tombstone retention is anchored to the wrong quantity.** "Retained for
at least the clock skew tolerance plus one sync interval" — that is ±6 h plus
hours. But the object being suppressed can legitimately arrive up to `MAX_TTL`
after creation (RFC 1 §11), and a courier node returning after months is
exactly the case §8 opens with. A tombstone that expires before the resurrection
it exists to suppress does nothing.

This is the **fifth** occurrence of the pattern named in
`RFC-2-review.md` §1: a retention parameter anchored to a measured or typical
quantity rather than to the protocol's declared guarantee. The rule that would
have prevented all five is in `RFC-5-blocking-items.md` §7.

**§4.4's `Σ H(id) mod 2²⁵⁶` needs its collision resistance stated.** Additive
fingerprints over a modulus are not collision-resistant in the hash sense — an
adversary controlling identifiers can search for sets whose sums agree, which
makes a range appear synchronised when it is not, silently withholding objects.
The reasoning given for addition over XOR ("XOR is malleable") is right and
incomplete: addition is malleable too, just less conveniently. What makes it
safe is that identifiers are `BLAKE3` outputs the adversary cannot choose
freely, and §4.4 should say so — the property is inherited from content
addressing, not from the fingerprint.

**§7's `redb` recommendation reaches outside the dependency discipline.**
Every other component in the series is justified as dependency-free or
standard; RFC 5 names a specific store without the analysis RFC 4 §4.3 applied
to ZMQ and QUIC. The `O(1)` range-summary requirement is the real constraint
and is well-argued; the library choice should follow the same rejected-
alternatives treatment or be left to implementations.

## What RFC 5 got right

- **§4.2 is the strongest analysis in the series.** "The two modes are
  complements, not competitors" inverts a natural assumption with a mechanism,
  not an assertion, and the mechanism is §2's own filter.
- **§3's `watermark` in `HELLO`** solves a problem no earlier document named:
  a peer whose retention cannot close your gap should be able to say so before
  either side spends a cycle discovering it. On a link that reconciles four
  times a day this is the difference between a viable protocol and an unusable
  one, and it costs eight bytes.
- **§3's filter digest as a hard error rather than a negotiation.** Divergent
  credentials are not a case to reconcile around.
- **§7's "eviction is `unlink()` of a whole segment"** — no compaction, no
  tombstone sweep, no write amplification, and courier export is a file copy.
  The storage layout falls out of immutability and bulk expiry rather than
  being imposed on them.
- **§6.1 asks for a test, not a comment**, asserting that inter-sync intervals
  are uncorrelated with message events. That is the right shape for an
  invariant that looks like a performance bug to anyone measuring latency.
- **§11's erratum is honest about a claim this repository also accepted.**
  Filter-scoping is necessary and not sufficient, and 68% overhead is still
  overhead.
