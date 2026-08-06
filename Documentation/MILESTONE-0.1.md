# Milestone 0.1

    Branch:   0.1
    Status:   in progress
    Scope:    the parts of the frozen format that are unambiguous, plus fuzzing

---

## What 0.1 is for

Nine RFCs are at Draft. **None can be implemented end to end yet**, and the
reasons are specific rather than general — four open items, each with a known
fix, block distinct parts of the object pipeline.

0.1 therefore builds what is *frozen and unambiguous*, wires up the fuzzing
RFC 0 §9 requires, and stops at each blocker with a test that records why. The
alternative — guessing at the blocked parts to keep momentum — is exactly how
a frozen format acquires an accidental answer.

## In scope

| component | RFC | state |
|---|---|---|
| deterministic CBOR profile | RFC 1 §4.3 | **done** — `krab_core::cbor` |
| frozen routing header | RFC 1 §4.1 | **done** — `RoutingHeader::parse` |
| size bucket selection | RFC 1 §8.1 | **done** — `bucket_for` |
| segment + rebuildable index | RFC 5 §7 | next |
| control opcodes | RFC 5 §3 | next |
| `Fabric` trait, `LinkProfile` | RFC 4 §2, §3 | next |
| fuzz targets | RFC 0 §9 | next |

Both completed pieces carry a `never_panics_on_arbitrary_input` test, because
RFC 0 §9 puts them on the pre-authentication attack surface. The CBOR reader
borrows throughout and allocates nothing, so a declared length can only fail
to fit the input — it can never cause an allocation.

`RoutingHeader::parse` deliberately **does not validate `ver`**. RFC 1 §10
requires a relay to route, filter and expire an unknown version from these
sixteen bytes alone; rejecting it here would partition the network at the
first protocol revision, permanently, since the nodes that would bridge the
partition are the ones offline for a month. A test asserts unknown versions
still parse.

## Blocked, with the reason

Each of these is implemented as an error return plus a test asserting the
error, so that a future change making it "work" fails loudly.

### `object_id` — padding content is unspecified

`CRYPTO-REVIEW.md` §4. The identifier covers the whole object including its
padding (RFC 1 §3, §4), and RFC 1 §8 never says what the padding bytes are.
Zero-padding and random-padding implementations compute **different
identifiers for identical plaintext**.

This blocks everything downstream: content addressing, duplicate suppression,
reconciliation, and the store. It is the highest-priority unblock in the
project and it costs one sentence in RFC 1 §8. Zero is the obvious choice —
it also makes the invariant checkable on ingest, where random padding is
unauthenticated by the AEAD and protected only by the identifier.

### Envelope encode/decode — `admission` presence is ambiguous

`RFC-1-review.md` §3. RFC 1 §4.2 lists body key 3 as "reserved, empty in v1"
without saying whether a v1 encoder MUST emit it as a zero-length `bstr` or
MUST omit it. Both readings satisfy the text, and they produce different
identifiers. Same class of defect as the padding one, same one-sentence fix.

### Reservoir path — open critical defect

`CRYPTO-REVIEW.md` §1, marked in `RFC-7.md` §6. `msg_key` is constant per
(pair, epoch). Not implementable until the construction is fixed; the
recommended `mode_auth_psk` form needs no format change.

### Signature verification — strictness undecided

`CRYPTO-REVIEW.md` §2. Ed25519 malleability defeats duplicate suppression
unless verification rejects non-canonical `S` and non-canonical point
encodings. The fix is a validation rule, so RFC 1 stays frozen — but it has to
be stated before any verifier is written, or the first implementation sets the
default by accident.

### Tag derivation — Extract and low-order rejection undecided

`CRYPTO-REVIEW.md` §3. Raw X25519 output currently feeds HKDF-Expand as a PRK,
and low-order public keys are not rejected anywhere.

## Not in scope for 0.1

Everything requiring a decision that has not been made: HPKE sealing, prekeys,
peering negotiation, groups, channels, the TUI beyond its current scaffold.
RFC 1 §12's test vectors do not exist, and two implementations agreeing on
them is a precondition for calling any of it correct.

## Unblocking order

1. **Padding content** — one sentence, unblocks `object_id` and therefore
   the store, reconciliation, and every integration test.
2. **`admission` presence** — one sentence, unblocks envelope encoding.
3. **Strict signature verification** — a validation rule, unblocks bulletins.
4. **Tag derivation** — Extract plus low-order rejection, unblocks addressing.
5. **Reservoir construction** — the critical defect; unblocks RFC 7 and
   RFC 1 §6.5's post-quantum claim, which is contingent until then.

Items 1 and 2 are the cheapest and unblock the most. Both are ambiguities in a
frozen document, so they get more expensive the longer they wait — once
objects exist, whichever reading shipped first becomes the answer.
