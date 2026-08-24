# Proposed amendments

Every open finding against the frozen RFCs, with drop-in text. All of them came
out of implementing the thing the paragraph describes.

| # | target | finding | text |
|---|---|---|---|
| 1 | RFC 7 §6 | `msg_key` reuses one key per (pair, epoch) — **critical** | **ADOPTED** 2026-08-07 |
| 2 | RFC 7 §6.2 | no channel rule; the post-quantum property can be silently void | **ADOPTED** 2026-08-07 |
| 3 | RFC 7 §6 | chunk derivation is drawn as an arrow, never defined | **ADOPTED** 2026-08-07 |
| 4 | RFC 3 §2.1 | the credential is the one signed document with no signature domain | **ADOPTED** 2026-08-07 |
| 5 | RFC 4 §5.5 | nothing says an archive must be a window rather than a diff | **ADOPTED** 2026-08-07 |
| 6 | RFC 1 §11 | the checks are prose; three of six were never implemented | **ADOPTED** 2026-08-07 |
| 7 | RFC 3 §9.1 | "153 bytes computed" for a rollcall entry, with no field list to compute it from | open — see below |
| 8 | RFC 3 §5.1 | the table numbers keys 0–7 and never numbers the signature | open — see below |

## 8. RFC 3 §5.1's `peer-request` has an unnumbered field

§5.1 tabulates keys 0–7 for a `peer-request` and then requires an inner
Ed25519 signature, which the table does not number. §3 does the same for
`peer-link`, writing both signatures as `—`.

For `peer-link` that is harmless: the signatures are appended around a body
whose extent §3 defines. For `peer-request` there is no such statement, so the
signature has to go somewhere in the same map and **every implementation picks
its own key**. This one uses 8.

Found while implementing §10's introduction token, which §5.1 puts at key 6 —
and key 6 was occupied, because an earlier encoder here had flattened "proposed
terms" across keys 5, 6 and 7. That is worth recording separately as the same
failure from the other direction: the table said terms was one field, the
encoder made it three, and the collision was invisible until something needed
the key. Two implementations, one from the table and one from that encoder,
would have disagreed about every field after `to` — and a `peer-request` that
does not parse is simply a peering that never happens, with nothing logged
anywhere.

Suggested text — number it:

> | 8 | signature | Ed25519 by the identity in key 1, over `"krab/req/v1" ‖ body`, where `body` is the deterministic CBOR map of keys 0–7 |
>
> Keys 3, 4 and 6 are optional and MUST be omitted entirely when absent rather
> than encoded as empty or null: RFC 1 §4.3 admits one encoding per value, and
> a present-but-empty introduction token is a different document from no token.

The second paragraph matters as much as the first. Without it, "optional" has
two readings that produce different signed bytes over the same intent, which is
the same class of silent divergence as the key numbering itself.

## 7. RFC 3 §9.1's rollcall entry size

§9.1 says an entry is "153 bytes computed". Implementing §9 produces **160**.

The seven bytes are not the finding. The finding is that there is no way to
find out which of us is right: §9.1 gives a number and not the fields it came
from, so a reader cannot tell whether 153 omits the corpus watermark, packs the
capability bits more tightly, or assumed a different signature envelope.
`apps/krab-sizes/src/creds.rs` already records the same about RFC 3 §3's
credential figures — they "cannot be recomputed from the document … and are
taken here as stated inputs".

This is the shape named below. Two implementations can satisfy §9.1
differently, and **neither would ever discover it**: an entry is
self-describing CBOR, so a 160-byte one is read perfectly well by a node
expecting 153, and nothing reports a size mismatch because nothing checks one.
It surfaces, if at all, as an entry that unexpectedly does not fit somebody's
buffer.

Suggested text — state the composition, not the total:

> A rollcall entry is a `bulletin` object (RFC 1 §5.2) whose payload is the
> deterministic CBOR map: `1` correspondence key (32 bytes), `2` max bucket
> index, `3` shard bits, `4` relay flag, `5` corpus watermark. The author's
> `sig_pk` is the bulletin's author field and the node id derives from it;
> neither is repeated in the payload. Implementations MUST NOT include any
> further field: §9.2 forbids reachability, and §9.1's second column forbids
> the rest.

A total that can be recomputed is worth more than a total that is asserted, and
this one currently cannot be.

Findings 1–3 land in one section, so `RFC-7-section-6-proposed.md` closes all
three in a single edit.

**All six adopted 2026-08-07.** The RFC 0 editorial rule below is in
`Documentation/RFC-0-editorial-rule.md`, as text to paste — RFC 0 is not in
this repository.

## The pattern worth naming in RFC 0

Findings 2, 3, 4 and 5 share a shape, and it is not "the author forgot". Each is
a paragraph **two competent implementers can read differently, where neither
would find out they had diverged.**

Krab has no delivery receipts and no error path — RFC 0 §6 makes failure silent
by design. So a divergence does not surface as an error. It surfaces months
later as *"that peer stopped being able to read my mail"*, with both nodes
reporting success and no log on either side saying anything.

Ordinary specifications get away with prose because their failures are loud.
This one cannot. Suggested addition to RFC 0's editorial rules:

> Every normative paragraph MUST be checked against two questions: **can two
> independent implementations of this paragraph disagree, and would either of
> them notice?** Where the answer to the first is yes and the second is no, the
> paragraph MUST be made mechanical — a named function, a frozen constant, an
> enumerated list — rather than left to prose.

Finding 6 is the same rule applied to conformance rather than to derivation.

---

## §A — RFC 3 §2.1, credential signature domain

The series domain-separates every hash, and two of its three signed documents.
The credential is the exception, and it is the document carrying a node's Noise
static, its correspondence key, and its policy.

| document | signature covers | where |
|---|---|---|
| peer-link | `"krab/link/v1" ‖ body` | RFC 3 §4 |
| bulletin | `"krab/bul/v1" ‖ header ‖ body-without-key-3` | RFC 1 §5.2 |
| **credential** | **unspecified** | RFC 3 §2.1 |

Append to §2.1:

> A credential's signature is Ed25519 over `"krab/cred/v1" ‖ body`, where
> `body` is the deterministic CBOR encoding of the document with the signature
> field omitted.
>
> **Every signed document in this series MUST prefix its signing input with a
> domain string unique to that document type. A signature produced over one
> document type MUST NOT be valid over any other.**
>
> A credential body MUST be a flat CBOR map. Nested maps are not permitted:
> RFC 1 §4.3 requires map keys to ascend, a nested map's keys restart, and a
> decoder reading both levels from one cursor correctly rejects its own
> encoder's output.

The second paragraph is the part that matters most, because it converts a
per-document decision into a rule the next document inherits.

**Why it is also an interoperability gap.** §2.1 as written is not
implementable interoperably. An implementer following the pattern set by §4 and
RFC 1 §5.2 will invent a prefix and pick their own string; one following §2.1
literally will use none. Neither is wrong by the text, and their credentials do
not verify against each other. The failure surfaces at the ceremony, in person,
with no diagnostic — an event RFC 3 §11 makes people travel for.

`apps/krab-tui/src/peering.rs` uses `krab/card/v1` pending adoption; if §2.1
takes `krab/cred/v1` the constant changes and no format does.

---

## §B — RFC 4 §5.5, an archive is a window

§5.5 constrains the archive's *container* thoroughly and says nothing about its
*contents*. Append:

> A courier archive MUST contain a time window of the sender's corpus, selected
> by expiry range and independent of when any object was acquired or composed.
> An implementation MUST NOT restrict an archive to objects acquired since a
> previous archive.
>
> An archive of what changed is a statement about what its author did between
> two dates. Successive archives handed to one courier reconstruct the sender's
> composition schedule, which is the correlation RFC 5 §6.1 forbids on the
> network arriving by another route.

§5.5 already supplies the reason this is affordable, in a line currently
reading as reassurance:

> "**Capacity never binds.** A 128 GB medium holds 286× the measured n=500
> corpus and writes in 15 seconds. The constraint is human latency, always."

That sentence is load-bearing. It is what makes the privacy-preserving choice
free, and it should be presented as the justification for the rule above rather
than as a note about disk sizes. An implementer optimising the obvious way —
send only what is new, it is smaller — builds a timing oracle, and the RFC
currently gives them no reason not to.

---

## §C — RFC 1 §11, make the checks enumerable

§11 describes the ingest checks in prose. **Two of the six were absent from
`krab-store` and nothing failed** — objects flowed, reconciliation converged,
385 tests passed. They were found by writing a test that tried to smuggle
something past them, not by reading the code against the text.

The two:

- **Check 5 — the identifier was never verified against the content.** `ingest`
  took the caller's word. This is the check that makes content addressing
  load-bearing rather than decorative: without it a peer supplies arbitrary
  bytes under an identifier a node already wants, and duplicate suppression
  (RFC 0 I-1), reconciliation, and the range fingerprint are all built on "an
  identifier names its content" meaning something.
- **Check 1 — length against declared bucket, and zero padding.** Non-zero
  padding is a covert channel that *replicates*: the identifier covers it, so
  every relay carries whatever was put there until expiry, believing it
  ordinary.

Proposed: restate §11 as a numbered list with a stable identifier per check, so
an implementation can be audited against it line by line and a conformance
suite can name what it exercises.

> ```
> I1  length equals declared bucket; padding is zero          (§8.1)
> I2  expiry is in the future and within MAX_TTL              (§2)
> I3  version and class are recognised                        (§4.1)
> I4  body decodes under the declared version; unknown keys rejected  (§4.3)
> I5  id == BLAKE3("krab/obj/v1" ‖ OBJECT)                    (§4)
> I6  not already held, and not tombstoned                    (I-1, RFC 5 §8)
> ```
>
> An implementation MUST apply every check before an object enters the store,
> and MUST NOT accept an object on which any check was skipped. A conformance
> suite SHOULD exercise each by identifier.

The ordering matters and should be stated: **I5 before anything that consults
the identifier**, since a store that indexes by an unverified identifier has
already lost the property the rest depends on.
