# Proposed addition to RFC 0 — the editorial rule

RFC 0 is not in this repository, so this is text to paste rather than an edit.
Adopted in principle 2026-08-07; pending insertion into RFC 0's editorial
section.

---

> **Every normative paragraph MUST be checked against two questions: can two
> independent implementations of this paragraph disagree, and would either of
> them notice?**
>
> Where the answer to the first is yes and to the second no, the paragraph MUST
> be made mechanical — a named function, a frozen constant, an enumerated list
> — rather than left to prose.

## Why this series needs a rule ordinary specifications do not

Most specifications survive prose because their failures are loud. A malformed
field produces a parse error; a version mismatch produces a rejection; someone
sees a log line and files a bug.

**Krab has no error path.** RFC 0 §6 makes delivery failure silent by design,
and that is not an omission to be corrected — it is the property that keeps a
node from confirming to an observer which messages it could not read. The
consequence is that a specification divergence does not surface as an error. It
surfaces months later as *"that peer stopped being able to read my mail"*, with
both nodes reporting success and nothing in either log.

The two questions are therefore not a style preference. They are the only
review step that catches a class of defect this design has deliberately made
undetectable at runtime.

## The findings that motivated it

Five, from implementing the documents as written:

| where | what was ambiguous | how it would have failed |
|---|---|---|
| RFC 1 §6.2 | "HKDF-Expand" with no hash named | an implementer reaching for BLAKE3 — every other digest in Krab — shares no tags with anyone |
| RFC 7 §6 | `reservoir → chunk_N` drawn as an arrow | two implementations pick different functions; neither is told |
| RFC 7 §6.2 | no channel rule for contributions | the post-quantum property is void and the link works perfectly |
| RFC 3 §2.1 | no signature domain for credentials | credentials do not verify against each other, at the ceremony, in person |
| RFC 4 §5.5 | nothing forbidding a diff-shaped archive | successive sticks reconstruct the sender's composition schedule |

Each was found by writing code, not by reading. None would have produced an
error message.

## The corollary for conformance

The same rule applied to checking rather than to deriving produced RFC 1 §11's
`I1`–`I6` identifiers. In a reference implementation, **three of those six
checks were absent and nothing failed** — objects flowed, reconciliation
converged, the test suite passed. Each was found by writing a test that tried
to smuggle something past a check.

A numbered prose list invites an implementer to believe they have done all six.
Stable identifiers let a reviewer ask which one a given line implements, and
let a conformance suite name what it exercises.

## What the rule does not ask for

It does not ask that prose be removed. RFC 1 §12 already states the
relationship correctly — "for a format that cannot be revised, vectors are the
specification; the prose is commentary" — and commentary is what makes a
specification reviewable by someone who did not write it.

The rule asks only that where prose is *load-bearing*, something mechanical
sits underneath it.
