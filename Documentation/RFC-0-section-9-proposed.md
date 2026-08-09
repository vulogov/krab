# Proposed replacement for RFC 0 §9's review requirement

RFC 0 is not in this repository, so this is text to paste.

## The problem with the current text

RFC 0 §9 requires external cryptographic review before any release, and RFC 1
§13 restates it: "External cryptographic review is required before any release."

**That review will not happen.** The author has no access to unpaid external
reviewers and no budget for paid ones. The probability is zero, not low.

A requirement that will not be met is worse than an honest description of what
was done, for a reason specific to this project: **a reader who sees the
requirement assumes it was satisfied.** RFC 0 §9's own argument is that a user
should not have to trust the author personally — and an unmeetable requirement
sitting in a frozen document asks for exactly that trust, while appearing to
remove the need for it. It is a claim about process that the process cannot
support.

The same applies to RFC 1 §12's "two independent implementations MUST agree",
which is also unmet and unlikely to be met.

## Proposed text

> ## 9. Review
>
> ### 9.1 What review this project has had
>
> **No external cryptographic review has been performed, and none is planned.**
> The author has no access to reviewers. This is stated first because a reader
> encountering a review requirement will otherwise assume it was met.
>
> What has been performed is **adversarial self-review**: systematic attempts
> to break the design and the implementation, conducted by the same party that
> produced them. Its findings, including the ones that changed the
> specification, are in `CRYPTO-REVIEW.md` and `ADVERSARIAL-PASS.md`, with the
> defects recorded rather than summarised.
>
> ### 9.2 What that does and does not establish
>
> Self-review has found real defects in this project, including two that would
> have silently voided a stated security property:
>
> - a message-key derivation reusing one key per (pair, epoch)
> - a forward-secrecy claim that a static reservoir root could not deliver
> - a duress passphrase distinguishable by wall-clock time
>
> Each was found by attacking a specific sentence, and each sentence had been
> written and believed by the reviewer until it was attacked. **That is the
> limit of the method, stated as evidence rather than as caution**: it finds
> what the author thinks to question, and its blind spots are the author's,
> which is what external review exists to correct.
>
> A reader MUST NOT treat the presence of this review as equivalent to
> independent review. It is strictly better than none and strictly worse than
> one.
>
> ### 9.3 What a deployer should therefore do
>
> - **Treat this as unreviewed cryptography.** Deploy it where the consequence
>   of a break is acceptable, and not where it is not.
> - **Read the findings, not the summary.** `CRYPTO-REVIEW.md` and
>   `ADVERSARIAL-PASS.md` name what was checked and, explicitly, what was not.
> - **The open findings are open.** They are listed as such, with the reason
>   each was not fixed, and none is closed by having been written down.
>
> ### 9.4 Standing invitation
>
> If you are able to review this, the project wants it and will publish your
> findings unedited, including ones the author disagrees with. The
> specifications and the implementation are both public, both frozen at a
> tagged commit, and the review surface is bounded: two crates hold all
> cryptographic dependencies (`CRYPTO-BOUNDARIES.md`).
>
> ### 9.5 Reproducible builds
>
> *(unchanged)* A user who cannot verify the binary matches the source is
> trusting the author personally, which is the trust relationship this design
> exists to avoid.
>
> This is now the **only** verifiable claim in this section, which raises
> rather than lowers its importance.

## And RFC 1 §12

§12 requires two independent implementations to agree on the test vectors
before RFC 1 reaches Final. There is one, and the vector file
(`Documentation/vectors/rfc-1.txt`) says so at the top.

Recommend the same treatment: state that one implementation exists, that the
vectors are therefore a **drift check rather than an interoperability proof**,
and that the fixed-PRK entries are the only ones anchored outside this codebase.
Keep the requirement for Final; do not pretend it is met.

## Why not simply drop the requirements

Because they are correct. External review and a second implementation are what
this design needs, and removing the requirement would be pretending the need
went away rather than the supply.

The proposal is to keep the requirement, state plainly that it is unmet, and
describe what was done instead — so that the gap is legible to a reader who did
not write the code, which is the entire audience the requirement was written
for.
