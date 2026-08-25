# What is next

    Status:   drawn up 2026-08-25, against 970 passing tests
    Scope:    normative requirements that are unmet, ranked, with a plan
    Note:     every RFC 3 *section* is now implemented. What follows are
              requirements inside them that are not.

---

## 1. The list

Four items. Three are `MUST`s in documents that are frozen, and the fourth is a
module built and never called.

| # | requirement | state | why it is where it is |
|---|---|---|---|
| 1 | RFC 3 §4 — expiry must be an explicit state | **unmet** | there is a 90-day clock already running |
| 2 | RFC 3 §8.4 — termination must purge attributable artifacts | **unmet** | five new attributable artifacts were added last week, and nothing removes any of them |
| 3 | RFC 3 §13 — implementations MUST warn below the peer-count floor | **built, never called** | `krab_node::warnings` has zero callers in the interface |
| 4 | RFC 3 §12 — the accountability panel | **partial** | most metrics exist; the panel shows some of them |

### 1.1 Why §4 is first, and why it is urgent rather than merely unmet

RFC 3 §4:

> "Implementations SHOULD prompt for renewal at 75% of the term and **MUST
> surface an expired peering as an explicit state rather than as a silent sync
> failure** — the two look identical from the outside and confusing them will
> waste a great deal of operator time."

The `MUST` is not decoration, and the failure it names is now *reachable*.
`Credential::verify` refuses an expired credential, so `credential_with`
returns `None`, so `scope_for` returns `Filter::unscoped` — and an unscoped
node does not reconcile with a scoped one. That is correct behaviour and it is
correct behaviour that looks exactly like a dead link.

Every credential minted since the credential landed carries
`DEFAULT_TERM_DAYS = 90`. So there is a date, roughly ninety days after each
peering was countersigned, on which that link goes quiet and nothing anywhere
says why. Pass 9 found the same class of failure already shipped once; this one
is shipped and merely has not fired yet.

**This is the item with a deadline. Nothing else on the list has one.**

### 1.2 Why §8.4 is second

> "Fragments, beacons, credentials, and negotiation chains are attributable —
> they are records of a relationship. On termination or expiry a node **MUST
> purge those** and **MUST retain the corpus**."

There is no unpeer path at all — no `forget`, no `unpeer`, no termination verb.
`disconnect` tears down a transport and touches nothing on disk.

That was a smaller gap when a peering was a card and a sealed reservoir. It is
a larger one now: the last two weeks added `credential`, `chain`, `quota`,
`nodelist` and `terms`, and RFC 3 §15 says what the first of those is worth to
someone holding the disk —

> "Seizing a disk yields the peer list **with cryptographic proof** — worse
> than an address book."

`wipe` destroys everything, which is RFC 7 §10's panic protocol and the wrong
granularity: an operator who ends one relationship should not have to end all
of them.

### 1.3 Why §13 is third

`krab_node::warnings` computes the peer-count and coverage warnings SIM-0 and
SIM-1 ground, and **nothing in the interface calls it**. §13:

> "Operators choose peers by hand and will not know any of this.
> Implementations MUST warn below the lower bound for the node's actual
> transport mix, and SHOULD warn above 25 on constrained links."

The same defect as `exchange::respond_to`, `receive::scan_requests` and
`fragment::Delta` — built, tested, never called. Two of those three were found
by accident months later.

### 1.4 Why §12 is last

The metrics exist; what is thin is the panel. §12's closing line is the
requirement that matters:

> "A disconnect decision should be one keystroke from the evidence justifying
> it. If it is not, operators will not make it, and the accountability model
> degrades to nothing."

`peers` now carries quota, standing, novelty and nodelist reach. Missing:
duplicate arrivals, unique-source contribution, tag-match ratio and storage
share. Each is an aggregate the node already has or can keep cheaply, and none
changes a security property — this is the item that improves judgement rather
than correctness.

---

## 2. The plan

Three phases and a decision. Each phase is independently shippable and ends
with a pass over what it touched.

### Phase 1 — expiry becomes visible (§4)

1. **An explicit state.** A peering whose credential has expired reports as
   *expired*, in `peers` and wherever a send or a reconciliation declines
   because of it. Never as "nothing happened".
2. **Renewal at 75%.** `peer status` and `peers` say a credential is due, and
   name the command. §4 makes renewal "a fresh `peer-link` with a new nonce,
   superseding by `established` time" — the countersign path already does
   this, so the work is the prompt and not the mechanism.
3. **A test that fails on the day it would matter**: a credential aged past its
   term must produce a named state, not a silent unscoped filter.

Small. The mechanism exists; what is missing is that anyone is told.

### Phase 2 — unpeering (§8.4)

1. `peer forget <peer>` — purge the credential, chain, quota, nodelist, terms,
   reservoir and card for one peer, shredded per `SECURE-DELETE.md`, and
   **retain the corpus**, which §8.4 makes an equal `MUST`.
2. Drop them from the fragment, the scheduler, the allowed set and the link
   table, so the relationship stops being acted on and not merely stops being
   stored.
3. **Automatic on expiry.** §8.4 says "on termination *or expiry*", so the
   purge is not only a verb. Phase 1's expiry state is the trigger.
4. A test that walks `PeerFile::ALL` and asserts nothing for that peer
   survives — the structural form, so a new per-peer artifact fails it.

Medium, and it depends on Phase 1 for the expiry trigger.

### Phase 3 — the operator can act (§13, §12)

1. Call `krab_node::warnings` from the interface and render it, with the
   transport mix the node actually has.
2. Add §12's four missing aggregates to `peers`.
3. Make the disconnect decision one keystroke from the evidence, which is the
   sentence the whole section is written around.

Small, and mostly wiring.

### Then: a decision, not a phase

With those closed, every normative requirement in RFC 3 that this
implementation can meet is met, and `MILESTONE-0.1.md` §2.2.2's one remaining
gate stays open for ever — RFC 1 §12 needs a second implementation from a
second reader, and there will not be one.

At that point the question is not what to build. It is whether 0.1 ships with
that gate recorded unmet, and the work is release engineering: a version, a
changelog, `REPRODUCIBLE-BUILDS.md` verified end to end, and a README that
tells someone how to run it.

---

## 3. What is deliberately not on this list

- **A second implementation of RFC 1 §12's vectors.** Not mine to write; the
  reasoning is in `MILESTONE-0.1.md` §2.2.2 and in `vectors.rs`.
- **Ring-signature endorsement.** RFC 3 §10 defers it to Future Work and says
  it "MUST NOT be built unless the private-token path demonstrably fails".
  The private-token path has not been used yet, let alone failed.
- **A public bootstrap node.** RFC 3 §11.2: "RFC 0 §6 has already refused it."
- **Anything in RFC 3 §14's multi-device story.** It is guidance rather than a
  requirement, and the machinery it asks for — an operator as a group — exists.

---

## 4. The standing rule

Every phase above ends with an adversarial pass over what it touched, before
the next begins.

Passes 7 and 8 found rules enforced over stale field lists. Pass 9 found the
opposite: a value reused where it did not fit, and a solved problem in the same
function that was not reused. All three found things that had shipped, and
Pass 9's finding — a credentialled link silently accepting nothing — would have
appeared to an operator exactly when they did what the preceding commits
encouraged.

The pass is not a release step. It is what makes the previous feature true.
