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
| 1 | RFC 3 §4 — expiry must be an explicit state | **done** | there was a 90-day clock already running |
| 2 | RFC 3 §8.4 — termination must purge attributable artifacts | **done** | five new attributable artifacts were added last week, and nothing removed any of them |
| 3 | RFC 3 §13 — implementations MUST warn below the peer-count floor | **done** | `krab_node::warnings` had zero callers in the interface |
| 4 | RFC 3 §12 — the accountability panel | **done** | one signal unfed: coverage has no production constructor |

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

### Phase 1 — expiry becomes visible (§4) · **done 2026-08-25**

1. **An explicit state.** A peering whose credential has expired reports as
   *expired*, in `peers` and wherever a send or a reconciliation declines
   because of it. Never as "nothing happened".
2. **Renewal at 75%.** `peer status` and `peers` say a credential is due, and
   name the command. §4 makes renewal "a fresh `peer-link` with a new nonce,
   superseding by `established` time" — the countersign path already does
   this, so the work is the prompt and not the mechanism.
3. **A test that fails on the day it would matter**: a credential aged past its
   term must produce a named state, not a silent unscoped filter.

Done. `credential::Life` names the three stages of a term, `Standing`
distinguishes "never countersigned" from "lapsed last Tuesday" — they arrived
as the same `None` before — and `peer renew` is the fresh credential §4 asks
for, carrying the flags and terms across so a renewal changes the dates and
nothing else. A scheduled reconciliation that declines on an expired credential
logs why.

One thing the work taught: editing a signed document's dates makes it a
forgery, and `verify` reports that first. Expiry is a state of a *valid*
document, which is why `Life` is separate from `Invalid` — a test that faked an
expiry by editing dates got `BadSignature`, correctly.

### Phase 2 — unpeering (§8.4) · **done 2026-08-25**

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

Done. `peer forget <peer>` shreds every per-peer file, removes the directory,
and drops the peer from the scheduler, the link table, the allowed set, the
quota counters and the nodelist — stopping the conversation and removing the
record in the same breath, because a node still dialling someone whose card it
has just destroyed fails in a way nothing explains.

**The split §8.4 forced.** Expiry and termination are not the same purge.
§8.4 names four things — fragments, beacons, credentials and negotiation
chains — and the list is doing work: those are records that two parties agreed
something. A card and a reservoir are not. Destroying them on a lapsed term
would end a relationship the operator may be about to renew, and §4 makes
renewal the ordinary path.

So `PeerFile::purged_on_expiry` splits them, as a method rather than a list, so
a new per-peer file has to answer the question. Termination takes everything.

The cost, stated because it is real: renewing a peering that has already lapsed
starts from default terms, since the agreed ones went with the credential.
§4 prompts at 75% precisely so that does not happen, and §15 accepts the case —
"a node offline longer than a credential term returns unable to peer with
anyone".

### Phase 3 — the operator can act (§13, §12) · **done 2026-08-25**

1. Call `krab_node::warnings` from the interface and render it, with the
   transport mix the node actually has.
2. Add §12's four missing aggregates to `peers`.
3. Make the disconnect decision one keystroke from the evidence, which is the
   sentence the whole section is written around.

Done, and it was not only wiring. `krab_node::warnings` computed five warnings
and **rendered none**, so wiring it into an interface would have meant writing
the prose there — which is where the reasoning stops travelling with the
threshold it came from. `Warning::line` now carries both, and the transport mix
is read from the links the node has rather than configured: a floor the
operator sets is a floor the operator can set wrong.

`Debug` leaked into operator text on the first attempt — "the floor for a
IpConnected deployment" — which is the shape of every enum that reaches an
interface without being asked how it should read. `TransportMix::describe`
fixes it and a test refuses any line containing `{` or a double space.

§12's rows come from the two counters the budget already keeps: objects this
peer was first to deliver, and what they offered that this node already had.
That is unique-source contribution and duplicate arrivals measured at the only
moment they *can* be measured without storing which object came from whom —
which §12 forbids outright.

One signal is still unfed and is marked so in the code: `metrics::Coverage` has
no production constructor, so the ramp warning cannot fire. It is the last of
§13's four.

### Phase 4 onward — the rest of the series

Everything above is RFC 3. A survey of the other eight documents follows in
§2.1; the phases it produces run after Phase 3.

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

## 2.1 The other RFCs — survey, and Phases 4–6

**Scope of this survey, stated honestly.** RFC 8 §7 and §10 were read in full
and checked against the tree; the items marked *verified* below were confirmed
by looking for the mechanism, not by looking for the word. The rest were found
by extracting normative lines and spot-checking, and are marked *to verify* —
they are candidates, not findings. Finishing that audit is itself the first
task of Phase 4, and it should take an afternoon.

RFC 8 carries the most normative weight in the series (60 `MUST`/`SHOULD`
lines against RFC 1's 43) and has had the least of it checked, because the
implementation work has been protocol-first throughout.

### Phase 4 — RFC 8 §7: names are attacker-controlled · **done 2026-08-25**

```
A key fingerprint MUST appear alongside every display name in list views,
  not only in a detail pane.
The client MUST run Unicode confusable detection against names the user
  already follows, and MUST mark matches.
```

Neither is implemented. There is no confusable check anywhere, and no
fingerprint beside a name in any list.

It is not vacuous: `groups::Group` carries an operator-chosen `name`, and a
roster arrives **signed by another member** — so the name is chosen by someone
else and rendered by this node. §7's own sentence is the threat: "a Cyrillic
homoglyph defeats the strongest cryptographic guarantee in the system with a
font."

§7 also anticipates the half-fix: "Fingerprints in the detail pane only would
satisfy the letter and miss the point: the confusion happens while scanning a
list."

Done, and the audit changed the answer. **§7's first MUST holds by
construction**: this client has no petnames. Every identifier an operator sees
is a short id derived from a key, and `groups::Group::name` — which looks like
a display name — is "local only … not in any signature", so it never crosses
the wire and no one but the operator can choose it.

Stopping there would have been wrong. The audit found what *does* arrive from a
stranger and reach a list: the free-text note on a `peer-request` (RFC 3 §5.1
key 7) and on a `peer-counter`. Both were rendered **verbatim**, and there was
no sanitisation anywhere in the codebase.

Because every identifier here is hex, §7's attack has a precise form: a note
reading `acedface` where the letters are Cyrillic. `display::skeleton` folds
Cyrillic, Greek and fullwidth onto ASCII; `confusable_with_known` marks a note
that renders like a peering this node holds; and quoting a real identifier is
deliberately *not* marked, because a mark that fires on ordinary text is
trained out of an operator within a week.

`display::safe` removes control characters, bidi overrides and zero-width
formatting before anything reaches a pane — a newline broke the list's layout
and U+202E reversed the rest of the row — and **reports how many it removed**,
because silently swallowing an attacker's bytes is its own kind of lie.

Two things the work taught. The confusables table is a subset and says so; a
name built outside it renders unmarked, and the fingerprint beside it is what
the operator has left — which is why §7 asks for both. And the first version of
the check compared `"асеdfасе,"` against `"acedface"` and found nothing: an
attacker writing a full stop would have walked past it. Punctuation is trimmed
now, and a test pins five kinds of it.

### Phase 5 — RFC 8 §10: retention is a foreground property *(verified)*

```
The client MUST make the consequence of the retention window visible
  BEFORE the window elapses.
A pin action MUST be available, re-encrypting a selected conversation
  under a long-lived key.
```

**Entirely absent.** The word "pin" occurs once in the tree, in a comment about
test vectors.

§10's reasoning is the strongest argument in RFC 8 for doing it:

> "Epoch erasure makes a node's own archive of that epoch permanently
> unreadable. That is the point — it is the only genuine form of message expiry
> — but a user who discovers it afterwards has lost something irrecoverably,
> and no support channel can help."

This one is not an interface nicety. `shred_expired_epochs` already runs on the
schedule and destroys epoch keys, so the loss is real, automatic and running
today. Pinning is the only thing that can precede it, which makes this the
highest-consequence item outside RFC 3.

Work: a pin verb re-encrypting a conversation under a long-lived key (RFC 7
§8.1 is the derivation), and a foreground warning before an epoch's keys are
shredded rather than after.

### Phase 6 — the remainder *(to verify)*

Candidates, in the order they should be checked:

| document | line | requirement | note |
|---|---|---|---|
| RFC 6 §216 | "MUST surface burn rate and MUST warn when joining a group would make the batch insufficient" | `groups::prekey_warning` exists; whether `keys` surfaces the rate is unchecked |
| RFC 6 §281 | "Nodes MUST support excluding class 1 (bulletin) entirely via `class_mask`" | the filter enforces `class_mask`; **nothing sets it** — `Flags::class_mask` is `0xFF` and no verb changes it |
| RFC 7 §509 | "Implementations MUST store ciphertext and derive on display" | no marker found in the tree; needs reading rather than grepping |
| RFC 7 §410 | "MUST surface this wherever the link is displayed" (non-post-quantum reservoir) | `peers` does say it; other views unchecked |
| RFC 6 §158 | "Divergence MUST be surfaced, not silently resolved" | `groups::divergence` exists; whether every caller surfaces it is unchecked |

§281 is the one that looks most like a real gap: the enforcement is built and
the control is not, which is the same shape as the share flag before `peer
share` existed.

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
