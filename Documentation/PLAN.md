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

### Phase 5 — RFC 8 §10: retention is a foreground property · **done 2026-08-25**

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

Done. `shred_expired_epochs` logged "that mail is unreadable **now**" — the
exact sentence §8.1 is written against. It now warns first, once per epoch,
naming how many messages and how many days.

The long-lived key is a **subkey of the KEK**, not of `W_N`: a pin sealed under
the epoch key is unreadable exactly when it was supposed to be readable. The
derivation lives in `krab-crypto` because the KEK's bytes do not leave that
crate — a caller that could read them to hash them could write them somewhere,
and RFC 7 §4 is that the KEK is memory-only.

The cost is stated rather than discovered: a pinned conversation is **exempt
from the erasure everything else gets**, and that erasure is what stops a
seized disk being a transcript. Every pin is a hole in it, `pin` says how many
holes there are, and `pin release` closes one.

### Phase 6 — the remainder · **done 2026-08-25**

Audited. Of the five candidates, **one was a real gap and one was half-built**;
the other three were already met, and one of my own findings was wrong.

| candidate | verdict |
|---|---|
| RFC 6 §281 — exclude class 1 via `class_mask` | **real gap, now built.** The filter enforced the mask and nothing ever set it: `Flags::class_mask` was `0xFF` and no verb changed it, so a node could not decline public content however much it wanted to. `peer carry <peer> on\|off` re-signs the credential; the same shape the share flag had before `peer share` |
| RFC 6 §216 — surface burn rate | **half-built.** The join-time warning was already wired; the `keys` report said nothing about prekeys at all, and §216's point is that "exhaustion degrades forward secrecy **silently**" |
| RFC 6 §216 — warn at join | already met — `prekey_warning` is called from `group_member` |
| RFC 7 §410 — surface a non-post-quantum reservoir | already met, in seven places |
| RFC 6 §158 — divergence surfaced, not resolved | already met — `roster_divergences` renders in the group list |

**A correction worth recording.** The audit's first pass reported that
`prekey_warning` had no production caller, and it does — `main.rs:1757`. The
grep that produced the finding ended in `head -4` and the four lines it kept
were all from `groups.rs`; the caller was on the fifth. A truncated search
reported as an absence.

That is the same failure the passes keep finding, turned on the audit itself: a
rule — here "this function is never called" — asserted over a set that was not
the whole set. It is recorded because the fix is not "be careful with `head`",
it is to make a claim of absence prove itself, and this one did not.


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

---

# What is next — 0.2, compiled 2026-08-27

Phases 1–6 are done and the release shipped. This is the survey that follows
them, and it is a different list: what 0.1 does **not** do, as opposed to what
it did not yet do when the plan above was written.

## 5. How this was compiled, and what would make it wrong

Four sources, because no one of them is complete:

1. `grep` for `todo!`, `unimplemented!`, `FIXME`. **Nothing.** That is not
   evidence of completeness — this codebase records gaps in prose, not
   markers, so the search proves only that nobody left a marker.
2. `Documentation/RFC-*-blocking-items.md` — rows still marked **open**.
3. `AMENDMENTS.md` — findings against the frozen RFCs with nothing built.
4. The `CHANGELOG` limitations, and what running two real nodes turned up
   this week.

**The standing risk on a list like this** is the one Phase 6 recorded against
itself: a claim of absence asserted over a set that was not the whole set. A
truncated `grep` reported a function as uncalled when it was called on the
next line. So each item below names *how it was established*, and anything
resting only on "I did not find it" says so.

---

## 6. The list

### A — functionality that is absent

| # | what | where it bites |
|---|---|---|
| **A1** | **Payload fragmentation.** `krab` refuses anything larger than one object: "too long for one object — split it" (`main.rs:6657`). The largest bucket is 256 KB. | A photograph cannot be sent. RFC 8 §6 permits pictures and SIM-0's traffic model assumes 50–500 KB ones, so the product refuses the traffic its own simulation is built on. `--frag` implements store-and-forward fragmentation **in the simulator**, so the network model has it and the client does not. Note `apps/krab-tui/src/fragment.rs` is RFC 3 §8 *nodelist* fragments — a different thing with the same word. |
| **A2** | **The RFC 3 §12 per-peer panel is never populated.** `peers::Row`, `PeerMetrics` and `Coverage` are built and tested; `peers_panel` passes an empty `Vec` and says so in a comment. | §12 wants a disconnect decision one keystroke from the evidence for it. There is no evidence — the operator sees quota and today's counts, assembled separately, and nothing about what a peer actually brings. |
| **A3** | **RFC 3 §13's coverage-ramp warning cannot fire.** `Coverage` has no production constructor; every one is in a test. | The other three §13 warnings do fire. This is the one that says possession has become evidence (SIM-1 §3), which is the warning with a consequence for the operator's safety rather than their availability. |
| **A4** | **Channels carry no attachment.** `send <peer> --picture` exists; `channel post` publishes the flag as characters. Pinned by a test. | RFC 8 §6 permits pictures and does not scope them to private messages, so this is a gap rather than a decision — but a picture on a public, signed, permanent post is a privacy choice the operator should make knowingly, and that is a design question before it is a coding one. |

### B — frozen numbers with no measurement behind them

`RFC-1-blocking-items.md` exists so that "nothing reaches Draft on a number
nobody measured". Four rows are still **open**, and the code ships values for
all four anyway.

| # | parameter | shipped | recorded status |
|---|---|---|---|
| **B1** | epoch length | 1 day | open — "the hardest": sneakernet pushes long, unlinkability short, and one counter is shared by tag derivation, key erasure and the reservoir |
| **B2** | max object size | **256 KB** (`BUCKETS` top) | open — **and it conflicts**: B3 proposes 64 KB. The code has already chosen 4× that, without the sweep |
| **B3** | size buckets | 6: 256 B … 256 KB | open — unmeasured |
| **B4** | clock skew tolerance | **none** | open — and unlike B1–B3 there is no value to argue about, because `grep -i skew` across the workspace returns nothing |

**B4 is the one that is also a bug.** The routing header's expiry is minutes
since epoch and is read from the cleartext. Reconciliation admits a ±45-day
window, which is not a skew tolerance — it is the TTL used as one. A node with
a wrong clock mis-expires objects in both directions and nothing anywhere
says so.

### C — spec defects, not code

`AMENDMENTS.md` #7, #8 and #9 are open: a rollcall entry whose stated size has
no field list, a key table that never numbers its signature, and a credential
that does not say which party is A. Each has drop-in text written. They need
an RFC editor, and this project has one author, so they stay open and stay
recorded — which is the honest outcome, not a blocked one.

### D — release engineering

- **RFC 1 §12's second implementation.** Refused, with reasons, in
  `MILESTONE-0.1.md` §2.2.2. Not a task.
- **Reproducibility is verified on `aarch64-apple-darwin` only.** Linux and
  Windows use different linkers with their own stamps.

---

## 7. The plan

Ordered by what makes the product *wrong now*, ahead of what is merely
unmeasured, with one exception: B2 comes before A1 because the answer to
"how big may an object be" is the input to "how do we split one".

### Phase 7 — clock skew (B4)

First because it is the only item that is both unmeasured **and** unbuilt, and
because a wrong clock currently fails silently in both directions. Decide a
tolerance, apply it where expiry is read, and say what happens outside it —
refusing an object is a decision an operator should be told about, not one
that shows up as mail that never arrived.

### Phase 8 — settle B2, then B1 and B3

`RFC-1-blocking-items.md` already names the experiment for B2: re-run SIM-1's
`recon` and `idlen` sweeps with the traffic model capped at the chosen maximum
and `--frag` on. It says half an hour of simulator time and no new code. B1
and B3 follow the same shape.

This phase produces numbers and a document, not a feature. It is worth its
place because RFC 1 is frozen: these values are permanent, and one of them is
already 4× the proposal.

### Phase 9 — payload fragmentation (A1)

Sized by Phase 8. The simulator has store-and-forward fragmentation; the
client needs it, with reassembly, a partial-object state the interface can
show, and a decision about what a missing fragment looks like to the reader.

### Phase 10 — the evidence an operator disconnects on (A2, A3)

Together, because both need the same thing: coverage by age bucket, derived
from the corpus. A2 is the panel; A3 is the warning that panel makes
actionable. Neither is worth building without the other.

### Phase 11 — channel attachments (A4)

A decision first: whether a picture belongs on a public, signed, permanent
post at all, and if so what the interface says at the moment of posting. The
code after that is small — the pipeline exists and is tested.

### Not phases

C is an editor's work. D is a platform matter and a refusal already argued.

---

## 8. What this list may still be missing

It rests on markers that do not exist, documents I wrote, and this week's
runs. The three defects found this week — a peering that could not read its
own mail, received mail that never reached disk, a forced send that reported
failure while succeeding — were **in none of those sources**. Every one came
from running two real nodes and watching.

So the honest expectation is that the next real gap is found the same way, not
by reading. Phases 7–11 each end with an adversarial pass over what they
touched, per §4 — and the pass that matters is the one driven through two
processes rather than one test harness.

---

## 9. RFC 8 requirement audit, 2026-08-27 — partial

Prompted by four usability reports that all turned out to be unmet §4.2
requirements. Every numbered MUST in RFC 8 was enumerated; the ones below were
checked against the code. **This is not the whole file** — the unchecked ones
are listed so the gap in the audit is visible rather than implied.

| requirement | verdict |
|---|---|
| §4.2 r1 — security context in the composer | **was unmet, now met.** There was no composer for a post at all |
| §4.2 r2 — first post of a session confirms | met before, but by retyping the verb; now one keystroke |
| §4.2 r3 — reply is private, publish is a separate key | reply was already private; the *author* it replies to was on screen nowhere. Now shown |
| §4.2 r4 — roster divergence shown, never silently merged | met — `roster_divergences` |
| §4.2 r5 — group-size and prekey warnings at join | met |
| §3 — output over one line goes to the view pane or a zoomed command pane, never scrolls the two-line pane | met, and more nearly than before: the reveal added on 2026-08-26 is the zoomed form |
| §4.3 — carriage warning at the point of enabling, default off | met |
| §6 — decode/re-encode, pixel cap, no viewer, LoRa refusal | met |
| §7 — fingerprint beside display names, confusable detection | met |
| §9 — **per link, whether it provides LOCATION privacy** | **unmet.** Nothing renders it |
| §9 — **per link, whether it provides VOLUME privacy** | **unmet.** Nothing renders it |

**Not yet checked**: §2.1's zeroize-on-close and the MUST NOT on caching
decrypted bodies (`self.messages` holds plaintext and is cleared on lock —
whether that satisfies "not cached" needs reading, not guessing); §5's
progress rules; §8's expired-peering state; §11's remote-ceremony
restriction; §12's amateur-band acknowledgement; §13's TUI/node channel
separation.

**Add to the plan**: the two §9 items belong in Phase 10, beside the other
per-peer evidence — they are the same panel and the same missing derivation.

The pattern worth naming: all four reports came from an operator using the
thing, and each mapped to a requirement that had been read as satisfied. The
audit above is what should have been run when RFC 8 was implemented, and
running it now found two more.

---

## 10. RFCs 1–7 requirement audit, 2026-08-27 — first pass, incomplete

168 MUST lines across RFCs 1–7. This pass enumerated all of them and checked
a prioritised subset: RFC 1 because it is frozen and permanent, RFC 7 because
it is key custody. **Most of the 168 are still unchecked**, and they are named
below so the gap in the audit is visible rather than implied — an audit that
reports only what it looked at is the truncated-`grep` failure in another form.

### Found unmet

**RFC 1 §6.4 — no cache of failed `(id, epoch)` pairs.**

> An adversary who learns a current tag can flood objects bearing it, forcing
> full constant-time trial decapsulation at roughly 10 ms per object for zero
> cost. Implementations **MUST** cache failed `(id, epoch)` pairs so a
> replayed object costs one lookup.

There is no such cache: `grep` for one across the workspace returns nothing.
Every object that matches a tag and fails to open is retried in full on every
`refresh_inbox`, which now runs on every tick that drains an exchange.

This is not hypothetical. The live runs this week printed
`! 3 matched a tag and did not open` — three objects paying full trial
decapsulation on every refresh, on an idle two-node network with no adversary
at all. The cost is linear in objects that match a tag, and an attacker who
learns a tag chooses that number.

**Not fixed in this commit, deliberately.** A cache keyed on attacker-supplied
identifiers is itself unbounded memory, so it needs a bound and an eviction
rule before it is written, and the §6.4 sentence continues into a SHOULD about
per-peer attempt caps and a quota signal that belong in the same design. It is
Phase 12 below.

### Checked and met

| requirement | evidence |
|---|---|
| RFC 1 §4.3 — indefinite-length CBOR rejected | `krab-core/src/cbor.rs`, `AI_INDEFINITE` |
| RFC 1 §8.1 — padding is zero, non-zero rejected on ingest | `object.rs:233`, `object.rs:531` |
| RFC 1 §10 — reserved header bits zero on emission, ignored on receipt | `FLAG_RESERVED` |
| RFC 7 §5.1 — signed prekey rotation cadence | `republish_prekeys_if_due` |
| RFC 7 §8.2 — store ciphertext, derive on display | `refresh_inbox` clears and rebuilds plaintext |

### Not checked

RFC 1: the six ingest checks I1–I6 and their ordering (§11), silent rejection,
cover-object indistinguishability (§5.3), `EPOCH_WINDOW` ±45 (§7), the
full-private-key-set attempt (§6.3), the base32 short form (§9).
**RFC 2, 3, 4, 5, 6: nothing.** RFC 7: the destruction of `root_N` (§6),
part-finished ceremony handling (§10.3), and the reservoir's
no-post-quantum-property disclosure (§7.4) — that last one is recorded as met
"in seven places" by Phase 6 but was not re-checked here.

### Phase 12 — the trial-decapsulation cache (RFC 1 §6.4)

Bounded, evicted on epoch rollover, and paired with §6.4's SHOULDs: a cap on
decapsulation attempts per epoch per peer, and the tag-match/decrypt-success
ratio feeding RFC 3's quota reduction. The ratio is already computed for the
`! n matched a tag and did not open` line, so the signal exists and is
currently only printed.

### What this pass says about the others

Two audits in two days, of two different documents, each found unmet MUSTs in
code that had been written against them. That is a poor rate, and it is
evidence about method rather than about any one requirement: implementing a
paragraph and believing it satisfied is not the same as checking it. The
remaining ~150 should be treated as unaudited rather than as probably fine.

---

## 11. RFCs 2 and 3, 2026-08-27 — second pass

RFC 2's MUSTs were enumerated and the ones with a checkable footprint were
checked; the same for RFC 3. **RFCs 4, 5 and 6 remain unaudited.**

### Unmet

**RFC 2 §9 — no cap on decapsulation attempts per peer per epoch.**

> Implementations MUST cache failed (id, epoch) pairs so a replay costs one
> lookup. Implementations MUST cap inbox-tagged decapsulation attempts per
> peer per epoch.

Two MUSTs, neither built. The first is the RFC 1 §6.4 finding from the pass
above — and note that what RFC 1 states as a SHOULD ("SHOULD cap decapsulation
attempts per epoch per peer"), **RFC 2 states as a MUST**. The stricter of the
two governs. Both belong in Phase 12, which should be read against RFC 2 §9
rather than RFC 1 §6.4 alone.

**RFC 2 §7 — no median-of-peers time estimate.**

> Implementations MUST accept objects whose epoch falls within W of local
> time. Implementations MUST NOT emit objects when the median-of-peers time
> estimate [diverges from local time].

Nothing computes a median of peers' clocks; `grep` finds no time estimate at
all. This is the same hole as B4 in §6 above, and it is worse than recorded
there: B4 called clock skew an unmeasured parameter, and it is in fact an
unimplemented MUST. A node with a wrong clock will emit objects it should
withhold, and there is no machinery to notice.

**RFC 3 §2 — a credential cannot be rendered as HJSON.**

> Implementations MUST render any credential as HJSON on request, so that a
> human can read what they are agreeing to.

HJSON exists in this codebase only for the courier's `MANIFEST.hjson`. No verb
renders a credential. `peer` has `counter`, `countersign`, `renew`, `forget`,
`share`, `carry` and `fragment`, and none of them shows the document. An
operator countersigns terms they are told about in prose rather than shown.

### A conflict between two frozen documents

RFC 1 §7: **`EPOCH_WINDOW` MUST be at least `MAX_TTL / EPOCH`, and is
therefore ±45.**
RFC 2 §7: **W MUST default to ±30 epochs**, and MUST NOT be below ±14.

With `MAX_TTL` = 45 d and a 1-day epoch, RFC 2's default of ±30 is below
RFC 1's floor of ±45. The two cannot both be satisfied. The code ships
`EPOCH_WINDOW = 45` and so follows RFC 1.

This is **amendment #10**: not a code defect, and not resolvable by an
implementer. It also interacts with B1 — if the epoch length moves from 1 day
to 7, RFC 1's floor becomes ±7 and the conflict disappears, so settling B1
may settle this too. That is an argument for doing Phase 8 before touching
either number.

### Checked and met

| requirement | evidence |
|---|---|
| RFC 2 §5 — unknown keys preserved and ignored, not stripped | RFC 1 §4.3 path, shared |
| RFC 2 §8 — envelope does not indicate which recipient key was used | prekey trial set |
| RFC 3 §12 — aggregates only, no per-object provenance retained | `PeerMetrics` is counters-only by construction |
| RFC 3 §10 — a token is bound to the requester's `sig_pk` and single-use | `introduction.rs`, `Spent` |
| RFC 3 §4 — reject a link whose validity exceeds 180 days | `MAX_TERM_DAYS` |

### Still unaudited

RFC 4 (25 MUSTs), RFC 5 (17), RFC 6 (22) — **untouched**. Within RFC 2 and 3,
the requirements without a mechanical footprint were not checked: RFC 2's
constant-time batch attempts (§9), its zeroize-on-drop of table entries (§6),
RFC 3's signing-input domain separation (§2 — likely met, the codebase is
careful about domains, but "likely" is what this audit exists to replace),
and §11.3's release-gate demonstration.

Three passes have now found unmet MUSTs in every document examined: RFC 8
(two), RFC 1 (one), RFC 2 (three), RFC 3 (one). Seven in total, none of which
the tests caught, because the tests were written from the same reading of the
documents that the code was.

---

## 12. RFCs 4, 5 and 6, 2026-08-27 — third pass, audit complete

The three remaining documents. With §9–§11 above, every RFC in the series has
now had its MUSTs enumerated and its checkable ones checked.

### Unmet

**RFC 4 §9 — concurrent in-progress handshakes per peer are not capped.**
*(Closed 2026-08-30. The citation was also wrong: this block is §9,
"Denial of service", not §12. See the correction below.)*

> Handshake timeout MUST be enforced (SHOULD be 30 s on interactive links).
> Concurrent in-progress handshakes per peer MUST be capped (SHOULD be 4).

The timeout is enforced — `HANDSHAKE_TIMEOUT_S` in the listener. The cap is
not: nothing counts in-progress handshakes, so a peer whose static key we
accept can open them without limit, each holding a thread and a Noise state
until it times out. The two requirements sit in the same three-line block and
one of them was implemented; this is the shape of defect the passes keep
finding, at the granularity of adjacent sentences.

**RFC 6 §3.6 — channels do not occupy a separate shard space.**

> Channels MUST occupy a separate shard space from sealed traffic.

`shard_bits` exists on the filter and is negotiated between peers, but nothing
assigns channels a different shard from sealed mail: there is one space and
both live in it. RFC 1's B3 settles the default shard `k` at **0 in v1** with
the field mandatory — so in v1 there is exactly one shard, and the separation
RFC 6 requires cannot be expressed at all.

This is **amendment #11**, not a code defect. RFC 6 requires a separation that
RFC 1's v1 parameter choice makes unrepresentable. Either B3's default moves
off 0, or RFC 6 §3.6 acknowledges that the requirement begins at v2. It cannot
be satisfied as both documents currently stand.

### Checked and met

| requirement | evidence |
|---|---|
| RFC 4 §12 — handshake timeout enforced | `HANDSHAKE_TIMEOUT_S`, listener |
| RFC 4 §12 — frame length validated against Noise's 65535 before allocation | `frame.rs`, `MAX_FRAME` |
| RFC 4 §7 — courier archive is flat length-prefixed records, no foreign database opened | `courier.rs` |
| RFC 5 §8 — receiver rejects passed expiry; tombstone set; `min_expiry` watermark | `krab-store/index.rs`: `Tombstoned`, `BelowWatermark`, `min_expiry_min` |
| RFC 5 §6 — RBSR round trips capped | `RBSR_MAX_ROUNDS` |
| RFC 5 §6.1 — Poisson schedule with randomised interval | `scheduler`, and `force-send` states the cost of the one exception |
| RFC 6 §2.7 — fan-out staggered over a window derived from observed arrival rate, not a constant | `observed_arrivals` feeds the window |
| RFC 6 §3.6 — carriage off by default; class 1 excludable via `class_mask` | Phase 6 |
| RFC 6 §5 — the five interface requirements | met as of the channels work above; §4.2 of RFC 8 is the same five |

### Not checked

RFC 4's LoRa `max_bucket` ceiling and the amateur-band class restrictions
(§10) — the constants exist and the refusal is written, but no test drives a
LoRa profile end to end. RFC 4 §8's `short` class: `Class::Short = 3` is
defined and documented as "not a corpus object", and nothing emits one, so
the MUST NOTs about forwarding and storing it are satisfied vacuously — but
that an *incoming* class 3 object is refused before the store was not
verified. RFC 5 §7's "index MUST be fully rebuildable from the segments by one
scan" is asserted by the store's design and was not exercised by deleting an
index and rebuilding.

### The audit, whole

| document | MUSTs | unmet found |
|---|---|---|
| RFC 1 | 36 | 1 — no failed-`(id, epoch)` cache (§6.4) |
| RFC 2 | 17 | 3 — the same cache, no decapsulation cap, no median-of-peers time (§7, §9) |
| RFC 3 | 22 | 1 — no HJSON rendering of a credential (§2) |
| RFC 4 | 25 | 1 — concurrent handshakes uncapped (§12) |
| RFC 5 | 17 | 0 |
| RFC 6 | 22 | 1 — channels share a shard space (§3.6) |
| RFC 7 | 29 | 0 found; §10.3 and §6 unchecked |
| RFC 8 | — | 2 — LOCATION and VOLUME privacy not shown per link (§9) |

**Nine unmet requirements, and two conflicts between frozen documents**
(#10 `EPOCH_WINDOW` vs W, #11 channel shard space vs v1's single shard).

Every document examined had at least one, except RFC 5 — which is also the
document whose requirements are most nearly mechanical, and therefore the
easiest to check by grep. That is a caution about this audit's method, not a
compliment to RFC 5: the requirements this pass could verify are the ones with
a distinctive noun in them, and requirements without one were skipped and are
listed as skipped.

None of the nine was caught by 1045 tests, because the tests were written from
the same reading of the documents as the code was. That is the finding that
matters most, and it argues for conformance vectors driven from the RFC text
rather than more tests written by the implementer.

---

## 13. Status of the nine, 2026-08-27

| # | requirement | status |
|---|---|---|
| 1 | RFC 1 §6.4 / RFC 2 §9 — cache failed `(id, epoch)` pairs | **fixed** — bounded at 4096, cleared with the tag table |
| 2 | RFC 2 §9 — cap decapsulation attempts | **fixed** — 256 per scan, stricter than per-peer-per-epoch |
| 3 | RFC 8 §9 — LOCATION privacy shown per link | **fixed** |
| 4 | RFC 8 §9 — VOLUME privacy shown per link | **fixed** |
| 5 | RFC 4 §12 — cap concurrent handshakes | **was never unmet.** Met at one by the listener's structure; the audit read a missing counter as a missing property |
| 6 | RFC 2 §7 — median-of-peers time estimate | open — needs a wire field |
| 7 | RFC 3 §2 — render a credential as HJSON | open — needs a serialiser and a verb |
| 8 | RFC 6 §3.6 — channels in a separate shard space | **not fixable in code** — amendment #11 |
| 9 | RFC 1 §7 vs RFC 2 §7 — `EPOCH_WINDOW` ±45 against W ±30 | **not fixable in code** — amendment #10 |

### Why 6 and 7 were not done here

**#6, the median-of-peers time estimate**, is not a local computation. RFC 2 §7
forbids *emitting* when the estimate diverges from local time, so the node has
to learn what its peers think the time is — and nothing on the wire carries
that today. Adding a field to the reconciliation handshake is a protocol
change to a frozen series, which needs an amendment before an implementation,
not after. It is also the same hole as B4 and belongs with Phase 7, where the
skew tolerance is decided; doing it twice would settle the number twice.

**#7, HJSON credential rendering**, is a day's work rather than an hour's: a
credential is a flat CBOR map (RFC 3 §2 requires flat precisely so this is
possible), so the serialiser is small, but it needs a verb, a place to render
into, and a decision about whether an *incoming* credential can be rendered
before it is countersigned — which is the case that matters, since the point
is to read what you are agreeing to. Rushing it would produce the thing the
requirement exists to prevent: a rendering nobody reads.

### The correction, and what it says about the audit

Finding 5 was not a defect. I searched for a counter, found none, and reported
the property missing — when the property was satisfied structurally by code
that cannot have more than one handshake in flight. That is the
truncated-`grep` failure Phase 6 recorded against itself, committed again by
the audit that was written to catch this class of thing.

It argues the eight remaining findings should each be confirmed the way this
one was disconfirmed: by reading the path, not by grepping for the mechanism I
expected. Two have been (#8 and #9 are conflicts between documents, checked
against both texts). Six have not.

---

## 14. Decision: message bodies are not compressed, 2026-08-28

Recorded because the absence looked like an omission, was checked, and is a
choice — and because the obvious-seeming fix does not work, which is worth
writing down so it is not proposed again.

### What the RFC actually requires

RFC 1 §3's pipeline reads `→ [compress]  optional, BEFORE encryption`. The
brackets mean what they mean for `[FEC]` and `[armor]` on the lines below:
optional. The MUST that follows —

> **Compression MUST precede encryption and padding.**

— constrains the *ordering*, not the *doing*. Not compressing is conformant.
An earlier note in this session called this an unmet MUST and was wrong; it
would have put a requirement that does not exist onto the audit list.

### What the code does

Nothing compresses a body. No `flate2`, `miniz`, `zstd` or `lz4` in any
crate; no compression in `krab-crypto`, `krab-core`, `krab-proto` or the send
path; `seal_one` seals the plaintext as it stands. The only compression in
the tree is PNG encoding in the picture pipeline, and the courier archive
which documents itself as "flat length-prefixed records, uncompressed".

### Why it stays that way

**Padding makes the safe version pointless.** The proposal that looked best —
compress only when the object stays in the same size bucket — captures no
benefit at all. If the bucket is unchanged the object is padded to the same
size either way, so the bytes on the wire, on disk and on a courier's stick
are identical in count. It spends CPU at both ends to change nothing.

Compression pays only when it **drops** a bucket. Dropping a bucket is
precisely the observable that creates a CRIME-style oracle. The benefit and
the leak are the same event, so there is no middle position:

| | bandwidth win | leak |
|---|---|---|
| compress, bucket may change | real | a genuine, if slow, ratio oracle |
| compress, bucket fixed | **none** | none |
| don't compress | none | none |

### The oracle, assessed rather than waved at

Against this protocol a CRIME-style attack needs attacker-chosen bytes beside
a secret — plausible, via a hostile group member or quoted text; an observable
length — bucketed to six values, which *degrades* the attack without
defeating it, because an attacker who pads their injected content can position
a message one byte below a bucket edge and read the bucket as a reliable
one-bit oracle; and many trials — which is where it fails, because the medium
is human-speed store-and-forward rather than a browser emitting thousands of
requests unattended. That last defence is a property of the medium, not of the
cryptography, and it is the one worth being uneasy about.

§8.2 already concedes bucketing "bounds that leak to bucket granularity but
does not eliminate it". Compression would make that residue
attacker-influenceable rather than merely content-dependent.

### If it is ever built

Only the bucket-changing version is worth building, and it needs an explicit
threat-model decision plus a defence against boundary-positioning — which is
not obviously possible while RFC 1 §8 fixes padding to buckets rather than
allowing jitter.

Two constraints hold whatever is decided. The compressed/not flag belongs in
the **inner plaintext**, where §4.3's "unknown keys in the inner plaintext
MUST be ignored" makes it forward-compatible and where it discloses nothing.
It **MUST NOT** go in the routing header: there it is a per-message "this
compressed well" bit that every relay can read, which is a cleaner oracle than
the one the scheme was trying to avoid.

---

## 15. Decision: no embedded database before 0.1, 2026-08-30

**The corpus stays as segment files, and `graphitesql` is deferred until
there is a measured scalability problem rather than an anticipated one.**

### What prompted the question

Saving the corpus rewrote every object the node held, on every exchange that
received anything — at RFC 3 §5's gigabyte retention, a gigabyte of I/O to
record one object. That is a real liability on a busy node and it is what an
embedded store would have removed for free.

It was not what the layout required. RFC 5 §7 had already specified TTL
buckets so that "eviction is `unlink()` of a whole segment: no compaction, no
tombstone sweep, no fragmentation, no write amplification"; the store had the
buckets and only the writer did not use them. One file per bucket brought a
save down to the bucket that changed — measured at 267 KB against 12.8 MB for
a 50 000-object corpus — which removes the pressure that made a database look
necessary.

### Why not adopt one anyway

Two candidates were considered. `graphitesql` is the better fit of the pair —
`no_std` + `alloc`, `#![forbid(unsafe_code)]`, public domain, core-and-alloc
dependencies only — and `minigraf` is a Datalog graph store with eleven
dependencies and a query language, for a workload that is "give me the bytes
for this 32-byte key".

Against either, four arguments hold:

1. **RFC 5 §7's own analysis.** Reconciliation needs a maintained per-bucket
   `(count, fingerprint)`; §7 says "neither a plain key-value store nor a
   relational index provides this without a scan, and it is the single storage
   property the algorithm depends on". The aggregates stay ours regardless, so
   a database adds a second structure to keep in step with them — the failure
   mode Pass 14 found in `range_fingerprint` and Pass 15 found in
   `StoreView::put`.
2. **The rebuild requirement.** §7 requires the index be fully rebuildable from
   the segments in one scan, so corruption is a delay rather than data loss. A
   database conflates the two.
3. **Encrypted values are not sufficient.** The objects are already ciphertext,
   and that protects the values, not the container: a storage engine parses its
   own page headers, free lists and B-tree pointers, and RFC 7 §4's premise is
   that the disk may have been tampered with while the node was off. Those
   bytes are covered by no key the operator holds. `corpus.krab` is loaded
   through the same content-address verification as a stranger's courier stick,
   deliberately; a database file cannot be. This project already made the same
   call once, in `krab-fabric/src/backend/courier.rs`, rejecting SQLite for the
   archive because it means parsing an attacker-supplied database.
4. **Maturity.** `graphitesql` is 0.1.6 at roughly 80 downloads a month, and
   its goal — byte-for-byte SQLite file-format compatibility — means
   implementing the parts of that format an attacker controls. Vendoring and
   auditing it is a larger security review than the whole of `krab-store`, and
   it recurs on every upgrade.

### What is deferred, not solved

**The corpus is still fully resident in RAM**, bounded by
`peering::Policy::default().retention_bytes` — one gigabyte. That is the real
remaining limit, and it is a read-through or memory-mapped segment file, which
is a file-layout change to code this project already owns. It is not a reason
to adopt a storage engine; it is the work an engine would have done as a side
effect.

Revisit when a node measurably cannot hold its retention window in memory. The
harness for that measurement exists: `crates/krab-store/tests/range_cost.rs`.

---

## 16. The audit's own status, corrected — 2026-08-30

§12 above declared the RFCs 1–7 audit complete on 2026-08-27 and has been
quoted as current ever since. It was not, in three ways, and the shape of each
is the one the adversarial passes keep finding: **a statement that was true
when written and was never re-read against the code that moved under it.**

### Corrections to §12

**RFC 4's handshake cap is met.** §12 lists it unmet. `MAX_PENDING_HANDSHAKES`
caps in-progress handshakes and `Listener::accept` completes them off the
accept loop — Pass 14 §5 and Pass 15 §5. The cap is on the total rather than
per peer, because before a handshake completes there is no peer to attribute
one to; that is stated where it is enforced.

**The citation was wrong.** §12 quotes RFC 4's denial-of-service block and
attributes it to §12 of that document. It is **§9**. The quoted text was
correct, which is why nobody noticed — a wrong pointer to the right words.

**Two of the three "not checked" items are now checked**, and checking them
was not a formality:

- *RFC 5 §7, "the index MUST be fully rebuildable from the segments by one
  scan."* Exercising it found `rebuild_index` rebuilt `index` and not
  `by_trunc` — the map `get_truncated` and `has_truncated` answer from, which
  is every object a peer asks for by its manifest row. A node that had lost
  its index would have rebuilt, served reconciliation, and found nothing it
  held. The test passed before the fix, because nothing had cleared
  `by_trunc` either: the rebuild was being exercised against a map that had
  never lost anything.
- *RFC 4 §8's `short` class, incoming.* Refused since RFC 1 §11 I4 was
  enforced — `validate_body` has no branch that admits class 3 — and now
  tested rather than inferred.

### And one that was unmet rather than unchecked

*RFC 4 §5.4: "Objects above the link's `max_object_size` are filtered **at the
sender**. Receiver-side rejection wastes the scarcest resource in the system
and creates invisible partitions."*

`courier::pack` honoured this. Nothing else did. A LoRa link declaring
`MaxBucket(1)` would still have a 4 KB object written to it by `serve_wants` —
over an hour of airtime at SF10, for something the far end had already said it
could not take. §12 had this listed under "not checked" as a constant with no
end-to-end exercise; writing the exercise found the requirement unmet.

`ExchangeView` now carries the link's ceiling and withholds an object above it,
which makes ten unmet requirements found by this audit rather than nine.

Filtered at `get` and not at `entries`, deliberately: withholding the manifest
row would leave this end's rows disagreeing with its own range fingerprint,
and RBSR reads that as a divergence no exchange can close. One wasted 22-byte
row is the cheaper error.

### What is still not checked

The prose MUSTs with no distinctive noun. §12's own method note is the honest
statement of the limit — "the requirements this pass could verify are the ones
with a distinctive noun in them, and requirements without one were skipped and
are listed as skipped" — and 168 lines across RFCs 1–7 contain `MUST`, most of
them in prose rather than in the fenced normative blocks. How many of those
were skipped is not known, because the passes recorded what they checked and
not what they declined to.

That number is the next thing worth having, and getting it means classifying
168 lines by hand rather than quoting a figure derived from nothing.

---

## 17. RFC 1, requirement by requirement — 2026-08-30

The first document classified line by line rather than by keyword. Method:
resolve every `MUST` occurrence into a requirement, then for each, find the
enforcement or establish there is none, and find the test or record that there
is none.

**The unit was wrong in every previous count.** RFC 1 has 36 lines containing
`MUST`; they carry 41 occurrences, of which 8 are `MUST NOT`; one line is RFC
2119 boilerplate and one is a heading using the word rhetorically; several
requirements span two or three lines and several lines carry two requirements.
What follows is **31 requirements**, which is the number that was never
available by counting anything.

| § | requirement | verdict | enforced at |
|---|---|---|---|
| 3 | FEC and armor MUST NOT participate in the identifier | met | `object_id` covers header ‖ body only; neither is applied below the identifier |
| 3 | compression MUST precede encryption and padding | vacuous | no compression — §14 |
| 4.1 | every version MUST parse the 16 bytes | met | `RoutingHeader::parse` is version-independent |
| 4.2 | a v1 encoder MUST NOT emit key 3 | met | `Envelope::write` writes five keys, none of them 3 |
| 4.2 | a v1 decoder MUST reject key 3 | met + tested | `decode_envelope`, `reserved_body_key` vector |
| 4.3 | indefinite-length items MUST be rejected | met + tested | `cbor::Reader::head`, `rejects_indefinite_lengths` |
| 4.3 | unknown body keys MUST be rejected | met + tested | `decode_envelope`; ingest I4 |
| 4.3 | unknown *inner plaintext* keys MUST be ignored | vacuous | the inner plaintext is a marker and bytes, not a keyed map |
| 5.2 | nodes MUST support excluding class 1 via `class_mask` | met | `filter::Filter`, `Policy::class_mask` |
| 5.3 | cover objects MUST be indistinguishable from `sealed` | vacuous | nothing emits cover in v1 |
| 5.3 | cover MUST use class 0, not class 2 | vacuous | as above; `ReservedCover` exists only to reserve the value |
| 5.4 | the size/timing caveat MUST be restated in security considerations | met | documentation obligation, met by RFC 1 §8.2 and this tree's `SECURE-DELETE.md` |
| 6.2 | `EPOCH_WINDOW` MUST be ≥ `MAX_TTL / EPOCH` | met | `MAX_TTL_MIN = EPOCH_WINDOW * 1440` derives the other way; conflict #10 |
| 6.2 | a deployment MUST NOT narrow it | met | not configurable |
| 6.3 | the envelope MUST NOT indicate which recipient key was used | met | §4.2's five keys carry no index |
| 6.3 | implementations MUST attempt the full set | met + tested | `receive.rs`, "every private key, and no early exit" |
| 6.3 | and MUST NOT stop at first success | met + tested | same |
| 6.4 | MUST cache failed `(id, epoch)` pairs | met + tested | `receive::Attempts` |
| 7 | suite `0x0002` MUST be selectable per message | met | per-recipient mode in `compose::seal_to` |
| 7 | MUST NOT be a deployment-wide default | met | no setting expresses one |
| 8.1 | padding MUST be zero | met + tested | `canonical_bytes` |
| 8.1 | a receiver MUST reject non-zero padding | met + tested | ingest I1, `non_zero_padding_is_refused` |
| 8.2 | cover MUST match the bucket distribution of real traffic | vacuous | nothing emits cover |
| 9.2 | MUST show a fingerprint alongside any display name | met + tested | `alias::Aliases::show` renders both, always |
| 9.3 | truncated identifiers MUST NOT appear in a routing header, a `WANT` outside a session, or any stored structure | met | the header has no such field; `by_trunc` is derived and unpersisted |
| 10 | a relay MUST route, filter and expire an unknown `ver` from the header alone, and MUST store and forward it opaquely | **UNMET** | see below |
| 10 | reserved header bits MUST be zero on emission | met | `RoutingHeader::write` |
| 10 | and MUST be ignored on receipt | **conflict #12** | `parse` rejects; §11 I3 requires rejecting |
| 11 | a receiver MUST reject unless I1–I6 hold | met + tested | `Store::ingest`; vectors name each |
| 11 | every check MUST be applied before an object enters the store | met | I1 and I4 closed 2026-08-29 |
| 11 | I5 MUST run before anything consulting the identifier | met | first check in `ingest` |
| 11 | rejection MUST be silent to the peer | met | nothing is written back |
| 11 | and MUST be counted per peer as a quota signal | **was unmet, now met** | `Spend::rejected` |
| 12 | RFC 1 MUST NOT reach Final without machine-checkable vectors | met | `Documentation/vectors/rfc-1.txt` |
| 12 | two independent implementations MUST agree on every vector | **unmet, by design** | there is one implementation; recorded in README |

### The one that matters: §10's opaque relay

> "A relay encountering `ver` it does not know MUST route, filter, and expire
> from the 16-byte routing header alone, and MUST store and forward the
> remaining bytes opaquely."

`Store::ingest` refuses `version != 1`, and there is no other path into the
corpus. So this node does not relay a v2 object at all.

The deviation is deliberate and the reasoning is in the code: "an object this
node cannot fully validate must not enter the store, because the identifier
covers bytes it did not understand — which is a malleability surface." That
argument is not wrong. But §10 answers it directly — "this is safe because the
identifier covers the whole object; an unparsed object cannot be tampered with
undetected" — and states the cost of getting it wrong:

> "Without opaque relay of unknown versions, the first protocol revision
> partitions the network along version lines and the partition is permanent,
> because the nodes that would bridge it are the ones offline for a month."

**This is the eleventh unmet requirement and the most consequential found so
far**, because it is invisible until there is a v2 and unrepairable afterwards
by the nodes that matter. It is not fixed here: admitting unvalidatable objects
touches I3, I4, eviction accounting and the quota model at once, and it wants
its own change rather than a line in an audit.

### Conflict #12: reserved header bits

§10 says reserved bits "MUST be **ignored** on receipt". §11's I3 requires
"reserved flag bits zero" and §11's preamble says a receiver MUST **reject** an
object unless every check holds. For the same field, one section says ignore
and the other says refuse.

`RoutingHeader::parse` refuses, implementing §11. Under §10's reading a v2
object setting bit 2 is refused by every v1 relay, which is the partition §10
exists to prevent — so the two sections disagree about the same bytes, and the
implementation cannot satisfy both. Third conflict between frozen documents,
after #10 and #11.

### Counts

31 requirements. **25 met** (17 with a test that names them), **4 vacuous**
(cover traffic and inner-plaintext keys, both unimplemented in v1), **1 unmet**
(§10 opaque relay), **1 unmet by design** (§12's second implementation), and
**1 conflict**. One requirement — §11's per-peer rejection counter — was unmet
when this pass began and was fixed during it.

---

## 18. RFC 2, requirement by requirement — 2026-08-30

17 lines carrying 19 occurrences; one is RFC 2119 boilerplate and one is RFC 2
*withdrawing* a MUST from RFC 6 and RFC 7 rather than imposing one. **16
requirements.**

| § | requirement | verdict | enforced at |
|---|---|---|---|
| 3 | a node identifier MUST NOT appear in a tag position | met | tags are `pairwise_tag`/`inbox_tag` output; no path writes an id into `RoutingHeader::tag` |
| 3 | a destination tag MUST NOT appear in a beacon, nodelist fragment, rollcall entry, transport header, or any log line | met + tested | `activity_log`'s own test refuses a line containing "tag"; beacons and rollcall carry node ids |
| 3.4 | unknown address keys MUST be preserved and ignored, not stripped | vacuous | the `dst=` address form is modelled in `krab-sizes` and is not parsed by the node |
| 4.3 | table entries MUST be zeroized on drop | **was unmet, now met** | `impl Drop for TagTable` |
| 5 | W MUST default to ±30 | **conflict #10** | `EPOCH_WINDOW = 45`; RFC 1 §6.2 requires ≥45 |
| 5 | W MUST NOT be below ±14 | met | 45 |
| 5.1 | MUST accept objects whose epoch falls within W of local time | met + tested | `TagTable::build` covers `pairwise_window` |
| 5.1 | MUST NOT emit when median-of-peers time diverges by more than ±6 h | **unmet** | no median-of-peers estimate exists — recorded §11 |
| 7.1 | the envelope MUST NOT indicate which recipient key was used | met | §4.2's five keys carry no index |
| 7.2 | inbox-tagged objects MUST be rate-capped per peer per epoch | **unmet** | `Attempts` caps per scan, not per peer per epoch — recorded §11 |
| 7.4 | MUST cache failed `(id, epoch)` pairs | met + tested | `receive::Attempts` |
| 7.4 | MUST cap inbox-tagged decapsulation per peer per epoch | **unmet** | same requirement as §7.2, stated twice |
| 7.4 | MUST attempt all live batches in constant time | met + tested | `Inbox::scan_with` |
| 7.4 | and MUST NOT stop at first success | met + tested | same |
| 8 | MUST warn about in-flight loss on rotation | **unmet** | no correspondence-key rotation command exists to warn from |
| 8 | the precomputation table MUST be treated as key material: never paged, never logged, never persisted | **partly met** | never logged and never persisted; **never paged is unmet** — nothing calls `mlock` |

### What this pass found

**RFC 2 §4.3's zeroization was absent**, and it is the requirement RFC 2 argues
hardest for: the table "is a map from tag to correspondent, which is exactly
the correlation the design exists to prevent", and §8 calls it "the single most
valuable artifact on a seized running node". `Shared` zeroizes; the identity
keys zeroize; the one structure whose *contents* are public and whose *shape*
is the secret had no `Drop` at all.

Fixed, with its limit stated where it is implemented: the values are
overwritten, the `HashMap` keys cannot be, and the keys are tags — public by
construction, readable off the wire. What must not survive is which of them
belong to this node's correspondents, and that is what the values hold.

**"Never paged" is unmet and is not a RFC 2 problem.** Nothing in this tree
calls `mlock`; RFC 7 §9's memory-locking requirement is unmet across the board,
and it is recorded here because §4.3 and §8 both lean on it. It belongs to
RFC 7's pass.

**§8's rotation warning is unmet in a way worth distinguishing** from the
others: the warning is missing because the thing it warns about is missing.
There is no command that rotates a correspondence key, so there is nothing to
warn from. `peer rekey` rotates the *reservoir*, which is a different key with
different consequences and already warns about its own.

### Counts

16 requirements. **9 met** (6 with a test that names them), **1 vacuous**,
**4 unmet** — median-of-peers time, the inbox decapsulation cap stated twice,
and the rotation warning — **1 partly met** (paged/logged/persisted, two of
three), and **1 conflict** already recorded as #10. One — §4.3's zeroization —
was unmet when this pass began and was fixed during it.

Running total across RFC 1 and RFC 2: **47 requirements, 13 unmet or partly
unmet, 3 conflicts.** Two of the thirteen were fixed by the passes that found
them.

---

## 19. RFC 3, requirement by requirement — 2026-08-30

22 lines carrying 25 occurrences; one is RFC 2119 boilerplate. **22
requirements**, more of them documentation and default-value obligations than
either previous document — RFC 3 is about a ceremony between people, and
several of its MUSTs bind what an operator is told rather than what a byte does.

| § | requirement | verdict | enforced at |
|---|---|---|---|
| 3 | every signed document MUST prefix its signing input with a domain unique to that type | met + **now mechanised** | twelve `DOMAIN` constants; `domain_separation.rs` |
| 3 | a signature over one type MUST NOT be valid over any other | met + tested | same |
| 3 | a credential body MUST be a flat CBOR map | met | `Credential::encode` embeds parties, flags and terms as `bstr`, never as nested maps |
| 3 | MUST render any credential as HJSON on request | **unmet** | recorded §11; `peer show` renders prose |
| 4 | MUST reject a link whose validity exceeds 180 days | met + tested | `credential::MAX_TERM_DAYS` |
| 4 | MUST surface an expired peering as an explicit state | met + tested | `Standing::Live(Life::Expired)`, shown in `peers` |
| 5 | the negotiation chain MUST NOT be published | met | written to `peers/<id>/chain`; no path puts it in the corpus |
| 6.1 | three consequences MUST be stated in deployment documentation | met | `PEERING.md`, and RFC 3 §6.1 itself |
| 6.1 | the relay-responsibility price MUST be stated as a deliberate choice | met | same |
| 8.2 | deltas MUST reference the last full fragment by hash | met + tested | `fragment::DOMAIN_BASE`; a reader without the base refuses |
| 8.3 | share flags MUST default to false | met + tested | `Flags::default` |
| 8.4 | on termination a node MUST purge attributable artifacts | met + tested | `peer forget` |
| 8.4 | and MUST retain the corpus | met + tested | same test asserts both halves |
| 9 | rollcall opt-in MUST be the default | met + tested | `rollcall`, and it says so twice |
| 10 | ring signatures MUST NOT be built unless the token path fails | met | not built |
| 11.1 | MUST NOT present remote peering as equivalent | met | `peer meet` output says so at length |
| 11.3 | MUST demonstrate peering and first message with all interfaces down | met + tested | `courier_only_peering_completes_with_no_network`, in `smoke.sh` |
| 12 | MUST NOT retain per-object provenance | met + tested | `PeerMetrics` is counters only, by construction |
| 13 | MUST warn below the lower bound for the transport mix | met + tested | `krab_node::warnings::evaluate` |
| 14 | the credential store MUST be encrypted under the RFC 7 hierarchy | met | sealed under `epoch_key` before `atomic::write` |
| 14 | an introduction token MUST be bound to the requester's `sig_pk` | met + tested | `introduction::Token` |
| 14 | and MUST be single-use | met + tested | `introduction::Spent` |

### What this pass found

**Nothing unmet that was not already recorded.** RFC 3 is the first document to
come through with only its known gap — §3's HJSON rendering — and that is
worth stating plainly rather than glossing: the yield of this method is not
constant, and a document about a human ceremony has fewer places for a silent
byte-level omission to hide.

**§3's rule was met and is now enforced.** Twelve domain constants, all
distinct, and nothing prevented a thirteenth reusing a string. RFC 3 states the
general rule instead of one more constant precisely because the next document
inherits it, so the check belongs in the suite rather than in a reviewer's
head: `no_two_signed_documents_share_a_domain_string` walks every `pub const
… = b"krab/…"` in the workspace and refuses a collision. Verified against a
deliberate one — pointing `introduction::DOMAIN` at `krab/link/v1` fails it and
names both files.

What it cannot check is that a signed document *has* a domain at all. A
document written with no prefix is invisible to it, and RFC 3 §3 exists because
the credential was exactly that case until somebody noticed.

**§3's flat-map rule was met for the stated reason**, which is worth recording
because it is the kind of rule an implementation usually satisfies by accident
and then breaks: `Credential::encode` embeds parties, flags and terms as byte
strings rather than as nested maps, and RFC 3's reasoning — "a nested map's
keys restart, and a decoder reading both levels from one cursor correctly
rejects its own encoder's output" — is the reason it must stay that way.

### Counts

22 requirements. **21 met** (14 with a test that names them), **1 unmet**
(§3's HJSON rendering, already recorded), no vacuous, no new conflicts.

Running total across RFCs 1–3: **69 requirements, 14 unmet or partly unmet,
3 conflicts.** Three of the fourteen were fixed by the pass that found them.

---

## 20. RFC 4, requirement by requirement — 2026-08-31

25 lines carrying 30 occurrences; one is RFC 2119 boilerplate. Several lines
carry three clauses — §8's `short` rule is one sentence with three prohibitions.
**26 requirements.**

| § | requirement | verdict | enforced at |
|---|---|---|---|
| 4.1 | constrained links MUST hold sessions open across cycles | met | `LinkTable` keeps the session; nothing closes on idle |
| 4.1 | both parties MUST verify the peer's static key against the credential | met + tested | `noise::check_peer`, both halves |
| 4.2 | *(framing table: 2 frames at 65 536, 5 at 262 144)* | met | chunked transport, Pass 14 §1 |
| 5.2 | the onion key MUST NOT derive from the identity key | vacuous | no onion service; `socks` is an outbound feature only |
| 5.2 | clients MUST show bootstrap progress | vacuous | as above |
| 5.4 | LoRa `max_bucket` MUST NOT exceed 1024 at SF7–SF10 | met | `lora_sf10` is `MaxBucket(1)` |
| 5.4 | …and 256 at SF11–SF12 | **unrepresentable** | no SF11/SF12 profile exists — see below |
| 5.4 | filtering is at the sender | met + tested | `ExchangeView::get`, closed 2026-08-30 |
| 5.4 | armor MUST be off on LoRa | met | `lora_sf10` sets `armor: false` |
| 5.5 | the container MUST be a flat sequence of length-prefixed records | met + tested | courier archive is `frame::write` records |
| 5.5 | filenames MUST be ignored entirely | met + tested | import reads content, never the name |
| 5.5 | compression MUST be off | met | nothing compresses — §14 |
| 5.5 | every object MUST be verified by content hash on ingest | met + tested | I5, first check in `ingest` |
| 5.5 | MUST NOT open a foreign database file | met | the archive is this project's own format |
| 5.5 | an archive MUST be a time window selected by expiry range | met + tested | `courier::pack` takes `(lo, hi)` |
| 5.5 | MUST NOT restrict an archive to objects acquired since a previous one | met | no acquisition time is recorded to restrict by |
| 7 | classes 0, 2, 3 MUST NOT be carried on amateur bands | vacuous | no amateur-band profile exists |
| 7 | amateur and ISM MUST NOT be conflated in configuration | vacuous | as above |
| 8 | a `short` message MUST NOT be forwarded | met + tested | `validate_body` refuses class 3 |
| 8 | MUST NOT be stored beyond display | met + tested | same |
| 8 | MUST NOT enter reconciliation | met + tested | same |
| 8 | the 64-bit MAC caveat MUST be restated in security documentation | vacuous | `short` framing is not implemented |
| 9 | handshake timeout MUST be enforced | met + tested | `HANDSHAKE_TIMEOUT_S`, Pass 15 |
| 9 | concurrent in-progress handshakes MUST be capped | met + tested | `MAX_PENDING_HANDSHAKES`, Pass 14 |
| 9 | frame length MUST be validated before allocation | met + tested | `frame::read_len` |
| 9 | objects exceeding the link's `max_bucket` MUST be rejected before buffering | **was unmet, now met** | `ExchangeView::put` |
| 9 | the LoRa duty-cycle attack MUST be stated to operators | met | RFC 4 §9 and `PEERING.md` |
| 10 | clients MUST show which links provide location privacy | met + tested | `peers` panel, `loc ● / ○` per link |

### Two ceilings, not one

§5.4 and §9 both constrain `max_bucket` and they are **different
requirements**. §5.4 filters at the *sender*, so a constrained link never
spends airtime on something the far end cannot take; §9 rejects at the
*receiver*, so a peer that ignores the agreement cannot make this node hold
what it agreed not to carry. One is about waste, the other about a peer
behaving badly.

Only §5.4's was implemented, and only since 2026-08-30. §9's is now in
`ExchangeView::put`, with its own limit recorded: "before buffering" is
satisfied as early as this code can manage, because the frame reader has
already read the bytes by the time anything knows which link they came from,
and its bound is `frame::MAX_CONTROL` rather than the link's. Refusing in `put`
is before the *store* buffers it, which is the allocation that lasts.

### The one that is neither met nor unmet

§5.4 gives a table for SF7 through SF12. **The implementation offers one row.**
`LinkProfile::lora_sf10` is the only LoRa profile, so the SF11–SF12 ceiling
cannot be violated — and an operator running SF11 hardware has no profile that
describes it, and would use the SF10 one, which admits 1 KB objects where §5.4
caps them at 256 B.

That is not a rule broken; it is a configuration that cannot be expressed.
Recorded as unrepresentable rather than vacuous, because vacuous suggests
nothing is missing.

### Counts

26 requirements. **19 met** (14 with a test that names them), **6 vacuous** —
Tor's onion service, amateur bands, and `short` framing, none of them built —
**1 unrepresentable**, and **0 unmet**, after one was fixed by this pass.

Running total across RFCs 1–4: **95 requirements, 15 unmet or partly unmet,
3 conflicts.** Four of the fifteen were fixed by the pass that found them.

---

## 21. RFC 5, requirement by requirement — 2026-08-31

17 lines carrying 19 occurrences; one is RFC 2119 boilerplate, and one is a
mode table listing `PushOnly → MUST NOT be used`, restated as prose four
sections later. **17 requirements.**

§12 of this plan recorded RFC 5 as the one document with **zero** unmet
requirements, and flagged that as a caution rather than a compliment: "the
document whose requirements are most nearly mechanical, and therefore the
easiest to check by grep." Reading it line by line found one.

| § | requirement | verdict | enforced at |
|---|---|---|---|
| 2 | reconciliation MUST be scoped to the filter | met + tested | `ExchangeView.filter`, checked on `put` |
| 3.1 | truncated identifiers MUST NOT appear in a routing header, stored structures, or a request outside a session | met, with a note | see below |
| 4.1 | `PushOnly` MUST NOT be used as a link's sync mode | met structurally | `Mode` has two variants and neither is `PushOnly` |
| 4.4 | fingerprints MUST be additively composable, `Σ H(id) mod 2²⁵⁶` | met + tested | `Fingerprint::add`, and `sub` for prefix sums |
| 4.4 | implementations MUST cap round trips | met + tested | `RBSR_MAX_ROUNDS = 8` |
| 4.4 | …**and fall back to manifest mode on exceeding it** | **was unmet, now met** | `descend`, see below |
| 4.5 | `PushOnly` MUST NOT be used as a link's sync mode | met structurally | the same requirement, stated twice |
| 5 | deployments MUST NOT rely on LoRa as a majority transport | deployment obligation | the SHOULD-warn at 30 % of links is not implemented |
| 6.1 | reconciliation MUST run on a Poisson schedule, randomised interval and peer order, independent of user activity | met + tested | `Scheduler::due` takes time and entropy and nothing else — RFC 0 I-5 |
| 7 | the index MUST be fully rebuildable from the segments by one scan | **was unmet, now met** | `rebuild_index`, closed 2026-08-30 |
| 8 | a receiver MUST reject any object whose expiry has passed | met + tested | I2 |
| 8 | a node MUST maintain a tombstone set | met + tested | `Store::tombstones` |
| 8 | a node MUST maintain a `min_expiry` watermark | met + tested | `Store::watermark`, advertised in `HELLO` |
| 8 | tombstones MUST be bounded | met + tested | `prune_tombstones` |
| 8 | an implementation MUST drop tombstones past the horizon | met + tested | same, at `expiry + MAX_TTL` |
| 9 | eviction MUST be oldest-first and uniform across shards | met + tested | `evict_to` takes a byte budget and nothing else |
| 9 | eviction policy MUST NOT depend on any property other than age | met structurally | the signature is the enforcement — there is no parameter a policy could enter through |

### The one §12 missed: the fallback, not the cap

> "Implementations MUST cap round trips (SHOULD be 8) **and fall back to
> manifest mode on exceeding it.** An adversarial peer can otherwise
> manufacture divergence patterns that never converge."

`RBSR_MAX_ROUNDS = 8` exists, is used, and is named in a comment citing §4.4 —
which is exactly why a keyword-anchored pass reads the requirement as met. Past
the cap, `descend` answered with an empty response, said `RangeDone`, and the
exchange ended having moved whatever had already crossed.

That is the right outcome for the adversary the cap exists for and the wrong
one for two honest nodes whose disagreement is simply wider than eight rounds
of splitting can resolve: they give up where **one manifest round trip would
have finished**. §4.4 asks for both behaviours and only one was built.

Falling back means listing the ranges still in dispute instead of splitting
them further, which is what `respond` already does for a range it resolves as a
leaf — so the fallback is the leaf path applied to what is left, with no second
code path to disagree with the first.

**And the first version of the fix was wrong in a way the test caught.** It
listed on *every* round past the cap, so a peer sending a two-byte `Range`
drew a manifest back each time, up to `MAX_MESSAGES` of them — the
amplification RFC 5 §12 names, reintroduced by the fix for a different
requirement in the same file. The fallback fires once. The bound in the test
was what failed, not the behaviour under test.

### §3.1 and the truncated-identifier index

§3.1 says truncated identifiers MUST NOT appear "in stored structures".
`Store::by_trunc` is a map keyed by exactly that.

Recorded as met, with the reasoning rather than the conclusion: the rule
protects against *accepting* a truncated identifier as a claim outside an
agreed scope, because 16 bytes is grindable. `by_trunc` is a local index over
objects this node already holds, derived rather than persisted — it is rebuilt
by `rebuild_index` and appears in no artifact — and every read of it
(`get_truncated`, `has_truncated`) is reached only from inside a session.

That is a reading, not a proof, and it is written down so the next person
disagrees with an argument rather than rediscovering the question.

### Counts

17 requirements. **15 met** (12 with a test that names them), **1 deployment
obligation** whose optional warning is unimplemented, and **1 that was unmet
and is now met**. No vacuous, no conflicts.

Running total across RFCs 1–5: **112 requirements, 16 unmet or partly unmet,
3 conflicts.** Six of the sixteen were fixed by the pass that found them.

---

## 22. RFC 6, requirement by requirement — 2026-08-31

22 lines carrying 28 occurrences; one is RFC 2119 boilerplate, and one —
§2.8's "members of large groups MUST republish prekeys weekly" — was
**withdrawn by RFC 2 §9**, which corrected the batch-size model it rested on.
**25 requirements.**

| § | requirement | verdict | enforced at |
|---|---|---|---|
| 2.4 | MUST warn above 25 members | met + tested | `groups::WARN_ABOVE` |
| 2.4 | MUST refuse above 50 | met + tested | `groups::REFUSE_ABOVE` |
| 2.4 | clients MUST surface which recipients are LoRa-reachable before sending | **was unmet, now met** | `group send`, see below |
| 2.6 | divergence MUST be surfaced, not silently resolved | met + tested | `Group::divergence` |
| 2.6 | MUST record roster authority | met + tested | `groups::Authority`, encoded |
| 2.6 | and MUST NOT allow it to change | met + tested | no path rewrites it |
| 2.7 | MUST stagger fan-out over a randomised window | met + tested | `fanout::offsets` |
| 2.7 | W MUST be derived from the observed background rate, not a constant | met + tested | `App::background_rate` is arrivals ÷ hours |
| 2.8 | members of large groups MUST republish weekly | **withdrawn** | RFC 2 §9.2 retracts it by name |
| 2.8 | MUST surface prekey burn rate | met | `status` reports it |
| 2.8 | MUST warn when joining a group would make cadence insufficient | met + tested | `groups`, at join |
| 3.3 | shared-write channels MUST NOT be added | met | not built |
| 3.4 | nodes MUST support excluding class 1 via `class_mask` | met | `filter::Filter` |
| 3.4 | channel carriage MUST be off by default | met + tested | `CarriagePolicy::default` |
| 3.4 | channels MUST occupy a separate shard space from sealed traffic | **unmet — conflict #11** | one shard space; RFC 2 §6 defines one |
| 3.4 | a node MUST be able to carry its operator's mail and no channels | met + tested | carriage off is the default state |
| 3.6 | the jurisdiction consequence MUST be stated where a user enables channels | met + tested | `channel carry on` arms, then commits, and says why |
| 5.1 | the security context MUST be visible in the composer | met + tested | `Banner::PublicSignedPermanent` |
| 5.2 | the first channel post of a session MUST require explicit confirmation | met + tested | two-step, like `wipe` |
| 5.3 | reply MUST default to a private sealed message to the author | met | `reply` composes a sealed message |
| 5.3 | the publish action MUST be a separate keystroke | met | `channel post` is its own verb |
| 5.4 | roster divergence MUST be shown, never silently merged | met + tested | the same requirement as §2.6, restated |
| 5.5 | group size and prekey adequacy MUST be shown at join time, not failure time | met + tested | `groups`, at join |
| 6 | users MUST be told channels are permanent at the point of posting | met + tested | the banner, and the first-post confirmation |

### §2.4: whose duty cycle is being spent

> "Groups over LoRa SHOULD NOT exceed 10 members, and **clients MUST surface
> which recipients are LoRa-reachable before sending.**"

`group send` reported how many copies were sealed, the stagger window, and who
had no peer-link. It said nothing about the carrier.

§2.4's own table is why that matters: one message to a 20-member group is
**1.6 hours of LoRa airtime**. A sender who does not know that three of their
twenty members are on a radio link is committing hours of somebody else's duty
cycle, and RFC 4 §9 is explicit that nothing at the protocol layer can defend
it — "there is no protocol defence; it is a physical-layer property of the
band, and it MUST be stated to operators rather than implied."

Now named, with the figure, per send.

### And a link that would not change its transport

Writing the test for the above found `LinkTable::connect` using
`or_insert_with`, so a second `connect` to a peer that already had a link kept
the **first** profile and discarded the one passed in. `connect <peer> lora
<addr>` after `connect <peer> tcp <addr>` reported success and left the node
believing the peer was still on TCP.

That profile decides the sync mode (RFC 5 §4.1), the object ceiling (RFC 4 §5.4
and §9), the session deadline, and what the peers panel says about location
privacy. All four would have been answered for a carrier the link no longer
used. The session is deliberately kept across the change: a profile describes
the carrier, an open socket is a fact about the world, and tearing one down on
re-`connect` would kill a working exchange.

Not an RFC 6 requirement — found by testing one.

### Counts

25 requirements. **23 met** (18 with a test that names them), **1 withdrawn**
by a later RFC, and **1 unmet** — §3.4's separate shard space, which is
conflict #11 and cannot be closed without an RFC editor, since RFC 2 §6 defines
a single shard space that RFC 6 §3.4 asks channels to sit outside.

Running total across RFCs 1–6: **137 requirements, 17 unmet or partly unmet,
3 conflicts.** Seven of the seventeen were fixed by the pass that found them.

---

## 23. RFC 7, requirement by requirement — 2026-08-31

29 lines carrying 34 occurrences — the most of any document. One is RFC 2119
boilerplate; one is the `⚠ CRITICAL DEFECT` header, which is a status marker
rather than a requirement; and one — §5.3's "high-traffic nodes MUST republish
weekly" — was **withdrawn by RFC 2 §9.1**, which removed the `MAX_OBJECT`
ceiling it rested on. **30 requirements.**

| § | requirement | verdict | enforced at |
|---|---|---|---|
| 4 | MUST NOT rely on file deletion or overwriting for any forward-secrecy property | met | `shred`'s module doc states it; every erasure is key destruction |
| 4.1 | MUST store the KDF parameters alongside the salt | met + tested | `kek.params` |
| 5.3 | high-traffic nodes MUST republish weekly | **withdrawn** | RFC 2 §9.1 removes the ceiling it rested on |
| 6 | *(the `⚠ CRITICAL DEFECT` header)* | **closed in the body** | §6's own text withdraws the broken derivation; the code implements the replacement |
| 6.1 | MUST destroy `root_N` once `root_{N+1}` is derived | met + tested | `Reservoir::advance_to` — "this line is the destruction claim" |
| 6.1 | MUST NOT retain any value from which a destroyed chunk can be recomputed | met + tested | the ratchet is one-way; no root is kept |
| 6.1 | a chunk outside the acceptance window MUST be unrecoverable | met + tested | same |
| 6.1 | `chunk_N` MUST NOT be used as a message key | met + tested | `Mode::AuthPsk` — HPKE `mode_auth_psk`, `psk_id = u32_le(N)` |
| 6.2 | both parties MUST contribute to the reservoir | met + tested | `R_A ⊕ R_B`, two courier legs |
| 6.2 | a contribution MUST reach its destination over a channel not depending on the asymmetric cryptography it outlives | met | `peer pad` is removable media; the live path is refused post-quantum credit |
| 6.2 | MUST record that a network-established reservoir has no post-quantum property | met + tested | `Channel::Network` in the peer record |
| 6.2 | and MUST surface it wherever the link is displayed | met + tested | `peers` shows it per link |
| 6.4 | the reservoir material MUST NOT appear in the credential | met + tested | the credential carries identifier and epoch only |
| 6.4 | a part-finished ceremony MUST NOT accept a second, differing card | met + tested | `ceremony`, with the substitution attack named |
| 8 | MUST store ciphertext and derive on display | met | `receive`'s module doc; there is no plaintext cache and no Sent folder |
| 8.1 | MUST make the retention consequence visible before the window elapses | met | `pin` exists and `status` reports the horizon |
| 9 | **`mlock` key buffers; MUST fail loudly at startup if locking is unavailable** | **unmet** | nothing calls `mlock`; see below |
| 9 | `Debug` on key types MUST print nothing | met + tested | every key type prints `<redacted>` |
| 9.1 | the "Rust cannot guarantee a secret was never copied" limit MUST appear in the security considerations of any release | **was unmet, now met** | `SECURE-DELETE.md` |
| 10 | neither panic wipe nor dead-man timer MUST be enabled by default | met | the chord is a chord; the timer is not built |
| 10 | both MUST be discoverable | partly met | the chord is in `help`; there is no timer to discover |
| 10 | the dead-man timer MUST warn well before it fires | vacuous | not built |
| 11 | the identity key MUST be backed up offline at creation | met + tested | `init` shows the words once, as a step |
| 11 | MUST state plainly that message history is not recoverable | met + tested | said at `init` and in `help` |
| 12 | MUST surface prekey burn rate, not merely remaining count | met | `status` |
| 13.1 | senders MUST use the deterministic index when the tag mode is pairwise | met + tested | `compose` |
| 13.2 | recipients MUST attempt all live batches in constant time | met + tested | `Inbox::scan_with` |
| 13.2 | and MUST NOT stop at first success | met + tested | same |
| 13.3 | MUST cap inbox-tagged decapsulation attempts per peer per epoch | **unmet** | `Attempts` caps per scan; the same gap as RFC 2 §7.2 and §7.4 |

### The `⚠ CRITICAL DEFECT` header, traced

It has been quoted in this plan and never followed. It says §6 "MUST NOT BE
IMPLEMENTED AS WRITTEN" because `msg_key = HKDF(chunk_N, "krab/msg/v1" ‖ tag)`
derives one key per *(pair, epoch)* rather than per message — keystream reuse
and Poly1305 one-time-key recovery, "confidentiality **and** integrity lost for
all reservoir-protected traffic between a pair within an epoch". Status is
recorded as "open, awaiting fix".

**The body of §6 already carries the fix.** Further down, the same section says
"the previous derivation is withdrawn. `chunk_N` is not a message key and MUST
NOT be used as one", and specifies HPKE `mode_auth_psk` with `psk = chunk_N`
and `psk_id = u32_le(N)`. That is what `krab_crypto::seal::Mode::AuthPsk`
implements, and the epoch travels as `psk_id` so a chunk cannot be replayed
into a different one.

So the header is stale rather than the code being broken. It is a status marker
that outlived its status — the same defect class this series keeps finding, in
the document that defines the property. **Recorded, not edited**: the RFCs are
frozen, and correcting a header is an editor's job. What is fixed here is that
it has now been traced rather than repeated.

### §9's `mlock`, and why it is not a line of code

> "`mlock`/`VirtualLock` key buffers. The full secret working set is under
> 100 KB (§2.1), so this is cheap. On Linux it requires `RLIMIT_MEMLOCK`
> headroom; implementations MUST fail loudly at startup if locking is
> unavailable rather than proceeding unlocked."

Neither half is implemented: nothing locks, and nothing fails loudly. Key
material may be paged to swap and nothing says so. RFC 2 §4.3 and §8 both lean
on this for the tag table, which is why it surfaced during that document's pass
and was deferred to this one.

It is not a one-line fix. `mlock` needs `libc` or a wrapper crate, and every
crate in this workspace carries `#![forbid(unsafe_code)]` — so it is a
dependency decision and an unsafe-boundary decision at once, in a tree that has
exactly one such boundary today (`getrandom`). It also cannot be done honestly
by locking *some* buffers: the requirement is about the working set, and a
partial lock invites the belief that the rest is covered.

What has been done instead is to say so where an operator reads: RFC 7 §9.1's
disclosure now appears in `SECURE-DELETE.md`, naming `mlock` as unimplemented,
hibernation as undefeatable, and the operator's own swap configuration as the
mitigation this build does not substitute for.

### Counts

30 requirements. **25 met** (19 with a test that names them), **1 withdrawn**,
**1 vacuous**, **1 partly met**, and **2 unmet** — §9's memory locking and
§13.3's inbox decapsulation cap, the latter being the third statement of a
requirement RFC 2 makes twice. One was unmet when this pass began and was fixed
during it.

### The series, whole

| document | requirements | unmet | fixed by the pass |
|---|---|---|---|
| RFC 1 | 31 | 2 | 1 |
| RFC 2 | 16 | 4 | 1 |
| RFC 3 | 22 | 1 | 0 |
| RFC 4 | 26 | 0 | 1 |
| RFC 5 | 17 | 0 | 1 |
| RFC 6 | 25 | 1 | 1 |
| RFC 7 | 30 | 2 | 1 |
| **total** | **167** | **10** | **6** |

Plus 3 conflicts between frozen documents (#10 `EPOCH_WINDOW` vs W, #11 channel
shard space, #12 reserved header bits), 2 requirements withdrawn by later RFCs,
and 12 vacuous or unrepresentable.

**167 requirements, against the "~150 MUSTs" this plan quoted for weeks.** The
figure was close by accident: it counted lines, and lines are neither
requirements nor occurrences.

Six unmet requirements were closed by the passes that found them. The four that
remain are RFC 1 §10's opaque relay of unknown versions, RFC 2/7's inbox
decapsulation cap, RFC 3 §3's HJSON rendering, and RFC 7 §9's memory locking —
each recorded with why it is not a commit.

---

## 24. RFC 1 §10's opaque relay, closed — 2026-08-31

The most consequential of the ten unmet requirements §23 tallied, and the one
whose cost is invisible until it is too late to pay.

> "A relay encountering `ver` it does not know MUST route, filter, and expire
> from the 16-byte routing header alone, and MUST store and forward the
> remaining bytes opaquely. This is safe because the identifier covers the
> whole object; an unparsed object cannot be tampered with undetected."
>
> "Without opaque relay of unknown versions, the first protocol revision
> partitions the network along version lines and the partition is permanent,
> because the nodes that would bridge it are the ones offline for a month."

`Store::ingest` refused `version != 1`, and there was no other path into the
corpus.

### The argument that was answered in advance

The deviation was deliberate and its reasoning sat in a comment: an object this
node cannot fully validate must not enter the store, because the identifier
covers bytes it did not understand — a malleability surface. §10 answers that
in its own sentence: the identifier covers the *whole* object, so an unparsed
one cannot be tampered with undetected. **I5 is what makes opacity safe**, and
I5 applies to every version.

### Which of §11's checks survive, and why

§11 scopes the exclusions itself; nothing here was invented.

| check | applies to an unreadable version? | why |
|---|---|---|
| I1 length | yes | `size_bucket` is in the frozen header |
| I1 zero padding | **no** | needs the body length, which needs I4 |
| I2 expiry | yes | `expiry_min` is frozen |
| I3 class | **no** | §11 says "class known **for this ver**" |
| I3 reserved flags | yes | frozen; `RoutingHeader::parse` already refuses them |
| I4 body | **no** | §11 says "no unknown keys **for a known ver**" |
| I5 identifier | yes | covers every byte — §10's whole safety argument |
| I6 duplicate/tombstone | yes | identifier-based |

**What is given up is real.** For a version this node cannot read, the padding
rule cannot be enforced, so RFC 1 §8.1's covert channel is open in objects it
relays and cannot open. §10 makes that trade by scoping I4, and the alternative
it rejects is a permanent partition. Stated here rather than discovered later.

### Nothing decodes what it cannot read

`RoutingHeader::parse` stays version-blind — routing, filtering and expiry are
exactly what §10 says must work without knowing the version.
`parse_readable` is its counterpart and guards everything that reads *past* the
sixteen frozen bytes: both inbox scans, `channels::from_object`, and
`bulletin::from_object`. The corpus is no longer all v1, and a decoder that
assumed otherwise would hand a future format's bytes to a v1 parser.

### Where §10 and RFC 6 §3.4 collide

An unreadable object in the **public** class cannot be identified as a channel
post or as infrastructure, so the carriage decision cannot be made by decoding.
§10 says carry it; RFC 6 §3.4 says "a node MUST be able to carry its operator's
mail and no channels at all".

**The operator's decision wins.** RFC 6 §3.6 makes carriage a statement about
legal exposure in their jurisdiction, and hosting future public content
*because it could not be identified* is exactly the false claim about that
exposure `will_carry` exists to prevent. The class byte is frozen, so this much
is decidable without a decoder.

The cost, stated: a carriage-off node also declines a v2 prekey batch or roster,
which §10 would have it relay. A partial deviation, on one class, for nodes
that have opted out of that class — the narrower of the two failures available.

### The vectors say so

`Documentation/vectors/rfc-1.txt` gains a `## forward compatibility (§10)`
section. `reject.bad_version Unrecognised` is gone, because it was recording
the defect as conformance — another implementation reading that file would have
copied the partition. Four vectors replace it: an unknown version is `carried`,
and `IdMismatch`, `Expired` and `BadPadding` still bite.

### What remains

Three of the ten: RFC 2/7's inbox decapsulation cap, RFC 3 §3's HJSON
rendering, and RFC 7 §9's memory locking. Seven of the ten have now been closed
by the passes that found them.

---

## 25. The inbox decapsulation cap, closed — 2026-08-31

Stated three times — RFC 2 §7.2, RFC 2 §7.4, RFC 7 §13.3 — and unmet in a way
none of the earlier passes saw, because a constant with the right name existed.

### The cap was on the wrong path

`MAX_ATTEMPTS_PER_SCAN` bounds `Inbox::scan_with`: the **pairwise** path. Its
own doc comment cited RFC 2 §9 and argued that per-scan was stricter than per
peer per epoch, which is true and was answering the wrong question.

Every statement of the requirement is about the other path. RFC 7 §13.3:

> "**Inbox-mode objects have no sender to index by** and therefore require
> exhaustive search. Implementations MUST cap inbox-tagged decapsulation
> attempts per peer per epoch. This is the DoS surface RFC 1 §6.4 identifies,
> and it is narrower than that section implies — it applies to inbox mode
> specifically."

The pairwise path is cheap by construction: §13.1 makes the deterministic index
mandatory, so a matched tag names its sender and the candidate set is small.
`scan_requests` is the expensive one — and it had **no cap, no cache, and no
budget of any kind**. A full HPKE decapsulation per object bearing this node's
inbox tag, for as many as a peer cared to send, on a path any stranger can
reach because computing an inbox tag needs only the target's public key.

RFC 1 §6.4's other requirement was missing there too: "implementations MUST
cache failed `(id, epoch)` pairs so a replayed object costs one lookup". The
cache existed, in the same struct, and this path did not consult it.

### Why per epoch and not per peer

Every statement says "per peer per epoch", and an inbox-tagged object **has no
peer** — that is the premise of the sentence imposing it. The object arrived
over some link, but RFC 3 §12 forbids remembering which:

> "Implementations MUST NOT retain per-object provenance: arrival timestamps
> and per-object attribution are a forensic reconstruction of the graph and its
> timing gradients, sitting on disk, waiting for seizure."

So the two cannot both be satisfied literally, and the choice is which. A
per-peer cap needs the provenance §12 refuses; a per-epoch cap needs nothing.
**Per epoch is strictly stronger against the attack** — it bounds total work
rather than one attacker's share, and an adversary holding several peerings
gains nothing by spreading the flood. What it gives up is attribution, which
§12 has already given up on purpose.

That is a fourth tension between frozen documents. Unlike #10, #11 and #12 it
is resolvable without an editor, because one reading is strictly safer than the
other — recorded rather than numbered.

### The budget refills on the epoch, not the scan

`refresh` is per scan and a scan runs on every tick, so reusing it would have
been a cap that bounds nothing. `charge_inbox` takes the epoch and resets when
it turns. Exhaustion is silent: RFC 0 §6 makes delivery failure silent, and a
peer told it had exhausted the budget would know it had found the cap.

**256 attempts per epoch, derived from what §13 measured.** Exhaustive search
across a 512-key batch at 200 tag-matched objects costs 30.7 s. This is the
exhaustive path, so 256 is on the order of a minute of CPU per epoch in the
worst case §13 prices — beyond any honest first-contact volume, and a flood
buys a minute a day rather than a core.

### What remains

Two of the ten: RFC 3 §3's HJSON rendering and RFC 7 §9's memory locking.
Eight have been closed by the passes that found them.

---

## 26. RFC 3 §3's HJSON rendering, closed — 2026-08-31

> "Implementations MUST render any credential as HJSON on request
> (`krab peer show`), and **that rendering is what an operator inspects**."

There was no `peer show`. The verb the RFC names by name did not exist, so §3's
sentence was false in both halves.

### What an operator was inspecting instead

The `peers` panel's prose: quota percentages, standing, novelty, the credential
term. All of it accurate, and all of it a **description** of the credential
written by this program rather than the document itself.

The difference is invisible until it matters, and then it is the whole thing.
RFC 3 §3 makes the credential "simultaneously the contract governing what
[peering] means", and §6.1 makes a quota dispute "a checkable statement against
a signed artifact rather than a unilateral judgement". A counterparty who
altered a term is caught by reading the document. A summary of what the program
believes the document says catches nothing, because the program believes the
altered term.

### Written, not depended on

HJSON is JSON with comments, unquoted keys and optional commas. This *emits* it
and never parses it, so there was nothing to depend on: a serialiser for a
format whose grammar is "JSON, relaxed" is a formatting function, and adding a
crate to produce text would have been the larger risk in a tree that names
every dependency in `Cargo.toml` with a paragraph.

**The comments are most of why §3 asks for HJSON rather than JSON.** §3's table
gives each key a meaning; a rendering an operator inspects should carry that
meaning rather than assume the RFC is open beside the terminal. So each field
is annotated with what it is for — the quota as "a ceiling this side is held
to", retention as "a floor this side promises, and breach is detectable", the
share flags with §8.3's "opt in to being listed, never out".

### Omitting nothing is the requirement

A field the rendering does not show is a field nobody checks, including the
ones a malicious counterparty would most want unexamined. Every key in §3's
table appears, and so does the **absence** of a signature:

```
  sig_b: null   # NOT SIGNED — this is a proposal, not a contract
```

§3: "a singly-signed document lets one party assert a relationship the other
never agreed to… Mutual signature makes the link a contract rather than a
claim." A renderer that omitted an empty field would have hidden exactly that.

Expiry is rendered against the clock it is read at, because "is this still
valid" is the question an operator opens the document with.

### Where the tests are

The rendering's completeness is asserted in `credential::tests`, on constructed
credentials covering signed, half-signed and lapsed. The verb's plumbing —
that it exists, that it reads from disk rather than from memory, and that a
peering with no credential says which of the two reasons applies — is asserted
in `main`. Splitting them puts the completeness assertion next to the thing
whose completeness is at stake, where a new field added to `Credential` is
one file away from the test that would fail.

### What remains

One of the ten: RFC 7 §9's memory locking, which is a dependency decision and
an unsafe-boundary decision rather than a commit. Nine have been closed by the
passes that found them.

---

## 27. The three conflicts, edited — 2026-08-31

`Documentation/RFC-ERRATA.md` is the register. The RFCs are frozen and no
frozen text was altered: the series already had the instrument for this — RFC 2
§9 withdraws requirements from RFC 6 and RFC 7 by name, RFC 7 §13 is titled
"Errata to RFC 1" — and this applies it to conflicts nobody noticed at the time.

Three rules decide a resolution, and each entry says which one applied:
correctness over gradient; scope before precedence; the narrower deviation.

### E-1 — `EPOCH_WINDOW` vs W (#10): RFC 1 §6.2 governs, ±30 is withdrawn

The two documents were measuring different things and neither said so. RFC 2
§5 sized W against **observed delivery latency** — its table is percentiles of
how long mail takes — and concluded ±30 covers the p99. RFC 1 §6.2 sizes it
against the TTL the protocol **declares valid**, because an object may
legitimately arrive `MAX_TTL` after its tag's epoch.

A recipient with the narrower window never computes that tag. The object is
accepted, stored, and undecryptable for ever, and RFC 0 §6 guarantees nobody is
told. A p99 argument cannot reach that: the p100 is what the expiry field
permits, and the failure is total past the window rather than proportional.

RFC 2's exposure-window concern is not dismissed — §5 is right that "every
retained epoch is a decryptable epoch" and right that the two cannot be tuned
independently. **The knob is `MAX_TTL`**, which moves both. Narrowing W alone
buys the same reduction by silently discarding mail, which is not a trade an
operator can consent to because they are never told about it.

### E-2 — the channel shard space (#11): no conflict, and two audits were wrong

RFC 2 §6 shards **destination tags** — `peering::Policy::shard_bits`,
negotiated in the credential. RFC 6 §3.4 asks for a separate space over
**channel identifiers**, and it exists: `krab_crypto::CarriagePolicy` carries
its own `shard_bits` and `shard` and decides with `accepts(&post.channel_id())`.

Two configurations, two disjoint namespaces, neither constraining the other —
RFC 0 I-2's namespace separation doing exactly what it is for.

**§12 of this plan recorded §3.4 as unmet, and §22 repeated it.** Both had
found `filter::Filter` and not `CarriagePolicy`, and concluded "there is one
space". There are two. That is a claim of absence asserted over a set that was
not the whole set — the third time in this series, and twice by passes looking
for that error specifically.

### E-3 — reserved header bits (#12): both, in their own scope

I3 is scoped "class known **for this ver**"; §10 is the forward-compatibility
section and its subject is a version the receiver does not know. Read with
those scopes they do not overlap:

- emission: always zero, both agree;
- receipt, version known: reject — §11's covert-channel argument, since the
  identifier covers the flags;
- receipt, version unknown: carry — a future version may define those bits, and
  refusing would refuse the first object that used one.

"Ignored" means *assign no meaning*, not *do not reject*. The check moved out
of `RoutingHeader::parse`, which is version-blind by design, into
`Store::ingest`, where the version is known. The conformance vector
`reject.reserved_flag_set` becomes `Unrecognised` rather than `Malformed`: it
is I3's refusal, not a header that failed to parse.

This was a live defect and not only a paper one. After §24 made the store carry
unknown versions, `parse` was still refusing reserved bits regardless of
version — so a v2 object using bit 2 would have been refused, which is the
partition §24 had just fixed, reintroduced through a different door.

### E-4 — the inbox cap against provenance

Recorded as an entry rather than a fourth conflict, because one reading is
strictly safer: a per-epoch cap bounds total work rather than one attacker's
share and needs no provenance, so RFC 3 §12 is untouched. Already implemented
in §25; the register now says why the "per peer" dimension was dropped.

### What this leaves

Nothing on the conflict list, and nothing unmet from the requirement pass. What
remains is scope this project has deliberately not built — Tor's onion service,
amateur-band profiles, `short` framing, cover traffic, SF11/SF12 LoRa profiles
— each recorded as vacuous or unrepresentable in §§17–23 rather than as met.
