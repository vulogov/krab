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
