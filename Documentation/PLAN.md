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
| §9 — **per link, whether it provides LOCATION privacy** | **met** — `peers` renders `loc ● / ○` from `LinkProfile::location_privacy`. §13 recorded this fixed on 2026-08-27 and this table was never updated (swept 2026-09-01) |
| §9 — **per link, whether it provides VOLUME privacy** | **met** — `vol ● / ○` from `LinkProfile::volume_privacy`, same history (swept 2026-09-01) |

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
| 5.3 | cover objects MUST be indistinguishable from `sealed` | **met** | `krab_node::cover`, emitted on its own Poisson schedule from `App::tick_cover` (§29) |
| 5.3 | cover MUST use class 0, not class 2 | **met + tested** | `Cover::emit` writes class 0; two tests fail if it ever writes 2 (§29) |
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
| 8.2 | cover MUST match the bucket distribution of real traffic | **met + tested** | sampled from what `ExchangeView::put` accepts; a node that has observed nothing emits nothing (§29) |
| 9.2 | MUST show a fingerprint alongside any display name | met + tested | `alias::Aliases::show` renders both, always |
| 9.3 | truncated identifiers MUST NOT appear in a routing header, a `WANT` outside a session, or any stored structure | met | the header has no such field; `by_trunc` is derived and unpersisted |
| 10 | a relay MUST route, filter and expire an unknown `ver` from the header alone, and MUST store and forward it opaquely | **met + tested** | closed in §24; `RoutingHeader::parse` is version-blind and `ingest` carries what it cannot read (swept 2026-09-01) |
| 10 | reserved header bits MUST be zero on emission | met | `RoutingHeader::write` |
| 10 | and MUST be ignored on receipt | **met — errata E-3** | reject for a known version, carry for an unknown one; the check moved from `parse` to `ingest` (§27, swept 2026-09-01) |
| 11 | a receiver MUST reject unless I1–I6 hold | met + tested | `Store::ingest`; vectors name each |
| 11 | every check MUST be applied before an object enters the store | met | I1 and I4 closed 2026-08-29 |
| 11 | I5 MUST run before anything consulting the identifier | met | first check in `ingest` |
| 11 | rejection MUST be silent to the peer | met | nothing is written back |
| 11 | and MUST be counted per peer as a quota signal | **was unmet, now met** | `Spend::rejected` |
| 12 | RFC 1 MUST NOT reach Final without machine-checkable vectors | **met + tested** | `Documentation/vectors/rfc-1.txt`, all eight categories asserted present; §11's six checks exercised by identifier (§33) |
| 12 | two independent implementations MUST agree on every vector | **obligation** | a gate on RFC 1 reaching Final, not on a node. RFC 1 is `Status: Draft`, so nothing is in violation — an implementation cannot break this, only an editor promoting the document can (§33) |

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

> **Counts superseded by §30 (2026-09-01).** The verdicts in the table above
> were corrected by that sweep; the paragraph below is the tally as it stood on
> the date of this section and is kept as the record of it.

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
| 5 | W MUST default to ±30 | **withdrawn — errata E-1** | RFC 1 §6.2's floor governs; `EPOCH_WINDOW = 45` and W is not independently configurable (§27, swept 2026-09-01) |
| 5 | W MUST NOT be below ±14 | met | 45 |
| 5.1 | MUST accept objects whose epoch falls within W of local time | met + tested | `TagTable::build` covers `pairwise_window` |
| 5.1 | MUST NOT emit when median-of-peers time diverges by more than ±6 h | **was unmet, now met — errata E-6** | `clock::PeerClock` fed one sample per exchange; `App::emit` is the only path a local object takes. One-epoch resolution, because the frozen header carries no creation time (§31) |
| 7.1 | the envelope MUST NOT indicate which recipient key was used | met | §4.2's five keys carry no index |
| 7.2 | inbox-tagged objects MUST be rate-capped per peer per epoch | **met — errata E-4** | capped per epoch by `MAX_INBOX_ATTEMPTS_PER_EPOCH`; the *per peer* dimension is withdrawn, because attributing an inbox-tagged object to a link is the provenance RFC 3 §12 forbids (§25, swept 2026-09-01) |
| 7.4 | MUST cache failed `(id, epoch)` pairs | met + tested | `receive::Attempts` |
| 7.4 | MUST cap inbox-tagged decapsulation per peer per epoch | **met — errata E-4** | same requirement as §7.2, stated twice; same resolution (swept 2026-09-01) |
| 7.4 | MUST attempt all live batches in constant time | met + tested | `Inbox::scan_with` |
| 7.4 | and MUST NOT stop at first success | met + tested | same |
| 9 | MUST warn about in-flight loss on rotation | **was unmet, now met + tested** | `rotate`, warned at the confirmation and again at the prompt — before the passphrase is asked for (§32). *The § was wrong here too: this is RFC 2 §9, not §8* |
| 9 | the precomputation table MUST be treated as key material: never paged, never logged, never persisted | **was partly met, now met** | `App::tag_table` is a `krab_lock::Held<TagTable>`; the header is in locked pages and the map's buckets are not, which is stated rather than claimed away (§32). *RFC 2 §9, not §8* |

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

> **Counts superseded by §30 (2026-09-01).** The verdicts in the table above
> were corrected by that sweep; the paragraph below is the tally as it stood on
> the date of this section and is kept as the record of it.

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
| 3 | MUST render any credential as HJSON on request | **met + tested** | closed in §26; `peer show` renders the credential itself as HJSON (swept 2026-09-01) |
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

> **Counts superseded by §30 (2026-09-01).** The verdicts in the table above
> were corrected by that sweep; the paragraph below is the tally as it stood on
> the date of this section and is kept as the record of it.

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
| 5.2 | the onion key MUST NOT derive from the identity key | **met** | `krab_crypto::onion` — derived from a dedicated root, never the identity (§28) |
| 5.2 | clients MUST show bootstrap progress | **met** | polled on the tick, rendered on the status line (§28) |
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
| 7 | classes 0, 2, 3 MUST NOT be carried on amateur bands | vacuous | no amateur-band profile exists — **postponed for want of hardware**, §28 |
| 7 | amateur and ISM MUST NOT be conflated in configuration | vacuous | as above — **postponed**, §28 |
| 8 | a `short` message MUST NOT be forwarded | met + tested | `validate_body` refuses class 3; the live path carries frames out of the exchange and into no store (§29) |
| 8 | MUST NOT be stored beyond display | met + tested | `drain_shorts` writes to the output pane only — asserted against the inbox, the corpus and the activity log (§29) |
| 8 | MUST NOT enter reconciliation | met + tested | a frame has no identifier, so RBSR and the manifest have nothing to carry (§29) |
| 8 | the 64-bit MAC caveat MUST be restated in security documentation | **met** | `SECURE-DELETE.md`, final section (§28) |
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

### Counts — recounted 2026-09-01, and the old ones were wrong twice

**28 rows in the table above. 25 met** (17 with a test that names them),
**2 vacuous** — the two amateur-band requirements, postponed for want of
hardware — **1 unrepresentable**, and **0 unmet**.

The numbers this paragraph carried until now said "26 requirements, 19 met,
6 vacuous", and both halves were wrong:

- **The total never matched the table.** 19 + 6 + 1 = 26, and there are 28
  rows, and there always were. The paragraph was written from the tally rather
  than from the table, so the two could not disagree visibly.
- **§28 flipped five rows from vacuous to met and did not come back here.**
  Onion key derivation, bootstrap progress and the 64-bit MAC caveat all
  became met in that pass; the paragraph still described them as "none of them
  built". A summary that is edited only when it is written is a summary that
  is wrong from its second day.

This is the third time in this document that a claim of absence turned out to
be a claim about a set nobody re-read (E-2 records the other two). The lesson
is the same and it is not "be careful": it is that a count kept beside a table
must be derived from the table or it will drift, and nothing here derives it.

Running total across RFCs 1–4: **97 requirements, 15 unmet or partly unmet,
3 conflicts** — the total rises by two because this recount fixed the
arithmetic, not because anything was added. Four of the fifteen were fixed by
the pass that found them.

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
| 5 | deployments MUST NOT rely on LoRa as a majority transport | **obligation** | on a deployment, not on the code; the SHOULD-warn at 30 % of links is still unimplemented (§33) |
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

> **Counts superseded by §30 (2026-09-01).** The verdicts in the table above
> were corrected by that sweep; the paragraph below is the tally as it stood on
> the date of this section and is kept as the record of it.

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
| 3.4 | channels MUST occupy a separate shard space from sealed traffic | **was never unmet — errata E-2** | one shard space; RFC 2 §6 defines one |
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

> **Counts superseded by §30 (2026-09-01).** The verdicts in the table above
> were corrected by that sweep; the paragraph below is the tally as it stood on
> the date of this section and is kept as the record of it.

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
| 9 | **`mlock` key buffers; MUST fail loudly at startup if locking is unavailable** | **met** | `krab_lock::Held` locks and reports; `VirtualLock` on Windows (§28, swept 2026-09-01) |
| 9 | `Debug` on key types MUST print nothing | met + tested | every key type prints `<redacted>` |
| 9.1 | the "Rust cannot guarantee a secret was never copied" limit MUST appear in the security considerations of any release | **was unmet, now met** | `SECURE-DELETE.md` |
| 10 | neither panic wipe nor dead-man timer MUST be enabled by default | met + tested | the chord is a chord; the timer is armed only by `deadman <days>` (§28, swept 2026-09-01) |
| 10 | both MUST be discoverable | **was unmet, now met + tested** | the chord is in `help`; `deadman` was **not**, from §28 until this sweep — `every_verb_is_in_help` is the guard (§30) |
| 10 | the dead-man timer MUST warn well before it fires | **met** | last quarter of the window, proportional to the period (§28) |
| 11 | the identity key MUST be backed up offline at creation | met + tested | `init` shows the words once, as a step |
| 11 | MUST state plainly that message history is not recoverable | met + tested | said at `init` and in `help` |
| 12 | MUST surface prekey burn rate, not merely remaining count | met | `status` |
| 13.1 | senders MUST use the deterministic index when the tag mode is pairwise | met + tested | `compose` |
| 13.2 | recipients MUST attempt all live batches in constant time | met + tested | `Inbox::scan_with` |
| 13.2 | and MUST NOT stop at first success | met + tested | same |
| 13.3 | MUST cap inbox-tagged decapsulation attempts per peer per epoch | **met — errata E-4** | the same requirement as RFC 2 §7.2 and §7.4, and the same resolution (§25, swept 2026-09-01) |

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

### Counts — as of 2026-08-31, superseded by §30

29 requirements in the table above. **25 met**, **1 withdrawn**, **1 partly
met**, and **2 unmet** — §9's memory locking and §13.3's inbox decapsulation
cap, the latter being the third statement of a requirement RFC 2 makes twice.

Both were closed afterwards — §28 built the memory locking and §25 closed the
cap — and neither closure came back to this paragraph until the sweep in §30.
The rows above now say so; this paragraph is left as written, dated, because
the pattern it is an instance of is the finding.

### The series, whole — **recounted 2026-09-01, see §30**

The table below is the count as it stood on 2026-08-31. It is wrong in three
independent ways and is kept because §30 needs something to be a correction
*of*: the per-document totals do not match the tables they summarise, the
"unmet" column counts requirements that had already been closed in this very
document, and the grand total is the sum of the wrong column.

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

**167 requirements, against the "~150 MUSTs" this plan quoted for weeks.** The
figure was close by accident: it counted lines, and lines are neither
requirements nor occurrences. The true figure is 171 — see §30.

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

Nothing on the conflict list, and nothing unmet from the requirement pass.

*(That paragraph named Tor's onion service, `short` framing and cover traffic
as not built. All three are built now — see §28. Amateur-band profiles and the
SF11/SF12 LoRa profiles remain unbuilt, and §28 records why they are now
**postponed** rather than merely absent.)*

---

## 28. Windows, Tor, and three unbuilt requirements — 2026-08-31

A single pass, recorded together because several of its parts corrected
earlier entries in this document.

### What was built

| area | state before | state now |
|---|---|---|
| `VirtualLock` (RFC 7 §9) | `#[cfg(unix)]` only; Windows ran unlocked | both platforms, one `lock_pages`/`unlock_pages` boundary |
| `RLIMIT_CORE`/`PR_SET_DUMPABLE`/`PT_DENY_ATTACH` (RFC 7 §9) | **not implemented** | `krab_lock::harden`, first statement of `main` |
| SOCKS5 client (RFC 4 §5.2) | a six-line doc comment, not in `mod.rs`, never compiled | implemented |
| `tor` supervision (RFC 4 §5.2) | none | `backend::tor` — args only, zero-byte torrc, ephemeral control port |
| onion key (RFC 4 §5.2) | vacuous (§21) | `krab_crypto::onion` — permanent, derived, never stored |
| restricted discovery (RFC 4 §5.2) | vacuous (§21) | `ClientAuthV3` from verified peerings — errata **E-5** |
| dead-man timer (RFC 7 §10) | not built | `deadman` verb, fires before the passphrase prompt |
| `short` framing (RFC 4 §8) | not built | `krab_crypto::short` |
| cover traffic (RFC 1 §5.3, §8.2) | not built | `krab_node::cover` |
| CI | **none at all** | `.github/workflows/ci.yml`, five jobs |

### Three corrections to things this document or the code asserted

**`panic = "abort"` is not a core-dump control.** `Cargo.toml`,
`SECURE-DELETE.md` and `ADVERSARIAL-PASS.md` all said it was what stopped a
core dump carrying key material. It is the opposite: abort raises `SIGABRT`,
whose default disposition is to write a core file, while unwinding writes none.
RFC 7 §9 lists three measures and this build had shipped only the one that
makes a dump *more* likely, while describing it as doing the other two's job.
All three now exist. `panic = "abort"` stays for its real reason — a panic must
not unwind through a partially-zeroized structure.

**The tree already compiles C.** An earlier assessment in this document
compared arti's seven `-sys` crates against "zero C dependencies here". That
was measured by counting `-sys` suffixes and missed build scripts that shell
out to a compiler: `blake3`'s `build.rs` invokes `cc`, and
`target/debug/build/blake3-*/out/libblake3_neon.a` exists on any developer's
machine. The arti conclusion is unchanged — seven `-sys` crates is a different
order of magnitude — but the reproducible-builds argument is weaker than it was
stated to be. It is also why `x86_64-pc-windows-msvc` cannot be cross-built
from macOS: blake3 asks `cc` for `/arch:AVX512`. windows-gnu cross-checks fine
and a native MSVC build works.

**`socks` was a name, not a stub.** `LinkProfile::location_privacy` has always
matched `"socks"` and `"tor"`, and `profile_named` had no arm for either, so
the branch was unreachable rather than false. `LinkProfile::tor()` is what
makes that sentence true rather than dead.

### Amateur bands and SF11/SF12 LoRa — POSTPONED, not merely absent

RFC 4 §7's two requirements and the SF11/SF12 profiles are **postponed for want
of hardware**, at the operator's direction. This is a stronger statement than
the "vacuous" they were previously recorded as, and the distinction matters:

- *Vacuous* said the requirement had nothing to constrain, which invited a
  future reader to satisfy it by writing a profile table.
- *Postponed* says the opposite: **a profile written without a radio to test it
  against would be worse than none.** RFC 4 §7 governs what may legally be
  carried on an amateur band, and §11 notes that a LoRa transmission is
  direction-findable — a physical-layer property no protocol can undo. Both are
  claims about the physical world, and neither can be verified by a test suite.

So the rows in §20 stay `vacuous` as a statement about the code, and this
paragraph is the statement about the project: they are not to be implemented
until someone can put a packet on a real radio and measure it.

### What is built but not yet wired

> **Superseded by §29, 2026-09-01.** All four were wired, and the list is left
> as written because it is the record of what was true on 2026-08-31 — and
> because writing it is the reason they took one pass to close rather than an
> audit to rediscover.

Stated here rather than left for an audit to find:

- **`krab_node::cover` has no production caller.** The generator, the
  distribution matching and the emitter's own record are implemented and
  tested; nothing on the node's send path calls `emit` yet. Wiring it needs a
  Poisson schedule and a decision about which links may afford it — RFC 0 §7.3
  says cover is "unaffordable on a constrained link", so it must not simply be
  switched on for every profile.
- **`krab_crypto::short` has no production caller.** The framing, the AEAD and
  the truncated-MAC verification are implemented and tested; nothing composes
  or displays a `short` message yet.
- **No `Fabric` implementation over Tor.** `tor::dial` works and is tested, but
  nothing in the link table constructs a session through it, so
  `connect <peer> tor <addr>` has no path.
- **Onion rotation is not a verb.** `onion::service_key` takes a rotatable
  counter as RFC 4 §5.2 requires; the caller passes 0 and nothing advances it.

### What is verified, and how

- **1254 tests**, clippy clean under CI's `-D warnings` across `--all-features`.
- The Tor launch path is verified **against a real `tor` 0.4.9.11**: launched,
  cookie-authenticated over the control port, ephemeral SOCKS port read back,
  bootstrap queried, killed, cookie shredded. The test skips when tor is absent
  and is deliberately not `#[ignore]`d.
- `RLIMIT_CORE` was verified by **read-back, not return code** — a child
  inherits rlimits, so `ulimit -Hc` in a child shows `unlimited → 0`. That
  mattered: the soft limit was already 0 on the development machine, so the
  return code alone could not distinguish "applied" from "no-op".
- **`VirtualLock` has still never executed.** It cross-compiles and
  clippy-cleans for both Windows targets and nothing more. The Windows CI job
  added in this pass is what closes it, and it has not run yet.

### Not added: a `cargo fmt` gate

The CI has none, deliberately. `cargo fmt --all --check` reports 126 diffs
across 28 files, 25 of which predate this pass. A gate would go red on its
first run for reasons unrelated to any change being tested, and a red check
people learn to ignore trains them past the Windows job too. Turning it on is
two commits: `cargo fmt --all` touching nothing else, then the gate.

---

## 29. The four gaps §28 left open, closed — 2026-09-01

§28 ended with a section titled "What is built but not yet wired", listing four
things that existed, were tested, and nothing called. All four are now called.
That section was the right thing to write and it is worth saying why: a
requirement satisfied by a module nobody invokes is the failure mode this
document has recorded three times under other names, and naming it in advance
is the only reason it took one pass to close rather than an audit to rediscover.

### What was wired

| gap, as §28 stated it | closed by |
|---|---|
| `krab_node::cover` has no production caller | `App::tick_cover` on its own Poisson draw; `ExchangeView::put` feeds the distribution |
| `krab_crypto::short` has no production caller | `Control::Short` (opcode 12), the `short` verb, `App::drain_shorts` |
| no `Fabric` implementation over Tor | `backend::tor::TorFabric`; `connect <peer> tor <addr>` reaches it |
| onion rotation is not a verb | `onion rotate`, with both counters sealed beside the root |

And one requirement §28 did not list, added at the operator's direction:

| RFC 3 §9.2 | contact/sync endpoint separation | two onion services, two domain strings, two listeners |

### The defect the Tor gap was hiding

`connect <peer> tor <addr>` did not merely fail. With no `"tor"` arm in
`App::establish`, it fell through to the TCP branch, and
`TcpStream::connect("….onion:9001")` hands the name to the **system resolver**.
So the dial failed *and* told the operator's DNS server — and anyone watching
it — which hidden service this node was looking for. That is the precise thing
RFC 4 §5.2's restricted discovery exists to prevent, undone one layer below it
by a missing match arm.

It is worth recording how nearly it escaped: a test asserting "connecting over
tor without tor returns an error" passes on the broken version. The test that
catches it asserts the **SOCKS request carries `ATYP_DOMAIN` with the literal
onion name**, which is a statement about where the name went rather than about
whether the call succeeded. It was probed by reverting `TorFabric::connect` to
a direct `TcpStream::connect` and confirming it fails.

`TorFabric::accept` always returns `None`, and that is architecture rather than
omission: inbound over an onion arrives at the listener tor forwards to, so a
fabric that also accepted would be a second listener racing the first for the
same connections.

### `short`, and the counter that must survive a restart

RFC 4 §8's nonce is `(link_id, ctr)`. A counter that restarted at zero under a
key that had not changed would repeat a nonce, and a repeated nonce under
ChaCha20-Poly1305 leaks the XOR of two plaintexts **and the Poly1305 key**.
So:

- `PeerFile::ShortCtr` holds an epoch and a counter — two integers, unsealed.
  Deliberately unsealed: it says nothing about content, and requiring the KEK
  to read it would mean a **locked node could not refuse to reuse a nonce**.
- It is written **before** the frame is sent. A crash between the two costs one
  unused counter value; the other order costs a repeat.
- An unreadable counter reads as **exhausted**, never as zero. Zero is the one
  answer certain to repeat if the file was ever written.
- The epoch is stored alongside so the counter can safely restart when the
  reservoir chunk rotates, which is what keeps `MAX_CTR` out of reach in
  practice.

The message key is `domain_hash("krab/short-key/v1", chunk)` rather than the
chunk itself, which is already the HPKE PSK for sealed mail — one secret under
two constructions is an argument nobody would enjoy having to make. `link_id`
sorts the two node identifiers before hashing, with a test, because the failure
mode is that both ends compute a *valid* key, the keys differ, and every
message fails to open exactly as if the peer were offline (RFC 0 §6).

Refusing to send without a live link is the honest answer rather than a
limitation: RFC 1 §5.5 makes `short` link-local by construction, so "queue it
until they are reachable" is not a smaller version of this feature — it is
`send`, which already exists.

**Opcode 12 is an extension, and the enum already had four.** RFC 5 §3's table
lists 0–7; 8 and 9 are RFC 7 §7's re-key, 10 and 11 are RFC 3 §11's first
contact over a live link. `Control` is `#[non_exhaustive]` and its doc comment
said "the eight opcodes" while carrying twelve. Both are corrected.

The cost is stated rather than hidden: a CBOR array head, an opcode and a
byte-string head, four bytes, on top of §8's 18 + N. §8's 55-byte ceiling is
the *message*, not the frame it travels in.

### Cover traffic, and a bug only the end-to-end test could find

The observer feeds from `ExchangeView::put`, on objects that were **accepted** —
so a peer flooding rubbish this node refuses cannot steer the distribution its
cover copies. It skips objects `Cover::is_mine` recognises, which is what RFC 1
§5.3's "emitters track their own cover objects locally" is *for*: a dummy this
node emitted can come back from a peer, and observing it would feed the emitter
its own output.

The emitter draws from `scheduler::poisson_next`, which `Scheduler::draw` now
also calls. One exponential, two callers — a second one written out separately
would present as "the schedule looks a bit regular", which nobody notices.

**Off by default.** RFC 0 §7.3: volume privacy "requires cover traffic, and
cover traffic is unaffordable on a constrained link". A node emitting dummies
unasked spends an operator's duty cycle, metered link or battery to buy a
property they may not need. `cover on <60–86400s>` / `cover off`, and bare
`cover` reports the state and the observation count.

**The bug.** The first version passed the *body* slice to `validate_body`,
which parses the routing header itself and therefore returned `Malformed` for
every object. The distribution would have stayed empty for ever — and §8.2's
corollary is that a node with no distribution emits nothing, so **a broken
observer and a correctly quiet one are indistinguishable**. Nothing but an
end-to-end test could have told them apart, and nothing but an end-to-end test
did. The comment at the call site now says which argument the function takes
and what it costs to get it wrong.

### Rotation, and endpoint separation

RFC 4 §5.2 asks for "a rotatable epoch counter". A counter that is not stored
is not rotatable: the address reverts to counter 0 at the next start, which is
a rotation nobody asked for and nobody is told about. Both counters are now
sealed beside the root, and a 32-byte record — the old format, root alone —
still opens as counters `(0, 0)`, because refusing it would take an existing
node's permanent address away on upgrade.

`onion rotate` writes the counter **before** publishing, adds the new service
before withdrawing the old one so there is no window in which neither answers,
and says plainly that every peer holding the old address will find this node
unreachable and will not be told why. It also names the previous counter, so a
rotation done by mistake can be undone: the derivation is a pure function of
root and counter.

**RFC 3 §9.2's two endpoints are two services**, and they differ in three ways
at once, each load-bearing:

- **different key**, under `DOMAIN_CONTACT` rather than `DOMAIN`, so no counter
  value can make one equal the other. Separating them by counter alone would
  mean the contact address at counter *n* is byte-identical to the sync address
  at counter *n* — so rotating contact onto a counter sync had used would
  publish the sync address, unrestricted, to a stranger. It would happen
  silently and at exactly the moment an operator did what §9.2 calls "freely
  rotatable". There is a test that walks both endpoints across eight counters
  and asserts sixteen distinct keys.
- **different discovery**: the sync endpoint carries the `ClientAuthV3` set,
  the contact endpoint carries none, because a stranger has no peering from
  which to derive an auth key. Restricted discovery there would make the
  endpoint unreachable by exactly the people it exists for.
- **different listener**: the contact endpoint is mapped to the socket
  `peer meet` opens and nothing else, so what is behind it genuinely accepts
  only peer-requests — §9.2's phrase, satisfied by what the port reaches rather
  than by a rule.

The contact endpoint is opened by `peer meet` when tor is running, rotated on
every open, and withdrawn by `DEL_ONION` on every path out of a meeting —
completion, timeout, and `peer meet cancel`. Two strangers given the same
contact address could each confirm the other had been talking to this node,
which is graph information handed out for nothing.

### What is verified, and how

- **1282 tests**, zero failures, clippy clean under `-D warnings` across
  `--all-features`. Up from 1254 at §28.
- The DNS-leak test is bounded rather than blocking. A dial that never reaches
  the fake proxy would otherwise hang the test binary instead of failing it —
  the lesson the SOCKS helper learned in §28, applied before it cost anything.
- `Moved` lost `Copy` deliberately: `shorts` owns its frames, and a `short`
  must be moved and displayed rather than silently duplicated by an assignment.

### Still open

- **`ADD_ONION` for the contact endpoint has never run against a real tor.**
  The sync endpoint's has (§28's live test). The contact path is exercised only
  where tor is absent, which checks that it degrades rather than that it works.
- **`VirtualLock` has still never executed**, unchanged from §28. The Windows
  CI job is what closes it.
- **`del_onion` is untested against a live daemon** for the same reason.
- **No `cargo fmt` gate**, unchanged from §28 and for the same reason.

---

## 30. The audit tables, swept against the code — 2026-09-01

§29 corrected §20's counts and named the mechanism: *"a count kept beside a
table must be derived from the table or it will drift, and nothing here derives
it."* This section applies that to every table in the document, and to the
tables themselves rather than only their summaries — because it turned out the
rows had drifted too, and in the direction that matters least and reads worst:
**the audit understated what is built.**

### Nine rows that said unmet and were not

Every one of these was closed by a later section of this same document, or by
an errata entry, and none of the closures came back to the row it closed.

| table | row | said | closed by |
|---|---|---|---|
| §9 RFC 8 | §9 LOCATION privacy per link | unmet, "nothing renders it" | §13, 2026-08-27 |
| §9 RFC 8 | §9 VOLUME privacy per link | unmet, "nothing renders it" | §13, same day |
| §17 RFC 1 | §10 opaque relay of an unknown `ver` | **UNMET** | §24 |
| §17 RFC 1 | §10 reserved bits ignored on receipt | conflict #12 | errata **E-3**, §27 |
| §18 RFC 2 | §5 W defaults to ±30 | conflict #10 | errata **E-1**, §27 — withdrawn |
| §18 RFC 2 | §7.2 inbox cap per peer per epoch | unmet | errata **E-4**, §25 |
| §18 RFC 2 | §7.4 the same, stated twice | unmet | same |
| §19 RFC 3 | §3 HJSON rendering of a credential | unmet | §26 |
| §22 RFC 6 | §3.4 separate channel shard space | unmet, conflict #11 | errata **E-2** — never unmet |
| §23 RFC 7 | §9 `mlock` key buffers | unmet | §28 |
| §23 RFC 7 | §13.3 inbox cap, third statement | unmet | errata **E-4**, §25 |

Each was verified against the code before the row was changed, not against the
section that claimed to have closed it — `MAX_INBOX_ATTEMPTS_PER_EPOCH` in
`receive.rs`, `krab_lock::Held`, `CarriagePolicy::accepts`, `parse_readable`
and `Reject::Unrecognised`, `LinkProfile::location_privacy` — because a
document that can be stale about the code can be stale about itself.

**Two of the eleven are not "we built it and forgot".** E-1 and E-2 changed
what the requirement *is*: §5's ±30 default was withdrawn in favour of RFC 1
§6.2's floor, and §3.4 was met all along by a second shard space the audit had
not found. A row saying "unmet" for a withdrawn requirement is worse than a
stale row — it invites someone to implement something the series decided
against.

### One row that said met and was not

**RFC 7 §10: "both MUST be discoverable."** The row said *partly met — the
chord is in `help`; there is no timer to discover.* §28 built the timer. The
row was then wrong twice over, because §28 also **did not add `deadman` to
`Command::SYNOPSES`**, so `help` had never heard of it. A dead-man timer an
operator cannot find is not a dead-man timer, and it is the requirement §10
states in as many words.

`start-tor` and `stop-tor` were missing the same way, from the same pass. Three
verbs added in one commit, none of them advertised.

Fixed, with the guard that stops it recurring: **`every_verb_is_in_help`**
walks `Command::ALL`, takes each verb's canonical `Display` spelling, and fails
if `SYNOPSES` does not list it. Probed by removing `deadman` again, which fails
with `these verbs work and help does not mention them: ["deadman"]`.

Synonyms — `msg`, `pic`, `chan`, `exit` — are deliberately exempt. A synonym
that is not advertised is a convenience; a verb that is not advertised does not
exist.

### The series, recounted from the tables

Derived by walking the rows, not by adding up prose:

| document | rows | met | vacuous | unrepresentable | partly met | withdrawn | obligation | **unmet** |
|---|---|---|---|---|---|---|---|---|
| RFC 1 | 35 | 32 | 2 | — | — | — | 1 | **0** |
| RFC 2 | 16 | 14 | 1 | — | — | 1 | — | **0** |
| RFC 3 | 22 | 22 | — | — | — | — | — | 0 |
| RFC 4 | 28 | 25 | 2 | 1 | — | — | — | 0 |
| RFC 5 | 17 | 16 | — | — | — | — | 1 | 0 |
| RFC 6 | 24 | 23 | — | — | — | 1 | — | 0 |
| RFC 7 | 29 | 28 | — | — | — | 1 | — | 0 |
| **total** | **171** | **160** | **5** | **1** | — | **3** | **2** | **0** |

**`obligation`** is a requirement on somebody other than the code: RFC 1 §12's
two-implementation clause gates the *document* reaching Final, and RFC 5 §5's
"deployments MUST NOT rely on LoRa as a majority transport" gates a
*deployment*. Neither can be satisfied by a commit and neither is unmet, so
counting them as either would be wrong in a different direction. They stay
visible as their own column — see §33.

**171, not 167.** The old figure was the sum of per-document totals that had
each been written from a tally rather than counted from a table; four of the
seven were wrong, in both directions. Nothing was added to the series — the
frozen documents have not changed since 2026-08-31 — this is arithmetic being
done properly for the first time.

### What is actually unmet, now that the noise is gone

Three rows when this sweep ran. §31 closed one, §32 closed another, and §33
reclassified the third — it was never an implementation requirement. **Zero
unmet**, which is a smaller claim than it sounds: see §33 on why "obligation"
is its own column and not a way of reaching that number.

- ~~**RFC 2 §5.1 — median-of-peers time.**~~ **Closed the same day, in §31.**
  It was unmet when this sweep ran: nothing computed the estimate. The table
  above counts it as met, and the count is checked, so the two cannot drift
  apart again.
- ~~**RFC 2 §8 — the in-flight-loss warning on correspondence-key rotation.**~~
  **Closed in §32**, which also found the § was wrong: it is RFC 2 §9.
- ~~**RFC 1 §12 — two independent implementations MUST agree on every
  conformance vector.**~~ **Reclassified in §33 as an `obligation`**, which is
  not the same as closed: both of §12's clauses gate RFC 1 *reaching Final*,
  and RFC 1 is `Status: Draft`, so no implementation is in violation and none
  can be. Still open, still recorded, so that "we have vectors" is never
  mistaken for "the vectors have been checked against someone else's code".

~~And one partly met: **RFC 2 §8's precomputation table as key material**.~~
**Closed in §32.** The table is now a `krab_lock::Held<TagTable>`.

The five vacuous and one unrepresentable rows are the amateur-band and
SF11/SF12 requirements (**postponed for want of hardware**, §28), plus
compression, inner-plaintext keys and address keys — all of them requirements
about features this version does not have.

### The counts are now derived

Every per-section "Counts" paragraph above is marked superseded rather than
rewritten, because rewriting them would recreate exactly the thing that broke:
a number kept next to a table by hand. **The table in this section is the only
count in this document that is checked**, and it is checked by
`krab-node/tests/plan_counts.rs`, which reads `PLAN.md` as data the way
`domain_separation.rs` reads the source tree.

Two tests, failing for two different reasons:

- `the_recount_matches_the_audit_tables` walks §17–§23, buckets each verdict
  cell, and compares the tallies with this section's row for that document. It
  catches a table edited without its summary **and** a summary edited without
  its table — probed in both directions.
- `the_total_is_the_sum_of_the_documents` adds this section's own columns and
  compares them with its total row, and checks that the buckets partition the
  rows. The old "167" was this kind of error and nothing would have caught it.

**What it deliberately does not check is whether a verdict is true.** That is a
question about the code, and no parser can answer it — `MAX_INBOX_ATTEMPTS_PER_EPOCH`
existing does not prove it caps the right thing. The eleven stale rows this
section corrects were found by reading the code, and the next eleven will have
to be too. What the test removes is the *other* failure, the one that has now
happened three times: the arithmetic quietly ceasing to describe the table it
sits under.

A cell whose verdict this test cannot classify is a failure rather than a
default, so inventing a new verdict wording fails loudly instead of being
silently counted as met.

---

## 31. RFC 2 §5.1's clock check, and a requirement that could not be met as written — 2026-09-01

§30 left three unmet rows and said only two were code. This closes the first of
those two, and closing it turned out to require an errata entry: **§5.1 names a
mechanism RFC 1 §4.1 forbids.**

### The requirement is not implementable at its stated resolution

> The corpus is itself a clock: objects carry creation timestamps from many
> independent senders…

They do not. RFC 1 §4.1's routing header is titled *"frozen forever"* and
carries `ver`, `class`, `size_bucket`, `flags`, `expiry_min` and `tag`. There is
no creation time, and RFC 0 I-3 says "nothing else may be added". §5.1's ±6 h
tolerance rests on a field the frozen document does not define.

**The obvious repair is the wrong one.** Amending RFC 1 to carry a creation
minute would put a precise emission time in the clear, on every object, in front
of every relay. RFC 3 §12 already forbids *retaining* per-object arrival times
as "a forensic reconstruction of the graph and its timing gradients"; writing
the sender's own clock onto the wire hands the same gradients to everybody,
permanently, and cannot be withdrawn once objects exist. The coarse check is not
the achievable answer, it is the correct one — recorded as **errata E-6**.

What a receiver can actually read is the `epoch` in the §4.2 envelope: key 0, in
the clear, derived from the sender's clock at emission, one day wide. So the
check detects divergence of **more than one day**, and the threshold is two
epochs rather than one — a one-epoch difference is what a few minutes of skew
looks like across midnight, and treating that as divergence would stop a
correctly-set node for part of every day.

What is given up is the 6–24 h window, which is also the least damaging: an
expiry 45 days out shifted by half a day poisons nothing, while a clock wrong by
weeks writes tags no peer computes and is caught easily.

### One sample per exchange, because the obvious estimator measures the backlog

A running median over received objects does not estimate the network's clock. It
estimates **the age of the corpus being synced**: reconciliation moves history,
so a node returning after a month receives a month of it, whose median epoch is
a fortnight old. It would conclude its own clock was a fortnight fast and refuse
to emit at exactly the moment it had most to say — the failure inverted.

So the sample is the **maximum epoch within one exchange** — a peer with a
correct clock almost always has something recent, and the newest thing it offers
is a lower bound on its clock — and the estimate is the **median across
exchanges**, which is the robustness §5.1 asks for: one peer lying about the
time contributes one sample. There is a test for each half, including a majority
of liars moving it, recorded as the bound rather than assumed away.

This also keeps RFC 3 §12 intact. "From multiple peers" is satisfied by
structure — one sample per exchange — and nothing records *which* peer any
sample came from. No arrival time, no attribution, a bounded ring of integers in
memory.

**The sample is published by `Drop`, not by the caller.** There are two exchange
drivers and four entry points between them, and "remember to report the clock
afterwards" is the shape of rule this codebase has already been caught by twice.
A view is constructed once per exchange and dropped when it ends, including when
it ends by error.

### Thirteen emission sites became one

§5.1's requirement is about *all* emission, so a check at twelve of thirteen
call sites satisfies nothing. The two paths were already cleanly separated and
nobody had noticed: objects arriving from peers are admitted by
`ExchangeView::put` on an exchange thread and never touch `App`, so **`App`'s
thirteen ingest sites were already exactly this node's own emissions**.

They now go through `App::emit`, which asks the clock first. `App::clock_refusal`
is separate so the interface can report the state without emitting something to
find out.

The guard is a source scan — `the_only_ingest_in_this_file_is_the_one_inside_emit`
— because this is the kind of requirement a behavioural test cannot hold: a
fourteenth call site added next year would pass every behavioural test here and
walk straight past the check. Probed by restoring one bypass, which fails.

### Receiving is untouched, and that is §5.1's own argument

> Emitting with a bad clock poisons other nodes' stores with wrong expiry, and
> that damage cannot be undone. Receiving with a bad clock only hurts the node
> itself.

A diverged node keeps reconciling, keeps relaying, keeps taking delivery. It
stops adding to the damage and nothing else, and the test asserts both halves —
including that an object still lands in the corpus while emission is refused.

A node with **no** estimate emits normally: §5.1's requirement is conditional on
having a median-of-peers estimate, and a node that has spoken to nobody has
none. Refusing there would stop a fresh node composing its first message, which
no reading of §5.1 asks for.

### `clock`, a report and never a setting

There is nothing here to configure — the estimate is derived from traffic and
the repair is the system clock, which is not Krab's to change. But an operator
who cannot see the estimate cannot tell a refusal to emit from a node that has
broken, so `clock` shows the local epoch, the peers' median, the drift, the
verdict, and names E-6 for why the resolution is a day.

### What is verified

- **1298 tests**, zero failures, clippy clean under `-D warnings` across
  `--all-features`.
- §30's derived count is updated and `plan_counts.rs` agrees with it — the first
  time a closure in this document has been checked against its own audit table
  rather than assumed into it.

### Still unmet after this

> **Superseded: §32 closed the first two, §33 reclassified the third.** Left as
> the record of what was open on the day.

- **RFC 2 §8** — the in-flight-loss warning on correspondence-key rotation.
  Unmet because there is no correspondence-key rotation verb to warn *from*.
- **RFC 1 §12** — two independent implementations agreeing on the conformance
  vectors. Unmet by design; there is one implementation.

And one partly met, unchanged: **RFC 2 §8's precomputation table as key
material**. `App::tag_table` is a plain `Option<TagTable>` and not a
`krab_lock::Held`, so the recognition table is pageable while the identity is
not.

---

## 32. RFC 2 §9's rotation and its precomputation table — 2026-09-01

Both of §30's remaining code items, and they are the same section of the same
document — which the audit had recorded as **§8** for both. §8 is "Errata,"
about prekey batch sizing. The two requirements are in §9, Security
considerations. A wrong section number is a small error with a specific cost:
anyone checking the row against the RFC reads about prekeys and concludes the
row is nonsense.

### Rotation, and what it is allowed to move

> Rotation is the only remedy. It costs almost nothing locally (12 ms of ECDH
> at 200 correspondents) and a great deal socially: every correspondent must
> learn the new key before they can address you, and messages in flight under
> the old key are lost. Implementations SHOULD make rotation available and
> **MUST warn about in-flight loss**, which on a courier route may be weeks of
> traffic.

**Only the X25519 correspondence key moves.** The Ed25519 identity stays, so
`node_id` stays — RFC 3 §9.2's rollcall, RFC 6's channels and every stored
peer-link are keyed on it, and moving it would not be rotation but becoming a
different node. The Noise static stays for the reason it is a separate key at
all: it is a *transport* identity, and rotating it would break every configured
link address without touching the correlation §9 is about.

**The warning comes before the passphrase is asked for**, and again with the
result. §9's MUST is to *warn*; a warning printed alongside the outcome is a
notification, and the thing it warns about has already happened. `rotate` is
`is_destructive`, so the first typing is refused with a sentence naming the
specific loss — which meant `Command::destroys` had to become per-verb, since
the one hard-coded confirmation line said "destroys the key hierarchy" and that
is `wipe`'s consequence, not this one.

**The passphrase is asked for, and checked against the file.** The KEK is
memory-only (RFC 7 §4), so it has to be re-derived — and that makes the
passphrase a second authorisation for a destructive act, which is why this verb
asks rather than using the open session. Deriving a KEK always *succeeds*, so
the check is that it opens the stored identity: writing under a KEK the file
was not sealed with produces an identity nothing can ever open again.

**The backup words are shown again, once.** RFC 7 §11 makes the backup a
one-time ceremony and `Identity::backup_phrase` says showing it on request
"would turn a one-time ceremony into a settings item". This is not a request:
half of what the written-down words encode has just been replaced, so they no
longer restore this node. Withholding them would leave an operator holding a
backup that silently restores the wrong key — the failure §11 exists to
prevent, reached from the other side. A rotation is its own ceremony.

**A test asserts the consequence, not the mechanism.** The first version
checked that `tag_table` was `None` after rotating. It is not — `refresh_inbox`
rebuilds it immediately and correctly under the new key — so that assertion was
testing the invalidation rather than what invalidation is *for*. It now
computes the tag the peer will actually use, confirms the table recognises it
before, and confirms it does not after. That is what the operator will
experience and what the warning is about.

### The precomputation table, and the clause that was still open

> **The precomputation table is the correlation.** It maps tags to
> correspondents — precisely what the design prevents everyone else from
> doing. It is the single most valuable artifact on a seized running node and
> MUST be treated as key material under RFC 7 §9, never paged, never logged,
> never persisted.

Never persisted and never logged had held since the table was written. **Never
paged had not**, and after §28 built `krab_lock` it was the odd one out: the
identity sat in locked pages while the artifact §9 calls "the single most
valuable" was a plain `Option<TagTable>` on the heap.

It is now `krab_lock::Held<TagTable>`, and the test asserts it agrees with the
identity about being locked — comparing the two rather than asserting `true`,
because on a machine where `mlock` is refused both are unlocked and a test that
demanded success would fail for the platform rather than for the code.

**What that does not achieve, stated rather than claimed away.** `Held` locks
the box, not the map's own allocations: a `HashMap` owns a table allocated
elsewhere, and moving the struct into locked pages does not move that. The
header cannot be paged; the buckets can. Closing that needs a locking
allocator, which is a larger change and is not pretended to be done here. The
note in `receive.rs` used to say "never paged is not implemented" and was
correct when written; it now says what is and is not covered.

### What is verified

- **1302 tests**, zero failures, clippy clean under `-D warnings` across
  `--all-features`.
- §30's derived table is updated and `plan_counts.rs` agrees, which is now the
  routine rather than the exception.

### What remains

One row, and it is not code — **and §33 found it is not a requirement on the
code at all**:

- **RFC 1 §12** — "two independent implementations MUST agree on every
  conformance vector." There is one implementation. The vectors exist and are
  checked against themselves, which is not what §12 asks for and must not be
  mistaken for it. It closes when somebody else writes a Krab, and not before.

Plus the five vacuous and one unrepresentable rows — amateur bands and
SF11/SF12, **postponed for want of hardware** (§28), and three requirements
about features this version does not have.

And the things that are built but not proven, which are not audit rows and are
worth keeping visible: the contact endpoint's `ADD_ONION` and `del_onion` have
never run against a real tor, and `VirtualLock` has still never executed.

---

## 33. RFC 1 §12 is not a requirement on the implementation — 2026-09-01

§32 left one row and called it "not code". Reading §12 again, it is not a
requirement on the implementation at all, and the audit had it in the wrong
category rather than merely unmet.

```
RFC 1 MUST NOT reach Final without machine-checkable vectors covering, at
minimum: … Two independent implementations MUST agree on every vector before
the status changes.
```

**Both clauses gate RFC 1's status transition.** Neither says anything a node
does. `Documentation/RFC-1.md:5` reads `Status: Draft`, so nothing is in
violation and nothing can be: an implementation cannot break §12, only an
editor promoting the document to Final without the agreement can.

That is a reclassification and not a closure, which is why it goes in its own
column rather than into "met". The series already had one row of this shape —
RFC 5 §5's "deployments MUST NOT rely on LoRa as a majority transport", which
gates a *deployment* — and it had been counted as met, which is the same error
in the generous direction. Both are now **`obligation`**: a requirement on
somebody other than the code, satisfiable by no commit and unmet by no
implementation.

**`plan_counts.rs` refused the first attempt at this**, which is the guard §30
was written for doing its job one section later: the new verdict wording was
unclassifiable, so the test failed loudly instead of quietly bucketing it as
met. The bucket had to be added deliberately, in both the table and the parser.

### What was considered and rejected

**Writing the second implementation.** This does not satisfy §12 and would make
things worse. Two implementations by one author, from one reading, reproduce
that reading's errors in both — and `check.py` already says exactly this about
itself, unprompted, in its own docstring: "it was written by the same author,
from the same reading of §6.2, so a misreading of the specification would be
reproduced here rather than caught." Producing a second encoder and calling it
§12's would convert an honest open item into a false closed one, which is the
worst outcome available.

The only thing that closes §12 is somebody else implementing RFC 1 from the
prose and agreeing. Not something this repository can do to itself.

### What was done instead: making the agreement worth more when it comes

§12's *first* clause — that the vectors cover eight named categories — is a
real requirement and had three gaps.

**1. The rejection vectors did not name §11's identifiers.** §11 gives its six
checks stable identifiers "so an implementation can be audited against this
list line by line" and says a conformance suite SHOULD exercise each by
identifier. All six were covered — and the identifiers existed only in the
generator's Rust comments, so they reached neither the published file nor any
assertion. A second implementer had to reconstruct the mapping, which is
precisely where two readings diverge.

Each case now emits `reject.<name>.check I<n>`, and
`every_check_in_section_eleven_is_exercised_by_identifier` asserts the set is
exactly I1–I6 *and* that each identifier reaches the file. Counting them by eye
is how a gap survives a deletion.

**2. §12 says "each class" and the file had two.** Classes 2 and 3 have no
canonical object encoding — class 2 `cover` is reserved and MUST NOT be emitted
(RFC 1 §5.3: cover uses class 0, because a distinct class byte would make every
dummy separable by reading one byte), and class 3 `short` is not a corpus
object at all (§5.5; its framing is RFC 4 §8's). Both facts are now *in* the
file. A second implementer reading "each class" looks for four, and previously
found two with no explanation.

**3. The seal/open block was `anchor: drift`, and it need not have been.** Its
comment said HPKE "is randomised, so a ciphertext is not a fixed value and
cannot be". The first half is true of the API and false of these vectors, which
were already generated from a seeded generator; the second half confused
*reproducing* a ciphertext with *verifying* one, and only the first is
impossible.

The bytes are now printed — `enc`, `ciphertext`, `info`, `aad`, and the whole
object — alongside the recipient's private key that was already there. A second
implementation cannot reproduce them, because nothing in RFC 1 specifies how
HPKE consumes randomness; it can **open** them, which exercises the KEM, the
key schedule, the AEAD and the AAD construction against a different
implementation of all four. That is the check that matters and it was being
skipped on the strength of a sentence about a different one.

**`check.py` gained the part of that it can do.** ChaCha20-Poly1305 and RFC
9180's schedule are not in the Python standard library, so it cannot open the
ciphertext — but the *structure* is stdlib-checkable, and the AAD especially:
RFC 1 §6.1's AAD "binds expiry, tag, class, epoch, and suite", and an AAD built
from anything else produces an object that decrypts nowhere. 67 checks became
**91**. Probed by flipping one byte of `mode_auth.aad`, which fails with the
computed and file values side by side.

### The count, and what it does and does not mean

**171 rows: 160 met, 5 vacuous, 1 unrepresentable, 3 withdrawn, 2 obligation,
0 unmet.**

Zero unmet is a smaller claim than it looks and is worth deflating deliberately:

- **2 obligations** are open and cannot be closed here.
- **5 vacuous and 1 unrepresentable** are the amateur-band and SF11/SF12
  requirements — **postponed for want of hardware**, §28 — and three
  requirements about features this version does not have.
- **Every "met" is met against this implementation's reading of the prose**,
  which is exactly the thing §12's second clause exists to check and which
  remains unchecked. A conformance suite that agrees with itself is a
  conformance suite that agrees with itself.

And separately from the audit entirely: the contact endpoint's `ADD_ONION` and
`del_onion` have never run against a real tor, and `VirtualLock` has still
never executed.

---

## 34. An external review, and two findings that were wrong — 2026-09-01

A review of ~78k lines against the RFC series. Seven of its findings were real
and are fixed below; the two ranked **High** were not, and saying why matters
more than the fixes, because both are the failure mode this document keeps
recording under other names.

### The two High findings, checked and refuted

**"The per-day ingress quota is never called."** It is called, in
`ExchangeView::put` — `acct.spend.admits(…)` before the object lands and
`acct.spend.charge(…)` after, at `shared.rs:545-561`. `budget_for` never
returns `None` (a comment there records that returning `None` for a
credential-less link *was* the defect, and was fixed), and both exchange
threads apply it with `view.with_budget(b)`. `spend.bytes` and `spend.objects`
are incremented by `charge`; `refused` and `rejected` are incremented beside
it. The peers panel is reporting real numbers.

**"Exchange loops bound message count, not ingress bytes… ≈ 17 GB in one
session."** The bound is not in the loop, it is in `Corpus::put`, which for
this application *is* `ExchangeView::put` and applies the quota above. A peer's
ingress is capped at `LinkTerms::bytes_per_day` — 100 MiB by default, and an
eighth of that for a fresh peering under RFC 3 §6.2's standing dial. Not 17 GB;
12.5 MiB for a new peer.

Both findings read `krab-node/src/exchange.rs`, saw `take(corpus, bytes)` with
no byte accounting, and concluded there was none. The accounting is one layer
down, in the `Corpus` implementation the application supplies. **This is E-2's
error exactly** — "a claim of absence asserted over a set that was not the
whole set" — now made four times in this project, twice by audits looking for
precisely that mistake, and this time by a reader who had not seen E-2.

That is not a criticism of the review. It is the argument for the review: the
same reading that produced two wrong findings produced seven right ones, and a
codebase where the byte bound lives two files from the loop it bounds is a
codebase that will keep generating this report.

### What was real, and fixed

| finding | fix |
|---|---|
| No file mode is ever set | `atomic::write` opens at `0o600`; directories at `0o700` |
| `overflow-checks` unset in release | set, with the trade-off documented |
| Zero-length `MORE` chunks hold a session open | refused; the doc comment claimed they could not |
| Passphrase leaked into an un-zeroized `String` | bound, used, overwritten |
| `Line::overwrite` misses what editing removed | erased at the point of removal |
| Unbounded Argon2 `m_kib` from unauthenticated `params.cbor` | capped at 1 GiB |
| tor cookie survives in `hex()`'s temporary | bound and overwritten |
| `enforce_retention`'s comment contradicted its code | comment corrected — the code was right |

**The `MORE` one is the sharpest.** `StreamSession::recv` bounds *accumulated
bytes* against `MAX_CONTROL`, and its own doc comment said "a peer cannot hold
this end open by sending `MORE` for ever". A chunk with an empty body
accumulates nothing, so the bound never trips and the loop runs indefinitely,
one read-timeout per chunk. The bound was on the wrong quantity and the comment
asserted the property it did not have. `send` marks `MORE` only when another
full chunk follows, so refusing an empty one costs nothing a conforming writer
can produce.

**`overflow-checks` is the one with a cost worth stating.** Without it, `debug`
panicked on overflow and `release` wrapped — so every
`never_panics_on_arbitrary_input` test ran under arithmetic the shipped binary
did not have. With it, and with `panic = "abort"`, an overflow is a terminated
node rather than a silently wrong number. That is the right direction here: the
numbers that would wrap are expiries and sizes, an expiry that wraps is an
object stored for ever, and RFC 0 §6 makes that silent.

**`Line`'s residue is fixed as far as safe Rust reaches, and no further.**
`remove`, `drain` and `truncate` shorten the `Vec` without touching what they
drop, and `overwrite` iterates only live elements — so a corrected passphrase
stayed in the allocation past the length. Each operation now erases before it
shortens. The property cannot be *asserted*: reading past `Vec::len` is what
safety forbids, and this crate forbids `unsafe`. So the test checks the
mechanism and a source scan checks that every shortening call site reaches it.
The first version of that test built a helper that observed nothing and passed
by accident, which is worse than not testing it.

### The one that was neither right nor wrong

**"Two X25519s and two ChaCha20-Poly1305s in the binary… the check fails."**
The duplication is real and is `snow`'s, and `CRYPTO-BOUNDARIES.md` documents
it at length as the accepted cost of RFC 4 §4.1's Noise IK — including the
audit cost, "roughly a day of someone's attention, and it is stated here so
nobody discovers it during an audit and wonders what else was not mentioned".
The check the reviewer ran was the binary's; the documented check is scoped to
`krab-crypto`, and it passes.

But **nothing ran either check**. It was two `cargo tree` invocations in prose,
which is the same shape as a bound documented and never called. That is now
`krab-node/tests/crypto_boundaries.rs`: one version of each primitive inside
`krab-crypto`, at most two inside `krab-fabric`, and `snow` must still be in
the tree — because if it leaves, the documented reason for the second copy is
gone and `CRYPTO-BOUNDARIES.md` needs editing before the test does. Versions
are deliberately not pinned; a test about cryptographic boundaries that fails
on a routine bump teaches people to edit the test.

### Not acted on, and why

- ~~**No fuzz target on `picture::transcode`.**~~ **Done in §35**, and it was
  not a one-line change for a structural reason: the module lived in a binary
  crate, which `cargo fuzz` cannot depend on.
- **The 64-bit spoken fingerprint.** Correct, and spec-level: RFC 3 §11 defines
  it and the implementation is conformant. Changing it is an RFC amendment, not
  a commit.
- ~~**`cargo audit` was not run.**~~ **Done in §36**, which found a yanked
  `chacha20` under the cipher every sealed object uses.

### What is verified

**1308 tests**, zero failures, clippy clean under `-D warnings` across
`--all-features`. The release profile builds with `overflow-checks = true`.

---

## 35. `picture` becomes a crate, and gets the fuzz target — 2026-09-01

§34 recorded "no fuzz target on `picture::transcode`" as correct and not a
one-line change. The reason it was not one line is worth stating, because it is
the finding rather than an obstacle to it: **`picture` was a module of the
interface binary, and `cargo fuzz` cannot depend on a binary crate.**

So the largest attack surface in the system — two third-party image parsers, on
bytes a peer chose, in a module whose own comment calls them "historically the
richest source of remote code execution" — was the one thing in the tree that
could not be fuzzed, and was unfuzzable *by construction* rather than by
anybody deciding not to.

### The move

`crates/krab-picture`. The module needed it: it was already self-contained —
one external symbol, `krab_fabric::profile::LinkProfile` in `carriable` — and
zero coupling to any sibling interface module. A file that could have been a
crate all along, sitting where it could not be reached.

The binary no longer links `png` or `zune-jpeg` at all; they are dependencies
of `krab-picture` and dev-dependencies of `krab-tui`, where tests build
fixtures. A fixture builder is not an attack surface: those bytes come from the
test file, not from a peer.

### What the target asserts, beyond not crashing

A crash is a finding on its own and needs no assertion. What needs asserting is
the property the rest of the system leans on, and it is RFC 8 §6's actual
requirement rather than a proxy for it:

> The client MUST NOT validate an image. It MUST decode and re-encode it, and
> **MUST transmit the re-encoded bytes.**

So the output is fed back through the module's own header reader and checked:
it is a PNG this implementation produced, within `MAX_OBJECT` and `MAX_PIXELS`,
no larger than the input declared — and **it does not contain the input**. A
`transcode` that passed attacker bytes through would satisfy every "did not
crash" test ever written and defeat the requirement completely. A polyglot that
survived re-encoding shows up in that assertion and nowhere else.

`dimensions` is called on every input too, including the ones `transcode`
refuses: it runs before the pixel cap, so a panic there is reachable by anyone
who can send a picture, decodable or not.

### The seeds, and why they are checked in

| run | corpus | executions | coverage | result |
|---|---|---|---|---|
| unseeded | empty | 6 243 897 | 972 blocks | clean |
| unseeded, continued | discovered | 5 840 921 | 972 blocks | clean |
| **seeded** | 7 real images | 325 679 | **3 373 blocks** | clean |

**Twelve million unseeded executions reached less than a third of what three
hundred thousand seeded ones did.** Unseeded, almost every input dies on a
magic-byte comparison before a decoder is entered — so the first two runs were
fast because they were rejecting, and the third is fifty times slower because
it is actually decoding, downscaling and re-encoding.

`fuzz/corpus/` is gitignored, so without checked-in seeds every fresh checkout
would repeat the first row and report millions of clean executions against two
parsers it never entered. `fuzz/seeds/picture/` is seven files and 28 KB.

That is also a correction to how this project has been reading its own fuzz
results: the table in `fuzz/README.md` counts executions, and executions are
not coverage. The `control` crash found in under sixteen thousand runs is the
same lesson from the other direction.

### What is verified

**1308 tests**, zero failures, clippy clean under `-D warnings` across
`--all-features`; `krab-picture`'s own 21 tests moved with it and pass. The
fuzz target ran clean at 3 373 covered blocks.

### Still not done

~~`cargo audit` is still not installed here~~ — **§36**. And a clean fuzz run is
evidence, not proof: 325 679 executions is a few minutes, and the targets that
found something in this project found it early. §36 puts all five targets on a
nightly schedule with a carried-forward corpus.

---

## 36. `cargo audit` in CI, and a yanked cipher — 2026-09-01

§34 recorded `cargo audit` as not run and not installed, and put it in CI
"beside the Windows job". Installing it first was the right order: **it found
something on its first run**, and a CI job added without running is the thing
§35 was about.

### What the first run found

Zero vulnerabilities, four warnings, and one of them mattered:

| crate | class | via | acted on |
|---|---|---|---|
| `paste 1.0.15` | unmaintained | `ratatui` | no — proc-macro, build-time only |
| `lru 0.12.5` | unsound ×2 | `ratatui` | no — see below |
| **`chacha20 0.10.1`** | **yanked** | `chacha20poly1305` → `hpke` → `krab-crypto` | **yes** |

**The yanked one is on the primary crypto path.** Not `snow`'s copy — the
reviewer in §34 flagged two ChaCha20s and the older is the Noise side, so the
natural guess was that the yanked release was the old one. It was not:
`chacha20 0.10.1` is what `chacha20poly1305 0.11.0` pulls in, which is the AEAD
`krab-crypto` uses for **every sealed object**. Yanked means the authors
withdrew it, and a lockfile pins regardless. Pinned forward to 0.10.2 in this
commit; 1 308 tests and the boundary test unchanged.

Nothing else in this tree reads the advisory database, and the crate had been
yanked for some time. That is the argument for the job, made by the job.

`lru`'s two unsoundness advisories are left, and left visibly: both require a
panicking `Drop` inside `ratatui`'s internal cache, which this interface does
not put there. That is a judgement, not a dismissal — it is written down so the
next person can disagree with it rather than rediscover it.

### Vulnerabilities fail; warnings do not

`cargo audit` exits non-zero on a vulnerability and prints warnings without
failing, and the job keeps that split. A vulnerability is a defect in this tree
whoever introduced it. "Unmaintained" is a judgement about a maintainer's
attention, and a build that goes red because somebody stopped answering issues
is **the `cargo fmt` argument again** — a check people learn to click past, and
they click past the Windows job on the way there.

The fuzz crate's lockfile is audited too, and reported rather than enforced: it
ships nothing, so a vulnerability in `libfuzzer-sys` is worth knowing and is not
a vulnerability in Krab.

`cargo audit` is installed with `cargo install --locked`, not a marketplace
action. A third-party action inside the job that checks the supply chain is a
supply-chain step inside the supply-chain check.

### And the fuzz targets, on a schedule — which answers "run it for hours"

**A GitHub-hosted job is capped at six hours and the cap cannot be raised.** So
hours are available and indefinite is not — but the cap turns out not to be the
binding constraint. Thirty minutes a night, five targets, beats one long run,
because **the corpus carries forward**: the job caches `fuzz/corpus/<target>`
between runs, so each night starts where the last stopped.

Without that cache the measurement in §35 repeats every night for ever — 972
covered blocks from an empty corpus against 3 373 from a seeded one — and the
job would report millions of clean executions against ground it re-walks daily.
`fuzz/corpus/` is gitignored, so the cache is the only thing that accumulates.

Not on pushes: a fuzz run short enough to block a merge is a fuzz run too short
to find anything, and it would make every push wait on it.

Two details that are not decoration. `-timeout=25` makes one slow input a
finding rather than a lost run — the `picture` target decodes and re-encodes,
so a decompression bomb is a plausible input rather than a hypothetical one.
And a crash is uploaded as an artifact, because a crashing input nobody kept is
a crash nobody can reproduce.

### One interaction that would have been invisible

`concurrency.group` was `workflow-ref`, and `cancel-in-progress` is true. A
scheduled fuzz run on the default branch shares that group with pushes to it —
so any commit during those thirty minutes would kill the run. It would present
as a fuzz job that never finishes on an active day and always finishes on a
quiet one, which is the kind of thing that gets diagnosed as flakiness. The
event name is now in the group.

### What is verified

**1 308 tests**, zero failures, clippy clean under `-D warnings` across
`--all-features`. `cargo audit` reports zero vulnerabilities and three
warnings, all named above. The workflow parses, and both new command forms —
`cargo audit --file`, and `cargo fuzz run <target> <corpus> <seeds>` — were run
locally before being written into it.

**The jobs themselves have still never run**, like the Windows job before them.
That is the honest state on the day they are added, and it is why the local
runs above are recorded rather than the CI configuration alone.

---

## 37. The first Windows CI run, and what it caught — 2026-09-01

§28 added the workflow for one reason: `krab-lock`'s Windows arm had never
executed. §36 added two more jobs and closed with "the jobs themselves have
still never run, like the Windows job before them." They have now, and the
Windows run failed — which is what a first run on a platform nobody develops on
is for.

### The failure was a Unix-ism in a test fixture, not a defect

`backend::tor::tests::a_relative_binary_path_is_refused` asserted that
`TorLaunch::at("/nonexistent/tor", …)` gives `Binary` — absolute but absent.
On Windows it gives `Path` — relative — and **the code is right**:

> On Windows, a path with a root and no drive letter is *drive-relative*. `/tor`
> and `\tor` resolve against whichever drive the process happens to be on, so
> `Path::is_absolute` is false for them.

That is precisely the ambiguity the argument exists to refuse. `start-tor`
takes an explicit binary path so an operator is not at the mercy of `PATH`, and
a path resolved against an uncontrolled *drive* is the same hazard as one
resolved against an uncontrolled *working directory*. **The check was more
right than the test**, and nothing on a developer's Mac could have shown it.

Fixed by making the fixture per-platform and asserting the drive-relative cases
separately on Windows — rather than by loosening the assertion to accept either
error, which would have hidden the difference instead of naming it.

### And a message that was wrong on the platform it was refusing

The refusal said the path "is relative", which on Windows reads as a bug to the
operator: `\tor` does not look relative, and on unix it would not be. The
message now names the actual reason per platform — on Windows, that the path
must name a drive because otherwise it resolves against the one this process
happens to be on.

A finding about a test that turned into a finding about an error message, which
is the ordinary shape of these: the test failed because the *world* differs
there, and anything the code says about the world differs with it.

### The other Unix-isms in the tree, checked

Sixteen other tests use `/`-rooted literals. They are fine, and for a reason
worth stating rather than assuming: **every one of them only needs "this path
does not exist"**, which holds on Windows whether the path is absolute or
drive-relative. `courier`'s missing archive, `atomic`'s unwritable directory,
`--home`'s default — all still err.

The tor test was the only one where **absoluteness itself carried meaning**,
because it is the only one distinguishing two error variants by it. That is the
predicate to look for, not the leading slash.

### What is still not answered

The output above is `krab-fabric`'s. **The job this workflow was written for is
`krab-lock on Windows`, and its output is what closes `UNSAFE-AUDIT.md`'s open
question** — whether `VirtualLock` has ever executed, and whether it succeeded
or was refused. The crate's tests all tolerate a refusal, because a container
that cannot lock is a real machine, so a green tick does not answer it.
`report_what_this_platform_granted` prints the answer and the job runs with
`--nocapture` for exactly that reason.

Until that print is read, the audit's question is open and the arm is still
only *compiled*.

### What is verified here

**1 308 tests**, zero failures, clippy clean under `-D warnings` across
`--all-features`, and `cargo clippy -p krab-fabric --target
x86_64-pc-windows-gnu --all-targets` clean — which covers the `#[cfg(windows)]`
test block added above, since `--all-targets` includes tests. Compiling is not
running, and this section is careful to say which is which.
