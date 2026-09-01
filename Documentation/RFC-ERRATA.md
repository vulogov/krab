# RFC errata — the register

The RFCs in this series are frozen. Where two of them contradict each other, or
where one is wrong, the text is **not edited**: an errata entry records the
conflict, states the resolution, and says which document's sentence no longer
governs.

That is the mechanism the series already uses. RFC 2 §9 withdraws requirements
from RFC 6 §2.8 and RFC 7 §5.3 by name; RFC 7 §13 is titled "Errata to RFC 1"
and raises a SHOULD to a MUST. This document is the same instrument applied to
conflicts nobody noticed at the time, and it exists so that an implementer
reading two frozen documents that disagree has somewhere to find out which one
to follow.

**An entry here is normative for this implementation.** It is not an amendment
to the RFC, which stays as written; it is a statement of which reading the code
follows and why, so that a second implementation can follow the same one and
interoperate.

## How a resolution is chosen

Three rules, in order, and each entry says which one decided it.

1. **Correctness over gradient.** Where one reading produces a hard failure —
   mail that cannot be decrypted, a network that partitions — and the other
   produces a graded cost, the hard failure wins. RFC 0 §6 makes delivery
   failure silent by design, so a correctness failure here is also an
   undiagnosable one.
2. **Scope before precedence.** Two sentences that appear to contradict often
   govern different cases. Check for a scope that reconciles them before
   choosing between them; a resolution that keeps both texts true is better
   than one that overrules either.
3. **The narrower deviation.** Where neither of the above settles it, prefer
   the resolution that deviates from fewer requirements, for fewer nodes, in
   the direction an operator has already chosen.

---

## E-1 — `EPOCH_WINDOW` against W *(conflict #10)*

**RFC 1 §6.2:**

> `EPOCH_WINDOW` **MUST** be at least `MAX_TTL / EPOCH`, and is therefore ±45.
> A deployment MAY widen it. It **MUST NOT** narrow it below `MAX_TTL / EPOCH`.

**RFC 2 §5:**

> W **MUST** default to ±30 epochs.
> W **MUST NOT** be below ±14 — that fails to cover the measured p99.

±30 is below ±45. A deployment following RFC 2's default violates RFC 1's
floor, and there is no value satisfying both.

### Resolution: RFC 1 §6.2 governs. W is ±45, and RFC 2 §5's ±30 default is withdrawn.

Decided by rule 1.

The two documents are measuring different things and neither says so. RFC 2
sized W against **observed delivery latency** — its table is percentiles of how
long mail actually takes — and concluded that ±30 covers the p99. RFC 1 sizes
it against the TTL the protocol **declares valid**: an object may legitimately
arrive up to `MAX_TTL` after the epoch its tag derives from, because that is
what the expiry field permits.

A recipient whose W is narrower than `MAX_TTL / EPOCH` never computed the tag
for such an object. RFC 1 §11 accepts it, the store keeps it, and it is
undecryptable for ever — and nothing surfaces that, because RFC 0 §6 makes
delivery failure silent. A p99 argument does not help: the p100 is what the
expiry field allows, and the failure is total for every object past the window
rather than proportional.

**RFC 2's concern is real and is not dismissed.** §5 is right that "the window
is also the exposure window… every retained epoch is a decryptable epoch", and
right that "the two cannot be tuned independently". The correct knob is
therefore `MAX_TTL`, which moves both together: a deployment wanting a shorter
exposure window shortens the TTL, and W follows. Narrowing W alone buys the
same exposure reduction by silently discarding mail, which is not a trade an
operator can consent to because they are never told.

**What implementations must do.** `W = EPOCH_WINDOW = MAX_TTL / EPOCH`. It is
not independently configurable. RFC 2 §5's "±30" and its accompanying table
remain useful as a description of delivery latency and are no longer a
requirement on W.

**In the code:** `krab_core::tag::EPOCH_WINDOW = 45`, and `MAX_TTL_MIN` is
derived from it rather than the reverse, so the two cannot drift.

---

## E-2 — the channel shard space *(conflict #11)*

**RFC 6 §3.4:**

> Channels **MUST** occupy a separate shard space from sealed traffic.

**RFC 2 §6** defines sharding for destination tags, with one `shard_k`.

### Resolution: there is no conflict. The requirement is met, and two audits said otherwise.

Decided by rule 2 — the scope reconciles them, and checking the code was what
found it.

RFC 2 §6's shard space is over **destination tags**, and it is what
`peering::Policy::shard_bits` negotiates for sealed mail. RFC 6 §3.4's is over
**channel identifiers**, and it is `krab_crypto::CarriagePolicy`, which carries
its own `shard_bits` and `shard` and decides acceptance with
`accepts(&post.channel_id())`.

They are two independent configurations over two disjoint namespaces — which is
RFC 0 I-2's namespace separation, doing exactly what it exists for. A node's
mail shard and its channel shard are set separately and neither constrains the
other.

**This entry corrects two earlier findings.** `PLAN.md` §12 recorded §3.4 as
unmet — "`shard_bits` exists on the filter and is negotiated between peers, but
nothing assigns channels a different shard from sealed mail: there is one
space" — and §22 repeated it. Both were reading `filter::Filter` and had not
found `CarriagePolicy`. There are two spaces; the second was missed.

The lesson is the pass's own: a claim of absence asserted over a set that was
not the whole set. It has now been made three times in this series, twice by
audits looking for exactly that error.

---

## E-3 — reserved header bits *(conflict #12)*

**RFC 1 §10:**

> Reserved header bits MUST be zero on emission and MUST be **ignored** on
> receipt.

**RFC 1 §11**, whose preamble says "a receiver MUST **reject** an object unless
all of the following hold":

> I3  class known for this ver; **reserved flag bits zero**

For the same field, one section says ignore and the other says refuse.

### Resolution: both, in their own scope. Reject for a known version; carry for an unknown one.

Decided by rule 2.

I3 is explicitly scoped — "class known **for this ver**" — and §10 is the
forward-compatibility section, whose subject is a version the receiver does not
know. Read with those scopes the two sentences do not overlap:

- **Emission:** always zero. Both sections agree and nothing weakens it.
- **Receipt, version known:** reject. §11's covert-channel argument applies —
  the identifier covers the flags, so a relay carries whatever was put there
  believing it ordinary, which is exactly what §11 says about padding.
- **Receipt, version unknown:** carry. A future version may define those bits,
  and refusing would refuse the first object that used one — "the first
  protocol revision partitions the network along version lines and the
  partition is permanent" (§10).

"Ignored" therefore means *assign no meaning to them*, not *do not reject the
object*. For a known version there is no meaning to assign and a non-zero bit
is inadmissible; for an unknown one the meaning is simply not this build's to
know.

**In the code:** the check moved out of `RoutingHeader::parse`, which is
version-blind by design, into `Store::ingest`, where the version is already
known and every other version-scoped check lives. The conformance vector
`reject.reserved_flag_set` changes from `Malformed` to `Unrecognised`
accordingly — it is I3's refusal, not a header that failed to parse.

---

## E-4 — the inbox decapsulation cap *(not numbered as a conflict)*

**RFC 2 §7.2, RFC 2 §7.4 and RFC 7 §13.3** each require:

> Implementations MUST cap inbox-tagged decapsulation attempts **per peer per
> epoch**.

**RFC 3 §12:**

> Implementations **MUST NOT** retain per-object provenance: arrival timestamps
> and per-object attribution are a forensic reconstruction of the graph and its
> timing gradients, sitting on disk, waiting for seizure.

An inbox-tagged object has no sender — that is the premise of the sentence
imposing the cap — and attributing it to the *link* it arrived over is the
provenance §12 forbids.

### Resolution: cap per epoch. The "per peer" dimension is withdrawn.

Decided by rule 1, and unusually the safer reading is also the simpler one.

A per-epoch cap bounds the **total** exhaustive-search work rather than one
attacker's share, so an adversary holding several peerings gains nothing by
spreading the flood — which a per-peer cap would have let them do. It needs no
provenance at all, so §12 is untouched.

What is given up is attribution: this node cannot say *which* peer's traffic
exhausted the budget, and therefore cannot feed that specific signal into RFC 3
§6.2's standing adjustment. §12 has already given up attribution on purpose,
and the tag-match/decrypt-failure ratio it does keep is an aggregate that still
surfaces a flood.

**In the code:** `receive::MAX_INBOX_ATTEMPTS_PER_EPOCH`, charged in
`scan_requests` and refilled when the epoch turns.

---

## E-5 — the restricted-discovery client key *(an underspecification, not a conflict)*

**RFC 4 §5.2:**

> Only clients holding an authorised key can decrypt the service descriptor,
> so the sync endpoint is not merely unlisted but unenumerable and
> unconfirmable by anyone who is not already a peer. **The authorised-client
> set derives directly from the node's signed credentials.**

"Derives directly from" is not a construction. Tor's `ClientAuthV3` needs a
specific x25519 keypair per authorised client: the service publishes the public
half, the client holds the private half. §5.2 says where the set comes from and
never says how the keys are computed, so it is not implementable interoperably
as written.

This entry is not a contradiction between two documents. It is recorded here
because the consequence of two implementations choosing differently is the same
as a contradiction and is worse to diagnose: **peers simply cannot reach each
other, and nothing says why.** A client whose derived key is not in the
service's list cannot decrypt the descriptor, so the service is invisible to
it — which is indistinguishable from the node being offline, and RFC 0 §6
already makes delivery failure silent.

### Resolution: derive from the static-static agreement, under a distinct domain string.

```
S  = X25519(my_credential_key, their_credential_key)      (RFC 1 §6.2's S)
sk = clamp(BLAKE3-derive-key("krab/onion-client-auth/v1", S))
pk = X25519(sk, basepoint)
```

The service passes `pk` for every verified peering as `ClientAuthV3=`; the
client hands `sk` to its own tor. X25519 agreement is symmetric, so both ends
compute the same pair and neither has to send the other anything — which is
what makes the set "derive directly from the credentials" in the strongest
sense available: it is a pure function of who has peered with whom.

**Why not the credential's own key.** The shortcut is to hand tor the peer's
existing Noise static: it is already x25519 and already in the credential. §5.2
forbids exactly this one paragraph earlier — "reusing an Ed25519 key across the
Krab protocol and the hidden-service protocol is textbook cross-protocol
exposure" — and that argument does not depend on which key or which direction.

**Why reusing `S` is not the same mistake.** `S` is secret input to a KDF under
a distinct domain string, which is the construction §5.2 explicitly permits for
the service key itself. Nothing about RFC 1 §6.2's tag derivation is
recoverable from this output, or the reverse.

**What is given up.** The service knows the client's private half. This is
worth stating and is not worth closing: the key exists so the service can
decide who may decrypt its descriptor, and a service abusing it can only
impersonate a client to itself. Between different peers the values are
unrelated, because each derives from a different `S` — checked by
`different_peerings_give_unrelated_keys`.

**A card that does not verify contributes nothing**, and the count of skipped
peers is reported to the operator. Admitting an unverifiable credential would
widen the set §5.2 exists to narrow; dropping it silently would leave an
operator wondering why one peer can never reach them.

**In the code:** `krab_crypto::onion::client_auth`, and
`App::onion_client_set` which walks the peer directory. The domain string is
`krab_crypto::onion::DOMAIN_CLIENT_AUTH`, covered by RFC 3 §3's
domain-separation test.

---

## E-6 — §5.1's ±6 h tolerance against the frozen header

**RFC 2 §5.1:**

> Implementations **MUST NOT** emit objects when the median-of-peers time
> estimate diverges from the local clock by more than the skew tolerance
> (±6 h, RFC 1 §2).

> The corpus is itself a clock: objects carry creation timestamps from many
> independent senders, and a running median over recently received objects
> from multiple peers is a serviceable sanity check requiring no
> infrastructure.

**RFC 1 §4.1**, headed *"Routing header (frozen forever)"*, defines sixteen
bytes: `ver`, `class`, `size_bucket`, `flags`, `expiry_min`, `tag`. There is no
creation timestamp. **RFC 0 I-3:** "nothing else may be added."

The second paragraph describes a field the first forbids. The requirement is
therefore not implementable at the stated resolution by any conforming
implementation — not because it is hard, but because the data it names does not
exist on the wire.

### Resolution: implement the check at one-epoch resolution and say so.

Decided by rule 3, the narrower deviation: the requirement's *purpose* is met
in full, and only its threshold is coarsened, in the direction that still
catches every case §5.1 argues about.

**What a receiver can actually read.** For a `sealed` object the §4.2 envelope
carries `epoch` in the clear — key 0, the tag epoch the sender derived from its
own clock at emission. That is a genuine "creation timestamp from an
independent sender", and it is the only one. Its granularity is one day
(`EPOCH_SECS = 86 400`).

**Why a finer field must not be added.** This is the part worth stating
plainly, because the obvious repair is to amend RFC 1 and put a creation
minute in the header. A precise emission time in the clear, on every object,
handed to every relay, is a traffic-analysis gift. RFC 3 §12 already forbids
*retaining* per-object arrival times as "a forensic reconstruction of the graph
and its timing gradients"; putting the sender's own clock on the wire supplies
the same gradients to everyone, permanently, and cannot be withdrawn once
objects exist. The coarse check is not merely the achievable answer — it is the
correct one.

**The threshold.** Emission stops when the local epoch differs from the
median-of-peers epoch by **two or more epochs**. Not one: a one-epoch
difference is what a few minutes of skew looks like across a midnight boundary,
so treating it as divergence would stop a correctly-set node for part of every
day. Two guarantees more than a full day of real divergence.

**What is given up, stated rather than buried.** A clock wrong by between 6 h
and roughly 24 h is not detected. That window is also the least damaging: §5.1's
argument is that a bad clock "poisons other nodes' stores with wrong expiry",
and an expiry 45 days out shifted by half a day poisons nothing — while a clock
wrong by weeks writes tags no peer computes, which this check catches easily.

**One sample per exchange, not per object.** A running median over received
objects measures the age of the backlog rather than the network's clock:
reconciliation moves history, so a node returning after a month sees a month of
it and would conclude its own clock was a fortnight fast — refusing to emit at
exactly the moment it had most to say. The maximum epoch *within* an exchange
is a lower bound on that peer's clock; the median *across* exchanges is the
robustness §5.1 asks for, since one peer lying about the time contributes one
sample.

This also keeps RFC 3 §12 intact. "Multiple peers" is satisfied structurally —
one sample per exchange — and no record says which peer any sample came from,
so there is no arrival time and no attribution anywhere.

**In the code:** `krab_node::clock::PeerClock`, fed from
`ExchangeView`'s `Drop` so no driver can forget to report, and read by
`App::emit`, which is the single path every locally emitted object takes.
`MAX_SKEW_EPOCHS = 2`. The operator sees the estimate with `clock`.

---

## Status

| entry | conflict | resolved by | implemented |
|---|---|---|---|
| E-1 | #10 `EPOCH_WINDOW` vs W | rule 1 | yes — `EPOCH_WINDOW = 45` |
| E-2 | #11 channel shard space | rule 2 | no conflict; requirement was already met |
| E-3 | #12 reserved header bits | rule 2 | yes — check moved to `ingest` |
| E-4 | inbox cap vs provenance | rule 1 | yes — per epoch |
| E-5 | §5.2's client-auth key is unspecified | — underspecification | yes — `onion::client_auth` |
| E-6 | §5.1's ±6 h vs the frozen header | rule 3 | yes — one-epoch resolution, `clock::PeerClock` |

No frozen text was altered. Each affected section carries a pointer to its
entry in the source that implements it, the way RFC 7's own `⚠ CRITICAL DEFECT`
header points at `CRYPTO-REVIEW.md` §1.
