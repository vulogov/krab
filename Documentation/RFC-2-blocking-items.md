# RFC 2 — Blocking Item Status

    Status:      Working document, not an RFC
    Purpose:     the gate on RFC 2 reaching Draft — and whether it should exist
    Grounding:   RFC-1.md, RFC-3-review.md, RFC-6-review.md, RFC-7.md, rfc-2-runs/
    Depends on:  RFC 1

RFC 2 is the odd document in the series. **Its original scope has been
absorbed almost entirely by RFC 1**, and it has since been repopulated by
defects found while reviewing RFC 3, RFC 6 and RFC 7 — none of which has an
addressing home.

So the first question is not what RFC 2 should say. It is whether RFC 2 should
exist, and §1 answers that before §2 says what it would contain.

---

## 1. What is left of the original scope

The series plan gave RFC 2 seven items. RFC 1 froze five of them:

| plan item | where it now lives |
|---|---|
| pairwise tag derivation | **RFC 1 §6.2**, frozen |
| inbox tag derivation | **RFC 1 §6.2**, frozen |
| shard extraction, `shard = tag[0..k]` | **RFC 1 §5.4**, frozen |
| epoch acceptance window | **RFC 1 §6.2**, frozen at ±45 |
| prekey selection without a key ID | **RFC 1 §6.3**, corrected by RFC 7 §13 |
| address grammar canonicalisation | **nowhere** |
| namespace separation as a named invariant | RFC 0 I-2, informally |

RFC 6 has already dropped its RFC 2 dependency and requires RFC 0, 1, 3 and 7
instead — correctly, since everything it needs from tags is in RFC 1.

**RFC 0 §10's roadmap still lists RFC 2 as the document that "freezes the tag
scheme."** RFC 1 froze it. Leaving that in the roadmap invites someone to wait
for a document whose job is done.

On the original scope alone, RFC 2 should be retired and its two residual
items folded into RFC 6 and RFC 0. What changes the answer is §2.

---

## 2. What has accumulated that needs an addressing home

Three findings from the reviews are addressing questions, and each currently
belongs to no document.

### 2.1 The inbox-tag counting leak, and a correction

`RFC-3-review.md` §1 found that RFC 1 §6.2 derives the inbox tag from the
recipient's public key, RFC 3 §5.1 sends peer-requests to that tag as flooded
corpus objects, and RFC 3 §9.1 publishes that key in the rollcall — so anyone
can count a listed node's inbound peering attempts, per epoch, permanently.

**That review proposed a separate rotating contact key as the fix. That
proposal was wrong**, and this document is where the correction belongs.

Rotation only helps against an adversary who does not already hold the key.
Rollcall entries are `bulletin` objects, so they persist for their TTL and
indefinitely on any archival relay — which is precisely the adversary RFC 0
§7.6 says exists and does not evict:

| adversary | what rotation buys |
|---|---|
| archival relay, archiving from the start | **nothing** — it holds every contact key ever published |
| adversary who starts observing late | bounds the retrospective count to ~45 days of still-live bulletins |

The property is **structural, not a defect to be engineered away**. An inbox
tag must be computable by any stranger — that is exactly what makes first
contact possible without infrastructure — and by nobody else, which is what
would stop counting. Those two requirements contradict.

What RFC 2 can actually do:

1. **State the leak as a known unmitigable property**, alongside RFC 0 §7's
   list. Publishing a rollcall entry makes your inbound first-contact volume
   publicly countable, forever, by anyone who archives.
2. **Scope it honestly.** RFC 3 §9 already makes rollcall opt-in and
   default-off, so the leak applies only to nodes that chose public
   discoverability. That is a trade an operator can understand — but RFC 3
   §9.1 currently lists `kx_pk` under "may be published" with no mention of
   this consequence, and it MUST say so.
3. **Offer the one real mitigation:** first contact gated on an introduction
   token (RFC 3 §10), with the inbox tag derived from the token rather than
   from a published key. That closes the leak completely for token-holders and
   is unavailable to strangers — which is the point of a token. It cannot be
   the only path without breaking open first contact, so it is a per-node
   policy, not a protocol default.

Rotation is still worth doing for the late-arriving adversary, but it MUST NOT
be described as fixing the leak.

### 2.2 Per-class shard masks

`RFC-6-review.md` §1 found that RFC 6 §3.4's requirement — "channels MUST
occupy a separate shard space from sealed traffic" — does not follow from
RFC 1. Shard derives from the tag, and a bulletin's tag is BLAKE3-derived over
the same uniformly-distributed space sealed tags occupy. There is no separate
space, and RFC 1 is frozen.

The intent needs a filter of the form `(class, shard_prefix)` rather than one
shard prefix applied to everything. RFC 6 §3.4's own channel-interest
bucketing — carry a `k`-bit prefix so a peer learns only 1/2^k of what you
follow — cannot work without it, because a node's mail shard mask and its
channel shard mask must differ.

This is filter semantics, which RFC 5 owns. But RFC 5 does not exist, and the
question is *what a shard means* rather than how a filter is negotiated.
Either RFC 2 specifies per-class shard masking and RFC 5 negotiates it, or
RFC 6 §3.4's sentence is dropped.

### 2.3 Inbox decapsulation caps are required but unsized

RFC 7 §13.3 requires: "Implementations MUST cap inbox-tagged decapsulation
attempts per peer per epoch." It does not say what the cap is, and neither
does RFC 1 §6.4.

The plan assigned decapsulation caps to RFC 2, and it is the right home —
the cap is a property of inbox addressing, not of key custody. It is also now
better characterised than when the plan was written: RFC 7 §5.5 measured
exhaustive search at 19.2 ms per object for a 64-key batch, rising to 614 ms
at 2 048, and RFC 7 §13 established that only inbox mode needs it.

A cap can therefore be derived from a CPU budget rather than guessed.

---

## 3. Recommendation

**Reduce RFC 2 rather than retiring it.** Its original scope is gone, but the
three items in §2 are real, are addressing questions, and have no other home.
The document becomes short and specific:

```
RFC 2 — Inbox Addressing and Shard Semantics
  1. namespace separation, as a named normative invariant
  2. address grammar canonicalisation for matching and display
  3. the inbox-tag counting leak: statement, scope, and token-gated mitigation
  4. per-class shard masks
  5. inbox decapsulation caps, derived from a CPU budget
```

It requires RFC 1 and is required by RFC 5 and RFC 6 — the reverse of the
plan's dependency, which had RFC 6 waiting on RFC 2.

The alternative is to retire RFC 2 and scatter these across RFC 0 §7 (the
leak), RFC 5 (shard masks, caps) and RFC 6 (address grammar). That works, but
it puts an addressing property in three documents and loses the one place a
reader would look.

---

## 4. Gate

RFC 2 may reach Draft when:

- [x] original scope reconciled against RFC 1 — §1
- [x] the rotating-contact-key proposal corrected — §2.1
- [ ] RFC 0 §10's roadmap updated to stop listing RFC 2 as freezing tags
- [ ] RFC 3 §9.1 amended to state the consequence of publishing `kx_pk`
- [ ] token-gated inbox addressing specified, or explicitly deferred
- [ ] per-class shard masking specified, or RFC 6 §3.4 amended
- [ ] inbox decapsulation cap derived from a stated CPU budget
- [ ] address grammar canonicalisation written

Two of these are amendments to documents already at Draft, which is the usual
consequence of a document arriving late in a series: RFC 2 cannot state the
leak's scope without RFC 3 §9.1 also disclosing it.

---

## 5. What RFC 2 must not become

- **A second tag scheme.** RFC 1 §6.2 is frozen. RFC 2 specifies which keys
  feed it and how they are published, never how a tag is derived.
- **A directory.** RFC 0 §6 non-goal 2 forbids a global directory, and an
  addressing document is exactly where one gets proposed.
- **A place to relitigate the inbox tag's linkability.** RFC 1 §6.2 accepted
  linkability within an epoch as the price of open first contact and said so.
  §2.1 sharpens the consequence; it does not reopen the decision.
