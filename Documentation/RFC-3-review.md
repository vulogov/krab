# RFC 3 — Review

    Subject:  RFC 3, Peering, Credentials, and Accountability, Status: Draft
    Method:   cross-check against SIM-0, SIM-1, RFC 0, RFC 1, and apps/krab-sizes
    Verdict:  one composition defect, one silent failure mode, three gaps

RFC 3 is revisable — the credential format is not inside the object identifier
hash — so nothing here is irreversible the way RFC 1's findings were. Item 1
is nonetheless the most serious finding in the series so far, because it is a
leak that neither document creates on its own.

## What verifies

`apps/krab-sizes` gained a `creds` module. RFC 3 §8.1 and §8.2 reproduce
exactly from a single recovered constant pair — a 220-byte fragment wrapper
and a 200-byte delta wrapper around 416-byte credentials:

```
fragment(P)   = 220 + 416·P
all_copies(P) = P · fragment(P)
```

All five rows of §8.1 (fragment, all copies, LoRa reconciliations) and all
three of §8.2 (delta, full, ratio) check out, as does the prose claim that 50
peers is "roughly two weeks of airtime" — computed 14.6 days. `--check` now
covers 72 figures across RFC 1 and RFC 3.

The §13 peer cap is also confirmed as load-bearing rather than round-numbered:
a weekly fragment publication fits inside a week of LoRa airtime at 25 peers
(3.7 days) and does not at 50 (14.6 days).

### What does not verify, because it cannot

**RFC 3's credential sizes are not reproducible from RFC 3.** §3 gives field
*names* but not the sub-structure of `party`, `terms`, `flags`, or
`transports`, so the 343 / 416 / 562 / 284-byte figures and §5.1's 683 / 804
cannot be recomputed. They are taken as stated inputs.

This is the same gap RFC 1 had with its 150-byte floor, and it matters more
here: every number in §8.1, §8.2, §11 and §13 is built on the 416-byte
credential. Pin the sub-structure and the whole chain becomes checkable.

Minor: §8.1 truncates 11.5 KB to "11" while §8.2 rounds a ratio of 13.86 to
"14". Two conventions in adjacent tables.

---

## 1. Composition defect — rollcall makes inbound peer-requests publicly countable

Neither document is wrong alone. Together they leak.

- **RFC 1 §6.2**: `inbox_e = HKDF-Expand(pk_recipient, "krab/inbox/v1" ‖ epoch, 8)`.
  Computable by anyone holding the recipient's public key. RFC 1 accepts this,
  reasoning that first contact is inherently less private.
- **RFC 3 §5.1**: a `peer-request` is delivered as an ordinary `sealed` corpus
  object addressed to that inbox tag — so it floods to every node.
- **RFC 3 §9.1**: a rollcall entry publishes `kx_pk`. That is exactly the key
  the inbox tag derives from.

So for any node listed in the rollcall, **anyone can compute its inbox tag for
every epoch and count the peer-requests addressed to it.** Not the contents,
which stay sealed — but the fact, the volume, and the timing.

RFC 0 §7.6 makes this permanent: nothing compels a relay to evict, and an
adversarial relay keeps every ciphertext it ever handled. The count is
retrospective and unbounded.

What it discloses:

- how many parties have tried to peer with a given node, per epoch, for the
  life of the corpus
- when a node became interesting, and to how many people at once
- correlated against rollcall entry timing, whether a node's visibility drove
  inbound interest

RFC 1 §13 says the risk is "composition, not primitives," and names tag
derivation and mode coupling as the novel arrangements. This is one it did not
anticipate, because it requires RFC 3 §9.1 to publish the key that RFC 1 §6.2
assumed would be narrowly held.

**Candidate fix, cheap and idiomatic here.** RFC 3 §9.2 already separates a
*contact* endpoint from a *sync* endpoint. Do the same with keys: publish a
distinct **contact key** in the rollcall, used only for inbox-tag derivation
and first contact, rotated on the entry's ~7-day cadence. The correspondence
key stays unpublished.

> **Correction.** This proposal does not close the leak, and
> `RFC-2-blocking-items.md` §2.1 supersedes it. Rollcall entries are
> `bulletin` objects, so every contact key ever published persists on any
> archival relay — precisely the adversary RFC 0 §7.6 says exists. Such an
> adversary holds the whole key sequence and counts everything regardless of
> rotation. Rotation bounds the retrospective count only for an adversary who
> starts observing late.
>
> The property is structural: an inbox tag must be computable by any stranger,
> which is what makes open first contact possible, and by nobody else, which
> is what would stop counting. The real options are to state the leak as
> unmitigable and scope it to opt-in rollcall participants, or to gate first
> contact on an introduction token and derive the tag from the token.

This is worth resolving in RFC 3 rather than RFC 1, since RFC 1 is frozen and
RFC 3 is not — but RFC 1 §6.2's "computable by anyone holding the recipient's
public key" should be read as a constraint on what may be published, and RFC 3
§9.1 currently violates it.

---

## 2. Silent failure — 12% of austere negotiations never complete

§5.1's decision to route peer-requests through the corpus is right for the
reason given: it reaches a node with no endpoint. It also means each
negotiation leg inherits the corpus's *delivery probability*, and three legs
compound.

Recomputed against SIM-0 §3 (`rfc-3-runs/peering-latency.py`):

| transport mix | per-leg delivery | all three | negotiations lost | p50 | p90 |
|---|---|---|---|---|---|
| all-tcp | 100.0 % | 100.0 % | 0.0 % | 0.6 d | 1.0 d |
| mixed | 100.0 % | 100.0 % | 0.0 % | 0.9 d | 1.4 d |
| courier-heavy | 100.0 % | 100.0 % | 0.0 % | 1.5 d | 3.0 d |
| **austere** | 95.8 % | **87.9 %** | **12.1 %** | 21.2 d | 30.8 d |
| all-courier | 52.5 % | 14.5 % | 85.5 % | 32.7 d | 43.9 d |

Completion is exact — the delivery rate cubed. Latency is interpolated from
SIM-0's percentiles and is indicative only.

**Under austere transport roughly one peering attempt in eight is simply
lost**, and RFC 0 §6 non-goal 6 makes delivery failure silent. Both operators
see nothing happen, with no signal separating "still in flight at day 20" from
"the request died." §4's guidance that implementations "MUST surface an
expired peering as an explicit state rather than as a silent sync failure"
addresses the wrong end: the same reasoning applies to a negotiation that
never lands.

Two consequences RFC 3 should carry:

- **Retry is mandatory, not optional.** A `peer-request` is idempotent — it is
  a signed static document with a nonce — so re-emitting it after a timeout is
  safe and closes the gap: three attempts take 12.1 % to 0.18 %. RFC 3 says
  nothing about retry.
- **The negotiation needs its own validity window**, distinct from the
  credential term, and it must exceed the p90 negotiation latency of the
  *slowest* transport the parties share. At austere that is 31 days.

This also supersedes the model in my own earlier `RFC-3-blocking-items.md`,
which assumed each leg was one direct courier hop and produced 30 days mean.
That was the wrong model: peering is precisely the situation where no direct
link exists yet.

### On credential term

§4 says "SHOULD be 60–90 days" without choosing; §15 argues for the upper end
on offline-period grounds. The completion analysis gives an independent and
sharper reason for **90**: at austere, one negotiation at p90 consumes 34 % of
a 90-day term against 51 % of a 60-day term, and renewal is itself a
negotiation. A 60-day term spends over half its life renegotiating on the
transport mix that Krab exists to serve.

---

## 3. Gap — retention is a promise, not a capacity, so SIM-1's re-fetch loop survives

§7.3 puts `retention_window` into the reconciliation filter, derived from the
signed credential so both sides provably agree. That is exactly the mechanism
SIM-1 §4 called for, and it is the right shape.

But retention is defined in §7 as a **floor commitment** — what a node
*promised* to keep. It is not what the node *can* keep. Under capacity
pressure the two diverge: a node that promised 30 days but evicts at 10 will
have its peer keep offering 10-to-30-day-old objects, which it re-accepts and
re-evicts. That is precisely SIM-1 §4's loop, which cost **+68 % ingress** at
a 100 MB cap while delivery stayed at 100 %.

§7 has no rule tying retention to available storage, and §12's `storage share`
metric is reported but never fed back. RFC 3 needs either a hard requirement
that a node MUST NOT promise retention exceeding its provisioned capacity, or
a separate renegotiable "currently holding from" watermark distinct from the
promise.

Relatedly, §7.1's claim that a declared retention window "removes the thing to
infer" is right as far as it goes, and is a genuinely good observation. SIM-1
§4 found the complementary half: uniform eviction makes a capped node's
holdings a *deterministic* function of its cap and object age. Declaring the
window converts that from an inference into a disclosure, which is the
improvement §7.1 claims — but only if the declared window matches the actual
one. Under §3's gap above, it does not.

---

## 4. Gap — `transports` does not carry latency class

§3 key 9 is "endpoint list; MAY be empty."

SIM-1 §1 measured that reconciliation strategy has no safe default: a full
manifest starves **98.3 %** of LoRa reconciliations, while RBSR collapses
austere delivery from 95.8 % to **33.0 %** because each fingerprint-tree
descent level costs a courier round trip. RFC 5 must therefore choose per link
from `latency_class`.

`latency_class` belongs to RFC 4's `LinkProfile`, but the credential is what
tells a peer which profile applies *before any connection exists* — and on a
courier link, before any connection can exist. An endpoint list does not carry
it. Two consequences: RFC 5 cannot make its choice from signed data, and a
peer can induce the catastrophic strategy by misdeclaring, since nothing is
signed to contradict it.

---

## 5. Gap — §13's peer counts contradict RFC 0 §8.2

| deployment | RFC 0 §8.2 | RFC 3 §13 |
|---|---|---|
| IP-connected | 6–8 | 8–20 |
| mixed | 8 | 12–20 |
| courier / radio-dominated | 12+ | 12–25 |

Both cite SIM-0. RFC 3 is the more conservative and, on the later evidence,
the correct one — SIM-1 §3 found that degree 12 is what closes the holdings
leak under austere transport, which is a privacy argument RFC 0 §8.2 predates.
RFC 3 also supplies the upper bound RFC 0 lacks entirely.

RFC 0 §8.2 should be updated to match rather than leaving two normative
documents disagreeing on an operator-facing number. Note also that RFC 3's
lower bounds are stated without the SIM-1 grounding that actually justifies
raising them.

---

## 6. Minor

- **§9.1's "stale entries vanish"** overstates. A rollcall entry expires in
  ~7 days, but the *object* persists for its TTL (up to 45 days, RFC 1 §2) and
  indefinitely on any archival relay (RFC 0 §7.6). The entry stops being
  authoritative; it does not vanish. This matters for §1 above, since old
  entries keep disclosing old contact keys.
- **§6.2's automatic quota adjustment** is a policy sketch — "drift upward
  while behaviour is good, drop sharply on violation" — without saying how
  §12's eight signals combine, or what the drift rate is. Reversibility is
  correctly stated. Probably acceptable at Draft, but it is the mechanism §1
  calls "the central mechanism of the document."
- **§14 multi-device** multiplies fan-out by device count, which multiplies
  prekey burn (RFC 1 §6.3) and corpus volume. Neither is estimated.

---

## 7. Where the grounding still isn't

Unchanged from `RFC-3-blocking-items.md` §3, and RFC 3 does not overclaim on
it — §15 says graduated quota "limits early damage; it does not prevent
penetration," which is appropriately hedged.

SIM-1 §5 listed quota enforcement as unmodelled, so the primary defence
against vantage acquisition was absent from SIM-1 §3's measurement of that
attack. Whether graduated quota actually blunts it is testable — a low-quota
vantage point holds less corpus, which directly weakens the holdings signal —
and remains the SIM-2 item.

RFC 0 §9's courier-only end-to-end peering test is likewise still outstanding.
§11.3 correctly makes it a release gate. Note that it tests *mechanism* —
that no step needs an unnoticed round trip — and not *viability*: §2 above
shows the mechanism can be sound while one negotiation in eight still dies in
transit.

---

## 8. Gap — the credential is the one signed document with no signature domain

Raised while implementing `peer offer`. §2.1 says credential documents use the
deterministic CBOR profile of RFC 1 §4.3 and stops. It never says what an
Ed25519 signature over a credential covers.

That is an omission rather than a design choice, and the evidence is that **the
series gets this right everywhere else**:

| document | signature covers | where |
|---|---|---|
| peer-link | `"krab/link/v1" ‖ body` | RFC 3 §4 |
| bulletin | `"krab/bul/v1" ‖ header ‖ body-without-key-3` | RFC 1 §5.2 |
| **credential / rollcall entry** | **unspecified** | RFC 3 §2.1, §5.1 |

Every *hash* in the series is domain-separated — `krab/obj/v1`,
`krab/node/v1`, `krab/chan/v1`, `krab/tag/v1`, `krab/inbox/v1`,
`krab/pkidx/v1`. Two of the three signed documents are too. The credential is
the exception, and it is the document carrying the most consequential claims: a
node's Noise static, its correspondence key, and its policy.

### 8.1 What goes wrong

Without a domain prefix, a credential signature is a bare Ed25519 signature
over a deterministic CBOR map with small integer keys — and so is every other
document the same identity key signs. Two document types whose encodings
coincide are then interchangeable under one signature: the signer consented to
one meaning and is bound to the other.

The shapes are close enough to matter. A credential is `{1: bstr32, 2: bstr32,
3: bstr32, …}`. Any future document that opens with two or three 32-byte keys
under the same indices — a subscription (RFC 6 §8), an introduction, a rotation
notice — is a candidate. The attack needs no cryptographic weakness; it needs
two documents that happen to encode alike, and deterministic CBOR guarantees
that identical structure yields identical bytes. That is normally the property
one wants.

This is not hypothetical for a series still adding documents. Every new signed
document type is a new opportunity for a collision with an existing one, and
nothing in §2.1 makes the author of that document think about it.

### 8.2 It is also an interoperability gap

Independent of any attack: **§2.1 as written is not implementable
interoperably.** An implementer following the pattern set by §4 and RFC 1 §5.2
will invent a prefix — and will pick their own string. An implementer following
§2.1 literally will use none. Neither is wrong by the text, and their
credentials do not verify against each other.

The failure surfaces as "peering with that person never works", at the
ceremony, in person, with no diagnostic. RFC 3 §11 makes the ceremony a
deliberate event people travel for.

### 8.3 Proposed text for §2.1

> A credential's signature is Ed25519 over `"krab/cred/v1" ‖ body`, where
> `body` is the deterministic CBOR encoding of the document with the signature
> field omitted.
>
> Every signed document in this series MUST prefix its signing input with a
> domain string unique to that document type. A signature produced over one
> document type MUST NOT be valid over any other.

The second paragraph is the part worth adding, because it converts a per-document
decision into a rule the next document inherits.

### 8.4 What the implementation does

`apps/krab-tui/src/peering.rs` signs `DOMAIN_CARD ‖ deterministic_cbor(body)`
with `DOMAIN_CARD = b"krab/card/v1"`. That string is a placeholder pending the
RFC; if §2.1 adopts `krab/cred/v1` the constant changes and no format does.

Two implementation notes fell out of the same work:

- **The card body is a flat map, not nested.** RFC 1 §4.3 requires map keys to
  ascend, and a nested map's keys restart at 1 — so a decoder reading both
  levels from one cursor sees keys go backwards and correctly rejects its own
  encoder's output. Flattening removes the question. §2.1 should say whether
  credential documents may nest maps at all; if they may, the profile needs to
  say that ordering is per-map rather than per-document.
- **Decoding does not verify.** `Card::decode` returns an unverified card and
  `Card::verify` is separate, so there is one rejection path rather than two.
  Folding them together reads as safer and is not: it leaves no way to express
  "parsed but untrusted", which is exactly what a credential is until RFC 3 §11
  step 2 has been performed by a human.

---

## 9. §11.3's courier-only gate — status

The gate is implemented in two halves, because §11.3 asks for two things:

> "a complete peering **negotiation** and **first message exchange** with all
> network interfaces down, using only file import and export."

| half | where | status |
|---|---|---|
| peering negotiation | `apps/krab-tui/src/main.rs::courier_only_peering_completes_with_no_network` | **passes** |
| message exchange | `crates/krab-node/tests/courier_only.rs` | **passes** |

### 9.1 What the tests actually establish

The negotiation test runs two nodes with two directories and nothing between
them but `std::fs`. Both offer, both accept, both seal, and both derive the
same reservoir — having exchanged four files and no packets. Artifacts are
renamed in transit, since RFC 4 §5.5 requires filenames be ignored.

The message-exchange test is structured as **strictly alternating one-way
legs**. A leg writes an archive and stops; nothing reads while anything writes,
and no session is open at both ends at once. The sending node's inbox path is
one that never comes into existence, and the test asserts so at the end — if
any step had needed a reply, it would have had nowhere to look for one.

That structure is the point. The gate is not testing cryptography; it is
testing for a **hidden round trip**, which over TCP is free and invisible and
over a posted USB stick is fatal. §11.3 says as much: "if any step requires a
round trip that was not noticed, air-gapped nodes silently cannot join, and
that will not be discovered until someone tries."

A third test pins the reason RFC 5 §4.5 derives `sync_mode` from latency class
rather than configuring it: a courier link resolves to `Manifest`, and a node
that chose RBSR would negotiate one round per courier, forever.

### 9.2 Bodies are sealed — the earlier caveat is closed

An earlier revision of this section recorded that object bodies were opaque
bytes rather than HPKE-sealed plaintext, because sealing was blocked on
`CRYPTO-REVIEW.md` §1. That is resolved: `a_sealed_message_crosses_by_courier`
carries a real payload sealed under `mode_auth_psk` with a reservoir chunk as
PSK, and the recipient opens it having received nothing but a file.

Sealing turned out to be the more interesting half of the gate, not the
incidental one. A courier deployment cannot fall back on negotiation, so
**everything the key schedule needs must already be shared**: `mode_auth`
requires the recipient hold the sender's static key, and the PSK requires a
reservoir root. Both come from the offline ceremony. Had either quietly needed
a live exchange, the gate would have caught it — which is precisely the class
of defect §11.3 exists to find, and it would not have been visible over TCP.

One implementation note worth recording, because it is easy to get wrong in the
other direction: the body is padded to its size bucket and the identifier covers
the padding (RFC 1 §8.1), so **the ciphertext length cannot be recovered from
what is on disk**. It has to come from the sender's framing. An implementation
that inferred it from the object's length would decrypt padding as ciphertext
and fail authentication for reasons that look like corruption.

### 9.3 One thing the gate surfaced

Persisting a half-finished ceremony creates an opening §11 does not discuss:
the operator compares fingerprints aloud at step 2, and steps 3 and 4 may
happen days later. A second card arriving in between could substitute the
counterparty **after** the verification everyone remembers performing.

`Pending::accept_card` refuses a second, different card once one is recorded,
and re-accepting an identical one succeeds — a resend is not an attack. Worth a
sentence in §11: the ceremony is described as "one event", and for a sneakernet
peering it is demonstrably not.
