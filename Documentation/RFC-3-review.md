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
key stays unpublished. Inbox tags then rotate with the contact key, and a
historical count covers one entry period rather than all of history.

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
