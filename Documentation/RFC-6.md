# RFC 6 — Groups and Channels

    Number:      6
    Title:       Groups and Channels
    Status:      Draft
    Repository:  https://github.com/vulogov/krab
    Author:      Vladimir Ulogov
    Requires:    RFC 0, RFC 1, RFC 3, RFC 7
    Grounded by: krab-sizes/groups (all figures computed)

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be
interpreted as described in RFC 2119.

---

## 1. Scope

Krab has two multi-party mechanisms with **opposite security models and
opposite cost classes**:

| | group | channel |
|---|---|---|
| encrypted | yes | **no** |
| authorship | deniable | non-repudiable signature |
| audience | closed roster | anyone, permanently |
| mechanism | fan-out, one object per member | flood, one object |
| corpus cost | **quadratic** in size | **constant** |

They are not two views of one feature. Choosing between them is an
arithmetic question with a clear answer at every size (§4), and presenting
them as interchangeable in a client is the most dangerous mistake this
document can permit (§5).

---

## 2. Groups

### 2.1 Fan-out

A group message is `G−1` ordinary `sealed` objects (RFC 1 §5.1), one per
recipient, each with its own tag, ephemeral, and prekey.

No new cryptography. Copies are unlinkable to each other by construction.
It composes unchanged with prekeys, epochs, reservoirs, and courier
delivery.

**The reason to prefer it is security, not simplicity.** Signal and MLS
use sender keys because `G×` bandwidth is unacceptable at their scale, and
the price is that compromising any one member exposes the whole group's
traffic. Fan-out has no shared secret: breaking Bob reveals what Bob
received and nothing else.

At Krab's scale that stronger property is affordable. This should be
stated in any description of the design, because fan-out reads as a
shortcut and is not one.

### 2.2 MLS is rejected

RFC 9420 solves membership consistency properly and requires a delivery
service providing message ordering. Krab has no such service and will not
acquire one. MLS is therefore unavailable, and §2.5 is the consequence.

### 2.3 The quadratic wall

Every node in the eligible shard stores every copy, so corpus load from a
single group is `G(G−1)M` objects per day.

At 2 messages per member per day, 1 KB bucket, against SIM-0's measured
baseline of 31 MB/day/node ingress at n=500:

| G | objects/day | corpus MB/day | share of baseline | received/member/day |
|---|---|---|---|---|
| 5 | 40 | 0.04 | 0% | 8 |
| 10 | 180 | 0.18 | 1% | 18 |
| 20 | 760 | 0.78 | 3% | 38 |
| 30 | 1 740 | 1.78 | 6% | 58 |
| 50 | 4 900 | 5.02 | **16%** | 98 |
| 100 | 19 800 | 20.28 | **65%** | 198 |
| 200 | 79 600 | 81.51 | **263%** | 398 |

At G=100 a single group consumes two-thirds of every node's daily ingress.
At G=200 it more than doubles the network's total traffic. **Everyone
pays, including nodes with no member in the group.**

### 2.4 Size limits, and why they are principled

Fan-out costs `(G−1)×` a shared-sender-key scheme:

| G | ratio | what the cost buys |
|---|---|---|
| 5 | 4× | one compromise exposes one member |
| 20 | 19× | one compromise exposes one member |
| 50 | 49× | **social leakage dominates** |
| 100 | 99× | **social leakage dominates** |

The cryptographic compartmentalisation fan-out buys is real at small
sizes. At fifty members it is buying very little: a group that large has
no meaningful confidentiality against a member regardless of key
structure, because the realistic disclosure path is a person, not a
cryptanalyst. Paying 49× to compartmentalise a secret fifty people already
share is not a good trade.

```
Groups SHOULD NOT exceed 25 members.
Implementations MUST warn above 25 and MUST refuse above 50.
```

Above 25, the correct mechanism is a channel — which costs 380× less at
G=20 and does not grow with audience at all (§4).

Over LoRa the limit is tighter still:

| G | copies | frames | airtime |
|---|---|---|---|
| 5 | 4 | 24 | 0.3 h |
| 10 | 9 | 54 | 0.8 h |
| 20 | 19 | 114 | **1.6 h** |

One group message at G=20 is 1.6 hours of airtime. **Groups over LoRa
SHOULD NOT exceed 10 members**, and clients MUST surface which recipients
are LoRa-reachable before sending.

### 2.5 The roster is inside the ciphertext

Fan-out hides the roster from the network. It cannot hide it from members,
because Bob must know whom to fan his reply out to.

```cbor
9: {                          ; inner plaintext key 9 (RFC 1 §7)
  0: <group_id, 32 B random>
  1: <epoch>
  2: [ {node_id, kx_pk}, ... ]     ; roster
  3: <parent message id>           ; threading
}
```

**The honest claim is: hidden from everyone, known to every member.**
"Absolutely hidden" is not achievable in a design where members reply.

The alternative — only the creator fans out, everyone replies to the
creator — does hide membership from members, at the cost of a mandatory
hub who knows everything and whose absence kills the group. Wrong shape
for a network with no infrastructure. Rejected, and recorded as rejected
so it is not reproposed.

### 2.6 Membership divergence is guaranteed

Alice believes the group is {A,B,C}. Bob added D last week and Alice has
not received that message. Bob's messages reach D; Alice's do not. With
courier latency and no global ordering this is routine, not an edge case.

```
epoch      increments on every membership change
change     an ordinary signed group message
merge      on receiving a higher epoch, adopt that roster
```

**Divergence MUST be surfaced, not silently resolved:**

> *Bob sent this at roster epoch 4; you are on epoch 3. There is 1 member
> you do not know about.*

Silent convergence is the wrong default. "Someone was added to your group
and the interface smoothed it over" is precisely the event a user needs to
see, and it is indistinguishable from an attack.

Roster authority is a group policy recorded at creation: creator-only, or
any-member. Implementations MUST record which and MUST NOT allow it to
change, since a change to the authority model is indistinguishable from a
compromise of it.

### 2.7 Emission stagger

`G−1` objects appearing within a short window, all in the same size
bucket, is visible as "someone just sent to about G people" — and with
tight timing, possibly *which* G tags. That partially undoes the
unlinkability fan-out paid for.

The fix is to spread emission over a randomised window `W`. **The
required window depends on the network's background rate**, and is longer
in small networks, which is counterintuitive: less traffic means less
noise to hide in.

Window for a ≤10% local rate lift:

| network | background | G=10 | G=20 | G=50 |
|---|---|---|---|---|
| n=100 | 8.3 obj/h | 10.8 h | 22.8 h | 58.8 h |
| n=500 | 41.7 obj/h | 2.2 h | 4.6 h | 11.8 h |
| n=2 000 | 166.7 obj/h | 0.5 h | 1.1 h | 2.9 h |

```
Implementations MUST stagger fan-out emission over a randomised window.
W MUST be derived from the observed background arrival rate, NOT a constant.
```

A fixed default would be badly wrong at one end or the other. Krab already
tolerates days of latency, so the cost is nil — but a client that emits
the burst immediately silently discards the property.

### 2.8 Prekey burn

A member receives `G−1` messages per round, so group membership dominates
prekey consumption (RFC 7 §5.3):

| G | received/day | batch for 7 d | batch for 30 d |
|---|---|---|---|
| 5 | 8 | 128 | 512 |
| 10 | 18 | 256 | 1 024 |
| 20 | 38 | 512 | 2 048 |
| 50 | 98 | 2 048 | **8 192 — exceeds `MAX_OBJECT`** |

**Members of large groups MUST republish prekeys weekly.** A 50-member
group makes monthly republication impossible: the batch would not fit in
a single object. Exhaustion degrades forward secrecy silently, so clients
MUST surface burn rate and MUST warn when joining a group would make the
current cadence insufficient.

---

## 3. Channels

### 3.1 A channel is a key

```
channel_id = BLAKE3-256("krab/chan/v1" ‖ ed25519_pk)
tag        = leading 8 bytes of channel_id
```

Self-certifying. No registry, no hierarchy, no coordinators, no name
disputes. Names are **local labels** a client displays; two subscribers
may call the same channel different things and nothing breaks.

The tag is stable and public — the one place in Krab where a tag is
deliberately linkable, because a channel is a public feed. RFC 0 I-2's
namespace separation is why that is safe: a bulletin tag can never be
mistaken for a `sealed` tag.

### 3.2 Single-author, deliberately

Only the holder of the channel key may post. Posts are `bulletin` objects
(RFC 1 §5.2): signed, not encrypted, third-party verifiable.

**This needs no moderation because there is nothing to moderate** — an
unwanted poster simply cannot post.

"Open discussion" is a *client-side* construct: subscribe to N author
feeds and merge by thread reference. Moderation becomes unsubscription,
which requires no protocol, no authority, and no power that could be
captured.

```
Shared-write channels MUST NOT be added.
```

The moment anyone can post to a channel, moderation is required;
moderation requires authority; authority requires infrastructure; and
RFC 0 §6 forbids infrastructure. The chain is short and its conclusion is
not negotiable.

### 3.3 Cost is constant in audience

| posts/day | size | corpus MB/day | ×100 channels |
|---|---|---|---|
| 1 | 4 KB | 0.004 | 0.4 |
| 10 | 4 KB | 0.041 | 4.1 |
| 50 | 4 KB | 0.205 | 20.5 |
| 10 | 64 KB | 0.655 | 65.5 |

One post is one object regardless of whether ten or ten thousand people
read it. **A group of 20 costs 380× a channel post.**

But aggregate growth is unbounded in a way group traffic is not: anyone
may create a channel, and RFC 0 removed proof-of-work as unnecessary
because friend-to-friend peering bounds traffic. That reasoning holds for
person-to-person mail and **does not hold for public feeds.**

### 3.4 Opt-in, always

```
Nodes MUST support excluding class 1 (bulletin) entirely via class_mask.
Channel carriage MUST be off by default.
Channels MUST occupy a separate shard space from sealed traffic.
```

A node MUST be able to carry its operator's mail and no channels at all.

**Acceptance is by shard prefix, not exact channel identifier.** An exact
list is a list of your interests handed to your peer — and a peer who
wants to know whether you follow channel X can simply add X and observe.
A `k`-bit prefix bucket means you also carry channels you do not read, and
your peer learns 1/2^k of your interest. Same dial as everywhere else,
reused at no cost.

### 3.5 Subscriptions are not in the credential

Subscriptions change weekly; peer links last 60–90 days (RFC 3 §4).
Re-signing a mutual credential to follow something is friction that will
cause people to stop.

Subscriptions are a separate document, signed unilaterally, referencing
the link, valid within bounds the credential authorises. The credential
sets the *ceiling* on channel carriage; the subscription document sets the
current selection.

### 3.6 Channels change what a node is

Without channels, a Krab node is invisible: no public participation,
nothing enumerable, relaying only ciphertext for people its operator
chose.

**A channel is a published artifact** — indexable, attention-attracting,
and content a relay operator can neither inspect nor account for. Enabling
channel carriage moves a node from "I relay for four friends" to "I host
public content," with the legal and operational consequences that implies
in the operator's jurisdiction.

This is not an argument against building channels. It is the reason they
are off by default (§3.4), and it MUST be stated at the point a user
enables them — not buried in documentation they will not read.

---

## 4. Choosing

The decision is arithmetic, not preference:

| audience | mechanism | why |
|---|---|---|
| 2–10 | group | cost negligible, compartmentalisation real |
| 10–25 | group | 3–6% of baseline ingress; still worth 19× |
| 25–50 | **channel** | fan-out cost rising fast, security benefit falling |
| 50+ | **channel** | fan-out is 16–65% of every node's ingress |
| public | channel | constant cost, no roster to diverge |

The crossover near 25 is where two independent curves cross: fan-out cost
rising quadratically, and the value of cryptographic compartmentalisation
falling as social disclosure becomes the realistic path. Clients SHOULD
suggest a channel when a group approaches the limit, and explain the
tradeoff in those terms rather than as a capacity error.

---

## 5. The client requirement

Groups and channels are opposite security models presented in the same
interface as "a list of messages."

**A user who believes they are in a private group while posting to a
public channel is the worst failure this system can produce.** It is
irreversible: the post is signed, non-repudiable, flooded, and cannot be
recalled — RFC 3 §6.1 forbids any recall mechanism.

Normative (elaborated in RFC 8):

1. The security context MUST be visible **in the composer**, not only in a
   tab header: distinct border treatment and a persistent
   `PUBLIC — SIGNED — PERMANENT` banner.
2. The first channel post of a session MUST require explicit confirmation.
3. Reply MUST default to a private sealed message to the author.
   The publish action MUST be a separate keystroke.
4. Roster divergence (§2.6) MUST be shown, never silently merged.
5. Group size warnings (§2.4) and prekey adequacy (§2.8) MUST be shown at
   join time, not at failure time.

---

## 6. Security considerations

**Fan-out's advantage is bounded by group size.** §2.4. Below 25 it is a
real property; above 50 it is a cost with no corresponding benefit, which
is why the hard cap exists rather than a warning alone.

**The roster is a membership disclosure to every member.** Any member may
leak it, and it is inside plaintext they hold. Group membership is not
secret from members and must not be described as if it were.

**Divergence is indistinguishable from attack.** A member added without
your knowledge and a roster you have not yet synchronised look identical.
§2.6's surfacing requirement is what gives the user any chance of telling
them apart, and it is the reason silent merge is forbidden.

**Emission stagger is easy to lose.** It is scheduler behaviour with no
functional effect, so it will be removed by someone optimising perceived
latency. It is the same class of regression as RFC 0 I-5, and it should be
protected by a test that measures inter-object emission gaps, not by a
comment.

**Channels are permanent and non-repudiable.** Unlike sealed messages,
which are deniably authenticated and become unreadable when their epoch
key is erased (RFC 7 §8), a bulletin carries an Ed25519 signature over
plaintext that any archivist retains forever. Erasure does not apply.
Users MUST be told this at the point of posting.

**Channel tags are linkable by design.** Subscription is observable to
peers carrying the shard. §3.4's prefix bucketing bounds the disclosure;
it does not remove it.

**Group traffic is a load an operator did not consent to.** Every node in
the shard stores every copy, including nodes with no member in the group.
This is the same class of externality as RFC 3 §6.1's third consequence,
and quota is the only control.

---

## 7. References

- KRAB RFC 0 — Architecture and Threat Model
- KRAB RFC 1 — Object Format and Cryptography
- KRAB RFC 3 — Peering, Credentials, and Accountability
- KRAB RFC 7 — Key Custody and Erasure
- KRAB RFC 8 — Client Behaviour
- KRAB SIM-0 — Corpus Convergence Measurements
- `krab-sizes/groups` — reference calculator; source of every figure here
- RFC 9420 — MLS (evaluated, rejected: requires an ordering service)
- RFC 2119, RFC 8032
