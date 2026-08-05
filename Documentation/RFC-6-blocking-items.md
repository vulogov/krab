# RFC 6 — Blocking Item Status

    Status:      Working document, not an RFC
    Purpose:     the gate on RFC 6 reaching Draft
    Grounding:   SIM-0, SIM-1, RFC-1.md, RFC-7.md, rfc-6-runs/
    Depends on:  RFC 1, and RFC 2 — see §4

RFC 6 specifies groups and channels. Groups are fan-out: N single-recipient
sealed objects rather than one object under a shared group key. Channels are
single-author public feeds built on `bulletin` objects.

RFC 6 is revisable. Its difficulty is not permanence but arithmetic: **fan-out
is the first mechanism in the series that multiplies corpus volume**, and
every measurement the series rests on was taken with one object per message.

Reproduce with `rfc-6-runs/fanout.py`.

---

## 1. Fan-out invalidates the sharding threshold

SIM-0 §7 measured ingress at 0.063 MB/day per node, per node in the network,
and RFC 0 §8.3 turns that into "sharding is mandatory above approximately
n = 5 000." Both figures assume one object per message. A G-member group
produces G−1.

| group size | objects/message | ingress multiplier | sharding threshold |
|---|---|---|---|
| 1 (no groups) | 1 | 1× | ~4 900 |
| 5 | 4 | 4× | ~1 230 |
| 10 | 9 | 9× | ~550 |
| **20** | 19 | **19×** | **~260** |
| 50 | 49 | 49× | ~100 |

**A network whose traffic is mostly 20-person groups needs sharding from a few
hundred nodes, not from five thousand.**

RFC 0 §8.3's decision to put the shard field in v1 regardless is vindicated —
it is inside the identifier hash and could not be added later. But the
*threshold guidance* is wrong for any deployment that uses groups at all, and
it is stated as a scale property of the network rather than of its traffic
mix.

**Normative consequences.**

- RFC 6 MUST state that the effective sharding threshold is `n / mean_fanout`,
  and RFC 0 §8.3 should be corrected to say the threshold depends on traffic
  composition rather than network size alone.
- The client warning RFC 0 §8.2 already requires for peer count needs a
  sibling for shard configuration, keyed on observed fan-out rather than on
  node count — which a node can measure locally from its own group roster
  sizes.

---

## 2. Group size bounds prekey republication cadence

RFC 7 §5.3 sizes prekey batches from received-message rate and identifies
group membership as the driver, but stops short of computing it. Doing so
produces a hard limit.

A G-member group emits `G × 2` messages/day (SIM-0's rate), each fanning out
to G−1 recipients, so each member receives `(G−1) × 2` per day from that group
alone:

| group size | received/day | in two such groups | batch at 7 d | batch at 30 d |
|---|---|---|---|---|
| 5 | 8 | 16 | 128 | 512 |
| 10 | 18 | 36 | 256 | 1 024 |
| 20 | 38 | 76 | 512 | 2 048 |
| 50 | 98 | 196 | 2 048 | **impossible** |

The last cell is not a preference. RFC 7 §5.3 caps a batch at 2 048 keys
because 8 192 keys encodes to 262 264 B, past `MAX_OBJECT`. **A 50-person
group makes monthly prekey republication structurally impossible for every
member.**

Two chains follow into documents already at Draft:

- Membership in two 20-person groups puts a node at 76 received/day, forcing
  weekly republication and a 2 048-key batch — which is exactly where RFC 7
  §9's "under 100 KB" `mlock` argument stops holding (RFC 7 review §5, pinned
  as a test in `krab-sizes`).
- RFC 3 §14 makes each device its own node and the operator a group, so a
  three-device operator in a 20-person group is in a 60-way fan-out. That
  multiplier is not folded into any of the above.

**Normative consequence.** RFC 6 MUST state a maximum group size, or state
that republication cadence is a function of group membership and require the
client to compute it. The former is simpler and RFC 7 §5.3's table already
implies the number.

---

## 3. The measurements do not cover groups

Neither SIM-0 nor SIM-1 models fan-out — `sim.rs` generates one object per
message, with a single destination. So:

> **Every corpus size, ingress rate, storage figure and convergence result in
> this series describes a network with no groups.**

That is not stated in SIM-0 §9's limits list, and it should be. It is a larger
omission than several that are listed: fan-out multiplies the quantity SIM-0
exists to measure.

Adding it is cheap — `krab-sim` would draw a roster size and emit G−1 objects
per message with distinct destinations — and it would settle §1's threshold
empirically rather than by multiplication. It should be **SIM-2's second item**
after the quota-versus-vantage-acquisition measurement carried from
`RFC-3-blocking-items.md` §3.

---

## 4. RFC 2 does not exist, and RFC 1 has absorbed most of it

The series plan makes RFC 6 depend on RFC 1 *and RFC 2* (Addressing and Tag
Derivation). RFC 2 has not been written, and in practice RFC 1 has taken over
its substance:

| RFC 2 scope, per the plan | where it now lives |
|---|---|
| pairwise and inbox tag derivation | RFC 1 §6.2 |
| shard extraction from tag | RFC 1 §5.4 |
| epoch acceptance window | RFC 1 §6.2 |
| prekey selection without a key ID | RFC 1 §6.3, corrected by RFC 7 §13 |
| address lives inside ciphertext | RFC 1 §7.2 |
| **address grammar canonicalisation** | **nowhere** |
| **namespace separation as a named invariant** | RFC 0 I-2 only |

So RFC 6 is not actually blocked — everything it needs from tags is in RFC 1.
But the roadmap in RFC 0 §10 still lists RFC 2 as a document that freezes the
tag scheme, which RFC 1 has already frozen.

**Consequence.** Either retire RFC 2 and fold its two remaining items into
RFC 6 and RFC 0 respectively, or reduce it to those two items and re-sequence.
Leaving a phantom dependency in the roadmap invites someone to wait for it.

---

## 5. Open, with no grounding

- **Fan-out traffic signature.** The plan proposes randomised emission stagger
  over hours. It is not obvious this is needed: RFC 3 §6.1 establishes that a
  peer cannot distinguish originating from relaying, and objects are
  indistinguishable and tags unlinkable, so a burst of N objects is not
  self-evidently attributable. Against that, the burst arrives in one
  reconciliation from one peer. **Whether fan-out is detectable at all is
  measurable** with SIM-1's adversary machinery and has not been measured.
  Note also that any stagger mechanism must not violate I-5 by making emission
  timing correlate with user activity.
- **Membership divergence.** Epoch counter with adopt-on-higher, and the
  requirement to surface divergence in the UI rather than resolve it silently.
  No measurement bears on how often divergence occurs under SIM-0's latencies,
  though it is simulable.
- **Channel corpus growth.** Channels are `bulletin` objects, and RFC 1 §5.2
  already warns that bulletins risk unbounded corpus growth. RFC 6's
  mitigations — opt-in per link, separate shard space, excluded by
  `class_mask` by default — are the right shape, but the growth rate of a
  single busy channel is unestimated.

---

## 6. Permanent decisions to restate

- **No shared group key.** Fan-out means compromising one member exposes only
  that member. This is the security argument, and it is why the cost in §1 and
  §2 is worth paying — it should be stated as a deliberate trade, not
  discovered later as an accident.
- **MLS (RFC 9420) evaluated and rejected**: it requires an ordering delivery
  service, which Krab has no way to provide. Already recorded in RFC 0 §12.
- **Moderation is unsubscription.** No recall, no deletion — RFC 0 §6
  non-goal 5 forbids any recall mechanism, since it cannot be built
  selectively.
- **The character change is the real risk.** Enabling channels turns a node
  from a private relay into a host of public content, with legal and
  operational consequences RFC 0 §7.1 already refuses to mitigate technically.

---

## 7. Gate

RFC 6 may reach Draft when:

- [x] fan-out's effect on the sharding threshold quantified — §1
- [x] group size's effect on prekey cadence quantified — §2
- [ ] maximum group size stated, or client-computed cadence required
- [ ] RFC 0 §8.3's threshold corrected to depend on traffic mix
- [ ] RFC 2's status resolved — retired or reduced
- [ ] SIM-2 models fan-out, settling §1 empirically
- [ ] fan-out detectability measured before a stagger mechanism is specified
- [ ] channel growth rate estimated against `class_mask` defaults

Items 1 and 2 are done and are what RFC 6's cost sections should be built on.
