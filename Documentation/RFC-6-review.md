# RFC 6 — Review

    Subject:  RFC 6, Groups and Channels, Status: Draft
    Method:   cross-check against RFC 0, RFC 1, RFC 3, RFC 7, SIM-0, apps/krab-sizes
    Verdict:  one unimplementable requirement, one understated cost, three gaps

RFC 6 is revisable. Its §1 framing — two mechanisms with opposite security
models *and* opposite cost classes, where the choice is arithmetic rather than
preference — is the clearest organising idea in the series, and §4's crossover
table is what the plan's group section was missing.

## Every figure verifies

`apps/krab-sizes` gained a `groups` module. All five tables reproduce exactly:

- §2.3's fan-out table — objects/day, MB/day, share of baseline, received/day,
  across all eight group sizes
- §2.4's fan-out-versus-shared-key ratios and the LoRa frame/airtime table
- §2.7's stagger windows at all three network sizes
- §2.8's prekey burn, matching RFC 7 §5.3 including the 8 192-key overflow
- §3.3's channel table

28 tests now pass across RFC 1, RFC 3, RFC 6 and RFC 7.

Two presentational notes. §2.3 costs a group message at the 1 KB bucket while
§2.4's LoRa table costs the same message at 256 B; both reproduce only with
their own constant. And **the "380×" in §2.4 and §3.3 is per-author, not
per-message** — it compares a 20-author group (760 objects/day) against a
single-author channel at the same per-author rate (2 objects/day). The
like-for-like per-message figure is **19×**, which is the number §2.4's own
ratio table uses. The claim is true as stated; it just flatters.

---

## 1. Unimplementable — "separate shard space" does not follow from RFC 1

§3.4 requires:

> Channels MUST occupy a separate shard space from sealed traffic.

RFC 1 §5.4 defines `shard = leading k bits of tag`, and RFC 1 §5.2 sets a
bulletin's tag to the leading 8 bytes of `BLAKE3("krab/chan/v1" ‖ channel_id)`.
That is uniformly distributed over exactly the same tag space that sealed tags
(HKDF outputs) occupy. **There is no separate shard space to occupy** — both
classes populate every shard uniformly, and a peer filtering on shard `0x0F`
receives both.

RFC 1 is frozen, so the tag derivation cannot change.

The *intent* is achievable, and RFC 6 already specifies the mechanism that
achieves it one line earlier: `class_mask`. What is not currently specified
anywhere is a **per-class shard mask** — a filter of the form
`(class, shard_prefix)` rather than a single shard prefix applied to
everything. That is RFC 5's filter design, and RFC 5 does not exist yet.

**Fix.** Either drop the sentence and rely on `class_mask`, or restate it as a
requirement on RFC 5's filter: shard masks MUST be expressible per class. The
second is better, because §3.4's next paragraph — acceptance by shard prefix so
a peer learns only 1/2^k of your channel interest — genuinely needs a channel
shard mask independent of the mail shard mask to work.

---

## 2. Understated — §2.3 reports one group, not a network that uses groups

§2.3's share-of-baseline column is computed for **one** group against the
entire network's traffic. At G=20 that is 3%, which reads as comfortable.

But if group messaging is normal rather than exceptional, every authored
message becomes G−1 objects network-wide, and the multiplier is **19×**, not
3%. In a 500-node network where everyone is in one 20-person group there are
25 such groups, and 25 × 0.78 MB/day is 19.5 MB against a 31 MB baseline.

That moves a threshold RFC 0 states as a property of network size:

| deployment | ingress multiplier | sharding mandatory above |
|---|---|---|
| no groups (RFC 0 §8.3's assumption) | 1× | ~4 900 nodes |
| 10-person groups typical | 9× | ~550 nodes |
| **20-person groups typical** | **19×** | **~260 nodes** |
| 50-person groups typical | 49× | ~100 nodes |

RFC 0 §8.3's "sharding is mandatory above approximately n = 5 000" is derived
from SIM-0 §7's 0.063 MB/day-per-node-per-node, which was measured with one
object per message. **RFC 6 is the document that invalidates it and does not
say so.**

The decision to put the shard field in v1 regardless is vindicated — it is
inside the identifier hash and could not have been added later. But the
operator-facing threshold is wrong for any deployment that uses groups, and
§2.3's framing does not surface it.

**Fix.** State the systemic multiplier alongside the per-group figures, and
correct RFC 0 §8.3 to make the threshold a function of traffic composition.
A node can measure its own mean fan-out locally from roster sizes, so the
client warning RFC 0 §8.2 already requires for peer count has an obvious
sibling here.

---

## 3. Gap — the measurements do not cover fan-out at all

Neither SIM-0 nor SIM-1 models groups: `sim.rs` emits one object per message
with a single destination. So every corpus, ingress, storage and convergence
figure RFC 6 cites as a baseline — including the 31 MB/day it measures
everything against — describes a network with no groups in it.

RFC 6 uses those figures correctly as a *baseline*. The gap is that the
combined behaviour has never been simulated: fan-out interacts with
capacity-pressure eviction (SIM-1 §4), with the holdings-analysis adversary
(SIM-1 §3, where 19 correlated objects per message is new signal), and with
reconciliation overhead (SIM-1 §1, where object count drives manifest size).

None of those interactions is obviously benign, and §2.7's stagger requirement
is an attempt to manage one of them by reasoning alone. Adding fan-out to
`krab-sim` is cheap — draw a roster size, emit G−1 objects with distinct
destinations — and it should be SIM-2's second item after quota-versus-vantage.

---

## 4. Gap — §2.7's stagger is a heuristic, and its latency cost is unstated

The window derives from a "≤10% local rate lift" threshold. Ten percent is
asserted, not derived from any detection model — SIM-1 §3 built exactly the
machinery that could measure what lift is actually detectable, and it was not
used here.

The latency cost is also understated. §2.7 says "Krab already tolerates days
of latency, so the cost is nil," but the worst case is the early deployment:

| network | G=20 | G=50 |
|---|---|---|
| n=100 | 22.8 h | **58.8 h** |

At n=100 a 50-member group — permitted, since §2.4 only refuses above 50 —
needs a **2.5-day** emission window *before* Poisson propagation begins, on
top of SIM-0's austere median of 170 h. RFC 6 notes the counterintuitive
direction (small networks need longer windows) but does not draw the
conclusion: **the mechanism is most burdensome exactly when the network is
youngest and least able to absorb it.**

§6's observation that stagger will be optimised away by someone chasing
perceived latency is correct and well made. The test it asks for — measuring
inter-object emission gaps — is the right shape.

---

## 5. Gap — the LoRa recommendation rests on the contested gate

§2.4 recommends groups over LoRa stay ≤10 members, costing the group message
at the 256-byte bucket. That bucket fits every LoRa gate under discussion, so
the recommendation holds either way — but the underlying question is still
open: RFC 7 §5.4 assumes a 512 B LoRa gate, RFC 1 §8.3 tabulates airtime to
4 096 B, and the SIM-0 audit found the 512 B figure makes LoRa carry 0.16% of
objects.

RFC 4 must pin one number. Until it does, three documents are reasoning about
LoRa from different assumptions.

---

## 6. What RFC 6 got right that was open

- **The RFC 2 dependency is gone.** RFC 6 requires RFC 0, 1, 3 and 7 — correct,
  since RFC 1 absorbed tag derivation, shard extraction, the epoch window and
  prekey selection. RFC 0 §10's roadmap still lists RFC 2 as freezing a tag
  scheme RFC 1 has already frozen, and should be updated.
- **§2.8 folds group membership into RFC 7's prekey arithmetic** and reaches
  the same 8 192-key overflow independently. The requirement that clients warn
  *at join time* rather than at failure is the right place for it.
- **§3.2's refusal chain for shared-write channels** — anyone can post →
  moderation required → authority required → infrastructure required → RFC 0
  §6 forbids it — is four steps and airtight. Recording it as non-negotiable
  is what stops it being reproposed.
- **§2.5 records the rejected hub-and-spoke alternative** rather than leaving
  it to be rediscovered.
- **§6's note that channel posts survive epoch erasure** is a genuinely
  important asymmetry that RFC 7 §8 does not state from its side: erasure
  makes your own archive unreadable, but a bulletin you signed is plaintext
  an archivist keeps forever.

---

## 7. Consistency items for other documents

- **RFC 0 §8.3** — sharding threshold is a function of traffic composition,
  not network size. §2 above.
- **RFC 0 §10** — roadmap still lists RFC 2 as a dependency and a freeze
  point. RFC 1 has absorbed it.
- **RFC 5** (unwritten) — the filter must support per-class shard masks, or
  §3.4's channel-interest bucketing cannot be expressed. §1 above.
- **RFC 7 §8** — should note the channel asymmetry: cryptographic erasure
  covers sealed traffic and does not touch bulletins the same operator signed.
