# RFC 4 — Review

    Subject:  RFC 4, Transport and Link Profiles, Status: Draft
    Method:   cross-check against RFC 0/1/3/5/6/7, SIM-0, SIM-1, apps/krab-sizes
    Verdict:  one agreement defect, one stale deferral, two understated numbers

RFC 4 settles the LoRa gate the series has been waiting on, and settles it
better than `RFC-4-blocking-items.md` did — §2 below withdraws that document's
recommendation in favour of RFC 4's.

## Every figure verifies

`apps/krab-sizes` gained a `transport` module. All five tables reproduce:
Noise IK sizes, the framing overhead table across all six buckets, the LoRa
spreading-factor table including the 7.7× SF7/SF10 ratio, the fragmentation
table with 6-byte headers and 20% RaptorQ repair, and the serial table against
SIM-0's 447 MB corpus. 43 tests now pass across RFC 1, 2, 3, 4, 6 and 7.

Two small things. RFC 4 §5.4 says "SIM-0 modelled 0.83 B/s at SF10"; SIM-0's
`model.rs` uses **0.85**. The 2.4% gap changes nothing and the conclusion —
SIM-0's LoRa findings stand — is right. And §5.4's SF12 sustained rate of
0.2068 B/s prints as "0.21", which is two significant figures rather than an
error.

---

## 1. Agreement defect — `sync_mode` cannot be a local field

§3 lists which `LinkProfile` fields come from the signed credential:

> `quota`, `retention`, `shard_mask`, and `class_mask` derive from the signed
> `peer-link` credential, so **both sides provably agree on the
> reconciliation filter** (RFC 3 §7.3). The remaining fields are local.

`sync_mode` and `latency_class` are among the remaining fields.

That cannot hold. Reconciliation is a two-party protocol: if A runs
`Manifest` and B runs `Rbsr`, they do not reconcile — they fail to agree on
the shape of the exchange itself. The argument §3 makes for the filter applies
with more force to the strategy, because a filter mismatch produces phantom
divergence that recurs (RFC 3 §7.3) while a strategy mismatch produces nothing
at all.

The stakes are the ones SIM-1 §1 measured. Picking wrong is not a degradation:

- full manifest on a constrained link — **98.3% of reconciliations starved**
- RBSR on a courier link — **austere delivery falls 95.8% → 33.0%**

And because `latency_class` is local, a peer can induce either outcome by
misdeclaring, with nothing signed to contradict it. `RFC-3-review.md` §4 and
`RFC-4-blocking-items.md` §2 both raised this; RFC 4 §3 resolves it the wrong
way by putting both fields on the local side of the line.

**Fix.** `latency_class` MUST be carried in RFC 3's credential — a change to
RFC 3 §3 key 9, which is revisable — and `sync_mode` MUST be derived from it
by a normative mapping rather than configured. RFC 4 already has the mapping
implicitly; it needs stating:

```
Interactive, Batch  ->  Rbsr
Courier             ->  Manifest
```

---

## 2. RFC 4's LoRa cap supersedes the gate document's

`RFC-4-blocking-items.md` §1.3 recommended `max_object_size = 4096`. **RFC 4
§5.4 caps at bucket 1024 for SF7–SF10, and is right.** The gate document's
model omitted fragmentation and FEC:

```
a 1024-byte object at SF10 costs 28 fragments x 51 B = 1428 B on the wire
  = 39% more than the object
  = 51 objects/day, not the 72 the gate document computed
```

At bucket 4096 the same accounting gives 1.9 hours per object, which is what
makes RFC 4's tighter cap the correct call. The gate document overstated LoRa
throughput by 39% throughout; RFC 4's numbers replace it.

§3's treatment of `max_bucket` as **a bucket index rather than a byte count**
reaches the gate document's §1.1 finding independently and states it better:

> A byte gate that falls between buckets — 512 bytes, say — admits nothing
> above the 256-byte bucket while appearing to admit more.

That is exactly why SIM-0's 512 B gate carried nothing, and expressing the
field as an index makes the class of error unrepresentable.

### 2.1 What the cap costs, and is not stated

At bucket 1024, the share of SIM-0's text traffic that fits a LoRa link is
**4.8%**. At bucket 4096 it would be 45.7%.

So RFC 4's cap is correct on airtime grounds and leaves a LoRa peer unable to
receive roughly nineteen out of twenty ordinary messages — regardless of
budget, filter, or patience. That is consistent with everything else the
series has found about LoRa, and it is the operative consequence for anyone
deciding whether to deploy one. §5.4 gives the airtime and omits the coverage.

---

## 3. §5.4 defers to SIM-1, which is complete

> "Whether filter-scoping keeps the LoRa-eligible set below that is the open
> question assigned to SIM-1 (RFC 0 §9)." — RFC 4 §5.4

SIM-1 has been run. This is the same staleness `RFC-1-review.md` §2 found in
RFC 1 §9.3, and the answer is more specific than the deferral expects:

- at a narrow filter, the manifest is ~1.2 KB against an 18.4 KB window — but
  **90–95% of every byte a LoRa link carries is control traffic**
- at a filter wide enough to matter, a full manifest **starves 98.3%** of
  reconciliations
- RBSR fixes it — 0.3% starved, 13.3 KB payload per sync, a 66× improvement

That last point is the one §5.4 needs, because it is a `LinkProfile`
requirement and RFC 4 owns `LinkProfile`: **a LoRa profile MUST set
`sync_mode = Rbsr`.** §5.4 currently says nothing about `sync_mode` at all.

---

## 4. Gaps

**No "LoRa must not be a node's only link" requirement.** RFC 0 §8.1 states it
for courier — a courier-only node must be a leaf attached to a
better-connected peer — and the case for LoRa is stronger, since §5.4's own
numbers put it below courier. `RFC-4-blocking-items.md` §1.3 proposed it;
RFC 4 does not carry it.

**"Airtime" names two quantities.** §5.4's fragmentation tables report
duty-cycle-limited *elapsed* time — 8 fragments at SF10 is 4.9 s of
transmission but 8.2 minutes of wall clock. §4.1's "approximately 3 minutes of
airtime" for the handshake is the elapsed figure, while RFC 4's own computed
output reports the same handshake as **1.50 s**, which is raw transmission.
Only the elapsed figure is what a link costs. The tables are internally
consistent; the two senses should be named.

**§8's `short` keying.** "Keyed from the pairwise reservoir in the credential"
— RFC 7 §6.4 requires that the reservoir material MUST NOT appear in the
credential, which records only an identifier and epoch. The intent is right
and the wording implies otherwise.

---

## 5. What RFC 4 got right

- **§2's mechanical enforcement of I-4.** "If the courier backend cannot
  implement an operation, that operation does not belong in the protocol."
  This turns RFC 0's boundary rule from a review convention into a structural
  property of the trait, and it is the strongest single idea in the document.
- **§4.3's rejection of ZMQ**, and specifically the third reason — a socket
  cannot degrade to a file, and the courier archive *is* the control-message
  sequence with round trips removed. That reasoning generalises and is worth
  citing whenever a transport abstraction is proposed.
- **§5.2's three reasons the onion key must not derive from identity**, of
  which cross-protocol key reuse is the one most often missed.
- **§5.5's refusal to open a foreign SQLite file**, with the reasoning stated
  rather than assumed. Naming the tempting wrong answer is what stops it being
  reproposed, and the `MANIFEST.hjson` carve-out — a human reads it, nothing
  signs it, nothing hashes it — draws the line in exactly the right place.
- **§7 turns the amateur-band restriction into a feature.** Bulletin-only
  carriage is a real mode, and requiring explicit acknowledgement before
  enabling an amateur link addresses the LoRa/amateur confusion directly.
- **§5.3 makes the case for serial**, which the series had left as a name in a
  list. Eleven hours for a full corpus at 115 200 baud is four orders of
  magnitude better than LoRa and deserves the attention.

---

## 6. Consistency items

- **RFC 3 §3 key 9** — must carry `latency_class`, not just endpoints. §1.
- **RFC 4 §3** — `sync_mode` and `latency_class` must move to the
  credential-derived side. §1.
- **RFC 4 §5.4** — must set `sync_mode = Rbsr` for LoRa, and cite SIM-1
  rather than deferring to it. §3.
- **RFC 2 §8.1 point 4 and RFC 7 §5.4** cite a 512-byte LoRa gate. Under
  RFC 4 §5.4 the cap is bucket 1024, so a 64-key prekey batch (2 168 B →
  4096 bucket) still does not cross. Their conclusions survive; their cited
  number does not.
- **RFC 6 §2.4** costs group messages at the 256 bucket. Under RFC 4's cap the
  relevant bucket is 1024, which is where the ~4× airtime understatement
  `RFC-4-blocking-items.md` §1.4 identified comes from.
