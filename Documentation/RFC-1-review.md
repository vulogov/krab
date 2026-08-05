# RFC 1 — Review

    Subject:  RFC 1, Object Format and Cryptography, Status: Draft
    Method:   cross-check against SIM-0, SIM-0-audit, SIM-1, and krab-sizes output
    Verdict:  one blocking defect, one stale claim, three specification gaps

RFC 1 cannot be revised once objects exist. Everything below is therefore
worth resolving before Draft becomes Final, and item 1 is worth resolving
before anything ships at all.

## Byte counts verify

Every figure in RFC 1 was checked against the `krab-sizes` output:

- floor 150 B → 256 B bucket ✓
- all six bucket rows: 90/856/3 928/16 216/65 368/261 972 and 64.8/16.4/4.1/1.0/0.3/0.1 % ✓
- PQ floor 1 239 B → 4 096 B, 280-byte message 1 537 B → 4 096 B ✓
- LoRa airtimes: 6/21/81 frames, 301/1 205/4 819 s ✓
- manifest at 12 B ids: 0.2 / 1.6 / 8.0 MB ✓
- §7.2's 90 → 124 B (32 B key + 2 B CBOR) ✓

The arithmetic is sound. The findings below are about consistency, not
computation.

---

## 1. Blocking — `EPOCH_WINDOW` is smaller than `MAX_TTL`

`EPOCH` is 86 400 s and `MAX_TTL` is 45 days, so an object may legitimately
arrive **45 epochs** after its creation. The default `EPOCH_WINDOW` is
±30 epochs.

```
MAX_TTL 45 d  ->  arrival up to 45 epochs after creation
  EPOCH_WINDOW +/-30 (default)  ->  epochs 31..45 undecryptable  (15-epoch gap)
  EPOCH_WINDOW +/-45 (courier)  ->  OK
```

An object delivered inside the TTL the protocol itself declared valid, to a
recipient behaving correctly, cannot be decrypted — the recipient never
computed the tag. §11 check 2 accepts it, the store keeps it, and it is dead.
This is silent: RFC 0 §6 non-goal 6 already says failure is silent, so nothing
surfaces it.

§6.2 derives the window from *observed* delivery latency ("SIM-0 measured p99
of 382 hours (16 days)"). That is the wrong anchor. p99 is not a bound, and
the protocol's own guarantee is `MAX_TTL`, not a percentile. SIM-0's TTL-45
austere run has p99 at 441.9 h (18.4 d) with a tail beyond it, and courier
nodes are offline for exactly the periods this window must cover.

**Fix:** `EPOCH_WINDOW ≥ MAX_TTL / EPOCH`, i.e. ±45 unconditionally. The cost
is trivial and RFC 1 already computes it — 50 correspondents × ±30 is 3 050
tags; × ±45 is 4 550. One-off HKDF work on a table that is already
precomputed.

This is the cheapest finding to act on: `EPOCH_WINDOW` is a deployment
parameter that is not inside the identifier hash, so unlike everything else in
§2 it remains revisable. It should still be corrected before Final, because
the default is what implementations will ship.

---

## 2. Stale — §9.3 defers to SIM-1, which is complete and disagrees

> "Whether it is survivable in fact is the open question RFC 0 §9 assigns to
> SIM-1." — RFC 1 §9.3

SIM-1 has been run (`SIM-1-results.md` §1). The answer is not the one §9.3
anticipates, and RFC 1 contradicts itself on the way there.

§9.3 argues manifest exchange is survivable on LoRa because "the size gate
that makes LoRa slow also makes its eligible set small." That is true only at
a gate narrow enough to make the link useless. At SIM-0's shipped 512 B gate
the manifest is 1.2 KB against an 18.4 KB window — survivable, but the link
carries 0.16 % of objects and **90–95 % of every byte it moves is control
traffic**.

Meanwhile §8.3 tabulates LoRa airtime for buckets up to 4 096 B, so RFC 1
plainly expects LoRa to carry objects three orders of magnitude above that
gate. At that filter width SIM-1 measured, under a full manifest:

| mix | LoRa ctl% | payload KB/sync | reconciliations starved |
|---|---|---|---|
| mixed | 99.0 % | 0.2 | **98.3 %** |
| courier-heavy | 98.5 % | 0.3 | **97.8 %** |
| austere | 93.0 % | 1.3 | **89.4 %** |

*Starved* means control traffic consumed the entire window and no payload
moved at all. RBSR removes it (0.3 % starved, 13.3 KB payload/sync, 66×
throughput) — but RBSR collapses austere delivery from 95.8 % to 33.0 %,
because four fingerprint-tree descent levels cost four courier round trips of
three days each.

So §8.3 and §9.3 are inconsistent with each other: the filter width that makes
§8.3's airtime table meaningful is the one that makes §9.3's survivability
claim false.

**Fix:** §9.3 should cite SIM-1 rather than defer to it, and should state that
survivability depends on the reconciliation strategy, which is RFC 5's per-link
`sync_mode` decision. RFC 1 should not assert survivability on its own account.

---

## 3. Gap — key 3 `admission` has ambiguous presence, inside the identifier hash

§4.2 lists key 3 as "reserved, empty in v1"; §4.3 requires rejecting unknown
keys and mandates deterministic encoding.

It is not stated whether a v1 encoder MUST emit key 3 as a zero-length `bstr`
or MUST omit it. Both readings satisfy the text. Two conforming
implementations that read it differently produce **different identifiers for
identical content**, and since the identifier is the object's identity, the
corpus fractures along implementation lines — duplicate suppression fails,
reconciliation never converges, and there is no way to repair it later.

This is precisely the class of defect §1 says cannot be revised, and it costs
one sentence now.

**Fix:** state explicitly which. Omission is the better default — it saves
2 bytes in the bucket where they matter most (§8.1's 256 B bucket has only
90 B of usable body), and a future version that defines `admission` can add
the key under a new `ver`.

---

## 4. Gap — `MAX_OBJECT` leaves 5.3 % of the modelled traffic unrepresentable

`MAX_OBJECT` is 262 144 B. SIM-0's traffic model draws pictures uniformly from
[50 000, 500 000):

```
52.9% of pictures exceed MAX_OBJECT  =  5.3% of all objects
```

RFC 1 specifies no object-level chunking. §8.3's fragmentation is link-layer
and belongs to RFC 4 — it splits an object across frames, it does not split a
payload across objects. A 400 KB picture has no encoding under RFC 1.

The probable resolution is RFC 8's "re-encode, do not validate" rule, which
caps decoded pixel count and re-encodes to a canonical format, bounding output
below `MAX_OBJECT`. If so, **`MAX_OBJECT`'s enforceability depends on an RFC 8
client behaviour**, and that coupling is currently unstated in both documents.
A client that does not re-encode simply cannot send an ordinary photograph.

This also revises audit §6: `MAX_OBJECT` at 256 KB rather than the plan's
64 KB shrinks the conflict with SIM-0's traffic model considerably, and the
live object-count inflation that would have followed from a 64 KB cap
(≈ 1.4×) largely goes away. The B3 re-run I proposed is now much less urgent.

---

## 5. Gap — clock skew ±6 h is the one parameter with no grounding

Every other row of §2 traces to a measurement or an argument. Clock skew does
not, and §11 check 2 uses it on both sides of the expiry test.

The failure mode is specific to Krab's deployment envelope: a node that has
been air-gapped for months, or whose RTC battery died, returns by courier with
a clock off by far more than six hours. It then rejects objects that are
valid, or accepts objects that expired — and per §11 rejection is silent and
counts against the *peer's* quota, so a node with a bad clock quietly
penalises the peers doing the most to reach it.

**Fix:** either ground the number, or require nodes to detect gross skew from
peer-observed time during reconciliation and refuse to apply check 2 until
resynchronised. The second is more robust and belongs in RFC 5.

---

## 6. Minor

- **§5 class table vs §5.3.** The table presents class 2 `cover` as
  sealed/relayed, while §5.3 states cover traffic MUST use class 0 and class 2
  is reserved and unused. The reasoning in §5.3 is right; the table is what
  implementers will read. Mark the row reserved.
- **`krab-sizes` is not in the repository.** Every byte count verifies against
  the output, so the grounding is real — but a reader cannot reproduce it,
  which is the exact gap the SIM-0 audit was written about. RFC 1's own header
  says "Grounded by: krab-sizes". It should be committed alongside
  `krab-sim`, as `apps/krab-sizes`.
- **§13's tag-collision note.** "Adversarial collision is cheap (2³²)" — for
  an 8-byte (64-bit) tag the birthday bound is 2³², which is what is meant, but
  a *targeted* second-preimage on a specific tag is 2⁶⁴. Both matter and only
  one is stated; §6.4's mitigation addresses the first.

---

## What RFC 1 settles

Against `RFC-1-blocking-items.md`, RFC 1 closes every open B3 row:

| item | status before | RFC 1 |
|---|---|---|
| B2 field set | settled | unchanged, now with byte layout |
| B2 `expiry` resolution | settled (SIM-1 §3) | minute granularity, u32 |
| B3 identifier length | settled 32 B (SIM-1 §2) | 32 B canonical, 12 B in-range |
| B3 `MAX_TTL` | settled ≥ 30 d | 45 d |
| B3 default shard `k` | settled 0 | 0 |
| B3 max object size | **open** | 262 144 B — see §4 above |
| B3 epoch length | **open** | 86 400 s — see §1 above |
| B3 size buckets | **open** | six buckets, 256 B–256 KB |
| B3 clock skew | **open** | ±6 h — see §5 above |

The remaining gate items are §12's test vectors, two independent
implementations agreeing on them, and external cryptographic review of the
composition — which §13 correctly identifies as the real risk.
