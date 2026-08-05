# RFC 4 — Blocking Item Status

    Status:      Working document, not an RFC
    Purpose:     the gate on RFC 4 reaching Draft
    Grounding:   SIM-0, SIM-1, RFC-1.md, RFC-3.md, RFC-6.md, RFC-7.md, rfc-4-runs/
    Depends on:  RFC 0, RFC 3

RFC 4 specifies the `Fabric` boundary, `LinkProfile`, the Noise wire, and the
concrete backends.

It has one job the rest of the series is waiting on: **four documents assume
four different values for LoRa's `max_object_size`, and RFC 4 owns
`LinkProfile`.** §1 settles it. Everything else in this document is smaller.

Reproduce with `rfc-4-runs/lora-gate.py`.

---

## 1. The LoRa gate, settled

| document | assumed gate | what it concluded |
|---|---|---|
| SIM-0 model | 512 B | LoRa carried 0.16% of objects |
| RFC 1 §8.3 | ≥ 4 096 B | tabulates airtime for the 4096 bucket |
| RFC 6 §2.4 | 256 B | groups over LoRa ≤ 10 members |
| RFC 7 §5.4 | 512 B | no prekey batch can cross; reservoir is the only FS mechanism |

### 1.1 A correction to this repository's SIM-0 audit

`SIM-0-audit.md` §1 reported that LoRa carried **0.16%** of objects. That is
correct as a description of the simulator, which gates on `o.size` — the raw
message body. **It is optimistic about reality**, because RFC 1 gates the
encoded, padded object, and SIM-0's smallest text body of 500 B encodes to
**668 B and pads to the 1024 bucket**:

```
gate    buckets admitted     share of SIM-0's text traffic
 256                 256                             0.0%
 512                 256                             0.0%
1024            256, 1024                            4.8%
4096      256, 1024, 4096                           45.7%
```

At a 512-byte gate, **nothing SIM-0 generates crosses at all** — not 0.16%.
A 256-bucket object requires a body of ≤ 90 bytes (RFC 1 §8.1), and SIM-0
produces none.

The audit's conclusion — that the LoRa figures describe a network with inert
radio links — stands and is strengthened. The number should be restated.

### 1.2 No gate makes LoRa a flooding transport

LoRa's daily budget is 0.85 B/s × 86 400 s = **73 440 B/day**:

| bucket | frames | airtime | objects/day |
|---|---|---|---|
| 256 | 6 | 0.1 h | 286.9 |
| 1 024 | 21 | 0.3 h | 71.7 |
| 4 096 | 81 | 1.3 h | 17.9 |
| 16 384 | 322 | 5.4 h | 4.5 |

Against a flood requirement of 1 000 objects/day at n=500:

| gate | objects/day | share of flood |
|---|---|---|
| 1 024 | 71.7 | 7.17% |
| 4 096 | 17.9 | **1.79%** |
| 16 384 | 4.5 | 0.45% |

This confirms SIM-1 §1's ~2% figure from a different direction and settles the
question of what a LoRa link is *for*.

### 1.3 Recommendation

```
LoRa max_object_size = 4096 bytes.
A LoRa LinkProfile MUST carry a non-trivial shard_filter and class_mask.
A LoRa link MUST NOT be a node's only link (SIM-0 §3, RFC 0 §8.1).
```

4 096 admits 45.7% of realistic traffic at 1.3 h per object, and matches
RFC 1 §8.3's existing airtime table, which is the only place a gate value was
already implied by a Draft document. Below it the link carries essentially
nothing; above it a single object costs a fifth of a day's airtime.

The shard and class filter requirement is not advisory. At 17.9 objects/day a
LoRa link cannot carry an unfiltered corpus at any network size, so a profile
without a narrow filter is misconfigured by construction — and per SIM-1 §1 it
must also use RBSR, since a full manifest starves it.

### 1.4 Consequences for documents at Draft

- **RFC 7 §5.4 survives with a corrected gate.** At 4 096 B a 64-key batch
  (2 168 B → 4096 bucket) *does* cross, so "prekey-based forward secrecy is
  structurally unavailable to a LoRa-only correspondent" is too strong. What
  survives: at 17.9 objects/day, one republication costs 5.6% of a day's
  airtime, so it is available but expensive, and the reservoir remains the
  better mechanism. `RFC-7-review.md` §2 anticipated this.
- **RFC 6 §2.4's LoRa table understates airtime ~4×.** It costs a group
  message at the 256 bucket, which no message carrying a body occupies. At the
  realistic 1024 bucket:

  | G | RFC 6 says | at the 1024 bucket |
  |---|---|---|
  | 5 | 0.3 h | 1.3 h |
  | 10 | 0.8 h | 3.0 h |
  | 20 | 1.6 h | **6.4 h** |

  The recommendation — groups over LoRa ≤ 10 members — is if anything too
  generous: at G=10 a single group message is three hours of airtime.
- **RFC 2 §8.1 point 4** cites "LoRa's 512-byte gate" and should cite 4 096.
  Its conclusion changes as in the first bullet.

---

## 2. `latency_class` must be in the signed credential

`RFC-3-review.md` §4: RFC 3 §3 key 9 `transports` is "endpoint list; MAY be
empty." SIM-1 §1 established that reconciliation strategy has no safe default —
a full manifest starves 98.3% of LoRa reconciliations, RBSR collapses austere
delivery from 95.8% to 33.0% — and RFC 5 must therefore select per link from
`latency_class`.

`latency_class` belongs to RFC 4's `LinkProfile`. But the credential is what
tells a peer which profile applies *before any connection exists*, which on a
courier link is the only time it can be told. Two consequences:

- RFC 5 cannot make its choice from signed data.
- A peer can induce the catastrophic strategy by misdeclaring, because nothing
  signed contradicts it.

**RFC 4 must define `latency_class` as a value carried in RFC 3's credential,
not merely as a local profile field.** This is a change to RFC 3 §3's field
table, which is revisable.

```
LatencyClass = Interactive | Delayed | Sneakernet
sync_mode    = Rbsr        for Interactive and Delayed
             = FullManifest for Sneakernet
```

The mapping is normative and derives from SIM-1 §1, not from preference.

---

## 3. AX.25 excludes the class Krab exists to carry

47 CFR 97.113(a)(4) prohibits encrypted transmissions on amateur bands. A
Krab `sealed` object is indistinguishable from random bytes by design
(RFC 0 §7.1), which is precisely what the regulation forbids.

```
An AX.25 LinkProfile MUST set class_mask to bulletin only.
An AX.25 LinkProfile MUST NOT carry sealed, cover, or short objects.
```

This makes an amateur-radio link a **channel-carriage-only** transport, which
interacts with RFC 6 §3.4's requirement that channel carriage be off by
default: enabling an AX.25 link necessarily enables channel carriage, and
RFC 6 §3.6's "channels change what a node is" warning must fire at that point
too.

Station classification under Part 97 — whether an automatically-forwarding
Krab node is a repeater, a message forwarding system, or something else — is a
question for licensed review and should be flagged rather than answered here.

---

## 4. Inherited requirements

- **Head-of-line blocking.** The SIM-0 audit §4 found `break` where `continue`
  was meant: one oversized object at the head of an oldest-first transfer
  wedges the link permanently. RFC 5 owns reconciliation, but RFC 4 owns the
  capacity model that produces the condition, and the two must agree that a
  transfer skips rather than halts.
- **Retention as capacity, not promise.** `RFC-3-review.md` §3: SIM-1 §4's
  +68% re-fetch loop survives because retention is what a node promised, not
  what it can hold. A `LinkProfile` knows the local storage budget and is the
  natural place to compute the difference.
- **Courier container.** Flat framed byte stream, filenames ignored, every
  object hash-verified on ingest, and **a foreign database file is never
  opened** — the container is data, not a program. Already stated in the plan
  and worth carrying verbatim.
- **Tor.** Contact and sync endpoint split (RFC 3 §9.2), restricted discovery,
  and the no-key-derivation-from-identity rule: the onion key is separate and
  the address appears only inside the private credential.

---

## 5. Open, with no grounding

- **Noise IK handshake DoS.** The plan calls for timeouts and
  concurrent-handshake caps; neither is sized. Unlike the decapsulation caps
  in RFC 2 §7.4, there is no measurement to derive them from.
- **FEC parameters.** RFC 6330 RaptorQ is named; no redundancy ratio is chosen,
  and the right ratio depends on a per-link loss rate nobody has measured.
- **Serial and X.25 profiles** are named in RFC 0 §1 and specified nowhere.
- **Whether a gateway can transcode between link codecs without fracturing the
  corpus** is asserted by RFC 1 §3 — armor and FEC sit outside the identifier —
  but has never been tested end to end. This is cheap to test and belongs with
  RFC 0 §9's courier-only gate.

---

## 6. Gate

RFC 4 may reach Draft when:

- [x] LoRa `max_object_size` pinned — 4 096 B, §1
- [ ] the four documents citing other values corrected — §1.4
- [ ] `latency_class` defined and required in RFC 3's credential — §2
- [ ] `sync_mode` mapping from `latency_class` stated normatively — §2
- [ ] AX.25 class restriction stated, with the RFC 6 interaction — §3
- [ ] `Fabric` trait and `LinkProfile` field set frozen
- [ ] Noise IK handshake caps sized
- [ ] gateway transcode tested end to end

§1 is done and is what the rest of the series has been waiting on.
