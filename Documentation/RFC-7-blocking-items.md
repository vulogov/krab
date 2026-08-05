# RFC 7 — Blocking Item Status

    Status:      Working document, not an RFC
    Purpose:     the gate on RFC 7 reaching Draft
    Grounding:   RFC-1.md, RFC-1-review.md, SIM-1-results.md, rfc-7-runs/
    Depends on:  RFC 1

RFC 7 specifies key custody and erasure: the key hierarchy, crypto-shredding,
the epoch-chunked reservoir, and memory hygiene.

It became load-bearing when RFC 1 reached Draft. **RFC 1 §6.5 states that "the
epoch-chunked key reservoir (RFC 7) is Krab's primary post-quantum strategy,
not a secondary one"** — on the measured grounds that a per-message hybrid KEM
inflates the smallest objects 16×. RFC 1 is frozen and cannot be revised, so
RFC 7 now has to deliver a mechanism another frozen document depends on.

RFC 7 is itself revisable; the reservoir is not in the identifier hash.

Reproduce the arithmetic below with `rfc-7-runs/reservoir.py`.

---

## 1. The finding that changes the design

### Forward-secrecy granularity is bounded below by `MAX_TTL`, not by `EPOCH`

The reservoir's forward secrecy comes from erasing chunk *N* once epoch *N* is
past. The plan says "chunk erased at epoch close plus grace" without sizing
the grace.

It cannot be short. Chunk *N* decrypts objects whose tag epoch is *N*, and
RFC 1 §6.2 — as corrected in this repository — requires accepting such an
object up to `MAX_TTL / EPOCH` epochs later:

```
EPOCH 1 day, MAX_TTL 45 days
  => chunk N MUST survive until N+45
  => 45 chunks live at any time (1 440 B, trivial)
  => seizure at time T exposes epochs T-45d .. T
```

**So the reservoir's forward-secrecy window is 45 days regardless of epoch
length.** Shortening `EPOCH` to an hour would not improve it; lengthening it
to a week would not worsen it.

This decouples two things that RFC 0 §11 explicitly binds together — "epoch:
the rotation period shared by tag derivation, key erasure, and the reservoir.
One clock, one counter." One counter is fine. One *retention policy* is not:
tag unlinkability wants short epochs, and key erasure is pinned to `MAX_TTL`
regardless. RFC 7 must state that erasure lags rotation by 45 epochs, and
RFC 0 §11's terminology entry should stop implying they are the same period.

It is the same defect class as the `EPOCH_WINDOW` bug found in RFC 1 §6.2 —
a retention parameter derived from expected behaviour rather than from the
protocol's own declared guarantee — and it propagates from that one. Anyone
who fixes `EPOCH_WINDOW` without fixing chunk retention has moved the failure
from "recipient never computed the tag" to "recipient destroyed the key."

**Normative consequences.**

- Chunk retention MUST be `≥ MAX_TTL / EPOCH`. State it as that expression,
  not as a number, so it cannot drift out of step with `MAX_TTL` again.
- RFC 7 MUST state the 45-day forward-secrecy floor plainly. It is the honest
  answer to "how much does a seizure cost me," and it is not what "erased at
  epoch close" implies.
- Panic wipe and the dead-man timer (plan §RFC 7) are the only mechanisms that
  reduce the 45-day exposure, which makes them more important than they look —
  they are not redundancy over crypto-shredding, they are the only lever on
  the window.

---

## 2. Settled by arithmetic

### The reservoir should be established by hybrid KEM, not by physical exchange

The plan lists reservoir establishment as "physical exchange with
`pad = R_A ⊕ R_B`, or a single hybrid PQ KEM amortized across the reservoir's
lifetime" — physical first. The economics say the reverse.

From `krab-sizes`, for a 280-byte message:

| | cost |
|---|---|
| per-message hybrid surcharge | 3 072 B/message (4 096 vs 1 024 bucket) |
| reservoir setup, one hybrid KEM | 4 096 B, once per correspondent |
| **crossover** | **1.33 messages** |
| after 100 messages | 4 096 B against 307 200 B — 75× |

**A hybrid-KEM-established reservoir pays for itself before the second
message.** Since RFC 3 §11.1 already concedes that remote peering is the
common case, and RFC 1 §6.5 says suite `0x0002` "MUST NOT be a deployment-wide
default," the reservoir has to be reachable without a physical meeting or
Krab has no post-quantum story for most correspondents.

RFC 7 SHOULD therefore make hybrid-KEM establishment the default path and
physical exchange the higher-assurance option, rather than the other way
round.

### The ratchet preserves post-quantum security — state why

`reservoir_{n+1} = HKDF(reservoir_n ‖ DH(fresh))` uses X25519, and the plan
separately warns that "a reservoir transferred under X25519 alone provides no
PQ benefit." Read quickly, those contradict.

They do not. A quantum adversary recovers `DH(fresh)` but not `reservoir_n`,
so `reservoir_{n+1}` stays unknown **provided the root of the chain was
PQ-established**. The ratchet supplies compromise recovery; the root supplies
post-quantum security; neither substitutes for the other.

This matters practically, because it is what keeps reservoirs small — they
need only span the maximum interval between contacts, not a lifetime:

| reservoir span | size | QR codes at EC-M |
|---|---|---|
| one credential term (90 d) | 2 880 B | 1.2 |
| one year | 11 680 B | 5.0 |
| five years | 58 400 B | 25.1 |

RFC 3 §11 puts reservoir exchange in the QR-code ceremony. Only a
credential-term-sized reservoir is QR-practical there; a multi-year one needs
a file. Since the ratchet removes any need for a multi-year reservoir, RFC 7
should size it to one credential term and say so.

---

## 3. Open, with no grounding

### Prekey burn rate is unestimated, and it degrades silently

RFC 1 §6.3 makes prekey exhaustion invisible in the envelope by design. RFC 8
adds a `keys` command specifically because "forward secrecy degrades silently
otherwise." Nobody has computed the rate.

Two multipliers compound it, both introduced after the tier design:

- **RFC 3 §14** makes each device its own node and the operator a group, so
  fan-out multiplies by device count.
- **RFC 6** fan-out is N single-recipient sealed objects, so prekey burn
  scales with group size.

A node that exhausts one-time prekeys falls back to the signed-prekey tier,
where RFC 0 §7.5 says forward secrecy is bounded by the signed-prekey rotation
period rather than by the epoch. The fallback is silent, and with the §1
finding above the exposure floor is already 45 days.

**To settle:** compute burn against SIM-0's traffic model (2 messages/node/day)
across realistic roster and device counts, and derive a batch size and
republication cadence. This is arithmetic, not simulation.

### Unmeasured, lower priority

- **Argon2id parameters.** Must be chosen against the weakest supported
  device, which for Krab includes whatever runs a LoRa node.
- **Memory hygiene is unverifiable in Rust.** The plan already concedes this
  ("Rust cannot guarantee a secret was never copied"). RFC 7 should say what
  is actually checked rather than what is intended.
- **Dead-man timer default.** Interacts with the 45-day floor in §1 and with
  courier deployments where a node is legitimately offline for months —
  precisely the population most likely to trip it accidentally.

---

## 4. Consistency items for other documents

- **RFC 0 §11** defines epoch as one period shared by tag derivation and key
  erasure. §1 above shows erasure lags by `MAX_TTL / EPOCH`. Update.
- **RFC 0 §7.5** bounds pre-forward-secrecy exposure by the signed-prekey
  rotation period. With §1's floor, the binding constraint is
  `max(rotation period, MAX_TTL)`. Update.
- **RFC 1 §6.5** is frozen and correct as written, but its claim now depends
  on RFC 7 delivering hybrid-KEM establishment as a routine path. If RFC 7
  makes physical exchange the only practical route, RFC 1's post-quantum
  position is weaker than the document states.

---

## 5. Gate

RFC 7 may reach Draft when:

- [x] forward-secrecy floor identified and quantified — 45 days, §1
- [ ] chunk retention specified as `≥ MAX_TTL / EPOCH`, and the floor stated
      plainly in security considerations
- [x] establishment path chosen on cost — hybrid KEM default, §2
- [ ] reservoir span specified — one credential term, per §2
- [ ] ratchet's PQ property stated explicitly, with the root condition
- [ ] prekey burn rate computed under RFC 3 §14 and RFC 6 fan-out
- [ ] Argon2id parameters chosen against the weakest supported device
- [ ] panic wipe and dead-man timer specified, including the courier-offline
      false-positive case
- [ ] external cryptographic review of the reservoir construction and its
      interaction with tag derivation (RFC 0 §9, RFC 1 §13)

The last item is the same one RFC 1 §13 flags: the primitives are standard,
the composition is novel, and the reservoir/tag interaction is the most novel
part of it.
