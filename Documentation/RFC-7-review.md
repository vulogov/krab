# RFC 7 — Review

    Subject:  RFC 7, Key Custody and Erasure, Status: Draft
    Method:   cross-check against RFC 0, RFC 1, RFC 3, SIM-0, SIM-1, apps/krab-sizes
    Verdict:  ONE OPEN CRITICAL DEFECT (§6, see CRYPTO-REVIEW.md §1),
              plus one recurring defect, one contradiction, three gaps

RFC 7 is revisable — nothing in it is inside the object identifier hash. Its
§13 erratum to RFC 1 is the strongest piece of work in the series so far and
is treated as such below.

## Every figure verifies

`apps/krab-sizes` gained a `keys` module deriving RFC 7's arithmetic from the
constants RFC 7 states (32 B chunks, 60 B wrapped records, 100 µs per X25519
decapsulation, 416 B credentials from RFC 3). All four tables reproduce
exactly on the first run:

- reservoir sizing at 30/45/60/90 epochs, per peer and at 25 peers, and the
  11 680 B peer-year
- §6.1's headline — raw pad 74 752 000 B against reservoir 11 680 B, exactly
  **6 400×**
- §5.3's six batch rows: needed, batch, wire, bucket, including 8 192 keys
  exceeding `MAX_OBJECT` at 262 264 B
- §5.5's decapsulation costs, both columns, and the 200-object figures
  (30.7 s / 122.9 s / 0.06 s)
- §2.1's footprint, line by line, totalling 82 732 B

One constant is **recovered rather than derived**: the prekey batch wire size
is `32·N + 120`, and RFC 7 does not decompose the 120. A `bulletin` body per
RFC 1 §5.2 does not obviously account for it. Same class as RFC 3's fragment
wrapper and RFC 1's floor — the number is self-consistent across all six rows,
but a reader cannot check it.

---

## 1. Recurring defect — retention is still anchored to latency, not to `MAX_TTL`

This is the third appearance of one mistake, and the first two are already
fixed in this repository.

RFC 7 states its retention rules against measured behaviour:

> §12: "The grace window … must exceed maximum delivery latency"
> §5.2: "Retire a batch at expiry plus a grace window of roughly 2× maximum
> delivery latency"

But the protocol's guarantee is not a latency percentile. RFC 1 §11 check 2
accepts any object whose `expiry_min` is within `MAX_TTL` — 45 days — and
RFC 1 §6.2 (as corrected here) requires computing tags across that whole span.
Against SIM-0's measured tails:

| | latency | 1× | 2× | `MAX_TTL` |
|---|---|---|---|---|
| austere p99 | 15.9 d | 15.9 d | 31.9 d | **45 d** |
| all-courier p99 | 16.9 d | 16.9 d | 33.9 d | **45 d** |

**Both rules under-provision.** A chunk erased at 1× or 2× maximum observed
latency is destroyed while objects it decrypts are still valid, still
in flight, and still being offered by peers. The recipient accepts the object
under §11, stores it, and cannot read it — the exact failure the `EPOCH_WINDOW`
fix removed from RFC 1, reintroduced one layer down.

RFC 7's own arithmetic already uses the right number: §2.1 computes the
footprint at 45-epoch retention, and the reservoir table offers 45 as a row.
**The number is right and the rule that generates it is wrong**, which is the
dangerous combination — it works today and breaks silently the first time
`MAX_TTL` moves or an implementer follows §12 literally.

The pattern is worth naming, because it has now cost three findings: *a
retention parameter in this series must be derived from the protocol's
declared guarantee, never from measured behaviour.* Measured behaviour is
what the guarantee is chosen to cover, not a substitute for it.

**Fix.** State both as expressions:

- chunk retention `≥ MAX_TTL / EPOCH` (45 epochs)
- prekey batch retirement `≥ MAX_TTL` after the batch stops being a selection
  candidate

and add the resulting exposure floor to §12 plainly: a seizure costs 45 days,
whatever the epoch length.

---

## 2. Contradiction — §5.4's LoRa conclusion assumes a gate RFC 1 does not

§5.4 concludes that **no prekey batch can cross a LoRa link**, and builds a
significant design consequence on it: "the reservoir is the only
forward-secrecy mechanism available on constrained links."

The table uses a 512-byte LoRa object gate. But RFC 1 §8.3 tabulates LoRa
airtime for the 256, 1 024 and **4 096**-byte buckets — so RFC 1 plainly
expects LoRa to carry objects eight times that gate. At RFC 1's gate:

```
batch  64:  2 168 B -> 4 096 bucket   crosses at a 4096 B gate
batch 128:  4 216 B -> 16 384 bucket  does not
```

A 64-key batch fits. At 5 received messages/day that is 13 days of keys, and
one republication costs 4 096 B against a LoRa link's ~73 KB/day budget
(SIM-1 §1) — about 5% of one day. Workable.

So §5.4's conclusion inverts depending on a number the two documents disagree
about. This is the same 512-byte gate the SIM-0 audit flagged as pathological:
paired against SIM-0's traffic model it admitted **0.16%** of objects, making
LoRa inert rather than slow.

The design consequence survives in weakened form — prekey FS on LoRa is
limited to small batches and therefore to low-traffic correspondents, which is
a real constraint — but "structurally unavailable" is too strong, and the
reservoir's claim to being the *only* mechanism does not hold.

**Fix.** RFC 4 must pin one LoRa `max_object_size` and both documents must
cite it. Until then §5.4 should state its gate assumption explicitly.

---

## 3. §13's erratum is correct, and the mechanism deserves recording

RFC 7 §13 upgrades RFC 1 §6.3's deterministic prekey indexing from SHOULD to
MUST, on measurement: exhaustive search across a 512-key batch at 200
tag-matched objects costs **30.7 s**, and 2 048 keys costs **122.9 s**, against
0.06 s with indexing. All four figures reproduce.

The reasoning is right, and the refinement in §13.3 is better than RFC 1's own
text: inbox-mode objects have no sender to index by, so they genuinely require
exhaustive search — which localises RFC 1 §6.4's decapsulation DoS to inbox
mode specifically, rather than to all traffic. RFC 1 states it more broadly
than necessary.

The argument that RFC 1 stays frozen is sound. RFC 1 §1 freezes the
*encoding*; a requirement level is not an encoding, and no wire bytes change.

**Process gap, worth closing now that it has been used once.** The series has
no defined errata mechanism — RFC 0 §10's roadmap and §10.1's
forward-compatibility rules describe versioning, not corrections to frozen
prose. Since RFC 1 cannot be revised and will accumulate more of these, RFC 0
should say where errata live and how a reader of RFC 1 discovers that §6.3 has
been superseded. A reader who finds RFC 1 alone currently gets the weaker
requirement with no pointer.

---

## 4. Gap — remote reservoir establishment is unspecified

§6.2 permits network establishment and requires a hybrid KEM for it. §6.4 then
says establishment "is step 3 of the peering ceremony (RFC 3 §11), not a
separate operation someone might skip."

RFC 3 §11 is the **in-person** ceremony. RFC 3 §11.1 covers remote peering and
never mentions reservoirs. So the path most correspondents will actually take
is described by neither document: §6.4 binds establishment to a ceremony that
remote peers do not perform, and §6.2's network path has no specified carrier,
ordering, or relationship to the negotiation triple.

This matters more than a normal gap because of RFC 1 §6.5, which is frozen and
declares the reservoir Krab's *primary* post-quantum strategy. If the reservoir
is only reliably established in person, that claim holds for a minority of
correspondents.

The economics argue for making the network path primary: one hybrid-KEM
establishment costs a single 4 096 B object against a 3 072 B per-message
surcharge, so it repays after **1.33 messages** and is 75× cheaper at a hundred.

**Fix.** Specify reservoir establishment as a fourth document in RFC 3 §5's
chain, or as a defined follow-up object, so it has the same courier-safe
static-document property as the rest of peering.

---

## 5. Gap — "under 100 KB" is batch-dependent, and §9 rests on it

§2.1's 82 732 B total assumes a 1 024-key batch. §9's `mlock` requirement is
justified by that total being "under 100 KB."

At the largest batch §5.3 permits without exceeding `MAX_OBJECT` — 2 048 keys,
which §5.3's own table prescribes for a node receiving 100 messages/day — the
prekey privates double to 65 536 B and the footprint reaches **115 500 B**.
Still small, but past the stated bound, and a high-traffic node is exactly the
one under memory pressure.

**Fix.** State the footprint as a function of batch size, and set the
`RLIMIT_MEMLOCK` requirement against the largest permitted batch rather than
the assumed one. §9 already requires failing loudly when locking is
unavailable, which is right — this just needs the ceiling computed correctly.

---

## 6. Minor

- **Dead-man timer sizing (§10) is still untied to deployment.** §10 requires
  a warning before firing but does not relate N to the offline periods RFC 3
  §15 anticipates for courier nodes — which are the population most likely to
  trip it accidentally, and the population least able to recover.
- **§6.2's physical-exchange framing.** Keeping `R_A ⊕ R_B` as the gold
  standard is right, and the rationale — neither party's RNG alone determines
  the result — is a good argument that the plan did not make. It sits awkwardly
  against §4 above, where the network path needs to be routine.
- **§12's honesty is a strength worth preserving.** "Krab does not have
  per-message forward secrecy and should not claim it," and §9.1's admission
  that Rust cannot guarantee a secret was never copied, are the kind of stated
  limits that make the rest credible.

---

## 7. Consistency items this review does not close

Carried from `RFC-7-blocking-items.md`; RFC 7 does not address them and they
belong to other documents:

- **RFC 0 §11** still defines the epoch as one period shared by tag derivation
  and key erasure. §1 above shows erasure lags rotation by `MAX_TTL / EPOCH`.
- **RFC 0 §7.5** bounds pre-forward-secrecy exposure by the signed-prekey
  rotation period; with §1's floor the binding constraint is
  `max(rotation period, MAX_TTL)`.
- **Prekey burn under group fan-out** is now partly computed — §5.3 covers
  received-message rate, and correctly identifies group membership as the
  driver — but RFC 3 §14's per-device multiplier is not folded in. A
  three-device operator in a 20-person group receives 3× the fan-out.

---

## 8. Addendum — §4's single KEK cannot support a locked node

This finding came out of implementing RFC 8's screen lock. It is a defect in
§4's hierarchy rather than in the lock design, and it already exists today for
relays, independently of lock.

### 8.1 The contradiction

`RFC-8-review.md` §8.4 makes a locked TUI a relay: it drops the KEK and keeps
reconciling. Reconciliation requires three things — the Noise static key to
answer a handshake, the **peer credential** to verify the initiator's static
key and derive the filter (RFC 5 §2), and the object index.

But RFC 3 §15 requires:

> "The credential store MUST be encrypted under the RFC 7 key hierarchy."

And §7 of this document gives a relay no passphrase, therefore no KEK. And §4
has exactly one KEK, wrapping everything.

Three consequences, only the third of which is new:

1. A locked node whose credentials died with the KEK **cannot reconcile** —
   it cannot verify a peer or compute a filter.
2. A locked node whose credentials survived the KEK has a lock that **does not
   protect the peer list**, which is the social graph.
3. **This is already broken for relays, with no lock involved.** A relay has
   no passphrase, so under §4 its credentials are either unencrypted or
   unreadable. Neither is what RFC 3 §15 asks for.

### 8.2 RFC 0 §4.4 overstates the relay case

> "Relay. … Holds a link key and ciphertext it cannot read. **Seizure yields
> nothing not already replicated across the network.**"

The corpus is replicated. **The peer list is not** — it is precisely the
information RFC 0 §6 non-goal 2 refuses to publish, and RFC 3 §15 calls
"worse than an address book" because the mutual signatures make it
non-repudiable.

So a seized relay yields something the network does not contain. That sentence
needs qualifying regardless of what §4 does.

### 8.3 The fix: two roots, which is the relay/mailbox boundary made concrete

§4's hierarchy needs a second root rather than a second mechanism:

```
device secret ─────────▶ LINK KEK        survives lock, dies on process exit
   (OS keychain/TPM)      ├─ peer credentials
                          ├─ Noise static key
                          └─ corpus and object index

passphrase ──Argon2id──▶ CONTENT KEK     dies on lock
                          ├─ tag precomputation table
                          ├─ prekey privates
                          ├─ reservoir chunks
                          ├─ epoch wrapper keys
                          └─ read and pin state
```

**A relay holds only the link tier** — which is exactly what §7's table already
says it holds, so this is the existing role boundary given a key hierarchy that
can express it. A mailbox holds both. Lock drops the content tier and nothing
else. §4's shredding argument is unchanged; it now has two roots.

Putting the **corpus under the link tier** rather than leaving it unencrypted
is worth doing on its own account: it means a powered-off seizure cannot
enumerate which objects a node holds, which is the input to SIM-1 §2 and §3's
differential-holdings analysis. §4's diagram currently lists "message store"
under the single KEK, which cannot be right — §8 requires the store to *be*
ciphertext, and a relay serves it with no passphrase at all.

### 8.4 What this buys: the exposure ladder matches RFC 0 §5.1

| state | adversary gets |
|---|---|
| powered off | nothing — both roots are sealed |
| running, locked | corpus and peer list; no tag table, no keys |
| running, unlocked | everything, as RFC 0 §5.1 already concedes |

RFC 0 §5.1 lists "endpoint seizure, powered on" as undefended. With lock, that
becomes two rows instead of one, and the middle row is new defence rather than
restated concession.

### 8.5 A locked node cannot recognise its own mail, and that is the point

The tag precomputation table maps tags to correspondents. §9 of RFC 2 calls it
"the single most valuable artifact on a seized running node." It sits in the
content tier and dies on lock.

So a locked node **accepts, stores and relays traffic it is genuinely unable to
identify as its own.** RFC 0 §4.4 asserts that a relay holds no message
decryption keys; a locked TUI *demonstrates* it, in the same process that was a
mailbox a moment earlier.

Unlock re-derives the table and rescans what arrived meanwhile. RFC 2 §4.3
sizes the rebuild at 4 550 entries and 6.8 ms for 50 correspondents at ±45;
scanning a few thousand objects against it is milliseconds more.

### 8.6 The cost, stated rather than hidden

**The device secret needs somewhere to live.** It cannot be the passphrase, or
it would not survive lock. On a laptop that is an OS keychain or a TPM — which
is the C dependency §4.2 contemplates reluctantly for unattended mailboxes.

The irony is worth recording: refusing headless operation removed the need for
TPM in one place, and lock reintroduces it in another. The stakes are lower —
the link tier protects a peer list and a corpus rather than message content,
and losing the device secret costs a re-peering rather than the archive — but
an implementation without a keychain has to either keep the link tier
unencrypted at rest or prompt on every start, and it should say which.

**The link tier is not protected against a running-locked seizure.** That is
the middle row of §8.4's ladder and it is the honest boundary: lock protects
message content and the correspondent mapping, not the fact of who you peer
with.

### 8.7 Changes this implies

| document | change |
|---|---|
| RFC 7 §4 | two roots: link KEK from a device secret, content KEK from the passphrase |
| RFC 7 §4 | corpus and index move under the link tier; "message store" as listed is wrong |
| RFC 7 §7 | state that a relay holds the link tier only, and that lock is the runtime transition into it |
| RFC 7 §4.2 | the TPM discussion now applies to the link tier, at lower stakes |
| RFC 0 §4.4 | qualify "seizure yields nothing" — the peer list is not replicated |
| RFC 0 §5.1 | split "powered on" into locked and unlocked |
| RFC 3 §15 | say which tier the credential store sits in |
