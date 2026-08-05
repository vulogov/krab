# RFC 7 — Key Custody and Erasure

    Number:      7
    Title:       Key Custody and Erasure
    Status:      Draft
    Repository:  https://github.com/vulogov/krab
    Author:      Vladimir Ulogov
    Requires:    RFC 0, RFC 1
    Grounded by: krab-sizes/keys (all figures computed)
    Errata:      RFC 1 §6.3 — see §13

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be
interpreted as described in RFC 2119.

---

## 1. Scope

Krab's corpus is public, replicated toward every node, and archived
indefinitely by any relay that chooses not to evict (RFC 0 §7.6). It is a
textbook harvest-now-decrypt-later target. Message confidentiality
therefore depends less on the strength of the cipher than on **whether the
key still exists**.

This document specifies the key hierarchy, the erasure mechanism that
makes forward secrecy real rather than nominal, and the custody model for
what remains online.

The organising principle: **forward secrecy is achieved by destroying
keys, never by overwriting data** (RFC 0 I-7). Overwrite-based deletion is
not reliable on flash storage — wear levelling, over-provisioning, and the
flash translation layer may preserve the original blocks indefinitely.
Every erasure claim in this series rests on §4.

---

## 2. Key hierarchy

Krab's key material has radically different access patterns, and treating
it uniformly forces a bad custody tradeoff. Split it by frequency of use:

| key | used | custody |
|---|---|---|
| identity, Ed25519 | quarterly — signs prekey batches, credentials, bulletins | **offline media or hardware token** |
| Noise static, X25519 | every connection | online, wrapped |
| signed prekey, X25519 | rotates weekly–monthly | online, wrapped |
| one-time prekeys, X25519 | per received message | online, wrapped, expiring |
| reservoir chunks | per message, per peer | online, wrapped, **epoch-erased** |

**The identity key signs and never decrypts.** No ciphertext in the corpus
is ever sealed to it, so its compromise permits impersonation going
forward and reveals nothing historical. It is used four times a year and
belongs on removable media in a drawer, or on a hardware token from which
it never emerges.

Removable-media custody protects against **seizure of a powered-off
machine** and nothing else. A node must run continuously to reconcile, so
online material is in RAM continuously; the exposure window is "always,"
not "during exchange." Applied to the identity key alone it is excellent.
Applied to everything it is operational pain buying very little.

Hardware tokens do not help below the identity tier: on-token X25519
decapsulation runs at roughly 100 ms, and §5.3 shows the decapsulation
budget will not tolerate it. **Sign on token; decrypt in memory.**

### 2.1 Total footprint

Computed for 25 peers at 45-epoch retention:

```
reservoir chunks ....  36 000 B
epoch wrappers ......   2 700 B
prekey privates .....  32 768 B
peer credentials ....  10 400 B
noise statics .......     800 B
identity ............      64 B
TOTAL ...............  82 732 B  (80.8 KB)
```

All secret material fits in **under 100 KB**, which is why §9's
memory-locking requirement is practical rather than aspirational: the
entire secret working set fits in a handful of `mlock`ed pages on any
platform.

---

## 3. Erasure is the mechanism

Every forward-secrecy property in Krab reduces to one operation: destroy a
32-byte key and everything derived from it becomes permanently
unrecoverable. §4 is how that is made true on real storage.

---

## 4. Crypto-shredding

```
passphrase ──Argon2id──▶ KEK          memory only, mlock'd, never written
                          │ wraps
                    epoch wrapper key W_N     one per epoch, on disk, wrapped
                          │ wraps
        prekey privates · reservoir chunks · session state · message store
```

Destroying `W_N` — a 32-byte overwrite of an in-memory value plus removal
of one wrapped record — destroys everything beneath it, instantly and
reliably, regardless of what the flash controller did with the underlying
blocks.

**Implementations MUST NOT rely on file deletion or overwriting for any
forward-secrecy property.** Where a specification in this series says
"erase," it means destroy the wrapping key.

### 4.1 Parameters

```
KDF        Argon2id
m          65 536 KiB (64 MiB)
t          3
p          4
salt       16 bytes, random, stored alongside
```

Implementations SHOULD calibrate to approximately 500 ms on target
hardware and MUST store the parameters used alongside the salt, so a
future increase does not lock out existing stores.

Wrapping: ChaCha20-Poly1305, one wrapped record 60 bytes (32 key + 16 tag
+ 12 nonce). Forty-five epochs of wrappers is 2 700 bytes.

### 4.2 Unattended operation

A node requiring a passphrase cannot run unattended. §7 resolves this by
removing the requirement rather than weakening it: a relay holds no
decryption keys at all.

Where an unattended mailbox is genuinely required, TPM 2.0 sealing binds
the KEK to machine and boot state, giving unattended unlock while leaving
a seized disk useless. This introduces a C dependency and SHOULD be
weighed against simply accepting a passphrase prompt.

---

## 5. Forward secrecy, tiered

| tier | mechanism | granularity | status |
|---|---|---|---|
| v1 | three-tier prekeys + §4 | prekey batch period | **mandatory** |
| v1 | epoch-chunked reservoir (§6) | one epoch | where a reservoir exists |
| v2 | forward-secure PKE, epoch = tag epoch | one epoch | planned |
| v3 | puncturable / Bloom-filter encryption | per message | research |

### 5.1 Prekeys

```
identity (Ed25519)          permanent, signs only
  └─ signed prekey (X25519)   rotates weekly–monthly
       └─ one-time prekeys     batch, single use
```

A sender consumes a one-time prekey where available and falls back to the
signed prekey on exhaustion. **The identity key is never a decryption
key**, so worst-case exposure is the signed-prekey rotation period rather
than forever.

Batches are published as signed `bulletin` objects (RFC 1 §5.2) — the
corpus is the prekey server. This is X3DH with no infrastructure.

### 5.2 One-time prekeys are not one-time

Signal's prekey server hands each key to exactly one requester and deletes
it. A Krab batch is **flooded**, so every correspondent receives the same
batch and two senders may independently select prekey #7.

The recipient therefore cannot delete a private half on use without losing
the second message. Two mitigations, both required:

- **Deterministic per-sender index** (RFC 1 §6.3) makes collision a
  birthday problem rather than a certainty.
- **Delete on schedule, never on use.** Retire a batch at expiry plus a
  grace window of roughly 2× maximum delivery latency — weeks, on a
  courier route.

**Forward-secrecy granularity is therefore the batch period, not the
message.** This is weaker than Signal and is the honest consequence of
having no server. It is also the same coarse granularity forward-secure
PKE arrives at from the other direction, which is why v2 is attractive: it
achieves the same property with no batch publishing and no exhaustion.

### 5.3 Batch sizing is bounded from both ends

```
batch ≈ received_messages_per_day × republish_interval × 1.5
```

Group membership dominates: fan-out (RFC 6) means a 20-person group
delivers 19 messages per group-message-round to every member.

| received/day | republish | needed | batch | wire | bucket |
|---|---|---|---|---|---|
| 5 | 30 d | 150 | 256 | 8 312 B | 16 K |
| 20 | 7 d | 140 | 256 | 8 312 B | 16 K |
| 50 | 7 d | 350 | 1 024 | 32 888 B | 64 K |
| 100 | 7 d | 700 | 2 048 | 65 656 B | 256 K |
| 100 | 30 d | 3 000 | 8 192 | 262 264 B | **exceeds `MAX_OBJECT`** |

**Republish cadence is bounded by `MAX_OBJECT`.** A node receiving 100
messages a day cannot republish monthly; the batch would not fit in a
single object. High-traffic nodes MUST republish weekly.

### 5.4 No prekey batch can cross a LoRa link

| batch | wire | bucket | fits LoRa gate (512 B)? |
|---|---|---|---|
| 64 | 2 168 B | 4 096 | **no** |
| 128 | 4 216 B | 16 384 | **no** |
| 512 | 16 504 B | 65 536 | **no** |
| 2 048 | 65 656 B | 262 144 | **no** |

Even a 64-key batch is four times the LoRa object gate. **Prekey-based
forward secrecy is structurally unavailable to a LoRa-only
correspondent**, who would otherwise be pinned to the signed-prekey tier
permanently.

This is decisive for §6: **the reservoir is the only forward-secrecy
mechanism available on constrained links**, because it requires no
publishing of any kind after establishment.

### 5.5 Decapsulation budget

Cost per tag-matched object, at 100 µs per X25519 decapsulation and three
live batches in the acceptance window:

| batch | exhaustive | deterministic index |
|---|---|---|
| 64 | 19.2 ms | 0.30 ms |
| 512 | 153.6 ms | 0.30 ms |
| 2 048 | 614.4 ms | 0.30 ms |

At 200 tag-matched objects in one reconciliation:

| batch | exhaustive | deterministic |
|---|---|---|
| 512 | **30.7 s** | 0.06 s |
| 2 048 | **122.9 s** | 0.06 s |

Exhaustive search does not scale. See the erratum in §13.

---

## 6. The epoch-chunked reservoir

A shared secret between two peers, partitioned by epoch, from which
message keys derive symmetrically.

```
reservoir → chunk_N  (32 bytes, one per epoch)
            msg_key = HKDF(chunk_N, "krab/msg/v1" ‖ tag)
```

At the close of epoch N plus a grace window, **`chunk_N` is destroyed**
(§4). Every message of that epoch becomes permanently undecryptable — by
anyone, including the participants.

### 6.1 Why this shape

The naive one-time pad consumes key material equal to message volume and
requires both parties to track a consumption offset — which cannot be kept
in sync across a network that delivers out of order, duplicates, and
loses. Reuse of an offset is catastrophic.

Deriving instead of consuming removes all of it:

- **No offsets, no counters, no consumption state.** The tag is already in
  the envelope, already unlinkable, already unique per message.
- **Two-time-pad reuse is structurally impossible**, not merely prevented.
- **Out-of-order delivery is free** within an epoch and grace window.
- **The epoch number is the same one used for tag derivation and key
  erasure.** One clock, one counter, three mechanisms.

And the material required collapses:

| | one peer-year at 50 msg/day |
|---|---|
| raw pad | 74.8 MB |
| **reservoir** | **11.7 KB** |

**6 400× smaller.** A year of forward-secret, post-quantum messaging with
one peer costs under 12 KB. Twenty-five peers at 45-epoch retention is
36 KB total. This fits in a credential exchange, a QR sequence, or a
single LoRa reconciliation.

The tradeoff is granularity: compromising an unexpired chunk exposes that
epoch's traffic with that peer. That is the same granularity §5.2 already
accepted for prekeys, so nothing worsens. Finer granularity is available
by enlarging chunks and sub-partitioning by hour, at negligible size cost.

### 6.2 Establishment

**Physical exchange** is the gold standard, and both parties MUST
contribute:

```
reservoir = R_A ⊕ R_B
```

A brings `R_A`, B returns `R_B`, both XOR. Neither party's generator alone
determines the result, so a backdoored or broken RNG on one end does not
compromise it. Two courier legs — already the request/response pattern, so
structurally free.

**Network establishment MUST use a hybrid post-quantum KEM.** A reservoir
transferred under X25519 alone provides *no* post-quantum benefit: an
adversary captures the transfer, decrypts it when X25519 falls, and holds
the reservoir and therefore everything derived from it.

RFC 1 §6.5 shows per-message hybrid KEM costs a 16× corpus inflation on
short traffic. A **single** hybrid exchange seeding a multi-year reservoir
amortises that to nothing. This is why the reservoir is Krab's primary
post-quantum strategy and suite `0x0002` is the fallback for
correspondents without one.

### 6.3 Ratchet on contact

```
reservoir_{n+1} = HKDF(reservoir_n ‖ DH(fresh ephemerals))
```

Hybrid logic applied over time: if the DH is broken later, the original
physical entropy still protects; if the reservoir leaks, the fresh DH
still protects. **It fails only if both fail.**

Peers SHOULD top up from fresh material on every courier exchange — the
media is already moving and entropy is free — so the reservoir strengthens
with contact rather than aging into a static shared secret on two disks.

### 6.4 Establishment belongs to the ceremony

Reservoir exchange is step 3 of the peering ceremony (RFC 3 §11), not a
separate operation someone might skip. The `peer-link` records the
reservoir identifier and current epoch; **the material itself MUST NOT
appear in the credential.**

---

## 7. Relay is not mailbox

**A relay holds no message decryption keys.** It holds a Noise static key
for its links and stores ciphertext it cannot read. Seizure yields
material already replicated across the network.

| role | keys held | unattended | passphrase |
|---|---|---|---|
| relay | Noise static | yes | no |
| mailbox | full hierarchy | no | on unlock |
| point | full hierarchy, narrow shard | no | on unlock |

This resolves the tension between unattended operation and key protection
by removing it: the machine that must run without a human present is the
one with nothing to protect.

Deployments SHOULD default any always-on, reachable node to relay-only.
The friend's box providing reachability for a CGNAT'd phone (RFC 0 §4.4)
is a relay, not a mailbox.

---

## 8. Do not store plaintext

Protecting keys carefully while caching decrypted messages leaves the
plaintext an adversary wanted sitting in the database.

**Implementations MUST store ciphertext and derive on display.** Plaintext
exists transiently in a buffer zeroized when the view closes.

This closes a loop opened in RFC 0. Erasing `chunk_N` does not merely make
new interception useless — **it makes the node's own archive of that epoch
permanently unreadable.** That is genuine cryptographic message expiry,
achieved through key erasure rather than magic, and it is the only form
that exists.

It falls out of the design at no cost. It is undone by caching plaintext
for convenience, which will be proposed.

### 8.1 Pinning

Some users want a permanent archive. Provide an explicit **pin** action
that re-encrypts a selected conversation under a long-lived key, so
retention is a conscious act rather than the default.

Implementations MUST make the consequence visible before the retention
window elapses: mail older than the window becomes unreadable, and a user
who discovers this afterwards has lost something irrecoverably.

---

## 9. Memory hygiene

In rough order of value:

- **Disable hibernation.** It writes all of RAM to disk and silently
  defeats everything above. Most threat models omit it.
- **Disable swap, or use a randomly-keyed swap device.**
- **`mlock`/`VirtualLock` key buffers.** The full secret working set is
  under 100 KB (§2.1), so this is cheap. On Linux it requires
  `RLIMIT_MEMLOCK` headroom; implementations MUST fail loudly at startup
  if locking is unavailable rather than proceeding unlocked.
- `panic = "abort"`, `RLIMIT_CORE = 0`, `prctl(PR_SET_DUMPABLE, 0)`.
- `prctl(PR_SET_PTRACER, 0)` and Yama `ptrace_scope` — blocks same-user
  debugger attach, and is widely available and rarely applied.
- Zeroize on drop for all secrets; **fixed-size arrays rather than `Vec`**,
  since growth reallocates and leaves the previous contents behind.
- `Debug` implementations on key types MUST print nothing.

### 9.1 An honest limit

**Rust cannot guarantee a secret was never copied.** Moves, reallocation,
and compiler optimisations may leave residue that zeroizing never sees.
Fixed buffers and `mlock` reduce the exposure substantially; nothing
eliminates it. This MUST appear in the security considerations of any
release rather than being glossed.

---

## 10. Panic wipe and dead-man

Both are cheap only because §4 exists — each is a 32-byte overwrite.

**Panic wipe.** A command, and a duress passphrase that appears to unlock
normally, either of which destroys the KEK. The store becomes
unrecoverable in milliseconds. This is the control that matters at the
moment of seizure.

**Dead-man timer.** Wipe if not unlocked within N days. Useful for a node
its operator may not be able to return to, and it degrades safely: the
corpus is replicated elsewhere, so wiping costs nobody anything.

Neither MUST be enabled by default. Both MUST be discoverable, and the
dead-man timer MUST warn well before it fires.

---

## 11. Identity backup

Crypto-shredding plus no server means a dead laptop is total loss: message
history (intended) and identity (not intended). Losing identity means
every peer must re-verify out of band, in person, from scratch.

**The identity key MUST be backed up offline at creation**, as part of the
setup ceremony rather than a settings-menu item. The moment someone needs
a backup is the moment they can no longer create one.

The backup is 64 bytes: printable as a word list on paper, or written to
the same removable media holding the online copy.

Implementations MUST state plainly that **message history is not
recoverable and that this is intentional.** Users will otherwise assume a
backup exists somewhere.

---

## 12. Security considerations

**Erasure is the only claim that matters, and §4 is the only thing making
it true.** An implementation that shreds correctly but gets the hierarchy
wrong loses one epoch. An implementation that gets the hierarchy right and
shreds by `unlink()` loses everything, silently, while appearing correct.

**Epoch granularity is the honest ceiling.** Krab does not have per-message
forward secrecy and should not claim it. Compromise of an unexpired chunk
or an unretired prekey batch exposes that window.

**The grace window is exposure.** It must exceed maximum delivery latency
— weeks on a courier route — and every retained chunk is a decryptable
epoch. Courier deployments buy delivery reliability with a longer exposure
window, and the tradeoff is not adjustable independently.

**A reservoir is a long-lived shared secret on two disks.** Seizure of
either endpoint before erasure yields every unexpired epoch with that
peer. §6.3's ratchet limits it going forward; it does not limit it
backward within the retained window.

**Hybrid KEM is mandatory for network establishment** (§6.2). An
implementation that permits X25519-only reservoir transfer has silently
removed the reservoir's principal benefit while appearing to work.

**Group membership drives prekey burn** (§5.3), and exhaustion degrades
forward secrecy silently. Implementations MUST surface prekey burn rate,
not merely remaining count.

---

## 13. Errata to RFC 1

**RFC 1 §6.3 states that senders SHOULD use deterministic prekey
indexing. Measurement shows it MUST.**

Exhaustive trial decapsulation across a 512-key batch at 200 tag-matched
objects per reconciliation costs **30.7 seconds**; at 2 048 keys, **122.9
seconds**. Deterministic indexing reduces both to 0.06 s. Exhaustive
search is not a fallback, it is a denial-of-service vector against the
recipient's own CPU.

Corrected requirements:

1. Senders MUST use the deterministic index when the tag mode is pairwise.
2. Recipients MUST attempt **all live batches** in the acceptance window
   (three, typically) in constant time, and MUST NOT stop at first
   success. The constant-time requirement applies to the candidate set in
   use, not to the whole batch.
3. **Inbox-mode objects have no sender to index by** and therefore require
   exhaustive search. Implementations MUST cap inbox-tagged
   decapsulation attempts per peer per epoch. This is the DoS surface
   RFC 1 §6.4 identifies, and it is narrower than that section implies —
   it applies to inbox mode specifically.

No wire-format change is implied, so RFC 1 remains frozen. This is a
correction to a requirement level, not to an encoding.

---

## 14. References

- KRAB RFC 0 — Architecture and Threat Model
- KRAB RFC 1 — Object Format and Cryptography
- KRAB RFC 3 — Peering, Credentials, and Accountability
- `krab-sizes/keys` — reference calculator; source of every figure here
- Canetti, Halevi, Katz — forward-secure public-key encryption (v2)
- Green & Miers, *Forward Secure Asynchronous Messaging from Puncturable
  Encryption*, IEEE S&P 2015 (v3)
- Derler et al. — Bloom Filter Encryption; puncture by key deletion (v3)
- Signal — X3DH and the Double Ratchet (prekey model, partially applicable)
- RFC 9106 — Argon2
- RFC 8439 — ChaCha20-Poly1305
- RFC 5869 — HKDF
- FIPS 203 — ML-KEM
