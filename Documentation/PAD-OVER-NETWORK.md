# Moving a pad when you cannot meet — a proposal

**Status: §3 is implemented.** The spoken route is `peer wrap` / `peer seal …
spoken` (`apps/krab-tui/src/spoken.rs`), and `peer reseal` upgrades a weak
peering in place by re-deriving the root over a stronger channel
(`krab_crypto::rekey::reseal_root`). Terms are recorded on disk beside each
link, so what a peering is worth survives a restart.

The in-band `network` bootstrap is `peer meet` (`apps/krab-tui/src/bootstrap.rs`),
over Noise XX. It is labelled `Channel::Network`, refuses a card that does not
match the session's static, and does not mark itself verified.

The framing this document opened with was wrong and is corrected here. It
argued for a careful exception to a rule. The rule is the problem:

> Controlled push/pull of the pad between nodes, signed and session-encrypted,
> is more secure than forcing 80% of users onto unsafe channels.

That is the governing judgement. A protocol that offers no network route does
not prevent network transfer — it exports it to `scp`, a shared drive, or a
chat app, where it is unauthenticated, unlogged, leaves copies, and where the
peering records `network` or nothing at all. An in-band exchange over the
node's own authenticated session is strictly better than every one of those,
and it is what the software should do by default.

**Sneakernet stays first-class.** `in-person` and `media` remain the strongest
routes, they keep their post-quantum classification, and nothing here is
allowed to make them harder to choose or make an operator who chose them feel
they took the slow path. The point is to stop punishing the 80% who cannot.

---

## 1. The problem with the rule we have

`PEERING.md` says: hand the pad over in person, or carry it on media. That is
the strongest advice and it is also unfollowable for most pairs. A user in
South America and a user in Africa are not going to meet, and telling them the
supported options are "meet" or "accept a weak peering" produces a third
option that Krab never sees: they move the pad over SSH or a shared disk and
tell each other it was fine.

That outcome is worse than an in-band transfer on every operational axis:

| | out-of-band `scp` | in-band exchange |
|---|---|---|
| Authenticated to the peer's static key | no | yes — RFC 4 §4.1 |
| Encrypted to that peer specifically | no | yes |
| Copies left behind | on both hosts, and any relay | shredded after seal |
| What the link records | `network`, or a lie | the actual route |
| Operator can get it wrong | in a dozen ways | it is one verb |
| **Post-quantum** | **no** | **no** |

**That last row is the one that matters, and an earlier draft of this table
omitted it.** In-band runs over Noise, which is X25519. `scp` runs over
X25519 or a NIST curve. A quantum adversary who recorded either gets the pad.
On the single axis the reservoir was invented for, the two are *identical*.

So the argument above is correct and it is not an argument for post-quantum
credit. In-band transfer is better than `scp` in every way except the one the
reservoir exists for, where it is the same. Build it, and label it `network`.

Getting this wrong would be the exact failure `AMENDMENTS.md` keeps finding:
an operator watches Krab move the pad over an authenticated encrypted session,
concludes they got a strong peering, and is wrong — silently, permanently, and
in a way nothing tells them about.

There is a real solution, and it is not "make the network transfer stronger".
It is §3.

## 2. Why `network` gets no credit

The reservoir exists to make a peering survive X25519 being broken. A
store-and-forward adversary records ciphertext now and decrypts later.

If the pad travels under X25519 — Noise, TLS, the Krab corpus, any of it — then
that same later decryption yields the pad, and the reservoir derived from it.
The pad is not *additionally* protected by being mixed in; it is the input. So

> **A reservoir is post-quantum only if its inputs never crossed a channel the
> adversary can record and later break.**

`corpus` is the circular case and deserves naming: sending the pad through
Krab wraps the thing that backstops X25519 in X25519. It is not useless — it
resists a classical attacker — but it earns no post-quantum credit and never
should.

This is why the fix cannot be "use a stronger network protocol". Any
key-agreement over the wire is the thing in question. The pad has to be
protected by something the wire never carried.

## 3. The better solution: bootstrap once, ratchet in-band forever

The constraint in §2 is information-theoretic and cannot be designed around:
**for the root to be post-quantum secret, some component of it must have full
entropy and must never have crossed a channel the adversary records.** No
protocol removes that. A short authenticated string does not help — it
authenticates, it does not keep a secret, and a 30-bit secret is 30 bits to a
quantum adversary and to a classical one.

But the requirement is *once*, not *every time*. That is the whole design.

```
  ONCE, ever, per peer          →   root_0   (out of band: in person, media,
                                              or 32 spoken words)

  thereafter, automatically     →   root_{n+1} =
                                      HKDF(root_n ‖ dh ‖ fresh_A ‖ fresh_B)

                                    where fresh_A and fresh_B travel IN-BAND,
                                    encrypted under a chunk of root_n
```

`root_n` never crossed the wire. So the transport protecting `fresh_A` and
`fresh_B` is a symmetric key the adversary has never seen, and the chain stays
post-quantum **forever, with no further out-of-band steps ever**.

This inverts the burden. The rule stops being "meet, or accept a weak
peering," and becomes:

> **Establish one secret out of band, once. Krab maintains it from then on.**

Alice in South America and Bob in Africa do one voice call, ever. Not one per
rekey, not one a year. One.

### What mixing `dh` buys

Post-compromise security. A pure symmetric ratchet never heals: an adversary
who reads `root_n` once reads every root after it. Folding a fresh X25519
exchange into each rekey means that adversary is locked out again at the next
one — provided they cannot break X25519, which is precisely the *classical*
adversary a state compromise implies.

The two components cover each other:

| Adversary | Beaten by |
|---|---|
| Records everything, breaks X25519 later | `root_n`, which never crossed the wire |
| Reads the disk once, cannot break X25519 | `dh`, fresh at each rekey |
| Both, at the same time | nothing — and nothing can |

Neither alone is enough, which is the argument for a hybrid rather than a
choice.

### It also fixes an exhaustion nobody had noticed

`Reservoir::MAX_ADVANCE` is `2 × EPOCH_WINDOW` — 90 epochs, and an epoch is a
day. A node offline longer than **90 days cannot catch its ratchet up**, and
`advance_to` correctly refuses rather than destroying roots on a bad clock. The
peering is then permanently dead and has to be redone from scratch, out of
band.

That is the real "the pad ran out" condition — not chunks, which are infinite.
A rekey exchange re-seats both ends at a common epoch, so a returning node
recovers instead of losing the friend.

### When to rekey

Anchored to a stated guarantee rather than a comfortable number, per RFC 0's
editorial rule:

> A reservoir compromised at time *T* stops protecting traffic within
> `REKEY_EPOCHS` epochs of *T*.

`REKEY_EPOCHS = EPOCH_WINDOW` (45) falls out of it: rekeying faster buys
nothing, because chunks inside the acceptance window are retained anyway and
remain derivable from material the adversary already has. Rekeying slower
directly weakens the stated guarantee. The parameter is the guarantee, not a
tuning knob.

A rekey is also attempted whenever a link comes up and the peer's ratchet is
more than `EPOCH_WINDOW` behind ours — the returning-node case above.

### The initial bootstrap, for people who cannot even call

Offer the in-band route, and be honest about it:

```
> peer seal --in-band network

peer-link signed with <fingerprint>

NOT post-quantum. The pad crossed a channel an adversary can record and
later break. Everything else about this peering is sound.

Run `peer reseal` the first time you meet, or share media. It upgrades
this link in place — you will not have to peer again.
```

`peer reseal` is the property that makes this honest: **a weak peering can be
upgraded without being redone.** Start where you are, strengthen when you get
the chance, keep your message history and your peer-link throughout.

### Where the spoken transfer key fits

It is one of three ways to establish `root_0`, and the only one that works at
intercontinental distance without waiting for a flight:

| Route | Post-quantum | Cost |
|---|---|---|
| `in-person` | yes | meet |
| `media` | yes | post a stick |
| `spoken` — 32 words on a voice call | yes, if the call is not recorded | one call, ever |
| `network` — in-band | **no**, upgradable later | one verb |

Krab's word alphabet is 256 words at even positions and 256 at odd — exactly
8 bits per word, and the encoder already exists (`krab_crypto::words`), where
it renders the 8-byte spoken fingerprint and the 64-word identity backup. 32
words is 256 bits. Position-dependent alphabets make a transposition *audible*:
swapped words land in the wrong alphabet and `words::parse` rejects them
instead of silently accepting a different key.

**Krab generates it; the operator cannot choose it.** An operator-chosen
phrase is guessable, and an offline dictionary attack against the recorded
ciphertext then recovers the pad — silently, with the peering appearing to
have succeeded.

Not a PAKE. CPace, SPAKE2 and OPAQUE are the textbook answer to bootstrapping
from a shared secret, and every standard one is Diffie–Hellman based, so they
fail exactly the adversary being defended against. **A PAKE here would look
stronger and be weaker.** Worth stating because it is the first thing a
reviewer proposes.

### Construction

```
root_0 (spoken)    transfer_key ← CSPRNG(32);  shown as words::phrase(...)
                   k       ← Argon2id(words::parse(spoken), salt, §4.1 params)
                   wrapped ← AEAD(k, "krab/pad/spoken/v1", contribution)

rekey n→n+1        fresh_X ← CSPRNG(32)                       // each end
                   carrier ← HKDF(root_n, "krab/rekey/v1" ‖ n)
                   payload ← AEAD(carrier, "krab/rekey/v1", fresh_X ‖ policy)
                   signed  ← Ed25519(identity, payload)       // §5
                   root_n+1← HKDF(root_n ‖ dh ‖ fresh_A ‖ fresh_B ‖ n+1)
```

The rekey payload is signed as well as encrypted, so a peer who has the
carrier key cannot be impersonated by anyone who does not also hold the
identity key — the two compromises stay separate.

`fresh_A ‖ fresh_B` is ordered by node id, not by who spoke first, so both
ends derive the same root without a role negotiation.

### Policy rides the same exchange

A rekey is a periodic, authenticated, encrypted, peer-to-peer state update.
So is a policy change. Building two mechanisms for one shape would be a
mistake — see §7 of `PEERING.md` for the gap this closes: `Policy` is signed
into the card at peering and **never propagates again**, so a peer who stops
relaying or shrinks their retention is never heard. Message TTL is not in
`Policy` at all, and `CarriagePolicy` (RFC 6 §3.6, accepted channels) is
exported from `krab-crypto` with **zero callers**.

## 4. When there is no voice channel either

Split the pad into *n* shares with a *k*-of-*n* threshold scheme and send each
over an unrelated channel — one by Signal, one by email, one via a mutual
friend, one by post.

Be clear about what this is: it **raises the cost** of collecting the pad. It
does not change the model. A global passive adversary who records everything
still gets every share. It is worth having because most adversaries are not
that, and it is worth refusing to call post-quantum because some are.

If this is built it should be its own channel — `split` — and it should earn no
more credit than `network`. Its value is in the caveat text an operator reads,
not in the classification.

## 5. What this does not fix

- **It does not make a remote peering equal to meeting.** It makes it equal to
  a trusted voice call, which is a real thing and a lesser thing.
- **It does not help if the voice channel is recorded.** Everything below.
- **It does not remove the pad's plaintext moment.** The contribution is still
  plaintext in memory at both ends and briefly on disk at the receiver. See
  `SECURE-DELETE.md` for what shredding does and does not buy.

## 6. Warnings

These belong in the interface, not only here. `peer wrap` should print them.

**1. Your voice can be synthesised.** This is the biggest change since the
"read it aloud" step was designed. A recording of your friend is enough to
produce a convincing live voice. The fingerprint comparison in step 3 does not
help — an attacker relaying the call reads the fingerprints faithfully.

Mitigation, and it is a weak one: ask something only they would know, that is
not in any message either of you has sent. Prefer video. Prefer a call on a
channel that authenticates the endpoint. Recognise that a determined adversary
defeats all of this and that in-person exists for a reason.

**2. If the call is recorded, this is worth nothing.** Not "weakened" — worth
nothing, because the transfer key is the whole protection. PSTN and cellular
are interceptable by parties who do it routinely. An E2EE voice app is
better and is itself a key agreement that a quantum adversary may break later,
which means **the recording of your call is the attack**. This is the sharpest
limitation and it should not be softened: a spoken key over a *recorded*
E2EE call is `network`, not `spoken`.

**3. Never type the words into anything but your peer's node.** Not into chat
"so they can copy it", not into a password manager you sync, not into a
terminal you are screen-sharing. Any of those puts the key onto a recorded
channel and silently downgrades the peering to `network` while the interface
still says `spoken`. This is the most likely way this mechanism fails in
practice, and it fails invisibly.

**4. Krab cannot verify any of it.** The channel argument is an operator
assertion, exactly as `in-person` is today. Nothing in the software knows
whether you were on a call, whether it was recorded, or whether you pasted the
words into Discord. `spoken` means "I assert I did this properly". Anyone
reviewing a link is trusting the operator who made it.

**5. Do not reuse a transfer key.** One key, one pad, one direction. Each
direction gets its own — Alice's pad to Bob and Bob's pad to Alice are
separate wraps with separate keys. Reuse across peerings would let one
compromised peering unwrap another.

**6. A tampered file fails closed.** The AEAD rejects it and `seal` refuses.
There is no partial acceptance and no prompt to proceed anyway.

**7. This is more steps, and steps get skipped.** The honest risk of adding
`spoken` is that operators who would have driven two hours now do not.
The counter-argument is the one in §1: they were not going to drive, they were
going to use `network`. That should be tested against real behaviour rather
than assumed.

## 7. Open questions

1. **Does `spoken` belong in RFC 3 §11.3 at all**, or is it a client-level
   convenience that the RFC should decline to bless? The classification drives
   a security property, which argues for the RFC.
2. **32 words, or 24?** 24 words is 192 bits, ~96 post-Grover, and a quarter
   less to read. 256 bits is the conservative choice and the argument for
   trimming it is purely ergonomic — which is exactly the argument
   `AMENDMENTS.md` §4 found to be how parameters get anchored to convenience
   rather than to a stated guarantee.
3. **Should `peer wrap` refuse when the node has no completed fingerprint
   comparison recorded?** The voice call is a prerequisite; the ceremony
   already tracks whether fingerprints were verified.
4. **Is a `split` channel worth building**, given it earns no credit and its
   whole value is operator judgement?
