# Moving a pad when you cannot meet — a proposal

**Status: proposal.** Nothing here is implemented. It is written to be argued
with before it is built.

---

## 1. The problem with the rule we have

`PEERING.md` says: hand the pad over in person, or carry it on media. That is
correct and it is also a rule that will be broken. Friends who cannot meet will
peer anyway, and the only route Krab offers them today is `corpus` or
`network` — which means the reservoir contributes nothing against the adversary
it exists for.

A rule that is right and unfollowable produces worse outcomes than a mechanism
that is honest about its assumptions. So: what is the strongest thing we can do
over a network, and what exactly does it cost?

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

## 3. The proposal: a spoken transfer key

**Krab generates a 256-bit transfer key, displays it as 32 words, and the two
operators read it to each other over a live voice call. The pad is encrypted
under it and then may travel over TCP, email, or anything else.**

The security rests on the voice channel, not the network. That is the same
shape as `in-person` — an out-of-band channel the operators trust — with
different, and weaker, properties. §6 says how.

### Why this is post-quantum

Symmetric. A 256-bit key from a CSPRNG, an AEAD, and a KDF. There is no
key agreement anywhere in it, so there is nothing for a quantum computer to
solve. An adversary who recorded the encrypted pad and later builds a quantum
computer has a 256-bit symmetric ciphertext, which Grover reduces to a ~128-bit
search that is not a practical attack.

Contrast a PAKE — CPace, SPAKE2, OPAQUE. A PAKE is the textbook answer to
"bootstrap from a low-entropy shared secret" and it would be the right answer
if the threat were classical. All the standard ones are Diffie–Hellman based,
so they fail exactly the adversary we are defending against. **A PAKE here
would look stronger and be weaker.** Worth stating because it is the first
thing a reviewer will propose.

### Why Krab generates the key and the operator cannot

If operators pick the phrase, they will pick something guessable, and an
offline dictionary attack against the recorded ciphertext recovers the pad.
That failure is silent — the peering appears to succeed and is worth nothing.

So the key is drawn from the system CSPRNG and displayed. There is no verb that
accepts an operator-chosen transfer phrase. This is the same reasoning that
makes the *seal channel* an explicit argument rather than a guess.

### Why 32 words

Krab's word alphabet is 256 words at even positions and 256 at odd — exactly
8 bits per word, and the encoder already exists (`krab_crypto::words`). It is
already used for the 8-byte spoken fingerprint and the 64-word identity backup.

- 32 words = **256 bits**
- Position-dependent alphabets mean a transposition is *audible* — swapped
  words land in the wrong alphabet and `words::parse` rejects them rather than
  silently accepting a different key

32 words is a long thing to read aloud. It is roughly half the identity backup
an operator already writes down, on a call they are already making to compare
fingerprints. That seems like the right price.

### The shape

```
        ALICE                              BOB
        ─────                              ───
  1.    peer offer                         peer offer
                    ── cards, any channel ──▶
  2.    peer accept bob.card               peer accept alice.card

        ══════════ one voice call, both steps ══════════
  3.    read fingerprints aloud     ◀══▶   read fingerprints aloud
  4.    peer wrap alice.pad                (writes to Bob's node)
        ── read 32 words aloud ──▶         (Bob types them in)
        ◀── Bob reads his 32 back ──       peer wrap bob.pad
        ════════════════════════════════════════════════

  5.                ── wrapped pads over TCP ──▶
                    ◀── wrapped pads over TCP ──
  6.    peer seal bob.wrapped spoken       peer seal alice.wrapped spoken
```

Two new verbs, one new channel:

| | |
|---|---|
| `peer wrap <dest>` | write the pad encrypted under a fresh transfer key; display the 32 words |
| `peer seal <file> spoken` | prompt for the 32 words, unwrap, then seal as today |

### Construction

```
transfer_key   ← CSPRNG, 32 bytes
displayed as   words::phrase(transfer_key)              // 32 words

salt           ← CSPRNG, 16 bytes
k              ← Argon2id(words::parse(spoken), salt, RFC 7 §4.1 params)
wrapped        ← AEAD_seal(k, "krab/pad/spoken/v1", contribution)
file           ← cbor{ salt, wrapped }
```

Argon2id is redundant at 256 bits and is there anyway: it is the cost of one
`unlock`, it costs nothing to include, and it is the only thing standing
between a future shorter phrase and an offline attack. A construction that is
safe only because of a parameter chosen elsewhere is the pattern
`AMENDMENTS.md` keeps finding.

The transfer key is used once and destroyed. The wrapped pad is shredded after
`seal`, the same as `peer.pad` is today.

**The words and the file must not travel together** — the words by voice, the
file by network. This is the same discipline as the card and the pad, for the
same reason, and it is the discipline that is easiest to break by accident.
See §6.

### What the link records

`spoken` is a distinct channel, not an alias for `in-person`. The peer-link
records which was used, and RFC 3 §11.3's classification should place it:

- **with** `in-person` and `media` for post-quantum credit
- **apart from** them in the caveat the link carries, because the trust
  assumption is different and an operator reviewing a link months later should
  be able to see which one they made

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
