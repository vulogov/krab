# Peering — quickstart

Two nodes that have each run `init` (see `INIT.md`) are strangers. Peering is
what makes them friends: it exchanges signed cards, mixes a shared reservoir,
and produces a **peer-link** — the durable artifact RFC 3 §4 makes the contract
between two nodes.

There is no discovery, no directory, and no trust-on-first-use. RFC 4 §4.1
makes a static-key mismatch a hard failure and never a prompt.

---

## The shape of it, A to B

Peering is **symmetric** — Alice and Bob run the same five verbs, in the same
order, each producing artifacts the other consumes. Nobody is the initiator.

```
        ALICE  (a1b2c3d4)                    BOB  (fed356f2)
        ─────────────────                    ────────────────
  1.    peer offer                           peer offer
          writes peer.card                     writes peer.card
                        ── peer.card ──▶
                        ◀── peer.card ──
  2.    peer accept from-bob.card            peer accept from-alice.card
          prints both fingerprints             prints both fingerprints

  3.    ═══════════ ONE VOICE CALL, BOTH DIRECTIONS ═══════════
        read your 8 words aloud       ◀══▶   read your 8 words aloud
        they must match what step 2 printed at the other end

  4.    peer pad /media/alice.pad           peer pad /media/bob.pad
          NOW the secret half exists          NOW the secret half exists
                        ══ carried ══▶
                        ◀══ carried ══
  5.    peer seal bob.pad media             peer seal alice.pad media
          writes peers/fed356f2/…             writes peers/a1b2c3d4/…
```

Each end produces exactly two artifacts, and they must not travel together:

| Artifact | Written by | Secret? | How it travels |
|---|---|---|---|
| `peer.card` | `peer offer`, into your `--home` | **No** — public and signed | any channel you like |
| your pad | `peer pad <dest>`, **where you say** | **Yes** — half a shared secret, plaintext | in person or on media |

Anyone holding both has what they need. That is the whole reason for splitting
them across two channels.

> **`peer offer` does not write your pad.** It writes only `peer.card`. The
> contribution stays wrapped inside the ceremony until step 4, because a
> plaintext secret that exists for two minutes is better than one that exists
> for two weeks. If you go looking for `peer.pad` after step 1, it is not
> there and that is correct.

> **After a restart, `unlock` first.** Every `peer` verb needs an unlocked
> node: the contribution is wrapped inside the ceremony, and sealing needs the
> epoch wrapper. A locked node is a relay — it reconciles and cannot read.

**Lost track?** `peer status` names the step you are on and the verb that comes
next. `peers` lists completed peerings, which survive restarts and failed
connections — those are on disk, not in memory.

---

## 1. Both ends: `peer offer`

```
> peer offer
wrote /home/alice/krab/peer.card

This is your card. It is public and signed — send it any way you like.

your fingerprint — eight words that stand for your identity key:

  <eight words>

At step 3 you read these to them over a voice call, and they read theirs
back. Both must match what `peer accept` printed. If they do not, stop:
someone is between you. Nothing else in the ceremony establishes who you
are talking to.

next, in order:
  1. send them peer.card, and get theirs
  2. peer accept <their.card>
  3. compare fingerprints aloud
  4. peer pad <destination>   — writes your SECRET half
  5. exchange pads, then: peer seal <their.pad> <channel>

Your pad does not exist yet. Step 4 creates it, where you tell it to — on
the medium you are carrying, not in this directory.
```

### What the eight words are for

They are your **fingerprint** — a spoken form of your identity public key,
using a word alphabet where each word carries 8 bits and the even and odd
positions draw from different lists, so a transposition is audible.

You use them exactly once, at step 3, and never again. They are not a
password, not a secret, and not something to write down: they are a value you
*say out loud* so your friend can check that the card they received is the
card you sent.

The card proves *a key* signed it. Only the voice call proves *whose* key.

---

## 2. Both ends: `peer accept <their.card>`

```
> peer accept /tmp/bob.card
card accepted. Now read these eight words aloud and hear the same back:

  <eight words>

then: peer seal <their.pad> <channel>
```

Give the path to the file **they** sent you.

If the signature does not verify you get *"that card's signature does not
verify — it is not what it claims"* and nothing is recorded.

### Read the words aloud

This is RFC 3 §11 step 2, and it is the step that actually establishes who you
are talking to. Get them on a voice call, or stand next to them. **You read
their fingerprint; they read yours.** Both must match.

If they do not match, stop. Someone is between you.

Whether this happened is recorded in the ceremony and affects what the link is
allowed to do.

---

## 3. Exchange pads

Now each end needs the other's contribution. **This is the part that decides
how strong the peering is.** You pick the channel at seal time and it is not
guessed:

| Channel | Meaning | Survives X25519 being broken? |
|---|---|---|
| `in-person` | handed over face to face | **yes** |
| `media` | on physical media, carried | **yes** |
| `spoken` | wrapped under 32 words read aloud on a call | **yes**, if the call is not recorded |
| `corpus` | through the Krab network itself | no |
| `network` | any other online path | no |

The reservoir is what makes a link post-quantum. A pad that travelled over the
network is only as good as the X25519 protecting it — which is fine today and
is exactly what a store-and-forward adversary is recording against later.

**`in-person` or `media` if you can.** If you cannot, `corpus` still works and
Krab will tell you what you got.

**Cannot meet at all?** Use `spoken` — §4b. The pad crosses the network; only
32 words cross a voice call, once ever. It keeps the post-quantum property,
because the words never touch the wire.

---

## 4. Writing the pad: `peer pad <destination>`

```
> peer pad /Volumes/usb/alice.pad
wrote your contribution to /Volumes/usb/alice.pad.

This is half a shared secret in plaintext. It is the only unprotected
artifact Krab produces, and once it is on a medium no software can
retract it — carry it, hand it over, and do not leave a copy behind.
```

Give the path **on the medium you are carrying**, not a path in your home
directory that you will copy later. Every copy is a copy of half a shared
secret.

The write is deliberately **not** atomic: an atomic write leaves a `.tmp` file
on failure, and here that file would be the plaintext contribution under a
name nothing cleans up, on removable media you are about to walk away with. A
partial write is visibly partial, and the pad is regenerable from the
ceremony.

For a sneakernet peering, carry the medium. For an in-person one, exchange
media or read it across. Do not email it.

---

## 4b. Peering at a distance: `peer wrap`

For two people who will not meet. Instead of carrying a pad, wrap it under a
key that only ever crosses a voice call.

```
> peer wrap /tmp/alice.wrapped
wrote /tmp/alice.wrapped

That file is safe to send over anything — email, chat, a shared drive.
It is useless without the words below.

READ THESE ALOUD, on a live voice call, and nowhere else:

  <32 words>
```

Send the file however you like. Read the words on the call you are already
making for step 3. Then each end runs:

```
> peer seal from-bob.wrapped spoken
type the 32 words they read to you, separated by spaces.

> <the 32 words>
peer-link signed with <fingerprint>
```

The words are typed at a **prompt**, not on the command line, so they never
enter the command history.

### Why this keeps the post-quantum property

The wrapping is symmetric throughout — a 256-bit key, Argon2id, an AEAD — and
that key never touched the wire. There is nothing for a quantum computer to
solve. Contrast a PAKE (CPace, SPAKE2, OPAQUE): all Diffie–Hellman based, so
they fail exactly the adversary the reservoir exists for. **A PAKE here would
look stronger and be weaker.**

Krab generates the words; you cannot choose them. A chosen phrase is
guessable, and an offline dictionary attack against the recorded file then
recovers the pad — silently, with the peering appearing to have worked.

32 words is 256 bits: the alphabet carries 8 bits per word, and even and odd
positions draw from different lists, so **a transposition is audible** — two
words read out of order land in the wrong alphabet and are rejected rather
than producing a different key.

### What defeats it

- **A recorded call.** The words are the whole protection. A spoken key over
  a recorded call is `network`, not `spoken`, and nothing in the software can
  tell the difference.
- **A synthesised voice.** Cheap now. The fingerprint comparison does not
  help — an attacker relaying the call reads them faithfully. Ask something
  only they would know, that is in no message either of you has sent.
- **Typing the words into chat "so they can copy them."** This puts the key
  on the same recorded channel as the file and downgrades the peering
  invisibly, while the interface still says `spoken`. It is the likeliest way
  this fails in practice.

Krab cannot verify any of it. `spoken` means *"I assert I did this properly"*,
exactly as `in-person` does.

---

## 5. Both ends: `peer seal <their.pad> <channel>`

```
> peer seal /Volumes/usb/bob.pad in-person
peer-link signed with <their fingerprint>

agreed: buckets to 65536, relaying for others, 1073741824 retained
```

This mixes both contributions into a reservoir, seals it under the current
epoch wrapper, and writes two files into your `--home`:

| File | What |
|---|---|
| `<short-id>.link` | their signed card — the peer-link |
| `<short-id>.reservoir` | the shared reservoir, sealed |

`<short-id>` is the first four bytes of their node id, in hex — `3f9a2c01`.
**That is the name you use in every later verb.** `connect 3f9a2c01 …`, not
`connect bob`.

The ceremony and your `peer.pad` are both **shredded** — overwritten, then
removed. The pad has no further use once the reservoir exists, and it is the
one file in the layout that is neither signed nor sealed.

The agreed terms are the *lower* of what each end offered, since a link is
only as capable as its least capable end (RFC 4 §5.4).

If the link would be unusable you get `refused:` and the caveats, and nothing
is written.

---

## 5b. Where policy comes from

You never type a policy. There is no policy file — Krab reads no
configuration (`NO-CONFIG.md`).

**At peering**, each end's `Policy` is signed *into the card*, so `peer offer`
publishes yours and `peer accept` takes in theirs. `peer seal` reports the
agreed terms, which are the **lower** of the two on every field, since a link
is only as capable as its least capable end (RFC 4 §5.4):

```
agreed: buckets to 5, relaying for others, 1073741824 retained
```

| Field | Means |
|---|---|
| `max_bucket` | largest object size accepted, as an RFC 1 §8.1 bucket index |
| `relay` | whether this node carries objects not addressed to it |
| `retention_bytes` | how much it holds for the shared corpus |
| `shard_bits` | RFC 2 §6 sharding — divides your load *and your anonymity set* |

Today these are the defaults: full participation, no sharding, 1 GB, all
buckets. There is no verb to change them yet.

**After peering**, terms travel on each re-key (`peer rekey`, and the
automatic one). That payload also carries what the card cannot: the node's
`CarriagePolicy` (RFC 6 §3.6 — whether it hosts channel content at all) and
its accepted TTL. The peer's current terms land in `peers/<their-id>/policy`,
and `peers` shows whether you are holding terms as of peering or terms as of
the last re-key.

Before re-keying existed, a policy was agreed once and never spoken of again:
a peer who stopped relaying had no way to say so.

---

## 5c. Starting weak is recoverable: `peer reseal`

A peering formed over `corpus` or `network` is not permanent. When you next
meet, or next get a voice call, upgrade it **in place** — you keep the
peer-link, the correspondent, and every message you hold.

```
> peer reseal fed356f2
re-sealing fed356f2.

currently: corpus — NOT post-quantum

next:
  peer reseal pad <destination>   — onto the medium you carry
  peer reseal wrap <file>         — or wrapped under spoken words

then, once you have theirs:
  peer reseal seal <their file> <in-person|media|spoken>
```

Both ends run it. Each generates a **fresh** contribution, exchanges it over
the stronger channel, and the new root is derived from the old root plus both
fresh halves:

```
new_root = HKDF(old_root ‖ fresh_A ‖ fresh_B ‖ epoch)
```

There is no Diffie–Hellman in it, unlike a re-key. A re-key mixes one because
its contributions travel *over the session*, so `dh` is what locks out an
adversary who read the disk. A re-seal's contributions never cross a recorded
channel at all — they are strictly better at that job, and adding a DH would
mix in a value the adversary *can* attack.

The old root stays in the mix so a re-seal proves **continuity**: only the two
ends of the existing peering hold it, so someone who obtains both fresh
contributions — by being handed a stick — still cannot produce the new root.
Without it, a re-seal would be indistinguishable from a fresh peering under an
old card, which is the shape of an impersonation.

**Both ends must run it**, or your roots differ and nothing opens.

A re-seal will not claim a weak channel, and it does not invent a fingerprint
comparison nobody performed: if that step is still outstanding, it stays
outstanding.

---

## 6. Check: `peer status` and `peers`

```
> peer status
step 3 of 5 — their card is recorded.

theirs:  <eight words>
yours:   <eight words>

compare those two aloud, then: peer pad <destination>
         (your SECRET half — write it onto the medium you carry)

then:    peer seal <their.pad> <in-person|media|corpus|network>
```

`peer status` names the step and the next verb. The ceremony survives
restarts, so you can start a peering, quit, and finish it tomorrow.

```
> peers
fed356f2  peered  ·  not connected  ·  terms as of peering
    a key read aloud · post-quantum, re-sealed 1×
```

The second line is **how the peering was formed** — the channel, whether it
survives X25519 being broken, whether fingerprints were ever compared, and how
many times it has been re-sealed. It is stored on disk beside the link, so a
peering made remotely on a bad afternoon still says so a year later.

`peers` lists **peerings**, which live on disk — they survive restarts and
failed connections. A dial that fails takes the link down and leaves the
peering untouched.

---

## 7. Then connect

One end waits, the other dials. **Both are needed** — two nodes that both dial
never meet.

```
# Bob, waiting
> listen 3f9a2c01 127.0.0.1:40000

# Alice, dialling
> connect 7b1e04ff tcp 127.0.0.1:40000
```

With `--listen` given at launch, the address may be omitted: `listen fed356f2`.

> **`--listen` starts the receive service.** Given at launch, it binds one
> socket and accepts calls from **any node this one has peered with** — no
> verb to type, nobody at the keyboard. A peering completed while it runs is
> accepted at once, without a restart.
>
> One socket, never one per peer: a port per peer publishes the size of your
> friend list to anyone who runs a port scan.
>
> An unknown caller is refused and not logged. RFC 4 §4.1 makes a mismatch a
> hard failure and never a prompt, and making it a log line would let anyone
> fill your activity log from outside.
>
> The `listen <peer>` verb still exists for a one-off, and waits 30 seconds
> before handing the prompt back.

**A peer with no stored `.link` cannot be connected to at all.** `establish`
reads the card to learn which static key to expect, and RFC 4 §4.1 forbids
proceeding without one. *"no peer-link for X — complete a peering first"*
means exactly that.

Over a modem or serial cable:

```
> listen 3f9a2c01 /dev/cu.usbserial-1420
> connect 7b1e04ff serial /dev/cu.usbserial-1420
```

On macOS use the `cu.` device, not `tty.` — `tty.` blocks in `open()` until
carrier detect, so dialling through it hangs with no error and no timeout.
Krab refuses it and tells you the right one.

No transport at all? That is what `pack` and `import` are for — write the
queue to a file, carry it, import it at the other end.

---

## 8. Connecting transfers nothing

```
link up 3f9a2c01 · tcp

nothing was transferred. Reconciliation is scheduled and does not
follow your keypresses (RFC 8 §5.1).
```

This is not a bug. Reconciliation runs on a schedule whose first interval is
drawn from entropy, not from the moment you connected — RFC 5 §6.1. A node
that synced when you pressed a key would leak when you pressed keys.

---

## Sequence, both ends

```
        ALICE                              BOB
        ─────                              ───
  1.    peer offer                         peer offer
                    ── alice.card ──▶
                    ◀── bob.card ───
  2.    peer accept bob.card               peer accept alice.card
                    ◀═ read aloud ═▶
  3.    peer pad /media/alice.pad          peer pad /media/bob.pad
                    ══ carried ═══▶
                    ◀══ carried ═══
  4.    peer seal bob.pad in-person        peer seal alice.pad in-person

        ──── or, no medium available: `corpus`, and a weaker link ────

  5.    connect <bob> tcp <addr>           listen <alice> <addr>
```

Step 2's voice call and step 3's carry are the only two things a network
attacker cannot forge. Everything else in the ceremony rests on them.

---

## What can go wrong

**"no ceremony in progress"** — run `peer offer` first. Ceremonies survive
restarts, so this means there genuinely is not one, not that you lost it.

**"a different card is already recorded for this ceremony"** — you accepted
someone else's card into this ceremony. Finish or discard it before starting
another.

**"no card recorded yet — run `peer accept <their.card>` first"** — `seal`
needs both halves. Accept their card before sealing.

**"unknown channel"** — the channel is not guessed, because it decides whether
the reservoir survives X25519 being broken. Say `in-person`, `media`, `corpus`
or `network`.

**"the stored peer-link does not verify"** — the `.link` file is corrupt or
was tampered with. Peer again.

**Fingerprints do not match when you read them aloud** — stop. Do not seal.
This is the check working.
