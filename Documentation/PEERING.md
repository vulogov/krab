# Peering — quickstart

Two nodes that have each run `init` (see `INIT.md`) are strangers. Peering is
what makes them friends: it exchanges signed cards, mixes a shared reservoir,
and produces a **peer-link** — the durable artifact RFC 3 §4 makes the contract
between two nodes.

There is no discovery, no directory, and no trust-on-first-use. RFC 4 §4.1
makes a static-key mismatch a hard failure and never a prompt.

---

## The shape of it

Peering is **symmetric**. Both ends run the same four verbs. Each end produces
two artifacts and needs two from the other:

| Artifact | Secret? | How it travels |
|---|---|---|
| `peer.card` | **No** — public and signed | any channel you like |
| `peer.pad` | **Yes** — half a shared secret, in plaintext | see §4 |

The card and the pad **must not travel together**. Anyone who has both has
what they need; the whole point of splitting them is that no single channel
carries the peering.

---

> **After a restart, `unlock` first.** Every `peer` verb needs an unlocked
> node: the contribution is held wrapped inside the ceremony, and sealing the
> reservoir needs the epoch wrapper. A locked node is a relay — it reconciles
> and cannot read.

## 1. Both ends: `peer offer`

```
> peer offer
peer.card  — publishable; send it any way you like
peer.pad   — SECRET; hand over in person or on media

your fingerprint, to read aloud:

  <eight words>
```

This writes `peer.card` into your `--home` and opens a ceremony that survives
a restart.

**`peer.pad` is not written yet.** The contribution is held wrapped inside the
ceremony. It becomes a plaintext file only when you ask for it, with
`peer pad`, onto the medium you are carrying — see §4. That is deliberate: it
is the one artifact Krab cannot protect once it exists, so it exists for as
short a time as possible.

Send your `peer.card` to the other end. Email, chat, a web page, a QR code —
it is signed, so tampering is detectable, and public, so exposure costs
nothing.

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
| `corpus` | through the Krab network itself | no |
| `network` | any other online path | no |

The reservoir is what makes a link post-quantum. A pad that travelled over the
network is only as good as the X25519 protecting it — which is fine today and
is exactly what a store-and-forward adversary is recording against later.

**`in-person` or `media` if you can.** If you cannot, `corpus` still works and
Krab will tell you what you got.

Neither route practical? There is a proposal for moving a pad over a network
without giving up the post-quantum property — a transfer key read aloud over a
voice call, with all the warnings that implies. It is **not implemented**; see
`PAD-OVER-NETWORK.md`.

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

## 6. Check: `peer status` and `peers`

```
> peer status     how far along each ceremony is
> peers           who this node is peered with
```

`peer status` is what to run if you lose track — the ceremony survives
restarts, so you can start a peering, quit, and finish it tomorrow.

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

With `--listen` given at launch, the address may be omitted: `listen 3f9a2c01`.

`listen` waits 30 seconds, then hands the prompt back. It does not run in the
background — that wait is on the UI thread, and an unbounded one would be a
hung interface.

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
