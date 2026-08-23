# Priming an empty node

How to take a machine with nothing on it and end up with a node that has a
key hierarchy, a store, and a passphrase that opens it.

This describes what the code does. Where it differs from an RFC, the RFC is
cited and the difference is stated.

---

## 1. Before you start

Krab **reads no configuration file** — see `NO-CONFIG.md`. Everything is
either a command-line argument or a verb typed into the command pane. There is
nothing to prepare, edit, or copy onto the machine first.

Two arguments exist:

```
krab [--home <dir>] [--sync-interval <seconds>] [--listen <address>] [--relay]
```

- `--home` is where the store lives. **Default is the working directory.**
  Give it explicitly if you are running more than one node on a host, or if
  you care where the files land.
- `--listen` names the address inbound links arrive on. Optional; a node that
  only dials never needs it.
- `--relay` locks the node the moment it opens — see §8.
- `--sync-interval` is the mean reconciliation interval. Under 60 seconds is
  refused — RFC 5 §6.1, a node that syncs that often is correlated with its
  own activity.

`KRAB_HOME` is **not** consulted, deliberately. Environment is inherited, so a
parent process would be choosing the store location without the operator
seeing it.

The directory is created if it does not exist.

---

## 2. The first screen

```
krab --home ~/krab-alice
```

```
┌ messages ─────────┐┌ message ───────────────────────────┐
│(no messages)      ││no message selected                 │
│                   ││                                    │
└───────────────────┘└────────────────────────────────────┘
┌ output ───────────────────────────────────────────────┐
│krab — no identity yet. Type `init`, or `help`.        │
└───────────────────────────────────────────────────────┘
 Ctrl-Q quit · Ctrl-O full screen · Esc back · help ─────
> ▏
```

Focus starts on the command line. Type.

Four panes: the message list, the message view, command **output**, and the
command line. The rule above the prompt carries node status, or the chords
when there is no status to report.

| | |
|---|---|
| `Ctrl-Q` | quit — writes the corpus out first |
| `Ctrl-O` | full-screen the focused pane; the command line and output pane go together |
| `Ctrl-L` | lock immediately |
| `Ctrl-1` / `Ctrl-2` | private messages / channels |
| `Esc` | back to the default screen, in one keystroke |
| `Tab` | move between panes |
| `z` | zoom the focused pane |

The command line is a real line editor: arrows, `Home`/`End`, `Ctrl-←`/`Ctrl-→`
for words, `Ctrl-W` / `Ctrl-U` / `Ctrl-K` to delete a word, to the start, to
the end. **This works at the passphrase prompt too**, which is the place it
matters most — the passphrase is masked, so an operator who cannot correct a
typo cannot recover from one.

Type `help` for every verb. Output longer than two lines renders into the
message pane (RFC 8 §3), so look right, not down.

---

## 3. `init`

One verb, four acknowledged steps. Each `Enter` advances one step. The
ceremony owns `Enter` while it runs, and `Esc` does **not** cancel it —
losing a half-built key hierarchy to a stray keystroke would mean starting
over.

### Step 1 — the passphrase

```
> init
choose a passphrase — it is the only root
```

Type it. The prompt masks it and shows length only.

**An empty passphrase is refused.** RFC 7 §4 makes the KEK the only root: an
empty one is a store that anyone who picks up the disk can open. There is no
way past this step without one.

The passphrase is stretched with Argon2id at RFC 7 §4.1's parameters — 64 MiB
and roughly half a second. That delay is the feature; it is what a seized disk
has to get through, per guess.

### Step 2 — generation

```
generating…
generated 3f9a2c01
```

Every key this node will ever hold originates here:

| Key | Curve | For |
|---|---|---|
| identity | Ed25519 | signing cards, credentials, channel posts |
| Noise static | X25519 | the link handshake (RFC 4 §4.1) |
| correspondence | X25519 | tag derivation, sealing |
| first prekey batch | X25519 | RFC 7 §5 |

`3f9a2c01` is this node's **short id** — the first four bytes of its node id,
which is derived from the identity public key.

It is **not secret**. It is in every card you hand out, it is the filename
your peers store your link under, and it is the name you type into `connect`.
Treat it like an address, because that is what it is.

You do not need to write it down. `keys` and `verify` print it any time the
node is unlocked, and `verify` also gives the eight-word form you read aloud
during peering.

### Step 3 — the backup words

```
write these words down, offline, now

  <word list>

This is the only copy.
```

The word list renders into the **message pane**, because it does not fit in
two rows. If you see "see the message pane", look right.

This is the 64-byte offline backup from RFC 7 §11 — the identity seed and the
correspondence key, as words.

**This is the part that is actually secret, and actually shown once.** Write it
on paper. Now, not later:

- **It is shown once.** RFC 7 §11 requires the backup be made at creation, and
  the ceremony is what enforces that. There is no verb that prints it again.
  This is unlike the short id above, which is public and always available.
- **It does not recover your messages.** RFC 7 §11 is explicit that message
  history is not recoverable, and that is intentional — see §8, epoch keys are
  erased.
- **What it recovers is your identity.** Without it, every peer must re-verify
  you out of band, in person, from scratch.

### Step 4 — confirm

```
> (Enter)
```

The step that cannot be skipped. Pressing `Enter` here asserts you wrote the
words down. Nothing checks that you did; the friction is the point.

Then the KEK is derived, the epoch wrapper is opened, and three files appear
in `--home`:

| File | What |
|---|---|
| `identity.wrapped` | the key hierarchy, wrapped under the KEK |
| `kek.params` | Argon2 parameters and salt |
| `corpus.krab` | the store |

If any write fails — a read-only directory, a full disk — **the ceremony says
so and stops**. It does not report success over an empty disk.

---

## 4. Check it worked

```
> keys
> verify
```

`verify` prints your eight-word fingerprint, the one you read aloud during
peering. `keys` says what key material exists.

Then quit and come back:

```
> quit
$ krab --home ~/krab-alice
a store is here. `unlock` to open it.
> unlock
```

`unlock` asks for the passphrase and re-derives the KEK. It is the only way
back in — there is no recovery path, by design.

`init` on a node that already has a store is **refused**. It would generate a
new hierarchy over the old one and make every existing message unreadable.

---

## 5. What can go wrong

**"a passphrase is required — it is the only root"** — the passphrase step
will not advance while empty. Type one.

**"could not write kek.params: …"** — the store could not be written. The
ceremony stopped rather than pretending. Check the directory is writable and
run `init` again; nothing was saved.

**"this node already has an identity; `init` runs once"** — there is a store
in this `--home`. Use `unlock`. If you meant a *different* node, give a
different `--home`.

**"the passphrase did not unwrap the identity"** — a wrong passphrase and a
tampered store are deliberately indistinguishable (RFC 7 §4). Distinguishing
them would tell someone holding the disk which guess was closer.

**Nothing appeared in `--home`** — check you completed all four steps. Nothing
is written until the last one: the KEK is derived at the end, and without it
there is nothing to wrap the keys under.

---

## 6. Two nodes on one host

Separate homes, separate listen addresses:

```
krab --home ~/krab-alice --listen 127.0.0.1:40000
krab --home ~/krab-bob   --listen 127.0.0.1:40001
```

`init` each one separately. They are strangers until you peer them — see
`PEERING.md`.

---

## 7. Panic

`wipe` destroys the key hierarchy. It asks once, and it means it: RFC 7 §10,
irreversible, no recovery from the backup words for anything but identity.

`duress` sets a second passphrase that opens a different corpus. Under
coercion, it unlocks silently and presents what a freshly initialised node
presents — no warning, no distinct message, and no timing tell, because one
Argon2 derivation runs either way.

Erased artefacts are overwritten before removal — see `SECURE-DELETE.md` for
what that does and does not buy you.

---

## 8. Running a relay

A relay carries for the friends you chose without holding a readable corpus.
It is **not** a daemon and not a special build: it is this same program in the
state `lock` already defines.

```
$ krab --home ~/krab-relay --listen 0.0.0.0:40000 --relay
> unlock
  (passphrase)

relay.

This node is locked and will stay locked. It reconciles for the peers you
chose and cannot read a message — including its own.

Its disk is encrypted under the passphrase you just entered, which is the
whole reason it asked: a relay that took no passphrase would leave its
peer list in the clear.

`unlock` makes it an ordinary node again.
```

**It still asks for the passphrase, and that is the point.** An earlier design
had a relay take none, which left its disk unencrypted and made RFC 0 §4.4's
*"seizure yields nothing"* false for the peer list — the one thing a seized
relay would actually reveal. One prompt at start buys the same key hierarchy
every other node has.

It keeps reconciling while locked. Pausing would publish the operator's daily
rhythm — when they are at the keyboard and when they are not — which
`MILESTONE-0.1.md` calls a worse violation than mail-driven sync.

There is deliberately **no headless mode**. RFC 8 forbids one, and a relay that
could start without a human is a relay whose passphrase lives somewhere a
machine can read.
