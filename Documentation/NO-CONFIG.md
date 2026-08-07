# No configuration files

**Krab reads no configuration file, at any point, for any purpose.** Every
behaviour is chosen by a keyboard chord, a command-pane verb, or a
command-line argument at launch. Where those disagree, the command pane wins,
because it is the most recent deliberate act.

Author's constraint, recorded here because it is not derivable from the RFCs
and an implementer will otherwise add one — a config file is the obvious way to
avoid retyping things.

## Why

A config file is **unauthenticated state that changes behaviour**, sitting on
the one surface this system assumes is hostile.

RFC 7 §4's entire premise is that the disk may be seized or tampered with. The
response everywhere else is to wrap or sign: message bodies are sealed,
epoch keys are wrapped under the KEK, credentials are signed, and objects are
named by their own hash. A config file has none of that, and it does not need
to be read to be dangerous — it needs only to be *written*.

The concrete failures are quiet ones:

| edit | effect | what the operator sees |
|---|---|---|
| `shard_k = 12` | admits 1/4096 of the corpus | mail stops arriving, no error |
| `max_bucket = 0` | drops everything over 256 B | some mail arrives, some does not |
| `relay = false` | node stops carrying for others | nothing; the network degrades |
| `sync_interval = 30` | correlates the node with its own activity | nothing; an observer benefits |

Every one is silent. RFC 0 §6 makes delivery failure silent **by design**, so
there is no error path for a misconfiguration to surface through. A file that
can turn off delivery, and a system that never reports delivery failing, is a
combination with no failure mode a user can act on.

The same applies to a leaked file rather than a tampered one: a config listing
peers, endpoints, or shard parameters is a map of who this node talks to, in
plaintext, with no expiry, next to a store where everything else has one.

## What is allowed on disk, and why it is different

The distinction is **authentication**, not secrecy:

| file | protection | why it is fine |
|---|---|---|
| `*.link` | Ed25519 signature | a forged card fails `Card::verify` |
| `*.reservoir` | sealed under `W_N` | unreadable without the passphrase |
| `ceremony.cbor` | signed cards + wrapped contribution | same, per field |
| segments | content-addressed | every object hashes to its own name |

Each is either signed or wrapped, so tampering is *detected* rather than
*obeyed*. That is the property a config file cannot have, because the thing it
configures is the code that would check it.

## Consequences for the implementation

- **Startup options are command-line arguments.** Not an env var: environment
  is inherited, so a parent process chooses it and the operator may not know.
- **Runtime changes are command-pane verbs**, and last only for the session.
- **Nothing is remembered between runs except signed or wrapped data.** If a
  setting would need to persist, it belongs in the peer-link — which is signed
  by both parties and therefore is not configuration but agreement.
- **A dropped default is stated, not silently applied.** Where a command omits
  an argument, the interface says which default was used.

That last point is what makes this liveable. The cost of no config is retyping;
the mitigation is that the node says what it assumed.

## What this rules out that looks reasonable

- A remembered peer list that auto-connects at launch. Peers come from
  `*.link` files, which are signed, but *connecting* is an act the operator
  takes.
- A saved shard setting. `k` reduces a correspondent's anonymity set by `2^k`
  (RFC 2 §6); it is not a preference to be restored from disk.
- A "last used transport". `reach` exists because a wrong link profile is
  invisible (RFC 8 §5.2), and a remembered one is a wrong profile nobody chose.
