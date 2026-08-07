# Secure delete — why RFC 7 §4 forbids relying on it, and what to do instead

> "**Implementations MUST NOT rely on file deletion or overwriting for any
> forward-secrecy property.** Where a specification in this series says
> *erase*, it means destroy the wrapping key." — RFC 7 §4

## Why overwriting does not do what it looks like it does

The instinct is sound on 1990s hardware: the filesystem addresses a sector, the
drive writes that sector, the old magnetic state is replaced. On anything
shipped in the last fifteen years, almost every step of that is false.

**The flash translation layer.** An SSD, eMMC or UFS device presents a logical
block address space that has no fixed relationship to physical pages. Writing
LBA 100 allocates a *new* physical page and remaps; the page holding the old
content is marked stale and erased at the controller's convenience — possibly
in an hour, possibly never, and it is not addressable from the host in the
meantime.

**Wear levelling makes it worse, actively.** The controller *copies* data
between physical pages to spread erase cycles. A secret written once may exist
in several physical locations before anyone tries to delete it, and the host
was never told.

**Over-provisioning.** Consumer SSDs reserve roughly 7%, enterprise drives up
to 28%, of physical capacity that the host cannot address at all. Stale pages
live there. `blkdiscard` and TRIM are *hints*; the specification permits a
device to ignore them, and some do.

**Copy-on-write filesystems.** btrfs, ZFS and APFS do not overwrite in place by
design — an overwrite allocates a new extent and updates metadata. The old
extent survives, and if a snapshot references it, survives deliberately and
indefinitely. This is a filesystem the user probably chose for its
snapshotting.

**Journals and delayed allocation.** ext4 with `data=journal` writes content
into the journal as well. Without `fsync`, an overwrite may live only in the
page cache and never reach the medium before the unlink frees the blocks —
which is the failure that looks most like success.

**Anything underneath.** Full-disk encryption layers, LVM, network block
devices, VM disk images with their own copy-on-write, and hypervisor snapshots
each add another indirection that the overwrite does not reach.

So a successful overwrite tells you the **filesystem's view** is clear. It says
nothing about the device. RFC 7 §4 forbids relying on it because relying on
something that reports success while doing nothing is worse than not having it:
the operator believes a thing is gone and acts accordingly.

## Two mechanisms, two adversaries

The important thing RFC 7 §4 does *not* say is that overwriting is pointless.
It says it must not be **relied on for a forward-secrecy property** — because
that property must hold against an adversary with the disk and no key, and
overwriting cannot promise anything against that adversary.

But that is not the only adversary, and the two mechanisms are not substitutes:

| | key destruction | overwriting |
|---|---|---|
| adversary holds the disk, never gets the key | **defeats them** | irrelevant |
| adversary obtains the key **later** — coercion, keylogger, a weak passphrase brute-forced at leisure | useless; the key opens what remains | **defeats them, where it works** |
| the ciphertext becomes readable in twenty years | useless | **defeats them, where it works** |
| adversary reads only metadata — file names, counts, sizes | partial | removes the listing |

Key destruction is the *guarantee*, and it holds only against the first row.
Overwriting is the *hedge*, and it is the only thing that touches the rest.
Krab's threat model explicitly includes coercion (RFC 7 §10's panic wipe exists
because someone may be made to unlock), so the second row is not hypothetical —
it is a scenario the design already names.

**So overwriting is applied to everything Krab removes, ciphertext included.**
Ciphertext that has been overwritten is one fewer thing a later-obtained key
opens. It costs microseconds and claims nothing.

What it must never do is *license* writing plaintext, which is the failure the
next section is about.

## Where the guarantee comes from

**Never write the plaintext.** If every byte on disk is already ciphertext under
a key the node can destroy, then erasure is key destruction and the storage
controller's behaviour becomes irrelevant. That is RFC 7 §4's hierarchy, and it
is why it exists.

The audit question is therefore not *"how do we delete better?"* but **"is there
anything we write that is not ciphertext?"** For Krab, as of this change:

| file | ciphertext? | notes |
|---|---|---|
| `identity.wrapped` | yes | sealed under the KEK |
| `corpus.krab` | yes | object bodies are HPKE-sealed |
| `*.reservoir` | yes | sealed under `W_N` |
| `ceremony.cbor` | yes | contribution wrapped under `W_N` |
| `*.link`, `peer.card` | n/a | public, signed, meant to be readable |
| `kek.params` | n/a | non-secret; tampering is self-defeating |
| ~~`peer.pad`~~ | **was not** | **removed — see below** |

### The one that was wrong, and the fix

`peer.pad` held this node's reservoir contribution `R_A` **in the clear**,
because it has to be handed to a person. There is no key whose destruction
removes it, so it was the one file where overwriting was the only tool — which
is exactly the position RFC 7 §4 says not to be in.

It was also **redundant**. `ceremony.cbor` already holds `R_A` wrapped under
`W_N`. The plaintext copy existed only so the operator had a file to carry.

So the fix is not to shred it more carefully. It is:

- **`peer offer` writes only the card.** The card is public and signed; nothing
  unwrapped touches the node's disk.
- **`peer pad <destination>` materialises `R_A` to a path the operator names**,
  which should be the removable medium itself. The node's own storage never
  holds it.

The plaintext then exists only on the medium being handed over, which is a
physical object under the operator's control rather than a disk that stays
behind. That is the same trust model as the ceremony itself, and it is the
distinction RFC 7 §4 is drawing: a secret you are *carrying* is a different
problem from a secret you are *storing*.

If an operator does stage it locally, they chose to, and they know a file is
there — as opposed to the previous behaviour, where the node created one
silently.

## What the overwrite is for

`shred::remove` is applied to **every artifact Krab removes**, whether or not
its contents are encrypted:

- **`wipe`** — the identity, the corpus, every peer-link and reservoir. The
  erasure is the key destruction; the overwrite is what a later-obtained key
  cannot undo. It also removes the *listing*: a directory of `*.link` files is
  a list of who this node peered with, legible even when every file's contents
  are not.
- **A completed ceremony** — `ceremony.cbor` holds a wrapped contribution, and
  the wrapping key is `W_N`, which is retained for 45 epochs. Overwriting the
  record now means the reservoir root is not recoverable during that window
  even by someone who obtains the passphrase.
- **A staged pad**, if an operator wrote one to local storage.

On rotational media and in-place filesystems it works. On flash or
copy-on-write it may do nothing, and it does not need to — nothing depends on
it. That is the whole distinction between a hedge and a guarantee.

### Cost and unpredictability, not just probability

The weaker argument for overwriting is "it may have worked." There is a
stronger one, and it holds even when the overwrite touched nothing.

**Random bytes rather than zeros makes forensic triage harder.** An analyst
imaging a device works by prioritising: which regions look like structured
data, which look like a filesystem, which look like they were cleared. A
zero-filled region answers all three questions at once — it is visibly a region
someone deliberately erased, which is both a signpost and a statement about the
operator's intent.

Random bytes answer none of them. They are indistinguishable from the
ciphertext that surrounds them, and everything else Krab writes *is*
ciphertext. So an analyst cannot tell:

- which regions were overwritten and which are live objects,
- how much was deleted, or when,
- whether a region is a stale FTL page worth recovering or noise worth skipping.

That converts a targeted search into an undirected one. The adversary's cost
rises whether or not any particular overwrite reached the medium, and their
results become unreliable rather than merely incomplete — they cannot know what
they missed, which is a different and worse position than knowing a file is
gone.

None of this is a guarantee and none of it should be described as one. It is
the difference between *"we recovered nothing"* and *"we cannot establish what
was here"*, and for an adversary who has to act on findings, that difference is
substantial.

**`shred::remove` returning `true` is never evidence that data is
unrecoverable**, and the module says so where a caller will read it. The value
is real and it is probabilistic; the guarantee is elsewhere.

## What we do not do, and why

- **`blkdiscard` / TRIM on the file's extents.** A hint the device may ignore,
  requiring privileges Krab should not want, and offering a guarantee it cannot
  keep.
- **Multi-pass overwriting.** Gutmann patterns address encoding schemes no
  current drive uses. On flash, thirty-five passes remap thirty-five times.
- **Filesystem-specific secure-delete flags.** `chattr +s` is unimplemented on
  ext4. A feature that exists in the interface and not in the code is worse
  than its absence.

Each would add a claim the implementation cannot support. The hierarchy already
provides the property; the right move is to make sure everything is inside it.
