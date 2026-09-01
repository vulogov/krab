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

---

## In memory, the same limit applies — and it is worse

Everything above is about a secret leaving the disk. RFC 7 §9.1 states the
limit on the other side of that boundary, and requires it be said out loud:

> **Rust cannot guarantee a secret was never copied.** Moves, reallocation,
> and compiler optimisations may leave residue that zeroizing never sees.
> Fixed buffers and `mlock` reduce the exposure substantially; nothing
> eliminates it. This MUST appear in the security considerations of any
> release rather than being glossed.

It is stated here because it had been stated only in the specification, which
is not a release document — the requirement is that a *release* say it, and
this is the release document about exactly this subject.

What it means concretely, for this build:

- **`Zeroize` on drop reaches the buffer a value currently occupies.** It does
  not reach a buffer an earlier `Vec` growth abandoned, a stack slot the
  optimiser spilled to, or a register. `Line::overwrite` and
  `TagTable`'s `Drop` both say so where they are implemented.
- **Fixed-size arrays are used for key material** rather than `Vec`, because
  growth reallocates and leaves the previous contents behind. That is a
  reduction in exposure, not a removal of it.
- **Memory locking is implemented, for one secret, on unix and Windows.**
  `krab-lock` locks the pages the identity's private keys live in — `mlock` on
  unix, `VirtualLock` on Windows — and warns loudly at startup if the kernel
  refuses. That is usually `RLIMIT_MEMLOCK` headroom on unix, which `ulimit -l`
  raises, and the process minimum working set size on Windows. The epoch key,
  the KEK, the reservoir roots and the tag table are **not** locked, and
  `Documentation/UNSAFE-AUDIT.md` says why for each. Disabling swap, or using a
  randomly-keyed swap device, remains the operator's mitigation for everything
  not on that first line.
- **Windows operators have three extra exposures**, none of which this program
  can detect or fix: automatic crash dumps and Windows Error Reporting capture
  process memory regardless of locking; the pagefile is not encrypted unless
  `fsutil behavior set EncryptPagingFile 1` has been run; and the Windows arm
  is compiled and cross-checked but has never been *executed* by this project's
  test suite. `UNSAFE-AUDIT.md` states each in full. They are listed here
  because RFC 7 §9.1 requires the limits appear in a release document, and a
  limit that applies to one platform only is still a limit.
- **Hibernation writes all of RAM to disk** and defeats every mechanism in
  this document. RFC 7 §9 names it; nothing in software can prevent it.

- **Core dumps and debugger attach are shut at the first statement of `main`.**
  `krab_lock::harden` sets `RLIMIT_CORE` to 0 — soft *and* hard, so it cannot
  be raised back by this process — and on Linux clears `PR_SET_DUMPABLE`, which
  suppresses dumps and blocks same-uid `ptrace` in one call. macOS additionally
  refuses debugger attach with `PT_DENY_ATTACH`. On Windows this is only
  **partial**: `SetErrorMode` suppresses the crash dialog, Windows Error
  Reporting can still collect a dump, and there is no supported way for a
  process to refuse a debugger. The startup line says which of these you got.

  **None of it stops root, Administrator, or physical access.** It raises the
  cost for an adversary running at this process's own privilege. RFC 7 §4's
  crypto-shredding is what addresses seizure; this is defence in depth behind
  it and must not be described to an operator as more.

`panic = "abort"` is set so a panic cannot unwind through a partially-zeroized
structure, and `Debug` on every key type prints a redaction rather than bytes.
Those two are real and they are narrow.

**A correction.** This paragraph previously said `panic = "abort"` was what
stopped a core dump carrying key material, as did `Cargo.toml` and
`ADVERSARIAL-PASS.md`. It is the opposite: abort raises `SIGABRT`, whose
default disposition is to write a core file, whereas unwinding writes none. RFC
7 §9 lists `panic = "abort"`, `RLIMIT_CORE = 0` and `prctl(PR_SET_DUMPABLE, 0)`
as three separate measures; this build had implemented only the first and
described it as doing the job of the other two. All three are now in place.

---

## The 64-bit MAC on `short` framing — RFC 4 §8

§8 does not merely permit this disclosure, it requires it:

> A 64-bit truncated MAC is defensible only because the link is pairwise,
> mutually authenticated, and low-volume. Implementations MUST restate this in
> their security documentation rather than treating it as settled by citation.

This is that restatement, and it sits beside RFC 7 §9.1's above because the two
are the same kind of obligation: a limit the specification insists a *release*
state in its own words rather than point at.

**An 8-byte tag gives an online forger a 2⁻⁶⁴ chance per attempt.** By modern
standards that is not a comfortable margin — 128 bits is the default for good
reason — and it is accepted here only because all three of §8's conditions hold.
Each is load-bearing:

- **Pairwise.** There is exactly one other party who could forge, and they
  already hold the key, so forgery gains them nothing they cannot do honestly.
- **Mutually authenticated.** A forger must be inside an established Noise
  session (RFC 4 §4.1) to deliver an attempt at all. An off-path attacker gets
  no attempts, not merely unlikely ones.
- **Low-volume.** The counter caps a key at 65 535 messages, and
  `krab_crypto::short::seal` **refuses** rather than wrapping — a repeated
  nonce under ChaCha20-Poly1305 leaks the Poly1305 key, so a wrap is silent and
  total. The reservoir rotates the key per epoch (RFC 7 §6) long before the cap
  in normal use.

**If any of those three stops being true, this framing stops being
defensible.** In particular `short` must never be carried on a broadcast link,
on a channel, or on anything a third party can inject into. Nothing in the type
system enforces that — it is a deployment property, which is why it is written
here rather than left to a comment.

Two further properties of the implementation, since §8 asks for candour rather
than citation:

- The tag comparison has **no early exit**. Returning at the first differing
  byte would leak how much of a forged tag was correct, which is precisely the
  grind an 8-byte tag cannot afford.
- The 10-byte header travels in the clear and is **authenticated as associated
  data**. Without that, the destination tag and expiry of a message an attacker
  cannot read would still be malleable.
