# Keeping node artefacts out of the repository

    Status:   the 2026-08-24 purge is done; the three defences below are live
    Scope:    what leaked, why, and what stops it recurring

---

## 1. What was committed

Four kinds of node artefact reached this repository and stayed in its history
for about three months:

| file | what it is |
|---|---|
| `identity.wrapped` | the key hierarchy, sealed under the KEK |
| `kek.params` | Argon2id parameters and **salt** |
| `corpus.krab` | the object store |
| `peer.pad` | a reservoir contribution **in the clear** |

The first two together are an offline brute-force target: the salt and the
cost parameters (64 MiB, t=3, p=4) are exactly what an attacker needs to start
guessing the passphrase against the wrapped hierarchy. The fourth needs no
passphrase at all — a `.pad` is `R_A`, one half of a reservoir, and RFC 7 §6.2
makes the reservoir the thing that survives X25519 being broken.

This was test material sealed under a test passphrase, so the exposure was
nil in practice. It is written down anyway, because the mechanism that
produced it was not specific to test material.

## 2. How it happened

A node writes its artefacts into `--home`. With no `--home` that is the
working directory, and during `cargo test` the working directory is the
package root — `apps/krab-tui`. So the test suite wrote a real key hierarchy
into a tracked source directory every time it ran, and `git add` did the rest.

Three things had to be true, and all three were:

1. **The default was a real path.** `--home` defaulting to `.` is convenient
   for one manual run and catastrophic under a test runner.
2. **`.gitignore` was written by hand and went stale.** It listed six
   artefacts because six existed when it was written. Ten more were added over
   the following months and none of them reached it, so `prekeys.ring`,
   `groups.sealed`, `channels.roster`, `duress.wrapped` and the rest were never
   ignored at all.
3. **Ignore rules do not apply to tracked files.** Once a path is in the index,
   git ignores the ignore rules for it — which is why adding entries for
   `identity.wrapped` did not stop `identity.wrapped` from being committed
   again in the next commit.

The second is the same failure as `wipe`'s, twice over: a rule stated in one
place and enforced only over the things that existed when it was written. That
pattern is documented in `apps/krab-tui/src/artifact.rs` and in
`MILESTONE-0.1.md` §5.1, and it is the most common defect in this codebase.

## 3. What stops it now

Three layers, in the order they act.

### 3.1 The default is gone

Test homes are per-test scratch directories. This is the root cause and the
only fix that removes the possibility rather than catching it.

### 3.2 `.gitignore`, checked by a test rather than by hand

`.gitignore` covers every `Artifact` and `PeerFile` variant, plus `peers/`,
plus suffix patterns for artefacts that do not exist yet.

It is not trusted to stay complete. `every_artifact_is_gitignored` in
`apps/krab-tui/src/artifact.rs` asks **git** — `git check-ignore`, for every
variant, at two directory depths — so adding an `Artifact` variant fails the
test suite until `.gitignore` covers it.

`no_artifact_is_tracked_by_git` covers §2's third point: it reads
`git ls-files` rather than the ignore rules, because a tracked artefact is
invisible to the rules that were supposed to stop it.

### 3.3 A pre-commit hook

`.githooks/pre-commit` refuses a commit with a staged artefact. Enable it once
per clone:

    git config core.hooksPath .githooks

There is no way to make that automatic, which is why it is the last layer and
not the first. The test is the durable one; the hook is what turns a mistake
into a message instead of a push.

## 4. The purge

History was rewritten on 2026-08-24 with `git filter-branch --index-filter`
over all 104 commits, removing five paths: `identity.wrapped`, `kek.params`,
`corpus.krab`, `peer.card`, `peer.pad`. Only the `0.1` branch had ever carried
them — `main` and the `rfc-*` branches were clean.

`HEAD`'s tree hash was identical before and after, so no source was lost, and
the commit count was unchanged.

**One caveat, stated rather than assumed.** A force-push makes the old objects
unreachable; it does not guarantee GitHub has deleted them. Unreachable objects
can remain fetchable by SHA until the server garbage-collects, and a fork or a
clone taken before the rewrite still has everything. For material of real value
the rewrite would be a mitigation and **key rotation would be the fix**. Here
the material was a test hierarchy under a test passphrase, so the rewrite is
sufficient and rotation is unnecessary — that judgement is the reason it is
recorded, not skipped.
