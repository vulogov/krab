# The command language, and why bund is not it — yet

You proposed BUND as the command pane's parser: define `connect`, `rekey` and
the rest as words, and let the interpreter parse. Not to execute external
scripts — to make strings, numbers, and command dispatch uniform.

That is a better proposal than the one I first argued against, and the problem
it identifies is real. This is what I did instead, and what would have to be
true for bund to be right.

---

## 1. The problem was real

Every argument was `line.split_whitespace().nth(n)`. That cannot express a
path with a space, and it does not fail when given one:

```
peer accept /Volumes/My Disk/bob.card
              ↑ argument 2 = "/Volumes/My", and "Disk/bob.card" is discarded
```

The operator is told `could not read /Volumes/My` — a path they never typed.
Removable media is exactly where pads and cards travel, and removable media is
mounted under names people gave it. This was going to happen to everyone.

So: strings, quoting, and typed numbers. You were right that the parser was
the weak point.

---

## 2. What was built instead

`apps/krab-tui/src/words.rs`. About 150 lines, no new dependencies.

```
line     := word*
word     := bare | quoted
quoted   := '"' ( <any but " or \> | '\' <any> )* '"'
```

- A bare token that parses as an integer **is** an integer; everything else is
  text.
- A **quoted** number stays text. `listen 40000` is a port; `listen "40000"` is
  not. A port and a filename are different kinds of thing, and the operator
  said which.
- An unterminated quote is **refused with its reason**, before any verb runs.
  Assuming it closed at end of line turns a visible typo into a command
  executed against the wrong argument.
- `\"` and `\\` escape; every other backslash passes through, because a
  Windows path is full of them and none of them mean anything else.

That is the whole of what you named — strings, numbers, uniform dispatch —
and it is a lexer, not a language.

---

## 3. What bund would add, and what it would cost

### The dependency surface

`bundcore` pulls in, by its own manifest:

```
bund_language_parser  >= 0.*.*
rust_dynamic          >= 0.*.*
rust_multistackvm     >= 0.*.*
lazy_static  1.5.0    log  0.4.28    nanoid  0.4.0    easy-error  1.0.0
```

Krab's tree is 130 crates and **every version requirement in it is exact**.
Three at `>=0.*.*` is not a reproducibility problem — `Cargo.lock` pins what
was resolved — but `REPRODUCIBLE-BUILDS.md` claims an *auditable* dependency
set, and "any future 0.x, including breaking ones" is the opposite of a claim
about what went in.

Two of the others matter on their own terms:

- **`lazy_static`** is global mutable state. This codebase's central
  discipline is that randomness is an argument and never ambient —
  `krab-core` is `no_std` and zero-dependency so the compiler enforces no
  clock, no I/O, no entropy. A VM with global state is that rule inverted.
- **`nanoid`** draws randomness ambiently. Same rule, same objection.

None of this is a criticism of bund. It is a general-purpose language doing
general-purpose things, in a codebase that has spent its whole life refusing
them.

### The word order

Concatenative means postfix. Every documented command reverses:

```
connect fed356f2 tcp 127.0.0.1:40000        today
"127.0.0.1:40000" "tcp" "fed356f2" connect  concatenative
```

That invalidates `INIT.md`, `PEERING.md`, `help`, and whatever muscle memory
an operator has. Solvable — accept both, or make the verbs prefix-parsing
words — but it is a real cost paid on the common case to buy composition on
the rare one.

### The hazard: composition meets irreversibility

This is the part that is not a trade-off.

A concatenative language makes `peers each wipe` expressible. So is a loop
over `duress`, over `peer seal`, over the panic chord's effect.

The value of `wipe` asking twice, of the panic chord needing four fingers at
once, of the fingerprint comparison being a voice call — is **friction**.
Every one of those steps exists because a human should do it once,
deliberately, having thought about it. A loop is a friction remover. That is
what loops are for.

The panic chord is the instructive one, because its friction moved. It used to
arm on one press and fire on a second within three seconds, and that was the
wrong shape: the delay fell at the only moment the key exists for, while the
protection it bought — one second of second thoughts — is protection against a
mis-strike rather than against a mistake. The chord itself is the friction now.
Four simultaneous keys is a deliberate hand position; a loop cannot strike it,
and neither can a sleeve.

So a language here would need a rule its designer never intended, and the rule
is the interesting part:

> **Two classes of word.**
>
> - **Composable** — queries and idempotent actions: `peers`, `reach`,
>   `status`, `keys`, `connect`, `rekey`. Loop over these freely.
> - **Ceremony** — refuse to execute unless the word is the *sole* word on a
>   line typed by a human this keystroke: `init`, `wipe`, `duress`, `unlock`,
>   `peer accept`, `peer seal`.
>
> A ceremony word inside a definition, a loop, or a composed line is a parse
> error, not a runtime refusal — so it cannot be reached at all.

That rule is enforceable and it is most of the design work. Without it, adding
a language to this command pane makes the node less safe, and does so in a way
no test would catch because every individual verb still behaves correctly.

---

## 4. Where bund would genuinely win

Not command dispatch — twenty verbs do not need a VM. The places a language
earns its dependencies are where the *data* is open-ended:

| Candidate | Why a language helps |
|---|---|
| **Carriage policy** (RFC 6 §3.6) | "carry channels matching this prefix, under this size, from these authors" is a predicate, and predicates want an expression language |
| **Reconciliation filters** (RFC 5) | which objects to advertise on which link, by class and expiry |
| **Retention** (RFC 7 §4) | what to evict first when the quota binds |

All three are things Krab currently expresses as struct fields with fixed
semantics, and all three will want to be expressions eventually. That is a
much stronger case than parsing `connect`, and it does not touch the ceremony
verbs at all.

---

## 5. Recommendation

1. **Now:** `words.rs`. Ships, fixes the truncation bug, no new dependencies.
2. **If composition is still wanted:** bund behind a `--features bund`
   feature flag, off by default, with the two-class rule above enforced at
   parse time. That keeps the default build's dependency set exactly as
   auditable as it is today while the idea is evaluated against real use.
3. **The strong case:** revisit bund when carriage policy or reconciliation
   filters need to be expressions rather than fields. Then the language is
   buying something a struct cannot express, rather than replacing a parser
   that works.

The open question I cannot answer without reading further: whether
`bundcore` can be embedded with **no global state and no ambient
randomness** — a VM instance owned by the caller, entropy passed in. If it
can, objection (1) in §3 mostly dissolves and step 2 becomes cheap. If it
cannot, that is the thing to fix first, and it would make bund a better
citizen everywhere, not only here.
