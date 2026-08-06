# RFC 8 — Client Behaviour

    Number:      8
    Title:       Client Behaviour
    Status:      Draft
    Repository:  https://github.com/vulogov/krab
    Author:      Vladimir Ulogov
    Requires:    RFC 0, RFC 3, RFC 4, RFC 5, RFC 6, RFC 7
    Grounded by: none — see §1.1
    Errata:      none

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be
interpreted as described in RFC 2119.

---

## 1. Scope

The client is where every property the other seven documents establish is
either preserved or destroyed. A correct object format, a sound key
hierarchy, and a measured convergence model are all defeated by an
interface that lets a user post to a channel believing they are in a
group.

This document specifies the terminal client: layout, the security
boundary, the command set, and the constraints the rest of the series
places on presentation.

### 1.1 Epistemic status — this document is not measured

**Every other RFC in this series is grounded in measurement.** SIM-0 and
SIM-1 produced the convergence and overhead figures; `krab-sizes` produced
every byte count. Where those measurements contradicted a design claim,
the claim was corrected — three times so far, in RFC 2 §8, RFC 5 §11, and
RFC 7 §13.

**RFC 8 has no simulator, and the central risk it addresses cannot be
simulated.** There is no measurement for *the user believed they were in a
private group while posting to a public channel*, which RFC 6 §5 already
identifies as the worst failure Krab can produce. A usability study is not
a simulation, and this project has neither.

Requirements here fall into two classes, and the document marks which:

| class | basis | example |
|---|---|---|
| **derived** | a measured constraint elsewhere in the series | peer-count warnings (§9.2), from SIM-0's delivery figures |
| **judgement** | design argument only | the composer banner (§4.2) |

A derived requirement can be checked against its grounding. A judgement
requirement cannot, and a reviewer should treat it as an argument to be
disagreed with rather than a result to be accepted. Where this document
says "MUST" on a judgement requirement, it means *the author believes the
failure mode is severe enough to warrant a hard requirement despite the
absence of evidence* — not that evidence exists.

---

## 2. Layout

Two tabs. **Secure messaging is the default tab and MUST be the tab the
client opens on**, so that the safe context is the one reached by
inattention.

```
┌ Private messages │ Channels ─────────────────────────────────────────┐
│                        │                                             │
│  LIST PANE             │  MESSAGE VIEW PANE                          │
│  40%                   │  60%                                        │
│                        │                                             │
│                        │  ┌───────────────────────────────────────┐  │
│                        │  │ NEW MESSAGE PANE (overlays view)      │  │
│                        │  └───────────────────────────────────────┘  │
│                        │                                             │
├────────────────────────┴─────────────────────────────────────────────┤
│ COMMAND PANE — 2 lines, combined input and output                    │
└──────────────────────────────────────────────────────────────────────┘
```

```
The list pane MUST occupy 40% of width, on the left.
The message view pane MUST occupy 60% of width, on the right.
The command pane MUST occupy two lines at the bottom.
Any pane MAY be zoomed to the full screen.
```

**Private messages** — the list pane is a list of messages.

**Channels** — the list pane is a list of *channels*. `Enter` on a channel
descends to that channel's message list. The pane is therefore two-level,
and the client MUST indicate which level is displayed, because a channel
list and a message list rendered identically in the same 40% column is a
context ambiguity in the tab where context confusion is most costly.

### 2.1 Zoom makes the composer banner load-bearing

Any pane may be zoomed to full screen, and the new message pane overlays
the message view. Both mean **the tab header can be absent while the user
is composing.**

This is why RFC 6 §5 requires the security context in the composer rather
than in the tab strip: a tab indicator is not merely weaker, it is
periodically not on screen. The banner in §4.2 is the only indicator
guaranteed present at the moment of the decision.

```
A zoomed or overlaid composer MUST render its security banner.
The client MUST NOT suppress the banner to reclaim space.
```

*(Judgement.)*

### 2.2 Decryption happens at `Enter`

RFC 7 §8 forbids storing plaintext: the store holds ciphertext and the
epoch chunk, and plaintext exists only while displayed.

```
Enter on a message decrypts it into the message view pane.
Plaintext MUST be zeroized when the view closes or moves to another message.
The client MUST NOT cache decrypted message bodies.
```

*(Derived — RFC 7 §8.)*

A plaintext cache would be an obvious scrolling optimisation and would
silently undo the property that makes epoch erasure meaningful. It is the
same class of regression as RFC 5 §6.1's event-driven sync: strictly
better on every performance metric, and destructive of a security
property no performance test observes.

---

## 3. The command pane

Two lines, combined input and output. That is enough for a prompt, an
acknowledgement, and a fingerprint word list — and not enough for
`peers`, `reach`, or `keys`.

```
Commands whose output exceeds one line MUST render into the message view
pane, or into a zoomed command pane, and MUST NOT scroll the two-line pane.
```

*(Judgement.)* Structured operator evidence scrolled through a two-line
window is evidence nobody reads, and RFC 3 §12 requires that a disconnect
decision be one keystroke from the evidence justifying it.

---

## 4. The security boundary

RFC 6 §5 fixes five requirements. This section elaborates them; it does
not revisit them.

### 4.1 Why it is the highest-severity item

A mistaken channel post is **irreversible and non-repudiable**. It is
signed with the author's identity key, flooded, archived by every carrying
node, and RFC 3 §6.1 forbids any recall mechanism — permanently, because a
recall mechanism is a censorship mechanism and cannot be made selective.
Unlike a sealed message, it does not become unreadable when its epoch key
is erased (RFC 7 §8): there is no epoch key.

Every other mistake in Krab is recoverable or expires. This one does
neither.

### 4.2 The five requirements

```
1. The security context MUST be visible in the composer, not only in the
   tab header: distinct border treatment and a persistent
   `PUBLIC — SIGNED — PERMANENT` banner.
2. The first channel post of a session MUST require explicit confirmation.
3. Reply MUST default to a private sealed message to the author.
   Publish MUST be a separate keystroke.
4. Roster divergence MUST be shown and MUST NOT be silently merged.
5. Group-size and prekey-adequacy warnings MUST appear at join time,
   not at failure time.
```

*(All five derived — RFC 6 §5. Requirement 5's thresholds are derived
from RFC 6 §2.4 and RFC 2 §7.3; the decision to warn at join rather than
at send is judgement.)*

On requirement 3: in the channels tab, `r` on a channel post is ambiguous
between *privately message the author* and *publish a response to my own
channel*. It resolves to the private message. **Pressing reply must never
publish.**

On requirement 4: a member added without your knowledge and a roster you
have not yet synchronised are indistinguishable. Surfacing the divergence
is what gives a user any chance of telling an attack from ordinary
latency, and it is why silent merge is forbidden rather than discouraged.

### 4.3 Enabling channel carriage

RFC 6 §3.6: carrying channels moves a node from *private relay* to *host
of public content*, with legal and operational consequences in the
operator's jurisdiction.

```
The warning MUST fire at the point of enabling, and MUST state the change
in what the node is. It MUST NOT be documentation-only.
Channel carriage MUST default to off.
```

*(Derived — RFC 6 §3.4, §3.6.)*

---

## 5. Command set

```
connect     establish a transport to a peer
disconnect  tear down; optionally reduce quota (RFC 3 §6.2)
rollcall    publish or refresh this node's self-attestation (RFC 3 §9)
import      ingest a courier archive (RFC 4 §5.5)
pack        write a courier archive
send        compose and emit
keys        prekey burn rate, reservoir state, identity backup status
reach       path admission diagnostic
peers       per-peer accountability panel
verify      fingerprint word list for out-of-band comparison
```

### 5.1 `connect` does not sync

```
connect MUST establish a transport and MUST NOT trigger a reconciliation.
```

*(Derived — RFC 5 §6.1, RFC 0 I-5.)*

Reconciliation is Poisson-scheduled and must not correlate with user
activity. A node that syncs when a user asks it to has published that
user's activity pattern to anyone watching arrival timing.

**This will be reported as a bug.** Users press a button and nothing
appears to happen. The client's answer is not to sync, and not to lie:

```
The client MUST show progress for TRANSPORT ESTABLISHMENT -- handshake,
  Tor bootstrap, LoRa session setup. This is real work and RFC 4 §5.2
  requires it.
The client MAY show progress for a reconciliation while one is in fact
  running.
The client MUST NOT begin any progress indication for reconciliation in
  response to a keypress.
The client MUST NOT display "syncing now" or any signal implying that the
  user's action caused a transfer.
The client SHOULD display the transport state and the scheduled window:

    peer m4k2  ·  link up (tor)  ·  next reconciliation ~2h10m (scheduled)
```

*(Derived requirement; the specific presentation is judgement.)*

**The constraint is temporal association, not animation.** A spinner emits
nothing and leaks nothing; the objection is to the causal claim the
interface makes. If a keypress produces an indicator that resolves into
"12 objects received," the user learns that pressing the key causes
transfer. It does not — a scheduled reconciliation happened to fire — and
two things follow. The user begins pressing it when expecting mail or
after sending, clustering their keypresses around their real activity. And
the mental model becomes load-bearing, so the pressure to make the button
do what it appears to do becomes very difficult to resist. Event-driven
sync is not reintroduced by someone deciding to weaken privacy; it is
reintroduced by someone fixing what looks like a bug.

A progress bar during establishment is therefore correct and required. A
progress bar that *starts when the user presses connect and ends when
objects arrive* is the thing forbidden, however it is rendered.

Showing a *window* rather than a countdown matters: a precise countdown
invites waiting for it, and a user who learns the exact schedule will
correlate their own behaviour with it.

RFC 5 §6.1 requires a test asserting that inter-sync intervals are
uncorrelated with message events. That test is the durable protection;
this section is what keeps the interface from making the correlation
attractive to reintroduce.

### 5.2 `reach`

```
$ reach q3m9d1v6 --class sealed --size 4096
  via a→b→q3m9   OK      (tor, tor)         est. 4s
  via a→c→q3m9   BLOCK   lora max_bucket 256
  via a→d→…      BLOCK   shard mask 0x0F excludes 0x3A
  1 of 3 known paths admit this message
```

*(Derived — RFC 0 §4, RFC 4 §3.)*

Under partial coverage (RFC 0 §7.4) delivery failure is silent and a
misconfigured link profile is indistinguishable from a peer ignoring you.
`reach` is the only tool that separates them.

### 5.3 `peers`

Per-peer, windowed, aggregates only — RFC 3 §12 forbids per-object
provenance, because arrival timestamps and per-object attribution
reconstruct the graph and its timing gradients on disk for a seizing
adversary.

Displays: ingress against quota, novelty ratio, duplicate arrivals,
unique-source contribution, tag-match/decrypt-success ratio, shard and
size distribution, storage share, coverage, reconciliation overhead share.

```
The disconnect action MUST be reachable with one keystroke from the peers panel.
```

*(Derived — RFC 3 §12.)* If it is not, operators will not act, and quota
as an accountability mechanism degrades to nothing.

Two entries deserve highlighting rather than burial in a table:
**unique-source contribution** is the eclipse indicator and is invisible
otherwise, and **overhead share above 50% on a non-constrained link**
indicates misconfiguration (RFC 5 §10).

### 5.4 `verify`

Fingerprints render as a **word list**, never base32. Operators compare
them aloud, over a phone call, in a language they speak; base32 cannot be
read aloud reliably and a verification step people skip is not a
verification step.

*(Derived — RFC 3 §2.)*

### 5.5 `keys`

```
Prekey BURN RATE MUST be displayed, not merely the remaining count.
```

*(Derived — RFC 7 §12.)* Exhaustion degrades forward secrecy silently: the
system continues working, falls back to the signed-prekey tier, and says
nothing. A remaining count answers "how many," not "how long," and the
second is the operable question.

Also displayed: reservoir state per peer, epoch window, and **identity
backup status**. RFC 7 §11 requires backup at creation; the client MUST
show its absence persistently rather than once, because the moment a
backup is needed is the moment it can no longer be made.

---

## 6. Pictures

RFC 8 permits pictures and no other attachment type.

```
The client MUST NOT validate an image. It MUST decode and re-encode it,
and MUST transmit the re-encoded bytes.

  decode with a pure-Rust decoder
  cap total pixel count BEFORE allocating
  re-encode to a canonical format
  transmit the result
```

*(Judgement, with a well-documented threat basis.)*

Validation does not work. **Polyglot files** are simultaneously a valid
PNG and a valid ZIP, or a valid GIF and a valid JAR; they pass every
magic-byte check because they genuinely are images. And a genuine image is
not safe either — **the decoder is the attack surface**, image parsers
being historically the richest source of remote code execution.

Re-encoding gives four properties at once:

- Polyglots die: the output contains pixel data the client generated.
- **EXIF dies**, including GPS coordinates. A photograph carrying a
  location would be a catastrophic metadata leak in a system otherwise
  this careful, so **stripping MUST be automatic and MUST NOT be offered
  as a setting.**
- Trailing data, ICC profiles, and container steganography die with it.
- Sizes normalise, feeding RFC 1 §8.1's bucket padding.

```
Pixel count MUST be capped from the header before allocation.
Decoding SHOULD occur in a separate process; where it does not, it MUST
  occur on a task isolated from key material.
The client MUST NOT pass received bytes to a system image viewer.
```

Decompression bombs are the failure mode a file-size limit misses: a
100 KB PNG expanding to 50 GB.

Pictures cannot cross LoRa links (RFC 4 §5.4). The client MUST say so
before sending, not after silent non-delivery.

---

## 7. Display names

Channel and node identifiers are keys and cannot be spoofed. **Display
names are attacker-controlled**, and a Cyrillic homoglyph defeats the
strongest cryptographic guarantee in the system with a font.

```
A key fingerprint MUST appear alongside every display name in list views,
  not only in a detail pane.
The client MUST run Unicode confusable detection against names the user
  already follows, and MUST mark matches.
```

*(Judgement; the mechanism is standard — Unicode TR39.)*

Fingerprints in the detail pane only would satisfy the letter and miss the
point: the confusion happens while scanning a list.

---

## 8. Link status

A peer set routinely mixes Tor, plain IPv6, LoRa, and a USB stick. Users
will assume uniformity.

```
The client MUST show, per link, whether it provides LOCATION privacy.
The client MUST show, per link, whether it provides VOLUME privacy.
```

*(Derived — RFC 4 §10 and RFC 0 §7.3 respectively.)*

Location privacy is a transport property: a Tor link with restricted
discovery has it, plain IPv6 does not. Volume privacy requires cover
traffic, which is unaffordable on constrained links — so some links have
it and others structurally cannot.

```
peer m4k2  tor      loc ●  vol ●    peer 7hq9  ipv6   loc ○  vol ●
peer p2w8  lora     loc ○  vol ○    peer x1c5  usb    loc ●  vol ●
```

Two independent indicators, because they are independent properties and a
single "secure" badge would average them into something false.

---

## 9. Peering

### 9.1 Expired peering is a state, not a failure

```
An expired peering MUST be displayed as an explicit state.
It MUST NOT be presented as a sync failure or a connection error.
Renewal SHOULD be prompted at 75% of the credential term.
```

*(Derived — RFC 3 §4.)*

Krab has no revocation list; expiry *is* the revocation mechanism, so
credentials expire routinely and by design. An expired peering and an
unreachable peer are indistinguishable from outside, and conflating them
wastes an enormous amount of operator time on a transport problem that
does not exist.

### 9.2 Peer-count warnings

```
The client MUST warn when peer count falls below the threshold for the
node's actual transport mix:

  IP-connected                6–8 peers
  mixed                       8–12
  courier or radio dominated  12+

The client SHOULD warn above 25 peers on constrained links.
```

*(Derived — SIM-0 via RFC 0 §8.2 for the lower bound; RFC 3 §8.1 for the
upper.)*

The measured basis, stated so the warning text does not overclaim:
**delivery and latency degrade sharply below 8 peers, and degree 4 is a
cliff even on good transport** — p99 latency 159.7 h against 18.6 h at
degree 8, with the median barely moving, which is the signature of nodes
behind a single fragile path. Under courier- and radio-dominated
transport, degree 8 delivers 95.8% and degree 12 restores 100% while
cutting median latency from 170 h to 30 h.

The upper bound is RFC 3 §8.1's O(P²) nodelist propagation: at 50 peers a
full fragment costs roughly 58 LoRa reconciliations.

**Unmeasured, and therefore not claimed:** whether peer count affects
resistance to origin attribution. RFC 0 §5.3 argues that injection
anonymity is bounded by the peer graph's diameter rather than by network
size, but **no simulation in this project has measured a timing-gradient
or origin attack against degree.** The warning text MUST NOT assert a
deanonymisation figure. If such a claim is wanted, it requires a SIM-2
with an adversary model, and RFC 0 §9 forbids asserting it first.

### 9.3 Remote peering is not equivalent

```
Where the peering ceremony is completed remotely, the client MUST NOT
present it as equivalent to the in-person ceremony, and MUST require
explicit acknowledgement that fingerprints were compared out of band.
```

*(Derived — RFC 3 §11.1.)*

### 9.4 Amateur-band links

```
Enabling an amateur-band link MUST require explicit acknowledgement.
The client MUST state that classes 0, 2, and 3 cannot be carried and
  that the link admits bulletins only.
```

*(Derived — RFC 4 §7.)*

47 CFR 97.113(a)(4) forbids exactly the property sealed objects require.
LoRa in unlicensed ISM bands carries no such restriction, and **the two
are frequently confused** — which is why acknowledgement is explicit
rather than a configuration default.

---

## 10. Retention and pinning

```
The client MUST make the consequence of the retention window visible
BEFORE the window elapses.
A pin action MUST be available, re-encrypting a selected conversation
under a long-lived key.
```

*(Derived — RFC 7 §8.1.)*

Epoch erasure makes a node's own archive of that epoch permanently
unreadable. That is the point — it is the only genuine form of message
expiry — but a user who discovers it afterwards has lost something
irrecoverably, and no support channel can help.

Retention is therefore a **foreground** property, not a setting. Pinning
is a conscious act; the default is forgetting.

---

## 11. The node/TUI seam

```
The TUI MUST communicate with the node over a channel and MUST NOT call
into node internals directly.
```

*(Derived — RFC 0 §4.3.)*

In one binary this is an in-process channel; the identical interface over
a Unix socket yields headless operation with no code change on either
side. Today it means the core is drivable from tests without a TTY, which
is what makes RFC 3 §11.3's courier-only release gate testable at all.

The node MUST continue reconciling while the TUI is closed, backgrounded,
or crashed. Sync tied to UI lifetime is RFC 5 §6.1's violation in a
different costume.

---

## 12. Multi-device

```
Each device MUST be a separate node with its own identity.
An operator's devices MUST be represented as a group (RFC 6 §2).
```

*(Derived — RFC 3 §14.)*

Sharing an identity across devices breaks prekey accounting: two devices
consuming from one published batch, neither knowing what the other used.
As a group, messages fan out to all devices using machinery that already
exists, and losing a phone compromises the phone — drop it from the roster
and peers converge on the remainder.

The client MUST show a correspondent as a roster rather than a key, and
MUST show device count, since fan-out cost scales with it (RFC 6 §2.3).

---

## 13. Rejected alternatives

Recorded so they are not reproposed.

**Message forwarding.** Rejected. `mode_auth` gives deniable
authentication, so a forwarded message carries no verifiable provenance
whatever — the recipient has only the forwarder's word, and the forwarder
could have changed a character. Forward is not risky here; it is
*semantically empty*. Quote-in-reply is the supported form, where the user
is plainly the author of the quoted text and asserts no provenance.

**Attachment types other than pictures.** Rejected. Every additional type
is another parser reachable from untrusted input, and §6's re-encoding
defence works only for formats with a canonical decoded representation.

**A unified "secure" indicator.** Rejected. Location and volume privacy
are independent (§8); averaging them produces a badge that is false in
both directions.

**Progress indication implying user-caused transfer.** Rejected — §5.1.
Progress for transport establishment is required, not rejected; what is
rejected is an indicator that begins on a keypress and resolves on object
arrival, because it asserts a causal relationship that does not exist and
creates continuous pressure to make it exist.

**A plaintext cache for scroll performance.** Rejected — §2.2.

**Read receipts and typing indicators.** Rejected. Both are event-driven
emissions correlated with user activity, which is RFC 0 I-5's violation
in its purest form.

**Automatic image download from untrusted senders.** Rejected. Decoding is
the attack surface (§6), so decode is user-initiated per message.

**Suppressing the composer banner when the tab header is visible.**
Rejected — §2.1. The tab header is not always on screen.

---

## 14. Security considerations

**The client is where the series' properties are lost, and this document
cannot prove its own requirements.** §1.1. Seven RFCs of measured
constraint terminate in an interface whose central risk — a user
misreading their own security context — has no simulator, no benchmark,
and no proof. Reviewers should weigh §4 and §6 as arguments rather than
results, and a usability study would be worth more to this document than
any further protocol work.

**A mistaken channel post is the only unrecoverable user error in Krab.**
§4.1. Signed, non-repudiable, flooded, archived, and unaffected by epoch
erasure because it has no epoch key. Every other mistake either expires or
can be corrected. This asymmetry is why the confirmation in §4.2 is a hard
requirement despite the friction it imposes.

**Convenience optimisations are the standing threat to this design.** A
plaintext scroll cache (§2.2), event-driven sync (§5.1), a suppressed
banner (§2.1), and read receipts (§13) are each strictly better on every
metric a performance or usability test measures, and each destroys a
security property no such test observes. Regression tests asserting the
*absence* of behaviour are the only durable protection; RFC 5 §6.1
specifies one, and §2.2 and §4.2 warrant equivalents.

**Re-encoding is a mitigation, not a sandbox.** §6 removes polyglots,
EXIF, and container tricks, and it does so by *running a decoder on
attacker-controlled bytes*. Pure-Rust decoders convert a
memory-corruption class into a panic class; they do not eliminate it. The
separate-process recommendation is what makes the residual acceptable, and
an implementation that skips it should say so.

**Display names are the weakest link in an otherwise key-based system.**
§7. Identifiers cannot be spoofed and names can, so the fingerprint is the
real name and the display name is a hint. A client that hides fingerprints
behind a detail pane has inverted that relationship.

**Two privacy indicators, not one.** §8. Users assume uniformity across a
peer set that is structurally non-uniform, and a link that cannot afford
cover traffic cannot be made to look like one that can.

**Expiry is routine and must not read as failure.** §9.1. Krab deliberately
has no revocation mechanism, so credentials expire constantly by design.
A client that renders this as an error trains operators to ignore errors.

**The interface must not claim a causal relationship the protocol does not
have.** §5.1. `connect` establishes a transport and its progress should be
shown; what it does not do is cause a reconciliation. An indicator
spanning both makes a false claim, and a false claim users act on becomes
a true requirement someone eventually implements. The scheduled-window
display is what keeps the distinction legible without leaving the user
staring at an interface that appears dead.

---

## 15. References

**Series**

- KRAB RFC 0 — Architecture and Threat Model
- KRAB RFC 1 — Object Format and Cryptography
- KRAB RFC 3 — Peering, Credentials, and Accountability
- KRAB RFC 4 — Transport and Link Profiles
- KRAB RFC 5 — Synchronisation
- KRAB RFC 6 — Groups and Channels
- KRAB RFC 7 — Key Custody and Erasure
- KRAB SIM-0 — Corpus Convergence Measurements
- KRAB SIM-1 — Reconciliation Overhead Measurements

**Prior art**

- Unicode TR39 — security mechanisms, confusable detection
- Briar, Cwtch — friend-to-friend clients; out-of-band verification UX
- Signal — safety numbers as a spoken verification artifact
- PGP word list — spoken fingerprint encoding
- FidoNet point software — the node/point split reflected in §12
- GIFAR and subsequent polyglot literature — §6's basis
- CVE-2023-4863 (WebP) — image decoder as remote attack surface
- 47 CFR 97.113 — amateur service prohibited transmissions

**Standards**

- RFC 2119 — requirement keywords
