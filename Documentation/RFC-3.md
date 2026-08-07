# RFC 3 — Peering, Credentials, and Accountability

    Number:      3
    Title:       Peering, Credentials, and Accountability
    Status:      Draft
    Repository:  https://github.com/vulogov/krab
    Author:      Vladimir Ulogov
    Requires:    RFC 0, RFC 1
    Grounded by: SIM-0 (peer count), krab-sizes/creds (document sizes)

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be
interpreted as described in RFC 2119.

---

## 1. Scope

Krab has no proof-of-work, no reputation score, no directory, and no
admission authority. **The peering relationship is the entire
admission-control mechanism.** This document specifies how that
relationship is established, evidenced, parameterised, and ended.

Everything here is a static signed document. No step requires an
interactive handshake, so the complete peering flow — request,
counter-offer, acceptance, and subsequent nodelist propagation — works
across a courier link with days of latency. This is a hard requirement
(RFC 0 I-4), not an aspiration, and §11.3 makes it a release gate.

---

## 2. Identity

```
node_id = BLAKE3-256("krab/node/v1" ‖ ed25519_pk)
```

Self-certifying. There is no certificate authority, no registry, and no
name resolution. A node identifier is a key, and keys cannot be squatted.

**The identity key signs and never decrypts.** Compromise of an identity
key — by seizure, coercion, or theft — permits impersonation going
forward. It decrypts nothing historical, because no ciphertext in the
corpus was ever sealed to it. Message encryption uses the separate X25519
key hierarchy in RFC 7.

Display is the first 8 bytes as a word list, not base32. Operators verify
fingerprints aloud, over a phone call, in a language they speak; a human
cannot reliably read base32 aloud and a human is the verification
mechanism here.

### 2.1 Document encoding

Credential documents use the deterministic CBOR profile of RFC 1 §4.3.

A credential's signature is Ed25519 over `"krab/cred/v1" ‖ body`, where `body`
is the deterministic CBOR encoding of the document with the signature field
omitted.

**Every signed document in this series MUST prefix its signing input with a
domain string unique to that document type. A signature produced over one
document type MUST NOT be valid over any other.**

A credential body MUST be a flat CBOR map. Nested maps are not permitted:
RFC 1 §4.3 requires map keys to ascend, a nested map's keys restart, and a
decoder reading both levels from one cursor correctly rejects its own
encoder's output.

> **Why the general rule and not just the constant.** The series already
> domain-separates every hash and two of its three signed documents — RFC 3 §4's
> peer-link uses `"krab/link/v1"`, RFC 1 §5.2's bulletin uses `"krab/bul/v1"` —
> and the credential was the exception, carrying a node's Noise static, its
> correspondence key, and its policy.
>
> Without a prefix, two document types whose encodings coincide are
> interchangeable under one signature: the signer consented to one meaning and
> is bound to the other. Deterministic CBOR guarantees identical structure
> yields identical bytes, which is normally the property one wants. The rule
> above converts a per-document decision into one the next signed document
> inherits.
>
> It is also an interoperability requirement. Without it, an implementer
> following §4's pattern invents a prefix and picks their own string while one
> following this section literally uses none — and their credentials do not
> verify against each other, at the ceremony, in person, with no diagnostic.
Implementations MUST render any credential as HJSON on request
(`krab peer show`), and that rendering is what an operator inspects.

The canonical form is CBOR rather than HJSON despite HJSON being the more
readable artifact, for three reasons that together outweigh readability:
documents are chained by hash (§5), embedded inside one another as
evidence (§5.1), and encoded into QR codes (§11). Each of those requires
byte-exactness, and a format with optional quoting, comments, and
whitespace latitude makes byte-exactness a discipline rather than a
property. Human inspection is preserved by rendering; correctness is not
preserved by hope.

---

## 3. The `peer-link` credential

The evidence that two nodes agreed to peer, and simultaneously the
contract governing what that means.

| key | field | notes |
|---|---|---|
| 0 | version | |
| 1 | party A | `{sig_pk, kx_pk}` |
| 2 | party B | `{sig_pk, kx_pk}` |
| 3 | established | unix seconds |
| 4 | expires | §4 |
| 5 | nonce | 16 bytes, prevents replay of a superseded link |
| 6 | terms A→B | quota, retention, filters (§6, §7) |
| 7 | terms B→A | |
| 8 | flags | share bits (§8.3), class mask |
| 9 | transports | endpoint list; MAY be empty |
| — | sig A | Ed25519 over `"krab/link/v1" ‖ body` |
| — | sig B | same |

**Both signatures are required.** A singly-signed document lets one party
assert a relationship the other never agreed to — which matters because
these propagate one hop (§8) and are cited as evidence (§5.1). Mutual
signature makes the link a contract rather than a claim.

**The quota lives in the credential.** The peering agreement and the rate
limit are one document, so "you exceeded quota" is a checkable statement
against a signed artifact rather than a unilateral judgement. That is what
makes a quota reduction socially legible instead of arbitrary.

Computed sizes (`krab-sizes/creds`):

| document | size | single QR |
|---|---|---|
| `peer-link`, no endpoints | 343 B | yes |
| `peer-link`, 1 endpoint | 416 B | yes |
| `peer-link`, 3 endpoints | 562 B | yes |
| unsigned body (hash-chain input) | 284 B | — |

A credential fits comfortably in one QR code at error-correction level M,
which is what makes the in-person ceremony in §11 practical.

---

## 4. Expiry replaces revocation

```
expires − established SHOULD be 60–90 days.
Implementations MUST reject a link whose validity exceeds 180 days.
```

**Krab will never have a certificate revocation list.** Distributed
revocation without infrastructure is unsolved: CRLs and OCSP are servers,
and gossiped revocation objects are a new attack surface and a new
propagation-delay problem in a network where propagation is measured in
days.

Short-lived credentials dissolve the problem. Revocation is non-renewal:
zero protocol, zero propagation delay, zero new failure modes.

Immediate termination is purely local — close the transport, stop
reconciling, purge §8.4 artifacts. Revocation matters only to *third
parties* who believe the link exists, and expiry handles them within one
credential lifetime.

Renewal is a fresh `peer-link` with a new nonce, superseding by
`established` time. Implementations SHOULD prompt for renewal at 75% of
the term and MUST surface an expired peering as an explicit state rather
than as a silent sync failure — the two look identical from the outside
and confusing them will waste a great deal of operator time.

---

## 5. Negotiation

Three documents, chained by hash. All static; none requires the other
party to be online.

```
peer-request  ──hash──▶  peer-counter  ──hash──▶  peer-link
   (X signs)              (B signs,               (both sign)
                           references
                           request hash)
```

**The counter-offer is the step that matters.** Without it, peering is
accept-or-reject and therefore binary: friend or stranger. With it,
peering is negotiated, which is what makes §6 possible.

### 5.1 `peer-request`

| key | field |
|---|---|
| 0 | version |
| 1 | from `{sig_pk, kx_pk}` |
| 2 | to (node id) |
| 3 | via (introducer node id), optional |
| 4 | evidence — the introducer's `peer-link` with the requester |
| 5 | proposed terms |
| 6 | introduction token (§10), optional |
| 7 | operator note (free text, read by a human) |

Computed size: 683 B without a note, 804 B with a 120-byte note. Still a
single QR code.

Delivery is by `sealed` object to the recipient's **inbox tag** (RFC 1
§6.2), so it uses `mode_base` with an inner signature — first contact
cannot use deniable authentication, and is also the message a recipient is
most likely to want to be able to prove later.

Because it travels as an ordinary corpus object, **a peer-request reaches
a node that has no network endpoint at all**, including one reachable only
by courier. This is why rollcall entries carry no endpoints (§9.2).

### 5.2 `peer-counter`

Signed by B, referencing `H(peer-request)`. Carries B's revised terms.
B MAY counter repeatedly; each counter references the previous document's
hash, so the negotiation is a verifiable chain and neither party can later
misrepresent what was offered.

### 5.3 Acceptance

X countersigns the terms in the final counter, producing the `peer-link`.
Both parties store the full chain: `request → counter(s) → link`. The
chain is local evidence and MUST NOT be published — it names an
introducer and is therefore graph information.

---

## 6. Quota is a continuous trust dial

This is the central mechanism of the document.

The weakness of friend-to-friend networks is binary peering: hard to grow,
brittle, and every disconnection is a social event. Negotiated quota
removes it.

```
X requests:  10 MB/day, 30 d retention, all shards, all classes
B counters:   1 MB/day,  3 d retention, shard 0x0F, sealed + bulletin
X accepts.
```

**You can peer with a stranger at 1% trust.** Vouching is not required to
relay for someone; you allocate a sliver of capacity and observe. That is
graduated trust rather than a binary relationship, and it is what the
friend-to-friend literature is missing.

### 6.1 Quota is per-link bytes, never per-message attribution

RFC 0 §5 requires that message origination be unattributable. A peer
therefore **cannot** distinguish "this node is relaying the corpus, as
designed" from "this node is flooding" by inspecting traffic.

Accountability is therefore a **byte and object budget on the link**,
regardless of who originated anything. Exceed it and you are throttled,
then reduced, then cut. You then allocate your own budget between your
traffic and your relaying, which creates back-pressure that propagates
outward through the graph without anyone learning anything.

Three consequences that MUST be stated in any deployment documentation:

1. **A flood is indistinguishable from a well-connected peer relaying a
   busy region.** Quota is quota. Negotiate generously and renegotiate.
2. **Abuse survives one hop past a cut.** A peers with B, B with C, C
   spams. B cuts C — but the objects are in B's store and B relays them to
   A until TTL. They cannot be recalled, and **no recall mechanism will
   ever be built**, because a recall mechanism is a censorship mechanism
   and cannot be made selective.
3. **Your resources are consumed by parties you never approved.** A holds
   B accountable for everything B sends regardless of origin; B must
   police C. This makes a relay a *responsible* relay rather than a
   neutral pipe. It is the unavoidable price of having no proof-of-work
   and MUST be stated as a deliberate choice.

### 6.2 Automatic adjustment

Quota SHOULD drift upward toward an operator-set ceiling while behaviour
is good, and drop sharply on violation.

**"Flood → disconnect" is therefore "flood → quota reduction."**
Continuous, proportionate, reversible, and it does not require a human
awake at 03:00. Disconnection is the limit case, not the mechanism.

Signals (§12) are already collected for the operator panel; automatic
adjustment reuses them. Adjustment within the credential's negotiated
ceiling requires no re-signing; raising the ceiling does.

---

## 7. Retention

A per-link **floor commitment**: "I will keep at least N days of history
available to you."

This is distinct from `object.expiry`, which is absolute, sender-set,
inside the identifier hash, and identical on every node. Retention is
local policy, negotiable, private, and per-direction.

```
retention ≤ MAX_TTL          (45 days, RFC 1 §2)
```

Expressed as a duration evaluated against object creation time, so it is
stable under the clock drift a courier network will have.

**Quota is a ceiling you are held to; retention is a floor.** Both are
unverifiable in advance and both are detectable in breach: if B promised
30 days and reconciliation shows B missing objects from day 10 that A gave
B, A knows. Same enforcement, same social consequence, no new machinery.

### 7.1 Retention makes eviction non-inferential

RFC 0 §7.4 establishes coverage as a privacy parameter. Retention improves
the position in a way that is easy to miss: **a declared retention window
removes the thing to infer.** Diffing several peers' holdings then
recovers only what they already told you. Declaring beats hiding.

Uniform oldest-first eviction (RFC 0 I-6) still applies *within* the
retained window.

Residual leak, stated rather than hidden: differing retention across your
peers reveals which peers you promised more to. That is within-peer-set
information about a peer set they already know. Acceptable.

### 7.2 Initial sync window

Negotiated separately from steady-state retention. A fresh peer syncing
against a 30-day partner pulls 30 days at once — potentially gigabytes
over a metered mobile link on first run.

```
initial_window   SHOULD default to 7 days, growing over subsequent syncs.
```

### 7.3 Retention joins the reconciliation filter

```
filter = shard_mask ∩ size_cap ∩ class_mask ∩ retention_window
```

All four derive from the signed credential, so **both sides provably agree
on the scope**. Reconciliation is scoped to the filter (RFC 5); anything
else produces phantom divergence that recurs every cycle, permanently.

---

## 8. Nodelist fragments

Source routing needs two-hop visibility. Nothing needs more.

A node's fragment is the set of its currently valid `peer-link`
credentials, signed, and **encrypted individually to each of its own
peers**. Not published, not flooded, not readable by anyone at three hops.

### 8.1 Cost is quadratic in peer count

`P` credentials, one copy per peer, so O(P²) bytes:

| peers | fragment | all copies | LoRa reconciliations |
|---|---|---|---|
| 5 | 2.3 KB | 11 KB | 0.6 |
| 8 | 3.5 KB | 28 KB | 1.6 |
| 12 | 5.2 KB | 62 KB | 3.5 |
| 20 | 8.5 KB | 170 KB | 9.5 |
| 50 | 21 KB | 1.05 MB | 58 |

A LoRa reconciliation moves ~18 KB (RFC 1 §8.3). At 50 peers a full
fragment is 58 reconciliations — roughly two weeks of airtime for one
publication.

### 8.2 Cadence, and `NODEDIFF`

Full fragments SHOULD be published **weekly**; deltas covering only
changed links between. This is FidoNet's `NODEDIFF` and its cadence, and
the arithmetic is why:

| peers | 1 link changed | full | ratio |
|---|---|---|---|
| 12 | 7.4 KB | 62 KB | 8× |
| 20 | 12 KB | 170 KB | 14× |
| 50 | 31 KB | 1.05 MB | 34× |

Deltas MUST reference the last full fragment by hash. A peer that has
missed a delta requests the full fragment.

### 8.3 `share` flags

```
a_shares_b : bool     A will list B in fragments A hands out
b_shares_a : bool
```

Per direction, both signed, so neither party can unilaterally expose the
other. **Default MUST be false** — opt in to being listed, not out.

A node may have ten casual peers and one sensitive one. Without this flag,
the sensitive link is exposed to the other ten. It also bounds
graph-walking: without it, an adversary who acquires one peer requests
fragments, acquires more, and maps the network one hop at a time.

### 8.4 Termination purges attributable artifacts

Objects are content-addressed and unattributed, so the corpus is
unaffected by unpeering. Fragments, beacons, credentials, and negotiation
chains are attributable — they are records of a relationship.

On termination or expiry a node MUST purge those and MUST retain the
corpus. Unpeering should remove the relationship record, not merely stop
the conversation.

---

## 9. Public rollcall

The optional public tier. **Opt-in; a node that never publishes an entry
is invisible to it and reachable only through hand-exchanged credentials.**
That MUST be the default.

### 9.1 Nodes, never links

| may be published | must never be published |
|---|---|
| node id, `sig_pk`, `kx_pk` | any `peer-link` |
| capabilities, shard mask, max object | any statement that A peers with B |
| corpus watermark | operator identity, free text |
| coverage (RFC 0 §7.4) | IP addresses |

A directory of *nodes* is a public key directory. A directory of *links*
is the social graph. The first is safe; the second undoes the design.

Entries are self-signed `bulletin` objects (RFC 1 §5.2), 153 bytes
computed, expiring in ~7 days so stale entries vanish with no revocation
mechanism. There is no coordinator, no hierarchy, and no hosted file —
"the rollcall" is simply the set of live self-attestations in the corpus.

### 9.2 No endpoints, ever

A rollcall entry carries **no reachability information**.

Peer-requests travel through the corpus (§5.1), so an endpoint is not
needed to receive one. Endpoints are exchanged inside the signed
credential, after agreement, only with the counterparty.

This eliminates the stable-network-pseudonym problem at the root rather
than mitigating it, and it has a better property: the peering flow is
byte-identical for a node on fibre, a node on LoRa, and a node reachable
only by courier. No transport-specific path exists in the most
security-sensitive part of the protocol.

Where endpoints are exchanged, implementations SHOULD separate a
**contact endpoint** (accepts only peer-requests, freely rotatable) from a
**sync endpoint** (never published, protected by Tor restricted discovery
where applicable — RFC 4).

---

## 10. Introduction, not reputation

Krab will not have a public endorsement or reputation score.

Visible reputation concentrates: nodes with many endorsements become hubs,
hubs become chokepoints, chokepoints become compulsion targets and single
points of failure. FidoNet's coordinator hierarchy emerged this way — not
by design, but because visible standing accumulates. Endorsement counts
are also Sybil-farmable the moment they are worth anything, and a public
endorsement is itself a published link (§9.1).

Instead: a **private, single-use, expiring introduction token**, bound to
the requester's key so it is non-transferable, scoped to one introduction,
expiring in days, and revealed only to the party evaluating it. It carries
the credibility of vouching with none of the persistence.

`evidence` (§5.1) is the cryptographic component: the introducer's signed
link with the requester proves the vouch is real. The human decides
whether it is sufficient. That division is deliberate — the protocol
establishes facts, the operator makes judgements.

Unlinkable public endorsement is possible via a ring signature over the
endorser set ("one of these N vouches for X"). It is deferred to Future
Work and MUST NOT be built unless the private-token path demonstrably
fails.

---

## 11. The ceremony

Peering is a physical or deliberate act, and the implementation should
make it one event rather than a settings screen.

```
1. exchange rollcall entries or QR codes      (153–416 B, one QR each)
2. compare fingerprint word lists aloud       ← the actual security step
3. exchange reservoir contributions R_A ⊕ R_B (RFC 7)
4. sign the peer-link
```

One event, three trust artifacts, and the operator has a *memory* of doing
it — which for out-of-band verification is worth more than any protocol
property.

Reservoir establishment belongs here rather than as a separate operation
someone might skip. The `peer-link` records the reservoir identifier and
current epoch; the material never touches the credential.

### 11.1 Remote peering

Where an in-person ceremony is impossible, the same documents flow through
the corpus. Fingerprint comparison then requires an out-of-band channel —
a phone call — and implementations MUST NOT present remote peering as
equivalent.

### 11.2 Bootstrap is a security property

**There is no way to join Krab without knowing a participant.** This is
not a gap to be closed; it is the property that makes proof-of-work
unnecessary. It caps growth rate by design.

A public bootstrap node will be proposed as a convenience. RFC 0 §6 has
already refused it.

### 11.3 Courier-only peering is a release gate

An implementation MUST demonstrate a complete peering negotiation and
first message exchange **with all network interfaces down**, using only
file import and export. If any step requires a round trip that was not
noticed, air-gapped nodes silently cannot join, and that will not be
discovered until someone tries.

---

## 12. Observability

Manual and automatic quota decisions both require evidence. Per peer,
windowed:

| metric | reads as |
|---|---|
| ingress bytes / objects per day | against negotiated quota |
| **novelty ratio** | fraction of received objects not already held. The key metric: high volume at low novelty is misconfiguration or attack |
| duplicate arrivals | same object from N peers — graph over-connected here, under-connected elsewhere |
| **unique-source contribution** | objects that arrived *only* via this peer. High means cutting them partitions you. The eclipse indicator, invisible otherwise |
| tag-match / decrypt-success ratio | RFC 1 §6.4 — decapsulation DoS |
| shard and size distribution | uniform where others are skewed = synthetic load |
| storage share | disk attributable to this peer's introductions |
| coverage | RFC 0 §7.4 — your own privacy position |

Aggregates only. Implementations MUST NOT retain per-object provenance:
arrival timestamps and per-object attribution are a forensic reconstruction
of the graph and its timing gradients, sitting on disk, waiting for
seizure. Rolling counters lose nothing operationally.

A disconnect decision should be one keystroke from the evidence
justifying it. If it is not, operators will not make it, and the
accountability model degrades to nothing.

---

## 13. How many peers

Two independent measurements bound the answer from opposite directions.

**Lower bound, from SIM-0** (RFC 0 §8.2): delivery and latency degrade
sharply below 8 peers, and degree 4 is a cliff even on good transport —
p99 latency 159.7 h against 18.6 h at degree 8. Courier- and
radio-dominated deployments need 12+; at degree 12 delivery returns to
100% and median latency falls from 170 h to 30 h.

**Upper bound, from §8.1**: nodelist propagation is O(P²). At 50 peers a
full fragment costs ~58 LoRa reconciliations.

| deployment | recommended |
|---|---|
| IP-connected | 8–20 |
| mixed | 12–20 |
| courier / radio-dominated | **12–25** |

Operators choose peers by hand and will not know any of this.
Implementations MUST warn below the lower bound for the node's actual
transport mix, and SHOULD warn above 25 on constrained links.

---

## 14. Multi-device

One operator with a laptop and a phone. Sharing an identity across both
breaks prekey accounting: two devices consuming from one published batch,
neither knowing what the other used.

**Each device is its own node, and the operator is a group** (RFC 6).
Messages fan out to all devices, reusing existing machinery. Losing the
phone compromises the phone; drop it from the roster and peers converge on
the remainder.

Cost: correspondents treat an operator as a roster rather than a key, and
fan-out multiplies by device count. Both acceptable, and far cheaper than
device-linking with shared state.

---

## 15. Security considerations

**Peering is the whole attack surface.** An adversary who cannot obtain a
peering cannot observe. This is Krab's structural defence (RFC 0 §5.2) and
it rests entirely on operator judgement about whom to peer with —
historically the weakest component of every clandestine network. Graduated
quota (§6) limits early damage; it does not prevent penetration.

**Fragments are the graph.** §8.3's default-false share flag is the
control. An operator who sets it true everywhere has published their
social graph to their peers, one hop at a time.

**Credentials at rest are non-repudiable.** Seizing a disk yields the peer
list *with cryptographic proof* — worse than an address book. The
credential store MUST be encrypted under the RFC 7 key hierarchy. A
running node holds them in memory; this is mitigation, not a fix.

**Introduction tokens are transferable if not bound.** A token MUST be
bound to the requester's `sig_pk` and MUST be single-use, or an introducer
has effectively issued a bearer credential to their peer set.

**Expiry is a liveness dependency.** A node offline longer than a
credential term returns unable to peer with anyone. Terms SHOULD exceed
the deployment's expected maximum offline period, which for courier
deployments argues for the upper end of the 60–90 day range.

**A harvester is a sink.** A pure observer takes objects and rarely
originates ones you have not seen, so it scores badly on novelty ratio and
unique-source contribution. Not conclusive — a legitimate leaf node looks
identical — but it costs an adversary real traffic to fake, and it is
free to measure.

---

## 16. References

- KRAB RFC 0 — Architecture and Threat Model
- KRAB RFC 1 — Object Format and Cryptography
- KRAB RFC 7 — Key Custody and Erasure (reservoir, credential storage)
- KRAB SIM-0 — Corpus Convergence Measurements
- `krab-sizes/creds` — reference encoder; source of every byte count here
- FidoNet FTS-0005 — nodelist and `NODEDIFF` distribution
- RFC 2119, RFC 8032, RFC 8949 §4.2.1
