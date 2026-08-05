# RFC 4 — Transport and Link Profiles

    Number:      4
    Title:       Transport and Link Profiles
    Status:      Draft
    Repository:  https://github.com/vulogov/krab
    Author:      Vladimir Ulogov
    Requires:    RFC 0, RFC 1, RFC 3
    Grounded by: krab-sizes/transport (all figures computed)

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be
interpreted as described in RFC 2119.

---

## 1. Scope and the boundary rule

Krab runs over IP, Tor, serial, LoRa, X.25, and hand-carried media. These
differ by nine orders of magnitude in latency and six in bandwidth. The
only way that is tractable is a boundary the rest of the protocol cannot
see through.

**RFC 0 I-4, normative here:**

```
Nothing above the Fabric boundary may assume a transport is anonymous,
reachable, low-latency, or online.
```

The test for any proposed design above this layer: **does it still work
when the only link is a USB stick delivered fortnightly?** If not, it is
wrong. RFC 3 §11.3 makes this a release gate for peering specifically;
this document makes it the general rule.

---

## 2. The `Fabric` trait

```rust
trait Fabric {
    fn profile(&self) -> &LinkProfile;
    async fn connect(&self, peer: &PeerLink) -> Result<Session>;
    async fn accept(&self) -> Result<Session>;
}

trait Session {
    async fn send(&mut self, msg: &ControlMessage) -> Result<()>;
    async fn recv(&mut self) -> Result<ControlMessage>;
    async fn close(self) -> Result<()>;
}
```

Every backend implements the same trait, including the courier backend,
where `connect` opens an archive file and `send` appends to it. **If the
courier backend cannot implement an operation, that operation does not
belong in the protocol.** This is the mechanical enforcement of §1's rule,
and it is why the trait is expressed in terms of control messages rather
than bytes or connections.

`krab-core` and `krab-proto` (RFC 0 §4.3) depend on this trait and on
nothing below it. The `sim` backend is what makes deterministic testing
possible without conditional compilation.

---

## 3. `LinkProfile`

Every transport-specific decision is data, not code:

```rust
struct LinkProfile {
    kind:            LinkKind,
    mtu:             usize,
    sustained_bps:   u32,
    duty_cycle:      Option<f32>,     // regulatory, LoRa
    latency_class:   Interactive | Batch | Courier,
    metered:         bool,
    max_bucket:      u8,              // index into RFC 1 §8.1 buckets
    shard_mask:      ShardMask,
    class_mask:      ClassMask,
    armor:           Option<Codec>,
    fec:             Option<Codec>,
    sync_mode:       Manifest | Rbsr | PushOnly,
    quota:           Quota,           // from the credential, RFC 3 §6
    retention:       Duration,        // from the credential, RFC 3 §7
}
```

`max_bucket` is a **bucket index, not a byte count**. A byte gate that
falls between buckets — 512 bytes, say — admits nothing above the 256-byte
bucket while appearing to admit more, which is exactly the kind of silent
partition §7 is trying to avoid.

`quota`, `retention`, `shard_mask`, and `class_mask` derive from the signed
`peer-link` credential, so **both sides provably agree on the
reconciliation filter** (RFC 3 §7.3). The remaining fields are local.

---

## 4. Wire protocol

```
byte stream        TcpStream │ SOCKS5-dialed TcpStream │ Serial │ File │ Sim
      ↓
Noise_IK_25519_ChaChaPoly_BLAKE2s   static keys from the peer-link credential
      ↓
length-delimited frames             [u32 LE len][Noise transport message]
      ↓
CBOR control messages               RFC 5
```

### 4.1 Noise IK

The initiator already knows the responder's static key — that is what the
credential is — which is exactly the precondition pattern IK requires.

| message | size | contents |
|---|---|---|
| 1, initiator → responder | 96 B | `e, es, s, ss` |
| 2, responder → initiator | 48 B | `e, ee, se` |
| **total** | **144 B** | 1-RTT, mutual auth, initiator identity hidden from a passive observer |

No TLS, no certificates, no second identity system, no PKI. Link-level
forward secrecy comes free from the ephemeral DH.

**Handshake cost is transport-dependent and matters on LoRa.** At 144
bytes and SF10's computed 0.83 B/s (§6.4), a handshake costs
**approximately 3 minutes of airtime**. Constrained links therefore MUST
hold sessions open across reconciliation cycles rather than reconnecting,
and SHOULD treat session teardown as expensive.

Both parties MUST verify that the peer's presented static key matches the
credential. A mismatch is a hard failure, never a TOFU prompt — the
credential *is* the trust decision and it was made out of band.

### 4.2 Framing

`[u32 LE length][Noise transport message]`. Noise transport messages cap
at 65 535 bytes including a 16-byte tag.

| object bucket | frames | overhead | % |
|---|---|---|---|
| 256 | 1 | 20 B | 7.81% |
| 1 024 | 1 | 20 B | 1.95% |
| 16 384 | 1 | 20 B | 0.12% |
| 65 536 | 2 | 40 B | 0.06% |
| 262 144 | 5 | 100 B | 0.04% |

Negligible except at the smallest bucket, where RFC 1 §8.1's padding
overhead already dominates.

### 4.3 Rejected alternatives

**ZMQ.** Three reasons, the last decisive. `libzmq` has no SOCKS5, so
outbound `.onion` would need a per-peer local forwarder — an asymmetric,
half-built transport. It is a C dependency, and CurveZMQ would introduce a
second key format alongside the X25519 keys already in the credentials.
And **a ZMQ socket cannot degrade to a file**: the courier archive is the
control-message sequence written to disk with the round trips removed, and
the socket abstraction actively prevents that.

**QUIC.** UDP-only, and Tor onion services are TCP-only, so it cannot
serve the transport Krab most depends on. Worth reconsidering for direct
high-bandwidth IP links where multiplexing and connection migration would
earn their cost.

**TLS.** Would require a certificate identity system parallel to and
redundant with the credential.

---

## 5. Backends

### 5.1 TCP

Plain framed stream. Leaks network location to the peer — who is someone
the operator chose, negotiated a quota with, and very likely already knows
by name (RFC 0 §5.1). For many deployments this is the correct choice and
Tor is unnecessary complexity.

### 5.2 Tor

**Restricted discovery is what makes an onion service appropriate here.**
Only clients holding an authorised key can decrypt the service descriptor,
so the sync endpoint is not merely unlisted but unenumerable and
unconfirmable by anyone who is not already a peer. The authorised-client
set derives directly from the node's signed credentials.

```
The onion service key MUST NOT be derived from, or equal to, the node
identity key.
```

Three reasons: it would weld network location to identity permanently,
undoing the endpoint-free rollcall of RFC 3 §9.2; reusing an Ed25519 key
across the Krab protocol and the hidden-service protocol is textbook
cross-protocol exposure; and it would make onion rotation impossible
without changing identity. Where operators want one secret to back up, the
service key SHOULD be derived through a KDF with a distinct domain string
and a rotatable epoch counter.

Endpoint separation (RFC 3 §9.2): a **contact** endpoint accepting only
peer-requests, freely rotatable; a **sync** endpoint never published and
protected by restricted discovery.

Operational: bootstrap takes tens of seconds and descriptor publication
longer, so clients MUST show bootstrap progress or users will believe the
node is broken at every start. A ~3 s circuit RTT is irrelevant to
store-and-forward but fatal to a chatty protocol — which is an independent
argument for RFC 5's manifest mode over multi-round reconciliation on
these links.

Implementations SHOULD fail loudly at startup when a credential specifies
restricted discovery and the binary lacks support, rather than silently
running an unrestricted service.

### 5.3 Serial

Underrated as a bulk transport:

| baud | B/s | full n=500 corpus (447 MB) |
|---|---|---|
| 9 600 | 960 | 129 h |
| 19 200 | 1 920 | 65 h |
| 57 600 | 5 760 | 22 h |
| 115 200 | 11 520 | **11 h** |

At 115 200 a serial link is four orders of magnitude faster than LoRa and
moves an entire corpus overnight. A direct cable, a wired radio modem, or
an X.25 PAD are all serviceable links, and serial is the natural carrier
for a physically isolated but co-located pair.

Armor SHOULD be enabled where the carrier is text-only; FEC SHOULD be
enabled where there is no link-layer retransmission.

### 5.4 LoRa

Computed from the standard time-on-air formula, EU868, 125 kHz, CR 4/5,
1% duty cycle:

| SF | payload | ToA | sustained | per day |
|---|---|---|---|---|
| 7 | 222 B | 348 ms | **6.37 B/s** | 550 KB |
| 8 | 222 B | 615 ms | 3.61 B/s | 312 KB |
| 9 | 115 B | 615 ms | 1.87 B/s | 161 KB |
| 10 | 51 B | 616 ms | **0.83 B/s** | 72 KB |
| 11 | 51 B | 1 315 ms | 0.39 B/s | 34 KB |
| 12 | 51 B | 2 466 ms | 0.21 B/s | 18 KB |

SIM-0 modelled 0.83 B/s at SF10 against a computed 0.83; its LoRa
findings stand.

**SF7 is 7.7× faster than SF10** at the cost of range, which makes
spreading factor the single most consequential LoRa configuration choice —
more so than any protocol parameter.

Fragmentation, with a 6-byte fragment header and 20% RaptorQ repair
overhead:

| bucket | SF7 | SF10 | SF12 |
|---|---|---|---|
| 256 | 1.7 min | 8.2 min | 32.9 min |
| 1 024 | 3.5 min | 28.8 min | 1.9 h |
| 4 096 | 13.4 min | **1.9 h** | 7.6 h |

```
LoRa max_bucket MUST NOT exceed:
  bucket 1024 at SF7-SF10
  bucket  256 at SF11-SF12
```

Filtering is **at the sender**. Receiver-side rejection spends the
scarcest resource in the system discovering something both sides already
knew from the credential, and creates partitions that are invisible from
either end.

FEC is mandatory on LoRa — there is no retransmission worth having at
these rates — and RaptorQ is preferred to Reed-Solomon because a fountain
code never requires negotiating *which* fragment was lost, and negotiation
is exactly what cannot be afforded.

Armor MUST be off. RFC 1 §3 places it outside the object identifier
precisely so a gateway can strip it here.

**Capacity is the number RFC 5 must design against:** SF10 moves ~72 KB
per day, which at RFC 1 §9.3's 16 bytes per manifest entry is roughly
4 600 entries per day of airtime. Whether filter-scoping keeps the
LoRa-eligible set below that is the open question assigned to SIM-1
(RFC 0 §9).

### 5.5 Courier

`connect` opens an archive; `send` appends; `recv` reads. The same control
messages, with round trips removed.

**Capacity never binds.** A 128 GB medium holds 286× the measured n=500
corpus and writes in 15 seconds. The constraint is human latency, always.

**The archive is hostile input.**

```
The container MUST be a flat sequence of length-prefixed records.
Filenames, if any, MUST be ignored entirely -- every object is named by its hash.
Compression MUST be off: objects are ciphertext and do not compress,
  and store-only makes decompression bombs impossible.
Every object MUST be verified by content hash on ingest (RFC 1 §11).
An implementation MUST NOT open a foreign database file.
```

That last point is not hypothetical. Shipping the archive as SQLite is
tempting — self-describing, self-indexing, inspectable with standard
tools — and it means parsing an attacker-supplied database with a library
that has a long history of CVEs against malformed files. Import into your
own store; never open theirs.

A separate human-readable `MANIFEST.hjson` MAY accompany the archive for
the courier's benefit. This is where HJSON is genuinely the right format:
a human reads it, nothing signs it, and nothing hashes it.

### 5.6 Sim

Deterministic: seeded PRNG, controllable clock, injectable partitions,
churn, and byzantine peers. Not a test double but a first-class backend,
because gossip convergence bugs are effectively undebuggable in
production. SIM-0 is built on this seam.

---

## 6. Alternatives, documented not mandated

**IPv6** dissolves NAT outright — global addressing, working inbound
connections, no hole punching. Underrated and often the whole answer. Pin
a stable address rather than using privacy extensions on a node.

**Yggdrasil** gives an encrypted overlay where the address derives from
the public key: self-certifying like an onion, with no directory
authorities and no exit nodes. It provides reachability and self-certifying
addressing without providing anonymity — link-layer peers see real
addresses. Where reachability was the goal and privacy-from-peers was not,
it is much lighter than Tor and composes as a mesh rather than sitting
under one.

**Dial-out-only nodes** (RFC 0 §4.4's *point*) require no anonymity
network at all. With small, long-lived peer sets, one reachable node per
cluster suffices, and mobile, CGNAT, and corporate networks all collapse
into this case.

**I2P** is arguably a better structural fit than Tor — packet-switched,
long-lived tunnels, designed around hidden services rather than exits — at
the cost of a weaker Rust story and a smaller network.

Censorship resistance, if needed, belongs in a pluggable-transport layer
**below** the byte stream (obfs4-style), changing nothing above it.

---

## 7. Amateur radio is excluded for sealed traffic

47 CFR 97.113(a)(4) prohibits messages encoded to obscure their meaning,
and the FCC has declined to create an exception. An end-to-end encrypted
messaging system is squarely on the wrong side of that line.

```
class 0 (sealed), 2 (cover), and 3 (short) MUST NOT be carried on amateur bands.
class 1 (bulletin) MAY be, being signed and unencrypted.
```

The `class_mask` on such a link therefore admits bulletins only, which is
a genuinely useful mode — emergency notices, network health, public
announcements — and turns a legal blocker into a feature.

Two items for review by a licensed operator rather than by this document:
station classification under 97.113(d) for a node that automatically
forwards, and any jurisdiction outside FCC rules.

LoRa in unlicensed ISM bands carries no such restriction. **The two are
frequently confused and MUST NOT be conflated in configuration**: an
implementation SHOULD require explicit acknowledgement before enabling an
amateur-band link.

---

## 8. `short` framing

RFC 1 §5.5 defers the encoding here, because `short` is a transport
message and not a corpus object: no identifier, no relay, no
reconciliation.

```
[1B ver<<4|class][4B tag][3B expiry_h][2B ctr][N body][8B truncated MAC]
= 18 + N bytes;  N ≤ 37 at a 55-byte ceiling
```

Keyed from the pairwise reservoir in the credential (RFC 7 §6). Nonce from
`(link_id, ctr)`. A `short` message MUST NOT be forwarded, MUST NOT be
stored beyond display, and MUST NOT enter reconciliation.

A 64-bit truncated MAC is defensible only because the link is pairwise,
mutually authenticated, and low-volume. Implementations MUST restate this
in their security documentation rather than treating it as settled by
citation.

---

## 9. Denial of service

```
Handshake timeout MUST be enforced (SHOULD be 30 s on interactive links).
Concurrent in-progress handshakes per peer MUST be capped (SHOULD be 4).
Frame length MUST be validated against Noise's 65535 limit before allocation.
Objects exceeding the link's max_bucket MUST be rejected before buffering.
```

Handshake slowloris is the cheapest attack against a reachable node, and
the credential requirement means only peers can mount it — which makes it
a quota signal (RFC 3 §12) rather than an anonymous flood.

On LoRa, an adversary need only transmit to consume the receiver's
regulatory duty-cycle budget. There is no protocol defence; it is a
physical-layer property of the band, and it MUST be stated to operators
rather than implied.

---

## 10. Security considerations

**The boundary is the security property.** An implementation that reaches
around `Fabric` — special-casing Tor above it, assuming a clock from a
network peer, assuming a connection can be reopened — has broken §1 and
the failure will surface as a courier-only node that silently cannot
participate.

**Noise gives link secrecy, not message secrecy.** Compromising a session
key exposes what crossed that link, which is ciphertext the adversary
could have collected anyway. It is worth having because it denies a local
observer knowledge of *which* objects a node is pulling — a meaningful
traffic-analysis reduction for essentially no cost.

**Static key mismatch is a hard failure.** Never prompt. The credential is
the trust decision and a prompt invites the user to overrule it at the one
moment they are least equipped to.

**Transport choice is per-link and visible to the operator.** One peer set
may mix a Tor link to a distant contact, plain IPv6 to a friend, LoRa to a
neighbour, and a USB stick to a colleague. Clients MUST show which links
currently provide location privacy and which do not, because users will
otherwise assume uniformity (RFC 0 §7.3).

**LoRa gateways transcode.** Stripping armor and FEC and re-emitting is
only safe because RFC 1 §3 places both outside the object identifier. An
implementation that lets either affect the identifier will fracture the
corpus at every gateway, and the damage is silent and permanent.

**Duty-cycle exhaustion is unanswerable at the protocol layer.** §9.

---

## 11. References

- KRAB RFC 0 — Architecture and Threat Model
- KRAB RFC 1 — Object Format and Cryptography
- KRAB RFC 3 — Peering, Credentials, and Accountability
- KRAB RFC 5 — Synchronisation
- KRAB RFC 7 — Key Custody and Erasure
- KRAB SIM-0 — Corpus Convergence Measurements
- `krab-sizes/transport` — reference calculator; source of every figure here
- Noise Protocol Framework, revision 34 — pattern IK
- RFC 6330 — RaptorQ
- RFC 1928 — SOCKS5
- RFC 1613 — X.25 over TCP
- Tor Rendezvous Specification v3 — restricted discovery
- 47 CFR 97.113 — amateur service prohibited transmissions
- ETSI EN 300 220 — duty cycle limits, EU868
