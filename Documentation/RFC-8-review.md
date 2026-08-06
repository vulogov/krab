# RFC 8 — Review

    Subject:  RFC 8, Client Behaviour, Status: Draft
    Method:   cross-check against RFC 0–7, SIM-0, SIM-1
    Verdict:  one measured result declined; one operator number now three-way split

RFC 8 completes the series. §1.1 is a genuine contribution: marking every
requirement **derived** or **judgement**, and stating plainly that a "MUST" on
a judgement requirement means *the author believes the failure mode warrants
it despite the absence of evidence*, is a discipline the other seven documents
would benefit from retroactively. It is also the honest response to a document
that terminates seven RFCs of measurement in an interface nobody can simulate.

Three sections are the best writing in the series — §5.1, §13, and §14's
convenience-optimisation paragraph. Findings below are narrow by comparison.

---

## 1. §9.2 declines to state a result that was measured

> "**no simulation in this project has measured a timing-gradient or origin
> attack against degree.** The warning text MUST NOT assert a deanonymisation
> figure. If such a claim is wanted, it requires a SIM-2 with an adversary
> model, and RFC 0 §9 forbids asserting it first."

**SIM-1 §3 measured exactly that**, and it is in this repository. A
maximum-likelihood origin attack using only holdings and each object's
cleartext age, against 500 candidates, under austere transport at 25 vantage
points:

| configuration | true origin in top 10 | vs chance |
|---|---|---|
| degree 8, TTL 14 d | 12.45% | **6.2×** |
| degree 12 | 3.40% | 1.7× |
| degree 12 + TTL 30 d | 2.50% | 1.25× |

Under mixed or all-TCP transport the same attack never beats chance at any
vantage count up to 50.

The sentence is half right — SIM-1 measured a *holdings* attack, not a
*timing* gradient — but the conclusion drawn from it is wrong. A
deanonymisation figure exists, it is measured, it varies with degree, and
SIM-1 §3's own headline is that **the holdings leak is a symptom of
under-provisioning rather than an inherent property.**

That makes this an unusual finding for this series: RFC 8 is *under*-claiming.
Every previous finding has been a document asserting more than its grounding
supported; this one declines to assert something its grounding does support,
and the caution is admirable but costly. The effect is that the warning text
will tell an operator they may experience delivery problems, when the measured
position is that they are **measurably easier to deanonymise** — which is a
categorically stronger reason to add peers, and the one SIM-1 §3's
normative-consequences section was written to produce.

**Fix.** §9.2's "Unmeasured" paragraph should cite SIM-1 §3, and the warning
text should say that peer count is a privacy control as well as an
availability one. What remains genuinely unmeasured is a *timing*-gradient
attack; that distinction is worth keeping and is not what the paragraph
currently says.

---

## 2. Peer-count guidance is now three-way split, and RFC 8 is what renders it

| document | IP-connected | mixed | courier / radio |
|---|---|---|---|
| RFC 0 §8.2 | 6–8 | 8 | 12+ |
| RFC 3 §13 | 8–20 | 12–20 | 12–25 |
| **RFC 8 §9.2** | **6–8** | **8–12** | **12+** |

Three documents, three tables, and RFC 8 is the one that actually shows a
number to an operator.

`RFC-3-review.md` §5 found the RFC 0 / RFC 3 disagreement and concluded RFC 3
was correct on the later evidence — SIM-1 §3 found degree 12 is what closes
the holdings leak under austere transport, which is a privacy argument that
postdates RFC 0 §8.2. RFC 8 has followed RFC 0, the older and less
conservative set, and its mixed row (8–12) matches neither predecessor.

This compounds §1: RFC 8 warns below 8 on a mixed link, where SIM-1 §3's
evidence supports 12.

**Fix.** One table, in one document, cited by the others. RFC 8 is the natural
home since it is the only one that renders it, with RFC 0 §8.2 and RFC 3 §13
pointing here.

---

## 3. §5.3 lists coverage without saying it must be an age profile

`peers` displays "coverage" among a dozen aggregates. SIM-1 §2 found the
scalar actively misleading: a 37% aggregate concealed a **3%-to-82% ramp**
across object age, and the mean describes no node's actual holding
probability for any object.

RFC 0 §7.4's requirement that nodes measure and surface coverage predates that
finding. RFC 8 is where it becomes a display decision, and a single percentage
in a table is precisely the presentation SIM-1 §2 identified as wrong.

**Fix.** Require the age profile, or at minimum the youngest-bucket figure
alongside the mean — under austere transport those differ by an order of
magnitude and only the first tells an operator anything actionable.

---

## 4. §6's re-encoding is load-bearing for RFC 1, and the coupling is unstated

`RFC-1-review.md` §4 found that `MAX_OBJECT` (262 144 B) leaves 5.3% of
SIM-0's modelled traffic unrepresentable, with no object-level chunking
specified anywhere. The probable resolution was RFC 8's re-encode rule, which
caps decoded pixel count and re-encodes canonically, bounding output below
`MAX_OBJECT`.

§6 specifies exactly that and does not say it is what makes RFC 1's cap
enforceable. The dependency runs upward, which is unusual and therefore easy
to lose: **a client that skips re-encoding cannot send an ordinary
photograph**, and RFC 1 has no chunking mechanism to fall back on.

Worth one sentence in §6 and one in RFC 1 §8.

---

## 5. Minor

- **§2's layout percentages are unmarked MUSTs.** "The list pane MUST occupy
  40% of width" is a hard requirement on a presentation detail, and §1.1's own
  scheme would classify it as judgement. Every other normative block in the
  document carries its marker; this one does not, which is conspicuous in a
  document whose best idea is the marking.
- **§6's "pictures cannot cross LoRa links" is very nearly but not exactly
  true.** RFC 4 §5.4 caps LoRa at bucket 1024, which admits 858 bytes of body
  — a thumbnail, not nothing. "Cannot cross at any useful size" is the exact
  claim, and the client warning §6 requires should say which.
- **§4.2 correctly cites RFC 2 §7.3 rather than RFC 7 §5.3** for prekey
  thresholds, which is the corrected model. Worth noting because RFC 6 §2.8
  still carries the superseded one, and a reader following that chain instead
  would arrive at a withdrawn requirement.

---

## 6. What RFC 8 got right

- **§1.1's derived/judgement distinction**, and the explicit statement of what
  a judgement MUST means. This should propagate backward through the series.
- **§5.1 is the strongest single analysis in the document.** "Event-driven
  sync is not reintroduced by someone deciding to weaken privacy; it is
  reintroduced by someone fixing what looks like a bug" identifies the actual
  mechanism by which I-5 will be lost, and the separation of *transport
  establishment progress* (required) from *reconciliation progress on a
  keypress* (forbidden) resolves a tension the earlier documents left as a
  flat prohibition. The scheduled-window display is a genuinely good answer to
  "then what does the user see."
- **§2.1's observation that zoom makes the banner load-bearing.** RFC 6 §5
  required the composer banner without saying why the tab header was
  insufficient; §2.1 supplies the reason — the header is periodically not on
  screen — which converts a preference into a consequence.
- **§14's convenience-optimisation paragraph** names the pattern the whole
  series has been fighting, and the prescription — regression tests asserting
  the *absence* of behaviour — is the only durable form.
- **§13 records eight rejections with reasons.** Forwarding being
  *semantically empty* rather than merely risky is the sharpest of them.
- **§9.1** correctly treats routine expiry as a state rather than an error,
  and names the cost of getting it wrong: a client that renders expiry as an
  error trains operators to ignore errors.

---

## 7. Series status with RFC 8 at Draft

All nine documents exist. Outstanding, in order of cost to fix:

1. **The reservoir key-reuse defect** (`CRYPTO-REVIEW.md` §1) — open, marked
   in place, blocks RFC 7 §6 and RFC 1 §6.5's post-quantum claim.
2. **Three high crypto findings** — Ed25519 strictness, X25519 Extract plus
   low-order rejection, both unresolved.
3. **One operator table, three documents** — §2 above.
4. **RFC 5's grounding is not in the repository**, and where it overlaps the
   committed simulator the two disagree (33.0% against 64.8%).
5. **RFC 0 has accumulated twelve corrections** across the reviews, now
   including §9.2's peer-count table and the SIM-1 §3 citation.
6. **RFC 1 §12's test vectors do not exist**, and two implementations agreeing
   on them gates every Final.
