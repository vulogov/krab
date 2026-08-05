#!/usr/bin/env python3
"""Negotiation-triple completion over the corpus.

RFC 3's peering flow is three signed static documents chained by hash:

    peer-request  ->  peer-counter  ->  peer-link

RFC 3 §5.1 specifies that a peer-request travels as an ordinary `sealed`
corpus object addressed to the recipient's inbox tag -- deliberately, so that
it reaches a node with no endpoint at all. Each leg of the negotiation is
therefore a corpus delivery, and inherits the corpus's delivery probability
and latency rather than a single link's.

That matters because corpus delivery is not certain. SIM-0 measured delivery
rates below 1.0 under austere and courier-dominated transport, and three
sequential deliveries compound.

  NOTE: an earlier revision of this script modelled each leg as one direct
  courier hop (7-day Poisson journeys, 3-day transit), giving 30 d mean. That
  was the wrong model -- it assumed a direct link the peers do not yet have.
  Peering is precisely the situation where no link exists, which is why RFC 3
  routes it through the corpus.

Completion probability is exact: it is the delivery rate cubed. Latency is
approximate -- SIM-0 publishes percentiles rather than a distribution, so the
inverse CDF is interpolated piecewise-linearly through them and the tail
beyond p99 is extrapolated. Treat the latency figures as indicative and the
completion figures as sound.

Usage:  python3 peering-latency.py
"""

import random
import statistics

LEGS = 3
TRIALS = 200_000
SEED = 1

# SIM-0 §3, TTL 14 d, degree 8. (delivery, p50 h, p90 h, p99 h)
MIXES = [
    ("all-tcp        100/0/0", 1.000, 4.9, 8.7, 14.1),
    ("mixed           70/15/15", 1.000, 7.3, 12.7, 18.6),
    ("courier-heavy   50/20/30", 1.000, 11.6, 20.5, 60.5),
    ("austere         20/30/50", 0.958, 170.6, 296.8, 382.5),
    ("all-courier       0/0/100", 0.525, 311.5, 390.9, 406.3),
]


def inv_cdf(u, p50, p90, p99):
    """Piecewise-linear inverse CDF through SIM-0's published percentiles."""
    if u <= 0.50:
        return p50 * (u / 0.50)
    if u <= 0.90:
        return p50 + (p90 - p50) * (u - 0.50) / 0.40
    if u <= 0.99:
        return p90 + (p99 - p90) * (u - 0.90) / 0.09
    # Beyond p99 SIM-0 says nothing; extend the p90-p99 slope.
    return p99 + (p99 - p90) * (u - 0.99) / 0.09


def main():
    print("Negotiation triple over the corpus (RFC 3 §5.1)")
    print(f"  {LEGS} legs, each an ordinary sealed-object delivery\n")
    print(f"{'transport mix':<26} {'per-leg':>8} {'complete':>9} {'lost':>7} "
          f"{'p50':>8} {'p90':>8}")
    print(f"{'':<26} {'deliv':>8} {'all 3':>9} {'':>7} {'days':>8} {'days':>8}")
    print("-" * 72)

    for name, deliv, p50, p90, p99 in MIXES:
        rng = random.Random(SEED)
        complete = deliv ** LEGS
        lat = []
        for _ in range(TRIALS):
            total = 0.0
            ok = True
            for _ in range(LEGS):
                if rng.random() > deliv:
                    ok = False
                    break
                total += inv_cdf(rng.random(), p50, p90, p99)
            if ok:
                lat.append(total / 24.0)
        lat.sort()
        p = lambda q: lat[int(q * len(lat)) - 1] if lat else float("nan")
        print(f"{name:<26} {deliv:>7.1%} {complete:>8.1%} {1-complete:>6.1%} "
              f"{p(0.50):>8.1f} {p(0.90):>8.1f}")

    print()
    print("Completion is exact (delivery rate cubed). Latency is interpolated")
    print("from SIM-0's percentiles and is indicative only.\n")

    # Credential term: the negotiation must finish inside whatever window the
    # request and counter are valid for, and renewal must finish inside the term.
    print("Against candidate credential terms (RFC 3 §4: 'SHOULD be 60-90 days')")
    print(f"{'transport mix':<26} {'p90 days':>9} {'60 d':>10} {'90 d':>10}")
    print("-" * 60)
    for name, deliv, p50, p90, p99 in MIXES:
        rng = random.Random(SEED)
        lat = []
        for _ in range(TRIALS):
            total, ok = 0.0, True
            for _ in range(LEGS):
                if rng.random() > deliv:
                    ok = False
                    break
                total += inv_cdf(rng.random(), p50, p90, p99)
            if ok:
                lat.append(total / 24.0)
        lat.sort()
        d90 = lat[int(0.90 * len(lat)) - 1] if lat else float("nan")
        print(f"{name:<26} {d90:>9.1f} {d90/60:>9.1%} {d90/90:>9.1%}")
    print()
    print("Percentages are the share of a credential term consumed by one")
    print("negotiation at p90 -- which is also the renewal lead time required.")


if __name__ == "__main__":
    main()
