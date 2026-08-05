#!/usr/bin/env python3
"""Negotiation-triple latency over courier links.

RFC 3's peering flow is three signed static documents chained by hash:

    peer-request  ->  peer-counter  ->  peer-link

Static rather than interactive precisely so the flow completes without both
parties being online, which is what lets it run over a courier. That it
*completes* is a design property. How long it *takes* is arithmetic, and the
answer bears on the credential expiry RFC 3 has to choose.

Parameters come from SIM-0's courier model (apps/krab-sim/src/model.rs):
Poisson-scheduled journeys at a 7-day mean interval, 3-day transit. Waiting
time for the next journey is exponential and therefore memoryless, so the
expected wait from an arbitrary moment is the full mean interval, not half
of it.

This is analytic. RFC 0 §9 still lists "the peering flow completes over
courier alone" as an outstanding end-to-end test with the network down; this
computation does not discharge it, it sizes it.

Usage:  python3 peering-latency.py
"""

import random
import statistics

MEAN_GAP = 7.0   # days between courier journeys, SIM-0 LinkKind::Courier
TRANSIT = 3.0    # days in transit, SIM-0 LinkKind::Courier::latency_s
LEGS = 3         # request -> counter -> link
TRIALS = 200_000
SEED = 1


def one_leg(rng):
    """Wait for the next journey, then ride it."""
    return rng.expovariate(1 / MEAN_GAP) + TRANSIT


def main():
    rng = random.Random(SEED)
    trials = sorted(sum(one_leg(rng) for _ in range(LEGS)) for _ in range(TRIALS))

    def pct(q):
        return trials[int(q * len(trials)) - 1]

    mean = statistics.mean(trials)

    print("Negotiation triple over courier-only links")
    print(f"  {LEGS} one-way legs; per leg E[wait] {MEAN_GAP:.0f} d + transit "
          f"{TRANSIT:.0f} d = {MEAN_GAP + TRANSIT:.0f} d")
    print()
    print(f"  mean  {mean:5.1f} d")
    for q in (0.50, 0.90, 0.99):
        print(f"  p{int(q * 100):<3} {pct(q):5.1f} d")
    print()

    for expiry in (60, 90):
        stranded = sum(1 for t in trials if t > expiry) / len(trials)
        print(f"  credential expiry {expiry} d:")
        print(f"    establishment consumes {100 * mean / expiry:4.1f}% of lifetime (mean), "
              f"{100 * pct(0.90) / expiry:4.1f}% at p90")
        print(f"    renewal must begin >= {pct(0.90):.0f} d before expiry to complete at p90, "
              f"leaving {expiry - pct(0.90):.0f} d settled")
        print(f"    P(negotiation outlives a full credential term) = {100 * stranded:.2f}%")
        print()


if __name__ == "__main__":
    main()
