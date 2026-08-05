#!/usr/bin/env python3
"""RFC 5's three decisions, as arithmetic.

SIM-1 §1 established that reconciliation strategy has no safe default. This
turns that finding into a decision procedure a LinkProfile can evaluate, and
sizes the two other constraints RFC 5 inherits.

Constants come from documents already at Draft: RFC 1 §9.3 (16-byte manifest
entries), RFC 4 §5.4 (LoRa 72 KB/day at SF10), SIM-0 §1 (transport latencies),
SIM-0 §2 (corpus size at n=500).

Usage:  python3 sync-mode.py
"""

ENTRY = 16            # RFC 1 §9.3: expiry u32 + 12-byte truncated id
FP_TAG = 36           # 32-byte fingerprint + 4-byte count, RBSR range probe
RBSR_B = 16           # branching factor, SIM-1
TTL_D = 14            # SIM-0 baseline

# (name, per-sync window bytes, one-way latency seconds, syncs/day)
LINKS = [
    ("tcp over Tor",  1 << 30,   3.0,          6),
    ("LoRa SF10",     18_000,   10.0,          4),
    ("courier",       64 << 30, 3 * 86_400,  1 / 7),
]


def depth(m, b=RBSR_B):
    d, span = 0, max(m, 1)
    while span > 1:
        span = -(-span // b)
        d += 1
    return max(d, 1)


def main():
    corpus = 14_000                      # live objects at n=500, SIM-0
    print(f"Live corpus at n=500: {corpus:,} objects\n")

    print("1. Full manifest against the per-sync window\n")
    print(f"   a full manifest is 2 x m x {ENTRY} B (both sides name what they hold)\n")
    print(f"   {'link':<14} {'window':>12} {'manifest':>12} {'fits?':>8} {'max m':>9}")
    for name, window, _, _ in LINKS:
        man = 2 * corpus * ENTRY
        fits = "yes" if man <= window else "NO"
        print(f"   {name:<14} {window:>12,} {man:>12,} {fits:>8} {window//(2*ENTRY):>9,}")
    print()
    k = 0
    while corpus / (2 ** k) * 2 * ENTRY > 18_000:
        k += 1
    print(f"   A LoRa link needs shard k >= {k} for a full manifest to fit at n=500.")
    print(f"   RFC 2 §6: k={k} leaves a {100/2**k:.2f}% anonymity set.\n")

    print("2. RBSR against the round-trip budget\n")
    d = depth(corpus)
    print(f"   descent depth at b={RBSR_B}, m={corpus:,}: {d} rounds\n")
    print(f"   {'link':<14} {'RTT':>10} {'{d} rounds':>12} {'vs TTL':>10} {'verdict':>10}")
    for name, _, lat, _ in LINKS:
        rtt = 2 * lat
        total = d * rtt
        frac = total / (TTL_D * 86_400)
        verdict = "ok" if frac < 0.25 else "NO"
        unit = f"{total:,.0f}s" if total < 86_400 else f"{total/86_400:.1f}d"
        print(f"   {name:<14} {rtt:>9,.0f}s {unit:>12} {frac:>9.1%} {verdict:>10}")
    print()
    rbsr_bytes = 2 * RBSR_B * d * FP_TAG
    print(f"   RBSR control cost: 2 x {RBSR_B} x {d} x {FP_TAG} = {rbsr_bytes:,} B + 16 B per difference")
    print(f"   against a full manifest's {2*corpus*ENTRY:,} B -- {2*corpus*ENTRY/rbsr_bytes:.0f}x cheaper\n")

    print("   => the decision procedure, from the two tables above:\n")
    print("        full manifest feasible  iff  2*m*16 <= per-sync window")
    print("        RBSR feasible           iff  depth * 2 * latency << TTL")
    print("        LoRa: manifest infeasible, RBSR feasible  -> RBSR")
    print("        courier: manifest feasible, RBSR infeasible -> manifest")
    print("        TCP: both feasible -> RBSR, on bytes\n")

    print("3. Why Bloom filters fail asymmetrically\n")
    print("   A false positive means the sender believes the receiver already")
    print("   holds an object, so it is never offered -- silent loss, not delay.\n")
    print(f"   {'peers':>7} {'p=1%':>12} {'p=0.1%':>12}")
    for peers in (1, 2, 4, 8, 12):
        print(f"   {peers:>7} {0.01**peers:>12.2e} {0.001**peers:>12.2e}")
    print()
    print("   P(object never delivered) = p^peers, so the loss concentrates")
    print("   entirely on low-degree nodes -- which SIM-0 §5 already identifies")
    print("   as the population where delivery is worst. A leaf node loses 1% of")
    print("   its mail permanently at p=1%.\n")

    print("4. Effective retention under capacity pressure\n")
    ingress = 31.0                        # MB/day at n=500, SIM-0 §2
    print(f"   ingress {ingress} MB/day at n=500\n")
    print(f"   {'cap MB':>8} {'days held':>11} {'promise 30d?':>14}")
    for cap in (100, 200, 300, 450, 1_000):
        days = cap / ingress
        print(f"   {cap:>8} {days:>11.1f} {'kept' if days >= 30 else 'BROKEN':>14}")
    print()
    print("   effective_retention = min(promised, cap / daily_ingress)")
    print("   A node promising 30 days on a 100 MB cap actually holds 3.2, and")
    print("   SIM-1 §4 measured the resulting re-fetch loop at +68% ingress.")


if __name__ == "__main__":
    main()
