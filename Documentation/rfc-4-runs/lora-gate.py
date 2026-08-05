#!/usr/bin/env python3
"""What should LoRa's max_object_size be?

Four documents assume different answers, and RFC 4 owns LinkProfile so RFC 4
must pin one:

  SIM-0 model      512 B   (audit found this admits ~nothing)
  RFC 1 §8.3     4 096 B   (tabulates airtime for the 4096 bucket)
  RFC 6 §2.4       256 B   (costs a group message at the 256 bucket)
  RFC 7 §5.4       512 B   (concludes no prekey batch can cross)

The gate applies to the *encoded, padded object*, not to the message body.
That distinction turns out to matter more than the gate value: SIM-0 gated on
raw body size, so its 0.16%-of-objects figure understates the problem.

Formulas are from apps/krab-sizes, which reproduces RFC 1's published byte
counts exactly (`krab-sizes --check`).

Usage:  python3 lora-gate.py
"""

BUCKETS = [256, 1_024, 4_096, 16_384, 65_536, 262_144]
LORA_BPS = 0.85          # EU868 SF10 at 1% duty, SIM-0 §1
LORA_PAYLOAD = 51
SECONDS_DAY = 86_400


def head(v):
    if v <= 23: return 1
    if v <= 0xFF: return 2
    if v <= 0xFFFF: return 3
    if v <= 0xFFFF_FFFF: return 5
    return 9


def on_wire(body):
    """RFC 1 §3 layering, addr 'dst=<16 hex>' and text/plain."""
    inner = 83 + head(body) + body          # 51 + t(20) + t(10) + b(body)
    ct = inner + 16                          # AEAD tag
    return 63 + head(ct) + ct                # header 16 + envelope 47 + b(ct)


def bucket(n):
    for b in BUCKETS:
        if n <= b:
            return b
    return None


def main():
    print("1. SIM-0's traffic, encoded per RFC 1\n")
    print("   SIM-0 draws text bodies uniform [500, 8000) and pictures")
    print("   [50 000, 500 000). Encoded and padded, they land in:\n")
    lo, hi = 500, 8_000
    dist = {}
    for body in range(lo, hi):
        dist[bucket(on_wire(body))] = dist.get(bucket(on_wire(body)), 0) + 1
    span = hi - lo
    print(f"   {'bucket':>9} {'share of text':>15}")
    for b in sorted(k for k in dist if k):
        print(f"   {b:>9} {100*dist[b]/span:>14.1f}%")
    print(f"\n   smallest text object: {on_wire(lo)} B -> bucket {bucket(on_wire(lo))}")
    print(f"   RFC 1 §8.1 floor:     165 B -> bucket 256 (body 0)")
    print(f"   a 256-bucket object needs body <= 90 B; SIM-0 generates none.\n")

    print("2. What crosses each candidate gate\n")
    print(f"   {'gate':>8} {'buckets admitted':>18} {'share of SIM-0 text':>21}")
    for gate in (256, 512, 1_024, 4_096, 16_384):
        admitted = [b for b in BUCKETS if b <= gate]
        share = sum(v for k, v in dist.items() if k and k <= gate) / span
        names = ",".join(str(b) for b in admitted) or "none"
        print(f"   {gate:>8} {names:>18} {100*share:>20.1f}%")
    print()
    print("   At 512 B *zero* of SIM-0's traffic crosses -- not 0.16%. The audit")
    print("   measured raw body size; the gate applies to the padded object, and")
    print("   the smallest one SIM-0 produces is 667 B.\n")

    print("3. Throughput per gate against the flood requirement\n")
    budget = LORA_BPS * SECONDS_DAY
    print(f"   LoRa daily budget: {budget:,.0f} B/day\n")
    print(f"   {'bucket':>9} {'frames':>8} {'airtime':>10} {'objects/day':>12}")
    for b in BUCKETS[:5]:
        frames = -(-b // LORA_PAYLOAD)
        air = b / LORA_BPS
        print(f"   {b:>9} {frames:>8} {air/3600:>9.1f}h {budget/b:>12.1f}")
    print()
    n = 500
    need = n * 2                     # SIM-0: 2 objects/node/day flooded to all
    print(f"   flood requirement at n={n}: {need} objects/day")
    for gate in (1_024, 4_096, 16_384):
        cap = budget / gate
        print(f"     gate {gate:>6}: {cap:>6.1f} objects/day = {100*cap/need:>5.2f}% of flood")
    print()
    print("   No gate makes LoRa a flooding transport. A 4096 B gate carries ~17")
    print("   objects/day, which is useful only under a narrow shard and class")
    print("   filter -- targeted traffic, not corpus replication.")


if __name__ == "__main__":
    main()
