#!/usr/bin/env python3
"""Group fan-out cost: sharding threshold and prekey burn.

RFC 6 implements groups as fan-out -- N single-recipient sealed objects rather
than one object under a shared group key. The security argument is sound
(compromising one member exposes only that member) but the cost is not free,
and neither SIM-0 nor SIM-1 modelled it: both generate one object per message.

Two consequences follow from arithmetic already in the series.

Usage:  python3 fanout.py
"""

# SIM-0 §7. Ingress grows linearly in network size.
INGRESS_PER_NODE_PER_NODE = 0.063      # MB/day, one object per message
SHARD_THRESHOLD_MB = 310               # RFC 0 §8.3 puts sharding "mandatory"
                                       # at ~n=5000, which is this ingress
RATE_PER_DAY = 2.0                     # SIM-0 §1, messages per node per day


def main():
    print("Fan-out moves the sharding threshold down by the mean group size")
    print()
    print(f"  SIM-0 §7:      ingress = {INGRESS_PER_NODE_PER_NODE} MB/day per node, per node")
    print(f"  RFC 0 §8.3:    sharding mandatory above ~n=5000 (~{SHARD_THRESHOLD_MB} MB/day/node)")
    print()
    print(f"{'group size':>11} {'objects/msg':>12} {'ingress mult':>13} {'shard threshold n':>18}")
    print("-" * 58)
    for g in (1, 2, 5, 10, 20, 50):
        fan = max(g - 1, 1)
        n = SHARD_THRESHOLD_MB / (INGRESS_PER_NODE_PER_NODE * fan)
        print(f"{g:>11} {fan:>12} {fan:>12}x {n:>18,.0f}")
    print()
    print("  A network whose traffic is mostly 20-person groups needs sharding")
    print("  from a few hundred nodes, not from five thousand. RFC 0 §8.3's")
    print("  threshold assumes one object per message, which groups are not.")
    print()

    print("Group membership drives received-message rate, hence prekey batch size")
    print()
    print(f"  each member sends {RATE_PER_DAY:.0f}/day; a G-member group emits G x {RATE_PER_DAY:.0f}")
    print("  group-messages/day, each fanning out to G-1 recipients")
    print()
    print(f"{'group size':>11} {'recv/day':>10} {'+2 groups':>11} {'batch @7d':>11} {'batch @30d':>12}")
    print("-" * 60)
    for g in (5, 10, 20, 50):
        recv = (g - 1) * RATE_PER_DAY          # own group traffic received
        def batch(r, days):
            need = r * days
            b = 1
            while b < need * 1.5:
                b *= 2
            wire = b * 32 + 120                # RFC 7 §5.3, verified in krab-sizes
            return b, wire <= 262_144
        b7, ok7 = batch(recv, 7)
        b30, ok30 = batch(recv, 30)
        b7x, _ = batch(recv * 2, 7)
        print(f"{g:>11} {recv:>10.0f} {recv*2:>11.0f} {b7:>11} "
              f"{b30 if ok30 else 'IMPOSSIBLE':>12}")
    print()
    print("  RFC 7 §5.3 caps a batch at 2048 keys, because 8192 exceeds MAX_OBJECT.")
    print("  Membership in two 20-person groups puts a node at 76 received/day,")
    print("  which forces weekly republication -- and a 2048-key batch is where")
    print("  RFC 7 §9's 'under 100 KB' mlock argument stops holding.")


if __name__ == "__main__":
    main()
