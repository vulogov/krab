#!/usr/bin/env python3
"""Reservoir sizing, forward-secrecy floor, and post-quantum economics.

RFC 1 §6.5 names the epoch-chunked reservoir Krab's *primary* post-quantum
strategy, on the measured grounds that a per-message hybrid KEM inflates the
smallest objects 16x. RFC 1 is frozen, so RFC 7 has to deliver a mechanism a
frozen document already depends on. This sizes it.

Bucket figures come from apps/krab-sizes, which reproduces RFC 1's published
byte counts exactly (`krab-sizes --check`).

Usage:  python3 reservoir.py
"""

EPOCH_D = 1        # RFC 1 §2, EPOCH 86400 s
MAX_TTL_D = 45     # RFC 1 §2
CHUNK_B = 32       # plan: 32 bytes per epoch
QR_EC_M = 2331     # binary capacity, QR version 40 at error-correction M

# krab-sizes, 280-byte message, addr 'dst=<16 hex>', text/plain.
CLASSICAL_BUCKET = 1024
HYBRID_BUCKET = 4096
# One hybrid-KEM object establishing a reservoir: 1224 B floor -> 4096 bucket.
HYBRID_SETUP = 4096


def main():
    live = MAX_TTL_D // EPOCH_D

    print("Forward-secrecy window is bounded below by MAX_TTL")
    print("  chunk N decrypts objects whose tag epoch is N")
    print(f"  such an object may arrive up to MAX_TTL/EPOCH = {live} epochs later")
    print(f"  => chunk N MUST survive until N+{live}; live chunks = {live}")
    print(f"  => seizure at T exposes epochs T-{MAX_TTL_D} d .. T, whatever EPOCH is")
    print(f"  live reservoir state: {live} x {CHUNK_B} B = {live * CHUNK_B} B")
    print()

    print(f"Reservoir sizing ({CHUNK_B} B/epoch, {EPOCH_D}-day epochs)")
    for label, days in (("one credential term (90 d)", 90),
                        ("one year", 365),
                        ("five years", 365 * 5)):
        b = days * CHUNK_B
        print(f"  {label:<28} {b:>7} B   {b / QR_EC_M:>5.1f} QR codes at EC-M")
    print()
    print("  The ratchet -- reservoir_{n+1} = HKDF(reservoir_n || DH(fresh)) -- means")
    print("  a reservoir need only span the maximum interval between contacts, not a")
    print("  lifetime. A quantum adversary recovers DH(fresh) but not reservoir_n, so")
    print("  PQ security survives provided the ROOT of the chain was PQ-established.")
    print()

    print("Reservoir against per-message hybrid (280-byte message)")
    per_msg = HYBRID_BUCKET - CLASSICAL_BUCKET
    print(f"  per-message hybrid surcharge    {per_msg:>6} B/message "
          f"({HYBRID_BUCKET} vs {CLASSICAL_BUCKET} bucket)")
    print(f"  reservoir setup, one hybrid KEM {HYBRID_SETUP:>6} B, once per correspondent")
    print(f"  crossover                       {HYBRID_SETUP / per_msg:>6.2f} messages")
    for n in (10, 100, 1000):
        print(f"  after {n:>4} messages: reservoir {HYBRID_SETUP:>6} B "
              f"against hybrid {n * per_msg:>8} B  ({n * per_msg / HYBRID_SETUP:>5.0f}x)")
    print()
    print("  A hybrid-KEM-established reservoir pays for itself before the second")
    print("  message. RFC 3 §11.1 concedes remote peering is the common case, so the")
    print("  reservoir must be reachable without a physical meeting or Krab has no")
    print("  post-quantum story for most correspondents.")


if __name__ == "__main__":
    main()
