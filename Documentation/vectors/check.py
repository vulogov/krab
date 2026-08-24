#!/usr/bin/env python3
"""Check Documentation/vectors/rfc-1.txt without any Krab code.

RFC 1 §12 requires two independent implementations to agree on the vectors
before RFC 1 reaches Final. There is one. This script is not the second one and
does not pretend to be: it was written by the same author, from the same
reading of §6.2, so a misreading of the specification would be reproduced here
rather than caught.

What it is: a check that the *published derivations* are what the file says
they are, computed with primitives that are anchored against other people's
test vectors. Standard library only — no pip, no Krab, no Rust.

It catches the class of error a second reader is not needed to find:

  * a swapped concatenation order      (info = label ‖ epoch, not epoch ‖ label)
  * the wrong endianness on an epoch   (u32_le, so 20670 is be500000)
  * a label off by a byte
  * an Extract step that should not be there
  * an output length taken from the wrong line of the spec
  * a public key that is not the private key's

Every primitive below is self-tested against a published vector from the
standard that defines it, before it is used to check anything. If those fail,
this script is wrong and its opinion about Krab is worthless — which is the
right order to find that out in.

Usage:  python3 Documentation/vectors/check.py [path/to/rfc-1.txt]
Exit:   0 if everything checks, 1 otherwise.
"""

import hashlib
import hmac
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Primitives, each anchored against the standard that defines it
# ---------------------------------------------------------------------------

P = 2**255 - 19
A24 = 121665


def x25519(scalar: bytes, u_coord: bytes) -> bytes:
    """RFC 7748 §5. The Montgomery ladder, written from the RFC's pseudocode."""
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, "little")

    u = bytearray(u_coord)
    u[31] &= 127
    x1 = int.from_bytes(u, "little")

    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt

        a = (x2 + z2) % P
        aa = a * a % P
        b = (x2 - z2) % P
        bb = b * b % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = d * a % P
        cb = c * b % P
        x3 = pow(da + cb, 2, P)
        z3 = x1 * pow(da - cb, 2, P) % P
        x2 = aa * bb % P
        z2 = e * (aa + A24 * e) % P

    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 §2.3. Expand only — there is no Extract here, deliberately."""
    out, t, counter = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def self_test() -> None:
    """Anchor both primitives before using either."""
    # RFC 7748 §5.2, first test vector.
    got = x25519(
        bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
        bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
    ).hex()
    want = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    assert got == want, f"X25519 is wrong: {got}"

    # RFC 7748 §6.1's Diffie-Hellman example, which also checks the base point.
    a_sk = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    b_sk = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    nine = (9).to_bytes(32, "little")
    assert x25519(a_sk, nine).hex() == (
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    )
    shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    assert x25519(a_sk, x25519(b_sk, nine)).hex() == shared

    # RFC 5869 §A.1's Expand step, given its PRK.
    okm = hkdf_expand(
        bytes.fromhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
        bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
        42,
    ).hex()
    assert okm == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    ), f"HKDF-Expand is wrong: {okm}"


# ---------------------------------------------------------------------------
# The checks
# ---------------------------------------------------------------------------


def load(path: Path) -> dict:
    vals = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition(" ")
        vals[key] = value
    return vals


class Report:
    def __init__(self):
        self.ok = 0
        self.bad = []

    def check(self, what: str, got, want) -> None:
        if got == want:
            self.ok += 1
        else:
            self.bad.append(f"{what}\n    computed {got}\n    file     {want}")


def check_kdf(v: dict, r: Report) -> None:
    """The construction, from a fixed PRK. Externally anchored in the file."""
    prk = bytes.fromhex(v["kdf.prk"])
    length = int(v["kdf.L"])
    for name, label_key in (("pairwise", "label.tag.hex"), ("inbox", "label.inbox.hex")):
        label = bytes.fromhex(v[label_key])
        for epoch in (20670, 20671, 20672):
            # The info bytes must be label ‖ u32_le(epoch), and the file's
            # published info must equal that. Checking the file's info against
            # the rule is the point: it is where a byte-order error shows.
            expected_info = label + epoch.to_bytes(4, "little")
            r.check(
                f"kdf.info.{name}.{epoch} is label || u32_le(epoch)",
                expected_info.hex(),
                v[f"kdf.info.{name}.{epoch}"],
            )
            r.check(
                f"kdf.{name}.{epoch}",
                hkdf_expand(prk, expected_info, length).hex(),
                v[f"kdf.{name}.{epoch}"],
            )


def check_tags(v: dict, r: Report) -> None:
    """The full chain: X25519, then the same Expand construction."""
    a_sk = bytes.fromhex(v["kx.a.secret"])
    b_sk = bytes.fromhex(v["kx.b.secret"])
    a_pk = bytes.fromhex(v["kx.a.public"])
    b_pk = bytes.fromhex(v["kx.b.public"])
    nine = (9).to_bytes(32, "little")

    r.check("kx.a.public = X25519(a.secret, 9)", x25519(a_sk, nine).hex(), v["kx.a.public"])
    r.check("kx.b.public = X25519(b.secret, 9)", x25519(b_sk, nine).hex(), v["kx.b.public"])
    r.check("kx.shared = X25519(a.secret, b.public)", x25519(a_sk, b_pk).hex(), v["kx.shared"])
    r.check("kx.shared is symmetric", x25519(b_sk, a_pk).hex(), v["kx.shared"])

    shared = bytes.fromhex(v["kx.shared"])
    for epoch in (20670, 20671, 20672):
        # Pairwise: the PRK is the agreed secret.
        info = bytes.fromhex(v["label.tag.hex"]) + epoch.to_bytes(4, "little")
        r.check(
            f"tag.pairwise.{epoch}",
            hkdf_expand(shared, info, 8).hex(),
            v[f"tag.pairwise.{epoch}"],
        )
        # Inbox: the PRK is the recipient's PUBLIC key, used verbatim. That is
        # RFC 1 §6.2 as frozen, and it is what makes first contact possible.
        info = bytes.fromhex(v["label.inbox.hex"]) + epoch.to_bytes(4, "little")
        r.check(
            f"tag.inbox.{epoch}",
            hkdf_expand(b_pk, info, 8).hex(),
            v[f"tag.inbox.{epoch}"],
        )


def check_objects(v: dict, r: Report) -> None:
    """The canonical form: header ‖ body ‖ zero padding, to the bucket.

    The identifier itself is BLAKE3-256, which the Python standard library does
    not provide — so the preimage is checked here and the hash is left to a
    reader with a BLAKE3 utility. The file prints the whole preimage precisely
    so that is possible.
    """
    for cls in (0, 1):
        obj = bytes.fromhex(v[f"object.class{cls}.bytes"])
        header = bytes.fromhex(v[f"header.class{cls}.encoded"])
        body = bytes.fromhex(v[f"object.class{cls}.body"])

        r.check(f"object.class{cls} starts with its header", obj[:16].hex(), header.hex())
        r.check(
            f"object.class{cls} body follows the header",
            obj[16 : 16 + len(body)].hex(),
            body.hex(),
        )
        r.check(
            f"object.class{cls} padding is zero",
            set(obj[16 + len(body) :]) or {0},
            {0},
        )
        r.check(
            f"object.class{cls}.len is the bucket size",
            len(obj),
            int(v["bucket.0.bytes"]),
        )

        # The header's own fields, so the byte layout is checked and not assumed.
        r.check(f"header.class{cls} version", header[0], 1)
        r.check(f"header.class{cls} class", header[1], cls)
        r.check(f"header.class{cls} size_bucket", header[2], 0)
        r.check(f"header.class{cls} flags", header[3], 0)
        # Little-endian. This check said "big" in its first draft and failed,
        # which is how the vector file's own comment turned out to be wrong.
        r.check(
            f"header.class{cls} expiry_min is little-endian u32",
            int.from_bytes(header[4:8], "little"),
            int(v[f"header.class{cls}.expiry_min"]),
        )
        r.check(f"header.class{cls} tag", header[8:16].hex(), v[f"header.class{cls}.tag"])

        # One flipped padding byte, one different object — which is why RFC 1
        # §8.1 fixes padding at zero and the identifier covers it.
        dirty = bytes.fromhex(v[f"object.class{cls}.bytes_with_dirty_padding"])
        r.check(f"class{cls} dirty padding differs in one byte", dirty[:-1].hex(), obj[:-1].hex())
        r.check(f"class{cls} dirty padding byte", dirty[-1], 1)
        if v[f"object.class{cls}.id"] == v[f"object.class{cls}.id_with_dirty_padding"]:
            r.bad.append(
                f"class{cls}: padding does not change the identifier — "
                "the id does not cover the padding"
            )
        else:
            r.ok += 1


def check_info_strings(v: dict, r: Report) -> None:
    """The HPKE info string: prefix ‖ one byte of class — RFC 1 §6.1."""
    prefix = bytes.fromhex(v["info.prefix.hex"])
    r.check("info.prefix is ASCII as printed", prefix.decode(), v["info.prefix.ascii"])
    for cls in (0, 1):
        r.check(f"info.class{cls}", (prefix + bytes([cls])).hex(), v[f"info.class{cls}"])


def check_labels(v: dict, r: Report) -> None:
    r.check("label.tag hex matches ascii", bytes.fromhex(v["label.tag.hex"]).decode(), v["label.tag.ascii"])
    r.check(
        "label.inbox hex matches ascii",
        bytes.fromhex(v["label.inbox.hex"]).decode(),
        v["label.inbox.ascii"],
    )
    r.check(
        "domain.object hex matches ascii",
        bytes.fromhex(v["domain.object.hex"]).decode(),
        v["domain.object.ascii"],
    )


def check_buckets(v: dict, r: Report) -> None:
    """Each boundary: N lands in its bucket, N+1 in the next — RFC 1 §8.1."""
    sizes = []
    i = 0
    while f"bucket.{i}.bytes" in v:
        sizes.append(int(v[f"bucket.{i}.bytes"]))
        i += 1
    r.check("the ladder is ×4 steps", [s * 4 for s in sizes[:-1]], sizes[1:])
    for idx, size in enumerate(sizes):
        r.check(f"bucket.for.{size}", str(idx), v[f"bucket.for.{size}"])
        expect = str(idx + 1) if idx + 1 < len(sizes) else "none"
        r.check(f"bucket.for.{size + 1}", expect, v[f"bucket.for.{size + 1}"])


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("rfc-1.txt")
    try:
        self_test()
    except AssertionError as exc:
        print(f"FAIL: this script's own primitives are wrong — {exc}")
        print("Nothing below would have meant anything. Fix this first.")
        return 1
    print("primitives anchored: X25519 against RFC 7748 §5.2 and §6.1,")
    print("                     HKDF-Expand against RFC 5869 §A.1")

    v = load(path)
    r = Report()
    for name, fn in (
        ("bucket boundaries (§8.1)", check_buckets),
        ("labels and domains", check_labels),
        ("canonical form and preimages (§4)", check_objects),
        ("HKDF-Expand construction (§6.2)", check_kdf),
        ("tag derivation (§6.2)", check_tags),
        ("HPKE info strings (§6.1)", check_info_strings),
    ):
        before = r.ok, len(r.bad)
        fn(v, r)
        print(f"  {name}: {r.ok - before[0]} checked, {len(r.bad) - before[1]} failed")

    print()
    if r.bad:
        for line in r.bad:
            print(f"FAIL {line}")
        print(f"\n{len(r.bad)} failed, {r.ok} passed")
        return 1
    print(f"{r.ok} checks passed.")
    print()
    print("Not checked here: object identifiers (BLAKE3-256, absent from the")
    print("Python standard library — the file prints the whole preimage so a")
    print("reader with a BLAKE3 utility can finish the job), and seal/open,")
    print("which is randomised and has no fixed value to check.")
    print()
    print("This is not RFC 1 §12's second implementation. It shares an author")
    print("with the first, so a misreading of §6.2 is reproduced here rather")
    print("than caught.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
