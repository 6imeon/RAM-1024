"""RAM-1024 reduced-round cryptanalysis challenges (for external review).

    python3 tools/challenges.py list               # print the challenges
    python3 tools/challenges.py check ID HEX [HEX] # verify a solution

Collision C-r-n : two distinct messages whose r-round hash-mode digests
                  (n bytes, research instance) are equal.
Preimage  P-r-n : a message whose r-round n-byte digest equals the target.
Targets are SHA3-512 of a fixed label (nothing up the sleeve). Digests use
ram1024.ram_hash(msg, n, MODE_HASH, rounds=r, research=True), the same
function as the C research build (tests/kat.txt has reduced-round KATs).
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from ramhash import ram1024  # noqa: E402

# (rounds, digest bytes): generic cost 2^(4n) for collisions, 2^(8n) for preimages
COLLISION = [(1, 8), (1, 16), (2, 8), (2, 16), (3, 8), (3, 16), (4, 8), (4, 16),
             (6, 16), (8, 32)]
PREIMAGE = [(1, 4), (1, 8), (2, 4), (2, 8), (3, 4), (3, 8), (4, 8), (6, 16), (8, 32)]


def target(r, n):
    return hashlib.sha3_512(b"RAM-1024 v3 preimage challenge r=%d n=%d" % (r, n)).digest()[:n]


def digest(msg, r, n):
    return ram1024.ram_hash(msg, n, ram1024.MODE_HASH, rounds=r, research=True)


def main():
    if len(sys.argv) < 2 or sys.argv[1] == "list":
        print("%-10s %6s %6s  %-12s %s" % ("id", "rounds", "bytes", "generic", "target"))
        for r, n in COLLISION:
            print("%-10s %6d %6d  2^%-10d -" % ("C-%d-%d" % (r, n), r, n, 4 * n))
        for r, n in PREIMAGE:
            print("%-10s %6d %6d  2^%-10d %s" % ("P-%d-%d" % (r, n), r, n, 8 * n,
                                               target(r, n).hex()))
        return
    _, cid, *hexes = sys.argv[1:]
    kind, r, n = cid.split("-")
    r, n = int(r), int(n)
    msgs = [bytes.fromhex(h) for h in hexes]
    if kind == "C":
        ok = len(msgs) == 2 and msgs[0] != msgs[1] and \
            digest(msgs[0], r, n) == digest(msgs[1], r, n)
    elif kind == "P":
        ok = len(msgs) == 1 and digest(msgs[0], r, n) == target(r, n)
    else:
        ok = False
    print("VALID" if ok else "INVALID", cid)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
