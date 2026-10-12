"""Known-answer tests from the pure-Python reference (ramhash/ram1024.py).

    python3 tools/gen_kat.py > tests/kat.txt

One vector per line:  mode rounds outlen keylen msglen digest_hex
Message byte i = (i*i*7 + i*13 + 1) mod 256; key byte i = (i*31 + 0xa5) mod 256.
Every implementation, on every platform, must reproduce these exactly.
Vectors with reduced rounds or outputs below the per-mode minimum are for
research builds; production builds must reject them.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from ramhash import ram1024  # noqa: E402


def msg(n):
    return bytes((i * i * 7 + i * 13 + 1) & 0xFF for i in range(n))


def key(n):
    return bytes((i * 31 + 0xA5) & 0xFF for i in range(n))


H, X, M = ram1024.MODE_HASH, ram1024.MODE_XOF, ram1024.MODE_MAC
LENGTHS = [0, 1, 3, 127, 128, 129, 255, 256, 1000, 16383, 16384, 16385,
           32768, 32769, 3 * 16384, 5 * 16384 + 77]
CASES = [(H, 64, 128, 0, n) for n in LENGTHS]
CASES += [(H, 64, o, 0, n) for o in (1, 32, 64, 127, 129, 300) for n in (0, 200, 40000)]
CASES += [(X, 64, o, 0, n) for o in (1, 128, 129, 1000) for n in (0, 129, 40000)]
CASES += [(M, 64, 64, k, n) for k in (16, 32, 127, 128, 129, 300) for n in (0, 128, 5000)]
CASES += [(H, r, 128, 0, n) for r in (1, 2, 3, 4, 5, 7, 31, 63) for n in (0, 129, 20000)]


PW_CASES = [(32, 8, 1, 1, 0, 16), (64, 8, 1, 1, 8, 16), (40, 16, 2, 2, 3, 33),
            (32, 24, 1, 3, 100, 16), (128, 8, 3, 1, 129, 64)]


def main_pw():
    print("# RAM-Balloon known-answer tests (tools/gen_kat.py --pw)")
    print("# outlen m_kib t_cost lanes pwlen saltlen digest   (pw = msg, salt = key)")
    print("# msg byte i = (7*i*i + 13*i + 1) mod 256; key byte i = (31*i + 0xa5) mod 256")
    for outlen, m, t, p, pl, sl in PW_CASES:
        d = ram1024.pwhash(msg(pl), key(sl), outlen, m, t, p)
        print(outlen, m, t, p, pl, sl, d.hex())


def main():
    if "--pw" in sys.argv:
        return main_pw()
    print("# RAM-1024 v3 known-answer tests (tools/gen_kat.py)")
    print("# mode rounds outlen keylen msglen digest")
    print("# msg byte i = (7*i*i + 13*i + 1) mod 256; key byte i = (31*i + 0xa5) mod 256")
    print("# rounds != 64 or outlen below the minimum (hash 32, MAC 16): research builds only")
    for mode, rounds, outlen, kl, n in CASES:
        d = ram1024.ram_hash(msg(n), outlen, mode, rounds, key(kl), research=True)
        print(mode, rounds, outlen, kl, n, d.hex())


if __name__ == "__main__":
    main()
