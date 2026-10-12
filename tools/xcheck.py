"""Python-side conformance on the current platform (no numpy needed):
the C library via ctypes and the pure-Python reference must both match
tests/kat.txt.   python3 tools/xcheck.py [max_ref_len]"""

import os
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
from gen_kat import key, msg  # noqa: E402
from ramhash import _fast, ram1024  # noqa: E402


def main():
    pure = "--pure" in sys.argv  # no C library expected (pip without compiler)
    args = [a for a in sys.argv[1:] if a != "--pure"]
    max_ref = int(args[0]) if args else 1 << 30
    bad = n = ref_n = 0
    for line in open(os.path.join(ROOT, "tests", "kat.txt")):
        if line.startswith("#"):
            continue
        mode, rounds, outlen, kl, ln, want = line.split()
        mode, rounds, outlen, kl, ln = map(int, (mode, rounds, outlen, kl, ln))
        want = bytes.fromhex(want)
        m, k = msg(ln), key(kl)
        got = []
        if pure:
            if ln <= max_ref:
                got.append(ram1024.ram_hash(m, outlen, mode, rounds, k, research=True))
                ref_n += 1
                if mode == ram1024.MODE_HASH and rounds == 64 and outlen >= 32:
                    got.append(_fast.Ram1024(outlen, mode, rounds, k).digest()
                               if not m else ram1024.ram_hash(m, outlen))
            bad += sum(g != want for g in got)
            n += 1
            continue
        try:
            ram1024.Ram1024(outlen, mode, rounds, k)
            production = True
        except ValueError:  # research-only vector: production must refuse it
            production = False
            try:
                _fast.Ram1024(outlen, mode, rounds, k)
                bad += 1
            except ValueError:
                pass
        if production:
            h = _fast.Ram1024(outlen, mode, rounds, k)
            h.update(m)
            got.append(h.digest())
            if mode == ram1024.MODE_HASH:
                got.append(_fast.hash_parallel(m, outlen, rounds))
        if ln <= max_ref:
            got.append(ram1024.ram_hash(m, outlen, mode, rounds, k, research=True))
            ref_n += 1
        bad += sum(g != want for g in got)
        n += 1
    print("python: C library %s, %d vectors (%d also via pure Python), %d mismatches"
          % ("loaded" if _fast.FAST else "MISSING", n, ref_n, bad))
    sys.exit(1 if bad or (_fast.FAST == pure) else 0)


if __name__ == "__main__":
    main()
