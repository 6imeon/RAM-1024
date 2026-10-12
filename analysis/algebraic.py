"""Cryptanalyst pass 2: algebraic structure of the RAM-1024 permutation.

(A) Inside-out zero-sum: for each direction, the largest step count at
    which some cube (dim <= KMAX) still gives a constant sum in some output
    bit. Forward + backward = zero-sum distinguisher reach.
(B) Exact affine output bits: GF(2) elimination finds output bits that are
    exactly affine functions of the 2048 input bits.

    python3 analysis/algebraic.py [tag]
"""

import ctypes
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import numpy as np

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _budget import out as out_path  # noqa: E402
sys.path.insert(0, ROOT)
from ramhash import _libpath  # noqa: E402
L = _libpath.load("ramlab")
L.perm_cube.argtypes = [ctypes.c_int] * 6 + [ctypes.c_uint64] * 2
U64P = ctypes.POINTER(ctypes.c_uint64)
L.perm_samples.argtypes = [ctypes.c_int] * 4 + [U64P, U64P, ctypes.c_uint64]
POOL = ThreadPoolExecutor(os.cpu_count())
KMAX = 16


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def zero_sum(n, d):
    """Smallest cube dimension giving a confirmed constant output bit."""
    jobs = [(k, st, sd) for k in range(1, KMAX + 1) for st in range(4) for sd in range(2)]

    def run(j):
        k, st, sd = j
        cs = 31 * k + 7 * st + sd + 1
        if L.perm_cube(0, n, d, k, 12, st, cs, 11) == 0:
            return None
        c = L.perm_cube(0, n, d, k, 48, st, cs, 999)
        return (k, st, c) if c else None

    hits = [h for h in POOL.map(run, jobs) if h]
    return min(hits) if hits else None


def affine_bits(n, d, samples=2300):
    xs = np.zeros(samples * 32, np.uint64)
    ys = np.zeros(samples * 32, np.uint64)
    L.perm_samples(0, n, d, samples, xs.ctypes.data_as(U64P), ys.ctypes.data_as(U64P), 5)
    xs, ys = xs.reshape(samples, 32), ys.reshape(samples, 32)
    rows = []
    for t in range(samples):  # row = [x bits | 1 | y bits] as one big int
        xv = int.from_bytes(xs[t].tobytes(), "little")
        yv = int.from_bytes(ys[t].tobytes(), "little")
        rows.append(xv | (1 << 2048) | (yv << 2049))
    xmask = (1 << 2049) - 1
    pivot_rows = []
    for col in range(2049):
        bit = 1 << col
        for i, r in enumerate(rows):
            if r & bit:
                p = rows.pop(i)
                rows = [r ^ p if r & bit else r for r in rows]
                pivot_rows.append(p)
                break
    # Remaining rows have zero x-part; an output bit is affine iff it is 0
    # in all of them.
    bad = 0
    for r in rows:
        assert r & xmask == 0
        bad |= r >> 2049
    return 2048 - bin(bad).count("1"), len(rows)


def main():
    tag = sys.argv[1] if len(sys.argv) > 1 else "v3"
    out = {"kmax": KMAX, "zero_sum": {}, "affine": {}}
    for name, d in (("forward", 1), ("backward", -1)):
        reach = 0
        for n in range(1, 10):
            h = zero_sum(n, d)
            log(name, "zero-sum steps=%d" % n, h)
            out["zero_sum"]["%s_%d" % (name, n)] = h
            if h:
                reach = n
            elif n > reach + 1:
                break
        out["zero_sum"][name + "_reach"] = reach
        areach = 0
        for n in range(1, 7):
            k, extra = affine_bits(n, d)
            log(name, "affine bits after %d steps: %d (redundant eqs %d)" % (n, k, extra))
            out["affine"]["%s_%d" % (name, n)] = k
            if k:
                areach = n
            else:
                break
        out["affine"][name + "_reach"] = areach
    zs = out["zero_sum"]
    out["zero_sum_inside_out_steps"] = zs["forward_reach"] + zs["backward_reach"]
    log("zero-sum inside-out reach:", out["zero_sum_inside_out_steps"], "steps")
    with open(out_path("algebraic_%s.json" % tag), "w") as f:
        json.dump(out, f, indent=1)


if __name__ == "__main__":
    main()
