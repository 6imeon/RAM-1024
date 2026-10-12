"""Design exploration: diffusion reach of permutation variants, both ways.

    python3 analysis/explore_variants.py
"""
import ctypes
import json
import math
import os
import sys

import numpy as np

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _budget import out as out_path  # noqa: E402
sys.path.insert(0, os.path.join(ROOT, "tools"))
from gen_constants import pi_fraction_words  # noqa: E402

sys.path.insert(0, ROOT)
from ramhash import _libpath  # noqa: E402
L = _libpath.load("ramlab")
U32P = ctypes.POINTER(ctypes.c_uint32)
L.perm_sac.argtypes = [ctypes.c_int] * 6 + [U32P, ctypes.c_uint64]
L.perm_colshift.argtypes = [ctypes.c_int] * 5 + [ctypes.c_uint64]
L.perm_colshift.restype = ctypes.c_double
w = pi_fraction_words(2048)
L.perm_set_rc_all((ctypes.c_uint64 * 2048)(*w))
N = 300
NAMES = {0: "v2 baseline", 32: "diagonal constants (free)",
         32 | 16: "diagonal constants + rho rows 2-3 after chi",
         32 | 16 | 64: "diagonal constants + rho rows 2-3 mid-round",
         32 | 8 | 64: "diagonal constants + rho all words mid-round",
         1 | 8 | 64: "all-row constants + rho all words mid-round"}


def reach(d):
    for n in range(1, 16):
        c = np.zeros(2048 * 2048, np.uint32)
        L.perm_sac(0, n, d, N, 0, 32, c.ctypes.data_as(U32P), 1000 + n)
        z = np.abs(c / N - 0.5).max() / (0.5 / math.sqrt(N))
        if z < 6.0:
            return n - 1
    return 15


def colshift_reach():
    r = 0
    for n in range(1, 13):
        for d in (1, -1):
            if max(abs(L.perm_colshift(0, n, d, 20000, k, 5 + k)) for k in (1, 2, 3, 4)) > 6:
                r = max(r, n)
    return r


res = []
for v, name in NAMES.items():
    L.perm_set_variant(v)
    f, b = reach(1), reach(-1)
    row = {"variant": v, "name": name, "fwd": f, "bwd": b, "inside_out": f + b,
           "colshift": colshift_reach()}
    print(row, flush=True)
    res.append(row)
L.perm_set_variant(0)
json.dump(res, open(out_path("variants.json"), "w"), indent=1)
