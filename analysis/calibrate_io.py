"""Inside-out calibration: RAM-1024 and BLAKE2b permutations both measured
with full-state differences in both directions (like-for-like with the
published BLAKE2b attacks, which are inside-out boomerangs).

    python3 analysis/calibrate_io.py   (after perm_attack.py v3, calibrate.py)
"""

import ctypes
import json
import math
import os
import subprocess

import numpy as np

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _budget import out as out_path, src  # noqa: E402
LIB = os.path.join(ROOT, "build", "b2perm.dylib")
if not os.path.exists(LIB):
    subprocess.check_call(["cc", "-O3", "-std=c11", "-fPIC", "-shared", "-o", LIB,
                           os.path.join(ROOT, "csrc", "b2perm_lab.c")])
L = ctypes.CDLL(LIB)
U = ctypes.POINTER(ctypes.c_uint32)
L.b2_sac.argtypes = [ctypes.c_int] * 3 + [U, ctypes.c_uint64]
N = 300


def b2_reach(d):
    for n in range(1, 16):
        c = np.zeros(1024 * 1024, np.uint32)
        L.b2_sac(n, d, N, c.ctypes.data_as(U), 100 + n)
        if np.abs(c / N - 0.5).max() / (0.5 / math.sqrt(N)) < 6.0:
            return n - 1
    return 15


def main():
    assert L.b2_selftest() == 0
    f, b = b2_reach(1), b2_reach(-1)
    b2_io = (f + b) / 2  # half-rounds -> rounds
    ram = json.load(open(src("perm_attack_v3.json")))
    ram_io = ram["inside_out_reach_rounds"]
    mult = 8.5 / b2_io
    est = mult * ram_io
    fwd = json.load(open(src("calibration.json")))
    out = {
        "blake2b_perm_forward_half_rounds": f,
        "blake2b_perm_backward_half_rounds": b,
        "blake2b_inside_out_rounds": b2_io,
        "ram_inside_out_rounds": ram_io,
        "multiplier": round(mult, 2),
        "ram_estimated_expert_reach": round(est, 2),
        "ram_margin_inside_out": round(64 / est, 2),
        "ram_margin_forward_only": fwd["ram_margin"],
        "ram_margin_headline": round(min(64 / est, fwd["ram_margin"]), 2),
    }
    print(json.dumps(out, indent=1))
    with open(out_path("calibration_io.json"), "w") as fo:
        json.dump(out, fo, indent=1)


if __name__ == "__main__":
    main()
