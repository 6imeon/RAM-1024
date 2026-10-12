"""AI attacker on the permutation in its strongest setting: full-state
differences, both directions, input bit chosen where SAC is most biased.

    python3 analysis/perm_neural.py [tag]
"""
import ctypes
import json
import math
import os
import subprocess
import sys

import numpy as np

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _budget import out as out_path  # noqa: E402
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from neural import train_mlp  # noqa: E402

LIB = os.path.join(ROOT, "build", "permnn.so")
if not os.path.exists(LIB):
    os.makedirs(os.path.dirname(LIB), exist_ok=True)
    subprocess.check_call(["cc", "-O3", "-std=gnu11", "-fPIC", "-shared", "-DRAM_RESEARCH",
                           "-I", os.path.join(ROOT, "csrc"), "-o", LIB] +
                          [os.path.join(ROOT, "csrc", f) for f in
                           ("perm_nn.c", "perm_lab.c", "ram1024.c")] + ["-lpthread"])
L = ctypes.CDLL(LIB)
U8 = ctypes.POINTER(ctypes.c_uint8)
U32 = ctypes.POINTER(ctypes.c_uint32)
L.perm_pairs.argtypes = [ctypes.c_int] * 4 + [U8, U8, ctypes.c_uint64]
L.perm_sac.argtypes = [ctypes.c_int] * 6 + [U32, ctypes.c_uint64]


def best_bits(n, d, k=3):
    c = np.zeros(2048 * 2048, np.uint32)
    L.perm_sac(0, n, d, 200, 0, 32, c.ctypes.data_as(U32), 3)
    bias = np.abs(c.reshape(2048, 2048) / 200 - 0.5).sum(1)
    return [int(b) for b in np.argsort(-bias)[:k]]


def attack(n, d, bit, ntr=600_000, nte=150_000):
    X = np.zeros((ntr, 2048), np.uint8); y = np.zeros(ntr, np.uint8)
    L.perm_pairs(n, d, bit, ntr, X.ctypes.data_as(U8), y.ctypes.data_as(U8), 1)
    Xt = np.zeros((nte, 2048), np.uint8); yt = np.zeros(nte, np.uint8)
    L.perm_pairs(n, d, bit, nte, Xt.ctypes.data_as(U8), yt.ctypes.data_as(U8), 2)
    acc = train_mlp(X, y, Xt, yt, hidden=(512, 256), epochs=4)
    return acc, (acc - 0.5) / math.sqrt(0.25 / nte)


def main():
    tag = sys.argv[1] if len(sys.argv) > 1 else "v3"
    out = []
    for d, steps in ((1, (4, 5, 6)), (-1, (6, 7, 8))):
        for n in steps:
            best = None
            for bit in best_bits(n, d):
                acc, z = attack(n, d, bit)
                if best is None or z > best["z"]:
                    best = {"dir": d, "steps": n, "bit": bit, "acc": round(acc, 4), "z": round(z, 1)}
            best["broken"] = best["z"] > 5
            print(best, flush=True)
            out.append(best)
    reach = {d: max([r["steps"] for r in out if r["dir"] == d and r["broken"]] or [0])
             for d in (1, -1)}
    res = {"rows": out, "forward_reach": reach[1], "backward_reach": reach[-1],
           "inside_out_steps": reach[1] + reach[-1]}
    print(res["forward_reach"], res["backward_reach"], res["inside_out_steps"])
    json.dump(res, open(out_path("perm_neural_%s.json" % tag), "w"), indent=1)


if __name__ == "__main__":
    main()
