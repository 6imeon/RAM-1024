"""Cryptanalyst pass 1 on the RAM-1024 permutation (full state, both ways).

  * full-state SAC forward/backward per step -> inside-out reach
  * which input words diffuse slowest (incl. the parameter block 28-31)
  * linear bit-to-bit correlations forward/backward
  * column-shift (translation) symmetry

    python3 analysis/perm_attack.py [tag]
"""

import ctypes
import json
import math
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
U32P = ctypes.POINTER(ctypes.c_uint32)
L.perm_sac.argtypes = [ctypes.c_int] * 6 + [U32P, ctypes.c_uint64]
L.perm_linear.argtypes = [ctypes.c_int] * 3 + [ctypes.c_long, U32P, ctypes.c_uint64]
L.perm_colshift.argtypes = [ctypes.c_int] * 5 + [ctypes.c_uint64]
L.perm_colshift.restype = ctypes.c_double
POOL = ThreadPoolExecutor(os.cpu_count())
STEPS = range(1, 10)
SAC_N = 300
LIN_N = 1 << 14


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def sac(n, d, first=0, seed=0):
    c = np.zeros(2048 * 2048, np.uint32)
    L.perm_sac(first, n, d, SAC_N, 0, 32, c.ctypes.data_as(U32P), 1000 + n + 7919 * seed)
    p = c.reshape(2048, 2048) / SAC_N
    z = np.abs(p - 0.5) / (0.5 / math.sqrt(SAC_N))
    word_z = z.reshape(32, 64, 2048).max(axis=(1, 2))   # per input word
    return {"zmax": round(float(z.max()), 1),
            "never_flips": round(float((p == 0).mean()), 4),
            "full_diffusion": bool(z.max() < 6.0),
            "slowest_input_words": [int(w) for w in np.argsort(-word_z)[:4]],
            "param_block_zmax": round(float(word_z[28:32].max()), 1)}


def linear(n, d, seed=0):
    c = np.zeros(2048 * 2048, np.uint32)
    L.perm_linear(0, n, d, LIN_N, c.ctypes.data_as(U32P), 77 + n + 7919 * seed)
    corr = np.abs(2 * c / LIN_N - 1.0)
    z = corr * math.sqrt(LIN_N)
    return {"max_corr": round(float(corr.max()), 4), "zmax": round(float(z.max()), 1),
            "biased": bool(z.max() > 6.0)}


def main():
    tag = sys.argv[1] if len(sys.argv) > 1 else "v2"
    out = {"sac_samples": SAC_N, "linear_samples": LIN_N}
    for name, d in (("forward", 1), ("backward", -1)):
        rows = list(POOL.map(lambda n: dict(step=n, **sac(n, d)), STEPS))
        # A flagged step only counts if an independent sample confirms it
        # (4M cells per test: the max |z| of pure noise is ~5.3 +- 0.3).
        for r in rows:
            if not r["full_diffusion"]:
                r["confirm_zmax"] = sac(r["step"], d, seed=1)["zmax"]
                r["full_diffusion"] = r["confirm_zmax"] < 6.0
            log(name, "SAC", r)
        out["sac_" + name] = rows
        out[name + "_reach_steps"] = max([r["step"] for r in rows if not r["full_diffusion"]] or [0])
        lin = list(POOL.map(lambda n: dict(step=n, **linear(n, d)), STEPS))
        for r in lin:
            if r["biased"]:
                r["confirm_zmax"] = linear(r["step"], d, seed=1)["zmax"]
                r["biased"] = r["confirm_zmax"] > 6.0
            log(name, "linear", r)
        out["linear_" + name] = lin
        out[name + "_linear_reach_steps"] = max([r["step"] for r in lin if r["biased"]] or [0])
    cs = []
    for n in STEPS:
        for d in (1, -1):
            zs = [L.perm_colshift(0, n, d, 20000, k, 5 + k) for k in (1, 2, 3, 4)]
            cs.append({"step": n, "dir": d, "max_abs_z": round(max(map(abs, zs)), 1)})
    out["colshift"] = cs
    out["colshift_reach_steps"] = max([c["step"] for c in cs if c["max_abs_z"] > 6] or [0])
    log("colshift reach", out["colshift_reach_steps"], cs[:6])
    fw = max(out["forward_reach_steps"], out["forward_linear_reach_steps"])
    bw = max(out["backward_reach_steps"], out["backward_linear_reach_steps"])
    out["inside_out_reach_steps"] = fw + bw
    out["inside_out_reach_rounds"] = round((fw + bw) / 3, 2)
    log("inside-out reach: %d fwd + %d bwd steps = %.2f rounds" % (fw, bw, (fw + bw) / 3))
    with open(out_path("perm_attack_%s.json" % tag), "w") as f:
        json.dump(out, f, indent=1)


if __name__ == "__main__":
    main()
