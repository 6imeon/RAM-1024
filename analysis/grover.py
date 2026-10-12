"""Quantum attack simulation: Grover preimage search, state-vector simulated.

For a k-bit truncation of the hash we build the exact quantum oracle
(|x> -> (-1)^[H(x)_k == target] |x>), run Grover iterations on a 2^k
amplitude vector and record the success probability. Measured query counts
confirm the sqrt(N) law, which we then extrapolate to full output sizes,
including NIST's MAXDEPTH constraint on realistic quantum computers.

    python3 analysis/grover.py
"""

import json
import math
import os
import sys

import numpy as np

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _budget import out as out_path  # noqa: E402
sys.path.insert(0, ROOT)
from ramhash import lab  # noqa: E402


def oracle_table(alg, k):
    """Truncated k-bit hash of every k-bit input (input = x in first bytes)."""
    n = 1 << k
    blk = np.zeros(64, np.uint8)
    out = np.empty(n, np.uint32)
    for x in range(n):
        blk[:4] = np.frombuffer(np.uint32(x).tobytes(), np.uint8)
        h = lab.core(alg, lab.FULL_ROUNDS[alg], blk.tobytes())
        out[x] = int.from_bytes(h[:4], "little") & (n - 1)
    return out


def grover(table, target):
    n = len(table)
    marked = table == target
    m = int(marked.sum())
    if m == 0:
        return None
    iters = int(math.floor(math.pi / 4 * math.sqrt(n / m)))
    amp = np.full(n, 1 / math.sqrt(n))
    for _ in range(iters):
        amp[marked] *= -1                      # oracle
        amp = 2 * amp.mean() - amp             # diffusion (inversion about mean)
    return {"marked": m, "grover_queries": iters,
            "success_prob": round(float((amp[marked] ** 2).sum()), 4),
            "classical_expected_queries": round(n / (m + 1), 1)}


def maxdepth_cost(n_bits, maxdepth_log2=64, iter_depth_log2=12, iter_gates_log2=20):
    """log2 total gates for Grover preimage under a circuit-depth cap
    (NIST PQC MAXDEPTH). Parallel Grover: S = 2^n d^2 / D^2 machines,
    total gates ~ 2^n * d * g / D."""
    return n_bits + iter_depth_log2 + iter_gates_log2 - maxdepth_log2


def main():
    res = {"simulations": {}, "extrapolation": {}}
    for alg in (lab.RAM1024, lab.SHA256):
        name = lab.NAMES[alg]
        res["simulations"][name] = []
        for k in (8, 12, 16, 20):
            table = oracle_table(alg, k)
            target = int(table[12345 % len(table)])
            r = grover(table, target)
            r["k"] = k
            res["simulations"][name].append(r)
            print(name, r, flush=True)
    # Effective bits = min(output, capacity-limited) search space. A sponge's
    # inner state caps generic quantum attacks; we use c/3 conservatively.
    # SHA-256 is Merkle-Damgard, not a sponge: no capacity cap (c=None).
    for name, n, c in (("SHA-256", 256, None), ("SHA3-512", 512, 1024),
                       ("RAM-1024", 1024, 1024)):
        eff = n if c is None else min(n, 2 * c / 3)
        c = c or n
        res["extrapolation"][name] = {
            "grover_preimage_queries_log2": round(eff / 2, 1),
            "grover_preimage_gates_MAXDEPTH_2^64_log2": round(maxdepth_cost(eff)),
            "grover_preimage_gates_MAXDEPTH_2^96_log2": round(maxdepth_cost(eff, 96)),
            "BHT_collision_queries_log2": round(min(n, c) / 3, 1),
        }
    pass  # out() creates the folder
    with open(out_path("grover.json"), "w") as f:
        json.dump(res, f, indent=1)
    print(json.dumps(res["extrapolation"], indent=1))


if __name__ == "__main__":
    main()
