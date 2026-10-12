"""Red team round 2: stronger, finer-grained attacks.

1. Step-level resolution on RAM-1024 (3 steps per round) - exactly where
   does resistance start?
2. Multi-pair neural distinguisher (Gohr amplification: k pairs per sample)
   against every algorithm at the first round the basic attacker failed.
3. Large cubes (2^20..2^22) at the same rounds.

    python3 analysis/redteam.py
"""

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
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ramhash import lab  # noqa: E402
from neural import train_mlp, distinguish  # noqa: E402

POOL = ThreadPoolExecutor(os.cpu_count())
K_PAIRS = 4


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def best_delta(alg, r):
    p = lab.sac(alg, r, 1000, seed=r)
    return int(np.argmax(np.abs(p - 0.5).sum(1)))


def sac_z(alg, r, n=2000):
    p = lab.sac(alg, r, n, seed=r + 11)
    return float(np.abs(p - 0.5).max() / (0.5 / math.sqrt(n)))


def multi_pair(alg, r, d, n_train=500_000, n_test=100_000):
    Xtr, ytr = lab.pairs_multi(alg, r, d, K_PAIRS, n_train, seed=5)
    Xte, yte = lab.pairs_multi(alg, r, d, K_PAIRS, n_test, seed=6)
    acc = train_mlp(Xtr, ytr, Xte, yte, hidden=(512, 256), epochs=5)
    return acc, (acc - 0.5) / math.sqrt(0.25 / n_test)


def big_cube(alg, r, ks=(20, 21, 22), trials=16):
    jobs = [(k, st, sd) for k in ks for st in range(3) for sd in range(2)]

    def run(j):
        k, st, sd = j
        cs = 7000 * k + 10 * st + sd + 3
        if lab.cube(alg, r, k, trials, st, cs, 41) == 0:
            return None
        c = lab.cube(alg, r, k, 64, st, cs, 4242)
        return (k, st, c) if c else None

    hits = [h for h in POOL.map(run, jobs) if h]
    return min(hits) if hits else None


def main():
    out = {"k_pairs": K_PAIRS}

    # 1. step-level on RAM
    steps = []
    for st in range(3, 10):
        z = sac_z(lab.RAM_STEPS, st)
        d = best_delta(lab.RAM_STEPS, st)
        acc1, z1 = distinguish(lab.RAM_STEPS, st, d, 1_000_000, 200_000, 4, seed=st)
        accm, zm = multi_pair(lab.RAM_STEPS, st, d)
        cube = None
        for k in range(1, 19):
            hits = [lab.cube(lab.RAM_STEPS, st, k, 16, s, 900 + 10 * k + s, 5) for s in range(3)]
            if any(hits):
                conf = [lab.cube(lab.RAM_STEPS, st, k, 64, s, 900 + 10 * k + s, 77)
                        for s in range(3) if hits[s]]
                if any(conf):
                    cube = k
                    break
        row = {"step": st, "rounds": round(st / 3, 2), "sac_zmax": round(z, 1),
               "sac_pass": z < 5.5, "neural_z": round(z1, 1),
               "multipair_z": round(zm, 1), "cube_dim": cube}
        row["broken"] = (not row["sac_pass"]) or z1 > 5 or zm > 5 or cube is not None
        log("steps", row)
        steps.append(row)
    out["ram_steps"] = steps
    out["ram_first_unbroken_step"] = next(
        (r["step"] for r in steps if not r["broken"]), None)

    # 2 + 3. strongest attacks at each algorithm's first unbroken round
    targets = [(lab.SHA256, 23), (lab.SHA3_512, 4), (lab.SHA3_512, 5),
               (lab.BLAKE2B, 2), (lab.RAM1024, 2)]
    rows = []
    for alg, r in targets:
        d = best_delta(alg, r)
        acc, z = multi_pair(alg, r, d)
        cube = big_cube(alg, r)
        row = {"alg": lab.NAMES[alg], "round": r, "multipair_acc": round(acc, 4),
               "multipair_z": round(z, 1),
               "big_cube": None if cube is None else
               {"k": cube[0], "strategy": cube[1], "const_bits": cube[2]}}
        row["broken"] = z > 5 or cube is not None
        log("strong", row)
        rows.append(row)
    out["strong_attacks"] = rows
    with open(out_path("redteam.json"), "w") as f:
        json.dump(out, f, indent=1)
    log("done")


if __name__ == "__main__":
    main()
