"""Measured calibration of the pessimistic security model.

For each standard, "expert multiplier" = (best published attack reach) /
(reach of our lab attacks). The worst (largest) multiplier, applied to
RAM-1024's measured lab reach, estimates how far expert-grade cryptanalysis
might get into RAM-1024. BLAKE2b is measured at half-round resolution, RAM
at step resolution (redteam.json), so the multiplier isn't inflated by
coarse rounding.

    python3 analysis/calibrate.py      (after run_all.py and redteam.py)
"""

import json
import math
import os
import sys
import time

import numpy as np

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _budget import out as out_path, src  # noqa: E402
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ramhash import lab  # noqa: E402
from neural import distinguish  # noqa: E402
from redteam import best_delta, multi_pair, sac_z  # noqa: E402

PUBLISHED = {"SHA-256": 39, "SHA3-512": 6, "BLAKE2b": 8.5}


def attacked(alg, r):
    z = sac_z(alg, r)
    d = best_delta(alg, r)
    _, z1 = distinguish(alg, r, d, 1_000_000, 200_000, 4, seed=r)
    _, zm = multi_pair(alg, r, d)
    cube = None
    for k in range(1, 19):
        hits = [lab.cube(alg, r, k, 16, s, 900 + 10 * k + s, 5) for s in range(3)]
        if any(hits) and any(lab.cube(alg, r, k, 64, s, 900 + 10 * k + s, 77)
                             for s in range(3) if hits[s]):
            cube = k
            break
    row = {"sac_zmax": round(z, 1), "neural_z": round(z1, 1),
           "multipair_z": round(zm, 1), "cube_dim": cube}
    row["broken"] = z >= 5.5 or z1 > 5 or zm > 5 or cube is not None
    return row


def main():
    res = json.load(open(src("results.json")))
    rt = json.load(open(src("redteam.json")))
    halves = []
    for h in range(2, 7):
        row = attacked(lab.BLAKE2B_HALF, h)
        row.update(half_rounds=h, rounds=h / 2)
        print(time.strftime("%H:%M:%S"), "BLAKE2b", row, flush=True)
        halves.append(row)
    blake_reach = max(r["rounds"] for r in halves if r["broken"])
    reach = {
        "SHA-256": res["algs"]["SHA-256"]["max_round_broken_in_lab"],
        "SHA3-512": res["algs"]["SHA3-512"]["max_round_broken_in_lab"],
        "BLAKE2b": blake_reach,
    }
    mult = {n: PUBLISHED[n] / reach[n] for n in PUBLISHED}
    worst = max(mult, key=mult.get)
    ram_reach = max(r["step"] for r in rt["ram_steps"] if r["broken"]) / 3
    ram_rounds = res["algs"]["RAM-1024"]["full_rounds"]
    est = mult[worst] * ram_reach
    out = {
        "blake2b_half_rounds": halves,
        "lab_reach_rounds": {**reach, "RAM-1024": round(ram_reach, 3)},
        "published_reach_rounds": PUBLISHED,
        "expert_multiplier": {n: round(m, 2) for n, m in mult.items()},
        "worst_multiplier_from": worst,
        "ram_estimated_expert_reach": round(est, 2),
        "ram_margin": round(ram_rounds / est, 2),
        "standard_margins": {n: round(res["algs"][n]["full_rounds"] / PUBLISHED[n], 2)
                             for n in PUBLISHED},
    }
    print(json.dumps(out, indent=1))
    with open(out_path("calibration.json"), "w") as f:
        json.dump(out, f, indent=1)


if __name__ == "__main__":
    main()
