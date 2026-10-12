"""Robustness of the margin calibration.

1. Re-measures the break boundaries (BLAKE2b half-rounds 3/4, RAM-1024
   steps 4/5) with fresh seeds, so the multiplier isn't one lucky sample.
2. Sensitivity: RAM-1024's margin under every calibration model, including
   the most pessimistic mix of resolutions.

    python3 analysis/robustness.py    (after calibrate.py)
"""

import json
import os
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _budget import out as out_path, src  # noqa: E402
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ramhash import lab  # noqa: E402
from neural import distinguish  # noqa: E402
from redteam import best_delta, sac_z  # noqa: E402

SEEDS = (101, 202, 303)


def zs(alg, r, seed):
    d = best_delta(alg, r)
    _, z = distinguish(alg, r, d, 1_000_000, 200_000, 4, seed=seed)
    return z


def main():
    cal = json.load(open(src("calibration.json")))
    boundary = []
    for name, alg, broken_at, safe_at in (("BLAKE2b half-rounds", lab.BLAKE2B_HALF, 3, 4),
                                          ("RAM-1024 steps", lab.RAM_STEPS, 4, 5)):
        for seed in SEEDS:
            row = {"target": name, "seed": seed,
                   "z_at_%d" % broken_at: round(zs(alg, broken_at, seed), 1),
                   "z_at_%d" % safe_at: round(zs(alg, safe_at, seed), 1),
                   "sac_z_at_%d" % safe_at: round(sac_z(alg, safe_at), 1)}
            print(row, flush=True)
            boundary.append(row)
    stable = all(r.get("z_at_3", r.get("z_at_4")) > 5 for r in boundary) and \
        all(abs(r.get("z_at_4" if "BLAKE2b" in r["target"] else "z_at_5")) < 5
            for r in boundary)

    # Symmetric sensitivity: every model is applied to all four designs.
    # A design is "broken" under a model if estimated reach >= its rounds.
    totals = {"SHA-256": 64, "SHA3-512": 24, "BLAKE2b": 12, "RAM-1024": 64}
    lab_r = dict(cal["lab_reach_rounds"])
    published = cal["published_reach_rounds"]
    worst = max(cal["expert_multiplier"].values())
    coarse_b = 8.5 / 1.0  # BLAKE2b multiplier at round resolution
    models = {
        "Published reach (standards); measured multiplier × lab reach (RAM)":
            lambda n: published.get(n, cal["ram_estimated_expert_reach"]),
        "Worst measured multiplier × lab reach, for every design":
            lambda n: worst * lab_r[n],
        "Coarse BLAKE2b multiplier (8.5×) × lab reach, for every design":
            lambda n: coarse_b * lab_r[n],
        "Stress: worst multiplier × (lab reach + 1 round), for every design":
            lambda n: worst * (lab_r[n] + 1),
    }
    sens = []
    for m, f in models.items():
        row = {"model": m}
        for n, tot in totals.items():
            reach = f(n)
            row[n] = round(tot / reach, 2) if reach < tot else 0.0  # 0 = broken
        best_std = max(row[n] for n in totals if n != "RAM-1024")
        row["ram_leads"] = row["RAM-1024"] > best_std
        sens.append(row)
        print(row)
    out = {"boundary_repeats": boundary, "boundaries_stable": stable,
           "sensitivity": sens,
           "ram_leads_every_model": all(r["ram_leads"] for r in sens)}
    with open(out_path("robustness.json"), "w") as f:
        json.dump(out, f, indent=1)
    print("stable:", stable, " RAM leads every model:", out["ram_leads_every_model"])


if __name__ == "__main__":
    main()
