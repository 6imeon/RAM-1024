"""Rotational cryptanalysis sweep (targets ARX designs).

    python3 analysis/rotational.py
"""

import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _budget import out as out_path  # noqa: E402
sys.path.insert(0, ROOT)
from ramhash import lab  # noqa: E402

N = 200_000
ROTS = (1, 8, 32)
ROUNDS = {lab.SHA256: range(16, 25), lab.SHA3_512: range(1, 7),
          lab.BLAKE2B: range(1, 6), lab.RAM1024: range(1, 7)}


def main():
    jobs = [(a, r, k) for a, rs in ROUNDS.items() for r in rs for k in ROTS]
    with ThreadPoolExecutor(os.cpu_count()) as ex:
        zs = list(ex.map(lambda j: lab.rotational(j[0], j[1], N, j[2], seed=j[1]), jobs))
    res = {}
    for (a, r, k), z in zip(jobs, zs):
        row = res.setdefault(lab.NAMES[a], {}).setdefault(str(r), {})
        row["rot%d" % k] = round(z, 2)
    for name, rows in res.items():
        broken = [int(r) for r, v in rows.items() if max(map(abs, v.values())) > 5]
        rows["max_round_broken"] = max(broken) if broken else None
        print(name, "rotational distinguisher up to round", rows["max_round_broken"])
    with open(out_path("rotational.json"), "w") as f:
        json.dump(res, f, indent=1)


if __name__ == "__main__":
    main()
