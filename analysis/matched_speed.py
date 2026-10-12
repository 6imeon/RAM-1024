"""Speed at matched security: run RAM-1024 with just enough rounds to equal
each standard's security margin, and compare throughput like-for-like.

Pessimistic model: expert cryptanalysis of RAM reaches EXPERT_REACH rounds
(what it achieved on BLAKE2b, which shares RAM's G function). A competitor
with margin M is matched by ceil(M * EXPERT_REACH) RAM rounds.

    python3 analysis/matched_speed.py
"""

import hashlib
import json
import math
import os
import sys
import time

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _budget import out as out_path, src  # noqa: E402
sys.path.insert(0, ROOT)
from ramhash import _fast, ram1024  # noqa: E402

def _expert_reach():
    """Measured calibration (calibrate.py) if available, else the BLAKE2b
    literature figure."""
    p = src("calibration.json")
    if os.path.exists(p):
        with open(p) as f:
            return json.load(f)["ram_estimated_expert_reach"]
    return 8.5


EXPERT_REACH = _expert_reach()
COMPETITORS = {  # name: (hashlib name, total rounds, best published reach)
    "SHA-256": ("sha256", 64, 39),
    "SHA3-512": ("sha3_512", 24, 6),
    "BLAKE2b": ("blake2b", 12, 8.5),
}


def best(f, n=3):
    ts = []
    for _ in range(n):
        t = time.perf_counter()
        f()
        ts.append(time.perf_counter() - t)
    return min(ts)


def main():
    data = os.urandom(256 << 20)
    rows = []
    for name, (hl, total, reach) in COMPETITORS.items():
        margin = total / reach
        r = math.ceil(margin * EXPERT_REACH)
        std = len(data) / best(lambda: hashlib.new(hl, data).digest()) / 1e6
        one = len(data) / best(lambda: _fast.hash_parallel(data, rounds=r, threads=1, research=True)) / 1e6
        allc = len(data) / best(lambda: _fast.hash_parallel(data, rounds=r, research=True)) / 1e6
        gpu = len(data) / best(lambda: _fast.hash_parallel(data, rounds=r, gpu=True, research=True)) / 1e6
        rows.append({"competitor": name, "competitor_margin": round(margin, 2),
                     "ram_rounds_for_equal_margin": r,
                     "competitor_mb_s": round(std), "ram_1core_mb_s": round(one),
                     "ram_allcores_mb_s": round(allc), "ram_cpu_gpu_mb_s": round(gpu)})
        print(rows[-1], flush=True)
    full = {"rounds": ram1024.ROUNDS,
            "margin": round(ram1024.ROUNDS / EXPERT_REACH, 2),
            "ram_1core_mb_s": round(len(data) / best(
                lambda: _fast.hash_parallel(data, threads=1)) / 1e6),
            "ram_allcores_mb_s": round(len(data) / best(
                lambda: _fast.hash_parallel(data)) / 1e6),
            "ram_cpu_gpu_mb_s": round(len(data) / best(
                lambda: _fast.hash_parallel(data, gpu=True)) / 1e6)}
    print(full)
    with open(out_path("matched_speed.json"), "w") as f:
        json.dump({"expert_reach_rounds": EXPERT_REACH, "rows": rows,
                   "full": full}, f, indent=1)


if __name__ == "__main__":
    main()
