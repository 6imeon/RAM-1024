"""Head-to-head cryptanalysis of RAM-1024 vs SHA-256, SHA3-512, BLAKE2b.

    make && python3 analysis/run_all.py [--quick]

Writes results/results.json. Every attack is run identically against every
algorithm at reduced round counts; the highest round any attack still
distinguishes from random tells us how much of each design is "eaten" and
how many rounds of security margin remain.
"""

import argparse
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
from neural import distinguish  # noqa: E402

ALGS = [lab.SHA256, lab.SHA3_512, lab.BLAKE2B, lab.RAM1024]
POOL = ThreadPoolExecutor(os.cpu_count())


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


# ---------------------------------------------------------------- SAC
def sac_sweep(alg, samples):
    """Strict avalanche criterion per round. Pass = max |p-0.5| over all
    512x256 (input bit, output bit) cells within 5.5 sigma (Bonferroni)."""
    sigma = 0.5 / math.sqrt(samples)
    rows, passes, r = [], 0, 1
    while passes < 2 and r <= lab.FULL_ROUNDS[alg]:
        rs = list(range(r, min(r + 6, lab.FULL_ROUNDS[alg] + 1)))
        mats = list(POOL.map(lambda q: lab.sac(alg, q, samples, seed=q), rs))
        for q, p in zip(rs, mats):
            z = float(np.abs(p - 0.5).max() / sigma)
            ok = z < 5.5
            rows.append({"round": q, "zmax": round(z, 2), "pass": ok,
                         "never_flips": float((p == 0).mean()),
                         "best_delta_bits": [int(i) for i in np.argsort(
                             -np.abs(p - 0.5).sum(1))[:4]]})
            passes = passes + 1 if ok else 0
            if passes >= 2:
                break
        r = rs[-1] + 1
    first_pass = next(x["round"] for x in rows if x["pass"])
    return {"rows": rows, "full_diffusion_round": first_pass}


# ---------------------------------------------------------------- cube
def cube_round(alg, r, kmax, trials=16, confirm_trials=64):
    """Search cube dims 1..kmax with 3 strategies x 2 seeds. A candidate is
    confirmed only if the same cube stays constant over 64 fresh trials."""
    jobs = [(k, st, sd) for k in range(1, kmax + 1) for st in range(3)
            for sd in range(2)]

    def run(job):
        k, st, sd = job
        cs = 1000 * k + 10 * st + sd + 1
        if lab.cube(alg, r, k, trials, st, cs, 77) == 0:
            return None
        c = lab.cube(alg, r, k, confirm_trials, st, cs, 999331)
        return (k, st, c) if c else None

    hits = [h for h in POOL.map(run, jobs) if h]
    if not hits:
        return None
    k, st, c = min(hits)
    return {"cube_dim": k, "strategy": ["random", "contiguous", "spaced"][st],
            "constant_bits": c}


def cube_sweep(alg, start, kmax):
    rows, misses, r = [], 0, start
    while misses < 2 and r <= lab.FULL_ROUNDS[alg]:
        hit = cube_round(alg, r, kmax)
        rows.append({"round": r, "distinguisher": hit})
        log("  cube", lab.NAMES[alg], "r=%d" % r, hit)
        misses = 0 if hit else misses + 1
        r += 1
    broken = [x["round"] for x in rows if x["distinguisher"]]
    return {"rows": rows, "kmax": kmax, "max_round_broken": max(broken or [start - 1])}


# ---------------------------------------------------------------- neural
def neural_sweep(alg, start, sac_rows, n_train, n_test, epochs):
    rows, misses, r = [], 0, start
    bias = {x["round"]: x["best_delta_bits"] for x in sac_rows}
    while misses < 2 and r <= lab.FULL_ROUNDS[alg]:
        deltas = list(dict.fromkeys(
            bias.get(r, bias[max(bias)])[:4] + [0, 511]))
        best = None
        for d in deltas:
            acc, z = distinguish(alg, r, d, n_train, n_test, epochs, seed=r)
            if best is None or z > best["z"]:
                best = {"delta_bit": d, "accuracy": round(acc, 4), "z": round(z, 1)}
        hit = best["z"] > 5
        rows.append({"round": r, "best": best, "distinguisher": hit,
                     "deltas_tried": deltas})
        log("  neural", lab.NAMES[alg], "r=%d" % r, best)
        misses = 0 if hit else misses + 1
        r += 1
    broken = [x["round"] for x in rows if x["distinguisher"]]
    return {"rows": rows, "max_round_broken": max(broken or [start - 1]),
            "n_train": n_train, "epochs": epochs}


# ---------------------------------------------------------------- randomness
def randomness(alg, blocks):
    """Battery on 32*blocks bytes of counter-mode full-round output."""
    data = lab.stream(alg, blocks, seed=2026)
    bits = np.unpackbits(data)
    n = bits.size
    ones = int(bits.sum())
    mono_z = (2 * ones - n) / math.sqrt(n)
    runs = 1 + int(np.count_nonzero(bits[1:] != bits[:-1]))
    pi = ones / n
    runs_z = (runs - 2 * n * pi * (1 - pi)) / (2 * math.sqrt(n) * pi * (1 - pi))
    counts = np.bincount(data, minlength=256)
    exp = data.size / 256
    chi_byte = float(((counts - exp) ** 2 / exp).sum())          # dof 255
    pair = data[: data.size // 2 * 2].reshape(-1, 2).astype(np.int64)
    pc = np.bincount(pair[:, 0] * 256 + pair[:, 1], minlength=65536)
    pexp = len(pair) / 65536
    chi_pair = float(((pc - pexp) ** 2 / pexp).sum())             # dof 65535
    x = data.astype(np.float64)
    serial = float(np.corrcoef(x[:-1], x[1:])[0, 1])
    words = data[: blocks * 32].view(np.uint32)[: 1 << 20]
    m = len(words)
    collisions = m - len(np.unique(words))
    exp_coll = m * (m - 1) / 2 / 2 ** 32
    return {
        "bytes": int(data.size),
        "monobit_z": round(mono_z, 3),
        "runs_z": round(runs_z, 3),
        "byte_chi2_z": round((chi_byte - 255) / math.sqrt(2 * 255), 3),
        "pair_chi2_z": round((chi_pair - 65535) / math.sqrt(2 * 65535), 3),
        "serial_corr_z": round(serial * math.sqrt(data.size), 3),
        "trunc32_collisions": collisions,
        "trunc32_expected": round(exp_coll, 1),
        "trunc32_z": round((collisions - exp_coll) / math.sqrt(exp_coll), 3),
    }


# ---------------------------------------------------------------- speed
BLOCK_BYTES = {lab.SHA256: 64, lab.SHA3_512: 72, lab.BLAKE2B: 128, lab.RAM1024: 128}


def speed(alg):
    iters = 300_000
    lab.bench_core(alg, 20_000)
    t = min(lab.bench_core(alg, iters) for _ in range(3))
    return {"ns_per_block": round(t / iters * 1e9, 1),
            "block_bytes": BLOCK_BYTES[alg],
            "mb_per_s": round(BLOCK_BYTES[alg] * iters / t / 1e6, 1)}


def ram_long_message_speed():
    from ramhash import _fast
    data = os.urandom(256 << 20)
    out = {}
    for label, th, gpu in (("1_core", 1, False), ("all_cores", 0, False),
                           ("cpu_gpu", 0, True)):
        t = min(_timed(lambda: _fast.hash_parallel(data, threads=th, gpu=gpu))
                for _ in range(3))
        out[label] = round(len(data) / t / 1e6, 1)
    return out


def _timed(f):
    t = time.perf_counter()
    f()
    return time.perf_counter() - t


def hashlib_speed():
    import hashlib
    data = os.urandom(256 << 20)
    out = {}
    for name, fn in [("sha256", hashlib.sha256), ("sha3_512", hashlib.sha3_512),
                     ("blake2b", hashlib.blake2b)]:
        t = time.perf_counter()
        fn(data).digest()
        out[name] = round(len(data) / (time.perf_counter() - t) / 1e6, 1)
    return out


# ---------------------------------------------------------------- generic
def generic_security(output_bits, capacity_bits):
    """Best-known generic attack costs in log2 (classical / quantum)."""
    n, c = output_bits, capacity_bits
    return {
        "output_bits": n, "capacity_bits": c,
        "collision_classical": min(n / 2, c / 2),
        "collision_quantum_BHT": min(n / 3, c / 3),
        "collision_quantum_CNS_no_qram": min(2 * n / 5, c / 2),
        "preimage_classical": min(n, c / 2),
        "preimage_quantum_grover": min(n / 2, c / 3),  # c/3: conservative sponge bound
    }


GENERIC = {
    lab.SHA256: generic_security(256, 512),       # MD: chaining = 256
    lab.SHA3_512: generic_security(512, 1024),
    lab.BLAKE2B: generic_security(512, 1024),     # HAIFA, 512-bit chain
    lab.RAM1024: generic_security(1024, 1024),     # 1024-bit default output
}
# SHA-256's internal chaining value is 256 bits; cap its numbers there.
GENERIC[lab.SHA256].update(capacity_bits=256, collision_classical=128,
                           collision_quantum_BHT=85.3,
                           collision_quantum_CNS_no_qram=102.4,
                           preimage_classical=256, preimage_quantum_grover=128)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--only", help="re-run one algorithm and merge into existing results")
    args = ap.parse_args()
    q = args.quick
    cfg = {
        "sac_samples": 500 if q else 4000,
        "cube_kmax": 10 if q else 18,
        "nn_train": 100_000 if q else 1_000_000,
        "nn_test": 50_000 if q else 200_000,
        "nn_epochs": 2 if q else 5,
        "rand_blocks": 1 << 18 if q else 1 << 21,
    }
    out = out_path("results%s.json" % ("_quick" if q else ""))
    res = {"config": cfg, "algs": {}}
    algs = ALGS
    if args.only:
        with open(out) as f:
            res = json.load(f)
        algs = [a for a in ALGS if lab.NAMES[a] == args.only]
        known = set(lab.NAMES.values())
        res["algs"] = {k: v for k, v in res["algs"].items() if k in known}
    res["ram_rounds"] = lab.FULL_ROUNDS[lab.RAM1024]
    t0 = time.time()
    for alg in algs:
        name = lab.NAMES[alg]
        log("==", name)
        r = {"full_rounds": lab.FULL_ROUNDS[alg]}
        r["sac"] = sac_sweep(alg, cfg["sac_samples"])
        d = r["sac"]["full_diffusion_round"]
        log("  SAC full diffusion at round", d)
        r["cube"] = cube_sweep(alg, max(1, d - 1), cfg["cube_kmax"])
        r["neural"] = neural_sweep(alg, max(1, d - 1), r["sac"]["rows"],
                                   cfg["nn_train"], cfg["nn_test"], cfg["nn_epochs"])
        broken = max(d - 1, r["cube"]["max_round_broken"],
                     r["neural"]["max_round_broken"])
        r["max_round_broken_in_lab"] = broken
        r["rounds_unbroken_in_lab"] = r["full_rounds"] - broken
        r["margin_ratio"] = round(r["full_rounds"] / max(broken, 1), 2)
        r["randomness_full_rounds"] = randomness(alg, cfg["rand_blocks"])
        r["speed_portable_c"] = speed(alg)
        r["generic_security_log2"] = GENERIC[alg]
        res["algs"][name] = r
        log("  broken up to round", broken, "of", r["full_rounds"])
    res["ram1024_long_message_mb_s"] = ram_long_message_speed()
    res["hashlib_optimized_mb_s"] = hashlib_speed()
    res["elapsed_s"] = round(time.time() - t0)
    pass  # out() creates the folder
    with open(out, "w") as f:
        json.dump(res, f, indent=1)
    log("wrote", out, "in %ds" % res["elapsed_s"])


if __name__ == "__main__":
    main()
