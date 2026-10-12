"""Maximum-effort AI attack: bigger network, more data, more epochs, aimed
at the first rounds the standard sweep could NOT break. Shows whether
scaling up the learned attacker buys extra rounds.

    python3 analysis/max_effort.py
"""

import json
import math
import os
import sys
import time

import numpy as np

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _budget import out as out_path  # noqa: E402
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ramhash import lab  # noqa: E402
from neural import train_mlp  # noqa: E402

N_TRAIN, N_TEST, EPOCHS, HIDDEN = 3_000_000, 500_000, 6, (1024, 512, 256)
TARGETS = [(lab.BLAKE2B, 2), (lab.RAM1024, 2), (lab.RAM1024, 3)]


def best_delta(alg, r):
    p = lab.sac(alg, r, 2000, seed=r)
    return int(np.argmax(np.abs(p - 0.5).sum(1)))


def main():
    res = []
    for alg, r in TARGETS:
        d = best_delta(alg, r)
        t = time.time()
        Xtr, ytr = lab.pairs(alg, r, d, N_TRAIN, seed=101)
        Xte, yte = lab.pairs(alg, r, d, N_TEST, seed=202)
        acc = train_mlp(Xtr, ytr, Xte, yte, hidden=HIDDEN, epochs=EPOCHS)
        z = (acc - 0.5) / math.sqrt(0.25 / N_TEST)
        row = {"alg": lab.NAMES[alg], "round": r, "delta_bit": d,
               "accuracy": round(acc, 5), "z": round(z, 2),
               "distinguisher": z > 5, "seconds": round(time.time() - t)}
        print(row, flush=True)
        res.append(row)
        del Xtr, ytr, Xte, yte
    cfg = {"n_train": N_TRAIN, "n_test": N_TEST, "epochs": EPOCHS,
           "hidden": HIDDEN}
    with open(out_path("max_effort.json"), "w") as f:
        json.dump({"config": cfg, "rows": res}, f, indent=1)


if __name__ == "__main__":
    main()
