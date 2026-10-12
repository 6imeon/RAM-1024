"""Soundness + speed check of the Matsui bounding conditions in
trail_bounds.py: exact minima with and without them must be identical.

    sh tools/dockrun.sh python3 analysis/matsui_check.py [max_steps] [timeout]
"""
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import trail_bounds as tb  # noqa: E402

max_steps = int(sys.argv[1]) if len(sys.argv) > 1 else 3
timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 600
rows = []
for kind, bound in (("diff", tb.bound), ("lin", tb.bound_linear)):
    tb.KNOWN = {"diff": {}, "lin": {}}  # learn only from this run
    for n in range(1, max_steps + 1):
        res = {}
        for on in (False, True):
            tb.MATSUI = on
            t0 = time.time()
            with ThreadPoolExecutor(tb.WORKERS) as ex:
                rs = list(ex.map(lambda s: bound(s, n, 0, 64, timeout), range(12)))
            res[on] = ([r["weight_ge"] for r in rs], round(time.time() - t0, 1))
        for s, w in enumerate(res[True][0]):
            tb.learn(kind, s, n, w)
        row = {"kind": kind, "steps": n, "minima": res[True][0],
               "same": res[True][0] == res[False][0],
               "seconds_plain": res[False][1], "seconds_matsui": res[True][1]}
        print(json.dumps(row), flush=True)
        rows.append(row)
assert all(r["same"] for r in rows), "Matsui conditions changed a result"
print("OK: identical minima with and without Matsui conditions")
