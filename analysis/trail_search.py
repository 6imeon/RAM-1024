"""Cryptanalysis rounds 6-7 and 9: differential and linear trail search on the
permutation, their differential-linear combination, and boomerangs.

Builds and runs csrc/trail_lab.c (forward and backward trails, exact
carry model for additions, exact chi3 DDT, empirical check of short
trails), then combines the two directions inside-out:

  * steps an attacker can cover with total trail weight <= 1024 (the
    capacity: anything heavier is worse than generic attacks on the sponge)
    and <= 2048 (the whole state: no permutation distinguisher at all);
  * plus 2 rounds for message modification / rebound in the free middle,
    the usual allowance in published attacks on ARX permutations.

Rotational-XOR trails (round 7): pairs (x, x<<<1 ^ D); the pi constants
inject (c<<<1)^c every round, and each addition costs >= 1.415 bits.

Linear trails (round 7): Wallen's exact correlation for additions, the
exact chi3 LAT; correlation 2^-w needs ~2^(2w) data, so w > 512 is beyond
the capacity bound and w > 1024 beyond the whole codebook. Differential-
linear: a differential of weight wd followed by a linear trail of weight
wl needs ~2^(2wd + 4wl) data.

    python3 analysis/trail_search.py [steps] [restarts]
"""

import json
import os
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _budget import out as out_path  # noqa: E402
TOTAL_STEPS = 3 * 64


def main():
    steps = sys.argv[1] if len(sys.argv) > 1 else "12"
    restarts = sys.argv[2] if len(sys.argv) > 2 else "8"
    exe = os.path.join(ROOT, "build", "trail_search")
    subprocess.check_call(["cc", "-O2", "-I", os.path.join(ROOT, "csrc"), "-o", exe,
                           os.path.join(ROOT, "csrc", "trail_lab.c"), "-lm"])
    d = json.loads(subprocess.check_output([exe, steps, restarts]))
    lin = json.loads(subprocess.check_output([exe, "linear", steps, restarts]))
    rx = json.loads(subprocess.check_output([exe, "rx", steps, restarts]))
    fw = {0: 0, **{r["steps"]: r["weight"] for r in d["forward"]}}
    bw = {0: 0, **{r["steps"]: r["weight"] for r in d["backward"]}}
    out = {"search": d}
    for bound in (1024, 2048):
        best = max(((f + b, f, b) for f in fw for b in bw if fw[f] + bw[b] <= bound),
                   key=lambda x: x[0])
        out["inside_out_weight_le_%d" % bound] = {
            "steps": best[0], "forward": best[1], "backward": best[2],
            "weight": fw[best[1]] + bw[best[2]], "rounds": round(best[0] / 3, 2)}
    # round 9: boomerang (backward trail + measured middle switch + forward trail),
    # one process per step offset
    procs = [subprocess.Popen([exe, "boomerang", "4", str(st)], stdout=subprocess.PIPE)
             for st in range(12)]
    boom = [json.loads(p.communicate()[0]) for p in procs]
    for bound in (1024, 2048):
        k = "reach_le_%d" % bound
        best = max(boom, key=lambda r: (r[k]["steps"], -r[k]["weight"]))[k]
        out["boomerang_" + k] = best
        print("boomerang <=2^-%d:" % bound, best)
    out["boomerang_switch"] = {
        str(m["middle_steps"]): {"pairs_returning": sum(b["switch"][i]["pairs_returning"] for b in boom),
                                 "pairs_free": sum(b["switch"][i]["pairs_free"] for b in boom)}
        for i, m in enumerate(boom[0]["switch"])}
    # round 9b: all 2544 starting differences, lightest 48 trails per split
    procs = [subprocess.Popen([exe, "boomerang2", restarts, str(st), "14", "18"],
                              stdout=subprocess.PIPE) for st in range(12)]
    wide = {}
    for st, p in enumerate(procs):
        for r in json.loads(p.communicate()[0])["best"]:
            r["offset"] = st
            if r["steps"] not in wide or r["weight"] < wide[r["steps"]]["weight"]:
                wide[r["steps"]] = r
    out["boomerang_wide"] = [wide[k] for k in sorted(wide)]
    print("boomerang, all 2544 differences:", [(r["steps"], r["weight"]) for r in out["boomerang_wide"]])
    reach = max(out["inside_out_weight_le_2048"]["steps"],
                out["boomerang_reach_le_2048"]["steps"]) + 6  # + 2 free middle rounds
    out["attack_reach_steps_with_rebound"] = reach
    out["margin"] = round(TOTAL_STEPS / reach, 2)
    out["checks"] = [r for k in ("forward", "backward") for r in d[k] if r["empirical_p"] >= 0]
    out["linear"] = lin
    lw = {0: 0, **{r["steps"]: r["weight"] for r in lin["linear"]}}
    out["linear_reach_steps"] = {
        "data_le_2^1024": max(k for k in lw if 2 * lw[k] <= 1024),
        "data_le_2^2048": max(k for k in lw if 2 * lw[k] <= 2048)}
    dl = max(((f + l, f, l) for f in fw for l in lw if 2 * fw[f] + 4 * lw[l] <= 2048),
             key=lambda x: x[0])
    out["differential_linear"] = {"steps": dl[0], "diff_steps": dl[1], "lin_steps": dl[2],
                                  "log2_data": 2 * fw[dl[1]] + 4 * lw[dl[2]]}
    rf = {0: 0, **{r["steps"]: r["weight"] for r in rx["forward"]}}
    rb = {0: 0, **{r["steps"]: r["weight"] for r in rx["backward"]}}
    best = max(((f + b, f, b) for f in rf for b in rb if rf[f] + rb[b] <= 2048),
               key=lambda x: x[0])
    out["rx"] = rx
    out["rx_inside_out_le_2048"] = {"steps": best[0], "forward": best[1], "backward": best[2]}
    print("rx inside-out:", out["rx_inside_out_le_2048"])
    print("linear", [(r["steps"], r["weight"]) for r in lin["linear"]])
    print("linear reach:", out["linear_reach_steps"], " differential-linear:",
          out["differential_linear"])
    for k in ("forward", "backward"):
        print(k, [(r["steps"], r["weight"]) for r in d[k]])
    print("inside-out <=2^-1024:", out["inside_out_weight_le_1024"])
    print("inside-out <=2^-2048:", out["inside_out_weight_le_2048"])
    print("with 2 free rounds: %d steps (%.2f rounds) -> margin %.1fx"
          % (reach, reach / 3, out["margin"]))
    with open(out_path("trails_v3.json"), "w") as f:
        json.dump(out, f, indent=1)


if __name__ == "__main__":
    main()
