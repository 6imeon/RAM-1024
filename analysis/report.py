"""Build RESULTS.md from results/*.json.

    python3 analysis/report.py
"""

import json
import os

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
R = os.path.join(ROOT, "results")
NAMES = ["SHA-256", "SHA3-512", "BLAKE2b", "RAM-1024"]
RAM = "RAM-1024"
EXPERT_REACH = 8.5  # pessimistic: RAM attacked as far as BLAKE2b (shared G)

# Best published cryptanalysis (rounds reached / total), for calibration.
LITERATURE = {
    "SHA-256": (39, "practical semi-free-start collision 39/64 steps "
                    "(Li-Liu-Wang 2024); 31-step collision at 2^65.5 "
                    "(Mendel-Nad-Schläffer 2013)"),
    "SHA3-512": (6, "practical collisions on 5-round SHA-3 and 6-round Keccak "
                    "instances (Guo et al., JoC 2019); SHA3-512 attacks reach "
                    "4 rounds"),
    "BLAKE2b": (8.5, "8.5-round boomerang distinguisher at 2^474 (Hao 2014); "
                     "7.5-round compression pseudo-preimage (Espitau-Fouque-"
                     "Karpman 2015)"),
}

# Design iterations (measured on this machine; v1 numbers from its own run).
HISTORY = [
    ("v1 (24 rds, 512-bit out)", "first design: 2048-bit sponge, ARX+chi, 512-bit out",
     "2.8×", "2^171", "~215 MB/s", "margin below SHA-3 → more rounds"),
    ("v1.1 (32 rds, 512-bit out)", "rounds raised after calibrating vs. BLAKE2b literature",
     "3.8×", "2^171", "165 MB/s", "still ≈ SHA-3 (4.0×); quantum only tied; slowest"),
    ("v2 RAM-1024 (64 rds)", "1024-bit output, unrolled + SIMD (SHA-3 ISA: XAR/BCAX), "
     "parallel tree mode, 64 rounds", "7.5×", "2^341", "1.9 GB/s (all cores)",
     "ahead on every security axis; raw speed 2nd to SHA-256 silicon"),
    ("v2 red team", "step-level attacks + multi-pair AI + 2^22 cubes",
     "7.5×", "2^341", "—", "no new breaks; resistance from step 5 (1.67 rounds)"),
    ("v3 hybrid scalar+SIMD", "3rd state on integer units beside 2 SIMD lanes",
     "—", "—", "249 vs 300 MB/s/core", "**rejected**: register spills, slower"),
    ("v3 calibration", "assumed 8.5-round expert reach replaced by measured "
     "lab→literature multiplier (BLAKE2b at half-round resolution)",
     "**8.5×** (measured)", "2^341", "—", "margin now evidence-based, 2.1× SHA-3's"),
    ("v3 GPU tree", "16 KiB leaves on the GPU (Metal) concurrently with CPU threads",
     "8.5×", "2^341", "~4–5 GB/s", "**faster than hardware SHA-256** at full rounds"),
    ("v3 robustness", "boundaries re-measured with 3 seeds; 4 calibration models "
     "applied symmetrically", "4.8–8.5×", "2^341", "—",
     "leads under every model; only design left unbroken by the harshest ones"),
    ("v3 permutation", "cryptanalysis rounds 1–5: diagonal constants, ρ layer, "
     "key/API/OOM/downgrade fixes", "8.5× (10.2× like-for-like)", "2^341",
     "3.8 GB/s (CPU+GPU)", "inside-out reach 11→10 steps, symmetry 6→1"),
    ("v3 round 12", "Matsui-bounded SAT proofs; time-budgeted test suite (≤ 1 h)",
     "8.5× (trails: 8.7×)", "2^341", "unchanged",
     "5-step proofs 0/12 → 9/12 offsets in equal time; 3-step bounds raised at 4 offsets; make test 23.5 s → 4.2 s"),
    ("v3 round 11", "SAT-proven minimum trail weights (CaDiCaL, every input difference)",
     "8.5× (trails: 8.7×)", "2^341", "unchanged",
     "F44: forward-only table was far too high (3 steps: 3, not 28); inside-out estimates proven conservative to 5 steps"),
    ("v3 round 10", "independent review: cryptanalyst, implementation audit, spec reimplementation",
     "8.5× (trails: 8.7×)", "2^341", "unchanged",
     "spec matched 93/93 vectors; RAM-Balloon v2 (cross-lane, t=3); GPU heap overflow + 9 more fixed; fixes re-reviewed (F37–F43)"),
    ("v3 round 9", "boomerang search with switches measured on the real permutation",
     "8.5× (trails: 8.7×)", "2^341", "unchanged",
     "F22: boomerang reaches 16 steps (differential: 14); trail margin 9.6× → 8.7×, headline unchanged"),
    ("v3 round 8", "SAT/SMT (z3) preimage and collision attack on the public challenges",
     "8.5× (trails: 9.6×)", "2^341", "unchanged", "1 round solved; 2 rounds worse than brute force"),
    ("v3 round 7", "linear, differential-linear and rotational-XOR trail search",
     "8.5× (trails: 9.6×)", "2^341", "unchanged", "no finding; all within the differential bound"),
    ("v3 round 6", "trail search, constant-time + fuzz + sanitizers, misuse-proof "
     "API, RAM-Balloon password hashing, portable C (Win/Linux/macOS, BE/LE, "
     "32/64-bit)", "8.5× (trails: 9.6×)", "2^341", "unchanged",
     "third independent margin estimate agrees; no implementation findings"),
]


def load(name):
    p = os.path.join(R, name)
    if not os.path.exists(p):
        return None
    with open(p) as f:
        return json.load(f)


def main():
    res = load("results.json")
    grov = load("grover.json")
    rot = load("rotational.json")
    mx = load("max_effort.json")
    ms = load("matched_speed.json")
    rt = load("redteam.json")
    cal = load("calibration.json")
    rob = load("robustness.json")
    pa2, pa3 = load("perm_attack_v2.json"), load("perm_attack_v3.json")
    alg3, pn3, cio = load("algebraic_v3.json"), load("perm_neural_v3.json"), load("calibration_io.json")
    trails = load("trails_v3.json")
    A = res["algs"]
    G = {n: A[n]["generic_security_log2"] for n in NAMES}
    h = res["hashlib_optimized_mb_s"]
    std_speed = {"SHA-256": h["sha256"], "SHA3-512": h["sha3_512"], "BLAKE2b": h["blake2b"]}
    ram_speed = res["ram1024_long_message_mb_s"]
    pess = {n: A[n]["full_rounds"] / LITERATURE[n][0] for n in LITERATURE}
    reach_ram = cal["ram_estimated_expert_reach"] if cal else EXPERT_REACH
    pess[RAM] = A[RAM]["full_rounds"] / reach_ram
    L = []
    w = L.append

    def table(header, rows):
        w("| " + " | ".join(header) + " |")
        w("|" + "---|" * len(header))
        for r in rows:
            w("| " + " | ".join(r) + " |")
        w("")

    def winner(vals, higher=True):
        best = max(vals.values()) if higher else min(vals.values())
        ws = [n for n, v in vals.items() if v == best]
        return "**" + ws[0] + "**" if len(ws) == 1 else "tie"

    w("# RAM-1024 vs. SHA-256 / SHA3-512 / BLAKE2b — test results\n")
    w("Generated by `analysis/report.py` from `results/*.json` (Apple M3 Pro). "
      "Every attack runs with *identical* code against all four designs "
      "(`csrc/lab.c`); the SHA-256 / SHA3-512 / BLAKE2b implementations are "
      "verified bit-exact against `hashlib`.\n")

    w("## 0. Scoreboard\n")
    rows = []

    def score(label, vals, fmt, higher=True):
        rows.append([label] + [fmt(vals[n]) for n in NAMES] + [winner(vals, higher)])

    lab_margin = {n: A[n]["margin_ratio"] for n in NAMES}
    if rt:  # step-level resolution: RAM broken through step k = k/3 rounds
        broken_steps = max(r["step"] for r in rt["ram_steps"] if r["broken"])
        lab_margin[RAM] = A[RAM]["full_rounds"] / (broken_steps / 3)
    score("Lab margin via the message input (total ÷ rounds broken; RAM inside-out on the bare permutation: %s)"
          % ("%.0f×" % (A[RAM]["full_rounds"] / pa3["inside_out_reach_rounds"]) if pa3 else "n/a"),
          lab_margin, lambda v: "%.1f×" % v)
    score("Pessimistic margin (total ÷ best expert reach; RAM: measured calibration)",
          pess, lambda v: "%.1f×" % v)
    score("Collision, classical (log2)",
          {n: G[n]["collision_classical"] for n in NAMES}, lambda v: "%g" % v)
    score("Collision, quantum BHT (log2)",
          {n: G[n]["collision_quantum_BHT"] for n in NAMES}, lambda v: "%.0f" % v)
    score("Preimage, quantum Grover (log2)",
          {n: G[n]["preimage_quantum_grover"] for n in NAMES}, lambda v: "%.0f" % v)
    score("Immune to length extension",
          {"SHA-256": 0, "SHA3-512": 1, "BLAKE2b": 1, RAM: 1},
          lambda v: "yes" if v else "**no**")
    if ms:
        speeds = dict(std_speed)
        speeds[RAM] = ram_speed.get("cpu_gpu", ram_speed["all_cores"])
        score("Throughput, long message, full rounds (MB/s)", speeds, lambda v: "%.0f" % v)
        eq = {r["competitor"]: r for r in ms["rows"]}
        rows.append(["RAM-1024 at *equal* security margin, MB/s (1 core / all cores vs. standard)"] +
                    ["%d / %d vs %d" % (eq[n]["ram_1core_mb_s"], eq[n]["ram_allcores_mb_s"],
                                        eq[n]["competitor_mb_s"]) for n in NAMES[:3]] +
                    ["—", "RAM-1024 (all cores)"])
    table(["Metric"] + NAMES + ["Winner"], rows)
    w("Throughput: standards via `hashlib` (OpenSSL; SHA-256 uses dedicated "
      "SHA-2 CPU instructions). Their sequential Merkle-Damgård / sponge "
      "structure cannot spread one message over several cores or a GPU; "
      "RAM-1024's tree mode can: %.0f MB/s on one core, %.0f MB/s on all CPU "
      "cores, **%.0f MB/s on CPU + GPU** (Metal), all at the full 64 rounds "
      "and producing the identical digest.\n"
      % (ram_speed["1_core"], ram_speed["all_cores"],
         ram_speed.get("cpu_gpu", ram_speed["all_cores"])))

    if pa3:
        w("## 0b. Cryptanalysis rounds (full log: CRYPTANALYSIS.md)\n")
        w("Permutation-level attacks with the whole 2048-bit state, in both "
          "directions (inside-out = forward + backward reach, in steps of a "
          "third of a round):\n")
        rows = [["SAC / differential", "%d + %d = %d" % (pa2["forward_reach_steps"],
                 pa2["backward_reach_steps"], pa2["inside_out_reach_steps"]),
                 "%d + %d = %d" % (pa3["forward_reach_steps"], pa3["backward_reach_steps"],
                                   pa3["inside_out_reach_steps"])],
                ["Column-shift symmetry", str(pa2["colshift_reach_steps"]),
                 str(pa3["colshift_reach_steps"])]]
        if alg3:
            rows.append(["Zero-sum (cubes ≤ 2^%d)" % alg3["kmax"], "—",
                         "%d + %d = %d" % (alg3["zero_sum"]["forward_reach"],
                                           alg3["zero_sum"]["backward_reach"],
                                           alg3["zero_sum_inside_out_steps"])])
        if pn3:
            rows.append(["Neural (AI), full state", "—", "%d + %d = %d" % (
                pn3["forward_reach"], pn3["backward_reach"], pn3["inside_out_steps"])])
        table(["Attack", "v2 reach", "v3 reach"], rows)
        if cio:
            w("Like-for-like calibration (BLAKE2b's permutation measured the same "
              "way: %.1f rounds inside-out vs RAM-1024's %.2f): margin %.1f×; "
              "forward-only model %.1f×. Headline uses the smaller, **%.1f×**.\n"
              % (cio["blake2b_inside_out_rounds"], cio["ram_inside_out_rounds"],
                 cio["ram_margin_inside_out"], cio["ram_margin_forward_only"],
                 cio["ram_margin_headline"]))

    if trails:
        f = {r["steps"]: r["weight"] for r in trails["search"]["forward"]}
        b = {r["steps"]: r["weight"] for r in trails["search"]["backward"]}
        w("**Differential trail search** (round 6; exact carry model and chi "
          "table, 2544 starting differences × 12 offsets × %d restarts). Best "
          "trail weight w (probability 2^-w):\n" % trails["search"]["restarts"])
        ks = sorted(f)
        table(["Steps"] + [str(k) for k in ks],
              [["forward"] + [str(f[k]) for k in ks], ["backward"] + [str(b[k]) for k in ks]])
        io = trails["inside_out_weight_le_2048"]
        if "linear" in trails:
            lw = {r["steps"]: r["weight"] for r in trails["linear"]["linear"]}
            rf = {r["steps"]: r["weight"] for r in trails["rx"]["forward"]}
            rb = {r["steps"]: r["weight"] for r in trails["rx"]["backward"]}
            table(["Steps"] + [str(k) for k in ks],
                  [["linear (round 7)"] + [str(lw.get(k, "")) for k in ks],
                   ["rotational-XOR fwd"] + [str(rf.get(k, "")) for k in ks],
                   ["rotational-XOR bwd"] + [str(rb.get(k, "")) for k in ks]])
            w("Linear reach %d steps (data ≤ 2^2048); differential-linear %d steps; "
              "rotational-XOR inside-out %d steps. None exceeds the differential bound.\n"
              % (trails["linear_reach_steps"]["data_le_2^2048"],
                 trails["differential_linear"]["steps"],
                 trails["rx_inside_out_le_2048"]["steps"]))
        if "boomerang_reach_le_2048" in trails:
            bo = trails["boomerang_reach_le_2048"]
            w("**Boomerang** (round 9, F22): backward trail of %d steps (weight %d), a "
              "%d-step middle switch measured on the real permutation (2^-%.1f over 2^16 "
              "quartets), forward trail of %d steps (weight %d): **%d steps** at quartet "
              "weight %.0f ≤ 2048, beyond the %d-step differential. The trail-based "
              "margin below uses it.\n"
              % (bo["top"], bo["top_weight"], bo["switch"], bo["switch_weight_2^16"],
                 bo["bottom"], bo["bottom_weight"], bo["steps"], bo["weight"], io["steps"]))
        w("Best trail-based reach below 2^2048: %d steps; with 2 free "
          "rounds for rebound/message modification: %.2f rounds of 64, so a "
          "**%.1f×** margin, still above the 8.5× headline.\n"
          % (trails["attack_reach_steps_with_rebound"] - 6, trails["attack_reach_steps_with_rebound"] / 3,
             trails["margin"]))

    xp = os.path.join(ROOT, "results", "crossplatform", "summary.txt")
    if os.path.exists(xp):
        jobs = sorted(l.split() for l in open(xp) if l.strip())
        w("## 0c. Portability and implementation checks (tools/crossplatform.sh)\n")
        w("Every row builds the C library and reproduces all known-answer "
          "vectors (tests/kat.txt, tests/kat_pwhash.txt) bit for bit. The "
          "platform column is the Docker host image: Windows rows run under "
          "Wine, the FreeBSD 15.0 and OpenBSD 7.9 rows are full VMs in QEMU "
          "inside it, Android is the bionic userland, and foreign CPUs are "
          "emulated.\n")
        table(["Job", "Platform", "Result"],
              [[j[1], " ".join(j[2:-1]).strip("(),"), j[0]] for j in jobs])

    w("## 1. Design iterations\n")
    table(["Version", "Change", "Pessimistic margin", "Quantum collision",
           "Speed", "Verdict"], [list(x) for x in HISTORY])

    w("## 2. How many rounds can each attack break?\n")
    rows = []

    def row(label, f):
        rows.append([label] + [f(n) for n in NAMES])

    def sweep(key):
        def f(n):
            rs = A[n][key]["rows"]
            if any(r["distinguisher"] for r in rs):
                return str(A[n][key]["max_round_broken"])
            return "none tested ≥ %d" % rs[0]["round"]
        return f

    row("Total rounds", lambda n: str(A[n]["full_rounds"]))
    row("Full avalanche (SAC) at round", lambda n: str(A[n]["sac"]["full_diffusion_round"]))
    row("Cube attack (≤2^%d) breaks to round" % res["config"]["cube_kmax"], sweep("cube"))
    row("Neural-network (AI) attack breaks to round", sweep("neural"))
    if rot:
        row("Rotational attack breaks to round",
            lambda n: str(rot.get(n, {}).get("max_round_broken") or "none"))
    row("**Max round broken in our lab**",
        lambda n: "**%d**" % A[n]["max_round_broken_in_lab"])
    row("Unbroken rounds remaining", lambda n: str(A[n]["rounds_unbroken_in_lab"]))
    row("Best *published* attack reaches round",
        lambda n: str(LITERATURE[n][0]) if n in LITERATURE else "— (new; assume %g)" % EXPERT_REACH)
    table([""] + NAMES, rows)
    w("Published attacks: " + "; ".join("**%s** — %s" % (k, v[1])
                                        for k, v in LITERATURE.items()) + ".\n")
    if cal:
        w("### Measured calibration of the pessimistic model\n")
        w("Expert multiplier = best published reach ÷ our lab's reach. "
          "BLAKE2b measured at half-round, RAM-1024 at step resolution:\n")
        table(["", "Lab reach (rounds)", "Published reach", "Expert multiplier"],
              [[n, "%g" % cal["lab_reach_rounds"][n], "%g" % cal["published_reach_rounds"][n],
                "%.2f×" % cal["expert_multiplier"][n]] for n in cal["published_reach_rounds"]]
              + [[RAM, "%.2f" % cal["lab_reach_rounds"][RAM], "—",
                  "× %.2f (worst, from %s) → **%.2f rounds**"
                  % (cal["expert_multiplier"][cal["worst_multiplier_from"]],
                     cal["worst_multiplier_from"], cal["ram_estimated_expert_reach"])]])
        w("RAM-1024 margin under the worst observed multiplier: 64 ÷ %.2f = "
          "**%.1f×** (SHA-3 4.0×, SHA-256 1.6×, BLAKE2b 1.4×).\n"
          % (cal["ram_estimated_expert_reach"], cal["ram_margin"]))

    if rob:
        w("### Robustness of the calibration\n")
        w("Break boundaries re-measured with %d fresh seeds (1M-pair neural "
          "attacker): %s.\n" % (len({r["seed"] for r in rob["boundary_repeats"]}),
                                 "stable — BLAKE2b breaks at half-round 3 and resists "
                                 "from 4, RAM-1024 breaks at step 4 and resists from 5, "
                                 "every time" if rob["boundaries_stable"] else "**unstable**"))
        w("Each pessimistic model applied *symmetrically* to all four designs "
          "(margin; \"broken\" = model predicts attacks reach every round):\n")
        table(["Model"] + NAMES + ["RAM leads?"],
              [[r["model"]] + [("%.2f×" % r[n]) if r[n] else "**broken**" for n in NAMES]
               + ["yes" if r["ram_leads"] else "**no**"] for r in rob["sensitivity"]])

    w("**Earlier, assumption-based model.** Years of expert work pushed the "
      "standards far beyond what our lab finds (BLAKE2b, which shares "
      "RAM's G function: lab %d → published 8.5 rounds). We assume RAM-1024 "
      "falls just as far — %g rounds — which leaves %d of 64 rounds (%.1f×) "
      "untouched, vs. SHA-3's 4.0×, SHA-256's 1.6× and BLAKE2b's 1.4×.\n"
      % (A["BLAKE2b"]["max_round_broken_in_lab"], EXPERT_REACH,
         64 - EXPERT_REACH, pess[RAM]))

    if rt:
        w("### Red team round 2: finer resolution and stronger attackers\n")
        w("RAM-1024 cut after individual *steps* (3 per round: column G, "
          "diagonal G, chi). Every attack — SAC, cube (≤2^18), single-pair "
          "neural (1M pairs) and %d-pair neural (Gohr-style amplification) — "
          "must fail for a step to count as unbroken:\n" % rt["k_pairs"])
        table(["Step", "Rounds", "SAC z", "Neural z", "Multi-pair z", "Cube", "Broken?"],
              [[str(r["step"]), "%.2f" % r["rounds"], "%.1f" % r["sac_zmax"],
                "%.1f" % r["neural_z"], "%.1f" % r["multipair_z"],
                "2^%d" % r["cube_dim"] if r["cube_dim"] else "—",
                "**yes**" if r["broken"] else "no"] for r in rt["ram_steps"]])
        w("Strongest attackers (%d-pair neural, cubes 2^20–2^22) at each "
          "design's first round that resisted the standard sweep:\n" % rt["k_pairs"])
        table(["Target", "Multi-pair z", "Large cube", "Broken?"],
              [["%s, %d rounds" % (r["alg"], r["round"]), "%.1f" % r["multipair_z"],
                ("2^%d, %d const bits" % (r["big_cube"]["k"], r["big_cube"]["const_bits"]))
                if r["big_cube"] else "—",
                "**yes**" if r["broken"] else "no"] for r in rt["strong_attacks"]])

    if mx:
        w("### Maximum-effort AI attack\n")
        c = mx["config"]
        w("MLP %s, %s training pairs, %d epochs, input difference chosen from "
          "the strongest SAC bias:\n"
          % ("×".join(map(str, c["hidden"])), f"{c['n_train']:,}", c["epochs"]))
        table(["Target", "Accuracy", "z-score", "Distinguisher?"],
              [["%s, %d rounds" % (r["alg"], r["round"]), "%.4f" % r["accuracy"],
                "%.1f" % r["z"], "**yes**" if r["distinguisher"] else "no"]
               for r in mx["rows"]])

    w("## 3. Full-round output randomness\n")
    w("z-scores should lie roughly within ±3 for an ideal random function.\n")
    table(["Test"] + NAMES, [
        [label] + ["%.2f" % A[n]["randomness_full_rounds"][key] for n in NAMES]
        for key, label in [("monobit_z", "Monobit"), ("runs_z", "Runs"),
                           ("byte_chi2_z", "Byte χ²"), ("pair_chi2_z", "Byte-pair χ²"),
                           ("serial_corr_z", "Serial correlation"),
                           ("trunc32_z", "32-bit truncation collisions")]])

    w("## 4. Quantum security\n")
    table(["log2 cost"] + NAMES, [
        [label] + ["%g" % round(G[n][key], 1) for n in NAMES]
        for key, label in [("collision_classical", "Collision (classical)"),
                           ("collision_quantum_BHT", "Collision (quantum, BHT)"),
                           ("collision_quantum_CNS_no_qram", "Collision (quantum, no QRAM)"),
                           ("preimage_classical", "Preimage (classical)"),
                           ("preimage_quantum_grover", "Preimage (quantum)")]])
    if grov:
        w("**Grover simulated.** Exact state-vector simulation of Grover "
          "preimage search on k-bit truncations confirms the √N law the table "
          "assumes:\n")
        table(["k", "Grover queries", "success", "classical expected"],
              [[str(s["k"]), str(s["grover_queries"]), "%.3f" % s["success_prob"],
                f"{s['classical_expected_queries']:,.0f}"]
               for s in grov["simulations"][RAM]])
        e = grov["extrapolation"]
        w("Under NIST's MAXDEPTH = 2^64 limit on quantum circuit depth, a "
          "Grover preimage costs ≈2^%d gates for SHA-256, ≈2^%d for SHA3-512 "
          "and ≈2^%d for RAM-1024 (~2^80 operations is already beyond every "
          "computer on Earth).\n"
          % tuple(e[n]["grover_preimage_gates_MAXDEPTH_2^64_log2"]
                  for n in ("SHA-256", "SHA3-512", RAM)))

    w("## 5. Speed\n")
    if ms:
        w("**At equal security margin** (RAM rounds = competitor margin × "
          "%.2f measured expert reach; reduced round counts that are not a "
          "multiple of 4 run on the CPU only):\n" % ms["expert_reach_rounds"])
        table(["Competitor", "Its margin", "RAM rounds", "Competitor MB/s",
               "RAM 1 core", "RAM all cores"],
              [[r["competitor"], "%.2f×" % r["competitor_margin"],
                str(r["ram_rounds_for_equal_margin"]), str(r["competitor_mb_s"]),
                str(r["ram_1core_mb_s"]), "**%d**" % r["ram_allcores_mb_s"]]
               for r in ms["rows"]])
        f = ms["full"]
        w("At its full %d rounds (%.1f× margin): %d MB/s on 1 core, %d on all "
          "cores, **%d on CPU + GPU** — vs. SHA-256 (hardware-accelerated) "
          "%d MB/s.\n" % (f["rounds"], f["margin"], f["ram_1core_mb_s"],
                          f["ram_allcores_mb_s"], f.get("ram_cpu_gpu_mb_s", 0),
                          ms["rows"][0]["competitor_mb_s"]))
    w("Portable-C core speed in the lab (one block, single core):\n")
    table([""] + NAMES, [
        ["ns per block"] + ["%.0f" % A[n]["speed_portable_c"]["ns_per_block"] for n in NAMES],
        ["block bytes"] + [str(A[n]["speed_portable_c"]["block_bytes"]) for n in NAMES]])

    w("## 6. What these results do and do not show\n")
    w("* RAM-1024 diffuses as fast as the best standard, resists every attack "
      "in our lab beyond round %d of 64, and leads every security metric "
      "above — including under a deliberately pessimistic model of future "
      "cryptanalysis.\n"
      "* They do **not** prove RAM-1024 secure; no test can. Only years of "
      "public cryptanalysis build that confidence, which the standards here "
      "have had for 10–25 years. Hence `ramhash`'s default "
      "`ram-1024+sha3-512`: secure if *either* survives.\n"
      "* No public evidence supports \"AI is close to breaking SHA-256\": our "
      "neural attacker stalls at round %d of 64 while human cryptanalysts "
      "reach 39.\n"
      % (A[RAM]["max_round_broken_in_lab"], A["SHA-256"]["neural"]["max_round_broken"]))
    with open(os.path.join(ROOT, "RESULTS.md"), "w") as f:
        f.write("\n".join(L))
    print("wrote RESULTS.md")


if __name__ == "__main__":
    main()
