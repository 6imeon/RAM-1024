"""Time-budgeted test + analysis runner (default: at most one hour).

    python3 tools/suite.py                    # tier "full", 3600 s budget
    python3 tools/suite.py --tier quick       # correctness only (~3 min)
    python3 tools/suite.py --budget 900 --tier standard
    python3 tools/suite.py --list | --dry-run | --only build python-suite

Jobs come from tests/suite.json (order = priority). Guarantees:
  * the run never exceeds --budget: a job starts only if its estimate fits
    in the time left, and is killed at min(its max, the deadline);
  * killing is complete: the job's whole process group, and every Docker
    container labelled with the job's id (ramsuite=...);
  * long analyses get RAM_DEADLINE and stop cleanly on their own, saving
    partial results; all analysis output goes to results/suite/<run>/, so
    a short run never overwrites the canonical long-run results;
  * two lanes in parallel (local jobs, Docker jobs), each sized to half
    the cores, so the machine stays usable.
Writes results/suite/<run>/{<job>.log, summary.json, summary.md} and
results/suite/latest.md. Exit status 1 if any job failed or timed out.
"""
import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
TIERS = ["quick", "standard", "full", "proof"]  # proof: open research runs, opt-in
GRACE = 30          # seconds kept back for cleanup and the report
POSIX = os.name == "posix"
RUNNING = set()     # live job processes, killed on Ctrl-C


def load(path):
    with open(path) as f:
        return json.load(f)["jobs"]


def missing(job):
    return [t for t in job.get("needs", []) if shutil.which(t) is None]


def docker_kill(label):
    if shutil.which("docker") is None:
        return
    try:
        ids = subprocess.run(["docker", "ps", "-q", "--filter", "label=ramsuite=" + label],
                             capture_output=True, text=True, timeout=30).stdout.split()
        if ids:
            subprocess.run(["docker", "kill"] + ids, capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        pass


def kill_tree(p):
    try:
        if POSIX:
            os.killpg(p.pid, signal.SIGTERM)
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
        else:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True)
    except (OSError, ProcessLookupError):
        pass


class Runner:
    def __init__(self, jobs, budget, outdir, run_id, dry):
        self.jobs, self.dry = jobs, dry
        self.start = time.time()
        self.deadline = self.start + budget - GRACE
        self.outdir, self.run_id = outdir, run_id
        self.results = {}
        self.sim = {"local": 0.0, "docker": 0.0}   # --dry-run: simulated lane clocks
        self.lock = threading.Lock()
        half = max(1, (os.cpu_count() or 2) // 2)
        self.env = dict(os.environ, RAM_THREADS=str(half), RAMCI_JOBS=str(max(2, half)),
                        PYTHONDONTWRITEBYTECODE="1",
                        RAM_RESULTS=os.path.relpath(outdir, ROOT))

    def left(self, pool="local"):
        if self.dry:
            return self.deadline - self.start - self.sim[pool]
        return self.deadline - time.time()

    def record(self, job, status, secs, note=""):
        with self.lock:
            self.results[job["id"]] = {"id": job["id"], "tier": job["tier"],
                                       "pool": job["pool"], "status": status,
                                       "seconds": round(secs, 1), "est": job["est"],
                                       "note": note}
        print("%-8s %-22s %6.0fs  %s" % (status, job["id"], secs, note), flush=True)

    def run_job(self, job):
        sup = job.get("superseded_by")
        if sup and any(j["id"] == sup for j in self.jobs):
            return self.record(job, "SKIP", 0, "covered by " + sup)
        miss = missing(job)
        if miss:
            return self.record(job, "SKIP", 0, "missing: " + ", ".join(miss))
        left = self.left(job["pool"])
        if job["est"] > left:
            return self.record(job, "SKIP", 0, "budget: needs ~%ds, %ds left"
                               % (job["est"], max(0, left)))
        slot = int(min(job["max"], left))
        restarts = "8" if slot >= 900 else "4" if slot >= 400 else "2"
        cmd = [c.replace("{python}", sys.executable).replace("{slot}", str(max(30, slot - 60)))
               .replace("{restarts}", restarts) for c in job["cmd"]]
        if self.dry:
            self.sim[job["pool"]] += job["est"]
            return self.record(job, "PLAN", job["est"], "slot %ds: %s" % (slot, " ".join(cmd)))
        label = "%s-%s" % (self.run_id, job["id"])
        env = dict(self.env, RAM_DEADLINE=str(time.time() + slot), RAMSUITE=label)
        for k, v in job.get("env", {}).items():
            env[k] = v.replace("{ncpu}", str(os.cpu_count() or 2))
        log = open(os.path.join(self.outdir, job["id"] + ".log"), "w")
        t0 = time.time()
        kw = {"start_new_session": True} if POSIX else {
            "creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        p = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, **kw)
        RUNNING.add(p)
        try:
            rc = p.wait(slot)
            status = "PASS" if rc == 0 else "FAIL"
            note = "" if rc == 0 else "exit %d" % rc
        except subprocess.TimeoutExpired:
            kill_tree(p)
            status, note = "TIMEOUT", "killed at %ds" % slot
        finally:
            RUNNING.discard(p)
            docker_kill(label)
            log.close()
        if status != "PASS":
            with open(os.path.join(self.outdir, job["id"] + ".log")) as f:
                tail = f.read()[-600:].strip().splitlines()[-3:]
            note = (note + " | " + " / ".join(tail))[:300]
        self.record(job, status, time.time() - t0, note)

    def lane(self, jobs):
        for j in jobs:
            self.run_job(j)

    def run(self):
        lanes = [[j for j in self.jobs if j["pool"] == pool] for pool in ("local", "docker")]
        ts = [threading.Thread(target=self.lane, args=(l,)) for l in lanes]
        for t in ts:
            t.start()
        for t in ts:
            t.join()


def report(r, outdir, budget, tier):
    rows = [r.results[j["id"]] for j in r.jobs if j["id"] in r.results]
    wall = time.time() - r.start
    count = {s: sum(1 for x in rows if x["status"] == s)
             for s in ("PASS", "FAIL", "TIMEOUT", "SKIP", "PLAN")}
    summary = {"run": r.run_id, "tier": tier, "budget_s": budget, "wall_s": round(wall, 1),
               "counts": count, "jobs": rows}
    with open(os.path.join(outdir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=1)
    md = ["# Suite run %s" % r.run_id, "",
          "Tier **%s**, budget %ds, wall time **%ds**. %s" % (
              tier, budget, wall, ", ".join("%d %s" % (v, k) for k, v in count.items() if v)), "",
          "| job | tier | lane | status | seconds | note |", "|---|---|---|---|---|---|"]
    md += ["| %s | %s | %s | %s | %s | %s |" % (x["id"], x["tier"], x["pool"], x["status"],
                                               x["seconds"], x["note"].replace("|", "/"))
           for x in rows]
    text = "\n".join(md) + "\n"
    with open(os.path.join(outdir, "summary.md"), "w") as f:
        f.write(text)
    with open(os.path.join(ROOT, "results", "suite", "latest.md"), "w") as f:
        f.write(text)
    print("\nwall %.0fs of %ds budget: %s" % (wall, budget, count))
    print("report:", os.path.relpath(os.path.join(outdir, "summary.md"), ROOT))
    return count["FAIL"] + count["TIMEOUT"] == 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--budget", type=int, default=3600, help="seconds (default 3600)")
    ap.add_argument("--tier", choices=TIERS, default="full")
    ap.add_argument("--only", nargs="+", metavar="JOB")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--manifest", default=os.path.join(ROOT, "tests", "suite.json"))
    a = ap.parse_args()
    if a.budget < 2 * GRACE:
        ap.error("budget must be at least %d s" % (2 * GRACE))
    jobs = load(a.manifest)
    if a.only:
        unknown = set(a.only) - {j["id"] for j in jobs}
        if unknown:
            ap.error("unknown job(s): " + ", ".join(sorted(unknown)))
        jobs = [j for j in jobs if j["id"] in a.only]
    else:
        jobs = [j for j in jobs if TIERS.index(j["tier"]) <= TIERS.index(a.tier)]
    if a.list:
        for j in jobs:
            print("%-22s %-8s %-6s est %4ds max %4ds  %s" % (
                j["id"], j["tier"], j["pool"], j["est"], j["max"], " ".join(j["cmd"])))
        return 0
    run_id = time.strftime("%Y%m%d-%H%M%S")
    outdir = os.path.join(ROOT, "results", "suite", run_id)
    os.makedirs(outdir, exist_ok=True)
    r = Runner(jobs, a.budget, outdir, run_id, a.dry_run)
    print("suite %s: %s, %d jobs, budget %ds (hard stop at %ds)\n"
          % (run_id, "only " + " ".join(a.only) if a.only else "tier " + a.tier, len(jobs), a.budget, a.budget - GRACE), flush=True)

    def stop(*_):  # Ctrl-C / SIGTERM: kill everything this run started
        for p in list(RUNNING):
            kill_tree(p)
        for j in jobs:
            docker_kill("%s-%s" % (run_id, j["id"]))
        os._exit(130)
    signal.signal(signal.SIGINT, stop)
    if POSIX:
        signal.signal(signal.SIGTERM, stop)
    r.run()
    label = "only " + " ".join(a.only) if a.only else a.tier
    return 0 if report(r, outdir, a.budget, label) else 1


if __name__ == "__main__":
    sys.exit(main())
