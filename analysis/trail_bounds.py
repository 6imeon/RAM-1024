"""Proven lower bounds on differential trail weight (cryptanalysis round 11).

The trail search of round 6 (csrc/trail_lab.c) is heuristic: its weights
are upper bounds on the lightest trail. Here the same trail model is given
to a SAT solver (CaDiCaL, as CNF), which either finds a trail of weight <= W or
proves none exists. "unsat at W" is a proof that every characteristic over
those steps has weight >= W + 1, for every nonzero input difference.

Model (identical to trail_lab.c, so the bounds apply to the same trails):
  modular addition  Lipmaa-Moriai: bit 0: a0^b0^c0 = 0; bit i >= 1: if
                    a,b,c agree at i-1 then a_i^b_i^c_i = a_{i-1}; weight =
                    number of bits i < 63 where a_i, b_i, c_i do not agree.
  chi3              exact 8x8 difference table (weights 0, 1, 2).
  rotations, XOR,   linear, no weight; constants vanish from differences.
  iota
A step is 0 = column G + rho, 1 = diagonal G, 2 = chi; the step offset
(0..11) fixes the phase and the chi row that is skipped (round mod 4).

Every trail the solver finds is checked against the real permutation
steps on random pairs when its weight is <= 14 (measured probability must
be >= 2^-w up to sampling noise), which validates the model.

    python3 analysis/trail_bounds.py [timeout_s] [max_steps] [max_w]   (needs cadical)
Writes results/trail_bounds.json.
"""

import json
import os
import random
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
from ramhash._pi import pi_fraction_words  # noqa: E402
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _budget import cap, expired, out as out_path, src  # noqa: E402

# Parallel solver instances (each CaDiCaL is single-threaded).
WORKERS = int(os.environ.get("RAM_THREADS", 0)) or min(12, os.cpu_count() or 4)

M64 = (1 << 64) - 1
RHO = [1, 27, 53, 15, 41, 3, 29, 55, 17, 43, 5, 31, 57, 19, 45, 7]
G_ROT = (32, 24, 16, 63)


def rotr(x, n):
    return ((x >> n) | (x << (64 - n))) & M64


def chi3(x, y, z):
    return x ^ (~y & z & 1), y ^ (~z & x & 1), z ^ (~x & y & 1)


# exact chi3 DDT: weight = 3 - log2(count)
DDT = {}
for d in range(8):
    for v in range(8):
        a = chi3(v & 1, v >> 1 & 1, v >> 2 & 1)
        w = v ^ d
        b = chi3(w & 1, w >> 1 & 1, w >> 2 & 1)
        o = (a[0] ^ b[0]) | (a[1] ^ b[1]) << 1 | (a[2] ^ b[2]) << 2
        DDT[(d, o)] = DDT.get((d, o), 0) + 1
CHI_W = {k: {8: 0, 4: 1, 2: 2}[c] for k, c in DDT.items()}


class CNF:
    """Trail model as CNF (DIMACS ints). A word is a list of 64 variables."""

    def __init__(self):
        self.nv = 0
        self.cl = []
        self.weights = []

    def var(self):
        self.nv += 1
        return self.nv

    def word(self):
        return [self.var() for _ in range(64)]

    def table(self, vs, ok):
        """Forbid every assignment of vs for which ok(bits) is false."""
        for m in range(1 << len(vs)):
            bits = [(m >> i) & 1 for i in range(len(vs))]
            if not ok(bits):
                self.cl.append([-v if b else v for v, b in zip(vs, bits)])

    def xor(self, x, y):
        out = []
        for a, b in zip(x, y):
            c = self.var()
            self.cl += [[-a, -b, -c], [a, b, -c], [a, -b, c], [-a, b, c]]
            out.append(c)
        return out

    @staticmethod
    def rotr(x, n):
        return [x[(i + n) % 64] for i in range(64)]

    def add(self, a, b):
        c = self.word()
        w = [self.var() for _ in range(63)]
        self.weights += w
        self.table([a[0], b[0], c[0]], lambda t: t[0] ^ t[1] ^ t[2] == 0)
        for i in range(63):
            self.table([a[i], b[i], c[i], w[i]],
                       lambda t: t[3] == (not (t[0] == t[1] == t[2])))
        for i in range(1, 64):
            self.table([w[i - 1], a[i], b[i], c[i], a[i - 1]],
                       lambda t: t[0] == 1 or (t[1] ^ t[2] ^ t[3]) == t[4])
        return c

    def G(self, a, b, c, d):
        a = self.add(a, b); d = self.rotr(self.xor(d, a), G_ROT[0])
        c = self.add(c, d); b = self.rotr(self.xor(b, c), G_ROT[1])
        a = self.add(a, b); d = self.rotr(self.xor(d, a), G_ROT[2])
        c = self.add(c, d); b = self.rotr(self.xor(b, c), G_ROT[3])
        return a, b, c, d

    def chi(self, st, r):
        rows = [i for i in range(4) if i != r % 4]
        out = list(st)
        for col in range(8):
            ix = (rows[0] * 8 + col, rows[1] * 8 + (col + 3) % 8, rows[2] * 8 + (col + 5) % 8)
            nw = [self.word() for _ in range(3)]
            for bit in range(64):
                w1, w2 = self.var(), self.var()
                self.weights += [w1, w2]
                vs = [st[ix[k]][bit] for k in range(3)] + [nw[k][bit] for k in range(3)] + [w1, w2]

                def ok(t):
                    d = t[0] | t[1] << 1 | t[2] << 2
                    o = t[3] | t[4] << 1 | t[5] << 2
                    w = CHI_W.get((d, o))
                    return w is not None and t[6] == (w >= 1) and t[7] == (w >= 2)
                self.table(vs, ok)
            for k in range(3):
                out[ix[k]] = nw[k]
        return out

    def step(self, st, a):
        r, t = a // 3, a % 3
        st = list(st)
        if t == 0:
            for c in range(8):
                st[c], st[8 + c], st[16 + c], st[24 + c] = self.G(st[c], st[8 + c], st[16 + c], st[24 + c])
            for i in range(16):
                st[16 + i] = self.rotr(st[16 + i], 64 - RHO[i])
        elif t == 1:
            for c in range(8):
                i = (c, 8 + (c + 1) % 8, 16 + (c + 2) % 8, 24 + (c + 3) % 8)
                st[i[0]], st[i[1]], st[i[2]], st[i[3]] = self.G(*(st[k] for k in i))
        else:
            st = self.chi(st, r)
        return st

    def at_most_matsui(self, xs, k, marks, pre_max, suf_max):
        """sum(xs) <= k as one sequential counter s[i][j] ("xs[0..i] has
        >= j+1 ones"), plus Matsui bounding conditions at step boundaries:
        prefix xs[:b] <= pre_max[b], suffix xs[b:] <= suf_max[b]. Those are
        implied by the bound and the proven minima of shorter trails (a
        trail's tail is itself a trail), so they never cut off a real trail
        (UNSAT stays a proof) but prune the search a lot."""
        n = len(xs)
        if k < 0 or any(v < 0 for v in list(pre_max.values()) + list(suf_max.values())):
            self.cl.append([])  # some part already exceeds the budget
            return
        s = [[self.var() for _ in range(k + 1)] for _ in range(n)]
        self.cl.append([-xs[0], s[0][0]])
        for j in range(1, k + 1):
            self.cl.append([-s[0][j]])
        for i in range(1, n):
            self.cl.append([-xs[i], s[i][0]])
            for j in range(k + 1):
                self.cl.append([-s[i - 1][j], s[i][j]])
                if j:
                    self.cl.append([-xs[i], -s[i - 1][j - 1], s[i][j]])
        self.cl.append([-s[n - 1][k]])
        for b in marks:
            if b in pre_max and pre_max[b] <= k:
                self.cl.append([-s[b - 1][pre_max[b]]])
            q = suf_max.get(b)
            if q is not None:
                for l in range(k + 1 - q):  # total >= l+q+1  =>  prefix >= l+1
                    self.cl.append([-s[n - 1][l + q], s[b - 1][l]])

    def at_most(self, xs, k):
        """Sinz sequential counter: sum(xs) <= k."""
        n = len(xs)
        if k <= 0:
            self.cl += [[-x] for x in xs]
            return
        s = [[self.var() for _ in range(k)] for _ in range(n - 1)]
        self.cl.append([-xs[0], s[0][0]])
        for j in range(1, k):
            self.cl.append([-s[0][j]])
        for i in range(1, n - 1):
            self.cl.append([-xs[i], s[i][0]])
            self.cl.append([-s[i - 1][0], s[i][0]])
            for j in range(1, k):
                self.cl.append([-xs[i], -s[i - 1][j - 1], s[i][j]])
                self.cl.append([-s[i - 1][j], s[i][j]])
            self.cl.append([-xs[i], -s[i - 1][k - 1]])
        self.cl.append([-xs[n - 1], -s[n - 2][k - 1]])


def build(start, nsteps):
    m = CNF()
    st0 = [m.word() for _ in range(32)]
    m.cl.append([v for w in st0 for v in w])  # nonzero input difference
    st = st0
    m.marks = []
    for k in range(nsteps):
        st = m.step(st, (start + k) % 12)
        m.marks.append(len(m.weights))
    m.start, m.nsteps = start, nsteps
    return m, st0, st


# ---- real steps (values) for validating found trails ----
RC = pi_fraction_words(8 * 4)


def G_val(v, a, b, c, d):
    v[a] = (v[a] + v[b]) & M64; v[d] = rotr(v[d] ^ v[a], 32)
    v[c] = (v[c] + v[d]) & M64; v[b] = rotr(v[b] ^ v[c], 24)
    v[a] = (v[a] + v[b]) & M64; v[d] = rotr(v[d] ^ v[a], 16)
    v[c] = (v[c] + v[d]) & M64; v[b] = rotr(v[b] ^ v[c], 63)


def real_step(v, a):
    r, t = a // 3, a % 3
    if t == 0:
        for c in range(8):
            v[(c & 3) * 8 + c] ^= RC[r * 8 + c]
        for c in range(8):
            G_val(v, c, 8 + c, 16 + c, 24 + c)
        for i in range(16):
            v[16 + i] = rotr(v[16 + i], 64 - RHO[i])
    elif t == 1:
        for c in range(8):
            G_val(v, c, 8 + (c + 1) % 8, 16 + (c + 2) % 8, 24 + (c + 3) % 8)
    else:
        rows = [i for i in range(4) if i != r % 4]
        for c in range(8):
            ix = (rows[0] * 8 + c, rows[1] * 8 + (c + 3) % 8, rows[2] * 8 + (c + 5) % 8)
            X, Y, Z = (v[k] for k in ix)
            v[ix[0]] = X ^ (~Y & Z & M64)
            v[ix[1]] = Y ^ (~Z & X & M64)
            v[ix[2]] = Z ^ (~X & Y & M64)


def measure(din, dout, start, nsteps, pairs=1 << 12):
    hit = 0
    rng = random.Random(1)
    for _ in range(pairs):
        x = [rng.getrandbits(64) for _ in range(32)]
        y = [a ^ b for a, b in zip(x, din)]
        for k in range(nsteps):
            real_step(x, (start + k) % 12)
            real_step(y, (start + k) % 12)
        hit += all((a ^ b) == c for a, b, c in zip(x, y, dout))
    return hit / pairs


# Proven per-offset minima {kind: {(start, steps): weight_ge}}, for the
# Matsui conditions. Loaded from earlier runs and extended as bounds are
# proven in this run. RAM_MATSUI=0 turns the conditions off (for timing).
MATSUI = os.environ.get("RAM_MATSUI", "1") != "0"
KNOWN = {"diff": {}, "lin": {}}


def learn(kind, start, steps, w):
    key = (start % 12, steps)
    KNOWN[kind][key] = max(KNOWN[kind].get(key, 0), w)


def _load_known():
    for kind, name in (("diff", "trail_bounds.json"), ("lin", "trail_bounds_linear.json")):
        for path in {os.path.join(ROOT, "results", name), src(name)}:
            try:
                for b in json.load(open(path))["bounds"]:
                    learn(kind, b["start"], b["steps"], b["weight_ge"])
            except (OSError, ValueError, KeyError):
                pass
    for path in {os.path.join(ROOT, "results", "trail_bounds_check.json"),
                 src("trail_bounds_check.json")}:
        try:
            for r in json.load(open(path)):
                if r["result"] == "unsat":
                    learn("diff", r["start"], r["steps"], r["W"] + 1)
        except (OSError, ValueError, KeyError):
            pass


def matsui_limits(m, W):
    """Prefix/suffix weight limits at each internal step boundary."""
    kind = "lin" if isinstance(m, LinCNF) else "diff"
    B = lambda st, n: KNOWN[kind].get((st % 12, n), 0)
    pre, suf = {}, {}
    for j in range(1, m.nsteps):
        b = m.marks[j - 1]  # weights of steps 0..j-1 are xs[:b]
        pre[b] = W - B(m.start + j, m.nsteps - j)
        suf[b] = W - B(m.start, j)
    return m.marks[:-1], pre, suf


def solve(m, W, timeout):
    """(result, assignment) with result 'sat', 'unsat' or 'unknown'."""
    if expired():
        return "unknown", None
    nv0, ncl0 = m.nv, len(m.cl)
    if MATSUI and getattr(m, "marks", None):
        m.at_most_matsui(m.weights, W, *matsui_limits(m, W))
    else:
        m.at_most(m.weights, W)
    with tempfile.NamedTemporaryFile("w", suffix=".cnf", delete=False) as f:
        f.write("p cnf %d %d\n" % (m.nv, len(m.cl)))
        for c in m.cl:
            f.write(" ".join(map(str, c)) + " 0\n")
        path = f.name
    m.nv, m.cl = nv0, m.cl[:ncl0]
    try:
        r = subprocess.run(["cadical", "-q", "-t", str(cap(timeout)), path],
                           capture_output=True, text=True)
    finally:
        os.unlink(path)
    if "s SATISFIABLE" in r.stdout:
        val = set()
        for line in r.stdout.splitlines():
            if line.startswith("v "):
                val.update(int(x) for x in line[2:].split() if int(x) > 0)
        return "sat", val
    return ("unsat" if "s UNSATISFIABLE" in r.stdout else "unknown"), None


def words(val, ws):
    return [sum(1 << i for i, v in enumerate(w) if v in val) for w in ws]


def bound(start, nsteps, lo, hi, timeout):
    """Exact minimum weight in [lo, hi], or the best proven lower bound.
    Exponential then binary search; unsat answers are proofs."""
    m, st0, st = build(start, nsteps)
    proven, found, val_found = lo - 1, None, None
    W, stepw = lo, 1
    while found is None and W <= hi:
        res, val = solve(m, W, timeout)
        if res == "sat":
            found, val_found = W, val
        elif res == "unsat":
            proven = W
            W, stepw = W + stepw, stepw * 2
        else:
            break
    while found is not None and found - proven > 1:
        mid = (found + proven) // 2
        res, val = solve(m, mid, timeout)
        if res == "sat":
            found, val_found = mid, val
        elif res == "unsat":
            proven = mid
        else:
            break
    out = {"start": start, "steps": nsteps, "weight_ge": proven + 1}
    if found is not None:
        w = sum(1 for v in m.weights if v in val_found)
        out["trail_found"] = w
        out["exact"] = w == proven + 1
        if w <= 10:
            out["empirical_p"] = measure(words(val_found, st0), words(val_found, st), start, nsteps)
    return out


def check(nsteps, W, timeout):
    """Is there a trail over nsteps (any of the 12 offsets) with weight <= W?
    All 'unsat' = proof that every nsteps-step trail has weight >= W + 1."""
    def one(start):
        t0 = time.time()
        m, st0, st = build(start, nsteps)
        res, val = solve(m, W, timeout)
        r = {"start": start, "steps": nsteps, "W": W, "result": res,
             "seconds": round(time.time() - t0, 1), "matsui": MATSUI}
        if res == "sat":
            r["weight"] = sum(1 for v in m.weights if v in val)
        return r
    with ThreadPoolExecutor(WORKERS) as ex:
        rs = list(ex.map(one, range(12)))
    for r in rs:
        print(json.dumps(r), flush=True)
    return rs


# ---------------- linear trails (round 11b) ----------------
# Masks on every word, propagated through each operation as relations.
# a <- a + b: Wallen: with s = u^v^w, z_63 = 0, z_i = z_{i+1} ^ s_{i+1},
#   correlation != 0 iff (u^v) <= z and (u^w) <= z; weight = HW(z).
#   Here u = new mask on a, v = old mask on a, w = (old mask on b) ^ (new
#   mask on b), since b is also passed on (branch).
# d <- (d ^ a) >>> r: linear; new d mask = old d mask rotated, new a mask
#   = old a ^ old d (a was both kept and XORed in).
# chi3: exact 3-bit LAT, weight = 3 - log2 |LAT|.
LAT = {}
for a_ in range(8):
    for b_ in range(8):
        tot = 0
        for v in range(8):
            o = chi3(v & 1, v >> 1 & 1, v >> 2 & 1)
            ov = o[0] | o[1] << 1 | o[2] << 2
            tot += (-1) ** (bin(a_ & v).count("1") + bin(b_ & ov).count("1"))
        if tot:
            LAT[(a_, b_)] = {8: 0, 4: 1, 2: 2}[abs(tot)]


class LinCNF(CNF):
    def add_mask(self, u, v, w):
        z = [self.var() for _ in range(63)] + [None]
        self.weights += z[:63]
        for i in range(63):
            if i == 62:
                self.table([z[i], u[63], v[63], w[63]], lambda t: t[0] == (t[1] ^ t[2] ^ t[3]))
            else:
                self.table([z[i], z[i + 1], u[i + 1], v[i + 1], w[i + 1]],
                           lambda t: t[0] == (t[1] ^ t[2] ^ t[3] ^ t[4]))
        for i in range(64):
            if i < 63:
                self.table([u[i], v[i], w[i], z[i]],
                           lambda t: t[3] == 1 or (t[0] == t[1] and t[0] == t[2]))
            else:  # z_63 = 0
                self.table([u[i], v[i], w[i]], lambda t: t[0] == t[1] and t[0] == t[2])

    def op_add(self, M, a, b):
        ua, ub = self.word(), self.word()
        self.add_mask(ua, M[a], self.xor(M[b], ub))
        M[a], M[b] = ua, ub

    def op_xrot(self, M, d, a, r):
        nd = [M[d][(i + r) % 64] for i in range(64)]
        M[a] = self.xor(M[a], M[d])
        M[d] = nd

    def G(self, M, a, b, c, d):
        self.op_add(M, a, b); self.op_xrot(M, d, a, G_ROT[0])
        self.op_add(M, c, d); self.op_xrot(M, b, c, G_ROT[1])
        self.op_add(M, a, b); self.op_xrot(M, d, a, G_ROT[2])
        self.op_add(M, c, d); self.op_xrot(M, b, c, G_ROT[3])

    def chi(self, M, r):
        rows = [i for i in range(4) if i != r % 4]
        for col in range(8):
            ix = (rows[0] * 8 + col, rows[1] * 8 + (col + 3) % 8, rows[2] * 8 + (col + 5) % 8)
            nw = [self.word() for _ in range(3)]
            for bit in range(64):
                w1, w2 = self.var(), self.var()
                self.weights += [w1, w2]

                def ok(t):
                    a_ = t[0] | t[1] << 1 | t[2] << 2
                    b_ = t[3] | t[4] << 1 | t[5] << 2
                    w = LAT.get((a_, b_))
                    return w is not None and t[6] == (w >= 1) and t[7] == (w >= 2)
                self.table([M[ix[k]][bit] for k in range(3)] + [nw[k][bit] for k in range(3)]
                           + [w1, w2], ok)
            for k in range(3):
                M[ix[k]] = nw[k]

    def step(self, M, a):
        r, t = a // 3, a % 3
        M = list(M)
        if t == 0:
            for c in range(8):
                self.G(M, c, 8 + c, 16 + c, 24 + c)
            for i in range(16):
                M[16 + i] = [M[16 + i][(j + 64 - RHO[i]) % 64] for j in range(64)]
        elif t == 1:
            for c in range(8):
                self.G(M, c, 8 + (c + 1) % 8, 16 + (c + 2) % 8, 24 + (c + 3) % 8)
        else:
            self.chi(M, r)
        return M


def build_linear(start, nsteps):
    m = LinCNF()
    st0 = [m.word() for _ in range(32)]
    m.cl.append([v for w in st0 for v in w])  # nonzero input mask
    st = st0
    m.marks = []
    for k in range(nsteps):
        st = m.step(st, (start + k) % 12)
        m.marks.append(len(m.weights))
    m.start, m.nsteps = start, nsteps
    return m, st0, st


def measure_lin(uin, uout, start, nsteps, n=1 << 14):
    rng = random.Random(2)
    acc = 0
    par = lambda ws, ms: sum(bin(x & y).count("1") for x, y in zip(ws, ms)) & 1
    for _ in range(n):
        x = [rng.getrandbits(64) for _ in range(32)]
        p0 = par(x, uin)
        for k in range(nsteps):
            real_step(x, (start + k) % 12)
        acc += 1 - 2 * (p0 ^ par(x, uout))
    return abs(acc) / n


def bound_linear(start, nsteps, lo, hi, timeout):
    m, st0, st = build_linear(start, nsteps)
    proven, found, val_found = lo - 1, None, None
    W, stepw = lo, 1
    while found is None and W <= hi:
        res, val = solve(m, W, timeout)
        if res == "sat":
            found, val_found = W, val
        elif res == "unsat":
            proven = W
            W, stepw = W + stepw, stepw * 2
        else:
            break
    while found is not None and found - proven > 1:
        mid = (found + proven) // 2
        res, val = solve(m, mid, timeout)
        if res == "sat":
            found, val_found = mid, val
        elif res == "unsat":
            proven = mid
        else:
            break
    out = {"start": start, "steps": nsteps, "weight_ge": proven + 1}
    if found is not None:
        w = sum(1 for v in m.weights if v in val_found)
        out["trail_found"] = w
        out["exact"] = w == proven + 1
        if w <= 6:
            out["measured_corr"] = measure_lin(words(val_found, st0), words(val_found, st),
                                               start, nsteps)
            out["predicted_corr"] = 2.0 ** -w
    return out


def main_linear(timeout, max_steps, hi):
    out, prev = [], {s: 0 for s in range(12)}
    for nsteps in range(1, max_steps + 1):
        if expired():
            print("time budget reached before linear step %d" % nsteps, flush=True)
            break
        with ThreadPoolExecutor(WORKERS) as ex:
            rs = list(ex.map(lambda s: bound_linear(s, nsteps, prev[s], hi, timeout), range(12)))
        for r in rs:
            print(json.dumps(r), flush=True)
            prev[r["start"]] = r["weight_ge"]
            learn("lin", r["start"], nsteps, r["weight_ge"])
        out += rs
        print("linear, steps %d: every trail has weight >= %d (proven, all 12 offsets)"
              % (nsteps, min(r["weight_ge"] for r in rs)), flush=True)
        with open(out_path("trail_bounds_linear.json"), "w") as f:
            json.dump({"timeout_s": timeout, "solver": "CaDiCaL", "bounds": out}, f, indent=1)


def main():
    _load_known()
    if len(sys.argv) > 1 and sys.argv[1] == "linear":
        return main_linear(int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]))
    if len(sys.argv) > 1 and sys.argv[1] == "check":
        k, W, timeout = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
        rs = check(k, W, timeout)
        path = out_path("trail_bounds_check.json")
        old = json.load(open(path)) if os.path.exists(path) else []
        old = [o for o in old if not (o["steps"] == k and o["W"] == W)] + rs
        json.dump(old, open(path, "w"), indent=1)
        print("steps %d, weight <= %d: %s" % (k, W, "PROVEN IMPOSSIBLE" if all(
            r["result"] == "unsat" for r in rs) else
            ", ".join(sorted({r["result"] for r in rs}))), flush=True)
        return
    timeout = int(sys.argv[1]) if len(sys.argv) > 1 else 600
    max_steps = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    hi = int(sys.argv[3]) if len(sys.argv) > 3 else 128
    out, prev = [], {s: 0 for s in range(12)}
    for nsteps in range(1, max_steps + 1):
        if expired():
            print("time budget reached before step %d" % nsteps, flush=True)
            break
        with ThreadPoolExecutor(WORKERS) as ex:
            rs = list(ex.map(lambda s: bound(s, nsteps, prev[s], hi, timeout), range(12)))
        for r in rs:
            print(json.dumps(r), flush=True)
            prev[r["start"]] = r["weight_ge"]
            learn("diff", r["start"], nsteps, r["weight_ge"])
        out += rs
        mn = min(r["weight_ge"] for r in rs)
        print("steps %d: every trail has weight >= %d (proven, all 12 offsets)" % (nsteps, mn),
              flush=True)
        with open(out_path("trail_bounds.json"), "w") as f:
            json.dump({"timeout_s": timeout, "solver": "CaDiCaL", "bounds": out,
                       "min_by_steps": {str(k): min(r["weight_ge"] for r in out if r["steps"] == k)
                                        for k in range(1, nsteps + 1)}}, f, indent=1)


if __name__ == "__main__":
    main()
