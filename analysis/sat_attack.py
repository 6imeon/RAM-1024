"""Cryptanalysis round 8: SAT/SMT algebraic attack on the reduced-round
challenges (tools/challenges.py), the way an outside attacker would start.

The r-round hash of a one-block message is modelled exactly in z3 bit-
vectors (64-bit words: modular additions, rotations, XOR, chi, constants,
parameter block, pad10*1). 120 message bytes (960 bits) are free.
  P-r-n : solve  digest_n(m) == target
  C-r-n : solve  digest_n(m1) == digest_n(m2), m1 != m2
Every solution is re-checked with tools/challenges.py (independent code).

    python3 analysis/sat_attack.py [timeout_s]     (needs python3-z3)
"""

import json
import os
import subprocess
import sys
import time

import z3

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import challenges  # noqa: E402
from ramhash import ram1024  # noqa: E402
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _budget import cap, expired, out as out_path  # noqa: E402

M = (1 << 64) - 1


def rotr(x, n):
    return z3.RotateRight(x, n)


def g(s, a, b, c, d):
    s[a] = s[a] + s[b]; s[d] = rotr(s[d] ^ s[a], 32)
    s[c] = s[c] + s[d]; s[b] = rotr(s[b] ^ s[c], 24)
    s[a] = s[a] + s[b]; s[d] = rotr(s[d] ^ s[a], 16)
    s[c] = s[c] + s[d]; s[b] = rotr(s[b] ^ s[c], 63)


def permute(s, rounds):
    rc = ram1024._RC
    for r in range(rounds):
        for c in range(8):
            s[(c & 3) * 8 + c] = s[(c & 3) * 8 + c] ^ rc[r * 8 + c]
        for c in range(8):
            g(s, c, 8 + c, 16 + c, 24 + c)
        for i, k in enumerate(ram1024.RHO):
            s[16 + i] = rotr(s[16 + i], 64 - k)
        for c in range(8):
            g(s, c, 8 + (c + 1) % 8, 16 + (c + 2) % 8, 24 + (c + 3) % 8)
        r0, r1, r2 = [i for i in range(4) if i != r % 4]
        for c in range(8):
            x, y, z = r0 * 8 + c, r1 * 8 + (c + 3) % 8, r2 * 8 + (c + 5) % 8
            X, Y, Z = s[x], s[y], s[z]
            s[x] = X ^ (~Y & Z)
            s[y] = Y ^ (~Z & X)
            s[z] = Z ^ (~X & Y)


def digest_words(msg_words, rounds, n):
    """r-round hash-mode digest of a 120-byte message, as z3 terms."""
    s = [z3.BitVecVal(0, 64) for _ in range(32)]
    s[31] = z3.BitVecVal(ram1024.VERSION_WORD | (ram1024.MODE_HASH << 24) | (rounds << 16), 64)
    s[30] = z3.BitVecVal(n, 64)
    for i in range(15):
        s[i] = s[i] ^ msg_words[i]
    s[15] = s[15] ^ z3.BitVecVal(0x01 | (0x80 << 56), 64)  # pad10*1 of a 120-byte message
    permute(s, rounds)
    ws = list(reversed(s[:(n + 7) // 8]))               # little-endian byte string
    out = z3.Concat(*ws) if len(ws) > 1 else ws[0]
    return z3.Extract(8 * n - 1, 0, out)


def words_to_bytes(model, ws):
    return b"".join(model.eval(w, model_completion=True).as_long().to_bytes(8, "little")
                    for w in ws)


def attack(cid, timeout):
    kind, r, n = cid.split("-")
    r, n = int(r), int(n)
    s = z3.SolverFor("QF_BV")
    s.set("timeout", timeout * 1000)
    m1 = [z3.BitVec("a%d" % i, 64) for i in range(15)]
    d1 = digest_words(m1, r, n)
    if kind == "P":
        t = int.from_bytes(challenges.target(r, n), "little")
        s.add(d1 == z3.BitVecVal(t, 8 * n))
    else:
        m2 = [z3.BitVec("b%d" % i, 64) for i in range(15)]
        s.add(d1 == digest_words(m2, r, n))
        s.add(z3.Or(*[x != y for x, y in zip(m1, m2)]))
    t0 = time.time()
    res = s.check()
    dt = round(time.time() - t0, 1)
    out = {"id": cid, "result": str(res), "seconds": dt}
    if res == z3.sat:
        msgs = [words_to_bytes(s.model(), m1)]
        if kind == "C":
            msgs.append(words_to_bytes(s.model(), m2))
        chk = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "challenges.py"),
                              "check", cid] + [m.hex() for m in msgs],
                             capture_output=True, text=True)
        out["verified"] = chk.returncode == 0
        out["solution"] = [m.hex() for m in msgs]
    print(json.dumps({k: v for k, v in out.items() if k != "solution"}), flush=True)
    return out


def run_isolated(cid, timeout):
    """z3 can ignore its own timeout (e.g. while bit-blasting 3 rounds), so each
    instance runs in a child process that is killed at 1.2 x timeout."""
    import multiprocessing as mp
    ctx = mp.get_context("fork")   # child inherits the z3 model; no pickling
    q = ctx.Queue()
    p = ctx.Process(target=lambda: q.put(attack(cid, timeout)))
    p.start()
    p.join(timeout * 1.2 + 30)
    if p.is_alive():
        p.kill()
        p.join()
        out = {"id": cid, "result": "unknown", "seconds": round(timeout * 1.2 + 30, 1),
               "note": "killed: z3 ignored its timeout"}
        print(json.dumps(out), flush=True)
        return out
    return q.get()


def main():
    timeout = int(sys.argv[1]) if len(sys.argv) > 1 else 600
    ids = sys.argv[2:] or ["P-1-4", "P-1-8", "C-1-8", "P-2-4", "C-2-8", "P-3-4", "C-1-16",
                           "P-2-8"]
    res = []
    for c in ids:
        if expired():
            res.append({"id": c, "result": "skipped", "note": "time budget reached"})
            continue
        # leave room for the 1.2x + 30 s kill margin inside the budget
        res.append(run_isolated(c, cap(min(timeout, (cap(10 ** 9) - 30) / 1.2))))
    with open(out_path("sat_attack.json"), "w") as f:
        json.dump({"timeout_s": timeout, "z3": z3.get_version_string(), "runs": res}, f,
                  indent=1)


if __name__ == "__main__":
    main()
