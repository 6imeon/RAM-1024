# RAM-1024: guide for external cryptanalysts

All analysis so far is by the designer. This page is for independent
reviewers: what is claimed, where we think the weak points are, how to
reproduce everything, and public challenges.

## What is claimed

| Claim | Basis |
|---|---|
| Generic: 2^512 collision / preimage / second preimage (classical), ~2^341 (quantum, BHT) | 1024-bit capacity, 1024-bit default output |
| No distinguisher on the full 64-round permutation below 2^1024 | best attacks found reach ≤ 16 of 192 steps (a boomerang) (CRYPTANALYSIS.md) |
| Sound tree mode, MAC, XOF; no length extension | sponge + Sakura-style tree encoding (SPEC.md) |
| RAM-Balloon v2 is memory-hard (all M at once: lanes cross-reference) with data-independent access | Balloon proof, assuming one 64-round permutation call behaves as a random function; T ≥ 3 against depth reduction |
| Constant-time implementation | Valgrind "ctgrind" check |

## Where we would attack first

1. **Backward direction / inside-out.** Inverse G is free on MSB differences
   (F20: 2 backward steps with probability 1), so backward diffusion is
   slower. Best inside-out differential we found: 14 steps at weight ≤ 2048;
   best boomerang 16 steps (a 5-step middle switch at 2^-10, F22). Can a
   better switch (non-MSB β/γ, longer middle) or a rebound beat 16 + 6?
2. **chi3 is an involution** and only 3 of the 4 rows get it each round
   (the skipped row rotates). Are there invariant subspaces or nonlinear
   invariants across a 4-round period?
3. **Trail search is partly proven.** Round 11 proves exact minimum
   weights to 3 steps and proves the inside-out estimates conservative to
   5 steps (SAT, `analysis/trail_bounds.py`). Beyond that the numbers are
   heuristic. Round 12 added Matsui bounding conditions (5-step proofs
   0/12 → 9/12 offsets in the same time); better SAT/MILP encodings for
   6+ steps are welcome.
4. **Constants.** π words, one per column per round, spread diagonally. RX
   cryptanalysis dies within a round here; is there a better rotation amount
   or a related-constant attack?
5. **Parameter block in the capacity.** Mode, rounds, output length, key
   length and node index sit in s[28..31]. Are there related-IV attacks
   between modes (hash/XOF/MAC/leaf/root/password)?
6. **RAM-Balloon compression:** rate = x‖y, capacity = parameter block,
   output = 512 bits of one permutation call, with no feed-forward. Is
   truncation enough here?

## Reduced-round challenges

`python3 tools/challenges.py list` prints them;
`python3 tools/challenges.py check ID HEX…` verifies a solution.

| Kind | Instances (rounds, digest bytes) |
|---|---|
| Collision `C-r-n` | (1,8) (1,16) (2,8) (2,16) (3,8) (3,16) (4,8) (4,16) (6,16) (8,32) |
| Preimage `P-r-n` | (1,4) (1,8) (2,4) (2,8) (3,4) (3,8) (4,8) (6,16) (8,32) |

The 8-byte instances (generic cost 2^32) are within reach of brute force,
so for those only a **cryptanalytic** solution (cheaper than generic) is
interesting. The 16- and 32-byte instances are beyond brute force: any
solution is a real result. Targets are SHA3-512 of a fixed label.

Solved in-house (round 8, SAT/z3): all 1-round instances, in under a
second. 2-round instances defeated the solver at 900 s, while brute force
solved P-2-4 in 29 s, so a 2-round *cryptanalytic* solution would be new.

## Reproduce

```bash
make test                          # C + Python, research lab (~5 s)
make reference                     # KATs regenerated from the Python spec
python3 analysis/trail_search.py   # differential / linear / RX trails
python3 analysis/perm_attack.py v3 # SAC, linear bias, symmetry (inside-out)
python3 analysis/algebraic.py      # zero-sum, exact affine bits
python3 analysis/perm_neural.py    # neural distinguisher on the permutation
python3 analysis/sat_attack.py 900 # SAT/SMT on the challenges (needs z3)
python3 analysis/trail_bounds.py 300 3        # proven trail minima (needs cadical)
python3 analysis/trail_bounds.py check 5 11 3600   # no 5-step trail of weight <= 11
sh tools/crossplatform.sh quick    # 10-job subset, ~1 min once images are cached
sh tools/crossplatform.sh          # 22-job OS/CPU/compiler matrix
FUZZ_SECONDS=3600 sh tools/crossplatform.sh fuzz   # long fuzzing soak
sh tools/ios_check.sh              # iOS (Mac Catalyst + Simulator)
```

Reduced-round instances: `ram1024.ram_hash(..., rounds=r, research=True)`
in Python, or any C build with `-DRAM_RESEARCH`.

## Reporting

Please include the challenge ID or the step count reached, the
complexity, and code. Findings go into CRYPTANALYSIS.md with credit, and
are fixed in the same find → fix → re-test loop as rounds 1–7.
