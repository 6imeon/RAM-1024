# RAM-1024 cryptanalysis log

The method: attack the design the way an external reviewer would, fix
every finding, then re-run the whole attack suite on the fixed version and
look again. Each round below lists what was attacked, what was found, the
fix, and the re-measured result. All scripts are in `analysis/`, all raw
data in `results/`.

"Steps" are thirds of a round (iota + column-G [+ rho], diagonal-G, chi).
"Reach" = the last step at which an attack still tells the permutation
apart from random. "Inside-out" = forward reach + backward reach — the
setting of zero-sum, boomerang and rebound attacks, which start in the
middle of the permutation and run both ways.

## Round 1 — permutation-level attacks (full 2048-bit state, both directions)

Earlier testing only varied 512 message bits, forward. A reviewer gets the
whole state and the inverse permutation (`csrc/perm_lab.c`,
`analysis/perm_attack.py`).

| Finding | Severity | Evidence |
|---|---|---|
| **F1** Backward diffusion much slower than forward: 7 steps vs 4. Inside-out reach **11 steps (3.67 rounds)**, not the 1.33 rounds used before. | Medium: real margin ~2.7× smaller than claimed | the top input bits (63, 62, …) and the bottom output bits (0, 1, 2) are the slowest. Subtraction carries in G⁻¹ only move upward |
| **F2** Column-shift symmetry: P⁻¹ commutes with shifting every row by k columns for **6 backward steps** | Low–medium: the raw material of slide/symmetry attacks | constants touched row 0 only |
| **F3** chi3 is an involution (its own inverse) | Informational | exhaustive check |
| **F4** C API silently truncated MAC keys > 128 bytes → two different keys gave the same tag | **Bug** | `tests/test_ram1024.py::test_long_mac_keys_not_truncated` |
| **F5** Key material wiped with plain `memset` (removable by the optimizer) | Hardening | code review |
| **F6** Invalid parameters (rounds ∉ 1…64) silently clamped | Bug-prone API | code review |

**Design exploration** (`analysis/explore_variants.py`) — candidate fixes
measured, not guessed:

| Variant | Inside-out reach | Column-shift reach | Cost |
|---|---|---|---|
| v2 baseline | 11 | 6 | — |
| constants spread diagonally over all rows | 11 | 3 | free |
| + ρ (rows 2–3) after chi | 11 | 2 | +9% |
| **+ ρ (rows 2–3) mid-round** | **10** | **1** | **+9%** |
| + ρ (all words) mid-round | 10 | 0 | +19% |
| word shuffles (row rotation, cross-row) | 11 | 3 | free — no effect on F1 |

**Fixes → v3:** diagonal constants; ρ rotations of rows 2–3 after the
column step; MAC keys absorbed in full; volatile wipe; invalid parameters
rejected with −1. Version word bumped to `RAM\x03`.

**Re-measured:** inside-out reach 11 → **10 steps**; column-shift
symmetry 6 → **1 step**. The rest of F1 is inherent to ARX (G⁻¹) and is
covered by the margin.

## Round 2 — algebraic attacks and second code review

* **Inside-out zero-sum** (full-state cubes up to 2^16, four cube
  strategies incl. low-bit cubes; `analysis/algebraic.py`): forward 3
  steps, backward 6, so **9 steps**. That's inside the round-1 reach, so
  there's no new weakness.
* **Exactly affine output bits** (GF(2) elimination over 2300 samples):
  forward 0 after 1 step; backward 32 after 1 step (the known
  "LSB of a subtraction is linear" ARX property), **0 after 2 steps**.
  Inside the round-1 reach.
* **Code review findings, all fixed:**
  * **F7** OOM: `malloc` unchecked in tree/GPU paths (crash). Now falls
    back to the constant-memory stream (same digest).
  * **F8** Downgrade: `ramhash.verify()` silently accepted SHA-256 digests.
    Now only with `allow_legacy=True`.
  * **F9** DoS: `verify_password()` trusted the PBKDF2 iteration count in
    the stored string. Now capped at 10M.
  * **F10** `verify()` raised on malformed input. Now returns False.
  * **F11** Quadratic buffering in the Python reference. Now `bytearray`.

## Round 3 — constants and key policy

* **F12** The ρ table was not given by any stated rule ("nothing up my
  sleeve" failure; one entry broke the triangular-number pattern it
  seemed to follow). Three documented rules were measured; all reach 10 /
  column-shift 1. Adopted **ρ_j = 2·(13·j mod 32) + 1**: sixteen distinct
  odd amounts, never byte-aligned against G's rotations.
* **F13** MAC mode accepted empty/short keys (an "unkeyed MAC"). Now
  ≥ 16 bytes, enforced in C and Python.

## Round 4 — the margin methodology itself

* **F14** The margin calibration compared RAM's *forward-only* lab reach
  with published BLAKE2b attacks that are *inside-out*. Fixed by
  measuring BLAKE2b's permutation the same way (`csrc/b2perm_lab.c`):
  forward 3 half-rounds, backward 6, so **4.5 rounds** inside-out, against
  RAM-1024's **3.33 rounds**. RAM-1024 gives an attacker less, despite
  having twice the state.
  * Like-for-like multiplier: 8.5 / 4.5 = 1.89, so RAM expert reach is
    6.3 rounds and the margin **10.2×**.
  * Forward-only model: **8.5×**.
  * The report headlines the smaller (8.5×).
* **F15** (found in my own test harness): with ~4M cells per test, pure
  noise peaks at |z| ≈ 5.3 ± 0.3, so a 6.0 cut-off produced isolated false
  "breaks" (forward SAC step 9, linear step 6), which inflated a reach to
  9 + 6. Fixed: every flagged step must repeat on an independent sample.
  Both blips vanished (5.1, 5.5).

## Round 5 — AI attacker in its strongest setting

Neural distinguisher on the permutation itself, full-state differences,
both directions, input bit chosen where SAC is most biased (600k pairs,
MLP 2048→512→256; `analysis/perm_neural.py`):

| Direction | Broken at | Not broken at |
|---|---|---|
| forward | 4 steps (acc 0.986) | 5, 6 |
| backward | 6 steps (acc 1.000) | 7, 8 |

Exactly the round-1 boundary (4 + 6 = 10 steps). **No new finding.**

## Round 6 — differential trails, implementation attacks, misuse, portability

### Differential trail search (`csrc/trail_lab.c`, `analysis/trail_search.py`)

The standard attack on ARX designs: search for high-probability
differential characteristics, step by step, both directions. Modular
additions use the exact XOR-carry model (Lipmaa–Moriai, optimised per
addition by a 2-state Viterbi pass); chi uses its exact 3-bit difference
table. Starts: all 2048 single-bit differences and all 496 pairs of word
MSBs (the cheapest differences through addition), at all 12 step offsets,
8 randomised restarts each. Short trails were replayed on the real
permutation with 2^20 random pairs and matched the model (2 forward steps:
predicted 2^-2, measured 0.25; 3 backward steps: predicted 2^-10, measured
0.00097).

| Steps | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 12 |
|---|---|---|---|---|---|---|---|---|---|---|
| best forward weight | 0 | 2 | 28 | 86 | 259 | 737 | **1305** | **2287** | 3439 | 6715 |
| best backward weight | 0 | 0 | 10 | 33 | 81 | 292 | 596 | **1172** | **2238** | 5421 |

* **F20** (structural, informational): a single MSB difference passes
  **2 backward steps with probability 1** (the inverse G is free on
  MSBs, and the chi step skips one row). This is F1 seen as a trail.
  Covered by the margin; it is the same property every ARX design has.
* Inside-out (forward + backward from a free middle state): the best
  combination still above 2^-1024 covers **12 steps**; above 2^-2048,
  **14 steps (4.67 rounds)**. Adding the customary 2 rounds for rebound /
  message modification in the middle gives **6.67 rounds** reachable,
  so a **9.6×** margin. That is the third independent margin estimate
  (forward calibration 8.5×, inside-out calibration 10.2×), and all
  three agree.

### Implementation attacks

* **Constant time** (`csrc/check/ct_test.c`): the Valgrind "ctgrind"
  method, with every key, message and password byte marked undefined.
  Memcheck flags any branch or memory address derived from a secret. MAC
  (5 key lengths × 6 message lengths, one-shot and streaming), tag
  comparison (`ram_verify`), XOF, tree hashing and RAM-Balloon are all
  clean under gcc `-O2`, `-O3`, `-O2` without SIMD, and `-Os` without
  threads. **No finding.** The check is known to work: in an early
  version of the test the salt buffer was still marked secret, and
  Memcheck flagged exactly the Balloon neighbour lookup (which by design
  is indexed by the public salt).
* **Fuzzing** (`csrc/check/fuzz_ram.c`, libFuzzer + ASan + UBSan):
  one-shot vs streaming (fuzzer-chosen splits) vs multithreaded tree, for
  all modes, including > 16 KiB tree inputs; 201,319 runs, no crash, no
  disagreement, no memory error. (The first run's crash was in the
  harness itself: it expected a MAC with an empty key to be accepted.)
* **Sanitizers**: the full conformance suite under ASan+UBSan (with and
  without SIMD) and ThreadSanitizer (tree threads): clean.

### Misuse and code review

* **F16** The public API accepted reduced-round instances (`rounds=1`),
  which the lab shows are trivially broken. A caller could ask for an
  insecure hash and get one without warning. **Fix:** production builds
  accept only 64 rounds; reduced rounds need a `-DRAM_RESEARCH` build or
  `research=True` in Python.
* **F17** Hash and MAC outputs could be truncated to 1 byte. **Fix:**
  hash ≥ 32 bytes, MAC tag ≥ 16 bytes (XOF unrestricted, as its output
  is the caller's to size).
* **F18** Password hashing used PBKDF2, which is not memory-hard and so
  cheap to attack on GPUs/ASICs. Password cracking is where real
  hashes actually fall. **Fix:** RAM-Balloon (SPEC.md), Balloon hashing on
  the RAM-1024 permutation: memory-hard (16 MiB default), data-independent
  memory access (constant-time check above), all blocks wiped, stored
  parameters capped (no DoS via planted hashes). PBKDF2 hashes still
  verify and are flagged by `needs_rehash_password`.
* **F19** Windows: `WaitForMultipleObjects` waits for at most 64 handles.
  On a machine with > 64 cores the wait would fail and the tree hash
  would read chaining values before the threads had written them (wrong
  digest, use of uninitialised memory). **Fix:** wait per thread.

### Tree mode soundness (argument)

Bertoni et al.'s sufficient conditions for a sound tree hash mode
(*Sufficient conditions for sound tree and sequential hashing modes*,
2014):
1. **Tree-decodable.** The root input is a whole number of fixed-size
   1024-bit CVs followed by a fixed-width le64(n), so it parses uniquely.
2. **Message-complete.** Every chunk is hashed by exactly one leaf and
   the leaf index is bound in its IV.
3. **Final-node separable.** Leaf, root and plain-hash nodes have
   distinct modes in the capacity IV.

The same holds for the parameter block: different (mode, rounds, outlen,
keylen, node) give different IVs in the hidden capacity, so the inner
functions are independent.

### Portability (`tools/crossplatform.sh`)

The C library was made strictly portable: C99 with no required
extensions, POSIX/Win32/no threads, explicit little-endian I/O, and
`ram_test` checks known-answer vectors without needing Python. It passes on:

| Platform | Notes |
|---|---|
| macOS arm64 (clang) | + Metal GPU path |
| Linux arm64, x86-64, riscv64, ppc64le (gcc) | + Python suite against the C library |
| Linux **s390x (big-endian)** | identical digests |
| Linux i386 (32-bit) | |
| Alpine (musl libc, clang) | |
| Windows x64 and x86 (MinGW, run under Wine) | Win32 threads, DLL |
| TCC (no GCC extensions, no SIMD) | |
| strict `-std=c99 -pedantic -Wconversion -Wsign-conversion -Werror` | gcc and clang, all build options |
| CMake build + ctest | |
| `pip install` with and without a C compiler | builds `_libram` / pure-Python fallback |
| Android (bionic libc, Termux) | C library + Python |
| Windows x64 **MSVC ABI** (Microsoft CRT/SDK via xwin, clang-cl, `/W4 /WX`) | library warning-free at MSVC level 4; DLL exports all 17 API functions |
| **FreeBSD 15.0** arm64 (official VM image, QEMU) | system clang 19, `-Werror` |
| **OpenBSD 7.9** arm64 (autoinstall, QEMU) | system clang, `-Werror` |

**F21** (portability/performance): on CPUs without 128-bit integer SIMD
(plain i386, riscv64 without V) GCC split the vector code into scalar
code. That took about 10 minutes to compile and ran slower than the scalar
path. **Fix:** vector lanes only where the CPU has real SIMD.

iOS: the iOS 27.0 Simulator (platform 7 binary) and Mac Catalyst (iOS ABI)
pass all vectors (`tools/ios_check.sh`). Microsoft's own compiler,
`cl.exe` 19.51 (msvc-wine, under Wine), builds the library warning-free at
`/W4 /WX` with no source changes and passes all vectors in 3 build
configurations (`windows-x64-cl` job).

## Round 7 — linear, differential-linear and rotational-XOR trails

Same tool (`csrc/trail_lab.c`, `analysis/trail_search.py`), new attack
families:

* **Linear trails.** Masks propagate backwards through each step.
  Additions use Wallén's exact correlation (±2^-HW(z), with z = Mᵀ(u⊕v⊕w)),
  picking the lightest masks per addition by a Viterbi pass; chi uses its
  exact 3-bit LAT. Starts: all single-bit output masks and all pairs of
  word LSBs, at all 12 offsets, 8 restarts. The short trails were replayed
  on the real permutation (2 steps: predicted correlation 2^-2, measured
  0.25). Best correlation weight per number of steps:

  | Steps | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 |
  |---|---|---|---|---|---|---|---|---|---|---|---|---|
  | linear weight | 0 | 2 | 29 | 81 | 245 | 717 | 1111 | 1710 | 2384 | 2838 | 3518 | 4172 |

  A correlation of 2^-w needs about 2^(2w) data. Beyond the capacity bound
  (data > 2^1024) from **6 steps**; beyond the entire codebook (data
  > 2^2048) from **7 steps**.
* **Differential-linear** (a differential of weight w_d then a linear
  trail of weight w_l, data ≈ 2^(2w_d + 4w_l)): at most **10 steps**
  (5 + 5) below 2^2048.
* **Rotational-XOR** (pairs x and (x <<< 1) ⊕ D, Ashur–Liu). Rotations,
  XOR and chi preserve RX differences exactly; each π constant injects
  (c <<< 1) ⊕ c, and every addition costs ≥ 1.415 bits even when inactive
  (90.6 bits per round). The attacker may cancel the first injection with
  a chosen starting D. Best RX weight, forward: 45, 91, 91, 921, 2143, 3025 …; backward: 0, 45, 91, 377, 707, 1613 ….
  Inside-out below 2^2048: **9 steps**. The dense constants in every
  column of every round kill rotational structure within one round in
  each direction.

**No finding.** Every family stays inside the inside-out differential
reach of 14 steps (round 6), so the 9.6× trail-based margin stood (until the round-9 boomerang, F22: 8.7×).

## Round 8 — SAT/SMT algebraic attack on the challenges

`analysis/sat_attack.py` encodes the reduced-round hash (full sponge: parameter
block, padding, permutation, truncation) as bit-vector equations for z3 and asks
for a preimage or a collision on the public challenges of REVIEW.md. Every
solution is re-checked with `tools/challenges.py`. Time limit 900 s each.

| Rounds | Instances | Result |
|---|---|---|
| 1 | P-1-4, P-1-8, C-1-8, C-1-16 | all **solved** in ≤ 0.4 s, all verified |
| 2 | P-2-4, P-2-8, C-2-8, C-2-16 | no answer in 900 s |
| 3 | P-3-4 | no answer after 41 min (z3 stuck before search; stopped by hand) |

For comparison, plain brute force solved P-2-4 (a 32-bit preimage) in 29 s on
12 cores. So from 2 rounds on, the solver is already **worse than generic**.

One round (3 steps) falling to algebra matches the exact-linearity and
SAC results: one round is low-degree and leaves most words untouched. At 2
rounds the degree and the number of mixed additions blow up the formula.
**No finding**; 2 of 64 rounds is far inside the 14-step trail reach.

## Round 9 — boomerangs (the backward direction, REVIEW.md item 1)

`./build/trail_search boomerang R OFFSET` (run on all 12 offsets by
`analysis/trail_search.py`). The permutation is split as E1 ∘ S ∘ E0:

* E0: a trail run backward from β, and E1: a trail run forward from γ.
  Both use the round-6 model (exact carries and chi table).
* S: a middle of m = 1–6 steps, the "switch". Its return probability is
  **measured** on the real permutation, not modelled, so ladder, BCT and
  free-switch effects of ARX are counted in full. A quartet is
  x, x ⊕ β → S → ⊕ γ on both → S⁻¹, and it returns if the two results
  still differ by β.
* β, γ range over 560 candidates: every single MSB, every single LSB and
  every pair of MSBs.
* Cost of a quartet: switch + 2·w(E0) + 2·w(E1).

Measured switches (12 offsets × 560² pairs): one middle step returns for
almost every pair, much of the time with probability ≈ 1. The return rate
falls with each step added; by 5 middle steps the best switch costs about
2^-10.

**F22 (finding).** The best boomerang has a 6-step top trail (weight 381),
a 5-step switch (2^-10.4, re-measured over 2^16 quartets) and a 5-step
bottom trail (weight 388). That is **16 steps** at quartet weight 1549 ≤
2048, two more than the 14-step inside-out differential of round 6. Below
2^1024 it reaches 14 steps, against 12 for the differential.

The cause is F20 again. Backward diffusion is slow, so a long stretch in
the middle costs almost nothing when it is crossed in both directions, and
the boomerang turns that into steps.

Margin: 16 + 6 steps (2 free rounds for rebound) = 22 steps = 7.33
rounds, so the trail-based margin is **8.7×** (was 9.6×). The headline
is the smallest of the three estimates and stays at **8.5×**. No design
change: 64 rounds still cover 176 of 192 steps beyond any attack found.

**Wider search (9b).** `boomerang2` uses all 2544 starting differences of
round 6 (every single bit, every MSB pair). For each target length and
split it pairs the 48 lightest top trails with the 48 lightest bottom
trails, and measures each switch. Best quartet weight by length: 15 steps
1147, 16 steps 2133, 17 steps 3123, 18 steps 4279. No boomerang
reaches 17 steps below 2^2048 (the best one is 1.5× over), so 16 steps is
stable and does not depend on the narrow first candidate set.

**Decision: no design change.** F22 lowers the trail-based estimate to
8.7×, above the 8.5× headline, and 17 steps is far out of reach. Changing
the permutation now would reset every vector and platform result for a
margin the headline does not need. It is the first thing to revisit if an
external reviewer pushes the boomerang further.

Tool bug found while validating: the per-offset seed zeroed the xorshift
RNG at offset 0, so every "random" quartet was the zero state and every
switch looked free. An independent re-measurement caught it, and the
seed is now forced nonzero. The SAT driver was also fixed: z3 ignored
its own timeout on 3 rounds, so each instance now runs in a child
process that is killed on overrun.

## Round 10 — independent review (three fresh reviewers)

Three reviewers with no part in the design (separate agents, given only
the repository) attacked it in parallel: a cryptanalyst, an
implementation auditor, and an implementer working from SPEC.md alone.

**Spec reimplementation.** Written from SPEC.md only (π constants
derived independently): **88/88** hash vectors and **5/5** RAM-Balloon
vectors matched, as did random cross-checks against the Python and C
libraries. Ten spec defects were reported (KAT input rule only in the
generator, reduced-round convention, rotation direction, simultaneous
CHI3, padding details, output-length rules, node-id field reuse, field
widths, research builds lifting output minimums, RAM-Balloon details).
All are fixed in SPEC.md and the KAT headers; no digest changed.

**Cryptanalysis.** No break of the permutation, sponge, tree or MAC
modes. Domain separation, tree encoding, MAC key binding and the
truncated, feed-forward-free Balloon compression were checked and found
sound. F20 was reproduced independently (≤ 2 free backward steps, never
3). Findings:

| # | Finding | Severity | Fix |
|---|---|---|---|
| F23 | RAM-Balloon lanes never interacted: a lane-by-lane attacker needs only M/P memory (4 MiB at the defaults, on-chip-SRAM sized) | weakness | **RAM-Balloon v2**: neighbour 0 in another lane, 4 slices per pass with sync points (Argon2-style); P ≤ 16; rehash also on P |
| F24 | Data-independent Balloon at T = 2 is the most exposed to generic depth-reduction attacks (Alwen–Blocki) | weakness | default T = 3. A data-dependent (Argon2id-style) phase was not added, because it gives up the constant-time access pattern |
| F25 | Margin method: trail weights are heuristic upper bounds (limited start set, no clustering), "+2 free rounds" is assumed, and the ratio is non-standard | methodology | wording: the reach is a lower bound on what an expert can do; the margin is also stated as rounds left beyond the best attack (64 − 7.33 = 56.7) |
| F26 | Threshold: the sponge claim (2^512) is only threatened by distinguishers cheaper than 2^(c/2) = 2^512; weight 2048 is lenient *toward the attacker* | informational | at weight ≤ 512 the inside-out differential reaches 10 steps; the reported 16/14 steps are the conservative numbers |

**Implementation audit** (all fixed, regression tests in
`tests/test_ramhash.py::test_review_findings` and `csrc/ram_test.c`):

| # | Finding | Severity | Fix |
|---|---|---|---|
| F27 | `ram_hash_gpu` with `gpu_share > 1` (or NaN) overflowed the heap (reproduced under ASan, reachable from Python) | **high** | clamp to [0, 1] in C and reject in Python; ASan re-run clean |
| F28 | Verification DoS within the stored-hash caps (≈ 12 min, 1 GiB per verify), and unbounded PBKDF2 output length | medium | M·T ≤ 8× default, P ≤ 16, PBKDF2 output exactly 64 bytes and ≤ 4× default iterations |
| F29 | Without the C library, a RAM-Balloon verify ran the Python reference (≈ 85 min) | medium | returns False instead |
| F30 | `hash_password` did not validate parameters: ctypes wrapped 2^32+m to m, −1 to 2^32−1 passes, and over-cap hashes could never verify | medium | int type and the same caps as verification; 32-bit range checked before ctypes |
| F31 | `ram_final` left the message in the context (wipe after `clen = 0`), and reuse after final silently wrote nothing (an untouched MAC buffer) | low–medium | whole context wiped; `ram_update` / `ram_final` return int and refuse a finalized context |
| F32 | Stored hashes were malleable (`+`, `_`, spaces, repeated keys) | low | strict canonical parser |
| F33 | Exported `ram_tree_leaves_cpu` trusted its range (underflow / over-read on `inlen = 0`) | low | range clamped to the message |
| F34 | Library loading: `RAMHASH_*` override accepted bare names (loader search path); `site-packages/build` was searched | low | absolute paths only; `../build` only in a source checkout |
| F35 | `RAM_GPU_TG=0` crashed Metal | low | values outside 1–1024 ignored |
| F36 | `verify_keyed` raised on non-ASCII input | info | returns False |

The cross-lane change was checked three ways: the parallel C code equals
the sequential Python reference (2–4 lanes, slice boundaries),
ThreadSanitizer reports no race for 2–16 lanes, and results are
deterministic. Default cost: 16 MiB held at once, T = 3, P = 4, 1.06 s
on an M3 Pro.

**Re-review of the fixes (10b).** A fourth, fresh reviewer checked the
round-10 fixes. It confirmed RAM-Balloon v2 is race-free and scheduling-
independent (TSan, ASan and UBSan for 1–16 lanes, odd memory sizes and
the minimum m = 8P), that the spec pseudocode matches both
implementations, and that the GPU, context, tree and path fixes are
correct. It found gaps in the fixes themselves, all now closed:

| # | Finding | Fix |
|---|---|---|
| F37 | The cost cap counted M·T only; with P = 1 (no parallelism) a planted hash still cost 38 s (35× default) and 384 MiB | work counted as M·(4T+1)/min(P, 4) ≤ 8× default; memory ≤ 4× default (64 MiB); both are module constants |
| F38 | `verify_password` / `verify_keyed` could still raise (OverflowError, UnicodeEncodeError); an int password hashed as that many zero bytes | `_as_bytes` accepts only str and bytes-like; both verify functions catch every input error |
| F39 | A stored hash with junk before the first `$` verified (F32 was incomplete) | empty prefix and version required, also in `needs_rehash_password` |
| F40 | Weak PBKDF2 hashes (e.g. 1 iteration) were never flagged for rehash without the C library | rehash when iterations < default or output ≠ 64 bytes |
| F41 | A stale library (an old pip build, same ABI) or an unusable override was used or dropped silently | RAM-Balloon known-answer test at load; on mismatch or a bad override: RuntimeWarning and the pure-Python fallback |
| F42 | A failed `ram_init` left an earlier stream usable | context wiped on every init failure; test harnesses check the new return codes |
| F43 | SPEC said "all M at once"; pass 0 can run with lower average memory (unmixed expansion blocks are recomputable) | spec now says *peak* memory M |

## Round 11 — proven trail bounds (SAT, answering F25)

`analysis/trail_bounds.py` gives the round-6 trail model (Lipmaa–Moriai
additions, exact chi3 table, linear layers) to a SAT solver (CaDiCaL,
CNF with a sequential-counter weight bound) for every nonzero input
difference, not just a chosen start set. An UNSAT answer is a proof.
Every trail it finds of weight ≤ 10 is replayed on the real permutation;
all 20 matched 2^-w (e.g. weight 5 → 0.034, weight 3 → 0.126).

Exact minimum characteristic weight, forward, per starting offset:

| Steps | offsets 0–11 | minimum |
|---|---|---|
| 1 | all 0 | 0 |
| 2 | 5, 0, 3, 5, 1, 4, 5, 1, 2, 5, 1, 2 | 0 |
| 3 | ≥7, 4, ≥7, ≥7, 5, ≥6, ≥7, **3**, ≥6, ≥7, 4, ≥6 | **3** |

**F44 (finding, methodology).** The round-6 forward-only table said
3 steps cost ≥ 28; the true minimum is 3. The heuristic only started from
single bits and MSB pairs, while the light trails start from a structured
multi-word difference that G collapses to one MSB, which then passes a
chi step in its skipped row (the F20 effect, seen forward). The forward-
only numbers were therefore far too high.

**Does it change the margin? No, and that is now proven up to 5 steps.**
The margin never used the forward-only table: it combines the best
backward and the best forward trail from a free middle (inside-out),
which already credits the attacker with this collapse. Those inside-out
estimates are 0, 0, 0, 2, 12 for 1–5 steps. The solver proves, at all 12
offsets: no 4-step trail of weight ≤ 1 and no 5-step trail of weight
≤ 11. So for every length checked, the estimate the margin is built on
is at or below the true minimum, i.e. on the attacker's side.

The 6-step check (any trail of weight ≤ 34?) ran about 3.3 hours on all
12 offsets and was stopped with no answer: no trail found, no proof.
That is the limit of this encoding on this hardware, not a weakness
signal (published SAT/MILP proofs for ARX designs with ≤ 512-bit states
also stop after a few rounds). It is weak evidence only that a light
6-step trail would probably have been found as a satisfying example
faster than a proof.

**F45 (linear, same flaw as F44).** `trail_bounds.py linear` (Wallén
additions, exact chi3 LAT; all 36 trails checked by measuring their
correlation on the real steps) proves exact linear minima: 1 step 0,
2 steps 0, 3 steps **2** (round 7's heuristic said 29). The round-7
linear table and its "6 steps" linear reach are therefore too optimistic
and are withdrawn; linear reach is open until 4+ step bounds are
computed. It does not affect the headline (8.5×, calibrated) or the
differential/boomerang reach (16 steps), which remains the largest.

What stays heuristic: 6 steps and beyond (of 192), where the solver runs
out of time. The headline margin (8.5×) comes from calibrated
attack reach, not trails, and is unaffected.

## Round 12 — faster proofs, budgeted testing, status review

**Matsui bounding for the SAT proofs.** `trail_bounds.py` now encodes the
weight bound as one sequential counter and adds, at every step boundary,
the conditions of Sun–Wang–Wang (2021): a trail's first j steps may weigh
at most W − (proven minimum of the remaining steps from that offset), and
its last steps at most W − (proven minimum of the first j). A sub-trail of
a trail is itself a trail with a nonzero difference (the permutation is a
bijection), so every real trail satisfies these clauses: UNSAT is still a
proof. Checked, not assumed: `analysis/matsui_check.py` recomputes the
exact minima with and without the conditions (differential and linear,
1–2 steps, all offsets) and they are identical.

| Same proof, same 10-minute cap per offset | offsets proven |
|---|---|
| 5 steps, weight ≤ 11, plain encoding | 0 of 12 |
| 5 steps, weight ≤ 11, with Matsui conditions | **9 of 12** (106–441 s) |
| 4 steps, weight ≤ 1 | 13.6 s → 6.2 s |

New proven 3-step bounds (budgeted 20-minute run): offsets 0, 3, 6 ≥ 9
(were ≥ 7), offset 5 ≥ 8 (was ≥ 6); trails of weight 10–11 found there,
so those minima are now pinned to 9–11. The overall 3-step minimum stays
3 (offset 7, exact).

6-step proof (weight ≤ 34; stalled after 3.3 h in round 11), rerun with
the conditions under a 55-minute cap: still **undecided** at all 12
offsets (no trail found, no proof; stopped cleanly by the budget at
3258 s). The conditions help most where the remaining weight is small;
at 6 steps the allowed weight (34) is large next to the proven pieces
(≤ 12 for 5 steps), so the pruning is weak. Next lever: per-word or
per-column bounds, or a MILP/CP model (`python3 tools/suite.py --only
trail-proof-6` reruns it under the same cap).

**Testing.** Every test and analysis is now a job in `tests/suite.json`,
run by `tools/suite.py` under a hard wall-clock budget (default one hour,
verified: jobs that overrun are killed with their Docker containers, the
long analyses stop by themselves at `RAM_DEADLINE` and keep partial
results in a separate folder). Measured: quick tier 66 s, standard tier
19 min (12/12 pass; perm-attack, trail search and SAT results reproduce
the recorded numbers, including the 8.7× trail margin). A full-tier run
(one-hour budget) was stopped by hand after ~25 min: by then all 22
OS/CPU/compiler jobs had passed with the renamed sources (OpenBSD, the
slowest, 987 s) along with every correctness job and the permutation,
algebraic and trail-search attacks; the long attack suites and SAT bound
jobs had not finished. A complete full-tier run is still to do. `make test`
went from 23.5 s to 4.2 s (the slow pure-Python cross-checks moved to
`make reference`, which still regenerates every KAT), and the Docker
matrix caches its toolchains (e.g. Windows/MinGW job 329 s → 24 s).

### Status review: what is done, what is open

Done and verified: the spec and the two implementations agree (KATs
regenerate byte-for-byte from the Python spec); 45 findings fixed and
re-tested (F1–F45), four independent reviewers; constant-time, fuzzed,
sanitizer-clean, bit-identical on 22 OS/CPU/compiler jobs plus iOS;
margins 8.5× (calibrated), 8.7× (best trail/boomerang), 10.2×;
differential trails proven minimal to 3 steps and the margin's estimates
proven conservative to 5 steps.

Open, in order of value:

1. **Outside cryptanalysis.** The only thing that can turn "no attack
   found" into trust. Needs REVIEW.md published (the owner's call).
2. **Trail proofs beyond 5–6 steps** (of 192). Matsui conditions moved the
   frontier; going further needs per-word (not whole-state) bounds or a
   MILP/CP model. Linear bounds for 4+ steps are in the full tier.
3. **RAM-Balloon data-dependent phase** (Argon2id-style). Deliberately not
   done: it buys resistance to time–memory trade-offs at the price of
   cache-timing leaks of the password; the data-independent design keeps
   Balloon's proof and the constant-time property. Recommendation: keep.

What cannot be "pushed" further without changing the design: the generic
bounds (2^512 classical, ~2^341 quantum) are fixed by the 1024-bit
capacity; more rounds would cost speed without a measurable gain, since
no attack reaches past 16 of 192 steps.

## Current standing (v3)

| Attack family | RAM-1024 reach (of 192 steps) |
|---|---|
| **Boomerang** (trails + measured switch, weight ≤ 2048) | **16 steps (5.33 rounds)** |
| Differential trails, inside-out (weight ≤ 2048) | 14 steps (4.67 rounds) |
| Linear trails (data ≤ 2^2048) | heuristic 6 steps withdrawn (F45); proven: 3-step minimum weight 2 |
| Proven (SAT): inside-out estimates are conservative | up to 5 steps, all offsets (round 12: Matsui-accelerated) |
| Differential-linear (data ≤ 2^2048) | 10 steps |
| Rotational-XOR trails, inside-out | 9 steps |
| SAC / differential, inside-out | 10 steps (3.33 rounds) |
| Zero-sum / higher-order, inside-out | 9 steps |
| Neural (AI), inside-out | 10 steps |
| SAT/SMT (z3) preimage/collision | 1 round (3 steps); 2 rounds worse than brute force |
| Rotational | none at any round |
| Column-shift symmetry | 1 step |
| Exact linearity | 1 step (backward) |

64 rounds leave 176 of 192 steps untouched by any attack found. Three
independent estimates of an expert's reach (7.6, 6.3 and 7.33 rounds) give
margins of **8.5×, 10.2× and 8.7×** (the last was 9.6× before the boomerang, F22); the report headlines the smallest.
Put without ratios: the best attack found covers 7.33 of 64 rounds
(with 2 assumed free rounds), leaving 56.7 rounds. All reach numbers are
lower bounds on what an expert could do (F25); measured at the 2^512
sponge bound instead of 2^2048 they would be shorter (F26).

Implementation: constant-time (Valgrind), fuzzed, sanitizer-clean, and
bit-identical on every OS/CPU/compiler tested, big-endian included.

Review: round 10 was carried out by three reviewers independent of the design
(F23–F36), and a fourth reviewer checked the fixes (F37–F43); all fixed. Still missing: review by the wider cryptographic community.

Known limit: the rest is self-review. REVIEW.md packages the claims, the
places we would attack first and public reduced-round challenges
(`tools/challenges.py`) for independent cryptanalysts.
