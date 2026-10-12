# RAM-1024 / ramhash — a hash function built to outlast SHA-256

**RAM-1024** is a new hash function designed and iterated here: a 2048-bit
sponge with a hybrid ARX + chi permutation, **64 rounds**, 1024-bit capacity,
**1024-bit output**, and a parallel tree mode, plus **RAM-Balloon**, a
memory-hard password hash on the same permutation. **ramhash** is the Python
package around it; its default is *hedged* with NIST SHA3-512.

Runs everywhere: portable C99 with a pure-Python fallback. **Tested**, with
bit-identical known-answer vectors on each:

| OS | How it was run |
|---|---|
| macOS | native |
| Linux | x86-64, i386, arm64, riscv64, ppc64le, **big-endian s390x**; glibc and musl (Alpine) |
| Android | real bionic libc (Termux image), C library + Python |
| Windows | x64 and x86 (MinGW); **Microsoft `cl.exe` 19.51** (MSVC Build Tools via msvc-wine, `/W4 /WX`, exe + DLL); and clang-cl against the Microsoft CRT/SDK; all run under Wine |
| FreeBSD 15.0 | official VM image in QEMU, system clang |
| OpenBSD 7.9 | unattended install (autoinstall) in QEMU, system clang |
| iOS | iOS 27.0 Simulator (iPhone 18 Pro) and Mac Catalyst (iOS ABI), `tools/ios_check.sh` |

Also covered: compilers GCC, Clang and TCC, a strict C99 build with every
warning an error, CMake, and `pip install` with and without a C compiler.
`tools/crossplatform.sh` runs all 22 jobs (Docker; QEMU for foreign CPUs and
the BSDs; Wine for Windows), plus sanitizers, fuzzing and a constant-time
check; `tools/ios_check.sh` covers iOS.

- Spec: [SPEC.md](SPEC.md)
- For external reviewers (claims, suspected weak points, reduced-round
  challenges): [REVIEW.md](REVIEW.md)
- Cryptanalysis log (findings → fixes → re-tests, including round 10, an independent
  review by three reviewers outside the design): [CRYPTANALYSIS.md](CRYPTANALYSIS.md)
- Head-to-head results vs SHA-256, SHA3-512, BLAKE2b (scoreboard, attacks,
  quantum, speed, design iterations): [RESULTS.md](RESULTS.md)

## Headline (see RESULTS.md §0 for the measured scoreboard)

| | SHA-256 | SHA3-512 | BLAKE2b | **RAM-1024** |
|---|---|---|---|---|
| Quantum collision cost | 2^85 | 2^171 | 2^171 | **2^341** |
| Quantum preimage cost | 2^128 | 2^256 | 2^256 | **2^341** |
| Margin vs. best known attacks (RAM: smallest of 3 independent estimates: 8.5×, 8.7× (boomerang), 10.2×) | 1.6× | 4.0× | 1.4× | **8.5×** |
| Length-extension attacks | vulnerable | immune | immune | immune |
| Long-message speed, full rounds (M3 Pro) | 2.9 GB/s | 0.5 GB/s | 1.4 GB/s | **3.8–4.8 GB/s** (CPU+GPU) |

The standards are sequential, so one message runs on one core. RAM-1024's
tree mode spreads it over every CPU core and the GPU, producing the same
digest. At the *same* security margin as each standard it is 2.6–7.6×
faster than it on the CPU alone.

A note on the premise: SHA-256 is a hash, not encryption, so it can't be
"decrypted", and there is no public evidence that AI is close to breaking
it. In our lab a neural-network attacker stalls about a third of the way
into SHA-256's rounds. The credible long-term threat is quantum computing,
which RAM-1024's 1024-bit state/output targets directly.

## Honest status

RAM-1024 is **new**. It leads every metric we can measure, but a hash
function earns trust only through years of public cryptanalysis. So the
default algorithm is `ram-1024+sha3-512` (1536-bit concatenation):
**an attacker must break both**. Don't deploy bare `ram-1024` alone until
it has had that review. The project is a research release (alpha): the
format (`$rh1$...`) and the algorithm may still change if cryptanalysis
finds a problem.

## Usage

```bash
pip install .   # any OS: builds the C library, or falls back to pure Python
```

```bash
make            # C library + ram_test + ramsum (.dylib / .so / .dll by OS)
make check      # C conformance test only (no Python needed)
make test       # + research lab + Python suite (~5 s)
make reference  # regenerate the KATs from the pure-Python spec and diff (~15 s)
cmake -S . -B build && cmake --build build && ctest --test-dir build   # MSVC etc.
sh tools/crossplatform.sh quick   # 10 Docker jobs, native CPU + s390x + Wine (~1 min cached)
sh tools/crossplatform.sh         # all 22 jobs incl. emulated CPUs and BSD VMs
```

Everything, under a hard time limit (`tests/suite.json` lists the jobs):

```bash
python3 tools/suite.py --tier quick        # correctness: build, KATs, Python, xcheck, Docker quick set (~1 min)
python3 tools/suite.py --tier standard     # + sanitizers, permutation attacks, trail search, SAT
python3 tools/suite.py                     # + full OS matrix, all attack suites, SAT bounds; <= 1 hour
python3 tools/suite.py --budget 900 --dry-run   # show what would run in 15 min
python3 tools/suite.py --only trail-proof-6 # open research proof, capped at 55 min
```

The runner never exceeds `--budget` (default 3600 s): a job starts only if
its estimate fits, is killed (process group and labelled Docker containers)
at its limit, and the SAT/analysis scripts get `RAM_DEADLINE` so they stop
cleanly and keep partial results. Output goes to `results/suite/<run>/`
(never over the canonical results); `results/suite/latest.md` is the last
report.

```python
import ramhash

d = ramhash.digest(b"data")           # $rh1$ram-1024+sha3-512$<384 hex chars>
ramhash.verify(b"data", d)            # constant-time
ramhash.digest_file("big.iso")
ramhash.digest(b"data", "ram-1024")   # bare RAM-1024

h = ramhash.Ram1024(); h.update(b"part1"); h.update(b"part2"); h.hexdigest()
ramhash.hash_parallel(big_bytes)      # all cores, same digest as Ram1024
ramhash.hash_parallel(big_bytes, gpu=True)   # + GPU (macOS Metal)

from ramhash import ram1024            # reference implementation & modes
ram1024.ram_hash(b"seed", outlen=200, mode=ram1024.MODE_XOF)
ram1024.ram_hash(b"msg", mode=ram1024.MODE_MAC, key=b"a key of >= 16 bytes")

if ramhash.verify(data, old_sha256_hex) and ramhash.needs_rehash(old_sha256_hex):
    store(ramhash.digest(data))       # migrate stored SHA-256 digests

h = ramhash.hash_password("pw")       # RAM-Balloon v2: 16 MiB held at once, 3 passes
ramhash.verify_password("pw", h)      # constant-time; old PBKDF2 hashes too
ramhash.needs_rehash_password(h)      # True for PBKDF2 / weaker parameters
```

The library refuses insecure settings rather than computing them:
reduced-round instances (`rounds != 64`) need an explicit
`research=True` (Python) or a `-DRAM_RESEARCH` build (C). Hash outputs must
be at least 32 bytes and MAC tags at least 16.

```bash
python3 -m ramhash somefile.bin
./build/ramsum somefile.bin   # C command-line tool, any OS
```

## Reproducing the analysis

`python3 tools/suite.py` runs all of it under a one-hour limit (see Usage).
By hand:

```bash
make && python3 analysis/run_all.py && python3 analysis/rotational.py \
  && python3 analysis/grover.py && python3 analysis/max_effort.py \
  && python3 analysis/redteam.py && python3 analysis/calibrate.py \
  && python3 analysis/matched_speed.py && python3 analysis/trail_search.py \
  && python3 analysis/report.py
```

## Layout

| Path | |
|---|---|
| `csrc/ram1024.c` | RAM-1024 in C: unrolled/SIMD permutation, sponge, tree, RAM-Balloon, threads (POSIX/Win32) |
| `csrc/ram_test.c`, `tests/kat*.txt` | portable conformance test and known-answer vectors |
| `csrc/check/` | constant-time (Valgrind) and fuzzing (libFuzzer) harnesses |
| `csrc/trail_lab.c` | differential trail search (cryptanalysis round 6) |
| `tools/suite.py`, `tests/suite.json` | time-budgeted runner for every test and analysis (default ≤ 1 hour) |
| `tools/crossplatform.sh` | OS / CPU / compiler matrix in Docker (toolchains cached as `ramci-*` images, `RAMCI_JOBS` parallel, `FUZZ_SECONDS`) |
| `csrc/ram_gpu.m` | GPU (Metal) tree leaves, run concurrently with CPU threads |
| `ramhash/ram1024.py` | pure-Python reference (the executable spec) |
| `csrc/lab.c` | round-reduced SHA-256 / SHA3-512 / BLAKE2b / RAM + attack kernels |
| `analysis/` | SAC, cube, neural (AI), rotational, Grover, randomness, speed |
| `tools/` | π round-constant and unrolled-permutation generators, KAT generator, challenges, platform checks |
| `results/` | raw outputs of every analysis and platform run (RESULTS.md is built from them) |

## Contributing

Cryptanalysis is the most valuable contribution: start with
[REVIEW.md](REVIEW.md) (claims, suspected weak points, reduced-round
challenges). For code changes, `make test` must pass and
`make reference` must still reproduce the known-answer files; any change
to the algorithm needs new KATs from the Python spec (`tools/gen_kat.py`).

## License

MIT, see [LICENSE](LICENSE).
