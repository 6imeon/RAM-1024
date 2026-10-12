# RAM-1024 specification (version 3)

RAM-1024 is a sponge-based hash function / XOF / MAC with a 2048-bit
permutation that combines an ARX layer (BLAKE2b's G function) with a
Boolean chi layer (Keccak/Xoodoo). Reference code: `ramhash/ram1024.py`;
optimized C: `csrc/ram1024.c`. Both must agree bit-for-bit (`make test`).

## Parameters

| | |
|---|---|
| State | 32 × 64-bit words = 2048 bits, viewed as a 4×8 matrix `s[row*8+col]` |
| Rate *r* | rows 0–1 = 1024 bits (128-byte blocks) |
| Capacity *c* | rows 2–3 = 1024 bits |
| Rounds | **64** |
| Output | default 1024 bits. HASH/MAC: any length ≥ the minimum, bound in `s[30]` (different lengths give unrelated outputs); XOF: `s[30] = 0`, so outputs are prefixes of each other. Squeezed in 128-byte blocks, truncated to the requested length |
| Tree chunk | 16 KiB leaves, 1024-bit chaining values |
| Word order | little-endian |

## Permutation P (one round, round index *i* = 0…63)

The full permutation applies rounds *i* = 0, 1, …, 63 in order. An
*r*-round instance (1 ≤ r ≤ 64, research builds only) applies rounds
*i* = 0…r−1, and the rounds field of the parameter block holds *r*.
`>>>` and `<<<` are 64-bit rotations right and left; `+` is addition
mod 2^64.

1. **ι (constants).** `s[8·(c mod 4) + c] ^= RC[8i + c]` for `c = 0…7` —
   one constant per column, spread diagonally over all four rows (v3).
   `RC` is the sequence of 64-bit words of the binary expansion of frac(π)
   (`tools/gen_constants.py`; `RC[0] = 0x243f6a8885a308d3`).
2. **θ₁ (columns).** `G(s[c], s[8+c], s[16+c], s[24+c])` for each column `c`.
2b. **ρ (v3).** `s[16+j] = s[16+j] <<< ρ_j` for `j = 0…15`, with
   `ρ_j = 2·(13·j mod 32) + 1` = 1, 27, 53, 15, 41, 3, 29, 55, 17, 43, 5,
   31, 57, 19, 45, 7 (sixteen distinct odd amounts, never byte-aligned).
3. **θ₂ (diagonals).** `G(s[c], s[8+(c+1)%8], s[16+(c+2)%8], s[24+(c+3)%8])`.
4. **χ (Boolean).** Let rows `a<b<d` be the three rows ≠ `i mod 4`. For each
   `c`: apply `CHI3` to `(s[8a+c], s[8b+(c+3)%8], s[8d+(c+5)%8])`.

```
G(a,b,c,d):  a+=b; d=(d^a)>>>32;  c+=d; b=(b^c)>>>24;
             a+=b; d=(d^a)>>>16;  c+=d; b=(b^c)>>>63
CHI3(x,y,z): x'=x^(~y&z);  y'=y^(~z&x);  z'=z^(~x&y)
```

CHI3 computes x', y', z' simultaneously from the *input* x, y, z (not
in sequence).

G is a bijection on 4 words; CHI3 is 64 parallel copies of a bijective
3-bit S-box (verified exhaustively in tests); the triples partition the
words, so P is a permutation.

## Sponge

* **Init.** `s = 0`, then the parameter block in the capacity:
  `s[31] = VERSION | mode<<24 | rounds<<16 | kind<<8` with
  `VERSION = 0x52414D03_00000000` and 8-bit fields mode (bits 24–31),
  rounds (16–23) and kind (8–15). kind = 0 in every padded sponge;
  only the RAM-Balloon compression C uses kind ≥ 1, so the two can never
  share an input state.
  `s[30] = output length in bytes` (0 in XOF mode), `s[29] = key length`
  (0 without a key), `s[28] = node id`: the leaf index for tree leaves,
  the RAM-Balloon node ids below, 0 otherwise (including the tree root).
  Modes: 1 = hash, 2 = XOF, 3 = MAC, 4 = tree leaf, 5 = tree root,
  6 = password hashing (RAM-Balloon, below).
* **Key (MAC mode only).** Any length ≥ 16 bytes; zero-padded to whole
  128-byte blocks and absorbed first (its length is bound in `s[29]`).
  Keys in other modes, and shorter MAC keys, are rejected.
* **API (misuse-resistant).** `ram_init` / `ram_hash` / `ram_hash_tree`
  return 0, or −1 on invalid parameters. Production builds accept only
  **rounds = 64** and outputs of at least **32 bytes (hash)**, **16 bytes
  (MAC tag)**, 1 byte (XOF), and no upper limit. Reduced-round instances,
  and outputs below those minimums, exist only in builds compiled with
  `-DRAM_RESEARCH` (the cryptanalysis lab) and, in Python, with an
  explicit `research=True` (there any output ≥ 1 byte is accepted).
* **Absorb.** XOR each 128-byte block into rows 0–1, apply P.
* **Pad.** pad10\*1, always applied (a message filling whole blocks gets
  one more block): append `0x01`, then zeros up to the next multiple of
  128 bytes, then XOR the last byte with `0x80`. If only one byte is free
  it becomes `0x81`.
* **Squeeze.** Output rows 0–1 (128 bytes), apply P between blocks.

## Tree mode (hash mode only)

A hash-mode message of at most 16 384 bytes is hashed by the plain sponge
above. A longer message is split into 16 KiB chunks `M_0 … M_{n-1}` (the
last may be shorter):

```
CV_i   = sponge(mode=LEAF, node=i, outlen=128)(M_i)          # 1024-bit
digest = sponge(mode=ROOT, outlen)(CV_0 || … || CV_{n-1} || le64(n))
```

Leaves and root use the caller's round count and `s[29] = 0`; the root
has `s[28] = 0`. XOF and MAC never use tree mode, at any length.
Leaves are independent, so they are hashed in parallel (two per core in
SIMD lanes, all cores via threads); streaming produces the same digest.
Distinct modes for plain/leaf/root nodes, the leaf index, and the final
chunk count make the encoding injective (Sakura-style tree rules); the
1024-bit chaining value keeps the full 512-bit collision bound.

## RAM-Balloon v2 (password hashing, mode 6)

Balloon hashing (Boneh, Corrigan-Gibbs, Schechter, ASIACRYPT 2016) with
δ = 3 and 64-byte blocks, on the RAM-1024 permutation, with lanes that
reference each other in Argon2-style slices. Parameters: total memory
*M* KiB (8·P ≤ M ≤ 2^20), *T* passes (1 ≤ T ≤ 64, default 3), *P* lanes
(1 ≤ P ≤ 16, default 4), salt ≥ 16 bytes, output ≥ 32 bytes; the C API
takes M, T, P as 32-bit unsigned integers. Each lane has
*n* = ⌊16·M/P⌋ rounded down to a multiple of 4 blocks, in 4 slices of
*seg* = n/4 blocks. Password and salt may have any length.

```
C(kind, lane, ctr, x, y)   # x, y: 8 words each; one 64-round permutation call
    s = x || y || 0^16;  s[31] = VERSION | 6<<24 | 64<<16 | kind<<8
    s[30] = 64;  s[29] = lane;  s[28] = ctr;   P(s);  return s[0..7]

SD   = sponge(mode 6, node 2^64-2, outlen 64)(le64(|salt|) || salt)
for each lane l:                                                       # expand
    seed = sponge(mode 6, node l, outlen 64)(le64(|pw|)||pw||le64(|salt|)||salt
                                             ||le64(M)||le64(T)||le64(P)||le64(outlen))
    B_l[0] = C(1, l, 0, seed, 0);  B_l[j] = C(1, l, j, B_l[j-1], 0)  for j = 1..n-1
    ctr_l  = n
for pass t = 0..T-1, slice s = 0..3, each lane l (lanes in parallel):  # mix
    for block j = s·seg .. (s+1)·seg - 1:
        B_l[j] = C(2, l, ctr_l++, B_l[j-1 mod n], B_l[j])
        r = C(3, l, 0, SD, (t, j, 0, 0, 0, 0, 0, 0))     # salt-only: data-independent
        for i = 0..2:
            if i = 0 and P > 1:                           # another lane, other slices
                l' = (l + 1 + r[3] mod (P-1)) mod P
                k  = r[0] mod (n - seg);  if k >= s·seg: k += seg
                N  = B_l'[k]
            else:
                N  = B_l[r[i] mod n]
            B_l[j] = C(2, l, ctr_l++, B_l[j], N)
    (all lanes finish slice s before any starts slice s+1)
out = sponge(mode 6, node 2^64-3, outlen)(B_0[n-1] || … || B_{P-1}[n-1] || le64(P))
```

`VERSION = 0x52414D03_00000000` and the rounds field is always 64, also
in research builds. `ctr_l` is per lane, starts at n after the
expansion and runs on across passes; the kind-3 index call always uses
ctr = 0. Reads use the current contents of B (a block updated earlier in
the same pass is read in its new state). During slice s every lane
writes only its own slice-s blocks, and other lanes read only blocks
outside slice s, so the result is independent of thread scheduling
(checked with ThreadSanitizer) and equals the sequential order
"for t, for s, for l".

Why cross-lane references (v2, finding F23): in v1 the lanes never met
before the final sponge, so an attacker could compute them one after
another holding only M/P of memory (4 MiB at the defaults, small enough
for on-chip SRAM). Now every block depends on another lane's memory, so
the **peak** memory is all M KiB at once. During pass 0, part of the
references still land on unmixed expansion blocks, which can be
recomputed from checkpoints, so the time-averaged memory of pass 0 can
be lower; from pass 1 on, the full M is needed. Default T = 3 (was 2) because generic
depth-reduction attacks on data-independent memory-hard functions
(Alwen–Blocki 2016/2017) are strongest at low pass counts.

The compression is a single fixed-length permutation call with the
1024-bit capacity holding the parameter block (kind ≥ 1 never occurs in
the padded sponge calls, kind 0), so it behaves as a random function as
long as the permutation is ideal. Neighbour indices depend only on
(salt, lane, t, j), so memory access leaks nothing about the password
(checked under Valgrind, `csrc/check/ct_test.c`). All memory and
intermediate state are wiped before returning.

Stored format (Python `hash_password`):
`$rh1$ram-balloon2$m=M,t=T,p=P$<salt hex>$<64-byte hash hex>`, parsed
strictly (empty prefix, canonical decimal, lower-case hex, no repeated
keys). To bound verification cost for attacker-written strings, stored
hashes may use at most 4× the default memory (64 MiB) and at most 8× the
default work, counted as M·(4T+1)/min(P, 4) so that fewer lanes (less
parallelism) cost more. Both limits are module constants
(`PW_MAX_MEMORY_KIB`, `PW_MAX_COST`) for deployments that want more. v1 strings (`ram-balloon`) are not verified and
always need a rehash; v1 was never released. Known-answer vectors:
`tests/kat_pwhash.txt`.

## Portability and conformance

The library (`csrc/ram1024.c`) is C99 with no compiler extensions required:
GCC/Clang vector types are used when available (`RAM_VEC`), otherwise the
same generated round code runs on scalars. Threads are POSIX or Win32 (or
none with `-DRAM_NO_THREADS`). All byte↔word conversions are explicit
little-endian, so big-endian hosts produce identical digests.
`tests/kat.txt` and `tests/kat_pwhash.txt` are generated by the
pure-Python reference (`tools/gen_kat.py`). Inputs: message byte
*i* = (7i² + 13i + 1) mod 256, key byte *i* = (31i + 0xa5) mod 256; in
`kat_pwhash.txt` the password is the message and the salt is the key.
Lines with rounds ≠ 64 or an output below the production minimum are
research-only (a production build must reject them). Every build must
reproduce the vectors exactly:
`make check` (C only) or `ctest` (CMake/MSVC). `tools/crossplatform.sh`
runs that conformance test, the Python suite, sanitizers, a fuzzer and
the constant-time check across operating systems (macOS, Linux, Android,
Windows incl. the MSVC ABI, FreeBSD, OpenBSD, iOS via
`tools/ios_check.sh`), CPUs (x86, ARM, RISC-V,
POWER, big-endian s390x) and compilers.

## Changes in v3 (from cryptanalysis — see CRYPTANALYSIS.md)

| Finding | Fix |
|---|---|
| Column-shift symmetry survived 6 backward steps (constants only in row 0) | constants spread diagonally over all rows (free) → 1 step |
| Backward diffusion slower than forward (ARX subtraction carries only move up) | ρ rotations of rows 2–3 after the column step → inside-out reach 11 → 10 steps |
| Undocumented rotation table | ρ given by a one-line rule |
| C API truncated MAC keys > 128 bytes (distinct keys, equal tags) | full key absorbed |
| Key material wiped with elidable `memset` | volatile wipe |
| Invalid parameters silently clamped | rejected with −1 |
| Empty / short MAC keys accepted | ≥ 16 bytes required |
| Public API accepted reduced-round (broken) instances and 1-byte digests | rounds = 64 and per-mode minimum outputs; reduced rounds only in research builds |
| Password hashing was PBKDF2 (cheap on GPUs/ASICs) | RAM-Balloon, memory-hard, data-independent |
| Win32 thread wait silently failed above 64 threads | per-thread wait |

Digests for all valid production parameters are unchanged by the last
three rows (API, password hashing, threading); the version word stays
`RAM\x03`.

## Design rationale

| Goal | Mechanism |
|---|---|
| Generic security (classical) | *c* = 1024 → 2^512 bound; 1024-bit output → 2^512 collisions and preimages |
| Generic security (quantum) | BHT collision 2^341, preimage ≥ 2^341 (vs SHA-256: 2^85 / 2^128; SHA3-512: 2^171 / 2^256) |
| Speed despite 64 rounds | unrolled permutation compiles to ARMv8 SHA-3 instructions (XAR, BCAX); 2 states per SIMD register; parallel tree on all CPU cores and the GPU (Metal kernel generated from the same round description) |
| No length extension | sponge with hidden 1024-bit capacity; secure as a MAC with a prefix key |
| Two independent sources of nonlinearity | modular addition (carries) **and** AND-based chi; attacks that linearize one (e.g. algebraic/cube attacks vs. chi, differential trails vs. ARX) must still cross the other |
| No symmetry / rotational / slide structure | distinct π constants in every round and every column; parameter block in capacity |
| Fast diffusion | full avalanche after **2 rounds** (measured; same as BLAKE2b, faster than SHA-3's 4 and SHA-256's ~23) |
| Large security margin vs. unknown future (incl. AI-assisted) cryptanalysis | 64 rounds = 32× the full-diffusion depth. Three independent margin estimates: forward lab reach × worst lab→expert multiplier → **8.5×**; like-for-like inside-out calibration → **10.2×**; best trail attack (a 16-step boomerang) plus 2 free rounds → **8.7×** (CRYPTANALYSIS.md) |
| Domain separation | mode, rounds, output length and key length all bound into the initial state |

## Status

RAM-1024 is **new and unreviewed by the cryptographic community**. The
analysis in `RESULTS.md` is the strongest testing we could perform, but
real confidence in a hash function comes only from years of public
cryptanalysis. That is why `ramhash`'s default is the hedged combination
`ram-1024+sha3-512`: an attacker must break RAM-1024 **and** SHA3-512.
