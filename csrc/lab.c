/* Cryptanalysis lab: round-reduced cores of SHA-256, SHA3-512 (Keccak-f),
 * BLAKE2b and RAM-1024 behind one interface, plus fast test kernels that
 * the analysis scripts drive through ctypes.
 *
 * core(alg, rounds, in[64]) -> out[32]: one-block hash of a 64-byte input
 * truncated to 256 bits. At full rounds each equals the real algorithm
 * (validated against hashlib in tests/test_lab.py).
 */
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "ram1024.h"

enum { ALG_SHA256, ALG_SHA3_512, ALG_BLAKE2B, ALG_RAM1024, ALG_RAM_STEPS,
       ALG_BLAKE2B_HALF, NALGS };
/* ALG_RAM_STEPS: RAM-1024 cut after a number of *steps* (3 per round:
 * iota+column G, diagonal G, chi) for finer-than-round resolution. */
/* ALG_BLAKE2B_HALF: BLAKE2b cut after a number of half-rounds (column
 * step, diagonal step) for the calibration of the pessimistic model. */
const int lab_full_rounds[NALGS] = {64, 24, 12, RAM_ROUNDS, 3 * RAM_ROUNDS, 24};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

/* ---------------- SHA-256 compression, r rounds ---------------- */
static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
static const uint32_t IV256[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                                  0xa54ff53a, 0x510e527f, 0x9b05688c,
                                  0x1f83d9ab, 0x5be0cd19};

static void sha256_core(int rounds, const uint8_t *in, uint8_t *out)
{
    uint32_t w[64], h[8];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)in[4 * i] << 24 | (uint32_t)in[4 * i + 1] << 16 |
               (uint32_t)in[4 * i + 2] << 8 | in[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROTR32(w[i - 15], 7) ^ ROTR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROTR32(w[i - 2], 17) ^ ROTR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    memcpy(h, IV256, sizeof h);
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5],
             g = h[6], hh = h[7];
    for (int i = 0; i < rounds; i++) {
        uint32_t S1 = ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25);
        uint32_t t1 = hh + S1 + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        uint32_t S0 = ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22);
        uint32_t t2 = S0 + ((a & b) ^ (a & c) ^ (b & c));
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    for (int i = 0; i < 8; i++) {
        out[4 * i] = h[i] >> 24; out[4 * i + 1] = h[i] >> 16;
        out[4 * i + 2] = h[i] >> 8; out[4 * i + 3] = h[i];
    }
}

/* ---------------- Keccak-f[1600], first r rounds ---------------- */
static const uint64_t KRC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
static const int KRHO[25] = {0,  1,  62, 28, 27, 36, 44, 6,  55, 20, 3,  10, 43,
                             25, 39, 41, 45, 15, 21, 8,  18, 2,  61, 56, 14};

static void keccak_f(uint64_t A[25], int rounds)
{
    uint64_t B[25], C[5], D[5];
    for (int r = 0; r < rounds; r++) {
        for (int x = 0; x < 5; x++)
            C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
        for (int x = 0; x < 5; x++)
            D[x] = C[(x + 4) % 5] ^ ROTL64(C[(x + 1) % 5], 1);
        for (int i = 0; i < 25; i++) A[i] ^= D[i % 5];
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++) {
                int k = KRHO[x + 5 * y];
                uint64_t v = A[x + 5 * y];
                B[y + 5 * ((2 * x + 3 * y) % 5)] = k ? ROTL64(v, k) : v;
            }
        for (int y = 0; y < 5; y++)
            for (int x = 0; x < 5; x++)
                A[x + 5 * y] = B[x + 5 * y] ^
                               (~B[(x + 1) % 5 + 5 * y] & B[(x + 2) % 5 + 5 * y]);
        A[0] ^= KRC[r];
    }
}

static uint64_t ld64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

static void st64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

static void sha3_512_core(int rounds, const uint8_t *in, uint8_t *out)
{
    uint64_t A[25] = {0};
    for (int i = 0; i < 8; i++) A[i] = ld64(in + 8 * i);
    A[8] ^= 0x06;                    /* SHA-3 domain + pad, byte 64 */
    A[8] ^= 0x8000000000000000ULL;   /* final pad bit, byte 71 (rate 72) */
    keccak_f(A, rounds);
    for (int i = 0; i < 4; i++) st64(out + 8 * i, A[i]);
}

/* ---------------- BLAKE2b compression, r rounds ---------------- */
static const uint64_t B2IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
static const uint8_t SIGMA[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}};

#define B2G(a, b, c, d, x, y)                     \
    do {                                          \
        a = a + b + x; d = ROTR64(d ^ a, 32);     \
        c = c + d;     b = ROTR64(b ^ c, 24);     \
        a = a + b + y; d = ROTR64(d ^ a, 16);     \
        c = c + d;     b = ROTR64(b ^ c, 63);     \
    } while (0)

static void blake2b_halves(int halves, const uint8_t *in, uint8_t *out);

static void blake2b_core(int rounds, const uint8_t *in, uint8_t *out)
{
    blake2b_halves(2 * rounds, in, out);
}

static void blake2b_halves(int halves, const uint8_t *in, uint8_t *out)
{
    uint64_t h[8], v[16], m[16] = {0};
    for (int i = 0; i < 8; i++) m[i] = ld64(in + 8 * i);
    memcpy(h, B2IV, sizeof h);
    h[0] ^= 0x01010000ULL ^ 64; /* fanout=1, depth=1, digest 64 bytes */
    for (int i = 0; i < 8; i++) { v[i] = h[i]; v[i + 8] = B2IV[i]; }
    v[12] ^= 64;   /* t = 64 bytes */
    v[14] = ~v[14]; /* final block */
    for (int h = 0; h < halves; h++) {
        const uint8_t *s = SIGMA[h / 2];
        if (h % 2 == 0) {
        B2G(v[0], v[4], v[8], v[12], m[s[0]], m[s[1]]);
        B2G(v[1], v[5], v[9], v[13], m[s[2]], m[s[3]]);
        B2G(v[2], v[6], v[10], v[14], m[s[4]], m[s[5]]);
        B2G(v[3], v[7], v[11], v[15], m[s[6]], m[s[7]]);
        continue;
        }
        B2G(v[0], v[5], v[10], v[15], m[s[8]], m[s[9]]);
        B2G(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]]);
        B2G(v[2], v[7], v[8], v[13], m[s[12]], m[s[13]]);
        B2G(v[3], v[4], v[9], v[14], m[s[14]], m[s[15]]);
    }
    for (int i = 0; i < 4; i++) st64(out + 8 * i, h[i] ^ v[i] ^ v[i + 8]);
}

/* ---------------- RAM-1024, r rounds ---------------- */
static void ram1024_core(int rounds, const uint8_t *in, uint8_t *out)
{
    uint8_t full[RAM_OUT];
    ram_hash(full, RAM_OUT, in, 64, rounds, RAM_MODE_HASH, NULL, 0);
    memcpy(out, full, 32);
}

#include "ram_constants.h"
#define RG(a, b, c, d)                    \
    do {                                  \
        a += b; d = ROTR64(d ^ a, 32);    \
        c += d; b = ROTR64(b ^ c, 24);    \
        a += b; d = ROTR64(d ^ a, 16);    \
        c += d; b = ROTR64(b ^ c, 63);    \
    } while (0)

static void ram_steps_core(int steps, const uint8_t *in, uint8_t *out)
{
    uint64_t s[32];
    ram_init_state(s, RAM_OUT, RAM_MODE_HASH, RAM_ROUNDS, 0, 0);
    for (int i = 0; i < 8; i++) s[i] ^= ld64(in + 8 * i);
    s[8] ^= 0x01;                   /* pad byte 64 */
    s[15] ^= 0x80ULL << 56;         /* pad byte 127 */
    for (int st = 0; st < steps; st++) {
        int r = st / 3;
        switch (st % 3) {
        case 0:
            for (int c = 0; c < 8; c++) s[(c & 3) * 8 + c] ^= RAM_RC[r * 8 + c];
            for (int c = 0; c < 8; c++) RG(s[c], s[8 + c], s[16 + c], s[24 + c]);
            for (int i = 0; i < 16; i++)
                s[16 + i] = ROTR64(s[16 + i], 64 - RAM_RHO[i]);
            break;
        case 1:
            for (int c = 0; c < 8; c++)
                RG(s[c], s[8 + ((c + 1) & 7)], s[16 + ((c + 2) & 7)], s[24 + ((c + 3) & 7)]);
            break;
        default: {
            int rows[3], k = 0;
            for (int i = 0; i < 4; i++)
                if (i != (r & 3)) rows[k++] = i;
            for (int c = 0; c < 8; c++) {
                uint64_t *x = &s[rows[0] * 8 + c], *y = &s[rows[1] * 8 + ((c + 3) & 7)],
                         *z = &s[rows[2] * 8 + ((c + 5) & 7)];
                uint64_t X = *x, Y = *y, Z = *z;
                *x = X ^ (~Y & Z); *y = Y ^ (~Z & X); *z = Z ^ (~X & Y);
            }
        }
        }
    }
    for (int i = 0; i < 4; i++) st64(out + 8 * i, s[i]);
}

typedef void (*core_fn)(int, const uint8_t *, uint8_t *);
static const core_fn CORES[NALGS] = {sha256_core, sha3_512_core, blake2b_core,
                                     ram1024_core, ram_steps_core, blake2b_halves};

void lab_core(int alg, int rounds, const uint8_t *in, uint8_t *out)
{
    CORES[alg](rounds, in, out);
}

/* ---------------- test kernels ---------------- */
static uint64_t rng_next(uint64_t *s) /* splitmix64 */
{
    uint64_t z = (*s += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static void rand_block(uint64_t *s, uint8_t *b)
{
    for (int i = 0; i < 8; i++) st64(b + 8 * i, rng_next(s));
}

/* Strict avalanche: counts[i*256+j] = #samples where flipping input bit i
 * flipped output bit j. */
void lab_sac(int alg, int rounds, int samples, uint32_t *counts, uint64_t seed)
{
    core_fn f = CORES[alg];
    uint8_t x[64], y0[32], y1[32];
    memset(counts, 0, sizeof(uint32_t) * 512 * 256);
    for (int n = 0; n < samples; n++) {
        rand_block(&seed, x);
        f(rounds, x, y0);
        for (int i = 0; i < 512; i++) {
            x[i >> 3] ^= 1 << (i & 7);
            f(rounds, x, y1);
            x[i >> 3] ^= 1 << (i & 7);
            uint32_t *row = counts + i * 256;
            for (int j = 0; j < 32; j++) {
                uint8_t d = y0[j] ^ y1[j];
                while (d) {
                    int b = __builtin_ctz(d);
                    row[j * 8 + b]++;
                    d &= d - 1;
                }
            }
        }
    }
}

/* Cube / higher-order differential test.
 * Chooses k input bit positions (the cube) from cube_seed using a strategy:
 *   0 random positions, 1 k contiguous bits, 2 k evenly spaced bits.
 * For `trials` random settings of all other bits (from trial_seed) it
 * XOR-sums the output over all 2^k cube assignments. Output bits whose sum
 * is identical in every trial are constant -> algebraic distinguisher.
 * Returns the number of constant output bits. */
int lab_cube(int alg, int rounds, int k, int trials, int strategy,
             uint64_t cube_seed, uint64_t trial_seed)
{
    core_fn f = CORES[alg];
    int pos[32];
    int start = (int)(rng_next(&cube_seed) % 512);
    for (int i = 0; i < k; i++) {
        if (strategy == 1) {
            pos[i] = (start + i) % 512;
        } else if (strategy == 2) {
            pos[i] = (start + i * (512 / k)) % 512;
        } else {
            int p, dup;
            do {
                p = (int)(rng_next(&cube_seed) % 512);
                dup = 0;
                for (int j = 0; j < i; j++) dup |= pos[j] == p;
            } while (dup);
            pos[i] = p;
        }
    }
    uint8_t and_[32], or_[32];
    memset(and_, 0xff, 32);
    memset(or_, 0, 32);
    for (int t = 0; t < trials; t++) {
        uint8_t base[64], x[64], y[32], sum[32] = {0};
        rand_block(&trial_seed, base);
        for (int i = 0; i < k; i++) base[pos[i] >> 3] &= ~(1 << (pos[i] & 7));
        for (uint64_t m = 0; m < (1ULL << k); m++) {
            memcpy(x, base, 64);
            for (int i = 0; i < k; i++)
                if (m >> i & 1) x[pos[i] >> 3] |= 1 << (pos[i] & 7);
            f(rounds, x, y);
            for (int j = 0; j < 32; j++) sum[j] ^= y[j];
        }
        for (int j = 0; j < 32; j++) { and_[j] &= sum[j]; or_[j] |= sum[j]; }
    }
    int constant = 0;
    for (int j = 0; j < 32; j++)
        constant += __builtin_popcount(and_[j]) + __builtin_popcount((uint8_t)~or_[j]);
    return constant;
}

/* Training data for a Gohr-style neural distinguisher.
 * label 1: a = F(x), b = F(x ^ delta);  label 0: a = F(x), b = F(y), y random.
 * feats: n * 768 bytes of 0/1 = bits of a || b || a^b. */
void lab_pairs(int alg, int rounds, int delta_bit, int n, uint8_t *feats,
               uint8_t *labels, uint64_t seed)
{
    core_fn f = CORES[alg];
    uint8_t x[64], y[64], a[32], b[32];
    for (int s = 0; s < n; s++) {
        int lab = (int)(rng_next(&seed) & 1);
        rand_block(&seed, x);
        if (lab) {
            memcpy(y, x, 64);
            y[delta_bit >> 3] ^= 1 << (delta_bit & 7);
        } else {
            rand_block(&seed, y);
        }
        f(rounds, x, a);
        f(rounds, y, b);
        uint8_t *row = feats + (size_t)s * 768;
        for (int j = 0; j < 256; j++) {
            row[j] = (a[j >> 3] >> (j & 7)) & 1;
            row[256 + j] = (b[j >> 3] >> (j & 7)) & 1;
            row[512 + j] = row[j] ^ row[256 + j];
        }
        labels[s] = (uint8_t)lab;
    }
}

/* Multi-pair variant (Gohr-style amplification): each sample holds k pairs
 * from the same class; feats = n * k * 256 difference bits. */
void lab_pairs_multi(int alg, int rounds, int delta_bit, int k, int n,
                     uint8_t *feats, uint8_t *labels, uint64_t seed)
{
    core_fn f = CORES[alg];
    uint8_t x[64], y[64], a[32], b[32];
    for (int s = 0; s < n; s++) {
        int lab = (int)(rng_next(&seed) & 1);
        uint8_t *row = feats + (size_t)s * k * 256;
        for (int p = 0; p < k; p++) {
            rand_block(&seed, x);
            if (lab) {
                memcpy(y, x, 64);
                y[delta_bit >> 3] ^= 1 << (delta_bit & 7);
            } else {
                rand_block(&seed, y);
            }
            f(rounds, x, a);
            f(rounds, y, b);
            for (int j = 0; j < 256; j++)
                row[p * 256 + j] = ((a[j >> 3] ^ b[j >> 3]) >> (j & 7)) & 1;
        }
        labels[s] = (uint8_t)lab;
    }
}

/* Counter-mode output stream from the full-round core. */
void lab_stream(int alg, uint8_t *out, size_t blocks, uint64_t seed)
{
    uint8_t x[64] = {0};
    st64(x + 8, seed);
    for (size_t i = 0; i < blocks; i++) {
        st64(x, (uint64_t)i);
        CORES[alg](lab_full_rounds[alg], x, out + 32 * i);
    }
}

/* Seconds for `iters` full-round core calls. */
double lab_bench_core(int alg, long iters)
{
    uint8_t x[64] = {1}, y[32];
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (long i = 0; i < iters; i++) {
        CORES[alg](lab_full_rounds[alg], x, y);
        x[0] ^= y[0];
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return (t1.tv_sec - t0.tv_sec) + 1e-9 * (t1.tv_nsec - t0.tv_nsec);
}

int lab_ram_rounds(void) { return RAM_ROUNDS; }

/* Rotational test: does F(rotl(x)) agree with rotl(F(x)) more than chance?
 * Rotates every 64-bit word of the input/output by `rot`. Returns the
 * z-score of the number of agreeing output bits over n samples. */
double lab_rotational(int alg, int rounds, int n, int rot, uint64_t seed)
{
    core_fn f = CORES[alg];
    uint8_t x[64], xr[64], y[32], yr[32];
    long agree = 0;
    for (int s = 0; s < n; s++) {
        rand_block(&seed, x);
        for (int i = 0; i < 8; i++) st64(xr + 8 * i, ROTL64(ld64(x + 8 * i), rot));
        f(rounds, x, y);
        f(rounds, xr, yr);
        for (int i = 0; i < 4; i++)
            agree += 64 - __builtin_popcountll(ROTL64(ld64(y + 8 * i), rot) ^
                                               ld64(yr + 8 * i));
    }
    double mean = 128.0 * n, sd = 8.0 * __builtin_sqrt((double)n);
    return (agree - mean) / sd;
}

/* Benchmark helper: ns per permutation call for width 1, 2 or 4 states
 * (0 = the reference loop). */
double ram_bench_permute(int width, int rounds, long iters)
{
    static uint64_t st[4 * 32];
    for (int i = 0; i < 4 * 32; i++) st[i] = (uint64_t)i * 0x9e3779b97f4a7c15ULL;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (long i = 0; i < iters; i++) {
        if (width == 4) ram_permute_x4(st, rounds);
        else if (width == 2) ram_permute_x2(st, rounds);
        else if (width == 0) ram_permute_ref(st, rounds);
        else ram_permute(st, rounds);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return ((t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec)) / iters;
}
