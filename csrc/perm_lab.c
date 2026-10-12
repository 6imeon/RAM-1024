/* Permutation-level cryptanalysis lab for RAM-1024.
 *
 * Unlike lab.c (which only varies 512 message bits through the sponge),
 * these kernels give the attacker the whole 2048-bit state, in BOTH
 * directions, at step resolution (3 steps per round:
 * iota+column-G, diagonal-G, chi). This is the setting of inside-out
 * permutation distinguishers (zero-sum, boomerang, rebound).
 */
#include <stdint.h>
#include <string.h>

#include "ram1024.h"
#include "ram_constants.h"

/* Design-exploration variants (lab only):
 *  bit0  round constants into all 32 words (RC words r*32+w) instead of row 0
 *  bit1  word shuffle after chi: row r rotated by 2r columns (order 4)
 *  bit2  word shuffle after chi: transpose-like row mixing (row r col c ->
 *        row (r + c) & 3, same col) - moves words across rows
 *  bit3  rho: rotate every word w left by RHO[w] after chi (Keccak-like)
 *  bit4  rho on rows 2-3 only (half the cost)
 *  bit5  same 8 constants per round, spread diagonally: word ((c&3)*8 + c)
 *  bit6  rho applied after the column step instead of after chi          */
static int RHO[32] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8,
    1, 27, 53, 15, 41, 3, 29, 55, 17, 43, 5, 31, 57, 19, 45, 7};
int perm_variant = 112; /* = v3: diagonal constants + mid-round rho rows 2-3 */
static uint64_t RC_ALL[64 * 32];
static int rc_all_ready;
void perm_set_rc_all(const uint64_t *rc) { memcpy(RC_ALL, rc, sizeof RC_ALL); rc_all_ready = 1; }
void perm_set_variant(int v) { perm_variant = v; }
void perm_set_rho16(const int *r) { memcpy(RHO + 16, r, 16 * sizeof(int)); }

static void shuffle(uint64_t *s, int inverse)
{
    uint64_t t[32];
    memcpy(t, s, sizeof t);
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 8; c++) {
            int dst;
            if (perm_variant & 2) dst = r * 8 + ((c + 2 * r) & 7);
            else dst = ((r + c) & 3) * 8 + c;
            if (inverse) s[r * 8 + c] = t[dst];
            else s[dst] = t[r * 8 + c];
        }
}

static void rho(uint64_t *s, int inverse)
{
    int lo = (perm_variant & 8) ? 0 : 16;
    for (int w = lo; w < 32; w++) {
        int k = RHO[w];
        s[w] = inverse ? ((s[w] >> k) | (s[w] << (64 - k)))
                       : ((s[w] << k) | (s[w] >> (64 - k)));
    }
}

static void iota(uint64_t *s, int r)
{
    if (perm_variant & 32) {
        for (int c = 0; c < 8; c++) s[(c & 3) * 8 + c] ^= RAM_RC[r * 8 + c];
        return;
    }
    if (perm_variant & 1)
        for (int w = 0; w < 32; w++) s[w] ^= RC_ALL[r * 32 + w];
    else
        for (int c = 0; c < 8; c++) s[c] ^= RAM_RC[r * 8 + c];
}

#define ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define ROTL(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static void g_fwd(uint64_t *s, int a, int b, int c, int d)
{
    s[a] += s[b]; s[d] = ROTR(s[d] ^ s[a], 32);
    s[c] += s[d]; s[b] = ROTR(s[b] ^ s[c], 24);
    s[a] += s[b]; s[d] = ROTR(s[d] ^ s[a], 16);
    s[c] += s[d]; s[b] = ROTR(s[b] ^ s[c], 63);
}

static void g_inv(uint64_t *s, int a, int b, int c, int d)
{
    s[b] = ROTL(s[b], 63) ^ s[c]; s[c] -= s[d];
    s[d] = ROTL(s[d], 16) ^ s[a]; s[a] -= s[b];
    s[b] = ROTL(s[b], 24) ^ s[c]; s[c] -= s[d];
    s[d] = ROTL(s[d], 32) ^ s[a]; s[a] -= s[b];
}

static void chi_layer(uint64_t *s, int r) /* an involution: own inverse */
{
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

void perm_step(uint64_t *s, int st)
{
    int r = st / 3;
    switch (st % 3) {
    case 0:
        iota(s, r);
        for (int c = 0; c < 8; c++) g_fwd(s, c, 8 + c, 16 + c, 24 + c);
        if ((perm_variant & 64) && (perm_variant & 24)) rho(s, 0);
        break;
    case 1:
        for (int c = 0; c < 8; c++)
            g_fwd(s, c, 8 + ((c + 1) & 7), 16 + ((c + 2) & 7), 24 + ((c + 3) & 7));
        break;
    default:
        chi_layer(s, r);
        if (perm_variant & 6) shuffle(s, 0);
        if ((perm_variant & 24) && !(perm_variant & 64)) rho(s, 0);
    }
}

void perm_step_inv(uint64_t *s, int st)
{
    int r = st / 3;
    switch (st % 3) {
    case 0:
        if ((perm_variant & 64) && (perm_variant & 24)) rho(s, 1);
        for (int c = 7; c >= 0; c--) g_inv(s, c, 8 + c, 16 + c, 24 + c);
        iota(s, r);
        break;
    case 1:
        for (int c = 7; c >= 0; c--)
            g_inv(s, c, 8 + ((c + 1) & 7), 16 + ((c + 2) & 7), 24 + ((c + 3) & 7));
        break;
    default:
        if ((perm_variant & 24) && !(perm_variant & 64)) rho(s, 1);
        if (perm_variant & 6) shuffle(s, 1);
        chi_layer(s, r);
    }
}

/* dir > 0: steps [first, first+n) forward; dir < 0: the inverse of those. */
void perm_run(uint64_t *s, int first, int n, int dir)
{
    if (dir > 0)
        for (int i = 0; i < n; i++) perm_step(s, first + i);
    else
        for (int i = n - 1; i >= 0; i--) perm_step_inv(s, first + i);
}

static uint64_t rnd(uint64_t *x)
{
    uint64_t z = (*x += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

/* Full-state SAC: counts[i*2048+j] += [flip input bit i flips output bit j].
 * Input bits restricted to words [w0, w1). */
void perm_sac(int first, int n, int dir, int samples, int w0, int w1,
              uint32_t *counts, uint64_t seed)
{
    uint64_t x[32], y0[32], y1[32];
    memset(counts, 0, sizeof(uint32_t) * 2048 * 2048);
    for (int t = 0; t < samples; t++) {
        for (int i = 0; i < 32; i++) x[i] = rnd(&seed);
        memcpy(y0, x, sizeof x);
        perm_run(y0, first, n, dir);
        for (int i = 64 * w0; i < 64 * w1; i++) {
            memcpy(y1, x, sizeof x);
            y1[i >> 6] ^= 1ULL << (i & 63);
            perm_run(y1, first, n, dir);
            uint32_t *row = counts + (size_t)i * 2048;
            for (int w = 0; w < 32; w++) {
                uint64_t d = y0[w] ^ y1[w];
                while (d) {
                    row[w * 64 + __builtin_ctzll(d)]++;
                    d &= d - 1;
                }
            }
        }
    }
}

/* Linear bit-to-bit test: counts[i*2048+j] += [x_i == y_j]. */
void perm_linear(int first, int n, int dir, long samples, uint32_t *counts,
                 uint64_t seed)
{
    uint64_t x[32], y[32];
    memset(counts, 0, sizeof(uint32_t) * 2048 * 2048);
    for (long t = 0; t < samples; t++) {
        for (int i = 0; i < 32; i++) x[i] = y[i] = rnd(&seed);
        perm_run(y, first, n, dir);
        for (int i = 0; i < 2048; i++) {
            uint64_t xi = (x[i >> 6] >> (i & 63)) & 1 ? ~0ULL : 0;
            uint32_t *row = counts + (size_t)i * 2048;
            for (int w = 0; w < 32; w++) {
                uint64_t eq = ~(xi ^ y[w]);
                while (eq) {
                    row[w * 64 + __builtin_ctzll(eq)]++;
                    eq &= eq - 1;
                }
            }
        }
    }
}

/* Column-shift symmetry: shift every row by k columns. Returns z-score of
 * agreement between shift(P(x)) and P(shift(x)) over n samples. */
double perm_colshift(int first, int nsteps, int dir, int n, int k, uint64_t seed)
{
    uint64_t x[32], xs[32], y[32], ys[32];
    long agree = 0;
    for (int t = 0; t < n; t++) {
        for (int i = 0; i < 32; i++) x[i] = rnd(&seed);
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 8; c++) xs[r * 8 + ((c + k) & 7)] = x[r * 8 + c];
        memcpy(y, x, sizeof x);
        perm_run(y, first, nsteps, dir);
        perm_run(xs, first, nsteps, dir);
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 8; c++) ys[r * 8 + ((c + k) & 7)] = y[r * 8 + c];
        for (int i = 0; i < 32; i++) agree += 64 - __builtin_popcountll(ys[i] ^ xs[i]);
    }
    double mean = 1024.0 * n, sd = 16.0 * __builtin_sqrt((double)n);
    return (agree - mean) / sd;
}

/* Sanity: inverse undoes forward on random states. Returns 0 if OK. */
int perm_selftest(void)
{
    int saved = perm_variant;
    for (int v = 0; v < 128; v++) {
        if ((v & 6) == 6 || (v & 24) == 24 || ((v & 32) && (v & 1))) continue;
        perm_variant = v;
        uint64_t seed = 3, x[32], y[32];
        for (int t = 0; t < 20; t++) {
            for (int i = 0; i < 32; i++) x[i] = y[i] = rnd(&seed);
            perm_run(y, 0, 30, 1);
            perm_run(y, 0, 30, -1);
            if (memcmp(x, y, sizeof x)) { perm_variant = saved; return 10 + v; }
        }
    }
    perm_variant = 112;
    uint64_t seed = 7, x[32], y[32];
    for (int t = 0; t < 100; t++) {
        for (int i = 0; i < 32; i++) x[i] = y[i] = rnd(&seed);
        perm_run(y, 0, 3 * RAM_ROUNDS, 1);
        uint64_t z[32];
        memcpy(z, x, sizeof z);
        ram_permute(z, RAM_ROUNDS);
        if (memcmp(y, z, sizeof z)) return 1; /* step model == real permutation */
        perm_run(y, 0, 3 * RAM_ROUNDS, -1);
        if (memcmp(x, y, sizeof x)) return 2;
    }
    perm_variant = saved;
    return 0;
}

/* Full-state zero-sum / higher-order differential. Cube of k state bits
 * (strategy 0 random, 1 contiguous, 2 same bit position b in k distinct
 * words, 3 low bits: bit (i/32) of word (i%32)); sums the n-step output in
 * direction dir over the cube for `trials` random bases. Returns the number
 * of output bits (of 2048) that are constant across trials. */
int perm_cube(int first, int n, int dir, int k, int trials, int strategy,
              uint64_t cube_seed, uint64_t trial_seed)
{
    int pos[24];
    int start = (int)(rnd(&cube_seed) % 2048);
    for (int i = 0; i < k; i++) {
        if (strategy == 1) pos[i] = (start + i) % 2048;
        else if (strategy == 2) pos[i] = ((start / 64 + i) % 32) * 64 + start % 64;
        else if (strategy == 3) pos[i] = (i % 32) * 64 + i / 32;
        else {
            int p, dup;
            do {
                p = (int)(rnd(&cube_seed) % 2048);
                dup = 0;
                for (int j = 0; j < i; j++) dup |= pos[j] == p;
            } while (dup);
            pos[i] = p;
        }
    }
    uint64_t and_[32], or_[32];
    memset(and_, 0xff, sizeof and_);
    memset(or_, 0, sizeof or_);
    for (int t = 0; t < trials; t++) {
        uint64_t base[32], x[32], sum[32] = {0};
        for (int i = 0; i < 32; i++) base[i] = rnd(&trial_seed);
        for (int i = 0; i < k; i++) base[pos[i] >> 6] &= ~(1ULL << (pos[i] & 63));
        for (uint64_t m = 0; m < (1ULL << k); m++) {
            memcpy(x, base, sizeof x);
            for (int i = 0; i < k; i++)
                if (m >> i & 1) x[pos[i] >> 6] |= 1ULL << (pos[i] & 63);
            perm_run(x, first, n, dir);
            for (int i = 0; i < 32; i++) sum[i] ^= x[i];
        }
        for (int i = 0; i < 32; i++) { and_[i] &= sum[i]; or_[i] |= sum[i]; }
    }
    int c = 0;
    for (int i = 0; i < 32; i++)
        c += __builtin_popcountll(and_[i]) + __builtin_popcountll(~or_[i]);
    return c;
}

/* Samples for linear-algebra tests: x (32 words) and P_n(x) per sample. */
void perm_samples(int first, int n, int dir, int count, uint64_t *xs, uint64_t *ys,
                  uint64_t seed)
{
    for (int t = 0; t < count; t++) {
        for (int i = 0; i < 32; i++) xs[t * 32 + i] = ys[t * 32 + i] = rnd(&seed);
        perm_run(ys + t * 32, first, n, dir);
    }
}
