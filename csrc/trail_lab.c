/* Differential trail search on the RAM-1024 permutation (cryptanalysis
 * round 6). XOR differences are propagated step by step:
 *
 *   modular addition : exact Markov carry model (Lipmaa-Moriai). At bit i
 *                      with input differences a_i, b_i and carry difference
 *                      c_i, the output difference is a_i^b_i^c_i; if the
 *                      three are not all equal (and i < 63) the next carry
 *                      difference is free, at a cost of 1 bit of weight.
 *                      A 2-state Viterbi pass finds a minimum-weight output.
 *                      Subtraction (inverse direction) has the identical
 *                      cost rule, so the same routine serves both ways.
 *   chi3             : exact 8x8 difference table, best output per column.
 *   rotations, iota  : linear / constant, no cost.
 *
 * Ties are broken at random; many restarts from many starting differences
 * (every single bit, every pair of top bits) at every step offset give the
 * lowest-weight trail found, forward and backward, per number of steps.
 * Weight w means probability 2^-w for the characteristic. This is an
 * upper bound on the minimum weight (the search is heuristic): an attacker
 * may find lighter trails, which the margin has to cover.
 *
 *     cc -O2 -o build/trail_search csrc/trail_lab.c && ./build/trail_search 12 8
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#include "ram_constants.h"

#define ROTR(x, n) (((x) >> (n)) | ((x) << ((64 - (n)) & 63)))
#define ROTL(x, n) ROTR(x, (64 - (n)) & 63)

static const int RHO[16] = {1, 27, 53, 15, 41, 3, 29, 55, 17, 43, 5, 31, 57, 19, 45, 7};

static uint64_t rng = 0x9e3779b97f4a7c15ULL;
static uint64_t rnd(void)
{
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng;
}

/* Minimum-weight output difference of (x + y) for input differences a, b.
 * Also serves the inverse: x_old = x_new - y with a = diff(x_new). */
static uint64_t add_diff(uint64_t a, uint64_t b, int *w, int randomize)
{
    /* Viterbi over carry state. cost[c] = min weight so far with carry c. */
    int cost[2] = {0, 1 << 20};
    uint8_t choice[64][2]; /* previous carry for (bit, carry) */
    for (int i = 0; i < 63; i++) {
        int ai = (a >> i) & 1, bi = (b >> i) & 1;
        int nc[2] = {1 << 20, 1 << 20};
        uint8_t from[2] = {0, 0};
        for (int c = 0; c < 2; c++) {
            if (cost[c] >= 1 << 20) continue;
            if (ai == bi && bi == c) { /* all equal: carry diff forced */
                int t = cost[c];
                if (t < nc[c] || (t == nc[c] && randomize && (rnd() & 1))) {
                    nc[c] = t;
                    from[c] = (uint8_t)c;
                }
            } else {
                for (int n = 0; n < 2; n++) {
                    int t = cost[c] + 1;
                    if (t < nc[n] || (t == nc[n] && randomize && (rnd() & 1))) {
                        nc[n] = t;
                        from[n] = (uint8_t)c;
                    }
                }
            }
        }
        choice[i + 1][0] = from[0];
        choice[i + 1][1] = from[1];
        cost[0] = nc[0];
        cost[1] = nc[1];
    }
    int c = cost[0] < cost[1] || (cost[0] == cost[1] && (!randomize || (rnd() & 1))) ? 0 : 1;
    *w += cost[c];
    /* walk back the carry path */
    uint64_t carries = 0;
    for (int i = 63; i >= 1; i--) {
        if (c) carries |= 1ULL << i;
        c = choice[i][c];
    }
    return a ^ b ^ carries;
}

/* chi3 S-box (x,y,z) -> (x^(~y&z), y^(~z&x), z^(~x&y)); bit0=x. */
static int ddt[8][8];
static void build_ddt(void)
{
    for (int v = 0; v < 8; v++)
        for (int d = 0; d < 8; d++) {
            int f[2], in[2] = {v, v ^ d};
            for (int k = 0; k < 2; k++) {
                int x = in[k] & 1, y = (in[k] >> 1) & 1, z = (in[k] >> 2) & 1;
                f[k] = (x ^ (~y & z & 1)) | (y ^ (~z & x & 1)) << 1 | (z ^ (~x & y & 1)) << 2;
            }
            ddt[d][f[0] ^ f[1]]++;
        }
}

static int chi_best(int d, int randomize)
{
    int best = 0, bestn = 0, ties = 0;
    for (int o = 0; o < 8; o++) {
        if (ddt[d][o] > bestn) {
            bestn = ddt[d][o];
            best = o;
            ties = 1;
        } else if (ddt[d][o] == bestn && randomize && (rnd() % (uint64_t)++ties) == 0) {
            best = o;
        }
    }
    return best;
}

static int chi_weight(int d, int o)
{
    int n = ddt[d][o];
    return n == 8 ? 0 : n == 4 ? 1 : n == 2 ? 2 : 3;
}

static int RND; /* randomize ties */

static void g_fwd(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d, int *w)
{
    *a = add_diff(*a, *b, w, RND); *d = ROTR(*d ^ *a, 32);
    *c = add_diff(*c, *d, w, RND); *b = ROTR(*b ^ *c, 24);
    *a = add_diff(*a, *b, w, RND); *d = ROTR(*d ^ *a, 16);
    *c = add_diff(*c, *d, w, RND); *b = ROTR(*b ^ *c, 63);
}

static void g_inv(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d, int *w)
{
    *b = ROTL(*b, 63) ^ *c; *c = add_diff(*c, *d, w, RND);
    *d = ROTL(*d, 16) ^ *a; *a = add_diff(*a, *b, w, RND);
    *b = ROTL(*b, 24) ^ *c; *c = add_diff(*c, *d, w, RND);
    *d = ROTL(*d, 32) ^ *a; *a = add_diff(*a, *b, w, RND);
}

static void chi_layer(uint64_t *s, int r, int *w)
{
    int skip = r & 3, rows[3], k = 0;
    for (int i = 0; i < 4; i++)
        if (i != skip) rows[k++] = i;
    for (int c = 0; c < 8; c++) {
        uint64_t *X = &s[rows[0] * 8 + c], *Y = &s[rows[1] * 8 + ((c + 3) & 7)],
                 *Z = &s[rows[2] * 8 + ((c + 5) & 7)];
        uint64_t act = *X | *Y | *Z, nx = 0, ny = 0, nz = 0;
        while (act) {
            int b = __builtin_ctzll(act);
            act &= act - 1;
            int d = (int)((*X >> b) & 1) | (int)((*Y >> b) & 1) << 1 | (int)((*Z >> b) & 1) << 2;
            int o = chi_best(d, RND);
            *w += chi_weight(d, o);
            nx |= (uint64_t)(o & 1) << b;
            ny |= (uint64_t)((o >> 1) & 1) << b;
            nz |= (uint64_t)((o >> 2) & 1) << b;
        }
        *X = nx;
        *Y = ny;
        *Z = nz;
    }
}

/* step t of round r: 0 = iota+column G+rho, 1 = diagonal G, 2 = chi */
static void step_fwd(uint64_t *s, int r, int t, int *w)
{
    if (t == 0) {
        for (int c = 0; c < 8; c++) g_fwd(&s[c], &s[8 + c], &s[16 + c], &s[24 + c], w);
        for (int i = 0; i < 16; i++) s[16 + i] = ROTR(s[16 + i], 64 - RHO[i]);
    } else if (t == 1) {
        for (int c = 0; c < 8; c++)
            g_fwd(&s[c], &s[8 + ((c + 1) & 7)], &s[16 + ((c + 2) & 7)], &s[24 + ((c + 3) & 7)], w);
    } else {
        chi_layer(s, r, w);
    }
}

static void step_inv(uint64_t *s, int r, int t, int *w)
{
    if (t == 0) {
        for (int i = 0; i < 16; i++) s[16 + i] = ROTL(s[16 + i], 64 - RHO[i]);
        for (int c = 0; c < 8; c++) g_inv(&s[c], &s[8 + c], &s[16 + c], &s[24 + c], w);
    } else if (t == 1) {
        for (int c = 0; c < 8; c++)
            g_inv(&s[c], &s[8 + ((c + 1) & 7)], &s[16 + ((c + 2) & 7)], &s[24 + ((c + 3) & 7)], w);
    } else {
        chi_layer(s, r, w); /* chi3 is an involution: same table */
    }
}

#define MAXSTEPS 24

/* Run nsteps from start difference, starting at absolute step index st
 * (round st/3, step st%3); record the cumulative weight after each step. */
static void trail(const uint64_t *start, int st, int nsteps, int dir, int *wout,
                  uint64_t (*snap)[32])
{
    uint64_t s[32];
    memcpy(s, start, sizeof s);
    int w = 0;
    for (int k = 0; k < nsteps; k++) {
        int a = dir > 0 ? st + k : st - 1 - k; /* step being applied / undone */
        a = ((a % 12) + 12) % 12;           /* rounds matter only mod 4 */
        if (dir > 0) step_fwd(s, a / 3, a % 3, &w);
        else step_inv(s, a / 3, a % 3, &w);
        wout[k] = w;
        memcpy(snap[k], s, sizeof s);
    }
}

/* ---- real permutation steps (values, with constants) for verification ---- */
#define G(a, b, c, d)                                                 \
    do {                                                              \
        a += b; d = ROTR(d ^ a, 32); c += d; b = ROTR(b ^ c, 24);     \
        a += b; d = ROTR(d ^ a, 16); c += d; b = ROTR(b ^ c, 63);     \
    } while (0)
#define GI(a, b, c, d)                                                \
    do {                                                              \
        b = ROTL(b, 63) ^ c; c -= d; d = ROTL(d, 16) ^ a; a -= b;     \
        b = ROTL(b, 24) ^ c; c -= d; d = ROTL(d, 32) ^ a; a -= b;     \
    } while (0)

static void chi_val(uint64_t *s, int r)
{
    int skip = r & 3, rows[3], k = 0;
    for (int i = 0; i < 4; i++)
        if (i != skip) rows[k++] = i;
    for (int c = 0; c < 8; c++) {
        uint64_t *x = &s[rows[0] * 8 + c], *y = &s[rows[1] * 8 + ((c + 3) & 7)],
                 *z = &s[rows[2] * 8 + ((c + 5) & 7)];
        uint64_t X = *x, Y = *y, Z = *z;
        *x = X ^ (~Y & Z); *y = Y ^ (~Z & X); *z = Z ^ (~X & Y);
    }
}

static void real_step(uint64_t *s, int a, int dir)
{
    int r = a / 3, t = a % 3;
    if (dir > 0) {
        if (t == 0) {
            for (int c = 0; c < 8; c++) s[(c & 3) * 8 + c] ^= RAM_RC[r * 8 + c];
            for (int c = 0; c < 8; c++) G(s[c], s[8 + c], s[16 + c], s[24 + c]);
            for (int i = 0; i < 16; i++) s[16 + i] = ROTR(s[16 + i], 64 - RHO[i]);
        } else if (t == 1) {
            for (int c = 0; c < 8; c++)
                G(s[c], s[8 + ((c + 1) & 7)], s[16 + ((c + 2) & 7)], s[24 + ((c + 3) & 7)]);
        } else chi_val(s, r);
    } else {
        if (t == 0) {
            for (int i = 0; i < 16; i++) s[16 + i] = ROTL(s[16 + i], 64 - RHO[i]);
            for (int c = 0; c < 8; c++) GI(s[c], s[8 + c], s[16 + c], s[24 + c]);
            for (int c = 0; c < 8; c++) s[(c & 3) * 8 + c] ^= RAM_RC[r * 8 + c];
        } else if (t == 1) {
            for (int c = 0; c < 8; c++)
                GI(s[c], s[8 + ((c + 1) & 7)], s[16 + ((c + 2) & 7)], s[24 + ((c + 3) & 7)]);
        } else chi_val(s, r);
    }
}

/* Fraction of random pairs with input difference `in` whose difference
 * after nsteps equals `out` (a differential: >= the characteristic). */
static double verify(const uint64_t *in, const uint64_t *out, int st, int nsteps,
                     int dir, long pairs)
{
    long hit = 0;
    for (long p = 0; p < pairs; p++) {
        uint64_t x[32], y[32];
        for (int i = 0; i < 32; i++) { x[i] = rnd(); y[i] = x[i] ^ in[i]; }
        for (int k = 0; k < nsteps; k++) {
            int a = dir > 0 ? st + k : st - 1 - k;
            a = ((a % 12) + 12) % 12;
            real_step(x, a, dir);
            real_step(y, a, dir);
        }
        int ok = 1;
        for (int i = 0; i < 32 && ok; i++) ok = (x[i] ^ y[i]) == out[i];
        hit += ok;
    }
    return (double)hit / (double)pairs;
}

/* ---------------- linear trails (round 7) ----------------
 * Masks propagate from the output of a step back to its input (the
 * transpose). For a = a + b with output mask u on the new a, input masks v
 * (old a) and w (b): by Wallen's theorem the correlation is +-2^-HW(z),
 * z = M^T(u^v^w) (z_63 = 0, z_i = z_{i+1} ^ s_{i+1}), and it is nonzero iff
 * (u^v) and (u^w) are covered by z. So v, w may differ from u only where
 * z = 1; a 2-state Viterbi pass from the top bit picks the lightest z. */

static void add_mask(uint64_t u, uint64_t *v, uint64_t *w, int *wt, int randomize)
{
    int cost[2] = {0, 1 << 20}; /* z_63 = 0 */
    uint8_t from[64][2];
    for (int i = 62; i >= 0; i--) {
        int ub = (u >> (i + 1)) & 1, nc[2] = {1 << 20, 1 << 20};
        uint8_t fr[2] = {0, 0};
        for (int z = 0; z < 2; z++) {
            if (cost[z] >= 1 << 20) continue;
            for (int nz = 0; nz < 2; nz++) {
                if (!z && nz != ub) continue; /* z_{i+1} = 0: s forced to u */
                int t = cost[z] + nz;
                if (t < nc[nz] || (t == nc[nz] && randomize && (rnd() & 1))) {
                    nc[nz] = t;
                    fr[nz] = (uint8_t)z;
                }
            }
        }
        from[i][0] = fr[0];
        from[i][1] = fr[1];
        cost[0] = nc[0];
        cost[1] = nc[1];
    }
    int z = cost[0] < cost[1] || (cost[0] == cost[1] && (!randomize || (rnd() & 1))) ? 0 : 1;
    *wt += cost[z];
    /* rebuild z (bits 0..62), then p, q: where s_{i+1} != u_{i+1} flip v or w */
    uint64_t zz = 0;
    for (int i = 0; i <= 62; i++) {
        if (z) zz |= 1ULL << i;
        if (i < 62) z = from[i][z];
    }
    uint64_t p = 0, q = 0;
    for (int i = 0; i < 63; i++) {
        int zi = (zz >> i) & 1, zi1 = i + 1 <= 62 ? (zz >> (i + 1)) & 1 : 0;
        int s1 = zi ^ zi1, ub = (u >> (i + 1)) & 1;
        if (s1 != ub) { /* need p^q = 1 at bit i+1 (allowed: z_{i+1} = 1) */
            if (randomize && (rnd() & 1)) q |= 1ULL << (i + 1);
            else p |= 1ULL << (i + 1);
        }
    }
    *v = u ^ p;
    *w = u ^ q;
}

static int lat[8][8]; /* lat[in][out] = sum (-1)^(in.x ^ out.S(x)) */
static void build_lat(void)
{
    for (int a = 0; a < 8; a++)
        for (int b = 0; b < 8; b++) {
            int t = 0;
            for (int x = 0; x < 8; x++) {
                int X = x & 1, Y = (x >> 1) & 1, Z = (x >> 2) & 1;
                int y = (X ^ (~Y & Z & 1)) | (Y ^ (~Z & X & 1)) << 1 | (Z ^ (~X & Y & 1)) << 2;
                t += ((__builtin_popcount((unsigned)(a & x)) + __builtin_popcount((unsigned)(b & y))) & 1) ? -1 : 1;
            }
            lat[a][b] = t;
        }
}

static void chi_mask(uint64_t *s, int r, int *wt)
{
    int skip = r & 3, rows[3], k = 0;
    for (int i = 0; i < 4; i++)
        if (i != skip) rows[k++] = i;
    for (int c = 0; c < 8; c++) {
        uint64_t *X = &s[rows[0] * 8 + c], *Y = &s[rows[1] * 8 + ((c + 3) & 7)],
                 *Z = &s[rows[2] * 8 + ((c + 5) & 7)];
        uint64_t act = *X | *Y | *Z, nx = 0, ny = 0, nz = 0;
        while (act) {
            int b = __builtin_ctzll(act);
            act &= act - 1;
            int o = (int)((*X >> b) & 1) | (int)((*Y >> b) & 1) << 1 | (int)((*Z >> b) & 1) << 2;
            int best = 0, ties = 0, bm = 0;
            for (int in = 0; in < 8; in++) {
                int m = abs(lat[in][o]);
                if (m > bm) { bm = m; best = in; ties = 1; }
                else if (m == bm && RND && (rnd() % (uint64_t)++ties) == 0) best = in;
            }
            *wt += bm == 8 ? 0 : bm == 4 ? 1 : bm == 2 ? 2 : 3;
            nx |= (uint64_t)(best & 1) << b;
            ny |= (uint64_t)((best >> 1) & 1) << b;
            nz |= (uint64_t)((best >> 2) & 1) << b;
        }
        *X = nx; *Y = ny; *Z = nz;
    }
}

/* G forward = 12 ops; masks walk them in reverse. */
static void g_mask(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d, int *wt)
{
    uint64_t v, w;
    *b = ROTL(*b, 63); *c ^= *b;                         /* 12, 11 */
    add_mask(*c, &v, &w, wt, RND); *c = v; *d ^= w;      /* 10: c += d */
    *d = ROTL(*d, 16); *a ^= *d;                         /* 9, 8 */
    add_mask(*a, &v, &w, wt, RND); *a = v; *b ^= w;      /* 7: a += b */
    *b = ROTL(*b, 24); *c ^= *b;                         /* 6, 5 */
    add_mask(*c, &v, &w, wt, RND); *c = v; *d ^= w;      /* 4: c += d */
    *d = ROTL(*d, 32); *a ^= *d;                         /* 3, 2 */
    add_mask(*a, &v, &w, wt, RND); *a = v; *b ^= w;      /* 1: a += b */
}

/* masks after step (r, t) -> masks before it */
static void step_mask(uint64_t *s, int r, int t, int *wt)
{
    if (t == 0) {
        for (int i = 0; i < 16; i++) s[16 + i] = ROTL(s[16 + i], 64 - RHO[i]);
        for (int c = 0; c < 8; c++) g_mask(&s[c], &s[8 + c], &s[16 + c], &s[24 + c], wt);
    } else if (t == 1) {
        for (int c = 0; c < 8; c++)
            g_mask(&s[c], &s[8 + ((c + 1) & 7)], &s[16 + ((c + 2) & 7)], &s[24 + ((c + 3) & 7)], wt);
    } else {
        chi_mask(s, r, wt);
    }
}

/* Empirical |correlation| of (in . x) ^ (out . P_steps(x)). */
static double lin_verify(const uint64_t *in, const uint64_t *out, int st, int nsteps, long n)
{
    long agree = 0;
    for (long p = 0; p < n; p++) {
        uint64_t x[32], y[32];
        for (int i = 0; i < 32; i++) x[i] = y[i] = rnd();
        for (int k = 0; k < nsteps; k++) real_step(y, ((st + k) % 12 + 12) % 12, 1);
        int par = 0;
        for (int i = 0; i < 32; i++)
            par ^= __builtin_parityll(x[i] & in[i]) ^ __builtin_parityll(y[i] & out[i]);
        agree += par ? -1 : 1;
    }
    return fabs((double)agree / (double)n);
}

static int linear_main(int nsteps, int restarts)
{
    build_lat();
    int best[MAXSTEPS];
    char where[MAXSTEPS][64];
    static uint64_t bin[MAXSTEPS][32], bout[MAXSTEPS][32];
    static int bst[MAXSTEPS];
    for (int k = 0; k < MAXSTEPS; k++) best[k] = 1 << 30;
    /* output masks: every single bit, every pair of word LSBs */
    int nstart = 2048 + 32 * 31 / 2;
    for (int sidx = 0; sidx < nstart; sidx++) {
        uint64_t s0[32] = {0};
        char desc[64];
        if (sidx < 2048) {
            s0[sidx / 64] = 1ULL << (sidx % 64);
            snprintf(desc, sizeof desc, "out word %d bit %d", sidx / 64, sidx % 64);
        } else {
            int p = sidx - 2048, i = 0;
            while (p >= 31 - i) p -= 31 - i++;
            int j = i + 1 + p;
            s0[i] = s0[j] = 1;
            snprintf(desc, sizeof desc, "out LSB of words %d,%d", i, j);
        }
        for (int end = 0; end < 12; end++) /* trail ends after step `end` */
            for (int rr = 0; rr < restarts; rr++) {
                RND = rr > 0;
                uint64_t m[32];
                memcpy(m, s0, sizeof m);
                int wt = 0;
                for (int k = 0; k < nsteps; k++) {
                    int a = ((end - k) % 12 + 12) % 12;
                    step_mask(m, a / 3, a % 3, &wt);
                    if (wt < best[k]) {
                        best[k] = wt;
                        memcpy(bin[k], m, sizeof m);
                        memcpy(bout[k], s0, sizeof m);
                        bst[k] = a; /* first step of the trail */
                        snprintf(where[k], 64, "%s @step %d", desc, end);
                    }
                }
            }
    }
    printf("{\"restarts\": %d, \"starts\": %d,\n \"linear\": [", restarts, nstart);
    for (int k = 0; k < nsteps; k++) {
        double emp = -1;
        if (best[k] <= 8) emp = lin_verify(bin[k], bout[k], bst[k], k + 1, 1L << 22);
        printf("%s{\"steps\": %d, \"weight\": %d, \"start\": \"%s\", \"empirical_corr\": %.3g}",
               k ? ", " : "", k + 1, best[k], where[k], emp);
    }
    printf("]}\n");
    return 0;
}

/* ---------------- rotational-XOR trails (round 7) ----------------
 * Pairs (x, (x <<< 1) ^ D). Rotations, XORs and chi commute with rotation,
 * so D propagates exactly like an XOR difference through them; each
 * constant XOR injects (c <<< 1) ^ c; each modular addition costs the XOR-
 * differential weight plus log2(8/3) = 1.415 (rotational probability of
 * addition, Ashur-Liu 2016) whether its inputs are active or not. Rounds
 * are absolute here: the constants differ in every round. */
#define RX_ADD 1.415
static double rx_trail(int start_round, int nsteps, int dir, double *wout)
{
    uint64_t s[32] = {0}; /* best case for the attacker: exact rotational pair */
    int w = 0;
    double extra = 0;
    for (int k = 0; k < nsteps; k++) {
        int a = dir > 0 ? 3 * start_round + k : 3 * start_round - 1 - k;
        if (a < 0 || a >= 3 * 64) { wout[k] = 1e9; continue; }
        int r = a / 3, t = a % 3;
        if (dir > 0) {
            if (t == 0 && k > 0) /* the first injection is cancelled by the start D */
                for (int c = 0; c < 8; c++)
                    s[(c & 3) * 8 + c] ^= ROTL(RAM_RC[8 * r + c], 1) ^ RAM_RC[8 * r + c];
            step_fwd(s, r, t, &w);
        } else {
            step_inv(s, r, t, &w);
            if (t == 0)
                for (int c = 0; c < 8; c++)
                    s[(c & 3) * 8 + c] ^= ROTL(RAM_RC[8 * r + c], 1) ^ RAM_RC[8 * r + c];
        }
        if (t < 2) extra += 32 * RX_ADD;
        wout[k] = w + extra;
    }
    return wout[nsteps - 1];
}

static int rx_main(int nsteps, int restarts)
{
    build_ddt();
    printf("{\"restarts\": %d,\n", restarts);
    for (int dir = 1; dir >= -1; dir -= 2) {
        double best[MAXSTEPS];
        int at[MAXSTEPS];
        for (int k = 0; k < MAXSTEPS; k++) best[k] = 1e18;
        for (int r0 = 0; r0 <= 64; r0++)
            for (int rr = 0; rr < restarts; rr++) {
                RND = rr > 0;
                double w[MAXSTEPS];
                rx_trail(r0, nsteps, dir, w);
                for (int k = 0; k < nsteps; k++)
                    if (w[k] < best[k]) { best[k] = w[k]; at[k] = r0; }
            }
        printf(" \"%s\": [", dir > 0 ? "forward" : "backward");
        for (int k = 0; k < nsteps; k++)
            printf("%s{\"steps\": %d, \"weight\": %.0f, \"round\": %d}", k ? ", " : "", k + 1,
                   best[k], at[k]);
        printf("]%s\n", dir > 0 ? "," : "");
    }
    printf("}\n");
    return 0;
}

/* ---------------- boomerang (round 9) ----------------
 * E = E1 o S o E0 around a middle of m steps S (the "switch"). E0 is a
 * trail run backward from beta, E1 a trail run forward from gamma, both in
 * the differential model above. The switch is measured on the real steps:
 * x1 = x0 ^ beta, y = S(x), y' = y ^ gamma, x' = S^-1(y'); success if
 * x2 ^ x3 == beta. Ladder / BCT effects (free switches in ARX) show up here
 * as probabilities far above the trail estimate. Quartet cost exponent:
 * switch + 2 * w(E0) + 2 * w(E1), reported against 2^1024 and 2^2048. */
#define BK_K 12
#define BK_M 6

static void bk_cand(int i, uint64_t *s)
{
    memset(s, 0, 32 * sizeof *s);
    if (i < 32) s[i] = 1ULL << 63;
    else if (i < 64) s[i - 32] = 1;
    else {
        int p = i - 64, a = 0;
        while (p >= 31 - a) p -= 31 - a++;
        s[a] = s[a + 1 + p] = 1ULL << 63;
    }
}

static int bk_return(const uint64_t *beta, const uint64_t *gamma, int st, int m, long q)
{
    int hit = 0;
    for (long n = 0; n < q; n++) {
        uint64_t x[32], y[32];
        for (int i = 0; i < 32; i++) { x[i] = rnd(); y[i] = x[i] ^ beta[i]; }
        for (int k = 0; k < m; k++) { real_step(x, (st + k) % 12, 1); real_step(y, (st + k) % 12, 1); }
        for (int i = 0; i < 32; i++) { x[i] ^= gamma[i]; y[i] ^= gamma[i]; }
        for (int k = m - 1; k >= 0; k--) { real_step(x, (st + k) % 12, -1); real_step(y, (st + k) % 12, -1); }
        int ok = 1;
        for (int i = 0; i < 32 && ok; i++) ok = (x[i] ^ y[i]) == beta[i];
        hit += ok;
    }
    return hit;
}

static int boomerang_main(int restarts, int st)
{
    enum { NC = 64 + 32 * 31 / 2 };
    static int bw[12][NC][BK_K + 1], fw[12][NC][BK_K + 1];
    static uint64_t snap[MAXSTEPS][32];
    build_ddt();
    for (int st = 0; st < 12; st++)
        for (int i = 0; i < NC; i++) {
            uint64_t s0[32];
            bk_cand(i, s0);
            for (int k = 1; k <= BK_K; k++) bw[st][i][k] = fw[st][i][k] = 1 << 28;
            bw[st][i][0] = fw[st][i][0] = 0;
            for (int rr = 0; rr < restarts; rr++) {
                int w[MAXSTEPS];
                RND = rr > 0;
                trail(s0, st, BK_K, -1, w, snap);
                for (int k = 0; k < BK_K; k++) if (w[k] < bw[st][i][k + 1]) bw[st][i][k + 1] = w[k];
                trail(s0, st, BK_K, 1, w, snap);
                for (int k = 0; k < BK_K; k++) if (w[k] < fw[st][i][k + 1]) fw[st][i][k + 1] = w[k];
            }
        }
    const long Q1 = 32, Q2 = 1L << 14;
    int best_sw[BK_M + 1], nfree[BK_M + 1], nseen[BK_M + 1];
    int reach[2] = {0, 0}, rk[2][5];
    double rw[2] = {0, 0};
    for (int m = 0; m <= BK_M; m++) { best_sw[m] = m ? 99 : 0; nfree[m] = nseen[m] = 0; }
    for (int m = 0; m <= BK_M; m++)
        for (int i = 0; i < NC; i++)
                for (int j = 0; j < NC; j++) {
                    double ws = 0;
                    if (m) {
                        uint64_t b[32], g[32];
                        bk_cand(i, b);
                        bk_cand(j, g);
                        long q = Q1, h = bk_return(b, g, st, m, Q1);
                        if (!h) continue;
                        while (h < 64 && q < Q2) { h += bk_return(b, g, st, m, q); q *= 2; }
                        ws = -log2((double)h / (double)q);
                        nseen[m]++;
                        if (h == q) nfree[m]++;
                        if ((int)ceil(ws) < best_sw[m]) best_sw[m] = (int)ceil(ws);
                    }
                    for (int k0 = 0; k0 <= BK_K; k0++)
                        for (int k1 = 0; k1 <= BK_K; k1++) {
                            double tot = ws + 2.0 * bw[st][i][k0] + 2.0 * fw[(st + m) % 12][j][k1];
                            int steps = k0 + m + k1;
                            for (int b = 0; b < 2; b++)
                                if (tot <= (b ? 2048 : 1024) &&
                                    (steps > reach[b] || (steps == reach[b] && tot < rw[b]))) {
                                    reach[b] = steps; rw[b] = tot;
                                    rk[b][0] = k0; rk[b][1] = m; rk[b][2] = k1; rk[b][3] = st;
                                    rk[b][4] = i * NC + j;
                                }
                        }
                }
    printf("{\"offset\": %d, \"restarts\": %d, \"candidates\": %d, \"max_quartets\": %ld,\n \"switch\": [",
           st, restarts, NC, Q2);
    for (int m = 1; m <= BK_M; m++)
        printf("%s{\"middle_steps\": %d, \"best_weight\": %d, \"pairs_returning\": %d, \"pairs_free\": %d}",
               m > 1 ? ", " : "", m, best_sw[m] == 99 ? -1 : best_sw[m], nseen[m], nfree[m]);
    printf("],\n");
    for (int b = 0; b < 2; b++) {
        /* re-measure the winning switch with 2^16 quartets (the scan stops at 64 hits) */
        uint64_t bb[32], gg[32];
        double chk = 0;
        bk_cand(rk[b][4] / NC, bb);
        bk_cand(rk[b][4] % NC, gg);
        if (rk[b][1]) {
            int h = bk_return(bb, gg, st, rk[b][1], 1L << 16);
            chk = h ? -log2(h / 65536.0) : 99;
        }
        printf(" \"reach_le_%d\": {\"steps\": %d, \"weight\": %.1f, \"top\": %d, \"switch\": %d, "
               "\"bottom\": %d, \"offset\": %d, \"beta\": %d, \"gamma\": %d, "
               "\"switch_weight_2^16\": %.2f, \"top_weight\": %d, \"bottom_weight\": %d}%s\n",
               b ? 2048 : 1024, reach[b], rw[b], rk[b][0], rk[b][1], rk[b][2], rk[b][3],
               rk[b][4] / NC, rk[b][4] % NC, chk, bw[st][rk[b][4] / NC][rk[b][0]],
               fw[(st + rk[b][1]) % 12][rk[b][4] % NC][rk[b][2]], b ? "" : ",");
    }
    printf("}\n");
    return 0;
}

/* Targeted boomerang (round 9b): all 2544 starting differences of the
 * round-6 search (every single bit, every MSB pair). For a target length T
 * and every split T = k0 + m + k1, take the TOPN lightest backward trails
 * (k0 steps) as beta and the TOPN lightest forward trails (k1 steps) as
 * gamma, and measure the switch of every pair on the real permutation. */
#define TOPN 48
enum { NC2 = 2048 + 32 * 31 / 2 };
static void bk_cand2(int i, uint64_t *s)
{
    memset(s, 0, 32 * sizeof *s);
    if (i < 2048) s[i / 64] = 1ULL << (i % 64);
    else bk_cand(64 + i - 2048, s);
}

static int bw2[12][NC2][BK_K + 1], fw2[12][NC2][BK_K + 1];
static int cmp_key[NC2];
static int by_key(const void *a, const void *b)
{
    return cmp_key[*(const int *)a] - cmp_key[*(const int *)b];
}

static int boomerang2_main(int restarts, int st, int tmin, int tmax)
{
    static uint64_t snap[MAXSTEPS][32];
    build_ddt();
    for (int o = 0; o < 12; o++)
        for (int i = 0; i < NC2; i++) {
            uint64_t s0[32];
            bk_cand2(i, s0);
            for (int k = 1; k <= BK_K; k++) bw2[o][i][k] = fw2[o][i][k] = 1 << 28;
            bw2[o][i][0] = fw2[o][i][0] = 0;
            for (int rr = 0; rr < restarts; rr++) {
                int w[MAXSTEPS];
                RND = rr > 0;
                trail(s0, o, BK_K, -1, w, snap);
                for (int k = 0; k < BK_K; k++) if (w[k] < bw2[o][i][k + 1]) bw2[o][i][k + 1] = w[k];
                trail(s0, o, BK_K, 1, w, snap);
                for (int k = 0; k < BK_K; k++) if (w[k] < fw2[o][i][k + 1]) fw2[o][i][k + 1] = w[k];
            }
        }
    static int ib[NC2], ig[NC2];
    printf("{\"offset\": %d, \"candidates\": %d, \"topn\": %d, \"best\": [", st, NC2, TOPN);
    for (int T = tmin; T <= tmax; T++) {
        double best = 1e9;
        int bk[5] = {0};
        double bsw = 0;
        for (int m = 1; m <= BK_M; m++)
            for (int k0 = 1; k0 + m < T; k0++) {
                int k1 = T - m - k0;
                if (k0 > BK_K || k1 > BK_K) continue;
                for (int i = 0; i < NC2; i++) { ib[i] = ig[i] = i; }
                for (int i = 0; i < NC2; i++) cmp_key[i] = bw2[st][i][k0];
                qsort(ib, NC2, sizeof *ib, by_key);
                for (int i = 0; i < NC2; i++) cmp_key[i] = fw2[(st + m) % 12][i][k1];
                qsort(ig, NC2, sizeof *ig, by_key);
                double floor_ = 2.0 * bw2[st][ib[0]][k0] + 2.0 * fw2[(st + m) % 12][ig[0]][k1];
                if (floor_ >= best) continue;
                for (int a = 0; a < TOPN; a++)
                    for (int c = 0; c < TOPN; c++) {
                        int i = ib[a], j = ig[c];
                        double tw = 2.0 * bw2[st][i][k0] + 2.0 * fw2[(st + m) % 12][j][k1];
                        if (tw >= best) continue;
                        uint64_t b[32], g[32];
                        bk_cand2(i, b);
                        bk_cand2(j, g);
                        long q = 32, h = bk_return(b, g, st, m, 32);
                        if (!h) continue;
                        while (h < 64 && q < (1L << 14)) { h += bk_return(b, g, st, m, q); q *= 2; }
                        double ws = -log2((double)h / (double)q);
                        if (tw + ws < best) {
                            best = tw + ws; bsw = ws;
                            bk[0] = k0; bk[1] = m; bk[2] = k1; bk[3] = i; bk[4] = j;
                        }
                    }
            }
        if (best < 1e9) {
            uint64_t b[32], g[32];
            bk_cand2(bk[3], b);
            bk_cand2(bk[4], g);
            int h = bk_return(b, g, st, bk[1], 1L << 16);
            double chk = h ? -log2(h / 65536.0) : 99;
            best += chk - bsw;
        }
        printf("%s{\"steps\": %d, \"weight\": %.1f, \"top\": %d, \"switch\": %d, \"bottom\": %d, "
               "\"beta\": %d, \"gamma\": %d, \"top_weight\": %d, \"bottom_weight\": %d}",
               T > tmin ? ", " : "", T, best, bk[0], bk[1], bk[2], bk[3], bk[4],
               bw2[st][bk[3]][bk[0]], fw2[(st + bk[1]) % 12][bk[4]][bk[2]]);
        fflush(stdout);
    }
    printf("]}\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "boomerang2")) {
        int st = argc > 3 ? atoi(argv[3]) : 0;
        rng += (uint64_t)(st + 101) * 0xd1342543de82ef95ULL;
        if (!rng) rng = 1;
        return boomerang2_main(argc > 2 ? atoi(argv[2]) : 4, ((st % 12) + 12) % 12,
                               argc > 4 ? atoi(argv[4]) : 15, argc > 5 ? atoi(argv[5]) : 18);
    }
    if (argc > 1 && !strcmp(argv[1], "boomerang"))
    {
        int st = argc > 3 ? atoi(argv[3]) : 0;
        rng += (uint64_t)(st + 1) * 0xd1342543de82ef95ULL; /* stays nonzero: xorshift must not be 0 */
        if (!rng) rng = 1;
        return boomerang_main(argc > 2 ? atoi(argv[2]) : 4, ((st % 12) + 12) % 12);
    }
    if (argc > 1 && !strcmp(argv[1], "rx")) {
        int n = argc > 2 ? atoi(argv[2]) : 12, r = argc > 3 ? atoi(argv[3]) : 4;
        return rx_main(n > MAXSTEPS ? MAXSTEPS : n, r);
    }
    if (argc > 1 && !strcmp(argv[1], "linear")) {
        int n = argc > 2 ? atoi(argv[2]) : 12, r = argc > 3 ? atoi(argv[3]) : 4;
        return linear_main(n > MAXSTEPS ? MAXSTEPS : n, r);
    }
    int nsteps = argc > 1 ? atoi(argv[1]) : 12;
    int restarts = argc > 2 ? atoi(argv[2]) : 8;
    if (nsteps > MAXSTEPS) nsteps = MAXSTEPS;
    build_ddt();
    int best[2][MAXSTEPS];
    char where[2][MAXSTEPS][64];
    static uint64_t bin[2][MAXSTEPS][32], bout[2][MAXSTEPS][32];
    static int bst[2][MAXSTEPS];
    static uint64_t snap[MAXSTEPS][32];
    for (int d = 0; d < 2; d++)
        for (int k = 0; k < MAXSTEPS; k++) best[d][k] = 1 << 30;

    /* starting differences: all single bits, all pairs of word MSBs */
    int nstart = 2048 + 32 * 31 / 2;
    for (int dir = 1; dir >= -1; dir -= 2) {
        int di = dir > 0 ? 0 : 1;
        for (int sidx = 0; sidx < nstart; sidx++) {
            uint64_t s0[32] = {0};
            char desc[64];
            if (sidx < 2048) {
                s0[sidx / 64] = 1ULL << (sidx % 64);
                snprintf(desc, sizeof desc, "word %d bit %d", sidx / 64, sidx % 64);
            } else {
                int p = sidx - 2048, i = 0;
                while (p >= 31 - i) p -= 31 - i++;
                int j = i + 1 + p;
                s0[i] = s0[j] = 1ULL << 63;
                snprintf(desc, sizeof desc, "MSB of words %d,%d", i, j);
            }
            for (int st = 0; st < 12; st++)
                for (int rr = 0; rr < restarts; rr++) {
                    RND = rr > 0;
                    int w[MAXSTEPS];
                    trail(s0, st, nsteps, dir, w, snap);
                    for (int k = 0; k < nsteps; k++)
                        if (w[k] < best[di][k]) {
                            best[di][k] = w[k];
                            memcpy(bin[di][k], s0, sizeof s0);
                            memcpy(bout[di][k], snap[k], sizeof s0);
                            bst[di][k] = st;
                            snprintf(where[di][k], 64, "%s @step %d", desc, st);
                        }
                }
        }
    }
    printf("{\"restarts\": %d, \"starts\": %d,\n", restarts, nstart);
    for (int di = 0; di < 2; di++) {
        printf(" \"%s\": [", di ? "backward" : "forward");
        for (int k = 0; k < nsteps; k++)
        {
            /* empirical check of short trails: P(differential) >= 2^-w */
            double emp = -1;
            if (best[di][k] <= 16)
                emp = verify(bin[di][k], bout[di][k], bst[di][k], k + 1, di ? -1 : 1, 1L << 20);
            printf("%s{\"steps\": %d, \"weight\": %d, \"start\": \"%s\", \"empirical_p\": %.3g}",
                   k ? ", " : "", k + 1, best[di][k], where[di][k], emp);
        }
        printf("]%s\n", di ? "" : ",");
    }
    printf("}\n");
    return 0;
}
