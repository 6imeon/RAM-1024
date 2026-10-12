/* BLAKE2b's internal permutation (16 x 64-bit words, message words fixed to
 * zero so it is a keyless permutation) at half-round resolution, both
 * directions - the same full-state, inside-out setting perm_lab.c uses for
 * RAM-1024, so the two can be calibrated like for like. */
#include <stdint.h>
#include <string.h>

#define ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define ROTL(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static void g_fwd(uint64_t *v, int a, int b, int c, int d)
{
    v[a] += v[b]; v[d] = ROTR(v[d] ^ v[a], 32);
    v[c] += v[d]; v[b] = ROTR(v[b] ^ v[c], 24);
    v[a] += v[b]; v[d] = ROTR(v[d] ^ v[a], 16);
    v[c] += v[d]; v[b] = ROTR(v[b] ^ v[c], 63);
}

static void g_inv(uint64_t *v, int a, int b, int c, int d)
{
    v[b] = ROTL(v[b], 63) ^ v[c]; v[c] -= v[d];
    v[d] = ROTL(v[d], 16) ^ v[a]; v[a] -= v[b];
    v[b] = ROTL(v[b], 24) ^ v[c]; v[c] -= v[d];
    v[d] = ROTL(v[d], 32) ^ v[a]; v[a] -= v[b];
}

static const int COL[4][4] = {{0, 4, 8, 12}, {1, 5, 9, 13}, {2, 6, 10, 14}, {3, 7, 11, 15}};
static const int DIA[4][4] = {{0, 5, 10, 15}, {1, 6, 11, 12}, {2, 7, 8, 13}, {3, 4, 9, 14}};

static void half(uint64_t *v, int h, int dir)
{
    const int (*q)[4] = (h % 2 == 0) ? COL : DIA;
    if (dir > 0)
        for (int i = 0; i < 4; i++) g_fwd(v, q[i][0], q[i][1], q[i][2], q[i][3]);
    else
        for (int i = 3; i >= 0; i--) g_inv(v, q[i][0], q[i][1], q[i][2], q[i][3]);
}

void b2_run(uint64_t *v, int n, int dir)
{
    if (dir > 0)
        for (int h = 0; h < n; h++) half(v, h, 1);
    else
        for (int h = n - 1; h >= 0; h--) half(v, h, -1);
}

static uint64_t rnd(uint64_t *x)
{
    uint64_t z = (*x += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

/* counts[i*1024 + j] += [flip state bit i flips output bit j] */
void b2_sac(int n, int dir, int samples, uint32_t *counts, uint64_t seed)
{
    uint64_t x[16], y0[16], y1[16];
    memset(counts, 0, sizeof(uint32_t) * 1024 * 1024);
    for (int t = 0; t < samples; t++) {
        for (int i = 0; i < 16; i++) x[i] = rnd(&seed);
        memcpy(y0, x, sizeof x);
        b2_run(y0, n, dir);
        for (int i = 0; i < 1024; i++) {
            memcpy(y1, x, sizeof x);
            y1[i >> 6] ^= 1ULL << (i & 63);
            b2_run(y1, n, dir);
            uint32_t *row = counts + (size_t)i * 1024;
            for (int w = 0; w < 16; w++) {
                uint64_t d = y0[w] ^ y1[w];
                while (d) {
                    row[w * 64 + __builtin_ctzll(d)]++;
                    d &= d - 1;
                }
            }
        }
    }
}

int b2_selftest(void)
{
    uint64_t seed = 1, x[16], y[16];
    for (int t = 0; t < 50; t++) {
        for (int i = 0; i < 16; i++) x[i] = y[i] = rnd(&seed);
        b2_run(y, 24, 1);
        b2_run(y, 24, -1);
        if (memcmp(x, y, sizeof x)) return 1;
    }
    return 0;
}
