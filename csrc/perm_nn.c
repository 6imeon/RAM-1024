/* Neural-distinguisher data on the RAM-1024 permutation, full state,
 * either direction: label 1 pairs (x, x ^ e_bit), label 0 (x, random y).
 * feats: n * 2048 bytes (0/1) of the output difference. */
#include <stdint.h>
#include <string.h>

void perm_run(uint64_t *s, int first, int n, int dir);

static uint64_t rnd(uint64_t *x)
{
    uint64_t z = (*x += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

void perm_pairs(int n, int dir, int bit, int count, uint8_t *feats, uint8_t *labels,
                uint64_t seed)
{
    uint64_t a[32], b[32];
    for (int s = 0; s < count; s++) {
        int lab = (int)(rnd(&seed) & 1);
        for (int i = 0; i < 32; i++) a[i] = rnd(&seed);
        if (lab) {
            memcpy(b, a, sizeof a);
            b[bit >> 6] ^= 1ULL << (bit & 63);
        } else {
            for (int i = 0; i < 32; i++) b[i] = rnd(&seed);
        }
        perm_run(a, 0, n, dir);
        perm_run(b, 0, n, dir);
        uint8_t *row = feats + (size_t)s * 2048;
        for (int w = 0; w < 32; w++) {
            uint64_t d = a[w] ^ b[w];
            for (int j = 0; j < 64; j++) row[w * 64 + j] = (d >> j) & 1;
        }
        labels[s] = (uint8_t)lab;
    }
}
