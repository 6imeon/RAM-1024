/* Portable conformance test for the C library (no Python needed):
 *
 *     ram_test tests/kat.txt
 *
 * Checks the permutation self-test, every known-answer vector through the
 * one-shot, streaming (several split patterns) and multithreaded paths,
 * parameter validation, and ram_verify. Exit status 0 = all passed. */
/* MSVC deprecates standard C stdio in favour of its _s variants. */
#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ram1024.h"

static int failures, nrejected;

#define CHECK(cond, ...)                                       \
    do {                                                       \
        if (!(cond)) {                                         \
            failures++;                                        \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
            fprintf(stderr, __VA_ARGS__);                      \
            fputc('\n', stderr);                               \
        }                                                      \
    } while (0)

static void fill_msg(uint8_t *m, size_t n)
{
    for (size_t i = 0; i < n; i++) m[i] = (uint8_t)(i * i * 7 + i * 13 + 1);
}

static void fill_key(uint8_t *k, size_t n)
{
    for (size_t i = 0; i < n; i++) k[i] = (uint8_t)(i * 31 + 0xa5);
}

static int unhex(const char *h, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(h + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return h[2 * n] == '\0' || h[2 * n] == '\n' || h[2 * n] == '\r' ? 0 : -1;
}

static void streamed(uint8_t *out, size_t outlen, const uint8_t *m, size_t n,
                     int rounds, int mode, const uint8_t *k, size_t kl, size_t step)
{
    ram_ctx *c = malloc(sizeof *c);
    if (!c || ram_init(c, outlen, mode, rounds, k, kl)) {
        failures++;
        free(c);
        return;
    }
    for (size_t off = 0; off < n; off += step)
        if (ram_update(c, m + off, n - off < step ? n - off : step)) failures++;
    if (ram_final(c, out)) failures++;
    free(c);
}

static int run_kat(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        perror(path);
        return -1;
    }
    static char line[1 << 14];
    int nvec = 0;
    static const size_t steps[] = {1, 7, 128, 129, 4096, 16384, 16385};
    while (fgets(line, sizeof line, f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        int mode, rounds, pos;
        unsigned long outlen, kl, n;
        if (sscanf(line, "%d %d %lu %lu %lu %n", &mode, &rounds, &outlen, &kl, &n,
                   &pos) != 5) {
            CHECK(0, "bad KAT line: %s", line);
            continue;
        }
        uint8_t *want = malloc(outlen), *got = malloc(outlen);
        uint8_t *m = malloc(n + 1), *k = malloc(kl + 1);
        if (!want || !got || !m || !k) return -1;
        CHECK(unhex(line + pos, want, outlen) == 0, "bad hex in KAT %d", nvec);
        fill_msg(m, n);
        fill_key(k, kl);

        if (ram_check_params(outlen, mode, rounds)) {
            /* research-only vector: a production build must refuse it */
#ifdef RAM_RESEARCH
            CHECK(0, "research build rejected KAT %d", nvec);
#else
            CHECK(ram_hash(got, outlen, m, n, rounds, mode, kl ? k : NULL, kl) == -1,
                  "accepted research-only KAT %d", nvec);
            CHECK(mode != RAM_MODE_HASH || ram_hash_tree(got, outlen, m, n, rounds, 0) == -1,
                  "tree accepted research-only KAT %d", nvec);
            nrejected++;
#endif
            free(want); free(got); free(m); free(k);
            nvec++;
            continue;
        }
        CHECK(ram_hash(got, outlen, m, n, rounds, mode, kl ? k : NULL, kl) == 0,
              "ram_hash rejected KAT %d", nvec);
        CHECK(!memcmp(got, want, outlen), "one-shot KAT %d (mode %d, len %lu)",
              nvec, mode, n);
        for (size_t s = 0; s < sizeof steps / sizeof *steps; s++) {
            if (steps[s] > n && s) break;
            memset(got, 0, outlen);
            streamed(got, outlen, m, n, rounds, mode, k, kl, steps[s]);
            CHECK(!memcmp(got, want, outlen), "stream(step %lu) KAT %d",
                  (unsigned long)steps[s], nvec);
        }
        if (mode == RAM_MODE_HASH) {
            static const int threads[] = {0, 1, 3};
            for (int t = 0; t < 3; t++) {
                memset(got, 0, outlen);
                CHECK(ram_hash_tree(got, outlen, m, n, rounds, threads[t]) == 0,
                      "tree rejected KAT %d", nvec);
                CHECK(!memcmp(got, want, outlen), "tree(%d threads) KAT %d",
                      threads[t], nvec);
            }
        }
        free(want);
        free(got);
        free(m);
        free(k);
        nvec++;
    }
    fclose(f);
    return nvec;
}

static int run_pw_kat(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        perror(path);
        return -1;
    }
    char line[2048];
    int nvec = 0;
    while (fgets(line, sizeof line, f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        unsigned long outlen, m, t, p, pl, sl;
        int pos;
        if (sscanf(line, "%lu %lu %lu %lu %lu %lu %n", &outlen, &m, &t, &p, &pl, &sl,
                   &pos) != 6) {
            CHECK(0, "bad pwhash KAT line: %s", line);
            continue;
        }
        uint8_t want[1024], got[1024], pw[1024], salt[1024];
        if (outlen > 1024 || pl > 1024 || sl > 1024) return -1;
        CHECK(unhex(line + pos, want, outlen) == 0, "bad hex in pwhash KAT %d", nvec);
        fill_msg(pw, pl);
        fill_key(salt, sl);
        CHECK(ram_pwhash(got, outlen, pw, pl, salt, sl, (uint32_t)m, (uint32_t)t,
                         (uint32_t)p) == 0, "pwhash rejected KAT %d", nvec);
        CHECK(!memcmp(got, want, outlen), "pwhash KAT %d", nvec);
        nvec++;
    }
    fclose(f);
    return nvec;
}

static void test_pw_params(void)
{
    uint8_t out[64], salt[16] = {0};
    CHECK(ram_pwhash(out, 32, NULL, 0, salt, 16, 8, 1, 1) == 0, "pw minimal");
    CHECK(ram_pwhash(out, 31, NULL, 0, salt, 16, 8, 1, 1) == -1, "pw out 31");
    CHECK(ram_pwhash(out, 32, NULL, 0, salt, 15, 8, 1, 1) == -1, "pw salt 15");
    CHECK(ram_pwhash(out, 32, NULL, 0, salt, 16, 8, 0, 1) == -1, "pw t 0");
    CHECK(ram_pwhash(out, 32, NULL, 0, salt, 16, 8, 1, 0) == -1, "pw lanes 0");
    CHECK(ram_pwhash(out, 32, NULL, 0, salt, 16, 15, 1, 2) == -1, "pw m < 8/lane");
    CHECK(ram_pwhash(out, 32, NULL, 0, salt, 16, 8 * 17, 1, 17) == -1, "pw lanes 17");
    CHECK(ram_pwhash(out, 32, NULL, 0, salt, 16, 8, RAM_PW_MAX_T + 1, 1) == -1, "pw t max");
    CHECK(ram_pwhash(out, 32, NULL, 0, salt, 16, RAM_PW_MAX_KIB + 1, 1, 1) == -1, "pw m max");
}

static void test_params(void)
{
    uint8_t out[64], key[40] = {0};
    ram_ctx *c = malloc(sizeof *c);
    if (!c) return;
    CHECK(ram_hash(out, 64, NULL, 0, 0, RAM_MODE_HASH, NULL, 0) == -1, "rounds 0");
#ifndef RAM_RESEARCH
    CHECK(ram_hash(out, 64, NULL, 0, 63, RAM_MODE_HASH, NULL, 0) == -1, "rounds 63");
    CHECK(ram_hash(out, 64, NULL, 0, 1, RAM_MODE_XOF, NULL, 0) == -1, "rounds 1");
    CHECK(ram_hash(out, 31, NULL, 0, 64, RAM_MODE_HASH, NULL, 0) == -1, "hash out 31");
    CHECK(ram_hash(out, 32, NULL, 0, 64, RAM_MODE_HASH, NULL, 0) == 0, "hash out 32");
    CHECK(ram_hash(out, 15, NULL, 0, 64, RAM_MODE_MAC, key, 16) == -1, "tag 15");
    CHECK(ram_hash(out, 1, NULL, 0, 64, RAM_MODE_XOF, NULL, 0) == 0, "xof 1");
#endif
    CHECK(ram_hash(out, 64, NULL, 0, 65, RAM_MODE_HASH, NULL, 0) == -1, "rounds 65");
    CHECK(ram_hash(out, 0, NULL, 0, 64, RAM_MODE_HASH, NULL, 0) == -1, "outlen 0");
    CHECK(ram_hash(out, 64, NULL, 0, 64, 9, NULL, 0) == -1, "mode 9");
    CHECK(ram_hash(out, 64, NULL, 0, 64, RAM_MODE_LEAF, NULL, 0) == -1, "mode LEAF");
    CHECK(ram_hash(out, 64, NULL, 0, 64, RAM_MODE_HASH, key, 16) == -1, "key in HASH");
    CHECK(ram_hash(out, 64, NULL, 0, 64, RAM_MODE_MAC, key, 15) == -1, "MAC key 15");
    CHECK(ram_hash(out, 64, NULL, 0, 64, RAM_MODE_MAC, key, 16) == 0, "MAC key 16");
    CHECK(ram_init(c, 64, RAM_MODE_MAC, 64, key, 0) == -1, "init MAC no key");
    CHECK(ram_hash_tree(out, 64, NULL, 0, 99, 0) == -1, "tree rounds 99");
    CHECK(ram_ctx_size() == sizeof(ram_ctx), "ctx size");
    /* final wipes the context and refuses reuse (review round 10) */
    CHECK(ram_init(c, 32, RAM_MODE_MAC, 64, key, 16) == 0, "init MAC");
    CHECK(ram_update(c, key, 40) == 0 && ram_final(c, out) == 0, "MAC final");
    CHECK(ram_update(c, key, 40) == -1, "update after final");
    CHECK(ram_final(c, out) == -1, "final after final");
    CHECK(ram_init(c, 64, RAM_MODE_HASH, 64, NULL, 0) == 0 && ram_update(c, key, 40) == 0,
          "fresh stream");
    CHECK(ram_init(c, 64, RAM_MODE_HASH, 99, NULL, 0) == -1, "bad re-init");
    CHECK(ram_update(c, key, 1) == -1 && ram_final(c, out) == -1, "failed init kills old stream");
    {
        static uint8_t big[3 * 16384];
        int dirty = 0;
        memset(big, 0x5a, sizeof big);
        ram_init(c, 64, RAM_MODE_HASH, 64, NULL, 0);
        ram_update(c, big, sizeof big);
        ram_final(c, out);
        for (size_t i = 0; i < sizeof *c; i++) dirty |= ((uint8_t *)c)[i];
        CHECK(!dirty, "context wiped after final");
    }
    /* exported tree helpers clamp their range */
    {
        uint8_t cvs[2 * 128];
        ram_tree_leaves_cpu(key, 0, 0, 5, cvs, 64, 1);
        ram_tree_leaves_cpu(key, 40, 0, 9, cvs, 64, 1);
    }
    free(c);
}

static void test_verify(void)
{
    uint8_t a[100], b[100];
    fill_msg(a, 100);
    memcpy(b, a, 100);
    CHECK(ram_verify(a, b, 100) == 0, "verify equal");
    CHECK(ram_verify(a, b, 0) == 0, "verify empty");
    for (int i = 0; i < 100; i += 33)
        for (int bit = 0; bit < 8; bit++) {
            b[i] ^= (uint8_t)(1 << bit);
            CHECK(ram_verify(a, b, 100) == -1, "verify byte %d bit %d", i, bit);
            b[i] ^= (uint8_t)(1 << bit);
        }
}

int main(int argc, char **argv)
{
    const char *kat = argc > 1 ? argv[1] : "tests/kat.txt";
    union { uint32_t u; uint8_t b[4]; } e = {0x01020304};
    printf("platform: %s-endian, %d-bit pointers, %s\n",
           e.b[0] == 4 ? "little" : "big", (int)(8 * sizeof(void *)),
#if defined(_WIN32) && defined(_MSC_VER)
           "Windows (MSVC ABI)"
#elif defined(_WIN32)
           "Windows"
#elif defined(__APPLE__)
           "Apple"
#elif defined(__ANDROID__)
           "Android"
#elif defined(__linux__)
           "Linux"
#elif defined(__FreeBSD__)
           "FreeBSD"
#elif defined(__OpenBSD__)
           "OpenBSD"
#elif defined(__NetBSD__)
           "NetBSD"
#else
           "other"
#endif
    );
    CHECK(ram_selftest_permute() == 0, "permutation self-test");
    test_params();
    test_verify();
    test_pw_params();
    int n = run_kat(kat);
    CHECK(n > 0, "no KAT vectors read from %s", kat);
    if (argc > 2) {
        int np = run_pw_kat(argv[2]);
        CHECK(np > 0, "no pwhash KAT vectors read from %s", argv[2]);
        printf("%d RAM-Balloon vectors\n", np);
    }
    printf("%d known-answer vectors (%d research-only, correctly refused), %d failures\n",
           n, nrejected, failures);
    return failures ? 1 : 0;
}
