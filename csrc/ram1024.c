/* SPDX-License-Identifier: MIT */
#include "ram1024.h"

#include <stdlib.h>
#include <string.h>

/* ---- platform layer: threads and core count (POSIX, Win32, or none) ---- */
#if defined(RAM_NO_THREADS)
#elif defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif

#include "ram_constants.h"

/* SIMD lanes via GCC/Clang vector extensions, only where the CPU has
 * 128-bit integer SIMD; elsewhere (e.g. plain i386, riscv64 without V) the
 * compiler would split the vectors into scalar code that is slower than the
 * scalar path and very slow to compile, so the scalar path is used. */
#if (defined(__GNUC__) || defined(__clang__)) && !defined(__TINYC__) &&    \
    !defined(RAM_NO_SIMD) &&                                               \
    (defined(__x86_64__) || defined(__SSE2__) || defined(__aarch64__) ||   \
     defined(__ARM_NEON) || defined(__VSX__) || defined(__ALTIVEC__) ||    \
     defined(RAM_FORCE_SIMD))
#define RAM_VEC 1
#endif

#define ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

RAM_API const int RAM_RHO[16] = {1, 27, 53, 15, 41, 3, 29, 55, 17, 43, 5, 31, 57, 19, 45, 7};

/* Zeroing that the compiler may not elide (secrets, key material). */
static void ram_wipe(void *p, size_t n)
{
    volatile uint8_t *v = p;
    while (n--) *v++ = 0;
}

/* BLAKE2b's G mixing function (heavily analyzed ARX quarter-round). */
#define G(a, b, c, d)                  \
    do {                               \
        a += b; d = ROTR(d ^ a, 32);   \
        c += d; b = ROTR(b ^ c, 24);   \
        a += b; d = ROTR(d ^ a, 16);   \
        c += d; b = ROTR(b ^ c, 63);   \
    } while (0)

/* 3-word chi (Keccak/Xoodoo nonlinear layer): 64 parallel 3-bit S-boxes,
 * a bijection, algebraic degree 2 over GF(2). */
#define CHI3(x, y, z)                  \
    do {                               \
        uint64_t X = x, Y = y, Z = z;  \
        x = X ^ (~Y & Z);              \
        y = Y ^ (~Z & X);              \
        z = Z ^ (~X & Y);              \
    } while (0)

/* Reference-style loop, kept for clarity; ram_permute uses the unrolled
 * generated body below and must agree with it (tests). */
void ram_permute_ref(uint64_t s[32], int rounds)
{
    if (rounds > RAM_MAX_ROUNDS) rounds = RAM_MAX_ROUNDS; /* constant table size */
    for (int r = 0; r < rounds; r++) {
        /* iota: round constants, spread diagonally over all four rows (v3)
         * so no row is left symmetric under column shifts */
        for (int c = 0; c < 8; c++)
            s[(c & 3) * 8 + c] ^= RAM_RC[r * 8 + c];
        /* theta-1: column mixing */
        for (int c = 0; c < 8; c++)
            G(s[c], s[8 + c], s[16 + c], s[24 + c]);
        /* rho (v3): distinct left-rotations of rows 2-3, moving high-bit
         * differences down where carries spread them (backward diffusion) */
        for (int i = 0; i < 16; i++)
            s[16 + i] = ROTR(s[16 + i], 64 - RAM_RHO[i]);
        /* theta-2: diagonal mixing */
        for (int c = 0; c < 8; c++)
            G(s[c], s[8 + ((c + 1) & 7)], s[16 + ((c + 2) & 7)],
              s[24 + ((c + 3) & 7)]);
        /* chi: Boolean nonlinearity on 3 of 4 rows (skipped row rotates),
         * column offsets 0,3,5 so it also mixes across columns. */
        int skip = r & 3, rows[3], k = 0;
        for (int i = 0; i < 4; i++)
            if (i != skip) rows[k++] = i;
        for (int c = 0; c < 8; c++)
            CHI3(s[rows[0] * 8 + c], s[rows[1] * 8 + ((c + 3) & 7)],
                 s[rows[2] * 8 + ((c + 5) & 7)]);
    }
}

/* Scalar unrolled permutation. */
void ram_permute(uint64_t s[32], int rounds)
{
    if (rounds > RAM_MAX_ROUNDS) rounds = RAM_MAX_ROUNDS;
#define T uint64_t
#define LOAD(i) s[i]
#define STORE(i, v) (s[i] = (v))
#include "ram_permute_gen.h"
#undef T
#undef LOAD
#undef STORE
}

/* N independent states in SIMD lanes: s[lane*32 + word]. */
#ifdef RAM_VEC
typedef uint64_t u64x2 __attribute__((vector_size(16)));
typedef uint64_t u64x4 __attribute__((vector_size(32)));

void ram_permute_x2(uint64_t *s, int rounds)
{
    if (rounds > RAM_MAX_ROUNDS) rounds = RAM_MAX_ROUNDS;
#define T u64x2
#define LOAD(i) ((u64x2){s[i], s[32 + i]})
#define STORE(i, v) (s[i] = (v)[0], s[32 + i] = (v)[1])
#include "ram_permute_gen.h"
#undef T
#undef LOAD
#undef STORE
}

void ram_permute_x4(uint64_t *s, int rounds)
{
    if (rounds > RAM_MAX_ROUNDS) rounds = RAM_MAX_ROUNDS;
#define T u64x4
#define LOAD(i) ((u64x4){s[i], s[32 + i], s[64 + i], s[96 + i]})
#define STORE(i, v) (s[i] = (v)[0], s[32 + i] = (v)[1], s[64 + i] = (v)[2], s[96 + i] = (v)[3])
#include "ram_permute_gen.h"
#undef T
#undef LOAD
#undef STORE
}
#else
void ram_permute_x2(uint64_t *s, int rounds)
{
    ram_permute(s, rounds);
    ram_permute(s + 32, rounds);
}

void ram_permute_x4(uint64_t *s, int rounds)
{
    for (int l = 0; l < 4; l++) ram_permute(s + 32 * l, rounds);
}
#endif

/* Constant time in len only: no early exit, no data-dependent branch. */
int ram_verify(const uint8_t *a, const uint8_t *b, size_t len)
{
    volatile uint8_t d = 0;
    for (size_t i = 0; i < len; i++) d |= a[i] ^ b[i];
    return (int)((1u & (((unsigned)d - 1u) >> 8)) - 1u);
}

static uint64_t load64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

static void store64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

/* ---------------- plain sponge ---------------- */

/* Parameter block in the capacity: domain-separates every
 * (version, mode, rounds, output length, key length, tree node). */
void ram_init_state(uint64_t s[32], size_t outlen, int mode, int rounds,
                    size_t keylen, uint64_t node)
{
    memset(s, 0, 32 * sizeof *s);
    s[31] = RAM_VERSION_WORD | ((uint64_t)mode << 24) | ((uint64_t)rounds << 16);
    s[30] = mode == RAM_MODE_XOF ? 0 : (uint64_t)outlen; /* XOF: prefix-consistent */
    s[29] = (uint64_t)keylen;
    s[28] = node;
}

static void sp_absorb_block(ram_sponge *c, const uint8_t *blk)
{
    for (int i = 0; i < 16; i++) c->s[i] ^= load64(blk + 8 * i);
    ram_permute(c->s, c->rounds);
}

static void sp_init(ram_sponge *c, size_t outlen, int mode, int rounds,
                    size_t keylen, uint64_t node)
{
    memset(c, 0, sizeof *c);
    c->outlen = outlen;
    c->rounds = rounds;
    ram_init_state(c->s, outlen, mode, rounds, keylen, node);
}

static void sp_update(ram_sponge *c, const uint8_t *in, size_t len)
{
    while (len) {
        if (c->pos == 0 && len >= RAM_RATE) {
            sp_absorb_block(c, in);
            in += RAM_RATE;
            len -= RAM_RATE;
            continue;
        }
        size_t n = RAM_RATE - c->pos;
        if (n > len) n = len;
        memcpy(c->buf + c->pos, in, n);
        c->pos += n;
        in += n;
        len -= n;
        if (c->pos == RAM_RATE) {
            sp_absorb_block(c, c->buf);
            c->pos = 0;
        }
    }
}

static void sp_final(ram_sponge *c, uint8_t *out)
{
    /* pad10*1 */
    memset(c->buf + c->pos, 0, RAM_RATE - c->pos);
    c->buf[c->pos] ^= 0x01;
    c->buf[RAM_RATE - 1] ^= 0x80;
    sp_absorb_block(c, c->buf);
    for (size_t done = 0; done < c->outlen;) {
        if (done) ram_permute(c->s, c->rounds);
        for (size_t i = 0; i < RAM_RATE && done < c->outlen; i++, done++)
            out[done] = (uint8_t)(c->s[i / 8] >> (8 * (i % 8)));
    }
    ram_wipe(c, sizeof *c);
}

/* ---------------- tree mode (hash mode, messages > RAM_CHUNK) -------------
 * leaf i  = sponge(mode LEAF, node i, outlen 128) over chunk i  -> 1024-bit CV
 * digest  = sponge(mode ROOT, outlen) over CV_0 || ... || CV_{n-1} || le64(n)
 * Messages <= RAM_CHUNK bytes use the plain HASH-mode sponge. */

static void leaf_scalar(const uint8_t *in, size_t len, uint64_t idx, int rounds,
                        uint8_t cv[RAM_CV])
{
    ram_sponge c;
    sp_init(&c, RAM_CV, RAM_MODE_LEAF, rounds, 0, idx);
    sp_update(&c, in, len);
    sp_final(&c, cv);
}

/* Two full chunks in SIMD lanes. */
static void leaf_x2(const uint8_t *a, const uint8_t *b, uint64_t idx, int rounds,
                    uint8_t *cv_a, uint8_t *cv_b)
{
    uint64_t st[64];
    ram_init_state(st, RAM_CV, RAM_MODE_LEAF, rounds, 0, idx);
    ram_init_state(st + 32, RAM_CV, RAM_MODE_LEAF, rounds, 0, idx + 1);
    for (size_t off = 0; off < RAM_CHUNK; off += RAM_RATE) {
        for (int i = 0; i < 16; i++) {
            st[i] ^= load64(a + off + 8 * i);
            st[32 + i] ^= load64(b + off + 8 * i);
        }
        ram_permute_x2(st, rounds);
    }
    st[0] ^= 0x01; st[15] ^= UINT64_C(0x80) << 56; /* pad block of a full chunk */
    st[32] ^= 0x01; st[47] ^= UINT64_C(0x80) << 56;
    ram_permute_x2(st, rounds);
    for (int i = 0; i < 16; i++) {
        store64(cv_a + 8 * i, st[i]);
        store64(cv_b + 8 * i, st[32 + i]);
    }
}

static void root_finish(ram_sponge *root, uint64_t nchunks, uint8_t *out)
{
    uint8_t n[8];
    store64(n, nchunks);
    sp_update(root, n, 8);
    sp_final(root, out);
}

/* ---------------- streaming API ---------------- */

/* Plain sponge for any mode, with the MAC key absorbed. The key (any
 * length; its length is bound in the parameter block) is zero-padded to
 * whole blocks so the message always starts on a fresh block. */
static void sp_setup(ram_sponge *sp, size_t outlen, int mode, int rounds,
                     const uint8_t *key, size_t keylen)
{
    sp_init(sp, outlen, mode, rounds, keylen, 0);
    for (size_t off = 0; off < keylen; off += RAM_RATE) {
        uint8_t blk[RAM_RATE] = {0};
        size_t n = keylen - off < RAM_RATE ? keylen - off : RAM_RATE;
        memcpy(blk, key + off, n);
        sp_absorb_block(sp, blk);
        ram_wipe(blk, sizeof blk);
    }
}

/* Misuse resistance: production builds only accept the full permutation
 * and outputs long enough to keep their security level. Reduced-round
 * instances (cryptanalysis) need a -DRAM_RESEARCH build. */
static int params_ok(size_t outlen, int mode, int rounds)
{
#ifdef RAM_RESEARCH
    if (rounds < 1 || rounds > RAM_MAX_ROUNDS) return 0;
    if (outlen == 0) return 0;
#else
    if (rounds != RAM_ROUNDS) return 0;
    if (outlen < (mode == RAM_MODE_HASH ? RAM_MIN_HASH_OUT :
                  mode == RAM_MODE_MAC ? RAM_MIN_TAG : 1))
        return 0;
#endif
    return mode == RAM_MODE_HASH || mode == RAM_MODE_XOF || mode == RAM_MODE_MAC;
}

int ram_check_params(size_t outlen, int mode, int rounds)
{
    return params_ok(outlen, mode, rounds) ? 0 : -1;
}

int ram_init(ram_ctx *c, size_t outlen, int mode, int rounds,
             const uint8_t *key, size_t keylen)
{
    if (!params_ok(outlen, mode, rounds) || (mode != RAM_MODE_MAC && keylen) ||
        (mode == RAM_MODE_MAC && keylen < RAM_MIN_KEY)) {
        ram_wipe(c, sizeof *c); /* never leave an earlier stream usable */
        return -1;
    }
    c->outlen = outlen;
    c->rounds = rounds;
    c->mode = mode;
    c->clen = 0;
    c->nchunks = 0;
    if (mode != RAM_MODE_HASH)
        sp_setup(&c->sp, outlen, mode, rounds, key, keylen);
    return 0;
}

static void flush_chunk(ram_ctx *c)
{
    uint8_t cv[RAM_CV];
    if (c->nchunks == 0)
        sp_init(&c->root, c->outlen, RAM_MODE_ROOT, c->rounds, 0, 0);
    leaf_scalar(c->chunk, c->clen, c->nchunks, c->rounds, cv);
    sp_update(&c->root, cv, RAM_CV);
    c->nchunks++;
    c->clen = 0;
}

int ram_update(ram_ctx *c, const uint8_t *in, size_t len)
{
    if (!params_ok(c->outlen, c->mode, c->rounds)) return -1; /* finalized / not init */
    if (c->mode != RAM_MODE_HASH) {
        sp_update(&c->sp, in, len);
        return 0;
    }
    while (len) {
        if (c->clen == RAM_CHUNK) flush_chunk(c); /* more data follows */
        size_t n = RAM_CHUNK - c->clen;
        if (n > len) n = len;
        memcpy(c->chunk + c->clen, in, n);
        c->clen += n;
        in += n;
        len -= n;
    }
    return 0;
}

int ram_final(ram_ctx *c, uint8_t *out)
{
    if (!params_ok(c->outlen, c->mode, c->rounds)) return -1; /* finalized / not init */
    if (c->mode != RAM_MODE_HASH) {
        sp_final(&c->sp, out);
    } else if (c->nchunks == 0) {
        ram_sponge sp;
        sp_init(&sp, c->outlen, RAM_MODE_HASH, c->rounds, 0, 0);
        sp_update(&sp, c->chunk, c->clen);
        sp_final(&sp, out);
    } else {
        flush_chunk(c);
        root_finish(&c->root, c->nchunks, out);
    }
    ram_wipe(c, sizeof *c); /* message, key state; mode 0 marks it finalized */
    return 0;
}

/* ---------------- multithreaded one-shot ---------------- */

/* ---- generic parallel-for: fn(ctx, i) for i in [0, n) on nthreads ---- */

typedef struct {
    void (*fn)(void *ctx, uint64_t i);
    void *ctx;
    uint64_t n;
#if defined(RAM_NO_THREADS)
    uint64_t next;
#elif defined(_WIN32)
    volatile LONG64 next;
#else
    uint64_t next;
    pthread_mutex_t lock;
#endif
} par_job;

/* Claim the next item (items are >= ~10 us of work, so a mutex costs
 * nothing measurable and needs no C11 atomics). */
static uint64_t claim(par_job *j)
{
#if defined(RAM_NO_THREADS)
    return j->next++;
#elif defined(_WIN32)
    return (uint64_t)(InterlockedIncrement64(&j->next) - 1);
#else
    pthread_mutex_lock(&j->lock);
    uint64_t p = j->next++;
    pthread_mutex_unlock(&j->lock);
    return p;
#endif
}

static void par_work(par_job *j)
{
    for (;;) {
        uint64_t p = claim(j);
        if (p >= j->n) return;
        j->fn(j->ctx, p);
    }
}

#if defined(RAM_NO_THREADS)
static int ncores(void) { return 1; }
#elif defined(_WIN32)
static DWORD WINAPI par_thread(LPVOID arg) { par_work(arg); return 0; }
static int ncores(void)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (int)si.dwNumberOfProcessors;
}
#else
static void *par_thread(void *arg) { par_work(arg); return NULL; }
static int ncores(void)
{
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)n : 1;
}
#endif

/* The caller is one of the nthreads workers (0 = all cores). If a thread
 * cannot be started the others simply do its share. */
static void par_for(void (*fn)(void *, uint64_t), void *ctx, uint64_t n, int nthreads)
{
    par_job j;
    memset(&j, 0, sizeof j);
    j.fn = fn;
    j.ctx = ctx;
    j.n = n;
    if (nthreads <= 0) nthreads = ncores();
    if ((uint64_t)nthreads > n) nthreads = (int)n;
#if defined(RAM_NO_THREADS)
    (void)nthreads;
    par_work(&j);
#else
    enum { MAXT = 256 };
    int started = 0;
    if (nthreads > MAXT) nthreads = MAXT;
#if defined(_WIN32)
    HANDLE th[MAXT];
    for (int t = 1; t < nthreads; t++) {
        th[started] = CreateThread(NULL, 0, par_thread, &j, 0, NULL);
        if (th[started]) started++;
    }
    par_work(&j);
    /* one at a time: WaitForMultipleObjects stops at 64 handles */
    for (int t = 0; t < started; t++) {
        WaitForSingleObject(th[t], INFINITE);
        CloseHandle(th[t]);
    }
#else
    pthread_mutex_init(&j.lock, NULL);
    pthread_t th[MAXT];
    for (int t = 1; t < nthreads; t++)
        if (pthread_create(&th[started], NULL, par_thread, &j) == 0) started++;
    par_work(&j);
    for (int t = 0; t < started; t++) pthread_join(th[t], NULL);
    pthread_mutex_destroy(&j.lock);
#endif
#endif
}

typedef struct {
    const uint8_t *in;
    uint8_t *cvs;
    uint64_t first; /* chunk index of pair 0 */
    int rounds;
} tree_job;

static void tree_pair(void *ctx, uint64_t p)
{
    tree_job *j = ctx;
    uint64_t i = j->first + 2 * p;
    leaf_x2(j->in + (size_t)i * RAM_CHUNK, j->in + (size_t)(i + 1) * RAM_CHUNK, i,
            j->rounds, j->cvs + (size_t)i * RAM_CV, j->cvs + (size_t)(i + 1) * RAM_CV);
}

/* CVs of chunks [first, last) of a tree message of inlen bytes, on
 * nthreads threads. cvs is indexed by absolute chunk number. */
void ram_tree_leaves_cpu(const uint8_t *in, size_t inlen, uint64_t first,
                         uint64_t last, uint8_t *cvs, int rounds, int nthreads)
{
    uint64_t nch = (inlen + RAM_CHUNK - 1) / RAM_CHUNK;
    if (last > nch) last = nch; /* exported: never read past the input */
    if (first >= last) return;
    uint64_t nfull = inlen / RAM_CHUNK; /* chunks that are exactly full */
    if (nfull == nch) nfull--; /* last: scalar */
    uint64_t pair_end = nfull < last ? nfull : last;
    uint64_t npairs = pair_end > first ? (pair_end - first) / 2 : 0;
    tree_job job = {in, cvs, first, rounds};
    par_for(tree_pair, &job, npairs, nthreads);
    for (uint64_t i = first + 2 * npairs; i < last; i++) {
        size_t off = (size_t)i * RAM_CHUNK;
        size_t len = inlen - off < RAM_CHUNK ? inlen - off : RAM_CHUNK;
        leaf_scalar(in + off, len, i, rounds, cvs + (size_t)i * RAM_CV);
    }
}

void ram_tree_root(uint8_t *out, size_t outlen, const uint8_t *cvs,
                   uint64_t nchunks, int rounds)
{
    ram_sponge root;
    sp_init(&root, outlen, RAM_MODE_ROOT, rounds, 0, 0);
    sp_update(&root, cvs, (size_t)nchunks * RAM_CV);
    root_finish(&root, nchunks, out);
}

int ram_hash_tree(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen,
                  int rounds, int nthreads)
{
    if (!params_ok(outlen, RAM_MODE_HASH, rounds)) return -1;
    if (inlen <= RAM_CHUNK)
        return ram_hash(out, outlen, in, inlen, rounds, RAM_MODE_HASH, NULL, 0);
    uint64_t nchunks = (inlen + RAM_CHUNK - 1) / RAM_CHUNK;
    uint8_t *cvs = malloc((size_t)nchunks * RAM_CV);
    if (!cvs) { /* out of memory: same digest via the O(1)-memory stream */
        ram_ctx *c = malloc(sizeof *c);
        if (!c) return -2;
        ram_init(c, outlen, RAM_MODE_HASH, rounds, NULL, 0);
        ram_update(c, in, inlen);
        ram_final(c, out);
        free(c);
        return 0;
    }
    ram_tree_leaves_cpu(in, inlen, 0, nchunks, cvs, rounds, nthreads);
    ram_tree_root(out, outlen, cvs, nchunks, rounds);
    free(cvs);
    return 0;
}

int ram_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen,
             int rounds, int mode, const uint8_t *key, size_t keylen)
{
    if (!params_ok(outlen, mode, rounds)) return -1;
    if (mode != RAM_MODE_MAC && keylen) return -1;
    if (mode == RAM_MODE_MAC && keylen < RAM_MIN_KEY) return -1;
    if (mode == RAM_MODE_HASH && inlen > RAM_CHUNK)
        return ram_hash_tree(out, outlen, in, inlen, rounds, 1);
    ram_sponge sp;
    sp_setup(&sp, outlen, mode, rounds, key, keylen);
    sp_update(&sp, in, inlen);
    sp_final(&sp, out);
    return 0;
}

/* ---------------- RAM-Balloon password hashing ---------------- */

#define PW_DELTA 3
/* node ids of the padded sponge calls: lane seeds use node = lane */
#define PW_SALT (UINT64_MAX - 1)
#define PW_FINAL (UINT64_MAX - 2)

/* One permutation call: rate = x || y (2 x 512 bits), capacity = the
 * parameter block (mode PW, kind, lane, counter); output = first 512 bits.
 * Fixed-length input, so no padding; kind >= 1 never occurs in the
 * padded sponge calls (kind 0), so the two cannot collide. */
static void pw_compress(uint64_t out[8], int kind, uint64_t lane, uint64_t ctr,
                        const uint64_t x[8], const uint64_t y[8])
{
    uint64_t s[32];
    ram_init_state(s, 64, RAM_MODE_PW, RAM_ROUNDS, (size_t)lane, ctr);
    s[31] |= (uint64_t)kind << 8;
    for (int i = 0; i < 8; i++) {
        s[i] ^= x[i];
        s[8 + i] ^= y[i];
    }
    ram_permute(s, RAM_ROUNDS);
    memcpy(out, s, 64);
    ram_wipe(s, sizeof s);
}

static void put64(ram_sponge *sp, uint64_t v)
{
    uint8_t b[8];
    store64(b, v);
    sp_update(sp, b, 8);
}

static void words(uint64_t w[8], const uint8_t b[64])
{
    for (int i = 0; i < 8; i++) w[i] = load64(b + 8 * i);
}

#define PW_SLICES 4

typedef struct {
    const uint8_t *pw, *salt;
    size_t pwlen, saltlen, outlen;
    uint32_t m_kib, t_cost, lanes;
    uint64_t n, seg;      /* blocks per lane (multiple of PW_SLICES), per slice */
    uint64_t t, sl;       /* current pass and slice */
    uint64_t *mem;        /* lanes * n * 8 words */
    uint64_t sd[8];       /* salt digest */
    uint64_t ctr[RAM_PW_MAX_LANES];
} pw_job;

static void pw_expand(void *ctx, uint64_t l)
{
    pw_job *j = ctx;
    uint64_t n = j->n, *B = j->mem + (size_t)l * (size_t)n * 8;
    uint64_t zero[8] = {0}, seed[8];
    uint8_t sb[64];
    ram_sponge sp;
    sp_init(&sp, 64, RAM_MODE_PW, RAM_ROUNDS, 0, l); /* per-lane seed */
    put64(&sp, j->pwlen);
    sp_update(&sp, j->pw, j->pwlen);
    put64(&sp, j->saltlen);
    sp_update(&sp, j->salt, j->saltlen);
    put64(&sp, j->m_kib);
    put64(&sp, j->t_cost);
    put64(&sp, j->lanes);
    put64(&sp, j->outlen);
    sp_final(&sp, sb);
    words(seed, sb);
    ram_wipe(sb, sizeof sb);
    pw_compress(B, 1, l, 0, seed, zero);
    for (uint64_t m = 1; m < n; m++) pw_compress(B + 8 * m, 1, l, m, B + 8 * (m - 1), zero);
    ram_wipe(seed, sizeof seed);
    j->ctr[l] = n;
}

/* One slice of one pass in lane l. Neighbour 0 lies in another lane (when
 * lanes > 1), outside the slice those lanes are writing now; the others
 * lie in this lane. Indices depend on (salt, lane, t, m) only. */
static void pw_slice(void *ctx, uint64_t l)
{
    pw_job *j = ctx;
    uint64_t n = j->n, seg = j->seg, ctr = j->ctr[l];
    uint64_t *B = j->mem + (size_t)l * (size_t)n * 8, idx[8] = {0}, r[8];
    for (uint64_t m = j->sl * seg; m < (j->sl + 1) * seg; m++) {
        uint64_t *cur = B + 8 * m, *prev = B + 8 * ((m + n - 1) % n);
        pw_compress(cur, 2, l, ctr++, prev, cur);
        idx[0] = j->t;
        idx[1] = m;
        pw_compress(r, 3, l, 0, j->sd, idx);
        for (int i = 0; i < PW_DELTA; i++) {
            const uint64_t *nb;
            if (i == 0 && j->lanes > 1) {
                uint64_t l2 = (l + 1 + r[3] % (j->lanes - 1)) % j->lanes;
                uint64_t k = r[0] % (n - seg);
                if (k >= j->sl * seg) k += seg; /* skip the slice being written */
                nb = j->mem + ((size_t)l2 * (size_t)n + (size_t)k) * 8;
            } else {
                nb = B + 8 * (r[i] % n);
            }
            pw_compress(cur, 2, l, ctr++, cur, nb);
        }
    }
    j->ctr[l] = ctr;
}

int ram_pwhash(uint8_t *out, size_t outlen, const uint8_t *pw, size_t pwlen,
               const uint8_t *salt, size_t saltlen, uint32_t m_kib,
               uint32_t t_cost, uint32_t lanes)
{
    if (outlen < RAM_MIN_HASH_OUT || saltlen < RAM_MIN_SALT || t_cost < 1 ||
        t_cost > RAM_PW_MAX_T || lanes < 1 || lanes > RAM_PW_MAX_LANES ||
        m_kib < 8 * lanes || m_kib > RAM_PW_MAX_KIB)
        return -1;
    pw_job j;
    memset(&j, 0, sizeof j);
    j.pw = pw;
    j.salt = salt;
    j.pwlen = pwlen;
    j.saltlen = saltlen;
    j.outlen = outlen;
    j.m_kib = m_kib;
    j.t_cost = t_cost;
    j.lanes = lanes;
    j.n = ((uint64_t)m_kib * 16 / lanes) & ~(uint64_t)(PW_SLICES - 1);
    j.seg = j.n / PW_SLICES;
    uint64_t words_total = j.n * lanes * 8;
    if (words_total > SIZE_MAX / 8) return -2;
    j.mem = malloc((size_t)words_total * 8);
    if (!j.mem) return -2;

    uint8_t sb[64];
    ram_sponge sp;
    sp_init(&sp, 64, RAM_MODE_PW, RAM_ROUNDS, 0, PW_SALT);
    put64(&sp, saltlen);
    sp_update(&sp, salt, saltlen);
    sp_final(&sp, sb);
    words(j.sd, sb);

    par_for(pw_expand, &j, lanes, (int)lanes);
    for (j.t = 0; j.t < t_cost; j.t++)
        for (j.sl = 0; j.sl < PW_SLICES; j.sl++) /* sync point after each slice */
            par_for(pw_slice, &j, lanes, (int)lanes);

    sp_init(&sp, outlen, RAM_MODE_PW, RAM_ROUNDS, 0, PW_FINAL);
    for (uint32_t l = 0; l < lanes; l++) {
        const uint64_t *last = j.mem + ((size_t)l * (size_t)j.n + (size_t)j.n - 1) * 8;
        for (int i = 0; i < 8; i++) store64(sb + 8 * i, last[i]);
        sp_update(&sp, sb, 64);
    }
    put64(&sp, lanes);
    sp_final(&sp, out);
    ram_wipe(sb, sizeof sb);
    ram_wipe(&sp, sizeof sp);
    ram_wipe(j.mem, (size_t)words_total * 8);
    free(j.mem);
    ram_wipe(&j, sizeof j);
    return 0;
}

size_t ram_ctx_size(void) { return sizeof(ram_ctx); }

int ram_selftest_permute(void)
{
    uint64_t a[32], b[4 * 32];
    for (int rounds = 1; rounds <= RAM_MAX_ROUNDS; rounds++) {
        for (int i = 0; i < 32; i++) a[i] = (uint64_t)(i + rounds) * UINT64_C(0x9e3779b97f4a7c15);
        for (int l = 0; l < 4; l++)
            for (int i = 0; i < 32; i++) b[l * 32 + i] = a[i] ^ (uint64_t)l;
        uint64_t ref[32];
        memcpy(ref, a, sizeof ref);
        ram_permute_ref(ref, rounds);
        ram_permute(a, rounds);
        if (memcmp(a, ref, sizeof ref)) return 1;
        uint64_t b2[2 * 32];
        memcpy(b2, b, sizeof b2);
        ram_permute_x2(b2, rounds);
        ram_permute_x4(b, rounds);
        for (int l = 0; l < 4; l++) {
            uint64_t one[32];
            for (int i = 0; i < 32; i++) one[i] = (uint64_t)(i + rounds) * UINT64_C(0x9e3779b97f4a7c15) ^ (uint64_t)l;
            ram_permute_ref(one, rounds);
            if (memcmp(one, b + l * 32, sizeof one)) return 2;
            if (l < 2 && memcmp(one, b2 + l * 32, sizeof one)) return 3;
        }
    }
    return 0;
}
