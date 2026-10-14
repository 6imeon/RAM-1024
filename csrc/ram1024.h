/* SPDX-License-Identifier: MIT */
/* RAM-1024 (v3): a 2048-bit sponge hash with a hybrid ARX + chi permutation.
 *
 * State   : 32 x 64-bit words, a 4x8 matrix  s[row*8 + col]
 * Rate    : rows 0-1  = 1024 bits (128-byte blocks)
 * Capacity: rows 2-3  = 1024 bits  -> generic security 2^512 classical
 * Output  : 1024 bits by default; any length (XOF)
 * Tree    : hash-mode messages > 16 KiB are hashed as parallel 16 KiB
 *           leaves (1024-bit chaining values) combined by a root node.
 *
 * Portable C99: any compiler (GCC, Clang, MSVC, MinGW, TCC), any byte
 * order, 32- or 64-bit. Threads: POSIX or Win32 (define RAM_NO_THREADS to
 * build without). SIMD lanes are used where the compiler supports GCC
 * vector extensions; otherwise the same code runs on scalars.
 */
#ifndef RAM1024_H
#define RAM1024_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(RAM_BUILD_DLL)
#define RAM_API __declspec(dllexport)
#else
#define RAM_API
#endif

#define RAM_ROUNDS 64
#define RAM_MAX_ROUNDS 64
#define RAM_RATE 128
#define RAM_CV 128
#define RAM_CHUNK 16384
#define RAM_OUT 128
#define RAM_VERSION_WORD UINT64_C(0x52414D0300000000) /* "RAM" v3 */
#define RAM_MODE_HASH 1
#define RAM_MODE_XOF 2
#define RAM_MODE_MAC 3
#define RAM_MODE_LEAF 4
#define RAM_MODE_ROOT 5
#define RAM_MODE_PW 6       /* password hashing (RAM-Balloon) */
#define RAM_MIN_KEY 16      /* MAC keys: at least 128 bits */
#define RAM_MIN_HASH_OUT 32 /* hash digests: at least 256 bits */
#define RAM_MIN_TAG 16      /* MAC tags: at least 128 bits */

typedef struct {
    uint64_t s[32];
    uint8_t buf[RAM_RATE];
    size_t pos;
    size_t outlen;
    int rounds;
} ram_sponge;

typedef struct {
    ram_sponge sp;   /* XOF / MAC modes */
    ram_sponge root; /* hash mode, once the message exceeds one chunk */
    uint8_t chunk[RAM_CHUNK];
    size_t clen;
    uint64_t nchunks;
    size_t outlen;
    int rounds;
    int mode;
} ram_ctx;

/* Streaming. mode RAM_MODE_HASH / XOF / MAC; rounds must be RAM_ROUNDS
 * (reduced-round instances exist only in builds with -DRAM_RESEARCH);
 * key only in MAC mode (>= RAM_MIN_KEY bytes, any length); outlen >=
 * RAM_MIN_HASH_OUT (hash), >= RAM_MIN_TAG (MAC), >= 1 (XOF).
 * Returns 0, or -1 on bad parameters. ram_final wipes the context; after
 * that, ram_update / ram_final return -1 until ram_init is called again. */
RAM_API int ram_init(ram_ctx *c, size_t outlen, int mode, int rounds,
                     const uint8_t *key, size_t keylen);
RAM_API int ram_update(ram_ctx *c, const uint8_t *in, size_t len);
RAM_API int ram_final(ram_ctx *c, uint8_t *out);
RAM_API size_t ram_ctx_size(void);

/* One-shot (single thread). Returns 0, -1 on bad parameters, or -2 out of
 * memory (hash mode, messages > RAM_CHUNK). */
RAM_API int ram_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen,
                     int rounds, int mode, const uint8_t *key, size_t keylen);
/* One-shot hash mode on nthreads threads (0 = all cores); same digest.
 * Returns 0, -1 on bad parameters, -2 out of memory. */
RAM_API int ram_hash_tree(uint8_t *out, size_t outlen, const uint8_t *in,
                          size_t inlen, int rounds, int nthreads);
/* CPU + GPU (macOS Metal) one-shot hash mode; same digest and return
 * codes as ram_hash_tree (falls back to the CPU without a GPU). gpu_share
 * in [0,1] = fraction of chunks sent to the GPU (negative = auto). Only
 * present in builds with ram_gpu.m. */
RAM_API int ram_hash_gpu(uint8_t *out, size_t outlen, const uint8_t *in,
                         size_t inlen, int rounds, double gpu_share);
RAM_API int ram_gpu_available(void);

/* 0 if (outlen, mode, rounds) is accepted by this build, else -1. */
RAM_API int ram_check_params(size_t outlen, int mode, int rounds);

/* RAM-Balloon v2: memory-hard password hashing (Balloon hashing, Boneh-
 * Corrigan-Gibbs-Schechter 2016, delta = 3) on the RAM-1024 permutation,
 * with lanes that reference each other (4 slices per pass, as in Argon2),
 * so all m_kib must be held at once. Memory access depends on the salt
 * only (no password-dependent cache timing). m_kib = total memory in KiB
 * (>= 8 KiB per lane, <= RAM_PW_MAX_KIB); 1 <= t_cost <= RAM_PW_MAX_T
 * passes; 1 <= lanes <= RAM_PW_MAX_LANES threads; salt >= RAM_MIN_SALT
 * bytes; outlen >= RAM_MIN_HASH_OUT. Memory is wiped before returning.
 * Returns 0, -1 on bad parameters, -2 out of memory. */
#define RAM_MIN_SALT 16
#define RAM_PW_MAX_LANES 16
#define RAM_PW_MAX_T 64
#define RAM_PW_MAX_KIB (1u << 20)
RAM_API int ram_pwhash(uint8_t *out, size_t outlen, const uint8_t *pw, size_t pwlen,
                       const uint8_t *salt, size_t saltlen, uint32_t m_kib,
                       uint32_t t_cost, uint32_t lanes);

/* Constant-time equality of two byte strings: 0 if equal, -1 otherwise. */
RAM_API int ram_verify(const uint8_t *a, const uint8_t *b, size_t len);

/* Permutation and building blocks (tests, analysis, GPU path). */
RAM_API void ram_permute(uint64_t s[32], int rounds);
RAM_API void ram_permute_ref(uint64_t s[32], int rounds);
RAM_API void ram_permute_x2(uint64_t *s, int rounds); /* 2 states, s[lane*32+i] */
RAM_API void ram_permute_x4(uint64_t *s, int rounds); /* 4 states */
RAM_API void ram_init_state(uint64_t s[32], size_t outlen, int mode, int rounds,
                            size_t keylen, uint64_t node);
RAM_API void ram_tree_leaves_cpu(const uint8_t *in, size_t inlen, uint64_t first,
                                 uint64_t last, uint8_t *cvs, int rounds,
                                 int nthreads);
RAM_API void ram_tree_root(uint8_t *out, size_t outlen, const uint8_t *cvs,
                           uint64_t nchunks, int rounds);
/* 0 if every permutation implementation agrees with the reference. */
RAM_API int ram_selftest_permute(void);

extern RAM_API const int RAM_RHO[16];

#ifdef __cplusplus
}
#endif

#endif
