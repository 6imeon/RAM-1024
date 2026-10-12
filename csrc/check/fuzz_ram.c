/* libFuzzer harness: every API path must give the same digest for the
 * same input, for any split of the input, and never touch memory it does
 * not own (built with ASan/UBSan).
 *
 *     clang -O1 -g -fsanitize=fuzzer,address,undefined -I csrc \
 *           csrc/check/fuzz_ram.c csrc/ram1024.c -o fuzz_ram
 */
#include <stdlib.h>
#include <string.h>

#include "ram1024.h"

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n);

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    if (n < 4) return 0;
    int mode = 1 + d[0] % 3;
    size_t outlen = 1 + (size_t)d[1] * 3;
    size_t split = d[2], keylen = mode == RAM_MODE_MAC ? 16 + d[3] % 200 : 0;
    d += 4;
    n -= 4;
    if (keylen > n) keylen = n;
    const uint8_t *key = d;
    const uint8_t *m = d + keylen;
    size_t mlen = n - keylen;
    /* stretch the message so tree mode (> 16 KiB) is exercised too */
    size_t big = mode == RAM_MODE_HASH && (split & 1) ? mlen * 97 + 16385 : mlen;
    uint8_t *msg = malloc(big + 1);
    for (size_t i = 0; i < big; i++) msg[i] = mlen ? m[i % mlen] ^ (uint8_t)(i / 4099) : 0;

    uint8_t *a = malloc(outlen), *b = malloc(outlen);
    int rc = ram_hash(a, outlen, msg, big, RAM_ROUNDS, mode, key, keylen);
    if (rc == 0) {
        ram_ctx *c = malloc(sizeof *c);
        if (ram_init(c, outlen, mode, RAM_ROUNDS, key, keylen)) abort();
        size_t step = 1 + split * 131;
        for (size_t off = 0; off < big; off += step)
            ram_update(c, msg + off, big - off < step ? big - off : step);
        ram_final(c, b);
        if (memcmp(a, b, outlen)) abort();
        if (mode == RAM_MODE_HASH) {
            memset(b, 0, outlen);
            if (ram_hash_tree(b, outlen, msg, big, RAM_ROUNDS, 1 + split % 4)) abort();
            if (memcmp(a, b, outlen)) abort();
        }
        free(c);
    } else if (ram_check_params(outlen, mode, RAM_ROUNDS) == 0 &&
               (mode != RAM_MODE_MAC || keylen >= RAM_MIN_KEY)) {
        abort(); /* rejected a valid call */
    }
    free(a);
    free(b);
    free(msg);
    return 0;
}
