/* Constant-time check (the "ctgrind" method): run under Valgrind memcheck
 * with every secret byte marked *undefined*. Memcheck then reports any
 * branch or memory address that depends on a secret, i.e. a timing or
 * cache side channel. Outputs are re-marked defined before use.
 *
 *     cc -O2 -I csrc -o ct csrc/check/ct_test.c csrc/ram1024.c -lpthread
 *     valgrind --error-exitcode=1 ./ct
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <valgrind/memcheck.h>

#include "ram1024.h"

#define SECRET(p, n) VALGRIND_MAKE_MEM_UNDEFINED(p, n)
#define PUBLIC(p, n) VALGRIND_MAKE_MEM_DEFINED(p, n)

static uint8_t key[300], msg[3 * RAM_CHUNK + 77], out[1000], tag2[64];

int main(void)
{
    for (size_t i = 0; i < sizeof key; i++) key[i] = (uint8_t)(i * 7);
    for (size_t i = 0; i < sizeof msg; i++) msg[i] = (uint8_t)(i * 13);
    static const size_t keylens[] = {16, 32, 128, 129, 300};
    static const size_t msglens[] = {0, 1, 127, 128, 129, 5000};
    unsigned acc = 0;

    for (size_t a = 0; a < 5; a++)          /* MAC: secret key and message */
        for (size_t b = 0; b < 6; b++) {
            SECRET(key, sizeof key);
            SECRET(msg, sizeof msg);
            ram_hash(out, 64, msg, msglens[b], RAM_ROUNDS, RAM_MODE_MAC, key, keylens[a]);
            ram_ctx c; /* streaming, odd split */
            if (ram_init(&c, 64, RAM_MODE_MAC, RAM_ROUNDS, key, keylens[a]) ||
                ram_update(&c, msg, msglens[b] / 3) ||
                ram_update(&c, msg + msglens[b] / 3, msglens[b] - msglens[b] / 3) ||
                ram_final(&c, tag2))
                abort();
            /* tag comparison on secret data must be constant time too */
            int eq = ram_verify(out, tag2, 64);
            PUBLIC(&eq, sizeof eq);
            acc += (unsigned)(eq == 0);
        }
    SECRET(msg, sizeof msg);                /* XOF / KDF over a secret seed */
    ram_hash(out, sizeof out, msg, 200, RAM_ROUNDS, RAM_MODE_XOF, NULL, 0);
    SECRET(msg, sizeof msg);                /* hash of a secret, tree mode */
    ram_hash(out, 128, msg, sizeof msg, RAM_ROUNDS, RAM_MODE_HASH, NULL, 0);
    ram_hash_tree(out, 128, msg, sizeof msg, RAM_ROUNDS, 2);
    SECRET(key, sizeof key);                /* password hashing: the password */
    PUBLIC(msg, 16);                        /* is secret, the salt is public */
    ram_pwhash(out, 64, key, 20, msg, 16, 64, 2, 2);  /* (Balloon indexes by salt) */
    PUBLIC(out, sizeof out);
    printf("ct_test: %u/30 MAC tags matched across one-shot/streaming\n", acc);
    return acc == 30 ? 0 : 1;
}
