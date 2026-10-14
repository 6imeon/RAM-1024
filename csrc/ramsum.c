/* ramsum: RAM-1024 digests of files (or stdin), like sha256sum.
 *
 *     ramsum [-l bytes] [FILE...]
 */
/* MSVC deprecates standard C stdio in favour of its _s variants. */
#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ram1024.h"

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

static int sum(FILE *f, const char *name, size_t outlen)
{
    static uint8_t buf[1 << 16];
    uint8_t *out = malloc(outlen);
    ram_ctx *c = malloc(sizeof *c);
    if (!out || !c || ram_init(c, outlen, RAM_MODE_HASH, RAM_ROUNDS, NULL, 0)) {
        free(out);
        free(c);
        return 1;
    }
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) ram_update(c, buf, n);
    int err = ferror(f);
    ram_final(c, out);
    if (!err) {
        for (size_t i = 0; i < outlen; i++) printf("%02x", out[i]);
        printf("  %s\n", name);
    } else {
        fprintf(stderr, "ramsum: %s: read error\n", name);
    }
    free(out);
    free(c);
    return err != 0;
}

int main(int argc, char **argv)
{
    size_t outlen = RAM_OUT;
    int i = 1, rc = 0;
    if (argc > 1 && !strcmp(argv[1], "-l")) {
        char *end = NULL;
        outlen = argc > 2 ? (size_t)strtoul(argv[2], &end, 10) : 0;
        if (!end || *end || outlen < RAM_MIN_HASH_OUT || outlen > 1 << 20) {
            fprintf(stderr, "ramsum: bad length (%d to %d bytes)\n",
                    RAM_MIN_HASH_OUT, 1 << 20);
            return 2;
        }
        i = 3;
    }
    if (i == argc) {
#ifdef _WIN32
        _setmode(_fileno(stdin), _O_BINARY); /* no CRLF translation */
#endif
        return sum(stdin, "-", outlen);
    }
    for (; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) {
            perror(argv[i]);
            rc = 1;
            continue;
        }
        rc |= sum(f, argv[i], outlen);
        fclose(f);
    }
    return rc;
}
