#!/bin/sh
# ASan+UBSan (with and without SIMD) and TSan on the host compiler: catches
# memory/UB/race bugs in seconds without Docker. Linux and macOS (clang/gcc).
set -eu
cd "$(dirname "$0")/.."
CC=${CC:-cc}
T=build/san; mkdir -p "$T"
L=; [ "$(uname -s)" = Linux ] && L=-lpthread
for d in '' '-DRAM_NO_SIMD'; do
    echo "== asan+ubsan $d"
    $CC -std=c99 -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all $d \
        -o $T/asan csrc/ram_test.c csrc/ram1024.c $L
    ./$T/asan tests/kat.txt tests/kat_pwhash.txt | tail -1
done
echo "== tsan"
$CC -std=c99 -g -O1 -fsanitize=thread -o $T/tsan csrc/ram_test.c csrc/ram1024.c $L
TSAN_OPTIONS=halt_on_error=1 ./$T/tsan tests/kat.txt tests/kat_pwhash.txt | tail -1
