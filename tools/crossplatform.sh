#!/bin/sh
# Build + conformance test across OSes, CPUs, byte orders and compilers in
# Docker (QEMU/Rosetta emulation for foreign CPUs, Wine for Windows).
#
#     sh tools/crossplatform.sh [quick | all | job...]     logs: results/crossplatform/
#
# Cheap by default:
#   * each job's toolchain is installed once and cached as a local image
#     (ramci-<job>:<hash of its setup>); later runs only build and test.
#     RAMCI_REFRESH=1 rebuilds the images (e.g. to pick up distro updates).
#   * at most RAMCI_JOBS containers run at once (default: half the cores),
#     longest jobs first, so the wall time is ~ the slowest job.
#   * the fuzzer runs FUZZ_SECONDS (default 60; 3600+ for a soak run).
#   * every container is labelled ramci=1: `docker kill $(docker ps -q
#     --filter label=ramci=1)` stops a run completely.
set -u
cd "$(dirname "$0")/.."
OUT=results/crossplatform
mkdir -p "$OUT"

PREP='W=\${HOME:-/root}/w; [ -w / ] && W=/w; cp -a /src \$W && cd \$W && rm -rf build'
DEB='apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq'
DEBN="$DEB --no-install-recommends"   # lean images for plain compiler jobs
CLEAN='&& apt-get clean && rm -rf /var/lib/apt/lists/*'
POSIX='make all check CFLAGS=-O2 && python3 tools/xcheck.py 1000 && ./build/ramsum tests/kat.txt'
FUZZ_SECONDS=${FUZZ_SECONDS:-60}

job() { # name platform image setup test
    name=$1; plat=$2; img=$3; setup=$4; shift 4
    start=$(date +%s)
    tag="ramci-$name:$(printf '%s|%s|%s' "$plat" "$img" "$setup" | cksum | cut -d' ' -f1)"
    log="$OUT/$name.log"
    : >"$log"
    if [ "${RAMCI_REFRESH:-0}" = 1 ] || ! docker image inspect "$tag" >/dev/null 2>&1; then
        tmp="ramci-setup-$name-$$"
        docker rm -f "$tmp" >/dev/null 2>&1
        if docker run --platform "$plat" --label ramci=1 --name "$tmp" "$img" sh -c "$setup" >>"$log" 2>&1 \
            && docker commit "$tmp" "$tag" >/dev/null; then :; else
            docker rm -f "$tmp" >/dev/null 2>&1
            echo "FAIL $name ($plat, $img) $(( $(date +%s) - start ))s [setup]"; return
        fi
        docker rm -f "$tmp" >/dev/null 2>&1
    fi
    if docker run --rm --init --label ramci=1 --label "ramsuite=${RAMSUITE:-none}" --platform "$plat" -e FUZZ_SECONDS="$FUZZ_SECONDS" \
        -v "$PWD:/src:ro" -v ram-xwin:/xwin -v ram-bsd:/bsd -v ram-msvc:/msvc \
        "$tag" sh -c "$PREP && $*" >>"$log" 2>&1; then st=PASS; else st=FAIL; fi
    echo "$st $name ($plat, $img) $(( $(date +%s) - start ))s"
}

run() {
case $1 in
linux-arm64-gcc)   job $1 linux/arm64 debian:bookworm-slim "$DEBN gcc libc6-dev make python3 >/dev/null $CLEAN" "$POSIX" ;;
linux-x86_64-gcc)  job $1 linux/amd64 debian:bookworm-slim "$DEBN gcc libc6-dev make python3 >/dev/null $CLEAN" "$POSIX" ;;
linux-i386-gcc)    job $1 linux/386 debian:bookworm-slim "$DEBN gcc libc6-dev make python3 >/dev/null $CLEAN" "$POSIX" ;;
linux-s390x-bigendian) job $1 linux/s390x ubuntu:24.04 "$DEBN gcc libc6-dev make python3 >/dev/null $CLEAN" "$POSIX" ;;
linux-riscv64-gcc) job $1 linux/riscv64 ubuntu:24.04 "$DEBN gcc libc6-dev make python3 >/dev/null $CLEAN" "$POSIX" ;;
linux-ppc64le-gcc) job $1 linux/ppc64le ubuntu:24.04 "$DEBN gcc libc6-dev make python3 >/dev/null $CLEAN" "$POSIX" ;;
alpine-musl-clang) job $1 linux/arm64 alpine:3.20 "apk add -q --no-cache clang make python3 musl-dev >/dev/null" "make all check CC=clang && python3 tools/xcheck.py 1000" ;;
tcc-no-simd)       job $1 linux/amd64 debian:bookworm-slim "$DEBN tcc libc6-dev make >/dev/null $CLEAN" "mkdir build && tcc -O2 -o build/ram_test csrc/ram_test.c csrc/ram1024.c -lpthread && ./build/ram_test tests/kat.txt tests/kat_pwhash.txt" ;;
strict-c99)        job $1 linux/arm64 debian:bookworm-slim "$DEBN gcc clang libc6-dev make >/dev/null $CLEAN" "mkdir build && for cc in gcc clang; do for d in '' '-DRAM_NO_SIMD' '-DRAM_NO_THREADS' '-DRAM_NO_SIMD -DRAM_NO_THREADS'; do echo \"== \$cc \$d\"; \$cc -std=c99 -pedantic -Wall -Wextra -Wshadow -Wconversion -Wsign-conversion -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes -Werror -O2 \$d -o build/t csrc/ram_test.c csrc/ram1024.c -lpthread && ./build/t tests/kat.txt tests/kat_pwhash.txt && \$cc -std=c99 -O2 -DRAM_RESEARCH \$d -o build/tr csrc/ram_test.c csrc/ram1024.c -lpthread && ./build/tr tests/kat.txt tests/kat_pwhash.txt || exit 1; done; done" ;;
sanitizers)        job $1 linux/arm64 debian:bookworm-slim "$DEBN clang libclang-rt-14-dev libc6-dev make >/dev/null $CLEAN" "mkdir build && for d in '' '-DRAM_NO_SIMD'; do clang -std=c99 -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \$d -o build/t csrc/ram_test.c csrc/ram1024.c -lpthread && ./build/t tests/kat.txt tests/kat_pwhash.txt || exit 1; done && clang -std=c99 -g -O1 -fsanitize=thread -o build/tt csrc/ram_test.c csrc/ram1024.c -lpthread && ./build/tt tests/kat.txt tests/kat_pwhash.txt" ;;
windows-x64-mingw) job $1 linux/amd64 debian:bookworm-slim "dpkg --add-architecture i386 && $DEB gcc-mingw-w64-x86-64 make wine wine64 >/dev/null $CLEAN" "make all OS=Windows_NT CC=x86_64-w64-mingw32-gcc CFLAGS=-O2 && make build/ram_test_research.exe OS=Windows_NT CC=x86_64-w64-mingw32-gcc CFLAGS=-O2 && export WINEDEBUG=-all && wine build/ram_test.exe tests/kat.txt tests/kat_pwhash.txt && wine build/ram_test_research.exe tests/kat.txt tests/kat_pwhash.txt && wine build/ramsum.exe tests/kat.txt" ;;
windows-x86-mingw) job $1 linux/amd64 debian:bookworm-slim "dpkg --add-architecture i386 && $DEB gcc-mingw-w64-i686 make wine wine32 >/dev/null $CLEAN" "make all OS=Windows_NT CC=i686-w64-mingw32-gcc CFLAGS=-O2 && WINEDEBUG=-all wine build/ram_test.exe tests/kat.txt tests/kat_pwhash.txt" ;;
cmake)             job $1 linux/arm64 debian:bookworm-slim "$DEBN gcc libc6-dev cmake make >/dev/null $CLEAN" "cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >/dev/null && cmake --build build -j2 && cd build && ctest --output-on-failure" ;;
constant-time)     job $1 linux/arm64 debian:bookworm-slim "$DEBN gcc libc6-dev valgrind >/dev/null $CLEAN" "mkdir build && for d in '-O2' '-O3' '-O2 -DRAM_NO_SIMD' '-Os -DRAM_NO_THREADS'; do echo \"== gcc \$d\"; gcc -std=c99 -g \$d -I csrc -o build/ct csrc/check/ct_test.c csrc/ram1024.c -lpthread && valgrind -q --error-exitcode=1 ./build/ct || exit 1; done" ;;
fuzz)              job $1 linux/arm64 debian:bookworm-slim "$DEBN clang libclang-rt-14-dev libc6-dev >/dev/null $CLEAN" "mkdir build && clang -O1 -g -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -I csrc csrc/check/fuzz_ram.c csrc/ram1024.c -o build/fuzz -lpthread && ./build/fuzz -max_total_time=\$FUZZ_SECONDS -max_len=4096 -print_final_stats=1 >build/fuzz.log 2>&1; rc=\$?; tail -15 build/fuzz.log; exit \$rc" ;;
pip-linux)         job $1 linux/amd64 debian:bookworm-slim "$DEB gcc python3-venv >/dev/null $CLEAN" "python3 -m venv /tmp/v && /tmp/v/bin/pip install -q . && rm -rf ramhash && /tmp/v/bin/python -c 'import ramhash._libpath as l; print(l.find(\"ram\"))' && /tmp/v/bin/python tools/xcheck.py 1000 && /tmp/v/bin/python -c 'import ramhash as r; h=r.hash_password(\"pw\"); assert r.verify_password(\"pw\", h); print(h[:34])'" ;;
pip-no-compiler)   job $1 linux/arm64 debian:bookworm-slim "$DEBN python3-venv >/dev/null $CLEAN" "python3 -m venv /tmp/v && /tmp/v/bin/pip install -q . && rm -rf ramhash && /tmp/v/bin/python tools/xcheck.py 300 --pure && /tmp/v/bin/python -c 'import ramhash as r; h=r.hash_password(\"pw\"); assert r.verify_password(\"pw\", h); print(h[:26])'" ;;
windows-x64-msvc)  docker volume create ram-xwin >/dev/null; job $1 linux/amd64 debian:bookworm-slim "dpkg --add-architecture i386 && $DEB clang lld llvm wine wine64 curl ca-certificates >/dev/null $CLEAN" "sh tools/msvc_check.sh" ;;
freebsd-arm64)     docker volume create ram-bsd >/dev/null; job $1 linux/arm64 debian:bookworm-slim "$DEB qemu-system-arm qemu-efi-aarch64 python3 xz-utils curl ca-certificates >/dev/null $CLEAN" "sh tools/bsd_check.sh" ;;
openbsd-arm64)     docker volume create ram-bsd >/dev/null; job $1 linux/arm64 debian:bookworm-slim "$DEB qemu-system-arm qemu-efi-aarch64 qemu-utils python3 curl ca-certificates openssh-client >/dev/null $CLEAN" "sh tools/openbsd_check.sh" ;;
windows-x64-cl)    docker volume create ram-msvc >/dev/null; job $1 linux/amd64 debian:bookworm-slim "$DEB wine64 python3 msitools ca-certificates winbind git >/dev/null $CLEAN" "sh tools/clexe_check.sh" ;;
android-termux)    job $1 linux/arm64 termux/termux-docker:aarch64 "pkg update -y >/dev/null 2>&1; pkg install -y clang make python >/dev/null 2>&1" "make all check CC=clang && python3 tools/xcheck.py 1000" ;;
*) echo "FAIL $1 (unknown job)" ;;
esac
}

if [ "${1:-}" = --one ]; then run "$2" >>"$3"; exit 0; fi

# Longest first (from earlier runs), so the slowest jobs never start last.
ALL="openbsd-arm64 freebsd-arm64 windows-x64-cl windows-x64-msvc android-termux windows-x64-mingw windows-x86-mingw linux-i386-gcc linux-ppc64le-gcc linux-s390x-bigendian linux-riscv64-gcc pip-linux linux-x86_64-gcc fuzz strict-c99 sanitizers constant-time linux-arm64-gcc tcc-no-simd cmake pip-no-compiler alpine-musl-clang"
# Native-arch subset (no CPU emulation, no VMs): every compiler/sanitizer
# check plus one big-endian CPU; ~2-3 min once images are cached.
QUICK="linux-s390x-bigendian windows-x64-mingw fuzz strict-c99 sanitizers constant-time linux-arm64-gcc cmake pip-no-compiler alpine-musl-clang"
case "${1:-all}" in
    all) set -- $ALL ;;
    quick) set -- $QUICK ;;
esac
NCPU=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)
JOBS=${RAMCI_JOBS:-$(( NCPU / 2 > 2 ? NCPU / 2 : 2 ))}
RUN="$OUT/run.$$"
: >"$RUN"
printf '%s\n' "$@" | xargs -P "$JOBS" -I{} sh "$0" --one {} "$RUN"
# merge into summary.txt: the latest result of every job
cat "$OUT/summary.txt" "$RUN" 2>/dev/null | awk '{last[$2]=$0} END {for (k in last) print last[k]}' \
    | sort -k2 >"$OUT/summary.new" && mv "$OUT/summary.new" "$OUT/summary.txt"
sort -k2 "$RUN"
grep -q FAIL "$RUN" && { rm -f "$RUN"; exit 1; }
rm -f "$RUN"
