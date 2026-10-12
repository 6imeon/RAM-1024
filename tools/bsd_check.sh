#!/bin/sh
# FreeBSD conformance run (inside a linux/arm64 Debian container with the
# ram-bsd volume caching the official VM image).
set -eu
REL=15.0
IMG=FreeBSD-$REL-RELEASE-arm64-aarch64-ufs.qcow2
URL=https://download.freebsd.org/releases/VM-IMAGES/$REL-RELEASE/aarch64/Latest
cd /bsd
if [ ! -f $IMG ]; then
    curl -sSfLO $URL/$IMG.xz
    curl -sSfL $URL/CHECKSUM.SHA256 | grep "($IMG.xz)" | sed 's/.*= //' > sum
    echo "$(cat sum)  $IMG.xz" | sha256sum -c -
    xz -d $IMG.xz
fi
cd "$OLDPWD"
mkdir -p /srv && tar -cf /srv/src.tar --exclude=./build --exclude=./results .
(cd /srv && python3 -m http.server 8000 >/dev/null 2>&1 &)
python3 tools/bsd_vm.py /bsd/$IMG root '
uname -srm; cd /tmp && fetch -q http://10.0.2.2:8000/src.tar && mkdir w && cd w && tar -xf ../src.tar &&
for d in "" "-DRAM_NO_SIMD" "-DRAM_RESEARCH"; do echo "== cc -O2 $d";
  cc -std=c99 -O2 -Wall -Wextra -Werror $d -o t csrc/ram_test.c csrc/ram1024.c -lpthread && ./t tests/kat.txt tests/kat_pwhash.txt || break; done'
