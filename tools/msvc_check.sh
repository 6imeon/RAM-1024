#!/bin/sh
# MSVC-ABI build check (run inside a linux/amd64 Debian container):
# Microsoft's CRT + Windows SDK (fetched by xwin; licence accepted by the
# project owner), compiled by clang-cl in MSVC mode (_MSC_VER defined, no
# GNU extensions), static MSVC CRT (/MT), run under Wine.
set -eu
V=0.10.0
X=xwin-$V-x86_64-unknown-linux-musl
if [ ! -f /xwin/sdk/include/ucrt/stdio.h ] || [ ! -f /xwin/crt/include/vcruntime.h ]; then
    rm -rf /xwin/crt /xwin/sdk
    curl -sSfL -o /tmp/x.tgz https://github.com/Jake-Shadle/xwin/releases/download/$V/$X.tar.gz
    curl -sSfL -o /tmp/x.sha https://github.com/Jake-Shadle/xwin/releases/download/$V/$X.tar.gz.sha256
    echo "$(cut -d' ' -f1 /tmp/x.sha)  /tmp/x.tgz" | sha256sum -c -
    tar -xzf /tmp/x.tgz -C /tmp
    /tmp/$X/xwin --accept-license --cache-dir /xwin/.cache splat --output /xwin
fi
INC="-imsvc /xwin/crt/include -imsvc /xwin/sdk/include/ucrt -imsvc /xwin/sdk/include/um -imsvc /xwin/sdk/include/shared"
LIBS="/libpath:/xwin/crt/lib/x86_64 /libpath:/xwin/sdk/lib/um/x86_64 /libpath:/xwin/sdk/lib/ucrt/x86_64"
mkdir -p build
for d in "" "-DRAM_NO_THREADS" "-DRAM_RESEARCH"; do
    echo "== clang-cl /O2 /MT $d"
    clang --driver-mode=cl --target=x86_64-pc-windows-msvc /nologo /O2 /MT /W4 /WX /std:c11 $d $INC \
        -Wno-unused-command-line-argument \
        csrc/ram_test.c csrc/ram1024.c /Fobuild/ /Febuild/ram_test_msvc.exe \
        -fuse-ld=lld /link $LIBS
    WINEDEBUG=-all wine build/ram_test_msvc.exe tests/kat.txt tests/kat_pwhash.txt
done
echo "== DLL with exports"
clang --driver-mode=cl --target=x86_64-pc-windows-msvc /nologo /O2 /MT /LD /DRAM_BUILD_DLL $INC \
    csrc/ram1024.c /Fobuild/ /Febuild/ram.dll -fuse-ld=lld /link $LIBS
$(ls /usr/bin/llvm-readobj* | head -1) --coff-exports build/ram.dll | grep -c "Name: ram_" | sed 's/^/exported ram_* symbols: /'
