#!/bin/sh
# Real Microsoft cl.exe (MSVC Build Tools via msvc-wine, licence accepted by
# the project owner), run under Wine in a linux/amd64 Debian container. The
# ram-msvc volume caches the toolchain.
set -eu
MSVC_WINE=514f8ea34842cd6d831804d0e9658d3a32870ae1
if [ ! -x /msvc/bin/x64/cl ]; then
    rm -rf /tmp/msvc-wine && git clone -q https://github.com/mstorsjo/msvc-wine /tmp/msvc-wine
    git -C /tmp/msvc-wine checkout -q $MSVC_WINE
    python3 /tmp/msvc-wine/vsdownload.py --accept-license --dest /msvc >/tmp/vsdl.log 2>&1 \
        || { tail -20 /tmp/vsdl.log; exit 1; }
    sh /tmp/msvc-wine/install.sh /msvc >/tmp/inst.log 2>&1 || { tail -20 /tmp/inst.log; exit 1; }
fi
export PATH=/msvc/bin/x64:$PATH WINEDEBUG=-all
mkdir -p build && cd build
cl 2>&1 | head -1
for d in "" "/DRAM_NO_THREADS" "/DRAM_RESEARCH"; do
    echo "== cl /O2 /W4 /WX /std:c11 $d"
    cl /nologo /O2 /W4 /WX /std:c11 /MT $d /I../csrc ../csrc/ram_test.c ../csrc/ram1024.c \
        /Feram_test_cl.exe >cl.log 2>&1 || { cat cl.log; exit 1; }
    wine ram_test_cl.exe ../tests/kat.txt ../tests/kat_pwhash.txt
done
echo "== cl DLL"
cl /nologo /O2 /W4 /WX /std:c11 /LD /DRAM_BUILD_DLL ../csrc/ram1024.c /Feram.dll >cl.log 2>&1 \
    || { cat cl.log; exit 1; }
ls -l ram.dll ram.lib | awk '{print $5, $NF}'
