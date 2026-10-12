#!/bin/sh
# iOS conformance (macOS host).
#  1. Mac Catalyst: the iOS ABI + iOS libSystem running on macOS (always).
#  2. iOS Simulator: real iOS runtime, if Xcode is installed.
#     sh tools/ios_check.sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p build
SRC="csrc/ram_test.c csrc/ram1024.c"
KAT="tests/kat.txt tests/kat_pwhash.txt"

echo "== Mac Catalyst (arm64-apple-ios15.0-macabi)"
clang -target arm64-apple-ios15.0-macabi -std=c99 -O2 -Wall -Wextra -Werror \
    -o build/ram_test_catalyst $SRC
./build/ram_test_catalyst $KAT

if ! xcrun --sdk iphonesimulator --show-sdk-path >/dev/null 2>&1; then
    echo "== iOS Simulator: SKIPPED (install Xcode, then re-run this script)"
    exit 2
fi
echo "== iOS Simulator"
SDK=$(xcrun --sdk iphonesimulator --show-sdk-path)
xcrun --sdk iphonesimulator clang -target arm64-apple-ios15.0-simulator -isysroot "$SDK" \
    -std=c99 -O2 -Wall -Wextra -Werror -o build/ram_test_iossim $SRC
DEV=$(xcrun simctl list devices available | grep -m1 -oE 'iPhone[^(]*\(([0-9A-F-]{36})\)' \
      | grep -oE '[0-9A-F-]{36}')
xcrun simctl boot "$DEV" 2>/dev/null || true
xcrun simctl spawn "$DEV" "$PWD/build/ram_test_iossim" "$PWD/tests/kat.txt" "$PWD/tests/kat_pwhash.txt"
