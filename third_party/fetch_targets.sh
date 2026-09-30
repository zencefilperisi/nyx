#!/usr/bin/env bash
# Fetch and build the fuzzing targets with coverage + sanitizer instrumentation.
# Targets are NOT vendored into the repo; this script pins known versions so the
# benchmark is reproducible. Run from the repo root: third_party/fetch_targets.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

CC="${CC:-clang}"
COV_FLAGS="-g -O1 -fsanitize=address,undefined -fsanitize-coverage=trace-pc-guard,trace-cmp"

# Pinned versions for reproducibility.
LIBTASN1_VER="4.19.0"
MBEDTLS_VER="3.6.0"

echo "[fetch] libtasn1 ${LIBTASN1_VER}"
# curl -LO "https://ftp.gnu.org/gnu/libtasn1/libtasn1-${LIBTASN1_VER}.tar.gz"
# tar xf "libtasn1-${LIBTASN1_VER}.tar.gz"
# (cd libtasn1-${LIBTASN1_VER} && CFLAGS="$COV_FLAGS" ./configure --disable-shared && make -j)

echo "[fetch] mbedtls ${MBEDTLS_VER}"
# git clone --depth 1 --branch v${MBEDTLS_VER} https://github.com/Mbed-TLS/mbedtls
# (cd mbedtls && CFLAGS="$COV_FLAGS" cmake -B build -DENABLE_TESTING=Off && cmake --build build -j)

cat <<'NOTE'
NOTE: download/build commands are commented out so this script is safe to read
and adapt. Uncomment once you are on a machine with network + the toolchain.
Each target is built with:
    -fsanitize=address,undefined            (memory + UB bug detection)
    -fsanitize-coverage=trace-pc-guard,trace-cmp   (edge coverage + cmp operands)
Then link the matching harness from ../harnesses/ against the built library.
NOTE
