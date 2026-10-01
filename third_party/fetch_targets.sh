#!/usr/bin/env bash
# Fetch and build the real fuzzing targets with coverage instrumentation.
# Produces static libraries the benchmark links against. Reproducible: pins
# versions and builds every target with the same SanitizerCoverage flags.
#
#   ./third_party/fetch_targets.sh          # builds mbedTLS (deep) + libtasn1
#
# Requires: clang, git, curl, ar. Run from the repo root.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
CC="${CC:-clang}"
COV="-O1 -g -fsanitize-coverage=trace-pc-guard,trace-cmp -w"

# ---------------------------------------------------------------------------
# mbedTLS -- the DEEP X.509 parser (mbedtls_x509_crt_parse_der). This is the
# headline benchmark target: a real certificate parser that recursively decodes
# the whole structure, so structure-aware fuzzing has room to pay off.
# ---------------------------------------------------------------------------
build_mbedtls() {
  echo "[mbedtls] fetching v3.6.2"
  rm -rf mbedtls
  git clone --depth 1 --branch v3.6.2 https://github.com/Mbed-TLS/mbedtls.git
  echo "[mbedtls] compiling library/*.c with coverage"
  mkdir -p mbedtls_obj
  for c in mbedtls/library/*.c; do
    "$CC" -c $COV -Imbedtls/include -Imbedtls/library "$c" \
          -o "mbedtls_obj/$(basename "${c%.c}").o"
  done
  ar rcs libmbedtls_cov.a mbedtls_obj/*.o
  echo "[mbedtls] -> $HERE/libmbedtls_cov.a (link harnesses/mbedtls_harness.c)"
}

# ---------------------------------------------------------------------------
# GNU libtasn1 -- a dedicated ASN.1 library. Built from a git checkout without
# the full autotools/gnulib bootstrap: we vendor the few gnulib headers the core
# parser needs and supply a minimal config.h. (Note: the shipped harness drives
# the low-level tag/length API, which is comparatively shallow; mbedTLS is the
# better target for showing the structure-aware advantage.)
# ---------------------------------------------------------------------------
build_libtasn1() {
  echo "[libtasn1] fetching"
  rm -rf libtasn1
  git clone --depth 1 https://github.com/gnutls/libtasn1.git
  cd libtasn1
  for h in intprops.h intprops-internal.h minmax.h c-ctype.h; do
    curl -fsSL -o "lib/$h" "https://raw.githubusercontent.com/coreutils/gnulib/master/lib/$h"
  done
  sed -e 's/@MAJOR_VERSION@/4/g' -e 's/@MINOR_VERSION@/20/g' \
      -e 's/@PATCH_VERSION@/0/g' -e 's/@NUMBER_VERSION@/0x041400/g' \
      -e 's/@VERSION@/4.20.0/g' lib/includes/libtasn1.h.in > lib/includes/libtasn1.h
  cat > lib/config.h <<'CFG'
#ifndef NYX_LIBTASN1_CONFIG_H
#define NYX_LIBTASN1_CONFIG_H
#define _GL_CONFIG_H_INCLUDED 1
#include <stdbool.h>
#include <stddef.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#define SIZEOF_UNSIGNED_INT 4
#define SIZEOF_UNSIGNED_LONG_INT 8
#define SIZEOF_INT 4
#define SIZEOF_LONG 8
#define _GL_INLINE static inline
#define _GL_EXTERN_INLINE static inline
#define _GL_INLINE_HEADER_BEGIN
#define _GL_INLINE_HEADER_END
#define _GL_UNUSED
#define _GL_ATTRIBUTE_CONST
#define _GL_ATTRIBUTE_PURE
#define _GL_ATTRIBUTE_MAYBE_UNUSED
#define _GL_ATTRIBUTE_NODISCARD
#endif
CFG
  for f in coding decoding element errors gstr parser_aux structure; do
    "$CC" -c $COV -DHAVE_CONFIG_H -include config.h -Ilib -Ilib/includes \
          "lib/$f.c" -o "/tmp/lt_$f.o"
  done
  ar rcs "$HERE/liblibtasn1_cov.a" /tmp/lt_*.o
  cd "$HERE"
  echo "[libtasn1] -> $HERE/liblibtasn1_cov.a (link harnesses/libtasn1_harness.c)"
}

build_mbedtls
build_libtasn1
echo "Done. Build the benchmark with third_party/build_bench.sh"
