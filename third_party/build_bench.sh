#!/usr/bin/env bash
# Build the benchmark runner against a target built by fetch_targets.sh, run it,
# and analyse the results. Default target: mbedTLS (the deep X.509 parser).
#
#   ./third_party/build_bench.sh [mbedtls|libtasn1] [iters] [trials]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TP="$ROOT/third_party"
TARGET="${1:-mbedtls}"
ITERS="${2:-25000}"
TRIALS="${3:-15}"
COV="-O1 -g -fsanitize-coverage=trace-pc-guard,trace-cmp -w"

cd "$ROOT"
mkdir -p /tmp/nyx_obj
echo "[bench] compiling nyx_core"
for f in coverage corpus byte_mutator der_parser der_serializer mutator engine grammar_x509 scheduler; do
  clang++ -c -std=c++20 -O2 -Iinclude "src/$f.cpp" -o "/tmp/nyx_obj/$f.o"
done

case "$TARGET" in
  mbedtls)
    clang -c $COV -Imbedtls/include 2>/dev/null >/dev/null || true
    clang -c -O1 -g -fsanitize-coverage=trace-pc-guard,trace-cmp \
          -I"$TP/mbedtls/include" harnesses/mbedtls_harness.c -o /tmp/nyx_obj/harness.o
    LIB="$TP/libmbedtls_cov.a" ;;
  libtasn1)
    clang -c -O1 -g -fsanitize-coverage=trace-pc-guard,trace-cmp \
          -I"$TP/libtasn1/lib/includes" harnesses/libtasn1_harness.c -o /tmp/nyx_obj/harness.o
    LIB="$TP/liblibtasn1_cov.a" ;;
  *) echo "unknown target: $TARGET"; exit 1 ;;
esac

echo "[bench] linking bench_runner against $TARGET"
clang++ -std=c++20 -O2 -Iinclude bench/bench_runner.cpp \
        /tmp/nyx_obj/*.o "$LIB" -o /tmp/nyx_bench

mkdir -p bench_results
# Seed: a real DER certificate, if openssl is available.
if [ ! -f bench_results/seed.der ] && command -v openssl >/dev/null; then
  openssl req -x509 -newkey rsa:2048 -keyout /tmp/k.pem -out /tmp/c.pem -days 365 \
    -nodes -subj "/CN=nyx-bench" 2>/dev/null
  openssl x509 -in /tmp/c.pem -outform DER -out bench_results/seed.der
fi

echo "[bench] running $TARGET: $TRIALS trials x $ITERS iters x 3 modes"
/tmp/nyx_bench --iters "$ITERS" --trials "$TRIALS" --out bench_results \
  ${SEED:+--seed-file "$SEED"} \
  $( [ -f bench_results/seed.der ] && echo --seed-file bench_results/seed.der )

python3 bench/run_benchmark.py --in bench_results --out bench/results
