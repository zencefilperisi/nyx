# Benchmark

A FuzzBench-style comparison of Nyx's fuzzing modes against real, instrumented
targets, with statistical analysis and a coverage-over-time plot.

## Modes compared

| Mode | Mutation | Scheduler |
|------|----------|-----------|
| `byte` | byte-level | — |
| `uniform` | structure-aware (DER tree) | uniform (control) |
| `entropy` | structure-aware (DER tree) | entropy-guided (rarity + UCB1) |

All modes drive the **same** instrumented target via `LLVMFuzzerTestOneInput`,
so the comparison is fair.

## Headline result

On the **mbedTLS X.509 parser** (a real, deep certificate parser), structure-aware
fuzzing reaches ~10% more coverage than byte-level (p ≈ 1.7e-6), and the entropy
scheduler adds a further significant gain over uniform (p ≈ 0.017). See
[`results/RESULTS.md`](results/RESULTS.md) and the plot there.

## Run it yourself

```bash
# 1. Build the real targets with coverage instrumentation (mbedTLS + libtasn1):
./third_party/fetch_targets.sh

# 2. Build the runner, fuzz each mode over N trials, analyse + plot:
./third_party/build_bench.sh mbedtls 25000 15
#   -> writes bench_results/{summary,timeline}.csv and bench/results/coverage.png
```

## Files

- `bench_runner.cpp` — runs each mode × N trials against the linked target,
  emits `summary.csv` (final coverage per run) and `timeline.csv` (coverage
  over time).
- `run_benchmark.py` — median/mean/spread, one-sided Mann-Whitney U between
  modes, and the coverage-over-time plot.
- `results/` — committed results from a reference run (CSVs + plot + writeup).

## Methodology notes

- **N independent trials** (different RNG seeds) per mode; we report the median
  and interquartile band, not a single cherry-picked run.
- **Mann-Whitney U** (one-sided, non-parametric) tests whether a difference in
  final coverage is significant rather than noise.
- Each campaign resets cumulative coverage, so runs are independent.
