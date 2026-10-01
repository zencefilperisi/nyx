# Benchmark results — Nyx on the mbedTLS X.509 parser

**Target:** `mbedtls_x509_crt_parse_der` from mbedTLS v3.6.2, compiled with
`-fsanitize-coverage=trace-pc-guard,trace-cmp` (11,783 instrumented edges). This
is a real, production certificate parser that recursively decodes the whole
structure — the setting where structure-aware fuzzing has room to pay off.

**Protocol:** 15 independent trials per mode, 25,000 iterations each, seeded with
one real DER certificate. Edge coverage is the cumulative distinct edges hit.
Each mode drives the *same* instrumented target, so the comparison is fair.

![coverage over time](coverage.png)

## Final edge coverage (15 trials, 25k iterations)

| Mode | Median | Mean | SD | vs byte-level |
|------|-------:|-----:|---:|--------------|
| byte-level | 347 | 345.9 | 5.7 | — |
| structure-aware (uniform) | 383 | 382.9 | 6.3 | **+10%** |
| structure-aware (entropy) | 389 | 387.9 | 5.3 | **+12%** |

## Significance (one-sided Mann-Whitney U)

| Comparison | p-value | Significant (α=0.05) |
|------------|--------:|:--------------------:|
| structure-aware (uniform) > byte-level | 1.7e-06 | ✅ |
| structure-aware (entropy) > byte-level | 1.7e-06 | ✅ |
| structure-aware (entropy) > uniform | 0.017 | ✅ |

## What this shows

1. **Structure awareness matters on deep parsers.** Mutating the parsed DER
   tree (and re-serialising consistent lengths) reaches ~10% more of the mbedTLS
   certificate parser than byte-level mutation, with overwhelming significance.
2. **The entropy scheduler adds a further, significant gain** over the uniform
   control (p = 0.017) — the rarity-weighted seed energy and UCB1 operator bandit
   are doing measurable work, not just adding complexity.

## An honest counter-result (shallow targets)

On a **shallow** harness — libtasn1's low-level `asn1_get_tag_der` /
`asn1_get_length_der`, which only inspect the first tag/length — structure
awareness gives **no** advantage (byte-level does as well or better), because
only the first few bytes are ever examined. Structure-aware fuzzing helps exactly
when the target parses deep, nested structure. Reporting this rather than hiding
it is the point: the benefit is real but scoped, and the benchmark says where.

## Reproduce

```bash
./third_party/fetch_targets.sh            # build mbedTLS + libtasn1 with coverage
./third_party/build_bench.sh mbedtls 25000 15
```
