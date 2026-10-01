# Nyx — Design Document

**Nyx** is a structure-aware, entropy-guided coverage fuzzer for ASN.1/DER
parsers, with X.509 certificate parsing as its primary domain. This document is
the technical spec: what it does, why the design is shaped this way, how it is
evaluated, and how it relates to prior work.

> Status: DER core (tree IR + parser + serializer) implemented and tested.
> Everything else is phased below.

---

## 1. Problem

Generic byte-level fuzzers (AFL++, libFuzzer) waste most of their energy on
inputs that a structured parser rejects in the first few bytes — a wrong tag or
an inconsistent length is discarded before any interesting code runs. For a
format like DER, whose values are nested Tag-Length-Value triples, almost every
random mutation is dead on arrival.

Nyx attacks this on two fronts at once:

1. **Structure-aware generation/mutation** — mutate a *parsed DER tree*, not raw
   bytes, so every candidate is structurally coherent and reaches deep parser
   code.
2. **Entropy-guided scheduling** — spend mutation energy where it carries the
   most *information*, measured with an information-theoretic signal rather than
   fixed heuristics.

Target domain: **X.509 certificate parsing**, historically a rich source of
memory-safety CVEs, and directly connected to the author's prior work on
certificate/crypto tooling.

---

## 2. Prior art (honest positioning)

This is **not** the first grammar-aware fuzzer, and the design says so plainly:

- **Nautilus** (grammar-based, coverage-guided) is the closest prior work and
  the primary benchmark competitor.
- **AFL++** offers grammar mutators and rare-branch power schedules as add-ons.
- **libFuzzer** is the in-process baseline.

**Where Nyx differs:** it combines DER-specialised structure-aware mutation
(like Nautilus's tree mutations, but native to ASN.1) with a *principled,
information-theoretic scheduler* — rarity-weighted seed energy plus a bandit
operator selector governed by reward-distribution entropy. Whether that
combination actually wins is treated as an empirical question, settled by the
benchmark (§5), never asserted on faith.

---

## 3. Architecture

```
 corpus ──▶ scheduler ──▶ pick seed ──▶ DER parse ──▶ tree
                                                        │
                                              structure-aware mutate
                                              (+ X.509 semantic layer)
                                                        │
                                                    serialize
                                                        │
                                              run instrumented target
                                                        │
                                         SanitizerCoverage: edges + cmp operands
                                                        │
                              ┌─────────────────────────┴───────────┐
                        new coverage?                           crash?
                         save seed, feed                  minimize + dedup,
                         scheduler the reward                 save crash
```

### 3.1 DER tree IR — `include/nyx/der_tree.hpp` ✅
`DerNode` = tag + (primitive content | children). Universal to all ASN.1.

### 3.2 Parser / serializer — `der_parser.*`, `der_serializer.*` ✅
Definite-length DER. **Invariant, tested:** for valid canonical DER,
`serialize(parse(x)) == x` byte-for-byte (verified on a real X.509 cert:
58 nodes, exact round-trip). This invariant is what lets the mutator work on the
tree and still emit valid DER.

### 3.3 Structure-aware mutator — `mutator.hpp` (Phase 2)
Tree-level operators: content flip/resize, tag-number swap (type confusion),
primitive⇄constructed toggle, child duplicate/delete/insert/swap, deliberate
length corruption, deep-nesting attacks. Each operator keeps the tree
serialisable; each ships with a unit test.

### 3.4 X.509 semantic layer — `grammar_x509.hpp` (Phase 2b)
Knows the `Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
signatureValue }` structure down to validity dates, OIDs and extensions. Emits
**valid-but-hostile** certificates that pass shallow checks and drive the parser
into date handling, OID tables and extension parsing — where the bugs live.

### 3.5 Coverage — `coverage.hpp` (Phase 0–1)
LLVM SanitizerCoverage: `-fsanitize-coverage=trace-pc-guard,trace-cmp`.
`trace-cmp` exposes comparison operands, letting Nyx synthesise the exact
tag/length bytes a parser checks for instead of guessing them.

### 3.6 Entropy-guided scheduler — `scheduler.hpp` (Phase 3)
- **Seed energy:** rarity-weighted. An edge hit with probability `p` in the
  global histogram carries self-information `-log2(p)`; a seed's energy is the
  sum over the rare edges it reaches.
- **Operator selection:** multi-armed bandit, reward = new edges, exploration
  governed by the entropy of the operator-reward distribution.
- **Ablation baselines behind the same interface:** uniform / round-robin
  (entropy OFF) vs the entropy scheduler — so the benchmark can isolate exactly
  what the entropy guidance contributes.

---

## 4. Targets

| Target | Entry point | Why |
|--------|-------------|-----|
| GNU **libtasn1** | `asn1_get_tag_der`, `asn1_get_length_der` | dedicated ASN.1 lib, clean harness, historic CVEs, not saturated |
| **mbedTLS** | `mbedtls_x509_crt_parse_der` | full X.509 path; reaches the deep code the grammar layer targets |
| **OpenSSL** | `d2i_X509` | hard baseline; proves Nyx works on a heavily-fuzzed target |

All built with `-fsanitize=address,undefined` + coverage; all fuzzers hit the
identical `LLVMFuzzerTestOneInput` harness so the comparison is fair.

---

## 5. Evaluation (the heart of the project)

"Better" is only ever a measured claim:

- **FuzzBench-style methodology:** fixed wall-clock budget per trial (24h),
  **N≥10 independent trials** per fuzzer with different seeds.
- **Metrics:** edge coverage over time, unique crashes over time,
  time-to-first-crash.
- **Statistics:** median coverage with 95% CI; **Mann-Whitney U** test between
  Nyx and each baseline to establish whether a difference is significant
  (p<0.05), not noise.
- **Fuzzers:** nyx, nyx-uniform (ablation), libFuzzer, AFL++, **Nautilus**.
- **Honest outcomes are acceptable outcomes.** "Nyx finds edge X% faster than
  Nautilus (p<0.05)" is the goal; "no significant difference on target T,
  here's the analysis of why" is still a legitimate, publishable-quality result.

---

## 6. Phases (each ends with something demonstrable)

- **Phase 0** — SanitizerCoverage plumbing: read edges + cmp operands from an
  instrumented target.
- **Phase 1** — Minimal coverage-guided loop: seeds, byte mutations, crash
  detection. *A working fuzzer.*
- **Phase 2** — Structure-aware mutator on the DER tree (core ready ✅).
- **Phase 2b** — X.509 semantic grammar layer.
- **Phase 3** — Entropy-guided scheduler + uniform ablation baseline. ✅
- **Phase 4** — Benchmark harness, real targets, trials, statistics, plots. ✅
  Result on the real mbedTLS X.509 parser: structure-aware +10% coverage over
  byte-level (p≈1.7e-6); entropy scheduler > uniform (p≈0.017). See
  `bench/results/RESULTS.md`.

Each phase is independently showable, so the project is portfolio-valuable at
every milestone, not only at the end.

---

## 7. Non-goals

- Not a general-purpose fuzzer; ASN.1/DER focus is deliberate.
- Not a replacement for AFL++/libFuzzer in their domains.
- Not claiming novelty over Nautilus without benchmark evidence.
