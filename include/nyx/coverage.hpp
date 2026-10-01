#pragma once
// Coverage feedback via LLVM SanitizerCoverage (in-process model).
//
// Targets are compiled with:
//   -fsanitize-coverage=trace-pc-guard,trace-cmp
//
// The instrumented target calls the __sanitizer_cov_* callbacks (defined in
// coverage.cpp) as it runs, in the SAME process as the fuzzer. trace-pc-guard
// gives edge coverage; trace-cmp exposes comparison operands, which is decisive
// for ASN.1 -- it lets the fuzzer learn the exact tag/length bytes a parser
// checks for instead of guessing them.
//
// Because the callbacks are global (one coverage map per process), this is a
// free-function API rather than an instantiable class.
#include <cstddef>
#include <cstdint>
#include <vector>

namespace nyx {

// A comparison captured by trace-cmp during the last execution. `is_const`
// marks comparisons against a compile-time constant (e.g. `tag == 0x30`), whose
// operand the fuzzer can copy straight into the input to satisfy the branch.
struct CmpOperand {
  uint64_t lhs = 0;
  uint64_t rhs = 0;
  uint8_t width = 0;   // operand width in bytes (1/2/4/8)
  bool is_const = false;
};

// Clear per-execution state. Call immediately before running the target.
void coverage_reset();

// Clear the CUMULATIVE histogram too (start a fresh fuzzing campaign). Without
// this, separate campaigns in the same process share coverage state, which
// would invalidate an A/B comparison between two fuzzers.
void coverage_reset_global();

// Number of distinct edges hit during the last execution.
size_t coverage_edges_hit();

// Total number of instrumented edges (guards) in the target. Known after the
// target's constructors have run.
size_t coverage_total_edges();

// Number of distinct edges hit at least once across ALL executions so far
// (cumulative coverage). This is the fuzzer's headline progress metric.
size_t coverage_covered_edges();

// Fold the last execution into the cumulative histogram. Returns the number of
// edges seen for the FIRST time ever -- the fuzzer's primary reward signal.
size_t coverage_commit();

// Information-theoretic rarity of an edge: -log2(p), where p is how often the
// edge has been hit across all executions so far. Used by the entropy scheduler.
double coverage_edge_rarity(size_t edge_index);

// Comparison operands captured during the last execution.
const std::vector<CmpOperand>& coverage_cmp_operands();

// Indices of the edges hit during the last execution (the seed's edge set),
// used by the entropy scheduler to score a seed's rarity.
std::vector<uint32_t> coverage_current_edges();

}  // namespace nyx
