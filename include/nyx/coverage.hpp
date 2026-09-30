#pragma once
// Coverage feedback via LLVM SanitizerCoverage.
//
// Targets are compiled with:
//   -fsanitize-coverage=trace-pc-guard,trace-cmp
//
// trace-pc-guard gives edge coverage; trace-cmp exposes comparison operands,
// which is decisive for ASN.1 -- it lets the fuzzer learn the exact tag/length
// bytes a parser checks for, instead of guessing them blindly.
//
// PHASE 0-1. This header defines how the engine reads coverage; the callbacks
// themselves are provided by the instrumented target and captured in coverage.cpp.
#include <cstddef>
#include <cstdint>
#include <vector>

namespace nyx {

class CoverageMap {
 public:
  // Reset per-execution edge hits before running the target.
  void reset();

  // Snapshot the edges hit by the last execution.
  const std::vector<uint8_t>& edges() const { return edges_; }

  // Fold the last execution into the global histogram; returns the number of
  // NEW edges seen for the first time (the fuzzer's primary reward signal).
  size_t commit();

  // -log2(p) rarity of an edge, from the global histogram (used by the scheduler).
  double rarity(size_t edge_index) const;

 private:
  std::vector<uint8_t> edges_;        // per-execution
  std::vector<uint64_t> global_hits_; // cumulative
  uint64_t total_execs_ = 0;
};

// Comparison operands captured by trace-cmp during the last execution, used to
// synthesise the exact bytes a parser compares against (magic-value bypass).
struct CmpOperand {
  uint64_t lhs = 0;
  uint64_t rhs = 0;
  uint8_t width = 0;  // bytes
};
const std::vector<CmpOperand>& last_cmp_operands();

}  // namespace nyx
