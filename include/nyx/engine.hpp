#pragma once
// The Phase-1 fuzzing loop.
//
//   pick seed -> mutate -> run instrumented target -> read coverage
//     -> new edges? keep the input   -> crash? save it   -> repeat
//
// The target is an in-process libFuzzer-style entry point:
//     int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);
// which is exactly what the harnesses in harnesses/ expose, so the same target
// works here and under libFuzzer/AFL++ in the benchmark.
#include <cstdint>
#include <string>
#include <vector>

#include "nyx/corpus.hpp"

namespace nyx {

using TargetFn = int (*)(const uint8_t*, size_t);

struct EngineOptions {
  uint64_t seed = 0x9E3779B97F4A7C15ull;
  uint64_t max_iterations = 0;   // 0 => unbounded (use max_seconds)
  double max_seconds = 0.0;      // 0 => unbounded (use max_iterations)
  bool stop_on_first_crash = false;
  std::string crash_dir;         // if set, crashing inputs are written here
  bool quiet = false;
  // When false, inputs that discover new edges are NOT kept -- i.e. blind
  // fuzzing with no coverage feedback. Used as the ablation baseline that shows
  // how much the coverage guidance is actually worth.
  bool coverage_guided = true;
};

struct FuzzStats {
  uint64_t iterations = 0;
  size_t corpus_size = 0;
  size_t total_edges = 0;        // cumulative distinct edges covered
  size_t crashes = 0;
  std::vector<uint8_t> first_crash;
  double elapsed_seconds = 0.0;
};

// Run the loop against `target`, growing `corpus` in place. Returns stats.
FuzzStats fuzz(TargetFn target, Corpus& corpus, const EngineOptions& opts);

}  // namespace nyx
