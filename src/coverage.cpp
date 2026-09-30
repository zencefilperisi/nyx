// SanitizerCoverage runtime for Nyx (in-process).
//
// IMPORTANT: this file must be compiled WITHOUT -fsanitize-coverage, otherwise
// the callbacks would instrument themselves and recurse infinitely. Only the
// TARGET is compiled with coverage; this runtime captures what it reports.
//
// Implements the callbacks emitted by:
//   -fsanitize-coverage=trace-pc-guard,trace-cmp
#include "nyx/coverage.hpp"

#include <cmath>
#include <cstring>

namespace nyx {
namespace {

struct CoverageState {
  // Per-execution edge hits (index 0 unused; guards are 1-based).
  std::vector<uint8_t> edges;
  // Cumulative hit count per edge, across all executions.
  std::vector<uint64_t> global_hits;
  uint64_t total_execs = 0;
  size_t num_edges = 0;  // number of guards (excludes the unused 0 slot)
  std::vector<CmpOperand> cmps;
};

// Single global map: the callbacks are global C symbols with nowhere else to write.
CoverageState& state() {
  static CoverageState s;
  return s;
}

}  // namespace

void coverage_reset() {
  auto& s = state();
  std::memset(s.edges.data(), 0, s.edges.size());
  s.cmps.clear();
}

size_t coverage_edges_hit() {
  auto& s = state();
  size_t n = 0;
  for (uint8_t e : s.edges) n += (e != 0);
  return n;
}

size_t coverage_total_edges() { return state().num_edges; }

size_t coverage_covered_edges() {
  auto& s = state();
  size_t n = 0;
  for (uint64_t h : s.global_hits) n += (h != 0);
  return n;
}

size_t coverage_commit() {
  auto& s = state();
  size_t new_edges = 0;
  for (size_t i = 0; i < s.edges.size(); ++i) {
    if (s.edges[i]) {
      if (s.global_hits[i] == 0) ++new_edges;
      s.global_hits[i] += 1;
    }
  }
  s.total_execs += 1;
  return new_edges;
}

double coverage_edge_rarity(size_t edge_index) {
  auto& s = state();
  if (edge_index >= s.global_hits.size() || s.total_execs == 0) return 0.0;
  const uint64_t hits = s.global_hits[edge_index];
  if (hits == 0) return 0.0;
  const double p = static_cast<double>(hits) / static_cast<double>(s.total_execs);
  return -std::log2(p);  // rarer edge => higher self-information
}

const std::vector<CmpOperand>& coverage_cmp_operands() { return state().cmps; }

}  // namespace nyx

// ---------------------------------------------------------------------------
// SanitizerCoverage callbacks (C linkage, called by the instrumented target).
// ---------------------------------------------------------------------------
extern "C" {

// Called once per instrumented module before main(). Assigns each guard a
// unique 1-based index and sizes the coverage maps accordingly.
void __sanitizer_cov_trace_pc_guard_init(uint32_t* start, uint32_t* stop) {
  auto& s = nyx::state();
  if (start == stop || *start) return;  // already initialised
  uint32_t index = static_cast<uint32_t>(s.num_edges);
  for (uint32_t* x = start; x < stop; ++x) {
    *x = ++index;  // 1-based; 0 means "no edge"
  }
  s.num_edges = index;
  s.edges.assign(s.num_edges + 1, 0);
  s.global_hits.assign(s.num_edges + 1, 0);
}

// Called at every instrumented edge.
void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
  const uint32_t idx = *guard;
  auto& s = nyx::state();
  if (idx == 0 || idx >= s.edges.size()) return;
  s.edges[idx] = 1;
}

// --- comparison callbacks -------------------------------------------------
static void record_cmp(uint64_t a, uint64_t b, uint8_t width, bool is_const) {
  nyx::state().cmps.push_back({a, b, width, is_const});
}

void __sanitizer_cov_trace_cmp1(uint8_t a, uint8_t b)  { record_cmp(a, b, 1, false); }
void __sanitizer_cov_trace_cmp2(uint16_t a, uint16_t b){ record_cmp(a, b, 2, false); }
void __sanitizer_cov_trace_cmp4(uint32_t a, uint32_t b){ record_cmp(a, b, 4, false); }
void __sanitizer_cov_trace_cmp8(uint64_t a, uint64_t b){ record_cmp(a, b, 8, false); }

void __sanitizer_cov_trace_const_cmp1(uint8_t a, uint8_t b)  { record_cmp(a, b, 1, true); }
void __sanitizer_cov_trace_const_cmp2(uint16_t a, uint16_t b){ record_cmp(a, b, 2, true); }
void __sanitizer_cov_trace_const_cmp4(uint32_t a, uint32_t b){ record_cmp(a, b, 4, true); }
void __sanitizer_cov_trace_const_cmp8(uint64_t a, uint64_t b){ record_cmp(a, b, 8, true); }

// switch statements: cases[0]=count, cases[1]=width-in-bits, cases[2..]=labels.
void __sanitizer_cov_trace_switch(uint64_t val, uint64_t* cases) {
  const uint64_t n = cases[0];
  const uint8_t width = static_cast<uint8_t>(cases[1] / 8);
  for (uint64_t i = 0; i < n; ++i) record_cmp(val, cases[2 + i], width, true);
}

}  // extern "C"
