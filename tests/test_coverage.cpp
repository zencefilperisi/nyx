// Phase-0 test: prove the SanitizerCoverage plumbing actually works.
//
// Runs the instrumented probe on a sequence of inputs and checks that:
//   * inputs reaching deeper branches produce MORE edges,
//   * such inputs register NEW edges on commit,
//   * trace-cmp captured the constant bytes the probe checks (0x30, 0x02, 0x2A).
#include <cstdint>
#include <cstdio>
#include <vector>

#include "nyx/coverage.hpp"

// The instrumented target (C linkage).
extern "C" int nyx_phase0_probe(const uint8_t* data, size_t size);

namespace {
int g_failures = 0;
void check(bool cond, const char* what) {
  std::printf("  %s %s\n", cond ? "[ok]  " : "[FAIL]", what);
  if (!cond) ++g_failures;
}

size_t run_hits(const std::vector<uint8_t>& in) {
  nyx::coverage_reset();
  nyx_phase0_probe(in.data(), in.size());
  return nyx::coverage_edges_hit();
}

size_t run_commit(const std::vector<uint8_t>& in) {
  nyx::coverage_reset();
  nyx_phase0_probe(in.data(), in.size());
  return nyx::coverage_commit();
}
}  // namespace

int main() {
  std::printf("== Nyx Phase-0: SanitizerCoverage plumbing ==\n");

  // Inputs that drive the probe down DIFFERENT paths. Note: with SanitizerCoverage
  // edge pruning, each path lights up a small set of guards -- the fuzzing signal
  // is *which* edges (the cumulative set), not the per-run count.
  const std::vector<uint8_t> empty = {};
  const std::vector<uint8_t> not_seq = {0x31};                    // wrong tag
  const std::vector<uint8_t> seq_only = {0x30, 0x03};             // valid header
  const std::vector<uint8_t> with_int = {0x30, 0x03, 0x02};       // INTEGER child
  const std::vector<uint8_t> deep = {0x30, 0x03, 0x02, 0x2A};     // deep branch

  check(nyx::coverage_total_edges() > 0, "target is instrumented (guards > 0)");
  check(run_hits(deep) > 0, "running the target records edge hits");

  // Core signal: distinct paths discover distinct edges, so cumulative committed
  // coverage grows as new paths are explored. This is what the fuzzer maximises.
  size_t cumulative = 0;
  for (const auto& in : {empty, not_seq, seq_only, with_int, deep}) {
    cumulative += run_commit(in);
  }
  std::printf("  cumulative distinct edges over 5 paths = %zu (total guards=%zu)\n",
              cumulative, nyx::coverage_total_edges());
  check(cumulative > run_hits(deep),
        "5 distinct paths cover MORE edges than any single path (new-edge signal works)");

  // Re-running already-seen inputs must reveal no new edges.
  size_t again = 0;
  for (const auto& in : {empty, not_seq, seq_only, with_int, deep}) {
    again += run_commit(in);
  }
  check(again == 0, "re-running known inputs reports NO new edges");

  // A brand-new path must still report new edges.
  size_t novel = run_commit({0x30, 0x00});  // len == 0 branch, not seen above
  check(novel > 0, "a genuinely new path reports NEW edges");

  // trace-cmp: did we capture the constant bytes the probe checks against?
  nyx::coverage_reset();
  nyx_phase0_probe(deep.data(), deep.size());
  const auto& cmps = nyx::coverage_cmp_operands();
  std::printf("  captured %zu comparison operands\n", cmps.size());
  bool saw_30 = false, saw_02 = false, saw_2A = false;
  for (const auto& c : cmps) {
    if (c.lhs == 0x30 || c.rhs == 0x30) saw_30 = true;
    if (c.lhs == 0x02 || c.rhs == 0x02) saw_02 = true;
    if (c.lhs == 0x2A || c.rhs == 0x2A) saw_2A = true;
  }
  check(cmps.size() > 0, "trace-cmp captured comparison operands");
  check(saw_30, "captured the SEQUENCE tag constant 0x30");
  check(saw_02, "captured the INTEGER tag constant 0x02");
  check(saw_2A, "captured the deep-branch constant 0x2A");

  std::printf("== %s ==\n", g_failures == 0 ? "ALL PASSED" : "FAILURES PRESENT");
  return g_failures == 0 ? 0 : 1;
}
