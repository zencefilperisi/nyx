// Phase-1 test: prove the coverage-guided fuzzing loop works end to end.
//
// Against the instrumented demo target we assert:
//   1. coverage-guided search discovers new edges and grows the corpus,
//   2. the loop finds the planted bug within a bounded budget,
//   3. (contrast) a blind search with NO coverage feedback is far less likely
//      to reach the bug in the same budget -- showing guidance actually helps.
#include <cstdint>
#include <cstdio>
#include <vector>

#include "nyx/coverage.hpp"
#include "nyx/engine.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

namespace {
int g_failures = 0;
void check(bool cond, const char* what) {
  std::printf("  %s %s\n", cond ? "[ok]  " : "[FAIL]", what);
  if (!cond) ++g_failures;
}
}  // namespace

int main() {
  std::printf("== Nyx Phase-1: coverage-guided fuzzing loop ==\n");

  // Seed with a partial prefix so the test is fast and deterministic; coverage
  // feedback must still discover the remaining bytes and the bug.
  nyx::Corpus corpus;
  corpus.add({0x30, 0x03});  // correct first two bytes only

  nyx::EngineOptions opts;
  opts.seed = 12345;
  opts.max_iterations = 2'000'000;
  opts.stop_on_first_crash = true;
  opts.quiet = true;

  size_t seed_corpus = corpus.size();
  nyx::FuzzStats st = nyx::fuzz(&LLVMFuzzerTestOneInput, corpus, opts);

  std::printf("  iterations=%llu  corpus=%zu->%zu  edges=%zu  crashes=%zu  (%.2fs)\n",
              (unsigned long long)st.iterations, seed_corpus, st.corpus_size,
              st.total_edges, st.crashes, st.elapsed_seconds);

  check(st.total_edges > 0, "coverage was recorded");
  check(st.corpus_size > seed_corpus,
        "coverage guidance grew the corpus (new paths discovered)");
  check(st.crashes > 0, "the planted bug was found");
  if (st.crashes > 0) {
    // The crashing input must satisfy the full prefix + trigger byte.
    const auto& c = st.first_crash;
    bool valid = c.size() >= 5 && c[0] == 0x30 && c[1] == 0x03 &&
                 c[2] == 0x02 && c[3] == 0x01 && c[4] == 0x7F;
    check(valid, "crashing input matches the exact bug trigger");
  }

  // Contrast: blind fuzzing (no coverage feedback) from the same seed and a
  // COMPARABLE iteration budget should be far less effective at reaching the bug.
  {
    nyx::Corpus blind_corpus;
    blind_corpus.add({0x30, 0x03});
    nyx::EngineOptions blind = opts;
    blind.coverage_guided = false;
    blind.max_iterations = st.iterations;  // same budget the guided run used
    blind.stop_on_first_crash = true;
    nyx::FuzzStats bst = nyx::fuzz(&LLVMFuzzerTestOneInput, blind_corpus, blind);
    std::printf("  [contrast] blind fuzzing same budget (%llu iters): crashes=%zu, corpus=%zu\n",
                (unsigned long long)blind.max_iterations, bst.crashes, bst.corpus_size);
    check(bst.corpus_size == 1,
          "blind mode keeps corpus at the seed (no coverage feedback)");
    // Not a hard failure if blind gets lucky, but report the comparison.
    std::printf("  [contrast] guided found the bug in %llu iters; "
                "blind %s in the same budget\n",
                (unsigned long long)st.iterations,
                bst.crashes > 0 ? "also found it" : "did NOT find it");
  }

  std::printf("== %s ==\n", g_failures == 0 ? "ALL PASSED" : "FAILURES PRESENT");
  return g_failures == 0 ? 0 : 1;
}
