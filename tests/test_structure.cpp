// Phase-2 test: the structure-aware mutator.
//
//   1. Robustness: mutating a parsed tree thousands of times never breaks the
//      serializer -- every mutated tree still produces bytes.
//   2. Effectiveness: on a target whose bug is gated behind nested, length-
//      consistent DER, structure-aware fuzzing reaches it far more reliably
//      than byte-level fuzzing in the same budget.
#include <cstdint>
#include <cstdio>
#include <vector>

#include "nyx/coverage.hpp"
#include "nyx/der_parser.hpp"
#include "nyx/der_serializer.hpp"
#include "nyx/engine.hpp"
#include "nyx/mutator.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

namespace {
int g_failures = 0;
void check(bool cond, const char* what) {
  std::printf("  %s %s\n", cond ? "[ok]  " : "[FAIL]", what);
  if (!cond) ++g_failures;
}

// SEQUENCE { SEQUENCE { INTEGER 0x00 } } = 30 05 30 03 02 01 00
std::vector<uint8_t> nested_seed() { return {0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00}; }
}  // namespace

int main() {
  std::printf("== Nyx Phase-2: structure-aware mutator ==\n");

  // 1. Robustness -- mutate a parsed tree many times, serializer must survive.
  {
    nyx::ParseError err;
    auto tree = nyx::parse_der(nested_seed(), err);
    check(tree.has_value(), "seed parses to a DER tree");
    nyx::Mutator m(999);
    nyx::MutatorConfig cfg;
    size_t produced = 0;
    for (int i = 0; i < 5000; ++i) {
      nyx::DerNode t = *tree;             // fresh copy each round
      m.mutate(t, cfg);
      auto bytes = nyx::serialize_der(t); // must not crash
      produced += bytes.size();
    }
    check(produced > 0, "5000 tree mutations all serialize without crashing");
  }

  // 2a. Structure-aware run.
  auto run = [](bool structure_aware) {
    nyx::Corpus corpus;
    corpus.add(nested_seed());
    nyx::EngineOptions o;
    o.seed = 2024;
    o.max_iterations = 300'000;
    o.structure_aware = structure_aware;
    o.stop_on_first_crash = true;
    o.quiet = true;
    return nyx::fuzz(&LLVMFuzzerTestOneInput, corpus, o);
  };

  nyx::FuzzStats sa = run(true);
  std::printf("  structure-aware: iters=%llu edges=%zu crashes=%zu corpus=%zu\n",
              (unsigned long long)sa.iterations, sa.total_edges, sa.crashes,
              sa.corpus_size);

  nyx::FuzzStats bl = run(false);
  std::printf("  byte-level     : iters=%llu edges=%zu crashes=%zu corpus=%zu\n",
              (unsigned long long)bl.iterations, bl.total_edges, bl.crashes,
              bl.corpus_size);

  check(sa.crashes > 0, "structure-aware found the nested, structure-gated bug");
  check(sa.total_edges >= bl.total_edges,
        "structure-aware covers at least as many edges as byte-level");

  // Report the contrast honestly (byte-level finding it too is not a failure,
  // but structure-aware should be clearly better -- fewer iters or byte-level miss).
  std::printf("  [contrast] structure-aware %s the bug; byte-level %s it\n",
              sa.crashes ? "FOUND" : "missed",
              bl.crashes ? "also found" : "did NOT find");
  if (sa.crashes && bl.crashes) {
    std::printf("  [contrast] iters-to-crash: structure-aware=%llu vs byte-level=%llu\n",
                (unsigned long long)sa.iterations, (unsigned long long)bl.iterations);
  }

  std::printf("== %s ==\n", g_failures == 0 ? "ALL PASSED" : "FAILURES PRESENT");
  return g_failures == 0 ? 0 : 1;
}
