// Phase-2b test: the X.509 semantic grammar layer.
//
//   1. The skeleton builder produces a valid certificate: it serializes, parses
//      back, round-trips, and is recognised as X.509.
//   2. Effectiveness: against a target whose bug is gated behind a *semantically
//      valid boundary date*, semantic mutation reaches it, while generic
//      structure-aware mutation (which corrupts dates blindly) does not in the
//      same budget.
#include <cstdint>
#include <cstdio>
#include <vector>

#include "nyx/coverage.hpp"
#include "nyx/der_parser.hpp"
#include "nyx/der_serializer.hpp"
#include "nyx/engine.hpp"
#include "nyx/grammar_x509.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

namespace {
int g_failures = 0;
void check(bool cond, const char* what) {
  std::printf("  %s %s\n", cond ? "[ok]  " : "[FAIL]", what);
  if (!cond) ++g_failures;
}
}  // namespace

int main() {
  std::printf("== Nyx Phase-2b: X.509 semantic grammar ==\n");

  // 1. Skeleton validity.
  std::mt19937_64 rng(1);
  nyx::DerNode skel = nyx::make_x509_skeleton(rng);
  auto der = nyx::serialize_der(skel);
  nyx::ParseError err;
  auto reparsed = nyx::parse_der(der, err);
  check(reparsed.has_value(), "skeleton serializes and parses back");
  if (reparsed) {
    check(nyx::serialize_der(*reparsed) == der, "skeleton round-trips byte-for-byte");
    check(nyx::looks_like_x509(*reparsed), "skeleton is recognised as X.509");
  }

  // 2. Semantic vs generic structure-aware on the date-gated target.
  auto run = [&](bool semantic) {
    nyx::Corpus corpus;
    corpus.add(der);  // seed is the valid certificate skeleton
    nyx::EngineOptions o;
    o.seed = 7;
    o.max_iterations = 400'000;
    o.structure_aware = true;
    o.x509_semantic = semantic;
    o.stop_on_first_crash = true;
    o.quiet = true;
    return nyx::fuzz(&LLVMFuzzerTestOneInput, corpus, o);
  };

  nyx::FuzzStats sem = run(true);
  std::printf("  semantic        : iters=%llu edges=%zu crashes=%zu\n",
              (unsigned long long)sem.iterations, sem.total_edges, sem.crashes);

  nyx::FuzzStats gen = run(false);
  std::printf("  generic struct  : iters=%llu edges=%zu crashes=%zu\n",
              (unsigned long long)gen.iterations, gen.total_edges, gen.crashes);

  // The honest, meaningful comparison: semantic reaches the semantically-gated
  // bug; generic structure-aware does not in the same budget. (Total coverage is
  // NOT compared here -- semantic stops early precisely because it succeeds, so
  // comparing accumulated edges would be apples-to-oranges.)
  check(sem.crashes > 0, "semantic mutation found the boundary-date bug");
  check(gen.crashes == 0, "generic structure-aware did NOT find it in the same budget");
  std::printf("  [contrast] semantic found it in %llu iters; generic missed it in %llu\n",
              (unsigned long long)sem.iterations, (unsigned long long)gen.iterations);

  std::printf("== %s ==\n", g_failures == 0 ? "ALL PASSED" : "FAILURES PRESENT");
  return g_failures == 0 ? 0 : 1;
}
