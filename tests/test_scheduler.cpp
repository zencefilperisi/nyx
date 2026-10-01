// Phase-3 test: the entropy-guided scheduler.
//
// Scheduler comparisons are inherently noisy, so the rigorous A/B-with-statistics
// belongs in the Phase-4 benchmark. Here we prove the scheduler MECHANICS
// deterministically -- that each mechanism does what it claims -- plus an
// end-to-end sanity check that the entropy scheduler drives a real campaign.
#include <cstdint>
#include <cstdio>
#include <vector>

#include "nyx/coverage.hpp"
#include "nyx/engine.hpp"
#include "nyx/scheduler.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

namespace {
int g_failures = 0;
void check(bool cond, const char* what) {
  std::printf("  %s %s\n", cond ? "[ok]  " : "[FAIL]", what);
  if (!cond) ++g_failures;
}
}  // namespace

int main() {
  std::printf("== Nyx Phase-3: entropy-guided scheduler ==\n");

  // --- Mechanism 1: rarity-weighted seed energy --------------------------
  // Five seeds; seed #3 covers much rarer edges (high self-information). The
  // entropy scheduler should pick it far more than its 1/5 uniform share; the
  // uniform scheduler should not.
  {
    std::vector<nyx::SeedInfo> seeds;
    for (uint64_t i = 0; i < 5; ++i) {
      nyx::SeedInfo s;
      s.id = i;
      s.rarity_score = (i == 3) ? 20.0 : 0.2;  // seed 3 is the rare one
      seeds.push_back(s);
    }
    auto ent = nyx::make_entropy_scheduler(1);
    auto uni = nyx::make_uniform_scheduler(1);
    const int N = 20000;
    int ent3 = 0, uni3 = 0;
    for (int k = 0; k < N; ++k) {
      if (ent->choose_seed(seeds) == 3) ++ent3;
      if (uni->choose_seed(seeds) == 3) ++uni3;
    }
    double ent_frac = double(ent3) / N, uni_frac = double(uni3) / N;
    std::printf("  seed #3 chosen: entropy=%.1f%%  uniform=%.1f%%\n",
                ent_frac * 100, uni_frac * 100);
    check(ent_frac > 0.80, "entropy scheduler concentrates energy on the rare seed");
    check(uni_frac > 0.12 && uni_frac < 0.28, "uniform scheduler stays ~1/5 per seed");
    check(ent_frac > uni_frac * 2, "entropy favours the rare seed far more than uniform");
  }

  // --- Mechanism 2: operator bandit converges ----------------------------
  // Only one operator ever pays off (reward>0). The UCB1 bandit should learn to
  // pull it most of the time; the uniform policy never concentrates.
  {
    const auto kRewarding = nyx::MutationOp::kResizeContent;
    auto ent = nyx::make_entropy_scheduler(2);
    // Warm-up: let the bandit learn which arm pays.
    for (int k = 0; k < 8000; ++k) {
      auto op = ent->choose_operator();
      ent->update(0, op, op == kRewarding ? 5 : 0);
    }
    // Measure concentration over the next 2000 choices.
    int hits = 0;
    const int M = 2000;
    for (int k = 0; k < M; ++k) {
      auto op = ent->choose_operator();
      ent->update(0, op, op == kRewarding ? 5 : 0);
      if (op == kRewarding) ++hits;
    }
    double frac = double(hits) / M;

    auto uni = nyx::make_uniform_scheduler(2);
    int uhits = 0;
    for (int k = 0; k < M; ++k)
      if (uni->choose_operator() == kRewarding) ++uhits;
    double ufrac = double(uhits) / M;

    std::printf("  rewarding op chosen: bandit=%.1f%%  uniform=%.1f%%\n",
                frac * 100, ufrac * 100);
    check(frac > 0.5, "UCB1 bandit concentrates on the rewarding operator");
    check(frac > ufrac * 3, "bandit far exceeds uniform on the rewarding operator");
  }

  // --- End-to-end sanity: entropy scheduler drives a real campaign --------
  {
    auto run = [](nyx::EngineOptions::SchedulerKind kind) {
      nyx::Corpus corpus;
      corpus.add({0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00});  // nested seed
      nyx::EngineOptions o;
      o.seed = 42;
      o.max_iterations = 300'000;
      o.structure_aware = true;
      o.scheduler = kind;
      o.stop_on_first_crash = true;
      o.quiet = true;
      return nyx::fuzz(&LLVMFuzzerTestOneInput, corpus, o);
    };
    auto ent = run(nyx::EngineOptions::SchedulerKind::kEntropy);
    auto uni = run(nyx::EngineOptions::SchedulerKind::kUniform);
    std::printf("  e2e (phase2 target): entropy crashes=%zu iters=%llu | uniform crashes=%zu iters=%llu\n",
                ent.crashes, (unsigned long long)ent.iterations,
                uni.crashes, (unsigned long long)uni.iterations);
    check(ent.crashes > 0, "entropy scheduler drives an end-to-end campaign to the bug");
  }

  std::printf("== %s ==\n", g_failures == 0 ? "ALL PASSED" : "FAILURES PRESENT");
  return g_failures == 0 ? 0 : 1;
}
