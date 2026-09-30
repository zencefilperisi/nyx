#pragma once
// Entropy-guided scheduler -- the research core of Nyx.
//
// Two coupled decisions, both driven by an information-theoretic signal rather
// than fixed heuristics:
//
//   1. Seed energy (power schedule): how much mutation budget each corpus entry
//      gets. Seeds that reach RARE coverage edges carry more information, so
//      they get more energy. Rarity is scored from the global edge-hit
//      histogram (a low-probability edge => high self-information -log2(p)).
//
//   2. Operator selection: which MutationOp to apply, modelled as a
//      multi-armed bandit whose reward is new coverage and whose
//      exploration/exploitation balance is governed by the entropy of the
//      operator-reward distribution.
//
// The claim that this beats fixed schedules is an empirical one, settled by the
// benchmark harness (see DESIGN.md, Phase 4) -- never asserted without numbers.
//
// PHASE 3.
#include <cstdint>
#include <vector>

#include "nyx/mutator.hpp"

namespace nyx {

// Per-seed record the scheduler reasons over.
struct SeedInfo {
  uint64_t id = 0;
  size_t times_chosen = 0;
  size_t new_edges_found = 0;
  double rarity_score = 0.0;   // sum of -log2(p) over the edges this seed hits
};

class Scheduler {
 public:
  // Pick the next seed to fuzz, weighted by rarity-driven energy.
  virtual uint64_t choose_seed(const std::vector<SeedInfo>& seeds) = 0;

  // Pick the next mutation operator (bandit arm).
  virtual MutationOp choose_operator() = 0;

  // Feed back the result of a mutation round so the schedule adapts.
  virtual void update(uint64_t seed_id, MutationOp op, size_t new_edges) = 0;

  virtual ~Scheduler() = default;
};

// Baselines for the ablation study in the benchmark:
//   - RoundRobinScheduler / UniformScheduler: no entropy guidance (control)
//   - EntropyScheduler: the proposed method
// TODO(phase-3): implement all three behind this interface.
std::unique_ptr<Scheduler> make_uniform_scheduler(uint64_t seed);
std::unique_ptr<Scheduler> make_entropy_scheduler(uint64_t seed);

}  // namespace nyx
