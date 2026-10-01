#include "nyx/scheduler.hpp"

#include <cmath>
#include <limits>
#include <numeric>
#include <random>

namespace nyx {
namespace {

constexpr size_t kNumOps = static_cast<size_t>(MutationOp::kCount);

// ---------------------------------------------------------------------------
// Uniform scheduler -- the control. No guidance: seeds and operators are picked
// uniformly at random, and feedback is ignored. This is the ablation baseline
// the entropy scheduler is measured against.
// ---------------------------------------------------------------------------
class UniformScheduler final : public Scheduler {
 public:
  explicit UniformScheduler(uint64_t seed) : rng_(seed) {}

  uint64_t choose_seed(const std::vector<SeedInfo>& seeds) override {
    if (seeds.empty()) return 0;
    return seeds[std::uniform_int_distribution<size_t>(0, seeds.size() - 1)(rng_)].id;
  }

  MutationOp choose_operator() override {
    return static_cast<MutationOp>(
        std::uniform_int_distribution<size_t>(0, kNumOps - 1)(rng_));
  }

  void update(uint64_t, MutationOp, size_t) override {}  // ignores feedback

 private:
  std::mt19937_64 rng_;
};

// ---------------------------------------------------------------------------
// Entropy scheduler -- the proposed method.
//
//  * Seed energy: a seed is chosen with probability proportional to its rarity
//    score, which the engine computes as the sum of self-information -log2(p)
//    over the edges it covers (rarer edges => more information => more energy).
//
//  * Operator selection: a UCB1 multi-armed bandit over the mutation operators,
//    with reward = new edges discovered. UCB1 balances exploiting the operator
//    that has paid off against exploring under-tried ones; the exploration term
//    is large exactly when an operator's payoff is still uncertain.
// ---------------------------------------------------------------------------
class EntropyScheduler final : public Scheduler {
 public:
  explicit EntropyScheduler(uint64_t seed)
      : rng_(seed), pulls_(kNumOps, 0), reward_(kNumOps, 0.0) {}

  uint64_t choose_seed(const std::vector<SeedInfo>& seeds) override {
    if (seeds.empty()) return 0;
    double total = 0.0;
    for (const auto& s : seeds) total += weight(s);
    if (total <= 0.0) {  // no information yet -> uniform fallback
      return seeds[std::uniform_int_distribution<size_t>(0, seeds.size() - 1)(rng_)].id;
    }
    double r = std::uniform_real_distribution<double>(0.0, total)(rng_);
    for (const auto& s : seeds) {
      r -= weight(s);
      if (r <= 0.0) return s.id;
    }
    return seeds.back().id;
  }

  MutationOp choose_operator() override {
    // Pull any never-tried arm first (UCB1 initialisation).
    for (size_t i = 0; i < kNumOps; ++i)
      if (pulls_[i] == 0) return static_cast<MutationOp>(i);

    double total = 0.0;
    for (size_t p : pulls_) total += static_cast<double>(p);
    double best = -std::numeric_limits<double>::infinity();
    size_t best_op = 0;
    for (size_t i = 0; i < kNumOps; ++i) {
      double mean = reward_[i] / static_cast<double>(pulls_[i]);
      double bonus = kExploration * std::sqrt(std::log(total) / pulls_[i]);
      double ucb = mean + bonus;
      if (ucb > best) {
        best = ucb;
        best_op = i;
      }
    }
    return static_cast<MutationOp>(best_op);
  }

  void update(uint64_t, MutationOp op, size_t new_edges) override {
    size_t i = static_cast<size_t>(op);
    if (i >= kNumOps) return;
    pulls_[i] += 1;
    reward_[i] += static_cast<double>(new_edges);
  }

 private:
  // A seed's weight: rarity plus a small floor so every seed keeps some chance.
  static double weight(const SeedInfo& s) { return s.rarity_score + 0.1; }

  static constexpr double kExploration = 1.4;  // UCB1 exploration constant (~sqrt(2))
  std::mt19937_64 rng_;
  std::vector<uint64_t> pulls_;
  std::vector<double> reward_;
};

}  // namespace

std::unique_ptr<Scheduler> make_uniform_scheduler(uint64_t seed) {
  return std::make_unique<UniformScheduler>(seed);
}

std::unique_ptr<Scheduler> make_entropy_scheduler(uint64_t seed) {
  return std::make_unique<EntropyScheduler>(seed);
}

}  // namespace nyx
