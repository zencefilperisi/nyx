#include "nyx/engine.hpp"

#include <csetjmp>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <filesystem>
#include <fstream>

#include "nyx/byte_mutator.hpp"
#include "nyx/coverage.hpp"
#include "nyx/der_parser.hpp"
#include "nyx/der_serializer.hpp"
#include "nyx/grammar_x509.hpp"
#include "nyx/mutator.hpp"
#include "nyx/scheduler.hpp"

namespace nyx {
namespace {

// --- in-process crash trapping --------------------------------------------
//
// A crash in the target (SIGSEGV/SIGABRT/...) would normally kill the whole
// fuzzer. We install handlers that siglongjmp back into the loop so a single
// process can record the crash and keep going.
//
// HONEST LIMITATION: recovering from a genuine memory-corruption SIGSEGV via
// longjmp is not fully safe -- process state may be inconsistent afterwards.
// It is fine for demonstrating the loop and for clean aborts (ASan/UBSan/abort);
// the robust upgrade is fork-per-exec isolation (a documented future step).
sigjmp_buf g_jmp;
volatile sig_atomic_t g_signal = 0;

void crash_handler(int sig) {
  g_signal = sig;
  siglongjmp(g_jmp, 1);
}

void install_handlers() {
  struct sigaction sa;
  std::memset(&sa, 0, sizeof(sa));
  sa.sa_handler = crash_handler;
  sigemptyset(&sa.sa_mask);
  for (int sig : {SIGSEGV, SIGABRT, SIGFPE, SIGBUS, SIGILL}) {
    sigaction(sig, &sa, nullptr);
  }
}

// Run one input; returns true if it crashed.
bool run_once(TargetFn target, const uint8_t* data, size_t size) {
  coverage_reset();
  g_signal = 0;
  if (sigsetjmp(g_jmp, 1) == 0) {
    target(data, size);
    return false;
  }
  return true;  // returned via siglongjmp from the handler
}

void save_crash(const std::string& dir, uint64_t id, const std::vector<uint8_t>& data) {
  if (dir.empty()) return;
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  char name[64];
  std::snprintf(name, sizeof(name), "/crash_%04llu.bin",
                static_cast<unsigned long long>(id));
  std::ofstream f(dir + name, std::ios::binary);
  f.write(reinterpret_cast<const char*>(data.data()),
          static_cast<std::streamsize>(data.size()));
}

double now_seconds() {
  using namespace std::chrono;
  return duration<double>(steady_clock::now().time_since_epoch()).count();
}

}  // namespace

FuzzStats fuzz(TargetFn target, Corpus& corpus, const EngineOptions& opts) {
  install_handlers();
  coverage_reset_global();  // each campaign starts with a clean coverage history
  ByteMutator mutator(opts.seed);
  Mutator tree_mutator(opts.seed ^ 0xA5A5A5A5A5A5A5A5ull);
  MutatorConfig mcfg;
  std::mt19937_64 rng(opts.seed ^ 0xD1B54A32D192ED03ull);
  std::mt19937_64 sem_rng(opts.seed ^ 0x517CC1B727220A95ull);  // X.509 semantic ops

  std::unique_ptr<Scheduler> scheduler =
      (opts.scheduler == EngineOptions::SchedulerKind::kEntropy)
          ? make_entropy_scheduler(opts.seed ^ 0x2545F4914F6CDD1Dull)
          : make_uniform_scheduler(opts.seed ^ 0x2545F4914F6CDD1Dull);

  // Structure-aware candidate generation: parse the seed to a DER tree, mutate
  // the tree, re-serialize. Falls back to byte mutation when the seed is not
  // valid DER (so the loop never stalls on unparseable inputs). `op_used`
  // receives the single tree operator the scheduler chose (or -1 when a
  // non-bandit path was taken: byte mutation or a semantic mutation).
  auto make_candidate = [&](const std::vector<uint8_t>& seed,
                            const std::vector<uint8_t>* other,
                            int& op_used) -> std::vector<uint8_t> {
    op_used = -1;
    if (opts.structure_aware) {
      ParseError err;
      auto tree = parse_der(seed, err);
      if (tree) {
        if (opts.x509_semantic && looks_like_x509(*tree) && (sem_rng() & 1)) {
          // Typed semantic mutation (not a single bandit operator).
          mutate_x509_semantic(*tree, sem_rng);
        } else if (opts.scheduler == EngineOptions::SchedulerKind::kEntropy) {
          // Entropy scheduler drives operator choice via the UCB1 bandit.
          MutationOp op = scheduler->choose_operator();
          tree_mutator.apply(op, *tree, mcfg);
          op_used = static_cast<int>(op);
        } else {
          // Control: the hand-weighted mutator (a strong baseline the bandit
          // must match or beat).
          tree_mutator.mutate(*tree, mcfg);
        }
        auto out = serialize_der(*tree);
        if (out.empty()) out.push_back(0);
        return out;
      }
      // fall through to byte mutation on parse failure
    }
    return mutator.mutate(seed, other);
  };

  // Build the scheduler's view of the corpus: each seed's rarity is the summed
  // self-information (-log2 p) of the edges it covers, under the current histogram.
  auto build_seed_infos = [&]() {
    std::vector<SeedInfo> infos;
    infos.reserve(corpus.size());
    for (size_t i = 0; i < corpus.size(); ++i) {
      double rarity = 0.0;
      for (uint32_t e : corpus[i].edges) rarity += coverage_edge_rarity(e);
      infos.push_back({static_cast<uint64_t>(i), corpus[i].times_chosen,
                       corpus[i].new_edges, rarity});
    }
    return infos;
  };

  // Prime cumulative coverage with the existing corpus, recording each seed's
  // edge set so the scheduler can score rarity from the start.
  for (size_t i = 0; i < corpus.size(); ++i) {
    run_once(target, corpus[i].data.data(), corpus[i].data.size());
    coverage_commit();
    corpus.at(i).edges = coverage_current_edges();
  }
  if (corpus.empty()) corpus.add({0x00});  // ensure at least one seed

  const double start = now_seconds();
  FuzzStats stats;

  auto out_of_budget = [&](uint64_t iter) {
    if (opts.max_iterations && iter >= opts.max_iterations) return true;
    if (opts.max_seconds > 0.0 && (now_seconds() - start) >= opts.max_seconds)
      return true;
    return false;
  };

  uint64_t iter = 0;
  for (; !out_of_budget(iter); ++iter) {
    // Seed selection: the scheduler weights by rarity (entropy) or uniformly.
    auto infos = build_seed_infos();
    size_t idx = static_cast<size_t>(scheduler->choose_seed(infos));
    if (idx >= corpus.size()) idx = 0;
    corpus.at(idx).times_chosen++;

    const std::vector<uint8_t>* other = nullptr;
    if (corpus.size() > 1) {
      size_t j = corpus.pick(rng);
      other = &corpus[j].data;
    }
    int op_used = -1;
    std::vector<uint8_t> candidate = make_candidate(corpus[idx].data, other, op_used);

    bool crashed = run_once(target, candidate.data(), candidate.size());
    if (crashed) {
      stats.crashes++;
      if (stats.first_crash.empty()) stats.first_crash = candidate;
      save_crash(opts.crash_dir, stats.crashes, candidate);
      if (!opts.quiet) {
        std::printf("[nyx] CRASH (signal %d) at iter %llu, input %zu bytes\n",
                    static_cast<int>(g_signal),
                    static_cast<unsigned long long>(iter), candidate.size());
      }
      if (opts.stop_on_first_crash) {
        ++iter;
        break;
      }
      continue;
    }

    size_t new_edges = coverage_commit();
    // Feed the operator bandit its reward (new edges discovered this round).
    if (op_used >= 0) scheduler->update(idx, static_cast<MutationOp>(op_used), new_edges);
    if (new_edges > 0 && opts.coverage_guided) {
      auto edges = coverage_current_edges();
      corpus.add(candidate, new_edges);
      corpus.at(corpus.size() - 1).edges = std::move(edges);  // for rarity scoring
    }

    if (opts.coverage_sample_interval &&
        (iter % opts.coverage_sample_interval == 0)) {
      stats.coverage_timeline.emplace_back(iter, coverage_covered_edges());
    }
  }

  stats.iterations = iter;
  stats.corpus_size = corpus.size();
  stats.total_edges = coverage_covered_edges();  // cumulative distinct edges hit
  stats.elapsed_seconds = now_seconds() - start;
  return stats;
}

}  // namespace nyx
