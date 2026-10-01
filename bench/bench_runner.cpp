// Benchmark runner: fuzz one linked target in several modes over several trials
// and emit CSVs for statistical analysis + plotting (see bench/run_benchmark.py).
//
// Modes (the ablation axes):
//   byte     -- byte-level mutation, no structure awareness
//   uniform  -- structure-aware DER mutation, uniform scheduler (control)
//   entropy  -- structure-aware DER mutation, entropy-guided scheduler
//
// Linked against the target's LLVMFuzzerTestOneInput at build time, so the same
// instrumented target is driven by every mode -- a fair comparison.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "nyx/engine.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

namespace {

std::vector<uint8_t> read_file(const std::string& p) {
  std::ifstream f(p, std::ios::binary);
  return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                              std::istreambuf_iterator<char>());
}

struct Mode {
  const char* name;
  bool structure_aware;
  nyx::EngineOptions::SchedulerKind sched;
};

}  // namespace

int main(int argc, char** argv) {
  uint64_t iters = 50000;
  int trials = 10;
  std::string out_dir = "bench_results";
  std::string seed_file;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--iters" && i + 1 < argc) iters = std::strtoull(argv[++i], nullptr, 10);
    else if (a == "--trials" && i + 1 < argc) trials = std::atoi(argv[++i]);
    else if (a == "--out" && i + 1 < argc) out_dir = argv[++i];
    else if (a == "--seed-file" && i + 1 < argc) seed_file = argv[++i];
  }

  std::vector<uint8_t> seed =
      seed_file.empty() ? std::vector<uint8_t>{0x30, 0x03, 0x02, 0x01, 0x01}
                        : read_file(seed_file);

  const Mode modes[] = {
      {"byte", false, nyx::EngineOptions::SchedulerKind::kUniform},
      {"uniform", true, nyx::EngineOptions::SchedulerKind::kUniform},
      {"entropy", true, nyx::EngineOptions::SchedulerKind::kEntropy},
  };

  std::string sum_path = out_dir + "/summary.csv";
  std::string tl_path = out_dir + "/timeline.csv";
  std::ofstream sum(sum_path), tl(tl_path);
  sum << "mode,trial,final_edges,crashes,iters\n";
  tl << "mode,trial,iter,edges\n";

  for (const auto& m : modes) {
    for (int t = 0; t < trials; ++t) {
      nyx::Corpus corpus;
      corpus.add(seed);
      nyx::EngineOptions o;
      o.seed = 0xBEEF0000ull + static_cast<uint64_t>(t);  // distinct per trial
      o.max_iterations = iters;
      o.structure_aware = m.structure_aware;
      o.scheduler = m.sched;
      o.quiet = true;
      o.coverage_sample_interval = iters / 50 ? iters / 50 : 1;  // ~50 samples
      nyx::FuzzStats s = nyx::fuzz(&LLVMFuzzerTestOneInput, corpus, o);
      sum << m.name << ',' << t << ',' << s.total_edges << ',' << s.crashes
          << ',' << s.iterations << '\n';
      for (auto& [it, ed] : s.coverage_timeline)
        tl << m.name << ',' << t << ',' << it << ',' << ed << '\n';
      std::fprintf(stderr, "[bench] %-8s trial %2d/%d -> %zu edges\n", m.name,
                   t + 1, trials, s.total_edges);
    }
  }
  std::fprintf(stderr, "[bench] wrote %s and %s\n", sum_path.c_str(), tl_path.c_str());
  return 0;
}
