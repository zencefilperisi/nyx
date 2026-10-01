#pragma once
// Corpus: the set of inputs the fuzzer keeps and mutates.
//
// Phase 1 keeps it simple -- a growable list of inputs, each tagged with how
// many edges it was responsible for discovering. Seed selection is uniform for
// now; the entropy-guided scheduler (Phase 3) replaces the picking policy
// without changing this storage.
#include <cstdint>
#include <random>
#include <string>
#include <vector>

namespace nyx {

struct CorpusEntry {
  std::vector<uint8_t> data;
  size_t new_edges = 0;              // edges this input first discovered
  size_t times_chosen = 0;
  std::vector<uint32_t> edges;       // edge set this input covers (for rarity)
};

class Corpus {
 public:
  // Load every file in `dir` as a seed. Missing dir => empty corpus.
  size_t load_dir(const std::string& dir);

  // Add a seed directly (e.g. a synthetic starting input).
  void add(std::vector<uint8_t> data, size_t new_edges = 0);

  bool empty() const { return entries_.empty(); }
  size_t size() const { return entries_.size(); }
  const CorpusEntry& operator[](size_t i) const { return entries_[i]; }

  // Uniform pick (Phase 1). Returns index; caller may bump times_chosen.
  size_t pick(std::mt19937_64& rng);
  CorpusEntry& at(size_t i) { return entries_[i]; }

 private:
  std::vector<CorpusEntry> entries_;
};

}  // namespace nyx
