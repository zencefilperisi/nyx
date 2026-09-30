#include "nyx/corpus.hpp"

#include <filesystem>
#include <fstream>

namespace nyx {

namespace fs = std::filesystem;

size_t Corpus::load_dir(const std::string& dir) {
  std::error_code ec;
  if (!fs::is_directory(dir, ec)) return 0;
  size_t loaded = 0;
  for (const auto& e : fs::directory_iterator(dir, ec)) {
    if (!e.is_regular_file()) continue;
    std::ifstream f(e.path(), std::ios::binary);
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),
                              std::istreambuf_iterator<char>());
    if (!data.empty()) {
      add(std::move(data));
      ++loaded;
    }
  }
  return loaded;
}

void Corpus::add(std::vector<uint8_t> data, size_t new_edges) {
  entries_.push_back({std::move(data), new_edges, 0});
}

size_t Corpus::pick(std::mt19937_64& rng) {
  std::uniform_int_distribution<size_t> dist(0, entries_.size() - 1);
  return dist(rng);
}

}  // namespace nyx
