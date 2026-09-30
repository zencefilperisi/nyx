#include "nyx/byte_mutator.hpp"

#include <algorithm>

namespace nyx {

namespace {
template <typename RNG>
size_t rnd(RNG& rng, size_t n) {  // [0, n)
  return std::uniform_int_distribution<size_t>(0, n - 1)(rng);
}
}  // namespace

void ByteMutator::bit_flip(std::vector<uint8_t>& v) {
  if (v.empty()) return;
  size_t i = rnd(rng_, v.size());
  v[i] ^= static_cast<uint8_t>(1u << rnd(rng_, 8));
}

void ByteMutator::byte_set(std::vector<uint8_t>& v) {
  if (v.empty()) return;
  v[rnd(rng_, v.size())] = static_cast<uint8_t>(rnd(rng_, 256));
}

void ByteMutator::byte_arith(std::vector<uint8_t>& v) {
  if (v.empty()) return;
  size_t i = rnd(rng_, v.size());
  int delta = static_cast<int>(rnd(rng_, 71)) - 35;  // [-35, 35]
  v[i] = static_cast<uint8_t>(v[i] + delta);
}

void ByteMutator::insert_byte(std::vector<uint8_t>& v) {
  size_t pos = v.empty() ? 0 : rnd(rng_, v.size() + 1);
  v.insert(v.begin() + pos, static_cast<uint8_t>(rnd(rng_, 256)));
}

void ByteMutator::delete_byte(std::vector<uint8_t>& v) {
  if (v.empty()) return;
  v.erase(v.begin() + rnd(rng_, v.size()));
}

void ByteMutator::duplicate_chunk(std::vector<uint8_t>& v) {
  if (v.empty()) return;
  size_t len = 1 + rnd(rng_, std::min<size_t>(v.size(), 16));
  size_t src = rnd(rng_, v.size() - len + 1);
  size_t dst = rnd(rng_, v.size() + 1);
  std::vector<uint8_t> chunk(v.begin() + src, v.begin() + src + len);
  v.insert(v.begin() + dst, chunk.begin(), chunk.end());
}

void ByteMutator::splice(std::vector<uint8_t>& v, const std::vector<uint8_t>& other) {
  if (other.empty()) return;
  size_t cut_a = v.empty() ? 0 : rnd(rng_, v.size() + 1);
  size_t cut_b = rnd(rng_, other.size());
  v.resize(cut_a);
  v.insert(v.end(), other.begin() + cut_b, other.end());
}

std::vector<uint8_t> ByteMutator::mutate(const std::vector<uint8_t>& input,
                                         const std::vector<uint8_t>* other) {
  std::vector<uint8_t> v = input;
  // Stack a few operators for a stronger mutation per round.
  int rounds = 1 + static_cast<int>(rnd(rng_, 4));
  for (int r = 0; r < rounds; ++r) {
    int op = static_cast<int>(rnd(rng_, (other && !other->empty()) ? 7 : 6));
    switch (op) {
      case 0: bit_flip(v); break;
      case 1: byte_set(v); break;
      case 2: byte_arith(v); break;
      case 3: insert_byte(v); break;
      case 4: delete_byte(v); break;
      case 5: duplicate_chunk(v); break;
      case 6: splice(v, *other); break;
    }
  }
  if (v.empty()) v.push_back(0);  // never hand the target a zero-length buffer
  return v;
}

}  // namespace nyx
