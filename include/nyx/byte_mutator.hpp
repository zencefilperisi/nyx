#pragma once
// Byte-level mutator (Phase 1).
//
// Deliberately "dumb" byte mutations -- bit flips, arithmetic, insert/delete,
// chunk duplication, splice. This is the baseline. Phase 2's structure-aware
// mutator (which works on the parsed DER tree) is what should beat it; keeping
// this around lets the benchmark measure exactly how much the structure
// awareness is worth.
#include <cstdint>
#include <random>
#include <vector>

namespace nyx {

class ByteMutator {
 public:
  explicit ByteMutator(uint64_t seed) : rng_(seed) {}

  // Return a mutated copy of `input`. `other` (optional) is a second corpus
  // input available for splicing; pass nullptr to disable splice.
  std::vector<uint8_t> mutate(const std::vector<uint8_t>& input,
                              const std::vector<uint8_t>* other = nullptr);

 private:
  std::mt19937_64 rng_;

  void bit_flip(std::vector<uint8_t>& v);
  void byte_set(std::vector<uint8_t>& v);
  void byte_arith(std::vector<uint8_t>& v);
  void insert_byte(std::vector<uint8_t>& v);
  void delete_byte(std::vector<uint8_t>& v);
  void duplicate_chunk(std::vector<uint8_t>& v);
  void splice(std::vector<uint8_t>& v, const std::vector<uint8_t>& other);
};

}  // namespace nyx
