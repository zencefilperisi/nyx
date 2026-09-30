#pragma once
// Structure-aware mutator: mutates a DER tree, not raw bytes.
//
// Because it operates on the TLV tree, every mutation is re-serialized into
// structurally coherent DER. This is the layer that gets past a parser's early
// length/tag checks so the fuzzer can reach deep code paths.
//
// PHASE 2 (see DESIGN.md). The interface is fixed here; the mutation operators
// are implemented incrementally.
#include <cstdint>
#include <random>

#include "nyx/der_tree.hpp"

namespace nyx {

// Structural mutation operators, applied to a randomly chosen subtree.
enum class MutationOp {
  kFlipContentBytes,    // corrupt bytes inside a primitive value
  kResizeContent,       // grow/shrink a primitive value
  kChangeTagNumber,     // swap the tag number (type confusion)
  kToggleConstructed,   // flip primitive<->constructed (structure confusion)
  kDuplicateChild,      // duplicate a child in a constructed node
  kDeleteChild,         // drop a child
  kInsertChild,         // splice in a child (from another tree / generated)
  kSwapChildren,        // reorder children
  kCorruptLength,       // emit a deliberately wrong length (raw-level, post-serialize)
  kDeepNest,            // wrap a node in extra SEQUENCE layers (depth attack)
  kCount,
};

// Configuration for a single mutation round.
struct MutatorConfig {
  int max_mutations_per_round = 4;   // stacked mutations
  int max_generated_depth = 6;       // bound on kInsertChild / kDeepNest
};

class Mutator {
 public:
  explicit Mutator(uint64_t seed) : rng_(seed) {}

  // Apply one or more mutation operators to `tree` in place.
  // Returns the operators actually applied (for the scheduler's feedback loop).
  std::vector<MutationOp> mutate(DerNode& tree, const MutatorConfig& cfg);

  // Apply a specific operator (used by the scheduler to target operators).
  bool apply(MutationOp op, DerNode& tree, const MutatorConfig& cfg);

 private:
  std::mt19937_64 rng_;
  // TODO(phase-2): subtree selection, per-op implementations, seed splicing.
};

}  // namespace nyx
