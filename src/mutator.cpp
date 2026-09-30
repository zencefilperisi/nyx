#include "nyx/mutator.hpp"

// PHASE 2 implementation. The DER core (parse/serialize) it builds on is
// already complete and tested; these operators walk the tree the parser
// produces. Implemented incrementally, each with a unit test proving it keeps
// the tree serialisable.

namespace nyx {

bool Mutator::apply(MutationOp op, DerNode& tree, const MutatorConfig& cfg) {
  (void)op;
  (void)tree;
  (void)cfg;
  // TODO(phase-2): implement each operator from MutationOp.
  return false;
}

std::vector<MutationOp> Mutator::mutate(DerNode& tree, const MutatorConfig& cfg) {
  (void)tree;
  (void)cfg;
  // TODO(phase-2): pick 1..max_mutations_per_round operators and apply them.
  return {};
}

}  // namespace nyx
