#pragma once
// DER serializer: DerNode tree -> raw bytes.
//
// Emits canonical DER (minimal-length encoding, definite length). For an input
// that was valid DER, parse() followed by serialize() reproduces the original
// bytes exactly -- this round-trip identity is a core test invariant and the
// guarantee the structure-aware mutator relies on.
#include <cstdint>
#include <vector>

#include "nyx/der_tree.hpp"

namespace nyx {

// Append the DER encoding of `node` to `out`.
void serialize_der(const DerNode& node, std::vector<uint8_t>& out);

// Return the DER encoding of `node`.
std::vector<uint8_t> serialize_der(const DerNode& node);

}  // namespace nyx
