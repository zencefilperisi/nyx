#pragma once
// DER parser: raw bytes -> DerNode tree.
//
// Definite-length DER only (indefinite-length BER is rejected). The parser is
// deliberately strict about structure but tolerant enough to ingest real-world
// certificates as seeds. Errors are reported with an offset so malformed seeds
// can be diagnosed rather than silently dropped.
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "nyx/der_tree.hpp"

namespace nyx {

struct ParseError {
  std::string message;
  size_t offset = 0;
};

// Parse one top-level TLV subtree starting at data[0]. `consumed` receives the
// number of bytes read. Returns std::nullopt on error (see `err`).
std::optional<DerNode> parse_der(const uint8_t* data, size_t len,
                                 size_t& consumed, ParseError& err);

// Convenience overload: parse and require the whole buffer to be consumed.
std::optional<DerNode> parse_der(const std::vector<uint8_t>& data, ParseError& err);

// Maximum nesting depth accepted, to bound recursion on hostile inputs.
inline constexpr int kMaxDepth = 100;

}  // namespace nyx
