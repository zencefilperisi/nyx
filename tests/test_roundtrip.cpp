// Round-trip and structural tests for the DER core.
//
// Core invariant: for valid canonical DER, parse -> serialize reproduces the
// input byte-for-byte. This is what lets the structure-aware mutator work on
// the tree and still emit valid DER.
#include <cstdio>
#include <cstdint>
#include <fstream>
#include <vector>

#include "nyx/der_parser.hpp"
#include "nyx/der_serializer.hpp"

namespace {

int g_failures = 0;

void check(bool cond, const char* what) {
  if (!cond) {
    std::printf("  [FAIL] %s\n", what);
    ++g_failures;
  } else {
    std::printf("  [ok]   %s\n", what);
  }
}

std::vector<uint8_t> read_file(const char* path) {
  std::ifstream f(path, std::ios::binary);
  return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                              std::istreambuf_iterator<char>());
}

// Count total nodes in the tree (for a quick structural sanity check).
size_t count_nodes(const nyx::DerNode& n) {
  size_t total = 1;
  for (const auto& c : n.children) total += count_nodes(c);
  return total;
}

}  // namespace

int main(int argc, char** argv) {
  std::printf("== Nyx DER core tests ==\n");

  // 1. Hand-built tiny structure: SEQUENCE { INTEGER 1, BOOLEAN true }.
  {
    nyx::DerNode seq;
    seq.tag = {nyx::TagClass::Universal, true, nyx::universal::kSequence};
    nyx::DerNode integer;
    integer.tag = {nyx::TagClass::Universal, false, nyx::universal::kInteger};
    integer.content = {0x01};
    nyx::DerNode boolean;
    boolean.tag = {nyx::TagClass::Universal, false, nyx::universal::kBoolean};
    boolean.content = {0xFF};
    seq.children = {integer, boolean};

    auto bytes = nyx::serialize_der(seq);
    // Expected: 30 06 02 01 01 01 01 FF
    const std::vector<uint8_t> expected = {0x30, 0x06, 0x02, 0x01, 0x01,
                                           0x01, 0x01, 0xFF};
    check(bytes == expected, "hand-built SEQUENCE serializes to expected bytes");

    nyx::ParseError err;
    auto parsed = nyx::parse_der(bytes, err);
    check(parsed.has_value(), "re-parse of hand-built bytes succeeds");
    if (parsed) {
      auto reser = nyx::serialize_der(*parsed);
      check(reser == bytes, "hand-built round-trip is identity");
      check(count_nodes(*parsed) == 3, "hand-built tree has 3 nodes");
    }
  }

  // 2. High-tag-number + long-form length round-trip.
  {
    nyx::DerNode n;
    n.tag = {nyx::TagClass::ContextSpecific, false, 12345};  // forces high-tag form
    n.content = std::vector<uint8_t>(300, 0xAB);             // forces long-form length
    auto bytes = nyx::serialize_der(n);
    nyx::ParseError err;
    auto parsed = nyx::parse_der(bytes, err);
    check(parsed.has_value(), "high-tag + long-length parses");
    if (parsed) {
      check(parsed->tag.number == 12345, "high tag number preserved");
      check(parsed->content.size() == 300, "long-form length preserved");
      check(nyx::serialize_der(*parsed) == bytes, "high-tag round-trip is identity");
    }
  }

  // 3. Real certificate round-trip (path passed as argv[1]).
  if (argc > 1) {
    auto der = read_file(argv[1]);
    std::printf("  loaded %s (%zu bytes)\n", argv[1], der.size());
    nyx::ParseError err;
    auto parsed = nyx::parse_der(der, err);
    if (!parsed) {
      std::printf("  [FAIL] real cert parse: %s @ offset %zu\n",
                  err.message.c_str(), err.offset);
      ++g_failures;
    } else {
      std::printf("  parsed real cert: %zu nodes\n", count_nodes(*parsed));
      auto reser = nyx::serialize_der(*parsed);
      check(reser == der, "REAL CERTIFICATE round-trip is byte-identical");
    }
  } else {
    std::printf("  (no cert path given; skipping real-cert test)\n");
  }

  std::printf("== %s ==\n", g_failures == 0 ? "ALL PASSED" : "FAILURES PRESENT");
  return g_failures == 0 ? 0 : 1;
}
