#pragma once
// -----------------------------------------------------------------------------
// DER TLV tree -- the structure-aware intermediate representation.
//
// Every ASN.1/DER value is a Tag-Length-Value triple. Primitive values carry raw
// content bytes; constructed values carry an ordered list of child TLVs. Nyx's
// structure-aware mutator operates on this tree (not on raw bytes), so every
// mutation it produces is still structurally well-formed enough to reach deep
// into a parser instead of being rejected at the first length/tag check.
// -----------------------------------------------------------------------------
#include <cstdint>
#include <vector>

namespace nyx {

// ASN.1 tag class (top two bits of the identifier octet).
enum class TagClass : uint8_t {
  Universal = 0,
  Application = 1,
  ContextSpecific = 2,
  Private = 3,
};

// A decoded ASN.1 tag (identifier).
struct Tag {
  TagClass cls = TagClass::Universal;
  bool constructed = false;   // bit 6 of the identifier octet
  uint32_t number = 0;        // tag number (supports high-tag-number form)

  bool operator==(const Tag&) const = default;
};

// A node in the DER tree. Primitive when !tag.constructed (uses `content`);
// constructed otherwise (uses `children`).
struct DerNode {
  Tag tag;
  std::vector<uint8_t> content;    // valid for primitive nodes
  std::vector<DerNode> children;   // valid for constructed nodes

  bool is_constructed() const { return tag.constructed; }
};

// Common UNIVERSAL tag numbers, for readability in the X.509 grammar layer.
namespace universal {
constexpr uint32_t kBoolean = 0x01;
constexpr uint32_t kInteger = 0x02;
constexpr uint32_t kBitString = 0x03;
constexpr uint32_t kOctetString = 0x04;
constexpr uint32_t kNull = 0x05;
constexpr uint32_t kObjectIdentifier = 0x06;
constexpr uint32_t kUtf8String = 0x0C;
constexpr uint32_t kSequence = 0x10;   // always constructed
constexpr uint32_t kSet = 0x11;        // always constructed
constexpr uint32_t kPrintableString = 0x13;
constexpr uint32_t kUtcTime = 0x17;
constexpr uint32_t kGeneralizedTime = 0x18;
}  // namespace universal

}  // namespace nyx
