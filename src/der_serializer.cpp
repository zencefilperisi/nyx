#include "nyx/der_serializer.hpp"

namespace nyx {
namespace {

void encode_tag(const Tag& tag, std::vector<uint8_t>& out) {
  uint8_t first = static_cast<uint8_t>((static_cast<uint8_t>(tag.cls) << 6));
  if (tag.constructed) first |= 0x20;

  if (tag.number < 0x1F) {
    first |= static_cast<uint8_t>(tag.number & 0x1F);
    out.push_back(first);
    return;
  }
  // High-tag-number form.
  first |= 0x1F;
  out.push_back(first);
  uint8_t buf[5];
  int n = 0;
  uint32_t v = tag.number;
  do {
    buf[n++] = static_cast<uint8_t>(v & 0x7F);
    v >>= 7;
  } while (v > 0);
  for (int i = n - 1; i >= 0; --i) {
    uint8_t b = buf[i];
    if (i != 0) b |= 0x80;  // continuation flag on all but the last octet
    out.push_back(b);
  }
}

void encode_length(size_t length, std::vector<uint8_t>& out) {
  if (length < 0x80) {  // short form
    out.push_back(static_cast<uint8_t>(length));
    return;
  }
  // Long form, minimal number of octets (canonical DER).
  uint8_t buf[sizeof(size_t)];
  int n = 0;
  size_t v = length;
  while (v > 0) {
    buf[n++] = static_cast<uint8_t>(v & 0xFF);
    v >>= 8;
  }
  out.push_back(static_cast<uint8_t>(0x80 | n));
  for (int i = n - 1; i >= 0; --i) out.push_back(buf[i]);
}

}  // namespace

void serialize_der(const DerNode& node, std::vector<uint8_t>& out) {
  encode_tag(node.tag, out);
  if (node.tag.constructed) {
    std::vector<uint8_t> body;
    for (const auto& child : node.children) serialize_der(child, body);
    encode_length(body.size(), out);
    out.insert(out.end(), body.begin(), body.end());
  } else {
    encode_length(node.content.size(), out);
    out.insert(out.end(), node.content.begin(), node.content.end());
  }
}

std::vector<uint8_t> serialize_der(const DerNode& node) {
  std::vector<uint8_t> out;
  serialize_der(node, out);
  return out;
}

}  // namespace nyx
