#include "nyx/der_parser.hpp"

namespace nyx {
namespace {

bool read_tag(const uint8_t* d, size_t len, size_t& pos, Tag& tag, ParseError& err) {
  if (pos >= len) {
    err = {"unexpected end of input while reading tag", pos};
    return false;
  }
  const uint8_t first = d[pos++];
  tag.cls = static_cast<TagClass>((first >> 6) & 0x03);
  tag.constructed = (first & 0x20) != 0;
  uint32_t number = first & 0x1F;

  if (number == 0x1F) {
    // High-tag-number form: base-128, big-endian, continuation flag in bit 8.
    number = 0;
    bool terminated = false;
    while (pos < len) {
      const uint8_t b = d[pos++];
      if (number > (0xFFFFFFFFu >> 7)) {
        err = {"tag number overflow", pos};
        return false;
      }
      number = (number << 7) | (b & 0x7F);
      if ((b & 0x80) == 0) {
        terminated = true;
        break;
      }
    }
    if (!terminated) {
      err = {"unterminated high-tag-number form", pos};
      return false;
    }
  }
  tag.number = number;
  return true;
}

bool read_length(const uint8_t* d, size_t len, size_t& pos, size_t& length, ParseError& err) {
  if (pos >= len) {
    err = {"unexpected end of input while reading length", pos};
    return false;
  }
  const uint8_t first = d[pos++];
  if ((first & 0x80) == 0) {  // short form
    length = first;
    return true;
  }
  const uint8_t num_octets = first & 0x7F;
  if (num_octets == 0) {
    err = {"indefinite length is not valid DER", pos - 1};
    return false;
  }
  if (num_octets > sizeof(size_t)) {
    err = {"length field too large for this platform", pos - 1};
    return false;
  }
  size_t value = 0;
  for (uint8_t i = 0; i < num_octets; ++i) {
    if (pos >= len) {
      err = {"unexpected end of input in long-form length", pos};
      return false;
    }
    value = (value << 8) | d[pos++];
  }
  length = value;
  return true;
}

std::optional<DerNode> parse_node(const uint8_t* d, size_t len, size_t& pos,
                                  ParseError& err, int depth) {
  if (depth > kMaxDepth) {
    err = {"maximum nesting depth exceeded", pos};
    return std::nullopt;
  }
  DerNode node;
  if (!read_tag(d, len, pos, node.tag, err)) return std::nullopt;

  size_t length = 0;
  if (!read_length(d, len, pos, length, err)) return std::nullopt;

  if (length > len - pos) {
    err = {"declared content length exceeds remaining input", pos};
    return std::nullopt;
  }
  const size_t content_end = pos + length;

  if (node.tag.constructed) {
    while (pos < content_end) {
      auto child = parse_node(d, len, pos, err, depth + 1);
      if (!child) return std::nullopt;
      node.children.push_back(std::move(*child));
    }
    if (pos != content_end) {
      err = {"constructed value children overran declared length", pos};
      return std::nullopt;
    }
  } else {
    node.content.assign(d + pos, d + content_end);
    pos = content_end;
  }
  return node;
}

}  // namespace

std::optional<DerNode> parse_der(const uint8_t* data, size_t len,
                                 size_t& consumed, ParseError& err) {
  size_t pos = 0;
  auto node = parse_node(data, len, pos, err, 0);
  consumed = pos;
  return node;
}

std::optional<DerNode> parse_der(const std::vector<uint8_t>& data, ParseError& err) {
  size_t consumed = 0;
  auto node = parse_der(data.data(), data.size(), consumed, err);
  if (node && consumed != data.size()) {
    err = {"trailing bytes after top-level TLV", consumed};
    return std::nullopt;
  }
  return node;
}

}  // namespace nyx
