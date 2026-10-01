#include "nyx/grammar_x509.hpp"

#include <algorithm>
#include <array>

#include "nyx/der_serializer.hpp"

namespace nyx {
namespace {

// ---- small DER builders ---------------------------------------------------

DerNode prim(uint32_t tagnum, std::vector<uint8_t> content) {
  DerNode n;
  n.tag = {TagClass::Universal, false, tagnum};
  n.content = std::move(content);
  return n;
}

DerNode seq(std::vector<DerNode> children) {
  DerNode n;
  n.tag = {TagClass::Universal, true, universal::kSequence};
  n.children = std::move(children);
  return n;
}

DerNode set_(std::vector<DerNode> children) {
  DerNode n;
  n.tag = {TagClass::Universal, true, universal::kSet};
  n.children = std::move(children);
  return n;
}

std::vector<uint8_t> bytes(std::initializer_list<uint8_t> b) { return std::vector<uint8_t>(b); }
std::vector<uint8_t> ascii(const char* s) {
  std::vector<uint8_t> v;
  for (const char* p = s; *p; ++p) v.push_back(static_cast<uint8_t>(*p));
  return v;
}

// Real OID encodings.
const std::vector<uint8_t> kOidRsaEncryption =
    {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};   // 1.2.840.113549.1.1.1
const std::vector<uint8_t> kOidSha256Rsa =
    {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B};   // 1.2.840.113549.1.1.11
const std::vector<uint8_t> kOidCommonName = {0x55, 0x04, 0x03};  // 2.5.4.3

DerNode alg_id(const std::vector<uint8_t>& oid) {
  return seq({prim(universal::kObjectIdentifier, oid), prim(universal::kNull, {})});
}

DerNode name_cn(const char* cn) {
  return seq({set_({seq({prim(universal::kObjectIdentifier, kOidCommonName),
                         prim(universal::kPrintableString, ascii(cn))})})});
}

// Boundary / hostile UTCTime and GeneralizedTime strings -- the shapes that
// historically break date handling (Y2K pivot, leap boundaries, malformed).
const char* kBoundaryUtc[] = {
    "000101000000Z", "491231235959Z", "500101000000Z", "991231235959Z",
    "210229000000Z" /* invalid leap */, "999999999999Z", "", "Z", "25",
};
const char* kBoundaryGen[] = {
    "00000101000000Z", "99991231235959Z", "20000229000000Z", "19700101000000Z",
};

template <typename RNG>
size_t pick(RNG& rng, size_t n) {
  return n == 0 ? 0 : std::uniform_int_distribution<size_t>(0, n - 1)(rng);
}

void collect(DerNode& n, std::vector<DerNode*>& out) {
  out.push_back(&n);
  for (auto& c : n.children) collect(c, out);
}

}  // namespace

DerNode make_x509_skeleton(std::mt19937_64& rng) {
  (void)rng;
  // TBSCertificate (minimal but structurally real).
  DerNode tbs = seq({
      prim(universal::kInteger, {0x01}),                 // serialNumber
      alg_id(kOidSha256Rsa),                             // signature
      name_cn("Nyx Test CA"),                            // issuer
      seq({prim(universal::kUtcTime, ascii("240101000000Z")),   // validity.notBefore
           prim(universal::kUtcTime, ascii("340101000000Z"))}), // validity.notAfter
      name_cn("Nyx Test Leaf"),                          // subject
      seq({alg_id(kOidRsaEncryption),                    // subjectPublicKeyInfo
           prim(universal::kBitString, {0x00, 0x11, 0x22, 0x33})}),
  });
  // Certificate.
  return seq({
      tbs,
      alg_id(kOidSha256Rsa),                             // signatureAlgorithm
      prim(universal::kBitString, {0x00, 0xAB, 0xCD}),   // signatureValue
  });
}

bool looks_like_x509(const DerNode& tree) {
  if (!tree.tag.constructed || tree.tag.number != universal::kSequence) return false;
  if (tree.children.size() < 3) return false;
  const DerNode& tbs = tree.children[0];
  if (!tbs.tag.constructed || tbs.tag.number != universal::kSequence) return false;
  return tbs.children.size() >= 4;  // serial, sig, issuer, validity, ...
}

void mutate_x509_semantic(DerNode& cert, std::mt19937_64& rng) {
  std::vector<DerNode*> all;
  collect(cert, all);

  // Bucket nodes by semantic role.
  std::vector<DerNode*> times, integers, oids, strings, constructed;
  for (auto* n : all) {
    if (!n->tag.constructed &&
        (n->tag.number == universal::kUtcTime || n->tag.number == universal::kGeneralizedTime))
      times.push_back(n);
    else if (!n->tag.constructed && n->tag.number == universal::kInteger)
      integers.push_back(n);
    else if (!n->tag.constructed && n->tag.number == universal::kObjectIdentifier)
      oids.push_back(n);
    else if (!n->tag.constructed &&
             (n->tag.number == universal::kPrintableString || n->tag.number == universal::kUtf8String))
      strings.push_back(n);
    else if (n->tag.constructed)
      constructed.push_back(n);
  }

  // Choose a category that exists and apply a typed, hostile mutation.
  enum Cat { TIME, INT, OID, STR, STRUCT, NCAT };
  std::array<bool, NCAT> ok = {!times.empty(), !integers.empty(), !oids.empty(),
                               !strings.empty(), !constructed.empty()};
  std::vector<int> avail;
  for (int c = 0; c < NCAT; ++c)
    if (ok[c]) avail.push_back(c);
  if (avail.empty()) return;
  int cat = avail[pick(rng, avail.size())];

  switch (cat) {
    case TIME: {
      DerNode* n = times[pick(rng, times.size())];
      switch (pick(rng, 3)) {
        case 0:  // boundary UTCTime
          n->tag.number = universal::kUtcTime;
          n->content = ascii(kBoundaryUtc[pick(rng, std::size(kBoundaryUtc))]);
          break;
        case 1:  // boundary GeneralizedTime (and tag confusion)
          n->tag.number = universal::kGeneralizedTime;
          n->content = ascii(kBoundaryGen[pick(rng, std::size(kBoundaryGen))]);
          break;
        case 2:  // flip UTCTime<->GeneralizedTime tag without fixing content
          n->tag.number = (n->tag.number == universal::kUtcTime)
                              ? universal::kGeneralizedTime
                              : universal::kUtcTime;
          break;
      }
      break;
    }
    case INT: {
      DerNode* n = integers[pick(rng, integers.size())];
      switch (pick(rng, 4)) {
        case 0: n->content.assign(1 + pick(rng, 40), 0xFF); break;   // huge
        case 1: n->content = {0x80};                                 // negative
        case 2: n->content = {};                                     // empty (invalid)
        case 3: n->content = {0x00, 0x00, 0x01};                     // non-minimal
      }
      break;
    }
    case OID: {
      DerNode* n = oids[pick(rng, oids.size())];
      switch (pick(rng, 3)) {
        case 0: n->content = {};                                     // empty OID
        case 1: n->content.assign(1 + pick(rng, 30), 0x80); break;   // non-terminated arcs
        case 2: n->content.push_back(0x80); break;                   // trailing continuation
      }
      break;
    }
    case STR: {
      DerNode* n = strings[pick(rng, strings.size())];
      switch (pick(rng, 3)) {
        case 0: n->content.push_back(0x00); break;                   // embedded NUL
        case 1: n->content = {0xFF, 0xFE, 0xFF};                     // invalid UTF-8
        case 2: n->content.assign(1 + pick(rng, 64), 0x41); break;   // overlong
      }
      break;
    }
    case STRUCT: {
      DerNode* n = constructed[pick(rng, constructed.size())];
      if (!n->children.empty()) {
        size_t i = pick(rng, n->children.size());
        n->children.insert(n->children.begin() + i, n->children[i]);  // duplicate (e.g. extension)
      }
      break;
    }
  }
}

}  // namespace nyx
