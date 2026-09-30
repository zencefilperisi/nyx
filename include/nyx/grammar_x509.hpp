#pragma once
// X.509 semantic grammar layer.
//
// The DER tree layer knows only TLV structure. This layer adds *meaning*: it
// knows an X.509 Certificate is
//
//   Certificate ::= SEQUENCE {
//       tbsCertificate       TBSCertificate,
//       signatureAlgorithm   AlgorithmIdentifier,
//       signatureValue       BIT STRING }
//
// ...and so on down to validity dates, OIDs, and extensions. With this it can
// generate "valid-but-hostile" certificates -- ones that pass shallow checks and
// drive the parser into deep validation code (date handling, OID tables,
// extension parsing) where the interesting bugs live.
//
// PHASE 2b (after the generic TLV tree + mutator).
#include <cstdint>
#include <optional>
#include <random>

#include "nyx/der_tree.hpp"

namespace nyx {

// Build a structurally-valid skeleton X.509 certificate tree that the mutator
// can then perturb. Fields are minimally valid so the parser accepts the shell.
DerNode make_x509_skeleton(std::mt19937_64& rng);

// Semantic-aware mutation: mutate while respecting X.509 field roles, e.g. emit
// boundary validity dates, oversized serial numbers, malformed OIDs, deeply
// nested / duplicated extensions -- the shapes that historically break parsers.
void mutate_x509_semantic(DerNode& cert, std::mt19937_64& rng);

// Recognise whether a parsed tree looks like an X.509 certificate, so real
// seeds can be fed into the semantic layer.
bool looks_like_x509(const DerNode& tree);

}  // namespace nyx
