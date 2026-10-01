#include "nyx/mutator.hpp"

#include <algorithm>

#include "nyx/der_serializer.hpp"

namespace nyx {
namespace {

// Interesting DER tag numbers to swap in (type confusion fodder).
constexpr uint32_t kInterestingTags[] = {
    universal::kBoolean,     universal::kInteger,   universal::kBitString,
    universal::kOctetString, universal::kNull,      universal::kObjectIdentifier,
    universal::kSequence,    universal::kSet,       universal::kUtcTime,
    0, 1, 31, 127, 128, 255, 65535,
};

// Interesting length values for length_override (boundaries & overflows).
constexpr uint64_t kInterestingLengths[] = {
    0, 1, 127, 128, 255, 256, 65535, 65536, 0x7FFFFFFF, 0xFFFFFFFF,
};

template <typename RNG>
size_t rnd(RNG& rng, size_t n) {
  return n == 0 ? 0 : std::uniform_int_distribution<size_t>(0, n - 1)(rng);
}

// Depth-first pointer collection so operators can target any node uniformly.
void collect(DerNode& n, std::vector<DerNode*>& out) {
  out.push_back(&n);
  for (auto& c : n.children) collect(c, out);
}

// Collect only constructed nodes (those that can hold children).
void collect_constructed(DerNode& n, std::vector<DerNode*>& out) {
  if (n.tag.constructed) out.push_back(&n);
  for (auto& c : n.children) collect_constructed(c, out);
}

DerNode make_random_primitive(std::mt19937_64& rng) {
  DerNode n;
  n.tag = {TagClass::Universal, false,
           kInterestingTags[rnd(rng, std::size(kInterestingTags))]};
  size_t len = rnd(rng, 8);
  n.content.resize(len);
  for (auto& b : n.content) b = static_cast<uint8_t>(rnd(rng, 256));
  return n;
}

}  // namespace

bool Mutator::apply(MutationOp op, DerNode& tree, const MutatorConfig& cfg) {
  std::vector<DerNode*> all;
  collect(tree, all);
  std::vector<DerNode*> constructed;
  collect_constructed(tree, constructed);

  switch (op) {
    case MutationOp::kFlipContentBytes: {
      // Mutate a few bytes of a primitive value. Mixes bit-flips with random
      // byte-sets: bit-flips are good for small perturbations, but setting a
      // whole random byte is what actually discovers magic values (1/256 per
      // try) -- pure bit-flipping struggles to reach an exact target byte.
      std::vector<DerNode*> prims;
      for (auto* n : all)
        if (!n->tag.constructed && !n->content.empty()) prims.push_back(n);
      if (prims.empty()) return false;
      DerNode* n = prims[rnd(rng_, prims.size())];
      int edits = 1 + static_cast<int>(rnd(rng_, 4));
      for (int i = 0; i < edits; ++i) {
        size_t idx = rnd(rng_, n->content.size());
        switch (rnd(rng_, 3)) {
          case 0: n->content[idx] ^= static_cast<uint8_t>(1u << rnd(rng_, 8)); break;
          case 1: n->content[idx] = static_cast<uint8_t>(rnd(rng_, 256)); break;
          case 2: {  // small arithmetic step
            int d = static_cast<int>(rnd(rng_, 21)) - 10;
            n->content[idx] = static_cast<uint8_t>(n->content[idx] + d);
            break;
          }
        }
      }
      return true;
    }
    case MutationOp::kResizeContent: {
      std::vector<DerNode*> prims;
      for (auto* n : all)
        if (!n->tag.constructed) prims.push_back(n);
      if (prims.empty()) return false;
      DerNode* n = prims[rnd(rng_, prims.size())];
      if (rnd(rng_, 2) == 0) {  // grow
        size_t add = 1 + rnd(rng_, 16);
        for (size_t i = 0; i < add; ++i)
          n->content.push_back(static_cast<uint8_t>(rnd(rng_, 256)));
      } else if (!n->content.empty()) {  // shrink
        size_t keep = rnd(rng_, n->content.size());
        n->content.resize(keep);
      }
      return true;
    }
    case MutationOp::kChangeTagNumber: {
      DerNode* n = all[rnd(rng_, all.size())];
      n->tag.number = kInterestingTags[rnd(rng_, std::size(kInterestingTags))];
      return true;
    }
    case MutationOp::kToggleConstructed: {
      DerNode* n = all[rnd(rng_, all.size())];
      if (n->tag.constructed) {
        // constructed -> primitive: flatten children into raw content.
        std::vector<uint8_t> body;
        for (auto& c : n->children) serialize_der(c, body);
        n->children.clear();
        n->content = std::move(body);
        n->tag.constructed = false;
      } else {
        // primitive -> constructed: content becomes an opaque child-less body.
        n->tag.constructed = true;
        n->children.clear();
        n->content.clear();
      }
      return true;
    }
    case MutationOp::kDuplicateChild: {
      std::vector<DerNode*> parents;
      for (auto* n : constructed)
        if (!n->children.empty()) parents.push_back(n);
      if (parents.empty()) return false;
      DerNode* p = parents[rnd(rng_, parents.size())];
      size_t i = rnd(rng_, p->children.size());
      p->children.insert(p->children.begin() + i, p->children[i]);
      return true;
    }
    case MutationOp::kDeleteChild: {
      std::vector<DerNode*> parents;
      for (auto* n : constructed)
        if (!n->children.empty()) parents.push_back(n);
      if (parents.empty()) return false;
      DerNode* p = parents[rnd(rng_, parents.size())];
      p->children.erase(p->children.begin() + rnd(rng_, p->children.size()));
      return true;
    }
    case MutationOp::kInsertChild: {
      if (constructed.empty()) return false;
      DerNode* p = constructed[rnd(rng_, constructed.size())];
      size_t pos = rnd(rng_, p->children.size() + 1);
      p->children.insert(p->children.begin() + pos, make_random_primitive(rng_));
      return true;
    }
    case MutationOp::kSwapChildren: {
      std::vector<DerNode*> parents;
      for (auto* n : constructed)
        if (n->children.size() >= 2) parents.push_back(n);
      if (parents.empty()) return false;
      DerNode* p = parents[rnd(rng_, parents.size())];
      size_t a = rnd(rng_, p->children.size());
      size_t b = rnd(rng_, p->children.size());
      std::swap(p->children[a], p->children[b]);
      return true;
    }
    case MutationOp::kCorruptLength: {
      DerNode* n = all[rnd(rng_, all.size())];
      n->length_override = kInterestingLengths[rnd(rng_, std::size(kInterestingLengths))];
      return true;
    }
    case MutationOp::kDeepNest: {
      DerNode* n = all[rnd(rng_, all.size())];
      int layers = 1 + static_cast<int>(rnd(rng_, cfg.max_generated_depth));
      for (int i = 0; i < layers; ++i) {
        DerNode wrapper;
        wrapper.tag = {TagClass::Universal, true, universal::kSequence};
        wrapper.children.push_back(std::move(*n));
        *n = std::move(wrapper);
      }
      return true;
    }
    case MutationOp::kCount:
      return false;
  }
  return false;
}

namespace {
// Operator weights. Real fuzzers don't pick operators uniformly: most energy
// goes into exploring VALUES within a valid structure, with occasional, rarer
// structural edits. Uniform selection over destructive ops wastes almost every
// candidate. These weights mirror that wisdom (they are not tuned to any
// specific target -- just "explore mostly, restructure sometimes").
struct OpWeight { MutationOp op; int weight; };
constexpr OpWeight kWeights[] = {
    {MutationOp::kFlipContentBytes, 30},  // explore values
    {MutationOp::kResizeContent,    20},  // resize values (couples lengths)
    {MutationOp::kDuplicateChild,    8},
    {MutationOp::kSwapChildren,      6},
    {MutationOp::kInsertChild,       6},
    {MutationOp::kDeleteChild,       6},
    {MutationOp::kChangeTagNumber,   8},  // type confusion (structural)
    {MutationOp::kCorruptLength,     4},  // length confusion (structural)
    {MutationOp::kToggleConstructed, 3},  // aggressive structural
    {MutationOp::kDeepNest,          3},  // aggressive structural
};
constexpr int kWeightTotal = [] {
  int s = 0;
  for (auto w : kWeights) s += w.weight;
  return s;
}();
}  // namespace

std::vector<MutationOp> Mutator::mutate(DerNode& tree, const MutatorConfig& cfg) {
  std::vector<MutationOp> applied;
  // Favour a small number of edits per round; too many stacked edits turn most
  // candidates into garbage that the target rejects immediately.
  int rounds = 1 + static_cast<int>(rnd(rng_, 2));  // 1..2 edits
  for (int r = 0; r < rounds; ++r) {
    int roll = static_cast<int>(rnd(rng_, kWeightTotal));
    MutationOp op = kWeights[0].op;
    for (auto w : kWeights) {
      if (roll < w.weight) { op = w.op; break; }
      roll -= w.weight;
    }
    if (apply(op, tree, cfg)) applied.push_back(op);
  }
  return applied;
}

}  // namespace nyx
