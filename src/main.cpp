// Nyx fuzzer driver.
//
// Wires together: corpus -> scheduler picks a seed -> parse to DER tree ->
// structure-aware mutate -> serialize -> run instrumented target -> read
// coverage -> feed back to scheduler -> save new-coverage inputs & crashes.
//
// This is the top-level loop skeleton; the phased components (mutator, scheduler,
// coverage, target runner) fill in behind their interfaces. See DESIGN.md.
#include <cstdio>
#include <cstring>
#include <string>

#include "nyx/der_parser.hpp"
#include "nyx/der_serializer.hpp"
#include "nyx/mutator.hpp"

namespace {

void usage(const char* argv0) {
  std::printf(
      "Nyx -- structure-aware, entropy-guided DER/ASN.1 fuzzer\n"
      "usage: %s <corpus_dir> <target> [--seconds N] [--scheduler entropy|uniform]\n"
      "\n"
      "  corpus_dir   directory of seed inputs (DER certificates)\n"
      "  target       instrumented target binary (SanitizerCoverage)\n"
      "  --seconds    time budget for this run (benchmark uses fixed budgets)\n"
      "  --scheduler  which scheduler to use (default: entropy)\n",
      argv0);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 3) {
    usage(argv[0]);
    return 2;
  }
  const std::string corpus_dir = argv[1];
  const std::string target = argv[2];

  std::printf("[nyx] corpus=%s target=%s\n", corpus_dir.c_str(), target.c_str());
  std::printf("[nyx] fuzzing loop is assembled in phases (see DESIGN.md):\n");
  std::printf("      phase 0-1: coverage + minimal loop\n");
  std::printf("      phase 2  : structure-aware mutator (DER core ready & tested)\n");
  std::printf("      phase 3  : entropy-guided scheduler\n");
  std::printf("      phase 4  : benchmark vs libFuzzer / AFL++ / Nautilus\n");

  // TODO(phase-1): load corpus, spawn/instrument target, run the loop below.
  //   Mutator mutator(seed);
  //   auto scheduler = make_entropy_scheduler(seed);
  //   while (time_left()) { ... }
  return 0;
}
