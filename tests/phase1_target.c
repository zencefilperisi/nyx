/*
 * Phase-1 demo target -- compiled WITH coverage instrumentation.
 *
 * A libFuzzer-style entry point that parses a tiny DER-like structure and
 * contains a reachable bug. The bug sits behind several exact-byte checks, so a
 * blind byte fuzzer would take enormous effort to reach it, while a
 * coverage-guided loop is rewarded at each correct byte and homes in quickly --
 * which is exactly what the Phase-1 test demonstrates.
 *
 * The "bug" is signalled with abort() (a clean, catchable SIGABRT) to stand in
 * for what ASan/UBSan would raise on a real memory error, so the test is
 * deterministic and safe in CI.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 5) return 0;
  if (data[0] != 0x30) return 0;   /* SEQUENCE            */
  if (data[1] != 0x03) return 0;   /* length = 3          */
  if (data[2] != 0x02) return 0;   /* INTEGER             */
  if (data[3] != 0x01) return 0;   /* int length = 1      */
  if (data[4] == 0x7F) {           /* specific value -> bug */
    abort();                        /* simulated vulnerability */
  }
  return 0;
}
