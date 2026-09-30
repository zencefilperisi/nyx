/*
 * Phase-0 demo target -- compiled WITH -fsanitize-coverage=trace-pc-guard,trace-cmp.
 *
 * A miniature DER-ish probe with several branches and constant comparisons, so
 * the Phase-0 test can show three things working:
 *   1. different inputs light up different numbers of edges,
 *   2. inputs reaching deeper branches trigger NEW edges,
 *   3. trace-cmp captures the exact constant bytes checked (0x30, 0x02, ...),
 *      which is what later lets the fuzzer satisfy magic-byte checks.
 */
#include <stdint.h>
#include <stddef.h>

int nyx_phase0_probe(const uint8_t *data, size_t size) {
  if (size < 1) return 0;
  if (data[0] != 0x30) return 1;          // must be SEQUENCE
  if (size < 2) return 2;
  int len = data[1];
  if (len == 0) return 3;                 // empty body
  if (size < 3) return 4;
  if (data[2] != 0x02) return 5;          // first child must be INTEGER
  if (size < 4) return 6;
  if (data[3] == 0x2A) return 42;         // deep branch: specific value
  return 7;
}
