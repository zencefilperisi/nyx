/*
 * Phase-2 demo target -- rewards STRUCTURE awareness.
 *
 * Reaching the bug requires three correctly-nested, length-consistent TLVs:
 *     SEQUENCE { SEQUENCE { INTEGER (value 0x2A) } }
 * The length checks are strict: any byte mutation that touches a tag or length
 * octet breaks the structure and the parser bails early. A structure-aware
 * mutator re-serialises correct lengths every time, so it stays valid and can
 * explore the INTEGER's value -- which is the whole point of Phase 2.
 *
 * abort() stands in for what ASan would raise on a real memory bug.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

/* Strict TLV header read: returns content start or NULL; content must fit. */
static const uint8_t *rdhdr(const uint8_t *p, const uint8_t *end,
                            uint8_t *tag, size_t *len) {
  if (p + 1 > end) return 0;
  *tag = *p++;
  if (p + 1 > end) return 0;
  uint8_t l = *p++;
  if (l < 0x80) {
    *len = l;
  } else {
    uint8_t n = (uint8_t)(l & 0x7F);
    if (n == 0 || n > 4 || p + n > end) return 0;
    size_t v = 0;
    for (uint8_t i = 0; i < n; i++) v = (v << 8) | *p++;
    *len = v;
  }
  if (p + *len > end) return 0;      /* content must fit exactly within bounds */
  return p;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const uint8_t *end = data + size;
  uint8_t tag;
  size_t len;

  const uint8_t *p = rdhdr(data, end, &tag, &len);
  if (!p || tag != 0x30) return 0;             /* outer SEQUENCE */
  const uint8_t *outer_end = p + len;

  p = rdhdr(p, outer_end, &tag, &len);
  if (!p || tag != 0x30) return 0;             /* inner SEQUENCE */
  const uint8_t *inner_end = p + len;

  p = rdhdr(p, inner_end, &tag, &len);
  if (!p || tag != 0x02) return 0;             /* INTEGER */

  /* The bug is a 4-byte magic in the INTEGER value, checked byte-by-byte so
   * there is a COVERAGE GRADIENT to climb. It is gated two ways:
   *   (a) len must be 4 -- the seed's INTEGER is 1 byte, so the value must GROW,
   *       forcing every enclosing SEQUENCE length to update consistently;
   *   (b) each correct magic byte opens a new edge.
   * A byte mutator cannot coordinate the multi-level length change to even reach
   * (a) with lengths still consistent, so it never sees the gradient. A
   * structure-aware mutator resizes the value and re-serializes correct lengths,
   * unlocking the gradient and climbing it. */
  /* The gate is the LENGTH: the seed's INTEGER is 1 byte, the bug needs 2.
   * Growing the value forces every enclosing SEQUENCE length octet to update
   * consistently -- coordination a byte mutator cannot do, but a structure-aware
   * mutator gets for free on re-serialization. The single magic byte is then
   * easy to find once the structure is right. */
  if (len != 2) return 0;
  if (p[0] != 0x2A) return 0;
  abort();                                       /* structure-gated, length-coupled bug */
}
