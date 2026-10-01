/*
 * Phase-2b demo target -- rewards X.509 SEMANTIC awareness.
 *
 * It walks the certificate structure, finds the validity UTCTime, and validates
 * it as a real date (length, digits, terminator) -- a coverage gradient. The
 * bug is a classic UTCTime Y2K-pivot boundary ("491231235959Z"): a date-handling
 * fault reachable only with a *well-formed, boundary-valued* date.
 *
 * Generic structure-aware mutation corrupts the date bytes randomly and almost
 * never yields a valid 13-char date, so it cannot climb the gradient. The X.509
 * semantic layer emits boundary dates by construction, walks the gradient, and
 * hits the bug. abort() stands in for the real date-handling crash.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

static const uint8_t *hdr(const uint8_t *p, const uint8_t *end,
                          uint8_t *tag, int *constructed, size_t *len) {
  if (p + 2 > end) return 0;
  uint8_t t = *p++;
  *tag = (uint8_t)(t & 0x1F);
  *constructed = (t & 0x20) != 0;
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
  if (p + *len > end) return 0;
  return p;
}

static void check_date(const uint8_t *d, size_t len) {
  if (len != 13) return;
  for (int i = 0; i < 12; i++)
    if (d[i] < '0' || d[i] > '9') return;   /* 12 digits ... */
  if (d[12] != 'Z') return;                  /* ... then 'Z' */
  /* Y2K-pivot boundary: year "49", 1231 235959Z -- a real date-handling edge. */
  if (d[0]=='4' && d[1]=='9' && d[2]=='1' && d[3]=='2' && d[4]=='3' &&
      d[5]=='1' && d[6]=='2' && d[7]=='3' && d[8]=='5' && d[9]=='9' &&
      d[10]=='5' && d[11]=='9')
    abort();
}

/* Recursively find the first UTCTime (universal tag 0x17) and validate it. */
static int scan(const uint8_t *p, const uint8_t *end) {
  while (p < end) {
    uint8_t tag; int cons; size_t len;
    const uint8_t *c = hdr(p, end, &tag, &cons, &len);
    if (!c) return 0;
    if (cons) {
      if (scan(c, c + len)) return 1;
    } else if (tag == 0x17) {   /* UTCTime */
      check_date(c, len);
      return 1;
    }
    p = c + len;
  }
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  scan(data, data + size);
  return 0;
}
