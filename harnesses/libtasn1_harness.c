/*
 * libFuzzer-style harness for GNU libtasn1 (primary target).
 *
 * Build (with coverage + sanitizers), e.g.:
 *   clang -g -O1 -fsanitize=address,undefined \
 *         -fsanitize-coverage=trace-pc-guard,trace-cmp \
 *         libtasn1_harness.c -ltasn1 -o target_libtasn1
 *
 * The same entry point (LLVMFuzzerTestOneInput) works with libFuzzer, AFL++
 * (afl-clang-lto), and Nyx's own runner, so all fuzzers hit an identical target
 * -- which is what makes the benchmark a fair comparison.
 */
#include <stdint.h>
#include <stddef.h>
#include <libtasn1.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* Exercise the DER decoder on arbitrary input. asn1_get_length_der and
   * asn1_get_tag_der are the low-level TLV parsers where length/tag confusion
   * bugs have historically lived. */
  int len_len = 0;
  long len = asn1_get_length_der(data, size, &len_len);
  (void)len;

  unsigned char class = 0;
  int tag_len = 0;
  unsigned long tag = 0;
  asn1_get_tag_der(data, size, &class, &tag_len, &tag);
  (void)tag;

  return 0;
}
