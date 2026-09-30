/*
 * libFuzzer-style harness for mbedTLS X.509 DER parsing (secondary target).
 *
 * Build (with coverage + sanitizers), e.g.:
 *   clang -g -O1 -fsanitize=address,undefined \
 *         -fsanitize-coverage=trace-pc-guard,trace-cmp \
 *         mbedtls_harness.c -lmbedx509 -lmbedcrypto -o target_mbedtls
 *
 * mbedtls_x509_crt_parse_der drives the full certificate parser: TBSCertificate,
 * validity dates, algorithm OIDs and the extension list -- the deep code paths
 * the X.509 semantic grammar layer is designed to reach.
 */
#include <stdint.h>
#include <stddef.h>
#include <mbedtls/x509_crt.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);
  mbedtls_x509_crt_parse_der(&crt, data, size);
  mbedtls_x509_crt_free(&crt);
  return 0;
}
