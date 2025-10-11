#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "cfrg_oprf_test_vectors.h"
#include "../oprf.h"
#include "../utils.h"

extern int liboprf_debug;

int main(void) {
  liboprf_debug = 1;
  int res;

  uint8_t r[crypto_core_ristretto255_SCALARBYTES];
  uint8_t blinded[crypto_core_ristretto255_BYTES];

  res = oprf_Blind(input, input_len, r, blinded);
  if(res) return 1;
  if(memcmp(blinded, blinded_element, blindedelement_len)!=0) {
    fail("calulated Blinded Element is not expected value:");
    dump(blinded, sizeof(blinded), "calculated: ");
    dump(blinded_element, blindedelement_len, "expected:   ");
    return 1;
  }

  uint8_t Z[crypto_core_ristretto255_BYTES];
  res = oprf_Evaluate(sks, blinded, Z);
  if(res) {
    fprintf(stderr,"oprf_Evaluate returned error\n");
    return 1;
  }
  if(memcmp(Z, evaluationelement, evaluationelement_len)!=0) {
    fail("calulated Evaluation Element is not expected value:");
    dump(Z, sizeof(Z), "calculated: ");
    dump(evaluationelement, evaluationelement_len, "expected:   ");
    return 1;
  }

  uint8_t N[crypto_core_ristretto255_BYTES];
  res = oprf_Unblind(r, Z, N);
  if(res) {
    fprintf(stderr,"oprf_Unblind returned error\n");
    return 1;
  }
  uint8_t rwd[OPRF_BYTES];
  res = oprf_Finalize(input, input_len, N, rwd);
  if(res) {
    fprintf(stderr,"oprf_Finalize returned error\n");
    return 1;
  }
  if(memcmp(rwd, output, output_len)!=0) {
    fail("calulated output is not expected value:");
    dump(rwd, sizeof(rwd), "calculated: ");
    dump(output, output_len, "expected:   ");
    return 1;
  }

  printf("all ok\n");
  return 0;
}
