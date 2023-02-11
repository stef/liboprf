#include <stdio.h>
#include <string.h>

#include "oprf.h"
#include "toprf.h"

int main(void) {
  // setup
  // imagine some magical DKG which works with r255 here
  const unsigned peers = 3, threshold = 2;
  uint8_t k[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_random(k);
  // split k into shares
  TOPRF_Share shares[peers];
  toprf_create_shares(k, peers, threshold, shares);

  // start the OPRF
  const uint8_t password[8]="password";
  uint8_t r[crypto_core_ristretto255_SCALARBYTES];
  uint8_t alpha[crypto_core_ristretto255_BYTES];
  // we blind once
  if(oprf_Blind(password, sizeof password, r, alpha)) return 1;
  // until here all is like with the non-threshold version

  // calculate points of shares
  // this really happens at each peer separately
  TOPRF_Part xresps[peers];
  for(size_t i=0;i<peers;i++) { // we calculate all, but we don't need all
    // xresps[i]=g^k_i
    xresps[i].index=shares[i].index;
    if(oprf_Evaluate(shares[i].value, alpha, xresps[i].value)) return 1;
  }

  // here we select threshold responses debian-randomly
  // simulating the internet, by reordering and dropping responses
  const TOPRF_Part responses[]={xresps[2], xresps[0]};
  const size_t response_len = sizeof responses / sizeof(TOPRF_Part);

  // now comes the threshold recovery part, were we do lagrange magic
  // in the exponent
  uint8_t beta[crypto_scalarmult_ristretto255_BYTES];
  if(toprf_thresholdmult(responses, response_len, beta)) return 1;
  // end of magic trick
  // from here on the threshold and non-threshold version join paths again

  uint8_t unblinded[crypto_core_ristretto255_BYTES];
  if(oprf_Unblind(r, beta, unblinded)) return 1;

  uint8_t oprf[OPRF_BYTES];
  if(oprf_Finalize(password, sizeof password, unblinded, oprf)) return 1;

  // verification by doing the non-threshold version as well
  // g^k
  if(crypto_scalarmult_ristretto255(beta, k, alpha)) return 1;
  if(oprf_Unblind(r, beta, unblinded)) return 1;
  uint8_t oprf0[OPRF_BYTES];
  if(oprf_Finalize(password, sizeof password, unblinded, oprf0)) return 1;
  if(memcmp(oprf0,oprf,OPRF_BYTES)!=0) {
    printf("humiliating failure\n");
    return 1;
  }
  printf("great success!!5!\n");
  return 0;
}
