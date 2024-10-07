#include <stdio.h>
#include "../mpmult.h"
#include <assert.h>
#include <string.h>

int main(void) {
  const unsigned threshold = 2, peers = (threshold*2) + 1;

  // share value k0
  uint8_t k0[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_random(k0);
  //debian_rng(k0);
  //dump(k0, sizeof k0, "k0");
  // split k into shares
  uint8_t shares0[peers][TOPRF_Share_BYTES];
  toprf_create_shares(k0, peers, threshold, shares0);
  //for(unsigned j=0;j<peers;j++)
  //  dump(shares0[j], TOPRF_Share_BYTES, "shares0");
  //printf("\n");

  // share value k1
  uint8_t k1[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_random(k1);
  //debian_rng(k1);
  //dump(k1, sizeof k1, "k1");
  // split k into shares
  uint8_t shares1[peers][TOPRF_Share_BYTES];
  toprf_create_shares(k1, peers, threshold, shares1);
  //for(unsigned j=0;j<peers;j++)
  //  dump(shares1[j], TOPRF_Share_BYTES, "shares1");
  //printf("\n");

  // each shareholder multiplies their k0,k1 shares
  // and creates a sharing of this product
  uint8_t mulshares[peers][peers][TOPRF_Share_BYTES];
  for(unsigned i=0;i<peers;i++) {
    if( toprf_mpc_mul_start(shares0[i], shares1[i], peers, threshold, mulshares[i])) return 1;
  }

  uint8_t indexes[peers];
  for(unsigned i=0; i<peers; i++) indexes[i]=i+1;

  uint8_t sharesP[peers][TOPRF_Share_BYTES];
  //memset(sharesP,0,sizeof sharesP);

  for(unsigned i=0;i<peers;i++) {
    uint8_t shares[peers][TOPRF_Share_BYTES];
    for(unsigned j=0; j<peers;j++) {
      memcpy(shares[j], mulshares[j][i], TOPRF_Share_BYTES);
      //dump(mulshares[j][i], TOPRF_Share_BYTES, "mulsharesx");
      //dump(shares[i], TOPRF_Share_BYTES, "sharesx");
    }
    toprf_mpc_mul_finish(peers, indexes, i+1, shares, sharesP[i]);
  }

  // verify
  uint8_t k0k1[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_mul(k0k1, k0, k1);

  uint8_t r[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_random(r);
  //debian_rng(r);
  uint8_t gr[crypto_core_ristretto255_BYTES];
  crypto_scalarmult_ristretto255_base(gr, r);
  uint8_t verifier[crypto_core_ristretto255_BYTES];
  if(crypto_scalarmult_ristretto255(verifier, k0k1, gr)) return 1;

  uint8_t sharesP2[2][TOPRF_Share_BYTES];
  if(crypto_scalarmult_ristretto255(sharesP2[0]+1, sharesP[0]+1, gr)) return 1;
  sharesP2[0][0]=1;
  if(crypto_scalarmult_ristretto255(sharesP2[1]+1, sharesP[2]+1, gr)) return 1;
  sharesP2[1][0]=3;
  uint8_t result[crypto_core_ristretto255_BYTES];
  if(toprf_thresholdmult(2, sharesP2, result)) return 1;

  if(memcmp(result,verifier,crypto_core_ristretto255_BYTES)!=0) {
    printf("humiliating failure /o\\n");
    return 1;
  }
  printf("great success!!5!\n");

  return 0;
}
