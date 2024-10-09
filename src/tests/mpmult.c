#include <stdio.h>
#include "../mpmult.h"
#include "../dkg.h"
#include "../utils.h"
#include <assert.h>
#include <string.h>

int main(void) {
  debug = 1; // is a global variable from utils.h
  const unsigned threshold = 2, dealers = (threshold*2) + 1, peers = dealers * 2;

  // share value k0
  uint8_t k0[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_random(k0);
  //debian_rng(k0);
  dump(k0, sizeof k0, "k0");
  // split k into shares
  uint8_t shares0[peers][TOPRF_Share_BYTES];
  toprf_create_shares(k0, peers, threshold, shares0);
  if(debug) {
    for(unsigned j=0;j<peers;j++)
      dump(shares0[j], TOPRF_Share_BYTES, "shares0[%d]", j);
    printf("\n");
  }

  // share value k1
  uint8_t k1[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_random(k1);
  //debian_rng(k1);
  dump(k1, sizeof k1, "k1");
  // split k into shares
  uint8_t shares1[peers][TOPRF_Share_BYTES];
  toprf_create_shares(k1, peers, threshold, shares1);
  if(debug) {
    for(unsigned j=0;j<peers;j++)
      dump(shares1[j], TOPRF_Share_BYTES, "shares1[%d]", j);
    printf("\n");
  }

  // each shareholder multiplies their k0,k1 shares
  // and creates a sharing of this product
  uint8_t mulshares[dealers][peers][TOPRF_Share_BYTES];
  for(unsigned i=0;i<dealers;i++) {
    if( toprf_mpc_mul_start(shares0[i], shares1[i], peers, threshold, mulshares[i])) return 1;
  }

  uint8_t indexes[dealers];
  for(unsigned i=0; i<dealers; i++) indexes[i]=i+1;

  uint8_t sharesP[peers][TOPRF_Share_BYTES];
  //memset(sharesP,0,sizeof sharesP);

  for(unsigned i=0;i<peers;i++) {
    uint8_t shares[dealers][TOPRF_Share_BYTES];
    for(unsigned j=0; j<dealers;j++) {
      memcpy(shares[j], mulshares[j][i], TOPRF_Share_BYTES);
      dump(mulshares[j][i], TOPRF_Share_BYTES, "mulsharesx[%d][%d]", j,i);
      dump(shares[j], TOPRF_Share_BYTES, "sharesx[%d]", i);
    }
    toprf_mpc_mul_finish(dealers, indexes, i+1, shares, sharesP[i]);
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
    printf("\n");
    fprintf(stderr,"\e[0;31mhumiliating failure /o\\e[0m\n");
    return 1;
  }

  for(unsigned i=0;i<=peers-threshold;i++) {
    uint8_t v[crypto_core_ristretto255_BYTES];
    TOPRF_Share *shares = (TOPRF_Share *) sharesP[i];
    dkg_reconstruct(threshold, shares, v);
    dump(v,sizeof v, "v[%d] ", i);
    if(memcmp(v,k0k1,sizeof v)!=0) {
      fprintf(stderr,"\e[0;31mfailed to verify reconstruction of generated x from final shares!\e[0m\n");
      dump(k0k1,sizeof k0k1, "k0k1 ");
      dump(v,sizeof v, "v ");
      return 1;
    }
  }

  fprintf(stderr, "\e[0;32mgreat success!!5!\e[0m\n");

  return 0;
}
