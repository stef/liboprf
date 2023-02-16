#include <sodium.h>
#include <stdint.h>
#include <string.h>
#include "matrices.h"
#include "toprf.h"

typedef struct {
  uint8_t index;
  uint8_t value[crypto_core_ristretto255_SCALARBYTES];
} __attribute((packed)) TOPRF_Share;

int toprf_mpc_mul_start(const uint8_t _a[TOPRF_Share_BYTES],
                        const uint8_t _b[TOPRF_Share_BYTES],
                        const uint8_t peers, const uint8_t threshold,
                        uint8_t shares[peers][TOPRF_Share_BYTES]) {
  const TOPRF_Share *a=(TOPRF_Share*) _a;
  const TOPRF_Share *b=(TOPRF_Share*) _b;

  if(a->index!=b->index ||
     peers<threshold ||
     threshold == 0) return 1;

  uint8_t ab[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_mul(ab, a->value, b->value);
  //dump(ab, sizeof ab, "ab");
  toprf_create_shares(ab, peers, threshold, shares);
  //for(unsigned j=0;j<peers;j++)
    //dump(shares[j], TOPRF_Share_BYTES, "mulshare");
  return 0;
}

void toprf_mpc_mul_finish(const uint8_t peers, const uint8_t indexes[peers],
                          const uint8_t peer,
                          const uint8_t shares[peers][TOPRF_Share_BYTES],
                          uint8_t _share[TOPRF_Share_BYTES]) {
  TOPRF_Share *share=(TOPRF_Share*) _share;

  // pre-calculate inverted vandermonde matrix of the indexes of the peers
  uint8_t vdm[peers][peers][crypto_core_ristretto255_SCALARBYTES];
  genVDMmatrix(indexes, peers, vdm);
  uint8_t inverted[peers][peers][crypto_core_ristretto255_SCALARBYTES];
  invert(peers, vdm, inverted);

  // execute step 2 of simple mult
  // H(j) = sum(lambda[i] * h[i](j) for i in 1..2t+1)
  memset(share,0,TOPRF_Share_BYTES);
  share->index=peer;
  uint8_t tmp[crypto_core_ristretto255_SCALARBYTES];
  for(unsigned i=0;i<peers;i++) {
    crypto_core_ristretto255_scalar_mul(tmp, shares[i]+1, inverted[0][i]);
    //dump(shares[i], TOPRF_Share_BYTES, "mulshare[i][j]");
    crypto_core_ristretto255_scalar_add(share->value, share->value, tmp);
  }
  //dump(share->value, sizeof share->value, "share");
}

#ifdef UNIT_TEST
#include <stdio.h>
//static void dump(const uint8_t *p, const size_t len, const char* msg) {
//  size_t i;
//  fprintf(stderr,"%s ",msg);
//  for(i=0;i<len;i++)
//    fprintf(stderr,"%02x", p[i]);
//  fprintf(stderr,"\n");
//}
//
//static void print_matrix(const uint8_t size, const uint8_t matrix[size][size][crypto_core_ristretto255_SCALARBYTES]) {
//  int i = 0;
//  for(int j=0;j<size;j++) {
//    uint8_t len=crypto_core_ristretto255_SCALARBYTES-1;
//    for(; matrix[i][j][len]==0; len--);
//    dump(matrix[i][j],len+1,"");
//    fprintf(stderr, " ");
//  }
//  fprintf(stderr, "\n");
//}
//
//static void debian_rng(uint8_t *scalar) {
//  static uint8_t i=0;
//  uint8_t tmp[64];
//  for(unsigned j=0;j<64;j++) {
//    tmp[j]=i++;
//  }
//  crypto_core_ristretto255_scalar_reduce(scalar,tmp);
//}

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
#endif // UNIT_TEST
