#include <stdio.h>
#include "../oprf.h"
#include "../mpmult.h"
#include "../dkg.h"
#include "../utils.h"
#include <assert.h>
#include <string.h>

int test_mpmul(void) {
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
  return 0;
}

static void print_matrix(const uint8_t size, const uint8_t matrix[size][size][crypto_core_ristretto255_SCALARBYTES]) {
  for(int i=0;i<size;i++) {
    for(int j=0;j<size;j++) {
      for(int k=0;k<crypto_core_ristretto255_SCALARBYTES;k++)
        fprintf(stderr,"%02x", matrix[i][j][k]);
      fprintf(stderr, " ");
    }
    fprintf(stderr, "\n");
  }
}

static int _vsps(const uint8_t t,
                 const uint8_t C[t][crypto_core_ristretto255_BYTES],
                 const uint8_t delta[crypto_core_ristretto255_SCALARBYTES],
                 const uint8_t inverted[t][t][crypto_core_ristretto255_SCALARBYTES],
                 uint8_t v[crypto_core_ristretto255_BYTES]) {

  // pre-calculate δ^j for j=0..t
  uint8_t delta_exp[t][crypto_core_ristretto255_SCALARBYTES];
  memset(delta_exp,0,sizeof delta_exp);
  delta_exp[0][0]=1;
  for(int exp=1;exp<t;exp++) {
    crypto_core_ristretto255_scalar_mul(delta_exp[exp], delta_exp[exp-1], delta);
  }

  // make sure v == 0
  memset(v, 0,crypto_core_ristretto255_BYTES);

  for(int i=0;i<t;i++) {
    uint8_t DELTAi[crypto_core_ristretto255_SCALARBYTES]={0};
    for(int j=0;j<t;j++) {
      // calculate λ_ij * δ^j
      uint8_t tmp[crypto_core_ristretto255_SCALARBYTES];
      crypto_core_ristretto255_scalar_mul(tmp, inverted[j][i], delta_exp[j]);
      // sum_(j=0..t) (λ_ij * δ^j)
      crypto_core_ristretto255_scalar_add(DELTAi, DELTAi, tmp);
    }
    uint8_t tmp[crypto_core_ristretto255_BYTES];
    if(0!=crypto_scalarmult_ristretto255(tmp, DELTAi, C[i])) return 1;
    crypto_core_ristretto255_add(v, v, tmp);
  }

  return 0;
}

int vsps_check(const uint8_t t, const uint8_t C[t*2][crypto_core_ristretto255_BYTES]) {
  uint8_t indexes[t];

  uint8_t delta[crypto_core_ristretto255_SCALARBYTES] = {0};
  crypto_core_ristretto255_scalar_random(delta);

  // left-hand side of the equation (1)
  for(int i=0;i<=t;i++) indexes[i]=i;
  uint8_t inverted[t+1][t+1][crypto_core_ristretto255_SCALARBYTES];
  invertedVDMmatrix(t+1,indexes,inverted);
  print_matrix(t+1,inverted);

  uint8_t v1[crypto_core_ristretto255_BYTES] = {0};
  if(0!=_vsps(t+1, C, delta, inverted, v1)) return 1;
  dump(v1, sizeof v1, "v1");

  // right-hand side of the equation (1)
  for(int i=0;i<=t;i++) indexes[i]=t+i+1;
  invertedVDMmatrix(t+1,indexes,inverted);
  print_matrix(t+1,inverted);

  uint8_t v2[crypto_core_ristretto255_BYTES] = {0};
  if(0!=_vsps(t+1, &C[t], delta, inverted, v2)) return 1;
  dump(v2, sizeof v2, "v2");

  // v1 == v2
  if(memcmp(v1,v2,sizeof v1)!=0) return 1;
  return 0;
}

int test_vsps(void) {
  const uint8_t t = 3;
  const uint8_t n = 2*t + 1;
  uint8_t a[crypto_core_ristretto255_SCALARBYTES] = {0};
  crypto_core_ristretto255_scalar_random(a);
  uint8_t r[crypto_core_ristretto255_SCALARBYTES] = {0};
  crypto_core_ristretto255_scalar_random(r);

  // callculate A_i = f(i)
  uint8_t A[n][TOPRF_Share_BYTES];
  toprf_create_shares(a, n, t, A);

  // callculate R_i = r(i)
  uint8_t R[n][TOPRF_Share_BYTES];
  toprf_create_shares(r, n, t, R);

  // we need a second generator h = g^z, without knowning what z is.
  const uint8_t numsn[] = "nothing up my sleeve number";
  uint8_t hash[crypto_core_ristretto255_HASHBYTES] = {0};
  crypto_generichash(hash, sizeof hash, numsn, sizeof numsn, NULL, 0);
  uint8_t h[crypto_scalarmult_ristretto255_BYTES] = {0};
  if(0!=voprf_hash_to_group(hash, sizeof hash, h)) return -1;

  // calulate the commitments C_i = g^f(i) * h^r(i)
  uint8_t C[n][crypto_scalarmult_ristretto255_BYTES];
  uint8_t tmp[crypto_scalarmult_ristretto255_BYTES];
  for(int i=0;i<n;i++) {
    //dump(A[i], TOPRF_Share_BYTES, "A_i");
    // C_i = g^A_i
    crypto_scalarmult_ristretto255_base(C[i],A[i]);
    //dump(h, sizeof h, "h    ");
    //dump(R[i], TOPRF_Share_BYTES, "R_i");
    // h ^ R_i
    if(0!=crypto_scalarmult_ristretto255(tmp, R[i], h)) {
      return -1;
    }
    //dump(tmp, sizeof tmp, "tmp  ");
    // C_i = g^A_i * h ^ R_i
    crypto_core_ristretto255_add(C[i], C[i], tmp);
    //dump(C[i], crypto_scalarmult_ristretto255_BYTES, "C_i");
  }

  // in practice each peer i receives their f(i) and their r(i) privately
  // and C is broadcast to everyone
  // each peer i checks if C[i] == g^f[i]*h^r[i]
  // we skip this for this test

  if(0!=vsps_check(t, C)) {
    fprintf(stderr,"\e[0;31mhumiliating failure /o\\\e[0m\n");
    return 1;
  }

  return 0;
}

int main(void) {
  debug = 0; // is a global variable from utils.h
  if(0!=test_mpmul()) return 1;
  debug = 1; // is a global variable from utils.h
  if(0!=test_vsps()) return 1;

  fprintf(stderr, "\e[0;32mgreat success!!5!\e[0m\n");

  return 0;
}
