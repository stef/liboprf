#include <stdio.h>
#include "../oprf.h"
#include "../mpmult.h"
#include "../dkg.h"
#include "../utils.h"
#include <assert.h>
#include <string.h>
#include <stdint.h>

int test_mpmul(void) {
  const uint8_t threshold = 2, dealers = (threshold*2) + 1U, peers = dealers * 2;

  // share value k0
  uint8_t k0[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_random(k0);
  //debian_rng(k0);
  dump(k0, sizeof k0, "k0");
  // split k into shares
  uint8_t shares0[peers][TOPRF_Share_BYTES];
  toprf_create_shares(k0, peers, threshold, shares0);
  if(liboprf_debug) {
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
  if(liboprf_debug) {
    for(unsigned j=0;j<peers;j++)
      dump(shares1[j], TOPRF_Share_BYTES, "shares1[%d]", j);
    printf("\n");
  }

  // each shareholder multiplies their k0,k1 shares
  // and creates a sharing of this product
  uint8_t mulshares[dealers][peers][TOPRF_Share_BYTES];
  for(uint8_t i=0;i<dealers;i++) {
    if( toprf_mpc_mul_start(shares0[i], shares1[i], peers, threshold, mulshares[i])) return 1;
  }

  uint8_t indexes[dealers];
  for(uint8_t i=0; i<dealers; i++) indexes[i]=i+1;

  uint8_t sharesP[peers][TOPRF_Share_BYTES];
  //memset(sharesP,0,sizeof sharesP);

  for(uint8_t i=0;i<peers;i++) {
    uint8_t shares[dealers][TOPRF_Share_BYTES];
    for(uint8_t j=0; j<dealers;j++) {
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

static void rnd_poly(const uint8_t threshold,
                     uint8_t a[threshold][crypto_core_ristretto255_SCALARBYTES]) {
#ifdef UNIT_TEST
  fprintf(stderr,"coeffs\n");
#endif
  for(int i=0;i<threshold;i++) {
#ifdef UNIT_TEST
    debian_rng_scalar(a[i]);
    dump(a[i],crypto_core_ristretto255_SCALARBYTES,"\t");
#else
    crypto_core_ristretto255_scalar_random(a[i]);
#endif
  }
}

static void eval_poly(const uint8_t t,
                      const uint8_t a[t][crypto_core_ristretto255_SCALARBYTES],
                      const uint8_t _x,
                      uint8_t result[crypto_core_ristretto255_SCALARBYTES]) {
  uint8_t x0[crypto_core_ristretto255_SCALARBYTES]={0};
  x0[0]=_x;
  uint8_t x[crypto_core_ristretto255_SCALARBYTES]={0};
  x[0]=1;
  memset(result,0, crypto_core_ristretto255_SCALARBYTES);
  uint8_t tmp[crypto_core_ristretto255_SCALARBYTES]={0};
  for(int i=0;i<t;i++) {
    crypto_core_ristretto255_scalar_mul(tmp, a[i], x);
    crypto_core_ristretto255_scalar_add(result, result, tmp);
    crypto_core_ristretto255_scalar_mul(x, x, x0);
  }
}

int test_vsps(void) {
  // page 8, paragraph 3, line 1.
  const uint8_t t = 1; // the degree of the polynomial
  const uint8_t n = 2*(t + 1U);

  // we need a second generator h = g^z, without knowning what z is.
  uint8_t h[crypto_scalarmult_ristretto255_BYTES] = {0};
#ifdef UNIT_TEST
  uint8_t z[crypto_scalarmult_ristretto255_BYTES];
  debian_rng_scalar(z);
  dump(z, sizeof z, "z");
  crypto_scalarmult_ristretto255_base(h,z);
  dump(h, sizeof h, "h");
#else
  const uint8_t numsn[] = "nothing up my sleeve number";
  uint8_t hash[crypto_core_ristretto255_HASHBYTES] = {0};
  crypto_generichash(hash, sizeof hash, numsn, sizeof numsn, NULL, 0);
  if(0!=voprf_hash_to_group(hash, sizeof hash, h)) return -1;
#endif

  uint8_t f[t+1][crypto_core_ristretto255_SCALARBYTES];
  rnd_poly(t+1,f);
  uint8_t r[t+1][crypto_core_ristretto255_SCALARBYTES];
  rnd_poly(t+1,r);

  // calulate the commitments A_i = g^f(i) * h^r(i)
  // A[0] contains A_1, not A_0 which is not calculated above
  uint8_t A[n][crypto_scalarmult_ristretto255_BYTES];
  uint8_t tmp_s[crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t tmp[crypto_scalarmult_ristretto255_BYTES];
  for(uint8_t i=0;i<n;i++) {
    eval_poly(t+1, f, i, tmp_s);
    fprintf(stderr,"f(%d)",i);
    dump(tmp_s, sizeof tmp_s, "");
    //dump(F[i], TOPRF_Share_BYTES, "f(%d)", i);
    // A_i = g^f(i)
    crypto_scalarmult_ristretto255_base(A[i],tmp_s);
    //dump(h, sizeof h, "h    ");
    //dump(R[i], TOPRF_Share_BYTES, "R_i");
    eval_poly(t+1, r, i, tmp_s);
    fprintf(stderr,"f(%d)",i);
    dump(tmp_s, sizeof tmp_s, "");
    // h ^ R_i
    if(0!=crypto_scalarmult_ristretto255(tmp, tmp_s, h)) {
      return -1;
    }
    //dump(tmp, sizeof tmp, "tmp  ");
    // A_i = g^f(i) * h ^ r(i)
    // the group is additive, the notation multiplicative
    crypto_core_ristretto255_add(A[i], A[i], tmp);
  }
  fprintf(stderr,"commitments\n");
  for(uint8_t i=0;i<n;i++) {
    dump(A[i], crypto_scalarmult_ristretto255_BYTES, "A_%d\t", i);
  }

  // in practice each peer i receives their f(i) and their r(i) privately
  // and A is broadcast to everyone
  // each peer i checks if A[i] == g^f(i)*h^r(i)
  // we skip this for this test

  // check if A is of degree t
  if(0!=toprf_mpc_vsps_check(t, A)) {
    fprintf(stderr,"\e[0;31mhumiliating failure /o\\\e[0m\n");
    return 1;
  }

  return 0;
}

int main(void) {
  liboprf_debug = 0; // is a global variable from utils.h
  if(0!=test_mpmul()) return 1;
  liboprf_debug = 1; // is a global variable from utils.h
  if(0!=test_vsps()) return 1;

  fprintf(stderr, "\e[0;32mgreat success!!5!\e[0m\n");

  return 0;
}
