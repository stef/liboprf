#include <sodium.h>
#include <stdint.h>
#include <string.h>
#include "toprf.h"
#include "utils.h"
#include "dkg.h"

// nothing up my sleeve generator H, generated with:
// hash_to_group((uint8_t*)"DKG Generator H on ristretto255", 32, H)
const __attribute__((visibility("hidden"))) uint8_t H[crypto_core_ristretto255_BYTES]= {
  0x66, 0x4e, 0x4c, 0xb5, 0x89, 0x0e, 0xb3, 0xe4,
  0xc0, 0xd5, 0x48, 0x02, 0x74, 0x8a, 0xb2, 0x25,
  0xf9, 0x73, 0xda, 0xe5, 0xc0, 0xef, 0xc1, 0x68,
  0xf4, 0x4d, 0x1b, 0x60, 0x28, 0x97, 0x8f, 0x07};

int dkg_vss_commit(const uint8_t a[crypto_core_ristretto255_SCALARBYTES],
                   const uint8_t r[crypto_core_ristretto255_SCALARBYTES],
                   uint8_t C[crypto_core_ristretto255_BYTES]) {
  // compute commitments
    uint8_t X[crypto_core_ristretto255_BYTES];
    uint8_t R[crypto_core_ristretto255_BYTES];
    // x = g^a_ik
    crypto_scalarmult_ristretto255_base(X, a);
    // r = h^b_ik
    if(crypto_scalarmult_ristretto255(R, r, H)) return 1;
    // C_ik = x+r
    crypto_core_ristretto255_add(C,X,R);

    return 0;
}

int dkg_vss_share(const uint8_t n,
                  const uint8_t threshold,
                  const uint8_t secret[crypto_core_ristretto255_SCALARBYTES],
                  uint8_t commitments[n][crypto_core_ristretto255_BYTES],
                  TOPRF_Share shares[n][2],
                  uint8_t blind[crypto_core_ristretto255_SCALARBYTES]) {
  if(threshold==0) return 1;
  uint8_t a[threshold][crypto_core_ristretto255_SCALARBYTES];
  uint8_t b[threshold][crypto_core_ristretto255_SCALARBYTES];
  if(secret!=NULL) memcpy(a[0],secret, crypto_core_ristretto255_SCALARBYTES);
  for(int k=0;k<threshold;k++) {
#ifndef UNIT_TEST
    if(k!=0 || secret==NULL) crypto_core_ristretto255_scalar_random(a[k]);
    crypto_core_ristretto255_scalar_random(b[k]);
#else
    if(k!=0 || secret==NULL) debian_rng_scalar(a[k]);
    dump(a[k],crypto_core_ristretto255_SCALARBYTES,"a[%d] ", k);
    debian_rng_scalar(b[k]);
    dump(b[k],crypto_core_ristretto255_SCALARBYTES,"b[%d] ", k);
#endif
  }

  if(blind!=NULL) {
    memcpy(blind, b[0], crypto_core_ristretto255_SCALARBYTES);
  }

  for(uint8_t j=1;j<=n;j++) {
    //f(x) = a_0 + a_1*x + a_2*x^2 + a_3*x^3 + ⋯ + a_(t)*x^(t)
    polynom(j, threshold, a, &shares[j-1][0]);
    //f'(x) = b_0 + b_1*x + b_2*x^2 + b_3*x^3 + ⋯ + b_(t)*x^(t)
    polynom(j, threshold, b, &shares[j-1][1]);

    if(0!=dkg_vss_commit(shares[j-1][0].value, shares[j-1][1].value, commitments[j-1])) return 1;
  }

  return 0;
}

int dkg_vss_verify_commitment(const uint8_t commitment[crypto_core_ristretto255_BYTES],
                              const TOPRF_Share share[2]) {
  uint8_t c[crypto_core_ristretto255_SCALARBYTES];
  if(0!=dkg_vss_commit(share[0].value, share[1].value, c)) return 1;
  if(sodium_memcmp(c,commitment,sizeof c)!=0) return 1;
  return 0;
}

int dkg_vss_finish(const uint8_t n,
                    const uint8_t qual[n],
                    const TOPRF_Share shares[n][2],
                    const uint8_t self,
                    TOPRF_Share share[2],
                    uint8_t commitment[crypto_core_ristretto255_BYTES]) {
  memset(share[0].value, 0, crypto_core_ristretto255_SCALARBYTES);
  memset(share[1].value, 0, crypto_core_ristretto255_SCALARBYTES);
  for(int i=0;qual[i] && i<n;i++) {
    // todo should we assert that there are no duplicate indexes in qual?
    if(self!=shares[qual[i]-1][0].index) {
      fprintf(stderr, "\x1b[0;31mbad share i=%d qual[i]=%d, index=%d\x1b[0m\n", i, qual[i], shares[qual[i]-1][0].index);
    }
    crypto_core_ristretto255_scalar_add(share[0].value, share[0].value, shares[qual[i]-1][0].value);
    //dump((uint8_t*)&shares[qual[i]-1][0], sizeof(TOPRF_Share), "s[%d,%d] ", qual[i], self);
    crypto_core_ristretto255_scalar_add(share[1].value, share[1].value, shares[qual[i]-1][1].value);
    //dump((uint8_t*)&shares[qual[i]-1][1], sizeof(TOPRF_Share), "S[%d,%d] ", qual[i], self);
  }
  //dump(xi->value, crypto_core_ristretto255_SCALARBYTES, "x[%d]     ", self);
  //dump(x_i->value, crypto_core_ristretto255_SCALARBYTES, "x'[%d]    ", self);
  if(0!=dkg_vss_commit(share[0].value, share[1].value, commitment)) return 1;
  return 0;
}

static void sort_shares(const int n, uint8_t arr[n], uint8_t indexes[n]) {
  for (uint8_t c = 1 ; c <= n - 1; c++) {
    uint8_t d = c, t, t1;
    while(d > 0 && arr[d] < arr[d-1]) {
      t = arr[d];
      t1 = indexes[d];
      arr[d] = arr[d-1];
      indexes[d] = indexes[d-1];
      arr[d-1] = t;
      indexes[d-1] = t1;
      d--;
    }
  }
}

int dkg_vss_reconstruct(const uint8_t t,
                        const uint8_t x,
                        const size_t shares_len,
                        const TOPRF_Share shares[shares_len][2],
                        const uint8_t commitments[shares_len][crypto_scalarmult_ristretto255_BYTES],
                        uint8_t result[crypto_scalarmult_ristretto255_SCALARBYTES],
                        uint8_t blind[crypto_scalarmult_ristretto255_SCALARBYTES]) {
  if(shares_len>128) return 1;
  uint8_t qual[t];
  uint8_t indexes[t];
  unsigned j=0;
  for(uint8_t i=0;i<shares_len && j<t;i++) {
    if(commitments != NULL && dkg_vss_verify_commitment(commitments[i],shares[i])!=0) continue;
    qual[j]=shares[i][0].index;
    indexes[j++]=i;
  }
  if(j<t) return 1;
  sort_shares(t, qual, indexes);

  TOPRF_Share si[t];
  for(unsigned i=0;i<t;i++) {
    memcpy(&si[i], &shares[indexes[i]], TOPRF_Share_BYTES);
    //dump((uint8_t*) &si[i], TOPRF_Share_BYTES, "s%d", i);
  }
  interpolate(x, t, si, result);
  if(blind!=NULL) {
    for(unsigned i=0;i<t;i++) {
      memcpy(&si[i], &shares[indexes[i]][1], TOPRF_Share_BYTES);
      //dump((uint8_t*) &si[i], TOPRF_Share_BYTES, "s%d", i);
    }
    interpolate(x, t, si, blind);
  }
  return 0;
}
