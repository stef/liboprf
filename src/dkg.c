#include <sodium.h>
#include <stdint.h>
#include <string.h>
#include "toprf.h"
#include "utils.h"
#include "dkg.h"

static void polynom(const uint8_t j, const uint8_t threshold,
                    const uint8_t a[threshold][crypto_core_ristretto255_SCALARBYTES],
                    TOPRF_Share *result) {
  //f(z) = a_0 + a_1*z + a_2*z^2 + a_3*z^3 + ⋯ + (a_t)*(z^t)
  result->index=j;
  // f(z) = result = a[0] +.....
  memcpy(result->value, a[0], crypto_core_ristretto255_SCALARBYTES);

  // z = j
  uint8_t z[crypto_core_ristretto255_SCALARBYTES]={j};
  // z^t ->
  for(int t=1;t<threshold;t++) {
    // tmp = 1
    uint8_t tmp[crypto_core_ristretto255_SCALARBYTES]={1};
    for(int exp=1;exp<=t;exp++) {
      // tmp *= z
      crypto_core_ristretto255_scalar_mul(tmp, tmp, z);
    }
    // a[t] * z^t
    crypto_core_ristretto255_scalar_mul(tmp, a[t], tmp);
    // add into result
    crypto_core_ristretto255_scalar_add(result->value, result->value, tmp);
  }
}

int dkg_start(const uint8_t n,
              const uint8_t threshold,
              uint8_t commitments[threshold][crypto_core_ristretto255_BYTES],
              TOPRF_Share shares[n]) {

  uint8_t a[threshold][crypto_core_ristretto255_SCALARBYTES];
  if(0!=sodium_mlock(a,sizeof a)) {
    return -1;
  }

  for(int k=0;k<threshold;k++) {
#ifndef UNIT_TEST
    crypto_core_ristretto255_scalar_random(a[k]);
#else
    debian_rng_scalar(a[k]);
    dump(a[k],crypto_core_ristretto255_SCALARBYTES,"a[%d] ", k);
#endif

    // compute commitments
    // A_ik = g^a_ik
    crypto_scalarmult_ristretto255_base(commitments[k], a[k]);
  }

  // calculate shares s_ij
  for(uint8_t j=1;j<=n;j++) {
    //f(x) = a_0 + a_1*x + a_2*x^2 + a_3*x^3 + ⋯ + a_(t)*x^(t)
    polynom(j, threshold, a, &shares[j-1]);
  }

  sodium_munlock(a,sizeof a);

  return 0;
}

int dkg_verify_commitments(const uint8_t n,
                           const uint8_t threshold,
                           const uint8_t self,
                           const uint8_t commitments[n][threshold][crypto_core_ristretto255_BYTES],
                           const TOPRF_Share shares[n],
                           uint8_t fails[n],
                           uint8_t *fails_len) {
  *fails_len = 0;

  uint8_t j[crypto_core_ristretto255_SCALARBYTES]={self};
  //dump(j,sizeof(j), "\nj        ");

  for(unsigned i=1;i<=n;i++) {
    if(i==self) continue;
    uint8_t v0[crypto_core_ristretto255_BYTES];

    // v0 = g*(s_ij)
    //dump((uint8_t*)&shares[i-1], sizeof(TOPRF_Share), "s(%d,%d) ", i, self);
    // g*(s_ij)
    crypto_scalarmult_ristretto255_base(v0, shares[i-1].value);

    // v1=sum(C_ik*j*k for k=0..t)
    uint8_t v1[crypto_core_ristretto255_BYTES];
    //dump(commitments[i-1],crypto_core_ristretto255_BYTES, "c(%d,%d)   ", i, 0);
    // v1 = C_i0*j
    memcpy(v1, &commitments[i-1][0], sizeof v1);
    // sum
    for(uint8_t k=1;k<threshold;k++) {
      uint8_t tmp[crypto_core_ristretto255_SCALARBYTES];
       memcpy(tmp, j, sizeof j); // tmp = j^1
       for(int exp=1;exp<k;exp++) {
          // tmp *= j
          crypto_core_ristretto255_scalar_mul(tmp, tmp, j);
       }
       uint8_t tmP[crypto_core_ristretto255_BYTES];
       dump(tmp, sizeof tmp, "%d tmp", k);
       dump(commitments[i-1][k], crypto_core_ristretto255_BYTES, "c[%d][%d]", i-1, k);
       if(crypto_scalarmult_ristretto255(tmP, tmp, commitments[i-1][k])) return 1;
      crypto_core_ristretto255_add(v1,v1,tmP);
    }

    // v0 == v1
    if(sodium_memcmp(v0,v1,sizeof v1)!=0) {
      // complain about P_i
      if(debug) fprintf(stderr, "\e[0;31mfailed to verify contribs of P_%d in stage 1\e[0m\n", i);
      fails[(*fails_len)++] = (uint8_t) i;
      //return 1;
    }
  }
  if(*fails_len!=0) return 1;

  return 0;
}

void dkg_finish(const uint8_t n,
                const TOPRF_Share shares[n],
                const uint8_t self,
                TOPRF_Share *xi) {
  memset(xi->value, 0, crypto_core_ristretto255_SCALARBYTES);
  for(int i=0;i<n;i++) {
    if(self!=shares[i].index) {
      if(debug) fprintf(stderr, "\e[0;31mbad share i=%d index=%d\e[0m\n", i, shares[i].index);
    }
    crypto_core_ristretto255_scalar_add(xi->value, xi->value, shares[i].value);
    //dump((uint8_t*)&shares[i][0], sizeof(TOPRF_Share), "s[%d,%d] ", qual[i], self);
  }
  //dump(xi->value, crypto_core_ristretto255_SCALARBYTES, "x[%d]     ", self);
}

void dkg_reconstruct(const size_t response_len,
                     const TOPRF_Share responses[response_len],
                     uint8_t result[crypto_scalarmult_ristretto255_BYTES]) {
  uint8_t lpoly[crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t tmp[crypto_scalarmult_ristretto255_SCALARBYTES];
  memset(result,0,crypto_scalarmult_ristretto255_BYTES);

  uint8_t indexes[response_len];
  for(size_t i=0;i<response_len;i++) {
    indexes[i]=responses[i].index;
  }
  for(size_t i=0;i<response_len;i++) {
    coeff(responses[i].index, response_len, indexes, lpoly);
    crypto_core_ristretto255_scalar_mul(tmp, responses[i].value, lpoly);
    crypto_core_ristretto255_scalar_add(result, result, tmp);
  }
}
