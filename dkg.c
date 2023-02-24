#include <sodium.h>
#include <stdint.h>
#include <string.h>
#include "toprf.h"
#include "utils.h"

typedef struct {
  uint8_t index;
  uint8_t value[crypto_core_ristretto255_SCALARBYTES];
} __attribute((packed)) TOPRF_Share;

// nothing up my sleeve generator H, generated with:
// hash_to_group((uint8_t*)"DKG Generator H on ristretto255", 32, H)
static const uint8_t H[crypto_core_ristretto255_BYTES]= {
  0x66, 0x4e, 0x4c, 0xb5, 0x89, 0x0e, 0xb3, 0xe4,
  0xc0, 0xd5, 0x48, 0x02, 0x74, 0x8a, 0xb2, 0x25,
  0xf9, 0x73, 0xda, 0xe5, 0xc0, 0xef, 0xc1, 0x68,
  0xf4, 0x4d, 0x1b, 0x60, 0x28, 0x97, 0x8f, 0x07};

#ifdef UNIT_TEST
const int debug=1;
#endif //UNIT_TEST

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

#ifdef UNIT_TEST
static int test_dkg_start(const uint8_t n,
                   const uint8_t a[crypto_core_ristretto255_SCALARBYTES],
                   const uint8_t b[crypto_core_ristretto255_SCALARBYTES],
                   const TOPRF_Share shares[n][2]);
#endif // UNIT_TEST

int dkg_start(const uint8_t n,
              const uint8_t threshold,
              uint8_t commitments[threshold][crypto_core_ristretto255_BYTES],
              TOPRF_Share shares[n][2]) {
  uint8_t a[threshold][crypto_core_ristretto255_SCALARBYTES];
  uint8_t b[threshold][crypto_core_ristretto255_SCALARBYTES];
  for(int k=0;k<threshold;k++) {
#ifndef UNIT_TEST
    crypto_core_ristretto255_scalar_random(a[k]);
    crypto_core_ristretto255_scalar_random(b[k]);
#else
    debian_rng_scalar(a[k]);
    dump(a[k],crypto_core_ristretto255_SCALARBYTES,"a[%d] ", k);
    debian_rng_scalar(b[k]);
    dump(b[k],crypto_core_ristretto255_SCALARBYTES,"b[%d] ", k);
#endif

    // compute commitments
    uint8_t x[crypto_core_ristretto255_BYTES];
    uint8_t r[crypto_core_ristretto255_BYTES];
    // x = g^a_ik
    crypto_scalarmult_ristretto255_base(x, a[k]);
    // r = h^b_ik
    if(crypto_scalarmult_ristretto255(r, b[k], H)) return 1;
    // C_ik = x+r
    crypto_core_ristretto255_add(commitments[k],x,r);
    //dump((uint8_t*) &commitments[k],crypto_core_ristretto255_BYTES, "c[%d]     ", k);
  }

  for(int j=1;j<=n;j++) {
    //f(x) = a_0 + a_1*x + a_2*x^2 + a_3*x^3 + ⋯ + a_(t)*x^(t)
    polynom(j, threshold, a, &shares[j-1][0]);
    //f'(x) = b_0 + b_1*x + b_2*x^2 + b_3*x^3 + ⋯ + b_(t)*x^(t)
    polynom(j, threshold, b, &shares[j-1][1]);
  }

#ifdef UNIT_TEST
  if(test_dkg_start(n, a[0], b[0], shares)) return 1;
#endif // UNIT_TEST

  return 0;
}

int dkg_verify_commitments(const uint8_t n,
                           const uint8_t threshold,
                           const uint8_t self,
                           const uint8_t commitments[n][threshold][crypto_core_ristretto255_BYTES],
                           const TOPRF_Share shares[n][2],
                           uint8_t complaints[n],
                           uint8_t *complaints_len) {
  uint8_t j[crypto_core_ristretto255_SCALARBYTES]={self};
  //dump(j,sizeof(j), "\nj        ");

  for(uint8_t i=1;i<=n;i++) {
    if(i==self) continue;
    uint8_t x[crypto_core_ristretto255_BYTES];
    uint8_t r[crypto_core_ristretto255_BYTES];
    uint8_t v0[crypto_core_ristretto255_BYTES];

    // v0 = g*(s_ij) + h*(s'_ij)
    //dump((uint8_t*)&shares[i-1][0], sizeof(TOPRF_Share), "s(%d,%d) ", i, self);
    // g*(s_ij)
    crypto_scalarmult_ristretto255_base(x, shares[i-1][0].value);
    //dump((uint8_t*)&shares[i-1][1], sizeof(TOPRF_Share), "S(%d,%d) ", i, self);
    // h*(s'_ij)
    if(crypto_scalarmult_ristretto255(r, shares[i-1][1].value, H)) return 1;
    // v0 = x + r
    crypto_core_ristretto255_add(v0,x,r);

    // v1=sum(C_ik*j*k for k=0..t)
    uint8_t v1[crypto_core_ristretto255_BYTES];
    //dump(commitments[i-1][0],crypto_core_ristretto255_BYTES, "c(%d,%d)   ", i, 0);
    // v1 = C_i0*j
    memcpy(v1, commitments[i-1][0], sizeof v1);
    // sum
    for(uint8_t k=1;k<threshold;k++) {
      uint8_t tmp[crypto_core_ristretto255_SCALARBYTES];
       memcpy(tmp, j, sizeof j); // tmp = j^1
       for(int exp=1;exp<k;exp++) {
          // tmp *= j
          crypto_core_ristretto255_scalar_mul(tmp, tmp, j);
       }
       uint8_t tmP[crypto_core_ristretto255_BYTES];
       if(crypto_scalarmult_ristretto255(tmP, tmp, commitments[i-1][k])) return 1;
      crypto_core_ristretto255_add(v1,v1,tmP);
    }

    // v0 == v1
    if(sodium_memcmp(v0,v1,sizeof v1)!=0) {
      // complain about P_i
      fprintf(stderr, "\e[0;31mfailed to verify contribs of P_%d in stage 1\e[0m\n", i);
      complaints[*complaints_len++]=i;
      //return 1;
    } else {
#ifdef UNIT_TEST
      if(debug) fprintf(stderr, "\e[0;32mP_%d stage 1 correct!\e[0m\n", i);
#endif // UNIT_TEST
    }
  }
  return 0;
}

void dkg_finish(const uint8_t n,
                const uint8_t qual[n],
                const TOPRF_Share shares[n][2],
                const uint8_t self,
                TOPRF_Share *xi,
                TOPRF_Share *x_i) {
  memset(xi->value, 0, crypto_core_ristretto255_SCALARBYTES);
  memset(x_i->value, 0, crypto_core_ristretto255_SCALARBYTES);
  for(int i=0;qual[i] && i<n;i++) {
    if(self!=shares[qual[i]-1][0].index) {
      fprintf(stderr, "\e[0;31mbad share i=%d qual[i]=%d, index=%d\e[0m\n", i, qual[i], shares[qual[i]-1][0].index);
    }
    crypto_core_ristretto255_scalar_add(xi->value, xi->value, shares[qual[i]-1][0].value);
    //dump((uint8_t*)&shares[qual[i]-1][0], sizeof(TOPRF_Share), "s[%d,%d] ", qual[i], self);
    crypto_core_ristretto255_scalar_add(x_i->value, x_i->value, shares[qual[i]-1][1].value);
    //dump((uint8_t*)&shares[qual[i]-1][1], sizeof(TOPRF_Share), "S[%d,%d] ", qual[i], self);
  }
  //dump(xi->value, crypto_core_ristretto255_SCALARBYTES, "x[%d]     ", self);
  //dump(x_i->value, crypto_core_ristretto255_SCALARBYTES, "x'[%d]    ", self);
}

void dkg_reconstruct(const size_t response_len,
                     const TOPRF_Share responses[response_len][2],
                     uint8_t result[crypto_scalarmult_ristretto255_BYTES]) {
  uint8_t lpoly[crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t tmp[crypto_scalarmult_ristretto255_SCALARBYTES];
  memset(result,0,crypto_scalarmult_ristretto255_BYTES);
  result[0]=0;

  uint8_t indexes[response_len];
  for(size_t i=0;i<response_len;i++) {
    indexes[i]=responses[i][0].index;
  }
  for(size_t i=0;i<response_len;i++) {
    coeff(responses[i][0].index, response_len, indexes, lpoly);
    crypto_core_ristretto255_scalar_mul(tmp, responses[i][0].value, lpoly);
    crypto_core_ristretto255_scalar_add(result, result, tmp);
  }
}

#ifdef UNIT_TEST
typedef struct {
  uint8_t index;
  uint8_t value[crypto_core_ristretto255_BYTES];
} __attribute((packed)) TOPRF_Part;

static void topart(TOPRF_Part *r, const TOPRF_Share *s) {
  r->index=s->index;
  crypto_scalarmult_ristretto255_base(r->value, s->value);
}

static int test_dkg_start(const uint8_t n,
                          const uint8_t a[crypto_core_ristretto255_SCALARBYTES],
                          const uint8_t b[crypto_core_ristretto255_SCALARBYTES],
                          const TOPRF_Share shares[n][2]) {
  const size_t response_len = 3;
  uint8_t responses[response_len][TOPRF_Part_BYTES];
  uint8_t result[crypto_scalarmult_ristretto255_BYTES];
  uint8_t v[crypto_scalarmult_ristretto255_BYTES];

  topart((TOPRF_Part *) responses[0], &shares[4][0]);
  topart((TOPRF_Part *) responses[1], &shares[2][0]);
  topart((TOPRF_Part *) responses[2], &shares[0][0]);

  if(toprf_thresholdmult(response_len, responses, result)) return 1;

  crypto_scalarmult_ristretto255_base(v, a);

  if(memcmp(v,result,sizeof v)!=0) {
    fprintf(stderr,"\e[0;31mmeh!\e[0m\n");
    return 1;
  }

  topart((TOPRF_Part *) responses[0], &shares[4][1]);
  topart((TOPRF_Part *) responses[1], &shares[2][1]);
  topart((TOPRF_Part *) responses[2], &shares[0][1]);
  if(toprf_thresholdmult(response_len, responses, result)) return 1;

  crypto_scalarmult_ristretto255_base(v, b);

  if(memcmp(v,result,sizeof v)!=0) {
    fprintf(stderr,"\e[0;31mfailed to verify shares from dkg_start!\e[0m\n");
    return 1;
  }
  return 0;
}

static int test_dkg_finish(const uint8_t n, const TOPRF_Share shares[n][2]) {
  const size_t response_len = 3;
  uint8_t responses[response_len][TOPRF_Part_BYTES];
  uint8_t v0[crypto_scalarmult_ristretto255_BYTES]={0};
  uint8_t v1[crypto_scalarmult_ristretto255_BYTES]={0};

  dump((uint8_t*) &shares[4][0], sizeof(TOPRF_Share), "&shares[4][0] ");
  topart((TOPRF_Part *) responses[0], &shares[4][0]);
  topart((TOPRF_Part *) responses[1], &shares[2][0]);
  topart((TOPRF_Part *) responses[2], &shares[0][0]);
  //topart((TOPRF_Part *) responses[3], &shares[1][0]);
  //topart((TOPRF_Part *) responses[4], &shares[3][0]);
  if(toprf_thresholdmult(response_len, responses, v0)) return 1;
  dump(v0,sizeof v0, "v0 ");

  topart((TOPRF_Part *) responses[0], &shares[3][0]);
  topart((TOPRF_Part *) responses[1], &shares[1][0]);
  topart((TOPRF_Part *) responses[2], &shares[0][0]);
  //topart((TOPRF_Part *) responses[3], &shares[2][0]);
  //topart((TOPRF_Part *) responses[4], &shares[4][0]);
  if(toprf_thresholdmult(response_len, responses, v1)) return 1;
  dump(v1,sizeof v1, "v1 ");

  if(memcmp(v0,v1,sizeof v1)!=0) {
    fprintf(stderr,"\e[0;31mfailed to verify shares from dkg_finish!\e[0m\n");
    return 1;
  }
  return 0;
}

int main(void) {
  uint8_t n=5, threshold=3;
  uint8_t commitments[n][threshold][crypto_core_ristretto255_BYTES];
  TOPRF_Share shares[n][n][2];

  for(int i=0;i<n;i++) {
    if(dkg_start(n, threshold, commitments[i], shares[i])) {
      return 1;
    }
    if(debug) {
      for(int j=0;j<n;j++) {
        dump((uint8_t*) &shares[i][j][0], sizeof(TOPRF_Share), "s[%d,%d] ", i+1, j+1);
        dump((uint8_t*) &shares[i][j][1], sizeof(TOPRF_Share), "r[%d,%d] ", i+1, j+1);
      }
      fprintf(stderr,"\n");
    }
  }

  // each Pi sends s_ij, and s'_ij to Pj
  // basically we are transposing here the shares matrix above
  TOPRF_Share sent_shares[n][2];
  TOPRF_Share final_shares[n][2];
  for(int i=0;i<n;i++) {
    for(int j=0;j<n;j++) {
      memcpy(&sent_shares[j][0], &shares[j][i][0], sizeof(TOPRF_Share));
      memcpy(&sent_shares[j][1], &shares[j][i][1], sizeof(TOPRF_Share));
    }
    if(debug) {
      fprintf(stderr, "\nsent to peer %d\n",i+1);
      for(int j=0;j<n;j++) {
        dump((uint8_t*) &sent_shares[j][0], sizeof(TOPRF_Share), "s[%d,%d] ", i+1, j+1);
        dump((uint8_t*) &sent_shares[j][1], sizeof(TOPRF_Share), "r[%d,%d] ", i+1, j+1);
      }
    }

    uint8_t complaints[n];
    memset(complaints, 0, sizeof complaints);
    uint8_t complaints_len=0;
    if(dkg_verify_commitments(n,threshold,i+1,commitments,sent_shares,complaints, &complaints_len)) return 1;
    // todo handle complaints, build qual set
    uint8_t qual[n+1];
    for(int i=0;i<n;i++) qual[i]=i+1; //everyone qualifies
    qual[n]=0;
    final_shares[i][0].index=i+1;
    final_shares[i][1].index=i+1;
    // finalize dkg
    dkg_finish(n,qual,sent_shares,i+1,&final_shares[i][0],&final_shares[i][1]);
  }
  for(int i=0;i<n;i++) {
    dump((uint8_t*) &final_shares[i][0], sizeof(TOPRF_Share), "final_shares[%d][0] ", i+1);
    dump((uint8_t*) &final_shares[i][1], sizeof(TOPRF_Share), "final_shares[%d][1] ", i+1);
  }

  if(test_dkg_finish(n, final_shares)) return 1;

  // x = sum(a[0]) == 0x46 if debian_rng_scalar is used
  uint8_t x[crypto_core_ristretto255_BYTES]={0x46};
  // x' = sum(b[0]) == 0x4b if debian_rng_scalar is used
  uint8_t x_[crypto_core_ristretto255_BYTES]={0x4b};
  if(test_dkg_start(n, x, x_, final_shares)) return 1;

  uint8_t v[crypto_core_ristretto255_BYTES];
  dkg_reconstruct(threshold, final_shares, v);
  if(memcmp(v,x,sizeof v)!=0) {
    fprintf(stderr,"\e[0;31mfailed to verify reconstruction of generated x from final shares!\e[0m\n");
    dump(x,sizeof x, "x ");
    dump(v,sizeof v, "v ");
    return 1;
  }

  fprintf(stderr, "\e[0;32meverything correct!\e[0m\n");
  return 0;
}

#endif // UNIT_TEST
