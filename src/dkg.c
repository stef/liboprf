#include <sodium.h>
#include <stdint.h>
#include <string.h>
#include "toprf.h"
#include "utils.h"

typedef struct {
  uint8_t index;
  uint8_t value[crypto_core_ristretto255_SCALARBYTES];
} __attribute((packed)) TOPRF_Share;

#ifdef UNIT_TEST
extern int debug;
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
                   const TOPRF_Share shares[n]);
#endif // UNIT_TEST

int dkg_start(const uint8_t n,
              const uint8_t threshold,
              const uint8_t sk[crypto_sign_SECRETKEYBYTES],
              uint8_t commitment_hash[crypto_generichash_BYTES],
              uint8_t signed_commitments[crypto_sign_BYTES+(threshold*crypto_core_ristretto255_BYTES)],
              TOPRF_Share shares[n],
              crypto_generichash_state *transcript) {

  crypto_generichash_init(transcript, NULL, 0, crypto_generichash_BYTES);
  crypto_generichash_update(transcript, &n, 1);
  crypto_generichash_update(transcript, &threshold, 1);

  uint8_t a[threshold][crypto_core_ristretto255_SCALARBYTES];
  uint8_t commitments[threshold][crypto_core_ristretto255_BYTES];
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

  // compute hash of commitments
  crypto_generichash(commitment_hash, crypto_generichash_BYTES,
                     (const uint8_t*) commitments, threshold * crypto_core_ristretto255_BYTES,
                     NULL, 0);

  // sign commitments
  unsigned long long sc_len;
  crypto_sign(signed_commitments, &sc_len, (uint8_t*) commitments, sizeof commitments, sk);
  if(sc_len!=crypto_sign_BYTES+(threshold*crypto_core_ristretto255_BYTES)) {
    sodium_munlock(a,sizeof a);
    return 1;
  }

  // calculate shares s_ij
  for(uint8_t j=1;j<=n;j++) {
    //f(x) = a_0 + a_1*x + a_2*x^2 + a_3*x^3 + ⋯ + a_(t)*x^(t)
    polynom(j, threshold, a, &shares[j-1]);
  }

#ifdef UNIT_TEST
  if(test_dkg_start(n, a[0], shares)) {
    sodium_munlock(a,sizeof a);
    return 1;
  }
#endif // UNIT_TEST

  sodium_munlock(a,sizeof a);

  return 0;
}

int dkg_verify_commitments(const uint8_t n,
                           const uint8_t threshold,
                           const uint8_t self,
                           const uint8_t commitment_hashes[n][crypto_generichash_BYTES],
                           const uint8_t signed_commitments[n][crypto_sign_BYTES+(threshold*crypto_core_ristretto255_BYTES)],
                           const uint8_t pk[n][crypto_sign_PUBLICKEYBYTES],
                           const TOPRF_Share shares[n],
                           uint8_t failed_sigs[n],
                           uint8_t *failed_sigs_len,
                           uint8_t failed_hashes[n],
                           uint8_t *failed_hashes_len,
                           uint8_t complaints[n],
                           uint8_t *complaints_len,
                           crypto_generichash_state *transcript) {
  *failed_hashes_len = 0;
  *failed_sigs_len = 0;

  crypto_generichash_update(transcript, (uint8_t*) commitment_hashes, n*crypto_generichash_BYTES);
  crypto_generichash_update(transcript, (uint8_t*) signed_commitments, n*crypto_sign_BYTES+(threshold*crypto_core_ristretto255_BYTES));
  crypto_generichash_update(transcript, (uint8_t*) pk, n*crypto_sign_PUBLICKEYBYTES);

  // verify sigs and hashes
  uint8_t commitments[n][threshold][crypto_core_ristretto255_BYTES];
  for(unsigned i=0;i<n;i++) {

    unsigned long long m_len;
    if (crypto_sign_open((uint8_t*) commitments[i], &m_len,
                         signed_commitments[i], crypto_sign_BYTES+(threshold*crypto_core_ristretto255_BYTES),
                         pk[i]) != 0) {
      failed_sigs[(*failed_sigs_len)++]=(uint8_t) i;
    }

    // verify hash
    uint8_t commitment_hash[crypto_generichash_BYTES];
    crypto_generichash(commitment_hash, crypto_generichash_BYTES,
                       (const uint8_t*) commitments[i], threshold * crypto_core_ristretto255_BYTES,
                       NULL, 0);

    if(sodium_memcmp(commitment_hash, commitment_hashes[i], sizeof commitment_hash) != 0) {
      failed_hashes[(*failed_hashes_len)++]=(uint8_t) i;
    }
  }
  if(*failed_sigs_len != 0 || *failed_hashes_len != 0) return -1;

#ifdef UNIT_TEST
  if(debug) fprintf(stderr, "\e[0;32m[%d] commitment hashes and sigs ok \e[0m\n", self);
#endif //UNIT_TEST

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
       dump(tmp, sizeof tmp, "%d tmp", k);
       dump(commitments[i-1][k], crypto_core_ristretto255_BYTES, "c[%d][%d]", i-1, k);
       if(crypto_scalarmult_ristretto255(tmP, tmp, commitments[i-1][k])) return 1;
      crypto_core_ristretto255_add(v1,v1,tmP);
    }

    // v0 == v1
    if(sodium_memcmp(v0,v1,sizeof v1)!=0) {
      // complain about P_i
      fprintf(stderr, "\e[0;31mfailed to verify contribs of P_%d in stage 1\e[0m\n", i);
      complaints[(*complaints_len)++]=(uint8_t) i;
      //return 1;
    } else {
#ifdef UNIT_TEST
      if(debug) fprintf(stderr, "\e[0;32mP_%d stage 1 correct!\e[0m\n", i);
#endif // UNIT_TEST
    }
  }
  if(*complaints_len!=0) return 1;

  return 0;
}

void dkg_finish(const uint8_t n,
                const TOPRF_Share shares[n],
                const uint8_t self,
                const uint8_t sk[crypto_sign_SECRETKEYBYTES],
                crypto_generichash_state *transcript,
                TOPRF_Share *xi,
                uint8_t final_message[1+crypto_generichash_BYTES+crypto_sign_BYTES]) {
  memset(xi->value, 0, crypto_core_ristretto255_SCALARBYTES);
  for(int i=0;i<n;i++) {
    if(self!=shares[i].index) {
      fprintf(stderr, "\e[0;31mbad share i=%d index=%d\e[0m\n", i, shares[i].index);
    }
    crypto_core_ristretto255_scalar_add(xi->value, xi->value, shares[i].value);
    //dump((uint8_t*)&shares[i][0], sizeof(TOPRF_Share), "s[%d,%d] ", qual[i], self);
  }
  //dump(xi->value, crypto_core_ristretto255_SCALARBYTES, "x[%d]     ", self);

  final_message[crypto_sign_BYTES]=0;
  crypto_generichash_final(transcript, &final_message[1+crypto_sign_BYTES], crypto_generichash_BYTES);
  unsigned long long sc_len;
  crypto_sign(final_message, &sc_len, &final_message[crypto_sign_BYTES], 1+crypto_generichash_BYTES, sk);
}

int dkg_agree(const uint8_t n,
              const uint8_t pks[n][crypto_sign_PUBLICKEYBYTES],
              const uint8_t final_messages[n][1+crypto_generichash_BYTES+crypto_sign_BYTES]) {
  int ret = 0;
  uint8_t final_message_opened[n][1+crypto_generichash_BYTES];
  for(int i=0;i<n;i++) {
    unsigned long long m_len;
    if (crypto_sign_open((uint8_t*) final_message_opened[i], &m_len,
                         final_messages[i], crypto_sign_BYTES+1+crypto_generichash_BYTES, pks[i]) != 0) {
      fprintf(stderr,"\e[0;31mfailed to verify transcript from %d!\e[0m\n", i+1);
      ret = 1;
    }
  }
  for(int i=1;i<n;i++) {
    if(memcmp(final_message_opened[i], final_message_opened[i-1], 33) !=0) {
      fprintf(stderr,"\e[0;31mtranscript disagreement between %d and %d!\e[0m\n", i, i+1);
      ret = 1;
    }
  }

  return ret;
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
                          const TOPRF_Share shares[n]) {
  const size_t response_len = 3;
  uint8_t responses[response_len][TOPRF_Part_BYTES];
  uint8_t result[crypto_scalarmult_ristretto255_BYTES];
  uint8_t v[crypto_scalarmult_ristretto255_BYTES];

  topart((TOPRF_Part *) responses[0], &shares[4]);
  topart((TOPRF_Part *) responses[1], &shares[2]);
  topart((TOPRF_Part *) responses[2], &shares[0]);

  if(toprf_thresholdmult(response_len, responses, result)) return 1;

  crypto_scalarmult_ristretto255_base(v, a);

  if(memcmp(v,result,sizeof v)!=0) {
    fprintf(stderr,"\e[0;31mmeh!\e[0m\n");
    dump(v,sizeof v, "v");
    dump(result,sizeof v, "r");
    return 1;
  }
  return 0;
}

static int test_dkg_finish(const uint8_t n, const TOPRF_Share shares[n]) {
  const size_t response_len = 3;
  uint8_t responses[response_len][TOPRF_Part_BYTES];
  uint8_t v0[crypto_scalarmult_ristretto255_BYTES]={0};
  uint8_t v1[crypto_scalarmult_ristretto255_BYTES]={0};

  //dump((uint8_t*) &shares[4], sizeof(TOPRF_Share), "&shares[4][0] ");
  topart((TOPRF_Part *) responses[0], &shares[4]);
  topart((TOPRF_Part *) responses[1], &shares[2]);
  topart((TOPRF_Part *) responses[2], &shares[0]);
  //topart((TOPRF_Part *) responses[3], &shares[1][0]);
  //topart((TOPRF_Part *) responses[4], &shares[3][0]);
  if(toprf_thresholdmult(response_len, responses, v0)) return 1;
  dump(v0,sizeof v0, "v0 ");

  topart((TOPRF_Part *) responses[0], &shares[3]);
  topart((TOPRF_Part *) responses[1], &shares[1]);
  topart((TOPRF_Part *) responses[2], &shares[0]);
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
  debug = 1;
  uint8_t n=5, threshold=3;
  uint8_t commitments[n][threshold][crypto_core_ristretto255_BYTES];
  TOPRF_Share shares[n][n];

  uint8_t commitment_hash[n][crypto_generichash_BYTES];
  uint8_t signed_commitments[n][crypto_sign_BYTES+(threshold*crypto_core_ristretto255_BYTES)];
  crypto_generichash_state transcripts[n];
  unsigned char pks[n][crypto_sign_PUBLICKEYBYTES];
  unsigned char sks[n][crypto_sign_SECRETKEYBYTES];
  for(int i=0;i<n;i++) {
    crypto_sign_keypair(pks[i], sks[i]);
  }

  for(int i=0;i<n;i++) {
    if(dkg_start(n, threshold, sks[i], commitment_hash[i], signed_commitments[i], shares[i], &transcripts[i])) {
      return 1;
    }
    if(debug) {
      for(int j=0;j<n;j++) {
        dump((uint8_t*) &shares[i][j], sizeof(TOPRF_Share), "s[%d,%d] ", i+1, j+1);
      }
      fprintf(stderr,"\n");
    }
  }

  // each Pi sends s_ij, and s'_ij to Pj
  // basically we are transposing here the shares matrix above
  TOPRF_Share sent_shares[n];
  TOPRF_Share final_shares[n];
  uint8_t final_messages[n][1+crypto_generichash_BYTES+crypto_sign_BYTES];
  memset(final_messages,1,sizeof final_messages);

  for(int i=0;i<n;i++) {
    for(int j=0;j<n;j++) {
      memcpy(&sent_shares[j], &shares[j][i], sizeof(TOPRF_Share));
      if(debug) {
         fprintf(stderr, "\nsent to peer %d\n",i+1);
         dump((uint8_t*) &sent_shares[j], sizeof(TOPRF_Share), "s[%d,%d] ", i+1, j+1);
      }
    }

    uint8_t complaints[n];
    memset(complaints, 0, sizeof complaints);
    uint8_t complaints_len=0;
    uint8_t failed_sigs[n];
    memset(failed_sigs, 0, sizeof failed_sigs);
    uint8_t failed_sigs_len;
    uint8_t failed_hashes[n];
    memset(failed_hashes, 0, sizeof failed_hashes);
    uint8_t failed_hashes_len;

    // verify step (2)
    if(dkg_verify_commitments(n,threshold,i+1,commitment_hash, signed_commitments,
                              pks, sent_shares, failed_sigs, &failed_sigs_len,
                              failed_hashes, &failed_hashes_len,
                              complaints, &complaints_len, &transcripts[i])) {

      if(failed_sigs_len==0) {
        fprintf(stderr, "\e[0;32m[%d] all sigs ok\e[0m\n", i+1);
      } else {
        for(int j=0;j<failed_sigs_len;j++) {
          fprintf(stderr,"\e[0;31m[%d]failed to verify signatures of commitments from %d!\e[0m\n", i+1, failed_sigs[j]);
        }
      }
      if(failed_hashes_len==0) {
        fprintf(stderr, "\e[0;32m[%d] all hashes ok\e[0m\n", i+1);
      } else {
        for(int j=0;j<failed_hashes_len;j++) {
          fprintf(stderr,"\e[0;31m[%d]failed to verify hashes of commitments from %d!\e[0m\n", i+1, failed_hashes[j]);
        }
      }
      if(complaints_len==0) {
        fprintf(stderr, "\e[0;32m[%d] no complaints\e[0m\n", i+1);
      } else {
        for(int j=0;j<failed_hashes_len;j++) {
          fprintf(stderr,"\e[0;31m[%d] has complaints about %d!\e[0m\n", i+1, complaints[j]);
        }
      }
      return 1;
    }

    final_shares[i].index=i+1;
    // finalize dkg (3)
    dkg_finish(n,sent_shares,i+1,sks[i], &transcripts[i], &final_shares[i], final_messages[i]);
  }

  // final step (4)
  int abort = 0;
  for(int i=0;i<n;i++) {
    if(dkg_agree(n, pks, final_messages)!=0) {
      fprintf(stderr,"\e[0;31mpeer %d aborts!\e[0m\n", i+1);
      abort=1;
    }
  }
  if(abort==0) {
    fprintf(stderr, "\e[0;32mDKG sucessful, all peers agree\e[0m\n");
  }

  for(int i=0;i<n;i++) {
    dump((uint8_t*) &final_messages[i], 97, "final_messages[%d]", i+1);
  }

  for(int i=0;i<n;i++) {
    dump((uint8_t*) &final_shares[i], sizeof(TOPRF_Share), "final_shares[%d]", i+1);
  }

  if(test_dkg_finish(n, final_shares)) return 1;

  // x = sum(a[0]) == 0x28 if debian_rng_scalar is used
  uint8_t x[crypto_core_ristretto255_BYTES]={0x28};
  if(test_dkg_start(n, x, final_shares)) return 1;

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
