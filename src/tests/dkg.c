#include <string.h>
#include "dkg.h"
#include "toprf.h"
#include "utils.h"

extern int debug;

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

    fprintf(stderr, "\e[0;32mP_%d stage 1 correct!\e[0m\n", i);

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
