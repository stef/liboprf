#include <string.h>
#include "dkg.h"
#include "toprf.h"
#include "utils.h"

extern int liboprf_debug;

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
  liboprf_debug = 1;
  uint8_t n=5, threshold=3;
  uint8_t commitments[n][threshold][crypto_core_ristretto255_BYTES];
  TOPRF_Share shares[n][n];

  for(int i=0;i<n;i++) {
    if(dkg_start(n, threshold, commitments[i], shares[i])) {
      return 1;
    }
    if(liboprf_debug) {
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

  for(int i=0;i<n;i++) {
    for(int j=0;j<n;j++) {
      memcpy(&sent_shares[j], &shares[j][i], sizeof(TOPRF_Share));
      if(liboprf_debug) {
         fprintf(stderr, "\nsent to peer %d\n",i+1);
         dump((uint8_t*) &sent_shares[j], sizeof(TOPRF_Share), "s[%d,%d] ", i+1, j+1);
      }
    }

    uint8_t fails[n];
    memset(fails, 0, sizeof fails);
    uint8_t fails_len=0;

    // verify step (2)
    if(dkg_verify_commitments(n,threshold,i+1, commitments,
                              sent_shares, fails, &fails_len)) {
      for(int j=0;j<fails_len;j++) {
         fprintf(stderr,"\e[0;31m[%d] failed to verify commitments from %d!\e[0m\n", i+1, fails[j]);
      }
      return 1;
    }

    fprintf(stderr, "\e[0;32mP_%d stage 1 correct!\e[0m\n", i);

    final_shares[i].index=i+1;
    // finalize dkg (3)
    dkg_finish(n,sent_shares,i+1,&final_shares[i]);
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
