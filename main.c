#include <sss.h>
#include <stdio.h>
#include <string.h>

#include "oprf.h"
#include "toprf.h"

static void dump(const uint8_t *p, const size_t len, const char* msg) {
  size_t i;
  fprintf(stderr,"%s ",msg);
  for(i=0;i<len;i++)
    fprintf(stderr,"%02x", p[i]);
  fprintf(stderr,"\n");
}

int main(void) {
  int err;
  const unsigned servers = 10;
  const uint8_t password[8]="password";
  uint8_t r[servers][crypto_core_ristretto255_SCALARBYTES];
  uint8_t alphas[servers][crypto_core_ristretto255_BYTES];

  // setup phase
  // run N OPRF instantiations in parallel
  err = toprf_init(servers, password, sizeof password, r, alphas);
  if(err) return err;

  // send each alpha to one of the configures oprf servers
  // each generates a new key, and evaluates the alpha into a beta
  uint8_t keys[servers][crypto_core_ristretto255_SCALARBYTES];
  uint8_t betas[servers][crypto_core_ristretto255_BYTES];
  unsigned i;
  for(i=0;i<servers;i++) {
    oprf_KeyGen(keys[i]);
    err = oprf_Evaluate(keys[i], alphas[i], betas[i]);
    if(err) return err;
  }
  // each server sends back it's beta

  sss_Share shares[servers];
  uint8_t result0[sss_MLEN];

  err = toprf_share(servers, 2,
                    password, sizeof password,
                    r, betas, shares, result0);

  // Protocol run phase
  // blind your input secret N times, and run OPRF with each OPRF server
  err = toprf_init(servers, password, sizeof password, r, alphas);
  if(err) return err;

  // each server seperately evaluates
  for(i=0;i<servers;i++) {
    err = oprf_Evaluate(keys[i], alphas[i], betas[i]);
    if(err) return err;
  }

  uint8_t result1[sss_MLEN];
  err = toprf_recover(2,
                      password, sizeof password,
                      r, betas, shares, result1);
  if(err) return err;

  if(memcmp(result0,result1,sss_MLEN)!=0) return 1;

  return 0;
}
