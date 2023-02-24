#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sodium.h>

extern int debug;

void debian_rng_scalar(uint8_t *scalar) {
  static uint8_t rng_i=2;
  memset(scalar,0,crypto_core_ristretto255_SCALARBYTES);
  scalar[0]=rng_i++;
  //static uint16_t rng_i=0;
  //uint16_t tmp[64 / sizeof(uint16_t)];
  //for(unsigned j=0;j<(64/ sizeof(uint16_t));j++) {
  //  tmp[j]=rng_i++;
  //}
  //crypto_core_ristretto255_scalar_reduce(scalar,(uint8_t*)tmp);
}

void dump(const uint8_t *p, const size_t len, const char* msg, ...) {
  if(!debug) return;
  va_list args;
  va_start(args, msg);
  vfprintf(stderr,msg, args);
  va_end(args);
  for(size_t i=0;i<len;i++)
    fprintf(stderr,"%02x", p[i]);
  fprintf(stderr,"\n");
}

void fail(char* msg, ...) {
  va_list args;
  va_start(args, msg);
  fprintf(stderr, "\e[0;31m");
  vfprintf(stderr, msg, args);
  va_end(args);
  fprintf(stderr, "\e[0m\n");
}
