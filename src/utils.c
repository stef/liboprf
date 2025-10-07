#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sodium.h>

#if (defined UNIT_TEST || defined UNITTEST_CORRUPT)
int  liboprf_debug = 1;
#else
int  liboprf_debug = 0;
#endif
FILE *liboprf_log_file=NULL;

#ifdef UNIT_TEST
void debian_rng_scalar(uint8_t *scalar) {
  static int warned=0;
  static uint8_t rng_i[4]={1,0,0,0};
  if(!warned) {
     fprintf(stderr, "\x1b[0;31mWARNING! This version of liboprf DKG is compiled with a *NON* random generator for UNIT_TESTS\x1b[0m\n");
     warned=1;
  }
  memset(scalar,0,crypto_core_ristretto255_SCALARBYTES);
  sodium_increment(rng_i,4);
  memcpy(scalar,rng_i,4);
  //static uint16_t rng_i=0;
  //uint16_t tmp[64 / sizeof(uint16_t)];
  //for(unsigned j=0;j<(64/ sizeof(uint16_t));j++) {
  //  tmp[j]=rng_i++;
  //}
  //crypto_core_ristretto255_scalar_reduce(scalar,(uint8_t*)tmp);
}
#endif

void __attribute__((visibility("hidden"))) dump(const uint8_t *p, const size_t len, const char* msg, ...) {
  FILE* lf = stderr;
  if(!liboprf_debug) return;
  if(liboprf_log_file!=NULL) lf = liboprf_log_file;
  va_list args;
  va_start(args, msg);
  vfprintf(lf, msg, args);
  va_end(args);
  fprintf(lf," ");
  for(size_t i=0;i<len;i++)
    fprintf(lf,"%02x", p[i]);
  fprintf(lf,"\n");
  fflush(lf);
}

void __attribute__((visibility("hidden"))) fail(const char* msg, ...) {
  va_list args;
  va_start(args, msg);
  fprintf(stderr, "\x1b[0;31m");
  vfprintf(stderr, msg, args);
  va_end(args);
  fprintf(stderr, "\x1b[0m\n");
}

#ifndef htonll
#include <arpa/inet.h>
uint64_t __attribute__((visibility("hidden"))) htonll(uint64_t n) {
#if __BYTE_ORDER == __BIG_ENDIAN
    return n;
#else
    return (((uint64_t)htonl((uint32_t)n)) << 32) + htonl((uint32_t) (n >> 32));
#endif
}
#endif // htonll

#ifndef ntohll
uint64_t __attribute__((visibility("hidden"))) ntohll(uint64_t n) {
#if __BYTE_ORDER == __BIG_ENDIAN
    return n;
#else
    return (((uint64_t)ntohl((uint32_t)n)) << 32) + ntohl((uint32_t)(n >> 32));
#endif
}
#endif // ntohll
