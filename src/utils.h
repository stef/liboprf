#ifndef TOPRF_UTILS_H
#define TOPRF_UTILS_H

#include <sodium.h>
#include <stdint.h>
#include <stdio.h>

extern int liboprf_debug;
extern FILE* liboprf_log_file;

#define RED "\x1b[0;31m"
#define NORMAL "\x1b[0m"
#define GREEN "\x1b[0;32m"

#ifdef UNIT_TEST
void debian_rng_scalar(uint8_t *scalar);
#endif //UNIT_TEST

void dump(const uint8_t *p, const size_t len, const char* msg, ...);
void fail(char* msg, ...);

#ifndef htonll
uint64_t htonll(uint64_t n);
#endif

#ifndef ntohll
uint64_t ntohll(uint64_t n);
#endif

#endif // TOPRF_UTILS_H
