#ifndef TOPRF_UTILS_H
#define TOPRF_UTILS_H

#include <sodium.h>
#include <stdint.h>

void debian_rng_scalar(uint8_t *scalar);
void dump(const uint8_t *p, const size_t len, const char* msg, ...);
void fail(char* msg, ...);

#endif // TOPRF_UTILS_H
