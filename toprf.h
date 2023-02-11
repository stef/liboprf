#ifndef TOPRF_H
#define TOPRF_H

#include <sodium.h>
#include <stdint.h>

typedef struct {
  uint8_t index;
  uint8_t value[crypto_core_ristretto255_SCALARBYTES];
} __attribute((packed)) TOPRF_Share;

typedef struct {
  uint8_t index;
  uint8_t value[crypto_core_ristretto255_BYTES];
} __attribute((packed)) TOPRF_Part;



void create_shares(const uint8_t secret[crypto_core_ristretto255_SCALARBYTES],
                   const uint8_t n,
                   const uint8_t threshold,
                   TOPRF_Share shares[n]);

int TOPRF_thresholdmult(const TOPRF_Part *responses,
                        const size_t response_len,
                        uint8_t result[crypto_scalarmult_ristretto255_BYTES]);

#endif // TOPRF_H
