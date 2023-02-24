#ifndef DKG_H
#define DKG_H

#include <sodium.h>
#include <stdint.h>

typedef struct {
  uint8_t index;
  uint8_t value[crypto_core_ristretto255_SCALARBYTES];
} __attribute((packed)) TOPRF_Share;

int dkg_start(const uint8_t n,
              const uint8_t threshold,
              uint8_t commitments[threshold][crypto_core_ristretto255_BYTES],
              TOPRF_Share shares[n][2]);

int dkg_verify_commitments(const uint8_t n,
                           const uint8_t threshold,
                           const uint8_t self,
                           const uint8_t commitments[n][threshold][crypto_core_ristretto255_BYTES],
                           const TOPRF_Share shares[n][2],
                           uint8_t complaints[n],
                           uint8_t *complaints_len);

void dkg_finish(const uint8_t n,
                const uint8_t qual[n],
                const TOPRF_Share shares[n][2],
                const uint8_t self,
                TOPRF_Share *xi,
                TOPRF_Share *x_i);

void dkg_reconstruct(const size_t response_len,
                     const TOPRF_Share responses[response_len][2],
                     uint8_t result[crypto_scalarmult_ristretto255_BYTES]);

#endif // DKG_H
