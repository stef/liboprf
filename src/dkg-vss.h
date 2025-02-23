#ifndef DKG_VSS_H
#define DKG_VSS_H

#include <sodium.h>
#include <stdint.h>
#include "dkg.h"

extern const uint8_t H[crypto_core_ristretto255_BYTES];

int dkg_vss_share(const uint8_t n,
                  const uint8_t threshold,
                  const uint8_t secret[crypto_core_ristretto255_SCALARBYTES],
                  uint8_t commitments[threshold][crypto_core_ristretto255_BYTES],
                  TOPRF_Share shares[n][2],
                  uint8_t blind[crypto_core_ristretto255_SCALARBYTES]);

int dkg_vss_verify_commitment(const uint8_t commitment[crypto_core_ristretto255_BYTES],
                              const TOPRF_Share shares[2]);

uint8_t dkg_vss_verify_commitments(const uint8_t n,
                                   const uint8_t threshold,
                                   const uint8_t self,
                                   const uint8_t commitments[n][n+1][crypto_core_ristretto255_BYTES],
                                   const TOPRF_Share shares[n][2],
                                   uint8_t complaints[n]);

int dkg_vss_finish(const uint8_t n,
                   const uint8_t qual[n],
                   const TOPRF_Share shares[n][2],
                   const uint8_t self,
                   TOPRF_Share share[2],
                   uint8_t commitment[crypto_core_ristretto255_BYTES]);

void dkg_vss_reconstruct(const size_t response_len,
                         const TOPRF_Share responses[response_len][2],
                         uint8_t result[crypto_scalarmult_ristretto255_SCALARBYTES],
                         uint8_t blind[crypto_scalarmult_ristretto255_SCALARBYTES]);

int dkg_vss_commit(const uint8_t a[crypto_core_ristretto255_SCALARBYTES],
                   const uint8_t r[crypto_core_ristretto255_SCALARBYTES],
                   uint8_t C[crypto_core_ristretto255_BYTES]);

#endif // DKG_VSS_H
