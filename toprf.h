#ifndef toprf_h
#define toprf_h

#include <stdint.h>
#include <sodium.h>
#include <sss.h>

int toprf_init(const unsigned shares,
               const uint8_t *input, const size_t input_len,
               uint8_t r[shares][crypto_core_ristretto255_SCALARBYTES],
               uint8_t alphas[shares][crypto_core_ristretto255_BYTES]);


int toprf_share(const unsigned shares,
                const unsigned threshold,
                const uint8_t *input, const size_t input_len,
                const uint8_t r[shares][crypto_core_ristretto255_SCALARBYTES],
                const uint8_t betas[shares][crypto_core_ristretto255_BYTES],
                sss_Share xshares[shares],
                uint8_t result[sss_MLEN]);

int toprf_recover(const unsigned shares_len,
                  const uint8_t *input, const size_t input_len,
                  const uint8_t r[shares_len][crypto_core_ristretto255_SCALARBYTES],
                  const uint8_t betas[shares_len][crypto_core_ristretto255_BYTES],
                  sss_Share xshares[shares_len],
                  uint8_t result[sss_MLEN]);
#endif
