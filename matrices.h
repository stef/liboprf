#ifndef MATRICES_H
#define MATRICES_H

#include <stdint.h>
#include <sodium.h>

void invert(const uint8_t n,
            uint8_t a[n][n][crypto_core_ristretto255_SCALARBYTES],
            uint8_t x[n][n][crypto_core_ristretto255_SCALARBYTES]);
void genVDMmatrix(const uint8_t indexes[], const uint8_t index_len,
                  uint8_t matrix[index_len][index_len][crypto_core_ristretto255_SCALARBYTES]);
#endif // MATRICES_H
