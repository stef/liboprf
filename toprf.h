/*
    @copyright 2023, opaque@ctrlc.hu
    This file is part of liboprf.

    liboprf is free software: you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public License
    as published by the Free Software Foundation, either version 3 of
    the License, or (at your option) any later version.

    liboprf is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with liboprf. If not, see <http://www.gnu.org/licenses/>.
*/

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
