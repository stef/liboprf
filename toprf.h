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

/**
 * This function calculates a lagrange coefficient based on the index
 * and the indexes of the other contributing shareholders.
 *
 * @param [in] i - the index of the shareholder whose lagrange
 *                 coefficient we're calculating
 *
 * @param [in] peers - the shares that contribute to the reconstruction
 *
 * @param [in] peers_len - the number of shares in peers
 *
 * @param [out] result - the lagrange coefficient
 */
void coeff(const int i, const TOPRF_Part *peers, const int peers_len, uint8_t *result);

/**
 * This function creates shares of secret in a (threshold, n) scheme
 * over the curve ristretto255
 *
 * @param [in] secret - the scalar value to be secretly shared
 *
 * @param [in] n - the number of shares created
 *
 * @param [in] threshold - the threshold needed to reconstruct the secret
 *
 * @param [out] shares - n shares
 *
 * @return The function returns 0 if everything is correct.
 */
void toprf_create_shares(const uint8_t secret[crypto_core_ristretto255_SCALARBYTES],
                   const uint8_t n,
                   const uint8_t threshold,
                   TOPRF_Share shares[n]);

/**
 * This function recovers the secret in the exponent using lagrange interpolation
 * over the curve ristretto255j
 *
 * The shareholders are not aware if they are contributing to a
 * threshold or non-threshold oprf evaluation, from their perspective
 * nothing changes in this approach.
 *
 * @param [in] responses - is an array of shares (k_i) multiplied by a
 *        point (P) on the r255 curve
 *
 * @param [in] responses - is an array of shares (k_i) multiplied by a
 *
 * @param [in] responses_len - the number of elements in the response array
 *
 * @param [out] result - the reconstructed value of P multipled by k
 *
 * @return The function returns 0 if everything is correct.
 */
int toprf_thresholdmult(const TOPRF_Part *responses,
                        const size_t response_len,
                        uint8_t result[crypto_scalarmult_ristretto255_BYTES]);

/**
 * This function is the efficient threshold version of oprf_Evaluate.
 *
 * This function needs to know in advance the indexes of all the
 * shares that will be combined later in the toprf_thresholdcombine() function.
 * by doing so this reduces the total costs and distributes them to the shareholders.
 *
 * @param [in] k - a private key (for OPAQUE, this is kU, the user's
 *        OPRF private key)
 *
 * @param [in] blinded - a serialized OPRF group element, a byte array
 *         of fixed length, an output of oprf_Blind (for OPAQUE, this
 *         is the blinded pwdU, the user's password)
 *
 * @param [in] self - the index of the current shareholder
 *
 * @param [in] indexes - the indexes of the all the shareholders
 *        contributing to this oprf evaluation,
 *
 * @param [in] index_len - the length of the indexes array,
 *
 * @param [out] Z - a serialized OPRF group element, a byte array of fixed length,
 *        an input to oprf_Unblind
 *
 * @return The function returns 0 if everything is correct.
 */
int toprf_Evaluate(const uint8_t k[crypto_core_ristretto255_SCALARBYTES],
                   const uint8_t blinded[crypto_core_ristretto255_BYTES],
                   const uint8_t self, const uint8_t *indexes, const uint16_t index_len,
                   uint8_t Z[crypto_core_ristretto255_BYTES]);

/**
 * This function is combines the results of the toprf_Evaluate()
 * function to recover the shared secret in the exponent.
 *
 * @param [in] responses - is an array of shares (k_i) multiplied by a point (P) on the r255 curve
 *
 * @param [in] responses_len - the number of elements in the response array
 *
 * @param [out] result - the reconstructed value of P multipled by k
 *
 * @return The function returns 0 if everything is correct.
 */
void toprf_thresholdcombine(const TOPRF_Part *responses,
                            const size_t response_len,
                            uint8_t result[crypto_scalarmult_ristretto255_BYTES]);


#endif // TOPRF_H
