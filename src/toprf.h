#ifndef TOPRF_H
#define TOPRF_H

/**
 * @file toprf.h
 * @brief API for the Threshold Oblivious Pseudorandom Function (TOPRF)
 *        implementation
 * 
 * SPDX-FileCopyrightText: 2023, Marsiske Stefan
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * This file defines the structures, types, and functions for implementing
 * a Threshold Oblivious Pseudorandom Function (TOPRF) based on the
 * paper section 3 of the paper:
 * "TOPPSS: Cost-minimal Password-Protected Secret Sharing based on
 * Threshold OPRF" by Stanislaw Jarecki, Aggelos Kiayias, Hugo Krawczyk,
 * and Jiayu Xu, 2017 (https://eprint.iacr.org/2017/363)
 */

#include <sodium.h>
#include <stdint.h>

/**
 * @struct TOPRF_Share
 * @brief Share structure for TOPRF
 */
typedef struct
{
  uint8_t index;
  uint8_t value[crypto_core_ristretto255_SCALARBYTES];
} __attribute((packed)) TOPRF_Share;

#define TOPRF_Share_BYTES (sizeof(TOPRF_Share))
#define TOPRF_Part_BYTES (crypto_core_ristretto255_BYTES + 1UL)

/**
 * @brief Interpolates a polynomial of degree `t` at an arbitrary point
 *        `x: y = f(x)`
 *
 * Uses Lagrange interpolation to reconstruct the polynomial value at `x`,
 * given `t` shares (evaluations) of the polynomial.
 *
 * @param[in] x The value at which the polynomial is evaluated
 * @param[in] t The degree of the polynomial
 * @param[in] shares Evaluated points on the polynomial.
 * @param[out] y Output buffer to store the computed result, `f(x)`
 */
void interpolate(const uint8_t x, const uint8_t t, const TOPRF_Share shares[t], uint8_t y[crypto_scalarmult_ristretto255_SCALARBYTES]);

/**
 * @brief Computes the Lagrange coefficient for `f(x)`
 *
 * This function calculates a Lagrange coefficient for `f(x)`
 * based on the index and the indices of the other contributing peers
 *
 * @param[in] index The index of the peer for which the Lagrange coefficient
 *            is being calculated
 * @param[in] x The evaluation point for the polynomial
 * @param[in] degree Total number of shares participating (number of peers)
 * @param[in] peers Array of indices of all participating peers that
 *            contribute to the reconstruction
 * @param[out] result Output buffer to store the computed Lagrange
 *             coefficient
 */

void lcoeff(const uint8_t index, const uint8_t x, const size_t degree, const uint8_t peers[degree], uint8_t result[crypto_scalarmult_ristretto255_SCALARBYTES]);

/**
 * @brief Computes the Lagrange coefficient for `f(0)
 *
 * This function calculates a lagrange coefficient for `f(0)` based on
 * the index and the indices of the other contributing peers
 *
 * @param[in] index The index of the peer for which the Lagrange coefficient
 *            is being calculated
 * @param[in] peers_len Total number of shares in the peers
 * @param[in] peers Shares that contribute to the reconstruction
 * @param[out] result Output buffer to store the computed Lagrange
 *             coefficient
 */
void coeff(const uint8_t index, const size_t peers_len, const uint8_t peers[peers_len], uint8_t result[crypto_scalarmult_ristretto255_SCALARBYTES]);

/**
 * @brief Splits a secret into `n` shares using Shamir's secret sharing over
 *        the curve Ristretto255
 *
 * The secret is shared in a (threshold, n) scheme: any threshold number
 * of shares can reconstruct the secret, but fewer reveal nothing.
 * This function wraps `lcoeff()`, allowing to recover the shared
 * secret without providing `x=0` as a parameter. This is mostly for
 * backward compatibility.
 *
 * @param[in] secret The scalar value to be secretly shared
 * @param[in] n The number of shares created
 * @param[in] threshold Minimum number of shares required to reconstruct
 *            the secret
 * @param[out] shares Output buffer receiving `n` generated shares
 *
 * @return 0 on success, non-zero on failure
 */
void toprf_create_shares(const uint8_t secret[crypto_core_ristretto255_SCALARBYTES],
                         const uint8_t n,
                         const uint8_t threshold,
                         uint8_t shares[n][TOPRF_Share_BYTES]);

/**
 * @brief Combines shares in the exponent using Lagrange interpolation over
 *        the curve Ristretto255
 *
 * This function combines a threshold number of shares to recover the secret
 * in the exponent. It uses Lagrange interpolation over the curve
 * Ristretto255.
 * The peers are unaware of whether they participate in threshold or
 * standalone mode. Their computation remains the same in both cases.
 *
 * @param[in] response_len Number of elements in the `responses` array
 * @param[in] responses Array of shares to be combined
 * @param[out] result  Output buffer receiving the reconstructed secret
 *
 * @return 0 on success, non-zero on error
 */
int toprf_thresholdmult(const size_t response_len,
                        const uint8_t responses[response_len][TOPRF_Part_BYTES],
                        uint8_t result[crypto_scalarmult_ristretto255_BYTES]);

/**
 * @brief Efficiently evaluates a blinded input using the private key
 *        in a threshold setting
 *
 * This function is the efficient threshold version of `oprf_Evaluate()`
 * defined in oprf.h.
 * It needs to know in advance the indices of all shares that will be
 * combined later in the `toprf_thresholdcombine()` function. This
 * precomputation reduces the total costs and distributes them to the peers
 *
 * @param[in] k The server's secret key share. For OPAQUE, this is kU, the
 *            user's OPRF private key
 * @param[in] blinded Serialized OPRF group element, an output of
 *            `oprf_Blind()`. For OPAQUE, this is the blinded user's
 *             password, pwdU
 * @param[in] self The index of the current peer
 * @param[in] indexes Array of indices of all peers contributing to this
 *            OPRF evaluation
 * @param[in] index_len Number of participating peers (Length of `indexes`)
 * @param[out] Z Serialized OPRF group element, used as input to
 *            `oprf_Unblind()`
 *
 * @return 0 on success, non-zero on error
 */
int toprf_Evaluate(const uint8_t k[TOPRF_Share_BYTES],
                   const uint8_t blinded[crypto_core_ristretto255_BYTES],
                   const uint8_t self, const uint8_t *indexes, const uint16_t index_len,
                   uint8_t Z[TOPRF_Part_BYTES]);

/**
 * @brief Combines the partial results to reconstruct the final OPRF output
 *
 * This function is combines the results of the `toprf_Evaluate()` to recover
 * the shared secret in the exponent.

 * @param[in] response_len Number of elements in the `responses` array
 * @param[in] responses Array of shares to be combined
 * @param[out] result  Output buffer receiving the reconstructed secret
 *
 * @return 0 on success, non-zero on error
 */
int toprf_thresholdcombine(const size_t response_len,
                           const uint8_t _responses[response_len][TOPRF_Part_BYTES],
                           uint8_t result[crypto_scalarmult_ristretto255_BYTES]);

typedef int (*toprf_evalcb)(void *ctx,
                            const uint8_t k[crypto_core_ristretto255_SCALARBYTES],
                            const uint8_t alpha[crypto_core_ristretto255_BYTES],
                            uint8_t beta[crypto_core_ristretto255_BYTES]);

typedef int (*toprf_keygencb)(void *ctx, uint8_t k[crypto_core_ristretto255_SCALARBYTES]);

/**
 * @brief Implements the 3HashTDH protocol
 *
 * This function implements the 3HashTDH protocol from the paper:
 * "Threshold PAKE with Security against Compromise of All Servers"
 * (https://eprint.iacr.org/2024/1455) by Gu, Jarecki, Kedzior,
 * Nazarian, Xu.
 *
 * Use this function to implement a threshold OPRF.
 *
 * @param[in] k A share of the secret key
 * @param[in] z A random zero-sharing of the secret key. This is a share of
 *            a random `t`-degree polynomial that evaluates to zero, where t
 *            is the threshold
 * @param[in] alpha The blinded element from the client
 * @param[in] ssid_S A session-specific identifier that all participants in
 *            the threshold evaluation must agree on (it must be the same
 *            for all participants)
 * @param[in] ssid_S_len Length of the `ssid_S` identifier
 * @param[out] beta Output buffer containing the result of evaluation, to
 *             be returned to the client
 *
 * @return 0 on success, non-zero on error
 */
int toprf_3hashtdh(const uint8_t k[TOPRF_Share_BYTES],
                   const uint8_t z[TOPRF_Share_BYTES],
                   const uint8_t alpha[crypto_core_ristretto255_BYTES],
                   const uint8_t *ssid_S, const uint16_t ssid_S_len,
                   uint8_t beta[TOPRF_Part_BYTES]);

#endif // TOPRF_H
