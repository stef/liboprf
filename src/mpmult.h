/**
 * @file dkg_mult.h
 * @brief API for the Distributed Key Generation (DKG) Multiplication
 *        Protocols
 *
 * SPDX-FileCopyrightText: 2025, Marsiske Stefan
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * 
 * Implements a secure multiplication protocol that, given sharings of
 * secret `a` and secret `b`, generates a sharing of the product `a*b`
 * without revealing either secret.
 *
 * The interfaces in this header provide access to functions
 * implementing the Simple-Mult protocol defined in Fig. 2 from
 * R. Gennaro, M. O. Rabin, and T. Rabin. "Simplified VSS and
 * fast-track multiparty computations with applications to threshold
 * cryptography". In B. A. Coan and Y. Afek, editors, 17th ACM PODC,
 * pages 101–111. ACM, June / July 1998.
 *
 * Also implements the Fast-Track Multiplication (FT-Mult) protocol
 * defined in Fig. 5 of the same paper, which allows for faster
 * multiparty computations.
 *
 **/

#ifndef THMULT_H
#define THMULT_H

#include <stdint.h>
#include <sodium.h>
#include "toprf.h"
#include "dkg.h"

/**
 * @brief Computes the inverse of a Vandermonde matrix
 *
 * Given a list of dealer indices, this function generates the
 * corresponding Vandermonde matrix and computes its inverse, storing
 * the result in `inverted`.
 *
 * @param[in] dealers Number of dealers (matrix dimension)
 * @param[in] indexes Array of indices corresponding to each dealer
 * @param[out] inverted Output inverted Vandermonde matrix
 */
void invertedVDMmatrix(const uint8_t dealers,
                       const uint8_t indexes[dealers],
                       uint8_t inverted[dealers][dealers][crypto_core_ristretto255_SCALARBYTES]);

/**
 * @brief Phase 1 of multiparty threshold multiplication.
 *
 * Performs the  multiplication of two shares, `a` and `b`.
 *
 * @param[in] a One share held by the dealer contributing to the
 *            multiplication
 * @param[in] b Another share held by the dealer contributing to
 *            the multiplication
 * @param[in] peers The number of peers participating in the
 *            computation. This should equal the number of peers
 *            holding shares of `a` and `b`.
 * @param[in] threshold The number of peers minimum necessary to
 *            reconstruct either of the input or the result
 *            shares. Should equal the threshold for the `a` and `b`
 *            values.
 * @param[out] shares Output array of shares of a*b, one for each peer
 *
 * @return 0 on success, non-zero on error
 */
int toprf_mpc_mul_start(const uint8_t _a[TOPRF_Share_BYTES],
                        const uint8_t _b[TOPRF_Share_BYTES],
                        const uint8_t peers, const uint8_t threshold,
                        uint8_t shares[peers][TOPRF_Share_BYTES]);

/**
 * @brief Phase 2 of multiparty threshold multiplication.
 *
 * Each peer calls this function to finalize their share of a*b,
 * using all shares from phase 1 and the inverted Vandermonde matrix.
 *
 * @param[in] dealers Number of dealers
 * @param[in] indexes Indices of the participating dealers
 * @param[in] peer Index of the current peer computing their share
 * @param[in] shares All shares from phase 1 for this participant
 * @param[out] share Output share of a*b for this participant
 */
void toprf_mpc_mul_finish(const uint8_t dealers,
                          const uint8_t indexes[dealers],
                          const uint8_t peer,
                          const uint8_t shares[dealers][TOPRF_Share_BYTES],
                          uint8_t _share[TOPRF_Share_BYTES]);

/**
 * @brief Checks the correctness of a set of commitments
 *
 * @param[in] t Degree of the polynomials + 1 (threshold)
 * @param[in] A Array of commitments to check
 *
 * @return 0 if the check passes, non-zero otherwise
 */
int toprf_mpc_vsps_check(const uint8_t t,
                         const uint8_t A[t*2][crypto_core_ristretto255_BYTES]);

/**
 * @brief Step 1 of the Fast-Track Multiplication (FT-Mult) protocol
 *
 * Each player shares a value (λ_iα_iβ_i) using VSS, producing shares and commitments
 * for the next phase. FT-Mult is defined in Fig. 5 of "Simplified VSS and Fast-track
 * Multiparty Computations  with Applications to Threshold Cryptography" by R. Gennaro, M. O.
 * Rabin, and T. Rabin, PODC 1998.
 *
 * @param[in] dealers Number of participants acting as dealers (always 2t+1)
 * @param[in] n Number of parties receiving shares (must be more or equal 2t+1)
 * @param[in] t Threshold for reconstruction
 * @param[in] self Index of the current participant
 * @param[in] alpha Share of secret `a` (and its blinding factor)
 * @param[in] beta Share of secret `b` (and its blinding factor)
 * @param[in] lambdas Lagrange coefficients
 * @param[out] ci_shares Output array of shares for each participant
 * @param[out] ci_commitments Output array of commitments
 * @param[out] ci_tau Output blinding factor for the commitment
 *
 * @return 0 on success, non-zero on error
 */
int toprf_mpc_ftmult_step1(const uint8_t dealers, const uint8_t n, const uint8_t t, const uint8_t self,
                           const TOPRF_Share alpha[2], const TOPRF_Share beta[2],
                           const uint8_t lambdas[dealers][crypto_core_ristretto255_SCALARBYTES],
                           TOPRF_Share ci_shares[n][2],
                           uint8_t ci_commitments[n][crypto_core_ristretto255_BYTES],
                           uint8_t ci_tau[crypto_core_ristretto255_SCALARBYTES]);

/**
 * @brief Computes zero-knowledge (ZK) commitments for fast-track
 *        multiplication
 *
 * Generates commitments for use in the zero-knowledge proof of correct
 * multiplication.
 *
 * @param[in] B_i Commitment to the value being proved
 * @param[out] d Random scalar for the proof
 * @param[out] s Random scalar for the proof
 * @param[out] x Random scalar for the proof
 * @param[out] s_1 Random scalar for the proof
 * @param[out] s_2 Random scalar for the proof
 * @param[out] zk_commitments Output array of three commitments
 *
 * @return 0 on success, non-zero on error
 */
int toprf_mpc_ftmult_zk_commitments(const uint8_t B_i[crypto_core_ristretto255_BYTES],
                                    uint8_t d[crypto_scalarmult_ristretto255_SCALARBYTES],
                                    uint8_t s[crypto_scalarmult_ristretto255_SCALARBYTES],
                                    uint8_t x[crypto_scalarmult_ristretto255_SCALARBYTES],
                                    uint8_t s_1[crypto_scalarmult_ristretto255_SCALARBYTES],
                                    uint8_t s_2[crypto_scalarmult_ristretto255_SCALARBYTES],
                                    uint8_t zk_commitments[3][crypto_scalarmult_ristretto255_BYTES]);

#endif // THMULT_H
