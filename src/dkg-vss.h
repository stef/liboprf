#ifndef DKG_VSS_H
#define DKG_VSS_H

/**
 * @file dkg-vss.h
 * @brief Verifiable Secret Sharing (VSS) implementation for Distributed 
 *        Key Generation
 *
 * SPDX-FileCopyrightText: 2025, Marsiske Stefan
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * 
 * Implements functions for Verifiable Secret Sharing, which allows participants
 * to verify that the shares they received are consistent with the commitments
 * published by the dealer, ensuring that all participants can reconstruct the
 * same secret.
 */

#include <sodium.h>
#include <stdint.h>
#include "dkg.h"

/**
 * @brief Generator for the VSS scheme
 *
 * This generator was derived by hashing the fixed string
 * "DKG Generator H on ristretto255" into the Ristretto255 group.
 */
extern const uint8_t H[crypto_core_ristretto255_BYTES];

/**
 * @brief Creates shares of a secret with commitments
 *
 * @param[in] n The number of participants
 * @param[in] threshold The minimum number of shares needed to reconstruct the secret
 * @param[in] secret The secret to share
 * @param[out] commitments Array of commitments to shares, one for each participant
 * @param[out] shares Array of generated shares (each has secret and blinding shares)
 * @param[out] blind The blinding factor used for the commitment to the secret
 *
 * @return 0 on success, non-zero on error
 */
int dkg_vss_share(const uint8_t n,
                  const uint8_t threshold,
                  const uint8_t secret[crypto_core_ristretto255_SCALARBYTES],
                  uint8_t commitments[n][crypto_core_ristretto255_BYTES],
                  TOPRF_Share shares[n][2],
                  uint8_t blind[crypto_core_ristretto255_SCALARBYTES]);

/**
 * @brief Verifies that a share matches its commitment
 *
 * @param[in] commitment The commitment to verify against
 * @param[in] share The received secret share and its blinding share
 *
 * @return 0 if the commitment is valid, non-zero otherwise
 */
int dkg_vss_verify_commitment(const uint8_t commitment[crypto_core_ristretto255_BYTES],
                              const TOPRF_Share share[2]);

/**
 * @brief Finalizes the DKG VSS protocol for a participant
 *
 * Combines valid shares from qualified participants to compute the final
 * secret share and its corresponding commitment.
 *
 * @param[in] n The number of participants
 * @param[in] qual Array of indices of qualified participants
 * @param[in] shares Array of shares received from all participants
 * @param[in] self The index of the current participant
 * @param[out] share The final secret share and its blinding share
 * @param[out] commitment The commitment to the final share
 *
 * @return 0 on success, non-zero on error
 */
int dkg_vss_finish(const uint8_t n,
                   const uint8_t qual[n],
                   const TOPRF_Share shares[n][2],
                   const uint8_t self,
                   TOPRF_Share share[2],
                   uint8_t commitment[crypto_core_ristretto255_BYTES]);

/**
 * @brief Reconstructs a secret from a set of shares
 *
 * Given at least `t` valid shares, reconstructs the original secret
 * and optionally its blinding share.
 *
 * @param[in] t The threshold (minimum number of shares needed to reconstruct the secret)
 * @param[in] x The point at which to evaluate the polynomial (0 for the secret)
 * @param[in] shares_len The number of shares provided
 * @param[in] shares Array of shares provided for reconstruction
 * @param[in] commitments Array of commitments to verify shares
 * @param[out] result Buffer to store the reconstructed secret
 * @param[out] blind optional Buffer to store the reconstructed blinding factor skipped if NULL
 *
 * @return 0 on success, non-zero on error
 */
int dkg_vss_reconstruct(const uint8_t t,
                        const uint8_t x,
                        const size_t shares_len,
                        const TOPRF_Share shares[shares_len][2],
                        const uint8_t commitments[shares_len][crypto_scalarmult_ristretto255_BYTES],
                        uint8_t result[crypto_scalarmult_ristretto255_SCALARBYTES],
                        uint8_t blind[crypto_scalarmult_ristretto255_SCALARBYTES]);

/**
 * @brief Creates a Pedersen commitment to a value
 *
 * Computes C = g^a · h^r where `g` is the base point of the curve,
 * `h` is the fixed generator `H`, `a` is the value being committed to,
 * and `r` is the blinding factor.
 *
 * @param[in] a The value to commit to
 * @param[in] r The blinding factor
 * @param[out] C The resulting commitment
 *
 * @return 0 on success, non-zero on error
 */
int dkg_vss_commit(const uint8_t a[crypto_core_ristretto255_SCALARBYTES],
                   const uint8_t r[crypto_core_ristretto255_SCALARBYTES],
                   uint8_t C[crypto_core_ristretto255_BYTES]);

#endif // DKG_VSS_H
