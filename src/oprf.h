#ifndef oprf_h
#define oprf_h

/**
 * @file oprf.h
 * @brief API for Oblivious Pseudorandom Function (OPRF) implementation
 *
 * This file provides the API for Oblivious Pseudorandom Functions (OPRFs)
 * using the Ristretto255 group. It includes functions for key generation,
 * blinding inputs, evaluating OPRFs, and unblinding results.
 *
 * This implementation is based on RFC 9497: Oblivious Pseudorandom
 * Functions (OPRFs) Using Prime-Order Groups
 * (https://www.rfc-editor.org/rfc/rfc9497.html).
 *
 *
 * This implementation also uses hashing techniques as defined in
 * RFC 9380: Hashing to Elliptic Curves
 * (https://www.rfc-editor.org/rfc/rfc9380).
 *
 */

#include <stdint.h>
#include <sodium.h>
#include "toprf.h"

#define OPRF_BYTES 64

/**
 * @brief Generates an OPRF private key
 *
 * This is almost the `KeyGen` OPRF function defined in RFC 9497.
 * Since this library does not implement Verfiable OPRF (VOPRF)
 * functionality, no public key is needed, so steps related to that
 * are omitted.
 *
 * @param[out] kU The per-user OPRF private key
 */

void oprf_KeyGen(uint8_t kU[crypto_core_ristretto255_SCALARBYTES]);

/**
 * @brief Computes the final OPRF output
 *
 * Implements the `Finalize` OPRF function defined in RFC 9497.
 * It hashes the input and the OPRF evaluation to produce the
 * final output for the client.
 *
 * @param[in] x A value used to compute OPRF (the same value that
 *            was used as input to be blinded)
 * @param[in] x_len Length of input x in bytes.
 * @param[in] N Evaluated group element (output from oprf_Unblind)
 * @param[out] rwdU Output buffer for the OPRF result
 */
int oprf_Finalize(const uint8_t *x, const uint16_t x_len,
                  const uint8_t N[crypto_core_ristretto255_BYTES],
                  uint8_t rwdU[OPRF_BYTES]);

/**
 * @brief Blinds an input value for OPRF evaluation
 *
 * Implements the `Blind` OPRF function defined in RFC 9497.
 * This function converts the input into an OPRF group element and
 * randomizes it with a scalar value `r`. Both the scalar and blinded
 * element are returned.
 *
 * @param[in] x Input value to blind. E.g., the user's password in
 *            OPAQUE (pwdU)
 * @param[in] x_len Length of the input value in bytes
 * @param[out] r Random scalar used to blind the input
 * @param[out] alpha Serialized OPRF group element, the blinded version
 *             of `x`, used as input to `oprf_Evaluate()`
 *
 * @return 0 on success, non-zero on error
 */
int oprf_Blind(const uint8_t *x, const uint16_t x_len,
               uint8_t r[crypto_core_ristretto255_SCALARBYTES],
               uint8_t alpha[crypto_core_ristretto255_BYTES]);

/**
 * @brief Evaluates a blinded input using the OPRF private key
 *
 * Implements the `Evaluate` OPRF function defined in RFC 9497.
 * This function is run by the server. It uses the server's private
 * key `k` to evaluate the client's blinded input, producing a group
 * element `beta` that the client can later unblind.
 *
 * @param[in] k OPRF private key E.g., the user's private key in OPAQUE
 *            (kU)
 * @param[in] alpha  Serialized OPRF group element, an output of
 *            `oprf_Blind()`. For OPAQUE, this is the blinded user's
 *             password, pwdU
 * @param[out] beta Serialized OPRF group element, used as input to
 *            `oprf_Unblind()`
 *
 * @return 0 on success, non-zero on error
 */
int oprf_Evaluate(const uint8_t k[crypto_core_ristretto255_SCALARBYTES],
                  const uint8_t alpha[crypto_core_ristretto255_BYTES],
                  uint8_t beta[crypto_core_ristretto255_BYTES]);

/**
 * @brief Unblinds an evaluated OPRF element
 *
 * Implements the `Unblind` OPRF function defined in RFC 9497.
 * This function removes the random scalar `r` from the evaluated
 * element `beta`, producing the unblinded output `N`.
 *
 * @param[in] r Scalar used to blind the input originally
 * @param[in] beta OPRF evaluation result from the server, an output of
 *            `oprf_Evaluate()`
 * @param[out] N Serialized OPRF group element with random scalar `r`
 *             remove, used as input to `oprf_Finalize()`.
 *
 * @return 0 on success, non-zero on error
 */
int oprf_Unblind(const uint8_t r[crypto_core_ristretto255_SCALARBYTES],
                 const uint8_t beta[crypto_core_ristretto255_BYTES],
                 uint8_t N[crypto_core_ristretto255_BYTES]);

/**
 * @brief Hashes an input message to a point on the Ristretto255 curve
 *
 * Implements the `hash-to-curve` function defined in RFC 9380.
 * This function is needed for the OPRF implementation.
 *
 * @param[in] msg Input message to hash to a Ristretto255 point
 * @param[in] msg_len Length of the input message in bytes
 * @param[out] p The resulting Ristretto255 point
 *
 * @return 0 on success, non-zero on error
 */
int voprf_hash_to_group(const uint8_t *msg, const uint16_t msg_len, uint8_t p[crypto_core_ristretto255_BYTES]);

/**
 * @brief Expands an input message to a uniformly random byte string
 *        using a cryptographic hash function
 *
 * Implements `expand_message_xmd` as defined in RFC 9380.
 *
 * @param[in] msg The input message to expand
 * @param[in] msg_len The length of the input message in bytes
 * @param[in] dst Domain separation tag (DST)
 * @param[in] dst_len The length of the DST
 * @param[in] len_in_bytes Desired number of output bytes
 * @param[out] uniform_bytes Output buffer of length `len_in_bytes` to
 *             receive the high entropy result
 *
 * @return 0 on success, non-zero on error
 */
int expand_message_xmd(const uint8_t *msg, const uint16_t msg_len, const uint8_t *dst, const uint8_t dst_len, const uint8_t len_in_bytes, uint8_t *uniform_bytes);

#ifdef __EMSCRIPTEN__
/**
 * if compiling to webassembly, there is no sodium_m(un)?lock and thus we suppress that with the following
 */

// Per
// https://emscripten.org/docs/compiling/Building-Projects.html#detecting-emscripten-in-preprocessor,
// "The preprocessor define __EMSCRIPTEN__ is always defined when compiling
// programs with Emscripten". For why we are replacing sodium_m(un)?lock, see
// common.c for more details.
#define sodium_mlock(a,l) (0)
#define sodium_munlock(a,l) (0)
#endif //__EMSCRIPTEN__


#endif
