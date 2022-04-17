#ifndef oprf_h
#define oprf_h

#include <stdint.h>
#include <sodium.h>

#define OPRF_BYTES 64

/**
 * This function generates an OPRF private key.
 *
 * This is almost the KeyGen OPRF function defined in the RFC: since
 * this lib does not implement V oprf, we don't need a pubkey and so
 * we don't bother with all that is related.
 *
 * @param [out] kU - the per-user OPRF private key
 */

void oprf_KeyGen(uint8_t kU[crypto_core_ristretto255_SCALARBYTES]);

/**
 * This function computes the OPRF output using input x, N, and domain separation
 * tag info.
 *
 * This is the Finalize OPRF function defined in the RFC.
 *
 * @param [in] x - a value used to compute OPRF (the same value that
 * was used as input to be blinded)
 * @param [in] x_len - the length of param x in bytes
 * @param [in] N - a serialized OPRF group element, a byte array of fixed length,
 * an output of oprf_Unblind
 * @param [in] info - a domain separation tag
 * @param [in] info_len - the length of param info in bytes
 * @param [out] y - an OPRF output
 * @return The function returns 0 if everything is correct.
 */
int oprf_Finalize(const uint8_t *x, const uint16_t x_len,
                  const uint8_t N[crypto_core_ristretto255_BYTES],
                  uint8_t rwdU[OPRF_BYTES]);

/**
 * This function converts input x into an element of the OPRF group, randomizes it
 * by some scalar r, producing blinded, and outputs (r, blinded).
 *
 * This is the Blind OPRF function defined in the RFC.
 *
 * @param [in] x - the value to blind (for OPAQUE, this is pwdU, the user's
 * password)
 * @param [in] x_len - the length of param x in bytes
 * @param [out] r - an OPRF scalar value used for randomization
 * @param [out] blinded - a serialized OPRF group element, a byte array of fixed length,
 * the blinded version of x, an input to oprf_Evaluate
 * @return The function returns 0 if everything is correct.
 */
int oprf_Blind(const uint8_t *x, const uint16_t x_len,
               uint8_t r[crypto_core_ristretto255_SCALARBYTES],
               uint8_t blinded[crypto_core_ristretto255_BYTES]);

/**
 * This function evaluates input element blinded using private key k, yielding output
 * element Z.
 *
 * This is the Evaluate OPRF function defined in the RFC.
 *
 * @param [in] k - a private key (for OPAQUE, this is kU, the user's OPRF private
 * key)
 * @param [in] blinded - a serialized OPRF group element, a byte array of fixed length,
 * an output of oprf_Blind (for OPAQUE, this is the blinded pwdU, the user's
 * password)
 * @param [out] Z - a serialized OPRF group element, a byte array of fixed length,
 * an input to oprf_Unblind
 * @return The function returns 0 if everything is correct.
 */
int oprf_Evaluate(const uint8_t k[crypto_core_ristretto255_SCALARBYTES],
                  const uint8_t blinded[crypto_core_ristretto255_BYTES],
                  uint8_t Z[crypto_core_ristretto255_BYTES]);

/**
 * This function removes random scalar r from Z, yielding output N.
 *
 * This is the Unblind OPRF function defined in the RFC.
 *
 * @param [in] r - an OPRF scalar value used for randomization in oprf_Blind
 * @param [in] Z - a serialized OPRF group element, a byte array of fixed length,
 * an output of oprf_Evaluate
 * @param [out] N - a serialized OPRF group element with random scalar r removed,
 * a byte array of fixed length, an input to oprf_Finalize
 * @return The function returns 0 if everything is correct.
 */
int oprf_Unblind(const uint8_t r[crypto_core_ristretto255_SCALARBYTES],
                 const uint8_t Z[crypto_core_ristretto255_BYTES],
                 uint8_t N[crypto_core_ristretto255_BYTES]);
#endif
