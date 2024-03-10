#ifndef oprf_h
#define oprf_h

#include <stdint.h>
#include <sodium.h>
#include "toprf.h"

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
int oprf_Blind(const uint8_t *x, const uint8_t x_len,
               uint8_t r[crypto_core_ristretto255_SCALARBYTES],
               uint8_t blinded[crypto_core_ristretto255_BYTES]);

/**
 * This function evaluates input element blinded using private key k, yielding output
 * element Z.
 *
 * This is the Evaluate OPRF function defined in the RFC. If the
 * internal proxy_cfg variable has been set using oprf_set_evalproxy() then
 * the Evaluation will be a threshold computation.
 *
 * @param [in] k - a private key (for OPAQUE, this is kU, the user's OPRF private
 * key) - if proxy_cfg is set, than this value will be ignored!
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

/**
 * Implements the hash to curve CFRG IRTF https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/
 * function needed for the OPRF implementation
 *
 * @param [in] msg: the input to hash to a ristretto255 point
 * @param [in] msg_len: the length of the input
 * @param [out] p: the resulting ristretto255 point
 */
int voprf_hash_to_group(const uint8_t *msg, const uint8_t msg_len, uint8_t p[crypto_core_ristretto255_BYTES]);

/**
 * A utility function from the hash to curve CFRG IRTF draft/spec
 *
 * uses the input parameters msg/msg_len and dst/dst_len (dst stands
 * for domain separation tag), and produces a high entropy output in
 * uniform_bytes of length: len_in_bytes
 */
int expand_message_xmd(const uint8_t *msg, const uint8_t msg_len, const uint8_t *dst, const uint8_t dst_len, const uint8_t len_in_bytes, uint8_t *uniform_bytes);

/**
 * Clears the internal variable that stores the configuration for
 * proxying to a threshold oprf.
*/
void oprf_clear_evalproxy(void);

/**
 * Sets the configuration of the proxy theshold evaluator
 *
 * @param [in] eval: a callback function that has the same parameters
 *                   as oprf_Evaluate. This is provided, so
 *                   implementers can provide their own means to
 *                   contact the shareholders and communicate with
 *                   them and can decide if they want to do
 *                   toprf_thresholdmult or toprf_thresholdcombine
 *                   based evaluation. Also this can be subverted for
 *                   providing static values for testvectors.
 *
 * @param [in] keygen: a callback function that takes an index, the
 *                   blinded operand, and returns an partly evaluated
 *                   element. This is provided, so implementers can
 *                   provide their own means to contact the
 *                   shareholders and communicate with them.
 */
int oprf_set_evalproxy(const toprf_evalcb eval, const toprf_keygencb keygen);

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
