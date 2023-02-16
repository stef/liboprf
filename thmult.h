/** Simple multiparty multiplication
 *
 * a Distributed Multiplication protocol which given the sharings of
 * secret a and secret b generates a sharing of the product a · b
 * without learning anything about either secret
 *
 * The interfaces in this header provide access to functions
 * implementing Fig. 2 from R. Gennaro, M. O. Rabin, and
 * T. Rabin. Simplified VSS and fact-track multiparty computa- tions
 * with applications to threshold cryptography. In B. A. Coan and
 * Y. Afek, editors, 17th ACM PODC, pages 101–111. ACM, June / July
 * 1998.
 *
 **/

#ifndef THMULT_H
#define THMULT_H

#include <stdint.h>
#include <sodium.h>
#include "toprf.h"


/**
 * This function is the first phase of a multiparty threshold
 * multiplication
 *
 * This function is called by each shareholder contributing to the
 * calculation.
 *
 * @param [in] a - One of the shares held by the shareholder
 * contributing to the multiplication.
 *
 * @param [in] b - The other one of the shares held by the shareholder
 * contributing to the multiplication.
 *
 * @param [in] peers - the number of shareholders cooperating in this
 * computation, should be equal to the number of shareholders holding
 * shares of a and b.
 *
 * @param [in] threshold - the number of shareholders minimum
 * necessary to parcipate in this computation. Should be the same as
 * the threshold for the a and b values.
 *
 * @param [out] Z - The output shares containing a sharing of
 * a*b. Each of those shares should be distributed to the shareholder
 * indicated in the index of the share.
 *
 * @return The function returns 0 if everything is correct.
 */
int toprf_mpc_mul_start(const uint8_t _a[TOPRF_Share_BYTES],
                        const uint8_t _b[TOPRF_Share_BYTES],
                        const uint8_t peers, const uint8_t threshold,
                        uint8_t shares[peers][TOPRF_Share_BYTES]);

/**
 * This function is the second phase of a multiparty threshold
 * multiplication
 *
 * This function is called by each shareholder contributing to the
 * calculation. At the end of this function a share is returned that
 * contributes to the value a*b from the first phase.
 *
 * @param [in] peers - the number of shareholders cooperating in this
 * computation, should be equal to the number of shareholders holding
 * shares of a and b.
 *
 * @param [in] indexes of the sender of each share in shares
 *
 * @param [in] peer the index of the shareholder executing the
 * computation.
 *
 * @param [in] shares - all the shares from phase 1 for this
 * shareholder.
 *
 * @param [out] shre - The output share, which can reconstruct the
 * value of a*b.
 *
 * @return The function returns 0 if everything is correct.
 */
void toprf_mpc_mul_finish(const uint8_t peers, const uint8_t indexes[peers],
                          const uint8_t peer,
                          const uint8_t shares[peers][TOPRF_Share_BYTES],
                          uint8_t _share[TOPRF_Share_BYTES]);

#endif // THMULT_H
