/*
    @copyright 2022, Stefan Marsiske toprf@ctrlc.hu
    This file is part of liboprf.

    liboprf is free software: you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public License
    as published by the Free Software Foundation, either version 3 of
    the License, or (at your option) any later version.

    liboprf is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the License
    along with liboprf. If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "oprf.h"
#include "utils.h"
#include "toprf.h"

#ifdef CFRG_TEST_VEC
#ifdef CFRG_OPRF_TEST_VEC
#include "tests/cfrg_oprf_test_vector_decl.h"
#else
#include "tests/cfrg_test_vector_decl.h"
#endif
#endif

#define VOPRF "OPRFV1"

/**
 * This function generates an OPRF private key.
 *
 * This is almost the KeyGen OPRF function defined in the RFC: since
 * this lib does not implement V oprf, we don't need a pubkey and so
 * we don't bother with all that is related.
 *
 * @param [out] kU - the per-user OPRF private key
 */
void oprf_KeyGen(uint8_t kU[crypto_core_ristretto255_SCALARBYTES]) {
#if (defined CFRG_TEST_VEC && defined oprf_key_len)
  memcpy(kU,oprf_key,oprf_key_len);
#else
  crypto_core_ristretto255_scalar_random(kU);
#endif
}

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
                         uint8_t rwdU[OPRF_BYTES]) {
  // according to paper: hash(pwd||H0^k)
  // acccording to voprf IRTF CFRG specification: hash(htons(len(pwd))||pwd||
  //                                              htons(len(H0_k))||H0_k|||
  //                                              htons(len("Finalize-"VOPRF"-\x00-ristretto255-SHA512"))||"Finalize-"VOPRF"-\x00-ristretto255-SHA512")
  crypto_hash_sha512_state state;
  if(-1==sodium_mlock(&state,sizeof state)) {
    return -1;
  }
  crypto_hash_sha512_init(&state);
  // pwd
  uint16_t size=htons(x_len);
  crypto_hash_sha512_update(&state, (uint8_t*) &size, 2);
  crypto_hash_sha512_update(&state, x, x_len);
#if (defined TRACE || defined CFRG_TEST_VEC)
  dump(x,x_len,"finalize input");
#endif
  // H0_k
  size=htons(crypto_core_ristretto255_BYTES);
  crypto_hash_sha512_update(&state, (uint8_t*) &size, 2);
  crypto_hash_sha512_update(&state, N, crypto_core_ristretto255_BYTES);
  //const uint8_t DST[]="Finalize-"VOPRF"-\x00\x00\x01";
  const uint8_t DST[]="Finalize";
  const uint8_t DST_size=sizeof DST -1;
  //size=htons(DST_size);
  //crypto_hash_sha512_update(&state, (uint8_t*) &size, 2);
  crypto_hash_sha512_update(&state, DST, DST_size);

  crypto_hash_sha512_final(&state, rwdU);
  sodium_munlock(&state, sizeof state);

  return 0;
}

/* expand_loop
 10.    b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
 */
static void expand_loop(const uint8_t *b_0, const uint8_t *b_i, const uint8_t i, const uint8_t *dst_prime, const uint8_t dst_prime_len, uint8_t *b_ii) {
  uint8_t xored[crypto_hash_sha512_BYTES];
  unsigned j;
  for(j=0;j<sizeof xored;j++) xored[j]=b_0[j]^b_i[j];
  // 8.  b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
  crypto_hash_sha512_state state;
  crypto_hash_sha512_init(&state);
  crypto_hash_sha512_update(&state, xored, sizeof xored);
  crypto_hash_sha512_update(&state,(const uint8_t*) &i, 1);
  crypto_hash_sha512_update(&state, dst_prime, dst_prime_len);
  crypto_hash_sha512_final(&state, b_ii);
  sodium_memzero(&state,sizeof state);
}

/*
 * oprf_expand_message_xmd(msg, DST, len_in_bytes)
 * as defined by https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/blob/master/draft-irtf-cfrg-hash-to-curve.md#expand_message_xmd-hashtofield-expand-xmd
 *
 * Parameters:
 * - H, a hash function (see requirements above).
 * - b_in_bytes, b / 8 for b the output size of H in bits.
 *   For example, for b = 256, b_in_bytes = 32.
 * - r_in_bytes, the input block size of H, measured in bytes (see
 *   discussion above). For example, for SHA-256, r_in_bytes = 64.
 *
 * Input:
 * - msg, a byte string.
 * - DST, a byte string of at most 255 bytes.
 *   See below for information on using longer DSTs.
 * - len_in_bytes, the length of the requested output in bytes.
 *
 * Output:
 * - uniform_bytes, a byte string.
 *
 * Steps:
 * 1.  ell = ceil(len_in_bytes / b_in_bytes)
 * 2.  ABORT if ell > 255
 * 3.  DST_prime = DST || I2OSP(len(DST), 1)
 * 4.  Z_pad = I2OSP(0, r_in_bytes)
 * 5.  l_i_b_str = I2OSP(len_in_bytes, 2)
 * 6.  msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
 * 7.  b_0 = H(msg_prime)
 * 8.  b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
 * 9.  for i in (2, ..., ell):
 * 10.    b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
 * 11. uniform_bytes = b_1 || ... || b_ell
 * 12. return substr(uniform_bytes, 0, len_in_bytes)
 */
int oprf_expand_message_xmd(const uint8_t *msg, const uint16_t msg_len, const uint8_t *dst, const uint8_t dst_len, const uint8_t len_in_bytes, uint8_t *uniform_bytes) {
  // 1.  ell = ceil(len_in_bytes / b_in_bytes)
  const unsigned ell = (len_in_bytes + crypto_hash_sha512_BYTES-1) / crypto_hash_sha512_BYTES;
#ifdef TRACE
  fprintf(stderr, "ell %d\n", ell);
  dump(msg, msg_len, "msg");
  dump(dst, dst_len, "dst");
#endif

  // 2.  ABORT if ell > 255
  if(ell>255) return -1;
  // 3.  DST_prime = DST || I2OSP(len(DST), 1)
  if(dst_len==255) return -1;
  uint8_t dst_prime[dst_len+1];
  memcpy(dst_prime, dst, dst_len);
  dst_prime[dst_len] = dst_len;
#ifdef TRACE
  dump(dst_prime, sizeof dst_prime, "dst_prime");
#endif
  // 4.  Z_pad = I2OSP(0, r_in_bytes)
  //const uint8_t r_in_bytes = 128; // for sha512
  uint8_t z_pad[128 /*r_in_bytes*/] = {0}; // supress gcc error: variable-sized object may not be initialized
#ifdef TRACE
  dump(z_pad, sizeof z_pad, "z_pad");
#endif
  // 5.  l_i_b_str = I2OSP(len_in_bytes, 2)
  const uint16_t l_i_b = htons(len_in_bytes);
  const uint8_t *l_i_b_str = (const uint8_t*) &l_i_b;
  // 6.  msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
  uint8_t msg_prime[sizeof z_pad + msg_len + sizeof l_i_b + 1 + sizeof dst_prime];
  uint8_t *ptr = msg_prime;
  memcpy(ptr, z_pad, sizeof z_pad);
  ptr += sizeof z_pad;
  memcpy(ptr, msg, msg_len);
  ptr += msg_len;
  memcpy(ptr, l_i_b_str, sizeof l_i_b);
  ptr += sizeof l_i_b;
  *ptr = 0;
  ptr++;
  memcpy(ptr, dst_prime, sizeof dst_prime);
#ifdef TRACE
  dump(msg_prime, sizeof msg_prime, "msg_prime");
#endif
  // 7.  b_0 = H(msg_prime)
  uint8_t b_0[crypto_hash_sha512_BYTES];
  crypto_hash_sha512(b_0, msg_prime, sizeof msg_prime);
#ifdef TRACE
  dump(b_0, sizeof b_0, "b_0");
#endif
  // 8.  b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
  uint8_t b_i[crypto_hash_sha512_BYTES];
  crypto_hash_sha512_state state;
  crypto_hash_sha512_init(&state);
  crypto_hash_sha512_update(&state, b_0, sizeof b_0);
  crypto_hash_sha512_update(&state,(const uint8_t*) &"\x01", 1);
  crypto_hash_sha512_update(&state, dst_prime, (long long unsigned int) sizeof dst_prime);
  crypto_hash_sha512_final(&state, b_i);
#ifdef TRACE
  dump(b_i, sizeof b_i, "b_1");
#endif
  // 9.  for i in (2, ..., ell):
  unsigned left = len_in_bytes;
  uint8_t *out = uniform_bytes;
  unsigned clen = (left>sizeof b_i)?sizeof b_i:left;
  memcpy(out, b_i, clen);
  out+=clen;
  left-=clen;
  uint8_t b_ii[crypto_hash_sha512_BYTES];
  for(uint8_t i=2;i<=ell;i+=2) {
    // 11. uniform_bytes = b_1 || ... || b_ell
    // 12. return substr(uniform_bytes, 0, len_in_bytes)
    // 10.    b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
    expand_loop(b_0, b_i, i, dst_prime, (uint8_t) (sizeof dst_prime), b_ii);
    clen = (left>sizeof b_ii)?sizeof b_ii:left;
    memcpy(out, b_ii, clen);
    out+=clen;
    left-=clen;
    // unrolled next iteration so we don't have to swap b_i and b_ii
    expand_loop(b_0, b_ii, i+1, dst_prime, (uint8_t) (sizeof dst_prime), b_i);
    clen = (left>sizeof b_i)?sizeof b_i:left;
    memcpy(out, b_i, clen);
    out+=clen;
    left-=clen;
  }
  return 0;
}

/* hash-to-ristretto255 - as defined by  https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/blob/master/draft-irtf-cfrg-hash-to-curve.md#hashing-to-ristretto255-appx-ristretto255
 * Steps:
 * -1. context-string = \x0 + htons(1) // contextString = I2OSP(modeBase(==0), 1) || I2OSP(suite.ID(==1), 2)
 * 0. dst="HashToGroup-OPRFV1-\x00-ristretto255-SHA512")
 * 1. uniform_bytes = expand_message(msg, DST, 64)
 * 2. P = ristretto255_map(uniform_bytes)
 * 3. return P
 */
int voprf_hash_to_group(const uint8_t *msg, const uint16_t msg_len, uint8_t p[crypto_core_ristretto255_BYTES]) {
  const uint8_t dst[] = "HashToGroup-"VOPRF"-\x00-ristretto255-SHA512";
  const uint8_t dst_len = (sizeof dst) - 1;
  uint8_t uniform_bytes[crypto_core_ristretto255_HASHBYTES]={0};
  if(0!=sodium_mlock(uniform_bytes,sizeof uniform_bytes)) {
    return -1;
  }
  if(0!=oprf_expand_message_xmd(msg, msg_len, dst, dst_len, crypto_core_ristretto255_HASHBYTES, uniform_bytes)) {
    sodium_munlock(uniform_bytes,sizeof uniform_bytes);
    return -1;
  }
#if (defined TRACE || defined CFRG_TEST_VEC)
  dump(uniform_bytes, sizeof uniform_bytes, "uniform_bytes");
#endif
  crypto_core_ristretto255_from_hash(p, uniform_bytes);
  sodium_munlock(uniform_bytes,sizeof uniform_bytes);
#if (defined TRACE || defined CFRG_TEST_VEC)
  dump(p, crypto_core_ristretto255_BYTES, "hashed-to-curve");
#endif
  return 0;
}

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
               uint8_t blinded[crypto_core_ristretto255_BYTES]) {
#if (defined TRACE || defined CFRG_TEST_VEC)
  dump(x, x_len, "input");
#endif
  uint8_t H0[crypto_core_ristretto255_BYTES];
  if(0!=sodium_mlock(H0,sizeof H0)) {
    return -1;
  }
  // sets α := (H^0(pw))^r
  if(0!=voprf_hash_to_group(x, x_len, H0)) return -1;
#if (defined TRACE || defined CFRG_TEST_VEC)
  dump(H0,sizeof H0, "H0");
#endif

  // U picks r
#ifdef CFRG_TEST_VEC
  static int vecidx=0;
  const unsigned char *rtest[2] = {blind_registration, blind_login};
  const unsigned int rtest_len = 32;
  memcpy(r,rtest[vecidx++ % 2],rtest_len);
#else
  crypto_core_ristretto255_scalar_random(r);
#endif

#ifdef TRACE
  dump(r, crypto_core_ristretto255_SCALARBYTES, "r");
#endif
  // H^0(pw)^r
  if (crypto_scalarmult_ristretto255(blinded, r, H0) != 0) {
    sodium_munlock(H0,sizeof H0);
    return -1;
  }
  sodium_munlock(H0,sizeof H0);
#if (defined TRACE || defined CFRG_TEST_VEC)
  dump(blinded, crypto_core_ristretto255_BYTES, "blinded");
#endif
  return 0;
}

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
                  uint8_t Z[crypto_core_ristretto255_BYTES]) {
  return crypto_scalarmult_ristretto255(Z, k, blinded);
}

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
                        uint8_t N[crypto_core_ristretto255_BYTES]) {
#ifdef TRACE
  dump(r, crypto_core_ristretto255_SCALARBYTES, "r ");
  dump(Z, crypto_core_ristretto255_BYTES, "Z ");
#endif

  // (a) Checks that β ∈ G ∗ . If not, outputs (abort, sid , ssid ) and halts;
  if(crypto_core_ristretto255_is_valid_point(Z) != 1) return -1;

  // (b) Computes rw := H(pw, β^1/r );
  // invert r = 1/r
  uint8_t ir[crypto_core_ristretto255_SCALARBYTES];
  if(-1==sodium_mlock(ir, sizeof ir)) return -1;
  if (crypto_core_ristretto255_scalar_invert(ir, r) != 0) {
    sodium_munlock(ir, sizeof ir);
    return -1;
  }
#ifdef TRACE
  dump((uint8_t*) ir, sizeof ir, "r^-1 ");
#endif

  // H0 = β^(1/r)
  // beta^(1/r) = h(pwd)^k
  if (crypto_scalarmult_ristretto255(N, ir, Z) != 0) {
    sodium_munlock(ir, sizeof ir);
    return -1;
  }
#ifdef TRACE
  dump(N, crypto_core_ristretto255_BYTES, "N ");
#endif

  sodium_munlock(ir, sizeof ir);
  return 0;
}
