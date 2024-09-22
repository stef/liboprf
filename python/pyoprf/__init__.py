#!/usr/bin/env python
"""
Wrapper for liboprf library

   SPDX-FileCopyrightText: 2023, Marsiske Stefan
   SPDX-License-Identifier: LGPL-3.0-or-later

Copyright (c) 2023, Marsiske Stefan.
All rights reserved.

  This file is part of liboprf.

  liboprf is free software: you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public License
  as published by the Free Software Foundation, either version 3 of
  the License, or (at your option) any later version.

  liboprf is distributed in the hope that it will be
  useful, but WITHOUT ANY WARRANTY; without even the implied
  warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
  See the GNU Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with liboprf. If not, see <http://www.gnu.org/licenses/>.

"""

import ctypes
import ctypes.util
import pysodium, os
from typing import List, Tuple
from itertools import zip_longest

if "BYZANTINE_DKG" in os.environ:
    liboprf = ctypes.cdll.LoadLibrary(os.environ['BYZANTINE_DKG'])
else:
    liboprf = ctypes.cdll.LoadLibrary(ctypes.util.find_library('oprf') or ctypes.util.find_library('liboprf'))

if not liboprf._name:
    raise ValueError('Unable to find liboprf')

def split_by_n(iterable, n):
    return list(zip_longest(*[iter(iterable)]*n, fillvalue=''))

def __check(code):
    if code != 0:
        raise ValueError(f"error: {code}")

# (CFRG/IRTF) OPRF section

OPRF_BYTES=64

# This function generates an OPRF private key.
#
# This is almost the KeyGen OPRF function defined in the RFC: since
# this lib does not implement V oprf, we don't need a pubkey and so
# we don't bother with all that is related.
#
# @param [out] k - the per-user OPRF private key
# void oprf_KeyGen(uint8_t kU[crypto_core_ristretto255_SCALARBYTES]);
def keygen() -> bytes:
    k = ctypes.create_string_buffer(pysodium.crypto_core_ristretto255_SCALARBYTES)
    liboprf.oprf_KeyGen(k)
    return k.raw


# This function converts input x into an element of the OPRF group, randomizes it
# by some scalar r, producing blinded, and outputs (r, blinded).
#
# This is the Blind OPRF function defined in the RFC.
#
# @param [in] x - the input value to blind
# @param [out] r - an OPRF scalar value used for randomization
# @param [out] blinded - a serialized OPRF group element, a byte array of fixed length,
# the blinded version of x, an input to oprf_Evaluate
# @return The function raises a ValueError if there is something wrong with the inputs.
#
#int oprf_Blind(const uint8_t *x, const uint16_t x_len,
#               uint8_t r[crypto_core_ristretto255_SCALARBYTES],
#               uint8_t blinded[crypto_core_ristretto255_BYTES]);
def blind(x: bytes) -> (bytes, bytes):
    r =       ctypes.create_string_buffer(pysodium.crypto_core_ristretto255_SCALARBYTES)
    blinded = ctypes.create_string_buffer(pysodium.crypto_core_ristretto255_BYTES)
    __check(liboprf.oprf_Blind(x, ctypes.c_size_t(len(x)), r, blinded))
    return r.raw, blinded.raw


# This function evaluates input element blinded using private key k, yielding output
# element Z.
#
# This is the Evaluate OPRF function defined in the RFC.
#
# @param [in] key - a private key - the output of keygen()
# @param [in] blinded - a serialized OPRF group element, a byte array
#                     of fixed length, an output of blind()
# @param [out] Z - a serialized OPRF group element, a byte array of fixed
#                     length, an input to oprf_Unblind
# @return The function raises a ValueError if there is something wrong with the inputs.
#int oprf_Evaluate(const uint8_t k[crypto_core_ristretto255_SCALARBYTES],
#                  const uint8_t blinded[crypto_core_ristretto255_BYTES],
#                  uint8_t Z[crypto_core_ristretto255_BYTES]);
def evaluate(key: bytes, blinded: bytes) -> bytes:
    if len(key) != pysodium.crypto_core_ristretto255_SCALARBYTES:
        raise ValueError("key has incorrect length")
    if not isinstance(key, bytes):
        raise ValueError("key is not of type bytes")
    if len(blinded) != pysodium.crypto_core_ristretto255_BYTES:
        raise ValueError("blinded param has incorrect length")
    if not isinstance(blinded, bytes):
        raise ValueError("blinded is not of type bytes")
    Z = ctypes.create_string_buffer(pysodium.crypto_core_ristretto255_BYTES)
    __check(liboprf.oprf_Evaluate(key, blinded, Z))
    return Z.raw


# This function removes random scalar r from Z, yielding output N.
#
# This is the Unblind OPRF function defined in the RFC.
#
# If you do not call finalize() on the result the output is equivalent
# to the OPRF protcol we refer to as HashDH - this protocol retains
# the algebraic structure of the value, and has weaker security
# guarantees, than the full 2HashDH which is equivalent to running
# finalize on the output of blind(). The hashDH variant is not
# explicitly specified by the CFRG/IRTF specification. This hashDH
# variant has one property that makes it interesting: it is an
# updateable OPRF - that is if the server updates their key, they can
# calculate a public delta value, that can be applied by the client to
# the output of blind() and the result will be as if the client and
# the server run the OPRF protocol with the original input and the new
# key. It is important to note that the delta value is not sensitive,
# and can be public.
#
# @param [in] r - an OPRF scalar value used for randomization in oprf_Blind
# @param [in] Z - a serialized OPRF group element, a byte array of fixed length,
#                 an output of oprf_Evaluate
# @param [out] N - a serialized OPRF group element with random scalar r removed,
#                 a byte array of fixed length, an input to oprf_Finalize
# @return The function raises a ValueError if there is something wrong with the inputs.
#int oprf_Unblind(const uint8_t r[crypto_core_ristretto255_SCALARBYTES],
#                 const uint8_t Z[crypto_core_ristretto255_BYTES],
#                 uint8_t N[crypto_core_ristretto255_BYTES]);
def unblind(r: bytes, Z: bytes) -> bytes:
    if len(r) != pysodium.crypto_core_ristretto255_SCALARBYTES:
        raise ValueError("param r has incorrect length")
    if not isinstance(r, bytes):
        raise ValueError("param r is not of type bytes")
    if len(Z) != pysodium.crypto_core_ristretto255_BYTES:
        raise ValueError("param Z has incorrect length")
    if not isinstance(Z, bytes):
        raise ValueError("param Z is not of type bytes")
    N = ctypes.create_string_buffer(pysodium.crypto_core_ristretto255_BYTES)
    __check(liboprf.oprf_Unblind(r, Z, N))
    return N.raw

# This function computes the OPRF output using input x, N, and domain
# separation tag info.
#
# This is the Finalize OPRF function defined in the RFC.
#
# @param [in] x - a value used to compute OPRF (the same value that
#                 was used as input to be blinded)
# @param [in] N - a serialized OPRF group element, a byte array of fixed length,
#                 an output of oprf_Unblind
# @param [out] y - an OPRF output
# @return The function raises a ValueError if there is something wrong with the inputs.
#int oprf_Finalize(const uint8_t *x, const uint16_t x_len,
#                  const uint8_t N[crypto_core_ristretto255_BYTES],
#                  uint8_t rwdU[OPRF_BYTES]);
def finalize(x: bytes, N: bytes) -> bytes:
    if len(N) != pysodium.crypto_core_ristretto255_BYTES:
        raise ValueError("param N has incorrect length")
    if not isinstance(N, bytes):
        raise ValueError("param N is not of type bytes")
    y = ctypes.create_string_buffer(OPRF_BYTES)
    __check(liboprf.oprf_Finalize(x, ctypes.c_size_t(len(x)), N, y))
    return y.raw

# This function combines unblind() and finalize() as a convenience
def unblind_finalize(r: bytes, Z: bytes, x: bytes) -> bytes:
    return finalize(x, unblind(r,Z))

# TOPRF section

TOPRF_Share_BYTES=pysodium.crypto_core_ristretto255_SCALARBYTES+1
TOPRF_Part_BYTES=pysodium.crypto_core_ristretto255_BYTES+1

# This function calculates a lagrange coefficient based on the index
# and the indexes of the other contributing shareholders.
#
# @param [in] index - the index of the shareholder whose lagrange
#             coefficient we're calculating, must be greater than 0
#
# @param [in] peers - list of the shares that contribute to the reconstruction
#
# @param [out] result - the lagrange coefficient
#void coeff(const int index, const int peers_len, const uint8_t peers[peers_len], uint8_t result[crypto_scalarmult_ristretto255_SCALARBYTES]);
def coeff(index: int, peers: list) -> bytes:
    if index < 1: raise ValueError("index must be positive integer")
    if len(peers) < 2: ValueError("peers must be a list of at least 2 integers")
    peers_len=ctypes.c_size_t(len(peers))
    c = ctypes.create_string_buffer(pysodium.crypto_core_ristretto255_SCALARBYTES)
    liboprf.coeff(index, peers_len, peers, c)
    return c.raw


# This function creates shares of secret in a (threshold, n) scheme
# over the curve ristretto255
#
# @param [in] secret - the scalar value to be secretly shared
#
# @param [in] n - the number of shares created
#
# @param [in] threshold - the threshold needed to reconstruct the secret
#
# @param [out] shares - n shares
#
# @return The function raises a ValueError if there is something wrong with the inputs.
#void toprf_create_shares(const uint8_t secret[crypto_core_ristretto255_SCALARBYTES],
#                   const uint8_t n,
#                   const uint8_t threshold,
#                   uint8_t shares[n][TOPRF_Share_BYTES]);
bytes_list_t = List[bytes]
def create_shares(secret: bytes, n: int, t: int) -> bytes_list_t:
    if len(secret) != pysodium.crypto_core_ristretto255_SCALARBYTES:
        raise ValueError("secret has incorrect length")
    if not isinstance(secret, bytes):
        raise ValueError("secret is not of type bytes")
    if n < t:
        raise ValueError("t cannot be bigger than n")
    if t < 2:
        raise ValueError("t must be bigger than 1")
    shares = ctypes.create_string_buffer(n*TOPRF_Share_BYTES)
    __check(liboprf.toprf_create_shares(secret, n, t, shares))
    return tuple([bytes(s) for s in split_by_n(shares.raw, TOPRF_Share_BYTES)])


# This function recovers the secret in the exponent using lagrange interpolation
# over the curve ristretto255
#
# The shareholders are not aware if they are contributing to a
# threshold or non-threshold oprf evaluation, from their perspective
# nothing changes in this approach.
#
# @param [in] responses - is an array of shares (k_i) multiplied by a
#        point (P) on the r255 curve
#
# @param [in] responses_len - the number of elements in the response array
#
# @param [out] result - the reconstructed value of P multipled by k
#
# @return The function raises a ValueError if there is something wrong with the inputs.
#int toprf_thresholdmult(const size_t response_len,
#                        const uint8_t responses[response_len][TOPRF_Part_BYTES],
#                        uint8_t result[crypto_scalarmult_ristretto255_BYTES]);
def thresholdmult(responses: bytes_list_t) -> bytes:
    if len(responses) < 2: ValueError("responses must be a list of at least 2 integers")
    if not all(isinstance(r,bytes) for r in responses):
        raise ValueError("at least one of the responses is not of type bytes")
    if not all(len(r)==TOPRF_Part_BYTES for r in responses):
        raise ValueError("at least one of the responses is not of correct size")
    responses_len=ctypes.c_size_t(len(responses))
    responses_buf = ctypes.create_string_buffer(b''.join(responses))
    result = ctypes.create_string_buffer(pysodium.crypto_core_ristretto255_BYTES)
    __check(liboprf.toprf_thresholdmult(responses_len, responses_buf, result))
    return result.raw


# This function is the efficient threshold version of oprf_Evaluate.
#
# This function needs to know in advance the indexes of all the
# shares that will be combined later in the toprf_thresholdcombine() function.
# by doing so this reduces the total costs and distributes them to the shareholders.
#
# @param [in] k - a private key (for OPAQUE, this is kU, the user's
#        OPRF private key)
#
# @param [in] blinded - a serialized OPRF group element, a byte array
#         of fixed length, an output of oprf_Blind (for OPAQUE, this
#         is the blinded pwdU, the user's password)
#
# @param [in] self - the index of the current shareholder
#
# @param [in] indexes - the indexes of the all the shareholders
#        contributing to this oprf evaluation,
#
# @param [in] index_len - the length of the indexes array,
#
# @param [out] Z - a serialized OPRF group element, a byte array of fixed length,
#        an input to oprf_Unblind
#
# @return The function raises a ValueError if there is something wrong with the inputs.
#int toprf_Evaluate(const uint8_t k[TOPRF_Share_BYTES],
#                   const uint8_t blinded[crypto_core_ristretto255_BYTES],
#                   const uint8_t self, const uint8_t *indexes, const uint16_t index_len,
#                   uint8_t Z[TOPRF_Part_BYTES]);
def threshold_evaluate(k: bytes, blinded: bytes, self: int, indexes: list) -> bytes:
    if len(k) != TOPRF_Share_BYTES:
        raise ValueError("param k has incorrect length")
    if not isinstance(k, bytes):
        raise ValueError("param k is not of type bytes")
    if len(blinded) != pysodium.crypto_core_ristretto255_BYTES:
        raise ValueError("blinded param has incorrect length")
    if not isinstance(blinded, bytes):
        raise ValueError("blinded is not of type bytes")
    if(self>255 or self<1):
        raise ValueError("self outside valid range")
    if(not all(i>0 and i<256 for i in indexes)):
        raise ValueError("index(es) outside valid range")
    index_len=ctypes.c_uint16(len(indexes))

    indexes_buf=ctypes.create_string_buffer(bytes(indexes))
    Z = ctypes.create_string_buffer(TOPRF_Part_BYTES)

    __check(liboprf.toprf_Evaluate(k, blinded, self, indexes_buf, index_len, Z))
    return Z.raw

# This function is combines the results of the toprf_Evaluate()
# function to recover the shared secret in the exponent.
#
# @param [in] responses - is an array of shares (k_i) multiplied by a point (P) on the r255 curve
#
# @param [in] responses_len - the number of elements in the response array
#
# @param [out] result - the reconstructed value of P multipled by k
#
# @return The function raises a ValueError if there is something wrong with the inputs.
#void toprf_thresholdcombine(const size_t response_len,
#                            const uint8_t _responses[response_len][TOPRF_Part_BYTES],
#                            uint8_t result[crypto_scalarmult_ristretto255_BYTES]);
def threshold_combine(responses: bytes_list_t) -> bytes:
    if len(responses) < 2: ValueError("responses must be a list of at least 2 integers")
    if not all(isinstance(r,bytes) for r in responses):
        raise ValueError("at least one of the responses is not of type bytes")
    if not all(len(r)==TOPRF_Part_BYTES for r in responses):
        raise ValueError("at least one of the responses is not of correct size")
    responses_len=ctypes.c_size_t(len(responses))
    responses_buf = ctypes.create_string_buffer(b''.join(responses))
    result = ctypes.create_string_buffer(pysodium.crypto_core_ristretto255_BYTES)

    __check(liboprf.toprf_thresholdcombine(responses_len, responses_buf, result))
    return result.raw

#int toprf_3hashtdh(const uint8_t k[TOPRF_Share_BYTES],
#                   const uint8_t z[TOPRF_Share_BYTES],
#                   const uint8_t alpha[crypto_core_ristretto255_BYTES],
#                   const uint8_t *ssid_S, const uint16_t ssid_S_len,
#                   uint8_t beta[TOPRF_Part_BYTES]);
def _3hashtdh(k: bytes, z: bytes, alpha: bytes, ssid_S: bytes) -> bytes:
    if len(k) != TOPRF_Share_BYTES:
        raise ValueError("param k has incorrect length")
    if not isinstance(k, bytes):
        raise ValueError("param k is not of type bytes")
    if len(z) != TOPRF_Share_BYTES:
        raise ValueError("param z has incorrect length")
    if not isinstance(z, bytes):
        raise ValueError("param z is not of type bytes")
    if len(alpha) != pysodium.crypto_core_ristretto255_BYTES:
        raise ValueError("alpha param has incorrect length")
    if not isinstance(alpha, bytes):
        raise ValueError("alpha is not of type bytes")
    if not isinstance(ssid_S, bytes):
        raise ValueError("ssid_S is not of type bytes")
    if len(ssid_S) > (1<<16)-1:
        raise ValueError("ssid_S is too long")

    ssid_S_len=ctypes.c_uint16(len(ssid_S))
    beta = ctypes.create_string_buffer(TOPRF_Part_BYTES)
    __check(liboprf.toprf_3hashtdh(k, z, alpha, ssid_S, ssid_S_len, beta))
    return beta.raw

# todo documentation!
#int dkg_start(const uint8_t n,
#              const uint8_t threshold,
#              uint8_t commitment_hash[dkg_hash_BYTES],
#              uint8_t commitments[dkg_commitment_BYTES(threshold)],
#              TOPRF_Share shares[n]);
def dkg_start(n : int, t : int) -> (bytes, bytes, bytes_list_t):
    if n < t:
        raise ValueError("t cannot be bigger than n")
    if t < 2:
        raise ValueError("t must be bigger than 1")
    shares = ctypes.create_string_buffer(n*TOPRF_Share_BYTES)
    commitments = ctypes.create_string_buffer(t*pysodium.crypto_core_ristretto255_BYTES)

    __check(liboprf.dkg_start(n, t, commitments, shares))

    shares = tuple([bytes(s) for s in split_by_n(shares.raw, TOPRF_Share_BYTES)])
    return commitments.raw, shares

#int dkg_verify_commitments(const uint8_t n,
#                           const uint8_t threshold,
#                           const uint8_t self,
#                           const uint8_t commitments[n][threshold*crypto_core_ristretto255_BYTES],
#                           const TOPRF_Share shares[n],
#                           uint8_t fails[n],
#                           uint8_t *fails_len);
def dkg_verify_commitments(n: int, t: int, self: int,
                           commitments : bytes_list_t,
                           shares: bytes_list_t) -> bytes:
    if n < t:
        raise ValueError("t cannot be bigger than n")
    if t < 2:
        raise ValueError("t must be bigger than 1")
    if self < 1 or self > n:
        raise ValueError("self must 1 <= self <= n")
    if len(commitments) != n*t*pysodium.crypto_core_ristretto255_BYTES:
        raise ValueError(f"signed_commitments must be {n*t*pysodium.crypto_core_ristretto255_BYTES} bytes is instead: {len(commitments)}")
    shares = b''.join(shares)
    if len(shares) != n*TOPRF_Share_BYTES:
        raise ValueError(f"shares must be {TOPRF_Share_BYTES*n} bytes is instead {len(shares)}")

    shares = ctypes.create_string_buffer(shares)
    fails = ctypes.create_string_buffer(n)
    fails_len = ctypes.c_uint8()
    __check(liboprf.dkg_verify_commitments(n, t, self,
                                           commitments, shares,
                                           fails, ctypes.byref(fails_len)))
    return fails[:fails_len.value]

#void dkg_finish(const uint8_t n,
#                const TOPRF_Share shares[n],
#                const uint8_t self,
#                TOPRF_Share *xi);
def dkg_finish(n: int, shares: List[bytes], self: int, ) -> bytes:
    if self < 1 or self > n:
        raise ValueError("self must 1 <= self <= n")
    shares = b''.join(shares)
    if len(shares) != n*TOPRF_Share_BYTES:
        raise ValueError(f"shares must be {TOPRF_Share_BYTES*n} bytes is instead {len(shares)}")

    shares = ctypes.create_string_buffer(shares)

    xi = ctypes.create_string_buffer(TOPRF_Share_BYTES)
    xi[0]=self

    liboprf.dkg_finish(n, shares, self, xi)
    return xi.raw

#void dkg_reconstruct(const size_t response_len,
#                     const TOPRF_Share responses[response_len][2],
#                     uint8_t result[crypto_scalarmult_ristretto255_BYTES]);
def dkg_reconstruct(responses) -> bytes_list_t:
    rlen = len(responses)
    responses = ctypes.create_string_buffer(b''.join(responses))
    result = ctypes.create_string_buffer(pysodium.crypto_core_ristretto255_BYTES)

    liboprf.dkg_reconstruct(rlen, responses, result)
    return result.raw

tpdkg_sessionid_SIZE=32
tpdkg_msg0_SIZE = 177 # ( sizeof(TP_DKG_Message)                       \
                      # + crypto_generichash_BYTES/*dst*/              \
                      # + 2 /*n,t*/                                    \
                      # + crypto_sign_PUBLICKEYBYTES /* tp_sign_pk */)
tpdkg_msg8_SIZE = 256 # (sizeof(TP_DKG_Message) /* header */                             \
                      #  + noise_xk_handshake3_SIZE /* 4th&final noise handshake */      \
                      #  + sizeof(TOPRF_Share) /* msg: the noise_xk wrapped share */     \
                      #  + crypto_secretbox_xchacha20poly1305_MACBYTES /* mac of msg */  \
                      #  + crypto_auth_hmacsha256_BYTES /* key-committing mac over msg*/ )
tpdkg_max_err_SIZE = 128

class TP_DKG_PeerState(ctypes.Structure):
    _fields_ = [('step',             ctypes.c_int),
                ('prev',             ctypes.c_int),
                ('sessionid',        ctypes.c_uint8 * tpdkg_sessionid_SIZE),
                ('n',                ctypes.c_uint8),
                ('t',                ctypes.c_uint8),
                ('index',            ctypes.c_uint8),
                ('lt_sk',            ctypes.c_uint8 * pysodium.crypto_sign_SECRETKEYBYTES),
                ('sig_pk',           ctypes.c_uint8 * pysodium.crypto_sign_PUBLICKEYBYTES),
                ('sig_sk',           ctypes.c_uint8 * pysodium.crypto_sign_SECRETKEYBYTES),
                ('noise_pk',         ctypes.c_uint8 * pysodium.crypto_scalarmult_BYTES),
                ('noise_sk',         ctypes.c_uint8 * pysodium.crypto_scalarmult_SCALARBYTES),
                ('tp_sig_pk',        ctypes.c_uint8 * pysodium.crypto_sign_PUBLICKEYBYTES),
                ('tp_last_ts',       ctypes.c_uint64),
                ('last_ts',          ctypes.c_void_p),
                ('ts_epsilon',       ctypes.c_uint64),
                ('peer_sig_pks',     ctypes.c_char_p),
                ('peer_noise_pks',   ctypes.c_char_p),
                ('dev',              ctypes.c_void_p),
                ('noise_outs',       ctypes.c_void_p),
                ('noise_ins',        ctypes.c_void_p),
                ('commitments',      ctypes.c_char_p),
                ('shares',           ctypes.c_void_p),
                ('xshares',          ctypes.c_void_p),
                ('complaints_len',   ctypes.c_uint16),
                ('complaints',       ctypes.POINTER(ctypes.c_uint16)),
                ('my_complaints_len',ctypes.c_uint8),
                ('my_complaints',    ctypes.c_char_p),
                ('padding',          ctypes.c_byte * 24), # important padding generichash_state must be 64byte aligned
                ('transcript',       ctypes.c_uint8 * pysodium.crypto_generichash_STATEBYTES),
                ('share',            ctypes.c_uint8 * 33),
                ]

class TP_DKG_Cheater(ctypes.Structure):
    _fields_ = [('step',             ctypes.c_int),
                ('error',            ctypes.c_int),
                ('peer',             ctypes.c_uint8),
                ('other_peer',       ctypes.c_uint8),
                ('invalid_index',    ctypes.c_int),
                ]

class TP_DKG_TPState(ctypes.Structure):
    _fields_ = [('step',             ctypes.c_int),
                ('prev',             ctypes.c_int),
                ('sessionid',        ctypes.c_uint8 * tpdkg_sessionid_SIZE),
                ('n',                ctypes.c_uint8),
                ('t',                ctypes.c_uint8),
                ('sig_pk',           ctypes.c_uint8 * pysodium.crypto_sign_PUBLICKEYBYTES),
                ('sig_sk',           ctypes.c_uint8 * pysodium.crypto_sign_SECRETKEYBYTES),
                ('last_ts',          ctypes.c_void_p),
                ('ts_epsilon',       ctypes.c_uint64),
                ('peer_sig_pks',     ctypes.c_char_p),
                ('peer_lt_pks',      ctypes.c_char_p),
                ('commitments',      ctypes.c_char_p),
                ('encrypted_shares', ctypes.c_char_p),
                ('complaints_len',   ctypes.c_uint16),
                ('complaints',       ctypes.POINTER(ctypes.c_uint16)),
                ('cheater_len',      ctypes.c_size_t),
                ('cheaters',         ctypes.c_void_p),
                ('cheater_max',      ctypes.c_size_t),
                ('padding',          ctypes.c_byte * 24), # important padding generichash_state must be 64byte aligned
                ('transcript',       ctypes.c_uint8 * pysodium.crypto_generichash_STATEBYTES),
                ]

#int tpdkg_start_tp(TP_DKG_TPState *ctx, const uint64_t ts_epsilon,
#             const uint8_t n, const uint8_t t,
#             const char *proto_name, const size_t proto_name_len,
#             const size_t msg0_len, TP_DKG_Message *msg0);
#
# also wraps conveniently:
#
# void tpdkg_tp_set_bufs(TP_DKG_TPState *ctx,
#                  uint8_t (*commitments)[][crypto_core_ristretto255_BYTES],
#                  uint16_t (*complaints)[],
#                  uint8_t (*suspicious)[],
#                  uint8_t (*tp_peers_sig_pks)[][crypto_sign_PUBLICKEYBYTES],
#                  uint8_t (*peer_lt_pks)[][crypto_sign_PUBLICKEYBYTES],
#                  uint64_t (*last_ts)[]);
def tpdkg_start_tp(n, t, ts_epsilon, proto_name, peer_lt_pks):
    state = TP_DKG_TPState()
    # force 32 byte alignment of state
    while ctypes.addressof(state) % 32 != 0:
      state = TP_DKG_TPState()

    msg = ctypes.create_string_buffer(tpdkg_msg0_SIZE)
    __check(liboprf.tpdkg_start_tp(ctypes.byref(state), ts_epsilon, n, t, proto_name, ctypes.c_size_t(len(proto_name)), ctypes.c_size_t(len(msg.raw)), msg))

    peers_sig_pks = ctypes.create_string_buffer(n*pysodium.crypto_sign_PUBLICKEYBYTES)
    commitments = ctypes.create_string_buffer(n*t*pysodium.crypto_core_ristretto255_BYTES)
    complaints = ctypes.create_string_buffer(n*n*2)
    noisy_shares = ctypes.create_string_buffer(n*n*tpdkg_msg8_SIZE)
    cheaters = (TP_DKG_Cheater * (t*t - 1))()
    peer_lt_pks = b''.join(peer_lt_pks)
    last_ts = (ctypes.c_uint64 * n)()

    liboprf.tpdkg_tp_set_bufs(ctypes.byref(state),
                              ctypes.byref(commitments),
                              ctypes.byref(complaints),
                              ctypes.byref(noisy_shares),
                              ctypes.byref(cheaters),
                              len(cheaters),
                              ctypes.byref(peers_sig_pks),
                              peer_lt_pks,
                              ctypes.byref(last_ts))

    # we need to keep these arrays around, otherwise the gc eats them up.
    ctx = (state, cheaters, peers_sig_pks, commitments, complaints, noisy_shares, peer_lt_pks, last_ts)

    return ctx, msg.raw


#size_t tpdkg_tp_input_size(const TP_DKG_TPState *ctx);
def tpdkg_tp_input_size(ctx):
   return liboprf.tpdkg_tp_input_size(ctypes.byref(ctx[0]))

#int tpdkg_tp_input_sizes(const TP_DKG_TPState *ctx, size_t *sizes);
def tpdkg_tp_input_sizes(ctx):
   sizes = (ctypes.c_size_t * ctx[0].n)()
   ret = liboprf.tpdkg_tp_input_sizes(ctypes.byref(ctx[0]), ctypes.byref(sizes))
   return ret, [x for x in sizes]

#size_t tpdkg_tp_output_size(const TP_DKG_TPState *ctx);
def tpdkg_tp_output_size(ctx):
   return liboprf.tpdkg_tp_output_size(ctypes.byref(ctx[0]))

#int tpdkg_tp_next(TP_DKG_TPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len);
def tpdkg_tp_next(ctx, msg):
    input_len = tpdkg_tp_input_size(ctx)
    if len(msg) != input_len: raise ValueError(f"input msg is invalid size: {len(msg)}B must be: {input_len}B")
    output_len = tpdkg_tp_output_size(ctx)
    output = ctypes.create_string_buffer(output_len)
    __check(liboprf.tpdkg_tp_next(ctypes.byref(ctx[0]), msg, input_len, output, output_len))
    return output

#int tpdkg_tp_peer_msg(const TP_DKG_TPState *ctx, const uint8_t *base, const size_t base_size, const uint8_t peer, const uint8_t **msg, size_t *len);
def tpdkg_tp_peer_msg(ctx, base, peer):
    msg = ctypes.POINTER(ctypes.c_char)()
    size = ctypes.c_size_t()
    __check(liboprf.tpdkg_tp_peer_msg(ctypes.byref(ctx[0]), base, len(base.raw), peer, ctypes.byref(msg), ctypes.byref(size)))
    msg = b''.join([msg[i] for i in range(size.value)])
    return msg

#int tpdkg_tp_not_done(const TP_DKG_TPState *tp);
def tpdkg_tp_not_done(ctx):
    return liboprf.tpdkg_tp_not_done(ctypes.byref(ctx[0])) == 1

def tpdkg_get_cheaters(ctx):
    cheats = []
    cheaters = set()
    for i in range(ctx[0].cheater_len):
        err = ctypes.create_string_buffer(tpdkg_max_err_SIZE)
        p = liboprf.tpdkg_cheater_msg(ctypes.byref(ctx[1][i]), err, tpdkg_max_err_SIZE)
        if 0 >= p > ctx[0].n:
            print(f"invalid cheater index: {p}, skipping this entry")
            continue
        cheaters.add(p)
        cheats.append((p, err.raw[:err.raw.find(b'\x00')].decode('utf8')))
    return cheaters, cheats

#int tpdkg_start_peer(TP_DKG_PeerState *ctx, const uint64_t ts_epsilon,
#               const uint8_t peer_lt_sk[crypto_sign_SECRETKEYBYTES],
#               const TP_DKG_Message *msg0);
#
# also wraps conveniently
#
#void tpdkg_peer_set_bufs(TP_DKG_PeerState *ctx,
#                         uint8_t (*peers_sig_pks)[][crypto_sign_PUBLICKEYBYTES],
#                         uint8_t (*peers_noise_pks)[][crypto_scalarmult_BYTES],
#                         Noise_XK_session_t *(*noise_outs)[],
#                         Noise_XK_session_t *(*noise_ins)[],
#                         TOPRF_Share (*shares)[],
#                         TOPRF_Share (*xshares)[],
#                         uint8_t (*commitments)[][crypto_core_ristretto255_BYTES],
#                         uint16_t (*complaints)[],
#                         uint8_t (*my_complaints)[]);
def tpdkg_peer_start(ts_epsilon, peer_lt_sk, msg0):
    state = TP_DKG_PeerState()
    # force 32 byte alignment of state
    while ctypes.addressof(state) % 32 != 0:
      print(f"bad TP_DKG_PeerState alignment: {ctypes.addressof(state) % 32}")
      state = TP_DKG_PeerState()

    __check(liboprf.tpdkg_start_peer(ctypes.byref(state), ts_epsilon, peer_lt_sk, msg0))

    peers_sig_pks = ctypes.create_string_buffer(b"peer_sig_pks", state.n * pysodium.crypto_sign_PUBLICKEYBYTES)
    peers_noise_pks = ctypes.create_string_buffer(b"peer_noise_pks", state.n * pysodium.crypto_scalarmult_BYTES)
    noise_outs = (ctypes.c_void_p * state.n)()
    noise_ins = (ctypes.c_void_p * state.n)()
    shares = ctypes.create_string_buffer(state.n * TOPRF_Share_BYTES)
    xshares = ctypes.create_string_buffer(state.n * TOPRF_Share_BYTES)
    commitments = ctypes.create_string_buffer(state.n * state.t * pysodium.crypto_core_ristretto255_BYTES)
    complaints = ctypes.create_string_buffer(state.n * state.n * 2)
    my_complaints = ctypes.create_string_buffer(state.n)
    last_ts = (ctypes.c_uint64 * state.n)()
    liboprf.tpdkg_peer_set_bufs(ctypes.byref(state),
                                ctypes.byref(peers_sig_pks),
                                ctypes.byref(peers_noise_pks),
                                noise_outs,
                                noise_ins,
                                ctypes.byref(shares),
                                ctypes.byref(xshares),
                                ctypes.byref(commitments),
                                ctypes.byref(complaints),
                                ctypes.byref(my_complaints),
                                ctypes.byref(last_ts))

    # we need to keep these arrays around, otherwise the gc eats them up.
    ctx = (state, peers_sig_pks, peers_noise_pks, noise_outs, noise_ins, shares, xshares, commitments, complaints, my_complaints, last_ts)
    return ctx

#size_t tpdkg_peer_input_size(const TP_DKG_PeerState *ctx);
def tpdkg_peer_input_size(ctx):
   return liboprf.tpdkg_peer_input_size(ctypes.byref(ctx[0]))

#size_t tpdkg_peer_output_size(const TP_DKG_PeerState *ctx);
def tpdkg_peer_output_size(ctx):
   return liboprf.tpdkg_peer_output_size(ctypes.byref(ctx[0]))

#int tpdkg_peer_next(TP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len);
def tpdkg_peer_next(ctx, msg):
    input_len = tpdkg_peer_input_size(ctx)
    if len(msg) != input_len: raise ValueError(f"input msg is invalid size: {len(msg)}B must be: {input_len}B")
    output_len = tpdkg_peer_output_size(ctx)
    output = ctypes.create_string_buffer(output_len)
    __check(liboprf.tpdkg_peer_next(ctypes.byref(ctx[0]), msg, input_len, output, output_len))
    return output.raw

#int tpdkg_peer_not_done(const TP_DKG_PeerState *peer);
def tpdkg_peer_not_done(ctx):
    return liboprf.tpdkg_peer_not_done(ctypes.byref(ctx[0])) == 1

#void tpdkg_peer_free(TP_DKG_PeerState *ctx);
def tpdkg_peer_free(ctx):
    liboprf.tpdkg_peer_free(ctypes.byref(ctx[0]))
