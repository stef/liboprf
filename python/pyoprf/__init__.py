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
import pysodium
from typing import List, Tuple
from itertools import zip_longest

liboprf = ctypes.cdll.LoadLibrary(ctypes.util.find_library('oprf') or ctypes.util.find_library('liboprf'))
if not liboprf._name:
    raise ValueError('Unable to find liboprf')

def split_by_n(iterable, n):
    return list(zip_longest(*[iter(iterable)]*n, fillvalue=''))

def __check(code):
    if code != 0:
        raise ValueError

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
# This is the Evaluate OPRF function defined in the RFC. If the
# internal proxy_cfg variable has been set using oprf_set_evalproxy() then
# the Evaluation will be a threshold computation.
#
# @param [in] key - a private key - the output of keygen() - if
#                     proxy_cfg is set, than this value will be ignored!
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
    peers_len=ctypes.c_size_t(len(x))
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
