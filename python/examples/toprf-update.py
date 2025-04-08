#!/usr/bin/env python

"""
Test for TP DKG wrapper of pyoprf/liboprf

  SPDX-FileCopyrightText: 2024, Marsiske Stefan
  SPDX-License-Identifier: LGPL-3.0-or-later

  Copyright (c) 2024, Marsiske Stefan.
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

import pyoprf, pysodium, ctypes as c
from itertools import combinations

n = 9
t = 4
ts_epsilon = 5

# enable verbose logging for tp-dkg
libc = c.cdll.LoadLibrary('libc.so.6')
cstderr = c.c_void_p.in_dll(libc, 'stderr')
log_file = c.c_void_p.in_dll(pyoprf.liboprf,'log_file')
log_file.value = cstderr.value

# create some long-term keypairs
sig_pks = []
sig_sks = []
for _ in range(n+1):
    pk, sk = pysodium.crypto_sign_keypair()
    sig_pks.append(pk)
    sig_sks.append(sk)

noise_pks = []
noise_sks = []
for _ in range(n):
    sk = pysodium.randombytes(pysodium.crypto_scalarmult_SCALARBYTES)
    pk = pysodium.crypto_scalarmult_base(sk)
    noise_sks.append(sk)
    noise_pks.append(pk)

# initialize the TP and get the first message
stp, msg0 = pyoprf.stp_dkg_start_stp(n, t, ts_epsilon, "pyoprf stp_dkg test", sig_pks, sig_sks[0])

print(f"n: {pyoprf.stp_dkg_stpstate_n(stp)}, t: {pyoprf.stp_dkg_stpstate_t(stp)}, sid: {bytes(c for c in pyoprf.stp_dkg_stpstate_sessionid(stp)).hex()}")

# initialize all peers with the 1st message from TP

keystore = { pysodium.crypto_generichash(s): (s, n) for s,n in zip(sig_pks[1:], noise_pks)}
#typedef int (*Keyloader_CB)(const uint8_t id[crypto_generichash_BYTES],
#                 void *arg,
#                 uint8_t sigpk[crypto_sign_PUBLICKEYBYTES],
#                 uint8_t noise_pk[crypto_scalarmult_BYTES]);
@c.CFUNCTYPE(c.c_int, c.POINTER(c.c_ubyte), c.POINTER(c.c_ubyte), c.POINTER(c.c_ubyte), c.POINTER(c.c_ubyte))
def load_key(keyid, arg, sig_pk, noise_pk):
    rec = keystore.get(bytes(keyid[:pysodium.crypto_generichash_BYTES]))
    if rec is None: return 1
    c.memmove(sig_pk, rec[0], len(rec[0]))
    c.memmove(noise_pk, rec[1], len(rec[1]))
    return 0

peers=[]
for i in range(n):
    peer = pyoprf.stp_dkg_peer_start(ts_epsilon, sig_sks[i+1], noise_sks[i], sig_pks[0], msg0, keyloader=load_key)
    peers.append(peer)

for i in range(n):
    assert(pyoprf.stp_dkg_peerstate_sessionid(peers[i]) == pyoprf.stp_dkg_stpstate_sessionid(stp))
    assert(sig_sks[i+1] == pyoprf.stp_dkg_peerstate_lt_sk(peers[i]))

peer_msgs = []
while pyoprf.stp_dkg_stp_not_done(stp):
    ret, sizes = pyoprf.stp_dkg_stp_input_sizes(stp)
    # peer_msgs = (recv(size) for size in sizes)
    msgs = b''.join(peer_msgs)

    cur_step = pyoprf.stp_dkg_stpstate_step(stp)
    try:
      stp_out = pyoprf.stp_dkg_stp_next(stp, msgs)
      #print(f"tp: msg[{tp[0].step}]: {tp_out.raw.hex()}")
    except Exception as e:
      #cheaters, cheats = pyoprf.stp_dkg_get_cheaters(stp)
      #print(f"Warning during the distributed key generation the peers misbehaved: {sorted(cheaters)}")
      #for k, v in cheats:
      #    print(f"\tmisbehaving peer: {k} was caught: {v}")
      raise ValueError(f"{e} | tp step {cur_step}")

    peer_msgs = []
    while(len(b''.join(peer_msgs))==0 and pyoprf.stp_dkg_peer_not_done(peers[0])):
        for i in range(n):
            if(len(stp_out)>0):
                msg = pyoprf.stp_dkg_stp_peer_msg(stp, stp_out, i)
                #print(f"tp -> peer[{i+1}] {msg.hex()}")
            else:
                msg = ''
            out = pyoprf.stp_dkg_peer_next(peers[i], msg)
            if(len(out)>0):
                peer_msgs.append(out)
                #print(f"peer[{i+1}] -> tp {peer_msgs[-1].hex()}")
        stp_out = ''

# we are done, let's check the shares

k0shares = [pyoprf.stp_dkg_peerstate_share(peers[i]) for i in range(n)]
k0commitments = pyoprf.stp_dkg_stpstate_commitments(stp)
print("commitments", k0commitments)
for i, share in enumerate(k0shares):
    print(f"share[{i+1}] {share.hex()} {k0commitments[i].hex()}")
    ci = pyoprf.stp_dkg_peerstate_commitments(peers[i])
    assert ci == k0commitments

kc0, blind = pyoprf.dkg_vss_reconstruct(n, t, 0, k0shares, k0commitments)
print("kc0 is", kc0.hex())

for s_sub in combinations(k0shares, t):
    v, _ = pyoprf.dkg_vss_reconstruct(n, t, 0, s_sub)
    assert kc0 == v

keyid = pyoprf.stp_dkg_stpstate_sessionid(stp)

# clean up allocated buffers
for i in range(n):
    pyoprf.stp_dkg_peer_free(peers[i])

# calculate some OPRF

r, alpha = pyoprf.blind(b"test")
betas = tuple(s[:1]+pyoprf.evaluate(s[1:33], alpha) for s in k0shares)
beta = pyoprf.thresholdmult(betas)
oprfed_test = pyoprf.unblind(r, beta)

print('oprf("test")', oprfed_test.hex())

# tOPRF update

stp, msg0 = pyoprf.tupdate_start_stp(n, t, ts_epsilon, "tOPRF update test", sig_pks, keyid, sig_sks[0], k0commitments)

for s,p in zip(sig_sks, sig_pks):
    print("sp", s.hex(), p.hex())
for s,p in zip(noise_sks, noise_pks):
    print("nsp", s.hex(), p.hex())

peers=[]
for i in range(n):
    ctx, keyid, stp_pub = pyoprf.tupdate_peer_start(ts_epsilon, sig_sks[i+1], msg0)
    #print(keyid.hex(), stp_pub.hex())
    # based on keyid load the relevant parameters: n, t, share, commitment.
    ctx = pyoprf.tupdate_peer_set_bufs(ctx, n, t, i+1, sig_pks, noise_sks[i], noise_pks, k0shares[i], k0commitments)
    peers.append(ctx)
    #print(ctx)

for i in range(n):
    assert(pyoprf.tupdate_peerstate_sessionid(peers[i]) == pyoprf.tupdate_stpstate_sessionid(stp))
    assert(sig_sks[i+1] == pyoprf.tupdate_peerstate_lt_sk(peers[i]))

peer_msgs = []
while pyoprf.tupdate_stp_not_done(stp):
    peer_msgs = []
    while(len(b''.join(peer_msgs))==0 and pyoprf.tupdate_peer_not_done(peers[0])):
        for i in range(n):
            if(len(stp_out)>0):
                msg = pyoprf.tupdate_stp_peer_msg(stp, stp_out, i)
                #print(f"tp -> peer[{i+1}] {msg.hex()}")
            else:
                msg = ''
            out = pyoprf.tupdate_peer_next(peers[i], msg)
            if(len(out)>0):
                peer_msgs.append(out)
                #print(f"peer[{i+1}] -> tp {peer_msgs[-1].hex()}")
        stp_out = ''
    ret, sizes = pyoprf.tupdate_stp_input_sizes(stp)
    # peer_msgs = (recv(size) for size in sizes)
    msgs = b''.join(peer_msgs)

    cur_step = pyoprf.tupdate_stpstate_step(stp)
    try:
      stp_out = pyoprf.tupdate_stp_next(stp, msgs)
      #print(f"tp: msg[{tp[0].step}]: {tp_out.raw.hex()}")
    except Exception as e:
      #cheaters, cheats = pyoprf.stp_dkg_get_cheaters(stp)
      #print(f"Warning during the distributed key generation the peers misbehaved: {sorted(cheaters)}")
      #for k, v in cheats:
      #    print(f"\tmisbehaving peer: {k} was caught: {v}")
      raise ValueError(f"{e} | tp step {cur_step}")

delta = pyoprf.tupdate_stpstate_delta(stp)
print("delta", delta.hex())

k1shares = [pyoprf.tupdate_peerstate_share(peers[i]) for i in range(n)]
k1commitments = tuple(pyoprf.tupdate_peerstate_commitment(peers[i]) for i in range(n))
assert k1commitments == pyoprf.tupdate_stpstate_commitments(stp)
for i, share in enumerate(k1shares):
    print(f"share[{i+1}] {share.hex()} {k1commitments[i].hex()}")
    assert k1commitments == pyoprf.tupdate_peerstate_commitments(peers[i])

kc1, blind = pyoprf.dkg_vss_reconstruct(n, t, 0, k1shares, k1commitments)
print("kc1 is", kc1.hex())

for s_sub in combinations(k1shares, t):
    v, _ = pyoprf.dkg_vss_reconstruct(n, t, 0, s_sub)
    assert kc1 == v

kc0inv = pysodium.crypto_core_ristretto255_scalar_invert(kc0)
deltakc = pysodium.crypto_core_ristretto255_scalar_mul(kc1, kc0inv)
print("delta", deltakc.hex())
assert delta == deltakc

updated_test = pysodium.crypto_scalarmult_ristretto255(deltakc, oprfed_test)

r, alpha = pyoprf.blind(b"test")
betas = tuple(s[:1]+pyoprf.evaluate(s[1:33], alpha) for s in k1shares)
beta = pyoprf.thresholdmult(betas)
updated_oprfed_test = pyoprf.unblind(r, beta)

print('updated oprf\'("test")', updated_test.hex())
print('oprf\'("test")        ', updated_oprfed_test.hex())
