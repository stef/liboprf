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

import pyoprf, pysodium, ctypes

n = 5
t = 3
ts_epsilon = 5

# enable verbose logging for tp-dkg
libc = ctypes.cdll.LoadLibrary('libc.so.6')
cstderr = ctypes.c_void_p.in_dll(libc, 'stderr')
log_file = ctypes.c_void_p.in_dll(pyoprf.liboprf,'log_file')
log_file.value = cstderr.value

# create some long-term keypairs
peer_lt_pks = []
peer_lt_sks = []
for _ in range(n):
    pk, sk = pysodium.crypto_sign_keypair()
    peer_lt_pks.append(pk)
    peer_lt_sks.append(sk)

# initialize the TP and get the first message
tp, msg0 = pyoprf.tpdkg_start_tp(n, t, ts_epsilon, "pyoprf tpdkg test", peer_lt_pks)

print(f"n: {pyoprf.tpdkg_tpstate_n(tp)}, t: {pyoprf.tpdkg_tpstate_t(tp)}, sid: {bytes(c for c in pyoprf.tpdkg_tpstate_sessionid(tp)).hex()}")

# initialize all peers with the 1st message from TP

peers=[]
for i in range(n):
    peer = pyoprf.tpdkg_peer_start(ts_epsilon, peer_lt_sks[i], msg0)
    peers.append(peer)

for i in range(n):
    assert(pyoprf.tpdkg_peerstate_sessionid(peers[i]) == pyoprf.tpdkg_tpstate_sessionid(tp))
    assert(peer_lt_sks[i] == pyoprf.tpdkg_peerstate_lt_sk(peers[i]))

peer_msgs = []
while pyoprf.tpdkg_tp_not_done(tp):
    ret, sizes = pyoprf.tpdkg_tp_input_sizes(tp)
    # peer_msgs = (recv(size) for size in sizes)
    msgs = b''.join(peer_msgs)

    cur_step = pyoprf.tpdkg_tpstate_step(tp)
    try:
      tp_out = pyoprf.tpdkg_tp_next(tp, msgs)
      #print(f"tp: msg[{tp[0].step}]: {tp_out.raw.hex()}")
    except Exception as e:
      cheaters, cheats = pyoprf.tpdkg_get_cheaters(tp)
      print(f"Warning during the distributed key generation the peers misbehaved: {sorted(cheaters)}")
      for k, v in cheats:
          print(f"\tmisbehaving peer: {k} was caught: {v}")
      raise ValueError(f"{e} | tp step {cur_step}")

    peer_msgs = []
    while(len(b''.join(peer_msgs))==0 and pyoprf.tpdkg_peer_not_done(peers[0])):
        for i in range(n):
            if(len(tp_out)>0):
                msg = pyoprf.tpdkg_tp_peer_msg(tp, tp_out, i)
                #print(f"tp -> peer[{i+1}] {msg.hex()}")
            else:
                msg = ''
            out = pyoprf.tpdkg_peer_next(peers[i], msg)
            if(len(out)>0):
                peer_msgs.append(out)
                #print(f"peer[{i+1}] -> tp {peer_msgs[-1].hex()}")
        tp_out = ''

# we are done, let's check the shares

shares = [pyoprf.tpdkg_peerstate_share(peers[i]) for i in range(n)]
for i, share in enumerate(shares):
    print(f"share[{i+1}] {share.hex()}")

v0 = pyoprf.thresholdmult([bytes([i+1])+pysodium.crypto_scalarmult_ristretto255_base(shares[i][1:]) for i in (0,1,2)])
v1 = pyoprf.thresholdmult([bytes([i+1])+pysodium.crypto_scalarmult_ristretto255_base(shares[i][1:]) for i in (2,0,3)])
assert v0 == v1
v2 = pyoprf.thresholdmult([bytes([i+1])+pysodium.crypto_scalarmult_ristretto255_base(shares[i][1:]) for i in (2,1,4)])
assert v0 == v2

secret = pyoprf.dkg_reconstruct(shares[:t])
#print("secret", secret.hex())
assert v0 == pysodium.crypto_scalarmult_ristretto255_base(secret)

# clean up allocated buffers
for i in range(n):
    pyoprf.tpdkg_peer_free(peers[i])
