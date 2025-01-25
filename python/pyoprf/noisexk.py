#!/usr/bin/env python
"""
Wrapper for hacl-star XK_Noise

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


import ctypes
import ctypes.util
from ctypes import c_void_p, c_ubyte, c_uint32, c_char, c_size_t, POINTER, byref

lib = ctypes.cdll.LoadLibrary(ctypes.util.find_library('oprf-noiseXK')
                              or ctypes.util.find_library('liboprf-noiseXK'))
if not lib._name:
    raise ValueError('Unable to find liboprf-noiseXK')
libc = ctypes.cdll.LoadLibrary(ctypes.util.find_library('c') or ctypes.util.find_library('libc'))
if not libc._name:
    raise ValueError('Unable to find libc')

KEYSIZE = 32
NOISE_XK_CONF_ZERO = 0
NOISE_XK_AUTH_KNOWN_SENDER_NO_KCI = 2
NOISE_XK_CONF_STRONG_FORWARD_SECRECY = 5

def __check(code):
    if code != 0:
        raise ValueError

lib.Noise_XK_device_add_peer.restype = c_void_p
lib.Noise_XK_device_add_peer.argtypes = [c_void_p, c_void_p, ctypes.c_char_p]
def add_peer(device, name, key):
    return lib.Noise_XK_device_add_peer(device, name, key)

def pubkey(privkey):
    pubkey = ctypes.create_string_buffer(KEYSIZE)
    lib.Noise_XK_dh_secret_to_public(pubkey, privkey)
    return pubkey.raw

lib.Noise_XK_device_create.restype = c_void_p
def create_device(prologue, name, privkey):
    srlz_key = b'\x00'*KEYSIZE
    return lib.Noise_XK_device_create(len(prologue), prologue, name, srlz_key, privkey)

lib.Noise_XK_peer_get_id.restype = c_void_p
lib.Noise_XK_peer_get_id.argtypes = [c_void_p]
def get_peerid(peer):
    return lib.Noise_XK_peer_get_id(peer)

lib.Noise_XK_session_create_initiator.restype = c_void_p
lib.Noise_XK_session_create_initiator.argtypes = [c_void_p, c_void_p]
def create_session_initiator(device, peerid):
    return lib.Noise_XK_session_create_initiator(device, peerid)


lib.Noise_XK_session_create_initiator.restype = c_void_p
lib.Noise_XK_session_create_initiator.argtypes = [c_void_p, c_void_p]
def create_session_initiator(device, peerid):
    res = lib.Noise_XK_session_create_initiator(device, peerid)
    if res == 0: raise ValueError
    return res

lib.Noise_XK_session_create_responder.restype = c_void_p
lib.Noise_XK_session_create_responder.argtypes = [c_void_p]
def create_session_responder(device):
    res = lib.Noise_XK_session_create_responder(device)
    if res == 0: raise ValueError
    return res

lib.Noise_XK_pack_message_with_conf_level.restype = c_void_p
lib.Noise_XK_session_write.argtypes = [c_void_p, c_void_p, POINTER(c_uint32), POINTER(POINTER(c_ubyte))]
lib.Noise_XK_encap_message_p_free.argtypes = [c_void_p]
def initiator_1st_msg(session):
    encap_msg = lib.Noise_XK_pack_message_with_conf_level(0, 0, 0);
    msg_len = c_uint32()
    msg = POINTER(c_ubyte)()
    if 0!=lib.Noise_XK_session_write(encap_msg, session, byref(msg_len), byref(msg)):
        raise ValueError
    lib.Noise_XK_encap_message_p_free(encap_msg)
    res = bytes(msg[i] for i in range(msg_len.value))
    if msg_len.value > 0:
        libc.free(msg)
    return res

# Noise_XK_session_read(&encap_msg, bob_session, cipher_msg_len, cipher_msg);
lib.Noise_XK_session_read.argtypes = [POINTER(c_void_p), c_void_p, c_uint32, POINTER(c_ubyte)]
# Noise_XK_unpack_message_with_auth_level(&plain_msg_len, &plain_msg, NOISE_XK_AUTH_ZERO, encap_msg),
def responder_1st_msg(session, msg):
    encap_msg = c_void_p()
    msg = (c_ubyte * len(msg)).from_buffer(bytearray(msg))
    msg_len = c_uint32(len(msg))
    if 0 != lib.Noise_XK_session_read(byref(encap_msg), session, msg_len, msg):
        raise ValueError
    plain_msg_len = c_uint32()
    plain_msg = POINTER(c_ubyte)()
    if not lib.Noise_XK_unpack_message_with_auth_level(byref(plain_msg_len), byref(plain_msg), 0, encap_msg):
        raise ValueError
    lib.Noise_XK_encap_message_p_free(encap_msg)
    if plain_msg_len.value > 0:
        libc.free(plain_msg)
    return initiator_1st_msg(session)

def initiator_handshake_finish(session, msg):
    encap_msg = c_void_p()
    msg = (c_ubyte * len(msg)).from_buffer(bytearray(msg))
    msg_len = c_uint32(len(msg))
    if 0 != lib.Noise_XK_session_read(byref(encap_msg), session, msg_len, msg):
        raise ValueError
    plain_msg_len = c_uint32()
    plain_msg = POINTER(c_ubyte)()
    if not lib.Noise_XK_unpack_message_with_auth_level(byref(plain_msg_len), byref(plain_msg), 0, encap_msg):
        raise ValueError
    lib.Noise_XK_encap_message_p_free(encap_msg)
    if plain_msg_len.value > 0:
        libc.free(plain_msg)

def send_msg(session, msg):
    if isinstance(msg, str): msg = msg.encode('utf8')
    encap_msg = lib.Noise_XK_pack_message_with_conf_level(NOISE_XK_CONF_STRONG_FORWARD_SECRECY, len(msg), msg);
    ct_len = c_uint32()
    ct = POINTER(c_ubyte)()
    if 0!=lib.Noise_XK_session_write(encap_msg, session, byref(ct_len), byref(ct)):
        raise ValueError
    lib.Noise_XK_encap_message_p_free(encap_msg)
    res = bytes(ct[:ct_len.value])
    if ct_len.value > 0:
        libc.free(ct)
    return res

def read_msg(session, msg):
    encap_msg = c_void_p()
    u_bytes = (c_ubyte * (len(msg)))()
    u_bytes[:] = msg
    if 0 != lib.Noise_XK_session_read(byref(encap_msg), session, len(msg), u_bytes):
        raise ValueError
    plain_msg_len = c_uint32()
    plain_msg = POINTER(c_ubyte)()
    if not lib.Noise_XK_unpack_message_with_auth_level(byref(plain_msg_len), byref(plain_msg),
                                                              NOISE_XK_AUTH_KNOWN_SENDER_NO_KCI, encap_msg):
        raise ValueError
    lib.Noise_XK_encap_message_p_free(encap_msg)
    res = bytes(plain_msg[i] for i in range(plain_msg_len.value))
    if plain_msg_len.value > 0:
        libc.free(plain_msg)
    return res

lib.Noise_XK_session_get_peer_id.restype = c_uint32
lib.Noise_XK_session_get_peer_id.argtypes = [c_void_p]
lib.Noise_XK_device_lookup_peer_by_id.restype = c_void_p
lib.Noise_XK_device_lookup_peer_by_id.argtypes = [c_void_p, c_uint32]
lib.Noise_XK_peer_get_static.argtypes = [(c_char * 32), c_void_p]
def get_pubkey(session, device):
    peerid = lib.Noise_XK_session_get_peer_id(session)
    peer = lib.Noise_XK_device_lookup_peer_by_id(device, peerid);
    pubkey = ctypes.create_string_buffer(KEYSIZE)
    lib.Noise_XK_peer_get_static(pubkey, peer);
    return pubkey.raw

def initiator_session(initiator_privkey, responder_pubkey, iname=None,
                      rname=None, dst=None):
    if dst is None:
        dst = b"liboprf-noiseXK"
    if iname is None:
        iname = b"initiator"
    if rname is None:
        rname = b"responder"
    #initiator_pubkey = pubkey(initiator_privkey)
    dev = create_device(dst, iname, initiator_privkey)
    peer = add_peer(dev, rname, responder_pubkey)
    peerid = get_peerid(peer)

    session = create_session_initiator(dev, peerid)
    msg = initiator_1st_msg(session)
    return session, msg

libc.malloc.restype = POINTER(c_ubyte)
def responder_session(responder_privkey, auth_keys, msg, dst=None, name=None):
    if dst is None:
        dst = b"liboprf-noiseXK"
    if name is None:
        name = b"responder"
    #responder_pubkey = pubkey(responder_privkey)
    dev = create_device(dst, name, responder_privkey)
    for key, peer in auth_keys:
        add_peer(dev,peer,key)
    session = create_session_responder(dev)
    msg = responder_1st_msg(session, msg)
    return session, msg

def initiator_session_complete(session, msg):
    return initiator_handshake_finish(session, msg)

def test():
    from binascii import unhexlify, hexlify
    # low level
    alice_privkey = unhexlify("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    alice_pubkey = pubkey(alice_privkey)
    bob_privkey = unhexlify("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    bob_pubkey = pubkey(bob_privkey)

    adev = create_device("liboprf-noiseXK test", "Alice", alice_privkey)
    bpeer = add_peer(adev, "Bob", bob_pubkey)
    bobid = get_peerid(bpeer)

    bdev = create_device("liboprf-noiseXK test", "Bob", bob_privkey)
    add_peer(bdev, "Alice", alice_pubkey)

    asession = create_session_initiator(adev, bobid)
    bsession = create_session_responder(bdev)

    msg = initiator_1st_msg(asession)

    msg = responder_1st_msg(bsession, msg)

    initiator_handshake_finish(asession, msg)

    ct = send_msg(asession, "hello bob!")
    pt = read_msg(bsession, ct)

    peer_pk = get_pubkey(bsession, bdev)
    print(hexlify(peer_pk))

    print(pt)
    ct = send_msg(bsession, "hello alice!")
    pt = read_msg(asession, ct)
    print(pt)

    # high-level
    a2session, msg = initiator_session(alice_privkey, bob_pubkey)
    b2session, msg = responder_session(bob_privkey, [(alice_pubkey, "Alice")], msg)
    initiator_session_complete(a2session, msg)

    ct = send_msg(a2session, "hello bob!")
    pt = read_msg(b2session, ct)
    print(pt)
    ct = send_msg(b2session, "hello alice!")
    pt = read_msg(a2session, ct)
    print(pt)

    for _ in range(1000):
        if ct[0] % 2 == 0:
            sender = a2session
            receiver = b2session
        else:
            sender = b2session
            receiver = a2session
        message = ct[:16+(ct[1]>>4)] * (ct[1] & 0xf)
        ct = send_msg(sender, message)
        pt = read_msg(receiver, ct)
        assert(pt == message)

if __name__ == '__main__':
    test()
