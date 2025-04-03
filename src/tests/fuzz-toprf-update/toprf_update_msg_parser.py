#!/usr/bin/env python

import sys
from construct import *

dkg_msg = Struct(
    "signature" / Array(64, Byte),
    "type" / Int8ub,
    "version" / Int8ub,
    "msgno" / Int8ub,
    "size" / Int32ub,
    "sender" / Int8ub,
    "to" / Int8ub,
    "ts" / Timestamp(Int64ub, 1., 1970),
    "sessionid" / Array(32, Byte),
    "data" / Array(this.size - 113, Byte),
)

messages = GreedyRange(dkg_msg)

with open(sys.argv[1], 'rb') as fd:
    raw = fd.read()

while len(raw) > 0:
    print(raw[:113].hex())
    try:
        msg = dkg_msg.parse(raw)
        print(f"{str(msg.ts)[:-6]} type: {msg.type}, version: {msg.version}, msgno: {msg.msgno}, len: {msg.size}, from: {msg.sender}, to: {msg.to:x}\nsessionid: {bytes(msg.sessionid).hex()}\ndata: {bytes(msg.data).hex()}")
        raw = raw[msg.size:]
    except:
        print(raw[67:71].hex())
        raw = raw[113:]
