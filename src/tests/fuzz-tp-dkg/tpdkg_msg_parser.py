#!/usr/bin/env python

import sys
from construct import *

tpdkg_msg = Struct(
    "signature" / Array(64, Byte),
    "msgno" / Int8ub,
    "size" / Int32ub,
    "sender" / Int8ub,
    "to" / Int8ub,
    "ts" / Timestamp(Int64ub, 1., 1970),
    "data" / Array(this.size - 79, Byte),
)

messages = GreedyRange(tpdkg_msg)

with open(sys.argv[1], 'rb') as fd:
    raw = fd.read()

while len(raw) > 0:
    print(raw[:83].hex())
    try:
        msg = tpdkg_msg.parse(raw)
        print(f"{str(msg.ts)[:-6]} msgno: {msg.msgno}, len: {msg.size}, from: {msg.sender}, to: {msg.to:x}, data {bytes(msg.data).hex()}")
        raw = raw[msg.size:]
    except:
        print(raw[65:69].hex())
        raw = raw[83:]
