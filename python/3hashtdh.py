#!/usr/bin/env python

from pyoprf import keygen, create_shares, blind, evaluate, unblind, thresholdmult
from pysodium import randombytes, crypto_core_ristretto255_from_hash, crypto_generichash, crypto_core_ristretto255_add

k = keygen()
shares = create_shares(k, 5, 3)

zero_shares = create_shares(bytes([0]*32), 5, 3)

r, alpha = blind(b"test")

ssid_S = randombytes(32)
betas = []
for ki, zi in zip(shares,zero_shares):
    h2 = evaluate(
        zi[1:],
        crypto_core_ristretto255_from_hash(crypto_generichash(ssid_S + alpha, outlen=64)),
        )
    beta = evaluate(ki[1:], alpha)
    betas.append(ki[:1]+crypto_core_ristretto255_add(beta, h2))

# normal 2hashdh(k,"test")
beta = evaluate(k, alpha)
Nt0 = unblind(r, beta)
print(Nt0)
beta = thresholdmult(betas[:3])
Nt1 = unblind(r, beta)
print(Nt1)
assert Nt0 == Nt1
