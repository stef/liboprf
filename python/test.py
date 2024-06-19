#!/usr/bin/env python3

import pyoprf, pysodium
from binascii import unhexlify

######################################################################

print("CFRG/IRTF spec compliant run")

# Alice blinds the input "test"
r, alpha = pyoprf.blind(b"test")
#print("r    ", r.hex(), "alpha", alpha.hex())

# Bob generates a "secret" key
k = pyoprf.keygen()
#print("k    ", k.hex())

# Bob evaluates Alices blinded value with it's key
beta = pyoprf.evaluate(k, alpha)
#print("beta", beta.hex())

# Alice unblinds Bobs evaluation
N = pyoprf.unblind(r, beta)
#print("N    ", N.hex())

# Alice finalizes the calculation
y = pyoprf.finalize(b"test", N)
#print("y    ", y.hex())

# rerun and assert that oprf(k,"test") equals all runs
r, alpha = pyoprf.blind(b"test")
beta = pyoprf.evaluate(k, alpha)
N = pyoprf.unblind(r, beta)
y2 = pyoprf.finalize(b"test", N)
assert y == y2

######################################################################

print("IRTF/CFRG testvector 1")
x = unhexlify("00")
k = unhexlify("5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e")
out=unhexlify("527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6")

r, alpha = pyoprf.blind(x)
beta = pyoprf.evaluate(k, alpha)
N = pyoprf.unblind(r, beta)
y = pyoprf.finalize(x, N)
assert y == out

######################################################################

print("IRTF/CFRG testvector 2")
x=unhexlify("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a")
out=unhexlify("f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73")
r, alpha = pyoprf.blind(x)
beta = pyoprf.evaluate(k, alpha)
N = pyoprf.unblind(r, beta)
y = pyoprf.finalize(x, N)
assert y == out

######################################################################
# HashDH with update example
print("updatable HashDH")
# Alice blinds the input "test"
r, alpha = pyoprf.blind(b"test")
# Bob generates a "secret" key
k = pyoprf.keygen()

# Bob evaluates Alices blinded value with it's key
beta = pyoprf.evaluate(k, alpha)

# Alice unblinds Bobs evaluation
N = pyoprf.unblind(r, beta)

# Bob updates his key, by generating delta
delta = pysodium.crypto_core_ristretto255_scalar_random()

k2 = pysodium.crypto_core_ristretto255_scalar_mul(k, delta)

# Alice updates her previous calculation of N with delta
N2 = pysodium.crypto_scalarmult_ristretto255(delta, N)

# rerun hashDH to verify if N2 is equal with a full run
r, alpha = pyoprf.blind(b"test")
beta = pyoprf.evaluate(k2, alpha)
N2_ = pyoprf.unblind(r, beta)
assert N2 == N2_


######################################################################
print("tOPRF (hashDH), (3,5), with centrally shared key interpolation at client")
shares = pyoprf.create_shares(k2, 5, 3)
#print(' '.join(s.hex() for s in shares))
# we reuse values from te previous test
betas = tuple(s[:1]+pyoprf.evaluate(s[1:], alpha) for s in shares)
#print(''.join(b.hex() for b in betas))

beta = pyoprf.thresholdmult(betas)
Nt = pyoprf.unblind(r, beta)

assert N2 == Nt

######################################################################
print("tOPRF (hashDH), (3,5), with centrally shared key interpolation at servers")

indexes=(4,2,1)
betas = tuple(pyoprf.threshold_evaluate(shares[i-1], alpha, i, indexes) for i in indexes)

beta = pyoprf.threshold_combine(betas)

Nt2 = pyoprf.unblind(r, beta)
assert Nt == Nt2

######################################################################
print("DKG (3,5)")

n = 5
t = 3
mailboxes=[[] for _ in range(n)]
commitments=[]
for _ in range(n):
    coms, shares = pyoprf.dkg_start(n,t)
    commitments.append(coms)
    for i,s in enumerate(shares):
        mailboxes[i].append(s)

commitments=b''.join(commitments)

shares = []
for i in range(n):
   fails = pyoprf.dkg_verify_commitments(n,t,i+1,
                                         commitments,
                                         mailboxes[i])
   if len(fails) > 0:
       for fail in fails:
           print(f"fail: peer {fail}")
       raise ValueError("failed to verify contributions, aborting")
   xi = pyoprf.dkg_finish(n, mailboxes[i], i+1)
   #print(i, xi.hex(), x_i.hex())
   shares.append(xi)

# test if the final shares all reproduce the same shared `secret`
v0 = pyoprf.thresholdmult([bytes([i+1])+pysodium.crypto_scalarmult_ristretto255_base(shares[i][1:]) for i in (0,1,2)])
v1 = pyoprf.thresholdmult([bytes([i+1])+pysodium.crypto_scalarmult_ristretto255_base(shares[i][1:]) for i in (2,0,4)])
assert v0 == v1
v2 = pyoprf.thresholdmult([bytes([i+1])+pysodium.crypto_scalarmult_ristretto255_base(shares[i][1:]) for i in (1,4,3)])
assert v0 == v2
#print("v0    ", v0.hex())

secret = pyoprf.dkg_reconstruct(shares[:t])
#print("secret", secret.hex())
assert v0 == pysodium.crypto_scalarmult_ristretto255_base(secret)
print("all ok")
