#!/usr/bin/env python3
import unittest
import pyoprf, pysodium, ctypes
from binascii import unhexlify
from itertools import combinations

class TestEndToEnd(unittest.TestCase):
  def test_cfrg_irtf(self):
    """CFRG/IRTF spec compliant run"""
    # Alice blinds the input "test"
    r, alpha = pyoprf.blind(b"test")
    # Bob generates a "secret" key
    k = pyoprf.keygen()
    # Bob evaluates Alices blinded value with it's key
    beta = pyoprf.evaluate(k, alpha)
    # Alice unblinds Bobs evaluation
    N = pyoprf.unblind(r, beta)
    # Alice finalizes the calculation
    y = pyoprf.finalize(b"test", N)
    # rerun and assert that oprf(k,"test") equals all runs
    r, alpha = pyoprf.blind(b"test")
    beta = pyoprf.evaluate(k, alpha)
    N = pyoprf.unblind(r, beta)
    y2 = pyoprf.finalize(b"test", N)
    self.assertEqual(y, y2)

  def test_cfrg_irtf_testvec1(self):
    """IRTF/CFRG testvector 1"""
    x = unhexlify("00")
    k = unhexlify("5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e")
    out=unhexlify("527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6")

    r, alpha = pyoprf.blind(x)
    beta = pyoprf.evaluate(k, alpha)
    N = pyoprf.unblind(r, beta)
    y = pyoprf.finalize(x, N)
    self.assertEqual(y,out)

  def test_cfrg_irtf_testvec2(self):
    """IRTF/CFRG testvector 2"""
    x=unhexlify("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a")
    k = unhexlify("5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e")
    out=unhexlify("f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73")
    r, alpha = pyoprf.blind(x)
    beta = pyoprf.evaluate(k, alpha)
    N = pyoprf.unblind(r, beta)
    y = pyoprf.finalize(x, N)
    self.assertEqual(y, out)

  def test_hashDH_update(self):
    """HashDH with update example"""
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
    self.assertEqual(N2, N2_)


  def test_toprf_sss(self):
    """tOPRF (hashDH), (3,5), with centrally shared key interpolation at client"""
    k2 = pyoprf.keygen()
    shares = pyoprf.create_shares(k2, 5, 3)
    r, alpha = pyoprf.blind(b"test")
    #print(' '.join(s.hex() for s in shares))
    # we reuse values from te previous test
    betas = tuple(s[:1]+pyoprf.evaluate(s[1:], alpha) for s in shares)
    #print(''.join(b.hex() for b in betas))

    beta = pyoprf.thresholdmult(betas)
    Nt = pyoprf.unblind(r, beta)

    beta = pyoprf.evaluate(k2, alpha)
    N2 = pyoprf.unblind(r, beta)
    self.assertEqual(N2, Nt)

  def test_toprf_tcombine(self):
    """tOPRF (hashDH), (3,5), with centrally shared key interpolation at servers"""
    k2 = pyoprf.keygen()
    shares = pyoprf.create_shares(k2, 5, 3)
    r, alpha = pyoprf.blind(b"test")

    indexes=(4,2,1)
    betas = tuple(pyoprf.threshold_evaluate(shares[i-1], alpha, i, indexes) for i in indexes)

    beta = pyoprf.threshold_combine(betas)

    beta = pyoprf.evaluate(k2, alpha)
    Nt = pyoprf.unblind(r, beta)

    Nt2 = pyoprf.unblind(r, beta)
    self.assertEqual(Nt, Nt2)

  def test_raw_dkg(self):
    """naked Distributed KeyGen (3,5)"""
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
    for peers in combinations(range(1,5), 3):
      v1 = pyoprf.thresholdmult([bytes([i+1])+pysodium.crypto_scalarmult_ristretto255_base(shares[i][1:]) for i in peers])
      self.assertEqual(v0, v1)

    secret = pyoprf.dkg_reconstruct(shares[:t])
    #print("secret", secret.hex())
    self.assertEqual(v0, pysodium.crypto_scalarmult_ristretto255_base(secret))

  def test_explicit_3hashtdh(self):
    """toprf based on 2024/1455 [JSPPJ24] https://eprint.iacr.org/2024/1455
       using explicit implementation of 3hashtdh"""

    print("tOPRF (3hashTDH), (3,5), with centrally shared key interpolation at client")
    k2 = pyoprf.keygen()
    shares = pyoprf.create_shares(k2, 5, 3)
    zero_shares = pyoprf.create_shares(bytes([0]*32), 5, 3)

    r, alpha = pyoprf.blind(b"test")

    ssid_S = pysodium.randombytes(32)
    betas = []
    for k, z in zip(shares,zero_shares):
        h2 = pyoprf.evaluate(
            z[1:],
            pysodium.crypto_core_ristretto255_from_hash(pysodium.crypto_generichash(ssid_S + alpha, outlen=64)),
            )
        beta = pyoprf.evaluate(k[1:], alpha)
        betas.append(k[:1]+pysodium.crypto_core_ristretto255_add(beta, h2))

    # normal 2hashdh(k2,"test")
    beta = pyoprf.evaluate(k2, alpha)
    Nt0 = pyoprf.unblind(r, beta)
    for peers in combinations(betas, 3):
        beta = pyoprf.thresholdmult(betas[:3])
        Nt1 = pyoprf.unblind(r, beta)
        self.assertEqual(Nt0, Nt1)

  def test_native_3hashtdh(self):
    """toprf based on 2024/1455 [JSPPJ24] https://eprint.iacr.org/2024/1455
       using libopr native implementation of 3hashtdh
       tOPRF (3hashTDH), (3,5), with centrally shared key interpolation at client"""
    k2 = pyoprf.keygen()
    shares = pyoprf.create_shares(k2, 5, 3)
    zero_shares = pyoprf.create_shares(bytes([0]*32), 5, 3)

    r, alpha = pyoprf.blind(b"test")

    ssid_S = pysodium.randombytes(32)
    betas = []
    for k, z in zip(shares,zero_shares):
        betas.append(pyoprf._3hashtdh(k, z, alpha, ssid_S))

    beta = pyoprf.evaluate(k2, alpha)
    Nt0 = pyoprf.unblind(r, beta)
    for peers in combinations(betas, 3):
        beta = pyoprf.thresholdmult(betas[:3])
        Nt1 = pyoprf.unblind(r, beta)
        self.assertEqual(Nt0, Nt1)

  def test_tp_dkg(self):
    """Trusted Party Distributed KeyGeneration"""
    n = 5
    t = 3
    ts_epsilon = 5

    # enable verbose logging for tp-dkg
    #libc = ctypes.cdll.LoadLibrary('libc.so.6')
    #cstderr = ctypes.c_void_p.in_dll(libc, 'stderr')
    #log_file = ctypes.c_void_p.in_dll(pyoprf.liboprf,'log_file')
    #log_file.value = cstderr.value

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
        self.assertEqual(pyoprf.tpdkg_peerstate_sessionid(peers[i]), pyoprf.tpdkg_tpstate_sessionid(tp))
        self.assertEqual(peer_lt_sks[i], pyoprf.tpdkg_peerstate_lt_sk(peers[i]))

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
    for peers_idxs in combinations(range(1,5), 3):
      v1 = pyoprf.thresholdmult([bytes([i+1])+pysodium.crypto_scalarmult_ristretto255_base(shares[i][1:]) for i in peers_idxs])
      self.assertEqual(v0, v1)

    secret = pyoprf.dkg_reconstruct(shares[:t])
    #print("secret", secret.hex())
    self.assertEqual(v0, pysodium.crypto_scalarmult_ristretto255_base(secret))

    # clean up allocated buffers
    for i in range(n):
        pyoprf.tpdkg_peer_free(peers[i])
