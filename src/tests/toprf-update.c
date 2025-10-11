#include <stdio.h>
#include "../utils.h"
#include "../toprf.h"
#include "../dkg-vss.h"
#include "../mpmult.h"
#include "../toprf-update.h"
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#include <unistd.h>
#endif

#ifdef __AFL_FUZZ_INIT
__AFL_FUZZ_INIT();
#endif

#ifdef FUZZ_DUMP
#if !defined(FUZZ_PEER)
static void fuzz_dump(const uint8_t step, TOPRF_Update_STPState *ctx, const uint8_t *buf_in, const size_t buf_in_size, const char **argv, const int argc) {
#else
static void fuzz_dump(const uint8_t step, TOPRF_Update_PeerState *ctx, const uint8_t *buf_in, const size_t buf_in_size, const char **argv, const int argc) {
#endif //!defined(FUZZ_PEER)
  if(argc<5) {
    fprintf(stderr, "error incorrect number of params, run as: %% %s <n> <t> <step> <output-file>\n", argv[0]);
    exit(1);
  }
  if(ctx->step==step) {
    FILE *tc = fopen(argv[4], "wb");
    fwrite(buf_in, 1, buf_in_size, tc);
    fclose(tc);
    exit(0);
  }
}
#endif

// simulate network
#define NETWORK_BUF_SIZE (1024*1024*16)
//static size_t _send(uint8_t *net, size_t *pkt_len, const uint8_t *msg, const size_t msg_len) {
static void _send(uint8_t *net, size_t *pkt_len, const uint8_t *msg, const size_t msg_len) {
  if(*pkt_len+msg_len >= NETWORK_BUF_SIZE || msg_len==0 || msg == NULL) {
    return;// 0;
  }
  memcpy(net+*pkt_len, msg, msg_len);
  *pkt_len+=msg_len;
  //return msg_len;
}
//static size_t _recv(const uint8_t *net, size_t *pkt_len, uint8_t *buf, const size_t msg_len) {
static void _recv(const uint8_t *net, size_t *pkt_len, uint8_t *buf, const size_t msg_len) {
  if(*pkt_len < msg_len || msg_len == 0) {
    return; // 0;
  }
  memcpy(buf, net, msg_len);
  *pkt_len-=msg_len;
  //return msg_len;
}

static uint8_t dkg_vss_verify_commitments(const uint8_t n,
                                          const uint8_t self,
                                          const uint8_t commitments[n][n][crypto_core_ristretto255_BYTES],
                                          const TOPRF_Share shares[n][2],
                                          uint8_t complaints[n]) {
  uint8_t complaints_len=0;
  for(uint8_t i=1;i<=n;i++) {
    if(i==self) continue;

    if(0!=dkg_vss_verify_commitment(commitments[i-1][self-1], shares[i-1])) {
      // complain about P_i
      fprintf(stderr, "\x1b[0;31mfailed to verify contribs of P_%d in stage 1\x1b[0m\n", i);
      complaints[complaints_len++]=i;
      //return 1;
    } else {
#ifdef UNIT_TEST
      if(liboprf_debug) fprintf(stderr, "\x1b[0;32mP_%d stage 1 correct!\x1b[0m\n", i);
#endif // UNIT_TEST
    }
  }
  return complaints_len;
}

static int dkg_vss(const uint8_t n, const uint8_t t,
                   TOPRF_Share final_shares[n][2],
                   uint8_t commitments[n][crypto_core_ristretto255_BYTES]) {
  uint8_t dealer_commitments[n][n][crypto_core_ristretto255_BYTES];
  TOPRF_Share shares[n][n][2];

  for(int i=0;i<n;i++) {
    if(dkg_vss_share(n, t, NULL, dealer_commitments[i], shares[i], NULL)) {
      return 1;
    }
    //broadcast dealer_commitments
  }

  // each Pi sends s_ij, and s'_ij to Pj
  // basically we are transposing here the shares matrix above
  TOPRF_Share sent_shares[n][2];

  for(int i=0;i<n;i++) {
    for(int j=0;j<n;j++) {
      memcpy(&sent_shares[j][0], &shares[j][i][0], sizeof(TOPRF_Share));
      memcpy(&sent_shares[j][1], &shares[j][i][1], sizeof(TOPRF_Share));
    }

    uint8_t complaints[n];
    memset(complaints, 0, sizeof complaints);
    uint8_t complaints_len=dkg_vss_verify_commitments(n,i+1,dealer_commitments,sent_shares,complaints);
    if(complaints_len>0) {
      // todo accused dealer P_i publishes α_i, ρ_i such that A_i = 𝓗(α_i,ρ_i)
      // if dealer P_i fails, disqualify them.
      // otherwise the accuser sets their shares to α_i, ρ_i
      return 1;
    }
    // todo handle complaints, build qual set
    uint8_t qual[n+1];
    for(int i=0;i<n;i++) qual[i]=i+1; //everyone qualifies
    qual[n]=0;
    final_shares[i][0].index=i+1;
    final_shares[i][1].index=i+1;
    // finalize dkg
    if(0!=dkg_vss_finish(n,qual,sent_shares,i+1,final_shares[i], commitments[i])) return 1;
  }
  return 0;
}
               
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
#if !defined(FUZZ_PEER)
static int fuzz_loop(const uint8_t step, TOPRF_Update_STPState *stp, TOPRF_Update_PeerState *peers, uint8_t network_buf[][NETWORK_BUF_SIZE],size_t pkt_len[]) {
  if(stp->step!=step) return 0;

  TOPRF_Update_STPState checkpoint;
  memcpy(&checkpoint, stp, sizeof(checkpoint));
  TOPRF_Update_PeerState pcheckpoints[stp->n];
  memcpy(&pcheckpoints, peers, sizeof(pcheckpoints));

#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT
                                             // and before __AFL_LOOP!

  while (__AFL_LOOP(10000)) {

    int len = __AFL_FUZZ_TESTCASE_LEN;  // don't use the macro directly in a call!
    if (len < sizeof(DKG_Message)) continue;  // check for a required/useful minimum input length

    // doing vla - but avoiding 0 sized ones is ugly
    const size_t stp_out_size = toprf_update_stp_output_size(stp);
    uint8_t stp_out_buf[stp_out_size==0?1:stp_out_size], *stp_out;
    if(stp_out_size==0) stp_out = NULL;
    else stp_out = stp_out_buf;

    /* Setup function call, e.g. struct target *tmp = libtarget_init() */
    /* Call function to be fuzzed, e.g.: */
    int ret = toprf_update_stp_next(stp, buf, len, stp_out, stp_out_size);
    if(0!=ret) {
      // clean up peers
      for(uint8_t i=0;i<stp->n;i++) toprf_update_peer_free(&peers[i]);
      if(stp->cheater_len > 0) return 125;
      return ret;
    }

    while(toprf_update_stp_not_done(stp)) {
      for(uint8_t i=0;i<stp->n;i++) {
        const uint8_t *msg;
        size_t len;
        if(0!=toprf_update_stp_peer_msg(stp, stp_out, stp_out_size, i, &msg, &len)) {
          return 1;
        }
        _send(network_buf[i+1], &pkt_len[i+1], msg, len);
      }

      while(pkt_len[0]==0 && toprf_update_peer_not_done(&peers[1])) {
        for(uint8_t i=0;i<stp->n;i++) {
          // 0sized vla meh
          const size_t peer_out_size = toprf_update_peer_output_size(&peers[i]);
          uint8_t peers_out_buf[peer_out_size==0?1:peer_out_size], *peers_out;
          if(peer_out_size==0) peers_out = NULL;
          else peers_out = peers_out_buf;

          // 0sized vla meh for the last time..
          const size_t peer_in_size = toprf_update_peer_input_size(&peers[i]);
          uint8_t peer_in_buf[peer_in_size==0?1:peer_in_size], *peer_in;
          if(peer_in_size==0) peer_in = NULL;
          else peer_in = peer_in_buf;

          _recv(network_buf[i+1], &pkt_len[i+1], peer_in, peer_in_size);
          ret = toprf_update_peer_next(&peers[i],
                                peer_in, peer_in_size,
                                peers_out, peer_out_size);

          if(0!=ret) {
            // clean up peers
            for(uint8_t i=0;i<stp->n;i++) toprf_update_peer_free(&peers[i]);
            return ret;
          }

          _send(network_buf[0], &pkt_len[0], peers_out, peer_out_size);
        }
      }

      // doing vla - but avoiding 0 sized ones is ugly
      const size_t stp_out_size = toprf_update_stp_output_size(stp);
      uint8_t stp_out_buf[stp_out_size==0?1:stp_out_size], *stp_out;
      if(stp_out_size==0) stp_out = NULL;
      else stp_out = stp_out_buf;

      // avoiding zero-sized vla is still ugly
      const size_t stp_in_size = toprf_update_stp_input_size(stp);
      uint8_t stp_in_buf[stp_in_size==0?1:stp_in_size], *stp_in;
      if(stp_in_size==0) stp_in = NULL;
      else stp_in = stp_in_buf;

      _recv(network_buf[0], &pkt_len[0], stp_in, stp_in_size);

      ret = toprf_update_stp_next(stp, stp_in, stp_in_size, stp_out, stp_out_size);
      if(0!=ret) {
        // clean up peers
        for(uint8_t i=0;i<stp->n;i++) toprf_update_peer_free(&peers[i]);
        if(stp->cheater_len > 0) return 55;
        return ret;
      }
    }

    /* Reset state. e.g. libtarget_free(tmp) */
    memcpy(stp, &checkpoint, sizeof(TOPRF_Update_STPState));
    memcpy(peers, &pcheckpoints, sizeof(pcheckpoints));
  }
  return 0;
}
#else // !defined(FUZZ_PEER)
static int fuzz_loop(const uint8_t step, TOPRF_Update_STPState *stp, TOPRF_Update_PeerState *peers, uint8_t network_buf[][NETWORK_BUF_SIZE],size_t pkt_len[]) {
  if(peers[0].step!=step) return 0;

  TOPRF_Update_STPState checkpoint;
  memcpy(&checkpoint, stp, sizeof(checkpoint));
  TOPRF_Update_PeerState pcheckpoints[stp->n];
  memcpy(&pcheckpoints, peers, sizeof(pcheckpoints));

#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT
                                             // and before __AFL_LOOP!

  int ret;
  while (__AFL_LOOP(10000)) {

    int len = __AFL_FUZZ_TESTCASE_LEN;  // don't use the macro directly in a call!
    if (len < sizeof(DKG_Message)) continue;  // check for a required/useful minimum input length

    // doing vla - but avoiding 0 sized ones is ugly
    const size_t peer_out_size = toprf_update_peer_output_size(&peers[0]);
    uint8_t peer_out_buf[peer_out_size==0?1:peer_out_size], *peer_out;
    if(peer_out_size==0) peer_out = NULL;
    else peer_out = peer_out_buf;

    ret = toprf_update_peer_next(&peers[0], buf, len, peer_out, peer_out_size);
    if(ret!=0) {
      //for(uint8_t i=0;i<stp->n;i++) toprf_update_peer_free(&peers[i]);
      return ret;
    }
    _send(network_buf[0], &pkt_len[0], peer_out, peer_out_size);

    for(uint8_t i=1;i<stp->n;i++) {
      // 0sized vla meh
      const size_t peer_out_size = toprf_update_peer_output_size(&peers[i]);
      uint8_t peers_out_buf[peer_out_size==0?1:peer_out_size], *peers_out;
      if(peer_out_size==0) peers_out = NULL;
      else peers_out = peers_out_buf;

      // 0sized vla meh for the last time..
      const size_t peer_in_size = toprf_update_peer_input_size(&peers[i]);
      uint8_t peer_in_buf[peer_in_size==0?1:peer_in_size], *peer_in;
      if(peer_in_size==0) peer_in = NULL;
      else peer_in = peer_in_buf;

      _recv(network_buf[i+1], &pkt_len[i+1], peer_in, peer_in_size);
      ret = toprf_update_peer_next(&peers[i],
                            peer_in, peer_in_size,
                            peers_out, peer_out_size);

      if(0!=ret) {
        // clean up peers
        //for(uint8_t i=0;i<stp->n;i++) toprf_update_peer_free(&peers[i]);
        return ret;
      }
      _send(network_buf[0], &pkt_len[0], peers_out, peer_out_size);
    }

    while(toprf_update_stp_not_done(stp)) {
      while(pkt_len[0]==0 && toprf_update_peer_not_done(&peers[1])) {
        for(uint8_t i=0;i<stp->n;i++) {
          // 0sized vla meh
          const size_t peer_out_size = toprf_update_peer_output_size(&peers[i]);
          uint8_t peers_out_buf[peer_out_size==0?1:peer_out_size], *peers_out;
          if(peer_out_size==0) peers_out = NULL;
          else peers_out = peers_out_buf;

          // 0sized vla meh for the last time..
          const size_t peer_in_size = toprf_update_peer_input_size(&peers[i]);
          uint8_t peer_in_buf[peer_in_size==0?1:peer_in_size], *peer_in;
          if(peer_in_size==0) peer_in = NULL;
          else peer_in = peer_in_buf;

          _recv(network_buf[i+1], &pkt_len[i+1], peer_in, peer_in_size);
          ret = toprf_update_peer_next(&peers[i],
                                peer_in, peer_in_size,
                                peers_out, peer_out_size);

          if(0!=ret) {
            // clean up peers
            //for(uint8_t i=0;i<stp->n;i++) toprf_update_peer_free(&peers[i]);
            return ret;
          }

          _send(network_buf[0], &pkt_len[0], peers_out, peer_out_size);
        }
      }

      // doing vla - but avoiding 0 sized ones is ugly
      const size_t stp_out_size = toprf_update_stp_output_size(stp);
      uint8_t stp_out_buf[stp_out_size==0?1:stp_out_size], *stp_out;
      if(stp_out_size==0) stp_out = NULL;
      else stp_out = stp_out_buf;

      // avoiding zero-sized vla is still ugly
      const size_t stp_in_size = toprf_update_stp_input_size(stp);
      uint8_t stp_in_buf[stp_in_size==0?1:stp_in_size], *stp_in;
      if(stp_in_size==0) stp_in = NULL;
      else stp_in = stp_in_buf;

      _recv(network_buf[0], &pkt_len[0], stp_in, stp_in_size);

      ret = toprf_update_stp_next(stp, stp_in, stp_in_size, stp_out, stp_out_size);
      if(0!=ret) {
        // clean up peers
        for(uint8_t i=0;i<stp->n;i++) toprf_update_peer_free(&peers[i]);
        if(stp->cheater_len > 0) return 55;
        return ret;
      }

      for(uint8_t i=0;i<stp->n;i++) {
        const uint8_t *msg;
        size_t len;
        if(0!=toprf_update_stp_peer_msg(stp, stp_out, stp_out_size, i, &msg, &len)) {
          return 1;
        }
        _send(network_buf[i+1], &pkt_len[i+1], msg, len);
      }
    }

    /* Reset state. e.g. libtarget_free(tmp) */
    memcpy(stp, &checkpoint, sizeof(TOPRF_Update_STPState));
    memcpy(peers, &pcheckpoints, sizeof(pcheckpoints));
  }
  return 0;
}
#endif
#endif

int main(const int argc, const char **argv) {
  int ret=0;
  // enable logging
  liboprf_log_file = stderr;
  liboprf_debug = 0;

  if(argc<3) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(FUZZ_DUMP)
    fprintf(stderr, "error incorrect numbers of parameters, run as: %% %s <n> <t> [<step> [<path>]]\n", argv[0]);
#else
    fprintf(stderr, "error incorrect numbers of parameters, run as: %% %s <n> <t>\n", argv[0]);
#endif // defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(FUZZ_DUMP)
    exit(1);
  }

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(FUZZ_DUMP)
  uint8_t step=atoi(argv[3]);
#ifdef FUZZ_PEER
  if(step<1 || step > 33 ) {
#else
  if(step<1 || step > 23) {
#endif
    fprintf(stderr, "error incorrect value for step must be 1-23 or 33 for peers, run as: %% %s <1..{23|33}> <output-file>\n", argv[0]);
    exit(1);
  }
#endif

  const uint8_t n=atoi(argv[1]);
  const uint8_t t=atoi(argv[2]);
  const uint8_t dealers = (t-1)*2 + 1;

  // share value k0
  TOPRF_Share k0_shares[n][2];
  uint8_t k0_commitments[n][crypto_core_ristretto255_BYTES];
  if(0!=dkg_vss(n,t, k0_shares, k0_commitments)) return 1;
  if(0!=toprf_mpc_vsps_check(t-1, k0_commitments)) return 1;
  liboprf_debug = 1;
  for(int i=0;i<n;i++) {
    dump((uint8_t*) k0_shares[i], sizeof(TOPRF_Share)*2, "k0[%d]", i+1);
    dump(k0_commitments[i], crypto_core_ristretto255_BYTES, "A[%d]", i+1);
  }

  uint8_t kid[toprf_keyid_SIZE];
  randombytes_buf(kid, sizeof kid);

  // mock long-term peer keys
  // all known by TP
  uint8_t lt_pks[n+1][crypto_sign_PUBLICKEYBYTES];
  // only known by corresponding peer
  uint8_t lt_sks[n+1][crypto_sign_SECRETKEYBYTES];
  for(uint8_t i=0;i<n+1;i++) {
      crypto_sign_keypair(lt_pks[i], lt_sks[i]);
  }

  TOPRF_Update_STPState stp;
  uint8_t msg0[toprfupdate_stp_start_msg_SIZE];
  ret = toprf_update_start_stp(&stp, dkg_freshness_TIMEOUT, n, t,
                               "stp update proto test", 21,
                               kid, &lt_pks, lt_sks[0],
                               sizeof msg0, (TOPRF_Update_Message*) msg0);
  if(0!=ret) return ret;

  fprintf(stderr, "[T] allocating memory for STP State\n");
  // set bufs
  // we need to store these outside of the ctx, since they are
  // variable size, and the struct can only handle one variable size
  // entry...
  // stp needs to store the complaints, with max n==128 this takes max 16KB of ram.
  uint16_t stp_p_complaints[n*n];
  memset(stp_p_complaints,0,sizeof(stp_p_complaints));
  uint16_t stp_y2_complaints[n*n];
  memset(stp_y2_complaints,0,sizeof(stp_y2_complaints));
  uint64_t last_ts[n];

  uint8_t stp_p_commitments_hashes[n][toprf_update_commitment_HASHBYTES];
  memset(stp_p_commitments_hashes, 0, sizeof stp_p_commitments_hashes);
  uint8_t stp_p_share_macs[n*n][crypto_auth_hmacsha256_BYTES];
  memset(stp_p_share_macs, 0, sizeof stp_p_share_macs);
  uint8_t stp_p_commitments[n*n][crypto_core_ristretto255_BYTES];
  memset(stp_p_commitments, 0, sizeof stp_p_commitments);

  uint8_t stp_k0p_commitments[dealers*(n+1)][crypto_core_ristretto255_BYTES];
  uint8_t stp_zk_challenge_commitments[dealers*2][3][crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t stp_zk_challenge_e_i[2*dealers][crypto_scalarmult_ristretto255_SCALARBYTES];

  uint8_t k0p_final_commitments[n][crypto_scalarmult_ristretto255_BYTES];
  TOPRF_Update_Cheater stp_cheaters[n*n - 1];
  memset(stp_cheaters,0,sizeof(stp_cheaters));
  toprf_update_stp_set_bufs(&stp,
                            stp_p_complaints,
                            stp_y2_complaints,
                            &stp_cheaters,
                            sizeof(stp_cheaters) / sizeof(TOPRF_Update_Cheater),
                            &stp_p_commitments_hashes,
                            &stp_p_share_macs,
                            &stp_p_commitments,
                            &k0_commitments,
                            &stp_k0p_commitments,
                            &stp_zk_challenge_commitments,
                            &stp_zk_challenge_e_i,
                            &k0p_final_commitments,
                            last_ts);

  TOPRF_Update_PeerState peers[n];

  uint8_t peers_noise_pks[n][crypto_scalarmult_BYTES];
  uint8_t peers_noise_sks[n][crypto_scalarmult_SCALARBYTES];
  for(uint8_t i=0;i<n;i++) {
    randombytes_buf(peers_noise_sks[i], crypto_scalarmult_SCALARBYTES);
    crypto_scalarmult_base(peers_noise_pks[i], peers_noise_sks[i]);
  }

  for(uint8_t i=0;i<n;i++) {
    uint8_t pkid[toprf_keyid_SIZE];
    uint8_t stp_ltpk[crypto_sign_PUBLICKEYBYTES];
    ret = toprf_update_start_peer(&peers[i], dkg_freshness_TIMEOUT,
                                  lt_sks[i+1], peers_noise_sks[i],
                                  (DKG_Message*) msg0,
                                  pkid, stp_ltpk);
    if(0!=ret) return ret;
    // check if stp lt pubkey is in the list of authorized STPs, here only one, but could be a list
    if(memcmp(stp_ltpk, lt_pks[0], crypto_sign_PUBLICKEYBYTES)!=0) {
      return 1;
    }
    // copy stp_ltpk to lt_pks[0] if authorized STPs is a list
    // load share referenced by pkid.
    // set self/peer idx to the index of the loaded share.
  }

  fprintf(stderr, "[T] allocating memory for peers state..");
  // now that the peer(s) know the value of N, we can allocate buffers
  // to hold all the sig&noise keys, noise sessions, temp shares, commitments
  Noise_XK_session_t *noise_outs[n][n];
  memset(noise_outs, 0, sizeof noise_outs);
  Noise_XK_session_t *noise_ins[n][n];
  memset(noise_ins, 0, sizeof noise_ins);

  TOPRF_Share pshares[n][n][2];
  memset(pshares, 0, sizeof pshares);
  uint8_t p_commitments[n][n*n][crypto_core_ristretto255_BYTES];
  memset(p_commitments, 0, sizeof p_commitments);
  uint8_t p_commitments_hashes[n][n][toprf_update_commitment_HASHBYTES];
  memset(p_commitments_hashes, 0, sizeof p_commitments_hashes);
  uint8_t peers_p_share_macs[n][n*n][crypto_auth_hmacsha256_BYTES];
  memset(peers_p_share_macs, 0, sizeof peers_p_share_macs);
  uint16_t peer_p_complaints[n][n*n];
  memset(peer_p_complaints, 0, sizeof peer_p_complaints);
  uint8_t peer_my_p_complaints[n][n];
  memset(peer_my_p_complaints, 0, sizeof peer_my_p_complaints);

  uint8_t encrypted_shares[n][n][noise_xk_handshake3_SIZE + toprf_update_encrypted_shares_SIZE];
  memset(encrypted_shares, 0, sizeof encrypted_shares);

  uint64_t peer_last_ts[n][n];
  memset(peer_last_ts, 0, sizeof peer_last_ts);
  uint8_t lambdas[n][dealers][crypto_core_ristretto255_SCALARBYTES];
  TOPRF_Share k0p_shares[n][dealers][2];
  uint8_t k0p_commitments[n][dealers*(n+1)][crypto_core_ristretto255_BYTES];
  uint8_t zk_challenge_nonce_commitments[n][n][crypto_scalarmult_ristretto255_BYTES];
  uint8_t zk_challenge_nonces[n][n][2][crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t zk_challenge_commitments[n][dealers][3][crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t zk_challenge_e_i[n][dealers][crypto_scalarmult_ristretto255_SCALARBYTES];
  TOPRF_Update_Cheater peer_cheaters[n][n*n - 1];
  memset(peer_cheaters,0,sizeof(peer_cheaters));

  fprintf(stderr, " done\n");

  for(uint8_t i=0;i<n;i++) {
    // in a real deployment peers do not share the same pks buffers
    if(0!=toprf_update_peer_set_bufs(&peers[i], i+1, n, t, k0_shares[i],
                                     &k0_commitments,
                                     &lt_pks, &peers_noise_pks,
                                     &noise_outs[i], &noise_ins[i],
                                     &pshares[i],
                                     &p_commitments[i],
                                     &p_commitments_hashes[i],
                                     &peers_p_share_macs[i],
                                     &encrypted_shares[i],
                                     &peer_cheaters[i], sizeof(peer_cheaters) / sizeof(TOPRF_Update_Cheater) / n,
                                     &lambdas[i],
                                     &k0p_shares[i],
                                     &k0p_commitments[i],
                                     &zk_challenge_nonce_commitments[i],
                                     &zk_challenge_nonces[i],
                                     &zk_challenge_commitments[i],
                                     &zk_challenge_e_i[i],
                                     peer_p_complaints[i],
                                     peer_my_p_complaints[i],
                                     peer_last_ts[i])) {
      fprintf(stderr, "invalid n/t parameters. aborting\n");
      return 1;
    }
  }

  // simulate network.
  uint8_t network_buf[n+1][NETWORK_BUF_SIZE];
  size_t pkt_len[n+1];
  memset(pkt_len,0,sizeof pkt_len);

  // this is the mainloop - normally only one stp or one peer, but here
  // for demo purposes mixed.
  // end condition for peers is toprf_update_peer_not_done(&peer)
  while(toprf_update_peer_not_done(&peers[1])) {
    while(pkt_len[0]==0 && toprf_update_peer_not_done(&peers[1])) {
      for(uint8_t i=0;i<n;i++) {
        // 0sized vla meh
        const size_t peer_out_size = toprf_update_peer_output_size(&peers[i]);
        uint8_t peers_out_buf[peer_out_size==0?1:peer_out_size], *peers_out;
        if(peer_out_size==0) peers_out = NULL;
        else peers_out = peers_out_buf;

        // 0sized vla meh for the last time..
        const size_t peer_in_size = toprf_update_peer_input_size(&peers[i]);
        uint8_t peer_in_buf[peer_in_size==0?1:peer_in_size], *peer_in;
        if(peer_in_size==0) peer_in = NULL;
        else peer_in = peer_in_buf;

        _recv(network_buf[i+1], &pkt_len[i+1], peer_in, peer_in_size);

#if defined(FUZZ_DUMP) && defined(FUZZ_PEER)
        if(i==0) fuzz_dump(step, &peers[i], peer_in, peer_in_size, argv, argc);
#endif
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && defined(FUZZ_PEER)
        ret = fuzz_loop(step, &stp, peers, network_buf, pkt_len);
        if(0!=ret) return ret;
#endif

        ret = toprf_update_peer_next(&peers[i],
                              peer_in, peer_in_size,
                              peers_out, peer_out_size);

        if(0!=ret) {
          // clean up peers
          for(uint8_t i=0;i<n;i++) toprf_update_peer_free(&peers[i]);
          return ret;
        }

        _send(network_buf[0], &pkt_len[0], peers_out, peer_out_size);
      }
    }

    if(toprf_update_stp_not_done(&stp)) {
      // doing vla - but avoiding 0 sized ones is ugly
      const size_t stp_out_size = toprf_update_stp_output_size(&stp);
      uint8_t stp_out_buf[stp_out_size==0?1:stp_out_size], *stp_out;
      if(stp_out_size==0) stp_out = NULL;
      else stp_out = stp_out_buf;

      // avoiding zero-sized vla is still ugly
      const size_t stp_in_size = toprf_update_stp_input_size(&stp);
      uint8_t stp_in_buf[stp_in_size==0?1:stp_in_size], *stp_in;
      if(stp_in_size==0) stp_in = NULL;
      else stp_in = stp_in_buf;

      _recv(network_buf[0], &pkt_len[0], stp_in, stp_in_size);
      if(pkt_len[0]>0) fprintf(stderr, RED"[!] pkt_len[0] > 0 -> %ld unconsumed\n"NORMAL, pkt_len[0]);

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(FUZZ_PEER)
      ret = fuzz_loop(step, &stp, peers, network_buf, pkt_len);
      if(0!=ret) return ret;
#endif
#if defined(FUZZ_DUMP) && !defined(FUZZ_PEER)
      fuzz_dump(step, &stp, stp_in, stp_in_size, argv, argc);
#endif

      ret = toprf_update_stp_next(&stp, stp_in, stp_in_size, stp_out, stp_out_size);
      if(0!=ret) {
        // clean up peers
        for(uint8_t i=0;i<n;i++) toprf_update_peer_free(&peers[i]);
        if(stp.cheater_len > 0) break;
        return ret;
      }

      for(uint8_t i=0;i<stp.n;i++) {
        const uint8_t *msg;
        size_t len;
        if(0!=toprf_update_stp_peer_msg(&stp, stp_out, stp_out_size, i, &msg, &len)) {
          return 1;
        }
        _send(network_buf[i+1], &pkt_len[i+1], msg, len);
      }
    }
  }

  // check if delta is equal kc/kc'
  uint8_t kc0[crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t kc1[crypto_scalarmult_ristretto255_SCALARBYTES];

  dkg_vss_reconstruct(t, 0, n, k0_shares, k0_commitments, kc0, NULL);
  uint8_t kc0inv[crypto_scalarmult_ristretto255_SCALARBYTES];
  if(0!=crypto_core_ristretto255_scalar_invert(kc0inv, kc0)) return 1;

  TOPRF_Share kc1_shares[t][2];
  for(unsigned i=0;i<t;i++) memcpy((uint8_t*) kc1_shares[i], (uint8_t*) peers[i].k0p_share, 2*TOPRF_Share_BYTES);
  dkg_vss_reconstruct(t, 0, n, kc1_shares, NULL, kc1, NULL);

  uint8_t deltakc[crypto_scalarmult_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_mul(deltakc, kc1, kc0inv);
  if(memcmp(stp.delta, deltakc, sizeof deltakc)!=0) {
    dump(stp.delta,  sizeof deltakc, "delta  ");
    dump(deltakc,sizeof deltakc, "deltakc");
  } else {
    dump(stp.delta, sizeof deltakc, "delta");
    fprintf(stderr, "\x1b[0;32mewige blumenkraft!!5!\x1b[0m\n");
  }

  return ret;
}
