#include <stdio.h>
#include "../utils.h"
#include "../toprf.h"
#include "../dkg-vss.h"
#include "../mpmult.h"
#include "../toprf-update.h"

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
    uint8_t complaints_len=dkg_vss_verify_commitments(n,t,i+1,dealer_commitments,sent_shares,complaints);
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

int main(const int argc, const char **argv) {
  int ret=0;
  // enable logging
  log_file = stderr;
  debug = 0;

  if(argc<3) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(FUZZ_DUMP)
    fprintf(stderr, "error incorrect numbers of parameters, run as: %% %s <n> <t> [<step> [<path>]]\n", argv[0]);
#else
    fprintf(stderr, "error incorrect numbers of parameters, run as: %% %s <n> <t>\n", argv[0]);
#endif // defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(FUZZ_DUMP)
    exit(1);
  }
  const uint8_t n=atoi(argv[1]);
  const uint8_t t=atoi(argv[2]);

  // share value k0
  TOPRF_Share k0_shares[n][2];
  uint8_t k0_commitments[n][crypto_core_ristretto255_BYTES];
  if(0!=dkg_vss(n,t, k0_shares, k0_commitments)) return 1;
  if(0!=toprf_mpc_vsps_check(t-1, k0_commitments)) return 1;
  debug = 1;
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
  uint8_t msg0[toprf_update_msg0_SIZE];
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
  uint16_t stp_kc1_complaints[n*n];
  memset(stp_kc1_complaints,0,sizeof(stp_kc1_complaints));
  uint16_t stp_p_complaints[n*n];
  memset(stp_p_complaints,0,sizeof(stp_p_complaints));
  uint64_t last_ts[n];
  uint8_t k0p_final_commitments[n][crypto_scalarmult_ristretto255_BYTES];
  uint8_t k1p_final_commitments[n][crypto_scalarmult_ristretto255_BYTES];
  TOPRF_Update_Cheater stp_cheaters[t*t - 1];
  memset(stp_cheaters,0,sizeof(stp_cheaters));
  toprf_update_stp_set_bufs(&stp,
                            &stp_kc1_complaints,
                            &stp_p_complaints,
                            &stp_cheaters,
                            sizeof(stp_cheaters) / sizeof(TOPRF_Update_Cheater),
                            &k0p_final_commitments,
                            &k1p_final_commitments,
                            last_ts);

  TOPRF_Update_PeerState peers[n];
  for(uint8_t i=0;i<n;i++) {
    uint8_t pkid[toprf_keyid_SIZE];
    uint8_t stp_ltpk[crypto_sign_PUBLICKEYBYTES];
    ret = toprf_update_start_peer(&peers[i], dkg_freshness_TIMEOUT,
                                  lt_sks[i+1],
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
  uint8_t peers_noise_pks[n][crypto_scalarmult_BYTES];
  Noise_XK_session_t *noise_outs[n][n];
  memset(noise_outs, 0, sizeof noise_outs);
  Noise_XK_session_t *noise_ins[n][n];
  memset(noise_ins, 0, sizeof noise_ins);
  TOPRF_Share kc1shares[n][n][2];
  memset(kc1shares, 0, sizeof kc1shares);
  TOPRF_Share pshares[n][n][2];
  memset(pshares, 0, sizeof pshares);
  uint8_t kc1_commitments[n][n*n][crypto_core_ristretto255_BYTES];
  memset(kc1_commitments, 0, sizeof kc1_commitments);
  uint8_t p_commitments[n][n*n][crypto_core_ristretto255_BYTES];
  memset(p_commitments, 0, sizeof p_commitments);
  uint16_t peer_kc1_complaints[n][n*n];
  memset(peer_kc1_complaints, 0, sizeof peer_kc1_complaints);
  uint16_t peer_p_complaints[n][n*n];
  memset(peer_p_complaints, 0, sizeof peer_p_complaints);
  uint8_t peer_my_kc1_complaints[n][n];
  memset(peer_my_kc1_complaints, 0, sizeof peer_my_kc1_complaints);
  uint8_t peer_my_p_complaints[n][n];
  memset(peer_my_p_complaints, 0, sizeof peer_my_p_complaints);
  uint64_t peer_last_ts[n][n];
  memset(peer_last_ts, 0, sizeof peer_last_ts);
  const uint8_t dealers = (t-1)*2 + 1;
  uint8_t lambdas[n][dealers][crypto_core_ristretto255_SCALARBYTES];
  TOPRF_Share k0p_shares[n][dealers][2];
  uint8_t k0p_commitments[dealers*n][crypto_core_ristretto255_BYTES];
  uint8_t k0p_commitments0[dealers][crypto_core_ristretto255_BYTES];
  TOPRF_Share k1p_shares[n][dealers][2];
  uint8_t k1p_commitments[dealers*n][crypto_core_ristretto255_BYTES];
  uint8_t k1p_commitments0[dealers][crypto_core_ristretto255_BYTES];
  uint8_t zk_challenge_nonce_commitments[n][n*2][crypto_scalarmult_ristretto255_BYTES];
  uint8_t zk_challenge_nonces[n][n*2][2][crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t zk_challenge_commitments[n][dealers*2][3][crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t zk_challenge_e_i[n][2*dealers][crypto_scalarmult_ristretto255_SCALARBYTES];
  TOPRF_Update_Cheater peer_cheaters[n][t*t - 1];
  memset(peer_cheaters,0,sizeof(peer_cheaters));

  fprintf(stderr, " done\n");

  for(uint8_t i=0;i<n;i++) {
    // in a real deployment peers do not share the same pks buffers
    if(0!=toprf_update_peer_set_bufs(&peers[i], i+1, n, t, k0_shares[i],
                                     &k0_commitments,
                                     &lt_pks, &peers_noise_pks,
                                     &noise_outs[i], &noise_ins[i],
                                     &kc1shares[i], &pshares[i],
                                     &kc1_commitments[i], &p_commitments[i],
                                     &peer_cheaters[i], sizeof(peer_cheaters) / sizeof(TOPRF_Update_Cheater) / n,
                                     &lambdas[i],
                                     &k0p_shares[i],
                                     &k0p_commitments,
                                     &k0p_commitments0,
                                     &k1p_shares[i],
                                     &k1p_commitments,
                                     &k1p_commitments0,
                                     &zk_challenge_nonce_commitments[i],
                                     &zk_challenge_nonces[i],
                                     &zk_challenge_commitments[i],
                                     &zk_challenge_e_i[i],
                                     peer_kc1_complaints[i],
                                     peer_p_complaints[i],
                                     peer_my_kc1_complaints[i],
                                     peer_my_p_complaints[i],
                                     peer_last_ts[i])) {
      fprintf(stderr, "invalid n/t parameters. aborting\n");
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
      if(pkt_len[0]>0) fprintf(stderr, "\x1b[0;31m pkt_len[0] > 0 -> %ld\x1b[0m\n", pkt_len[0]);

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
  uint8_t tmp[crypto_scalarmult_ristretto255_SCALARBYTES];
  TOPRF_Share kc1_shares[t][2];
  for(unsigned i=0;i<t;i++) memcpy((uint8_t*) kc1_shares[i], (uint8_t*) peers[i].kc1_share, 2*TOPRF_Share_BYTES);
  dkg_vss_reconstruct(t, kc1_shares, tmp, NULL);
  uint8_t kc1inv[crypto_scalarmult_ristretto255_SCALARBYTES];
  if(0!=crypto_core_ristretto255_scalar_invert(kc1inv, tmp)) return 1;
  dkg_vss_reconstruct(t, k0_shares, tmp, NULL);
  uint8_t deltakc[crypto_scalarmult_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_mul(deltakc, tmp, kc1inv);
  if(memcmp(stp.delta, deltakc, sizeof deltakc)!=0) {
    dump(stp.delta,  sizeof deltakc, "delta  ");
    dump(deltakc,sizeof deltakc, "deltakc");
  } else {
    dump(stp.delta, sizeof deltakc, "delta");
    fprintf(stderr, "\e[0;32mewige blumenkraft!!5!\x1b[0m\n");
  }

  return ret;
}
