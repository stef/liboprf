#include <stdio.h>
#include <sodium.h>
#include <string.h>
#include "../utils.h"
#include "../toprf.h"
#include "../dkg-vss.h"
#include "../mpmult.h"
#include "../stp-dkg.h"

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

typedef struct {
  size_t len;
  uint8_t (*sig_pks)[][crypto_sign_PUBLICKEYBYTES];
  uint8_t (*noise_pks)[][crypto_scalarmult_BYTES];
} Keyloader_CB_Arg;

int keyloader_cb(const uint8_t id[crypto_generichash_BYTES], void *arg, uint8_t sigpk[crypto_sign_PUBLICKEYBYTES], uint8_t noise_pk[crypto_scalarmult_BYTES]) {
  Keyloader_CB_Arg *args = (Keyloader_CB_Arg *) arg;
  uint8_t pkhash[crypto_generichash_BYTES];
  dump(id, crypto_generichash_BYTES, "loading keys for keyid");
  for(unsigned i=0;i<args->len;i++) {
    crypto_generichash(pkhash,sizeof pkhash,(*args->sig_pks)[i+1],crypto_sign_PUBLICKEYBYTES,NULL,0);
    if(memcmp(pkhash, id, sizeof pkhash) == 0) {
      memcpy(sigpk, (*args->sig_pks)[i+1], crypto_sign_PUBLICKEYBYTES);
      memcpy(noise_pk, (*args->noise_pks)[i], crypto_scalarmult_BYTES);
      return 0;
    }
  }
  return 1;
}

int main(const int argc, const char **argv) {
  int ret=0;
  // enable logging
  liboprf_log_file = stderr;
  liboprf_debug = 1;

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

  // mock long-term peer keys
  // all known by STP
  uint8_t lt_pks[n+1][crypto_sign_PUBLICKEYBYTES];
  // only known by corresponding peer
  uint8_t lt_sks[n+1][crypto_sign_SECRETKEYBYTES];
  for(uint8_t i=0;i<n+1;i++) {
      crypto_sign_keypair(lt_pks[i], lt_sks[i]);
  }

  STP_DKG_STPState stp;
  uint8_t msg0[stpvssdkg_start_msg_SIZE];
  ret = stp_dkg_start_stp(&stp, dkg_freshness_TIMEOUT, n, t,
                               "stp update proto test", 21,
                               &lt_pks, lt_sks[0],
                               sizeof msg0, (STP_DKG_Message*) msg0);
  if(0!=ret) return ret;

  fprintf(stderr, "[T] allocating memory for STP State\n");
  // set bufs
  // we need to store these outside of the ctx, since they are
  // variable size, and the struct can only handle one variable size
  // entry...
  // stp needs to store the complaints, with max n==128 this takes max 32KB of ram.
  uint16_t stp_share_complaints[n*n];
  memset(stp_share_complaints,0,sizeof(stp_share_complaints));
  uint64_t last_ts[n];
  STP_DKG_Cheater stp_cheaters[t*t - 1];
  memset(stp_cheaters,0,sizeof(stp_cheaters));
  uint8_t tp_commitments_hashes[n][stp_dkg_commitment_HASHBYTES];
  memset(tp_commitments_hashes, 0, sizeof tp_commitments_hashes);
  uint8_t tp_share_macs[n*n][crypto_auth_hmacsha256_BYTES];
  memset(tp_share_macs, 0, sizeof tp_share_macs);
  uint8_t tp_commitments[n*n][crypto_core_ristretto255_BYTES];
  memset(tp_commitments, 0, sizeof tp_commitments);
  stp_dkg_stp_set_bufs(&stp,
                           &tp_commitments_hashes,
                           &tp_share_macs,
                           &tp_commitments,
                           &stp_share_complaints,
                           &stp_cheaters,
                           sizeof(stp_cheaters) / sizeof(STP_DKG_Cheater),
                           last_ts);

  STP_DKG_PeerState peers[n];
  uint8_t peers_noise_pks[n][crypto_scalarmult_BYTES];
  uint8_t peers_noise_sks[n][crypto_scalarmult_SCALARBYTES];
  for(uint8_t i=0;i<n;i++) {
    randombytes_buf(peers_noise_sks[i], crypto_scalarmult_SCALARBYTES);
    crypto_scalarmult_base(peers_noise_pks[i], peers_noise_sks[i]);
  }

  for(uint8_t i=0;i<n;i++) {
    uint8_t stp_ltpk[crypto_sign_PUBLICKEYBYTES];
    ret = stp_dkg_start_peer(&peers[i], dkg_freshness_TIMEOUT,
                             lt_sks[i+1],
                             peers_noise_sks[i],
                             (DKG_Message*) msg0,
                             stp_ltpk);
    if(0!=ret) return ret;
    if(memcmp(stp_ltpk, lt_pks[0], crypto_sign_PUBLICKEYBYTES)!=0) {
      return 1;
    }
  }

  fprintf(stderr, "[T] allocating memory for peers state..");
  // now that the peer(s) know the value of N, we can allocate buffers
  // to hold all the sig&noise keys, noise sessions, temp shares, commitments
  uint8_t peerids[n][crypto_generichash_BYTES];
  Noise_XK_session_t *noise_outs[n][n];
  memset(noise_outs, 0, sizeof noise_outs);
  Noise_XK_session_t *noise_ins[n][n];
  memset(noise_ins, 0, sizeof noise_ins);
  TOPRF_Share dealer_shares[n][n][2];
  memset(dealer_shares, 0, sizeof dealer_shares);
  uint8_t encrypted_shares[n][n][noise_xk_handshake3_SIZE + stp_dkg_encrypted_share_SIZE];
  memset(encrypted_shares,0,sizeof encrypted_shares);
  uint8_t dealer_commitments[n][n*n][crypto_core_ristretto255_BYTES];
  memset(dealer_commitments, 0, sizeof dealer_commitments);
  uint8_t share_macs[n][n*n][crypto_auth_hmacsha256_BYTES];
  uint8_t peer_k_commitments[n][n][crypto_core_ristretto255_BYTES];
  memset(peer_k_commitments, 0, sizeof peer_k_commitments);
  uint8_t commitments_hashes[n][n][stp_dkg_commitment_HASHBYTES];
  memset(commitments_hashes, 0, sizeof commitments_hashes);
  uint16_t peer_dealer_share_complaints[n][n*n];
  memset(peer_dealer_share_complaints, 0, sizeof peer_dealer_share_complaints);
  uint8_t peer_my_dealer_share_complaints[n][n];
  memset(peer_my_dealer_share_complaints, 0, sizeof peer_my_dealer_share_complaints);
  uint64_t peer_last_ts[n][n];
  memset(peer_last_ts, 0, sizeof peer_last_ts);
  STP_DKG_Cheater peer_cheaters[n][t*t - 1];
  memset(peer_cheaters,0,sizeof(peer_cheaters));
  Keyloader_CB_Arg cb_arg = {n, &lt_pks, &peers_noise_pks};

  fprintf(stderr, " done\n");

  for(uint8_t i=0;i<n;i++) {
    // in a real deployment peers do not share the same pks buffers
    if(0!=stp_dkg_peer_set_bufs(&peers[i], &peerids,
                                    &keyloader_cb, &cb_arg,
                                    &lt_pks,
                                    &peers_noise_pks,
                                    &noise_outs[i], &noise_ins[i],
                                    &dealer_shares[i],
                                    &encrypted_shares[i],
                                    &share_macs[i],
                                    &dealer_commitments[i],
                                    &peer_k_commitments[i],
                                    &commitments_hashes[i],
                                    &peer_cheaters[i], sizeof(peer_cheaters) / sizeof(STP_DKG_Cheater) / n,
                                    peer_dealer_share_complaints[i],
                                    peer_my_dealer_share_complaints[i],
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
  // end condition for peers is stp_dkg_peer_not_done(&peer)
  while(stp_dkg_stp_not_done(&stp)) {
    // doing vla - but avoiding 0 sized ones is ugly
    const size_t stp_out_size = stp_dkg_stp_output_size(&stp);
    uint8_t stp_out_buf[stp_out_size==0?1:stp_out_size], *stp_out;
    if(stp_out_size==0) stp_out = NULL;
    else stp_out = stp_out_buf;

    // avoiding zero-sized vla is still ugly
    const size_t stp_in_size = stp_dkg_stp_input_size(&stp);
    uint8_t stp_in_buf[stp_in_size==0?1:stp_in_size], *stp_in;
    if(stp_in_size==0) stp_in = NULL;
    else stp_in = stp_in_buf;

    _recv(network_buf[0], &pkt_len[0], stp_in, stp_in_size);

    ret = stp_dkg_stp_next(&stp, stp_in, stp_in_size, stp_out, stp_out_size);
    if(0!=ret) {
      // clean up peers
      for(uint8_t i=0;i<n;i++) stp_dkg_peer_free(&peers[i]);
      if(stp.cheater_len > 0) break;
      return ret;
    }

    for(uint8_t i=0;i<stp.n;i++) {
      const uint8_t *msg;
      size_t len;
      if(0!=stp_dkg_stp_peer_msg(&stp, stp_out, stp_out_size, i, &msg, &len)) {
        return 1;
      }
      _send(network_buf[i+1], &pkt_len[i+1], msg, len);
    }

    while(pkt_len[0]==0 && stp_dkg_peer_not_done(&peers[1])) {
      for(uint8_t i=0;i<n;i++) {
        // 0sized vla meh
        const size_t peer_out_size = stp_dkg_peer_output_size(&peers[i]);
        uint8_t peers_out_buf[peer_out_size==0?1:peer_out_size], *peers_out;
        if(peer_out_size==0) peers_out = NULL;
        else peers_out = peers_out_buf;

        // 0sized vla meh for the last time..
        const size_t peer_in_size = stp_dkg_peer_input_size(&peers[i]);
        uint8_t peer_in_buf[peer_in_size==0?1:peer_in_size], *peer_in;
        if(peer_in_size==0) peer_in = NULL;
        else peer_in = peer_in_buf;

        _recv(network_buf[i+1], &pkt_len[i+1], peer_in, peer_in_size);

        ret = stp_dkg_peer_next(&peers[i],
                              peer_in, peer_in_size,
                              peers_out, peer_out_size);

        if(0!=ret) {
          // clean up peers
          for(uint8_t i=0;i<n;i++) stp_dkg_peer_free(&peers[i]);
          return ret;
        }

        _send(network_buf[0], &pkt_len[0], peers_out, peer_out_size);
      }
    }
  }

  fprintf(stderr, "----------------------------\nfinal results:\n");
  for(unsigned i=0;i<n;i++) {
    if(peers[i].cheater_len>0) {
      fprintf(stderr, "peer %d has detected some cheaters:\n", i+1);
      int total_cheaters=0;
      uint8_t tmp[n+1];
      memset(tmp,0,n+1);
      for(int j=0;j<peers[i].cheater_len;j++) {
        char err[dkg_max_err_SIZE];
        uint8_t p = stp_dkg_peer_cheater_msg(&(*peers[i].cheaters)[j], err, sizeof(err));
        fprintf(stderr,"\x1b[0;31m\t%d. %s\x1b[0m\n", j+1, err);
        if(p==0) continue;
        if(p > n) return 1;
        if(tmp[p]==0) total_cheaters++;
        tmp[p]++;
      }
      fprintf(stderr, RED":/ dkg failed, total cheats detected %d, list of cheaters:", total_cheaters);
      for(int j=1;j<=n;j++) {
        if(tmp[j]==0) continue;
        fprintf(stderr," %d(%d)", j, tmp[j]);
      }
      fprintf(stderr, NORMAL"\n");
      //return 1;
    }
  }

  fprintf(stderr, "----------------------------\nfinal results as seen by stp:\n");
  if(stp.cheater_len>0) {
    int total_cheaters=0;
    uint8_t tmp[n+1];
    memset(tmp,0,n+1);
    for(int i=0;i<stp.cheater_len;i++) {
      char err[dkg_max_err_SIZE];
      uint8_t p = stp_dkg_stp_cheater_msg(&(*stp.cheaters)[i], err, sizeof(err));
      fprintf(stderr,"\x1b[0;31m\t%d. %s\x1b[0m\n", i+1, err);
      if(p==0) continue;
      if(p > n) return 1;
      if(tmp[p]==0) total_cheaters++;
      tmp[p]++;
    }
    fprintf(stderr, RED":/ dkg failed, total cheats detected %d, list of cheaters:", total_cheaters);
    for(int i=1;i<=n;i++) {
      if(tmp[i]==0) continue;
      fprintf(stderr," %d(%d)", i, tmp[i]);
    }
    fprintf(stderr, NORMAL"\n");
    return 1;
  }
  fprintf(stderr, "\x1b[0;32mewige blumenkraft!!5!\x1b[0m\n");

  return ret;
}
