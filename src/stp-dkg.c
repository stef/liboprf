#include <arpa/inet.h> //htons
#include "utils.h"
#include "stp-dkg.h"
#include "dkg-vss.h"
#include "mpmult.h"
#ifdef __ZEPHYR__
#include <zephyr/kernel.h>
#endif

/*
    @copyright 2025, Stefan Marsiske toprf@ctrlc.hu
    This file is part of liboprf.

    SPDX-FileCopyrightText: 2024, Marsiske Stefan
    SPDX-License-Identifier: LGPL-3.0-or-later

    liboprf is free software: you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public License
    as published by the Free Software Foundation, either version 3 of
    the License, or (at your option) any later version.

    liboprf is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the License
    along with liboprf. If not, see <http://www.gnu.org/licenses/>.
*/

/*
  This file implements a high-level DKG protocol facilitated by a
  semi-trusted orchestrator which connects to all participating peers
  in a star topology.

  The underlying algorithm is based on the FT-Joint-DL-VSS (fig 7.)
  from R. Gennaro, M. O. Rabin, and T. Rabin. "Simplified VSS and
  fact-track multiparty computations with applications to threshold
  cryptography" In B. A. Coan and Y. Afek, editors, 17th ACM PODC,
  pages 101–111. ACM, June / July 1998
*/


#ifdef UNITTEST_CORRUPT
static void corrupt_vsps_p1t1(STP_DKG_PeerState *ctx) { // deals shares with polynomial t+1 instead of 1
  if(ctx->index!=1) return;
  (void)dkg_vss_share(ctx->n, ctx->t+1, NULL, (*ctx->k_commitments), (*ctx->k_shares), NULL);
}

static void corrupt_commitment_p2(STP_DKG_PeerState *ctx) { // corrupts the 1st commitment with the 2nd
  if(ctx->index!=2) return;
  memcpy((*ctx->k_commitments)[0], (*ctx->k_commitments)[1], crypto_core_ristretto255_BYTES);
}

static void corrupt_wrongshare_correct_commitment_p3(STP_DKG_PeerState *ctx) { // swaps the share and it's blinder,
                                                                           // recalculates commitment
  if(ctx->index!=3) return;
  TOPRF_Share tmp;
  // swap shares for p1
  memcpy(&tmp, &(*ctx->k_shares)[0][0], sizeof tmp);
  memcpy(&(*ctx->k_shares)[0][0], &(*ctx->k_shares)[0][1], sizeof tmp);
  memcpy(&(*ctx->k_shares)[0][1], &tmp, sizeof tmp);
  dkg_vss_commit((*ctx->k_shares)[0][0].value,(*ctx->k_shares)[0][1].value,(*ctx->k_commitments)[0]);
}

static void corrupt_share_p4(STP_DKG_PeerState *ctx) {
  if(ctx->index!=4) return;
  (*ctx->k_shares)[0][0].value[2]^=0xff; // flip some bits
}

static void corrupt_false_accuse_p2p3(STP_DKG_PeerState *ctx, uint8_t *fails_len, uint8_t *fails) {
  if(ctx->index!=2) return;
  fails[(*fails_len)++]=3;
}
#endif // UNITTEST_CORRUPT

size_t stp_dkg_peerstate_size(void) {
  return sizeof(STP_DKG_PeerState);
}
uint8_t stp_dkg_peerstate_n(const STP_DKG_PeerState *ctx) {
  return ctx->n;
}
uint8_t stp_dkg_peerstate_t(const STP_DKG_PeerState *ctx) {
  return ctx->t;
}
const uint8_t* stp_dkg_peerstate_sessionid(const STP_DKG_PeerState *ctx) {
  return ctx->sessionid;
}
const uint8_t* stp_dkg_peerstate_lt_sk(const STP_DKG_PeerState *ctx) {
  return ctx->sig_sk;
}
const uint8_t* stp_dkg_peerstate_share(const STP_DKG_PeerState *ctx) {
  return (const uint8_t*) &ctx->share;
}
const uint8_t* stp_dkg_peerstate_commitments(const STP_DKG_PeerState *ctx) {
  return (const uint8_t*) *ctx->k_commitments;
}
int stp_dkg_peerstate_step(const STP_DKG_PeerState *ctx) {
  return ctx->step;
}

size_t stp_dkg_stpstate_size(void) {
  return sizeof(STP_DKG_STPState);
}
uint8_t stp_dkg_stpstate_n(const STP_DKG_STPState *ctx) {
  return ctx->n;
}
uint8_t stp_dkg_stpstate_t(const STP_DKG_STPState *ctx) {
  return ctx->t;
}
size_t stp_dkg_stpstate_cheater_len(const STP_DKG_STPState *ctx) {
  return ctx->cheater_len;
}
const uint8_t* stp_dkg_stpstate_sessionid(const STP_DKG_STPState *ctx) {
  return ctx->sessionid;
}
const uint8_t* stp_dkg_stpstate_commitments(const STP_DKG_STPState *ctx) {
  return (const uint8_t*) *ctx->commitments;
}
int stp_dkg_stpstate_step(const STP_DKG_STPState *ctx) {
  return ctx->step;
}

static int toprf_send_msg(uint8_t* msg_buf, const size_t msg_buf_len,
                          const uint8_t msgno,
                          const uint8_t from, const uint8_t to,
                          const uint8_t *sig_sk, const uint8_t sessionid[dkg_sessionid_SIZE]) {
  return send_msg(msg_buf, msg_buf_len, MSG_TYPE_SEMI_TRUSTED | MSG_TYPE_DKG, 0, msgno, from, to, sig_sk, sessionid);
}

static int toprf_recv_msg(const uint8_t *msg_buf, const size_t msg_buf_len,
                          const uint8_t msgno,
                          const uint8_t from, const uint8_t to,
                          const uint8_t *sig_pk, const uint8_t sessionid[dkg_sessionid_SIZE],
                          const uint64_t ts_epsilon, uint64_t *last_ts) {
  return recv_msg(msg_buf, msg_buf_len, MSG_TYPE_SEMI_TRUSTED | MSG_TYPE_DKG, 0, msgno, from, to, sig_pk, sessionid, ts_epsilon, last_ts);
}

static void set_cheater(STP_DKG_Cheater *cheater, const int step, const int error, const uint8_t peer, const uint8_t other_peer) {
  cheater->step = step;
  cheater->error = error;
  cheater->peer = peer;
  cheater->other_peer=other_peer;
}

static STP_DKG_Cheater* stp_add_cheater(STP_DKG_STPState *ctx, const int error, const uint8_t peer, const uint8_t other_peer) {
  if(ctx->cheater_len >= ctx->cheater_max) return NULL;
  STP_DKG_Cheater *cheater = &(*ctx->cheaters)[ctx->cheater_len++];
  set_cheater(cheater, ctx->step, error, peer, other_peer);
  return cheater;
}

static STP_DKG_Cheater* peer_add_cheater(STP_DKG_PeerState *ctx,const int error, const uint8_t peer, const uint8_t other_peer) {
  if(ctx->cheater_len >= ctx->cheater_max) return NULL;
  STP_DKG_Cheater *cheater = &(*ctx->cheaters)[ctx->cheater_len++];
  set_cheater(cheater, ctx->step, error, peer, other_peer);
  return cheater;
}

static int stp_recv_msg(STP_DKG_STPState *ctx,
                        const uint8_t *msg_buf, const size_t msg_buf_len,
                        const uint8_t msgno,
                        const uint8_t from, const uint8_t to) {
  dkg_dump_msg(msg_buf, msg_buf_len, 0);
  int ret = toprf_recv_msg(msg_buf, msg_buf_len, msgno, from, to, (*ctx->sig_pks)[from], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts[from-1]);
  if(0!=ret) {
    if(stp_add_cheater(ctx, 64+ret, from, to) == NULL) return STP_DKG_Err_CheatersFull;
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"failed to validate msg %d from %d, err: %d\n"NORMAL, msgno, from, ret);
    return ret;
  }
  return 0;
}

static int peer_recv_msg(STP_DKG_PeerState *ctx,
                         const uint8_t *msg_buf, const size_t msg_buf_len,
                         const uint8_t msgno,
                         const uint8_t from, const uint8_t to) {
  dkg_dump_msg(msg_buf, msg_buf_len, ctx->index);
  int ret = toprf_recv_msg(msg_buf, msg_buf_len, msgno, from, to, (*ctx->sig_pks)[from], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts[from-1]);
  if(0!=ret) {
    if(peer_add_cheater(ctx, 64+ret, from, to) == NULL) return STP_DKG_Err_CheatersFull;
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[%d] failed to validate msg %d from %d, err: %d\n"NORMAL, ctx->index, msgno, from, ret);
    return 1;
  }
  return 0;
}

static STP_DKG_Err stp_broadcast(STP_DKG_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len,
                                      const char *step_title,
                                      const uint8_t msg_count,          // usually n, sometimes dealers
                                      const size_t msg_size,
                                      const uint8_t msgno,
                                      const STP_DKG_STP_Steps next_step) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[!] %s\x1b[0m\n", step_title);
  if(msg_count * msg_size != input_len) return STP_DKG_Err_ISize;
  if(sizeof(STP_DKG_Message) + input_len != output_len) return STP_DKG_Err_OSize;
  size_t cheaters = ctx->cheater_len;
  const uint8_t *ptr = input;
  uint8_t *wptr = ((STP_DKG_Message *) output)->data;
  for(uint8_t i=0;i<msg_count;i++,ptr+=msg_size) {
    if(stp_recv_msg(ctx,ptr,msg_size,msgno,i+1,0xff)) continue;
    memcpy(wptr, ptr, msg_size);
    wptr+=msg_size;
  }
  if(ctx->cheater_len>cheaters) return STP_DKG_Err_CheatersFound;

  if(0!=toprf_send_msg(output, output_len, msgno+1, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return STP_DKG_Err_Send;
  dkg_dump_msg(output, output_len, 0);

  // add broadcast msg to transcript
  update_transcript(&ctx->transcript, output, output_len);

  ctx->step = next_step;

  return STP_DKG_Err_OK;
}

static STP_DKG_Err stp_route(STP_DKG_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len,
                                  const char *step_title,
                                  const uint8_t send_count,
                                  const uint8_t recv_count,
                                  const uint8_t msgno,
                                  const size_t msg_size,
                                  const STP_DKG_STP_Steps next_step) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[!] %s\x1b[0m\n", step_title);
  if(input_len != msg_size * send_count * recv_count) return STP_DKG_Err_ISize;
  if(input_len != output_len) return STP_DKG_Err_OSize;

  const uint8_t (*inputs)[send_count][recv_count][msg_size] = (const uint8_t (*)[send_count][recv_count][msg_size]) input;
  uint8_t *wptr = output;
  for(uint8_t i=0;i<recv_count;i++) {
    for(uint8_t j=0;j<send_count;j++) {
      int ret = toprf_recv_msg((*inputs)[j][i], msg_size,
                               msgno, j+1, i+1, (*ctx->sig_pks)[j+1],
                               ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts[j]);
      if(0!=ret) {
        if(stp_add_cheater(ctx, 64+ret, j+1, i+1) == NULL) return STP_DKG_Err_CheatersFull;
        const STP_DKG_Message *msg = (const STP_DKG_Message*) (*inputs)[j][i];
        fprintf(liboprf_log_file,"[x] msgno: %d, from: %d to: %d err: %d ", msg->msgno, msg->from, msg->to, ret);
        dump((*inputs)[j][i], msg_size, "msg");
        continue;
      }
      memcpy(wptr, (*inputs)[j][i], msg_size);
      wptr+=msg_size;
    }
  }
  //if(ctx->cheater_len>0) return STP_DKG_Err_CheatersFound;

  ctx->step = next_step;
  return STP_DKG_Err_OK;
}

static STP_DKG_Err unwrap_envelope(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, const uint8_t msgno, const uint8_t **contents) {
  // verify STP message envelope
  const STP_DKG_Message* msg = (const STP_DKG_Message*) input;
  dkg_dump_msg(input, input_len, ctx->index);
  int ret = toprf_recv_msg(input, input_len, msgno, 0, 0xff, ctx->stp_sig_pk, ctx->sessionid, ctx->ts_epsilon, &ctx->stp_last_ts);
  if(0!=ret) return STP_DKG_Err_BroadcastEnv+ret;

  // add broadcast msg to transcript
  update_transcript(&ctx->transcript, input, input_len);

  *contents = msg->data;
  return STP_DKG_Err_OK;
}

// todo test this
static void handle_complaints(const uint8_t n,
                              const uint8_t accuser,
                              const char *type,
                              const uint8_t fails_len, const uint8_t fails[],
                              uint16_t *ctx_complaints_len, uint16_t *ctx_complaints,
                              const uint8_t self,
                              uint8_t *ctx_my_complaints_len, uint8_t *ctx_my_complaints) {
  // keep a copy all complaint pairs (complainer, complained)
  for(unsigned k=0;k<fails_len && k<n;k++) {
    if(fails[k] > n || fails[k] < 1) {
      //fails[k] has an invalid peer idx value.
      // todo cheater handling
      //if(stp_add_cheater(ctx, 7, i+1, msg->data[k+1]) == NULL) return 6;
      continue;
    }
    uint16_t pair=(uint16_t) ((accuser<<8) | fails[k]);
    int j=0;
    for(j=0;j<*ctx_complaints_len;j++) if(ctx_complaints[j]==pair) break;
    if(j<*ctx_complaints_len) {
      //already seen this accuser/accused pair.
      // todo cheater handling
      //if(stp_add_cheater(ctx, 18, 8, i+1, msg->data[k+1]) == NULL) return 6;
      continue;
    }
    ctx_complaints[(*ctx_complaints_len)++] = pair;

    if(self!=0 && fails[k] == self && ctx_my_complaints_len != NULL && ctx_my_complaints != NULL) {
      ctx_my_complaints[(*ctx_my_complaints_len)++] = accuser;
    }
    if(liboprf_log_file!=NULL) {
      fprintf(liboprf_log_file,"\x1b[0;31m[!] peer %d failed to verify %s from peer %d!\x1b[0m\n", accuser, type, fails[k]);
    }
  }
}

static STP_DKG_Err ft_or_full_vsps(const uint8_t n, const uint8_t t, const uint8_t dealers, const uint8_t self,
                                        const uint8_t C_i[n][crypto_core_ristretto255_BYTES],
                                        const uint8_t (*C_ij)[n][n][crypto_core_ristretto255_BYTES],
                                        const char *ft_msg, const char *sub_msg, const char *no_sub_msg,
                                        uint8_t *fails_len, uint8_t fails[n]) {
  liboprf_debug=0;
  if(0!=toprf_mpc_vsps_check(t-1, C_i)) {
    if(liboprf_log_file!=NULL) fprintf(stderr, RED"[%d] %s\n"NORMAL, self, ft_msg);
    for(uint8_t i=0;i<dealers;i++) {
      if(0!=toprf_mpc_vsps_check(t-1, (*C_ij)[i])) {
        if(liboprf_log_file!=NULL) fprintf(stderr, RED"[%d] %s [%d]\n"NORMAL, self, sub_msg, i+1);
        fails[(*fails_len)++]=i+1;
      }
    }
    if(*fails_len == 0) {
      if(liboprf_log_file!=NULL) fprintf(stderr, RED"[%d] %s\n"NORMAL, self, no_sub_msg);
      return STP_DKG_Err_NoSubVSPSFail;
    }
  }
  liboprf_debug=1;
  return STP_DKG_Err_OK;
}

int stp_dkg_start_stp(STP_DKG_STPState *ctx, const uint64_t ts_epsilon,
                           const uint8_t n, const uint8_t t,
                           const char *proto_name, const size_t proto_name_len,
                           uint8_t (*sig_pks)[][crypto_sign_PUBLICKEYBYTES],
                           const uint8_t ltssk[crypto_sign_SECRETKEYBYTES],
                           const size_t msg0_len, STP_DKG_Message *msg0) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[!] step 0. start stp vss dkg\x1b[0m\n");
  if(2>n || t>=n || n>128 || n<2*t+1) return 1;
  if(proto_name_len<1) return 2;
  if(proto_name_len>1024) return 3;
  if(msg0_len != stpvssdkg_start_msg_SIZE) return 4;

  ctx->ts_epsilon = ts_epsilon;
  ctx->step = STP_DKG_STP_Send_Index;
  ctx->n = n;
  ctx->t = t;
  ctx->share_complaints_len = 0;
  ctx->cheater_len = 0;

  // dst hash(len(protoname) | "STP VSS DKG for protocol " | protoname | n | t)
  crypto_generichash_state dst_state;
  crypto_generichash_init(&dst_state, NULL, 0, crypto_generichash_BYTES);
  uint16_t len=htons((uint16_t) proto_name_len+20); // we have a guard above restricting to 1KB the proto_name_len
  crypto_generichash_update(&dst_state, (uint8_t*) &len, 2);
  crypto_generichash_update(&dst_state, (const uint8_t*) "STP VSS DKG for protocol ", 25);
  crypto_generichash_update(&dst_state, (const uint8_t*) proto_name, proto_name_len);
  crypto_generichash_update(&dst_state, &n, 1);
  crypto_generichash_update(&dst_state, &t, 1);
  uint8_t dst[crypto_generichash_BYTES];
  crypto_generichash_final(&dst_state,dst,sizeof dst);

  // set sessionid nonce, we abuse this session_id field in the state
  // to temporarily store the session id nonce; which will later
  // become the real session_id after the other peers also contributed
  // their nonces
  randombytes_buf(&ctx->sessionid, sizeof ctx->sessionid);

  // a list of all long-term pubkeys
  ctx->sig_pks = sig_pks;
  // keep a copy of our long-term signing key
  memcpy(ctx->sig_sk, ltssk, crypto_sign_SECRETKEYBYTES);

  // data = {stp_lt_pks, dst, n, t}
  uint8_t *ptr = msg0->data;
  memcpy(ptr, (*sig_pks)[0], crypto_sign_PUBLICKEYBYTES);
  ptr+=crypto_sign_PUBLICKEYBYTES;
  memcpy(ptr, dst, sizeof dst);
  ptr+=sizeof dst;
  *ptr++ = n;
  *ptr++ = t;

  if(0!=toprf_send_msg((uint8_t*) msg0, stpvssdkg_start_msg_SIZE, stpvssdkg_stp_start_msg, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return 5;

  // init transcript
  crypto_generichash_init(&ctx->transcript, NULL, 0, crypto_generichash_BYTES);
  crypto_generichash_update(&ctx->transcript, (const uint8_t*) "stp vss dkg session transcript", 31);
  // feed msg0 into transcript
  update_transcript(&ctx->transcript, (uint8_t*) msg0, msg0_len);

  dkg_dump_msg((uint8_t*) msg0, stpvssdkg_start_msg_SIZE, 0);

  return 0;
}

void stp_dkg_stp_set_bufs(STP_DKG_STPState *ctx,
                              uint8_t (*commitment_hashes)[][stp_dkg_commitment_HASHBYTES],
                              uint8_t (*share_macs)[][crypto_auth_hmacsha256_BYTES],
                              uint8_t (*commitments)[][crypto_core_ristretto255_BYTES],
                              uint16_t (*share_complaints)[],
                              STP_DKG_Cheater (*cheaters)[], const size_t cheater_max,
                              uint64_t *last_ts) {
  ctx->share_complaints = share_complaints;
  ctx->cheaters = cheaters;
  memset(*cheaters, 0, cheater_max*sizeof(STP_DKG_Cheater));
  ctx->commitment_hashes = commitment_hashes;
  ctx->share_macs = share_macs;
  ctx->commitments = commitments;
  ctx->cheater_max = cheater_max;
  ctx->last_ts = last_ts;
#ifdef __ZEPHYR__
  uint64_t now = (uint64_t) k_uptime_get();
#else
  uint64_t now = (uint64_t)time(NULL);
#endif
  for(uint8_t i=0;i<ctx->n;i++) ctx->last_ts[i]=now;
}

STP_DKG_Err stp_dkg_start_peer(STP_DKG_PeerState *ctx,
                               const uint64_t ts_epsilon,
                               const uint8_t lt_sk[crypto_sign_SECRETKEYBYTES],
                               const uint8_t noise_sks[crypto_scalarmult_SCALARBYTES],
                               const STP_DKG_Message *msg0,
                               uint8_t stp_ltpk[crypto_sign_PUBLICKEYBYTES]) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[?] step 0.5 start peer\x1b[0m\n");

  ctx->ts_epsilon = ts_epsilon;
  ctx->stp_last_ts = 0;
  ctx->keyloader_cb_arg = NULL;

  int ret = toprf_recv_msg((const uint8_t*) msg0, stpvssdkg_start_msg_SIZE, stpvssdkg_stp_start_msg, 0, 0xff, msg0->data, msg0->sessionid, ts_epsilon, &ctx->stp_last_ts);
  dkg_dump_msg((const uint8_t*) msg0, stpvssdkg_start_msg_SIZE, 0);
  if(0!=ret) return STP_DKG_Err_Env+ ret;

  // extract data from message
  // we abuse sessionid as a temporary storage for the nonce_stp value, until we have the final sessionid
  memcpy(ctx->sessionid, msg0->sessionid, sizeof ctx->sessionid);

  const uint8_t *ptr=msg0->data;
  memcpy(stp_ltpk,ptr,crypto_sign_PUBLICKEYBYTES);
  memcpy(ctx->stp_sig_pk,ptr,crypto_sign_PUBLICKEYBYTES);

  ptr+=crypto_sign_PUBLICKEYBYTES + crypto_generichash_BYTES; // also skip DST
  ctx->n = *ptr++;
  ctx->t = *ptr++;

  if(ctx->t < 2) return 1;
  if(ctx->t >= ctx->n) return 2;
  if(ctx->n > 128) return 3;

  ctx->share_complaints_len = 0;
  ctx->my_share_complaints_len = 0;
  ctx->cheater_len = 0;
  memcpy(ctx->sig_sk, lt_sk, crypto_sign_SECRETKEYBYTES);
  memcpy(ctx->noise_sk, noise_sks, crypto_scalarmult_SCALARBYTES);

  crypto_generichash_init(&ctx->transcript, NULL, 0, crypto_generichash_BYTES);
  crypto_generichash_update(&ctx->transcript, (const uint8_t*) "stp vss dkg session transcript", 31);
  // feed msg0 into transcript
  update_transcript(&ctx->transcript, (const uint8_t*) msg0, stpvssdkg_start_msg_SIZE);

  ctx->dev = NULL;
  ctx->step = STP_DKG_Peer_Broadcast_NPK_SIDNonce;

  return STP_DKG_Err_OK;
}

int stp_dkg_peer_set_bufs(STP_DKG_PeerState *ctx,
                          uint8_t (*peerids)[][crypto_generichash_BYTES],
                          Keyloader_CB keyloader_cb,
                          void *keyloader_cb_arg,
                          uint8_t (*peers_sig_pks)[][crypto_sign_PUBLICKEYBYTES],
                          uint8_t (*peers_noise_pks)[][crypto_scalarmult_BYTES],
                          Noise_XK_session_t *(*noise_outs)[],
                          Noise_XK_session_t *(*noise_ins)[],
                          TOPRF_Share (*k_shares)[][2],
                          uint8_t (*encrypted_shares)[][TOPRF_Share_BYTES * 2 + noise_xk_handshake3_SIZE + crypto_secretbox_xchacha20poly1305_MACBYTES],
                          uint8_t (*share_macs)[][crypto_auth_hmacsha256_BYTES],
                          uint8_t (*ki_commitments)[][crypto_core_ristretto255_BYTES],
                          uint8_t (*k_commitments)[][crypto_core_ristretto255_BYTES],
                          uint8_t (*commitments_hashes)[][stp_dkg_commitment_HASHBYTES],
                          STP_DKG_Cheater (*cheaters)[], const size_t cheater_max,
                          uint16_t *share_complaints,
                          uint8_t *my_share_complaints,
                          uint64_t *last_ts) {
  ctx->peerids = peerids;
  ctx->keyloader_cb = keyloader_cb;
  ctx->keyloader_cb_arg = keyloader_cb_arg;
  ctx->sig_pks = peers_sig_pks;
  ctx->peer_noise_pks = peers_noise_pks;
  ctx->noise_outs = noise_outs;
  ctx->noise_ins = noise_ins;
  ctx->k_shares = k_shares;
  ctx->encrypted_shares = encrypted_shares;
  ctx->share_macs = share_macs;
  ctx->ki_commitments = ki_commitments;
  ctx->k_commitments = k_commitments;
  ctx->commitments_hashes = commitments_hashes;
  ctx->share_complaints = share_complaints;
  ctx->my_share_complaints = my_share_complaints;
  ctx->cheaters = cheaters;
  ctx->cheater_max = cheater_max;
  ctx->last_ts = last_ts;
  for(uint8_t i=0;i<ctx->n;i++) ctx->last_ts[i]=0;
  return 0;
}

#define stp_dkg_stp_index_msg_SIZE(ctx) (sizeof(STP_DKG_Message) + ctx->n * crypto_generichash_BYTES)
static int stp_init_send_indexes(STP_DKG_STPState *ctx, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[!] step 0. assign peer indices\x1b[0m\n");
  if(output_len!=ctx->n * stp_dkg_stp_index_msg_SIZE(ctx)) return 2;

  uint8_t (*pkhashes)[crypto_generichash_BYTES] = (uint8_t (*)[crypto_generichash_BYTES]) ((STP_DKG_Message*) output)->data;
  for(unsigned i=0;i<ctx->n;i++) {
    crypto_generichash(pkhashes[i],crypto_generichash_BYTES,(*ctx->sig_pks)[i+1],crypto_sign_PUBLICKEYBYTES,NULL,0);
  }

  uint8_t* ptr = output;
  for(uint8_t i=1;i<=ctx->n;i++,ptr+=stp_dkg_stp_index_msg_SIZE(ctx)) {
    memcpy(((STP_DKG_Message*) ptr)->data, pkhashes, ctx->n * crypto_generichash_BYTES);
    if(0!=toprf_send_msg(ptr, stp_dkg_stp_index_msg_SIZE(ctx), stpvssdkg_stp_index_msg, 0, i, ctx->sig_sk, ctx->sessionid)) return 3;
  }

  ctx->step = STP_DKG_STP_Broadcast_NPKs;
  return 0;
}

#define stp_dkg_peer_init1_msg_SIZE (sizeof(STP_DKG_Message) + dkg_sessionid_SIZE)
static STP_DKG_Err peer_init1_handler(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const DKG_Message *msg1=(const DKG_Message*) input;
  ctx->index=msg1->to;
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] init1 send msg1 containing session nonce\x1b[0m\n", ctx->index);
  if(input_len != stp_dkg_stp_index_msg_SIZE(ctx)) return STP_DKG_Err_ISize;
  if(output_len != stp_dkg_peer_init1_msg_SIZE) return STP_DKG_Err_OSize;

  dkg_dump_msg(input, input_len, ctx->index);
  int ret = toprf_recv_msg(input, stp_dkg_stp_index_msg_SIZE(ctx), stpvssdkg_stp_index_msg, 0, msg1->to, ctx->stp_sig_pk, ctx->sessionid, ctx->ts_epsilon, &ctx->stp_last_ts);
  if(0!=ret) return STP_DKG_Err_Env + ret;
  if(msg1->to > 128 || msg1->to < 1 || msg1->to > ctx->n) return STP_DKG_Err_Index;

  // todo remove peerids
  memcpy((*ctx->peerids), msg1->data, ctx->n * crypto_generichash_BYTES);
  if(ctx->keyloader_cb!=NULL) {
    const uint8_t (*peerids)[crypto_generichash_BYTES]=(const uint8_t (*)[crypto_generichash_BYTES]) msg1->data;
    for(unsigned i=0;i<ctx->n;i++) {
        if(0!=ctx->keyloader_cb(peerids[i],ctx->keyloader_cb_arg,(*ctx->sig_pks)[i+1],(*ctx->peer_noise_pks)[i])) {
          return 23; // todo
        }
    }
  }

  uint8_t *wptr = ((STP_DKG_Message *) output)->data;
  randombytes_buf(wptr, dkg_sessionid_SIZE);
  if(0!=toprf_send_msg(output, stp_dkg_peer_init1_msg_SIZE, stpvssdkg_peer_init1_msg, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return STP_DKG_Err_Send;

  dkg_dump_msg(output, output_len, ctx->index);

  ctx->step = STP_DKG_Peer_Rcv_NPK_SIDNonce;

  return STP_DKG_Err_OK;
}

static STP_DKG_Err stp_init2_handler(STP_DKG_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[!] init2 broadcast msg1 containing sessionid nonces\x1b[0m\n");
  if(input_len  != (stp_dkg_peer_init1_msg_SIZE) * ctx->n) return STP_DKG_Err_ISize;
  if(output_len != stp_dkg_peer_init1_msg_SIZE * ctx->n + sizeof(STP_DKG_Message)) return STP_DKG_Err_OSize;

  crypto_generichash_state sid_hash_state;
  crypto_generichash_init(&sid_hash_state, NULL, 0, dkg_sessionid_SIZE);
  crypto_generichash_update(&sid_hash_state, ctx->sessionid, dkg_sessionid_SIZE);

  const uint8_t *ptr = input;
  uint8_t *wptr = ((STP_DKG_Message *) output)->data;
  for(uint8_t i=0;i<ctx->n;i++,ptr+=stp_dkg_peer_init1_msg_SIZE) {
    const uint8_t *dptr = ((const STP_DKG_Message*) ptr)->data;
    if(stp_recv_msg(ctx,ptr,stp_dkg_peer_init1_msg_SIZE,stpvssdkg_peer_init1_msg,i+1,0xff)) continue;
    // contribution to final session id
    crypto_generichash_update(&sid_hash_state, dptr, dkg_sessionid_SIZE);

    memcpy(wptr, ptr, stp_dkg_peer_init1_msg_SIZE);
    wptr+=stp_dkg_peer_init1_msg_SIZE;
  }
  if(ctx->cheater_len>0) return STP_DKG_Err_CheatersFound;

  crypto_generichash_final(&sid_hash_state,ctx->sessionid,dkg_sessionid_SIZE);

  if(0!=toprf_send_msg(output, output_len, stpvssdkg_stp_bc_init1_msg, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return STP_DKG_Err_Send;
  dkg_dump_msg(output, output_len, 0);
  update_transcript(&ctx->transcript, output, output_len);

  ctx->step = STP_DKG_STP_Route_Noise_Handshakes1;
  return STP_DKG_Err_OK;
}

#define stp_dkg_peer_start_noise_msg_SIZE (sizeof(STP_DKG_Message) + noise_xk_handshake1_SIZE)
static STP_DKG_Err peer_start_noise_handler(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] noise1 receive peers session nonces, finalize sessionid, start noise sessions\x1b[0m\n", ctx->index);
  if(input_len != (stp_dkg_peer_init1_msg_SIZE) * ctx->n + sizeof(STP_DKG_Message)) return STP_DKG_Err_ISize;
  if(output_len != stp_dkg_peer_start_noise_msg_SIZE * ctx->n) return STP_DKG_Err_OSize;

  const STP_DKG_Message* msg2 = (const STP_DKG_Message*) input;
  int ret = toprf_recv_msg(input, input_len, stpvssdkg_stp_bc_init1_msg, 0, 0xff, ctx->stp_sig_pk, msg2->sessionid, ctx->ts_epsilon, &ctx->stp_last_ts);
  if(0!=ret) return STP_DKG_Err_BroadcastEnv+ret;

  update_transcript(&ctx->transcript, input, input_len);

  // create noise device
  uint8_t iname[15];
  snprintf((char*) iname, sizeof iname, "toprf peer %02x", ctx->index);
  uint8_t dummy[32]={0}; // the following function needs a deserialization key, which we never use.

  ctx->dev = Noise_XK_device_create(13, (uint8_t*) "toprf p2p v0.1", iname, dummy, ctx->noise_sk);

  crypto_generichash_state sid_hash_state;
  crypto_generichash_init(&sid_hash_state, NULL, 0, dkg_sessionid_SIZE);
  crypto_generichash_update(&sid_hash_state, ctx->sessionid, dkg_sessionid_SIZE);

  const uint8_t *ptr = msg2->data;
  for(uint8_t i=0;i<ctx->n;i++, ptr+=stp_dkg_peer_init1_msg_SIZE) {
    const STP_DKG_Message* msg1 = (const STP_DKG_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,stp_dkg_peer_init1_msg_SIZE,stpvssdkg_peer_init1_msg,i+1,0xff)) continue;
    // extract peer noise pk
    crypto_generichash_update(&sid_hash_state, msg1->data, dkg_sessionid_SIZE);
  }

  if(ctx->cheater_len>0) return STP_DKG_Err_CheatersFound;

  crypto_generichash_final(&sid_hash_state,ctx->sessionid,dkg_sessionid_SIZE);
  if(memcmp(ctx->sessionid, msg2->sessionid, dkg_sessionid_SIZE)!=0) {
    return STP_DKG_Err_InvSessionID;
  }

  uint8_t *wptr = output;
  for(uint8_t i=0;i<ctx->n;i++, wptr+=stp_dkg_peer_start_noise_msg_SIZE) {
    STP_DKG_Message *msg3 = (STP_DKG_Message *) wptr;
    uint8_t rname[15];
    snprintf((char*) rname, sizeof rname, "toprf peer %02x", i+1);
    if(0!=dkg_init_noise_handshake(ctx->index, ctx->dev, (*ctx->peer_noise_pks)[i], rname, &(*ctx->noise_outs)[i], msg3->data)) return STP_DKG_Err_Noise;
    if(0!=toprf_send_msg(wptr, stp_dkg_peer_start_noise_msg_SIZE, stpvssdkg_peer_start_noise_msg, ctx->index, i+1, ctx->sig_sk, ctx->sessionid)) return STP_DKG_Err_Send;
    dkg_dump_msg(wptr, stp_dkg_peer_start_noise_msg_SIZE, ctx->index);
  }

  ctx->step = STP_DKG_Peer_Noise_Handshake;

  return STP_DKG_Err_OK;
}

static STP_DKG_Err stp_route_start_noise_handler(STP_DKG_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  return stp_route(ctx, input, input_len, output, output_len,
                   "noise1 route p2p noise handshakes to peers",
                  ctx->n, ctx->n, stpvssdkg_peer_start_noise_msg, stp_dkg_peer_start_noise_msg_SIZE, STP_DKG_STP_Route_Noise_Handshakes2);
}

#define stp_dkg_peer_respond_noise_msg_SIZE (sizeof(STP_DKG_Message) + noise_xk_handshake2_SIZE)
static STP_DKG_Err peer_respond_noise_handler(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] noise2 receive session requests\x1b[0m\n", ctx->index);
  if(input_len != stp_dkg_peer_start_noise_msg_SIZE * ctx->n) return STP_DKG_Err_ISize;
  if(output_len != stp_dkg_peer_respond_noise_msg_SIZE * ctx->n) return STP_DKG_Err_OSize;

  const uint8_t *ptr = input;
  uint8_t *wptr = output;
  for(uint8_t i=0;i<ctx->n;i++,ptr+=stp_dkg_peer_start_noise_msg_SIZE,wptr+=stp_dkg_peer_respond_noise_msg_SIZE) {
    STP_DKG_Message* msg3 = (STP_DKG_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,stp_dkg_peer_start_noise_msg_SIZE,stpvssdkg_peer_start_noise_msg,i+1,ctx->index)) continue;

    // respond to noise handshake request
    STP_DKG_Message *msg4 = (STP_DKG_Message *) wptr;
    uint8_t rname[15];
    snprintf((char*) rname, sizeof rname, "toprf peer %02x", i+1);
    if(0!=dkg_respond_noise_handshake(ctx->index, ctx->dev, rname, &(*ctx->noise_ins)[i], msg3->data, msg4->data)) return STP_DKG_Err_Noise;
    if(0!=toprf_send_msg(wptr, stp_dkg_peer_respond_noise_msg_SIZE, stpvssdkg_peer_respond_noise_msg, ctx->index, i+1, ctx->sig_sk, ctx->sessionid)) return STP_DKG_Err_Send;
    dkg_dump_msg(wptr, stp_dkg_peer_respond_noise_msg_SIZE, ctx->index);
  }
  if(ctx->cheater_len>0) return STP_DKG_Err_CheatersFound;

  ctx->step=STP_DKG_Peer_Finish_Noise_Handshake;
  return STP_DKG_Err_OK;
}

static STP_DKG_Err stp_route_noise_respond_handler(STP_DKG_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  return stp_route(ctx, input, input_len, output, output_len,
                   "noise2 route p2p noise handshakes to peers",
                   ctx->n, ctx->n, stpvssdkg_peer_respond_noise_msg, stp_dkg_peer_respond_noise_msg_SIZE, STP_DKG_STP_Broadcast_DKG_Hash_Commitments);
}

#define stp_dkg_peer_start_dkg_msg_SIZE(ctx) (sizeof(STP_DKG_Message) + stp_dkg_commitment_HASHBYTES  + ctx->n * crypto_auth_hmacsha256_BYTES)
static STP_DKG_Err peer_dkg1_handler(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] dkg1 finish session handshake, start with dkg\x1b[0m\n", ctx->index);
  if(input_len != stp_dkg_peer_respond_noise_msg_SIZE * ctx->n) return STP_DKG_Err_ISize;
  if(output_len != stp_dkg_peer_start_dkg_msg_SIZE(ctx)) return STP_DKG_Err_OSize;

  const uint8_t *ptr = input;
  for(uint8_t i=0;i<ctx->n;i++, ptr+=stp_dkg_peer_respond_noise_msg_SIZE) {
    STP_DKG_Message* msg4 = (STP_DKG_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,stp_dkg_peer_respond_noise_msg_SIZE,stpvssdkg_peer_respond_noise_msg,i+1,ctx->index)) continue;
    // process final step of noise handshake
    if(0!=dkg_finish_noise_handshake(ctx->index, ctx->dev, &(*ctx->noise_outs)[i], msg4->data)) return STP_DKG_Err_Noise;
  }
  if(ctx->cheater_len>0) return STP_DKG_Err_CheatersFound;

  // start DKG
  STP_DKG_Message* msg5 = (STP_DKG_Message*) output;
  // we stash our commitments temporarily in k_commitments - they will be sent out in the next step
  if(dkg_vss_share(ctx->n, ctx->t, NULL, (*ctx->k_commitments), (*ctx->k_shares), NULL)) {
    return STP_DKG_Err_Share;
  }
#ifdef UNITTEST_CORRUPT
  corrupt_vsps_p1t1(ctx);
  corrupt_commitment_p2(ctx);
  corrupt_wrongshare_correct_commitment_p3(ctx);
  corrupt_share_p4(ctx);
#endif // UNITTEST_CORRUPT

  if(liboprf_log_file!=NULL) {
    dump((const uint8_t*) (*ctx->k_commitments), crypto_core_ristretto255_BYTES*ctx->n, "[%d] dealer commitments", ctx->index);
  }

  uint8_t *wptr = msg5->data;
  crypto_generichash(wptr, stp_dkg_commitment_HASHBYTES, (uint8_t*) (*ctx->k_commitments), crypto_core_ristretto255_BYTES*ctx->n, NULL, 0);
  wptr+=stp_dkg_commitment_HASHBYTES;

  uint8_t *dptr = (uint8_t*) (*ctx->encrypted_shares);
  for(uint8_t i=0;i<ctx->n;i++) {
    // we need to send an empty packet, so that the handshake completes
    // and we have a final symetric key, the key during the handshake changes, only
    // when the handshake completes does the key become static.
    // this is important, so that when there are complaints, we can disclose the key.
    uint8_t empty[1]={0}; // would love to do [0] but that is undefined c
    if(0!=dkg_noise_encrypt(empty, 0, dptr, noise_xk_handshake3_SIZE, &(*ctx->noise_outs)[i])) return STP_DKG_Err_NoiseEncrypt;
    dptr+=noise_xk_handshake3_SIZE;

    if(0!=dkg_noise_encrypt((uint8_t*) &(*ctx->k_shares)[i], TOPRF_Share_BYTES*2,
                            dptr, stp_dkg_encrypted_share_SIZE, &(*ctx->noise_outs)[i])) return STP_DKG_Err_NoiseEncrypt;

    // we also need to use a key-commiting mac over the encrypted share, since poly1305 is not...
    // these we broadcast
    crypto_auth(wptr, dptr, stp_dkg_encrypted_share_SIZE, Noise_XK_session_get_key((*ctx->noise_outs)[i]));

    dptr+=TOPRF_Share_BYTES * 2 + crypto_secretbox_xchacha20poly1305_MACBYTES;
    wptr+=crypto_auth_hmacsha256_BYTES;
  }

  if(liboprf_log_file!=NULL) {
    dump(msg5->data+stp_dkg_commitment_HASHBYTES, ctx->n*crypto_auth_hmacsha256_BYTES, "[%d] share macs", ctx->index);
  }

  //broadcast dealer_commitments and share HMACS
  if(0!=toprf_send_msg(output, stp_dkg_peer_start_dkg_msg_SIZE(ctx), stpvssdkg_peer_dkg1_msg, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return STP_DKG_Err_Send;
  dkg_dump_msg(output, stp_dkg_peer_start_dkg_msg_SIZE(ctx), ctx->index);

  ctx->step = STP_DKG_Peer_Rcv_Commitments_Send_Commitments;

  return STP_DKG_Err_OK;
}

static STP_DKG_Err stp_dkg1_handler(STP_DKG_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  STP_DKG_Err ret;
  ret = stp_broadcast(ctx, input, input_len, output, output_len,
                      "dkg1 broadcast commitment commitments",
                      ctx->n, stp_dkg_peer_start_dkg_msg_SIZE(ctx), stpvssdkg_peer_dkg1_msg, STP_DKG_STP_Broadcast_DKG_Commitments);
  if(ret != STP_DKG_Err_OK) return ret;
  const uint8_t *ptr = input;
  for(unsigned i=0;i<ctx->n;i++,ptr+=stp_dkg_peer_start_dkg_msg_SIZE(ctx)) {
    const DKG_Message* msg = (const DKG_Message*) ptr;
    memcpy((*ctx->commitment_hashes)[i], msg->data, stp_dkg_commitment_HASHBYTES);
    memcpy((*ctx->share_macs)[i*ctx->n], msg->data+stp_dkg_commitment_HASHBYTES, ctx->n*crypto_auth_hmacsha256_BYTES);
  }
  return ret;
}

#define stp_dkg_peer_dkg2_msg_SIZE(ctx) (sizeof(STP_DKG_Message) + crypto_core_ristretto255_BYTES * ctx->n)
static STP_DKG_Err peer_dkg2_handler(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] dkg2 receive commitment hashes, broadcast commitments\x1b[0m\n", ctx->index);
  if(input_len != sizeof(STP_DKG_Message) + stp_dkg_peer_start_dkg_msg_SIZE(ctx) * ctx->n) return STP_DKG_Err_ISize;
  if(output_len != stp_dkg_peer_dkg2_msg_SIZE(ctx)) return STP_DKG_Err_OSize;

  // verify STP message envelope
  const uint8_t *ptr;
  int ret = unwrap_envelope(ctx,input,input_len,stpvssdkg_stp_bc_dkg1_msg,&ptr);
  if(ret!=STP_DKG_Err_OK) return ret;

  for(uint8_t i=0;i<ctx->n;i++, ptr+=stp_dkg_peer_start_dkg_msg_SIZE(ctx)) {
    const STP_DKG_Message* msg5 = (const STP_DKG_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,stp_dkg_peer_start_dkg_msg_SIZE(ctx),stpvssdkg_peer_dkg1_msg,i+1,0xff)) continue;

    const uint8_t *dptr=msg5->data;
    // extract peer commitment hash
    memcpy((*ctx->commitments_hashes)[i], dptr, stp_dkg_commitment_HASHBYTES);
    // extract and store encrypted share mac
    dptr+=stp_dkg_commitment_HASHBYTES;
    memcpy((*ctx->share_macs)[i*ctx->n], dptr, crypto_auth_hmacsha256_BYTES*ctx->n);
    if(liboprf_log_file!=NULL) {
      dump((*ctx->commitments_hashes)[i], stp_dkg_commitment_HASHBYTES, "[%d] commitment hash [%d]", ctx->index, i+1);
      dump((*ctx->share_macs)[i*ctx->n], crypto_auth_hmacsha256_BYTES*ctx->n, "[%d] share macs [%d]", ctx->index, i+1);
    }
  }
  //if(ctx->cheater_len>0) return STP_DKG_Err_CheatersFound;

  STP_DKG_Message* msg = (STP_DKG_Message*) output;
  // we stashed our commitments temporarily in k_commitments
  memcpy(msg->data, (*ctx->k_commitments), ctx->n * crypto_core_ristretto255_BYTES);
  //broadcast dealer_commitments
  if(0!=toprf_send_msg(output, stp_dkg_peer_dkg2_msg_SIZE(ctx), stpvssdkg_peer_dkg2_msg, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return STP_DKG_Err_Send;
  dkg_dump_msg(output, stp_dkg_peer_dkg2_msg_SIZE(ctx), ctx->index);

  ctx->step = STP_DKG_Peer_Rcv_Commitments_Send_Shares;

  return STP_DKG_Err_OK;
}

static STP_DKG_Err stp_dkg2_handler(STP_DKG_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  STP_DKG_Err ret = stp_broadcast(ctx, input, input_len, output, output_len,
                                    "dkg2 broadcast commitments dkg step 1",
                                    ctx->n, stp_dkg_peer_dkg2_msg_SIZE(ctx), stpvssdkg_peer_dkg2_msg, STP_DKG_STP_Route_Encrypted_Shares);
  if(ret!=STP_DKG_Err_OK) return ret;
  const uint8_t *ptr = input;

  // fixup step, that has already been advanced in the call to stp_broadcast above.
  uint8_t step = ctx->step;
  ctx->step = STP_DKG_STP_Broadcast_DKG_Commitments;

  uint8_t chash[stp_dkg_commitment_HASHBYTES];
  uint8_t (*c)[ctx->n][ctx->n][crypto_core_ristretto255_BYTES] = (uint8_t (*)[ctx->n][ctx->n][crypto_core_ristretto255_BYTES]) ctx->commitments;
  for(uint8_t i=0;i<ctx->n;i++,ptr+=stp_dkg_peer_dkg2_msg_SIZE(ctx)) {
    const DKG_Message* msg = (const DKG_Message*) ptr;
    // verify against commitment hashes
    crypto_generichash(chash, stp_dkg_commitment_HASHBYTES, msg->data, crypto_core_ristretto255_BYTES*ctx->n, NULL, 0);
    if(memcmp(chash, (*ctx->commitment_hashes)[i], stp_dkg_commitment_HASHBYTES)!=0) {
      if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"f[!] failed to verify hash for commitments of dealer %d\n"NORMAL, i+1);
      if(stp_add_cheater(ctx, 4, i+1, 0) == NULL) {
        ctx->step=step;
        return STP_DKG_Err_CheatersFull;
      }
    }
    memcpy((*c)[i], msg->data, crypto_core_ristretto255_BYTES * ctx->n);
  }

  // calculate preliminary final commitments
  uint8_t kcom[ctx->n][crypto_core_ristretto255_BYTES];
  for(unsigned i=0;i<ctx->n;i++) {
    memcpy(kcom[i], (*c)[0][i], crypto_scalarmult_ristretto255_BYTES);
    for(unsigned j=1;j<ctx->n;j++) {
      crypto_core_ristretto255_add(kcom[i], kcom[i], (*c)[j][i]);
    }
  }

  uint8_t fails_len=0;
  uint8_t fails[ctx->n];
  memset(fails,0,ctx->n);

  ret = ft_or_full_vsps(ctx->n, ctx->t, ctx->n, 0, kcom, c,
                        "VSPS failed k during DKG, doing full VSPS check on all peers",
                        "VSPS failed k",
                        "ERROR, could not find any dealer commitments that fail the VSPS check",
                        &fails_len, fails);
  if(ret!=STP_DKG_Err_OK) {
    ctx->step=step;
    return ret;
  }

  for(unsigned i=0;i<fails_len;i++) {
    if(stp_add_cheater(ctx,1,fails[i],0) == NULL) {
      ctx->step=step;
      return STP_DKG_Err_CheatersFull;
    }
  }

  if(ctx->n - fails_len < 2) {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[!] less than 2 honest dealers: %d \n"NORMAL, ctx->n - fails_len);
    if(stp_add_cheater(ctx,2,0,0) == NULL) {
      ctx->step=step;
      return STP_DKG_Err_CheatersFull;
    }
  }
  if(fails_len >= ctx->t) {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[!] more than t cheaters (t=%d, cheaters=%d)\n"NORMAL, ctx->t, fails_len);
    if(stp_add_cheater(ctx,3,fails_len,0) == NULL) {
      ctx->step=step;
      return STP_DKG_Err_CheatersFull;
    }
  }
  ctx->step=step;

  return ret;
}

#define stp_dkg_peer_dkg3_msg_SIZE (sizeof(STP_DKG_Message) /* header */                        \
                                        + noise_xk_handshake3_SIZE /* 4th&final noise handshake */     \
                                        + sizeof(TOPRF_Share) /* msg: the noise_xk wrapped k share */  \
                                        + sizeof(TOPRF_Share) /* msg: the noise_xk wrapped k blind */  \
                                        + crypto_secretbox_xchacha20poly1305_MACBYTES /* mac of msg */ )
static STP_DKG_Err peer_dkg3_handler(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] dkg3 receive commitments & distribute shares via noise chans\x1b[0m\n", ctx->index);
  if(input_len != sizeof(STP_DKG_Message) + stp_dkg_peer_dkg2_msg_SIZE(ctx) * ctx->n) return STP_DKG_Err_ISize;
  if(output_len != ctx->n * stp_dkg_peer_dkg3_msg_SIZE) return STP_DKG_Err_OSize;

  // verify STP message envelope
  const uint8_t *ptr;
  int ret = unwrap_envelope(ctx,input,input_len,stpvssdkg_stp_bc_dkg2_msg,&ptr);
  if(ret!=STP_DKG_Err_OK) return ret;

  for(uint8_t i=0;i<ctx->n;i++, ptr+=stp_dkg_peer_dkg2_msg_SIZE(ctx)) {
    const STP_DKG_Message* msg5 = (const STP_DKG_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,stp_dkg_peer_dkg2_msg_SIZE(ctx),stpvssdkg_peer_dkg2_msg,i+1,0xff)) continue;

    // extract peer commitments
    memcpy((*ctx->ki_commitments)[i*ctx->n], msg5->data, crypto_core_ristretto255_BYTES * ctx->n);
    if(liboprf_log_file!=NULL) {
      dump((*ctx->ki_commitments)[i*ctx->n], crypto_core_ristretto255_BYTES*ctx->n, "[%d] k commitments [%d]", ctx->index, i+1);
    }

    // verify against commitment hashes
    uint8_t chash[stp_dkg_commitment_HASHBYTES];
    crypto_generichash(chash, stp_dkg_commitment_HASHBYTES, (*ctx->ki_commitments)[i*ctx->n], crypto_core_ristretto255_BYTES*ctx->n, NULL, 0);
    if(memcmp(chash, (*ctx->commitments_hashes)[i], stp_dkg_commitment_HASHBYTES)!=0) {
      if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"f[%d] failed to verify hash for commitments of dealer %d\n"NORMAL, ctx->index, i+1);
      if(peer_add_cheater(ctx, 1, i+1, 0) == NULL) return STP_DKG_Err_CheatersFull;
    }
  }
  // yes we abort here if the hash commitment fails.
  if(ctx->cheater_len>0) return STP_DKG_Err_CheatersFound;
  // we could check VSPS here, but that would complicate msg size
  // calculation taking into account demoted dealers, so we do it
  // after the shares have been dealt.

  uint8_t *wptr = output;
  for(uint8_t i=0;i<ctx->n;i++, wptr+=stp_dkg_peer_dkg3_msg_SIZE) {
    STP_DKG_Message *msg7 = (STP_DKG_Message *) wptr;
    memcpy(msg7->data, (*ctx->encrypted_shares)[i], noise_xk_handshake3_SIZE + stp_dkg_encrypted_share_SIZE);

    if(0!=toprf_send_msg(wptr, stp_dkg_peer_dkg3_msg_SIZE, stpvssdkg_peer_dkg3_msg, ctx->index, i+1, ctx->sig_sk, ctx->sessionid)) return STP_DKG_Err_Send;
    dkg_dump_msg(wptr, stp_dkg_peer_dkg3_msg_SIZE, ctx->index);
  }

  ctx->step = STP_DKG_Peer_Verify_Commitments;

  return STP_DKG_Err_OK;
}

static STP_DKG_Err stp_dkg3_handler(STP_DKG_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  return stp_route(ctx, input, input_len, output, output_len,
                   "dkg3 route shares to peers",
                   ctx->n, ctx->n, stpvssdkg_peer_dkg3_msg, stp_dkg_peer_dkg3_msg_SIZE, STP_DKG_STP_Broadcast_Complaints);
}

#define stp_dkg_peer_verify_shares_msg_SIZE(ctx) (sizeof(STP_DKG_Message) + (size_t)(ctx->n + 1))
static STP_DKG_Err peer_verify_shares_handler(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] verify1 DKG step 2 - receive shares, verify commitments\x1b[0m\n", ctx->index);
  if(input_len != stp_dkg_peer_dkg3_msg_SIZE * ctx->n) return STP_DKG_Err_ISize;
  if(output_len != stp_dkg_peer_verify_shares_msg_SIZE(ctx)) return STP_DKG_Err_OSize;

  const uint8_t *ptr = input;
  for(uint8_t i=0;i<ctx->n;i++) {
    const STP_DKG_Message* msg = (const STP_DKG_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,stp_dkg_peer_dkg3_msg_SIZE,stpvssdkg_peer_dkg3_msg,i+1,ctx->index)) continue;

    // decrypt final empty handshake packet
    if(0!=dkg_noise_decrypt(msg->data, noise_xk_handshake3_SIZE, NULL, 0, &(*ctx->noise_ins)[i])) return STP_DKG_Err_NoiseDecrypt;
    if(0!=dkg_noise_decrypt(msg->data + noise_xk_handshake3_SIZE, TOPRF_Share_BYTES*2 + crypto_secretbox_xchacha20poly1305_MACBYTES,
                              (uint8_t*) &(*ctx->k_shares)[i], TOPRF_Share_BYTES*2,
                              &(*ctx->noise_ins)[i])) return STP_DKG_Err_NoiseDecrypt;
    ptr+=stp_dkg_peer_dkg3_msg_SIZE;
  }
  //if(ctx->cheater_len>0) return STP_DKG_Err_CheatersFound;

  STP_DKG_Message* msg = (STP_DKG_Message*) output;
  uint8_t *fails_len = msg->data;
  uint8_t *fails = fails_len+1;
  memset(fails_len, 0, ctx->n+1);

  uint8_t (*c)[ctx->n][ctx->n][crypto_core_ristretto255_BYTES] = (uint8_t (*)[ctx->n][ctx->n][crypto_core_ristretto255_BYTES]) ctx->ki_commitments;
  // verify that the shares match the commitment
  for(uint8_t i=0;i<ctx->n;i++) {
    if(0!=dkg_vss_verify_commitment((*c)[i][ctx->index-1],(*ctx->k_shares)[i])) {
      if(liboprf_log_file!=NULL) fprintf(liboprf_log_file,"\x1b[0;31m[%d] failed to verify k commitments from %d!\x1b[0m\n", ctx->index, i+1);
      fails[(*fails_len)++]=i+1;
    }
  }

#ifdef UNITTEST_CORRUPT
  corrupt_false_accuse_p2p3(ctx, fails_len, fails);
#endif //UNITTEST_CORRUPT

  if(liboprf_log_file!=NULL && *fails_len>0) {
    fprintf(liboprf_log_file, RED"[%d] commitment fails#: %d -> ", ctx->index, *fails_len);
    for(unsigned i=0;i<*fails_len;i++) fprintf(liboprf_log_file, "%s%d", (i>0)?", ":"", fails[i]);
    fprintf(liboprf_log_file, NORMAL"\n");
  }

  if(0!=toprf_send_msg(output, stp_dkg_peer_verify_shares_msg_SIZE(ctx), stpvssdkg_peer_verify_shares_msg, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return STP_DKG_Err_Send;
  dkg_dump_msg(output, stp_dkg_peer_verify_shares_msg_SIZE(ctx), ctx->index);

  ctx->step = STP_DKG_Peer_Handle_DKG_Complaints;

  return STP_DKG_Err_OK;
}

static STP_DKG_Err stp_complaint_handler(STP_DKG_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len,
                                 const char* step_title,
                                 const uint8_t msg_count,
                                 const size_t msg_size,
                                 const uint8_t msgno,
                                 const STP_DKG_STP_Steps pass_step,
                                 const STP_DKG_STP_Steps fail_step) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[!] %s\x1b[0m\n", step_title);

  if(input_len != msg_size * msg_count) return STP_DKG_Err_ISize;
  if(sizeof(STP_DKG_Message) + input_len != output_len) return STP_DKG_Err_OSize;

  ctx->share_complaints_len = 0;

  const uint8_t *ptr = input;
  uint8_t *wptr = ((STP_DKG_Message *) output)->data;
  for(uint8_t i=0;i<msg_count;i++, ptr+=msg_size) {
    const STP_DKG_Message* msg = (const STP_DKG_Message*) ptr;
    if(stp_recv_msg(ctx,ptr,msg_size,msgno,i+1,0xff)) continue;
    if(msg->len - sizeof(STP_DKG_Message) < msg->data[0]) return STP_DKG_Err_OOB;

    const uint8_t *fails_len = msg->data;
    const uint8_t *fails = msg->data+1;
    handle_complaints(msg_count, i+1, "share commitment", *fails_len, fails, &ctx->share_complaints_len, (*ctx->share_complaints), 0, 0, 0);

    memcpy(wptr, ptr, msg_size);
    wptr+=msg_size;
  }

  // if more than t^2 complaints are received the protocol also fails
  if(ctx->share_complaints_len >= ctx->t * ctx->t) {
    if(stp_add_cheater(ctx, 6, 0xfe, 0xfe) == NULL) return STP_DKG_Err_CheatersFull;
    return STP_DKG_Err_TooManyCheaters;
  }

  //if(ctx->cheater_len>0) return STP_DKG_Err_CheatersFound;

  if(0!=toprf_send_msg(output, output_len, msgno+1, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return STP_DKG_Err_Send;
  dkg_dump_msg(output, output_len, 0);

  // add broadcast msg to transcript
  update_transcript(&ctx->transcript, output, output_len);

  ctx->prev = ctx->step;
  if(ctx->share_complaints_len == 0) {
    ctx->step = pass_step;
  } else {
    dump((uint8_t*) (*ctx->share_complaints), ctx->share_complaints_len*sizeof(uint16_t), "[!] complaints");
    ctx->step = fail_step;
  }

  return STP_DKG_Err_OK;
}

#define stp_dkg_stp_bc_verify_shares_msg_SIZE(ctx) (sizeof(STP_DKG_Message) + (stp_dkg_peer_verify_shares_msg_SIZE(ctx) * ctx->n))
static STP_DKG_Err stp_verify_shares_handler(STP_DKG_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  return stp_complaint_handler(ctx, input, input_len, output, output_len,
                              "verify1 broadcast complaints of peers",
                              ctx->n, stp_dkg_peer_verify_shares_msg_SIZE(ctx),
                              stpvssdkg_peer_verify_shares_msg,
                              STP_DKG_STP_Broadcast_DKG_Transcripts,
                              STP_DKG_STP_Broadcast_DKG_Defenses);
}

static STP_DKG_Err peer_complaint_handler(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len,
                                               const char *step_title,
                                               const size_t msg_size,
                                               const uint8_t msgno,
                                               const STP_DKG_Peer_Steps pass_step,
                                               const STP_DKG_Peer_Steps fail_step) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] %s\x1b[0m\n", ctx->index, step_title);
  if(input_len != sizeof(STP_DKG_Message) + msg_size * ctx->n) return STP_DKG_Err_ISize;

  // verify STP message envelope
  const uint8_t *ptr;
  int ret = unwrap_envelope(ctx,input,input_len,msgno+1,&ptr);
  if(ret!=STP_DKG_Err_OK) return ret;

  ctx->share_complaints_len = 0;

  for(uint8_t i=0;i<ctx->n;i++, ptr+=msg_size) {
    const STP_DKG_Message* msg = (const STP_DKG_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,msg_size,msgno,i+1,0xff)) continue;
    if(msg->len - sizeof(STP_DKG_Message) < msg->data[0]) return STP_DKG_Err_OOB;
    const uint8_t *fails_len = msg->data;
    const uint8_t *fails = msg->data+1;
    handle_complaints(ctx->n, i+1, "share commitment",
                      *fails_len, fails,
                      &ctx->share_complaints_len, ctx->share_complaints,
                      ctx->index,
                      &ctx->my_share_complaints_len, ctx->my_share_complaints);
  }

  //if(ctx->cheater_len>0) return STP_DKG_Err_CheatersFound;

  ctx->prev = ctx->step;
  if(ctx->share_complaints_len == 0) {
    ctx->step = pass_step;
  } else {
    dump((uint8_t*) ctx->share_complaints, ctx->share_complaints_len*sizeof(uint16_t), "[%d] share complaints", ctx->index);
    ctx->step = fail_step;
  }

  return STP_DKG_Err_OK;
}

static STP_DKG_Err peer_dkg_fork(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len) {
  return peer_complaint_handler(ctx, input, input_len,
                                "verify2 receive complaints broadcast",
                                stp_dkg_peer_verify_shares_msg_SIZE(ctx),
                                stpvssdkg_peer_verify_shares_msg,
                                STP_DKG_Peer_Finish_DKG,
                                STP_DKG_Peer_Defend_DKG_Accusations);
}

static STP_DKG_Err peer_defend(STP_DKG_PeerState *ctx, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] defend disclose share encryption key\x1b[0m\n", ctx->index);
  if(output_len != stp_dkg_peer_output_size(ctx)) return STP_DKG_Err_OSize;
  if(output_len == 0) {
    if(liboprf_log_file!=NULL) {
      fprintf(liboprf_log_file,"[%d] nothing to defend against, no message to send\n", ctx->index);
    }
    ctx->step = STP_DKG_Peer_Check_Shares;
    return 0;
  }

  // send out all shares that belong to peers that complained.
  STP_DKG_Message* msg = (STP_DKG_Message*) output;
  uint8_t *wptr = msg->data;
  for(int i=0;i<ctx->my_share_complaints_len;i++) {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;36m[%d] defending against complaint from %d\x1b[0m\n", ctx->index, ctx->my_share_complaints[i]);

    *wptr++ = ctx->my_share_complaints[i];
    // reveal key for noise wrapped share sent previously
    memcpy(wptr, Noise_XK_session_get_key((*ctx->noise_outs)[ctx->my_share_complaints[i]-1]), dkg_noise_key_SIZE);
    wptr+=dkg_noise_key_SIZE;
    memcpy(wptr, (*ctx->encrypted_shares)[ctx->my_share_complaints[i]-1] + noise_xk_handshake3_SIZE, stp_dkg_encrypted_share_SIZE);
    wptr+=stp_dkg_encrypted_share_SIZE;
  }

  if(0!=toprf_send_msg(output, stp_dkg_peer_output_size(ctx), stpvssdkg_peer_share_key_msg, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return STP_DKG_Err_Send;
  dkg_dump_msg(output, stp_dkg_peer_output_size(ctx), ctx->index);

  ctx->step = STP_DKG_Peer_Check_Shares;
  return STP_DKG_Err_OK;
}

static STP_DKG_Err stp_broadcast_defenses(STP_DKG_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[!] defense1 broadcast defenses\x1b[0m\n");
  if(input_len != stp_dkg_stp_input_size(ctx)) return STP_DKG_Err_ISize;
  if(output_len != stp_dkg_stp_output_size(ctx)) return STP_DKG_Err_OSize;

  unsigned int ctr[ctx->n];
  memset(ctr,0,sizeof(ctr));
  for(int i=0;i<ctx->share_complaints_len;i++) {
    ctr[((*ctx->share_complaints)[i] & 0xff)-1]++;
  }

  uint8_t (*c)[ctx->n][ctx->n][crypto_core_ristretto255_BYTES] = (uint8_t (*)[ctx->n][ctx->n][crypto_core_ristretto255_BYTES]) ctx->commitments;
  const uint8_t *ptr = input;
  uint8_t *wptr = ((STP_DKG_Message *) output)->data;
  size_t msg_size;
  for(uint8_t i=0;i<ctx->n;i++,ptr += msg_size) {
    if(ctr[i]==0) {
      msg_size = 0;
      continue; // no complaints against this peer
    }
    msg_size = sizeof(DKG_Message) + (1+dkg_noise_key_SIZE+stp_dkg_encrypted_share_SIZE) * ctr[i];
    if(stp_recv_msg(ctx,ptr,msg_size,stpvssdkg_peer_share_key_msg,i+1,0xff)) continue;

    const STP_DKG_Message *msg = (const STP_DKG_Message *) ptr;
    const uint8_t *dptr = msg->data;
    for(unsigned j=0;j<ctr[i];j++) {
      const uint8_t accused=i+1;
      const uint8_t accuser=dptr[0];
      const uint8_t *key=dptr+1;
      const uint8_t *shares=key+dkg_noise_key_SIZE;
      if(liboprf_log_file!=NULL) fprintf(liboprf_log_file,"[!] accused: %d, by %d\n", accused, accuser);

      if(0!=crypto_auth_verify((*ctx->share_macs)[(accused-1)*ctx->n+(accuser-1)], shares, stp_dkg_encrypted_share_SIZE, key)) {
        if(liboprf_log_file!=NULL) fprintf(liboprf_log_file,RED"[!] invalid HMAC on shares of accused: %d, by %d\n"NORMAL, accused, accuser);
        if(stp_add_cheater(ctx, 1, accused, accuser) == NULL) return STP_DKG_Err_CheatersFull;
        continue;
      }
      TOPRF_Share share[2];
      Noise_XK_error_code res0 = Noise_XK_aead_decrypt((uint8_t*)key, 0, 0U, NULL, TOPRF_Share_BYTES*2, (uint8_t*) &share, (uint8_t*) shares);
      if (!(res0 == Noise_XK_CSuccess)) {
        if(liboprf_log_file!=NULL) fprintf(liboprf_log_file,RED"[!] failed to decrypt shares of accused: %d, by %d\n"NORMAL, accused, accuser);
        // share decryption failure
        if(stp_add_cheater(ctx,  2, accused, accuser) == NULL) return STP_DKG_Err_CheatersFull;
        continue;
      }
      if(share[0].index != accuser) {
        // invalid share index
        STP_DKG_Cheater* cheater = stp_add_cheater(ctx, 3, accused, accuser);
        if(cheater == NULL) return STP_DKG_Err_CheatersFull;
        cheater->invalid_index = share[0].index;
        continue;
      }
      if(0!=dkg_vss_verify_commitment((*c)[accused-1][accuser-1],share)) {
        if(liboprf_log_file!=NULL) fprintf(liboprf_log_file,"\x1b[0;31m[!] failed to verify commitment of accused %d by accuser %d!\x1b[0m\n", accused, accuser);
        STP_DKG_Cheater* cheater = stp_add_cheater(ctx, 4, accused, accuser);
        if(cheater == NULL) return STP_DKG_Err_CheatersFull;
        cheater->invalid_index = share[0].index;
        continue;
      } else {
        if(liboprf_log_file!=NULL) fprintf(liboprf_log_file,GREEN"[!] succeeded to verify commitment of accused %d by accuser %d!\x1b[0m\n", accused, accuser);
        if(stp_add_cheater(ctx, 5, accuser, accused) == NULL) return STP_DKG_Err_CheatersFull;
      }
    }

    memcpy(wptr, ptr, msg_size);
    wptr+=msg_size;
  }
  //if(ctx->cheater_len>0) return STP_DKG_Err_CheatersFound;

  if(0!=toprf_send_msg(output, output_len, stpvssdkg_stp_bc_key_msg, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return STP_DKG_Err_Send;
  dkg_dump_msg(output, output_len, 0);

  // add broadcast msg to transcript
  update_transcript(&ctx->transcript, output, output_len);

  ctx->step = STP_DKG_STP_Broadcast_DKG_Transcripts;

  return STP_DKG_Err_OK;
}

#define stp_dkg_peer_bc_transcript_msg_SIZE (sizeof(STP_DKG_Message) + crypto_generichash_BYTES + crypto_core_ristretto255_BYTES)
static STP_DKG_Err peer_verify_vsps(STP_DKG_PeerState *ctx, uint8_t *output, const size_t output_len);

static STP_DKG_Err peer_check_shares(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] verify3 disclosed shares\x1b[0m\n", ctx->index);
  if(input_len != stp_dkg_peer_input_size(ctx)) return STP_DKG_Err_ISize;
  if(output_len != stp_dkg_peer_bc_transcript_msg_SIZE) return STP_DKG_Err_OSize;

  // verify STP message envelope
  const uint8_t *ptr;
  int ret = unwrap_envelope(ctx,input,input_len,stpvssdkg_stp_bc_key_msg,&ptr);
  if(ret!=STP_DKG_Err_OK) return ret;

  unsigned int ctr[ctx->n];
  memset(ctr,0,sizeof(ctr));
  for(int i=0;i<ctx->share_complaints_len;i++) {
    ctr[(ctx->share_complaints[i] & 0xff)-1]++;
    ctx->share_complaints[i]=0;
  }
  ctx->share_complaints_len=0;

  uint8_t (*c)[ctx->n][ctx->n][crypto_core_ristretto255_BYTES] = (uint8_t (*)[ctx->n][ctx->n][crypto_core_ristretto255_BYTES]) ctx->ki_commitments;

  size_t msg_size;
  for(uint8_t i=0;i<ctx->n;i++,ptr += msg_size) {
    if(ctr[i]==0) {
      msg_size = 0;
      continue; // no complaints against this peer
    }
    msg_size = sizeof(DKG_Message) + (1+dkg_noise_key_SIZE+stp_dkg_encrypted_share_SIZE) * ctr[i];
    if(peer_recv_msg(ctx,ptr,msg_size,stpvssdkg_peer_share_key_msg,i+1,0xff)) continue;
    const STP_DKG_Message *msg = (const STP_DKG_Message *) ptr;
    const uint8_t *dptr = msg->data;
    for(unsigned j=0;j<ctr[i];j++) {
      const uint8_t accused=i+1;
      const uint8_t accuser=dptr[0];
      const uint8_t *key=dptr+1;
      const uint8_t *shares=key+dkg_noise_key_SIZE;
      if(liboprf_log_file!=NULL) fprintf(liboprf_log_file,"[%d] accused: %d, by %d\n", ctx->index, accused, accuser);

      if(0!=crypto_auth_verify((*ctx->share_macs)[(accused-1)*ctx->n+(accuser-1)], shares, stp_dkg_encrypted_share_SIZE, key)) {
        if(liboprf_log_file!=NULL) fprintf(liboprf_log_file,RED"[%d] invalid HMAC on shares of accused: %d, by %d\n"NORMAL, ctx->index, accused, accuser);
        if(peer_add_cheater(ctx, 1, accused, accuser) == NULL) return STP_DKG_Err_CheatersFull;
        ctx->share_complaints[ctx->share_complaints_len++]=accused;
        continue;
      }
      TOPRF_Share share[2];
      Noise_XK_error_code
        res0 = Noise_XK_aead_decrypt((uint8_t*)key, 0, 0U, NULL, TOPRF_Share_BYTES*2, (uint8_t*) &share, (uint8_t*) shares);
      if (!(res0 == Noise_XK_CSuccess)) {
        if(liboprf_log_file!=NULL) fprintf(liboprf_log_file,RED"[%d] failed to decrypt shares of accused: %d, by %d\n"NORMAL, ctx->index, accused, accuser);
        // share decryption failure
        if(peer_add_cheater(ctx,  2, accused, accuser) == NULL) return STP_DKG_Err_CheatersFull;
        ctx->share_complaints[ctx->share_complaints_len++]=accused;
        continue;
      }
      if(share[0].index != accuser) {
        // invalid share index
        STP_DKG_Cheater* cheater = peer_add_cheater(ctx, 3, accused, accuser);
        if(cheater == NULL) return STP_DKG_Err_CheatersFull;
        cheater->invalid_index = share[0].index;
        ctx->share_complaints[ctx->share_complaints_len++]=accused;
        continue;
      }
      if(0!=dkg_vss_verify_commitment((*c)[accused-1][accuser-1],share)) {
        if(liboprf_log_file!=NULL) fprintf(liboprf_log_file,"\x1b[0;31m[%d] failed to verify commitment of accused %d by accuser %d!\x1b[0m\n", ctx->index, accused, accuser);
        STP_DKG_Cheater* cheater = peer_add_cheater(ctx, 4, accused, accuser);
        if(cheater == NULL) return STP_DKG_Err_CheatersFull;
        cheater->invalid_index = share[0].index;
        ctx->share_complaints[ctx->share_complaints_len++]=accused;
        continue;
      } else {
        if(liboprf_log_file!=NULL) fprintf(liboprf_log_file,GREEN"[%d] succeeded to verify commitment of accused %d by accuser %d!\x1b[0m\n", ctx->index, accused, accuser);
        if(peer_add_cheater(ctx, 5, accuser, accused) == NULL) return STP_DKG_Err_CheatersFull;
        //ctx->share_complaints[ctx->share_complaints_len++]=accused;
      }
    }
  }
  return peer_verify_vsps(ctx, output, output_len);
}

static STP_DKG_Err peer_verify_vsps(STP_DKG_PeerState *ctx, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] verify1 DKG step 2 - VSPS check commitments, calculate share and broadcast transcript and final commitment\x1b[0m\n", ctx->index);
  if(output_len != stp_dkg_peer_bc_transcript_msg_SIZE) return STP_DKG_Err_OSize;

  // 2. Players verify the VSPS property of the sum of the shared secrets by running
  //     VSPS-Check on  𝓐_i,..,𝓐_n where
  //
  //           𝓐_j = Π 𝓐_i,j
  //                 i
  //
  // If this check fails the players run VSPS-Check on each individual
  // sharing from step 1. Any player that fails this check is disqualified.
  uint8_t (*c)[ctx->n][ctx->n][crypto_core_ristretto255_BYTES] = (uint8_t (*)[ctx->n][ctx->n][crypto_core_ristretto255_BYTES]) ctx->ki_commitments;
  uint8_t (*kcom)[ctx->n][crypto_core_ristretto255_BYTES] = (uint8_t (*)[ctx->n][crypto_core_ristretto255_BYTES]) ctx->k_commitments;
  for(unsigned i=0;i<ctx->n;i++) {
    memcpy((*kcom)[i], (*c)[0][i], crypto_scalarmult_ristretto255_BYTES);
    for(unsigned j=1;j<ctx->n;j++) {
      crypto_core_ristretto255_add((*kcom)[i], (*kcom)[i], (*c)[j][i]);
    }
  }

  uint8_t fails_len=0;
  uint8_t fails[ctx->n];
  memset(fails,0,ctx->n);
  STP_DKG_Err ret = ft_or_full_vsps(ctx->n, ctx->t, ctx->n, ctx->index, (*kcom), c,
                                       "VSPS failed k during DKG, doing full VSPS check on all peers",
                                       "VSPS failed k",
                                       "ERROR, could not find any dealer commitments that fail the VSPS check",
                                       &fails_len, fails);
  if(ret!=STP_DKG_Err_OK) return ret;
  if(ctx->n - fails_len < 2) {
    if(liboprf_log_file!=NULL) {
      fprintf(liboprf_log_file, RED"[%d] less than 2 honest dealers: %d \n"NORMAL, ctx->index, ctx->n - fails_len);
      if(peer_add_cheater(ctx, 6, 0, 0) == NULL) return STP_DKG_Err_CheatersFull;
    }
    return STP_DKG_Err_NotEnoughDealers;
  }
  if(fails_len >= ctx->t) {
    if(liboprf_log_file!=NULL) {
      fprintf(liboprf_log_file, RED"[%d] more than t cheaters (t=%d, cheaters=%d)\n"NORMAL, ctx->index, ctx->t, fails_len);
      if(peer_add_cheater(ctx, 7, fails_len, 0) == NULL) return STP_DKG_Err_CheatersFull;
    }
    return STP_DKG_Err_TooManyCheaters;
  }

  uint8_t qual[ctx->n+1];
  uint8_t qual_len=0;
  for(uint8_t i=0;i<ctx->n;i++) {
    unsigned j,k;
    for(j=0;j<fails_len;j++) {
      if(fails[j]==i+1) break;
    }
    for(k=0;k<ctx->share_complaints_len;k++) {
      if(ctx->share_complaints[k]==i+1) break;
    }
    if(j>=fails_len) {
      if(k>=ctx->share_complaints_len) qual[qual_len++]=i+1;
    } else if(peer_add_cheater(ctx, 8, ctx->index, i+1) == NULL) return STP_DKG_Err_CheatersFull;
  }
  qual[qual_len]=0;
  if(liboprf_log_file!=NULL) {
    fprintf(liboprf_log_file,"[%d] qual is: ", ctx->index);
    for(unsigned i=0;i<qual_len;i++) fprintf(liboprf_log_file,"%s%d", ((i==0)?"":", "), qual[i]);
    fprintf(liboprf_log_file,"\n");
  }

  ctx->share[0].index=ctx->index;
  ctx->share[1].index=ctx->index;
  // finalize dkg
  if(0!=dkg_vss_finish(ctx->n,qual,(*ctx->k_shares),ctx->index,ctx->share, ctx->k_commitment)) return STP_DKG_Err_DKGFinish;

  STP_DKG_Message* msg20 = (STP_DKG_Message*) output;
  crypto_generichash_final(&ctx->transcript, msg20->data, crypto_generichash_BYTES);
  memcpy(ctx->final_transcript, msg20->data, crypto_generichash_BYTES);
  memcpy(msg20->data+crypto_generichash_BYTES, ctx->k_commitment, crypto_core_ristretto255_BYTES);

  if(0!=toprf_send_msg(output, stp_dkg_peer_bc_transcript_msg_SIZE, stpvssdkg_peer_bc_transcript_msg, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return STP_DKG_Err_Send;
  dkg_dump_msg(output, stp_dkg_peer_bc_transcript_msg_SIZE, ctx->index);

  ctx->step = STP_DKG_Peer_Confirm_Transcripts;
  return STP_DKG_Err_OK;
}

#define stp_dkg_stp_bc_transcript_msg_SIZE(ctx) (sizeof(STP_DKG_Message) + stp_dkg_peer_bc_transcript_msg_SIZE*ctx->n)
static STP_DKG_Err stp_bc_transcript_handler(STP_DKG_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[!] final1 broadcast DKG transcripts\x1b[0m\n");

  if((stp_dkg_peer_bc_transcript_msg_SIZE * ctx->n) != input_len) return STP_DKG_Err_ISize;
  if(output_len != stp_dkg_stp_bc_transcript_msg_SIZE(ctx)) return STP_DKG_Err_OSize;

  uint8_t transcript_hash[crypto_generichash_BYTES];
  crypto_generichash_final(&ctx->transcript, transcript_hash, crypto_generichash_BYTES);

  size_t cheaters = ctx->cheater_len;
  uint8_t *wptr = ((STP_DKG_Message *) output)->data;
  const uint8_t *ptr = input;
  for(uint8_t i=0;i<ctx->n;i++, ptr+=stp_dkg_peer_bc_transcript_msg_SIZE) {
    const STP_DKG_Message* msg = (const STP_DKG_Message*) ptr;
    if(stp_recv_msg(ctx,ptr,stp_dkg_peer_bc_transcript_msg_SIZE,stpvssdkg_peer_bc_transcript_msg,i+1,0xff)) continue;

    memcpy((*ctx->commitments)[i], msg->data + crypto_generichash_BYTES, crypto_core_ristretto255_BYTES);

    if(sodium_memcmp(transcript_hash, msg->data, sizeof(transcript_hash))!=0) {
      if(liboprf_log_file!=NULL) {
        fprintf(liboprf_log_file,"\x1b[0;31m[!] failed to verify transcript from %d!\x1b[0m\n", i);
      }
      if(stp_add_cheater(ctx, 1, i+1, 0) == NULL) return STP_DKG_Err_CheatersFull;
      continue;
    }

    memcpy(wptr, ptr, stp_dkg_peer_bc_transcript_msg_SIZE);
    wptr+=stp_dkg_peer_bc_transcript_msg_SIZE;
  }
  if(ctx->cheater_len>cheaters) return STP_DKG_Err_CheatersFound;

  liboprf_debug=0;
  if(0!=toprf_mpc_vsps_check(ctx->t-1, *ctx->commitments)) {
    liboprf_debug=1;
    if(liboprf_log_file!=NULL) fprintf(stderr, RED"[!] result of DKG final commitments fail VSPS\n"NORMAL);
    if(stp_add_cheater(ctx, 2, 0, 0) == NULL) return STP_DKG_Err_CheatersFull;
  }
  liboprf_debug=1;

  if(0!=toprf_send_msg(output, output_len, stpvssdkg_stp_bc_transcript_msg, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return STP_DKG_Err_Send;
  dkg_dump_msg(output, output_len, 0);

  ctx->step = STP_DKG_STP_Done;
  return STP_DKG_Err_OK;
}

static STP_DKG_Err peer_final_handler(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] finish receive and check final transcript\x1b[0m\n", ctx->index);
  if(input_len != stp_dkg_stp_bc_transcript_msg_SIZE(ctx)) return STP_DKG_Err_ISize;

  // verify STP message envelope
  const uint8_t *ptr;
  int ret = unwrap_envelope(ctx,input,input_len,stpvssdkg_stp_bc_transcript_msg,&ptr);
  if(ret!=STP_DKG_Err_OK) return ret;

  size_t cheaters = ctx->cheater_len;
  uint8_t (*kcom)[ctx->n][crypto_core_ristretto255_BYTES] = (uint8_t (*)[ctx->n][crypto_core_ristretto255_BYTES]) ctx->k_commitments;
  for(uint8_t i=0;i<ctx->n;i++, ptr+=stp_dkg_peer_bc_transcript_msg_SIZE) {
    const STP_DKG_Message* msg = (const STP_DKG_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,stp_dkg_peer_bc_transcript_msg_SIZE,stpvssdkg_peer_bc_transcript_msg,i+1,0xff)) continue;

    if(sodium_memcmp(ctx->final_transcript, msg->data, crypto_generichash_BYTES)!=0) {
      if(liboprf_log_file!=NULL) {
        fprintf(liboprf_log_file,"\x1b[0;31m[!] failed to verify transcript from %d!\x1b[0m\n", i);
      }
      if(peer_add_cheater(ctx, 1, i+1, 0) == NULL) return STP_DKG_Err_CheatersFull;
      continue;
    }
    memcpy((*kcom)[i], msg->data + crypto_generichash_BYTES, crypto_core_ristretto255_BYTES);
  }
  if(ctx->cheater_len>cheaters) return STP_DKG_Err_CheatersFound;

  // in theory this should not be needed, and not fail. except for the
  // case when the dealer shares were corrupted after calculating a
  // correct commitment for them.
  liboprf_debug=0;
  if(0!=toprf_mpc_vsps_check(ctx->t-1, (*kcom))) {
    liboprf_debug=1;
    if(liboprf_log_file!=NULL) fprintf(stderr, RED"[%d] result of DKG commitments fail VSPS\n"NORMAL, ctx->index);
    if(peer_add_cheater(ctx, 2, 0, 0) == NULL) return STP_DKG_Err_CheatersFull;
  }
  liboprf_debug=1;

  ctx->step = STP_DKG_Peer_Done;
  return STP_DKG_Err_OK;
}

int stp_dkg_stp_not_done(const STP_DKG_STPState *stp) {
  return stp->step<STP_DKG_STP_Done;
}

int stp_dkg_peer_not_done(const STP_DKG_PeerState *peer) {
  return peer->step<STP_DKG_Peer_Done;
}

void stp_dkg_peer_free(STP_DKG_PeerState *ctx) {
  for(int i=0;i<ctx->n;i++) {
    if((*ctx->noise_ins)[i]!=NULL) Noise_XK_session_free((*ctx->noise_ins)[i]);
    if((*ctx->noise_outs)[i]!=NULL) Noise_XK_session_free((*ctx->noise_outs)[i]);
  }
  if(ctx->dev!=NULL) Noise_XK_device_free(ctx->dev);
}

size_t stp_dkg_stp_input_size(const STP_DKG_STPState *ctx) {
  size_t sizes[ctx->n];
  //memset(sizes,0,sizeof sizes);
  if(stp_dkg_stp_input_sizes(ctx, sizes) == 1) {
    return sizes[0] * ctx->n;
  } else {
    size_t result=0;
    for(int i=0;i<ctx->n;i++) result+=sizes[i];
    return result;
  }
}

int stp_dkg_stp_input_sizes(const STP_DKG_STPState *ctx, size_t *sizes) {
  size_t item=0;
  switch(ctx->step) {
  case STP_DKG_STP_Send_Index: { item = 0; break; }
  case STP_DKG_STP_Broadcast_NPKs: { item = stp_dkg_peer_init1_msg_SIZE; break; }
  case STP_DKG_STP_Route_Noise_Handshakes1: { item=stp_dkg_peer_start_noise_msg_SIZE * ctx->n; break; }
  case STP_DKG_STP_Route_Noise_Handshakes2: { item=stp_dkg_peer_respond_noise_msg_SIZE * ctx->n; break; }
  case STP_DKG_STP_Broadcast_DKG_Hash_Commitments: { item=stp_dkg_peer_start_dkg_msg_SIZE(ctx); break; }
  case STP_DKG_STP_Broadcast_DKG_Commitments: { item = stp_dkg_peer_dkg2_msg_SIZE(ctx); break; }
  case STP_DKG_STP_Route_Encrypted_Shares: { item = stp_dkg_peer_dkg3_msg_SIZE * ctx->n; break; }
  case STP_DKG_STP_Broadcast_Complaints: { item = stp_dkg_peer_verify_shares_msg_SIZE(ctx); break; }
  case STP_DKG_STP_Broadcast_DKG_Defenses: {
    uint8_t ctr[ctx->n];
    memset(ctr,0,ctx->n);
    for(int i=0;i<ctx->share_complaints_len;i++) ctr[((*ctx->share_complaints)[i] & 0xff) - 1]++;
    for(int i=0;i<ctx->n;i++) {
      if(ctr[i]>0) {
        sizes[i]=sizeof(STP_DKG_Message) + (1+dkg_noise_key_SIZE+stp_dkg_encrypted_share_SIZE) * ctr[i];
      } else {
        sizes[i]=0;
      }
    }
    return 0;
  }
  case STP_DKG_STP_Broadcast_DKG_Transcripts: { item = stp_dkg_peer_bc_transcript_msg_SIZE; break; }
  case STP_DKG_STP_Done: { item = 0; break; }
  default: {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "[!] isize invalid stp step: %d\n", ctx->step);
  }
  }

  for(uint8_t i=0;i<ctx->n;i++) {
    sizes[i] = item;
  }
  return 1;
}

size_t stp_dkg_stp_output_size(const STP_DKG_STPState *ctx) {
  switch(ctx->step) {
  case STP_DKG_STP_Send_Index: return stp_dkg_stp_index_msg_SIZE(ctx) * ctx->n;
  case STP_DKG_STP_Broadcast_NPKs: return (stp_dkg_peer_init1_msg_SIZE) * ctx->n + sizeof(STP_DKG_Message);
  case STP_DKG_STP_Route_Noise_Handshakes1: return stp_dkg_peer_start_noise_msg_SIZE * ctx->n * ctx->n;
  case STP_DKG_STP_Route_Noise_Handshakes2: return stp_dkg_peer_respond_noise_msg_SIZE * ctx->n * ctx->n;
  case STP_DKG_STP_Broadcast_DKG_Hash_Commitments: return sizeof(STP_DKG_Message) + (stp_dkg_peer_start_dkg_msg_SIZE(ctx) * ctx->n);
  case STP_DKG_STP_Broadcast_DKG_Commitments: return sizeof(STP_DKG_Message) + (stp_dkg_peer_dkg2_msg_SIZE(ctx) * ctx->n);
  case STP_DKG_STP_Route_Encrypted_Shares: return stp_dkg_peer_dkg3_msg_SIZE * ctx->n * ctx->n;
  case STP_DKG_STP_Broadcast_Complaints: return stp_dkg_stp_bc_verify_shares_msg_SIZE(ctx);
  case STP_DKG_STP_Broadcast_DKG_Defenses: return sizeof(STP_DKG_Message) + stp_dkg_stp_input_size(ctx);
  case STP_DKG_STP_Broadcast_DKG_Transcripts: return stp_dkg_stp_bc_transcript_msg_SIZE(ctx);
  case STP_DKG_STP_Done: return 0;
  default: if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "[!] osize invalid stp step: %d\n", ctx->step);
  }
  return 0;
}

int stp_dkg_stp_peer_msg(const STP_DKG_STPState *ctx, const uint8_t *base, const size_t base_size, const uint8_t peer, const uint8_t **msg, size_t *len) {
  if(peer>=ctx->n) return -1;

  switch(ctx->prev) {
  case STP_DKG_STP_Send_Index: {
    *msg = base + peer * stp_dkg_stp_index_msg_SIZE(ctx);
    *len = stp_dkg_stp_index_msg_SIZE(ctx);
    break;
  }
  case STP_DKG_STP_Broadcast_NPKs: {
    *msg = base;
    *len = (stp_dkg_peer_init1_msg_SIZE) * ctx->n + sizeof(STP_DKG_Message);
    break;
  }
  case STP_DKG_STP_Route_Noise_Handshakes1: {
    *msg = base + peer * stp_dkg_peer_start_noise_msg_SIZE * ctx->n;
    *len = stp_dkg_peer_start_noise_msg_SIZE * ctx->n;
    break;
  }
  case STP_DKG_STP_Route_Noise_Handshakes2: {
    *msg = base + peer * stp_dkg_peer_respond_noise_msg_SIZE * ctx->n;
    *len = stp_dkg_peer_start_noise_msg_SIZE * ctx->n;
    break;
  }
  case STP_DKG_STP_Broadcast_DKG_Hash_Commitments: {
    *msg = base;
    *len = sizeof(STP_DKG_Message) + (stp_dkg_peer_start_dkg_msg_SIZE(ctx) * ctx->n);
    break;
  }
  case STP_DKG_STP_Broadcast_DKG_Commitments: {
    *msg = base;
    *len = sizeof(STP_DKG_Message) + (stp_dkg_peer_dkg2_msg_SIZE(ctx) * ctx->n);
    break;
  }
  case STP_DKG_STP_Route_Encrypted_Shares: {
    *msg = base + peer * stp_dkg_peer_dkg3_msg_SIZE * ctx->n;
    *len = stp_dkg_peer_dkg3_msg_SIZE * ctx->n;
    break;
  }
  case STP_DKG_STP_Broadcast_Complaints: {
    *msg = base;
    *len = stp_dkg_stp_bc_verify_shares_msg_SIZE(ctx);
    break;
  }
  case STP_DKG_STP_Broadcast_DKG_Defenses: {
    *msg = base;
    *len = sizeof(STP_DKG_Message);
    uint8_t ctr[ctx->n];
    memset(ctr,0,ctx->n);
    for(int i=0;i<ctx->share_complaints_len;i++) ctr[((*ctx->share_complaints)[i] & 0xff) - 1]++;
    for(int i=0;i<ctx->n;i++) {
      if(ctr[i]>0) {
        *len+=sizeof(STP_DKG_Message) + (1+dkg_noise_key_SIZE+stp_dkg_encrypted_share_SIZE) * ctr[i];
      }
    }
    break;
  }
  case STP_DKG_STP_Broadcast_DKG_Transcripts: {
    *msg = base;
    *len = stp_dkg_stp_bc_transcript_msg_SIZE(ctx);
    break;
  }
  case STP_DKG_STP_Done: {
    *msg = NULL;
    *len = 0;
    break;
  }
  default: {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "[!] invalid stp step in stp_dkg_stp_peer_msg\n");
    return 1;
  }
  }

  if(base+base_size < *msg + *len) {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "buffer overread detected in stp_dkg_stp_peer_msg %ld, step %d\n", (base+base_size) - (*msg + *len), ctx->step);
    return 2;
  }

  return 0;
}

size_t stp_dkg_peer_input_size(const STP_DKG_PeerState *ctx) {
  switch(ctx->step) {
  case STP_DKG_Peer_Broadcast_NPK_SIDNonce: return stp_dkg_stp_index_msg_SIZE(ctx);
  case STP_DKG_Peer_Rcv_NPK_SIDNonce: return (stp_dkg_peer_init1_msg_SIZE) * ctx->n + sizeof(STP_DKG_Message);
  case STP_DKG_Peer_Noise_Handshake: return stp_dkg_peer_start_noise_msg_SIZE * ctx->n;
  case STP_DKG_Peer_Finish_Noise_Handshake: return stp_dkg_peer_respond_noise_msg_SIZE * ctx->n;
  case STP_DKG_Peer_Rcv_Commitments_Send_Commitments: return sizeof(STP_DKG_Message) + stp_dkg_peer_start_dkg_msg_SIZE(ctx) * ctx->n;
  case STP_DKG_Peer_Rcv_Commitments_Send_Shares: return sizeof(STP_DKG_Message) + (stp_dkg_peer_dkg2_msg_SIZE(ctx) * ctx->n);
  case STP_DKG_Peer_Verify_Commitments: return ctx->n * stp_dkg_peer_dkg3_msg_SIZE;
  case STP_DKG_Peer_Handle_DKG_Complaints: return stp_dkg_stp_bc_verify_shares_msg_SIZE(ctx);
  case STP_DKG_Peer_Defend_DKG_Accusations: return 0;
  case STP_DKG_Peer_Check_Shares: {
    uint8_t ctr[ctx->n];
    memset(ctr,0,ctx->n);
    for(int i=0;i<ctx->share_complaints_len;i++) ctr[(ctx->share_complaints[i] & 0xff) - 1]++;
    size_t ret = sizeof(STP_DKG_Message);
    for(int i=0;i<ctx->n;i++) {
      if(ctr[i]>0) {
        ret+=sizeof(STP_DKG_Message) + (1+dkg_noise_key_SIZE+stp_dkg_encrypted_share_SIZE) * ctr[i];
      }
    }
    return ret;
  }
  case STP_DKG_Peer_Finish_DKG: return 0;
  case STP_DKG_Peer_Confirm_Transcripts: return stp_dkg_stp_bc_transcript_msg_SIZE(ctx);
  case STP_DKG_Peer_Done: return 0;
  default: {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "[%d] invalid step\n", ctx->index);
  }
  }
  return 1;
}

size_t stp_dkg_peer_output_size(const STP_DKG_PeerState *ctx) {
  switch(ctx->step) {
  case STP_DKG_Peer_Broadcast_NPK_SIDNonce: return stp_dkg_peer_init1_msg_SIZE;
  case STP_DKG_Peer_Rcv_NPK_SIDNonce: return stp_dkg_peer_start_noise_msg_SIZE * ctx->n;
  case STP_DKG_Peer_Noise_Handshake: return stp_dkg_peer_respond_noise_msg_SIZE * ctx->n;
  case STP_DKG_Peer_Finish_Noise_Handshake: return stp_dkg_peer_start_dkg_msg_SIZE(ctx);
  case STP_DKG_Peer_Rcv_Commitments_Send_Commitments: return stp_dkg_peer_dkg2_msg_SIZE(ctx);
  case STP_DKG_Peer_Rcv_Commitments_Send_Shares: return ctx->n * stp_dkg_peer_dkg3_msg_SIZE;
  case STP_DKG_Peer_Verify_Commitments: return stp_dkg_peer_verify_shares_msg_SIZE(ctx);
  case STP_DKG_Peer_Handle_DKG_Complaints: return 0;
  case STP_DKG_Peer_Defend_DKG_Accusations: {
    if(ctx->my_share_complaints_len == 0 /* && ctx->my_vsps_complaints_len == 0*/) return 0;
    size_t res = sizeof(STP_DKG_Message);
    if(ctx->my_share_complaints_len > 0) {
      res += ctx->my_share_complaints_len * (1+dkg_noise_key_SIZE+stp_dkg_encrypted_share_SIZE);
    }
    //if(ctx->my_vsps_complaints_len > 0) {
    //  res += ctx->my_vsps_complaints_len * (1+dkg_noise_key_SIZE);
    //}
    return res;
  }
  case STP_DKG_Peer_Check_Shares: return stp_dkg_peer_bc_transcript_msg_SIZE;
  case STP_DKG_Peer_Finish_DKG: return stp_dkg_peer_bc_transcript_msg_SIZE;
  case STP_DKG_Peer_Confirm_Transcripts: return 0;
  case STP_DKG_Peer_Done: return 0;
  default: {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "[%d] invalid step\n", ctx->index);
  }
  }
  return 1;
}
int stp_dkg_stp_next(STP_DKG_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  int ret = 0;
  ctx->prev=ctx->step;
  switch(ctx->step) {
  case STP_DKG_STP_Send_Index: { ret = stp_init_send_indexes(ctx, output, output_len) ; break ; }
  case STP_DKG_STP_Broadcast_NPKs: { ret =  stp_init2_handler(ctx, input, input_len, output, output_len); break;}
  case STP_DKG_STP_Route_Noise_Handshakes1: { ret = stp_route_start_noise_handler(ctx, input, input_len, output, output_len); break;}
  case STP_DKG_STP_Route_Noise_Handshakes2: { ret = stp_route_noise_respond_handler(ctx, input, input_len, output, output_len); break;}
  case STP_DKG_STP_Broadcast_DKG_Hash_Commitments: { ret = stp_dkg1_handler(ctx, input, input_len, output, output_len); break;}
  case STP_DKG_STP_Broadcast_DKG_Commitments: { ret = stp_dkg2_handler(ctx, input, input_len, output, output_len); break;}
  case STP_DKG_STP_Route_Encrypted_Shares: { ret = stp_dkg3_handler(ctx, input, input_len, output, output_len); break;}
  case STP_DKG_STP_Broadcast_Complaints: { ret = stp_verify_shares_handler(ctx, input, input_len, output, output_len); break;}
  case STP_DKG_STP_Broadcast_DKG_Defenses: { ret = stp_broadcast_defenses(ctx, input, input_len, output, output_len); break;}
  case STP_DKG_STP_Broadcast_DKG_Transcripts: { ret = stp_bc_transcript_handler(ctx, input, input_len, output, output_len); break;}
  case STP_DKG_STP_Done: { ret = 0; break; }
  default: {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "[!] invalid step\n");
    return 99;
  }
  }
  if(ret!=0) ctx->step=99; // so that not_done reports done
  return ret;
}

int stp_dkg_peer_next(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  int ret=0;
  ctx->prev=ctx->step;
  switch(ctx->step) {
  case STP_DKG_Peer_Broadcast_NPK_SIDNonce: { ret = peer_init1_handler(ctx, input, input_len, output, output_len) ; break; }
  case STP_DKG_Peer_Rcv_NPK_SIDNonce: { ret = peer_start_noise_handler(ctx, input, input_len, output, output_len); break; }
  case STP_DKG_Peer_Noise_Handshake: { ret = peer_respond_noise_handler(ctx, input, input_len, output, output_len); break; }
  case STP_DKG_Peer_Finish_Noise_Handshake: { ret = peer_dkg1_handler(ctx, input, input_len, output, output_len); break; }
  case STP_DKG_Peer_Rcv_Commitments_Send_Commitments: { ret = peer_dkg2_handler(ctx, input, input_len, output, output_len); break; }
  case STP_DKG_Peer_Rcv_Commitments_Send_Shares: { ret = peer_dkg3_handler(ctx, input, input_len, output, output_len); break; }
  case STP_DKG_Peer_Verify_Commitments: { ret = peer_verify_shares_handler(ctx, input, input_len, output, output_len); break; }
  case STP_DKG_Peer_Handle_DKG_Complaints: { ret = peer_dkg_fork(ctx, input, input_len); break; }
  case STP_DKG_Peer_Defend_DKG_Accusations: { ret = peer_defend(ctx, output, output_len); break; }
  case STP_DKG_Peer_Check_Shares: { ret = peer_check_shares(ctx, input, input_len, output, output_len); break; }
  case STP_DKG_Peer_Finish_DKG: { ret = peer_verify_vsps(ctx, output, output_len); break; }
  case STP_DKG_Peer_Confirm_Transcripts: { ret = peer_final_handler(ctx, input, input_len); break; }
  case STP_DKG_Peer_Done: {
    // we are done
    ret = 0;
    break;
  }
  default: {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "[%d] invalid step\n", ctx->index);
    ret = 99;
  }
  }
  if(ret!=0) ctx->step=99; // so that not_done reports done
  return ret;
}

uint8_t stp_dkg_stp_cheater_msg(const STP_DKG_Cheater *c, char *out, const size_t outlen) {
  if(c->error>65 && c->error<=71) {
      snprintf(out, outlen, "step %d message from peer %d for peer %d could not be validated: %s",
               c->step, c->peer, c->other_peer, dkg_recv_err(c->error & 0x3f));
      return c->peer;
  }
  if(c->error>33 && c->error<=39) {
      snprintf(out, outlen, "step %d broadcast message from STP for peer %d could not be validated: %s",
               c->step, c->other_peer, dkg_recv_err(c->error & 0x1f));
      return c->peer;
  }
  if(c->step==STP_DKG_STP_Broadcast_DKG_Commitments) {
    switch(c->error) {
    case 1: {snprintf(out, outlen, "failed VSPS check for dealer %d.", c->peer); return c->peer; }
    case 2: {snprintf(out, outlen, "less than 2 honest dealers."); return 0; }
    case 3: {snprintf(out, outlen, "more than t cheaters (%d)", c->peer); return 0; }
    case 4: {snprintf(out, outlen, "failed to verify hash for commitments of dealer %d", c->peer); return c->peer; }
    }
  }
  if(c->step==STP_DKG_STP_Broadcast_DKG_Defenses) {
    switch(c->error) {
    case 1: {snprintf(out, outlen, "invalid HMAC on shares of accused: %d, by %d.", c->peer, c->other_peer); return c->peer; }
    case 2: {snprintf(out, outlen, "failed to decrypt shares of accused: %d, by %d", c->peer, c->other_peer); return c->peer; }
    case 3: {snprintf(out, outlen, "accused peer %d sent an invalid share with index %d to complaining peer %d", c->peer, c->other_peer, c->invalid_index); return c->peer; }
    case 4: {snprintf(out, outlen, "failed to verify commitment of accused %d by accuser %d!", c->peer, c->other_peer); return c->peer; }
    case 5: {snprintf(out, outlen, "succeeded to verify commitment of accused %d by accuser %d", c->peer, c->other_peer); return c->other_peer; }
    }
  }
  if(c->step==STP_DKG_STP_Broadcast_DKG_Transcripts) {
    switch(c->error) {
    case 1: {snprintf(out, outlen, "failed to verify transcript from %d.", c->peer); return c->peer; }
    case 2: {snprintf(out, outlen, "result of DKG final commitments fail VSPS."); return 0; }
    }
  }
  snprintf(out, outlen, "step: %d, error: %d, peer: %d, other peer: %d", c->step, c->error, c->peer, c->other_peer);
  return 0;
}

uint8_t stp_dkg_peer_cheater_msg(const STP_DKG_Cheater *c, char *out, const size_t outlen) {
  if(c->error>65 && c->error<=71) {
      snprintf(out, outlen, "step %d message from peer %d for peer %d could not be validated: %s",
               c->step, c->peer, c->other_peer, dkg_recv_err(c->error & 0x3f));
      return c->peer;
  }
  if(c->error>33 && c->error<=39) {
      snprintf(out, outlen, "step %d broadcast message from STP for peer %d could not be validated: %s",
               c->step, c->other_peer, dkg_recv_err(c->error & 0x1f));
      return c->peer;
  }
  if(c->step==STP_DKG_Peer_Rcv_Commitments_Send_Shares && c->error==1) {
      snprintf(out, outlen, "failed to verify hash for commitments of dealer %d", c->step);
      return c->peer;
  }
  if(c->step==STP_DKG_Peer_Check_Shares) {
    switch(c->error) {
    case 1: {snprintf(out, outlen, "invalid HMAC on shares of accused: %d, by %d.", c->peer, c->other_peer); return c->peer; }
    case 2: {snprintf(out, outlen, "failed to decrypt shares of accused: %d, by %d", c->peer, c->other_peer); return c->peer; }
    case 3: {snprintf(out, outlen, "accused peer %d sent an invalid share with index %d to complaining peer %d", c->peer, c->other_peer, c->invalid_index); return c->peer; }
    case 4: {snprintf(out, outlen, "failed to verify commitment of accused %d by accuser %d!", c->peer, c->other_peer); return c->peer; }
    case 5: {snprintf(out, outlen, "succeeded to verify commitment of accused %d by accuser %d", c->peer, c->other_peer); return c->other_peer; }
    }
  }
  if(c->step==STP_DKG_STP_Broadcast_DKG_Transcripts || c->step==STP_DKG_Peer_Check_Shares) {
    switch(c->error) {
    case 6: {snprintf(out, outlen, "less than 2 honest dealers."); return 0; }
    case 7: {snprintf(out, outlen, "more than t cheaters (%d)", c->peer); return 0; }
    case 8: {snprintf(out, outlen, "failed VSPS check for dealer %d.", c->other_peer); return c->other_peer; }
    }
  }
  if(c->step==STP_DKG_Peer_Confirm_Transcripts) {
    switch(c->error) {
    case 1: {snprintf(out, outlen, "failed to verify transcript from %d.", c->peer); return c->peer; }
    case 2: {snprintf(out, outlen, "result of DKG final commitments fail VSPS."); return 0; }
    }
  }
  snprintf(out, outlen, "step: %d, error: %d, peer: %d, other peer: %d", c->step, c->error, c->peer, c->other_peer);
  return 0;
}
