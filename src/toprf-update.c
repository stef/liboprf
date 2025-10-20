#include <arpa/inet.h> //htons
#include "utils.h"
#include "toprf-update.h"
#include "dkg-vss.h"
#include "mpmult.h"
#ifndef HAVE_SODIUM_HKDF
#include "aux_/crypto_kdf_hkdf_sha256.h"
#endif
#ifdef __ZEPHYR__
#include <zephyr/kernel.h>
#endif

// todo handle adding new peers who don't have a share of kc
// todo handle random order of peers - related to prev todo
// todo revert to non-fast-track mult to catch the case when dealer
//      deals something else than λ_iα_iβ_i but 𝓒_i0 is based on the
//      correct value, so the ZK proof does not fail.
// todo add toprf_update_(stp|peer)_cheater_msg()

#ifdef UNITTEST_CORRUPT
static void corrupt_ci0_good_ci(const uint8_t peer, uint8_t commitments[][crypto_core_ristretto255_BYTES]) {
  // this corruption does not influence the outcome of the protocol
  // it merely fails the zkp *and* the vsps, but the end result is correct!
  uint8_t secret[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_random(secret);
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"!!! Corrupting C_i0 λ_iα_iβ_i %d\n"NORMAL, peer);
  dkg_vss_commit(secret,secret,commitments[0]);
}

/// deals shares with polynomial t+1 instead of 1
static void corrupt_vsps_t1(const TOPRF_Update_PeerState *ctx,
                            const uint8_t peer,
                            TOPRF_Share (*shares)[][2],
                            uint8_t (*commitments)[][crypto_core_ristretto255_BYTES]) {
  if(ctx->index!=peer) return;
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"!!! Corrupting with wrong degree of the polynom peer %d\n"NORMAL, peer);
  (void)dkg_vss_share(ctx->n, ctx->t+1, NULL, (*commitments), (*shares), NULL);
}

static void corrupt_mult_vsps_t1(TOPRF_Update_PeerState *ctx,
                                 const uint8_t peer) {
  if(ctx->index!=peer) return;
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[%d] !!! Corrupting mult sharing with degree t+1 polynomial\n"NORMAL, peer);
  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);
  (void)toprf_mpc_ftmult_step1(dealers, ctx->n, ctx->t+1, ctx->index-1,
                               ctx->kc0_share, ctx->p_share, (*ctx->lambdas),
                               // we reuse p_shares as we need to store n shares, and k0p_shares has only dealer entries
                               (*ctx->p_shares), (*ctx->k0p_commitments), ctx->k0p_tau);
}

static void corrupt_commitment(TOPRF_Update_PeerState *ctx, const uint8_t peer,
                               uint8_t (*commitments)[][crypto_core_ristretto255_BYTES]) { // corrupts the 1st commitment with the 2nd
  if(ctx->index!=peer) return;
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"!!! Corrupting commitment of peer %d\n"NORMAL, peer);
  memcpy((*commitments)[2], (*commitments)[1], crypto_core_ristretto255_BYTES);
}

static void corrupt_wrongshare_correct_commitment(TOPRF_Update_PeerState *ctx, // swaps the share and it's blinder,
                                                  const uint8_t peer,     // recalculates commitment
                                                  const uint8_t share_idx,
                                                  TOPRF_Share (*shares)[][2],
                                                  uint8_t (*commitments)[][crypto_core_ristretto255_BYTES]) {
  if(ctx->index!=peer) return;
  TOPRF_Share tmp;
  // swap shares
  memcpy(&tmp, &(*shares)[share_idx][0], sizeof tmp);
  memcpy(&(*shares)[share_idx][0], &(*shares)[share_idx][1], sizeof tmp);
  memcpy(&(*shares)[share_idx][1], &tmp, sizeof tmp);
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"!!! Corrupting share (but correct commitment) of peer %d\n"NORMAL, peer);
  dkg_vss_commit((*shares)[share_idx][0].value,(*shares)[share_idx][1].value,(*commitments)[share_idx]);
}

static void corrupt_share(TOPRF_Update_PeerState *ctx, const uint8_t peer,
                          const uint8_t share_idx,
                          const uint8_t share_type,
                          TOPRF_Share (*shares)[][2]) {
  if(ctx->index!=peer) return;
  if(liboprf_log_file!=NULL) {
    fprintf(liboprf_log_file, RED"!!! Corrupting share of peer %d\n"NORMAL, peer);
    dump((uint8_t*) (*shares)[share_idx], TOPRF_Share_BYTES * 2, "correct share");
  }
  (*shares)[share_idx][share_type].value[2]^=0xff; // flip some bits
  if(liboprf_log_file!=NULL) {
    dump((uint8_t*) (*shares)[share_idx], TOPRF_Share_BYTES * 2, "corrupt share");
  }
}

static void corrupt_false_accuse(TOPRF_Update_PeerState *ctx,
                                 const uint8_t peer,
                                 const uint8_t p2,
                                 uint8_t *fails_len, uint8_t *fails) {
  if(ctx->index!=peer) return;
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"!!! Corrupting falsely accusing peer %d by peer %d\n"NORMAL, p2, peer);
  fails[(*fails_len)++]=p2;
}
#endif // UNITTEST_CORRUPT

size_t toprf_update_peerstate_size(void) {
  return sizeof(TOPRF_Update_PeerState);
}
uint8_t toprf_update_peerstate_n(const TOPRF_Update_PeerState *ctx) {
  return ctx->n;
}
uint8_t toprf_update_peerstate_t(const TOPRF_Update_PeerState *ctx) {
  return ctx->t;
}
const uint8_t* toprf_update_peerstate_sessionid(const TOPRF_Update_PeerState *ctx) {
  return ctx->sessionid;
}
const uint8_t* toprf_update_peerstate_share(const TOPRF_Update_PeerState *ctx) {
  if(toprf_update_peer_not_done(ctx)) return NULL;
  return (const uint8_t*) &ctx->k0p_share;
}
const uint8_t* toprf_update_peerstate_commitments(const TOPRF_Update_PeerState *ctx) {
  if(toprf_update_peer_not_done(ctx)) return NULL;
  return (const uint8_t*) (*ctx->p_commitments);
}
const uint8_t* toprf_update_peerstate_commitment(const TOPRF_Update_PeerState *ctx) {
  if(toprf_update_peer_not_done(ctx)) return NULL;
  return (const uint8_t*) ctx->k0p_commitment;
}
int toprf_update_peerstate_step(const TOPRF_Update_PeerState *ctx) {
  return ctx->step;
}

size_t toprf_update_stpstate_size(void) {
  return sizeof(TOPRF_Update_STPState);
}
uint8_t toprf_update_stpstate_n(const TOPRF_Update_STPState *ctx) {
  return ctx->n;
}
uint8_t toprf_update_stpstate_t(const TOPRF_Update_STPState *ctx) {
  return ctx->t;
}
size_t toprf_update_stpstate_cheater_len(const TOPRF_Update_STPState *ctx) {
  return ctx->cheater_len;
}
const uint8_t* toprf_update_stpstate_sessionid(const TOPRF_Update_STPState *ctx) {
  return ctx->sessionid;
}
const uint8_t* toprf_update_stpstate_delta(const TOPRF_Update_STPState *ctx) {
  if(toprf_update_stp_not_done(ctx)) return NULL;
  return ctx->delta;
}
const uint8_t* toprf_update_stpstate_commitments(const TOPRF_Update_STPState *ctx) {
  if(toprf_update_stp_not_done(ctx)) return NULL;
  return (const uint8_t*) (*ctx->k0p_final_commitments);
}
int toprf_update_stpstate_step(const TOPRF_Update_STPState *ctx) {
  return ctx->step;
}

static int toprf_send_msg(uint8_t* msg_buf, const size_t msg_buf_len,
                          const uint8_t msgno,
                          const uint8_t from, const uint8_t to,
                          const uint8_t *sig_sk, const uint8_t sessionid[dkg_sessionid_SIZE]) {
  int ret = send_msg(msg_buf, msg_buf_len, MSG_TYPE_SEMI_TRUSTED | MSG_TYPE_UPDATE, 0, msgno, from, to, sig_sk, sessionid);
  //dkg_dump_msg(msg_buf, msg_buf_len, from);
  return ret;
}

static int toprf_recv_msg(const uint8_t *msg_buf, const size_t msg_buf_len,
                          const uint8_t msgno,
                          const uint8_t from, const uint8_t to,
                          const uint8_t *sig_pk, const uint8_t sessionid[dkg_sessionid_SIZE],
                          const uint64_t ts_epsilon, uint64_t *last_ts) {
  return recv_msg(msg_buf, msg_buf_len, MSG_TYPE_SEMI_TRUSTED | MSG_TYPE_UPDATE, 0, msgno, from, to, sig_pk, sessionid, ts_epsilon, last_ts);
}

static void set_cheater(TOPRF_Update_Cheater *cheater, const int step, const int error, const uint8_t peer, const uint8_t other_peer) {
  cheater->step = step;
  cheater->error = error;
  cheater->peer = peer;
  cheater->other_peer=other_peer;
}

static TOPRF_Update_Cheater* stp_add_cheater(TOPRF_Update_STPState *ctx, const int error, const uint8_t peer, const uint8_t other_peer) {
  if(ctx->cheater_len >= ctx->cheater_max) return NULL;
  TOPRF_Update_Cheater *cheater = &(*ctx->cheaters)[ctx->cheater_len++];
  set_cheater(cheater, ctx->step, error, peer, other_peer);
  return cheater;
}

static TOPRF_Update_Cheater* peer_add_cheater(TOPRF_Update_PeerState *ctx,const int error, const uint8_t peer, const uint8_t other_peer) {
  if(ctx->cheater_len >= ctx->cheater_max) return NULL;
  TOPRF_Update_Cheater *cheater = &(*ctx->cheaters)[ctx->cheater_len++];
  set_cheater(cheater, ctx->step, error, peer, other_peer);
  return cheater;
}

static unsigned isdealer(const uint8_t i, const uint8_t t) {
  return  i <= ((t-1)*2 + 1);
}

static int stp_recv_msg(TOPRF_Update_STPState *ctx,
                        const uint8_t *msg_buf, const size_t msg_buf_len,
                        const uint8_t msgno,
                        const uint8_t from, const uint8_t to) {
  //dkg_dump_msg(msg_buf, msg_buf_len, 0);
  int ret = toprf_recv_msg(msg_buf, msg_buf_len, msgno, from, to, (*ctx->sig_pks)[from], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts[from-1]);
  if(0!=ret) {
    if(stp_add_cheater(ctx, 64+ret, from, to) == NULL) return TOPRF_Update_Err_CheatersFull;
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"failed to validate msg %d from %d, err: %d\n"NORMAL, msgno, from, ret);
    return 1;
  }
  return 0;
}

static int peer_recv_msg(TOPRF_Update_PeerState *ctx,
                         const uint8_t *msg_buf, const size_t msg_buf_len,
                         const uint8_t msgno,
                         const uint8_t from, const uint8_t to) {
  //dkg_dump_msg(msg_buf, msg_buf_len, ctx->index);
  int ret = toprf_recv_msg(msg_buf, msg_buf_len, msgno, from, to, (*ctx->sig_pks)[from], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts[from-1]);
  if(0!=ret) {
    if(peer_add_cheater(ctx, 64+ret, from, to) == NULL) return TOPRF_Update_Err_CheatersFull;
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[%d] failed to validate msg %d from %d, err: %d\n"NORMAL, ctx->index, msgno, from, ret);
    return 1;
  }
  return 0;
}

static TOPRF_Update_Err stp_broadcast(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len,
                                      const char *step_title,
                                      const uint8_t msg_count,          // usually n, sometimes dealers
                                      const size_t msg_size,
                                      const uint8_t msgno,
                                      const TOPRF_Update_STP_Steps next_step) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[!] %s\x1b[0m\n", step_title);
  if(msg_count * msg_size != input_len) return TOPRF_Update_Err_ISize;
  const size_t cheaters = ctx->cheater_len;
  if(sizeof(TOPRF_Update_Message) + input_len != output_len) return TOPRF_Update_Err_OSize;
  const uint8_t *ptr = input;
  uint8_t *wptr = ((TOPRF_Update_Message *) output)->data;
  for(uint8_t i=0;i<msg_count;i++,ptr+=msg_size) {
    if(stp_recv_msg(ctx,ptr,msg_size,msgno,i+1,0xff)) continue;
    memcpy(wptr, ptr, msg_size);
    wptr+=msg_size;
  }
  if(ctx->cheater_len>cheaters) return TOPRF_Update_Err_CheatersFound;

  if(0!=toprf_send_msg(output, output_len, msgno+1, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;

  // add broadcast msg to transcript
  update_transcript(&ctx->transcript_state, output, output_len);

  ctx->step = next_step;

  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err stp_route(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len,
                                  const char *step_title,
                                  const uint8_t send_count,
                                  const uint8_t recv_count,
                                  const uint8_t msgno,
                                  const size_t msg_size,
                                  const TOPRF_Update_STP_Steps next_step) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[!] %s\x1b[0m\n", step_title);
  if(input_len != msg_size * send_count * recv_count) return TOPRF_Update_Err_ISize;
  if(input_len != output_len) return TOPRF_Update_Err_OSize;
  //const size_t cheaters = ctx->cheater_len;

  const uint8_t (*inputs)[send_count][recv_count][msg_size] = (const uint8_t (*)[send_count][recv_count][msg_size]) input;
  uint8_t *wptr = output;
  for(uint8_t i=0;i<recv_count;i++) {
    for(uint8_t j=0;j<send_count;j++) {
      int ret = toprf_recv_msg((*inputs)[j][i], msg_size,
                               msgno, j+1, i+1, (*ctx->sig_pks)[j+1],
                               ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts[j]);
      if(0!=ret) {
        if(stp_add_cheater(ctx, 64+ret, j+1, i+1) == NULL) return TOPRF_Update_Err_CheatersFull;
        const TOPRF_Update_Message *msg = (const TOPRF_Update_Message*) (*inputs)[j][i];
        fprintf(liboprf_log_file,"[x] msgno: %d, from: %d to: %d ", msg->msgno, msg->from, msg->to);
        dump((*inputs)[j][i], msg_size, "msg");
        continue;
      }
      memcpy(wptr, (*inputs)[j][i], msg_size);
      wptr+=msg_size;
    }
  }
  //if(ctx->cheater_len>cheaters) return TOPRF_Update_Err_CheatersFound;

  ctx->step = next_step;
  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err unwrap_envelope(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, const uint8_t msgno, const uint8_t **contents) {
  // verify STP message envelope
  const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) input;
  //dkg_dump_msg(input, input_len, ctx->index);
  int ret = toprf_recv_msg(input, input_len, msgno, 0, 0xff, (*ctx->sig_pks)[0], ctx->sessionid, ctx->ts_epsilon, &ctx->stp_last_ts);
  if(0!=ret) return TOPRF_Update_Err_BroadcastEnv+ret;

  // add broadcast msg to transcript
  update_transcript(&ctx->transcript_state, input, input_len);

  *contents = msg->data;
  return TOPRF_Update_Err_OK;
}

static void handle_complaints(const uint8_t n,
                              const uint8_t accuser,
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
      fprintf(liboprf_log_file,"\x1b[0;31m[%d] peer %d failed to verify commitments from peer %d!\x1b[0m\n", self, accuser, fails[k]);
    }
  }
}

static TOPRF_Update_Err stp_complaint_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len,
                                              const char* step_title,
                                              const uint8_t msg_count,
                                              const size_t msg_size,
                                              const uint8_t msgno,
                                              const uint8_t dealers,

                                              const TOPRF_Update_STP_Steps pass_step,
                                              const TOPRF_Update_STP_Steps fail_step) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[!] %s\x1b[0m\n", step_title);

  if(input_len != msg_size * msg_count) return TOPRF_Update_Err_ISize;
  if(sizeof(TOPRF_Update_Message) + input_len != output_len) return TOPRF_Update_Err_OSize;
  //const size_t cheaters = ctx->cheater_len;

  ctx->p_complaints_len = 0;

  const uint8_t *ptr = input;
  uint8_t *wptr = ((TOPRF_Update_Message *) output)->data;
  for(uint8_t i=0;i<msg_count;i++, ptr+=msg_size) {
    const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) ptr;
    if(stp_recv_msg(ctx,ptr,msg_size,msgno,i+1,0xff)) continue;
    if(ntohl(msg->len) - sizeof(TOPRF_Update_Message) < msg->data[0]) return TOPRF_Update_Err_OOB;

    const uint8_t *fails_len = msg->data;
    const uint8_t *fails = msg->data+1;
    handle_complaints(msg_count, i+1, *fails_len, fails, &ctx->p_complaints_len, ctx->p_complaints, 0, 0, 0);

    memcpy(wptr, ptr, msg_size);
    wptr+=msg_size;
  }

  // if more than t^2 complaints are received the protocol also fails
  if(ctx->p_complaints_len >= ctx->t * ctx->t) {
    if(stp_add_cheater(ctx, 6, 0xfe, 0xfe) == NULL) return TOPRF_Update_Err_CheatersFull;
    return TOPRF_Update_Err_TooManyCheaters;
  }

  //if(ctx->cheater_len>cheaters) return TOPRF_Update_Err_CheatersFound;

  if(0!=toprf_send_msg(output, output_len, msgno+1, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;

  // add broadcast msg to transcript
  update_transcript(&ctx->transcript_state, output, output_len);

  ctx->prev = ctx->step;
  if(ctx->p_complaints_len == 0) {
    ctx->step = pass_step;
  } else {
    dump((uint8_t*) ctx->p_complaints, ctx->p_complaints_len*sizeof(uint16_t), "[!] complaints_2");
    ctx->step = fail_step;
  }

  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err peer_complaint_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len,
                                               const char *step_title,
                                               const size_t msg_size,
                                               const uint8_t msgno,
                                               const uint8_t dealers,
                                               const TOPRF_Update_Peer_Steps pass_step,
                                               const TOPRF_Update_Peer_Steps fail_step) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] %s\x1b[0m\n", ctx->index, step_title);
  if(input_len != sizeof(TOPRF_Update_Message) + msg_size * ctx->n) return TOPRF_Update_Err_ISize;
  //const size_t cheaters = ctx->cheater_len;

  // verify STP message envelope
  const uint8_t *ptr=NULL;
  int ret = unwrap_envelope(ctx,input,input_len,msgno+1,&ptr);
  if(ret!=TOPRF_Update_Err_OK) return ret;

  for(uint8_t i=0;i<ctx->n;i++, ptr+=msg_size) {
    const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,msg_size,msgno,i+1,0xff)) continue;
    if(ntohl(msg->len) - sizeof(TOPRF_Update_Message) < msg->data[0]) return TOPRF_Update_Err_OOB;
    const uint8_t *fails_len = msg->data;
    const uint8_t *fails = msg->data+1;
    handle_complaints(ctx->n, i+1, *fails_len, fails, &ctx->p_complaints_len, ctx->p_complaints, ctx->index, &ctx->my_p_complaints_len, ctx->my_p_complaints);
  }

  //if(ctx->cheater_len>cheaters) return TOPRF_Update_Err_CheatersFound;

  ctx->prev = ctx->step;
  if(ctx->p_complaints_len == 0) {
    ctx->step = pass_step;
  } else {
    dump((uint8_t*) ctx->p_complaints, ctx->p_complaints_len*sizeof(uint16_t), "[!] complaints_2");
    ctx->step = fail_step;
  }

  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err ft_or_full_vsps(const uint8_t n, const uint8_t t, const uint8_t dealers, const uint8_t self,
                                        const uint8_t C_i[n][crypto_core_ristretto255_BYTES],
                                        const uint8_t (*C_ij)[dealers][n][crypto_core_ristretto255_BYTES],
                                        const char *ft_msg, const char *sub_msg, const char *no_sub_msg,
                                        uint8_t *fails_len, uint8_t fails[dealers]) {
  //fprintf(stderr,"asdf %d %d %d %d\n", n, t, dealers, self);
  //for(unsigned i=0;i<n;i++) dump(C_i[i], crypto_core_ristretto255_BYTES, "C_%d",i);
  //for(unsigned i=0;i<n;i++)
  //  for(unsigned j=0;j<n;j++)
  //    dump((*C_ij)[i][j], crypto_core_ristretto255_BYTES, "C_%d,%d", i, j);

  int _debug=liboprf_debug; liboprf_debug=0;
  if(0!=toprf_mpc_vsps_check(t-1, C_i)) {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[%d] %s\n"NORMAL, self, ft_msg);
    for(uint8_t i=0;i<dealers;i++) {
      if(0!=toprf_mpc_vsps_check(t-1, (*C_ij)[i])) {
        if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[%d] %s [%d]\n"NORMAL, self, sub_msg, i+1);
        fails[(*fails_len)++]=i+1;
      }
    }
    liboprf_debug=_debug;
    if(*fails_len == 0) {
      if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[%d] %s\n"NORMAL, self, no_sub_msg);
      return TOPRF_Update_Err_NoSubVSPSFail;
    }
  }
  return TOPRF_Update_Err_OK;
}

int toprf_update_start_stp(TOPRF_Update_STPState *ctx, const uint64_t ts_epsilon,
                           const uint8_t n, const uint8_t t,
                           const char *proto_name, const size_t proto_name_len,
                           const uint8_t keyid[toprf_keyid_SIZE],
                           const uint8_t (*sig_pks)[][crypto_sign_PUBLICKEYBYTES],
                           const uint8_t ltssk[crypto_sign_SECRETKEYBYTES],
                           const size_t msg0_len,
                           TOPRF_Update_Message *msg0) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[!] init 0. start toprf update\x1b[0m\n");
  if(2>n || t>=n || n>128 || n<2*t+1) return 1;
  if(proto_name_len<1) return 2;
  if(proto_name_len>1024) return 3;
  if(msg0_len != toprfupdate_stp_start_msg_SIZE) return 4;

  ctx->ts_epsilon = ts_epsilon;
  ctx->step = TOPRF_Update_STP_Broadcast_NPKs;
  ctx->n = n;
  ctx->t = t;
  ctx->p_complaints_len = 0;
  ctx->y2_complaints_len = 0;
  ctx->cheater_len = 0;

  // dst hash(len(protoname) | "TOPRF Update for protocol " | protoname | n | t)
  crypto_generichash_state dst_state;
  crypto_generichash_init(&dst_state, NULL, 0, crypto_generichash_BYTES);
  uint16_t len=htons((uint16_t) proto_name_len+20); // we have a guard above restricting to 1KB the proto_name_len
  crypto_generichash_update(&dst_state, (uint8_t*) &len, 2);
  crypto_generichash_update(&dst_state, (const uint8_t*) "TOPRF Update for protocol ", 26);
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

  // data = {stp_lt_pks, dst, keyid}
  uint8_t *ptr = msg0->data;
  memcpy(ptr, (*sig_pks)[0], crypto_sign_PUBLICKEYBYTES);
  ptr+=crypto_sign_PUBLICKEYBYTES;
  memcpy(ptr, dst, sizeof dst);
  ptr+=sizeof dst;
  memcpy(ptr, keyid, toprf_keyid_SIZE);

  if(0!=toprf_send_msg((uint8_t*) msg0, toprfupdate_stp_start_msg_SIZE, toprfupdate_stp_start_msg, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return 5;

  // init transcript
  crypto_generichash_init(&ctx->transcript_state, NULL, 0, crypto_generichash_BYTES);
  crypto_generichash_update(&ctx->transcript_state, (const uint8_t*) "toprf update session transcript", 31);
  // feed msg0 into transcript
  update_transcript(&ctx->transcript_state, (uint8_t*) msg0, msg0_len);

  return 0;
}

void toprf_update_stp_set_bufs(TOPRF_Update_STPState *ctx,
                               uint16_t p_complaints[],
                               uint16_t y2_complaints[],
                               TOPRF_Update_Cheater (*cheaters)[], const size_t cheater_max,
                               uint8_t (*p_commitments_hashes)[][toprf_update_commitment_HASHBYTES],
                               uint8_t (*p_share_macs)[][crypto_auth_hmacsha256_BYTES],
                               uint8_t (*p_commitments)[][crypto_core_ristretto255_BYTES],
                               uint8_t (*kc0_commitments)[][crypto_core_ristretto255_BYTES],
                               uint8_t (*k0p_commitments)[][crypto_core_ristretto255_BYTES],
                               uint8_t (*zk_challenge_commitments)[][3][crypto_scalarmult_ristretto255_SCALARBYTES],
                               uint8_t (*zk_challenge_e_i)[][crypto_scalarmult_ristretto255_SCALARBYTES],
                               uint8_t (*k0p_final_commitments)[][crypto_scalarmult_ristretto255_BYTES],
                               uint64_t *last_ts) {
  ctx->p_complaints = p_complaints;
  memset(ctx->p_complaints, 0, sizeof(uint16_t) * ctx->n*ctx->n);
  ctx->y2_complaints = y2_complaints;
  memset(ctx->y2_complaints, 0, sizeof(uint16_t) * ctx->n*ctx->n);
  ctx->cheaters = cheaters;
  memset(*cheaters, 0, cheater_max*sizeof(TOPRF_Update_Cheater));
  ctx->cheater_max = cheater_max;
  ctx->last_ts = last_ts;
  ctx->p_commitments_hashes = p_commitments_hashes;
  ctx->p_share_macs = p_share_macs;
  ctx->p_commitments = p_commitments;
  ctx->kc0_commitments = kc0_commitments;
  ctx->k0p_commitments = k0p_commitments;
  ctx->zk_challenge_commitments = zk_challenge_commitments;
  ctx->zk_challenge_e_i = zk_challenge_e_i;
  ctx->k0p_final_commitments = k0p_final_commitments;
#ifdef __ZEPHYR__
  uint64_t now = (uint64_t) k_uptime_get();
#else
  uint64_t now = (uint64_t)time(NULL);
#endif
  for(uint8_t i=0;i<ctx->n;i++) ctx->last_ts[i]=now;
}

TOPRF_Update_Err toprf_update_start_peer(TOPRF_Update_PeerState *ctx,
                                         const uint64_t ts_epsilon,
                                         const uint8_t lt_sk[crypto_sign_SECRETKEYBYTES],
                                         const uint8_t noise_sk[crypto_scalarmult_SCALARBYTES],
                                         const TOPRF_Update_Message *msg0,
                                         uint8_t keyid[toprf_keyid_SIZE],
                                         uint8_t stp_ltpk[crypto_sign_PUBLICKEYBYTES]) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[?] init1 start peer\x1b[0m\n");
  //dkg_dump_msg((const uint8_t*) msg0, toprfupdate_stp_start_msg_SIZE, msg0->from);

  ctx->ts_epsilon = ts_epsilon;
  ctx->stp_last_ts = 0;

  int ret = toprf_recv_msg((const uint8_t*) msg0, toprfupdate_stp_start_msg_SIZE, toprfupdate_stp_start_msg, 0, 0xff, msg0->data, msg0->sessionid, ts_epsilon, &ctx->stp_last_ts);
  if(0!=ret) return TOPRF_Update_Err_Env+ ret;

  // extract data from message
  // we abuse sessionid as a temporary storage for the nonce_stp value, until we have the final sessionid
  memcpy(ctx->sessionid, msg0->sessionid, sizeof ctx->sessionid);

  const uint8_t *ptr=msg0->data;
  memcpy(stp_ltpk,ptr,crypto_sign_PUBLICKEYBYTES);
  ptr+=crypto_sign_PUBLICKEYBYTES + crypto_generichash_BYTES; // also skip DST
  memcpy(keyid,ptr,toprf_keyid_SIZE);

  ctx->p_complaints_len = 0;
  ctx->my_p_complaints_len = 0;
  ctx->cheater_len = 0;
  memcpy(ctx->sig_sk, lt_sk, crypto_sign_SECRETKEYBYTES);
  memcpy(ctx->noise_sk, noise_sk, crypto_scalarmult_SCALARBYTES);

  crypto_generichash_init(&ctx->transcript_state, NULL, 0, crypto_generichash_BYTES);
  crypto_generichash_update(&ctx->transcript_state, (const uint8_t*) "toprf update session transcript", 31);
  // feed msg0 into transcript
  update_transcript(&ctx->transcript_state, (const uint8_t*) msg0, toprfupdate_stp_start_msg_SIZE);

  ctx->dev = NULL;
  ctx->step = TOPRF_Update_Peer_Broadcast_NPK_SIDNonce;

  return TOPRF_Update_Err_OK;
}

int toprf_update_peer_set_bufs(TOPRF_Update_PeerState *ctx,
                               const uint8_t self,
                               const uint8_t n, const uint8_t t,
                               const TOPRF_Share k0[2],
                               uint8_t (*kc0_commitments)[][crypto_core_ristretto255_BYTES],
                               const uint8_t (*sig_pks)[][crypto_sign_PUBLICKEYBYTES],
                               uint8_t (*peer_noise_pks)[][crypto_scalarmult_BYTES],
                               Noise_XK_session_t *(*noise_outs)[],
                               Noise_XK_session_t *(*noise_ins)[],
                               TOPRF_Share (*p_shares)[][2],
                               uint8_t (*p_commitments)[][crypto_core_ristretto255_BYTES],
                               uint8_t (*p_commitments_hashes)[][toprf_update_commitment_HASHBYTES],
                               uint8_t (*p_share_macs)[][crypto_auth_hmacsha256_BYTES],
                               uint8_t (*encrypted_shares)[][noise_xk_handshake3_SIZE + toprf_update_encrypted_shares_SIZE],
                               TOPRF_Update_Cheater (*cheaters)[], const size_t cheater_max,
                               uint8_t (*lambdas)[][crypto_core_ristretto255_SCALARBYTES],
                               TOPRF_Share (*k0p_shares)[][2],
                               uint8_t (*k0p_commitments)[][crypto_core_ristretto255_BYTES],
                               uint8_t (*zk_challenge_nonce_commitments)[][crypto_scalarmult_ristretto255_BYTES],
                               uint8_t (*zk_challenge_nonces)[][2][crypto_scalarmult_ristretto255_SCALARBYTES],
                               uint8_t (*zk_challenge_commitments)[][3][crypto_scalarmult_ristretto255_SCALARBYTES],
                               uint8_t (*zk_challenge_e_i)[][crypto_scalarmult_ristretto255_SCALARBYTES],
                               uint16_t *p_complaints,
                               uint8_t *my_p_complaints,
                               uint64_t *last_ts) {
  if(2>n || t>=n || n>128 || n<2*t+1) return 1;
  ctx->index = self;
  ctx->n = n;
  ctx->t = t;
  memcpy((uint8_t*) ctx->kc0_share, (const uint8_t*) k0, sizeof(TOPRF_Share)*2);
  ctx->kc0_commitments = kc0_commitments;
  ctx->sig_pks = sig_pks;
  ctx->peer_noise_pks = peer_noise_pks;

  ctx->noise_outs = noise_outs;
  ctx->noise_ins = noise_ins;
  ctx->p_shares = p_shares;
  ctx->p_commitments = p_commitments;
  ctx->p_commitments_hashes = p_commitments_hashes;
  ctx->p_share_macs = p_share_macs;
  ctx->encrypted_shares = encrypted_shares;
  ctx->lambdas = lambdas;
  ctx->k0p_shares = k0p_shares;
  ctx->k0p_commitments = k0p_commitments;
  ctx->zk_challenge_nonce_commitments = zk_challenge_nonce_commitments;
  ctx->zk_challenge_nonces = zk_challenge_nonces;
  ctx->zk_challenge_commitments = zk_challenge_commitments;
  ctx->zk_challenge_e_i = zk_challenge_e_i;
  ctx->p_complaints = p_complaints;
  memset(ctx->p_complaints, 0, sizeof(uint16_t) * n);
  ctx->my_p_complaints = my_p_complaints;
  memset(ctx->my_p_complaints, 0, n);
  ctx->cheaters = cheaters;
  memset(cheaters,0,sizeof(TOPRF_Update_Cheater)*cheater_max);
  ctx->cheater_max = cheater_max;
  ctx->last_ts = last_ts;
  for(uint8_t i=0;i<ctx->n;i++) ctx->last_ts[i]=0;
  return 0;
}

#define toprfupdate_peer_init_msg_SIZE (sizeof(TOPRF_Update_Message) + dkg_sessionid_SIZE + crypto_core_ristretto255_BYTES)
static TOPRF_Update_Err peer_step1_handler(TOPRF_Update_PeerState *ctx, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] init2 send msg1 containing session id nonce\x1b[0m\n", ctx->index);
  if(output_len != toprfupdate_peer_init_msg_SIZE) return TOPRF_Update_Err_OSize;

  uint8_t *wptr = ((TOPRF_Update_Message *) output)->data;
  randombytes_buf(wptr, dkg_sessionid_SIZE);
  wptr+=dkg_sessionid_SIZE;
  if(0!=dkg_vss_commit(ctx->kc0_share[0].value, ctx->kc0_share[1].value,wptr)) return TOPRF_Update_Err_VSSCommit;
  if(0!=toprf_send_msg(output, toprfupdate_peer_init_msg_SIZE, toprfupdate_peer_init_msg, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;

  ctx->step = TOPRF_Update_Peer_Rcv_NPK_SIDNonce;

  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err stp_step2_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[!] init3 broadcast msg1 containing session id nonces of peers\x1b[0m\n");
  if(input_len  != toprfupdate_peer_init_msg_SIZE * ctx->n) return TOPRF_Update_Err_ISize;
  if(output_len != toprfupdate_peer_init_msg_SIZE * ctx->n + sizeof(TOPRF_Update_Message)) return TOPRF_Update_Err_OSize;

  crypto_generichash_state sid_state;
  crypto_generichash_init(&sid_state, NULL, 0, dkg_sessionid_SIZE);
  crypto_generichash_update(&sid_state, ctx->sessionid, dkg_sessionid_SIZE);

  const uint8_t *ptr = input;
  uint8_t *wptr = ((TOPRF_Update_Message *) output)->data;
  for(uint8_t i=0;i<ctx->n;i++,ptr+=toprfupdate_peer_init_msg_SIZE) {
    const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) ptr;
    if(stp_recv_msg(ctx,ptr,toprfupdate_peer_init_msg_SIZE,toprfupdate_peer_init_msg,i+1,0xff)) continue;
    const uint8_t *dptr = msg->data;
    crypto_generichash_update(&sid_state, dptr, dkg_sessionid_SIZE);
    dptr+=dkg_sessionid_SIZE;
    memcpy((*ctx->kc0_commitments)[i], dptr, crypto_core_ristretto255_BYTES);

    memcpy(wptr, ptr, toprfupdate_peer_init_msg_SIZE);
    wptr+=toprfupdate_peer_init_msg_SIZE;
  }
  if(ctx->cheater_len>0) return TOPRF_Update_Err_CheatersFound;

  crypto_generichash_final(&sid_state,ctx->sessionid,sizeof ctx->sessionid);

  if(0!=toprf_send_msg(output, output_len, toprfupdate_stp_bc_init_msg, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;
  update_transcript(&ctx->transcript_state, output, output_len);

  ctx->step = TOPRF_Update_STP_Route_Noise_Handshakes1;
  return TOPRF_Update_Err_OK;
}

#define toprfupdate_peer_ake1_msg_SIZE (sizeof(TOPRF_Update_Message) + noise_xk_handshake1_SIZE)
static TOPRF_Update_Err peer_step3_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] noise1 receive peers session nonces, finalize sessionid, start noise sessions\x1b[0m\n", ctx->index);
  if(input_len != toprfupdate_peer_init_msg_SIZE * ctx->n + sizeof(TOPRF_Update_Message)) return TOPRF_Update_Err_ISize;
  if(output_len != toprfupdate_peer_ake1_msg_SIZE * ctx->n) return TOPRF_Update_Err_OSize;

  const TOPRF_Update_Message* msg2 = (const TOPRF_Update_Message*) input;
  int ret = toprf_recv_msg(input, input_len, toprfupdate_stp_bc_init_msg, 0, 0xff, (*ctx->sig_pks)[0], msg2->sessionid, ctx->ts_epsilon, &ctx->stp_last_ts);
  if(0!=ret) return TOPRF_Update_Err_BroadcastEnv+ret;

  update_transcript(&ctx->transcript_state, input, input_len);

  // create noise device
  uint8_t iname[15];
  snprintf((char*) iname, sizeof iname, "toprf peer %02x", ctx->index);
  uint8_t dummy[32]={0}; // the following function needs a deserialization key, which we never use.

  ctx->dev = Noise_XK_device_create(13, (uint8_t*) "toprf p2p v0.1", iname, dummy, ctx->noise_sk);

  crypto_generichash_state sid_state;
  crypto_generichash_init(&sid_state, NULL, 0, dkg_sessionid_SIZE);
  crypto_generichash_update(&sid_state, ctx->sessionid, dkg_sessionid_SIZE);

  const uint8_t *ptr = msg2->data;
  for(uint8_t i=0;i<ctx->n;i++, ptr+=toprfupdate_peer_init_msg_SIZE) {
    const TOPRF_Update_Message* msg1 = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprfupdate_peer_init_msg_SIZE,toprfupdate_peer_init_msg,i+1,0xff)) continue;
    const uint8_t *dptr = msg1->data;
    // extract peer sig and noise pk
    crypto_generichash_update(&sid_state, dptr, dkg_sessionid_SIZE);
    dptr+=dkg_sessionid_SIZE;
    if(memcmp(dptr, (*ctx->kc0_commitments)[i], crypto_core_ristretto255_BYTES)!=0) {
      return TOPRF_Update_Err_CommmitmentsMismatch;
    }
  }

  if(ctx->cheater_len>0) return TOPRF_Update_Err_CheatersFound;

  crypto_generichash_final(&sid_state,ctx->sessionid,sizeof ctx->sessionid);
  if(memcmp(ctx->sessionid, msg2->sessionid, dkg_sessionid_SIZE)!=0) {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "invalid sessionid generated\n");
    return TOPRF_Update_Err_InvSessionID;
  }

  uint8_t *wptr = output;
  for(uint8_t i=0;i<ctx->n;i++, wptr+=toprfupdate_peer_ake1_msg_SIZE) {
    TOPRF_Update_Message *msg3 = (TOPRF_Update_Message *) wptr;
    uint8_t rname[15];
    snprintf((char*) rname, sizeof rname, "toprf peer %02x", i+1);
    if(0!=dkg_init_noise_handshake(ctx->index, ctx->dev, (*ctx->peer_noise_pks)[i], rname, &(*ctx->noise_outs)[i], msg3->data)) return TOPRF_Update_Err_Noise;
    if(0!=toprf_send_msg(wptr, toprfupdate_peer_ake1_msg_SIZE, toprfupdate_peer_ake1_msg, ctx->index, i+1, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;
  }

  ctx->step = TOPRF_Update_Peer_Noise_Handshake;

  return TOPRF_Update_Err_OK;
}


static TOPRF_Update_Err stp_step4_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  return stp_route(ctx, input, input_len, output, output_len,
                   "noise2 route p2p noise handshakes to peers",
                   ctx->n, ctx->n, toprfupdate_peer_ake1_msg, toprfupdate_peer_ake1_msg_SIZE, TOPRF_Update_STP_Route_Noise_Handshakes2);
}

#define toprfupdate_peer_ake2_msg_SIZE (sizeof(TOPRF_Update_Message) + noise_xk_handshake2_SIZE)
static TOPRF_Update_Err peer_step5_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] noise3 receive session requests\x1b[0m\n", ctx->index);
  if(input_len != toprfupdate_peer_ake1_msg_SIZE * ctx->n) return TOPRF_Update_Err_ISize;
  if(output_len != toprfupdate_peer_ake2_msg_SIZE * ctx->n) return TOPRF_Update_Err_OSize;

  const uint8_t *ptr = input;
  uint8_t *wptr = output;
  for(uint8_t i=0;i<ctx->n;i++,ptr+=toprfupdate_peer_ake1_msg_SIZE,wptr+=toprfupdate_peer_ake2_msg_SIZE) {
    TOPRF_Update_Message* msg3 = (TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprfupdate_peer_ake1_msg_SIZE,toprfupdate_peer_ake1_msg,i+1,ctx->index)) continue;

    // respond to noise handshake request
    TOPRF_Update_Message *msg4 = (TOPRF_Update_Message *) wptr;
    uint8_t rname[15];
    snprintf((char*) rname, sizeof rname, "toprf peer %02x", i+1);
    if(0!=dkg_respond_noise_handshake(ctx->index, ctx->dev, rname, &(*ctx->noise_ins)[i], msg3->data, msg4->data)) return TOPRF_Update_Err_Noise;
    if(0!=toprf_send_msg(wptr, toprfupdate_peer_ake2_msg_SIZE, toprfupdate_peer_ake2_msg, ctx->index, i+1, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;
  }
  if(ctx->cheater_len>0) return TOPRF_Update_Err_CheatersFound;

  ctx->step=TOPRF_Update_Peer_Finish_Noise_Handshake;
  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err stp_step6_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  return stp_route(ctx, input, input_len, output, output_len,
                   "noise4 route p2p noise handshakes to peers",
                   ctx->n, ctx->n, toprfupdate_peer_ake2_msg, toprfupdate_peer_ake2_msg_SIZE, TOPRF_Update_STP_Broadcast_DKG_Hash_Commitments);
}

static void hash_commitments(const TOPRF_Update_PeerState *ctx,
                             const uint8_t c_len,
                             const uint8_t commitments[c_len][crypto_core_ristretto255_BYTES],
                             uint8_t **wptr) {
  crypto_generichash(*wptr, toprf_update_commitment_HASHBYTES, (uint8_t*) commitments, crypto_core_ristretto255_BYTES*c_len, NULL, 0);
  if(liboprf_log_file!=NULL) {
    dump(*wptr, toprf_update_commitment_HASHBYTES, "[%d] commitment hash", ctx->index);
    dump((uint8_t*) commitments, crypto_core_ristretto255_BYTES*c_len, "[%d] committed", ctx->index);
  }
  *wptr+=toprf_update_commitment_HASHBYTES;
}

static TOPRF_Update_Err dkg1(TOPRF_Update_PeerState *ctx, const uint8_t n,
                             const char *type,
                             const uint8_t secret[crypto_core_ristretto255_SCALARBYTES],
                             TOPRF_Share shares[n][2],
                             uint8_t commitments[n][crypto_core_ristretto255_BYTES],
                             uint8_t **wptr) {
  // start DKG
  if(dkg_vss_share(ctx->n, ctx->t, secret, commitments, shares, NULL)) {
    return TOPRF_Update_Err_VSSShare;
  }

#ifdef UNITTEST_CORRUPT
  corrupt_vsps_t1(ctx,1, ctx->p_shares, ctx->p_commitments);
  //corrupt_commitment(ctx,2,ctx->p_commitments);
  //corrupt_commitment(ctx,3,ctx->p_commitments);
  //corrupt_wrongshare_correct_commitment(ctx,4,2,ctx->p_shares,ctx->p_commitments);
  //corrupt_share(ctx,5,3,1,ctx->p_shares);
  //corrupt_share(ctx,5,2,0,ctx->p_shares);
#endif // UNITTEST_CORRUPT

  if(liboprf_log_file!=NULL) {
    dump((const uint8_t*) commitments, crypto_core_ristretto255_BYTES*ctx->n, "[%d] dealer %s commitments", ctx->index, type);
  }
  hash_commitments(ctx,ctx->n,commitments,wptr);

  return TOPRF_Update_Err_OK;
}

static void derive_key(const Noise_XK_session_t *noise_session,
                       const uint8_t i,
                       const char *type,
                       uint8_t key[crypto_auth_KEYBYTES]) {
  const uint8_t *mk = Noise_XK_session_get_key(noise_session);
  char kdf_context[64];
  size_t context_len = (size_t) snprintf(kdf_context, sizeof(kdf_context), "key for encryption of %s share for %d", type, i);
  crypto_kdf_hkdf_sha256_expand(key, crypto_auth_KEYBYTES, kdf_context, context_len, mk);
}

static void encrypt_shares(const TOPRF_Update_PeerState *ctx,
                           const uint8_t i,
                           const char *type,
                           const TOPRF_Share share[2],
                           const uint8_t nonce_ctr,
                           uint8_t hmac[crypto_auth_hmacsha256_BYTES],
                           uint8_t ct[toprf_update_encrypted_shares_SIZE]) {

  uint8_t key[crypto_auth_KEYBYTES];
  derive_key((*ctx->noise_outs)[i],i+1,type,key);
  uint8_t nonce[crypto_stream_NONCEBYTES]={0};
  nonce[0]=nonce_ctr;

  crypto_stream_xor(ct, (const uint8_t*) share, TOPRF_Share_BYTES*2, nonce, key);
  crypto_auth(hmac, ct, toprf_update_encrypted_shares_SIZE, key);
  if(liboprf_log_file!=NULL) {
    //dump(key, sizeof key, "[%d] key for %s share of p_%d", ctx->index, type, i+1);
    //dump(ct, toprf_update_encrypted_shares_SIZE, "[%d] encrypted %s share of p_%d", ctx->index, type, i+1);
    //dump(hmac, crypto_auth_hmacsha256_BYTES, "[%d] hmac for %s share of p_%d", ctx->index, type, i+1);
  }
}

#define toprfupdate_peer_dkg1_msg_SIZE(ctx) (sizeof(TOPRF_Update_Message) + (toprf_update_commitment_HASHBYTES + ctx->n * crypto_auth_hmacsha256_BYTES))
static TOPRF_Update_Err peer_dkg1_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] noise5 finish session handshake, start core update with dkg for p\x1b[0m\n", ctx->index);
  if(input_len != toprfupdate_peer_ake2_msg_SIZE * ctx->n) return TOPRF_Update_Err_ISize;
  if(output_len != toprfupdate_peer_dkg1_msg_SIZE(ctx)) return TOPRF_Update_Err_OSize;

  const uint8_t *ptr = input;
  for(uint8_t i=0;i<ctx->n;i++, ptr+=toprfupdate_peer_ake2_msg_SIZE) {
    TOPRF_Update_Message* msg4 = (TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprfupdate_peer_ake2_msg_SIZE,toprfupdate_peer_ake2_msg,i+1,ctx->index)) continue;
    // process final step of noise handshake
    if(0!=dkg_finish_noise_handshake(ctx->index, ctx->dev, &(*ctx->noise_outs)[i], msg4->data)) return TOPRF_Update_Err_Noise;
  }
  if(ctx->cheater_len>0) return TOPRF_Update_Err_CheatersFound;

  TOPRF_Update_Message* msg5 = (TOPRF_Update_Message*) output;
  uint8_t *wptr = msg5->data;
  uint8_t *dptr = (uint8_t*) (*ctx->encrypted_shares);

  TOPRF_Update_Err ret;
  ret = dkg1(ctx, ctx->n, "p", NULL, (*ctx->p_shares), (*ctx->p_commitments), &wptr);
  if(ret != TOPRF_Update_Err_OK) return ret;

  for(uint8_t i=0;i<ctx->n;i++) {
    // we need to send an empty packet, so that the handshake completes
    // and we have a final symetric key, the key during the handshake changes, only
    // when the handshake completes does the key become static.
    // this is important, so that when there are complaints, we can disclose the key.
    uint8_t empty[1]={0}; // would love to do [0] but that is undefined c
    if(0!=dkg_noise_encrypt(empty, 0, dptr, noise_xk_handshake3_SIZE, &(*ctx->noise_outs)[i])) return TOPRF_Update_Err_NoiseEncrypt;
    dptr+=noise_xk_handshake3_SIZE;

    // we might need to disclose the encryption key for the p shares,
    // but we don't want even the STP to learn more than necessary for
    // proving the correct encryption of the shares, hence the
    // following: we extract the current noise key, hkdf() it into two
    // dedicated subkeys, encrypt the shares using a stream cipher,
    // and calculate an hmac over these with the subkeys.
    encrypt_shares(ctx,i,"p",(*ctx->p_shares)[i],0,wptr,dptr);
    dptr+=toprf_update_encrypted_shares_SIZE;
    wptr+=crypto_auth_hmacsha256_BYTES;
  }

  //broadcast dealer_commitments

  if(0!=toprf_send_msg(output, toprfupdate_peer_dkg1_msg_SIZE(ctx), toprfupdate_peer_dkg1_msg, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;

  ctx->step = TOPRF_Update_Peer_Rcv_CHashes_Send_Commitments;

  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err stp_dkg1_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  TOPRF_Update_Err ret;
  ret = stp_broadcast(ctx, input, input_len, output, output_len,
                      "dkg1 broadcast commitment hashes and share hmacs for p dkg step 1",
                      ctx->n, toprfupdate_peer_dkg1_msg_SIZE(ctx), toprfupdate_peer_dkg1_msg, TOPRF_Update_STP_Broadcast_DKG_Commitments);
  if(ret != TOPRF_Update_Err_OK) return ret;
  const uint8_t *ptr = input;
  for(unsigned i=0;i<ctx->n;i++,ptr+=toprfupdate_peer_dkg1_msg_SIZE(ctx)) {
    const DKG_Message* msg = (const DKG_Message*) ptr;
    const uint8_t *dptr=msg->data;
    memcpy((*ctx->p_commitments_hashes)[i], dptr, toprf_update_commitment_HASHBYTES);
    dptr+=toprf_update_commitment_HASHBYTES;

    for(uint8_t j=0;j<ctx->n;j++) {
      memcpy((*ctx->p_share_macs)[i*ctx->n+j], dptr, crypto_auth_hmacsha256_BYTES);
      dptr+=crypto_auth_hmacsha256_BYTES;
    }
  }
  return TOPRF_Update_Err_OK;
}

#define toprfupdate_peer_dkg2_msg_SIZE(ctx) (sizeof(TOPRF_Update_Message) + crypto_core_ristretto255_BYTES * ctx->n)
static TOPRF_Update_Err peer_dkg2_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] dkg2 receive commitment hashes, broadcast commitments\x1b[0m\n", ctx->index);
  if(input_len != sizeof(TOPRF_Update_Message) + toprfupdate_peer_dkg1_msg_SIZE(ctx) * ctx->n) return TOPRF_Update_Err_ISize;
  if(output_len != toprfupdate_peer_dkg2_msg_SIZE(ctx)) return TOPRF_Update_Err_OSize;

  // verify STP message envelope
  const uint8_t *ptr=NULL;
  int ret = unwrap_envelope(ctx,input,input_len,toprfupdate_stp_bc_dkg1_msg,&ptr);
  if(ret!=TOPRF_Update_Err_OK) return ret;

  for(uint8_t i=0;i<ctx->n;i++, ptr+=toprfupdate_peer_dkg1_msg_SIZE(ctx)) {
    const TOPRF_Update_Message* msg5 = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprfupdate_peer_dkg1_msg_SIZE(ctx),toprfupdate_peer_dkg1_msg,i+1,0xff)) continue;

    const uint8_t *dptr=msg5->data;
    // extract peer p commitment hash
    memcpy((*ctx->p_commitments_hashes)[i], dptr, toprf_update_commitment_HASHBYTES);
    dptr+=toprf_update_commitment_HASHBYTES;


    for(uint8_t j=0;j<ctx->n;j++) {
      // extract and store encrypted p share mac
      memcpy((*ctx->p_share_macs)[j*ctx->n + i], dptr, crypto_auth_hmacsha256_BYTES);
      //dump(dptr, crypto_auth_hmacsha256_BYTES, "[%d] p   share macs [%d,%d]", ctx->index, j+1, i+1);
      dptr+=crypto_auth_hmacsha256_BYTES;
    }

    if(liboprf_log_file!=NULL) {
      dump((*ctx->p_commitments_hashes)[i], toprf_update_commitment_HASHBYTES, "[%d] p   commitment hash [%d]", ctx->index, i+1);
    }
  }
  //if(ctx->cheater_len>cheaters) return TOPRF_Update_Err_CheatersFound;

  TOPRF_Update_Message* msg = (TOPRF_Update_Message*) output;
  uint8_t *wptr = msg->data;
  // we stashed our commitments temporarily in k_commitments
  memcpy(wptr, (*ctx->p_commitments), ctx->n * crypto_core_ristretto255_BYTES);
  //broadcast dealer_commitments
  if(0!=toprf_send_msg(output, toprfupdate_peer_dkg2_msg_SIZE(ctx), toprfupdate_peer_dkg2_msg, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;

  ctx->step = TOPRF_Update_Peer_Rcv_Commitments_Send_Shares;

  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err stp_vsps_check(TOPRF_Update_STPState *ctx,
                                       const char *type,
                                       const uint8_t dealers,
                                       const uint8_t clen,
                                       const uint8_t (*ctx_commitments)[][crypto_core_ristretto255_BYTES]) {
  TOPRF_Update_Err ret;
  const uint8_t (*c)[dealers][clen][crypto_core_ristretto255_BYTES] = (const uint8_t (*)[dealers][clen][crypto_core_ristretto255_BYTES]) ctx_commitments;
  // calculate preliminary final commitments
  uint8_t kcom[clen][crypto_core_ristretto255_BYTES];
  for(unsigned i=0;i<clen;i++) {
    memcpy(kcom[i], (*c)[0][i], crypto_scalarmult_ristretto255_BYTES);
    for(unsigned j=1;j<dealers;j++) {
      crypto_core_ristretto255_add(kcom[i], kcom[i], (*c)[j][i]);
    }
  }

  uint8_t fails_len=0;
  uint8_t fails[dealers];
  memset(fails,0,dealers);

  ret = ft_or_full_vsps(clen, ctx->t, dealers, 0, kcom, c,
                        "VSPS failed k during DKG, doing full VSPS check on all peers",
                        "VSPS failed k",
                        "ERROR, could not find any dealer commitments that fail the VSPS check",
                        &fails_len, fails);
  if(ret!=TOPRF_Update_Err_OK) {
    return ret;
  }

  for(unsigned i=0;i<fails_len;i++) {
    if(stp_add_cheater(ctx,1,fails[i],0) == NULL) {
      return TOPRF_Update_Err_CheatersFull;
    }
  }

  if(ctx->n - fails_len < 2) {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[!] less than 2 honest %s dealers: %d \n"NORMAL, type, ctx->n - fails_len);
    if(stp_add_cheater(ctx,2,0,0) == NULL) {
      return TOPRF_Update_Err_CheatersFull;
    }
  }
  if(fails_len >= ctx->t) {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[!] more than t %s cheaters (t=%d, cheaters=%d)\n"NORMAL, type, ctx->t, fails_len);
    if(stp_add_cheater(ctx,3,fails_len,0) == NULL) {
      return TOPRF_Update_Err_CheatersFull;
    }
  }
  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err stp_check_chash(TOPRF_Update_STPState *ctx,
                                        const uint8_t i,
                                        const char *type,
                                        const uint8_t dealers,
                                        const uint8_t clen,
                                        const uint8_t *commitments,
                                        const uint8_t (*commitments_hashes)[][toprf_update_commitment_HASHBYTES],
                                        uint8_t (*ctx_commitments)[][crypto_core_ristretto255_BYTES]) {
  uint8_t (*c)[dealers][clen][crypto_core_ristretto255_BYTES] = (uint8_t (*)[dealers][clen][crypto_core_ristretto255_BYTES]) ctx_commitments;
  uint8_t chash[toprf_update_commitment_HASHBYTES];
  crypto_generichash(chash, toprf_update_commitment_HASHBYTES, commitments, crypto_core_ristretto255_BYTES*clen, NULL, 0);
  if(memcmp(chash, (*commitments_hashes)[i], toprf_update_commitment_HASHBYTES)!=0) {
    dump((*commitments_hashes)[i], toprf_update_commitment_HASHBYTES, "[%d] commitment hash", i+1);
    dump(commitments, crypto_core_ristretto255_BYTES*clen, "[%d] committed", i+1);
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[!] failed to verify hash for %s commitments of dealer %d\n"NORMAL, type, i+1);
    if(stp_add_cheater(ctx, 4, i+1, 0) == NULL) {
      return TOPRF_Update_Err_CheatersFull;
    }
  }
  memcpy((*c)[i], commitments, crypto_core_ristretto255_BYTES * clen);

  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err stp_dkg2_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  TOPRF_Update_Err ret = stp_broadcast(ctx, input, input_len, output, output_len,
                                       "dkg3 broadcast commitments dkg step 1",
                                       ctx->n, toprfupdate_peer_dkg2_msg_SIZE(ctx), toprfupdate_peer_dkg2_msg, TOPRF_Update_STP_Route_Encrypted_Shares);
  if(ret!=TOPRF_Update_Err_OK) return ret;
  const uint8_t *ptr = input;

  // fixup step, that has already been advanced in the call to stp_broadcast above.
  uint8_t step = ctx->step;
  ctx->step = TOPRF_Update_STP_Broadcast_DKG_Commitments;

  for(uint8_t i=0;i<ctx->n;i++,ptr+=toprfupdate_peer_dkg2_msg_SIZE(ctx)) {
    const DKG_Message* msg = (const DKG_Message*) ptr;
    const uint8_t *dptr = msg->data;
    ret = stp_check_chash(ctx,i,"p",ctx->n, ctx->n, dptr,ctx->p_commitments_hashes,ctx->p_commitments);
    if(TOPRF_Update_Err_OK!=ret) {
      ctx->step=step;
      return ret;
    }
  }
  ret = stp_vsps_check(ctx, "p", ctx->n, ctx->n, ctx->p_commitments);

  ctx->step=step;
  return ret;
}

#define toprfupdate_peer_dkg3_msg_SIZE (sizeof(TOPRF_Update_Message) /* header */                      \
                                        + noise_xk_handshake3_SIZE /* 4th&final noise handshake */     \
                                        + toprf_update_encrypted_shares_SIZE                           )
static TOPRF_Update_Err peer_dkg3_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] dkg4 receive commitments & distribute encrypted shares\x1b[0m\n", ctx->index);
  if(input_len != sizeof(TOPRF_Update_Message) + toprfupdate_peer_dkg2_msg_SIZE(ctx) * ctx->n) return TOPRF_Update_Err_ISize;
  if(output_len != ctx->n * toprfupdate_peer_dkg3_msg_SIZE) return TOPRF_Update_Err_OSize;

  // verify STP message envelope
  const uint8_t *ptr=NULL;
  int ret = unwrap_envelope(ctx,input,input_len,toprfupdate_stp_bc_dkg2_msg,&ptr);
  if(ret!=TOPRF_Update_Err_OK) return ret;

  for(uint8_t i=0;i<ctx->n;i++, ptr+=toprfupdate_peer_dkg2_msg_SIZE(ctx)) {
    const TOPRF_Update_Message* msg5 = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprfupdate_peer_dkg2_msg_SIZE(ctx),toprfupdate_peer_dkg2_msg,i+1,0xff)) continue;

    // extract peer commitments
    const uint8_t *dptr = msg5->data;
    memcpy((*ctx->p_commitments)[i*ctx->n], dptr, crypto_core_ristretto255_BYTES * ctx->n);
    if(liboprf_log_file!=NULL) {
      dump((*ctx->p_commitments)[i*ctx->n], crypto_core_ristretto255_BYTES*ctx->n, "[%d] p commitments [%d]", ctx->index, i+1);
    }

    // verify against commitment hashes
    uint8_t chash[toprf_update_commitment_HASHBYTES];
    crypto_generichash(chash, toprf_update_commitment_HASHBYTES, (*ctx->p_commitments)[i*ctx->n], crypto_core_ristretto255_BYTES*ctx->n, NULL, 0);
    if(memcmp(chash, (*ctx->p_commitments_hashes)[i], toprf_update_commitment_HASHBYTES)!=0) {
      if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[%d] failed to verify hash for p commitments of dealer %d\n"NORMAL, ctx->index, i+1);
      if(peer_add_cheater(ctx, 2, i+1, 0) == NULL) return TOPRF_Update_Err_CheatersFull;
    }
  }
  // yes we abort here if the hash commitment fails.
  if(ctx->cheater_len>0) return TOPRF_Update_Err_CheatersFound;
  // we could check VSPS here, but that would complicate msg size
  // calculation taking into account demoted dealers, so we do it
  // after the shares have been dealt.

  uint8_t *wptr = output;
  for(uint8_t i=0;i<ctx->n;i++, wptr+=toprfupdate_peer_dkg3_msg_SIZE) {
    TOPRF_Update_Message *msg7 = (TOPRF_Update_Message *) wptr;
    memcpy(msg7->data, (*ctx->encrypted_shares)[i], noise_xk_handshake3_SIZE + toprf_update_encrypted_shares_SIZE);

    if(0!=toprf_send_msg(wptr, toprfupdate_peer_dkg3_msg_SIZE, toprfupdate_peer_dkg3_msg, ctx->index, i+1, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;
  }

  ctx->step = TOPRF_Update_Peer_Verify_Commitments;

  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err stp_dkg3_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  return stp_route(ctx, input, input_len, output, output_len,
                   "dkg4 route shares to peers",
                   ctx->n, ctx->n, toprfupdate_peer_dkg3_msg, toprfupdate_peer_dkg3_msg_SIZE, TOPRF_Update_STP_Broadcast_Complaints);
}


static TOPRF_Update_Err decrypt_shares(const TOPRF_Update_PeerState *ctx,
                                       const uint8_t i,
                                       const char *type,
                                       const uint8_t hmac[crypto_auth_hmacsha256_BYTES],
                                       const uint8_t ct[toprf_update_encrypted_shares_SIZE],
                                       const uint8_t nonce_ctr,
                                       TOPRF_Share share[2]) {
  uint8_t key[crypto_auth_KEYBYTES];
  derive_key((*ctx->noise_ins)[i],ctx->index,type,key);
  uint8_t nonce[crypto_stream_NONCEBYTES]={0};
  nonce[0]=nonce_ctr;
#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
  if(0!=crypto_auth_verify(hmac, ct, toprf_update_encrypted_shares_SIZE, key)) {
    //dump(key, sizeof key, "[%d] key for %s share of p_%d", ctx->index, type, i+1);
    dump(ct, toprf_update_encrypted_shares_SIZE, "[%d] encrypted %s share of p_%d", ctx->index, type, i+1);
    return TOPRF_Update_Err_HMac;
  }
#endif
  crypto_stream_xor((uint8_t*) share, ct, TOPRF_Share_BYTES*2, nonce, key);

  return TOPRF_Update_Err_OK;
}

static void verify_commitments(const TOPRF_Update_PeerState *ctx,
                               const char *type,
                               const uint8_t dealers,
                               const uint8_t clen,
                               const uint8_t cidx,
                               const uint8_t commitments[][crypto_core_ristretto255_BYTES],
                               const TOPRF_Share (*shares)[][2],
                               uint8_t *fails_len,
                               uint8_t *fails) {
  *fails_len=0;
  memset(fails, 0, dealers);

  const uint8_t (*c)[clen][crypto_core_ristretto255_BYTES] = (const uint8_t (*)[clen][crypto_core_ristretto255_BYTES]) commitments;
  // verify that the shares match the commitment
  for(uint8_t i=0;i<dealers;i++) {
    if(0!=dkg_vss_verify_commitment(c[i][cidx],(*shares)[i])) {
      if(liboprf_log_file!=NULL) fprintf(liboprf_log_file,"\x1b[0;31m[%d] failed to verify %s commitments from %d!\x1b[0m\n", ctx->index, type, i+1);
      fails[(*fails_len)++]=i+1;
    }
  }

  if(liboprf_log_file!=NULL) {
    if(*fails_len>0) {
      fprintf(liboprf_log_file, RED"[%d] %s commitment fails#: %d -> ", ctx->index, type, *fails_len);
      for(unsigned i=0;i<*fails_len;i++) fprintf(liboprf_log_file, "%s%d", (i>0)?", ":"", fails[i]);
      fprintf(liboprf_log_file, NORMAL"\n");
    } else {
      fprintf(liboprf_log_file, GREEN"[%d] no %s commitment fails\n"NORMAL, ctx->index, type);
    }
  }
}

#define toprfupdate_peer_verify_shares_msg_SIZE(ctx) (sizeof(TOPRF_Update_Message) + (size_t)(ctx->n + 1))
static TOPRF_Update_Err peer_verify_shares_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] dkg-verify1 DKG step 2 - receive shares, verify commitments\x1b[0m\n", ctx->index);
  if(input_len != toprfupdate_peer_dkg3_msg_SIZE * ctx->n) return TOPRF_Update_Err_ISize;
  if(output_len != toprfupdate_peer_verify_shares_msg_SIZE(ctx)) return TOPRF_Update_Err_OSize;

  const uint8_t *ptr = input;
  for(uint8_t i=0;i<ctx->n;i++) {
    if(peer_recv_msg(ctx,ptr,toprfupdate_peer_dkg3_msg_SIZE,toprfupdate_peer_dkg3_msg,i+1,ctx->index)) continue;

    const uint8_t *dptr = ((const TOPRF_Update_Message*) ptr)->data;
    // decrypt final empty handshake packet
    if(0!=dkg_noise_decrypt(dptr, noise_xk_handshake3_SIZE, NULL, 0, &(*ctx->noise_ins)[i])) return TOPRF_Update_Err_NoiseDecrypt;
    dptr += noise_xk_handshake3_SIZE;

    TOPRF_Update_Err ret;
    ret = decrypt_shares(ctx, i, "p", (*ctx->p_share_macs)[(ctx->index-1)*ctx->n + i], dptr, 0, (*ctx->p_shares)[i]);
    if(TOPRF_Update_Err_OK!=ret) {
      dump((*ctx->p_share_macs)[(ctx->index-1)*ctx->n + i], crypto_auth_hmacsha256_BYTES, "[%d] p hmac_%d", ctx->index, i+1);
      return ret;
    }

    ptr+=toprfupdate_peer_dkg3_msg_SIZE;
  }
  //if(ctx->cheater_len>cheaters) return TOPRF_Update_Err_CheatersFound;

  TOPRF_Update_Message* msg = (TOPRF_Update_Message*) output;
  uint8_t *fails_len = msg->data;
  uint8_t *fails = fails_len+1;
  verify_commitments(ctx, "p", ctx->n, ctx->n, ctx->index-1, (*ctx->p_commitments), ctx->p_shares, fails_len, fails);
#ifdef UNITTEST_CORRUPT
  corrupt_false_accuse(ctx, 2, 3, fails_len, fails);
#endif //UNITTEST_CORRUPT

  if(0!=toprf_send_msg(output, toprfupdate_peer_verify_shares_msg_SIZE(ctx), toprfupdate_peer_verify_shares_msg, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;

  ctx->step = TOPRF_Update_Peer_Handle_DKG_Complaints;

  return TOPRF_Update_Err_OK;
}

#define toprfupdate_stp_bc_verify_shares_msg_SIZE(ctx) (sizeof(TOPRF_Update_Message) + (toprfupdate_peer_verify_shares_msg_SIZE(ctx) * ctx->n))
static TOPRF_Update_Err stp_verify_shares_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  return stp_complaint_handler(ctx, input, input_len, output, output_len,
                               "dkg-verify2 broadcast complaints of peers",
                               ctx->n, toprfupdate_peer_verify_shares_msg_SIZE(ctx),
                               toprfupdate_peer_verify_shares_msg,
                               ctx->n,
                               TOPRF_Update_STP_Broadcast_DKG_Transcripts,
                               TOPRF_Update_STP_Broadcast_DKG_Defenses);
}

static TOPRF_Update_Err peer_dkg_fork(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len) {
  return peer_complaint_handler(ctx, input, input_len,
                                "dkg-verify3 receive complaints broadcast",
                                toprfupdate_peer_verify_shares_msg_SIZE(ctx),
                                toprfupdate_peer_verify_shares_msg,
                                ctx->n,
                                TOPRF_Update_Peer_Finish_DKG,
                                TOPRF_Update_Peer_Defend_DKG_Accusations);
}

static TOPRF_Update_Err peer_defend(TOPRF_Update_PeerState *ctx, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] dkg-defend1 disclose share encryption key\x1b[0m\n", ctx->index);
  if(output_len != toprf_update_peer_output_size(ctx)) return TOPRF_Update_Err_OSize;
  if(output_len == 0) {
    if(liboprf_log_file!=NULL) {
      fprintf(liboprf_log_file,"[%d] nothing to defend against, no message to send\n", ctx->index);
    }
    ctx->step = TOPRF_Update_Peer_Check_Shares;
    return 0;
  }

  // send out all shares that belong to peers that complained.
  TOPRF_Update_Message* msg = (TOPRF_Update_Message*) output;
  uint8_t *wptr = msg->data;
  for(int i=0;i<ctx->my_p_complaints_len;i++) {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;36m[%d] defending against p complaint from %d\x1b[0m\n", ctx->index, ctx->my_p_complaints[i]);

    *wptr++ = ctx->my_p_complaints[i];
    // reveal key for noise wrapped share sent previously
    derive_key((*ctx->noise_outs)[ctx->my_p_complaints[i]-1],ctx->my_p_complaints[i],"p",wptr);
    wptr+=dkg_noise_key_SIZE;

    memcpy(wptr, (*ctx->encrypted_shares)[ctx->my_p_complaints[i]-1] + noise_xk_handshake3_SIZE, toprf_update_encrypted_shares_SIZE);
    wptr+=toprf_update_encrypted_shares_SIZE;
  }

  if(0!=toprf_send_msg(output, output_len, toprfupdate_peer_share_key_msg, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;

  ctx->step = TOPRF_Update_Peer_Check_Shares;
  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err stp_check_defenses(TOPRF_Update_STPState *ctx,
                                           const uint8_t dealers,
                                           const uint8_t clen,
                                           const uint8_t coffset,
                                           const unsigned int ctr,
                                           const unsigned i,
                                           const uint8_t nonce_ctr,
                                           const uint8_t (*share_macs)[][crypto_auth_hmacsha256_BYTES],
                                           const uint8_t commitments[][crypto_core_ristretto255_BYTES],
                                           uint16_t *complaints_len,
                                           uint16_t *complaints,
                                           const uint8_t **dptr) {
  if(ctr>=ctx->n) return TOPRF_Update_Err_OOB;
  const uint8_t (*c)[clen][crypto_core_ristretto255_BYTES] = (const uint8_t (*)[clen][crypto_core_ristretto255_BYTES]) commitments;
  for(unsigned j=0;j<ctr;j++) {
    const uint8_t accused=(uint8_t) i+1U;
    const uint8_t accuser=(*dptr)[0];
    if(accuser<1 || accuser>ctx->n) return TOPRF_Update_Err_OOB;
    const uint8_t *key=(*dptr)+1;
    const uint8_t *shares=key+dkg_noise_key_SIZE;
    *dptr += 1U + dkg_noise_key_SIZE + toprf_update_encrypted_shares_SIZE;
    if(liboprf_log_file!=NULL) {
      fprintf(liboprf_log_file,"[!] accused: %d, by %d\n", accused, accuser);
      dump(key,dkg_noise_key_SIZE,"key");
      dump(shares,toprf_update_encrypted_shares_SIZE,"encrypted shares");
    }

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    if(0!=crypto_auth_verify((*share_macs)[(accused-1)*ctx->n+(accuser-1)], shares, toprf_update_encrypted_shares_SIZE, key)) {
      if(liboprf_log_file!=NULL) fprintf(liboprf_log_file,RED"[!] invalid HMAC on shares of accused: %d, by %d\n"NORMAL, accused, accuser);
      if(stp_add_cheater(ctx, 1, accused, accuser) == NULL) return TOPRF_Update_Err_CheatersFull;
      complaints[(*complaints_len)++]=accuser << 8 | accused;
      continue;
    }
#endif
    TOPRF_Share share[2];
    uint8_t nonce[crypto_stream_NONCEBYTES]={0};
    nonce[0]=nonce_ctr;
    crypto_stream_xor((uint8_t*) share, shares, TOPRF_Share_BYTES*2, nonce, key);
    if(share[0].index != accuser) {
      // invalid share index
      TOPRF_Update_Cheater* cheater = stp_add_cheater(ctx, 3, accused, accuser);
      if(cheater == NULL) return TOPRF_Update_Err_CheatersFull;
      cheater->invalid_index = share[0].index;
      complaints[(*complaints_len)++]=accuser << 8 | accused;
      continue;
    }
    if(0!=dkg_vss_verify_commitment(c[accused-1][accuser-coffset],share)) {
      if(liboprf_log_file!=NULL) fprintf(liboprf_log_file,"\x1b[0;31m[!] failed to verify commitment of accused %d by accuser %d!\x1b[0m\n", accused, accuser);
      TOPRF_Update_Cheater* cheater = stp_add_cheater(ctx, 4, accused, accuser);
      if(cheater == NULL) return TOPRF_Update_Err_CheatersFull;
      cheater->invalid_index = share[0].index;
      complaints[(*complaints_len)++]=accuser << 8 | accused;
      continue;
    } else {
      if(liboprf_log_file!=NULL) {
        fprintf(liboprf_log_file,GREEN"[!] succeeded to verify commitment of accused %d by accuser %d!\x1b[0m\n", accused, accuser);
        dump((uint8_t*) share, sizeof share, "share");
        dump(c[accused-1][accuser-coffset], crypto_core_ristretto255_BYTES, "commitment");
      }
      if(stp_add_cheater(ctx, 5, accuser, accused) == NULL) return TOPRF_Update_Err_CheatersFull;
    }
  }
  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err stp_broadcast_defenses(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[!] dkg-defend2 broadcast defenses\x1b[0m\n");
  if(input_len != toprf_update_stp_input_size(ctx)) return TOPRF_Update_Err_ISize;
  if(output_len != toprf_update_stp_output_size(ctx)) return TOPRF_Update_Err_OSize;

  unsigned int ctr1[ctx->n];
  memset(ctr1,0,sizeof(ctr1));
  for(int i=0;i<ctx->p_complaints_len;i++) {
    const uint8_t peer = (uint8_t) ((ctx->p_complaints[i] & 0xff)-1U);
    if(peer>=ctx->n) return TOPRF_Update_Err_OOB;
    ctr1[peer]++;
  }

  const uint8_t *ptr = input;
  uint8_t *wptr = ((TOPRF_Update_Message *) output)->data;
  size_t msg_size;
  for(uint8_t i=0;i<ctx->n;i++,ptr += msg_size) {
    if(ctr1[i]==0) {
      msg_size = 0;
      continue; // no complaints against this peer
    }
    msg_size = sizeof(TOPRF_Update_Message) \
             + (1+dkg_noise_key_SIZE+toprf_update_encrypted_shares_SIZE) * ctr1[i];
    if(stp_recv_msg(ctx,ptr,msg_size,toprfupdate_peer_share_key_msg,i+1,0xff)) continue;

    const TOPRF_Update_Message *msg = (const TOPRF_Update_Message *) ptr;
    const uint8_t *dptr = msg->data;

    TOPRF_Update_Err ret;
    ret = stp_check_defenses(ctx, ctx->n, ctx->n, 1, ctr1[i], i, 0, ctx->p_share_macs, *ctx->p_commitments, &ctx->p_complaints_len, ctx->p_complaints, &dptr);
    if(TOPRF_Update_Err_OK != ret) {
      return ret;
    }

    memcpy(wptr, ptr, msg_size);
    wptr+=msg_size;
  }
  //if(ctx->cheater_len>cheaters) return TOPRF_Update_Err_CheatersFound;

  if(0!=toprf_send_msg(output, output_len, toprfupdate_stp_bc_key_msg, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;

  // add broadcast msg to transcript
  update_transcript(&ctx->transcript_state, output, output_len);

  ctx->step = TOPRF_Update_STP_Broadcast_DKG_Transcripts;

  return TOPRF_Update_Err_OK;
}

#define toprfupdate_peer_bc_transcript_msg_SIZE (sizeof(TOPRF_Update_Message) + crypto_generichash_BYTES + crypto_core_ristretto255_BYTES*2)
static TOPRF_Update_Err peer_verify_vsps(TOPRF_Update_PeerState *ctx, uint8_t *output, const size_t output_len);

static TOPRF_Update_Err check_defenses(TOPRF_Update_PeerState *ctx,
                                       const uint8_t dealers,
                                       const uint8_t clen,
                                       const uint8_t coffset,
                                       const unsigned int ctr,
                                       const uint8_t i,
                                       const uint8_t nonce_ctr,
                                       const uint8_t (*share_macs)[][crypto_auth_hmacsha256_BYTES],
                                       const uint8_t commitments[][crypto_core_ristretto255_BYTES],
                                       uint16_t *complaints_len,
                                       uint16_t *complaints,
                                       const uint8_t **dptr) {
  if(ctr>=ctx->n) return TOPRF_Update_Err_OOB;
  const uint8_t (*c)[clen][crypto_core_ristretto255_BYTES] = (const uint8_t (*)[clen][crypto_core_ristretto255_BYTES]) commitments;
  for(unsigned j=0;j<ctr;j++) {
    const uint8_t accused=i+1;
    const uint8_t accuser=(*dptr)[0];
    if(accuser<1 || accuser>ctx->n) return TOPRF_Update_Err_OOB;
    const uint8_t *key=(*dptr)+1;
    const uint8_t *shares=key+dkg_noise_key_SIZE;
    *dptr += 1U + dkg_noise_key_SIZE + toprf_update_encrypted_shares_SIZE;
    if(liboprf_log_file!=NULL) {
      fprintf(liboprf_log_file,"[%d] accused: %d, by %d\n", ctx->index, accused, accuser);
      dump(key,dkg_noise_key_SIZE,"key");
      dump(shares,toprf_update_encrypted_shares_SIZE,"encrypted shares");
    }

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    if(0!=crypto_auth_verify((*share_macs)[(accuser-1)*ctx->n+(accused-1)], shares, toprf_update_encrypted_shares_SIZE, key)) {
      if(liboprf_log_file!=NULL) fprintf(liboprf_log_file,RED"[%d] invalid HMAC on shares of accused: %d, by %d\n"NORMAL, ctx->index, accused, accuser);
      if(peer_add_cheater(ctx, 1, accused, accuser) == NULL) return TOPRF_Update_Err_CheatersFull;
      complaints[(*complaints_len)++]=accuser << 8 | accused;
      continue;
    }
#endif
    TOPRF_Share share[2];
    uint8_t nonce[crypto_stream_NONCEBYTES]={0};
    nonce[0]=nonce_ctr;
    crypto_stream_xor((uint8_t*) share, shares, TOPRF_Share_BYTES*2, nonce, key);
    if(share[0].index != accuser) {
      // invalid share index
      TOPRF_Update_Cheater* cheater = peer_add_cheater(ctx, 3, accused, accuser);
      if(cheater == NULL) return TOPRF_Update_Err_CheatersFull;
      cheater->invalid_index = share[0].index;
      complaints[(*complaints_len)++]=accuser << 8 | accused;
      continue;
    }
    if(0!=dkg_vss_verify_commitment(c[accused-1][accuser-coffset],share)) {
      if(liboprf_log_file!=NULL) {
        fprintf(liboprf_log_file,"\x1b[0;31m[%d] failed to verify commitment of accused %d by accuser %d!\x1b[0m\n", ctx->index, accused, accuser);
        dump((uint8_t*) share, sizeof share, "share");
        dump(c[accused-1][accuser-1], crypto_core_ristretto255_BYTES, "commitment");
      }
      TOPRF_Update_Cheater* cheater = peer_add_cheater(ctx, 4, accused, accuser);
      if(cheater == NULL) return TOPRF_Update_Err_CheatersFull;
      cheater->invalid_index = share[0].index;
      complaints[(*complaints_len)++]=accuser << 8 | accused;
      continue;
    } else {
      if(liboprf_log_file!=NULL) fprintf(liboprf_log_file,GREEN"[%d] succeeded to verify commitment of accused %d by accuser %d!\x1b[0m\n", ctx->index, accused, accuser);
      if(peer_add_cheater(ctx, 5, accuser, accused) == NULL) return TOPRF_Update_Err_CheatersFull;
      //ctx->share_complaints[ctx->share_complaints_len++]=accused;
    }
  }
  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err aggregate_complaints(const uint8_t n, unsigned *ctr, uint16_t *complaints_len, uint16_t *complaints) {
  memset(ctr,0,n*sizeof(unsigned));
  for(int i=0;i<*complaints_len;i++) {
    const uint8_t peer = (uint8_t) (complaints[i] & 0xff)-1;
    if(peer>=n) return TOPRF_Update_Err_OOB;
    ctr[peer]++;
    complaints[i]=0;
  }
  *complaints_len=0;

  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err peer_check_shares(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] dkg-defend3 verify disclosed shares\x1b[0m\n", ctx->index);
  if(input_len != toprf_update_peer_input_size(ctx)) return TOPRF_Update_Err_ISize;
  if(output_len != toprfupdate_peer_bc_transcript_msg_SIZE) return TOPRF_Update_Err_OSize;

  // verify STP message envelope
  const uint8_t *ptr=NULL;
  TOPRF_Update_Err ret = unwrap_envelope(ctx,input,input_len,toprfupdate_stp_bc_key_msg,&ptr);
  if(ret!=TOPRF_Update_Err_OK) return ret;

  unsigned int ctr1[ctx->n];
  aggregate_complaints(ctx->n,ctr1,&ctx->p_complaints_len,ctx->p_complaints);

  size_t msg_size;
  for(uint8_t i=0;i<ctx->n;i++,ptr += msg_size) {
    if(ctr1[i]==0) {
      msg_size = 0;
      continue; // no complaints against this peer
    }
    msg_size = sizeof(TOPRF_Update_Message) \
               + (1+dkg_noise_key_SIZE+toprf_update_encrypted_shares_SIZE) * ctr1[i];

    if(peer_recv_msg(ctx,ptr,msg_size,toprfupdate_peer_share_key_msg,i+1,0xff)) continue;
    const TOPRF_Update_Message *msg = (const TOPRF_Update_Message *) ptr;
    const uint8_t *dptr = msg->data;

    ret = check_defenses(ctx, ctx->n, ctx->n, 1, ctr1[i], i, 0, ctx->p_share_macs, (*ctx->p_commitments), &ctx->p_complaints_len, ctx->p_complaints, &dptr);
    if(TOPRF_Update_Err_OK != ret) return ret;

  }
  return peer_verify_vsps(ctx, output, output_len);
}

static TOPRF_Update_Err finalize_dkg(TOPRF_Update_PeerState *ctx,
                                     const char *type,
                                     const uint16_t complaints_len,
                                     const uint16_t *complaints,
                                     const TOPRF_Share (*dealer_shares)[][2],
                                     uint8_t (*dealer_commitments)[][crypto_core_ristretto255_BYTES],
                                     TOPRF_Share my_share[2],
                                     uint8_t my_commitment[crypto_core_ristretto255_BYTES]) {
  // 2. Players verify the VSPS property of the sum of the shared secrets by running
  //     VSPS-Check on  𝓐_i,..,𝓐_n where
  //
  //           𝓐_j = Π 𝓐_i,j
  //                 i
  //
  // If this check fails the players run VSPS-Check on each individual
  // sharing from step 1. Any player that fails this check is disqualified.
  uint8_t (*c)[ctx->n][ctx->n][crypto_core_ristretto255_BYTES] = (uint8_t (*)[ctx->n][ctx->n][crypto_core_ristretto255_BYTES]) dealer_commitments;
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
  TOPRF_Update_Err ret = ft_or_full_vsps(ctx->n, ctx->t, ctx->n, ctx->index, kcom, c,
                                       "VSPS failed k during DKG, doing full VSPS check on all peers",
                                       "VSPS failed k",
                                       "ERROR, could not find any dealer commitments that fail the VSPS check",
                                       &fails_len, fails);
  if(ret!=TOPRF_Update_Err_OK) return ret;
  if(ctx->n - fails_len < 2) {
    if(liboprf_log_file!=NULL) {
      fprintf(liboprf_log_file, RED"[%d] less than 2 honest dealers for %s: %d \n"NORMAL, ctx->index, type, ctx->n - fails_len);
      if(peer_add_cheater(ctx, 6, 0, 0) == NULL) return TOPRF_Update_Err_CheatersFull;
    }
    return TOPRF_Update_Err_NotEnoughDealers;
  }
  if(fails_len >= ctx->t) {
    if(liboprf_log_file!=NULL) {
      fprintf(liboprf_log_file, RED"[%d] more than t cheaters for %s (t=%d, cheaters=%d)\n"NORMAL, ctx->index, type, ctx->t, fails_len);
      if(peer_add_cheater(ctx, 7, fails_len, 0) == NULL) return TOPRF_Update_Err_CheatersFull;
    }
    return TOPRF_Update_Err_TooManyCheaters;
  }

  // todo persist qual so we can consider who is a dealer for the ft-mult proto
  uint8_t qual[ctx->n+1];
  uint8_t qual_len=0;
  for(uint8_t i=0;i<ctx->n;i++) {
    unsigned j,k;
    for(j=0;j<fails_len;j++) {
      if(fails[j]==i+1) break;
    }
    for(k=0;k<complaints_len;k++) {
      if(complaints[k]==i+1) break;
    }
    if(j>=fails_len) {
      if(k>=complaints_len) qual[qual_len++]=i+1;
    } else if(peer_add_cheater(ctx, 8, ctx->index, i+1) == NULL) return TOPRF_Update_Err_CheatersFull;
  }
  qual[qual_len]=0;
  if(liboprf_log_file!=NULL) {
    fprintf(liboprf_log_file,"[%d] %s qual is: ", ctx->index, type);
    for(unsigned i=0;i<qual_len;i++) fprintf(liboprf_log_file,"%s%d", ((i==0)?"":", "), qual[i]);
    fprintf(liboprf_log_file,"\n");
  }

  my_share[0].index=ctx->index;
  my_share[1].index=ctx->index;
  // finalize dkg
  if(0!=dkg_vss_finish(ctx->n,qual,(*dealer_shares),ctx->index,my_share, my_commitment)) return TOPRF_Update_Err_DKGFinish;

  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err peer_verify_vsps(TOPRF_Update_PeerState *ctx, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] dkg-verify4 VSPS check commitments, calculate share and broadcast transcript and final commitment\x1b[0m\n", ctx->index);
  if(output_len != toprfupdate_peer_bc_transcript_msg_SIZE) return TOPRF_Update_Err_OSize;

  TOPRF_Update_Message* msg20 = (TOPRF_Update_Message*) output;
  uint8_t *wptr = msg20->data;
  crypto_generichash_state transcript_state;
  memcpy((uint8_t*) &transcript_state, (const uint8_t*) &ctx->transcript_state, sizeof transcript_state);
  crypto_generichash_final(&transcript_state, wptr, crypto_generichash_BYTES);
  memcpy(ctx->transcript, wptr, crypto_generichash_BYTES);
  wptr+=crypto_generichash_BYTES;

  TOPRF_Update_Err ret;
  ret=finalize_dkg(ctx, "p", ctx->p_complaints_len, ctx->p_complaints, ctx->p_shares, ctx->p_commitments, ctx->p_share, wptr);
  if(TOPRF_Update_Err_OK != ret) return ret;

  if(0!=toprf_send_msg(output, toprfupdate_peer_bc_transcript_msg_SIZE, toprfupdate_peer_bc_transcript_msg, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;

  ctx->step = TOPRF_Update_Peer_Confirm_Transcripts;
  return TOPRF_Update_Err_OK;
}

#define toprfupdate_stp_bc_transcript_msg_SIZE(ctx) (sizeof(TOPRF_Update_Message) + toprfupdate_peer_bc_transcript_msg_SIZE*ctx->n)
static TOPRF_Update_Err stp_bc_transcript_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[!] dkg-final1 broadcast DKG transcripts\x1b[0m\n");

  if((toprfupdate_peer_bc_transcript_msg_SIZE * ctx->n) != input_len) return TOPRF_Update_Err_ISize;
  if(output_len != toprfupdate_stp_bc_transcript_msg_SIZE(ctx)) return TOPRF_Update_Err_OSize;

  uint8_t transcript_hash[crypto_generichash_BYTES];
  crypto_generichash_state transcript_state;
  memcpy((uint8_t*) &transcript_state, (const uint8_t*) &ctx->transcript_state, sizeof transcript_state);
  crypto_generichash_final(&transcript_state, transcript_hash, crypto_generichash_BYTES);

  size_t cheaters = ctx->cheater_len;
  uint8_t *wptr = ((TOPRF_Update_Message *) output)->data;
  const uint8_t *ptr = input;
  for(uint8_t i=0;i<ctx->n;i++, ptr+=toprfupdate_peer_bc_transcript_msg_SIZE) {
    const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) ptr;
    if(stp_recv_msg(ctx,ptr,toprfupdate_peer_bc_transcript_msg_SIZE,toprfupdate_peer_bc_transcript_msg,i+1,0xff)) continue;
    const uint8_t *dptr=msg->data;

    if(sodium_memcmp(transcript_hash, dptr, sizeof(transcript_hash))!=0) {
      if(liboprf_log_file!=NULL) {
        fprintf(liboprf_log_file,"\x1b[0;31m[!] failed to verify transcript from %d!\x1b[0m\n", i);
      }
      if(stp_add_cheater(ctx, 1, i+1, 0) == NULL) return TOPRF_Update_Err_CheatersFull;
      continue;
    }
    dptr+=crypto_generichash_BYTES;
    memcpy((*ctx->p_commitments)[i], dptr, crypto_core_ristretto255_BYTES);

    memcpy(wptr, ptr, toprfupdate_peer_bc_transcript_msg_SIZE);
    wptr+=toprfupdate_peer_bc_transcript_msg_SIZE;
  }
  if(ctx->cheater_len>cheaters) return TOPRF_Update_Err_CheatersFound;

  int _debug=liboprf_debug; liboprf_debug=0;
  if(0!=toprf_mpc_vsps_check(ctx->t-1, (*ctx->p_commitments))) {
    liboprf_debug=_debug;
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[!] result of DKG final commitments fail VSPS\n"NORMAL);
    if(stp_add_cheater(ctx, 2, 0, 0) == NULL) return TOPRF_Update_Err_CheatersFull;
  }
  liboprf_debug=_debug;

  if(0!=toprf_send_msg(output, output_len, toprfupdate_stp_bc_transcript_msg, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;

  ctx->step = TOPRF_Update_STP_Route_Mult_Step1;
  return TOPRF_Update_Err_OK;
}

#define toprfupdate_peer_mult1_msg_SIZE(ctx) (sizeof(TOPRF_Update_Message) + (toprf_update_commitment_HASHBYTES + ctx->n * crypto_auth_hmacsha256_BYTES))
static TOPRF_Update_Err peer_final_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] dkg-final2 receive&check final transcript, receive & VSPS check p commitments\n"NORMAL, ctx->index);
  if(input_len != toprfupdate_stp_bc_transcript_msg_SIZE(ctx)) return TOPRF_Update_Err_ISize;
  if(output_len != isdealer(ctx->index, ctx->t) * toprfupdate_peer_mult1_msg_SIZE(ctx)) return TOPRF_Update_Err_OSize;

  // verify STP message envelope
  const uint8_t *ptr=NULL;
  int ret = unwrap_envelope(ctx,input,input_len,toprfupdate_stp_bc_transcript_msg,&ptr);
  if(ret!=TOPRF_Update_Err_OK) return ret;

  size_t cheaters = ctx->cheater_len;
  uint8_t (*pcom)[ctx->n][crypto_core_ristretto255_BYTES] = (uint8_t (*)[ctx->n][crypto_core_ristretto255_BYTES]) ctx->p_commitments;
  for(uint8_t i=0;i<ctx->n;i++, ptr+=toprfupdate_peer_bc_transcript_msg_SIZE) {
    const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) ptr;
    const uint8_t *dptr = msg->data;
    if(peer_recv_msg(ctx,ptr,toprfupdate_peer_bc_transcript_msg_SIZE,toprfupdate_peer_bc_transcript_msg,i+1,0xff)) continue;

    if(sodium_memcmp(ctx->transcript, dptr, crypto_generichash_BYTES)!=0) {
      if(liboprf_log_file!=NULL) {
        fprintf(liboprf_log_file,"\x1b[0;31m[!] failed to verify transcript from %d!\x1b[0m\n", i);
      }
      if(peer_add_cheater(ctx, 1, i+1, 0) == NULL) return TOPRF_Update_Err_CheatersFull;
      continue;
    }
    dptr+=crypto_generichash_BYTES;
    memcpy((*pcom)[i], dptr, crypto_core_ristretto255_BYTES);
  }
  if(ctx->cheater_len>cheaters) return TOPRF_Update_Err_CheatersFound;

  // in theory this should not be needed, and not fail. except for the
  // case when the dealer shares were corrupted after calculating a
  // correct commitment for them. but that should also be previously detected.
  int _debug=liboprf_debug; liboprf_debug=0;
  if(0!=toprf_mpc_vsps_check(ctx->t-1, (*pcom))) {
    liboprf_debug=_debug;
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[%d] result of p DKG commitments fail VSPS\n"NORMAL, ctx->index);
    if(peer_add_cheater(ctx, 2, 0, 0) == NULL) return TOPRF_Update_Err_CheatersFull;
  }
  liboprf_debug=_debug;

  if(ctx->cheater_len>cheaters) return TOPRF_Update_Err_CheatersFound;

  // reset complaints
  ctx->p_complaints_len = 0;
  ctx->my_p_complaints_len = 0;
  memset(ctx->p_complaints, 0, ctx->n*2);
  memset(ctx->my_p_complaints, 0, ctx->n);

  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] mult1 dealers calculate and share λ_iα_iβ_i\x1b[0m\n", ctx->index);

  // todo dealers based on cheaters and knowledge of kc0
  const uint8_t dealers = (uint8_t) ((ctx->t-1)*2 + 1);

  // precompute lambdas
  // λ_i is row 1 of inv VDM matrix
  uint8_t indexes[dealers];
  for(uint8_t i=0;i<dealers;i++) indexes[i]=i+1;
  uint8_t lambdas[dealers][dealers][crypto_core_ristretto255_SCALARBYTES];
  invertedVDMmatrix(dealers, indexes, lambdas);
  memcpy((*ctx->lambdas), lambdas[0], dealers*crypto_core_ristretto255_SCALARBYTES);
  //dump((uint8_t*) lambdas[0], dealers*crypto_core_ristretto255_SCALARBYTES, "vdm[0] ");
  //dump((uint8_t*) (*ctx->lambdas), dealers*crypto_core_ristretto255_SCALARBYTES, "lambdas");

  if(ctx->index>dealers) { // non-dealers are done
    ctx->step = TOPRF_Update_Peer_Rcv_Mult_CHashes_Send_Commitments;
    return TOPRF_Update_Err_OK;
  }
  // dealers only
  // step 1. Each player P_i shares λ_iα_iβ_i, using VSS
  if(0!=toprf_mpc_ftmult_step1(dealers, ctx->n, ctx->t, ctx->index-1,
                               ctx->kc0_share, ctx->p_share, (*ctx->lambdas),
                               // we reuse p_shares as we need to store n shares, and k0p_shares has only dealer entries
                               (*ctx->p_shares), (*ctx->k0p_commitments), ctx->k0p_tau)) {
      if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "[%d] failed toprf_mpc_ftmult_step1\n", ctx->index);
      return TOPRF_Update_Err_FTMULTStep1;
  }
#ifdef UNITTEST_CORRUPT
  corrupt_mult_vsps_t1(ctx, 1);
  corrupt_wrongshare_correct_commitment(ctx,2,4,ctx->p_shares,ctx->k0p_commitments);
  if(ctx->index==3) corrupt_ci0_good_ci(3, (*ctx->k0p_commitments));
  corrupt_commitment(ctx,4,ctx->k0p_commitments);
  corrupt_share(ctx,6,3,1,ctx->p_shares);
#endif // UNITTEST_CORRUPT

  // similar to dkg1 encrypt shares, broadcast commitment hash and hmacs.
  TOPRF_Update_Message* msg24 = (TOPRF_Update_Message*) output;
  uint8_t *wptr = msg24->data;
  // hash of k0p commitments
  hash_commitments(ctx,ctx->n+1,(*ctx->k0p_commitments),&wptr);

  for(uint8_t i=0;i<ctx->n;i++) {
    // we might need to disclose the encryption key for the p shares,
    // but we don't want even the STP to learn more than necessary for
    // proving the correct encryption of the shares, hence the
    // following: we extract the current noise key, hkdf() it into two
    // dedicated subkeys, encrypt the shares using a stream cipher,
    // and calculate an hmac over these with the subkeys.
    uint8_t *dptr = (uint8_t*) (*ctx->encrypted_shares)[i];
    encrypt_shares(ctx,i,"k0p",(*ctx->p_shares)[i],1,wptr,dptr);
    dptr+=toprf_update_encrypted_shares_SIZE;
    wptr+=crypto_auth_hmacsha256_BYTES;
  }

  if(0!=toprf_send_msg(output, toprfupdate_peer_mult1_msg_SIZE(ctx), toprfupdate_peer_mult1_msg, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;

  ctx->step = TOPRF_Update_Peer_Rcv_Mult_CHashes_Send_Commitments;
  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err stp_step25_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = (uint8_t) ((ctx->t-1)*2 + 1);
  TOPRF_Update_Err ret;
  ret = stp_broadcast(ctx, input, input_len, output, output_len,
                      "mult2 broadcast commitment hashes and share hmacs for k0p ft-mult step 1",
                      dealers, toprfupdate_peer_mult1_msg_SIZE(ctx), toprfupdate_peer_mult1_msg, TOPRF_Update_STP_Broadcast_Mult_Commitments);
  if(ret != TOPRF_Update_Err_OK) return ret;
  const uint8_t *ptr = input;
  for(unsigned i=0;i<dealers;i++,ptr+=toprfupdate_peer_mult1_msg_SIZE(ctx)) {
    const DKG_Message* msg = (const DKG_Message*) ptr;
    const uint8_t *dptr=msg->data;
    memcpy((*ctx->p_commitments_hashes)[i], dptr, toprf_update_commitment_HASHBYTES);
    dptr+=toprf_update_commitment_HASHBYTES;

    for(uint8_t j=0;j<ctx->n;j++) {
      memcpy((*ctx->p_share_macs)[i*ctx->n+j], dptr, crypto_auth_hmacsha256_BYTES);
      dptr+=crypto_auth_hmacsha256_BYTES;
    }
  }
  return TOPRF_Update_Err_OK;
}

#define toprfupdate_peer_mult_coms_msg_SIZE(ctx) (sizeof(TOPRF_Update_Message) + crypto_core_ristretto255_BYTES * (ctx->n+1U) * 2)
static TOPRF_Update_Err peer_mult2_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = (uint8_t) ((ctx->t-1)*2 + 1);
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] mult3 receive commitment hashes, broadcast commitments\x1b[0m\n", ctx->index);
  if(input_len != sizeof(TOPRF_Update_Message) + toprfupdate_peer_mult1_msg_SIZE(ctx) * dealers) return TOPRF_Update_Err_ISize;
  if(output_len != isdealer(ctx->index, ctx->t) * toprfupdate_peer_mult_coms_msg_SIZE(ctx)) return TOPRF_Update_Err_OSize;

  // verify STP message envelope
  const uint8_t *ptr=NULL;
  int ret = unwrap_envelope(ctx,input,input_len,toprfupdate_stp_bc_mult1_msg,&ptr);
  if(ret!=TOPRF_Update_Err_OK) return ret;

  for(uint8_t i=0;i<dealers;i++, ptr+=toprfupdate_peer_mult1_msg_SIZE(ctx)) {
    const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprfupdate_peer_dkg1_msg_SIZE(ctx),toprfupdate_peer_mult1_msg,i+1,0xff)) continue;

    const uint8_t *dptr=msg->data;
    // extract peer p commitment hash
    memcpy((*ctx->p_commitments_hashes)[i], dptr, toprf_update_commitment_HASHBYTES);
    dptr+=toprf_update_commitment_HASHBYTES;
    // todo rename {kc1|p}_{commitment_hashes|share_macs} into more
    // generic names so that they better fit dkg and mult usage

    for(uint8_t j=0;j<ctx->n;j++) {
      // extract and store encrypted p share mac
      memcpy((*ctx->p_share_macs)[j*ctx->n + i], dptr, crypto_auth_hmacsha256_BYTES);
      //dump(dptr, crypto_auth_hmacsha256_BYTES, "[%d] p   share macs [%d,%d]", ctx->index, j+1, i+1);
      dptr+=crypto_auth_hmacsha256_BYTES;
    }

    if(liboprf_log_file!=NULL) {
      dump((*ctx->p_commitments_hashes)[i], toprf_update_commitment_HASHBYTES, "[%d] p   commitment hash [%d]", ctx->index, i+1);
    }
  }
  //if(ctx->cheater_len>cheaters) return TOPRF_Update_Err_CheatersFound;

  if(ctx->index>dealers) { // non-dealers are done
    ctx->step = TOPRF_Update_Peer_Send_K0P_Shares;
    return TOPRF_Update_Err_OK;
  }

  TOPRF_Update_Message* msg = (TOPRF_Update_Message*) output;
  uint8_t *wptr = msg->data;
  // we stashed our commitments temporarily in k_commitments
  memcpy(wptr, (*ctx->k0p_commitments), (ctx->n+1U) * crypto_core_ristretto255_BYTES);
  if(liboprf_log_file!=NULL) dump((uint8_t*)(*ctx->k0p_commitments), (ctx->n+1U) * crypto_core_ristretto255_BYTES, "[%d] commitments", ctx->index);
  //broadcast dealer_commitments
  if(0!=toprf_send_msg(output, toprfupdate_peer_mult_coms_msg_SIZE(ctx), toprfupdate_peer_mult_coms_msg, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;

  ctx->step = TOPRF_Update_Peer_Send_K0P_Shares;

  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err stp_mult_com_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = (uint8_t) ((ctx->t-1)*2 + 1);
  TOPRF_Update_Err ret = stp_broadcast(ctx, input, input_len, output, output_len,
                                       "mult4 broadcast commitments mult step 1",
                                       dealers, toprfupdate_peer_mult_coms_msg_SIZE(ctx), toprfupdate_peer_mult_coms_msg, TOPRF_Update_STP_Route_Encrypted_Mult_Shares);
  if(ret!=TOPRF_Update_Err_OK) return ret;
  const uint8_t *ptr = input;

  // fixup step, that has already been advanced in the call to stp_broadcast above.
  uint8_t step = ctx->step;
  ctx->step = TOPRF_Update_STP_Broadcast_Mult_Commitments;

  for(uint8_t i=0;i<dealers;i++,ptr+=toprfupdate_peer_mult_coms_msg_SIZE(ctx)) {
    const DKG_Message* msg = (const DKG_Message*) ptr;
    const uint8_t *dptr = msg->data;
    ret = stp_check_chash(ctx,i,"k0p", dealers, ctx->n+1, dptr, ctx->p_commitments_hashes, ctx->k0p_commitments);
    if(TOPRF_Update_Err_OK!=ret) {
      ctx->step=step;
      return ret;
    }
  }

  ret = stp_vsps_check(ctx, "k0p", dealers, ctx->n+1, ctx->k0p_commitments);

  ctx->step=step;
  return ret;
}

#define toprfupdate_peer_mult2_msg_SIZE (sizeof(TOPRF_Update_Message) + sizeof(TOPRF_Share) * 4)
static TOPRF_Update_Err peer_step26_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = (uint8_t) ((ctx->t-1)*2 + 1);
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] mult5 receive Mul commitments & distribute encrypted Mult shares\x1b[0m\n", ctx->index);
  if(input_len != sizeof(TOPRF_Update_Message) + toprfupdate_peer_mult_coms_msg_SIZE(ctx) * dealers) return TOPRF_Update_Err_ISize;
  if(output_len != isdealer(ctx->index, ctx->t) * ctx->n * toprfupdate_peer_mult2_msg_SIZE) return TOPRF_Update_Err_OSize;

  const size_t cheaters = ctx->cheater_len;
  // verify STP message envelope
  const uint8_t *ptr=NULL;
  int ret = unwrap_envelope(ctx,input,input_len,toprfupdate_stp_bc_mult_coms_msg,&ptr);
  if(ret!=TOPRF_Update_Err_OK) return ret;

  for(uint8_t i=0;i<dealers;i++,ptr+=toprfupdate_peer_mult_coms_msg_SIZE(ctx)) {
    const TOPRF_Update_Message* msg24 = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprfupdate_peer_mult_coms_msg_SIZE(ctx),toprfupdate_peer_mult_coms_msg,i+1,0xff)) continue;

    const uint8_t *dptr = msg24->data;
    // k0*p commitments
    memcpy((*ctx->k0p_commitments)[i*(ctx->n+1U)], dptr, (ctx->n+1U) * crypto_core_ristretto255_BYTES);

    // verify against commitment hashes
    uint8_t chash[toprf_update_commitment_HASHBYTES];
    crypto_generichash(chash, toprf_update_commitment_HASHBYTES, (*ctx->k0p_commitments)[i*(ctx->n+1U)], crypto_core_ristretto255_BYTES*(ctx->n+1U), NULL, 0);
    if(memcmp(chash, (*ctx->p_commitments_hashes)[i], toprf_update_commitment_HASHBYTES)!=0) {
      if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[%d] failed to verify hash for k0p commitments of dealer %d\n"NORMAL, ctx->index, i+1);
      if(peer_add_cheater(ctx, 1, i+1, 0) == NULL) return TOPRF_Update_Err_CheatersFull;
    }
  }
  if(ctx->cheater_len>cheaters) return TOPRF_Update_Err_CheatersFound;

  if(ctx->index>dealers) { // non-dealers are done
    ctx->step = TOPRF_Update_Peer_Recv_K0P_Shares;
    return TOPRF_Update_Err_OK;
  }
  // dealers only
  // also distribute k0*p shares to all
  uint8_t *wptr = output;
  for(uint8_t i=0;i<ctx->n;i++,wptr+=toprfupdate_peer_mult2_msg_SIZE) {
    TOPRF_Update_Message* msg26 = (TOPRF_Update_Message*) wptr;
    memcpy(msg26->data, (*ctx->encrypted_shares)[i], toprf_update_encrypted_shares_SIZE*2);

    if(0!=toprf_send_msg(wptr, toprfupdate_peer_mult2_msg_SIZE, toprfupdate_peer_mult2_msg, ctx->index, i+1, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;
  }

  ctx->step = TOPRF_Update_Peer_Recv_K0P_Shares;
  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err stp_step27_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);
  return stp_route(ctx, input, input_len, output, output_len,
                   "mult6 route k0*p shares from all dealers to all peers",
                   dealers, ctx->n, toprfupdate_peer_mult2_msg, toprfupdate_peer_mult2_msg_SIZE, TOPRF_Update_STP_Broadcast_Mult_Complaints);
}

#define toprfupdate_peer_verify_mult_shares_msg_SIZE(ctx) (sizeof(TOPRF_Update_Message) + 2U + (size_t)((ctx->t-1U)*2 + 1U) * 2)
static TOPRF_Update_Err peer_step28_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] mult7 receive k0*p shares, starts checking of commitments\x1b[0m\n", ctx->index);
  if(input_len != dealers * toprfupdate_peer_mult2_msg_SIZE) return TOPRF_Update_Err_ISize;
  if(output_len != toprfupdate_peer_verify_mult_shares_msg_SIZE(ctx)) return TOPRF_Update_Err_OSize;

  //uint8_t (*c)[dealers][ctx->n+1][crypto_core_ristretto255_BYTES] = (uint8_t (*)[dealers][ctx->n+1][crypto_core_ristretto255_BYTES]) ctx->k0p_commitments;
  //for(unsigned i=0;i<dealers;i++) {
  //  for(unsigned j=0;j<ctx->n+1;j++) dump((*c)[i][j], crypto_core_ristretto255_BYTES, "c_%d%d", i+1,j);
  //}
  const size_t cheaters = ctx->cheater_len;

  const uint8_t *ptr = input;
  for(uint8_t i=0;i<dealers;i++) {
    const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprfupdate_peer_mult2_msg_SIZE,toprfupdate_peer_mult2_msg,i+1,ctx->index)) continue;

    const uint8_t *dptr = msg->data;

    TOPRF_Update_Err ret = decrypt_shares(ctx, i, "k0p", (*ctx->p_share_macs)[(ctx->index-1)*ctx->n + i], dptr, 1, (*ctx->k0p_shares)[i]);
    if(TOPRF_Update_Err_OK!=ret) {
      dump((*ctx->p_share_macs)[(ctx->index-1)*ctx->n + i], crypto_auth_hmacsha256_BYTES, "[%d] k0p hmac_%d", ctx->index, i+1);
      return ret;
    }

    ptr+=toprfupdate_peer_mult2_msg_SIZE;
  }
  if(ctx->cheater_len>cheaters) return TOPRF_Update_Err_CheatersFound;

  TOPRF_Update_Message* msg = (TOPRF_Update_Message*) output;
  uint8_t *fails_len = msg->data;
  uint8_t *fails = fails_len+1;
  verify_commitments(ctx, "k0p", dealers, ctx->n+1, ctx->index, (*ctx->k0p_commitments), ctx->k0p_shares, fails_len, fails);
#ifdef UNITTEST_CORRUPT
  corrupt_false_accuse(ctx, 2, 3, fails_len, fails);
#endif //UNITTEST_CORRUPT

  if(0!=toprf_send_msg(output, toprfupdate_peer_verify_mult_shares_msg_SIZE(ctx), toprfupdate_peer_verify_mult_shares_msg, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;

  ctx->step = TOPRF_Update_Peer_Handle_Mult_Share_Complaints;

  return TOPRF_Update_Err_OK;
}

#define toprfupdate_stp_bc_verify_mult_shares_msg_SIZE(ctx) (sizeof(TOPRF_Update_Message) + (toprfupdate_peer_verify_mult_shares_msg_SIZE(ctx) * ctx->n))
static TOPRF_Update_Err stp_verify_mult_shares_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);
  return stp_complaint_handler(ctx, input, input_len, output, output_len,
                               "mult-verify1 broadcast mult complaints of peers",
                               ctx->n, toprfupdate_peer_verify_mult_shares_msg_SIZE(ctx),
                               toprfupdate_peer_verify_mult_shares_msg,
                               dealers,
                               TOPRF_Update_STP_Route_ZK_Challenge_Commitments,
                               TOPRF_Update_STP_Broadcast_Mult_Defenses);
}

static TOPRF_Update_Err peer_mult_fork(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len) {
  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);
  return peer_complaint_handler(ctx, input, input_len,
                                "mult-verify2 receive mult complaints broadcast",
                                toprfupdate_peer_verify_mult_shares_msg_SIZE(ctx),
                                toprfupdate_peer_verify_mult_shares_msg,
                                dealers,
                                TOPRF_Update_Peer_Send_ZK_Challenge_Commitments,
                                TOPRF_Update_Peer_Defend_Mult_Accusations);
}

static TOPRF_Update_Err peer_mult_defend(TOPRF_Update_PeerState *ctx, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] mult-defend1 disclose share encryption key for contested Mult shares\x1b[0m\n", ctx->index);
  if(output_len != toprf_update_peer_output_size(ctx)) return TOPRF_Update_Err_OSize;
  if(output_len == 0) {
    if(liboprf_log_file!=NULL) {
      fprintf(liboprf_log_file,"[%d] nothing to defend against, no message to send\n", ctx->index);
    }
    ctx->step = TOPRF_Update_Peer_Check_Mult_Shares;
    return 0;
  }

  // send out all shares that belong to peers that complained.
  TOPRF_Update_Message* msg = (TOPRF_Update_Message*) output;
  uint8_t *wptr = msg->data;
  for(int i=0;i<ctx->my_p_complaints_len;i++) {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;36m[%d] defending against k0p complaint from %d\x1b[0m\n", ctx->index, ctx->my_p_complaints[i]);

    *wptr++ = ctx->my_p_complaints[i];
    // reveal key for noise wrapped share sent previously
    derive_key((*ctx->noise_outs)[ctx->my_p_complaints[i]-1],ctx->my_p_complaints[i],"k0p",wptr);
    wptr+=dkg_noise_key_SIZE;

    memcpy(wptr, (*ctx->encrypted_shares)[ctx->my_p_complaints[i]-1], toprf_update_encrypted_shares_SIZE);
    wptr+=toprf_update_encrypted_shares_SIZE;
  }

  if(0!=toprf_send_msg(output, output_len, toprfupdate_peer_share_mult_key_msg, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;

  ctx->step = TOPRF_Update_Peer_Check_Mult_Shares;
  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err stp_broadcast_mult_defenses(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[!] mult-defend2 broadcast mult defenses\x1b[0m\n");
  if(input_len != toprf_update_stp_input_size(ctx)) return TOPRF_Update_Err_ISize;
  if(output_len != toprf_update_stp_output_size(ctx)) return TOPRF_Update_Err_OSize;

  unsigned int ctr1[dealers];
  memset(ctr1,0,sizeof(ctr1));
  for(int i=0;i<ctx->p_complaints_len;i++) {
    const uint8_t peer = (uint8_t) ((ctx->p_complaints[i] & 0xff)-1U);
    if(peer>=dealers) return TOPRF_Update_Err_OOB;
    ctr1[peer]++;
  }

  ctx->y2_complaints_len = 0;
  memset(ctx->y2_complaints, 0, ctx->n*2);

  const uint8_t *ptr = input;
  uint8_t *wptr = ((TOPRF_Update_Message *) output)->data;
  size_t msg_size;
  for(uint8_t i=0;i<dealers;i++,ptr += msg_size) {
    if(ctr1[i]==0) {
      msg_size = 0;
      continue; // no complaints against this peer
    }
    msg_size = sizeof(TOPRF_Update_Message) \
               + (1+dkg_noise_key_SIZE+toprf_update_encrypted_shares_SIZE) * ctr1[i];
    if(stp_recv_msg(ctx,ptr,msg_size,toprfupdate_peer_share_mult_key_msg,i+1,0xff)) continue;

    const TOPRF_Update_Message *msg = (const TOPRF_Update_Message *) ptr;
    const uint8_t *dptr = msg->data;

    TOPRF_Update_Err ret = stp_check_defenses(ctx, dealers, ctx->n + 1, 0, ctr1[i], i, 1, ctx->p_share_macs, *ctx->k0p_commitments, &ctx->y2_complaints_len, ctx->y2_complaints, &dptr);
    if(TOPRF_Update_Err_OK != ret) {
      return ret;
    }

    memcpy(wptr, ptr, msg_size);
    wptr+=msg_size;
  }
  //if(ctx->cheater_len>cheaters) return TOPRF_Update_Err_CheatersFound;

  dump((uint8_t*)ctx->y2_complaints, ctx->y2_complaints_len*2, "k0p recover dealers:");
  if(0!=toprf_send_msg(output, output_len, toprfupdate_stp_bc_mult_key_msg, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;

  // add broadcast msg to transcript
  update_transcript(&ctx->transcript_state, output, output_len);

  if(ctx->y2_complaints_len==0) {
    ctx->step = TOPRF_Update_STP_Route_ZK_Challenge_Commitments;
  } else {
    ctx->step = TOPRF_Update_STP_Broadcast_Reconst_Mult_Shares;
  }
  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err peer_check_mult_shares(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len) {
  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] mult-defend3 verify disclosed mult shares\x1b[0m\n", ctx->index);
  if(input_len != toprf_update_peer_input_size(ctx)) return TOPRF_Update_Err_ISize;

  // verify STP message envelope
  const uint8_t *ptr=NULL;
  TOPRF_Update_Err ret = unwrap_envelope(ctx,input,input_len,toprfupdate_stp_bc_mult_key_msg,&ptr);
  if(ret!=TOPRF_Update_Err_OK) return ret;

  unsigned int ctr1[dealers];
  aggregate_complaints(dealers,ctr1,&ctx->p_complaints_len,ctx->p_complaints);

  size_t msg_size;
  for(uint8_t i=0;i<dealers;i++,ptr += msg_size) {
    if(ctr1[i]==0) {
      msg_size = 0;
      continue; // no complaints against this peer
    }
    msg_size = sizeof(TOPRF_Update_Message) \
               + (1+dkg_noise_key_SIZE+toprf_update_encrypted_shares_SIZE) * ctr1[i];

    if(peer_recv_msg(ctx,ptr,msg_size,toprfupdate_peer_share_mult_key_msg,i+1,0xff)) continue;
    const TOPRF_Update_Message *msg = (const TOPRF_Update_Message *) ptr;
    const uint8_t *dptr = msg->data;

    ret = check_defenses(ctx, dealers, ctx->n+1, 0, ctr1[i], i, 1, ctx->p_share_macs, *ctx->k0p_commitments, &ctx->p_complaints_len, ctx->p_complaints, &dptr);
    if(TOPRF_Update_Err_OK != ret) return ret;
  }

  dump((uint8_t*) ctx->p_complaints, ctx->p_complaints_len*2, "k0p recover dealers:");

  if(ctx->p_complaints_len > 0) {
    ctx->step = TOPRF_Update_Peer_Disclose_Mult_Shares;
  } else {
    ctx->step = TOPRF_Update_Peer_Send_ZK_Challenge_Commitments;
  }
  return TOPRF_Update_Err_OK;
}

static uint8_t unique_complaints(const uint8_t n,
                                 const uint16_t complaints_len,
                                 const uint16_t complaints[complaints_len]) {
  if(n==0) return 0xff;
  uint8_t total=0;
  uint8_t peer[n];
  memset(peer, 0, sizeof peer);
  for(unsigned i=0;i<complaints_len;i++) {
    const uint8_t accused = (uint8_t) (complaints[i] & 0xff);
    if(accused>n || accused == 0) return 0xff; // we set them ourselves. this should not happen
    peer[accused-1]=1;
  }
  for(unsigned i=0;i<n;i++) total+=peer[i];
  return total;
}
#define unique_p_complaints(ctx) unique_complaints(ctx->n, ctx->p_complaints_len, ctx->p_complaints)
#define unique_y2_complaints(ctx) unique_complaints(ctx->n, ctx->y2_complaints_len, ctx->y2_complaints)

static TOPRF_Update_Err disclose_shares(const uint8_t n,
                                        const uint8_t self,
                                        const char *type,
                                        const uint16_t complaints_len,
                                        const uint16_t complaints[complaints_len],
                                        TOPRF_Share shares[][2],
                                        uint8_t **wptr) {
  if(n==0) return 0xff;
  int sent[n];
  memset(sent,0,sizeof sent);
  for(unsigned i=0;i<complaints_len;i++) {
    const uint8_t peer = (uint8_t) (complaints[i] & 0xff);
    if(peer==0 || peer>=n) return TOPRF_Update_Err_OOB;
    if(sent[peer-1]!=0) continue;
    sent[peer-1]=1;
    memcpy(*wptr, shares[peer-1], TOPRF_Share_BYTES*2);
    dump(*wptr, TOPRF_Share_BYTES*2, "[%d] disclosing %s share of %d", self, type, peer);
    *wptr+=TOPRF_Share_BYTES*2;
  }
  return TOPRF_Update_Err_OK;
}

#define toprfupdate_peer_reconst_mult_shares_msg_SIZE(ctx) (sizeof(TOPRF_Update_Message)                                  \
                                                            + unique_p_complaints(ctx) * toprf_update_encrypted_shares_SIZE)
static TOPRF_Update_Err peer_disclose_mult_shares(TOPRF_Update_PeerState *ctx, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] mult-reconst1 disclose shares to reconstruct Mult secrets of cheaters\x1b[0m\n", ctx->index);
  if(output_len != toprfupdate_peer_reconst_mult_shares_msg_SIZE(ctx)) return TOPRF_Update_Err_OSize;

  TOPRF_Update_Message* msg = (TOPRF_Update_Message*) output;
  uint8_t *wptr = msg->data;
  TOPRF_Update_Err ret;
  ret =  disclose_shares(ctx->n, ctx->index, "k0p", ctx->p_complaints_len, ctx->p_complaints, (*ctx->k0p_shares), &wptr);
  if(ret != TOPRF_Update_Err_OK) return ret;

  if(0!=toprf_send_msg(output,
                       output_len,
                       toprfupdate_peer_reconst_mult_shares_msg,
                       ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;

  ctx->step = TOPRF_Update_Peer_Reconstruct_Mult_Shares;
  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err reconstruct(const uint8_t n, const uint8_t t,
                                    const char *type,
                                    const uint16_t complaints_len,
                                    const uint16_t complaints[complaints_len],
                                    const TOPRF_Share shares[unique_complaints(n, complaints_len, complaints)][n][2],
                                    const uint8_t (*commitments)[][crypto_core_ristretto255_BYTES],
                                    uint8_t secrets[unique_complaints(n, complaints_len, complaints)][2][crypto_core_ristretto255_SCALARBYTES]) {
  const uint8_t dealers = (uint8_t) ((t-1U)*2 + 1U);
  uint8_t (*c)[dealers][n+1][crypto_core_ristretto255_BYTES] = (uint8_t (*)[dealers][n+1][crypto_core_ristretto255_BYTES]) commitments;
  uint8_t seen[n];
  memset(seen, 0, sizeof seen);
  for(unsigned i=0, share_idx=0;i<complaints_len;i++) {
    TOPRF_Share r[2];
    const uint8_t accused = (uint8_t) (complaints[i] & 0xff);
    const uint8_t accuser = (uint8_t) (complaints[i] >> 8);

    if(accused == 0 || accused>=n) return TOPRF_Update_Err_OOB;
    if(seen[accused-1]) continue;
    seen[accused-1]=1;

    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "[!] reconstructing %s share/commitment of dealer %d accused by %d\n", type, accused, accuser);
    uint8_t t1=t;
    for(t1=t;t1<n;t1++) {
      fprintf(liboprf_log_file, "trying degree t+%d\n", t1-t);
      if(0!=dkg_vss_reconstruct(t1, 0, n, shares[share_idx], &(*commitments)[(n+1) * (accused - 1) + 1], r[0].value, r[1].value)) continue;
      if(0!=dkg_vss_verify_commitment((*c)[accused-1][0],r)) continue;
      break;
    }
    if(t1>=n) return TOPRF_Update_Err_Reconstruct;

    if(secrets!=NULL) {
      if(0!=dkg_vss_reconstruct(t1, 0, n, shares[share_idx], &(*commitments)[(n+1) * (accused - 1) + 1], secrets[i][0], secrets[i][1])) return TOPRF_Update_Err_Reconstruct;
      dump((uint8_t*) secrets[i], 2*crypto_core_ristretto255_SCALARBYTES, "[!] reconstructed secret of %d", accused);
    }

    if(0!=dkg_vss_reconstruct(t1, accuser, n, shares[share_idx], &(*commitments)[(n+1) * (accused - 1) + 1], r[0].value, r[1].value)) return TOPRF_Update_Err_Reconstruct;
    dump((uint8_t*) &r, sizeof r, "[!] reconstructed share of %d - accused by %d", accused, accuser);

    if(0!=dkg_vss_verify_commitment((*c)[accused-1][accuser],r)) {
      if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[!] failed to validate commitment for reconstructed %s share from %d\n"NORMAL, type, accused);
      dump((*c)[accused-1][accuser], 32, "[!] commitment", accuser);
      if(0!=dkg_vss_commit(r[0].value, r[1].value,(*c)[accused-1][accuser])) return TOPRF_Update_Err_VSSCommit;
      dump((*c)[accused-1][accuser], 32, "[!] corrected ", accuser);
      // todo check vsps on these commitments and if that fails return TOPRF_Update_Err_BadReconstruct;
      // better to do this only after all reconstructions have been
      // done in case multiple shares from the same dealer have
      // adjusted commitments.
    }

    share_idx++;
  }
  return TOPRF_Update_Err_OK;
}


#define toprfupdate_stp_reconst_mult_shares_msg_SIZE(ctx) (sizeof(TOPRF_Update_Message)      \
                                                           + unique_y2_complaints(ctx) * toprf_update_encrypted_shares_SIZE)
static TOPRF_Update_Err stp_broadcast_reconst_mult_shares(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  TOPRF_Update_Err ret;
  ret = stp_broadcast(ctx, input, input_len, output, output_len,
                       "mult-reconst2 broadcast shares to reconstruct mult secrets of cheating dealers",
                       ctx->n, toprfupdate_stp_reconst_mult_shares_msg_SIZE(ctx), toprfupdate_peer_reconst_mult_shares_msg, TOPRF_Update_STP_Route_ZK_Challenge_Commitments);
  if(ret != TOPRF_Update_Err_OK) return ret;

  TOPRF_Share k0p_shares[unique_y2_complaints(ctx)][ctx->n][2];
  const uint8_t *ptr = input;
  for(uint8_t i=0;i<ctx->n;i++,ptr+=toprfupdate_stp_reconst_mult_shares_msg_SIZE(ctx)) {
    const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) ptr;
    const uint8_t *dptr = msg->data;
    for(unsigned j=0;j<unique_y2_complaints(ctx);j++) {
      memcpy(k0p_shares[j][msg->from-1], dptr, TOPRF_Share_BYTES*2);
      dptr+=TOPRF_Share_BYTES*2;
    }
  }

  ret = reconstruct(ctx->n, ctx->t,"k0p", ctx->y2_complaints_len,ctx->y2_complaints,k0p_shares,ctx->k0p_commitments, NULL);

  return ret;
}

static TOPRF_Update_Err peer_reconstruct(TOPRF_Update_PeerState *ctx,
                                         const char *type,
                                         uint16_t *complaints_len,
                                         uint16_t complaints[*complaints_len],
                                         const TOPRF_Share shares[unique_complaints(ctx->n, *complaints_len, complaints)][ctx->n][2],
                                         const uint8_t (*commitments)[][crypto_core_ristretto255_BYTES],
                                         TOPRF_Share (*my_shares)[2]) {
  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);
  uint8_t (*c)[dealers][ctx->n+1][crypto_core_ristretto255_BYTES] = (uint8_t (*)[dealers][ctx->n+1][crypto_core_ristretto255_BYTES]) commitments;
  uint8_t seen[ctx->n];
  memset(seen, 0, sizeof seen);
  for(unsigned i=0, share_idx=0;i<*complaints_len;i++) {
    TOPRF_Share r[2];
    const uint8_t accused = (uint8_t) (complaints[i] & 0xff);
    const uint8_t accuser = (uint8_t) (complaints[i] >> 8);

    if(accused == 0 || accused>=ctx->n) return TOPRF_Update_Err_OOB;
    if(seen[accused-1]) continue;
    seen[accused-1]=1;

    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "[%d] reconstructing %s share/commitment of dealer %d accused by %d\n", ctx->index, type, accused, accuser);
    uint8_t t1=ctx->t;
    for(t1=ctx->t;t1<ctx->n;t1++) {
      fprintf(liboprf_log_file, "trying degree t+%d\n", t1-ctx->t);
      if(0!=dkg_vss_reconstruct(t1, 0, ctx->n, shares[share_idx], &(*commitments)[(ctx->n+1) * (accused - 1) + 1], r[0].value, r[1].value)) continue;
      if(0!=dkg_vss_verify_commitment((*c)[accused-1][0],r)) continue;
      break;
    }
    if(t1>=ctx->n) return TOPRF_Update_Err_Reconstruct;

    if(0!=dkg_vss_reconstruct(t1, accuser, ctx->n, shares[share_idx], &(*commitments)[(ctx->n+1) * (accused - 1) + 1], r[0].value, r[1].value)) return TOPRF_Update_Err_Reconstruct;
    dump((uint8_t*) &r, sizeof r, "[%d] reconstructed share of %d - accused by %d", ctx->index, accused, accuser);

    if(0!=dkg_vss_verify_commitment((*c)[accused-1][accuser],r)) {
      if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[%d] failed to validate commitment for reconstructed %s share from %d\n"NORMAL, ctx->index, type, accused);
      dump((*c)[accused-1][accuser], 32, "[%d] commitment", ctx->index);
      if(0!=dkg_vss_commit(r[0].value, r[1].value, (*c)[accused-1][accuser])) return TOPRF_Update_Err_VSSCommit;
      dump((*c)[accused-1][accuser], 32, "[%d] corrected ", ctx->index);
      // todo check vsps on these commitments and if that fails return TOPRF_Update_Err_BadReconstruct;
      // better to do this only after all reconstructions have been
      // done in case multiple shares from the same dealer have
      // adjusted commitments.
    }

    int incorrect = 0;
    for(unsigned j=0;j<*complaints_len;j++) {
      if((accused == (complaints[j] & 0xff)) && (ctx->index == (complaints[j] >> 8))) {
        incorrect = 1;
        break;
      }
    }

    if(accuser != ctx->index) {
      if(0!=dkg_vss_reconstruct(t1, ctx->index, ctx->n, shares[share_idx], &(*commitments)[(ctx->n+1) * (accused - 1) + 1], r[0].value, r[1].value)) return TOPRF_Update_Err_Reconstruct;
    }

    const int diff = (memcmp(r[0].value, my_shares[accused - 1][0].value, 32)!=0) |  (memcmp(r[1].value, my_shares[accused - 1][1].value, 32)!=0) << 1;
    if(diff!=0) {
      if(!incorrect) {
        if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[%d] reconstructed a different %s share from %d than " \
                                   "was previously validated using its commitment, was accused by %d\n"NORMAL, ctx->index, type, accused, accuser);
        return TOPRF_Update_Err_BadReconstruct;
      }
      if(diff & 1) {
        dump(r[0].value, 32, "[%d] reconstructed s share %d", ctx->index, accused);
        memcpy(my_shares[accused - 1][0].value, r[0].value, 32);
      }
      if(diff & 2) {
        dump(r[1].value, 32, "[%d] reconstructed r share %d", ctx->index, accused);
        memcpy(my_shares[accused - 1][1].value, r[1].value, 32);
      }
    }
    share_idx++;
  }
  *complaints_len = 0;
  memset(complaints, 0, ctx->n*2);
  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err peer_send_zk_chalcoms(TOPRF_Update_PeerState *ctx, uint8_t *output, const size_t output_len);
static TOPRF_Update_Err peer_reconst_mult_shares(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] mult-reconst3 reconstruct secrets of cheating mult dealers\x1b[0m\n", ctx->index);
  if(input_len!= sizeof(TOPRF_Update_Message) + toprfupdate_peer_reconst_mult_shares_msg_SIZE(ctx) * ctx->n) return TOPRF_Update_Err_ISize;

  // verify STP message envelope
  const uint8_t *ptr=NULL;
  int ret = unwrap_envelope(ctx,input,input_len,toprfupdate_stp_bc_reconst_mult_shares_msg,&ptr);
  if(ret!=TOPRF_Update_Err_OK) return ret;

  TOPRF_Share k0p_shares[unique_p_complaints(ctx)][ctx->n][2];
  for(uint8_t i=0;i<ctx->n;i++,ptr+=toprfupdate_peer_reconst_mult_shares_msg_SIZE(ctx)) {
    const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprfupdate_peer_reconst_mult_shares_msg_SIZE(ctx),toprfupdate_peer_reconst_mult_shares_msg,i+1,0xff)) continue;
    const uint8_t *dptr = msg->data;
    for(unsigned j=0;j<unique_p_complaints(ctx);j++) {
      memcpy(k0p_shares[j][msg->from-1], dptr, TOPRF_Share_BYTES*2);
      dptr+=TOPRF_Share_BYTES*2;
    }
  }

  ret = peer_reconstruct(ctx,"k0p", &ctx->p_complaints_len,ctx->p_complaints,k0p_shares,ctx->k0p_commitments,(*ctx->k0p_shares));
  if(ret != TOPRF_Update_Err_OK) return ret;

  // reset my_complaints
  ctx->my_p_complaints_len = 0;
  memset(ctx->my_p_complaints, 0, ctx->n);

  return peer_send_zk_chalcoms(ctx, output, output_len);
}

//ctx->step = TOPRF_Update_Peer_Send_ZK_Challenge_Commitments;
#define toprfupdate_peer_zkp1_msg_SIZE (sizeof(TOPRF_Update_Message) + crypto_scalarmult_ristretto255_BYTES)
static TOPRF_Update_Err peer_send_zk_chalcoms(TOPRF_Update_PeerState *ctx, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] zk1 send ZK challenge commitments\x1b[0m\n", ctx->index);
  if(output_len != toprfupdate_peer_zkp1_msg_SIZE) return TOPRF_Update_Err_OSize;

  // generate 2x nonces for ZK proof challenge, broadcast a commitment to it.
  TOPRF_Update_Message* msg = (TOPRF_Update_Message*) output;
  crypto_core_ristretto255_scalar_random(ctx->zk_chal_nonce[0]);
  crypto_core_ristretto255_scalar_random(ctx->zk_chal_nonce[1]);
  if(0!=dkg_vss_commit(ctx->zk_chal_nonce[0], ctx->zk_chal_nonce[1], msg->data)) return TOPRF_Update_Err_VSSCommit;
  //dump(msg->data + i*crypto_scalarmult_ristretto255_BYTES, crypto_scalarmult_ristretto255_BYTES, "<zk_challenge_commitment[%d][%d]", ctx->index, i);

  if(0!=toprf_send_msg(output, toprfupdate_peer_zkp1_msg_SIZE, toprfupdate_peer_zkp1_msg, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;

  ctx->step = TOPRF_Update_Peer_Send_ZK_Commitments;
  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err stp_step29_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  return stp_broadcast(ctx, input, input_len, output, output_len,
                       "step 29. broadcast zk challenge commitments",
                       ctx->n, toprfupdate_peer_zkp1_msg_SIZE, toprfupdate_peer_zkp1_msg, TOPRF_Update_STP_Route_ZK_commitments);
}

#define toprfupdate_peer_zkp2_msg_SIZE (sizeof(TOPRF_Update_Message) + 2 * 3 * crypto_scalarmult_ristretto255_SCALARBYTES)
static TOPRF_Update_Err peer_step30_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] zk2 everyone receives all e_j nonces, dealers broadcast ZK commitments\x1b[0m\n", ctx->index);
  if(input_len != sizeof(TOPRF_Update_Message) + toprfupdate_peer_zkp1_msg_SIZE * ctx->n) return TOPRF_Update_Err_ISize;
  if(output_len != isdealer(ctx->index, ctx->t) * toprfupdate_peer_zkp2_msg_SIZE) return TOPRF_Update_Err_OSize;
  const size_t cheaters = ctx->cheater_len;

  // verify STP message envelope
  const uint8_t *ptr=NULL;
  int ret = unwrap_envelope(ctx,input,input_len,toprfupdate_stp_bc_zkp1_msg,&ptr);
  if(ret!=TOPRF_Update_Err_OK) return ret;

  uint8_t (*zk_challenge_nonce_commitments)[ctx->n][crypto_scalarmult_ristretto255_BYTES] =
                               (uint8_t (*)[ctx->n][crypto_scalarmult_ristretto255_BYTES]) (ctx->zk_challenge_nonce_commitments);

  for(uint8_t i=0;i<ctx->n;i++,ptr+=toprfupdate_peer_zkp1_msg_SIZE) {
    const TOPRF_Update_Message* msg27 = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprfupdate_peer_zkp1_msg_SIZE,toprfupdate_peer_zkp1_msg,i+1,0xff)) continue;

    //dump(msg27->data, crypto_scalarmult_ristretto255_BYTES, "zk_e_nonce_%d commitment", i);
    memcpy((*zk_challenge_nonce_commitments)[i], msg27->data, crypto_scalarmult_ristretto255_BYTES);
    //dump((*ctx->zk_challenge_nonce_commitments)[i], crypto_scalarmult_ristretto255_BYTES, ">zk_challenge_commitment[%d]", i+1);
  }
  if(ctx->cheater_len>cheaters) return TOPRF_Update_Err_CheatersFound;

  if(ctx->index>dealers) { // non-dealers are done
    ctx->step = TOPRF_Update_Peer_Send_ZK_nonces;
    return TOPRF_Update_Err_OK;
  }
  // dealers only
  // also distribute k0*p shares to all
  uint8_t *wptr = output;
  TOPRF_Update_Message* msg29 = (TOPRF_Update_Message*) wptr;
  //dump((*ctx->p_commitments)[ctx->index-1], crypto_core_ristretto255_BYTES, "B[%d]", ctx->index);
  uint8_t (*msgs)[crypto_scalarmult_ristretto255_SCALARBYTES] = (uint8_t (*)[crypto_scalarmult_ristretto255_SCALARBYTES]) msg29->data;
  if(0!=toprf_mpc_ftmult_zk_commitments((*ctx->p_commitments)[ctx->index-1],
                                        ctx->zk_params.d,     // uint8_t d[crypto_scalarmult_ristretto255_SCALARBYTES],
                                        ctx->zk_params.s,     // uint8_t s[crypto_scalarmult_ristretto255_SCALARBYTES],
                                        ctx->zk_params.x,     // uint8_t x[crypto_scalarmult_ristretto255_SCALARBYTES],
                                        ctx->zk_params.s_1,   // uint8_t s_1[crypto_scalarmult_ristretto255_SCALARBYTES],
                                        ctx->zk_params.s_2,   // uint8_t s_2[crypto_scalarmult_ristretto255_SCALARBYTES],
                                        msgs)) {
    return TOPRF_Update_Err_FTMULTZKCommitments;
  }
  //dump(ctx->zk_params.d, crypto_core_ristretto255_SCALARBYTES, "[%d] d[%d]", ctx->index, ctx->index);
  //dump(ctx->zk_params.s, crypto_core_ristretto255_SCALARBYTES, "[%d] s[%d]", ctx->index, ctx->index);
  //dump(ctx->zk_params.x, crypto_core_ristretto255_SCALARBYTES, "[%d] x[%d]", ctx->index, ctx->index);
  //dump(ctx->zk_params.s_1, crypto_core_ristretto255_SCALARBYTES, "[%d] s_1[%d]", ctx->index, ctx->index);
  //dump(ctx->zk_params.s_2, crypto_core_ristretto255_SCALARBYTES, "[%d] s_2[%d]", ctx->index, ctx->index);
  //dump(msgs[0], crypto_scalarmult_ristretto255_SCALARBYTES, "[%d] M[%d]", ctx->index, ctx->index);
  //dump(msgs[1], crypto_scalarmult_ristretto255_SCALARBYTES, "[%d] M1[%d]", ctx->index, ctx->index);
  //dump(msgs[2], crypto_scalarmult_ristretto255_SCALARBYTES, "[%d] M2[%d]", ctx->index, ctx->index);

  if(0!=toprf_send_msg(wptr, toprfupdate_peer_zkp2_msg_SIZE, toprfupdate_peer_zkp2_msg, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;

  ctx->step = TOPRF_Update_Peer_Send_ZK_nonces;
  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err stp_step31_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);
  TOPRF_Update_Err ret;
  ret = stp_broadcast(ctx, input, input_len, output, output_len,
                       "zk3 broadcast ZK commitments",
                       dealers, toprfupdate_peer_zkp2_msg_SIZE, toprfupdate_peer_zkp2_msg, TOPRF_Update_STP_Broadcast_ZK_nonces);
  if(ret != TOPRF_Update_Err_OK) return ret;
  uint8_t (*zk_challenge_commitments)[dealers][3][crypto_scalarmult_ristretto255_SCALARBYTES] =
    (uint8_t (*)[dealers][3][crypto_scalarmult_ristretto255_SCALARBYTES]) ctx->zk_challenge_commitments;

  const uint8_t *ptr = input;
  for(uint8_t i=0;i<dealers;i++,ptr+=toprfupdate_peer_zkp2_msg_SIZE) {
    const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) ptr;
    //dump(msg27->data, crypto_scalarmult_ristretto255_BYTES, "zk_e_nonce_%d commitment", i);
    memcpy((*zk_challenge_commitments)[i], msg->data, 3*crypto_scalarmult_ristretto255_SCALARBYTES);
    //dump((uint8_t*) (*zk_challenge_commitments)[i], 3*crypto_scalarmult_ristretto255_SCALARBYTES, "zk_chal_com[%d]",i);
  }
  return TOPRF_Update_Err_OK;
}

#define toprfupdate_peer_zkp3_msg_SIZE (sizeof(TOPRF_Update_Message) + 4*crypto_scalarmult_ristretto255_SCALARBYTES)
static TOPRF_Update_Err peer_step32_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] zk4 receive dealers ZK commitments, broadcast zk nonce\x1b[0m\n", ctx->index);
  if(input_len != sizeof(TOPRF_Update_Message) + toprfupdate_peer_zkp2_msg_SIZE * dealers) return TOPRF_Update_Err_ISize;
  if(output_len != toprfupdate_peer_zkp3_msg_SIZE) return TOPRF_Update_Err_OSize;
  const size_t cheaters = ctx->cheater_len;

  // verify STP message envelope
  const uint8_t *ptr=NULL;
  int ret = unwrap_envelope(ctx,input,input_len,toprfupdate_stp_bc_zkp2_msg,&ptr);
  if(ret!=TOPRF_Update_Err_OK) return ret;

  uint8_t (*zk_challenge_commitments)[dealers][3][crypto_scalarmult_ristretto255_SCALARBYTES] =
    (uint8_t (*)[dealers][3][crypto_scalarmult_ristretto255_SCALARBYTES]) ctx->zk_challenge_commitments;

  for(uint8_t i=0;i<dealers;i++,ptr+=toprfupdate_peer_zkp2_msg_SIZE) {
    const TOPRF_Update_Message* msg29 = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprfupdate_peer_zkp2_msg_SIZE,toprfupdate_peer_zkp2_msg,i+1,0xff)) continue;

    //dump(msg27->data, crypto_scalarmult_ristretto255_BYTES, "zk_e_nonce_%d commitment", i);
    memcpy((*zk_challenge_commitments)[i], msg29->data, 3*crypto_scalarmult_ristretto255_SCALARBYTES);
    //uint8_t (*msgs)[3][crypto_scalarmult_ristretto255_SCALARBYTES] = (uint8_t (*)[3][crypto_scalarmult_ristretto255_SCALARBYTES]) (*ctx->zk_challenge_commitments);
    //dump(msgs[i][0], crypto_scalarmult_ristretto255_SCALARBYTES, "[%d] M[%d]", ctx->index, i+1);
    //dump(msgs[i][1], crypto_scalarmult_ristretto255_SCALARBYTES, "[%d] M1[%d]", ctx->index, i+1);
    //dump(msgs[i][2], crypto_scalarmult_ristretto255_SCALARBYTES, "[%d] M2[%d]", ctx->index, i+1);
    //
  }
  if(ctx->cheater_len>cheaters) return TOPRF_Update_Err_CheatersFound;

  TOPRF_Update_Message* msg31 = (TOPRF_Update_Message*) output;
  uint8_t *dptr = msg31->data;
  memcpy(dptr, ctx->zk_chal_nonce[0], 2*crypto_core_ristretto255_SCALARBYTES);
  //dump(dptr, 2*crypto_core_ristretto255_SCALARBYTES, "<zk_nonce[%d][0]", ctx->index);

  if(0!=toprf_send_msg(output, toprfupdate_peer_zkp3_msg_SIZE, toprfupdate_peer_zkp3_msg, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;

  ctx->step = TOPRF_Update_Peer_Send_ZK_proofs;

  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err stp_step33_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  TOPRF_Update_Err ret;
  ret = stp_broadcast(ctx, input, input_len, output, output_len,
                       "zk5 broadcast ZK nonces",
                       ctx->n, toprfupdate_peer_zkp3_msg_SIZE, toprfupdate_peer_zkp3_msg, TOPRF_Update_STP_Broadcast_ZK_Proofs);
  if(ret!=TOPRF_Update_Err_OK) return ret;
  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);
  const uint8_t *ptr = input;

  uint8_t zk_challenge_nonces[ctx->n][2][crypto_scalarmult_ristretto255_SCALARBYTES];
  // todo? we skip verifying the challenge_nonce commitments, but we also don't base any decision on this
  // we do this merely to anticipate how many dealers will be exposed/reconstructed
  for(uint8_t i=0;i<ctx->n;i++,ptr+=toprfupdate_peer_zkp3_msg_SIZE) {
    const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) ptr;
    const uint8_t *dptr=msg->data;
    memcpy(zk_challenge_nonces[i], dptr, 2*crypto_scalarmult_ristretto255_SCALARBYTES);
    //dump(dptr, 2*crypto_core_ristretto255_SCALARBYTES, ">zk_nonce[%d][0]", i+1);
  }

  uint8_t (*zk_challenge_e_i)[dealers][crypto_scalarmult_ristretto255_SCALARBYTES] =
    (uint8_t (*)[dealers][crypto_scalarmult_ristretto255_SCALARBYTES]) ctx->zk_challenge_e_i;
  for(unsigned dealer=0;dealer<dealers;dealer++) {
    memset((*zk_challenge_e_i)[dealer], 0, crypto_scalarmult_ristretto255_SCALARBYTES);
    for(unsigned i=0;i<ctx->n;i++) {
      if(dealer==i) continue;
      crypto_core_ristretto255_scalar_add((*zk_challenge_e_i)[dealer],
                                          (*zk_challenge_e_i)[dealer],
                                          zk_challenge_nonces[i][0]);
    }
    //dump((*zk_challenge_e_i)[p][dealer], crypto_scalarmult_ristretto255_SCALARBYTES, "zk%d_e_%d", p+1, dealer+1);
  }
  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err aggregate_zk_challenges(TOPRF_Update_PeerState *ctx,
                                                const uint8_t dealers, const uint8_t n,
                                                const uint8_t zk_challenge_nonces[n][2][crypto_scalarmult_ristretto255_SCALARBYTES],
                                                const uint8_t zk_challenge_nonce_commitments[n][crypto_scalarmult_ristretto255_BYTES],
                                                uint8_t zk_challenge_e_i[dealers][crypto_scalarmult_ristretto255_SCALARBYTES]) {
  // P_i verifies commitments for e_j,r_j
  // P_i computes e'_i:
  //  e'_i = Σ e_j
  //       j!=i
  for(unsigned dealer=0;dealer<dealers;dealer++) {
    memset(zk_challenge_e_i[dealer], 0, crypto_scalarmult_ristretto255_SCALARBYTES);
    uint8_t zk_challenge_commitment[crypto_scalarmult_ristretto255_BYTES];
    for(uint8_t i=0;i<n;i++) {
      if(dealer==i) continue;
      if(0!=dkg_vss_commit(zk_challenge_nonces[i][0], zk_challenge_nonces[i][1], zk_challenge_commitment)) {
        if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "vss-commit got an invalid point %d\n",i);
        return TOPRF_Update_Err_VSSCommit;
      }
      if(memcmp(zk_challenge_commitment, zk_challenge_nonce_commitments[i], crypto_scalarmult_ristretto255_BYTES)!=0) {
        if(peer_add_cheater(ctx, 1, i+1, 0) == NULL) return TOPRF_Update_Err_CheatersFull;
        if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "invalid e_i nonce commitment from %d\n",i);
        dump((const uint8_t*)zk_challenge_nonces[i], 2*crypto_scalarmult_ristretto255_SCALARBYTES, "zk_nonce[%d]", i+1);
        dump(zk_challenge_nonce_commitments[i], crypto_scalarmult_ristretto255_BYTES, "zk_challenge_commmitments[%d]", i+1);
      }
      crypto_core_ristretto255_scalar_add(zk_challenge_e_i[dealer],
                                          zk_challenge_e_i[dealer],
                                          zk_challenge_nonces[i][0]);
    }
    //dump(zk_challenge_e_i[dealer], crypto_scalarmult_ristretto255_SCALARBYTES, "zk%d_e",dealer+1);
  }
  return TOPRF_Update_Err_OK;
}

static uint8_t* gen_zk_witnesses(const uint8_t self, const uint8_t dealers,
                                 const TOPRF_Share *alpha, const TOPRF_Share *beta, const uint8_t *tau,
                                 const uint8_t e_i[dealers][crypto_scalarmult_ristretto255_SCALARBYTES],
                                 const TOPRF_Update_ZK_params zk_params,
                                 const uint8_t lambdas[dealers][crypto_core_ristretto255_SCALARBYTES],
                                 uint8_t *wptr
                                 ) {
  // P_i replies with the following values:
  // y   = d + e'_iβ,
  crypto_core_ristretto255_scalar_mul(wptr, e_i[self-1], beta[0].value);
  crypto_core_ristretto255_scalar_add(wptr, wptr, zk_params.d);
  wptr+=crypto_scalarmult_ristretto255_SCALARBYTES;
  // w   = s + e'_iσ
  crypto_core_ristretto255_scalar_mul(wptr, e_i[self-1], beta[1].value);
  crypto_core_ristretto255_scalar_add(wptr, wptr, zk_params.s);
  wptr+=crypto_scalarmult_ristretto255_SCALARBYTES;
  // z   = x + e'_iα
  crypto_core_ristretto255_scalar_mul(wptr, e_i[self-1], alpha[0].value);
  crypto_core_ristretto255_scalar_mul(wptr, wptr, lambdas[self-1]);
  crypto_core_ristretto255_scalar_add(wptr, wptr, zk_params.x);
  wptr+=crypto_scalarmult_ristretto255_SCALARBYTES;
  // w_1 = s_1 + e'_iρ
  crypto_core_ristretto255_scalar_mul(wptr, e_i[self-1], alpha[1].value);
  crypto_core_ristretto255_scalar_mul(wptr, wptr, lambdas[self-1]);
  crypto_core_ristretto255_scalar_add(wptr, wptr, zk_params.s_1);
  wptr+=crypto_scalarmult_ristretto255_SCALARBYTES;
  // w_2 = s_2 + e'_i(τ - σα)
  crypto_core_ristretto255_scalar_mul(wptr, beta[1].value, alpha[0].value);
  crypto_core_ristretto255_scalar_mul(wptr, wptr, lambdas[self-1]);
  crypto_core_ristretto255_scalar_sub(wptr, tau, wptr);
  crypto_core_ristretto255_scalar_mul(wptr, e_i[self-1], wptr);
  crypto_core_ristretto255_scalar_add(wptr, wptr, zk_params.s_2);
  wptr+=crypto_scalarmult_ristretto255_SCALARBYTES;
  return wptr;
}

#define toprfupdate_peer_zkp4_msg_SIZE (sizeof(TOPRF_Update_Message) + 5 * crypto_scalarmult_ristretto255_SCALARBYTES)
static TOPRF_Update_Err peer_step34_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] zk6 receive ZK nonces, dealers broadcast zk proof\x1b[0m\n", ctx->index);
  if(input_len != sizeof(TOPRF_Update_Message) + toprfupdate_peer_zkp3_msg_SIZE * ctx->n) return TOPRF_Update_Err_ISize;
  if(output_len != isdealer(ctx->index, ctx->t) * toprfupdate_peer_zkp4_msg_SIZE) return TOPRF_Update_Err_OSize;
  const size_t cheaters = ctx->cheater_len;

  // verify STP message envelope
  const uint8_t *ptr=NULL;
  int ret = unwrap_envelope(ctx, input, input_len, toprfupdate_stp_bc_zkp3_msg, &ptr);
  if(ret!=TOPRF_Update_Err_OK) return ret;

  uint8_t (*zk_challenge_nonces)[ctx->n][2][crypto_scalarmult_ristretto255_SCALARBYTES] =
                    (uint8_t (*)[ctx->n][2][crypto_scalarmult_ristretto255_SCALARBYTES]) ctx->zk_challenge_nonces;
  for(uint8_t i=0;i<ctx->n;i++,ptr+=toprfupdate_peer_zkp3_msg_SIZE) {
    const TOPRF_Update_Message* msg31 = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprfupdate_peer_zkp3_msg_SIZE,toprfupdate_peer_zkp3_msg,i+1,0xff)) continue;

    const uint8_t *dptr=msg31->data;
    memcpy((*zk_challenge_nonces)[i], dptr, 2*crypto_scalarmult_ristretto255_SCALARBYTES);
    //dump(dptr, 2*crypto_core_ristretto255_SCALARBYTES, ">zk_nonce[%d][0]", i+1);
  }
  if(ctx->cheater_len>cheaters) return TOPRF_Update_Err_CheatersFound;

  uint8_t (*zk_challenge_e_i)[dealers][crypto_scalarmult_ristretto255_SCALARBYTES] =
                 (uint8_t (*)[dealers][crypto_scalarmult_ristretto255_SCALARBYTES]) ctx->zk_challenge_e_i;
  uint8_t (*zk_challenge_nonce_commitments)[ctx->n][crypto_scalarmult_ristretto255_BYTES] =
                               (uint8_t (*)[ctx->n][crypto_scalarmult_ristretto255_BYTES]) ctx->zk_challenge_nonce_commitments;

  ret = aggregate_zk_challenges(ctx, dealers, ctx->n, (*zk_challenge_nonces), (*zk_challenge_nonce_commitments), (*zk_challenge_e_i));
  if(ret!=TOPRF_Update_Err_OK) return ret;

  if(ctx->cheater_len>cheaters) return TOPRF_Update_Err_CheatersFound;

  if(ctx->index>dealers) { // non-dealers are done
    ctx->step = TOPRF_Update_Peer_Verify_ZK_proofs;
    return TOPRF_Update_Err_OK;
  }

  // dealers only
  TOPRF_Update_Message* msg31 = (TOPRF_Update_Message*) output;
  uint8_t *wptr=msg31->data;
  wptr=gen_zk_witnesses(ctx->index, dealers, ctx->kc0_share, ctx->p_share, ctx->k0p_tau,
                   (*zk_challenge_e_i), ctx->zk_params, (*ctx->lambdas), wptr);

  if(0!=toprf_send_msg(output, toprfupdate_peer_zkp4_msg_SIZE, toprfupdate_peer_zkp4_msg, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;

  ctx->step = TOPRF_Update_Peer_Verify_ZK_proofs;
  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err zk_verify_proof(TOPRF_Update_PeerState *ctx,
                                        const uint8_t self,
                                        const uint8_t prover,
                                        const uint8_t A_i[crypto_core_ristretto255_BYTES],
                                        const uint8_t B_i[crypto_core_ristretto255_BYTES],
                                        const uint8_t C_i0[crypto_core_ristretto255_BYTES],
                                        const uint8_t e_i[crypto_scalarmult_ristretto255_SCALARBYTES],
                                        const uint8_t zk_challenge_commitments[3][crypto_scalarmult_ristretto255_SCALARBYTES],
                                        const uint8_t lambda[crypto_core_ristretto255_SCALARBYTES],
                                        const TOPRF_Update_ZK_proof proof,
                                        uint8_t *fails) {
  uint8_t v0[crypto_scalarmult_ristretto255_BYTES];
  uint8_t v1[crypto_scalarmult_ristretto255_BYTES];
  const uint8_t *M  = zk_challenge_commitments[0];
  const uint8_t *M1 = zk_challenge_commitments[1];
  const uint8_t *M2 = zk_challenge_commitments[2];
  //   g^y * h^w   == M * B^e'_i
  if(0!=dkg_vss_commit(proof.y, proof.w, v0)) return TOPRF_Update_Err_VSSCommit;
  if(crypto_scalarmult_ristretto255(v1, e_i, B_i)) return TOPRF_Update_Err_InvPoint;
  crypto_core_ristretto255_add(v1, M, v1);
  if(memcmp(v1, v0, crypto_scalarmult_ristretto255_BYTES)!=0) {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[%d] failed g^y * h^w   == M * B^e'_i for dealer %d\n"NORMAL, self, prover+1);
    dump(v1, crypto_scalarmult_ristretto255_BYTES, "lhs");
    dump(v0, crypto_scalarmult_ristretto255_BYTES, "rhs");
    fails[1+fails[0]++]=prover+1;
    if(self!=0 && peer_add_cheater(ctx, 1, prover+1, 0xff) == NULL) return TOPRF_Update_Err_CheatersFull;
    return TOPRF_Update_Err_OK;
  }

  //   g^z * h^w_1 == M_1 * A^e'_i
  if(0!=dkg_vss_commit(proof.z, proof.w_1, v0)) return TOPRF_Update_Err_VSSCommit;
  if(crypto_scalarmult_ristretto255(v1, e_i, A_i)) return TOPRF_Update_Err_InvPoint;
  if(crypto_scalarmult_ristretto255(v1, lambda, v1)) return TOPRF_Update_Err_InvPoint;
  crypto_core_ristretto255_add(v1, M1, v1);
  if(memcmp(v1, v0, crypto_scalarmult_ristretto255_BYTES)!=0) {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[%d] failed g^z * h^w_1 == M_1 * A^e'_i for dealer %d\n"NORMAL, self, prover+1);
    dump(v1, crypto_scalarmult_ristretto255_BYTES, "lhs");
    dump(v0, crypto_scalarmult_ristretto255_BYTES, "rhs");
    fails[1+fails[0]++]=prover+1;
    if(self!=0 && peer_add_cheater(ctx, 3, prover+1, 0xff) == NULL) return TOPRF_Update_Err_CheatersFull;
    return TOPRF_Update_Err_OK;
  }

  //   B^z * h^w_2 == M_2 * C^e'_i
  if(crypto_scalarmult_ristretto255(v0, proof.z, B_i)) return TOPRF_Update_Err_InvPoint;
  // we abuse v1 as a temp storage, v1 = h^w_2
  if(crypto_scalarmult_ristretto255(v1, proof.w_2, H)) return TOPRF_Update_Err_InvPoint;
  crypto_core_ristretto255_add(v0, v0, v1);

  if(crypto_scalarmult_ristretto255(v1, e_i, C_i0)) return TOPRF_Update_Err_InvPoint;
  crypto_core_ristretto255_add(v1, M2, v1);
  if(memcmp(v1, v0, crypto_scalarmult_ristretto255_BYTES)!=0) {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[%d] failed B^z * h^w_2 == M_2 * C^e'_i for dealer %d\n"NORMAL, self, prover+1);
    dump(v1, crypto_scalarmult_ristretto255_BYTES, "lhs");
    dump(v0, crypto_scalarmult_ristretto255_BYTES, "rhs");
    fails[1+fails[0]++]=prover+1;
    if(self!=0 && peer_add_cheater(ctx, 5, prover+1, 0xff) == NULL) return TOPRF_Update_Err_CheatersFull;
    return TOPRF_Update_Err_OK;
  }

  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err stp_step35_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);
  TOPRF_Update_Err ret;
  ret = stp_broadcast(ctx, input, input_len, output, output_len,
                      "zk7 broadcast ZK proofs",
                      dealers, toprfupdate_peer_zkp4_msg_SIZE, toprfupdate_peer_zkp4_msg, TOPRF_Update_STP_Broadcast_Mult_Ci);
  if(ret!=TOPRF_Update_Err_OK) return ret;

  uint8_t fails[dealers+1];
  memset(fails, 0, sizeof fails);
  const uint8_t (*zk_challenge_commitments)[dealers][3][crypto_scalarmult_ristretto255_SCALARBYTES] =
                         (const uint8_t (*)[dealers][3][crypto_scalarmult_ristretto255_SCALARBYTES]) ctx->zk_challenge_commitments;
  const uint8_t (*zk_challenge_e_i)[dealers][crypto_scalarmult_ristretto255_SCALARBYTES] =
                       (uint8_t (*)[dealers][crypto_scalarmult_ristretto255_SCALARBYTES]) ctx->zk_challenge_e_i;
  const uint8_t *ptr = input;

  uint8_t indexes[dealers];
  for(uint8_t i=0;i<dealers;i++) indexes[i]=i+1;
  uint8_t lambdas[dealers][dealers][crypto_core_ristretto255_SCALARBYTES];
  invertedVDMmatrix(dealers, indexes, lambdas);

  for(uint8_t i=0;i<dealers;i++,ptr+=toprfupdate_peer_zkp4_msg_SIZE) {
    const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) ptr;
    const TOPRF_Update_ZK_proof (*proof) = (const TOPRF_Update_ZK_proof*) msg->data;
    ret = zk_verify_proof(NULL, 0, i,
                          (*ctx->kc0_commitments)[i],
                          (*ctx->p_commitments)[i],
                          (*ctx->k0p_commitments)[i*(ctx->n+1)],
                          (*zk_challenge_e_i)[i],
                          (*zk_challenge_commitments)[i],
                          lambdas[0][i],
                          (*proof),
                          fails);
    if(ret != TOPRF_Update_Err_OK) return ret;
  }

  ctx->p_complaints_len = 0;
  const uint8_t *fails_len = fails;
  const uint8_t *xfails = fails_len+1;
  handle_complaints(dealers, 0, *fails_len, xfails, &ctx->p_complaints_len, ctx->p_complaints, 0, 0, 0);

  if(ctx->p_complaints_len != 0) {
    dump((uint8_t*) ctx->p_complaints, ctx->p_complaints_len*sizeof(uint16_t), "[!] complaints");
    ctx->step = TOPRF_Update_STP_Broadcast_ZK_Disclosures;
  }

  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err peer_step36_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len) {
  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] zk8 verify ZK proofs, accuse cheaters\x1b[0m\n", ctx->index);
  if(input_len != sizeof(TOPRF_Update_Message) + toprfupdate_peer_zkp4_msg_SIZE * dealers) return TOPRF_Update_Err_ISize;
  //const size_t cheaters = ctx->cheater_len;

  // verify STP message envelope
  const uint8_t *ptr=NULL;
  int ret = unwrap_envelope(ctx, input, input_len, toprfupdate_stp_bc_zkp4_msg, &ptr);
  if(ret!=TOPRF_Update_Err_OK) return ret;

  uint8_t fails[dealers+1];
  memset(fails, 0, sizeof fails);
  const uint8_t (*zk_challenge_commitments)[dealers][3][crypto_scalarmult_ristretto255_SCALARBYTES] =
                         (const uint8_t (*)[dealers][3][crypto_scalarmult_ristretto255_SCALARBYTES]) ctx->zk_challenge_commitments;
  const uint8_t (*zk_challenge_e_i)[dealers][crypto_scalarmult_ristretto255_SCALARBYTES] =
                       (uint8_t (*)[dealers][crypto_scalarmult_ristretto255_SCALARBYTES]) ctx->zk_challenge_e_i;

  for(uint8_t i=0;i<dealers;i++,ptr+=toprfupdate_peer_zkp4_msg_SIZE) {
    const TOPRF_Update_Message* msg33 = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprfupdate_peer_zkp4_msg_SIZE,toprfupdate_peer_zkp4_msg,i+1,0xff)) continue;

    const TOPRF_Update_ZK_proof (*proof) = (const TOPRF_Update_ZK_proof*) msg33->data;
    ret = zk_verify_proof(ctx, ctx->index, i,
                          (*ctx->kc0_commitments)[i],
                          (*ctx->p_commitments)[i],
                          (*ctx->k0p_commitments)[i*(ctx->n+1)],
                          (*zk_challenge_e_i)[i],
                          (*zk_challenge_commitments)[i],
                          (*ctx->lambdas)[i],
                          (*proof),
                          fails);
    if(ret != TOPRF_Update_Err_OK) return ret;
  }
  //if(ctx->cheater_len>cheaters) return TOPRF_Update_Err_CheatersFound;

  ctx->p_complaints_len = 0;
  const uint8_t *fails_len = &fails[0];
  const uint8_t *xfails = fails_len+1;
  handle_complaints(dealers, ctx->index, *fails_len, xfails, &ctx->p_complaints_len, ctx->p_complaints, 0, 0, 0);

  ctx->prev = ctx->step;
  if(ctx->p_complaints_len == 0) {
    ctx->step = TOPRF_Update_Peer_Send_Mult_Ci;
  } else {
    dump((uint8_t*) ctx->p_complaints, ctx->p_complaints_len*sizeof(uint16_t), "[%d] complaints", ctx->index);
    ctx->step = TOPRF_Update_Peer_Disclose_ZK_Cheaters;
  }

  return TOPRF_Update_Err_OK;
}

#define toprfupdate_peer_zk_disclose_msg_SIZE(ctx) (sizeof(TOPRF_Update_Message)                         \
                                                    +  ctx->p_complaints_len * TOPRF_Share_BYTES * 2     )
static TOPRF_Update_Err peer_zkproof_disclose(TOPRF_Update_PeerState *ctx, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] zk-reconst1 disclose shares of dealers unable to prove c=a*b\n"NORMAL, ctx->index);
  if(output_len != toprf_update_peer_output_size(ctx)) return TOPRF_Update_Err_OSize;

  TOPRF_Update_Message* msg = (TOPRF_Update_Message*) output;
  uint8_t *wptr = msg->data;

  TOPRF_Update_Err ret;
  ret = disclose_shares(ctx->n, ctx->index, "k0p", ctx->p_complaints_len, ctx->p_complaints, (*ctx->k0p_shares), &wptr);
  if(ret != TOPRF_Update_Err_OK) return ret;

  if(0!=toprf_send_msg(output, output_len, toprfupdate_peer_zk_disclose_msg, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;

  ctx->step = TOPRF_Update_Peer_Reconstruct_ZK_Shares;
  return TOPRF_Update_Err_OK;
}

#define toprfupdate_stp_bc_zkp_disclose_msg_SIZE(ctx) (sizeof(TOPRF_Update_Message) + (toprfupdate_peer_zk_disclose_msg_SIZE(ctx) * ctx->n))
static TOPRF_Update_Err stp_bc_zk_disclosures(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  TOPRF_Update_Err ret;
  ret = stp_broadcast(ctx, input, input_len, output, output_len,
                      "zk-reconst2 broadcast shares of dealers failing ZK proofs",
                      ctx->n, toprfupdate_peer_zk_disclose_msg_SIZE(ctx), toprfupdate_peer_zk_disclose_msg, TOPRF_Update_STP_Broadcast_Mult_Ci);
  if(ret != TOPRF_Update_Err_OK) return ret;

  TOPRF_Share k0p_shares[ctx->p_complaints_len][ctx->n][2];
  const uint8_t *ptr = input;
  for(uint8_t i=0;i<ctx->n;i++,ptr+=toprfupdate_peer_zk_disclose_msg_SIZE(ctx)) {
    const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) ptr;
    const uint8_t *dptr = msg->data;
    for(unsigned j=0;j<ctx->p_complaints_len;j++) {
      memcpy(k0p_shares[j][msg->from-1], dptr, TOPRF_Share_BYTES*2);
      dptr+=TOPRF_Share_BYTES*2;
    }
  }

  TOPRF_Share secret[2];
  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);
  uint8_t (*c)[dealers][ctx->n+1][crypto_core_ristretto255_BYTES] = (uint8_t (*)[dealers][ctx->n+1][crypto_core_ristretto255_BYTES]) (*ctx->k0p_commitments);
  for(unsigned i=0;i<ctx->p_complaints_len;i++) {
    const uint8_t accused = (uint8_t) (ctx->p_complaints[i] & 0xff);
    if(0!=dkg_vss_reconstruct(ctx->t, 0, ctx->n, k0p_shares[i], &(*c)[accused-1][1], secret[0].value, secret[1].value)) return TOPRF_Update_Err_Reconstruct;
    dump(secret[0].value, sizeof secret[0].value, "reconstructed lab");
    if(0!=dkg_vss_commit(secret[0].value, secret[1].value, (*c)[accused-1][0])) return TOPRF_Update_Err_VSSCommit;
  }

  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err peer_step39_handler(TOPRF_Update_PeerState *ctx, uint8_t *output, const size_t output_len);
static TOPRF_Update_Err peer_reconst_zk_shares(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] zk-reconst3 reconstruct secrets of dealers failing ZK proof\x1b[0m\n", ctx->index);
  if(input_len!= sizeof(TOPRF_Update_Message) + toprfupdate_peer_zk_disclose_msg_SIZE(ctx) * ctx->n) return TOPRF_Update_Err_ISize;

  // verify STP message envelope
  const uint8_t *ptr=NULL;
  int ret = unwrap_envelope(ctx,input,input_len,toprfupdate_stp_bc_zk_disclose_msg,&ptr);
  if(ret!=TOPRF_Update_Err_OK) return ret;

  TOPRF_Share k0p_shares[ctx->p_complaints_len][ctx->n][2];
  for(uint8_t i=0;i<ctx->n;i++,ptr+=toprfupdate_peer_zk_disclose_msg_SIZE(ctx)) {
    const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprfupdate_peer_zk_disclose_msg_SIZE(ctx),toprfupdate_peer_zk_disclose_msg,i+1,0xff)) continue;
    const uint8_t *dptr = msg->data;
    for(unsigned j=0;j<ctx->p_complaints_len;j++) {
      memcpy(k0p_shares[j][msg->from-1], dptr, TOPRF_Share_BYTES*2);
      dptr+=TOPRF_Share_BYTES*2;
    }
  }

  TOPRF_Share secret[2];
  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);
  uint8_t (*c)[dealers][ctx->n+1][crypto_core_ristretto255_BYTES] = (uint8_t (*)[dealers][ctx->n+1][crypto_core_ristretto255_BYTES]) (*ctx->k0p_commitments);
  for(unsigned i=0;i<ctx->p_complaints_len;i++) {
    const uint8_t accused = (uint8_t) (ctx->p_complaints[i] & 0xff);
    if(0!=dkg_vss_reconstruct(ctx->t, 0, ctx->n, k0p_shares[i], &(*c)[accused-1][1], secret[0].value, secret[1].value)) return TOPRF_Update_Err_Reconstruct;
    dump(secret[0].value, sizeof secret[0].value, "reconstructed lab");
    if(0!=dkg_vss_commit(secret[0].value, secret[1].value, (*c)[accused-1][0])) return TOPRF_Update_Err_VSSCommit;
  }

  // reset my_complaints
  ctx->my_p_complaints_len = 0;
  memset(ctx->my_p_complaints, 0, ctx->n);

  return peer_step39_handler(ctx, output, output_len);
}

static TOPRF_Update_Err compute_mul_share(const uint8_t dealers,
                              const TOPRF_Share shares_i[][2],
                              TOPRF_Share rshare[2],
                              uint8_t commitment[crypto_scalarmult_ristretto255_BYTES]) {
  // step 3. P_i computes:
  //      2t+1
  //  γ_i = Σ c_ji
  //       j=1
  //  which is a share of γ = αβ, via random polynomial of degree t and
  //      2t+1
  //  τ_i = Σ τ_ji
  //       j=1
  memcpy((uint8_t*) &rshare[0], (const uint8_t*) &shares_i[0][0], TOPRF_Share_BYTES);
  memcpy((uint8_t*) &rshare[1], (const uint8_t*) &shares_i[0][1], TOPRF_Share_BYTES);
  for(unsigned i=1;i<dealers;i++) {
    crypto_core_ristretto255_scalar_add(rshare[0].value, rshare[0].value, shares_i[i][0].value);
    crypto_core_ristretto255_scalar_add(rshare[1].value, rshare[1].value, shares_i[i][1].value);
  }
  // step 4. P_i computes and broadcasts
  //    𝓒_i = 𝓗(γ_i, τ_i)
  //        = g^(γ_i)*h^(τ_i)
  //
  //        2t+1
  //        = Π 𝓒_ji
  //         j=1
  if(0!=dkg_vss_commit(rshare[0].value, rshare[1].value, commitment)) return TOPRF_Update_Err_VSSCommit;
  return TOPRF_Update_Err_OK;
}

#define toprfupdate_peer_mult3_msg_SIZE (sizeof(TOPRF_Update_Message) + crypto_scalarmult_ristretto255_BYTES)
static TOPRF_Update_Err peer_step39_handler(TOPRF_Update_PeerState *ctx, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] final1 aggregate shares into final results and broadcast their commitment\x1b[0m\n", ctx->index);
  if(output_len != toprfupdate_peer_mult3_msg_SIZE) return TOPRF_Update_Err_OSize;

  TOPRF_Update_Message* msg = (TOPRF_Update_Message*) output;
  int ret = compute_mul_share(dealers ,(*ctx->k0p_shares), ctx->k0p_share, ctx->k0p_commitment);
  memcpy(msg->data, ctx->k0p_commitment, crypto_scalarmult_ristretto255_BYTES);
  if(ret!=TOPRF_Update_Err_OK) return ret;

  // use this below to calculate all commitments for the other peers
  uint8_t Cx_i[crypto_scalarmult_ristretto255_BYTES];
  uint8_t (*c)[dealers][ctx->n+1][crypto_core_ristretto255_BYTES] = (uint8_t (*)[dealers][ctx->n+1][crypto_core_ristretto255_BYTES]) ctx->k0p_commitments;
  memcpy(Cx_i, (*c)[0][ctx->index], crypto_scalarmult_ristretto255_BYTES);
  for(unsigned j=1;j<dealers;j++) {
    crypto_core_ristretto255_add(Cx_i, Cx_i, (*c)[j][ctx->index]);
  }
  // todo this check might not be needed
  if(memcmp(Cx_i, ctx->k0p_commitment, sizeof Cx_i) != 0) {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[%d] failed to verify commitment for k0p share"NORMAL, ctx->index);
    // todo cheater handling? who would be the cheater here?
    return TOPRF_Update_Err_CommmitmentsMismatch; // probably cannot happen?
  }

  if(0!=toprf_send_msg(output, toprfupdate_peer_mult3_msg_SIZE, toprfupdate_peer_mult3_msg, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;

  ctx->step = TOPRF_Update_Peer_Final_VSPS_Checks;
  return TOPRF_Update_Err_OK;
}

#define toprfupdate_stp_bc_mult3_msg_SIZE(ctx) (sizeof(TOPRF_Update_Message) + toprfupdate_peer_mult3_msg_SIZE * ctx->n)
static TOPRF_Update_Err stp_step40_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[!] final2 broadcast final mult commitments\x1b[0m\n");
  if(input_len != ctx->n * toprfupdate_peer_mult3_msg_SIZE) return TOPRF_Update_Err_ISize;
  if(output_len != toprfupdate_stp_bc_mult3_msg_SIZE(ctx)) return TOPRF_Update_Err_OSize;
  //const size_t cheaters = ctx->cheater_len;

  const uint8_t *ptr = input;
  uint8_t *wptr = ((TOPRF_Update_Message *) output)->data;
  for(uint8_t i=0;i<ctx->n;i++,ptr+=toprfupdate_peer_mult3_msg_SIZE) {
    if(stp_recv_msg(ctx,ptr,toprfupdate_peer_mult3_msg_SIZE, toprfupdate_peer_mult3_msg,i+1,0xff)) continue;
    const TOPRF_Update_Message *msg = (const TOPRF_Update_Message *) ptr;
    // keep a copy of all commitments for final verification and for check before reconstructing r and r'
    memcpy((*ctx->k0p_final_commitments)[i], msg->data, crypto_scalarmult_ristretto255_BYTES);

    memcpy(wptr, ptr, toprfupdate_peer_mult3_msg_SIZE);
    wptr+=toprfupdate_peer_mult3_msg_SIZE;

  }
  //if(ctx->cheater_len>cheaters) return TOPRF_Update_Err_CheatersFound;

  uint8_t fails[dealers+1];
  memset(fails, 0, sizeof fails);
  uint8_t (*c)[dealers][ctx->n+1][crypto_core_ristretto255_BYTES] = (uint8_t (*)[dealers][ctx->n+1][crypto_core_ristretto255_BYTES]) ctx->k0p_commitments;
  TOPRF_Update_Err ret;
  ret = ft_or_full_vsps(ctx->n+1, ctx->t, dealers, 0, (*ctx->k0p_final_commitments), c,
                        "VSPS failed k0p, doing full VSPS check on all dealers",
                        "VSPS failed k0p",
                        "ERROR, could not find and dealer commitments that fail the VSPS check",
                        fails, &fails[1]);
  if(ret!=TOPRF_Update_Err_OK) return ret;

  ctx->p_complaints_len = 0;

  const uint8_t *fails_len = fails;
  const uint8_t *xfails = fails_len+1;
  handle_complaints(dealers, 0, *fails_len, xfails, &ctx->p_complaints_len, ctx->p_complaints, 0, 0, 0);

  if(0!=toprf_send_msg(output, output_len, toprfupdate_stp_bc_mult3_msg, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;
  // add broadcast msg to transcript
  update_transcript(&ctx->transcript_state, output, output_len);

  if(ctx->p_complaints_len != 0) {
    dump((uint8_t*) ctx->p_complaints, ctx->p_complaints_len*sizeof(uint16_t), "[!] complaints");
    ctx->step = TOPRF_Update_STP_Broadcast_VSPS_Disclosures;
  } else {
    ctx->step = TOPRF_Update_STP_Reconstruct_Delta;
  }

  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err peer_step41_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len) {
  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] final3 receive final mult commitments, fast-track VSPS final results\x1b[0m\n", ctx->index);
  if(input_len != toprfupdate_stp_bc_mult3_msg_SIZE(ctx)) return TOPRF_Update_Err_ISize;
  const size_t cheaters = ctx->cheater_len;

  // verify STP message envelope
  const uint8_t *ptr=NULL;
  int ret = unwrap_envelope(ctx, input, input_len, toprfupdate_stp_bc_mult3_msg, &ptr);
  if(ret!=TOPRF_Update_Err_OK) return ret;

  uint8_t (*C_i)[crypto_scalarmult_ristretto255_BYTES] = (*ctx->p_commitments);
  for(uint8_t i=0;i<ctx->n;i++,ptr+=toprfupdate_peer_mult3_msg_SIZE) {
    const TOPRF_Update_Message* msg37 = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprfupdate_peer_mult3_msg_SIZE,toprfupdate_peer_mult3_msg,i+1,0xff)) continue;
    memcpy(C_i[i], msg37->data, crypto_scalarmult_ristretto255_BYTES);
  }
  if(ctx->cheater_len>cheaters) return TOPRF_Update_Err_CheatersFound;

  uint8_t fails[dealers+1];
  memset(fails, 0, sizeof fails);

  //liboprf_debug=0;
  //for(unsigned i=0;i<dealers;i++) {
  //  if(0!=toprf_mpc_vsps_check(ctx->t-1, (const uint8_t (*)[crypto_core_ristretto255_BYTES]) (*ctx->k0p_commitments)[i*(ctx->n+1)])) {
  //    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[%d] k0p vsps fails [%d]\n"NORMAL, ctx->index, i+1);
  //  }
  //}
  //liboprf_debug=1;

  uint8_t (*c)[dealers][ctx->n+1][crypto_core_ristretto255_BYTES] = (uint8_t (*)[dealers][ctx->n+1][crypto_core_ristretto255_BYTES]) ctx->k0p_commitments;
  ret = ft_or_full_vsps(ctx->n+1, ctx->t, dealers, ctx->index, C_i, c,
                        "VSPS failed k0p, doing full VSPS check on all dealers",
                        "VSPS failed k0p",
                        "ERROR, could not find and dealer commitments that fail the VSPS check",
                        fails, &fails[1]);
  if(ret!=TOPRF_Update_Err_OK) return ret;

  ctx->p_complaints_len = 0;
  const uint8_t *fails_len = fails;
  const uint8_t *xfails = fails_len+1;
  handle_complaints(dealers, ctx->index, *fails_len, xfails, &ctx->p_complaints_len, ctx->p_complaints, 0, 0, 0);

  ctx->prev = ctx->step;
  if(ctx->p_complaints_len == 0) {
    ctx->step = TOPRF_Update_Peer_Send_k0p_Share;
  } else {
    dump((uint8_t*) ctx->p_complaints, ctx->p_complaints_len*sizeof(uint16_t), "[%d] complaints", ctx->index);
    ctx->step = TOPRF_Update_Peer_Disclose_VSPS_Cheaters;
  }

  return TOPRF_Update_Err_OK;
}

#define toprfupdate_peer_vsps_disclose_msg_SIZE(ctx) (sizeof(TOPRF_Update_Message)                         \
                                                      +  ctx->p_complaints_len * TOPRF_Share_BYTES * 2     )
static TOPRF_Update_Err peer_vsps_disclose(TOPRF_Update_PeerState *ctx, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] final-reconst1 disclose shares of dealers failing vsps\n"NORMAL, ctx->index);
  if(output_len != toprf_update_peer_output_size(ctx)) return TOPRF_Update_Err_OSize;

  TOPRF_Update_Message* msg = (TOPRF_Update_Message*) output;
  uint8_t *wptr = msg->data;

  TOPRF_Update_Err ret;
  ret = disclose_shares(ctx->n, ctx->index, "k0p", ctx->p_complaints_len, ctx->p_complaints, (*ctx->k0p_shares), &wptr);
  if(ret != TOPRF_Update_Err_OK) return ret;

  if(0!=toprf_send_msg(output, output_len, toprfupdate_peer_vsps_disclose_msg, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;

  ctx->step = TOPRF_Update_Peer_Reconstruct_VSPS_Shares;
  return TOPRF_Update_Err_OK;
}

static int vss_reshare(const uint8_t n,
                       const uint8_t threshold,
                       const uint8_t *prk,
                       const uint8_t secret[crypto_core_ristretto255_SCALARBYTES],
                       TOPRF_Share shares[n][2],
                       uint8_t commitments[n][crypto_core_ristretto255_BYTES],
                       uint8_t blind[crypto_core_ristretto255_SCALARBYTES]) {
  if(threshold==0) return 1;
  if(secret==NULL) return 1;
  uint8_t a[threshold][crypto_core_ristretto255_SCALARBYTES];
  uint8_t b[threshold][crypto_core_ristretto255_SCALARBYTES];
  memcpy(a[0], secret, crypto_core_ristretto255_SCALARBYTES);

  // todo inlude also the idx of the dealer in the ctx.
  char share_ctx[] = "k0p lambda * a * b re-sharing";
  char blind_ctx[] = "k0p blind re-sharing";

  for(int k=0;k<threshold;k++) {
    uint8_t random[64];
    if(k!=0) {
      crypto_kdf_hkdf_sha256_expand(random, sizeof random, share_ctx, sizeof(share_ctx) - 1, prk);
      crypto_core_ristretto255_scalar_reduce(a[k], random);
    }
    crypto_kdf_hkdf_sha256_expand(random, sizeof random, blind_ctx, sizeof(blind_ctx) - 1, prk);
    crypto_core_ristretto255_scalar_reduce(b[k], random);
  }

  if(blind!=NULL) {
    memcpy(blind, b[0], crypto_core_ristretto255_SCALARBYTES);
  }

  for(uint8_t j=1;j<=n;j++) {
    //f(x) = a_0 + a_1*x + a_2*x^2 + a_3*x^3 + ⋯ + a_(t)*x^(t)
    polynom(j, threshold, a, &shares[j-1][0]);
    //f'(x) = b_0 + b_1*x + b_2*x^2 + b_3*x^3 + ⋯ + b_(t)*x^(t)
    polynom(j, threshold, b, &shares[j-1][1]);

    if(0!=dkg_vss_commit(shares[j-1][0].value, shares[j-1][1].value, commitments[j-1])) return 1;
  }

  return 0;
}

static TOPRF_Update_Err stp_reshare(TOPRF_Update_STPState *ctx
                                ,const uint16_t complaints_len
                                ,const uint16_t complaints[complaints_len]
                                ,const TOPRF_Share shares[complaints_len][ctx->n][2]
                                ,uint8_t (*commitments)[][crypto_core_ristretto255_BYTES]) {
  if(complaints_len==0) return TOPRF_Update_Err_OK;

  uint8_t secrets[complaints_len][2][crypto_core_ristretto255_SCALARBYTES];
  TOPRF_Update_Err ret;
  ret = reconstruct(ctx->n, ctx->t, "k0p", complaints_len,complaints, shares, commitments, secrets);
  if(ret != TOPRF_Update_Err_OK) return ret;

  TOPRF_Share reshares[ctx->n][2];
  for(unsigned i=0;i<complaints_len;i++) {
    if(vss_reshare(ctx->n, ctx->t, ctx->sessionid, secrets[i][0], reshares, &(*commitments)[1], secrets[i][1])) return TOPRF_Update_Err_VSSShare;
    if(0!=dkg_vss_commit(secrets[i][0], secrets[i][1], (*commitments)[0])) return 1;

    int _debug=liboprf_debug; liboprf_debug=0;
    if(0!=toprf_mpc_vsps_check(ctx->t-1, (*commitments))) {
      if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[!] VSPS asdfasdf failed k0p\n"NORMAL);
    }
    liboprf_debug=_debug;
    dump((uint8_t*) (*commitments), (ctx->n+1U)*crypto_core_ristretto255_BYTES, "reshared k0p commitments");
  }
  return TOPRF_Update_Err_OK;
}

#define toprfupdate_stp_bc_vsps_disclose_msg_SIZE(ctx) (sizeof(TOPRF_Update_Message) + (toprfupdate_peer_vsps_disclose_msg_SIZE(ctx) * ctx->n))
static TOPRF_Update_Err stp_bc_vsps_disclosures(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  TOPRF_Update_Err ret;
  ret = stp_broadcast(ctx, input, input_len, output, output_len,
                      "final-reconst2 broadcast shares of dealers failing vsps check",
                      ctx->n, toprfupdate_peer_vsps_disclose_msg_SIZE(ctx), toprfupdate_peer_vsps_disclose_msg, TOPRF_Update_STP_Reconstruct_Delta);
  if(ret != TOPRF_Update_Err_OK) return ret;

  TOPRF_Share k0p_shares[ctx->p_complaints_len][ctx->n][2];
  const uint8_t *ptr = input;
  for(uint8_t i=0;i<ctx->n;i++,ptr+=toprfupdate_peer_vsps_disclose_msg_SIZE(ctx)) {
    const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) ptr;
    const uint8_t *dptr = msg->data;
    for(unsigned j=0;j<ctx->p_complaints_len;j++) {
      memcpy(k0p_shares[j][msg->from-1], dptr, TOPRF_Share_BYTES*2);
      dptr+=TOPRF_Share_BYTES*2;
    }
  }

  ret = stp_reshare(ctx, ctx->p_complaints_len, ctx->p_complaints, k0p_shares, ctx->k0p_commitments);
  if(ret!=TOPRF_Update_Err_OK) return ret;

  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);
  uint8_t (*c)[dealers][ctx->n+1][crypto_core_ristretto255_BYTES] = (uint8_t (*)[dealers][ctx->n+1][crypto_core_ristretto255_BYTES]) ctx->k0p_commitments;
  for(unsigned i=0;i<ctx->n;i++) {
    memcpy((*ctx->k0p_final_commitments)[i], (*c)[0][i+1], crypto_scalarmult_ristretto255_BYTES);
    for(unsigned j=1;j<dealers;j++) {
      crypto_core_ristretto255_add((*ctx->k0p_final_commitments)[i], (*ctx->k0p_final_commitments)[i], (*c)[j][i+1]);
    }
  }

  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err peer_reshare(TOPRF_Update_PeerState *ctx
                                     ,uint16_t *complaints_len
                                     ,uint16_t complaints[*complaints_len]
                                     ,const TOPRF_Share shares[*complaints_len][ctx->n][2]
                                     ,TOPRF_Share my_shares[(ctx->t-1)*2+1][2]
                                     ,TOPRF_Share my_share[2]
                                     ,uint8_t (*commitments)[][crypto_core_ristretto255_BYTES]) {
  if(*complaints_len==0) return TOPRF_Update_Err_OK;

  uint8_t secrets[*complaints_len][2][crypto_core_ristretto255_SCALARBYTES];
  TOPRF_Update_Err ret;
  ret = reconstruct(ctx->n, ctx->t, "k0p", *complaints_len, complaints, shares, commitments, secrets);
  if(ret != TOPRF_Update_Err_OK) return ret;

  TOPRF_Share reshares[ctx->n][2];
  for(unsigned i=0;i<*complaints_len;i++) {
    if(vss_reshare(ctx->n, ctx->t, ctx->sessionid, secrets[i][0], reshares, &(*commitments)[1], secrets[i][1])) return TOPRF_Update_Err_VSSShare;
    if(0!=dkg_vss_commit(secrets[i][0], secrets[i][1], (*commitments)[0])) return 1;

    int _debug=liboprf_debug; liboprf_debug=0;
    if(0!=toprf_mpc_vsps_check(ctx->t-1, (*commitments))) {
      if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[!] VSPS asdfasdf failed k0p\n"NORMAL);
    }
    liboprf_debug=_debug;
    dump((uint8_t*) (*commitments), (ctx->n+1U)*crypto_core_ristretto255_BYTES, "reshared k0p commitments");

    const uint8_t accused = (uint8_t) (complaints[i] & 0xff);
    memcpy(my_shares[accused-1], reshares[ctx->index-1], sizeof(TOPRF_Share)*2);
  }

  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);
  uint8_t commitment[crypto_scalarmult_ristretto255_BYTES];
  if(*complaints_len>0) {
    ret = compute_mul_share(dealers, my_shares, my_share, commitment);
    if(ret!=TOPRF_Update_Err_OK) return ret;
  }

  *complaints_len = 0;
  memset(complaints, 0, ctx->n*2);
  return TOPRF_Update_Err_OK;
}

static int peer_step44_handler(TOPRF_Update_PeerState *ctx, uint8_t *output, const size_t output_len);
static TOPRF_Update_Err peer_reconst_vsps_shares(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] final-reconst3 reconstruct secrets of dealers failing VSPS check\x1b[0m\n", ctx->index);
  if(input_len!= sizeof(TOPRF_Update_Message) + toprfupdate_peer_zk_disclose_msg_SIZE(ctx) * ctx->n) return TOPRF_Update_Err_ISize;

  // verify STP message envelope
  const uint8_t *ptr=NULL;
  int ret = unwrap_envelope(ctx,input,input_len,toprfupdate_stp_bc_vsps_disclose_msg,&ptr);
  if(ret!=TOPRF_Update_Err_OK) return ret;

  TOPRF_Share k0p_shares[ctx->p_complaints_len][ctx->n][2];
  for(uint8_t i=0;i<ctx->n;i++,ptr+=toprfupdate_peer_vsps_disclose_msg_SIZE(ctx)) {
    const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprfupdate_peer_vsps_disclose_msg_SIZE(ctx),toprfupdate_peer_vsps_disclose_msg,i+1,0xff)) continue;
    const uint8_t *dptr = msg->data;
    for(unsigned j=0;j<ctx->p_complaints_len;j++) {
      memcpy(k0p_shares[j][msg->from-1], dptr, TOPRF_Share_BYTES*2);
      dptr+=TOPRF_Share_BYTES*2;
    }
  }

  ret = peer_reshare(ctx, &ctx->p_complaints_len, ctx->p_complaints, k0p_shares, (*ctx->k0p_shares), ctx->k0p_share, ctx->k0p_commitments);
  if(ret!=TOPRF_Update_Err_OK) return ret;

  // reset my_complaints
  ctx->my_p_complaints_len = 0;
  memset(ctx->my_p_complaints, 0, ctx->n);

  return peer_step44_handler(ctx, output, output_len);
}

#define toprfupdate_peer_end2_msg_SIZE (sizeof(TOPRF_Update_Message) + 2 * TOPRF_Share_BYTES)
static int peer_step44_handler(TOPRF_Update_PeerState *ctx, uint8_t *output, const size_t output_len) {
  // todo maybe check the global transcript before sending the r & r' shares to stp?
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] final4 send final shared p to STP\x1b[0m\n", ctx->index);
  if(output_len != toprfupdate_peer_end2_msg_SIZE) return TOPRF_Update_Err_OSize;

  TOPRF_Update_Message* msg41 = (TOPRF_Update_Message*) output;
  memcpy(msg41->data, (uint8_t*) ctx->p_share, 2*TOPRF_Share_BYTES);

  if(0!=toprf_send_msg(output, toprfupdate_peer_end2_msg_SIZE, toprfupdate_peer_end2_msg, ctx->index, 0, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;

  ctx->step = TOPRF_Update_Peer_Final_OK;
  return TOPRF_Update_Err_OK;
}

#define toprfupdate_stp_bc_end3_msg_SIZE (sizeof(TOPRF_Update_Message) + 1)
static int stp_step45_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[!] final5. reconstruct delta\x1b[0m\n");
  if(input_len != ctx->n * toprfupdate_peer_end2_msg_SIZE) return TOPRF_Update_Err_ISize;
  if(output_len != toprfupdate_stp_bc_end3_msg_SIZE) return TOPRF_Update_Err_OSize;
  const size_t cheaters = ctx->cheater_len;

  const uint8_t *ptr = input;
  TOPRF_Share p_shares[ctx->n][2];
  for(uint8_t i=0;i<ctx->n;i++,ptr+=toprfupdate_peer_end2_msg_SIZE) {
    const TOPRF_Update_Message *msg = (const TOPRF_Update_Message *) ptr;
    if(stp_recv_msg(ctx,ptr,toprfupdate_peer_end2_msg_SIZE, toprfupdate_peer_end2_msg,i+1,0)) continue;
    memcpy(p_shares[i],msg->data,2*TOPRF_Share_BYTES);
  }
  if(ctx->cheater_len>cheaters) return TOPRF_Update_Err_CheatersFound;

  TOPRF_Update_Message *outmsg = (TOPRF_Update_Message *) output;
  uint8_t *fail=outmsg->data;
  *fail = 0;

  int _debug=liboprf_debug; liboprf_debug=0;
  if(0!=toprf_mpc_vsps_check(ctx->t-1, (*ctx->p_commitments))) {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[!] VSPS failed k0p\n"NORMAL);
    *fail=1;
  }
  liboprf_debug=_debug;

  for(unsigned i=0;i<ctx->n;i++) {
    if(0!=dkg_vss_verify_commitment((*ctx->p_commitments)[i], p_shares[i])) {
      if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[!] failed to verify commitment for p share %d\n"NORMAL, i+1);
      dump((*ctx->p_commitments)[i], crypto_scalarmult_ristretto255_BYTES, "[!] C[%d]", i+1);
      dump((uint8_t*) p_shares[i], 2*TOPRF_Share_BYTES, "[!] s[%d]", i+1);
      *fail=1;
    }
  }

  if(*fail == 0) {
    // reconstruct delta
    dkg_vss_reconstruct(ctx->t, 0, ctx->n, p_shares, (*ctx->p_commitments), ctx->delta, NULL);
    dump(ctx->delta, crypto_scalarmult_ristretto255_SCALARBYTES, "[!] ∆");
  }

  if(0!=toprf_send_msg(output, output_len, toprfupdate_stp_end3_msg, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return TOPRF_Update_Err_Send;

  ctx->step = TOPRF_Update_STP_Done;
  return TOPRF_Update_Err_OK;
}

static TOPRF_Update_Err peer_step46_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;33m[%d] final6. receive final confirmation from STP\x1b[0m\n", ctx->index);
  if(input_len != toprfupdate_stp_bc_end3_msg_SIZE) return TOPRF_Update_Err_ISize;

  // verify STP message envelope
  const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) input;
  int ret = toprf_recv_msg(input, input_len, toprfupdate_stp_end3_msg, 0, 0xff, (*ctx->sig_pks)[0], ctx->sessionid, ctx->ts_epsilon, &ctx->stp_last_ts);
  if(0!=ret) return TOPRF_Update_Err_BroadcastEnv+ret;

  if(msg->data[0]!=0) {
      if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"[%d] STP indicated failure at final step discarding all results, keeping old key\n"NORMAL, ctx->index);
      return TOPRF_Update_Err_Proto;
  } else {
      if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "\x1b[0;32m[%d] STP indicated full success updating old key to new key\n"NORMAL, ctx->index);
  }

  ctx->step = TOPRF_Update_Peer_Done;
  return TOPRF_Update_Err_OK;
}

int toprf_update_stp_not_done(const TOPRF_Update_STPState *stp) {
  return stp->step<TOPRF_Update_STP_Done;
}

int toprf_update_peer_not_done(const TOPRF_Update_PeerState *peer) {
  return peer->step<TOPRF_Update_Peer_Done;
}

void toprf_update_peer_free(TOPRF_Update_PeerState *ctx) {
  for(int i=0;i<ctx->n;i++) {
    if((*ctx->noise_ins)[i]!=NULL) Noise_XK_session_free((*ctx->noise_ins)[i]);
    if((*ctx->noise_outs)[i]!=NULL) Noise_XK_session_free((*ctx->noise_outs)[i]);
  }
  if(ctx->dev!=NULL) Noise_XK_device_free(ctx->dev);
}

size_t toprf_update_stp_input_size(const TOPRF_Update_STPState *ctx) {
  size_t sizes[ctx->n];
  memset(sizes,0,sizeof sizes);
  if(toprf_update_stp_input_sizes(ctx, sizes) == 1) {
    return sizes[0] * ctx->n;
  } else {
    size_t result=0;
    for(int i=0;i<ctx->n;i++) result+=sizes[i];
    return result;
  }
}

int toprf_update_stp_input_sizes(const TOPRF_Update_STPState *ctx, size_t *sizes) {
  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);
  size_t item=0;
  switch(ctx->step) {
  case TOPRF_Update_STP_Broadcast_NPKs: { item=toprfupdate_peer_init_msg_SIZE; break; }
  case TOPRF_Update_STP_Route_Noise_Handshakes1: { item=toprfupdate_peer_ake1_msg_SIZE * ctx->n; break; }
  case TOPRF_Update_STP_Route_Noise_Handshakes2: { item=toprfupdate_peer_ake2_msg_SIZE * ctx->n; break; }
  case TOPRF_Update_STP_Broadcast_DKG_Hash_Commitments: { item = toprfupdate_peer_dkg1_msg_SIZE(ctx); break; }
  case TOPRF_Update_STP_Broadcast_DKG_Commitments: { item = toprfupdate_peer_dkg2_msg_SIZE(ctx); break; }
  case TOPRF_Update_STP_Route_Encrypted_Shares: { item = toprfupdate_peer_dkg3_msg_SIZE * ctx->n; break; }
  case TOPRF_Update_STP_Broadcast_Complaints: { item = toprfupdate_peer_verify_shares_msg_SIZE(ctx); break; }
  case TOPRF_Update_STP_Broadcast_DKG_Defenses: {
    uint8_t ctr1[ctx->n];
    memset(ctr1,0,ctx->n);
    for(int i=0;i<ctx->p_complaints_len;i++) {
      const uint8_t peer = (uint8_t) ((ctx->p_complaints[i] & 0xff) - 1U);
      if(peer>=ctx->n) return TOPRF_Update_Err_OOB;
      ctr1[peer]++;
    }
    for(int i=0;i<ctx->n;i++) {
      if(ctr1[i]>0) {
        sizes[i]=sizeof(TOPRF_Update_Message) \
                  + (1+dkg_noise_key_SIZE+toprf_update_encrypted_shares_SIZE) * ctr1[i];
      } else {
        sizes[i]=0;
      }
    }
    return 0;
  }
  case TOPRF_Update_STP_Broadcast_DKG_Transcripts: { item = toprfupdate_peer_bc_transcript_msg_SIZE; break; }
  case TOPRF_Update_STP_Route_Mult_Step1: {
    for(uint8_t i=0;i<ctx->n;i++) {
      sizes[i] = isdealer(i+1, ctx->t) * toprfupdate_peer_mult1_msg_SIZE(ctx);
    }
    return 0;
  }
  case TOPRF_Update_STP_Broadcast_Mult_Commitments: {
    for(uint8_t i=0;i<ctx->n;i++) {
      sizes[i] = isdealer(i+1, ctx->t) * toprfupdate_peer_mult_coms_msg_SIZE(ctx);
    }
    return 0;
  }
  case TOPRF_Update_STP_Route_Encrypted_Mult_Shares: {
    for(uint8_t i=0;i<ctx->n;i++) {
      sizes[i] = isdealer(i+1, ctx->t) * (toprfupdate_peer_mult2_msg_SIZE * ctx->n);
    }
    return 0;
  }
  case TOPRF_Update_STP_Broadcast_Mult_Complaints: { item = toprfupdate_peer_verify_mult_shares_msg_SIZE(ctx); break; }
  case TOPRF_Update_STP_Broadcast_Mult_Defenses: {
    uint8_t ctr1[dealers];
    memset(ctr1,0,sizeof ctr1);
    for(int i=0;i<ctx->p_complaints_len;i++) {
      const uint8_t peer = (uint8_t) ((ctx->p_complaints[i] & 0xff) - 1U);
      if(peer>=dealers) return TOPRF_Update_Err_OOB;
      ctr1[peer]++;
    }
    for(int i=0;i<ctx->n;i++) {
      if(i<dealers && (ctr1[i]>0)) {
        sizes[i]=sizeof(TOPRF_Update_Message) \
                  + (1+dkg_noise_key_SIZE+toprf_update_encrypted_shares_SIZE) * ctr1[i];
      } else {
        sizes[i]=0;
      }
    }
    return 0;
  }
  case TOPRF_Update_STP_Broadcast_Reconst_Mult_Shares: { item = toprfupdate_stp_reconst_mult_shares_msg_SIZE(ctx); break; }

  case TOPRF_Update_STP_Route_ZK_Challenge_Commitments: { item = toprfupdate_peer_zkp1_msg_SIZE; break; }
  case TOPRF_Update_STP_Route_ZK_commitments: {
    for(uint8_t i=0;i<ctx->n;i++) {
      sizes[i] = isdealer(i+1, ctx->t) * toprfupdate_peer_zkp2_msg_SIZE;
    }
    return 0;
  }
  case TOPRF_Update_STP_Broadcast_ZK_nonces: { item = toprfupdate_peer_zkp3_msg_SIZE; break; }
  case TOPRF_Update_STP_Broadcast_ZK_Proofs: {
    for(uint8_t i=0;i<ctx->n;i++) {
      sizes[i] = isdealer(i+1, ctx->t) * toprfupdate_peer_zkp4_msg_SIZE;
    }
    return 0;
  }
  case TOPRF_Update_STP_Broadcast_ZK_Disclosures: { item = toprfupdate_peer_zk_disclose_msg_SIZE(ctx); break; }
  case TOPRF_Update_STP_Broadcast_Mult_Ci: { item = toprfupdate_peer_mult3_msg_SIZE; break; }
  case TOPRF_Update_STP_Broadcast_VSPS_Disclosures: { item = toprfupdate_peer_vsps_disclose_msg_SIZE(ctx); break; }
  case TOPRF_Update_STP_Reconstruct_Delta: { item = toprfupdate_peer_end2_msg_SIZE; break; }
  default: {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "[!] isize invalid stp step: %d\n", ctx->step);
  }
  }

  for(uint8_t i=0;i<ctx->n;i++) {
    sizes[i] = item;
  }
  return 1;
}

size_t toprf_update_stp_output_size(const TOPRF_Update_STPState *ctx) {
  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);
  switch(ctx->step) {
  case TOPRF_Update_STP_Broadcast_NPKs: return toprfupdate_peer_init_msg_SIZE * ctx->n + sizeof(TOPRF_Update_Message);
  case TOPRF_Update_STP_Route_Noise_Handshakes1: return toprfupdate_peer_ake1_msg_SIZE * ctx->n * ctx->n;
  case TOPRF_Update_STP_Route_Noise_Handshakes2: return toprfupdate_peer_ake2_msg_SIZE * ctx->n * ctx->n;

  case TOPRF_Update_STP_Broadcast_DKG_Hash_Commitments: return sizeof(TOPRF_Update_Message) + (toprfupdate_peer_dkg1_msg_SIZE(ctx) * ctx->n);
  case TOPRF_Update_STP_Broadcast_DKG_Commitments: return sizeof(TOPRF_Update_Message) + (toprfupdate_peer_dkg2_msg_SIZE(ctx) * ctx->n);

  case TOPRF_Update_STP_Route_Encrypted_Shares: return toprfupdate_peer_dkg3_msg_SIZE * ctx->n * ctx->n;
  case TOPRF_Update_STP_Broadcast_Complaints: return toprfupdate_stp_bc_verify_shares_msg_SIZE(ctx);
  case TOPRF_Update_STP_Broadcast_DKG_Defenses: return sizeof(TOPRF_Update_Message) + toprf_update_stp_input_size(ctx);
  case TOPRF_Update_STP_Broadcast_DKG_Transcripts: return toprfupdate_stp_bc_transcript_msg_SIZE(ctx);

  case TOPRF_Update_STP_Route_Mult_Step1: return sizeof(TOPRF_Update_Message) + toprfupdate_peer_mult1_msg_SIZE(ctx) * dealers;
  case TOPRF_Update_STP_Broadcast_Mult_Commitments: return sizeof(TOPRF_Update_Message) + toprfupdate_peer_mult_coms_msg_SIZE(ctx) * dealers;
  case TOPRF_Update_STP_Broadcast_Mult_Complaints: return toprfupdate_stp_bc_verify_mult_shares_msg_SIZE(ctx);
  case TOPRF_Update_STP_Broadcast_Mult_Defenses: return sizeof(TOPRF_Update_Message) + toprf_update_stp_input_size(ctx);
  case TOPRF_Update_STP_Broadcast_Reconst_Mult_Shares: return sizeof(TOPRF_Update_Message) + toprfupdate_stp_reconst_mult_shares_msg_SIZE(ctx) * ctx->n;

  case TOPRF_Update_STP_Route_Encrypted_Mult_Shares: return (toprfupdate_peer_mult2_msg_SIZE * ctx->n) * dealers;
  case TOPRF_Update_STP_Route_ZK_Challenge_Commitments: return sizeof(TOPRF_Update_Message) + (toprfupdate_peer_zkp1_msg_SIZE * ctx->n);
  case TOPRF_Update_STP_Route_ZK_commitments: return sizeof(TOPRF_Update_Message) + toprfupdate_peer_zkp2_msg_SIZE * dealers;
  case TOPRF_Update_STP_Broadcast_ZK_nonces: return sizeof(TOPRF_Update_Message) + toprfupdate_peer_zkp3_msg_SIZE * ctx->n;
  case TOPRF_Update_STP_Broadcast_ZK_Proofs: return sizeof(TOPRF_Update_Message) + toprfupdate_peer_zkp4_msg_SIZE * dealers;
  case TOPRF_Update_STP_Broadcast_ZK_Disclosures: return toprfupdate_stp_bc_zkp_disclose_msg_SIZE(ctx);
  case TOPRF_Update_STP_Broadcast_Mult_Ci: return toprfupdate_stp_bc_mult3_msg_SIZE(ctx);
  case TOPRF_Update_STP_Broadcast_VSPS_Disclosures: return toprfupdate_stp_bc_vsps_disclose_msg_SIZE(ctx);
  case TOPRF_Update_STP_Reconstruct_Delta: return toprfupdate_stp_bc_end3_msg_SIZE;
  default: if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "[!] osize invalid stp step: %d\n", ctx->step);
  }
  return 0;
}

int toprf_update_stp_peer_msg(const TOPRF_Update_STPState *ctx, const uint8_t *base, const size_t base_size, const uint8_t peer, const uint8_t **msg, size_t *len) {
  if(peer>=ctx->n) return -1;
  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);

  switch(ctx->prev) {
  case TOPRF_Update_STP_Broadcast_NPKs: {
    *msg = base;
    *len = toprfupdate_peer_init_msg_SIZE * ctx->n + sizeof(TOPRF_Update_Message);
    break;
  }
  case TOPRF_Update_STP_Route_Noise_Handshakes1: {
    *msg = base + peer * toprfupdate_peer_ake1_msg_SIZE * ctx->n;
    *len = toprfupdate_peer_ake1_msg_SIZE * ctx->n;
    break;
  }
  case TOPRF_Update_STP_Route_Noise_Handshakes2: {
    *msg = base + peer * toprfupdate_peer_ake2_msg_SIZE * ctx->n;
    *len = toprfupdate_peer_ake1_msg_SIZE * ctx->n;
    break;
  }
  case TOPRF_Update_STP_Broadcast_DKG_Hash_Commitments: {
    *msg = base;
    *len = sizeof(TOPRF_Update_Message) + (toprfupdate_peer_dkg1_msg_SIZE(ctx) * ctx->n);
    break;
  }
  case TOPRF_Update_STP_Broadcast_DKG_Commitments: {
    *msg = base;
    *len = sizeof(TOPRF_Update_Message) + (toprfupdate_peer_dkg2_msg_SIZE(ctx) * ctx->n);
    break;
  }
  case TOPRF_Update_STP_Route_Encrypted_Shares: {
    *msg = base + peer * toprfupdate_peer_dkg3_msg_SIZE * ctx->n;
    *len = toprfupdate_peer_dkg3_msg_SIZE * ctx->n;
    break;
  }
  case TOPRF_Update_STP_Broadcast_Complaints: {
    *msg = base;
    *len = toprfupdate_stp_bc_verify_shares_msg_SIZE(ctx);
    break;
  }
  case TOPRF_Update_STP_Broadcast_DKG_Defenses: {
    *msg = base;
    *len = sizeof(TOPRF_Update_Message);
    uint8_t ctr1[ctx->n];
    memset(ctr1,0,sizeof ctr1);
    for(int i=0;i<ctx->p_complaints_len;i++) {
      const uint8_t peer = (uint8_t) ((ctx->p_complaints[i] & 0xff) - 1U);
      if(peer>=ctx->n) return TOPRF_Update_Err_OOB;
      ctr1[peer]++;
    }
    for(int i=0;i<ctx->n;i++) {
      if(ctr1[i]>0) {
        *len+=sizeof(TOPRF_Update_Message) \
              + (1+dkg_noise_key_SIZE+toprf_update_encrypted_shares_SIZE) * ctr1[i];
      }
    }
    break;
  }
  case TOPRF_Update_STP_Broadcast_DKG_Transcripts: {
    *msg = base;
    *len = toprfupdate_stp_bc_transcript_msg_SIZE(ctx);
    break;
  }
  case TOPRF_Update_STP_Route_Mult_Step1: {
    *msg = base;
    *len = sizeof(TOPRF_Update_Message) + toprfupdate_peer_mult1_msg_SIZE(ctx) * dealers;
    break;
  }
  case TOPRF_Update_STP_Broadcast_Mult_Commitments: {
    *msg = base;
    *len = sizeof(TOPRF_Update_Message) + toprfupdate_peer_mult_coms_msg_SIZE(ctx) * dealers;
    break;
  }
  case TOPRF_Update_STP_Route_Encrypted_Mult_Shares: {
    *msg = base + peer * toprfupdate_peer_mult2_msg_SIZE * ((ctx->t-1U)*2 + 1U);
    *len = toprfupdate_peer_mult2_msg_SIZE * ((ctx->t-1U)*2 + 1U);
    break;
  }

  case TOPRF_Update_STP_Broadcast_Mult_Complaints: {
    *msg = base;
    *len = toprfupdate_stp_bc_verify_mult_shares_msg_SIZE(ctx);
    break;
  }
  case TOPRF_Update_STP_Broadcast_Mult_Defenses: {
    *msg = base;
    *len = sizeof(TOPRF_Update_Message);
    uint8_t ctr1[dealers];
    memset(ctr1,0,sizeof ctr1);
    for(int i=0;i<ctx->p_complaints_len;i++) {
      const uint8_t peer = (uint8_t) ((ctx->p_complaints[i] & 0xff) - 1U);
      if(peer>=dealers) return TOPRF_Update_Err_OOB;
      ctr1[peer]++;
    }
    for(int i=0;i<dealers;i++) {
      if(ctr1[i]>0) {
        *len+=sizeof(TOPRF_Update_Message) \
              + (1+dkg_noise_key_SIZE+toprf_update_encrypted_shares_SIZE) * ctr1[i];
      }
    }
    break;
  }
  case TOPRF_Update_STP_Broadcast_Reconst_Mult_Shares: {
    *msg = base;
    *len = sizeof(TOPRF_Update_Message) + toprfupdate_stp_reconst_mult_shares_msg_SIZE(ctx) * ctx->n;
    break;
  }

  case TOPRF_Update_STP_Route_ZK_Challenge_Commitments: {
    *msg = base;
    *len = sizeof(TOPRF_Update_Message) + (toprfupdate_peer_zkp1_msg_SIZE * ctx->n);
    break;
  }
  case TOPRF_Update_STP_Route_ZK_commitments: {
    *msg = base;
    *len = sizeof(TOPRF_Update_Message) + toprfupdate_peer_zkp2_msg_SIZE * dealers;
    break;
  }
  case TOPRF_Update_STP_Broadcast_ZK_nonces: {
    *msg = base;
    *len = sizeof(TOPRF_Update_Message) + toprfupdate_peer_zkp3_msg_SIZE * ctx->n;
    break;
  }
  case TOPRF_Update_STP_Broadcast_ZK_Proofs: {
    *msg = base;
    *len = sizeof(TOPRF_Update_Message) + toprfupdate_peer_zkp4_msg_SIZE * dealers;
    break;
  }
  case TOPRF_Update_STP_Broadcast_ZK_Disclosures: {
    *msg = base;
    *len = toprfupdate_stp_bc_zkp_disclose_msg_SIZE(ctx);
    break;
  }
  case TOPRF_Update_STP_Broadcast_Mult_Ci: {
    *msg = base;
    *len = toprfupdate_stp_bc_mult3_msg_SIZE(ctx);
    break;
  }
  case TOPRF_Update_STP_Broadcast_VSPS_Disclosures: {
    *msg = base;
    *len = toprfupdate_stp_bc_vsps_disclose_msg_SIZE(ctx);
    break;
  }
  case TOPRF_Update_STP_Reconstruct_Delta: {
    *msg = base;
    *len = toprfupdate_stp_bc_end3_msg_SIZE;
    break;
  }
  default: {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "[!] invalid stp step in toprf_update_stp_peer_msg\n");
    return 1;
  }
  }

  if(base+base_size < *msg + *len) {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "buffer overread detected in toprf_update_stp_peer_msg %ld\n", (base+base_size) - (*msg + *len));
    return 2;
  }

  return 0;
}

size_t toprf_update_peer_input_size(const TOPRF_Update_PeerState *ctx) {
  const uint8_t dealers = (uint8_t) ((ctx->t-1U)*2 + 1U);
  switch(ctx->step) {
  case TOPRF_Update_Peer_Broadcast_NPK_SIDNonce: return 0;
  case TOPRF_Update_Peer_Rcv_NPK_SIDNonce: return toprfupdate_peer_init_msg_SIZE * ctx->n + sizeof(TOPRF_Update_Message);
  case TOPRF_Update_Peer_Noise_Handshake: return toprfupdate_peer_ake1_msg_SIZE * ctx->n;
  case TOPRF_Update_Peer_Finish_Noise_Handshake: return toprfupdate_peer_ake2_msg_SIZE * ctx->n;
  case TOPRF_Update_Peer_Rcv_CHashes_Send_Commitments: return sizeof(TOPRF_Update_Message) + (toprfupdate_peer_dkg1_msg_SIZE(ctx) * ctx->n);
  case TOPRF_Update_Peer_Rcv_Commitments_Send_Shares: return sizeof(TOPRF_Update_Message) + (toprfupdate_peer_dkg2_msg_SIZE(ctx) * ctx->n);
  case TOPRF_Update_Peer_Verify_Commitments: return  ctx->n * toprfupdate_peer_dkg3_msg_SIZE;
  case TOPRF_Update_Peer_Finish_DKG: return 0;
  case TOPRF_Update_Peer_Handle_DKG_Complaints: return toprfupdate_stp_bc_verify_shares_msg_SIZE(ctx);
  case TOPRF_Update_Peer_Defend_DKG_Accusations: return 0;
  case TOPRF_Update_Peer_Check_Shares: {
    uint8_t ctr1[ctx->n];
    memset(ctr1,0,ctx->n);
    for(int i=0;i<ctx->p_complaints_len;i++) {
      const uint8_t peer = (uint8_t) ((ctx->p_complaints[i] & 0xff) - 1U);
      if(peer>=ctx->n) return TOPRF_Update_Err_OOB;
      ctr1[peer]++;
    }
    size_t ret = sizeof(TOPRF_Update_Message);
    for(int i=0;i<ctx->n;i++) {
      if(ctr1[i]>0) {
        ret+=sizeof(TOPRF_Update_Message) \
             + (1U+dkg_noise_key_SIZE+toprf_update_encrypted_shares_SIZE) * ctr1[i];
      }
    }
    return ret;
  }
  case TOPRF_Update_Peer_Confirm_Transcripts: return toprfupdate_stp_bc_transcript_msg_SIZE(ctx);
  case TOPRF_Update_Peer_Rcv_Mult_CHashes_Send_Commitments: return sizeof(TOPRF_Update_Message) + toprfupdate_peer_mult1_msg_SIZE(ctx) * dealers;
  case TOPRF_Update_Peer_Send_K0P_Shares: return sizeof(TOPRF_Update_Message) + toprfupdate_peer_mult_coms_msg_SIZE(ctx) * dealers;
  case TOPRF_Update_Peer_Recv_K0P_Shares: return toprfupdate_peer_mult2_msg_SIZE * dealers;
  case TOPRF_Update_Peer_Handle_Mult_Share_Complaints: return toprfupdate_stp_bc_verify_mult_shares_msg_SIZE(ctx);
  case TOPRF_Update_Peer_Defend_Mult_Accusations: return 0;
  case TOPRF_Update_Peer_Check_Mult_Shares: {
    uint8_t ctr1[dealers];
    memset(ctr1,0,sizeof ctr1);
    for(int i=0;i<ctx->p_complaints_len;i++) {
      const uint8_t peer = (uint8_t) ((ctx->p_complaints[i] & 0xff) - 1U);
      if(peer>=dealers) return TOPRF_Update_Err_OOB;
      ctr1[peer]++;
    }
    size_t ret = sizeof(TOPRF_Update_Message);
    for(int i=0;i<dealers;i++) {
      if(ctr1[i]>0) {
        ret+=sizeof(TOPRF_Update_Message) \
             + (1U+dkg_noise_key_SIZE+toprf_update_encrypted_shares_SIZE) * ctr1[i];
      }
    }
    return ret;
  }
  case TOPRF_Update_Peer_Disclose_Mult_Shares: return 0;
  case TOPRF_Update_Peer_Reconstruct_Mult_Shares: return sizeof(TOPRF_Update_Message) + toprfupdate_peer_reconst_mult_shares_msg_SIZE(ctx) * ctx->n;
  case TOPRF_Update_Peer_Send_ZK_Challenge_Commitments: return 0;

  case TOPRF_Update_Peer_Send_ZK_Commitments: return sizeof(TOPRF_Update_Message) + toprfupdate_peer_zkp1_msg_SIZE * ctx->n;
  case TOPRF_Update_Peer_Send_ZK_nonces: return sizeof(TOPRF_Update_Message) + toprfupdate_peer_zkp2_msg_SIZE * dealers;
  case TOPRF_Update_Peer_Send_ZK_proofs: return sizeof(TOPRF_Update_Message) + toprfupdate_peer_zkp3_msg_SIZE * ctx->n;
  case TOPRF_Update_Peer_Verify_ZK_proofs: return sizeof(TOPRF_Update_Message) + toprfupdate_peer_zkp4_msg_SIZE * dealers;
  case TOPRF_Update_Peer_Disclose_ZK_Cheaters: return 0;
  case TOPRF_Update_Peer_Reconstruct_ZK_Shares: return sizeof(TOPRF_Update_Message) + toprfupdate_peer_zk_disclose_msg_SIZE(ctx) * ctx->n;
  case TOPRF_Update_Peer_Send_Mult_Ci: return 0;
  case TOPRF_Update_Peer_Final_VSPS_Checks: return toprfupdate_stp_bc_mult3_msg_SIZE(ctx);
  case TOPRF_Update_Peer_Disclose_VSPS_Cheaters: return 0;
  case TOPRF_Update_Peer_Reconstruct_VSPS_Shares: return sizeof(TOPRF_Update_Message) + toprfupdate_peer_vsps_disclose_msg_SIZE(ctx) * ctx->n;
  case TOPRF_Update_Peer_Send_k0p_Share: return 0;
  case TOPRF_Update_Peer_Final_OK: return toprfupdate_stp_bc_end3_msg_SIZE;
  default: {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "[%d] peer input size invalid step\n", ctx->index);
  }
  }
  return 1;
}

size_t toprf_update_peer_output_size(const TOPRF_Update_PeerState *ctx) {
  switch(ctx->step) {
  case TOPRF_Update_Peer_Broadcast_NPK_SIDNonce: return toprfupdate_peer_init_msg_SIZE;
  case TOPRF_Update_Peer_Rcv_NPK_SIDNonce: return toprfupdate_peer_ake1_msg_SIZE * ctx->n;
  case TOPRF_Update_Peer_Noise_Handshake: return toprfupdate_peer_ake2_msg_SIZE * ctx->n;
  case TOPRF_Update_Peer_Finish_Noise_Handshake: return toprfupdate_peer_dkg1_msg_SIZE(ctx);
  case TOPRF_Update_Peer_Rcv_CHashes_Send_Commitments: return toprfupdate_peer_dkg2_msg_SIZE(ctx);
  case TOPRF_Update_Peer_Rcv_Commitments_Send_Shares: return ctx->n * toprfupdate_peer_dkg3_msg_SIZE;
  case TOPRF_Update_Peer_Verify_Commitments: return toprfupdate_peer_verify_shares_msg_SIZE(ctx);
  case TOPRF_Update_Peer_Handle_DKG_Complaints: return 0;
  case TOPRF_Update_Peer_Defend_DKG_Accusations: {
    if(ctx->my_p_complaints_len == 0) return 0;
    size_t res = sizeof(TOPRF_Update_Message) \
                 + ctx->my_p_complaints_len * (1+dkg_noise_key_SIZE+toprf_update_encrypted_shares_SIZE);
    return res;
  }
  case TOPRF_Update_Peer_Check_Shares: return toprfupdate_peer_bc_transcript_msg_SIZE;
  case TOPRF_Update_Peer_Finish_DKG: return toprfupdate_peer_bc_transcript_msg_SIZE;
  case TOPRF_Update_Peer_Confirm_Transcripts: return isdealer(ctx->index, ctx->t) * toprfupdate_peer_mult1_msg_SIZE(ctx);
  case TOPRF_Update_Peer_Rcv_Mult_CHashes_Send_Commitments: return isdealer(ctx->index, ctx->t) * toprfupdate_peer_mult_coms_msg_SIZE(ctx);
  case TOPRF_Update_Peer_Send_K0P_Shares: return isdealer(ctx->index, ctx->t) * toprfupdate_peer_mult2_msg_SIZE * ctx->n;
  case TOPRF_Update_Peer_Recv_K0P_Shares: return toprfupdate_peer_verify_mult_shares_msg_SIZE(ctx);
  case TOPRF_Update_Peer_Handle_Mult_Share_Complaints: return 0;
  case TOPRF_Update_Peer_Defend_Mult_Accusations: {
    if(ctx->my_p_complaints_len == 0) return 0;
    size_t res = sizeof(TOPRF_Update_Message) \
                 + ctx->my_p_complaints_len * (1+dkg_noise_key_SIZE+toprf_update_encrypted_shares_SIZE);
    return res;
  }
  case TOPRF_Update_Peer_Check_Mult_Shares: return 0;
  case TOPRF_Update_Peer_Disclose_Mult_Shares: {
    if(ctx->p_complaints_len == 0) return 0;
    return toprfupdate_peer_reconst_mult_shares_msg_SIZE(ctx);
  }
  case TOPRF_Update_Peer_Reconstruct_Mult_Shares:
  case TOPRF_Update_Peer_Send_ZK_Challenge_Commitments: return toprfupdate_peer_zkp1_msg_SIZE;
  case TOPRF_Update_Peer_Send_ZK_Commitments: return isdealer(ctx->index, ctx->t) * toprfupdate_peer_zkp2_msg_SIZE;
  case TOPRF_Update_Peer_Send_ZK_nonces: return toprfupdate_peer_zkp3_msg_SIZE;
  case TOPRF_Update_Peer_Send_ZK_proofs: return isdealer(ctx->index, ctx->t) * toprfupdate_peer_zkp4_msg_SIZE;
  case TOPRF_Update_Peer_Verify_ZK_proofs: return 0;
  case TOPRF_Update_Peer_Disclose_ZK_Cheaters: return toprfupdate_peer_zk_disclose_msg_SIZE(ctx);
  case TOPRF_Update_Peer_Reconstruct_ZK_Shares:
  case TOPRF_Update_Peer_Send_Mult_Ci: return toprfupdate_peer_mult3_msg_SIZE;
  case TOPRF_Update_Peer_Final_VSPS_Checks: return 0;
  case TOPRF_Update_Peer_Disclose_VSPS_Cheaters: return toprfupdate_peer_vsps_disclose_msg_SIZE(ctx);
  case TOPRF_Update_Peer_Reconstruct_VSPS_Shares:
  case TOPRF_Update_Peer_Send_k0p_Share: return toprfupdate_peer_end2_msg_SIZE;
  case TOPRF_Update_Peer_Final_OK: return 0;
  default: {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "[%d] peer output size invalid step\n", ctx->index);
  }
  }
  return 1;
}

int toprf_update_stp_next(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  int ret = 0;
  if(ctx->cheater_max <= ctx->cheater_len) return TOPRF_Update_Err_CheatersFull;
  ctx->prev=ctx->step;
  switch(ctx->step) {
  case TOPRF_Update_STP_Broadcast_NPKs: { ret =  stp_step2_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Route_Noise_Handshakes1: { ret = stp_step4_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Route_Noise_Handshakes2: { ret = stp_step6_handler(ctx, input, input_len, output, output_len); break;}

  case TOPRF_Update_STP_Broadcast_DKG_Hash_Commitments: { ret = stp_dkg1_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Broadcast_DKG_Commitments: { ret = stp_dkg2_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Route_Encrypted_Shares: { ret = stp_dkg3_handler(ctx, input, input_len, output, output_len); break;}

  case TOPRF_Update_STP_Broadcast_Complaints: { ret = stp_verify_shares_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Broadcast_DKG_Defenses: { ret = stp_broadcast_defenses(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Broadcast_DKG_Transcripts: { ret = stp_bc_transcript_handler(ctx, input, input_len, output, output_len); break;}

  case TOPRF_Update_STP_Route_Mult_Step1: { ret = stp_step25_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Broadcast_Mult_Commitments: { ret = stp_mult_com_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Route_Encrypted_Mult_Shares: { ret = stp_step27_handler(ctx, input, input_len, output, output_len); break;}

  case TOPRF_Update_STP_Broadcast_Mult_Complaints: { ret = stp_verify_mult_shares_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Broadcast_Mult_Defenses: { ret = stp_broadcast_mult_defenses(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Broadcast_Reconst_Mult_Shares: { ret = stp_broadcast_reconst_mult_shares(ctx, input, input_len, output, output_len); break;}

  case TOPRF_Update_STP_Route_ZK_Challenge_Commitments: { ret = stp_step29_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Route_ZK_commitments: { ret = stp_step31_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Broadcast_ZK_nonces: { ret = stp_step33_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Broadcast_ZK_Proofs: { ret = stp_step35_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Broadcast_ZK_Disclosures: { ret = stp_bc_zk_disclosures(ctx, input, input_len, output, output_len); break;}

  case TOPRF_Update_STP_Broadcast_Mult_Ci: { ret = stp_step40_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Broadcast_VSPS_Disclosures: { ret = stp_bc_vsps_disclosures(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Reconstruct_Delta: { ret = stp_step45_handler(ctx, input, input_len, output, output_len); break;}
  default: {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "[!] stp next invalid step\n");
    return 99;
  }
  }
  if(ret!=0) ctx->step=99; // so that not_done reports done
  return ret;
}

int toprf_update_peer_next(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  int ret=0;
  if(ctx->cheater_max <= ctx->cheater_len) return TOPRF_Update_Err_CheatersFull;
  ctx->prev=ctx->step;
  switch(ctx->step) {
  case TOPRF_Update_Peer_Broadcast_NPK_SIDNonce: { ret = peer_step1_handler(ctx, output, output_len) ; break; }
  case TOPRF_Update_Peer_Rcv_NPK_SIDNonce: { ret = peer_step3_handler(ctx, input, input_len, output, output_len); break; }
  case TOPRF_Update_Peer_Noise_Handshake: { ret = peer_step5_handler(ctx, input, input_len, output, output_len); break; }
  case TOPRF_Update_Peer_Finish_Noise_Handshake: { ret = peer_dkg1_handler(ctx, input, input_len, output, output_len); break; }

  case TOPRF_Update_Peer_Rcv_CHashes_Send_Commitments: { ret = peer_dkg2_handler(ctx, input, input_len, output, output_len); break; }
  case TOPRF_Update_Peer_Rcv_Commitments_Send_Shares: { ret = peer_dkg3_handler(ctx, input, input_len, output, output_len); break; }

  case TOPRF_Update_Peer_Verify_Commitments: { ret = peer_verify_shares_handler(ctx, input, input_len, output, output_len); break; }
  case TOPRF_Update_Peer_Handle_DKG_Complaints: { ret = peer_dkg_fork(ctx, input, input_len); break; }
  case TOPRF_Update_Peer_Defend_DKG_Accusations: { ret = peer_defend(ctx, output, output_len); break; }
  case TOPRF_Update_Peer_Check_Shares: { ret = peer_check_shares(ctx, input, input_len, output, output_len); break; }

  case TOPRF_Update_Peer_Finish_DKG: { ret = peer_verify_vsps(ctx, output, output_len); break; }
  case TOPRF_Update_Peer_Confirm_Transcripts: { ret = peer_final_handler(ctx, input, input_len, output, output_len); break; }

  case TOPRF_Update_Peer_Rcv_Mult_CHashes_Send_Commitments: { ret = peer_mult2_handler(ctx, input, input_len, output, output_len); break; }
  case TOPRF_Update_Peer_Send_K0P_Shares: { ret = peer_step26_handler(ctx, input, input_len, output, output_len); break; }
  case TOPRF_Update_Peer_Recv_K0P_Shares: { ret = peer_step28_handler(ctx, input, input_len, output, output_len); break; }

  case TOPRF_Update_Peer_Handle_Mult_Share_Complaints: { ret = peer_mult_fork(ctx, input, input_len); break; }
  case TOPRF_Update_Peer_Defend_Mult_Accusations: { ret = peer_mult_defend(ctx, output, output_len); break; }
  case TOPRF_Update_Peer_Check_Mult_Shares: { ret = peer_check_mult_shares(ctx,input,input_len); break; }
  case TOPRF_Update_Peer_Disclose_Mult_Shares: { ret = peer_disclose_mult_shares(ctx, output, output_len); break; }
  case TOPRF_Update_Peer_Reconstruct_Mult_Shares: { ret = peer_reconst_mult_shares(ctx,input,input_len,output,output_len); break;}

  case TOPRF_Update_Peer_Send_ZK_Challenge_Commitments: { ret = peer_send_zk_chalcoms(ctx, output, output_len); break; }
  case TOPRF_Update_Peer_Send_ZK_Commitments: { ret = peer_step30_handler(ctx, input, input_len, output, output_len); break; }
  case TOPRF_Update_Peer_Send_ZK_nonces: { ret = peer_step32_handler(ctx, input, input_len, output, output_len); break; }
  case TOPRF_Update_Peer_Send_ZK_proofs: { ret = peer_step34_handler(ctx, input, input_len, output, output_len); break; }
  case TOPRF_Update_Peer_Verify_ZK_proofs: { ret = peer_step36_handler(ctx, input, input_len); break; }
  case TOPRF_Update_Peer_Disclose_ZK_Cheaters: { ret = peer_zkproof_disclose(ctx, output, output_len); break; }
  case TOPRF_Update_Peer_Reconstruct_ZK_Shares: { ret = peer_reconst_zk_shares(ctx,input,input_len,output,output_len); break;}

  case TOPRF_Update_Peer_Send_Mult_Ci: { ret = peer_step39_handler(ctx, output, output_len); break; }
  case TOPRF_Update_Peer_Final_VSPS_Checks: { ret = peer_step41_handler(ctx, input, input_len); break; }
  case TOPRF_Update_Peer_Disclose_VSPS_Cheaters: { ret = peer_vsps_disclose(ctx, output, output_len); break; }
  case TOPRF_Update_Peer_Reconstruct_VSPS_Shares: { ret = peer_reconst_vsps_shares(ctx,input,input_len,output,output_len); break;}

  case TOPRF_Update_Peer_Send_k0p_Share: { ret = peer_step44_handler(ctx, output, output_len); break; }
  case TOPRF_Update_Peer_Final_OK: { ret = peer_step46_handler(ctx, input, input_len); break; }
  case TOPRF_Update_Peer_Done: {
    // we are done
    ret = 0;
    break;
  }
  default: {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "[%d] peer next invalid step\n", ctx->index);
    ret = 99;
  }
  }
  if(ret!=0) ctx->step=99; // so that not_done reports done
  return ret;
}
