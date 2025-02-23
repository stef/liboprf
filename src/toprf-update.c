#include <arpa/inet.h> //htons
#include "utils.h"
#include "toprf-update.h"
#include "dkg-vss.h"
#include "mpmult.h"

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
const uint8_t* toprf_update_peerstate_lt_sk(const TOPRF_Update_PeerState *ctx) {
  return ctx->sig_sk;
}
const uint8_t* toprf_update_peerstate_share(const TOPRF_Update_PeerState *ctx) {
  return (const uint8_t*) &ctx->share;
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
int toprf_update_stpstate_step(const TOPRF_Update_STPState *ctx) {
  return ctx->step;
}

static int toprf_send_msg(uint8_t* msg_buf, const size_t msg_buf_len,
                          const uint8_t msgno,
                          const uint8_t from, const uint8_t to,
                          const uint8_t *sig_sk, const uint8_t sessionid[dkg_sessionid_SIZE]) {
  return send_msg(msg_buf, msg_buf_len, MSG_TYPE_SEMI_TRUSTED | MSG_TYPE_UPDATE, 0, msgno, from, to, sig_sk, sessionid);
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

static int isdealer(const uint8_t i, const uint8_t t) {
  return  i <= ((t-1)*2 + 1);
}

static int stp_recv_msg(TOPRF_Update_STPState *ctx,
                        const uint8_t *msg_buf, const size_t msg_buf_len,
                        const uint8_t msgno,
                        const uint8_t from, const uint8_t to) {
  dkg_dump_msg(msg_buf, msg_buf_len, 0);
  int ret = toprf_recv_msg(msg_buf, msg_buf_len, msgno, from, to, (*ctx->sig_pks)[from], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts[from-1]);
  if(0!=ret) {
    if(stp_add_cheater(ctx, 64+ret, from, to) == NULL) return Err_CheatersFull;
    if(log_file!=NULL) fprintf(log_file, RED"failed to validate msg %d from %d, err: %d\n"NORMAL, msgno, from, ret);
    return 1;
  }
  return 0;
}

static int peer_recv_msg(TOPRF_Update_PeerState *ctx,
                         const uint8_t *msg_buf, const size_t msg_buf_len,
                         const uint8_t msgno,
                         const uint8_t from, const uint8_t to) {
  dkg_dump_msg(msg_buf, msg_buf_len, 0);
  int ret = toprf_recv_msg(msg_buf, msg_buf_len, msgno, from, to, (*ctx->sig_pks)[from], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts[from-1]);
  if(0!=ret) {
    if(peer_add_cheater(ctx, 64+ret, from, to) == NULL) return Err_CheatersFull;
    if(log_file!=NULL) fprintf(log_file, RED"[%d] failed to validate msg %d from %d, err: %d\n"NORMAL, ctx->index, msgno, from, ret);
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
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m %s\x1b[0m\n", step_title);
  if(msg_count * msg_size != input_len) return Err_ISize;
  if(sizeof(TOPRF_Update_Message) + input_len != output_len) return Err_OSize;
  const uint8_t *ptr = input;
  uint8_t *wptr = ((TOPRF_Update_Message *) output)->data;
  for(uint8_t i=0;i<msg_count;i++,ptr+=msg_size) {
    if(stp_recv_msg(ctx,ptr,msg_size,msgno,i+1,0xff)) continue;
    memcpy(wptr, ptr, msg_size);
    wptr+=msg_size;
  }
  if(ctx->cheater_len>0) return Err_CheatersFound;

  if(0!=toprf_send_msg(output, output_len, msgno+1, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return Err_Send;
  dkg_dump_msg(output, output_len, 0);

  // add broadcast msg to transcript
  update_transcript(&ctx->transcript, output, output_len);

  ctx->step = next_step;

  return Err_OK;
}

static TOPRF_Update_Err stp_route(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len,
                                  const char *step_title,
                                  const uint8_t send_count,
                                  const uint8_t recv_count,
                                  const uint8_t msgno,
                                  const size_t msg_size,
                                  const TOPRF_Update_STP_Steps next_step) {
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[!] %s\x1b[0m\n", step_title);
  if(input_len != msg_size * send_count * recv_count) return Err_ISize;
  if(input_len != output_len) return Err_OSize;

  const uint8_t (*inputs)[send_count][recv_count][msg_size] = (const uint8_t (*)[send_count][recv_count][msg_size]) input;
  uint8_t *wptr = output;
  for(uint8_t i=0;i<recv_count;i++) {
    for(uint8_t j=0;j<send_count;j++) {
      int ret = toprf_recv_msg((*inputs)[j][i], msg_size,
                               msgno, j+1, i+1, (*ctx->sig_pks)[j+1],
                               ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts[j]);
      if(0!=ret) {
        if(stp_add_cheater(ctx, 64+ret, j+1, i+1) == NULL) return Err_CheatersFull;
        const TOPRF_Update_Message *msg = (const TOPRF_Update_Message*) (*inputs)[j][i];
        fprintf(log_file,"[x] msgno: %d, from: %d to: %d ", msg->msgno, msg->from, msg->to);
        dump((*inputs)[j][i], msg_size, "msg");
        continue;
      }
      memcpy(wptr, (*inputs)[j][i], msg_size);
      wptr+=msg_size;
    }
  }
  if(ctx->cheater_len>0) return Err_CheatersFound;

  ctx->step = next_step;
  return Err_OK;
}

static TOPRF_Update_Err unwrap_envelope(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, const uint8_t msgno, const uint8_t **contents) {
  // verify STP message envelope
  const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) input;
  dkg_dump_msg(input, input_len, ctx->index);
  int ret = toprf_recv_msg(input, input_len, msgno, 0, 0xff, (*ctx->sig_pks)[0], ctx->sessionid, ctx->ts_epsilon, &ctx->stp_last_ts);
  if(0!=ret) return Err_BroadcastEnv+ret;

  // add broadcast msg to transcript
  update_transcript(&ctx->transcript, input, input_len);

  *contents = msg->data;
  return Err_OK;
}

// todo test this
static void handle_complaints(const uint8_t n,
                              const uint8_t accuser,
                              const uint8_t fails_len, const uint8_t fails[],
                              uint16_t *ctx_complaints_len, uint16_t *ctx_complaints,
                              const uint8_t self,
                              uint8_t *ctx_my_complaints_len, uint8_t *ctx_my_complaints) {
  // keep a copy all complaint pairs (complainer, complained)
  for(unsigned k=0;k<fails_len && k<n;k++) {
    if(fails[k] > n || fails[k] < 1) {
      // todo cheater handling
      //if(stp_add_cheater(ctx, 7, i+1, msg->data[k+1]) == NULL) return 6;
      continue;
    }
    uint16_t pair=(uint16_t) ((accuser<<8) | fails[k]);
    int j=0;
    for(j=0;j<*ctx_complaints_len;j++) if(ctx_complaints[j]==pair) break;
    if(j<*ctx_complaints_len) {
      // todo cheater handling
      //if(stp_add_cheater(ctx, 18, 8, i+1, msg->data[k+1]) == NULL) return 6;
      continue;
    }
    ctx_complaints[(*ctx_complaints_len)++] = pair;

    if(self!=0 && fails[k] == self && ctx_my_complaints_len != NULL && ctx_my_complaints != NULL) {
        ctx_my_complaints[(*ctx_my_complaints_len)++] = accuser;
    }
    if(log_file!=NULL) {
      fprintf(log_file,"\x1b[0;31m[!] peer %d failed to verify commitments from peer %d!\x1b[0m\n", accuser, fails[k]);
    }
  }
}

static TOPRF_Update_Err stp_complaint_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len,
                                 const char* step_title,
                                 const uint8_t msg_count,
                                 const size_t msg_size,
                                 const uint8_t msgno,
                                 const TOPRF_Update_STP_Steps pass_step,
                                 const TOPRF_Update_STP_Steps fail_step) {
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[!] %s\x1b[0m\n", step_title);

  if(input_len != msg_size * msg_count) return Err_ISize;
  if(sizeof(TOPRF_Update_Message) + input_len != output_len) return Err_OSize;

  ctx->kc1_complaints_len = 0;
  ctx->p_complaints_len = 0;

  const uint8_t *ptr = input;
  uint8_t *wptr = ((TOPRF_Update_Message *) output)->data;
  for(uint8_t i=0;i<msg_count;i++, ptr+=msg_size) {
    const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) ptr;
    if(stp_recv_msg(ctx,ptr,msg_size,msgno,i+1,0xff)) continue;
    if(msg->len - sizeof(TOPRF_Update_Message) < msg->data[0]) return Err_OOB;

    const uint8_t *fails_len = msg->data;
    const uint8_t *fails = msg->data+1;
    handle_complaints(msg_count, i+1, *fails_len, fails, &ctx->kc1_complaints_len, (*ctx->kc1_complaints), 0, 0, 0);
    fails_len = fails+ctx->n;
    fails = fails_len + 1;
    handle_complaints(msg_count, i+1, *fails_len, fails, &ctx->p_complaints_len, (*ctx->p_complaints), 0, 0, 0);

    memcpy(wptr, ptr, msg_size);
    wptr+=msg_size;
  }

  // if more than t^2 complaints are received the protocol also fails
  if(ctx->kc1_complaints_len >= ctx->t * ctx->t) {
    if(stp_add_cheater(ctx, 6, 0xfe, 0xfe) == NULL) return Err_CheatersFull;
    return 5;
  }
  if(ctx->p_complaints_len >= ctx->t * ctx->t) {
    if(stp_add_cheater(ctx, 6, 0xfe, 0xfe) == NULL) return Err_CheatersFull;
    return 5;
  }

  if(ctx->cheater_len>0) return Err_CheatersFound;

  if(0!=toprf_send_msg(output, output_len, msgno+1, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return Err_Send;
  dkg_dump_msg(output, output_len, 0);

  // add broadcast msg to transcript
  update_transcript(&ctx->transcript, output, output_len);

  ctx->prev = ctx->step;
  if(ctx->kc1_complaints_len == 0 && ctx->p_complaints_len == 0) {
    ctx->step = pass_step;
  } else {
    dump((uint8_t*) (*ctx->kc1_complaints), ctx->kc1_complaints_len*sizeof(uint16_t), "[!] complaints_1");
    dump((uint8_t*) (*ctx->p_complaints), ctx->p_complaints_len*sizeof(uint16_t), "[!] complaints_2");
    ctx->step = fail_step;
  }

  return Err_OK;
}

static TOPRF_Update_Err peer_complaint_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len,
                                               const char *step_title,
                                               const size_t msg_size,
                                               const uint8_t msgno,
                                               const TOPRF_Update_Peer_Steps pass_step,
                                               const TOPRF_Update_Peer_Steps fail_step) {
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[%d] %s\x1b[0m\n", ctx->index, step_title);
  if(input_len != sizeof(TOPRF_Update_Message) + msg_size * ctx->n) return Err_ISize;

  // verify STP message envelope
  const uint8_t *ptr;
  int ret = unwrap_envelope(ctx,input,input_len,msgno+1,&ptr);
  if(ret!=Err_OK) return ret;

  for(uint8_t i=0;i<ctx->n;i++, ptr+=msg_size) {
    const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,msg_size,msgno,i+1,0xff)) continue;
    if(msg->len - sizeof(TOPRF_Update_Message) < msg->data[0]) return Err_OOB;
    const uint8_t *fails_len = msg->data;
    const uint8_t *fails = msg->data+1;
    handle_complaints(ctx->n, i+1, *fails_len, fails, &ctx->kc1_complaints_len, ctx->kc1_complaints, ctx->index, &ctx->my_kc1_complaints_len, ctx->my_kc1_complaints);
    fails_len = fails+ctx->n;
    fails = fails_len + 1;
    handle_complaints(ctx->n, i+1, *fails_len, fails, &ctx->p_complaints_len, ctx->p_complaints, ctx->index, &ctx->my_p_complaints_len, ctx->my_p_complaints);
  }

  if(ctx->cheater_len>0) return Err_CheatersFound;

  ctx->prev = ctx->step;
  if(ctx->kc1_complaints_len == 0 && ctx->p_complaints_len == 0) {
    ctx->step = pass_step;
  } else {
    dump((uint8_t*) ctx->kc1_complaints, ctx->kc1_complaints_len*sizeof(uint16_t), "[!] complaints_1");
    dump((uint8_t*) ctx->p_complaints, ctx->p_complaints_len*sizeof(uint16_t), "[!] complaints_2");
    ctx->step = fail_step;
  }

  return Err_OK;
}

static TOPRF_Update_Err ft_or_full_vsps(const uint8_t n, const uint8_t t, const uint8_t dealers, const uint8_t self,
                                        const uint8_t C_i[n][crypto_core_ristretto255_BYTES],
                                        const uint8_t (*C_ij)[n][n][crypto_core_ristretto255_BYTES],
                                        const char *ft_msg, const char *sub_msg, const char *no_sub_msg,
                                        const uint8_t *fails_len, uint8_t fails[n]) {
  debug=0;
  if(0!=toprf_mpc_vsps_check(t-1, C_i)) {
    if(log_file!=NULL) fprintf(stderr, RED"[%d] %s\n"NORMAL, self, ft_msg);
    for(unsigned i=0;i<dealers;i++) {
      if(0!=toprf_mpc_vsps_check(t-1, (*C_ij)[i])) {
        if(log_file!=NULL) fprintf(stderr, RED"[%d] %s [%d]\n"NORMAL, self, sub_msg, i+1);
        fails[*fails_len++]=i+1;
      }
    }
    if(*fails_len == 0) {
      if(log_file!=NULL) fprintf(stderr, RED"[%d] %s\n"NORMAL, self, no_sub_msg);
      return Err_NoSubVSPSFail;
    }
  }
  debug=1;
  return Err_OK;
}

int toprf_update_start_stp(TOPRF_Update_STPState *ctx, const uint64_t ts_epsilon,
                           const uint8_t n, const uint8_t t,
                           const char *proto_name, const size_t proto_name_len,
                           const uint8_t keyid[toprf_keyid_SIZE],
                           const uint8_t (*sig_pks)[][crypto_sign_PUBLICKEYBYTES],
                           const uint8_t ltssk[crypto_sign_SECRETKEYBYTES],
                           const size_t msg0_len, TOPRF_Update_Message *msg0) {
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[!] step 0. start toprf update\x1b[0m\n");
  if(2>n || t>=n || n>128 || n<2*t+1) return 1;
  if(proto_name_len<1) return 2;
  if(proto_name_len>1024) return 3;
  if(msg0_len != toprf_update_msg0_SIZE) return 4;

  ctx->ts_epsilon = ts_epsilon;
  ctx->step = TOPRF_Update_STP_Broadcast_NPKs;
  ctx->n = n;
  ctx->t = t;
  ctx->kc1_complaints_len = 0;
  ctx->p_complaints_len = 0;
  ctx->cheater_len = 0;

  // dst hash(len(protoname) | "TOPRF Update for protocol " | protoname)
  crypto_generichash_state dst_state;
  crypto_generichash_init(&dst_state, NULL, 0, crypto_generichash_BYTES);
  uint16_t len=htons((uint16_t) proto_name_len+20); // we have a guard above restricting to 1KB the proto_name_len
  crypto_generichash_update(&dst_state, (uint8_t*) &len, 2);
  crypto_generichash_update(&dst_state, (const uint8_t*) "TOPRF Update for protocol ", 26);
  crypto_generichash_update(&dst_state, (const uint8_t*) proto_name, proto_name_len);
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
  ptr+=toprf_keyid_SIZE;

  if(0!=toprf_send_msg((uint8_t*) msg0, toprf_update_msg0_SIZE, 0, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return 5;

  // init transcript
  crypto_generichash_init(&ctx->transcript, NULL, 0, crypto_generichash_BYTES);
  crypto_generichash_update(&ctx->transcript, (const uint8_t*) "toprf update session transcript", 31);
  // feed msg0 into transcript
  update_transcript(&ctx->transcript, (uint8_t*) msg0, msg0_len);

  dkg_dump_msg((uint8_t*) msg0, toprf_update_msg0_SIZE, 0);

  return 0;
}

void toprf_update_stp_set_bufs(TOPRF_Update_STPState *ctx,
                               uint16_t (*kc1_complaints)[],
                               uint16_t (*p_complaints)[],
                               TOPRF_Update_Cheater (*cheaters)[], const size_t cheater_max,
                               uint8_t (*k0p_final_commitments)[][crypto_scalarmult_ristretto255_BYTES],
                               uint8_t (*k1p_final_commitments)[][crypto_scalarmult_ristretto255_BYTES],
                               uint64_t *last_ts) {
  ctx->kc1_complaints = kc1_complaints;
  ctx->p_complaints = p_complaints;
  ctx->cheaters = cheaters;
  memset(*cheaters, 0, cheater_max*sizeof(TOPRF_Update_Cheater));
  ctx->cheater_max = cheater_max;
  ctx->last_ts = last_ts;
  ctx->k0p_final_commitments = k0p_final_commitments;
  ctx->k1p_final_commitments = k1p_final_commitments;
  uint64_t now = (uint64_t)time(NULL);
  for(uint8_t i=0;i<ctx->n;i++) ctx->last_ts[i]=now;
}

// TODO ret type is TOPRF_Update_Err
TOPRF_Update_Err toprf_update_start_peer(TOPRF_Update_PeerState *ctx,
                            const uint64_t ts_epsilon,
                            const uint8_t lt_sk[crypto_sign_SECRETKEYBYTES],
                            const TOPRF_Update_Message *msg0,
                            uint8_t keyid[toprf_keyid_SIZE],
                            uint8_t stp_ltpk[crypto_sign_PUBLICKEYBYTES]) {
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[?] step 0.5 start peer\x1b[0m\n");
  if(log_file!=NULL) {
    fprintf(log_file,"[?] msgno: %d, from: %d to: 0x%x ", msg0->msgno, msg0->from, msg0->to);
    dump((const uint8_t*) msg0, toprf_update_msg0_SIZE, "msg");
  }

  ctx->ts_epsilon = ts_epsilon;
  ctx->stp_last_ts = 0;

  int ret = toprf_recv_msg((const uint8_t*) msg0, toprf_update_msg0_SIZE, 0, 0, 0xff, msg0->data, msg0->sessionid, ts_epsilon, &ctx->stp_last_ts);
  if(0!=ret) return Err_Env+ ret;

  // extract data from message
  // we abuse sessionid as a temporary storage for the nonce_stp value, until we have the final sessionid
  memcpy(ctx->sessionid, msg0->sessionid, sizeof ctx->sessionid);

  const uint8_t *ptr=msg0->data;
  memcpy(stp_ltpk,ptr,crypto_sign_PUBLICKEYBYTES);
  ptr+=crypto_sign_PUBLICKEYBYTES + crypto_generichash_BYTES; // also skip DST
  memcpy(keyid,ptr,toprf_keyid_SIZE);

  ctx->kc1_complaints_len = 0;
  ctx->my_kc1_complaints_len = 0;
  ctx->p_complaints_len = 0;
  ctx->my_p_complaints_len = 0;
  ctx->cheater_len = 0;
  memcpy(ctx->sig_sk, lt_sk, crypto_sign_SECRETKEYBYTES);

  crypto_generichash_init(&ctx->transcript, NULL, 0, crypto_generichash_BYTES);
  crypto_generichash_update(&ctx->transcript, (const uint8_t*) "toprf update session transcript", 31);
  // feed msg0 into transcript
  update_transcript(&ctx->transcript, (const uint8_t*) msg0, toprf_update_msg0_SIZE);

  ctx->dev = NULL;
  ctx->step = TOPRF_Update_Peer_Broadcast_NPK_SIDNonce;

  return Err_OK;
}

int toprf_update_peer_set_bufs(TOPRF_Update_PeerState *ctx,
                               const uint8_t self,
                               const uint8_t n, const uint8_t t,
                               const TOPRF_Share k0[2],
                               uint8_t (*kc0_commitments)[][crypto_core_ristretto255_BYTES],
                               const uint8_t (*sig_pks)[][crypto_sign_PUBLICKEYBYTES],
                               uint8_t (*peers_noise_pks)[][crypto_scalarmult_BYTES],
                               Noise_XK_session_t *(*noise_outs)[],
                               Noise_XK_session_t *(*noise_ins)[],
                               TOPRF_Share (*kc1_shares)[][2],
                               TOPRF_Share (*p_shares)[][2],
                               uint8_t (*kc1_commitments)[][crypto_core_ristretto255_BYTES],
                               uint8_t (*p_commitments)[][crypto_core_ristretto255_BYTES],
                               TOPRF_Update_Cheater (*cheaters)[], const size_t cheater_max,
                               uint8_t (*lambdas)[][crypto_core_ristretto255_SCALARBYTES],
                               TOPRF_Share (*k0p_shares)[][2],
                               uint8_t (*k0p_commitments)[][crypto_core_ristretto255_BYTES],
                               uint8_t (*k0p_commitments0)[][crypto_core_ristretto255_BYTES],
                               TOPRF_Share (*k1p_shares)[][2],
                               uint8_t (*k1p_commitments)[][crypto_core_ristretto255_BYTES],
                               uint8_t (*k1p_commitments0)[][crypto_core_ristretto255_BYTES],
                               uint8_t (*zk_challenge_nonce_commitments)[][crypto_scalarmult_ristretto255_BYTES],
                               uint8_t (*zk_challenge_nonces)[][2][crypto_scalarmult_ristretto255_SCALARBYTES],
                               uint8_t (*zk_challenge_commitments)[][3][crypto_scalarmult_ristretto255_SCALARBYTES],
                               uint8_t (*zk_challenge_e_i)[][crypto_scalarmult_ristretto255_SCALARBYTES],
                               uint16_t *kc1_complaints, uint16_t *p_complaints,
                               uint8_t *my_kc1_complaints, uint8_t *my_p_complaints,
                               uint64_t *last_ts) {
  if(2>n || t>=n || n>128 || n<2*t+1) return 1;
  ctx->index = self;
  ctx->n = n;
  ctx->t = t;
  memcpy((uint8_t*) ctx->kc0_share, (uint8_t*) k0, sizeof(TOPRF_Share)*2);
  ctx->kc0_commitments = kc0_commitments;
  ctx->sig_pks = sig_pks;
  ctx->peer_noise_pks = peers_noise_pks;
  ctx->noise_outs = noise_outs;
  ctx->noise_ins = noise_ins;
  ctx->kc1_shares = kc1_shares;
  ctx->p_shares = p_shares;
  ctx->kc1_commitments = kc1_commitments;
  ctx->p_commitments = p_commitments;
  ctx->lambdas = lambdas;
  ctx->k0p_shares = k0p_shares;
  ctx->k0p_commitments = k0p_commitments;
  ctx->k0p_commitments0 = k0p_commitments0;
  ctx->k1p_shares = k1p_shares;
  ctx->k1p_commitments = k1p_commitments;
  ctx->k1p_commitments0 = k1p_commitments0;
  ctx->zk_challenge_nonce_commitments = zk_challenge_nonce_commitments;
  ctx->zk_challenge_nonces = zk_challenge_nonces;
  ctx->zk_challenge_commitments = zk_challenge_commitments;
  ctx->zk_challenge_e_i = zk_challenge_e_i;
  ctx->kc1_complaints = kc1_complaints;
  ctx->p_complaints = p_complaints;
  ctx->my_kc1_complaints = my_kc1_complaints;
  ctx->my_p_complaints = my_p_complaints;
  ctx->cheaters = cheaters;
  ctx->cheater_max = cheater_max;
  ctx->last_ts = last_ts;
  for(uint8_t i=0;i<ctx->n;i++) ctx->last_ts[i]=0;
  return 0;
}

#define toprf_update_msg1_SIZE (sizeof(TOPRF_Update_Message) + dkg_sessionid_SIZE + crypto_scalarmult_BYTES)
static TOPRF_Update_Err peer_step1_handler(TOPRF_Update_PeerState *ctx, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[%d] step 1. send msg1 containing ephemeral pubkey and session id nonce\x1b[0m\n", ctx->index);
  if(output_len != toprf_update_msg1_SIZE) return Err_OSize;

  randombytes_buf(ctx->noise_sk, sizeof ctx->noise_sk);
  crypto_scalarmult_base(ctx->noise_pk, ctx->noise_sk);

  uint8_t *wptr = ((TOPRF_Update_Message *) output)->data;
  randombytes_buf(wptr, dkg_sessionid_SIZE);
  wptr+=dkg_sessionid_SIZE;
  memcpy(wptr, ctx->noise_pk, sizeof ctx->noise_pk);
  if(0!=toprf_send_msg(output, toprf_update_msg1_SIZE, 1, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return Err_Send;

  dkg_dump_msg(output, output_len, ctx->index);

  ctx->step = TOPRF_Update_Peer_Rcv_NPK_SIDNonce;

  return Err_OK;
}

static TOPRF_Update_Err stp_step2_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[!] step 2. broadcast msg1 containing ephemeral pubkeys and session id nonces of peers\x1b[0m\n");
  if(input_len  != toprf_update_msg1_SIZE * ctx->n) return Err_ISize;
  if(output_len != toprf_update_msg1_SIZE * ctx->n + sizeof(TOPRF_Update_Message)) return Err_OSize;

  crypto_generichash_state sid_state;
  crypto_generichash_init(&sid_state, NULL, 0, dkg_sessionid_SIZE);
  crypto_generichash_update(&sid_state, ctx->sessionid, dkg_sessionid_SIZE);

  const uint8_t *ptr = input;
  uint8_t *wptr = ((TOPRF_Update_Message *) output)->data;
  for(uint8_t i=0;i<ctx->n;i++,ptr+=toprf_update_msg1_SIZE) {
    const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) ptr;
    if(stp_recv_msg(ctx,ptr,toprf_update_msg1_SIZE,1,i+1,0xff)) continue;
    crypto_generichash_update(&sid_state, msg->data, dkg_sessionid_SIZE);

    memcpy(wptr, ptr, toprf_update_msg1_SIZE);
    wptr+=toprf_update_msg1_SIZE;
  }
  if(ctx->cheater_len>0) return Err_CheatersFound;

  crypto_generichash_final(&sid_state,ctx->sessionid,sizeof ctx->sessionid);

  if(0!=toprf_send_msg(output, output_len, 2, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return Err_Send;
  update_transcript(&ctx->transcript, output, output_len);

  ctx->step = TOPRF_Update_STP_Route_Noise_Handshakes1;
  return Err_OK;
}

#define toprf_update_msg3_SIZE (sizeof(TOPRF_Update_Message) + noise_xk_handshake1_SIZE)

static TOPRF_Update_Err peer_step3_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[%d] step 3. receive peers ephemeral pubkeys, start noise sessions\x1b[0m\n", ctx->index);
  if(input_len != toprf_update_msg1_SIZE * ctx->n + sizeof(TOPRF_Update_Message)) return Err_ISize;
  if(output_len != toprf_update_msg3_SIZE * ctx->n) return Err_OSize;

  const TOPRF_Update_Message* msg2 = (const TOPRF_Update_Message*) input;
  int ret = toprf_recv_msg(input, input_len, 2, 0, 0xff, (*ctx->sig_pks)[0], msg2->sessionid, ctx->ts_epsilon, &ctx->stp_last_ts);
  if(0!=ret) return Err_BroadcastEnv+ret;

  update_transcript(&ctx->transcript, input, input_len);

  // create noise device
  uint8_t iname[14];
  snprintf((char*) iname, sizeof iname, "toprf peer %02x", ctx->index);
  uint8_t dummy[32]={0}; // the following function needs a deserialization key, which we never use.

  ctx->dev = Noise_XK_device_create(13, (uint8_t*) "toprf p2p v0.1", iname, dummy, ctx->noise_sk);

  crypto_generichash_state sid_state;
  crypto_generichash_init(&sid_state, NULL, 0, dkg_sessionid_SIZE);
  crypto_generichash_update(&sid_state, ctx->sessionid, dkg_sessionid_SIZE);

  const uint8_t *ptr = msg2->data;
  for(uint8_t i=0;i<ctx->n;i++, ptr+=toprf_update_msg1_SIZE) {
    const TOPRF_Update_Message* msg1 = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprf_update_msg1_SIZE,1,i+1,0xff)) continue;
    // extract peer sig and noise pk
    crypto_generichash_update(&sid_state, msg1->data, dkg_sessionid_SIZE);
    memcpy((*ctx->peer_noise_pks)[i], msg1->data + dkg_sessionid_SIZE, crypto_scalarmult_BYTES);
  }

  if(ctx->cheater_len>0) return Err_CheatersFound;

  crypto_generichash_final(&sid_state,ctx->sessionid,sizeof ctx->sessionid);
  if(memcmp(ctx->sessionid, msg2->sessionid, dkg_sessionid_SIZE)!=0) {
    if(log_file!=NULL) fprintf(log_file, "invalid sessionid generated\n");
    return Err_InvSessionID;
  }

  uint8_t *wptr = output;
  for(uint8_t i=0;i<ctx->n;i++, wptr+=toprf_update_msg3_SIZE) {
    TOPRF_Update_Message *msg3 = (TOPRF_Update_Message *) wptr;
    uint8_t rname[14];
    snprintf((char*) rname, sizeof rname, "toprf peer %02x", i+1);
    dkg_init_noise_handshake(ctx->index, ctx->dev, (*ctx->peer_noise_pks)[i], rname, &(*ctx->noise_outs)[i], msg3->data);
    if(0!=toprf_send_msg(wptr, toprf_update_msg3_SIZE, 3, ctx->index, i+1, ctx->sig_sk, ctx->sessionid)) return Err_Send;
    dkg_dump_msg(wptr, toprf_update_msg3_SIZE, ctx->index);
  }

  ctx->step = TOPRF_Update_Peer_Noise_Handshake;

  return Err_OK;
}


static TOPRF_Update_Err stp_step4_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  return stp_route(ctx, input, input_len, output, output_len,
                   "step 4. route p2p noise handshakes to peers",
                   ctx->n, ctx->n, 3, toprf_update_msg3_SIZE, TOPRF_Update_STP_Route_Noise_Handshakes2);
}

#define toprf_update_msg4_SIZE (sizeof(TOPRF_Update_Message) + noise_xk_handshake2_SIZE)
static TOPRF_Update_Err peer_step5_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[%d] step 5. receive session requests\x1b[0m\n", ctx->index);
  if(input_len != toprf_update_msg3_SIZE * ctx->n) return Err_ISize;
  if(output_len != toprf_update_msg4_SIZE * ctx->n) return Err_OSize;

  const uint8_t *ptr = input;
  uint8_t *wptr = output;
  for(uint8_t i=0;i<ctx->n;i++,ptr+=toprf_update_msg3_SIZE,wptr+=toprf_update_msg4_SIZE) {
    TOPRF_Update_Message* msg3 = (TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprf_update_msg3_SIZE,3,i+1,ctx->index)) continue;

    // respond to noise handshake request
    TOPRF_Update_Message *msg4 = (TOPRF_Update_Message *) wptr;
    uint8_t rname[14];
    snprintf((char*) rname, sizeof rname, "toprf peer %02x", i+1);
    dkg_respond_noise_handshake(ctx->index, ctx->dev, rname, &(*ctx->noise_ins)[i], msg3->data, msg4->data);
    if(0!=toprf_send_msg(wptr, toprf_update_msg4_SIZE, 4, ctx->index, i+1, ctx->sig_sk, ctx->sessionid)) return Err_Send;
    dkg_dump_msg(wptr, toprf_update_msg4_SIZE, ctx->index);
  }
  if(ctx->cheater_len>0) return Err_CheatersFound;

  ctx->step=TOPRF_Update_Peer_Finish_Noise_Handshake;
  return Err_OK;
}

static TOPRF_Update_Err stp_step6_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  return stp_route(ctx, input, input_len, output, output_len,
                   "step 6. route p2p noise handshakes to peers",
                   ctx->n, ctx->n, 4, toprf_update_msg4_SIZE, TOPRF_Update_STP_Broadcast_DGK_Commitments);
}

#define toprf_update_msg5_SIZE(ctx) (sizeof(TOPRF_Update_Message) + crypto_core_ristretto255_BYTES * ctx->n * 2)
static TOPRF_Update_Err peer_step7_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[%d] step 7 finish session handshake, start core update with dkg for kc' and p\x1b[0m\n", ctx->index);
  if(input_len != toprf_update_msg4_SIZE * ctx->n) return Err_ISize;
  if(output_len != toprf_update_msg5_SIZE(ctx)) return Err_OSize;

  const uint8_t *ptr = input;
  for(uint8_t i=0;i<ctx->n;i++, ptr+=toprf_update_msg4_SIZE) {
    TOPRF_Update_Message* msg4 = (TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprf_update_msg4_SIZE,4,i+1,ctx->index)) continue;
    // process final step of noise handshake
    dkg_finish_noise_handshake(ctx->index, ctx->dev, &(*ctx->noise_outs)[i], msg4->data);
  }
  if(ctx->cheater_len>0) return Err_CheatersFound;

  // start DKG for kc1
  TOPRF_Update_Message* msg5 = (TOPRF_Update_Message*) output;
  if(dkg_vss_share(ctx->n, ctx->t, NULL, (uint8_t (*)[32]) msg5->data, (*ctx->kc1_shares), NULL)) {
    return Err_VSSShare;
  }
  // start DKG for p
  uint8_t *wptr = msg5->data + crypto_core_ristretto255_BYTES * ctx->n;
  if(dkg_vss_share(ctx->n, ctx->t, NULL, (uint8_t (*)[32]) wptr, (*ctx->p_shares), NULL)) {
    return Err_VSSShare;
  }

  if(log_file!=NULL) {
    dump(msg5->data, crypto_core_ristretto255_BYTES*ctx->n, "[%d] kc1 commitments", ctx->index);
    dump(wptr, crypto_core_ristretto255_BYTES*ctx->n, "[%d] p commitments", ctx->index);
  }

  //broadcast dealer_commitments

  if(0!=toprf_send_msg(output, toprf_update_msg5_SIZE(ctx), 5, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return Err_Send;
  dkg_dump_msg(output, toprf_update_msg5_SIZE(ctx), ctx->index);

  ctx->step = TOPRF_Update_Peer_Rcv_Commitments_Send_Shares;

  return Err_OK;
}

static TOPRF_Update_Err stp_step8_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  return stp_broadcast(ctx, input, input_len, output, output_len,
                       "step 8. broadcast commitments for kc1 and p dkg step 1",
                       ctx->n, toprf_update_msg5_SIZE(ctx), 5, TOPRF_Update_STP_Route_Encrypted_Shares);
}

#define toprf_update_msg7_SIZE (sizeof(TOPRF_Update_Message) /* header */                           \
                                + noise_xk_handshake3_SIZE /* 4th&final noise handshake */          \
                                + sizeof(TOPRF_Share) /* msg: the noise_xk wrapped kc1 share */     \
                                + sizeof(TOPRF_Share) /* msg: the noise_xk wrapped kc1 blind */     \
                                + sizeof(TOPRF_Share) /* msg: the noise_xk wrapped p share */       \
                                + sizeof(TOPRF_Share) /* msg: the noise_xk wrapped p blind */       \
                                + crypto_secretbox_xchacha20poly1305_MACBYTES /* mac of msg */      \
                                + crypto_auth_hmacsha256_BYTES /* key-committing mac over msg*/     )
static TOPRF_Update_Err peer_step9_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[%d] step 9. receive commitments & distribute shares via noise chans\x1b[0m\n", ctx->index);
  if(input_len != sizeof(TOPRF_Update_Message) + toprf_update_msg5_SIZE(ctx) * ctx->n) return Err_ISize;
  if(output_len != ctx->n * toprf_update_msg7_SIZE) return Err_OSize;

  // verify STP message envelope
  const uint8_t *ptr;
  int ret = unwrap_envelope(ctx,input,input_len,6,&ptr);
  if(ret!=Err_OK) return ret;

  for(uint8_t i=0;i<ctx->n;i++, ptr+=toprf_update_msg5_SIZE(ctx)) {
    const TOPRF_Update_Message* msg5 = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprf_update_msg5_SIZE(ctx),5,i+1,0xff)) continue;

    // extract peer commitments
    memcpy((*ctx->kc1_commitments)[i*ctx->n], msg5->data, crypto_core_ristretto255_BYTES * ctx->n);
    memcpy((*ctx->p_commitments)[i*ctx->n], msg5->data + crypto_core_ristretto255_BYTES * ctx->n, crypto_core_ristretto255_BYTES * ctx->n);
    if(log_file!=NULL) {
      dump((*ctx->kc1_commitments)[i*ctx->n], crypto_core_ristretto255_BYTES*ctx->n, "[%d] kc1 commitments [%d]", ctx->index, i+1);
      dump((*ctx->p_commitments)[i*ctx->n], crypto_core_ristretto255_BYTES*ctx->n, "[%d] p commitments [%d]", ctx->index, i+1);
    }
  }
  if(ctx->cheater_len>0) return Err_CheatersFound;

  uint8_t *wptr = output;
  for(uint8_t i=0;i<ctx->n;i++, wptr+=toprf_update_msg7_SIZE) {
    TOPRF_Update_Message *msg7 = (TOPRF_Update_Message *) wptr;

    // we need to send an empty packet, so that the handshake completes
    // and we have a final symetric key, the key during the handshake changes, only
    // when the handshake completes does the key become static.
    // this is important, so that when there are complaints, we can disclose the key.
    uint8_t empty[1]={0}; // would love to do [0] but that is undefined c
    if(0!=dkg_noise_encrypt(empty, 0, msg7->data, noise_xk_handshake3_SIZE, &(*ctx->noise_outs)[i])) return Err_NoiseEncrypt;

    uint8_t payload[sizeof(TOPRF_Share) * 4];
    memcpy(payload, (uint8_t*) &(*ctx->kc1_shares)[i], sizeof(TOPRF_Share)*2);
    memcpy(payload+sizeof(TOPRF_Share)*2, (uint8_t*) &(*ctx->p_shares)[i], sizeof(TOPRF_Share)*2);

#ifdef UNITTEST_CORRUPT
    // corrupt all shares
    static int corrupted_shares = 0;
    if(i+1 != ctx->index && corrupted_shares++ < ctx->t-1) {
      dump(payload, sizeof(payload), "[%d] corrupting share_%d", ctx->index, i+1);
      payload[2]^=0xff; // flip some bits
      dump(payload, sizeof(payload), "[%d] corrupted share_%d ", ctx->index, i+1);
    }
#endif // UNITTEST_CORRUPT
    if(0!=dkg_noise_encrypt(payload, sizeof(payload),
                            msg7->data + noise_xk_handshake3_SIZE, sizeof(payload) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                            &(*ctx->noise_outs)[i])) return Err_NoiseEncrypt;

    // we also need to use a key-commiting mac over the encrypted share, since poly1305 is not...
    crypto_auth(msg7->data + noise_xk_handshake3_SIZE + sizeof(payload) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                msg7->data + noise_xk_handshake3_SIZE,
                sizeof(payload) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                Noise_XK_session_get_key((*ctx->noise_outs)[i]));

    if(0!=toprf_send_msg(wptr, toprf_update_msg7_SIZE, 7, ctx->index, i+1, ctx->sig_sk, ctx->sessionid)) return Err_Send;
    dkg_dump_msg(wptr, toprf_update_msg7_SIZE, ctx->index);
  }

  ctx->step = TOPRF_Update_Peer_Verify_Commitments;

  return Err_OK;
}

static TOPRF_Update_Err stp_step10_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  // todo possibly keep a copy of each of these messages for later cheater identification in step 13+
  return stp_route(ctx, input, input_len, output, output_len,
                   "step 10. route shares from all peers to all peers",
                   ctx->n, ctx->n, 7, toprf_update_msg7_SIZE, TOPRF_Update_STP_Broadcast_Complaints);
}

#define toprf_update_msg8_SIZE(ctx) (sizeof(TOPRF_Update_Message) + (size_t)((ctx->n + 1)*2) )
static TOPRF_Update_Err peer_step11_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[%d] step 11. DKG step 2 - receive shares, verify commitments\x1b[0m\n", ctx->index);
  if(input_len != ctx->n * toprf_update_msg7_SIZE) return Err_ISize;
  if(output_len != toprf_update_msg8_SIZE(ctx)) return Err_OSize;

  const uint8_t *ptr = input;
  for(uint8_t i=0;i<ctx->n;i++) {
    const TOPRF_Update_Message* msg7 = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprf_update_msg7_SIZE,7,i+1,ctx->index)) continue;

    // decrypt final empty handshake packet
    if(0!=dkg_noise_decrypt(msg7->data, noise_xk_handshake3_SIZE, NULL, 0, &(*ctx->noise_ins)[i])) return Err_NoiseDecrypt;

    uint8_t payload[sizeof(TOPRF_Share)*4];
    if(0!=crypto_auth_verify(msg7->data + noise_xk_handshake3_SIZE + sizeof(payload) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                             msg7->data + noise_xk_handshake3_SIZE,
                             sizeof(payload) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                             Noise_XK_session_get_key((*ctx->noise_ins)[i]))) {
      return Err_HMac;
    }

    if(0!=dkg_noise_decrypt(msg7->data + noise_xk_handshake3_SIZE, sizeof(payload) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                              payload, sizeof(payload),
                              &(*ctx->noise_ins)[i])) return Err_NoiseDecrypt;

    memcpy((uint8_t*) &(*ctx->kc1_shares)[i], payload, sizeof(TOPRF_Share)*2);
    memcpy((uint8_t*) &(*ctx->p_shares)[i], payload+sizeof(TOPRF_Share)*2, sizeof(TOPRF_Share)*2);

    ptr+=toprf_update_msg7_SIZE;
  }
  if(ctx->cheater_len>0) return Err_CheatersFound;

  // 2. Players verify the VSPS property of the sum of the shared secrets by running
  //     VSPS-Check on  𝓐_i,..,𝓐_n where
  //
  //           𝓐_j = Π 𝓐_i,j
  //                 i
  //
  // If this check fails the players run VSPS-Check on each individual
  // sharing from step 1. Any player that fails this check is disqualified.
  // should we report the cheater and abort the protocol instead
  TOPRF_Update_Message* msg8 = (TOPRF_Update_Message*) output;
  uint8_t *fails_len = msg8->data;
  uint8_t *fails = msg8->data+1;
  memset(fails, 0, ctx->n);
  *fails_len=0;
  // instead of commmitments we check VSPS
  //for(unsigned i=0;i<ctx->n;i++) {
  //  if(0!=dkg_vss_verify_commitment(((const uint8_t (*)[ctx->n][32]) (*ctx->kc1_commitments))[i][ctx->index-1],(*ctx->kc1_shares)[i])) {
  //    if(log_file!=NULL) fprintf(log_file,"\x1b[0;31m[%d] failed to verify kc1 commitments from %d!\x1b[0m\n", ctx->index, i+1);
  //    fails[*fails_len++]=i+1;
  //  }
  //}
  // TODO we could persist A in kc1_commitments (and p_commitments) respectively, and skip the steps where those are broadcast. 22-23 and 24.
  uint8_t A[ctx->n][crypto_scalarmult_ristretto255_BYTES];
  uint8_t (*c)[ctx->n][ctx->n][crypto_core_ristretto255_BYTES] = (uint8_t (*)[ctx->n][ctx->n][crypto_core_ristretto255_BYTES]) ctx->kc1_commitments;
  for(unsigned i=0;i<ctx->n;i++) {
    memcpy(A[i], (*c)[i][0], crypto_scalarmult_ristretto255_BYTES);
    for(unsigned j=1;j<ctx->n;j++) {
      crypto_core_ristretto255_add(A[i], A[i], (*c)[j][i]);
    }
  }

  int ret = ft_or_full_vsps(ctx->n, ctx->t, ctx->n, ctx->index, A, c,
                            "VSPS failed kc1 during DKG, doing full VSPS check on all peers",
                            "VSPS failed kc1",
                            "ERROR, could not find and dealer commitments that fail the VSPS check",
                            fails_len, fails);
  if(ret!=Err_OK) return ret;

  fails_len = fails+ctx->n;
  fails = fails_len + 1;
  memset(fails, 0, ctx->n);
  *fails_len=0;
  // we check VSPS instead of commitments.
  //for(unsigned i=0;i<ctx->n;i++) {
  //    if(0!=dkg_vss_verify_commitment(((const uint8_t (*)[ctx->n][32]) (*ctx->p_commitments))[i][ctx->index-1],(*ctx->p_shares)[i])) {
  //      if(log_file!=NULL) fprintf(log_file,"\x1b[0;31m[%d] failed to verify p commitments from %d!\x1b[0m\n", ctx->index, i+1);
  //      fails[*fails_len++]=i+1;
  //    }
  //}
  c = (uint8_t (*)[ctx->n][ctx->n][crypto_core_ristretto255_BYTES]) ctx->p_commitments;
  for(unsigned i=0;i<ctx->n;i++) {
    memcpy(A[i], (*c)[i][0], crypto_scalarmult_ristretto255_BYTES);
    for(unsigned j=1;j<ctx->n;j++) {
      crypto_core_ristretto255_add(A[i], A[i], (*c)[j][i]);
    }
  }

  ret = ft_or_full_vsps(ctx->n, ctx->t, ctx->n, ctx->index, A, c,
                        "VSPS failed p during DKG, doing full VSPS check on all peers",
                        "VSPS failed p",
                        "ERROR, could not find and dealer commitments that fail the VSPS check",
                        fails_len, fails);
  if(ret!=Err_OK) return ret;

#ifdef UNITTEST_CORRUPT
  static int totalfails = 0;
  for(uint8_t i=1;i<=ctx->n;i++) {
    if(totalfails < ctx->t - ctx->index && *fails_len < ctx->t-1 && i != ctx->index) {
      // avoid duplicates
      int j;
      for(j=1;j<=msg8->data[0];j++) if(msg8->data[j]==i) break;
      if(j<=msg8->data[0]) continue;

      fails[msg8->data[0]++]=i;
      totalfails++;
    }
  }
#endif //UNITTEST_CORRUPT

  if(0!=toprf_send_msg(output, toprf_update_msg8_SIZE(ctx), 8, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return Err_Send;
  dkg_dump_msg(output, toprf_update_msg8_SIZE(ctx), ctx->index);

  ctx->step = TOPRF_Update_Peer_Handle_DKG_Complaints;

  return Err_OK;
}

#define toprf_update_msg9_SIZE(ctx) (sizeof(TOPRF_Update_Message) + (toprf_update_msg8_SIZE(ctx) * ctx->n))
static TOPRF_Update_Err stp_step12_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  return stp_complaint_handler(ctx, input, input_len, output, output_len,
                               "step 12. broadcast complaints of peers",
                               ctx->n, toprf_update_msg8_SIZE(ctx), 8, TOPRF_Update_STP_Broadcast_DKG_Transcripts, TOPRF_Update_STP_Route_DKG_Defenses);
}

static TOPRF_Update_Err peer_dkg_fork(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len) {
  return peer_complaint_handler(ctx, input, input_len,
                                "step 13. receive complaints broadcast",
                                toprf_update_msg8_SIZE(ctx), 8, TOPRF_Update_Peer_Finish_DKG, TOPRF_Update_Peer_Defend_DKG_Accusations);
}

#define toprf_update_msg20_SIZE (sizeof(TOPRF_Update_Message) + crypto_generichash_BYTES)
static TOPRF_Update_Err peer_step20_handler(TOPRF_Update_PeerState *ctx, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[%d] step 20. send DKG transcript\x1b[0m\n", ctx->index);
  if(output_len != toprf_update_msg20_SIZE) return Err_OSize;

  TOPRF_Update_Message* msg20 = (TOPRF_Update_Message*) output;
  crypto_generichash_state transcript_state;
  memcpy(&transcript_state, &ctx->transcript, sizeof transcript_state);
  crypto_generichash_final(&transcript_state, msg20->data, crypto_generichash_BYTES);
  if(0!=toprf_send_msg(output, toprf_update_msg20_SIZE, 20, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return Err_Send;
  dkg_dump_msg(output, toprf_update_msg20_SIZE, ctx->index);

  ctx->step = TOPRF_Update_Peer_Start_Mult;
  return Err_OK;
}

#define toprf_update_msg21_SIZE(ctx) (sizeof(TOPRF_Update_Message) + toprf_update_msg20_SIZE*ctx->n)
static TOPRF_Update_Err stp_step21_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[!] step 21. broadcast DKG transcripts\x1b[0m\n");

  if((toprf_update_msg20_SIZE * ctx->n) != input_len) return Err_ISize;
  if(output_len != toprf_update_msg21_SIZE(ctx)) return Err_OSize;

  uint8_t transcript_hash[crypto_generichash_BYTES];
  crypto_generichash_state transcript_state;
  memcpy(&transcript_state, &ctx->transcript, sizeof transcript_state);
  crypto_generichash_final(&transcript_state, transcript_hash, crypto_generichash_BYTES);

  uint8_t *wptr = ((TOPRF_Update_Message *) output)->data;
  const uint8_t *ptr = input;
  for(uint8_t i=0;i<ctx->n;i++, ptr+=toprf_update_msg20_SIZE) {
    const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) ptr;
    if(stp_recv_msg(ctx,ptr,toprf_update_msg20_SIZE , 20,i+1,0xff)) continue;

    if(sodium_memcmp(transcript_hash, msg->data, sizeof(transcript_hash))!=0) {
      if(log_file!=NULL) {
        fprintf(log_file,"\x1b[0;31m[!] failed to verify transcript from %d!\x1b[0m\n", i);
      }
      if(stp_add_cheater(ctx, 1, i+1, 0) == NULL) return Err_CheatersFull;
      continue;
    }

    memcpy(wptr, ptr, toprf_update_msg20_SIZE);
    wptr+=toprf_update_msg20_SIZE;
  }

  // add broadcast msg to transcript
  update_transcript(&ctx->transcript, output, output_len);

  if(0!=toprf_send_msg(output, output_len, 21, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return Err_Send;
  dkg_dump_msg(output, output_len, 0);

  ctx->step = TOPRF_Update_STP_Broadcast_DKG_Final_Commitments;
  return Err_OK;
}

#define toprf_update_msg22_SIZE (sizeof(TOPRF_Update_Message) + crypto_core_ristretto255_BYTES * 2)
static TOPRF_Update_Err peer_step22_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[%d] step 22. verify DKG transcripts, calculate shares and broadcasts their commitments\x1b[0m\n", ctx->index);
  if(input_len != toprf_update_msg21_SIZE(ctx)) return Err_ISize;
  if(output_len != toprf_update_msg22_SIZE) return Err_OSize;

  uint8_t transcript_hash[crypto_generichash_BYTES];
  crypto_generichash_state transcript_state;
  memcpy(&transcript_state, &ctx->transcript, sizeof transcript_state);
  crypto_generichash_final(&transcript_state, transcript_hash, crypto_generichash_BYTES);

  // verify STP message envelope
  const uint8_t *ptr;
  int ret = unwrap_envelope(ctx,input,input_len,21,&ptr);
  if(ret!=Err_OK) return ret;

  for(uint8_t i=0;i<ctx->n;i++, ptr+=toprf_update_msg20_SIZE) {
    const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprf_update_msg20_SIZE,20,i+1,0xff)) continue;

    if(sodium_memcmp(transcript_hash, msg->data, sizeof(transcript_hash))!=0) {
      if(log_file!=NULL) {
        fprintf(log_file,"\x1b[0;31m[!] failed to verify transcript from %d!\x1b[0m\n", i);
      }
      if(peer_add_cheater(ctx, 1, i+1, 0) == NULL) return Err_CheatersFull;
      continue;
    }
  }
  if(ctx->cheater_len>0) return Err_CheatersFound;

  // add broadcast msg to transcript - done before cheater detection now in unwrap_envelope()
  // todo check if this is ok doing it earlier
  // update_transcript(&ctx->transcript, input, input_len);

  // todo handle qual?
  uint8_t qual[ctx->n+1];
  for(unsigned i=0;i<ctx->n;i++) qual[i]=i+1; //everyone qualifies
  qual[ctx->n]=0;
  ctx->kc1_share[0].index=ctx->index;
  ctx->kc1_share[1].index=ctx->index;
  ctx->p_share[0].index=ctx->index;
  ctx->p_share[1].index=ctx->index;
  // finalize dkg
  if(0!=dkg_vss_finish(ctx->n,qual,(*ctx->kc1_shares),ctx->index,ctx->kc1_share, ctx->kc1_commitment)) return Err_DKGFinish;
  if(0!=dkg_vss_finish(ctx->n,qual,(*ctx->p_shares),ctx->index,ctx->p_share, ctx->p_commitment)) return Err_DKGFinish;

  // broadcast ctx->kc1_commitment and ctx->p_commitment
  TOPRF_Update_Message* msg22 = (TOPRF_Update_Message*) output;
  memcpy(msg22->data, ctx->kc1_commitment, crypto_core_ristretto255_BYTES);
  memcpy(msg22->data+crypto_core_ristretto255_BYTES, ctx->p_commitment, crypto_core_ristretto255_BYTES);

  if(0!=toprf_send_msg(output, toprf_update_msg22_SIZE, 22, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return Err_Send;
  dkg_dump_msg(output, toprf_update_msg22_SIZE, ctx->index);

  ctx->step = TOPRF_Update_Peer_Recv_K1P_Commitments;
  return Err_OK;
}

#define toprf_update_msg23_SIZE(ctx) (sizeof(TOPRF_Update_Message) + toprf_update_msg22_SIZE*ctx->n)
static TOPRF_Update_Err stp_step23_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  return stp_broadcast(ctx, input, input_len, output, output_len,
                       "step 23. broadcast k1 & p commitments",
                       ctx->n, toprf_update_msg22_SIZE, 22, TOPRF_Update_STP_Route_Mult_Step1);
}

#define toprf_update_msg24_SIZE(ctx) (sizeof(TOPRF_Update_Message) + crypto_core_ristretto255_BYTES * 2 * (ctx->n+1))
static TOPRF_Update_Err peer_step24_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[%d] step 24. receive and VSPS check k1 and p commitments, dealers calculate and share λ_iα_iβ_i\x1b[0m\n", ctx->index);
  if(input_len != toprf_update_msg23_SIZE(ctx)) return Err_ISize;
  if(output_len != isdealer(ctx->index, ctx->t) * toprf_update_msg24_SIZE(ctx)) return Err_OSize;

  // verify STP message envelope
  const uint8_t *ptr;
  int ret = unwrap_envelope(ctx,input,input_len,23,&ptr);
  if(ret!=Err_OK) return ret;

  for(uint8_t i=0;i<ctx->n;i++, ptr+=toprf_update_msg22_SIZE) {
    const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprf_update_msg22_SIZE,22,i+1,0xff)) continue;
    // extract kc1 and p commitments.
    memcpy((*ctx->kc1_commitments)[i], msg->data, crypto_core_ristretto255_BYTES);
    memcpy((*ctx->p_commitments)[i], msg->data+crypto_core_ristretto255_BYTES, crypto_core_ristretto255_BYTES);
    //dump(msg->data+crypto_core_ristretto255_BYTES, crypto_core_ristretto255_BYTES, "[%d] P[%d]", ctx->index, i+1);
  }
  if(ctx->cheater_len>0) return Err_CheatersFound;

  // add broadcast msg to transcript - done before cheater detection now in unwrap_envelope()
  // todo check if this is ok doing it earlier
  // update_transcript(&ctx->transcript, input, input_len);

  const uint8_t dealers = (ctx->t-1)*2 + 1;

  // precompute lambdas
  // λ_i is row 1 of inv VDM matrix
  uint8_t indexes[dealers];
  for(unsigned i=0;i<dealers;i++) indexes[i]=i+1;
  uint8_t lambdas[dealers][dealers][crypto_core_ristretto255_SCALARBYTES];
  invertedVDMmatrix(dealers, indexes, lambdas);
  memcpy((*ctx->lambdas), lambdas[0], dealers*crypto_core_ristretto255_SCALARBYTES);
  //dump((uint8_t*) lambdas[0], dealers*crypto_core_ristretto255_SCALARBYTES, "vdm[0] ");
  //dump((uint8_t*) (*ctx->lambdas), dealers*crypto_core_ristretto255_SCALARBYTES, "lambdas");

  if(ctx->index>dealers) { // non-dealers are done
    ctx->step = TOPRF_Update_Peer_Send_K1P_Shares;
    return Err_OK;
  }
  // dealers only
  // step 1. Each player P_i shares λ_iα_iβ_i, using VSS
  if(0!=toprf_mpc_ftmult_step1(dealers, ctx->n, ctx->t, ctx->index-1,
                               ctx->kc0_share, ctx->p_share, (*ctx->lambdas),
                               // we reuse kc1_shares as we need to store n shares, and k0p_shares has only dealer entries
                               (*ctx->kc1_shares), (*ctx->k0p_commitments),
                               (*ctx->k0p_commitments0)[0], ctx->k0p_tau)) {
      if(log_file!=NULL) fprintf(log_file, "[%d] failed toprf_mpc_ftmult_step1\n", ctx->index);
      return Err_FTMULTStep1;
  }
  if(0!=toprf_mpc_ftmult_step1(dealers, ctx->n, ctx->t, ctx->index-1,
                               ctx->kc1_share, ctx->p_share, (*ctx->lambdas),
                               // we reuse p_shares as we need to store n shares, and k0p_shares has only dealer entries
                               (*ctx->p_shares), (*ctx->k1p_commitments),
                               (*ctx->k1p_commitments0)[0], ctx->k1p_tau)) {
      if(log_file!=NULL) fprintf(log_file, "[%d] failed toprf_mpc_ftmult_step1\n", ctx->index);
      return Err_FTMULTStep1;
  }
  // send ci_shares[j] to P_j
  // broadcast ci_commitments
  TOPRF_Update_Message* msg24 = (TOPRF_Update_Message*) output;
  uint8_t *wptr = msg24->data;
  // k0*p commitment0
  memcpy(wptr, (*ctx->k0p_commitments0)[0], crypto_core_ristretto255_BYTES);
  wptr+=crypto_core_ristretto255_BYTES;
  // k0*p commitments
  memcpy(wptr, (*ctx->k0p_commitments), ctx->n * crypto_core_ristretto255_BYTES);
  wptr+=ctx->n * crypto_core_ristretto255_BYTES;
  // k1*p commitment0
  memcpy(wptr, (*ctx->k1p_commitments0), crypto_core_ristretto255_BYTES);
  wptr+=crypto_core_ristretto255_BYTES;
  // k1*p commitments
  memcpy(wptr, (*ctx->k1p_commitments), ctx->n * crypto_core_ristretto255_BYTES);
  wptr+=ctx->n * crypto_core_ristretto255_BYTES;
  if(0!=toprf_send_msg(output, toprf_update_msg24_SIZE(ctx), 24, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return Err_Send;
  dkg_dump_msg(output, toprf_update_msg24_SIZE(ctx), ctx->index);

  ctx->step = TOPRF_Update_Peer_Send_K1P_Shares;
  return Err_OK;
}

static TOPRF_Update_Err stp_step25_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = ((ctx->t-1)*2 + 1);
  return stp_broadcast(ctx, input, input_len, output, output_len,
                       "step 25. broadcast commitments",
                       dealers, toprf_update_msg24_SIZE(ctx), 24, TOPRF_Update_STP_Route_Encrypted_Mult_Shares);
}

#define toprf_update_msg26_SIZE (sizeof(TOPRF_Update_Message) /* header */                           \
                                 + sizeof(TOPRF_Share) /* msg: the noise_xk wrapped kc1 share */     \
                                 + sizeof(TOPRF_Share) /* msg: the noise_xk wrapped kc1 blind */     \
                                 + sizeof(TOPRF_Share) /* msg: the noise_xk wrapped p share */       \
                                 + sizeof(TOPRF_Share) /* msg: the noise_xk wrapped p blind */       \
                                 + crypto_secretbox_xchacha20poly1305_MACBYTES /* mac of msg */      \
                                 + crypto_auth_hmacsha256_BYTES /* key-committing mac over msg*/     )
static TOPRF_Update_Err peer_step26_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = ((ctx->t-1)*2 + 1);
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[%d] step 26. receive Mul commitments & distribute Mul shares via noise chans\x1b[0m\n", ctx->index);
  if(input_len != sizeof(TOPRF_Update_Message) + toprf_update_msg24_SIZE(ctx) * dealers) return Err_ISize;
  if(output_len != isdealer(ctx->index, ctx->t) * ctx->n * toprf_update_msg26_SIZE) return Err_OSize;

  // verify STP message envelope
  const uint8_t *ptr;
  int ret = unwrap_envelope(ctx,input,input_len,25,&ptr);
  if(ret!=Err_OK) return ret;

  for(uint8_t i=0;i<dealers;i++,ptr+=toprf_update_msg24_SIZE(ctx)) {
    const TOPRF_Update_Message* msg24 = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprf_update_msg24_SIZE(ctx),24,i+1,0xff)) continue;

    const uint8_t *dptr = msg24->data;
    memcpy((*ctx->k0p_commitments0)[i], dptr, crypto_core_ristretto255_BYTES);
    dptr+=crypto_core_ristretto255_BYTES;
    // k0*p commitments
    memcpy((*ctx->k0p_commitments)[i*ctx->n], dptr, ctx->n * crypto_core_ristretto255_BYTES);
    dptr+=ctx->n * crypto_core_ristretto255_BYTES;
    // k1*p commitment0
    memcpy((*ctx->k1p_commitments0)[i], dptr, crypto_core_ristretto255_BYTES);
    dptr+=crypto_core_ristretto255_BYTES;
    // k1*p commitments
    memcpy((*ctx->k1p_commitments)[i*ctx->n], dptr, ctx->n * crypto_core_ristretto255_BYTES);
    dptr+=ctx->n * crypto_core_ristretto255_BYTES;
  }
  if(ctx->cheater_len>0) return Err_CheatersFound;

  if(ctx->index>dealers) { // non-dealers are done
    ctx->step = TOPRF_Update_Peer_Recv_K1P_Shares;
    return Err_OK;
  }
  // dealers only
  // also distribute k0*p and k1*p shares to all
  uint8_t *wptr = output;
  for(unsigned i=0;i<ctx->n;i++,wptr+=toprf_update_msg26_SIZE) {
    TOPRF_Update_Message* msg26 = (TOPRF_Update_Message*) wptr;

    uint8_t payload[sizeof(TOPRF_Share) * 4];
    memcpy(payload, (uint8_t*) &(*ctx->kc1_shares)[i], sizeof(TOPRF_Share)*2);
    memcpy(payload+sizeof(TOPRF_Share)*2, (uint8_t*) &(*ctx->p_shares)[i], sizeof(TOPRF_Share)*2);

//#ifdef UNITTEST_CORRUPT
//    // corrupt all shares
//    static int corrupted_shares = 0;
//    if(i+1 != ctx->index && corrupted_shares++ < ctx->t-1) {
//      dump(payload, sizeof(payload), "[%d] corrupting share_%d", ctx->index, i+1);
//      payload[2]^=0xff; // flip some bits
//      dump(payload, sizeof(payload), "[%d] corrupted share_%d ", ctx->index, i+1);
//    }
//#endif // UNITTEST_CORRUPT

    if(0!=dkg_noise_encrypt(payload, sizeof(payload),
                            msg26->data, sizeof(payload) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                            &(*ctx->noise_outs)[i])) return Err_NoiseEncrypt;

    // we also need to use a key-commiting mac over the encrypted share, since poly1305 is not...
    crypto_auth(msg26->data + sizeof(payload) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                msg26->data,
                sizeof(payload) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                Noise_XK_session_get_key((*ctx->noise_outs)[i]));

    if(0!=toprf_send_msg(wptr, toprf_update_msg26_SIZE, 26, ctx->index, i+1, ctx->sig_sk, ctx->sessionid)) return Err_Send;
    dkg_dump_msg(wptr, toprf_update_msg26_SIZE, ctx->index);
  }

  ctx->step = TOPRF_Update_Peer_Recv_K1P_Shares;
  return Err_OK;
}

static TOPRF_Update_Err stp_step27_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = ((ctx->t-1)*2 + 1);
  return stp_route(ctx, input, input_len, output, output_len,
                   "step 27. route k0*p and k1*p shares from all dealers to all peers",
                   dealers, ctx->n, 26, toprf_update_msg26_SIZE, TOPRF_Update_STP_Route_ZK_Challenge_Commitments);
}

#define toprf_update_msg27_SIZE (sizeof(TOPRF_Update_Message) + 2 * crypto_scalarmult_ristretto255_BYTES)
static TOPRF_Update_Err peer_step28_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = ((ctx->t-1)*2 + 1);
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[%d] step 28. receive k0*p and k1*p shares, starts ZK proof of k0*p and k1*p shares\x1b[0m\n", ctx->index);
  if(input_len != dealers * toprf_update_msg26_SIZE) return Err_ISize;
  if(output_len != toprf_update_msg27_SIZE) return Err_OSize;

  //uint8_t (*c)[dealers][ctx->n][crypto_core_ristretto255_BYTES] = (uint8_t (*)[dealers][ctx->n][crypto_core_ristretto255_BYTES]) ctx->k0p_commitments;
  //for(unsigned i=0;i<dealers;i++) {
  //  dump((*ctx->k0p_commitments0)[i], crypto_core_ristretto255_BYTES, "c_%d0", i+1);
  //  for(unsigned j=0;j<ctx->n;j++) dump((*c)[i][j], crypto_core_ristretto255_BYTES, "c_%d%d", i+1,j+1);
  //}

  const uint8_t *ptr = input;
  for(uint8_t i=0;i<dealers;i++) {
    const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprf_update_msg26_SIZE,26,i+1,ctx->index)) continue;

    uint8_t payload[sizeof(TOPRF_Share)*4];
    if(0!=crypto_auth_verify(msg->data + sizeof(payload) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                             msg->data,
                             sizeof(payload) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                             Noise_XK_session_get_key((*ctx->noise_ins)[i]))) {
      return Err_HMac;
    }

    if(0!=dkg_noise_decrypt(msg->data, sizeof(payload) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                              payload, sizeof(payload),
                              &(*ctx->noise_ins)[i])) return Err_NoiseDecrypt;

    memcpy((uint8_t*) (*ctx->k0p_shares)[i], payload, sizeof(TOPRF_Share)*2);
    memcpy((uint8_t*) (*ctx->k1p_shares)[i], payload+ sizeof(TOPRF_Share)*2, sizeof(TOPRF_Share)*2);

    uint8_t (*c)[dealers][ctx->n][crypto_core_ristretto255_BYTES] = (uint8_t (*)[dealers][ctx->n][crypto_core_ristretto255_BYTES]) ctx->k0p_commitments;
    // todo do we need to verify commitments against shares? not according to the papers. only during reconstruction.
    if(0!=dkg_vss_verify_commitment((*c)[i][ctx->index-1], (*ctx->k0p_shares)[i])) {
      if(log_file!=NULL) {
        if(peer_add_cheater(ctx, 1, i+1, 0) == NULL) return Err_CheatersFull;
        fprintf(log_file,"\x1b[0;31m[%d] failed to verify k0*p commitment from %d!\x1b[0m\n", ctx->index, i+1);
        dump((*c)[i][ctx->index-1], crypto_core_ristretto255_BYTES, "c_%d%d", i+1, ctx->index);
        dump((uint8_t*) (*ctx->k0p_shares)[i], sizeof(TOPRF_Share)*2 , "s_%d%d", i+1, ctx->index);
      }
    }

    c = (uint8_t (*)[dealers][ctx->n][crypto_core_ristretto255_BYTES]) ctx->k1p_commitments;
    if(0!=dkg_vss_verify_commitment((*c)[i][ctx->index-1], (*ctx->k1p_shares)[i])) {
      if(log_file!=NULL) {
        if(peer_add_cheater(ctx, 2, i+1, 0) == NULL) return Err_CheatersFull;
        fprintf(log_file,"\x1b[0;31m[%d] failed to verify k1*p commitment from %d!\x1b[0m\n", ctx->index, i+1);
        dump((*c)[i][ctx->index-1], crypto_core_ristretto255_BYTES, "c_%d%d", i+1, ctx->index);
        dump((uint8_t*) (*ctx->k1p_shares)[i], sizeof(TOPRF_Share)*2 , "s_%d%d", i+1, ctx->index);
      }
    }

    ptr+=toprf_update_msg26_SIZE;
  }
  if(ctx->cheater_len>0) return Err_CheatersFound;

  // generate 2x nonces for ZK proof challenge, broadcast a commitment to it.
  TOPRF_Update_Message* msg = (TOPRF_Update_Message*) output;
  for(unsigned i=0;i<2;i++) {
    crypto_core_ristretto255_scalar_random(ctx->zk_chal_nonce[i][0]);
    crypto_core_ristretto255_scalar_random(ctx->zk_chal_nonce[i][1]);
    if(0!=dkg_vss_commit(ctx->zk_chal_nonce[i][0], ctx->zk_chal_nonce[i][1], msg->data + i*crypto_scalarmult_ristretto255_BYTES)) return Err_VSSCommit;
    //dump(msg->data + i*crypto_scalarmult_ristretto255_BYTES, crypto_scalarmult_ristretto255_BYTES, "<zk_challenge_commitment[%d][%d]", ctx->index, i);
  }

  if(0!=toprf_send_msg(output, toprf_update_msg27_SIZE, 27, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return Err_Send;
  dkg_dump_msg(output, toprf_update_msg27_SIZE, ctx->index);

  ctx->step = TOPRF_Update_Peer_Send_ZK_Commitments;
  return Err_OK;
}

static TOPRF_Update_Err stp_step29_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  return stp_broadcast(ctx, input, input_len, output, output_len,
                       "step 29. broadcast zk challenge commitments",
                       ctx->n, toprf_update_msg27_SIZE, 27, TOPRF_Update_STP_Route_ZK_commitments);
}

#define toprf_update_msg29_SIZE (sizeof(TOPRF_Update_Message) + 2 * 3 * crypto_scalarmult_ristretto255_SCALARBYTES)
static TOPRF_Update_Err peer_step30_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = ((ctx->t-1)*2 + 1);
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[%d] step 30. everyone receives all e_j nonces, dealers broadcast ZK commitments\x1b[0m\n", ctx->index);
  if(input_len != sizeof(TOPRF_Update_Message) + toprf_update_msg27_SIZE * ctx->n) return Err_ISize;
  if(output_len != isdealer(ctx->index, ctx->t) * toprf_update_msg29_SIZE) return Err_OSize;

  // verify STP message envelope
  const uint8_t *ptr;
  int ret = unwrap_envelope(ctx,input,input_len,28,&ptr);
  if(ret!=Err_OK) return ret;

  uint8_t (*zk_challenge_nonce_commitments)[2][ctx->n][crypto_scalarmult_ristretto255_BYTES] =
                               (uint8_t (*)[2][ctx->n][crypto_scalarmult_ristretto255_BYTES]) (ctx->zk_challenge_nonce_commitments);

  for(uint8_t i=0;i<ctx->n;i++,ptr+=toprf_update_msg27_SIZE) {
    const TOPRF_Update_Message* msg27 = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprf_update_msg27_SIZE,27,i+1,0xff)) continue;

    //dump(msg27->data, crypto_scalarmult_ristretto255_BYTES, "zk_e_nonce_%d commitment", i);
    for(unsigned j=0;j<2;j++) {
      memcpy((*zk_challenge_nonce_commitments)[j][i], msg27->data + j*crypto_scalarmult_ristretto255_BYTES, crypto_scalarmult_ristretto255_BYTES);
      //dump((*ctx->zk_challenge_nonce_commitments)[i][j], crypto_scalarmult_ristretto255_BYTES, ">zk_challenge_commitment[%d][%d]", i+1, j);
    }
  }
  if(ctx->cheater_len>0) return Err_CheatersFound;

  if(ctx->index>dealers) { // non-dealers are done
    ctx->step = TOPRF_Update_Peer_Send_ZK_nonces;
    return Err_OK;
  }
  // dealers only
  // also distribute k0*p and k1*p shares to all
  uint8_t *wptr = output;
  TOPRF_Update_Message* msg29 = (TOPRF_Update_Message*) wptr;
  //dump((*ctx->p_commitments)[ctx->index-1], crypto_core_ristretto255_BYTES, "B[%d]", ctx->index);
  uint8_t (*msgs)[3][crypto_scalarmult_ristretto255_SCALARBYTES] = (uint8_t (*)[3][crypto_scalarmult_ristretto255_SCALARBYTES]) msg29->data;
  for(unsigned i=0;i<2;i++) {
    if(0!=toprf_mpc_ftmult_zk_commitments((*ctx->p_commitments)[ctx->index-1],
                                          ctx->zk_params[i].d,     // uint8_t d[crypto_scalarmult_ristretto255_SCALARBYTES],
                                          ctx->zk_params[i].s,     // uint8_t s[crypto_scalarmult_ristretto255_SCALARBYTES],
                                          ctx->zk_params[i].x,     // uint8_t x[crypto_scalarmult_ristretto255_SCALARBYTES],
                                          ctx->zk_params[i].s_1,   // uint8_t s_1[crypto_scalarmult_ristretto255_SCALARBYTES],
                                          ctx->zk_params[i].s_2,   // uint8_t s_2[crypto_scalarmult_ristretto255_SCALARBYTES],
                                          msgs[i])) {
      return Err_FTMULTZKCommitments;
    }
    //dump(ctx->zk_params[i].d, crypto_core_ristretto255_SCALARBYTES, "[%d] d[%d][%d]", ctx->index, ctx->index, i);
    //dump(ctx->zk_params[i].s, crypto_core_ristretto255_SCALARBYTES, "[%d] s[%d][%d]", ctx->index, ctx->index, i);
    //dump(ctx->zk_params[i].x, crypto_core_ristretto255_SCALARBYTES, "[%d] x[%d][%d]", ctx->index, ctx->index, i);
    //dump(ctx->zk_params[i].s_1, crypto_core_ristretto255_SCALARBYTES, "[%d] s_1[%d][%d]", ctx->index, ctx->index, i);
    //dump(ctx->zk_params[i].s_2, crypto_core_ristretto255_SCALARBYTES, "[%d] s_2[%d][%d]", ctx->index, ctx->index, i);
    //dump(msgs[i][0], crypto_scalarmult_ristretto255_SCALARBYTES, "[%d] M[%d][%d]", ctx->index, ctx->index, i);
    //dump(msgs[i][1], crypto_scalarmult_ristretto255_SCALARBYTES, "[%d] M1[%d][%d]", ctx->index, ctx->index, i);
    //dump(msgs[i][2], crypto_scalarmult_ristretto255_SCALARBYTES, "[%d] M2[%d][%d]", ctx->index, ctx->index, i);
  }

  if(0!=toprf_send_msg(wptr, toprf_update_msg29_SIZE, 29, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return Err_Send;
  dkg_dump_msg(wptr, toprf_update_msg29_SIZE, ctx->index);

  ctx->step = TOPRF_Update_Peer_Send_ZK_nonces;
  return Err_OK;
}

static TOPRF_Update_Err stp_step31_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = ((ctx->t-1)*2 + 1);
  return stp_broadcast(ctx, input, input_len, output, output_len,
                       "step 31. broadcast ZK commitments",
                       dealers, toprf_update_msg29_SIZE, 29, TOPRF_Update_STP_Broadcast_ZK_nonces);
}

#define toprf_update_msg30_SIZE (sizeof(TOPRF_Update_Message) + 4*crypto_scalarmult_ristretto255_SCALARBYTES)
static TOPRF_Update_Err peer_step32_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = ((ctx->t-1)*2 + 1);
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[%d] step 32. receive dealers ZK commitments, broadcast zk nonce\x1b[0m\n", ctx->index);
  if(input_len != sizeof(TOPRF_Update_Message) + toprf_update_msg29_SIZE * dealers) return Err_ISize;
  if(output_len != toprf_update_msg30_SIZE) return Err_OSize;

  // verify STP message envelope
  const uint8_t *ptr;
  int ret = unwrap_envelope(ctx,input,input_len,30,&ptr);
  if(ret!=Err_OK) return ret;

  uint8_t (*zk_challenge_commitments)[2][dealers][3][crypto_scalarmult_ristretto255_SCALARBYTES] =
    (uint8_t (*)[2][dealers][3][crypto_scalarmult_ristretto255_SCALARBYTES]) ctx->zk_challenge_commitments;

  for(uint8_t i=0;i<dealers;i++,ptr+=toprf_update_msg29_SIZE) {
    const TOPRF_Update_Message* msg29 = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprf_update_msg29_SIZE,29,i+1,0xff)) continue;

    //dump(msg27->data, crypto_scalarmult_ristretto255_BYTES, "zk_e_nonce_%d commitment", i);
    for(unsigned p=0;p<2;p++) {
      memcpy((*zk_challenge_commitments)[p][i], msg29->data + p*3*crypto_scalarmult_ristretto255_SCALARBYTES, 3*crypto_scalarmult_ristretto255_SCALARBYTES);
    }
    //uint8_t (*msgs)[2][3][crypto_scalarmult_ristretto255_SCALARBYTES] = (uint8_t (*)[2][3][crypto_scalarmult_ristretto255_SCALARBYTES]) (*ctx->zk_challenge_commitments);
    //for(int p=0;p<2;p++) {
    //  dump(msgs[i][p][0], crypto_scalarmult_ristretto255_SCALARBYTES, "[%d] M[%d][%d]", ctx->index, i+1, p);
    //  dump(msgs[i][p][1], crypto_scalarmult_ristretto255_SCALARBYTES, "[%d] M1[%d][%d]", ctx->index, i+1, p);
    //  dump(msgs[i][p][2], crypto_scalarmult_ristretto255_SCALARBYTES, "[%d] M2[%d][%d]", ctx->index, i+1, p);
    //}
  }
  if(ctx->cheater_len>0) return Err_CheatersFound;

  TOPRF_Update_Message* msg31 = (TOPRF_Update_Message*) output;
  uint8_t *dptr = msg31->data;
  memcpy(dptr, ctx->zk_chal_nonce[0], 2*crypto_core_ristretto255_SCALARBYTES);
  //dump(dptr, 2*crypto_core_ristretto255_SCALARBYTES, "<zk_nonce[%d][0]", ctx->index);
  dptr+=2*crypto_core_ristretto255_SCALARBYTES;
  memcpy(dptr, ctx->zk_chal_nonce[1], 2*crypto_core_ristretto255_SCALARBYTES);
  //dump(dptr, 2*crypto_core_ristretto255_SCALARBYTES, "<zk_nonce[%d][1]", ctx->index);

  if(0!=toprf_send_msg(output, toprf_update_msg30_SIZE, 31, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return Err_Send;
  dkg_dump_msg(output, toprf_update_msg30_SIZE, ctx->index);

  ctx->step = TOPRF_Update_Peer_Send_ZK_proofs;

  return Err_OK;
}

static TOPRF_Update_Err stp_step33_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  return stp_broadcast(ctx, input, input_len, output, output_len,
                       "step 33. broadcast ZK nonces",
                       ctx->n, toprf_update_msg30_SIZE, 31, TOPRF_Update_STP_Route_ZK_Proofs);
}

static TOPRF_Update_Err aggregate_zk_challenges(TOPRF_Update_PeerState *ctx,
                                                const uint8_t dealers, const uint8_t n, const uint8_t p,
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
    for(unsigned i=0;i<n;i++) {
      if(dealer==i) continue;
      if(0!=dkg_vss_commit(zk_challenge_nonces[i][0], zk_challenge_nonces[i][1], zk_challenge_commitment)) {
        if(log_file!=NULL) fprintf(log_file, "vss-commit got an invalid point %d\n",i);
        return Err_VSSCommit;
      }
      if(memcmp(zk_challenge_commitment, zk_challenge_nonce_commitments[i], crypto_scalarmult_ristretto255_BYTES)!=0) {
        if(peer_add_cheater(ctx, 1+p, i+1, 0) == NULL) return Err_CheatersFull;
        if(log_file!=NULL) fprintf(log_file, "invalid e_i nonce commitment from %d\n",i);
        dump((uint8_t*)zk_challenge_nonces[i], 2*crypto_scalarmult_ristretto255_SCALARBYTES, "zk_nonce[%d][%d]", i+1, p);
        dump(zk_challenge_nonce_commitments[i], crypto_scalarmult_ristretto255_BYTES, "zk_challenge_commmitments[%d][%d]", i+1, p);
      }
      crypto_core_ristretto255_scalar_add(zk_challenge_e_i[dealer],
                                          zk_challenge_e_i[dealer],
                                          zk_challenge_nonces[i][0]);
    }
  }
  return Err_OK;
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

#define toprf_update_msg33_SIZE (sizeof(TOPRF_Update_Message) + 2 * 5 * crypto_scalarmult_ristretto255_SCALARBYTES)
static TOPRF_Update_Err peer_step34_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = ((ctx->t-1)*2 + 1);
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[%d] step 34. receive ZK nonces, dealers broadcast zk proof\x1b[0m\n", ctx->index);
  if(input_len != sizeof(TOPRF_Update_Message) + toprf_update_msg30_SIZE * ctx->n) return Err_ISize;
  if(output_len != isdealer(ctx->index, ctx->t) * toprf_update_msg33_SIZE) return Err_OSize;

  // verify STP message envelope
  const uint8_t *ptr;
  int ret = unwrap_envelope(ctx, input, input_len, 32, &ptr);
  if(ret!=Err_OK) return ret;

  uint8_t (*zk_challenge_nonces)[2][ctx->n][2][crypto_scalarmult_ristretto255_SCALARBYTES] =
                    (uint8_t (*)[2][ctx->n][2][crypto_scalarmult_ristretto255_SCALARBYTES]) ctx->zk_challenge_nonces;
  for(uint8_t i=0;i<ctx->n;i++,ptr+=toprf_update_msg30_SIZE) {
    const TOPRF_Update_Message* msg31 = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprf_update_msg30_SIZE,31,i+1,0xff)) continue;

    const uint8_t *dptr=msg31->data;
    memcpy((*zk_challenge_nonces)[0][i], dptr, 2*crypto_scalarmult_ristretto255_SCALARBYTES);
    //dump(dptr, 2*crypto_core_ristretto255_SCALARBYTES, ">zk_nonce[%d][0]", i+1);
    dptr+=2*crypto_scalarmult_ristretto255_SCALARBYTES;
    memcpy((*zk_challenge_nonces)[1][i], dptr, 2*crypto_scalarmult_ristretto255_SCALARBYTES);
    //dump(dptr, 2*crypto_core_ristretto255_SCALARBYTES, ">zk_nonce[%d][1]", i+1);
  }
  if(ctx->cheater_len>0) return Err_CheatersFound;

  uint8_t (*zk_challenge_e_i)[2][dealers][crypto_scalarmult_ristretto255_SCALARBYTES] =
                 (uint8_t (*)[2][dealers][crypto_scalarmult_ristretto255_SCALARBYTES]) ctx->zk_challenge_e_i;
  uint8_t (*zk_challenge_nonce_commitments)[2][ctx->n][crypto_scalarmult_ristretto255_BYTES] =
                               (uint8_t (*)[2][ctx->n][crypto_scalarmult_ristretto255_BYTES]) ctx->zk_challenge_nonce_commitments;

  for(unsigned p=0;p<2;p++) { // for both kc0p and kc1p seperately
    ret = aggregate_zk_challenges(ctx, dealers, ctx->n, p, (*zk_challenge_nonces)[p], (*zk_challenge_nonce_commitments)[p], (*zk_challenge_e_i)[p]);
    if(ret!=Err_OK) return ret;
  }
  if(ctx->cheater_len>0) return Err_CheatersFound;

  if(ctx->index>dealers) { // non-dealers are done
    ctx->step = TOPRF_Update_Peer_Verify_ZK_proofs;
    return Err_OK;
  }

  // dealers only
  TOPRF_Update_Message* msg31 = (TOPRF_Update_Message*) output;
  uint8_t *wptr=msg31->data;
  wptr=gen_zk_witnesses(ctx->index, dealers, ctx->kc0_share, ctx->p_share, ctx->k0p_tau,
                   (*zk_challenge_e_i)[0], ctx->zk_params[0], (*ctx->lambdas), wptr);
  wptr=gen_zk_witnesses(ctx->index, dealers, ctx->kc1_share, ctx->p_share, ctx->k1p_tau,
                   (*zk_challenge_e_i)[1], ctx->zk_params[1], (*ctx->lambdas), wptr);

  if(0!=toprf_send_msg(output, toprf_update_msg33_SIZE, 33, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return Err_Send;
  dkg_dump_msg(output, toprf_update_msg33_SIZE, ctx->index);

  ctx->step = TOPRF_Update_Peer_Verify_ZK_proofs;
  return Err_OK;
}

static TOPRF_Update_Err stp_step35_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = ((ctx->t-1)*2 + 1);
  return stp_broadcast(ctx, input, input_len, output, output_len,
                       "step 35. broadcast ZK proofs",
                       dealers, toprf_update_msg33_SIZE, 33, TOPRF_Update_STP_Broadcast_Mult_Complaints);
}

static TOPRF_Update_Err zk_verify_proof(TOPRF_Update_PeerState *ctx,
                                        const uint8_t p, const uint8_t prover,
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
  if(0!=dkg_vss_commit(proof.y, proof.w, v0)) return Err_VSSCommit;
  if(crypto_scalarmult_ristretto255(v1, e_i, B_i)) return Err_InvPoint;
  crypto_core_ristretto255_add(v1, M, v1);
  if(memcmp(v1, v0, crypto_scalarmult_ristretto255_BYTES)!=0) {
    if(log_file!=NULL) fprintf(stderr, RED"[%d] failed g^y * h^w   == M * B^e'_i for dealer %d"NORMAL, ctx->index, prover+1);
    dump(v1, crypto_scalarmult_ristretto255_BYTES, "lhs");
    dump(v0, crypto_scalarmult_ristretto255_BYTES, "rhs");
    fails[fails[0]++]=prover+1;
    if(peer_add_cheater(ctx, 1+p, prover+1, 0xff) == NULL) return Err_CheatersFull;
    return Err_OK;
  }

  //   g^z * h^w_1 == M_1 * A^e'_i
  if(0!=dkg_vss_commit(proof.z, proof.w_1, v0)) return Err_VSSCommit;
  if(crypto_scalarmult_ristretto255(v1, e_i, A_i)) return Err_InvPoint;
  if(crypto_scalarmult_ristretto255(v1, lambda, v1)) return Err_InvPoint;
  crypto_core_ristretto255_add(v1, M1, v1);
  if(memcmp(v1, v0, crypto_scalarmult_ristretto255_BYTES)!=0) {
    if(log_file!=NULL) fprintf(stderr, RED"[%d] failed g^z * h^w_1 == M_1 * A^e'_i for dealer %d"NORMAL, ctx->index, prover+1);
    dump(v1, crypto_scalarmult_ristretto255_BYTES, "lhs");
    dump(v0, crypto_scalarmult_ristretto255_BYTES, "rhs");
    fails[fails[0]++]=prover+1;
    if(peer_add_cheater(ctx, 3+p, prover+1, 0xff) == NULL) return Err_CheatersFull;
    return Err_OK;
  }

  //   B^z * h^w_2 == M_2 * C^e'_i
  if(crypto_scalarmult_ristretto255(v0, proof.z, B_i)) return Err_InvPoint;
  // we abuse v1 as a temp storage, v1 = h^w_2
  if(crypto_scalarmult_ristretto255(v1, proof.w_2, H)) return Err_InvPoint;
  crypto_core_ristretto255_add(v0, v0, v1);

  if(crypto_scalarmult_ristretto255(v1, e_i, C_i0)) return Err_InvPoint;
  crypto_core_ristretto255_add(v1, M2, v1);
  if(memcmp(v1, v0, crypto_scalarmult_ristretto255_BYTES)!=0) {
    if(log_file!=NULL) fprintf(stderr, RED"[%d] failed B^z * h^w_2 == M_2 * C^e'_i for dealer %d"NORMAL, ctx->index, prover+1);
    dump(v1, crypto_scalarmult_ristretto255_BYTES, "lhs");
    dump(v0, crypto_scalarmult_ristretto255_BYTES, "rhs");
    fails[fails[0]++]=prover+1;
    if(peer_add_cheater(ctx, 5+p, prover+1, 0xff) == NULL) return Err_CheatersFull;
    return Err_OK;
  }

  return Err_OK;
}

#define toprf_update_msg35_SIZE(ctx) (sizeof(TOPRF_Update_Message) + 2 * (1 + ((ctx->t-1)*2 + 1)))
static TOPRF_Update_Err peer_step36_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = ((ctx->t-1)*2 + 1);
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[%d] step 36. verify ZK proofs, accuse cheaters\x1b[0m\n", ctx->index);
  if(input_len != sizeof(TOPRF_Update_Message) + toprf_update_msg33_SIZE * dealers) return Err_ISize;
  if(output_len != toprf_update_msg35_SIZE(ctx)) return Err_OSize;

  // verify STP message envelope
  const uint8_t *ptr;
  int ret = unwrap_envelope(ctx, input, input_len, 34, &ptr);
  if(ret!=Err_OK) return ret;

  TOPRF_Update_Message* msg35 = (TOPRF_Update_Message*) output;
  uint8_t (*fails)[dealers+1]=(uint8_t (*)[dealers+1]) msg35->data;
  memset(*fails,0,2*(dealers+1));
  const uint8_t (*zk_challenge_commitments)[2][dealers][3][crypto_scalarmult_ristretto255_SCALARBYTES] =
                         (const uint8_t (*)[2][dealers][3][crypto_scalarmult_ristretto255_SCALARBYTES]) ctx->zk_challenge_commitments;
  const uint8_t (*zk_challenge_e_i)[2][dealers][crypto_scalarmult_ristretto255_SCALARBYTES] =
                       (uint8_t (*)[2][dealers][crypto_scalarmult_ristretto255_SCALARBYTES]) ctx->zk_challenge_e_i;

  for(uint8_t i=0;i<dealers;i++,ptr+=toprf_update_msg33_SIZE) {
    const TOPRF_Update_Message* msg33 = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprf_update_msg33_SIZE,33,i+1,0xff)) continue;

    const TOPRF_Update_ZK_proof (*proof)[2] = (const TOPRF_Update_ZK_proof (*)[2]) msg33->data;
    ret = zk_verify_proof(ctx, 0, i,
                          (*ctx->kc0_commitments)[i],
                          (*ctx->p_commitments)[i],
                          (*ctx->k0p_commitments0)[i],
                          (*zk_challenge_e_i)[0][i],
                          (*zk_challenge_commitments)[0][i],
                          (*ctx->lambdas)[i],
                          (*proof)[0],
                          fails[0]);
    if(ret != Err_OK) return ret;

    ret = zk_verify_proof(ctx, 1, i,
                          (*ctx->kc1_commitments)[i],
                          (*ctx->p_commitments)[i],
                          (*ctx->k1p_commitments0)[i],
                          (*zk_challenge_e_i)[1][i],
                          (*zk_challenge_commitments)[1][i],
                          (*ctx->lambdas)[i],
                          (*proof)[1],
                          fails[1]);
    if(ret != Err_OK) return ret;

  }
  if(ctx->cheater_len>0) return Err_CheatersFound;

  if(0!=toprf_send_msg(output, toprf_update_msg35_SIZE(ctx), 35, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return Err_Send;
  dkg_dump_msg(output, toprf_update_msg35_SIZE(ctx), ctx->index);

  ctx->step = TOPRF_Update_Peer_Handle_Mult_Complaints;

  return Err_OK;
}

#define toprf_update_msg36_SIZE(ctx) (sizeof(TOPRF_Update_Message) + (toprf_update_msg35_SIZE(ctx) * ctx->n))
static TOPRF_Update_Err stp_step37_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  return stp_complaint_handler(ctx, input, input_len, output, output_len,
                               "step 37. broadcast multiplication failure complaints",
                               ctx->n, toprf_update_msg35_SIZE(ctx), 35, TOPRF_Update_STP_Broadcast_Mult_Ci, TOPRF_Update_STP_Route_Mult_Reconstructions);
}

static TOPRF_Update_Err peer_zkproof_fork(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len) {
  return peer_complaint_handler(ctx, input, input_len,
                                "step 38. receive complaints about mult cheaters",
                                toprf_update_msg35_SIZE(ctx), 35, TOPRF_Update_Peer_Send_Mult_Ci, TOPRF_Update_Peer_Handle_Mult_Cheaters);
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
  memcpy((uint8_t*) &rshare[0], (uint8_t*) &shares_i[0][0], TOPRF_Share_BYTES);
  memcpy((uint8_t*) &rshare[1], (uint8_t*) &shares_i[0][1], TOPRF_Share_BYTES);
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
  if(0!=dkg_vss_commit(rshare[0].value, rshare[1].value, commitment)) return Err_VSSCommit;
  return Err_OK;
}

#define toprf_update_msg37_SIZE (sizeof(TOPRF_Update_Message) + 2*crypto_scalarmult_ristretto255_BYTES)
static TOPRF_Update_Err peer_step39_handler(TOPRF_Update_PeerState *ctx, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = ((ctx->t-1)*2 + 1);
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[%d] step 39. aggregate shares into final results and broadcast their commitment\x1b[0m\n", ctx->index);
  if(output_len != toprf_update_msg37_SIZE) return Err_OSize;

  TOPRF_Update_Message* msg = (TOPRF_Update_Message*) output;
  uint8_t (*C_i)[crypto_scalarmult_ristretto255_BYTES] = (uint8_t (*)[crypto_scalarmult_ristretto255_BYTES]) msg->data;
  int ret = compute_mul_share(dealers ,(*ctx->k0p_shares), ctx->k0p_share, C_i[0]);
  if(ret!=Err_OK) return ret;
  ret = compute_mul_share(dealers ,(*ctx->k1p_shares), ctx->k1p_share, C_i[1]);
  if(ret!=Err_OK) return ret;

  // use this below to calculate all commitments for the other peers
  uint8_t Cx_i[crypto_scalarmult_ristretto255_BYTES];
  uint8_t (*c)[dealers][ctx->n][crypto_core_ristretto255_BYTES] = (uint8_t (*)[dealers][ctx->n][crypto_core_ristretto255_BYTES]) ctx->k0p_commitments;
  memcpy(Cx_i, (*c)[0][ctx->index-1], crypto_scalarmult_ristretto255_BYTES);
  for(unsigned j=1;j<dealers;j++) {
    crypto_core_ristretto255_add(Cx_i, Cx_i, (*c)[j][ctx->index-1]);
  }
  // todo this check might not be needed
  if(memcmp(Cx_i, C_i[0], sizeof Cx_i) != 0) {
    if(log_file!=NULL) fprintf(stderr, RED"[%d] failed to verify commitment for k0p share"NORMAL, ctx->index);
    // todo cheater handling?
    return Err_CommmitmentsMismatch;
  }

  c = (uint8_t (*)[dealers][ctx->n][crypto_core_ristretto255_BYTES]) ctx->k1p_commitments;
  memcpy(Cx_i, (*c)[0][ctx->index-1], crypto_scalarmult_ristretto255_BYTES);
  for(unsigned j=1;j<dealers;j++) {
    crypto_core_ristretto255_add(Cx_i, Cx_i, (*c)[j][ctx->index-1]);
  }
  if(memcmp(Cx_i, C_i[1], sizeof Cx_i) != 0) {
    if(log_file!=NULL) fprintf(stderr, RED"[%d] failed to verify commitment for k1p share"NORMAL, ctx->index);
    return 99;
  }

  if(0!=toprf_send_msg(output, toprf_update_msg37_SIZE, 37, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return Err_Send;
  dkg_dump_msg(output, toprf_update_msg37_SIZE, ctx->index);

  ctx->step = TOPRF_Update_Peer_Final_VSPS_Checks;
  return Err_OK;
}

#define toprf_update_msg38_SIZE(ctx) (sizeof(TOPRF_Update_Message) + toprf_update_msg37_SIZE * ctx->n)
static TOPRF_Update_Err stp_step40_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[!] step 40. broadcast final mult commitments\x1b[0m\n");
  if(input_len != ctx->n * toprf_update_msg37_SIZE) return Err_ISize;
  if(output_len != toprf_update_msg38_SIZE(ctx)) return Err_OSize;

  const uint8_t *ptr = input;
  uint8_t *wptr = ((TOPRF_Update_Message *) output)->data;
  for(unsigned i=0;i<ctx->n;i++,ptr+=toprf_update_msg37_SIZE) {
    if(stp_recv_msg(ctx,ptr,toprf_update_msg37_SIZE, 37,i+1,0xff)) continue;
    const TOPRF_Update_Message *msg = (const TOPRF_Update_Message *) ptr;
    uint8_t (*C_i)[crypto_scalarmult_ristretto255_BYTES] = (uint8_t (*)[crypto_scalarmult_ristretto255_BYTES]) msg->data;
    // keep a copy of all commitments for final verification and for check before reconstructing r and r'
    memcpy((*ctx->k0p_final_commitments)[i], C_i[0], crypto_scalarmult_ristretto255_BYTES);
    memcpy((*ctx->k1p_final_commitments)[i], C_i[1], crypto_scalarmult_ristretto255_BYTES);

    memcpy(wptr, ptr, toprf_update_msg37_SIZE);
    wptr+=toprf_update_msg37_SIZE;

  }
  if(ctx->cheater_len>0) return Err_CheatersFound;

  // add broadcast msg to transcript
  update_transcript(&ctx->transcript, output, output_len);

  if(0!=toprf_send_msg(output, output_len, 38, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return Err_Send;
  dkg_dump_msg(output, output_len, 0);

  ctx->step = TOPRF_Update_STP_Broadcast_VSPS_Results;
  return Err_OK;
}

#define toprf_update_msg39_SIZE(ctx) (sizeof(TOPRF_Update_Message) + (size_t)((((ctx->t-1)*2 + 1) /*dealer*/ + 1 /*len*/)*2/*k0p&k1p*/) )
static TOPRF_Update_Err peer_step41_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  const uint8_t dealers = ((ctx->t-1)*2 + 1);
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[%d] step 41. receive final mult commitments, broadcast results of VSPS checks on them\x1b[0m\n", ctx->index);
  if(input_len != toprf_update_msg38_SIZE(ctx)) return Err_ISize;
  if(output_len != toprf_update_msg39_SIZE(ctx)) return Err_OSize;

  // verify STP message envelope
  const uint8_t *ptr;
  int ret = unwrap_envelope(ctx, input, input_len, 38, &ptr);
  if(ret!=Err_OK) return ret;

  uint8_t C_i[2][ctx->n][crypto_scalarmult_ristretto255_BYTES];
  for(uint8_t i=0;i<ctx->n;i++,ptr+=toprf_update_msg37_SIZE) {
    const TOPRF_Update_Message* msg37 = (const TOPRF_Update_Message*) ptr;
    if(peer_recv_msg(ctx,ptr,toprf_update_msg37_SIZE,37,i+1,0xff)) continue;
    memcpy(C_i[0][i], msg37->data, crypto_scalarmult_ristretto255_BYTES);
    memcpy(C_i[1][i], msg37->data+crypto_scalarmult_ristretto255_BYTES, crypto_scalarmult_ristretto255_BYTES);
  }
  if(ctx->cheater_len>0) return Err_CheatersFound;

  TOPRF_Update_Message* outmsg = (TOPRF_Update_Message*) output;
  uint8_t *fails_len = outmsg->data;
  uint8_t *fails = outmsg->data+1;
  memset(fails, 0, dealers);
  *fails_len=0;

  uint8_t (*c)[ctx->n][ctx->n][crypto_core_ristretto255_BYTES] = (uint8_t (*)[ctx->n][ctx->n][crypto_core_ristretto255_BYTES]) ctx->k0p_commitments;
  ret = ft_or_full_vsps(ctx->n, ctx->t, dealers, ctx->index, C_i[0], c,
                        "VSPS failed k0p, doing full VSPS check on all dealers",
                        "VSPS failed k0p",
                        "ERROR, could not find and dealer commitments that fail the VSPS check",
                        fails_len, fails);
  if(ret!=Err_OK) return ret;

  fails_len = fails+ctx->n;
  fails = fails_len + 1;
  memset(fails, 0, dealers);
  *fails_len=0;
  ret = ft_or_full_vsps(ctx->n, ctx->t, dealers, ctx->index, C_i[1], c,
                        "VSPS failed k1p, doing full VSPS check on all dealers",
                        "VSPS failed k1p",
                        "ERROR, could not find and dealer commitments that fail the VSPS check",
                        fails_len, fails);
  if(ret!=Err_OK) return ret;

  if(0!=toprf_send_msg(output, toprf_update_msg39_SIZE(ctx), 39, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return Err_Send;
  dkg_dump_msg(output, toprf_update_msg39_SIZE(ctx), ctx->index);

  ctx->step = TOPRF_Update_Peer_Recv_VSPS_Results;

  return Err_OK;
}

#define toprf_update_msg40_SIZE(ctx) (sizeof(TOPRF_Update_Message) + toprf_update_msg39_SIZE(ctx) * ctx->n)
static TOPRF_Update_Err stp_step42_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  return stp_complaint_handler(ctx, input, input_len, output, output_len,
                               "step 40. broadcast final VSPS results",
                               ctx->n, toprf_update_msg39_SIZE(ctx), 39, TOPRF_Update_STP_Reconstruct_Delta, TOPRF_Update_STP_Broadcast_Full_VSPS_Results);
}

static TOPRF_Update_Err peer_final_fork(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len) {
  return peer_complaint_handler(ctx, input, input_len,
                                "step 43. receive fast-track VSPS check results",
                                toprf_update_msg39_SIZE(ctx), 39, TOPRF_Update_Peer_Send_k0p_k1p_Share, TOPRF_Update_Peer_MULT_VSPS_Fail_Recover);
}

#define toprf_update_msg41_SIZE (sizeof(TOPRF_Update_Message) + 4 * TOPRF_Share_BYTES)
static int peer_step44_handler(TOPRF_Update_PeerState *ctx, uint8_t *output, const size_t output_len) {
  // todo maybe check the global transcript before sending the r & r' shares to stp?
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[%d] step 41. send final shared r (k0p) and r' (k1p) to STP\x1b[0m\n", ctx->index);
  if(output_len != toprf_update_msg41_SIZE) return Err_OSize;

  TOPRF_Update_Message* msg41 = (TOPRF_Update_Message*) output;
  memcpy(msg41->data, (uint8_t*) ctx->k0p_share, 2*TOPRF_Share_BYTES);
  memcpy(msg41->data+2*TOPRF_Share_BYTES, (uint8_t*) ctx->k1p_share, 2*TOPRF_Share_BYTES);

  if(0!=toprf_send_msg(output, toprf_update_msg41_SIZE, 41, ctx->index, 0, ctx->sig_sk, ctx->sessionid)) return Err_Send;
  dkg_dump_msg(output, toprf_update_msg41_SIZE, ctx->index);

  ctx->step = TOPRF_Update_Peer_Final_OK;
  return Err_OK;
}

#define toprf_update_msg42_SIZE (sizeof(TOPRF_Update_Message) + 1)
static int stp_step45_handler(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[!] step 45. reconstruct delta\x1b[0m\n");
  if(input_len != ctx->n * toprf_update_msg41_SIZE) return Err_ISize;
  if(output_len != toprf_update_msg42_SIZE) return Err_OSize;

  const uint8_t *ptr = input;
  TOPRF_Share k0p_shares[ctx->n][2];
  TOPRF_Share k1p_shares[ctx->n][2];
  for(unsigned i=0;i<ctx->n;i++,ptr+=toprf_update_msg41_SIZE) {
    const TOPRF_Update_Message *msg = (const TOPRF_Update_Message *) ptr;
    if(stp_recv_msg(ctx,ptr,toprf_update_msg41_SIZE, 41,i+1,0)) continue;
    memcpy(k0p_shares[i],msg->data,2*TOPRF_Share_BYTES);
    memcpy(k1p_shares[i],msg->data+2*TOPRF_Share_BYTES,2*TOPRF_Share_BYTES);
  }
  if(ctx->cheater_len>0) return Err_CheatersFound;

  TOPRF_Update_Message *outmsg = (TOPRF_Update_Message *) output;
  uint8_t *fail=outmsg->data;
  *fail = 0;

  debug=0;
  if(0!=toprf_mpc_vsps_check(ctx->t-1, (*ctx->k0p_final_commitments))) {
    if(log_file!=NULL) fprintf(stderr, RED"[!] VSPS failed k0p"NORMAL);
    *fail=1;
  }

  if(0!=toprf_mpc_vsps_check(ctx->t-1, (*ctx->k1p_final_commitments))) {
    if(log_file!=NULL) fprintf(stderr, RED"[!] VSPS failed k1p"NORMAL);
    *fail=1;
  }
  debug=1;

  for(unsigned i=0;i<ctx->n;i++) {
    if(0!=dkg_vss_verify_commitment((*ctx->k0p_final_commitments)[i], k0p_shares[i])) {
      if(log_file!=NULL) fprintf(stderr, RED"[!] failed to verify commitment for k0p share %d"NORMAL, i+1);
      dump((*ctx->k0p_final_commitments)[i], crypto_scalarmult_ristretto255_BYTES, "[!] C[%d]", i+1);
      dump((uint8_t*) k0p_shares[i], 2*TOPRF_Share_BYTES, "[!] s[%d]", i+1);
      *fail=1;
    }
    if(0!=dkg_vss_verify_commitment((*ctx->k1p_final_commitments)[i], k1p_shares[i])) {
      if(log_file!=NULL) fprintf(stderr, RED"[!] failed to verify commitment for k1p share %d"NORMAL, i+1);
      dump((*ctx->k1p_final_commitments)[i], crypto_scalarmult_ristretto255_BYTES, "[!] C[%d]", i+1);
      dump((uint8_t*) k1p_shares[i], 2*TOPRF_Share_BYTES, "[!] s[%d]", i+1);
      *fail=1;
    }
  }

  if(*fail == 0) {
    // reconstruct delta
    uint8_t r[crypto_scalarmult_ristretto255_SCALARBYTES];
    uint8_t r1[crypto_scalarmult_ristretto255_SCALARBYTES];
    dkg_vss_reconstruct(ctx->t, k0p_shares, r, NULL);
    dump(r, sizeof r, "[!] r  ");
    dkg_vss_reconstruct(ctx->t, k1p_shares, r1, NULL);
    dump(r1, sizeof r1, "[!] r1 ");
    uint8_t r1inv[crypto_scalarmult_ristretto255_SCALARBYTES];
    if(0!=crypto_core_ristretto255_scalar_invert(r1inv, r1)) return Err_InvPoint;
    crypto_core_ristretto255_scalar_mul(ctx->delta, r, r1inv);
    dump(ctx->delta, crypto_scalarmult_ristretto255_SCALARBYTES, "[!] ∆ ");
  }

  if(0!=toprf_send_msg(output, output_len, 42, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return Err_Send;
  dkg_dump_msg(output, output_len, 0);

  ctx->step = TOPRF_Update_STP_Done;
  return Err_OK;
}

static TOPRF_Update_Err peer_step46_handler(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len) {
  if(log_file!=NULL) fprintf(log_file, "\x1b[0;33m[%d] step 46. receive final confirmation from STP\x1b[0m\n", ctx->index);
  if(input_len != toprf_update_msg42_SIZE) return Err_ISize;

  // verify STP message envelope
  const TOPRF_Update_Message* msg = (const TOPRF_Update_Message*) input;
  dkg_dump_msg(input, input_len, ctx->index);
  int ret = toprf_recv_msg(input, input_len, 42, 0, 0xff, (*ctx->sig_pks)[0], ctx->sessionid, ctx->ts_epsilon, &ctx->stp_last_ts);
  if(0!=ret) return Err_BroadcastEnv+ret;

  if(msg->data[0]!=0) {
      if(log_file!=NULL) fprintf(stderr, RED"[%d] STP indicated failure at final step discarding all results, keeping old key"NORMAL, ctx->index);
      return Err_Proto;
  } else {
      if(log_file!=NULL) fprintf(stderr, "\x1b[0;32m[%d] STP indicated full success updating old key to new key"NORMAL, ctx->index);
  }

  ctx->step = TOPRF_Update_Peer_Done;
  return Err_OK;
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
  //memset(sizes,0,sizeof sizes);
  if(toprf_update_stp_input_sizes(ctx, sizes) == 1) {
    return sizes[0] * ctx->n;
  } else {
    size_t result=0;
    for(int i=0;i<ctx->n;i++) result+=sizes[i];
    return result;
  }
}

int toprf_update_stp_input_sizes(const TOPRF_Update_STPState *ctx, size_t *sizes) {
  size_t item=0;
  switch(ctx->step) {
  case TOPRF_Update_STP_Broadcast_NPKs: { item=toprf_update_msg1_SIZE; break; }
  case TOPRF_Update_STP_Route_Noise_Handshakes1: { item=toprf_update_msg3_SIZE * ctx->n; break; }
  case TOPRF_Update_STP_Route_Noise_Handshakes2: { item=toprf_update_msg4_SIZE * ctx->n; break; }
  case TOPRF_Update_STP_Broadcast_DGK_Commitments: { item = toprf_update_msg5_SIZE(ctx); break; }
  case TOPRF_Update_STP_Route_Encrypted_Shares: { item = toprf_update_msg7_SIZE * ctx->n; break; }
  case TOPRF_Update_STP_Broadcast_Complaints: { item = toprf_update_msg8_SIZE(ctx); break; }
  case TOPRF_Update_STP_Broadcast_DKG_Transcripts: { item = toprf_update_msg20_SIZE; break; }
  case TOPRF_Update_STP_Broadcast_DKG_Final_Commitments: { item = toprf_update_msg22_SIZE; break; }
  case TOPRF_Update_STP_Route_Mult_Step1: {
    for(unsigned i=0;i<ctx->n;i++) {
      sizes[i] = isdealer(i+1, ctx->t) * toprf_update_msg24_SIZE(ctx);
    }
    return 0;
  }
  case TOPRF_Update_STP_Route_Encrypted_Mult_Shares: {
    for(unsigned i=0;i<ctx->n;i++) {
      sizes[i] = isdealer(i+1, ctx->t) * (toprf_update_msg26_SIZE * ctx->n);
    }
    return 0;
  }
  case TOPRF_Update_STP_Route_ZK_Challenge_Commitments: { item = toprf_update_msg27_SIZE; break; }
  case TOPRF_Update_STP_Route_ZK_commitments: {
    for(unsigned i=0;i<ctx->n;i++) {
      sizes[i] = isdealer(i+1, ctx->t) * toprf_update_msg29_SIZE;
    }
    return 0;
  }
  case TOPRF_Update_STP_Broadcast_ZK_nonces: { item = toprf_update_msg30_SIZE; break; }
  case TOPRF_Update_STP_Route_ZK_Proofs: {
    for(unsigned i=0;i<ctx->n;i++) {
      sizes[i] = isdealer(i+1, ctx->t) * toprf_update_msg33_SIZE;
    }
    return 0;
  }
  case TOPRF_Update_STP_Broadcast_Mult_Complaints: { item = toprf_update_msg35_SIZE(ctx); break; }
  case TOPRF_Update_STP_Broadcast_Mult_Ci: { item = toprf_update_msg37_SIZE; break; }
  case TOPRF_Update_STP_Broadcast_VSPS_Results: { item = toprf_update_msg39_SIZE(ctx); break; }
  case TOPRF_Update_STP_Reconstruct_Delta: { item = toprf_update_msg41_SIZE; break; }
    //case 8: {
    //  uint8_t ctr[ctx->n];
    //  memset(ctr,0,ctx->n);
    //  for(int i=0;i<ctx->complaints_len;i++) ctr[((*ctx->complaints)[i] & 0xff) - 1]++;
    //  for(int i=0;i<ctx->n;i++) {
    //    if(ctr[i]>0) {
    //      sizes[i]=sizeof(TOPRF_Update_Message) + (1+dkg_noise_key_SIZE) * ctr[i];
    //    } else {
    //      sizes[i]=0;
    //    }
    //  }
    //  return 0;
    //}
  default: {
    if(log_file!=NULL) fprintf(log_file, "[!] isize invalid stp step: %d\n", ctx->step);
  }
  }

  for(uint8_t i=0;i<ctx->n;i++) {
    sizes[i] = item;
  }
  return 1;
}

size_t toprf_update_stp_output_size(const TOPRF_Update_STPState *ctx) {
  switch(ctx->step) {
  case TOPRF_Update_STP_Broadcast_NPKs: return toprf_update_msg1_SIZE * ctx->n + sizeof(TOPRF_Update_Message);
  case TOPRF_Update_STP_Route_Noise_Handshakes1: return toprf_update_msg3_SIZE * ctx->n * ctx->n;
  case TOPRF_Update_STP_Route_Noise_Handshakes2: return toprf_update_msg4_SIZE * ctx->n * ctx->n;
  case TOPRF_Update_STP_Broadcast_DGK_Commitments: return sizeof(TOPRF_Update_Message) + (toprf_update_msg5_SIZE(ctx) * ctx->n);
  case TOPRF_Update_STP_Route_Encrypted_Shares: return toprf_update_msg7_SIZE * ctx->n * ctx->n;
  case TOPRF_Update_STP_Broadcast_Complaints: return toprf_update_msg9_SIZE(ctx);
  case TOPRF_Update_STP_Broadcast_DKG_Transcripts: return toprf_update_msg21_SIZE(ctx);
  case TOPRF_Update_STP_Broadcast_DKG_Final_Commitments: return toprf_update_msg23_SIZE(ctx);
  case TOPRF_Update_STP_Route_Mult_Step1: return sizeof(TOPRF_Update_Message) + toprf_update_msg24_SIZE(ctx) * ((ctx->t-1)*2 + 1);
  case TOPRF_Update_STP_Route_Encrypted_Mult_Shares: return (toprf_update_msg26_SIZE * ctx->n) * ((ctx->t-1)*2 + 1);
  case TOPRF_Update_STP_Route_ZK_Challenge_Commitments: return sizeof(TOPRF_Update_Message) + (toprf_update_msg27_SIZE * ctx->n);
  case TOPRF_Update_STP_Route_ZK_commitments: return sizeof(TOPRF_Update_Message) + toprf_update_msg29_SIZE * ((ctx->t-1)*2 + 1);
  case TOPRF_Update_STP_Broadcast_ZK_nonces: return sizeof(TOPRF_Update_Message) + toprf_update_msg30_SIZE * ctx->n;
  case TOPRF_Update_STP_Route_ZK_Proofs: return sizeof(TOPRF_Update_Message) + toprf_update_msg33_SIZE * ((ctx->t-1)*2 + 1);
  case TOPRF_Update_STP_Broadcast_Mult_Complaints: return toprf_update_msg36_SIZE(ctx);
  case TOPRF_Update_STP_Broadcast_Mult_Ci: return toprf_update_msg38_SIZE(ctx);
  case TOPRF_Update_STP_Broadcast_VSPS_Results: return toprf_update_msg40_SIZE(ctx);
  case TOPRF_Update_STP_Reconstruct_Delta: return toprf_update_msg42_SIZE;
  default: if(log_file!=NULL) fprintf(log_file, "[!] osize invalid stp step: %d\n", ctx->step);
  }
  return 0;
}

int toprf_update_stp_peer_msg(const TOPRF_Update_STPState *ctx, const uint8_t *base, const size_t base_size, const uint8_t peer, const uint8_t **msg, size_t *len) {
  if(peer>=ctx->n) return -1;

  switch(ctx->prev) {
  case TOPRF_Update_STP_Broadcast_NPKs: {
    *msg = base;
    *len = toprf_update_msg1_SIZE * ctx->n + sizeof(TOPRF_Update_Message);
    break;
  }
  case TOPRF_Update_STP_Route_Noise_Handshakes1: {
    *msg = base + peer * toprf_update_msg3_SIZE * ctx->n;
    *len = toprf_update_msg3_SIZE * ctx->n;
    break;
  }
  case TOPRF_Update_STP_Route_Noise_Handshakes2: {
    *msg = base + peer * toprf_update_msg4_SIZE * ctx->n;
    *len = toprf_update_msg3_SIZE * ctx->n;
    break;
  }
  case TOPRF_Update_STP_Broadcast_DGK_Commitments: {
    *msg = base;
    *len = sizeof(TOPRF_Update_Message) + (toprf_update_msg5_SIZE(ctx) * ctx->n);
    break;
  }
  case TOPRF_Update_STP_Route_Encrypted_Shares: {
    *msg = base + peer * toprf_update_msg7_SIZE * ctx->n;
    *len = toprf_update_msg7_SIZE * ctx->n;
    break;
  }
  case TOPRF_Update_STP_Broadcast_Complaints: {
    *msg = base;
    *len = sizeof(TOPRF_Update_Message) + (toprf_update_msg8_SIZE(ctx) * ctx->n);
    break;
  }
  case TOPRF_Update_STP_Broadcast_DKG_Transcripts: {
    *msg = base;
    *len = toprf_update_msg21_SIZE(ctx);
    break;
  }
  case TOPRF_Update_STP_Broadcast_DKG_Final_Commitments: {
    *msg = base;
    *len = toprf_update_msg23_SIZE(ctx);
    break;
  }
  case TOPRF_Update_STP_Route_Mult_Step1: {
    *msg = base;
    *len = sizeof(TOPRF_Update_Message) + toprf_update_msg24_SIZE(ctx) * ((ctx->t-1)*2 + 1);
    break;
  }
  case TOPRF_Update_STP_Route_Encrypted_Mult_Shares: {
    *msg = base + peer * toprf_update_msg26_SIZE * ((ctx->t-1)*2 + 1);
    *len = toprf_update_msg26_SIZE * ((ctx->t-1)*2 + 1);
    break;
  }
  case TOPRF_Update_STP_Route_ZK_Challenge_Commitments: {
    *msg = base;
    *len = sizeof(TOPRF_Update_Message) + (toprf_update_msg27_SIZE * ctx->n);
    break;
  }
  case TOPRF_Update_STP_Route_ZK_commitments: {
    *msg = base;
    *len = sizeof(TOPRF_Update_Message) + toprf_update_msg29_SIZE * ((ctx->t-1)*2 + 1);
    break;
  }
  case TOPRF_Update_STP_Broadcast_ZK_nonces: {
    *msg = base;
    *len = sizeof(TOPRF_Update_Message) + toprf_update_msg30_SIZE * ctx->n;
    break;
  }
  case TOPRF_Update_STP_Route_ZK_Proofs: {
    *msg = base;
    *len = sizeof(TOPRF_Update_Message) + toprf_update_msg33_SIZE * ((ctx->t-1)*2 + 1);
    break;
  }
  case TOPRF_Update_STP_Broadcast_Mult_Complaints: {
    *msg = base;
    *len = toprf_update_msg36_SIZE(ctx);
    break;
  }
  case TOPRF_Update_STP_Broadcast_Mult_Ci: {
    *msg = base;
    *len = toprf_update_msg38_SIZE(ctx);
    break;
  }
  case TOPRF_Update_STP_Broadcast_VSPS_Results: {
    *msg = base;
    *len = toprf_update_msg40_SIZE(ctx);
    break;
  }
  case TOPRF_Update_STP_Reconstruct_Delta: {
    *msg = base;
    *len = toprf_update_msg42_SIZE;
    break;
  }
  default: {
    if(log_file!=NULL) fprintf(log_file, "[!] invalid stp step in toprf_update_stp_peer_msg\n");
    return 1;
  }
  }

  if(base+base_size < *msg + *len) {
    if(log_file!=NULL) fprintf(log_file, "buffer overread detected in toprf_update_stp_peer_msg %ld\n", (base+base_size) - (*msg + *len));
    return 2;
  }

  return 0;
}

size_t toprf_update_peer_input_size(const TOPRF_Update_PeerState *ctx) {
  switch(ctx->step) {
  case TOPRF_Update_Peer_Broadcast_NPK_SIDNonce: return 0;
  case TOPRF_Update_Peer_Rcv_NPK_SIDNonce: return toprf_update_msg1_SIZE * ctx->n + sizeof(TOPRF_Update_Message);
  case TOPRF_Update_Peer_Noise_Handshake: return toprf_update_msg3_SIZE * ctx->n;
  case TOPRF_Update_Peer_Finish_Noise_Handshake: return toprf_update_msg4_SIZE * ctx->n;
  case TOPRF_Update_Peer_Rcv_Commitments_Send_Shares: return sizeof(TOPRF_Update_Message) + (toprf_update_msg5_SIZE(ctx) * ctx->n);
  case TOPRF_Update_Peer_Verify_Commitments: return ctx->n * toprf_update_msg7_SIZE;
  case TOPRF_Update_Peer_Handle_DKG_Complaints: return toprf_update_msg9_SIZE(ctx);
  case TOPRF_Update_Peer_Finish_DKG: return 0;
  case TOPRF_Update_Peer_Start_Mult: return toprf_update_msg21_SIZE(ctx);
  case TOPRF_Update_Peer_Recv_K1P_Commitments: return toprf_update_msg23_SIZE(ctx);
  case TOPRF_Update_Peer_Send_K1P_Shares: return sizeof(TOPRF_Update_Message) + toprf_update_msg24_SIZE(ctx) * ((ctx->t-1)*2 + 1);
  case TOPRF_Update_Peer_Recv_K1P_Shares: return toprf_update_msg26_SIZE * ((ctx->t-1)*2 + 1);
  case TOPRF_Update_Peer_Send_ZK_Commitments: return sizeof(TOPRF_Update_Message) + toprf_update_msg27_SIZE * ctx->n;
  case TOPRF_Update_Peer_Send_ZK_nonces: return sizeof(TOPRF_Update_Message) + toprf_update_msg29_SIZE * ((ctx->t-1)*2 + 1);
  case TOPRF_Update_Peer_Send_ZK_proofs: return sizeof(TOPRF_Update_Message) + toprf_update_msg30_SIZE * ctx->n;
  case TOPRF_Update_Peer_Verify_ZK_proofs: return sizeof(TOPRF_Update_Message) + toprf_update_msg33_SIZE * ((ctx->t-1)*2 + 1);
  case TOPRF_Update_Peer_Handle_Mult_Complaints: return toprf_update_msg36_SIZE(ctx);
  case TOPRF_Update_Peer_Send_Mult_Ci: return 0;
  case TOPRF_Update_Peer_Final_VSPS_Checks: return toprf_update_msg38_SIZE(ctx);
  case TOPRF_Update_Peer_Recv_VSPS_Results: return toprf_update_msg40_SIZE(ctx);
  case TOPRF_Update_Peer_Send_k0p_k1p_Share: return 0;
  case TOPRF_Update_Peer_Final_OK: return toprf_update_msg42_SIZE;
  default: {
    if(log_file!=NULL) fprintf(log_file, "[%d] invalid step\n", ctx->index);
  }
  }
  return 1;
}

size_t toprf_update_peer_output_size(const TOPRF_Update_PeerState *ctx) {
  switch(ctx->step) {
  case TOPRF_Update_Peer_Broadcast_NPK_SIDNonce: return toprf_update_msg1_SIZE;
  case TOPRF_Update_Peer_Rcv_NPK_SIDNonce: return toprf_update_msg3_SIZE * ctx->n;
  case TOPRF_Update_Peer_Noise_Handshake: return toprf_update_msg4_SIZE * ctx->n;
  case TOPRF_Update_Peer_Finish_Noise_Handshake: return toprf_update_msg5_SIZE(ctx);
  case TOPRF_Update_Peer_Rcv_Commitments_Send_Shares: return ctx->n * toprf_update_msg7_SIZE;
  case TOPRF_Update_Peer_Verify_Commitments: return toprf_update_msg8_SIZE(ctx);
  case TOPRF_Update_Peer_Handle_DKG_Complaints: return 0;
  case TOPRF_Update_Peer_Finish_DKG: return toprf_update_msg20_SIZE;
  case TOPRF_Update_Peer_Start_Mult: return toprf_update_msg22_SIZE;
  case TOPRF_Update_Peer_Recv_K1P_Commitments: return isdealer(ctx->index, ctx->t) * toprf_update_msg24_SIZE(ctx);
  case TOPRF_Update_Peer_Send_K1P_Shares: return isdealer(ctx->index, ctx->t) * toprf_update_msg26_SIZE * ctx->n;
  case TOPRF_Update_Peer_Recv_K1P_Shares: return toprf_update_msg27_SIZE;
  case TOPRF_Update_Peer_Send_ZK_Commitments: return isdealer(ctx->index, ctx->t) * toprf_update_msg29_SIZE;
  case TOPRF_Update_Peer_Send_ZK_nonces: return toprf_update_msg30_SIZE;
  case TOPRF_Update_Peer_Send_ZK_proofs: return isdealer(ctx->index, ctx->t) * toprf_update_msg33_SIZE;
  case TOPRF_Update_Peer_Verify_ZK_proofs: return toprf_update_msg35_SIZE(ctx);
  case TOPRF_Update_Peer_Handle_Mult_Complaints: return 0;
  case TOPRF_Update_Peer_Send_Mult_Ci: return toprf_update_msg37_SIZE;
  case TOPRF_Update_Peer_Final_VSPS_Checks: return toprf_update_msg39_SIZE(ctx);
  case TOPRF_Update_Peer_Recv_VSPS_Results: return 0;
  case TOPRF_Update_Peer_Send_k0p_k1p_Share: return toprf_update_msg41_SIZE;
  case TOPRF_Update_Peer_Final_OK: return 0;

    //case 8: {
    //  if(ctx->complaints_len > 0) {
    //    if(ctx->my_complaints_len > 0) {
    //      return sizeof(TOPRF_Update_Message) + ctx->my_complaints_len * (1+dkg_noise_key_SIZE);
    //    }
    //    return 0;
    //  }
    //  return toprf_update_msg19_SIZE;
    //}
  default: {
    if(log_file!=NULL) fprintf(log_file, "[%d] invalid step\n", ctx->index);
  }
  }
  return 1;
}
int toprf_update_stp_next(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  int ret = 0;
  ctx->prev=ctx->step;
  switch(ctx->step) {
  case TOPRF_Update_STP_Broadcast_NPKs: { ret =  stp_step2_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Route_Noise_Handshakes1: { ret = stp_step4_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Route_Noise_Handshakes2: { ret = stp_step6_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Broadcast_DGK_Commitments: { ret = stp_step8_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Route_Encrypted_Shares: { ret = stp_step10_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Broadcast_Complaints: { ret = stp_step12_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Broadcast_DKG_Transcripts: { ret = stp_step21_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Broadcast_DKG_Final_Commitments: { ret = stp_step23_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Route_Mult_Step1: { ret = stp_step25_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Route_Encrypted_Mult_Shares: { ret = stp_step27_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Route_ZK_Challenge_Commitments: { ret = stp_step29_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Route_ZK_commitments: { ret = stp_step31_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Broadcast_ZK_nonces: { ret = stp_step33_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Route_ZK_Proofs: { ret = stp_step35_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Broadcast_Mult_Complaints: { ret = stp_step37_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Broadcast_Mult_Ci: { ret = stp_step40_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Broadcast_VSPS_Results: { ret = stp_step42_handler(ctx, input, input_len, output, output_len); break;}
  case TOPRF_Update_STP_Reconstruct_Delta: { ret = stp_step45_handler(ctx, input, input_len, output, output_len); break;}
    //case 7: {
    //  ret = stp_step18_handler(ctx, input, input_len, output, output_len);
    //  ctx->prev = ctx->step;
    //  if(ctx->complaints_len == 0) {
    //    // we skip over to step 21
    //    ctx->step++;
    //  }
    //  ctx->step++;
    //  return ret;
    //}
  default: {
    if(log_file!=NULL) fprintf(log_file, "[!] invalid step\n");
    return 99;
  }
  }
  if(ret!=0) ctx->step=99; // so that not_done reports done
  return ret;
}

int toprf_update_peer_next(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  int ret=0;
  ctx->prev=ctx->step;
  switch(ctx->step) {
  case TOPRF_Update_Peer_Broadcast_NPK_SIDNonce: { ret = peer_step1_handler(ctx, output, output_len) ; break; }
  case TOPRF_Update_Peer_Rcv_NPK_SIDNonce: { ret = peer_step3_handler(ctx, input, input_len, output, output_len); break; }
  case TOPRF_Update_Peer_Noise_Handshake: { ret = peer_step5_handler(ctx, input, input_len, output, output_len); break; }
  case TOPRF_Update_Peer_Finish_Noise_Handshake: { ret = peer_step7_handler(ctx, input, input_len, output, output_len); break; }
  case TOPRF_Update_Peer_Rcv_Commitments_Send_Shares: { ret = peer_step9_handler(ctx, input, input_len, output, output_len); break; }
  case TOPRF_Update_Peer_Verify_Commitments: { ret = peer_step11_handler(ctx, input, input_len, output, output_len); break; }
  case TOPRF_Update_Peer_Handle_DKG_Complaints: { ret = peer_dkg_fork(ctx, input, input_len); break; }
    // todo case TOPRF_Update_Peer_Defend_DKG_Accusations:
  case TOPRF_Update_Peer_Finish_DKG: { ret = peer_step20_handler(ctx, output, output_len); break; }
  case TOPRF_Update_Peer_Start_Mult: { ret = peer_step22_handler(ctx, input, input_len, output, output_len); break; }
  case TOPRF_Update_Peer_Recv_K1P_Commitments: { ret = peer_step24_handler(ctx, input, input_len, output, output_len); break; }
  case TOPRF_Update_Peer_Send_K1P_Shares: { ret = peer_step26_handler(ctx, input, input_len, output, output_len); break; }
  case TOPRF_Update_Peer_Recv_K1P_Shares: { ret = peer_step28_handler(ctx, input, input_len, output, output_len); break; }
  case TOPRF_Update_Peer_Send_ZK_Commitments: { ret = peer_step30_handler(ctx, input, input_len, output, output_len); break; }
  case TOPRF_Update_Peer_Send_ZK_nonces: { ret = peer_step32_handler(ctx, input, input_len, output, output_len); break; }
  case TOPRF_Update_Peer_Send_ZK_proofs: { ret = peer_step34_handler(ctx, input, input_len, output, output_len); break; }
  case TOPRF_Update_Peer_Verify_ZK_proofs: { ret = peer_step36_handler(ctx, input, input_len, output, output_len); break; }
  case TOPRF_Update_Peer_Handle_Mult_Complaints: { ret = peer_zkproof_fork(ctx, input, input_len); break; }
  case TOPRF_Update_Peer_Send_Mult_Ci: { ret = peer_step39_handler(ctx, output, output_len); break; }
  case TOPRF_Update_Peer_Final_VSPS_Checks: { ret = peer_step41_handler(ctx, input, input_len, output, output_len); break; }
  case TOPRF_Update_Peer_Recv_VSPS_Results: { ret = peer_final_fork(ctx, input, input_len); break; }
  case TOPRF_Update_Peer_Send_k0p_k1p_Share: { ret = peer_step44_handler(ctx, output, output_len); break; }
  case TOPRF_Update_Peer_Final_OK: { ret = peer_step46_handler(ctx, input, input_len); break; }
  case TOPRF_Update_Peer_Done: {
    // we are done
    ret = 0;
    break;
  }
  default: {
    if(log_file!=NULL) fprintf(log_file, "[%d] invalid step\n", ctx->index);
    ret = 99;
  }
  }
  if(ret!=0) ctx->step=99; // so that not_done reports done
  return ret;
}
