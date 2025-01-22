#include <stdio.h>
#include <stdint.h>
#include <sodium.h>
#include <arpa/inet.h> //htons
#include <sys/param.h> // __BYTE_ORDER __BIG_ENDIAN
#include <string.h> // memcpy
#include <stdarg.h> // va_{start|end}
#include <stdlib.h> // free, rand

#include "XK.h"
#include "dkg.h"
#include "stp-dkg.h"
#include "utils.h"

/*
    @copyright 2024, Stefan Marsiske toprf@ctrlc.hu
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
  trusted orchestrator which connects to all participating peers in a
  star topology.

  The underlying algorithm is based on the JF-DKG (fig 1.) a variant
  on Pedersens DKG from the paper "Secure Distributed Key Generation
  for Discrete-Log Based Cryptosystems" by R. Gennaro, S. Jarecki,
  H. Krawczyk, and T. Rabin.
 */

#define stpdkg_msg1_SIZE (sizeof(DKG_Message))
#define stpdkg_msg2_SIZE (sizeof(DKG_Message) + dkg_sessionid_SIZE + crypto_scalarmult_BYTES)
#define stpdkg_msg4_SIZE (sizeof(DKG_Message) + noise_xk_handshake1_SIZE)
#define stpdkg_msg5_SIZE (sizeof(DKG_Message) + noise_xk_handshake2_SIZE)
#define stpdkg_msg6_SIZE (sizeof(DKG_Message) + stpdkg_commitment_HASHBYTES)
#define stpdkg_msg8_SIZE(ctx) (sizeof(DKG_Message) + (size_t)(crypto_core_ristretto255_BYTES * ctx->t))

#define stpdkg_msg9_SIZE(ctx) (sizeof(DKG_Message) + (size_t)(ctx->n + 1) )
#define stpdkg_msg10x_SIZE(ctx) (sizeof(DKG_Message) + (size_t)(ctx->n * stpdkg_msg9_SIZE(ctx)) )
#define stpdkg_msg19_SIZE (sizeof(DKG_Message) + crypto_generichash_BYTES)
#define stpdkg_msg20_SIZE (sizeof(DKG_Message) + 2)
#define stpdkg_msg21_SIZE (sizeof(DKG_Message) + 2)

size_t stpdkg_peerstate_size(void) {
  return sizeof(STP_DKG_PeerState);
}
uint8_t stpdkg_peerstate_n(STP_DKG_PeerState *ctx) {
  return ctx->n;
}
uint8_t stpdkg_peerstate_t(STP_DKG_PeerState *ctx) {
  return ctx->t;
}
uint8_t* stpdkg_peerstate_sessionid(STP_DKG_PeerState *ctx) {
  return ctx->sessionid;
}
uint8_t* stpdkg_peerstate_lt_sk(STP_DKG_PeerState *ctx) {
  return ctx->sig_sk;
}
uint8_t* stpdkg_peerstate_share(STP_DKG_PeerState *ctx) {
  return (uint8_t*) &ctx->share;
}
int stpdkg_peerstate_step(STP_DKG_PeerState *ctx) {
  return ctx->step;
}

size_t stpdkg_stpstate_size(void) {
  return sizeof(STP_DKG_STPState);
}
uint8_t stpdkg_stpstate_n(STP_DKG_STPState *ctx) {
  return ctx->n;
}
uint8_t stpdkg_stpstate_t(STP_DKG_STPState *ctx) {
  return ctx->t;
}
size_t stpdkg_stpstate_cheater_len(STP_DKG_STPState *ctx) {
  return ctx->cheater_len;
}
uint8_t* stpdkg_stpstate_sessionid(STP_DKG_STPState *ctx) {
  return ctx->sessionid;
}
int stpdkg_stpstate_step(STP_DKG_STPState *ctx) {
  return ctx->step;
}

static STP_DKG_Cheater* add_cheater(STP_DKG_STPState *ctx, const int step, const int error, const uint8_t peer, const uint8_t other_peer) {
  if(ctx->cheater_len >= ctx->cheater_max) return NULL;
  STP_DKG_Cheater *cheater = &(*ctx->cheaters)[ctx->cheater_len++];
  cheater->step = step;
  cheater->error = error;
  cheater->peer = peer;
  cheater->other_peer=other_peer;
  return cheater;
}

static void update_transcript(crypto_generichash_state *transcript, const uint8_t *msg, const size_t msg_len) {
  uint32_t msg_size_32b = htonl((uint32_t)msg_len);
  crypto_generichash_update(transcript, (uint8_t*) &msg_size_32b, sizeof(msg_size_32b));
  crypto_generichash_update(transcript, (uint8_t*) msg, msg_len);
}

size_t stpdkg_stp_input_size(const STP_DKG_STPState *ctx) {
  size_t sizes[ctx->n];
  //memset(sizes,0,sizeof sizes);
  if(stpdkg_stp_input_sizes(ctx, sizes) == 1) {
    return sizes[0] * ctx->n;
  } else {
    size_t result=0;
    for(int i=0;i<ctx->n;i++) result+=sizes[i];
    return result;
  }
}

int stpdkg_stp_input_sizes(const STP_DKG_STPState *ctx, size_t *sizes) {
  size_t item=0;
  switch(ctx->step) {
  case 0: { item=0; break; }
  case 1: { item=(stpdkg_msg2_SIZE); break; }
  case 2: { item=stpdkg_msg4_SIZE * ctx->n; break; }
  case 3: { item=stpdkg_msg4_SIZE * ctx->n; break; }
  case 4: { item=stpdkg_msg6_SIZE; break; }
  case 5: { item=stpdkg_msg8_SIZE(ctx); break; }
  case 6: { item=ctx->n * stpdkg_msg10_SIZE; break; }
  case 7: { item=stpdkg_msg9_SIZE(ctx); break; }
  case 8: {
    uint8_t ctr[ctx->n];
    memset(ctr,0,ctx->n);
    for(int i=0;i<ctx->complaints_len;i++) ctr[((*ctx->complaints)[i] & 0xff) - 1]++;
    for(int i=0;i<ctx->n;i++) {
      if(ctr[i]>0) {
        sizes[i]=sizeof(DKG_Message) + (1+dkg_noise_key_SIZE) * ctr[i];
      } else {
        sizes[i]=0;
      }
    }
    return 0;
  }
  case 9: { item=stpdkg_msg19_SIZE; break; }
  case 10: { item=stpdkg_msg21_SIZE; break; }
  default: {
    if(log_file!=NULL) fprintf(log_file, "[!] invalid stp step\n");
  }
  }

  for(uint8_t i=0;i<ctx->n;i++) {
    sizes[i] = item;
  }
  return 1;
}

size_t stpdkg_stp_output_size(const STP_DKG_STPState *ctx) {
  switch(ctx->step) {
  case 0: return ctx->n*stpdkg_msg1_SIZE;
  case 1: return stpdkg_msg2_SIZE * ctx->n + sizeof(DKG_Message);
  case 2: return stpdkg_msg4_SIZE * ctx->n * ctx->n;
  case 3: return stpdkg_msg5_SIZE * ctx->n * ctx->n;
  case 4: return sizeof(DKG_Message) + (stpdkg_msg6_SIZE * ctx->n);
  case 5: return sizeof(DKG_Message) + ctx->n * stpdkg_msg8_SIZE(ctx);
  case 6: return ctx->n * ctx->n * stpdkg_msg10_SIZE;
  case 7: return stpdkg_msg10x_SIZE(ctx);
  case 8: return 0;
  case 9: return stpdkg_msg20_SIZE;
  case 10: return 0;
  default: if(log_file!=NULL) fprintf(log_file, "[!] invalid stp step\n");
  }
  return 0;
}

int stpdkg_stp_peer_msg(const STP_DKG_STPState *ctx, const uint8_t *base, const size_t base_size, const uint8_t peer, const uint8_t **msg, size_t *len) {
  if(peer>=ctx->n || peer < 0) return -1;

  switch(ctx->prev) {
  case 0: {
    *msg = base + peer*stpdkg_msg1_SIZE;
    *len = stpdkg_msg1_SIZE;
    break;
  }
  case 1: {
    *msg = base;
    *len = stpdkg_msg2_SIZE * ctx->n + sizeof(DKG_Message);
    break;
  }
  case 2: {
    *msg = base + peer * stpdkg_msg4_SIZE * ctx->n;
    *len = stpdkg_msg4_SIZE * ctx->n;
    break;
  }
  case 3: {
    *msg = base + peer * stpdkg_msg5_SIZE * ctx->n;
    *len = stpdkg_msg5_SIZE * ctx->n;
    break;
  }
  case 4: {
    *msg = base;
    *len = sizeof(DKG_Message) + (stpdkg_msg6_SIZE * ctx->n);
    break;
  }
  case 5: {
    *msg = base ;
    *len = sizeof(DKG_Message) + (stpdkg_msg8_SIZE(ctx) * ctx->n);
    break;
  }
  case 6: {
    *msg = base + peer * (ctx->n * stpdkg_msg10_SIZE);
    *len = ctx->n * stpdkg_msg10_SIZE;
    break;
  }
  case 7: {
    *msg = base;
    *len = stpdkg_msg10x_SIZE(ctx);
    break;
  }
  case 8: {
    *len = 0;
    *msg = NULL;
    break;
  }
  case 9: {
    *msg = base;
    *len = stpdkg_msg20_SIZE;
    break;
  }
  case 10: {
    *len = 0;
    *msg = NULL;
    break;
  }
  default: {
    if(log_file!=NULL) fprintf(log_file, "[!] invalid stp step in stpdkg_stp_peer_msg\n");
    return 1;
  }
  }

  if(base+base_size < *msg + *len) {
    if(log_file!=NULL) fprintf(log_file, "buffer overread detected in stpdkg_stp_peer_msg %ld\n", (base+base_size) - (*msg + *len));
    return 2;
  }

  return 0;
}

size_t stpdkg_peer_input_size(const STP_DKG_PeerState *ctx) {
  switch(ctx->step) {
  case 0: return stpdkg_msg1_SIZE;
  case 1: return stpdkg_msg2_SIZE * ctx->n + sizeof(DKG_Message);
  case 2: return stpdkg_msg4_SIZE * ctx->n;
  case 3: return stpdkg_msg5_SIZE * ctx->n;
  case 4: return sizeof(DKG_Message) + (stpdkg_msg6_SIZE * ctx->n);
  case 5: return sizeof(DKG_Message) + ctx->n * stpdkg_msg8_SIZE(ctx);
  case 6: return ctx->n * stpdkg_msg10_SIZE;
  case 7: return stpdkg_msg10x_SIZE(ctx);
  case 8: return 0;
  case 9: return 0;
  case 10: return stpdkg_msg20_SIZE;
  case 11: return 0;
  default: {
    if(log_file!=NULL) fprintf(log_file, "[%d] invalid step\n", ctx->index);
  }
  }
  return 1;
}

size_t stpdkg_peer_output_size(const STP_DKG_PeerState *ctx) {
  switch(ctx->step) {
  case 0: return stpdkg_msg2_SIZE;
  case 1: return stpdkg_msg4_SIZE * ctx->n;
  case 2: return stpdkg_msg5_SIZE * ctx->n;
  case 3: return stpdkg_msg6_SIZE;
  case 4: return stpdkg_msg8_SIZE(ctx);
  case 5: return ctx->n * stpdkg_msg10_SIZE;
  case 6: return stpdkg_msg9_SIZE(ctx);
  case 7: return 0;
  case 8: {
    if(ctx->complaints_len > 0) {
      if(ctx->my_complaints_len > 0) {
        return sizeof(DKG_Message) + ctx->my_complaints_len * (1+dkg_noise_key_SIZE);
      }
      return 0;
    }
    return stpdkg_msg19_SIZE;
  }
  case 9: return stpdkg_msg19_SIZE;
  case 10: return stpdkg_msg21_SIZE;
  case 11: return 0;
  default: {
    if(log_file!=NULL) fprintf(log_file, "[%d] invalid step\n", ctx->index);
  }
  }
  return 1;
}

void stpdkg_peer_set_bufs(STP_DKG_PeerState *ctx,
                         uint8_t (*sig_pks)[][crypto_sign_PUBLICKEYBYTES],
                         uint8_t (*peers_noise_pks)[][crypto_scalarmult_BYTES],
                         Noise_XK_session_t *(*noise_outs)[],
                         Noise_XK_session_t *(*noise_ins)[],
                         TOPRF_Share (*shares)[],
                         TOPRF_Share (*xshares)[],
                         uint8_t (*commitment_hashes)[][stpdkg_commitment_HASHBYTES],
                         uint8_t (*commitments)[][crypto_core_ristretto255_BYTES],
                         uint16_t *complaints,
                         uint8_t *my_complaints,
                         uint64_t *last_ts) {
  ctx->sig_pks = sig_pks;
  ctx->peer_noise_pks = peers_noise_pks;
  ctx->noise_outs = noise_outs;
  ctx->noise_ins = noise_ins;
  ctx->shares = shares;
  ctx->xshares = xshares;
  ctx->commitment_hashes = commitment_hashes;
  ctx->commitments = commitments;
  ctx->complaints = complaints;
  ctx->my_complaints = my_complaints;
  ctx->last_ts = last_ts;
  for(uint8_t i=0;i<ctx->n;i++) ctx->last_ts[i]=0;
}

int stpdkg_stp_not_done(const STP_DKG_STPState *stp) {
  return stp->step<11;
}

int stpdkg_peer_not_done(const STP_DKG_PeerState *peer) {
  return peer->step<11;
}

void stpdkg_peer_free(STP_DKG_PeerState *ctx) {
  for(int i=0;i<ctx->n;i++) {
    if((*ctx->noise_ins)[i]!=NULL) Noise_XK_session_free((*ctx->noise_ins)[i]);
    if((*ctx->noise_outs)[i]!=NULL) Noise_XK_session_free((*ctx->noise_outs)[i]);
  }
  if(ctx->dev!=NULL) Noise_XK_device_free(ctx->dev);
}

void stpdkg_stp_set_bufs(STP_DKG_STPState *ctx,
                       uint8_t (*commitments)[][crypto_core_ristretto255_BYTES],
                       uint16_t (*complaints)[],
                       uint8_t (*encrypted_shares)[][stpdkg_msg10_SIZE],
                       STP_DKG_Cheater (*cheaters)[], const size_t cheater_max,
                       uint64_t *last_ts) {
  ctx->commitments = (uint8_t (*)[][crypto_core_ristretto255_BYTES]) commitments;
  ctx->complaints = complaints;
  ctx->encrypted_shares = encrypted_shares;
  ctx->cheaters = cheaters;
  memset(*cheaters, 0, cheater_max*sizeof(STP_DKG_Cheater));
  ctx->cheater_max = cheater_max;
  ctx->last_ts = last_ts;
  uint64_t now = (uint64_t)time(NULL);
  for(uint8_t i=0;i<ctx->n;i++) ctx->last_ts[i]=now;
}

int stpdkg_start_stp(STP_DKG_STPState *ctx, const uint64_t ts_epsilon,
                     const uint8_t n, const uint8_t t,
                     const char *proto_name, const size_t proto_name_len,
                     const uint8_t (*sig_pks)[][crypto_sign_PUBLICKEYBYTES],
                     const uint8_t ltssk[crypto_sign_SECRETKEYBYTES],
                     const size_t msg0_len, DKG_Message *msg0) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[!] step 0. start protocol\e[0m\n");
  if(2>n || t>=n || n>128) return 1;
  if(proto_name_len<1) return 2;
  if(proto_name_len>1024) return 3;
  if(msg0_len != stpdkg_msg0_SIZE) return 4;

  ctx->ts_epsilon = ts_epsilon;
  ctx->step = 0;
  ctx->n = n;
  ctx->t = t;
  ctx->complaints_len = 0;
  ctx->cheater_len = 0;

  // dst hash(len(protoname) | "DKG for protocol " | protoname)
  crypto_generichash_state dst_state;
  crypto_generichash_init(&dst_state, NULL, 0, crypto_generichash_BYTES);
  uint16_t len=htons((uint16_t) proto_name_len+20); // we have a guard above restricting to 1KB the proto_name_len
  crypto_generichash_update(&dst_state, (uint8_t*) &len, 2);
  crypto_generichash_update(&dst_state, (uint8_t*) "STP DKG for protocol ", 20);
  crypto_generichash_update(&dst_state, (uint8_t*) proto_name, proto_name_len);
  uint8_t dst[crypto_generichash_BYTES];
  crypto_generichash_final(&dst_state,dst,sizeof dst);

  // set nonce_stp, we abuse this session_id field in the state to
  // temporarily store the nonce_stp; which will later become the
  // session_id after the other peers also contributed their nonces
  randombytes_buf(&ctx->sessionid, sizeof ctx->sessionid);

  // a list of all long-term pubkeys
  ctx->sig_pks = sig_pks;
  // keep a copy of our long-term signing key
  memcpy(ctx->sig_sk, ltssk, crypto_sign_SECRETKEYBYTES);

  // data = {dst, nonce_stp, n, t}
  uint8_t *ptr = msg0->data;
  memcpy(ptr, dst, sizeof dst);
  ptr+=sizeof dst;
  *ptr++ = n;
  *ptr++ = t;

  if(0!=send_msg((uint8_t*) msg0, stpdkg_msg0_SIZE, 0, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return 5;

  // init transcript
  crypto_generichash_init(&ctx->transcript, NULL, 0, crypto_generichash_BYTES);
  crypto_generichash_update(&ctx->transcript, (uint8_t*) "stp dkg session transcript", 25);
  // feed msg0 into transcript
  update_transcript(&ctx->transcript, (uint8_t*) msg0, msg0_len);

  if(log_file!=NULL) {
    fprintf(log_file,"[!] msgno: %d, from: %d to: 0x%x ", msg0->msgno, msg0->from, msg0->to);
    dump((uint8_t*) msg0, stpdkg_msg0_SIZE, "msg");
  }

  return 0;
}

int stpdkg_start_peer(STP_DKG_PeerState *ctx, const uint64_t ts_epsilon,
                      const uint8_t (*sig_pks)[][crypto_sign_PUBLICKEYBYTES],
                      const uint8_t peer_lt_sk[crypto_sign_SECRETKEYBYTES],
                      const DKG_Message *msg0) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[?] step 0.5 start peer\e[0m\n");

  if(log_file!=NULL) {
    fprintf(log_file,"[?] msgno: %d, from: %d to: 0x%x ", msg0->msgno, msg0->from, msg0->to);
    dump((uint8_t*) msg0, stpdkg_msg0_SIZE, "msg");
  }

  ctx->ts_epsilon = ts_epsilon;
  ctx->stp_last_ts = 0;

  ctx->sig_pks = sig_pks;

  int ret = recv_msg((uint8_t*) msg0, stpdkg_msg0_SIZE, 0, 0, 0xff, (*ctx->sig_pks)[0], msg0->sessionid, ts_epsilon, &ctx->stp_last_ts);
  if(0!=ret) return 64 + ret;

  // extract data from message
  // we abuse sessionid as a temporary storage for the nonce_stp value, until we have the final sessionid
  memcpy(ctx->sessionid, msg0->sessionid, sizeof ctx->sessionid);

  const uint8_t *ptr=msg0->data;
  ptr+=crypto_generichash_BYTES; // also skip DST
  ctx->n = *ptr++;
  ctx->t = *ptr++;

  if(ctx->t < 2) return 1;
  if(ctx->t >= ctx->n) return 2;
  if(ctx->n > 128) return 3;

  ctx->complaints_len = 0;
  ctx->my_complaints_len = 0;
  memcpy(ctx->sig_sk, peer_lt_sk, crypto_sign_SECRETKEYBYTES);

  crypto_generichash_init(&ctx->transcript, NULL, 0, crypto_generichash_BYTES);
  crypto_generichash_update(&ctx->transcript, (uint8_t*) "stp dkg session transcript", 25);
  // feed msg0 into transcript
  update_transcript(&ctx->transcript, (uint8_t*) msg0, stpdkg_msg0_SIZE);

  ctx->dev = NULL;
  ctx->step = 0;

  return 0;
}

static int stp_step1_handler(STP_DKG_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[!] step 1. assign peer indices\e[0m\n");
  if(input_len!=0) return 1;
  if(output_len!=ctx->n * stpdkg_msg1_SIZE) return 2;

  uint8_t* ptr = output;
  for(uint8_t i=1;i<=ctx->n;i++,ptr+=stpdkg_msg1_SIZE) {
    if(0!=send_msg(ptr, sizeof(DKG_Message), 1, 0, i, ctx->sig_sk, ctx->sessionid)) return 3;
    if(log_file!=NULL) {
      DKG_Message *msg1 = (DKG_Message*) ptr;
      fprintf(log_file,"[!] msgno: %d, len: %d, from: %d to: %x ", msg1->msgno, htonl(msg1->len), msg1->from, msg1->to);
      dump(ptr, stpdkg_msg1_SIZE, "msg");
    }
  }

  return 0;
}


static int peer_step2_3_handler(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[?] step 2. receive peers index\e[0m\n");
  if(input_len != stpdkg_msg1_SIZE) return 1;
  if(output_len != stpdkg_msg2_SIZE) return 2;

  DKG_Message *msg1=(DKG_Message*) input;
  if(log_file!=NULL) {
    fprintf(log_file,"[?] msgno: %d, len: %d, from: %d to: %x ", msg1->msgno, ntohl(msg1->len), msg1->from, msg1->to);
    dump(input, stpdkg_msg1_SIZE, "msg");
  }
  int ret = recv_msg(input, stpdkg_msg1_SIZE, 1, 0, msg1->to, (*ctx->sig_pks)[0], ctx->sessionid, ctx->ts_epsilon, &ctx->stp_last_ts);
  if(0!=ret) return 4 + ret;
  if(msg1->to > 128 || msg1->to < 1) return 3;
  ctx->index=msg1->to;

  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[%d] step 3. send msg2 containing ephemeral pubkey and sessionid nonce\e[0m\n", ctx->index);

  randombytes_buf(ctx->noise_sk, sizeof ctx->noise_sk);
  crypto_scalarmult_base(ctx->noise_pk, ctx->noise_sk);

  uint8_t *wptr = ((DKG_Message *) output)->data;
  // generate session_id nonce_i
  randombytes_buf(wptr, dkg_sessionid_SIZE);
  wptr+=dkg_sessionid_SIZE;
  memcpy(wptr, ctx->noise_pk, sizeof ctx->noise_pk);
  if(0!=send_msg(output, stpdkg_msg2_SIZE, 2, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return 4;

  if(log_file!=NULL) {
    DKG_Message *msg2 = (DKG_Message *) output;
    fprintf(log_file,"[%d] msgno: %d, len: %d, from: %d to: %x ", ctx->index, msg2->msgno, ntohl(msg2->len), msg2->from, msg2->to);
    dump(output, stpdkg_msg2_SIZE, "msg");
  }

  return 0;
}

static int stp_step4_handler(STP_DKG_STPState *ctx, const uint8_t *msg2s, const size_t msg2s_len, uint8_t *msg3_buf, const size_t msg3_buf_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[!] step 4. broadcast msg2 containing ephemeral pubkeys of peers\e[0m\n");
  if((stpdkg_msg2_SIZE * ctx->n) != msg2s_len) return 1;
  if(msg3_buf_len != (stpdkg_msg2_SIZE * ctx->n) + sizeof(DKG_Message)) return 2;

  crypto_generichash_state sid_hash_state;
  crypto_generichash_init(&sid_hash_state, NULL, 0, dkg_sessionid_SIZE);
  crypto_generichash_update(&sid_hash_state, ctx->sessionid, dkg_sessionid_SIZE);

  const uint8_t *ptr = msg2s;
  uint8_t *wptr = ((DKG_Message *) msg3_buf)->data;
  for(uint8_t i=0;i<ctx->n;i++,ptr+=stpdkg_msg2_SIZE) {
    const DKG_Message* msg = (const DKG_Message*) ptr;
    // verify long-term pk sig on initial message
    if(log_file!=NULL) {
      fprintf(log_file,"[!] msgno: %d, from: %d to: %x ", msg->msgno, msg->from, msg->to);
      dump(ptr, stpdkg_msg2_SIZE, "msg");
    }
    int ret = recv_msg(ptr, stpdkg_msg2_SIZE, 2, i+1, 0xff, (*ctx->sig_pks)[i+1], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts[i]);
    if(0!=ret) {
      if(add_cheater(ctx, 4, 64+ret, i+1,0xff) == NULL) return 7;
      continue;
    }

    crypto_generichash_update(&sid_hash_state, msg->data, dkg_sessionid_SIZE);

    memcpy(wptr, ptr, stpdkg_msg2_SIZE);
    wptr+=stpdkg_msg2_SIZE;
  }
  if(ctx->cheater_len>0) return 6;

  crypto_generichash_final(&sid_hash_state,ctx->sessionid,dkg_sessionid_SIZE);

  if(0!=send_msg(msg3_buf, msg3_buf_len, 3, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return 5;
  update_transcript(&ctx->transcript, (uint8_t*) msg3_buf, msg3_buf_len);

  return 0;
}

static int peer_step5_handler(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[%d] step 5. receive peers ephemeral pubkeys, start noise sessions\e[0m\n", ctx->index);
  if(input_len != stpdkg_msg2_SIZE * ctx->n + sizeof(DKG_Message)) return 1;
  if(output_len != stpdkg_msg4_SIZE * ctx->n) return 2;

  DKG_Message* msg3 = (DKG_Message*) input;
  int ret = recv_msg(input, input_len, 3, 0, 0xff, (*ctx->sig_pks)[0], msg3->sessionid, ctx->ts_epsilon, &ctx->stp_last_ts);
  if(0!=ret) return 32+ret;

  update_transcript(&ctx->transcript, input, input_len);

  // create noise device
  uint8_t iname[13];
  snprintf((char*) iname, sizeof iname, "dkg peer %02x", ctx->index);
  uint8_t dummy[32]={0}; // the following function needs a deserialization key, which we never use.

  ctx->dev = Noise_XK_device_create(13, (uint8_t*) "dpkg p2p v0.1", iname, dummy, ctx->noise_sk);

  crypto_generichash_state sid_hash_state;
  crypto_generichash_init(&sid_hash_state, NULL, 0, dkg_sessionid_SIZE);
  crypto_generichash_update(&sid_hash_state, ctx->sessionid, dkg_sessionid_SIZE);

  const uint8_t *ptr = msg3->data;
  uint8_t *wptr = output;
  for(uint8_t i=0;i<ctx->n;i++) {
    DKG_Message* msg2 = (DKG_Message*) ptr;
    if(log_file!=NULL) {
      fprintf(log_file,"[%d] msgno: %d, from: %d to: %x ", ctx->index, msg2->msgno, msg2->from, msg2->to);
      dump(ptr, stpdkg_msg2_SIZE, "msg");
    }

    ret = recv_msg(ptr, stpdkg_msg2_SIZE, 2, i+1, 0xff, (*ctx->sig_pks)[i+1], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts[i]);
    if(0!=ret) return 64+ret;

    crypto_generichash_update(&sid_hash_state, msg2->data, dkg_sessionid_SIZE);
    // extract peer noise pk

    memcpy((*ctx->peer_noise_pks)[i], msg2->data + dkg_sessionid_SIZE, crypto_scalarmult_BYTES);
    ptr+=stpdkg_msg2_SIZE;

    DKG_Message *msg4 = (DKG_Message *) wptr;
    uint8_t rname[13];
    snprintf((char*) rname, sizeof rname, "dkg peer %02x", i+1);
    dkg_init_noise_handshake(ctx->index, ctx->dev, (*ctx->peer_noise_pks)[i], rname, &(*ctx->noise_outs)[i], msg4->data);
    if(0!=send_msg(wptr, stpdkg_msg4_SIZE, 4, ctx->index, i+1, ctx->sig_sk, msg3->sessionid)) return 5;
    if(log_file!=NULL) {
      fprintf(log_file,"[%d] msgno: %d, from: %d to: %d ", ctx->index, msg4->msgno, msg4->from, msg4->to);
      dump(wptr, stpdkg_msg4_SIZE, "msg");
    }
    wptr+=stpdkg_msg4_SIZE;
  }

  crypto_generichash_final(&sid_hash_state,ctx->sessionid,dkg_sessionid_SIZE);
  if(memcmp(ctx->sessionid, msg3->sessionid, dkg_sessionid_SIZE)!=0) {
    return 6;
  }

  return 0;
}

static int stp_step68_handler(STP_DKG_STPState *ctx, const uint8_t *msg4s, const size_t msg4s_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[!] step %d. route p2p noise handshakes to peers\e[0m\n", 4 + (ctx->step - 1) * 2);
  if(msg4s_len != stpdkg_msg4_SIZE * ctx->n * ctx->n) return 1;
  if(msg4s_len != output_len) return 2;

  uint8_t (*inputs)[ctx->n][ctx->n][stpdkg_msg4_SIZE] = (uint8_t (*)[ctx->n][ctx->n][stpdkg_msg4_SIZE]) msg4s;
  uint8_t *wptr = output;
  for(uint8_t i=0;i<ctx->n;i++) {
    for(uint8_t j=0;j<ctx->n;j++) {
      if(stpdkg_msg4_SIZE != stpdkg_msg5_SIZE) {
        if(log_file!=NULL) fprintf(log_file, "stpdkg_msg4_SIZE must be equal stpdkg_msg5_SIZE for the check to be correct in stp_step68_handler\n");
        return 3;
      } 
      int ret = recv_msg((*inputs)[j][i], stpdkg_msg4_SIZE, (uint8_t) (2+ctx->step), j+1, i+1, (*ctx->sig_pks)[j+1], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts[j]);
      if(0!=ret) {
        if(add_cheater(ctx, 6 + (ctx->step - 1) * 2, 64+ret, j+1, i+1) == NULL) return 7;
        DKG_Message *msg = (DKG_Message*) (*inputs)[j][i];
        fprintf(log_file,"[x] msgno: %d, from: %d to: %d ", msg->msgno, msg->from, msg->to);
        dump((*inputs)[j][i], stpdkg_msg4_SIZE, "msg");
        continue;
      }
      memcpy(wptr, (*inputs)[j][i], stpdkg_msg4_SIZE);
      wptr+=stpdkg_msg4_SIZE;
    }
  }
  if(ctx->cheater_len>0) return 6;

  return 0;
}

static int peer_step7_handler(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[%d] step 7. receive session requests\e[0m\n", ctx->index);
  if(input_len != stpdkg_msg4_SIZE * ctx->n) return 1;
  if(output_len != stpdkg_msg5_SIZE * ctx->n) return 2;

  const uint8_t *ptr = input;
  uint8_t *wptr = output;
  for(uint8_t i=0;i<ctx->n;i++) {
    DKG_Message* msg4 = (DKG_Message*) ptr;
    if(log_file!=NULL) {
      fprintf(log_file,"[%d] msgno: %d, from: %d to: %d ", ctx->index, msg4->msgno, msg4->from, msg4->to);
      dump(ptr, stpdkg_msg4_SIZE, "msg");
    }
    int ret = recv_msg(ptr, stpdkg_msg4_SIZE, 4, i+1, ctx->index, (*ctx->sig_pks)[i+1], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts[i]);
    if(0!=ret) return 64+ret;
    ptr+=stpdkg_msg4_SIZE;

    // respond to noise handshake request
    DKG_Message *msg5 = (DKG_Message *) wptr;
    uint8_t rname[13];
    snprintf((char*) rname, sizeof rname, "dkg peer %02x", i+1);
    dkg_respond_noise_handshake(ctx->index, ctx->dev, (*ctx->peer_noise_pks)[i], rname, &(*ctx->noise_ins)[i], msg4->data, msg5->data);
    if(0!=send_msg(wptr, stpdkg_msg5_SIZE, 5, ctx->index, i+1, ctx->sig_sk, ctx->sessionid)) return 4;
    if(log_file!=NULL) {
      fprintf(log_file,"[%d] msgno: %d, from: %d to: %d ", ctx->index, msg5->msgno, msg5->from, msg5->to);
      dump(wptr, stpdkg_msg5_SIZE, "msg");
    }
    wptr+=stpdkg_msg5_SIZE;
  }

  return 0;
}

static int peer_step911_handler(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[%d] step 9-11 finish session handshake, broadcast commitments\e[0m\n", ctx->index);
  if(input_len != stpdkg_msg5_SIZE * ctx->n) return 1;
  if(output_len != stpdkg_msg6_SIZE) return 2;

  const uint8_t *ptr = input;
  for(uint8_t i=0;i<ctx->n;i++) {
    DKG_Message* msg5 = (DKG_Message*) ptr;
    if(log_file!=NULL) {
      fprintf(log_file,"[%d] msgno: %d, from: %d to: %d ", ctx->index, msg5->msgno, msg5->from, msg5->to);
      dump(ptr, stpdkg_msg5_SIZE, "msg");
    }
    int ret = recv_msg(ptr, stpdkg_msg5_SIZE, 5, i+1, ctx->index, (*ctx->sig_pks)[i+1], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts[i]);
    if(0!=ret) return 64+ret;
    ptr+=stpdkg_msg5_SIZE;
    // process final step of noise handshake
    dkg_finish_noise_handshake(ctx->index, ctx->dev, &(*ctx->noise_outs)[i], msg5->data);
  }

  DKG_Message* msg6 = (DKG_Message*) output;
  if(0!=dkg_start(ctx->n, ctx->t, *ctx->commitments, *ctx->shares)) return 4;
  crypto_generichash(msg6->data, stpdkg_commitment_HASHBYTES, (uint8_t*) (*ctx->commitments), crypto_core_ristretto255_BYTES*ctx->t, NULL, 0);

  if(0!=send_msg(output, stpdkg_msg6_SIZE, 6, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return 4;
  if(log_file!=NULL) {
    fprintf(log_file,"[%d] msgno: %d, from: %d to: 0x%x ", ctx->index, msg6->msgno, msg6->from, msg6->to);
    dump(output, stpdkg_msg6_SIZE, "msg");
    dump(msg6->data, stpdkg_commitment_HASHBYTES, "[%d] commitments", ctx->index);
  }

  return 0;
}

static int stp_step12_handler(STP_DKG_STPState *ctx, const uint8_t *msg6s, const size_t msg6s_len, uint8_t *msg7_buf, const size_t msg7_buf_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[!] step 12. broadcast commitment hashes of peers\e[0m\n");

  if((stpdkg_msg6_SIZE * ctx->n) != msg6s_len) return 1;
  if(msg7_buf_len != sizeof(DKG_Message) + msg6s_len) return 2;
  const uint8_t *ptr = msg6s;
  uint8_t *wptr = ((DKG_Message *) msg7_buf)->data;
  for(uint8_t i=0;i<ctx->n;i++,ptr+=stpdkg_msg6_SIZE) {
    const DKG_Message* msg = (const DKG_Message*) ptr;
    if(log_file!=NULL) {
      fprintf(log_file,"[!] msgno: %d, from: %d to: 0x%x ", msg->msgno, msg->from, msg->to);
      dump(ptr, stpdkg_msg6_SIZE, "msg");
    }
    int ret = recv_msg(ptr, stpdkg_msg6_SIZE, 6, i+1, 0xff, (*ctx->sig_pks)[i+1], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts[i]);
    if(0!=ret) {
      if(add_cheater(ctx, 12, 64+ret, i+1,0xff) == NULL) return 7;
      continue;
    }

    memcpy((*ctx->commitments)[i*ctx->t], msg->data, stpdkg_commitment_HASHBYTES);
    if(log_file!=NULL) {
      dump((*ctx->commitments)[i*ctx->t], stpdkg_commitment_HASHBYTES, "[!] commitment hash[%d]", i+1);
    }

    memcpy(wptr, ptr, stpdkg_msg6_SIZE);
    wptr+=stpdkg_msg6_SIZE;
  }
  if(ctx->cheater_len>0) return 6;

  if(0!=send_msg(msg7_buf, msg7_buf_len, 7, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return 4;
  DKG_Message* msg7 = (DKG_Message*) msg7_buf;
  if(log_file!=NULL) {
    fprintf(log_file,"[!] msgno: %d, from: %d to: %x ", msg7->msgno, msg7->from, msg7->to);
    dump(msg7_buf, msg7_buf_len, "msg");
  }

  // add broadcast msg to transcript
  update_transcript(&ctx->transcript, (uint8_t*) msg7_buf, msg7_buf_len);

  return 0;
}

static int peer_step13_handler(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[%d] step 13. receive commitment hashes, broadcast commitments\e[0m\n", ctx->index);
  if(input_len != sizeof(DKG_Message) + (stpdkg_msg6_SIZE * ctx->n)) return 1;
  if(output_len != stpdkg_msg8_SIZE(ctx)) return 2;

  // verify STP message envelope
  DKG_Message* msg7 = (DKG_Message*) input;
  if(log_file!=NULL) {
    fprintf(log_file,"[%d] msgno: %d, from: %d to: %x ", ctx->index, msg7->msgno, msg7->from, msg7->to);
    dump(input, input_len, "msg");
  }
  int ret = recv_msg(input, input_len, 7, 0, 0xff, (*ctx->sig_pks)[0], ctx->sessionid, ctx->ts_epsilon, &ctx->stp_last_ts);
  if(0!=ret) return 32+ret;

  // add broadcast msg to transcript
  update_transcript(&ctx->transcript, input, input_len);

  const uint8_t *ptr = msg7->data;

  for(uint8_t i=0;i<ctx->n;i++, ptr+=stpdkg_msg6_SIZE) {
    DKG_Message* msg6 = (DKG_Message*) ptr;
    if(log_file!=NULL) {
      fprintf(log_file,"[%d] msgno: %d, from: %d to: 0x%x ", ctx->index, msg6->msgno, msg6->from, msg6->to);
      dump(ptr, stpdkg_msg6_SIZE, "msg");
    }
    if(0!=recv_msg(ptr, stpdkg_msg6_SIZE, 6, i+1, 0xff, (*ctx->sig_pks)[i+1], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts[i])) return 64+ret;
    memcpy((*ctx->commitment_hashes)[i], msg6->data, stpdkg_commitment_HASHBYTES);
  }

  uint8_t *wptr = output;
  // create broadcast message containing commitments
  DKG_Message *msg8 = (DKG_Message *) wptr;
  memcpy(msg8->data, *ctx->commitments, ctx->t * crypto_core_ristretto255_BYTES);
  if(0!=send_msg(wptr, stpdkg_msg8_SIZE(ctx), 8, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return 3;
  if(log_file!=NULL) {
    fprintf(log_file,"[%d] msgno: %d, from: %d to: %d ", ctx->index, msg8->msgno, msg8->from, msg8->to);
    dump(wptr, stpdkg_msg8_SIZE(ctx), "msg");
    dump((uint8_t*) (*ctx->commitments), crypto_core_ristretto255_BYTES*ctx->t, "[%d] commitments", ctx->index);
  }

  return 0;
}

static int stp_step14_handler(STP_DKG_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[!] step 14. broadcast commitments to all peers\e[0m\n");
  if(input_len != stpdkg_msg8_SIZE(ctx) * ctx->n) return 1;
  if(output_len != sizeof(DKG_Message) + input_len) return 2;

  DKG_Message* msg9 = (DKG_Message*) output;

  uint8_t *wptr = msg9->data;
  const uint8_t *ptr = input;

  for(uint8_t i=0;i<ctx->n;i++,ptr+=stpdkg_msg8_SIZE(ctx)) {
    const DKG_Message* msg = (const DKG_Message*) ptr;
    if(log_file!=NULL) {
      fprintf(log_file,"[!] msgno: %d, from: %d to: 0x%x ", msg->msgno, msg->from, msg->to);
      dump(ptr, stpdkg_msg8_SIZE(ctx), "msg");
    }
    int ret = recv_msg(ptr, stpdkg_msg8_SIZE(ctx), 8, i+1, 0xff, (*ctx->sig_pks)[i+1], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts[i]);
    if(0!=ret) {
      if(add_cheater(ctx, 14, 64+ret, i+1,0xff) == NULL) return 7;
      continue;
    }

    uint8_t C[stpdkg_commitment_HASHBYTES];
    crypto_generichash(C, stpdkg_commitment_HASHBYTES, msg->data, crypto_core_ristretto255_BYTES*ctx->t, NULL, 0);
    if(memcmp(C, (*ctx->commitments)[i*ctx->t], stpdkg_commitment_HASHBYTES) != 0) {
      if(add_cheater(ctx, 14, 128, i+1, 0xff) == NULL) return 8;
      continue;
    }

    memcpy((*ctx->commitments)[i*ctx->t], msg->data, crypto_core_ristretto255_BYTES*ctx->t);
    if(log_file!=NULL) {
      dump((*ctx->commitments)[i*ctx->t], crypto_core_ristretto255_BYTES*ctx->t, "[!] commitments [%d]", i+1);
    }

    memcpy(wptr, ptr, stpdkg_msg8_SIZE(ctx));
    wptr+=stpdkg_msg8_SIZE(ctx);
  }
  if(ctx->cheater_len>0) return 6;

  if(0!=send_msg(output, output_len, 9, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return 4;
  if(log_file!=NULL) {
    fprintf(log_file,"[!] msgno: %d, from: %d to: %x ", msg9->msgno, msg9->from, msg9->to);
    dump(output, output_len, "msg");
  }

  // add broadcast msg to transcript
  update_transcript(&ctx->transcript, (uint8_t*) output, output_len);

  return 0;
}

static int peer_step15_handler(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[%d] step 15. receive commitments & distribute shares via noise chans\e[0m\n", ctx->index);
  if(input_len != sizeof(DKG_Message) + stpdkg_msg8_SIZE(ctx) * ctx->n) return 1;
  if(output_len != ctx->n * stpdkg_msg10_SIZE) return 2;

  // verify STP message envelope
  DKG_Message* msg9 = (DKG_Message*) input;
  if(log_file!=NULL) {
    fprintf(log_file,"[%d] msgno: %d, from: %d to: %x ", ctx->index, msg9->msgno, msg9->from, msg9->to);
    dump(input, input_len, "msg");
  }
  int ret = recv_msg(input, input_len, 9, 0, 0xff, (*ctx->sig_pks)[0], ctx->sessionid, ctx->ts_epsilon, &ctx->stp_last_ts);
  if(0!=ret) return 32+ret;

  // add broadcast msg to transcript
  update_transcript(&ctx->transcript, input, input_len);

  const uint8_t *ptr = msg9->data;
  uint8_t *wptr = output;

  // create broadcast message containing commitments
  for(uint8_t i=0;i<ctx->n;i++, wptr+=stpdkg_msg10_SIZE,ptr+=stpdkg_msg8_SIZE(ctx)) {
    DKG_Message* msg8 = (DKG_Message*) ptr;
    if(log_file!=NULL) {
      fprintf(log_file,"[%d] msgno: %d, from: %d to: 0x%x ", ctx->index, msg8->msgno, msg8->from, msg8->to);
      dump(ptr, stpdkg_msg8_SIZE(ctx), "msg");
    }
    if(0!=recv_msg(ptr, stpdkg_msg8_SIZE(ctx), 8, i+1, 0xff, (*ctx->sig_pks)[i+1], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts[i])) return 64+ret;

    // extract peer commitments
    uint8_t C[stpdkg_commitment_HASHBYTES];
    crypto_generichash(C, stpdkg_commitment_HASHBYTES, msg8->data, crypto_core_ristretto255_BYTES*ctx->t, NULL, 0);
    if(memcmp(C, (*ctx->commitment_hashes)[i], stpdkg_commitment_HASHBYTES) != 0) {
      //todo if(add_cheater(ctx, 14, 128, i+1, 0xff) == NULL) return 8;
      fprintf(stderr, "\e[0;32mcheater %d wrong commitment hash\e[0m\n", i+1);
      continue;
    }

    memcpy((*ctx->commitments)[i*ctx->t], msg8->data, crypto_core_ristretto255_BYTES * ctx->t);
    if(log_file!=NULL) {
      dump((*ctx->commitments)[i*ctx->t], crypto_core_ristretto255_BYTES*ctx->t, "[!] commitments [%d]", i+1);
    }

    DKG_Message *msg10 = (DKG_Message *) wptr;

    // we need to send an empty packet, so that the handshake completes
    // and we have a final symetric key, the key during the handshake changes, only
    // when the handshake completes does the key become static.
    // this is important, so that when there are complaints, we can disclose the key.
    uint8_t empty[1]={0}; // would love to do [0] but that is undefined c
    if(0!=dkg_noise_encrypt(empty, 0, msg10->data, noise_xk_handshake3_SIZE, &(*ctx->noise_outs)[i])) return 5;

#ifdef UNITTEST_CORRUPT
    // corrupt all shares
    static int corrupted_shares = 0;
    uint8_t corrupted_share[sizeof(TOPRF_Share)];
    memcpy(corrupted_share, &(*ctx->shares)[i], sizeof(TOPRF_Share));
    if(i+1 != ctx->index && corrupted_shares++ < ctx->t-1) {
      dump(corrupted_share, sizeof(TOPRF_Share), "[%d] corrupting share_%d", ctx->index, i+1);
      corrupted_share[2]^=0xff; // flip some bits
      dump(corrupted_share, sizeof(TOPRF_Share), "[%d] corrupted share_%d ", ctx->index, i+1);
    }
    if(0!=dkg_noise_encrypt((uint8_t*) corrupted_share, sizeof(TOPRF_Share),
#else
    if(0!=dkg_noise_encrypt((uint8_t*) &(*ctx->shares)[i], sizeof(TOPRF_Share),
#endif // UNITTEST_CORRUPT
                              msg10->data + noise_xk_handshake3_SIZE, sizeof(TOPRF_Share) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                              &(*ctx->noise_outs)[i])) return 6;

    // we also need to use a key-commiting mac over the encrypted share, since poly1305 is not...
    crypto_auth(msg10->data + noise_xk_handshake3_SIZE + sizeof(TOPRF_Share) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                msg10->data + noise_xk_handshake3_SIZE,
                sizeof(TOPRF_Share) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                Noise_XK_session_get_key((*ctx->noise_outs)[i]));

    if(0!=send_msg(wptr, stpdkg_msg10_SIZE, 10, ctx->index, i+1, ctx->sig_sk, ctx->sessionid)) return 7;
    if(log_file!=NULL) {
      fprintf(log_file,"[%d] msgno: %d, from: %d to: %d ", ctx->index, msg10->msgno, msg10->from, msg10->to);
      dump(wptr, stpdkg_msg10_SIZE, "msg");
    }
  }

  return 0;
}

static int stp_step16_handler(STP_DKG_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[!] step 16. route shares from all peers to all peers\e[0m\n");
  if(input_len != (stpdkg_msg10_SIZE * ctx->n) * ctx->n) return 1;
  if(input_len != output_len) return 2;

  uint8_t (*inputs)[ctx->n][ctx->n][stpdkg_msg10_SIZE] = (uint8_t (*)[ctx->n][ctx->n][stpdkg_msg10_SIZE]) input;
  uint8_t *wptr = output;
  for(uint8_t i=0;i<ctx->n;i++) {
    for(uint8_t j=0;j<ctx->n;j++) {
      DKG_Message *msg10 = (DKG_Message *) (*inputs)[j][i];
      if(log_file!=NULL) {
        fprintf(log_file,"[!] msgno: %d, from: %d to: %d ", msg10->msgno, msg10->from, msg10->to);
        dump((*inputs)[j][i], stpdkg_msg10_SIZE, "msg");
      }
      int ret = recv_msg((*inputs)[j][i], stpdkg_msg10_SIZE, 10, j+1, i+1, (*ctx->sig_pks)[j+1], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts[j]);
      if(0!=ret) {
        if(add_cheater(ctx, 16, 64+ret, j+1, i+1) == NULL) return 7;
        continue;
      }

      memcpy(wptr, (*inputs)[j][i], stpdkg_msg10_SIZE);
      wptr+=stpdkg_msg10_SIZE;
    }
  }
  if(ctx->cheater_len>0) return 6;

  // keep a copy for complaint resolution.
  memcpy((*ctx->encrypted_shares), input, input_len);

  return 0;
}

static int peer_step17_handler(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[%d] step 17. DKG step 2 - receive shares, verify commitments\e[0m\n", ctx->index);
  if(input_len != ctx->n * stpdkg_msg10_SIZE) return 1;
  if(output_len != stpdkg_msg9_SIZE(ctx)) return 2;

  const uint8_t *ptr = input;
  for(uint8_t i=0;i<ctx->n;i++) {
    DKG_Message* msg10 = (DKG_Message*) ptr;
    if(log_file!=NULL) {
      fprintf(log_file,"[%d] msgno: %d, from: %d to: %d ", ctx->index, msg10->msgno, msg10->from, msg10->to);
      dump(ptr, stpdkg_msg10_SIZE, "msg");
    }
    int ret = recv_msg(ptr, stpdkg_msg10_SIZE, 10, i+1, ctx->index, (*ctx->sig_pks)[i+1], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts[i]);
    if(0!=ret) return 64+ret;

    // decrypt final empty handshake packet
    if(0!=dkg_noise_decrypt(msg10->data, noise_xk_handshake3_SIZE, NULL, 0, &(*ctx->noise_ins)[i])) return 4;

    if(0!=crypto_auth_verify(msg10->data + noise_xk_handshake3_SIZE + sizeof(TOPRF_Share) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                             msg10->data + noise_xk_handshake3_SIZE,
                             sizeof(TOPRF_Share) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                             Noise_XK_session_get_key((*ctx->noise_ins)[i]))) {
      return 5;
    }

    if(0!=dkg_noise_decrypt(msg10->data + noise_xk_handshake3_SIZE, sizeof(TOPRF_Share) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                              (uint8_t*) &(*ctx->xshares)[i], sizeof(TOPRF_Share),
                              &(*ctx->noise_ins)[i])) return 6;

    ptr+=stpdkg_msg10_SIZE;
  }

  DKG_Message* msg9 = (DKG_Message*) output;
  uint8_t *fails_len = msg9->data;
  uint8_t *fails = msg9->data+1;
  memset(fails, 0, ctx->n);
  // todo BUG? why does this succeed? it shouldn't
  dkg_verify_commitments(ctx->n, ctx->t, ctx->index, ctx->commitments, *ctx->xshares, fails, fails_len);

#ifdef UNITTEST_CORRUPT
  static int totalfails = 0;
  for(uint8_t i=1;i<=ctx->n;i++) {
    if(totalfails < ctx->t - ctx->index && *fails_len < ctx->t-1 && i != ctx->index) {
      // avoid duplicates
      int j;
      for(j=1;j<=msg9->data[0];j++) if(msg9->data[j]==i) break;
      if(j<=msg9->data[0]) continue;

      fails[msg9->data[0]++]=i;
      totalfails++;
    }
  }
#endif //UNITTEST_CORRUPT

  if(log_file!=NULL) {
    for(int j=0;j<*fails_len;j++) {
      fprintf(log_file,"\e[0;31m[%d] failed to verify commitments from %d!\e[0m\n", ctx->index, fails[j]);
    }
  }

  if(0!=send_msg(output, stpdkg_msg9_SIZE(ctx), 9, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return 7;
  if(log_file!=NULL) {
    fprintf(log_file,"[%d] msgno: %d, from: %d to: %x ", ctx->index, msg9->msgno, msg9->from, msg9->to);
    dump(output, stpdkg_msg9_SIZE(ctx), "msg");
  }

  return 0;
}

static int stp_step18_handler(STP_DKG_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[!] step 18. broadcast complaints of peers\e[0m\n");

  if((stpdkg_msg9_SIZE(ctx) * ctx->n) != input_len) return 1;
  if(output_len != stpdkg_msg10x_SIZE(ctx)) return 2;

  ctx->complaints_len = 0;

  const uint8_t *ptr = input;
  uint8_t *wptr = ((DKG_Message *) output)->data;
  for(uint8_t i=0;i<ctx->n;i++, ptr+=stpdkg_msg9_SIZE(ctx)) {
    const DKG_Message* msg = (const DKG_Message*) ptr;
    if(log_file!=NULL) {
      fprintf(log_file,"[!] msgno: %d, from: %d to: 0x%x ", msg->msgno, msg->from, msg->to);
      dump(ptr, stpdkg_msg9_SIZE(ctx), "msg");
    }
    int ret = recv_msg(ptr, stpdkg_msg9_SIZE(ctx), 9, i+1, 0xff, (*ctx->sig_pks)[i+1], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts[i]);
    if(0!=ret) {
      if(add_cheater(ctx, 16, 64+ret, i+1, 0xff) == NULL) return 6;
      continue;
    }
    if(msg->len - sizeof(DKG_Message) < msg->data[0]) return 4;

    // keep a copy all complaint pairs (complainer, complained)
    for(int k=0;k<msg->data[0] && (k+1)<msg->len-sizeof(DKG_Message);k++) {
      if(msg->data[k+1] > ctx->n || msg->data[k+1] < 1) {
        if(add_cheater(ctx, 16, 7, i+1, msg->data[k+1]) == NULL) return 6;
        continue;
      }
      uint16_t pair=(uint16_t) (((i+1)<<8) | msg->data[k+1]);
      int j=0;
      for(j=0;j<ctx->complaints_len;j++) if((*ctx->complaints)[j]==pair) break;
      if(j<ctx->complaints_len) {
        if(add_cheater(ctx, 16, 8, i+1, msg->data[k+1]) == NULL) return 6;
        continue;
      }
      (*ctx->complaints)[ctx->complaints_len++] = pair;
      if(log_file!=NULL) {
        fprintf(log_file,"\e[0;31m[!] peer %d failed to verify commitments from peer %d!\e[0m\n", i+1, msg->data[1+k]);
      }
    }

    memcpy(wptr, ptr, stpdkg_msg9_SIZE(ctx));
    wptr+=stpdkg_msg9_SIZE(ctx);
  }
  dump((uint8_t*) (*ctx->complaints), ctx->complaints_len*sizeof(uint16_t), "[!] complaints");

  // if more than t^2 complaints are received the protocol also fails
  if(ctx->complaints_len >= ctx->t * ctx->t) {
    if(add_cheater(ctx, 16, 6, 0xfe, 0xfe) == NULL) return 6;
    return 5;
  }

  if(ctx->cheater_len>0) return 5;

  if(0!=send_msg(output, output_len, 10, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return 7;
  DKG_Message* msg10 = (DKG_Message*) output;
  if(log_file!=NULL) {
    fprintf(log_file,"[!] msgno: %d, from: %d to: %x ", msg10->msgno, msg10->from, msg10->to);
    dump(output, output_len, "msg");
  }

  // add broadcast msg to transcript
  update_transcript(&ctx->transcript, (uint8_t*) output, output_len);

  return 0;
}

static int peer_step19_handler(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[%d] step 19. receive complaints broadcast\e[0m\n", ctx->index);
  if(input_len != stpdkg_msg10x_SIZE(ctx)) return 1;
  if(output_len !=0) return 2;

  // verify STP message envelope
  DKG_Message* msg10 = (DKG_Message*) input;
  if(log_file!=NULL) {
    fprintf(log_file,"[%d] msgno: %d, from: %d to: %x ", ctx->index, msg10->msgno, msg10->from, msg10->to);
    dump(input, input_len, "msg");
  }

  int ret = recv_msg(input, input_len, 10, 0, 0xff, (*ctx->sig_pks)[0], ctx->sessionid, ctx->ts_epsilon, &ctx->stp_last_ts);
  if(0!=ret) return 16+ret;

  // add broadcast msg to transcript
  update_transcript(&ctx->transcript, input, input_len);

  const uint8_t *ptr = msg10->data;
  for(uint8_t i=0;i<ctx->n;i++) {
    DKG_Message* msg9 = (DKG_Message*) ptr;
    if(log_file!=NULL) {
      fprintf(log_file,"[%d] msgno: %d, from: %d to: 0x%x ", ctx->index, msg9->msgno, msg9->from, msg9->to);
      dump(ptr, stpdkg_msg9_SIZE(ctx), "msg");
    }
    ret = recv_msg(ptr, stpdkg_msg9_SIZE(ctx), 9, i+1, 0xff, (*ctx->sig_pks)[i+1], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts[i]);
    if(0!=ret) return 32+ret;
    if(msg9->len - sizeof(DKG_Message) < msg9->data[0]) return 5;

    // keep a copy all complaint pairs (complainer, complained)
    for(int k=0;k<msg9->data[0] && (k+1)<msg9->len-sizeof(DKG_Message);k++) {
      uint16_t pair=(uint16_t) (((i+1)<<8) | msg9->data[k+1]);
      int j=0;
      for(j=0;j<ctx->complaints_len;j++) if(ctx->complaints[j]==pair) break;
      if(j<ctx->complaints_len) continue;
      ctx->complaints[ctx->complaints_len++] = pair;

      if(msg9->data[k+1] == ctx->index) {
        ctx->my_complaints[ctx->my_complaints_len++] = i+1;
        if(log_file!=NULL) fprintf(log_file,"\e[0;31m[%d] peer %d failed to verify commitments from peer %d!\e[0m\n", ctx->index, i+1, msg9->data[1+k]);
      }
    }

    ptr+=stpdkg_msg9_SIZE(ctx);
  }

  if(ctx->complaints_len == 0) {
    ctx->prev = ctx->step;
    ctx->step+=1; // skip to step 21
  }

  return 0;
}

static int peer_step19a_handler(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[%d] step 19a. potentially broadcast contested shares\e[0m\n", ctx->index);
  if(input_len != 0) return 1;
  if(output_len != stpdkg_peer_output_size(ctx)) return 2;
  if(output_len == 0) {
    if(log_file!=NULL) {
      fprintf(log_file,"[%d] nothing to defend against, no message to send\n", ctx->index);
    }
    return 0;
  }

  // send out all shares that belong to peers that complained.
  DKG_Message* msg11 = (DKG_Message*) output;
  uint8_t *wptr = msg11->data;
  for(int i=0;i<ctx->my_complaints_len;i++) {
    if(log_file!=NULL) fprintf(log_file, "\e[0;36m[%d] defending against complaint from %d\e[0m\n", ctx->index, ctx->my_complaints[i]);

    *wptr++ = ctx->my_complaints[i];
    // reveal key for noise wrapped share sent previously
    memcpy(wptr, Noise_XK_session_get_key((*ctx->noise_outs)[ctx->my_complaints[i]-1]), dkg_noise_key_SIZE);
    wptr+=dkg_noise_key_SIZE;
  }

  if(0!=send_msg(output, stpdkg_peer_output_size(ctx), 11, ctx->index, 0x0, ctx->sig_sk, ctx->sessionid)) return 3;
  if(log_file!=NULL) {
    fprintf(log_file,"[%d] msgno: %d, from: %d to: %x ", ctx->index, msg11->msgno, msg11->from, msg11->to);
    dump(output, stpdkg_peer_output_size(ctx), "msg");
  }

  // we skip to the end...
  ctx->step=99;

  return 0;
}

static int stp_step20_handler(STP_DKG_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[!] step 20. collect keys of contested shares and verify the commitments\e[0m\n");
  if(input_len != stpdkg_stp_input_size(ctx)) return 1;
  if(output_len != 0) return 2;

  unsigned int ctr[ctx->n];
  uint16_t complaints[ctx->complaints_len];
  memset(ctr,0,sizeof(ctr));
  for(int i=0;i<ctx->complaints_len;i++) {
    ctr[((*ctx->complaints)[i] & 0xff)-1]++;
    complaints[i] = (*ctx->complaints)[i];
  }

  uint8_t (*noisy_shares)[ctx->n][ctx->n][stpdkg_msg10_SIZE] = (uint8_t (*)[ctx->n][ctx->n][stpdkg_msg10_SIZE]) ctx->encrypted_shares;

  const uint8_t *ptr = input;
  size_t msg_len;
  for(uint8_t i=0;i<ctx->n;i++,ptr += msg_len) {
    if(ctr[i]==0) {
      msg_len = 0;
      continue; // no complaints against this peer
    }
    msg_len = sizeof(DKG_Message) + (1+dkg_noise_key_SIZE) * ctr[i];

    const DKG_Message* msg = (const DKG_Message*) ptr;
    if(log_file!=NULL) {
      fprintf(log_file,"[!] msgno: %d, from: %d to: 0x%x ", msg->msgno, msg->from, msg->to);
      dump(ptr, msg_len, "msg");
    }
    int ret = recv_msg(ptr, msg_len, 11, i+1, 0, (*ctx->sig_pks)[i+1], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts[i]);
    if(0!=ret) {
      if(add_cheater(ctx, 18, 32+ret, i+1, 0xfe) == NULL) return 4;
      continue;
    }

    // verify proofs
    const uint8_t *keyptr = msg->data;
    for(int k=0;k<ctr[i];k++,keyptr+=dkg_noise_key_SIZE) {
      TOPRF_Share share;

      const uint8_t complainer = *keyptr++;
      const uint8_t accused = msg->from;

      int j;
      for(j=0;j<ctx->complaints_len;j++) {
        if(complaints[j] == (((complainer)<<8) | accused)) {
          complaints[j]=0xffff;
          break;
        }
      }
      if(j==ctx->complaints_len) {
        // accused revealed a key that was not complained about
        if(add_cheater(ctx, 18, 6, accused, complainer) == NULL) return 4;
        continue;
      }

      uint8_t *msg10_ptr = (*noisy_shares)[accused-1][complainer-1];
      const DKG_Message *msg10 = (const DKG_Message *) msg10_ptr;
      if(log_file!=NULL) {
        fprintf(log_file,"[!] msgno: %d, from: %d to: %d ", msg10->msgno, msg10->from, msg10->to);
        dump(msg10_ptr, stpdkg_msg10_SIZE, "msg");
      }
      uint64_t last_ts = ntohll(msg10->ts);
      ret = recv_msg(msg10_ptr, stpdkg_msg10_SIZE, 10,
                     accused, complainer,
                     (*ctx->sig_pks)[accused-1 +1], ctx->sessionid,
                     ctx->ts_epsilon, &last_ts);
      if(0!=ret) {
        // key reveal msg_recv failure
        if(add_cheater(ctx, 18, 16+ret, accused, complainer) == NULL) return 4;
        continue;
      }
#ifdef UNITTEST
      dump(keyptr, dkg_noise_key_SIZE, "[!] key_%d,%d", accused, complainer);
#endif //UNITTEST

      // verify key committing hmac first!
#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
      if(0!=crypto_auth_verify(msg10->data + noise_xk_handshake3_SIZE + sizeof(TOPRF_Share) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                               msg10->data + noise_xk_handshake3_SIZE,
                               sizeof(TOPRF_Share) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                               keyptr)) {
        // failed to verify KC MAC on message
        if(add_cheater(ctx, 18, 3, accused, complainer) == NULL) return 4;
        continue;
      }
#endif

      Noise_XK_error_code
        res0 = Noise_XK_aead_decrypt((uint8_t*)keyptr, 0, (uint32_t)0U, NULL, sizeof(share), (uint8_t*) &share, (uint8_t*) msg10->data + noise_xk_handshake3_SIZE);
      if (!(res0 == Noise_XK_CSuccess)) {
        // share decryption failure
        if(add_cheater(ctx, 18, 4, accused, complainer) == NULL) return 4;
        continue;
      }

      if(share.index != complainer) {
        // invalid share index
        STP_DKG_Cheater *cheater = add_cheater(ctx, 18, 5, accused, complainer);
        if(cheater == NULL) return 4;
        cheater->invalid_index = share.index;
        continue;
      }

      if(log_file!=NULL) {
        fprintf(log_file, "[!] checking proof of peer %d for complaint by peer %d\n", msg->from, share.index);
        dump((void*) &share, sizeof(TOPRF_Share), "[!] share_%d,%d", msg->from, share.index);
        dump((*ctx->commitments)[(msg->from-1) * ctx->t], ctx->t * crypto_core_ristretto255_BYTES, "[!] commitments_%d", msg->from);
      }
      ret = dkg_verify_commitment(ctx->n, ctx->t,
                                  share.index,
                                  msg->from,
                                  (const uint8_t (*)[crypto_core_ristretto255_BYTES]) (*ctx->commitments)[(msg->from-1) * ctx->t],
                                  share);
      switch(ret) {
      case 0: {
        // verified correctly
        if(log_file!=NULL) fprintf(log_file, "\e[0;32m[!] complaint against %d by %d invalid, proof correct\e[0m\n", msg->from, share.index);

        if(add_cheater(ctx, 18, 128+ret, accused, complainer) == NULL) return 4;
        break;
      }
      case 1: {
        // confirmed corrupt
        if(log_file!=NULL) fprintf(log_file, "\e[0;31m[!] complaint against %d by %d valid, proof incorrect\e[0m\n", msg->from, share.index);
        if(add_cheater(ctx, 18, 128+ret, accused, complainer) == NULL) return 4;
        break;
      }
      case -1: {
        // invalid input
        if(log_file!=NULL) fprintf(log_file, "\e[0;31m[!] complaint against %d by %d, cannot be verified, invalid input\e[0m\n", msg->from, share.index);

        if(add_cheater(ctx, 18, 128+ret, accused, complainer) == NULL) return 4;
        break;
      }
      }
    }
  }

  for(int i=0;i<ctx->complaints_len;i++) {
    if(complaints[i] != 0xffff) {
      if(add_cheater(ctx, 18, 7, (uint8_t) (complaints[i] >> 8), (uint8_t) (complaints[i] & 0xff)) == NULL) return 4;
    }
  }

  ctx->step=99; // we skip to the end

  return 3;
}

static int peer_step21_handler(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[%d] step 21. send final transcript\e[0m\n", ctx->index);
  if(input_len != 0) return 1;
  if(output_len != stpdkg_msg19_SIZE) return 2;

  DKG_Message* msg20 = (DKG_Message*) output;
  crypto_generichash_final(&ctx->transcript, msg20->data, crypto_generichash_BYTES);
  if(0!=send_msg(output, stpdkg_msg19_SIZE, 20, ctx->index, 0, ctx->sig_sk, ctx->sessionid)) return 3;
  if(log_file!=NULL) {
    fprintf(log_file,"[%d] msgno: %d, from: %d to: %d ", ctx->index, msg20->msgno, msg20->from, msg20->to);
    dump(output, stpdkg_msg19_SIZE, "msg");
  }

  return 0;
}

static int stp_step22_handler(STP_DKG_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[!] step 22. collect and verify transcripts\e[0m\n");

  if((stpdkg_msg19_SIZE * ctx->n) != input_len) return 1;
  if(output_len != stpdkg_msg20_SIZE) return 2;

  uint8_t transcript_hash[crypto_generichash_BYTES];
  crypto_generichash_final(&ctx->transcript, transcript_hash, crypto_generichash_BYTES);

  uint8_t *wptr = ((DKG_Message *) output)->data;
  memcpy(wptr, "OK", 2);
  const uint8_t *ptr = input;
  for(uint8_t i=0;i<ctx->n;i++, ptr+=stpdkg_msg19_SIZE) {
    const DKG_Message* msg = (const DKG_Message*) ptr;
    if(log_file!=NULL) {
      fprintf(log_file,"[!] msgno: %d, from: %d to: %d ", msg->msgno, msg->from, msg->to);
      dump(ptr, stpdkg_msg19_SIZE, "msg");
    }
    int ret = recv_msg(ptr, stpdkg_msg19_SIZE, 20, i+1, 0, (*ctx->sig_pks)[i+1], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts[i]);
    if(0!=ret) {
      if(add_cheater(ctx, 20, 1+ret, i+1, 0) == NULL) return 4;

      memcpy(wptr,"NO",2);
      continue;
    }

    if(sodium_memcmp(transcript_hash, msg->data, sizeof(transcript_hash))!=0) {
      if(log_file!=NULL) {
        fprintf(log_file,"\e[0;31m[!] failed to verify transcript from %d!\e[0m\n", i);
      }
      if(add_cheater(ctx, 20, 1, i+1, 0) == NULL) return 4;
      memcpy(wptr,"NO",2);
    }
  }

  if(0!=send_msg(output, output_len, 21, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return 5;
  DKG_Message* msg21 = (DKG_Message*) output;
  if(log_file!=NULL) {
    fprintf(log_file,"[!] msgno: %d, from: %d to: %x ", msg21->msgno, msg21->from, msg21->to);
    dump(output, output_len, "msg");
  }
  if(ctx->cheater_len == 0) return 0;

  ctx->step = 99; // we finish here
  return 3;
}

static int peer_step23_handler(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[%d] step 23. get final approval\e[0m\n", ctx->index);
  if(input_len != stpdkg_msg20_SIZE) return 1;
  if(output_len != stpdkg_msg21_SIZE) return 2;

  // verify STP message envelope
  DKG_Message* msg21 = (DKG_Message*) input;
  if(log_file!=NULL) {
    fprintf(log_file,"[%d] msgno: %d, from: %d to: 0x%x ", ctx->index, msg21->msgno, msg21->from, msg21->to);
    dump(input, input_len, "msg");
  }
  int ret = recv_msg(input, input_len, 21, 0, 0xff, (*ctx->sig_pks)[0], ctx->sessionid, ctx->ts_epsilon, &ctx->stp_last_ts);
  if(0!=ret) return 4+ret;

  int fail = (memcmp(msg21->data, "OK", 2) != 0);
  if(!fail) {
    ctx->share.index=ctx->index;
    dkg_finish(ctx->n,*ctx->xshares,ctx->index,&ctx->share);

    DKG_Message* msg22 = (DKG_Message*) output;
    memcpy(msg22->data, msg21->data, 2);
    if(0!=send_msg(output, stpdkg_msg21_SIZE, 22, ctx->index, 0, ctx->sig_sk, ctx->sessionid)) return 3;
    if(log_file!=NULL) {
        fprintf(log_file,"[%d] msgno: %d, from: %d to: %d ", ctx->index, msg22->msgno, msg22->from, msg22->to);
        dump(output, stpdkg_msg21_SIZE, "msg");
    }
    return 0;
  }
  return 4;
}

static int stp_step24_handler(STP_DKG_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[!] step 24. collect acks from peers\e[0m\n");

  if((stpdkg_msg21_SIZE * ctx->n) != input_len) return 1;
  if(output_len != 0) return 2;

  const uint8_t *ptr = input;
  for(uint8_t i=0;i<ctx->n;i++, ptr+=stpdkg_msg21_SIZE) {
    const DKG_Message* msg = (const DKG_Message*) ptr;
    if(log_file!=NULL) {
      fprintf(log_file,"[!] msgno: %d, from: %d to: %d ", msg->msgno, msg->from, msg->to);
      dump(ptr, stpdkg_msg21_SIZE, "msg");
    }
    int ret = recv_msg(ptr, stpdkg_msg21_SIZE, 22, i+1, 0, (*ctx->sig_pks)[i+1], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts[i]);
    if(0!=ret) {
      if(add_cheater(ctx, 22, 64+ret, i+1, 0) == NULL) return 6;
      continue;
    }

    if(memcmp("OK", msg->data, 2)!=0) {
      if(log_file!=NULL) {
        fprintf(log_file,"\e[0;31m[!] failed to get ack from %d!\e[0m\n", i);
      }
    }
  }
  if(ctx->cheater_len>0) return 5;

  return 0;
}

int stpdkg_stp_next(STP_DKG_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  int ret = 0;
  switch(ctx->step) {
  case 0: {ret = stp_step1_handler(ctx, input, input_len, output, output_len); break;}
  case 1: {ret = stp_step4_handler(ctx, input, input_len, output, output_len); break;}
  case 2: {ret = stp_step68_handler(ctx, input, input_len, output, output_len); break;}
  case 3: {ret = stp_step68_handler(ctx, input, input_len, output, output_len); break;}
  case 4: {ret = stp_step12_handler(ctx, input, input_len, output, output_len); break;}
  case 5: {ret = stp_step14_handler(ctx, input, input_len, output, output_len); break;}
  case 6: {ret = stp_step16_handler(ctx, input, input_len, output, output_len); break;}
  case 7: {
    ret = stp_step18_handler(ctx, input, input_len, output, output_len);
    ctx->prev = ctx->step;
    if(ctx->complaints_len == 0) {
      // we skip over to step 21
      ctx->step++;
    }
    ctx->step++;
    return ret;
  }
  case 8: {ret = stp_step20_handler(ctx, input, input_len, output, output_len); break;}
  case 9: {ret = stp_step22_handler(ctx, input, input_len, output, output_len); break;}
  case 10: {ret = stp_step24_handler(ctx, input, input_len, output, output_len); break;}
  default: {
    if(log_file!=NULL) fprintf(log_file, "[!] invalid step\n");
    return 99;
  }
  }
  ctx->prev=ctx->step++;
  if(ret!=0) ctx->step=99; // so that not_done reports done
  return ret;
}

int stpdkg_peer_next(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  int ret=0;
  switch(ctx->step) {
  case 0: {ret = peer_step2_3_handler(ctx, input, input_len, output, output_len); break;}
  case 1: {ret = peer_step5_handler(ctx, input, input_len, output, output_len); break;}
  case 2: {ret = peer_step7_handler(ctx, input, input_len, output, output_len); break;}
  case 3: {ret = peer_step911_handler(ctx, input, input_len, output, output_len); break;}
  case 4: {ret = peer_step13_handler(ctx, input, input_len, output, output_len); break;}
  case 5: {ret = peer_step15_handler(ctx, input, input_len, output, output_len); break;}
  case 6: {ret = peer_step17_handler(ctx, input, input_len, output, output_len); break;}
  case 7: {ret = peer_step19_handler(ctx, input, input_len, output, output_len); break;}
  case 8: {ret = peer_step19a_handler(ctx, input, input_len, output, output_len); break;}
  case 9: {ret = peer_step21_handler(ctx, input, input_len, output, output_len); break;}
  case 10: {ret = peer_step23_handler(ctx, input, input_len, output, output_len); break;}
  case 11: {
    // we are done
    ret = 0;
    break;
  }
  default: {
    if(log_file!=NULL) fprintf(log_file, "[%d] invalid step\n", ctx->index);
    ret = 99;
  }
  }
  ctx->prev=ctx->step++;
  if(ret!=0) ctx->step=99; // so that not_done reports done
  return ret;
}

char* stpdkg_recv_err(const int code) {
  switch(code) {
  case 0: return "no error";
  case 1: return "invalid message len";
  case 2: return "invalid message number";
  case 3: return "invalid sender";
  case 4: return "invalid recipient";
  case 5: return "expired message";
  case 6: return "invalid signature";
  case 7: return "invalid sessionid";
  }
  return "invalid recv_msg error code";
}

uint8_t stpdkg_cheater_msg(const STP_DKG_Cheater *c, char *out, const size_t outlen) {
  if(c->error>65 && c->error<=70) {
      snprintf(out, outlen, "step %d message from peer %d for peer %d could not be validated: %s",
               c->step, c->peer, c->other_peer, stpdkg_recv_err(c->error & 0x3f));
      return c->peer;
  }
  if(c->step==16) {
    if(c->error == 6) {
      snprintf(out, outlen, "more than t^2 complaints, most peers are cheating.");
      return 0;
    } else if(c->error == 7) {
      snprintf(out, outlen, "peer %d sent complaint about invalid peer %d.", c->peer, c->other_peer);
      return c->peer;
    } else if(c->error == 8) {
      snprintf(out, outlen, "peer %d sent a duplicate complaint about peer %d.", c->peer, c->other_peer);
      return c->peer;
    }
    snprintf(out,outlen, "invalid error code for step 16: %d", c->error);
    return 0;
  } else if(c->step==18) {
    if(c->error & 16) {
      snprintf(out, outlen, "message containing encrypted share from peer %d for peer %d could not be validated: %s",
               c->peer, c->other_peer, stpdkg_recv_err(c->error & 0xf));
      return c->peer;
    } else if (c->error & 32) {
      snprintf(out, outlen, "message revealing key encrypting share from peer %d for peer %d could not be validated: %s",
               c->peer, c->other_peer, stpdkg_recv_err(c->error & 0x1f));
      return c->peer;
    }
    switch(c->error) {
    case 3: {
      snprintf(out,outlen, "accused peer %d revealed a key (for peer %d) that was not complained about", c->peer, c->other_peer);
      return c->peer;
    }
    case 4: {
      snprintf(out,outlen, "verification of hmac of message from accused peer %d to complaining peer %d failed", c->peer, c->other_peer);
      return c->peer;
    }
    case 5: {
      snprintf(out,outlen, "accused peer %d sent an invalid share with index %d to complaining peer %d", c->peer, c->other_peer, c->invalid_index);
      return c->peer;
    }
    case 6: {
      snprintf(out,outlen, "accused peer %d revealed a key for happy peer %d", c->peer, c->other_peer);
      return c->peer;
    }
    case 7: {
      snprintf(out,outlen, "accused peer %d complained by peer %d was not verified", c->peer, c->other_peer);
      return c->peer;
    }
    case 127: {
      snprintf(out,outlen, "accused peer %d provided invalid parameters to complaint from peer %d", c->peer, c->other_peer);
      return c->peer;
    }
    case 128: {
      snprintf(out,outlen, "peer %d was falsely accused by peer %d", c->peer, c->other_peer);
      return c->other_peer;
    }
    case 129: {
      snprintf(out,outlen, "accused peer %d was caught cheating by peer %d", c->peer, c->other_peer);
      return c->peer;
    }
    default: {
      snprintf(out,outlen, "invalid error code for step 18: %d", c->error);
      return 0;
    }
    }
  } else if(c->step==20) {
    if(c->error == 1) {
      snprintf(out,outlen, "transcript mismatch peer %d", c->peer);
      return c->peer;
    }
    snprintf(out,outlen, "invalid error code for step 20: %d", c->error);
    return 0;
  }
  snprintf(out,outlen, "invalid step %d", c->step);
  return 0;
}
