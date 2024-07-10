#include <stdio.h>
#include <stdint.h>
#include <sodium.h>
#include <arpa/inet.h> //htons
#include <time.h> // time
#include <sys/param.h> // __BYTE_ORDER __BIG_ENDIAN
#include <string.h> // memcpy
#include <stdarg.h> // va_{start|end}
#include <stdlib.h> // free, rand
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#include <unistd.h>
#endif

#include "XK.h"
#include "dkg.h"
#include "tp-dkg.h"

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

FILE* log_file=NULL;

#define tpdkg_freshness_TIMEOUT 120000

#define tpdkg_msg1_SIZE (sizeof(TP_DKG_Message))
#define tpdkg_msg2_SIZE (sizeof(TP_DKG_Message) + crypto_sign_PUBLICKEYBYTES + crypto_scalarmult_BYTES)
#define noise_xk_handshake1_SIZE 48UL
#define tpdkg_msg4_SIZE (sizeof(TP_DKG_Message) + noise_xk_handshake1_SIZE)
#define noise_xk_handshake2_SIZE 48UL
#define tpdkg_msg5_SIZE (sizeof(TP_DKG_Message) + noise_xk_handshake2_SIZE)
#define tpdkg_msg6_SIZE(ctx) (sizeof(TP_DKG_Message) + crypto_core_ristretto255_BYTES * ctx->t )
#define tpdkg_msg9_SIZE(ctx) (sizeof(TP_DKG_Message) + ctx->n + 1 )
#define tpdkg_msg10_SIZE(ctx) (sizeof(TP_DKG_Message) + ctx->n * tpdkg_msg9_SIZE(ctx))
#define tpdkg_msg19_SIZE (sizeof(TP_DKG_Message) + crypto_generichash_BYTES)
#define tpdkg_msg20_SIZE (sizeof(TP_DKG_Message) + 2)
#define tpdkg_msg21_SIZE (sizeof(TP_DKG_Message) + 2)
#define tpdkg_noise_key_SIZE (32UL)

static void dump(const uint8_t *p, const size_t len, const char* msg, ...) {
  if(log_file==NULL) return;
  va_list args;
  va_start(args, msg);
  vfprintf(log_file, msg, args);
  va_end(args);
  fprintf(log_file," ");
  for(size_t i=0;i<len;i++)
    fprintf(log_file,"%02x", p[i]);
  fprintf(log_file,"\n");
}

static uint64_t htonll(uint64_t n) {
#if __BYTE_ORDER == __BIG_ENDIAN
    return n;
#else
    return (((uint64_t)htonl((uint32_t)n)) << 32) + htonl((uint32_t) (n >> 32));
#endif
}

static uint64_t ntohll(uint64_t n) {
#if __BYTE_ORDER == __BIG_ENDIAN
    return n;
#else
    return (((uint64_t)ntohl((uint32_t)n)) << 32) + ntohl((uint32_t)(n >> 32));
#endif
}

static int check_ts(const uint64_t ts_epsilon, uint64_t *last_ts, const uint64_t ts) {
  if(*last_ts > ts) return 1;
  if(ts > *last_ts + ts_epsilon) return 2;
  *last_ts = ts;
  return 0;
}

static int send_msg(uint8_t* msg_buf, const size_t msg_buf_len, const uint8_t msgno, const uint8_t from, const uint8_t to, const uint8_t *sig_sk, const uint8_t sessionid[tpdkg_sessionid_SIZE]) {
  if(msg_buf==NULL) return 1;
  TP_DKG_Message* msg = (TP_DKG_Message*) msg_buf;
  msg->len = htonl((uint32_t)msg_buf_len);
  msg->msgno = msgno;
  msg->from = from;
  msg->to = to;
  msg->ts = htonll((uint64_t)time(NULL));

  uint8_t with_sessionid[msg_buf_len + tpdkg_sessionid_SIZE - crypto_sign_BYTES];
  memcpy(with_sessionid, msg_buf + crypto_sign_BYTES, msg_buf_len - crypto_sign_BYTES);
  memcpy(with_sessionid + msg_buf_len -  crypto_sign_BYTES, sessionid, tpdkg_sessionid_SIZE);

  crypto_sign_detached(msg->sig, NULL, with_sessionid, sizeof(with_sessionid), sig_sk);
  return 0;
}

// todo set as suspicious any peer that fails this.
static int recv_msg(const uint8_t *msg_buf, const size_t msg_buf_len, const uint8_t msgno, const uint8_t from, const uint8_t to, const uint8_t *sig_pk, const uint8_t sessionid[tpdkg_sessionid_SIZE], const uint64_t ts_epsilon, uint64_t *last_ts ) {
  if(msg_buf==NULL) return 7;
  TP_DKG_Message* msg = (TP_DKG_Message*) msg_buf;
  if(ntohl(msg->len) != msg_buf_len) return 1;
  if(msg->msgno != msgno) return 2;
  if(msg->from != from) return 3;
  if(msg->to != to) return 4;

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
  if(0!=check_ts(ts_epsilon, last_ts, ntohll(msg->ts))) return 5;
#endif

  const size_t unsigned_buf_len = msg_buf_len - crypto_sign_BYTES;

  uint8_t with_sessionid[unsigned_buf_len + tpdkg_sessionid_SIZE];
  memcpy(with_sessionid, msg_buf + crypto_sign_BYTES, unsigned_buf_len);
  memcpy(with_sessionid + unsigned_buf_len, sessionid, tpdkg_sessionid_SIZE);

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
  if(0!=crypto_sign_verify_detached(msg->sig, with_sessionid, sizeof(with_sessionid), sig_pk)) return 6;
#endif

  return 0;
}

static int tpdkg_init_noise_handshake(TP_DKG_PeerState *ctx,
                                      uint8_t rpk[crypto_scalarmult_BYTES],
                                      uint8_t *rname,
                                      Noise_XK_session_t** session,
                                      uint8_t msg[noise_xk_handshake1_SIZE]) {
  if(log_file != NULL) fprintf(log_file, "[%d] creating noise session -> %s\n", ctx->index, rname);
  // fixme: damnit this allocates stuff on the heap...
  Noise_XK_peer_t *peer = Noise_XK_device_add_peer(ctx->dev, rname, rpk);
  if(!peer) return 1;

  uint32_t peer_id = Noise_XK_peer_get_id(peer);
  *session = Noise_XK_session_create_initiator(ctx->dev, peer_id);
  if(!*session) return 2;

  Noise_XK_encap_message_t *encap_msg = Noise_XK_pack_message_with_conf_level(NOISE_XK_CONF_ZERO, 0, NULL);
  uint32_t cipher_msg_len;
  uint8_t *cipher_msg;
  Noise_XK_rcode ret = Noise_XK_session_write(encap_msg, *session, &cipher_msg_len, &cipher_msg);
  Noise_XK_encap_message_p_free(encap_msg);
  if(!Noise_XK_rcode_is_success(ret)) {
    Noise_XK_session_free(*session);
    return 3;
  }

  if(cipher_msg_len!=noise_xk_handshake1_SIZE) {
    Noise_XK_session_free(*session);
    free(cipher_msg);
    return 4;
  }
  if(msg==NULL) return 5;
  memcpy(msg,cipher_msg,cipher_msg_len);
  free(cipher_msg);

  return 0;
}

static int tpdkg_respond_noise_handshake(TP_DKG_PeerState *ctx,
                                         uint8_t rpk[crypto_scalarmult_BYTES],
                                         uint8_t *rname,
                                         Noise_XK_session_t** session,
                                         uint8_t inmsg[noise_xk_handshake1_SIZE],
                                         uint8_t outmsg[noise_xk_handshake2_SIZE]) {
  if(log_file != NULL) fprintf(log_file, "[%d] responding noise session -> %s\n", ctx->index, rname);
  // fixme: damnit this allocates stuff on the heap...

  *session = Noise_XK_session_create_responder(ctx->dev);
  if(!*session) return 1;

  Noise_XK_encap_message_t *encap_msg;
  Noise_XK_rcode ret = Noise_XK_session_read(&encap_msg, *session, noise_xk_handshake1_SIZE, inmsg);
  if(!Noise_XK_rcode_is_success(ret)) {
    Noise_XK_session_free(*session);
    return 2;
  }

  uint32_t plain_msg_len;
  uint8_t *plain_msg;
  if(!Noise_XK_unpack_message_with_auth_level(&plain_msg_len, &plain_msg, NOISE_XK_AUTH_ZERO, encap_msg)) {
    Noise_XK_session_free(*session);
    return 3;
  }
  Noise_XK_encap_message_p_free(encap_msg);

  encap_msg = Noise_XK_pack_message_with_conf_level(NOISE_XK_CONF_ZERO, 0, NULL);
  uint32_t cipher_msg_len;
  uint8_t *cipher_msg;
  ret = Noise_XK_session_write(encap_msg, *session, &cipher_msg_len, &cipher_msg);
  Noise_XK_encap_message_p_free(encap_msg);
  if(!Noise_XK_rcode_is_success(ret)) {
    Noise_XK_session_free(*session);
    return 4;
  }

  if(cipher_msg_len!=noise_xk_handshake2_SIZE) {
    Noise_XK_session_free(*session);
    free(cipher_msg);
    return 4;
  }
  if(outmsg==NULL) return 5;
  memcpy(outmsg,cipher_msg,cipher_msg_len);
  free(cipher_msg);
  return 0;
}

static int tpdkg_finish_noise_handshake(TP_DKG_PeerState *ctx,
                                        Noise_XK_session_t** session,
                                        uint8_t msg[noise_xk_handshake2_SIZE]) {
  if(!*session) {
    return 1;
  }

  if(log_file!=NULL) {
    // get peer name
    uint32_t peer_id = Noise_XK_session_get_peer_id(*session);
    Noise_XK_peer_t *peer = Noise_XK_device_lookup_peer_by_id(ctx->dev, peer_id);
    if(peer==NULL) {
      Noise_XK_session_free(*session);
      return 2;
    }
    uint8_t *pinfo;
    Noise_XK_peer_get_info((Noise_XK_noise_string*) &pinfo, peer);
    if(pinfo==NULL) {
      Noise_XK_session_free(*session);
      return 3;
    }
    fprintf(log_file, "[%d] finishing noise session -> %s\n", ctx->index, pinfo);
    free(pinfo);
  }

  Noise_XK_encap_message_t *encap_msg;
  Noise_XK_rcode ret = Noise_XK_session_read(&encap_msg, *session, noise_xk_handshake2_SIZE, msg);
  if(!Noise_XK_rcode_is_success(ret)) {
    if(log_file!=NULL) fprintf(log_file, "session read fail: %d\n", ret.val.case_Error);
    Noise_XK_session_free(*session);
    return 4;
  }

  uint32_t plain_msg_len;
  uint8_t *plain_msg;
  if(!Noise_XK_unpack_message_with_auth_level(&plain_msg_len, &plain_msg, NOISE_XK_AUTH_ZERO, encap_msg)) {
    Noise_XK_session_free(*session);
    return 5;
  }
  Noise_XK_encap_message_p_free(encap_msg);

  return 0;
}

static int tpdkg_noise_encrypt(uint8_t *input,
                               const size_t input_len,
                               uint8_t *output,
                               const size_t output_len,
                               Noise_XK_session_t** session) {
  if(!*session) {
    return 1;
  }
  if(input_len > 1024) {
    return 2;
  }

  Noise_XK_encap_message_t *encap_msg = Noise_XK_pack_message_with_conf_level(NOISE_XK_CONF_STRONG_FORWARD_SECRECY, (uint32_t) input_len, input);
  uint32_t cipher_msg_len;
  uint8_t *cipher_msg;
  Noise_XK_rcode ret = Noise_XK_session_write(encap_msg, *session, &cipher_msg_len, &cipher_msg);
  Noise_XK_encap_message_p_free(encap_msg);
  if(!Noise_XK_rcode_is_success(ret)) {
    return 3;
  }
  if(cipher_msg_len!=output_len) {
    if(cipher_msg!=NULL) free(cipher_msg);
    return 4;
  }
  if(output == NULL) return 5;
  if(cipher_msg==NULL) return 6;
  memcpy(output,cipher_msg,cipher_msg_len);
  free(cipher_msg);
  return 0;
}

static int tpdkg_noise_decrypt(uint8_t *input,
                               const size_t input_len,
                               uint8_t *output,
                               const size_t output_len,
                               Noise_XK_session_t** session) {
  if(*session==NULL) {
    return 1;
  }
  if(input_len > 1024) {
    return 2;
  }
  Noise_XK_encap_message_t *encap_msg;
  Noise_XK_rcode ret = Noise_XK_session_read(&encap_msg, *session, (uint32_t) input_len, input);
  if(!Noise_XK_rcode_is_success(ret)) {
    if(log_file!=NULL) fprintf(log_file, "session read fail: %d\n", ret.val.case_Error);
    return 3;
  }

  uint32_t plain_msg_len;
  uint8_t *plain_msg=NULL;
  if(!Noise_XK_unpack_message_with_auth_level(&plain_msg_len, &plain_msg, NOISE_XK_AUTH_KNOWN_SENDER_NO_KCI, encap_msg)) {
    return 4;
  }
  Noise_XK_encap_message_p_free(encap_msg);

  if(plain_msg_len!=output_len) {
    if(plain_msg!=NULL) free(plain_msg);
    return 5;
  }
  if(plain_msg!=NULL) {
    if(output == NULL) return 6;
    memcpy(output,plain_msg,plain_msg_len);
    free(plain_msg);
  }

  return 0;
}

/*
  Return the session unique send key, needed for tp-dkg reveal share.
*/
typedef struct Noise_XK_init_state_t_s {
  Noise_XK_init_state_t_tags tag;
  union {
    struct {
      uint32_t step;
      uint8_t *cipher_key;
      uint8_t *chaining_key;
      uint8_t *h;
      uint8_t *spriv;
      uint8_t *spub;
      uint8_t *epriv;
      uint8_t *epub;
      uint8_t *rs;
      uint8_t *re;
    } case_IMS_Handshake;
    struct {
      uint8_t *h;
      bool recv_transport_message;
      uint8_t *send_key;
      uint64_t send_nonce;
      uint8_t *receive_key;
      uint64_t receive_nonce;
    } case_IMS_Transport;
  } val;
} Noise_XK_init_state_t;

typedef struct Noise_XK_resp_state_t_s {
  Noise_XK_init_state_t_tags tag;
  union {
    struct {
      uint32_t step;
      uint8_t *cipher_key;
      uint8_t *chaining_key;
      uint8_t *h;
      uint8_t *spriv;
      uint8_t *spub;
      uint8_t *epriv;
      uint8_t *epub;
      uint8_t *rs;
      uint8_t *re;
    } case_IMS_Handshake;
    struct {
      uint8_t *h;
      uint8_t *send_key;
      uint64_t send_nonce;
      uint8_t *receive_key;
      uint64_t receive_nonce;
    } case_IMS_Transport;
  } val;
} Noise_XK_resp_state_t;

typedef struct Noise_XK_session_t_s {
  Noise_XK_session_t_tags tag;
  union {
    struct {
      Noise_XK_init_state_t state;
      uint32_t id;
      Noise_XK_noise_string *info;
      uint8_t *spriv;
      uint8_t *spub;
      uint32_t pid;
      Noise_XK_noise_string *pinfo;
      Noise_XK_device_t *dv;
    } case_DS_Initiator;
    struct {
      Noise_XK_resp_state_t state;
      uint32_t id;
      Noise_XK_noise_string *info;
      uint8_t *spriv;
      uint8_t *spub;
      uint32_t pid;
      Noise_XK_noise_string *pinfo;
      Noise_XK_device_t *dv;
    } case_DS_Responder;
  } val;
} Noise_XK_session_t;

static uint8_t* Noise_XK_session_get_key(Noise_XK_session_t *sn) {
  Noise_XK_session_t st = sn[0U];
  if (st.tag == Noise_XK_DS_Initiator && st.val.case_DS_Initiator.state.tag == Noise_XK_IMS_Transport)
    return st.val.case_DS_Initiator.state.val.case_IMS_Transport.send_key;
  if (st.tag == Noise_XK_DS_Responder && st.val.case_DS_Responder.state.tag == Noise_XK_IMS_Transport)
    return st.val.case_DS_Responder.state.val.case_IMS_Transport.receive_key;
  return NULL;
}

static TP_DKG_Cheater* add_cheater(TP_DKG_TPState *ctx, const int step, const int error, const uint8_t peer, const uint8_t other_peer) {
  if(ctx->cheater_len >= ctx->cheater_max) return NULL;
  TP_DKG_Cheater *cheater = &(*ctx->cheaters)[ctx->cheater_len++];
  cheater->step = step;
  cheater->error = error;
  cheater->peer = peer;
  cheater->other_peer=other_peer;
  return cheater;
}

size_t tpdkg_tp_input_size(const TP_DKG_TPState *ctx) {
  switch(ctx->step) {
  case 0: return 0;
  case 1: return ((tpdkg_msg2_SIZE + crypto_sign_BYTES) * ctx->n);
  case 2: return tpdkg_msg4_SIZE * ctx->n * ctx->n;
  case 3: return tpdkg_msg4_SIZE * ctx->n * ctx->n;
  case 4: return (tpdkg_msg6_SIZE(ctx) * ctx->n);
  case 5: return ctx->n * ctx->n * tpdkg_msg8_SIZE;
  case 6: return tpdkg_msg9_SIZE(ctx) * ctx->n;
  case 7: {
    size_t total = 0;
    uint8_t ctr[ctx->n];
    memset(ctr,0,ctx->n);
    for(int i=0;i<ctx->complaints_len;i++) ctr[((*ctx->complaints)[i] & 0xff) - 1]++;
    for(int i=0;i<ctx->n;i++) if(ctr[i]>0) total+=sizeof(TP_DKG_Message) + (1+tpdkg_noise_key_SIZE) * ctr[i];
    return total;
  }
  case 8: return tpdkg_msg19_SIZE * ctx->n;
  case 9: return (tpdkg_msg21_SIZE * ctx->n);
  default: {
    if(log_file!=NULL) fprintf(log_file, "[!] invalid tp step\n");
  }
  }
  return 0;
}

size_t tpdkg_tp_output_size(const TP_DKG_TPState *ctx) {
  switch(ctx->step) {
  case 0: return ctx->n*tpdkg_msg1_SIZE;
  case 1: return tpdkg_msg2_SIZE * ctx->n + sizeof(TP_DKG_Message);
  case 2: return tpdkg_msg4_SIZE * ctx->n * ctx->n;
  case 3: return tpdkg_msg5_SIZE * ctx->n * ctx->n;
  case 4: return sizeof(TP_DKG_Message) + (tpdkg_msg6_SIZE(ctx) * ctx->n);
  case 5: return ctx->n * ctx->n * tpdkg_msg8_SIZE;
  case 6: return tpdkg_msg10_SIZE(ctx);
  case 7: return 0;
  case 8: return tpdkg_msg20_SIZE;
  case 9: return 0;
  default: if(log_file!=NULL) fprintf(log_file, "[!] invalid tp step\n");
  }
  return 0;
}

int tpdkg_tp_peer_msg(const TP_DKG_TPState *ctx, const uint8_t *base, const size_t base_size, const uint8_t peer, const uint8_t **msg, size_t *len) {
  if(peer>=ctx->n || peer < 0) return -1;

  switch(ctx->prev) {
  case 0: {
    *msg = base + peer*tpdkg_msg1_SIZE;
    *len = tpdkg_msg1_SIZE;
    break;
  }
  case 1: {
    *msg = base;
    *len = tpdkg_msg2_SIZE * ctx->n + sizeof(TP_DKG_Message);
    break;
  }
  case 2: {
    *msg = base + peer * tpdkg_msg4_SIZE * ctx->n;
    *len = tpdkg_msg4_SIZE * ctx->n;
    break;
  }
  case 3: {
    *msg = base + peer * tpdkg_msg5_SIZE * ctx->n;
    *len = tpdkg_msg5_SIZE * ctx->n;
    break;
  }
  case 4: {
    *msg = base;
    *len = sizeof(TP_DKG_Message) + (tpdkg_msg6_SIZE(ctx) * ctx->n);
    break;
  }
  case 5: {
    *msg = base + peer * ctx->n * tpdkg_msg8_SIZE;
    *len = ctx->n * tpdkg_msg8_SIZE;
    break;
  }
  case 6: {
    *msg = base;
    *len = tpdkg_msg10_SIZE(ctx);
    break;
  }
  case 7: {
    *len = 0;
    *msg = NULL;
    break;
  }
  case 8: {
    *msg = base;
    *len = tpdkg_msg20_SIZE;
    break;
  }
  case 9: {
    *len = 0;
    *msg = NULL;
    break;
  }
  default: {
    if(log_file!=NULL) fprintf(log_file, "[!] invalid tp step in tpdkg_tp_peer_msg\n");
    return 1;
  }
  }

  // todo int overflow protection
  if(base+base_size < *msg + *len) {
    if(log_file!=NULL) fprintf(log_file, "buffer overread detected in tpdkg_tp_peer_msg %ld\n", (base+base_size) - (*msg + *len));
    return 2;
  }

  return 0;
}

size_t tpdkg_peer_input_size(const TP_DKG_PeerState *ctx) {
  switch(ctx->step) {
  case 0: return tpdkg_msg1_SIZE;
  case 1: return tpdkg_msg2_SIZE * ctx->n + sizeof(TP_DKG_Message);
  case 2: return tpdkg_msg4_SIZE * ctx->n;
  case 3: return tpdkg_msg5_SIZE * ctx->n;
  case 4: return sizeof(TP_DKG_Message) + (tpdkg_msg6_SIZE(ctx) * ctx->n);
  case 5: return ctx->n * tpdkg_msg8_SIZE;
  case 6: return tpdkg_msg10_SIZE(ctx);
  case 7: return 0;
  case 8: return 0;
  case 9: return tpdkg_msg20_SIZE;
  case 10: return 0;
  default: {
    if(log_file!=NULL) fprintf(log_file, "[%d] invalid step\n", ctx->index);
  }
  }
  return 1;
}

size_t tpdkg_peer_output_size(const TP_DKG_PeerState *ctx) {
  switch(ctx->step) {
  case 0: return tpdkg_msg2_SIZE+crypto_sign_BYTES;
  case 1: return tpdkg_msg4_SIZE * ctx->n;
  case 2: return tpdkg_msg5_SIZE * ctx->n;
  case 3: return tpdkg_msg6_SIZE(ctx);
  case 4: return ctx->n * tpdkg_msg8_SIZE;
  case 5: return tpdkg_msg9_SIZE(ctx);
  case 6: return 0;
  case 7: {
    if(ctx->complaints_len > 0) {
      if(ctx->my_complaints_len > 0) {
        return sizeof(TP_DKG_Message) + ctx->my_complaints_len * (1+tpdkg_noise_key_SIZE);
      }
      return 0;
    }
    return tpdkg_msg19_SIZE;
  }
  case 8: return tpdkg_msg19_SIZE;
  case 9: return tpdkg_msg21_SIZE;
  case 10: return 0;
  default: {
    if(log_file!=NULL) fprintf(log_file, "[%d] invalid step\n", ctx->index);
  }
  }
  return 1;
}

void tpdkg_peer_set_bufs(TP_DKG_PeerState *ctx,
                         uint8_t (*peers_sig_pks)[][crypto_sign_PUBLICKEYBYTES],
                         uint8_t (*peers_noise_pks)[][crypto_scalarmult_BYTES],
                         Noise_XK_session_t *(*noise_outs)[],
                         Noise_XK_session_t *(*noise_ins)[],
                         TOPRF_Share (*shares)[],
                         TOPRF_Share (*xshares)[],
                         uint8_t (*commitments)[][crypto_core_ristretto255_BYTES],
                         uint16_t (*complaints)[],
                         uint8_t (*my_complaints)[]) {
  ctx->peer_sig_pks = peers_sig_pks;
  ctx->peer_noise_pks = peers_noise_pks;
  ctx->noise_outs = noise_outs;
  ctx->noise_ins = noise_ins;
  ctx->shares = shares;
  ctx->xshares = xshares;
  ctx->commitments = commitments;
  ctx->complaints = complaints;
  ctx->my_complaints = my_complaints;
}

int tpdkg_tp_not_done(const TP_DKG_TPState *tp) {
  return tp->step<10;
}

int tpdkg_peer_not_done(const TP_DKG_PeerState *peer) {
  return peer->step<11;
}

void tpdkg_peer_free(TP_DKG_PeerState *ctx) {
  for(int i=0;i<ctx->n;i++) {
    if((*ctx->noise_ins)[i]!=NULL) Noise_XK_session_free((*ctx->noise_ins)[i]);
    if((*ctx->noise_outs)[i]!=NULL) Noise_XK_session_free((*ctx->noise_outs)[i]);
  }
  if(ctx->dev!=NULL) Noise_XK_device_free(ctx->dev);
}

void tpdkg_tp_set_bufs(TP_DKG_TPState *ctx,
                       uint8_t (*commitments)[][crypto_core_ristretto255_BYTES],
                       uint16_t (*complaints)[],
                       uint8_t (*encrypted_shares)[][tpdkg_msg8_SIZE],
                       TP_DKG_Cheater (*cheaters)[], const size_t cheater_max,
                       uint8_t (*tp_peers_sig_pks)[][crypto_sign_PUBLICKEYBYTES],
                       uint8_t (*peer_lt_pks)[][crypto_sign_PUBLICKEYBYTES]) {
  ctx->commitments = (uint8_t (*)[][crypto_core_ristretto255_BYTES]) commitments;
  ctx->complaints = complaints;
  ctx->encrypted_shares = encrypted_shares;
  ctx->cheaters = cheaters;
  memset(*cheaters, 0, cheater_max*sizeof(TP_DKG_Cheater));
  ctx->cheater_max = cheater_max;
  ctx->peer_sig_pks = tp_peers_sig_pks;
  ctx->peer_lt_pks = peer_lt_pks;
}

int tpdkg_start_tp(TP_DKG_TPState *ctx, const uint64_t ts_epsilon,
             const uint8_t n, const uint8_t t,
             const char *proto_name, const size_t proto_name_len,
             const size_t msg0_len, TP_DKG_Message *msg0) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[!] step 0. start protocol\e[0m\n");
  if(2>n || t>=n || n>128) return 1;
  if(proto_name_len<1) return 2;
  if(proto_name_len>1024) return 3;
  if(msg0_len != tpdkg_msg0_SIZE) return 4;

  ctx->last_ts=(uint64_t)time(NULL);
  ctx->ts_epsilon = ts_epsilon;
  ctx->step = 0;
  ctx->n = n;
  ctx->t = t;
  ctx->complaints_len = 0;
  ctx->cheater_len = 0;

  // dst hash(len(protoname) | "DKG for protocol " | protoname)
  crypto_generichash_state dst_state;
  crypto_generichash_init(&dst_state, NULL, 0, crypto_generichash_BYTES);
  uint16_t len=htons((uint16_t) proto_name_len+17); // we have a guard above restricting to 1KB the proto_name_len
  crypto_generichash_update(&dst_state, (uint8_t*) &len, 2);
  crypto_generichash_update(&dst_state, (uint8_t*) "DKG for protocol ", 17);
  crypto_generichash_update(&dst_state, (uint8_t*) proto_name, proto_name_len);
  uint8_t dst[crypto_generichash_BYTES];
  crypto_generichash_final(&dst_state,dst,sizeof dst);

  // set session id
  randombytes_buf(&ctx->sessionid, sizeof ctx->sessionid);

  // generate signing key for this session
  crypto_sign_keypair(ctx->sig_pk, ctx->sig_sk);

  // data = {tp_sign_pk, dst, sessionid, n, t}
  msg0->len=htonl(tpdkg_msg0_SIZE);
  msg0->msgno=0;
  msg0->from=0;
  msg0->to=0xff;
  msg0->ts=htonll((uint64_t)time(NULL));

  uint8_t *ptr = msg0->data;
  memcpy(ptr, ctx->sig_pk, sizeof ctx->sig_pk);
  ptr+=sizeof ctx->sig_pk;
  memcpy(ptr, dst, sizeof dst);
  ptr+=sizeof dst;
  memcpy(ptr, ctx->sessionid, sizeof ctx->sessionid);
  ptr+=sizeof ctx->sessionid;
  *ptr++ = n;
  *ptr++ = t;

  // sign messages
  crypto_sign_detached(msg0->sig, NULL, (uint8_t*) &msg0->msgno, msg0_len - crypto_sign_BYTES,ctx->sig_sk);
  //dump(msg0->sig, sizeof msg0->sig, "sig");
  //dump(&msg0->msgno, msg0_len - crypto_sign_BYTES, "msg");

  // init transcript
  crypto_generichash_init(&ctx->transcript, NULL, 0, crypto_generichash_BYTES);
  crypto_generichash_update(&ctx->transcript, (uint8_t*) "tp dkg session transcript", 25);
  // feed msg0 into transcript
  crypto_generichash_update(&ctx->transcript, (uint8_t*) msg0, msg0_len);

  if(log_file!=NULL) {
    fprintf(log_file,"[!] msgno: %d, from: %d to: 0x%x ", msg0->msgno, msg0->from, msg0->to);
    dump((uint8_t*) msg0, tpdkg_msg0_SIZE, "msg");
  }

  return 0;
}

int tpdkg_start_peer(TP_DKG_PeerState *ctx, const uint64_t ts_epsilon,
               const uint8_t peer_lt_sk[crypto_sign_SECRETKEYBYTES],
               const TP_DKG_Message *msg0) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[?] step 0.5 start peer\e[0m\n");

  if(log_file!=NULL) {
    fprintf(log_file,"[?] msgno: %d, from: %d to: 0x%x ", msg0->msgno, msg0->from, msg0->to);
    dump((uint8_t*) msg0, tpdkg_msg0_SIZE, "msg");
  }
#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
  if(0!=crypto_sign_verify_detached((uint8_t*) msg0->sig,
                                    &msg0->msgno,
                                    tpdkg_msg0_SIZE - crypto_sign_BYTES,
                                    msg0->data/*tp_sig_pk*/)) return 2;
#endif
  if(msg0->msgno!=0) return 3;
  if(ntohl(msg0->len)!=tpdkg_msg0_SIZE) return 4;
  if(msg0->from!=0) return 5;
  if(msg0->to!=0xff) return 6;
  ctx->last_ts=(uint64_t)time(NULL);
  if(0!=check_ts(ts_epsilon, &ctx->last_ts, ntohll(msg0->ts))) return 7;
  ctx->ts_epsilon = ts_epsilon;

  // extract data from message
  const uint8_t *ptr=msg0->data;
  memcpy(ctx->tp_sig_pk,ptr,sizeof ctx->tp_sig_pk);
  ptr+=sizeof ctx->tp_sig_pk + crypto_generichash_BYTES; // also skip DST
  memcpy(ctx->sessionid, ptr, sizeof ctx->sessionid);
  ptr+=sizeof ctx->sessionid;
  ctx->n = *ptr++;
  ctx->t = *ptr++;

  if(ctx->t < 2) return 8;
  if(ctx->t >= ctx->n) return 9;
  if(ctx->n > 128) return 10;

  ctx->complaints_len = 0;
  ctx->my_complaints_len = 0;
  memcpy(ctx->lt_sk, peer_lt_sk, crypto_sign_SECRETKEYBYTES);

  crypto_generichash_init(&ctx->transcript, NULL, 0, crypto_generichash_BYTES);
  crypto_generichash_update(&ctx->transcript, (uint8_t*) "tp dkg session transcript", 25);
  // feed msg0 into transcript
  crypto_generichash_update(&ctx->transcript, (uint8_t*) msg0, tpdkg_msg0_SIZE);

  ctx->dev = NULL;
  ctx->step = 0;

  return 0;
}

static int tp_step1_handler(TP_DKG_TPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[!] step 1. assign peer indices\e[0m\n");
  if(input_len!=0) return 1;
  if(output_len!=ctx->n * tpdkg_msg1_SIZE) return 2;

  uint8_t* ptr = output;
  for(uint8_t i=1;i<=ctx->n;i++) {
    if(0!=send_msg(ptr, sizeof(TP_DKG_Message), 1, 0, i, ctx->sig_sk, ctx->sessionid)) return 3;
    if(log_file!=NULL) {
      TP_DKG_Message *msg1 = (TP_DKG_Message*) ptr;
      fprintf(log_file,"[!] msgno: %d, len: %d, from: %d to: %x ", msg1->msgno, htonl(msg1->len), msg1->from, msg1->to);
      dump(ptr, tpdkg_msg1_SIZE, "msg");
    }
    ptr+=tpdkg_msg1_SIZE;
  }

  return 0;
}


static int peer_step23_handler(TP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[?] step 2. receive peers index\e[0m\n");
  if(input_len != tpdkg_msg1_SIZE) return 1;
  if(output_len != tpdkg_msg2_SIZE+crypto_sign_BYTES) return 2;

  TP_DKG_Message *msg1=(TP_DKG_Message*) input;
  if(log_file!=NULL) {
    fprintf(log_file,"[?] msgno: %d, len: %d, from: %d to: %x ", msg1->msgno, ntohl(msg1->len), msg1->from, msg1->to);
    dump(input, tpdkg_msg1_SIZE, "msg");
  }
  int ret = recv_msg(input, tpdkg_msg1_SIZE, 1, 0, msg1->to, ctx->tp_sig_pk, ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts);
  if(0!=ret) return 4 + ret;
  if(msg1->to > 128 || msg1->to < 1) return 3;
  ctx->index=msg1->to;

  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[%d] step 3. send msg2 containing ephemeral pubkey\e[0m\n", ctx->index);

  crypto_sign_keypair(ctx->sig_pk, ctx->sig_sk);

  randombytes_buf(ctx->noise_sk, sizeof ctx->noise_sk);
  crypto_scalarmult_base(ctx->noise_pk, ctx->noise_sk);

  uint8_t *wptr = ((TP_DKG_Message *) output)->data;
  memcpy(wptr, ctx->sig_pk, sizeof ctx->sig_pk);
  wptr+=sizeof ctx->sig_pk;
  memcpy(wptr, ctx->noise_pk, sizeof ctx->noise_pk);
  if(0!=send_msg(output, tpdkg_msg2_SIZE, 2, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return 4;
  // sign message with long-term key
  crypto_sign_detached(output+tpdkg_msg2_SIZE,NULL,output,tpdkg_msg2_SIZE,ctx->lt_sk);
  sodium_memzero(ctx->lt_sk,crypto_sign_SECRETKEYBYTES);

  if(log_file!=NULL) {
    TP_DKG_Message *msg2 = (TP_DKG_Message *) output;
    fprintf(log_file,"[%d] msgno: %d, len: %d, from: %d to: %x ", ctx->index, msg2->msgno, ntohl(msg2->len), msg2->from, msg2->to);
    dump(output, tpdkg_msg2_SIZE+crypto_sign_BYTES, "msg");
  }

  return 0;
}

static int tp_step4_handler(TP_DKG_TPState *ctx, const uint8_t *msg2s, const size_t msg2s_len, uint8_t *msg3_buf, const size_t msg3_buf_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[!] step 4. broadcast msg2 containing ephemeral pubkeys of peers\e[0m\n");
  if(((tpdkg_msg2_SIZE + crypto_sign_BYTES) * ctx->n) != msg2s_len) return 1;
  if(msg3_buf_len != (tpdkg_msg2_SIZE * ctx->n) + sizeof(TP_DKG_Message)) return 2;

  const uint8_t *ptr = msg2s;
  uint8_t *wptr = ((TP_DKG_Message *) msg3_buf)->data;
  for(uint8_t i=0;i<ctx->n;i++) {
    const TP_DKG_Message* msg = (const TP_DKG_Message*) ptr;
    // verify long-term pk sig on initial message
    if(log_file!=NULL) {
      fprintf(log_file,"[!] msgno: %d, from: %d to: %x ", msg->msgno, msg->from, msg->to);
      dump(ptr, tpdkg_msg2_SIZE, "msg");
    }
#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    if(0!=crypto_sign_verify_detached(ptr+tpdkg_msg2_SIZE,ptr,tpdkg_msg2_SIZE,(*ctx->peer_lt_pks)[i])) return 3;
#endif
    if(0!=recv_msg(ptr, tpdkg_msg2_SIZE, 2, i+1, 0xff, msg->data, ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts)) return 4;

    // keep copy of ephemeral signing key
    memcpy((*ctx->peer_sig_pks)[i], msg->data, crypto_sign_PUBLICKEYBYTES);
    // strip away long-term signature
    memcpy(wptr, ptr, tpdkg_msg2_SIZE);
    wptr+=tpdkg_msg2_SIZE;

    ptr+=tpdkg_msg2_SIZE+crypto_sign_BYTES;
  }
  if(0!=send_msg(msg3_buf, msg3_buf_len, 3, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return 5;;

  crypto_generichash_update(&ctx->transcript, (uint8_t*) msg3_buf, msg3_buf_len);

  return 0;
}

static int peer_step5_handler(TP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[%d] step 5. receive peers ephemeral pubkeys, start noise sessions\e[0m\n", ctx->index);
  if(input_len != tpdkg_msg2_SIZE * ctx->n + sizeof(TP_DKG_Message)) return 1;
  if(output_len != tpdkg_msg4_SIZE * ctx->n) return 2;

  uint64_t last_ts = ctx->last_ts;
  if(0!=recv_msg(input, input_len, 3, 0, 0xff, ctx->tp_sig_pk, ctx->sessionid, ctx->ts_epsilon, &last_ts)) return 3;

  crypto_generichash_update(&ctx->transcript, input, input_len);

  // create noise device
  uint8_t iname[12];
  snprintf((char*) iname, sizeof iname, "dkg peer %02x", ctx->index);
  uint8_t dummy[32]={0}; // the following function needs a deserialization key, which we never use.

  ctx->dev = Noise_XK_device_create(13, (uint8_t*) "dpkg p2p v0.1", iname, dummy, ctx->noise_sk);

  TP_DKG_Message* msg3 = (TP_DKG_Message*) input;
  const uint8_t *ptr = msg3->data;
  uint8_t *wptr = output;
  for(uint8_t i=0;i<ctx->n;i++) {
    TP_DKG_Message* msg2 = (TP_DKG_Message*) ptr;
    if(log_file!=NULL) {
      fprintf(log_file,"[%d] msgno: %d, from: %d to: %x ", ctx->index, msg2->msgno, msg2->from, msg2->to);
      dump(ptr, tpdkg_msg2_SIZE, "msg");
    }
    if(0!=recv_msg(ptr, tpdkg_msg2_SIZE, 2, i+1, 0xff, msg2->data, ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts)) return 4;
    // extract peer sig and noise pk
    memcpy((*ctx->peer_sig_pks)[i], msg2->data, crypto_sign_PUBLICKEYBYTES);
    memcpy((*ctx->peer_noise_pks)[i], msg2->data + crypto_sign_PUBLICKEYBYTES, crypto_scalarmult_BYTES);
    ptr+=tpdkg_msg2_SIZE;

    TP_DKG_Message *msg4 = (TP_DKG_Message *) wptr;
    uint8_t rname[12];
    snprintf((char*) rname, sizeof rname, "dkg peer %02x", i+1);
    tpdkg_init_noise_handshake(ctx, (*ctx->peer_noise_pks)[i], rname, &(*ctx->noise_outs)[i], msg4->data);
    if(0!=send_msg(wptr, tpdkg_msg4_SIZE, 4, ctx->index, i+1, ctx->sig_sk, ctx->sessionid)) return 5;
    if(log_file!=NULL) {
      fprintf(log_file,"[%d] msgno: %d, from: %d to: %d ", ctx->index, msg4->msgno, msg4->from, msg4->to);
      dump(wptr, tpdkg_msg4_SIZE, "msg");
    }
    wptr+=tpdkg_msg4_SIZE;
  }

  return 0;
}

static int tp_step68_handler(TP_DKG_TPState *ctx, const uint8_t *msg4s, const size_t msg4s_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[!] step %d. route p2p noise handshakes to peers\e[0m\n", 6 + (ctx->step - 1) * 2);
  if(msg4s_len != tpdkg_msg4_SIZE * ctx->n * ctx->n) return 1;
  if(msg4s_len != output_len) return 2;

  uint8_t (*inputs)[ctx->n][ctx->n][tpdkg_msg4_SIZE] = (uint8_t (*)[ctx->n][ctx->n][tpdkg_msg4_SIZE]) msg4s;
  uint8_t *wptr = output;
  for(uint8_t i=0;i<ctx->n;i++) {
    for(uint8_t j=0;j<ctx->n;j++) {
      if(tpdkg_msg4_SIZE != tpdkg_msg5_SIZE) {
        if(log_file!=NULL) fprintf(log_file, "tpdkg_msg4_SIZE must be equal tpdkg_msg5_SIZE for the check to be correct in tp_step68_handler\n");
        return 3;
      }
      uint64_t last_ts= ctx->last_ts;
      int ret = recv_msg((*inputs)[j][i], tpdkg_msg4_SIZE, (uint8_t) (2+ctx->step), j+1, i+1, (*ctx->peer_sig_pks)[j], ctx->sessionid, ctx->ts_epsilon, &last_ts);
      if(0!=ret) {
        TP_DKG_Message *msg = (TP_DKG_Message*) (*inputs)[j][i];
        fprintf(log_file,"[x] msgno: %d, from: %d to: %d ", msg->msgno, msg->from, msg->to);
        dump((*inputs)[j][i], tpdkg_msg4_SIZE, "msg");
        return 4+ret;
      }
      memcpy(wptr, (*inputs)[j][i], tpdkg_msg4_SIZE);
      wptr+=tpdkg_msg4_SIZE;
    }
  }

  return 0;
}

static int peer_step7_handler(TP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[%d] step 7. receive session requests\e[0m\n", ctx->index);
  if(input_len != tpdkg_msg4_SIZE * ctx->n) return 1;
  if(output_len != tpdkg_msg5_SIZE * ctx->n) return 2;

  const uint8_t *ptr = input;
  uint8_t *wptr = output;
  for(uint8_t i=0;i<ctx->n;i++) {
    TP_DKG_Message* msg4 = (TP_DKG_Message*) ptr;
    if(log_file!=NULL) {
      fprintf(log_file,"[%d] msgno: %d, from: %d to: %d ", ctx->index, msg4->msgno, msg4->from, msg4->to);
      dump(ptr, tpdkg_msg4_SIZE, "msg");
    }
    int ret = recv_msg(ptr, tpdkg_msg4_SIZE, 4, i+1, ctx->index, (*ctx->peer_sig_pks)[i], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts);
    if(0!=ret) return 3;
    ptr+=tpdkg_msg4_SIZE;

    // respond to noise handshake request
    TP_DKG_Message *msg5 = (TP_DKG_Message *) wptr;
    uint8_t rname[12];
    snprintf((char*) rname, sizeof rname, "dkg peer %02x", i+1);
    tpdkg_respond_noise_handshake(ctx, (*ctx->peer_noise_pks)[i], rname, &(*ctx->noise_ins)[i], msg4->data, msg5->data);
    if(0!=send_msg(wptr, tpdkg_msg5_SIZE, 5, ctx->index, i+1, ctx->sig_sk, ctx->sessionid)) return 4;
    if(log_file!=NULL) {
      fprintf(log_file,"[%d] msgno: %d, from: %d to: %d ", ctx->index, msg5->msgno, msg5->from, msg5->to);
      dump(wptr, tpdkg_msg5_SIZE, "msg");
    }
    wptr+=tpdkg_msg5_SIZE;
  }

  return 0;
}

static int peer_step911_handler(TP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[%d] step 9-11 finish session handshake, broadcast commitments\e[0m\n", ctx->index);
  if(input_len != tpdkg_msg5_SIZE * ctx->n) return 1;
  if(output_len != tpdkg_msg6_SIZE(ctx)) return 2;

  const uint8_t *ptr = input;
  for(uint8_t i=0;i<ctx->n;i++) {
    TP_DKG_Message* msg5 = (TP_DKG_Message*) ptr;
    if(log_file!=NULL) {
      fprintf(log_file,"[%d] msgno: %d, from: %d to: %d ", ctx->index, msg5->msgno, msg5->from, msg5->to);
      dump(ptr, tpdkg_msg5_SIZE, "msg");
    }
    int ret = recv_msg(ptr, tpdkg_msg5_SIZE, 5, i+1, ctx->index, (*ctx->peer_sig_pks)[i], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts);
    if(0!=ret) return 3;
    ptr+=tpdkg_msg5_SIZE;
    // process final step of noise handshake
    tpdkg_finish_noise_handshake(ctx, &(*ctx->noise_outs)[i], msg5->data);
  }

  TP_DKG_Message* msg6 = (TP_DKG_Message*) output;
  if(0!=dkg_start(ctx->n, ctx->t, (uint8_t (*)[32]) msg6->data, *ctx->shares)) return 4;
  if(0!=send_msg(output, tpdkg_msg6_SIZE(ctx), 6, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return 4;
  if(log_file!=NULL) {
    fprintf(log_file,"[%d] msgno: %d, from: %d to: 0x%x ", ctx->index, msg6->msgno, msg6->from, msg6->to);
    dump(output, tpdkg_msg6_SIZE(ctx), "msg");
    dump(msg6->data, ctx->t*crypto_core_ristretto255_BYTES, "[%d] commitments", ctx->index);
  }

  return 0;
}

static int tp_step12_handler(TP_DKG_TPState *ctx, const uint8_t *msg6s, const size_t msg6s_len, uint8_t *msg7_buf, const size_t msg7_buf_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[!] step 12. broadcast commitments of peers\e[0m\n");

  if((tpdkg_msg6_SIZE(ctx) * ctx->n) != msg6s_len) return 1;
  if(msg7_buf_len != sizeof(TP_DKG_Message) + msg6s_len) return 2;
  const uint8_t *ptr = msg6s;
  uint8_t *wptr = ((TP_DKG_Message *) msg7_buf)->data;
  for(uint8_t i=0;i<ctx->n;i++) {
    const TP_DKG_Message* msg = (const TP_DKG_Message*) ptr;
    if(log_file!=NULL) {
      fprintf(log_file,"[!] msgno: %d, from: %d to: 0x%x ", msg->msgno, msg->from, msg->to);
      dump(ptr, tpdkg_msg6_SIZE(ctx), "msg");
    }
    if(0!=recv_msg(ptr, tpdkg_msg6_SIZE(ctx), 6, i+1, 0xff, (*ctx->peer_sig_pks)[i], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts)) return 3;

    memcpy((*ctx->commitments)[i*ctx->t], msg->data, crypto_core_ristretto255_BYTES * ctx->t);
    if(log_file!=NULL) {
      dump((*ctx->commitments)[i*ctx->t], crypto_core_ristretto255_BYTES * ctx->t, "[!] commitments[%d]", i+1);
    }

    memcpy(wptr, ptr, tpdkg_msg6_SIZE(ctx));
    wptr+=tpdkg_msg6_SIZE(ctx);
    ptr+=tpdkg_msg6_SIZE(ctx);
  }
  if(0!=send_msg(msg7_buf, msg7_buf_len, 7, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return 4;
  TP_DKG_Message* msg7 = (TP_DKG_Message*) msg7_buf;
  if(log_file!=NULL) {
    fprintf(log_file,"[!] msgno: %d, from: %d to: %x ", msg7->msgno, msg7->from, msg7->to);
    dump(msg7_buf, msg7_buf_len, "msg");
  }

  // add broadcast msg to transcript
  crypto_generichash_update(&ctx->transcript, (uint8_t*) msg7_buf, msg7_buf_len);

  return 0;
}

static int peer_step13_handler(TP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[%d] step 13. receive commitments, distribute shares via noise chans\e[0m\n", ctx->index);
  if(input_len != sizeof(TP_DKG_Message) + (tpdkg_msg6_SIZE(ctx) * ctx->n)) return 1;
  if(output_len != ctx->n * tpdkg_msg8_SIZE) return 2;

  // verify TP message envelope
  TP_DKG_Message* msg7 = (TP_DKG_Message*) input;
  if(log_file!=NULL) {
    fprintf(log_file,"[%d] msgno: %d, from: %d to: %x ", ctx->index, msg7->msgno, msg7->from, msg7->to);
    dump(input, input_len, "msg");
  }
  uint64_t last_ts = ctx->last_ts;
  if(0!=recv_msg(input, input_len, 7, 0, 0xff, ctx->tp_sig_pk, ctx->sessionid, ctx->ts_epsilon, &last_ts)) return 3;

  // add broadcast msg to transcript
  crypto_generichash_update(&ctx->transcript, input, input_len);

  const uint8_t *ptr = msg7->data;
  uint8_t *wptr = output;
  for(uint8_t i=0;i<ctx->n;i++, wptr+=tpdkg_msg8_SIZE,ptr+=tpdkg_msg6_SIZE(ctx)) {
    TP_DKG_Message* msg6 = (TP_DKG_Message*) ptr;
    if(log_file!=NULL) {
      fprintf(log_file,"[%d] msgno: %d, from: %d to: 0x%x ", ctx->index, msg6->msgno, msg6->from, msg6->to);
      dump(ptr, tpdkg_msg6_SIZE(ctx), "msg");
    }
    if(0!=recv_msg(ptr, tpdkg_msg6_SIZE(ctx), 6, i+1, 0xff, (*ctx->peer_sig_pks)[i], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts)) return 4;
    // extract peer commitments
    memcpy((*ctx->commitments)[i*ctx->t], msg6->data, crypto_core_ristretto255_BYTES * ctx->t);

    TP_DKG_Message *msg8 = (TP_DKG_Message *) wptr;

    // we need to send an empty packet, so that the handshake completes
    // and we have a final symetric key, the key during the handshake changes, only
    // when the handshake completes does the key become static.
    // this is important, so that when there are complaints, we can disclose the key.
    uint8_t empty[0];
    if(0!=tpdkg_noise_encrypt(empty, 0, msg8->data, noise_xk_handshake3_SIZE, &(*ctx->noise_outs)[i])) return 5;

#ifdef UNITTEST
    // corrupt all shares
    static int corrupted_shares = 0;
    uint8_t corrupted_share[sizeof(TOPRF_Share)];
    memcpy(corrupted_share, &(*ctx->shares)[i], sizeof(TOPRF_Share));
    if(i+1 != ctx->index && corrupted_shares++<ctx->t) {
      dump(corrupted_share, sizeof(TOPRF_Share), "[%d] corrupting share_%d", ctx->index, i+1);
      corrupted_share[2]^=0xff; // flip some bits
      dump(corrupted_share, sizeof(TOPRF_Share), "[%d] corrupted share_%d ", ctx->index, i+1);
    }
    if(0!=tpdkg_noise_encrypt((uint8_t*) corrupted_share, sizeof(TOPRF_Share),
#else
    if(0!=tpdkg_noise_encrypt((uint8_t*) &(*ctx->shares)[i], sizeof(TOPRF_Share),
#endif // UNITTEST
                              msg8->data + noise_xk_handshake3_SIZE, sizeof(TOPRF_Share) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                              &(*ctx->noise_outs)[i])) return 6;

    // we also need to use a key-commiting mac over the encrypted share, since poly1305 is not...
    crypto_auth(msg8->data + noise_xk_handshake3_SIZE + sizeof(TOPRF_Share) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                msg8->data + noise_xk_handshake3_SIZE,
                sizeof(TOPRF_Share) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                Noise_XK_session_get_key((*ctx->noise_outs)[i]));

    if(0!=send_msg(wptr, tpdkg_msg8_SIZE, 8, ctx->index, i+1, ctx->sig_sk, ctx->sessionid)) return 7;
    if(log_file!=NULL) {
      fprintf(log_file,"[%d] msgno: %d, from: %d to: %d ", ctx->index, msg8->msgno, msg8->from, msg8->to);
      dump(wptr, tpdkg_msg8_SIZE, "msg");
    }
  }

  return 0;
}

static int tp_step14_handler(TP_DKG_TPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[!] step 14. route shares from all peers to all peers\e[0m\n");
  if(input_len != tpdkg_msg8_SIZE * ctx->n * ctx->n) return 1;
  if(input_len != output_len) return 2;

  uint8_t (*inputs)[ctx->n][ctx->n][tpdkg_msg8_SIZE] = (uint8_t (*)[ctx->n][ctx->n][tpdkg_msg8_SIZE]) input;
  uint8_t *wptr = output;
  for(uint8_t i=0;i<ctx->n;i++) {
    for(uint8_t j=0;j<ctx->n;j++) {
      TP_DKG_Message *msg8 = (TP_DKG_Message *) (*inputs)[j][i];
      if(log_file!=NULL) {
        fprintf(log_file,"[!] msgno: %d, from: %d to: %d ", msg8->msgno, msg8->from, msg8->to);
        dump((*inputs)[j][i], tpdkg_msg8_SIZE, "msg");
      }
      uint64_t last_ts = ctx->last_ts;
      int ret = recv_msg((*inputs)[j][i], tpdkg_msg8_SIZE, 8, j+1, i+1, (*ctx->peer_sig_pks)[j], ctx->sessionid, ctx->ts_epsilon, &last_ts);
      if(0!=ret) return 32+ret;

      memcpy(wptr, (*inputs)[j][i], tpdkg_msg8_SIZE);
      wptr+=tpdkg_msg8_SIZE;
    }
  }

  // keep a copy for complaint resolution.
  memcpy((*ctx->encrypted_shares), input, input_len);

  return 0;
}

static int peer_step15_handler(TP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[%d] step 15. DKG step 2 - receive shares, verify commitments\e[0m\n", ctx->index);
  if(input_len != ctx->n * tpdkg_msg8_SIZE) return 1;
  if(output_len != tpdkg_msg9_SIZE(ctx)) return 2;

  const uint8_t *ptr = input;
  for(uint8_t i=0;i<ctx->n;i++) {
    TP_DKG_Message* msg8 = (TP_DKG_Message*) ptr;
    if(log_file!=NULL) {
      fprintf(log_file,"[%d] msgno: %d, from: %d to: %d ", ctx->index, msg8->msgno, msg8->from, msg8->to);
      dump(ptr, tpdkg_msg8_SIZE, "msg");
    }
    int ret = recv_msg(ptr, tpdkg_msg8_SIZE, 8, i+1, ctx->index, (*ctx->peer_sig_pks)[i], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts);
    if(0!=ret) return 3;

    // decrypt final empty handshake packet
    if(0!=tpdkg_noise_decrypt(msg8->data, noise_xk_handshake3_SIZE, NULL, 0, &(*ctx->noise_ins)[i])) return 4;

    if(0!=crypto_auth_verify(msg8->data + noise_xk_handshake3_SIZE + sizeof(TOPRF_Share) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                             msg8->data + noise_xk_handshake3_SIZE,
                             sizeof(TOPRF_Share) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                             Noise_XK_session_get_key((*ctx->noise_ins)[i]))) {
      return 5;
    }

    if(0!=tpdkg_noise_decrypt(msg8->data + noise_xk_handshake3_SIZE, sizeof(TOPRF_Share) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                              (uint8_t*) &(*ctx->xshares)[i], sizeof(TOPRF_Share),
                              &(*ctx->noise_ins)[i])) return 6;

    ptr+=tpdkg_msg8_SIZE;
  }

  TP_DKG_Message* msg9 = (TP_DKG_Message*) output;
  uint8_t *fails_len = msg9->data;
  uint8_t *fails = msg9->data+1;
  memset(fails, 0, ctx->n);
  dkg_verify_commitments(ctx->n, ctx->t, ctx->index, ctx->commitments, *ctx->xshares, fails, fails_len);

#ifdef UNITTEST
  static int totalfails = 0;
  for(int i=1;i<=ctx->n;i++) {
    if(totalfails < ctx->t*ctx->t && *fails_len < ctx->t-1 && i != ctx->index) {
      // avoid duplicates
      int j;
      for(j=1;j<=msg9->data[0];j++) if(msg9->data[j]==i) break;
      if(j<=msg9->data[0]) continue;

      fails[msg9->data[0]++]=i;
      totalfails++;
    }
  }
#endif //UNITTEST

  if(log_file!=NULL) {
    for(int j=0;j<*fails_len;j++) {
      fprintf(log_file,"\e[0;31m[%d] failed to verify commitments from %d!\e[0m\n", ctx->index, fails[j]);
    }
  }

  if(0!=send_msg(output, tpdkg_msg9_SIZE(ctx), 9, ctx->index, 0xff, ctx->sig_sk, ctx->sessionid)) return 7;
  if(log_file!=NULL) {
    fprintf(log_file,"[%d] msgno: %d, from: %d to: %x ", ctx->index, msg9->msgno, msg9->from, msg9->to);
    dump(output, tpdkg_msg9_SIZE(ctx), "msg");
  }

  return 0;
}

static int tp_step16_handler(TP_DKG_TPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[!] step 16. broadcast complaints of peers\e[0m\n");

  if((tpdkg_msg9_SIZE(ctx) * ctx->n) != input_len) return 1;
  if(output_len != tpdkg_msg10_SIZE(ctx)) return 2;

  ctx->complaints_len = 0;

  const uint8_t *ptr = input;
  uint8_t *wptr = ((TP_DKG_Message *) output)->data;
  for(uint8_t i=0;i<ctx->n;i++) {
    const TP_DKG_Message* msg = (const TP_DKG_Message*) ptr;
    if(log_file!=NULL) {
      fprintf(log_file,"[!] msgno: %d, from: %d to: 0x%x ", msg->msgno, msg->from, msg->to);
      dump(ptr, tpdkg_msg9_SIZE(ctx), "msg");
    }
    if(0!=recv_msg(ptr, tpdkg_msg9_SIZE(ctx), 9, i+1, 0xff, (*ctx->peer_sig_pks)[i], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts)) return 3;
    if(msg->len - sizeof(TP_DKG_Message) < msg->data[0]) return 4;

    // keep a copy all complaint pairs (complainer, complained)
    for(int k=0;k<msg->data[0] && (k+1)<msg->len-sizeof(TP_DKG_Message);k++) {
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

    memcpy(wptr, ptr, tpdkg_msg9_SIZE(ctx));
    wptr+=tpdkg_msg9_SIZE(ctx);
    ptr+=tpdkg_msg9_SIZE(ctx);
  }
  dump((uint8_t*) (*ctx->complaints), ctx->complaints_len*sizeof(uint16_t), "[!] complaints");

  // if more than t^2 complaints are received the protocol also fails
  if(ctx->complaints_len >= ctx->t * ctx->t) {
    if(add_cheater(ctx, 16, 6, 0xfe, 0xfe) == NULL) return 6;
    return 5;
  }

  if(ctx->cheater_len>0) return 5;

  if(0!=send_msg(output, output_len, 10, 0, 0xff, ctx->sig_sk, ctx->sessionid)) return 7;
  TP_DKG_Message* msg10 = (TP_DKG_Message*) output;
  if(log_file!=NULL) {
    fprintf(log_file,"[!] msgno: %d, from: %d to: %x ", msg10->msgno, msg10->from, msg10->to);
    dump(output, output_len, "msg");
  }

  // add broadcast msg to transcript
  crypto_generichash_update(&ctx->transcript, (uint8_t*) output, output_len);

  return 0;
}

static int peer_step17_handler(TP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[%d] step 17. receive complaints broadcast\e[0m\n", ctx->index);
  if(input_len != tpdkg_msg10_SIZE(ctx)) return 1;
  if(output_len !=0) return 2;

  // verify TP message envelope
  TP_DKG_Message* msg10 = (TP_DKG_Message*) input;
  if(log_file!=NULL) {
    fprintf(log_file,"[%d] msgno: %d, from: %d to: %x ", ctx->index, msg10->msgno, msg10->from, msg10->to);
    dump(input, input_len, "msg");
  }

  uint64_t last_ts = ctx->last_ts;
  int ret = recv_msg(input, input_len, 10, 0, 0xff, ctx->tp_sig_pk, ctx->sessionid, ctx->ts_epsilon, &last_ts);
  if(0!=ret) return 16+ret;

  // add broadcast msg to transcript
  crypto_generichash_update(&ctx->transcript, input, input_len);

  const uint8_t *ptr = msg10->data;
  for(uint8_t i=0;i<ctx->n;i++) {
    TP_DKG_Message* msg9 = (TP_DKG_Message*) ptr;
    if(log_file!=NULL) {
      fprintf(log_file,"[%d] msgno: %d, from: %d to: 0x%x ", ctx->index, msg9->msgno, msg9->from, msg9->to);
      dump(ptr, tpdkg_msg9_SIZE(ctx), "msg");
    }
    ret = recv_msg(ptr, tpdkg_msg9_SIZE(ctx), 9, i+1, 0xff, (*ctx->peer_sig_pks)[i], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts);
    if(0!=ret) return 32+ret;
    if(msg9->len - sizeof(TP_DKG_Message) < msg9->data[0]) return 5;

    // keep a copy all complaint pairs (complainer, complained)
    for(int k=0;k<msg9->data[0] && (k+1)<msg9->len-sizeof(TP_DKG_Message);k++) {
      uint16_t pair=(uint16_t) (((i+1)<<8) | msg9->data[k+1]);
      int j=0;
      for(j=0;j<ctx->complaints_len;j++) if((*ctx->complaints)[j]==pair) break;
      if(j<ctx->complaints_len) continue;
      (*ctx->complaints)[ctx->complaints_len++] = pair;

      if(msg9->data[k+1] == ctx->index) {
        (*ctx->my_complaints)[ctx->my_complaints_len++] = i+1;
        if(log_file!=NULL) fprintf(log_file,"\e[0;31m[%d] peer %d failed to verify commitments from peer %d!\e[0m\n", ctx->index, i+1, msg9->data[1+k]);
      }
    }

    ptr+=tpdkg_msg9_SIZE(ctx);
  }

  if(ctx->complaints_len == 0) {
    ctx->prev = ctx->step;
    ctx->step+=1; // skip to step 19
  }

  return 0;
}

static int peer_step17a_handler(TP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[%d] step 17a. potentially broadcast contested shares\e[0m\n", ctx->index);
  if(input_len != 0) return 1;
  if(output_len != tpdkg_peer_output_size(ctx)) return 2;
  if(output_len == 0) {
    if(log_file!=NULL) {
      fprintf(log_file,"[%d] nothing to defend against, no message to send\n", ctx->index);
    }
    return 0;
  }

  // send out all shares that belong to peers that complained.
  TP_DKG_Message* msg11 = (TP_DKG_Message*) output;
  uint8_t *wptr = msg11->data;
  for(int i=0;i<ctx->my_complaints_len;i++) {
    if(log_file!=NULL) fprintf(log_file, "\e[0;36m[%d] defending against complaint from %d\e[0m\n", ctx->index, (*ctx->my_complaints)[i]);

    *wptr++ = (*ctx->my_complaints)[i];
    // reveal key for noise wrapped share sent previously
    memcpy(wptr, Noise_XK_session_get_key((*ctx->noise_outs)[(*ctx->my_complaints)[i]-1]), tpdkg_noise_key_SIZE);
    wptr+=tpdkg_noise_key_SIZE;
  }

  if(0!=send_msg(output, tpdkg_peer_output_size(ctx), 11, ctx->index, 0x0, ctx->sig_sk, ctx->sessionid)) return 3;
  if(log_file!=NULL) {
    fprintf(log_file,"[%d] msgno: %d, from: %d to: %x ", ctx->index, msg11->msgno, msg11->from, msg11->to);
    dump(output, tpdkg_peer_output_size(ctx), "msg");
  }

  // we skip to the end...
  ctx->step=99;

  return 0;
}

static int tp_step18_handler(TP_DKG_TPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[!] step 18. collect keys of contested shares and verify the commitments\e[0m\n");
  if(input_len != tpdkg_tp_input_size(ctx)) return 1;
  if(output_len != 0) return 2;

  unsigned int ctr[ctx->n];
  uint16_t complaints[ctx->complaints_len];
  memset(ctr,0,sizeof(ctr));
  for(int i=0;i<ctx->complaints_len;i++) {
    ctr[((*ctx->complaints)[i] & 0xff)-1]++;
    complaints[i] = (*ctx->complaints)[i];
  }

  uint8_t (*noisy_shares)[ctx->n][ctx->n][tpdkg_msg8_SIZE] = (uint8_t (*)[ctx->n][ctx->n][tpdkg_msg8_SIZE]) ctx->encrypted_shares;

  const uint8_t *ptr = input;
  size_t msg_len;
  for(uint8_t i=0;i<ctx->n;i++,ptr += msg_len) {
    if(ctr[i]==0) {
      msg_len = 0;
      continue; // no complaints against this peer
    }
    msg_len = sizeof(TP_DKG_Message) + (1+tpdkg_noise_key_SIZE) * ctr[i];

    const TP_DKG_Message* msg = (const TP_DKG_Message*) ptr;
    if(log_file!=NULL) {
      fprintf(log_file,"[!] msgno: %d, from: %d to: 0x%x ", msg->msgno, msg->from, msg->to);
      dump(ptr, msg_len, "msg");
    }
    int ret = recv_msg(ptr, msg_len, 11, i+1, 0, (*ctx->peer_sig_pks)[i], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts);
    if(0!=ret) {
      if(add_cheater(ctx, 18, 32+ret, i+1, 0xfe) == NULL) return 4;
      continue;
    }

    // verify proofs
    const uint8_t *keyptr = msg->data;
    for(int k=0;k<ctr[i];k++,keyptr+=tpdkg_noise_key_SIZE) {
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

      uint8_t *msg8_ptr = (*noisy_shares)[accused-1][complainer-1];
      const TP_DKG_Message *msg8 = (const TP_DKG_Message *) msg8_ptr;
      if(log_file!=NULL) {
        fprintf(log_file,"[!] msgno: %d, from: %d to: %d ", msg8->msgno, msg8->from, msg8->to);
        dump(msg8_ptr, tpdkg_msg8_SIZE, "msg");
      }
      uint64_t last_ts = ntohll(msg8->ts)-1; // ignore freshness
      ret = recv_msg(msg8_ptr, tpdkg_msg8_SIZE, 8,
                     accused, complainer,
                     (*ctx->peer_sig_pks)[accused-1], ctx->sessionid, ctx->ts_epsilon, &last_ts);
      if(0!=ret) {
        // key reveal msg_recv failure
        if(add_cheater(ctx, 18, 16+ret, accused, complainer) == NULL) return 4;
        continue;
      }
#ifdef UNITTEST
      dump(keyptr, tpdkg_noise_key_SIZE, "[!] key_%d,%d", accused, complainer);
#endif //UNITTEST

      // verify key committing hmac first!
#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
      if(0!=crypto_auth_verify(msg8->data + noise_xk_handshake3_SIZE + sizeof(TOPRF_Share) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                               msg8->data + noise_xk_handshake3_SIZE,
                               sizeof(TOPRF_Share) + crypto_secretbox_xchacha20poly1305_MACBYTES,
                               keyptr)) {
        // failed to verify KC MAC on message
        if(add_cheater(ctx, 18, 3, accused, complainer) == NULL) return 4;
        continue;
      }
#endif

      Noise_XK_error_code
        res0 = Noise_XK_aead_decrypt((uint8_t*)keyptr, 0, (uint32_t)0U, NULL, sizeof(share), (uint8_t*) &share, (uint8_t*) msg8->data + noise_xk_handshake3_SIZE);
      if (!(res0 == Noise_XK_CSuccess)) {
        // share decryption failure
        if(add_cheater(ctx, 18, 4, accused, complainer) == NULL) return 4;
        continue;
      }

      if(share.index != complainer) {
        // invalid share index
        TP_DKG_Cheater *cheater = add_cheater(ctx, 18, 5, accused, complainer);
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

static int peer_step19_handler(TP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "[%d] step 19. send final transcript\n", ctx->index);
  if(input_len != 0) return 1;
  if(output_len != tpdkg_msg19_SIZE) return 2;

  TP_DKG_Message* msg20 = (TP_DKG_Message*) output;
  crypto_generichash_final(&ctx->transcript, msg20->data, crypto_generichash_BYTES);
  if(0!=send_msg(output, tpdkg_msg19_SIZE, 20, ctx->index, 0, ctx->sig_sk, ctx->sessionid)) return 3;
  if(log_file!=NULL) {
    fprintf(log_file,"[%d] msgno: %d, from: %d to: %d ", ctx->index, msg20->msgno, msg20->from, msg20->to);
    dump(output, tpdkg_msg19_SIZE, "msg");
  }

  return 0;
}

static int tp_step20_handler(TP_DKG_TPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[!] step 20. collect and verify transcripts\e[0m\n");

  if((tpdkg_msg19_SIZE * ctx->n) != input_len) return 1;
  if(output_len != tpdkg_msg20_SIZE) return 2;

  uint8_t transcript_hash[crypto_generichash_BYTES];
  crypto_generichash_final(&ctx->transcript, transcript_hash, crypto_generichash_BYTES);

  uint8_t *wptr = ((TP_DKG_Message *) output)->data;
  memcpy(wptr, "OK", 2);
  const uint8_t *ptr = input;
  for(uint8_t i=0;i<ctx->n;i++, ptr+=tpdkg_msg19_SIZE) {
    const TP_DKG_Message* msg = (const TP_DKG_Message*) ptr;
    if(log_file!=NULL) {
      fprintf(log_file,"[!] msgno: %d, from: %d to: %d ", msg->msgno, msg->from, msg->to);
      dump(ptr, tpdkg_msg19_SIZE, "msg");
    }
    int ret = recv_msg(ptr, tpdkg_msg19_SIZE, 20, i+1, 0, (*ctx->peer_sig_pks)[i], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts);
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
  TP_DKG_Message* msg21 = (TP_DKG_Message*) output;
  if(log_file!=NULL) {
    fprintf(log_file,"[!] msgno: %d, from: %d to: %x ", msg21->msgno, msg21->from, msg21->to);
    dump(output, output_len, "msg");
  }
  if(ctx->cheater_len == 0) return 0;

  ctx->step = 99; // we finish here
  return 3;
}

static int peer_step21_handler(TP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[%d] step 21. get final approval\e[0m\n", ctx->index);
  if(input_len != tpdkg_msg20_SIZE) return 1;
  if(output_len != tpdkg_msg21_SIZE) return 2;

  // verify TP message envelope
  TP_DKG_Message* msg21 = (TP_DKG_Message*) input;
  if(log_file!=NULL) {
    fprintf(log_file,"[%d] msgno: %d, from: %d to: 0x%x ", ctx->index, msg21->msgno, msg21->from, msg21->to);
    dump(input, input_len, "msg");
  }
  int ret = recv_msg(input, input_len, 21, 0, 0xff, ctx->tp_sig_pk, ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts);
  if(0!=ret) return 4+ret;

  int fail = (memcmp(msg21->data, "OK", 2) != 0);
  if(!fail) {
    ctx->share.index=ctx->index;
    dkg_finish(ctx->n,*ctx->xshares,ctx->index,&ctx->share);

    TP_DKG_Message* msg22 = (TP_DKG_Message*) output;
    memcpy(msg22->data, msg21->data, 2);
    if(0!=send_msg(output, tpdkg_msg21_SIZE, 22, ctx->index, 0, ctx->sig_sk, ctx->sessionid)) return 3;
    if(log_file!=NULL) {
        fprintf(log_file,"[%d] msgno: %d, from: %d to: %d ", ctx->index, msg22->msgno, msg22->from, msg22->to);
        dump(output, tpdkg_msg21_SIZE, "msg");
    }
  }

  return fail*4;
}

static int tp_step22_handler(TP_DKG_TPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  if(log_file!=NULL) fprintf(log_file, "\e[0;33m[!] step 22. collect acks from peers\e[0m\n");

  if((tpdkg_msg21_SIZE * ctx->n) != input_len) return 1;
  if(output_len != 0) return 2;

  const uint8_t *ptr = input;
  for(uint8_t i=0;i<ctx->n;i++) {
    const TP_DKG_Message* msg = (const TP_DKG_Message*) ptr;
    if(log_file!=NULL) {
      fprintf(log_file,"[!] msgno: %d, from: %d to: %d ", msg->msgno, msg->from, msg->to);
      dump(ptr, tpdkg_msg21_SIZE, "msg");
    }
    if(0!=recv_msg(ptr, tpdkg_msg21_SIZE, 22, i+1, 0, (*ctx->peer_sig_pks)[i], ctx->sessionid, ctx->ts_epsilon, &ctx->last_ts)) return 3;

    if(memcmp("OK", msg->data, 2)!=0) {
      if(log_file!=NULL) {
        fprintf(log_file,"\e[0;31m[!] failed to get ack from %d!\e[0m\n", i);
      }
    }
    ptr+=tpdkg_msg21_SIZE;
  }
  return 0;
}

int tpdkg_tp_next(TP_DKG_TPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  int ret = 0;
  switch(ctx->step) {
  case 0: {ret = tp_step1_handler(ctx, input, input_len, output, output_len); break;}
  case 1: {ret = tp_step4_handler(ctx, input, input_len, output, output_len); break;}
  case 2: {ret = tp_step68_handler(ctx, input, input_len, output, output_len); break;}
  case 3: {ret = tp_step68_handler(ctx, input, input_len, output, output_len); break;}
  case 4: {ret = tp_step12_handler(ctx, input, input_len, output, output_len); break;}
  case 5: {ret = tp_step14_handler(ctx, input, input_len, output, output_len); break;}
  case 6: {
    ret = tp_step16_handler(ctx, input, input_len, output, output_len);
    ctx->prev = ctx->step;
    if(ctx->complaints_len == 0) {
      // we skip over to step 21
      ctx->step++;
    }
    ctx->step++;
    return ret;
  }
  case 7: {ret = tp_step18_handler(ctx, input, input_len, output, output_len); break;}
  case 8: {ret = tp_step20_handler(ctx, input, input_len, output, output_len); break;}
  case 9: {ret = tp_step22_handler(ctx, input, input_len, output, output_len); break;}
  default: {
    if(log_file!=NULL) fprintf(log_file, "[!] invalid step\n");
    return 99;
  }
  }
  ctx->prev=ctx->step++;
  if(ret!=0) ctx->step=99; // so that not_done reports done
  return ret;
}

int tpdkg_peer_next(TP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len) {
  int ret=0;
  switch(ctx->step) {
  case 0: {ret = peer_step23_handler(ctx, input, input_len, output, output_len); break;}
  case 1: {ret = peer_step5_handler(ctx, input, input_len, output, output_len); break;}
  case 2: {ret = peer_step7_handler(ctx, input, input_len, output, output_len); break;}
  case 3: {ret = peer_step911_handler(ctx, input, input_len, output, output_len); break;}
  case 4: {ret = peer_step13_handler(ctx, input, input_len, output, output_len); break;}
  case 5: {ret = peer_step15_handler(ctx, input, input_len, output, output_len); break;}
  case 6: {ret = peer_step17_handler(ctx, input, input_len, output, output_len); break;}
  case 7: {ret = peer_step17a_handler(ctx, input, input_len, output, output_len); break;}
  case 8: {ret = peer_step19_handler(ctx, input, input_len, output, output_len); break;}
  case 9: {ret = peer_step21_handler(ctx, input, input_len, output, output_len); break;}
  case 10: {
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

char* tpdkg_recv_err(const int code) {
  switch(code) {
  case 0: return "no error";
  case 1: return "invalid message len";
  case 2: return "invalid message number";
  case 3: return "invalid sender";
  case 4: return "invalid recipient";
  case 5: return "expired message";
  case 6: return "invalid signature";
  }
  return "invalid recv_msg error code";
}

uint8_t tpdkg_cheater_msg(const TP_DKG_Cheater *c, char *out, const size_t outlen) {
  if(c->step==16) {
    if(c->error == 5) {
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
               c->peer, c->other_peer, tpdkg_recv_err(c->error & 0xf));
      return c->peer;
    } else if (c->error & 32) {
      snprintf(out, outlen, "message revealing key encrypting share from peer %d for peer %d could not be validated: %s",
               c->peer, c->other_peer, tpdkg_recv_err(c->error & 0x1f));
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

#ifdef UNITTEST
#define N 3
#define T 2

#ifdef __AFL_FUZZ_INIT
__AFL_FUZZ_INIT();
#endif

// for testing only
#include "toprf.h"
typedef struct {
  uint8_t index;
  uint8_t value[crypto_core_ristretto255_BYTES];
} __attribute((packed)) TOPRF_Part;

static void topart(TOPRF_Part *r, const TOPRF_Share *s) {
  r->index=s->index;
  crypto_scalarmult_ristretto255_base(r->value, s->value);
}

static void shuffle(uint8_t *array, const size_t n) {
  if (n < 2) return;
  srand(time(NULL));
  for(int i=0; i<n-1; i++) {
    size_t j = i + rand() / (RAND_MAX / (n - i) + 1);
    int t = array[j];
    array[j] = array[i];
    array[i] = t;
  }
}

static int verify_shares(const uint8_t n, const TOPRF_Share shares[n], const uint8_t t) {
  uint8_t responses[t][sizeof(TOPRF_Part)];
  uint8_t v0[crypto_scalarmult_ristretto255_BYTES]={0};

  uint8_t indexes[n];
  for(int i=0;i<n;i++) indexes[i]=i;
  if(log_file!=NULL) {
    fprintf(stderr, "order: ");
    for(int i=0;i<t;i++) fprintf(stderr, "%2d, ",indexes[i]);
  }

  for(int i=0;i<t;i++) {
    topart((TOPRF_Part *) responses[i], &shares[indexes[i]]);
  }
  if(toprf_thresholdmult(t, responses, v0)) return 1;
  dump(v0,sizeof v0, "v0\t");

  for(int k=0;k<t-1;k++) {
    uint8_t v1[crypto_scalarmult_ristretto255_BYTES]={0};
    shuffle(indexes,n);
    if(log_file!=NULL) {
      fprintf(stderr, "order: ");
      for(int i=0;i<t;i++) fprintf(stderr, "%2d, ",indexes[i]);
    }

    for(int i=0;i<t;i++) {
        topart((TOPRF_Part *) responses[i], &shares[indexes[i]]);
    }

    if(toprf_thresholdmult(t, responses, v1)) return 1;
    dump(v1,sizeof v1, "v%d\t", k+1);

    if(memcmp(v0,v1,sizeof v1)!=0) {
        fprintf(stderr,"\e[0;31mfailed to verify shares from dkg_finish!\e[0m\n");
        return 1;
    }
  }
  return 0;
}

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

#ifdef FUZZ_DUMP
static void fuzz_dump(TP_DKG_TPState *tp, const uint8_t *tp_in, const size_t tp_in_size, const char **argv, const int argc) {
  if(argc!=2) exit(1);
  if(tp->step==6) {
    FILE *tc = fopen(argv[1], "wb");
    fwrite(tp_in, 1, tp_in_size, tc);
    fclose(tc);
    exit(0);
  }
}
#endif
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
static void fuzz_loop(TP_DKG_TPState *tp, uint8_t *tp_out, size_t tp_out_size) {
  if(tp->step==6) {
      TP_DKG_TPState checkpoint;
      memcpy(&checkpoint, tp, sizeof(checkpoint));

#ifdef __AFL_HAVE_MANUAL_CONTROL
      __AFL_INIT();
#endif
      unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT
                                                 // and before __AFL_LOOP!

      while (__AFL_LOOP(10000)) {

        int len = __AFL_FUZZ_TESTCASE_LEN;  // don't use the macro directly in a call!
        if (len < sizeof(TP_DKG_Message)) continue;  // check for a required/useful minimum input length

        /* Setup function call, e.g. struct target *tmp = libtarget_init() */
        /* Call function to be fuzzed, e.g.: */
        tpdkg_tp_next(tp, buf, len, tp_out, tp_out_size);
        /* Reset state. e.g. libtarget_free(tmp) */
        memcpy(tp, &checkpoint, sizeof(TP_DKG_TPState));
      }
  }
}
#endif

int main(const int argc, const char **argv) {
  int ret;
  // enable logging
  log_file = stderr;

  uint8_t n=N, t=T;

  // mock long-term peer keys
  // all known by TP
  uint8_t peer_lt_pks[n][crypto_sign_PUBLICKEYBYTES];
  // only known by corresponding peer
  uint8_t peer_lt_sks[n][crypto_sign_SECRETKEYBYTES];
  for(uint8_t i=0;i<n;i++) {
      crypto_sign_keypair(peer_lt_pks[i], peer_lt_sks[i]);
  }

  TP_DKG_TPState tp;
  uint8_t msg0[tpdkg_msg0_SIZE];
  ret = tpdkg_start_tp(&tp, tpdkg_freshness_TIMEOUT, n, t, "proto test", 10, sizeof msg0, (TP_DKG_Message*) msg0);
  if(0!=ret) return ret;

  // set bufs
  // we need to store these outside of the ctx, since they are
  // variable size, and the struct can only handle one variable size
  // entry...
  uint8_t tp_peers_sig_pks[n][crypto_sign_PUBLICKEYBYTES];
  memset(tp_peers_sig_pks,0,sizeof(tp_peers_sig_pks));
  // tp needs to store the commitments
  uint8_t tp_commitments[n*t][crypto_core_ristretto255_BYTES];
  memset(tp_commitments,0,sizeof(tp_commitments));
  // tp needs to store the complaints, with max n==128 this takes max 16KB of ram.
  uint16_t tp_complaints[n*n];
  memset(tp_complaints,0,sizeof(tp_complaints));
  uint8_t noisy_shares[n*n][tpdkg_msg8_SIZE];
  memset(noisy_shares,0,sizeof(noisy_shares));
  TP_DKG_Cheater cheaters[t*t - 1];
  memset(cheaters,0,sizeof(cheaters));
  tpdkg_tp_set_bufs(&tp, &tp_commitments, &tp_complaints, &noisy_shares, &cheaters, sizeof(cheaters) / sizeof(TP_DKG_Cheater), &tp_peers_sig_pks, &peer_lt_pks);

  // only tp_out can survive for the peers in local scope of the "main protocol loop"
  // and thus we simulate a network with this buffer

  TP_DKG_PeerState peers[n];
  for(uint8_t i=0;i<n;i++) {
    ret = tpdkg_start_peer(&peers[i], tpdkg_freshness_TIMEOUT, peer_lt_sks[i], (TP_DKG_Message*) msg0);
    if(0!=ret) return ret;
  }

  // now that the peer(s) know the value of N, we can allocate buffers
  // to hold all the sig&noise keys, noise sessions, temp shares, commitments
  uint8_t peers_sig_pks[peers[1].n][crypto_sign_PUBLICKEYBYTES];
  memset(peers_sig_pks, 0, sizeof(peers_sig_pks));
  uint8_t peers_noise_pks[peers[1].n][crypto_scalarmult_BYTES];
  Noise_XK_session_t *noise_outs[n][n];
  memset(noise_outs, 0, sizeof noise_outs);
  Noise_XK_session_t *noise_ins[n][n];
  memset(noise_ins, 0, sizeof noise_ins);
  TOPRF_Share ishares[peers[1].n][peers[1].n];
  memset(ishares, 0, sizeof ishares);
  TOPRF_Share xshares[peers[1].n][peers[1].n];
  memset(xshares, 0, sizeof xshares);
  uint8_t commitments[peers[1].n][peers[1].n *peers[1].t][crypto_core_ristretto255_BYTES];
  memset(commitments, 0, sizeof commitments);
  uint16_t peer_complaints[peers[1].n][peers[1].n*peers[1].n];
  memset(peer_complaints, 0, sizeof peer_complaints);
  uint8_t peer_my_complaints[peers[1].n][peers[1].n];
  memset(peer_my_complaints, 0, sizeof peer_my_complaints);

  for(uint8_t i=0;i<n;i++) {
    // in a real deployment peers do not share the same pks buffers
    tpdkg_peer_set_bufs(&peers[i], &peers_sig_pks, &peers_noise_pks,
                        &noise_outs[i], &noise_ins[i],
                        &ishares[i], &xshares[i],
                        &commitments[i],
                        &peer_complaints[i], &peer_my_complaints[i]);
  }


  // simulate network.
  uint8_t network_buf[n+1][NETWORK_BUF_SIZE];
  size_t pkt_len[n+1];
  memset(pkt_len,0,sizeof pkt_len);

  // this is the mainloop - normally only one tp or one peer, but here
  // for demo purposes mixed.
  // end condition for peers is tpdkg_peer_not_done(&peer)
  while(tpdkg_tp_not_done(&tp)) {

    // doing vla - but avoiding 0 sized ones is ugly
    const size_t tp_out_size = tpdkg_tp_output_size(&tp);
    uint8_t tp_out_buf[tp_out_size==0?1:tp_out_size], *tp_out;
    if(tp_out_size==0) tp_out = NULL;
    else tp_out = tp_out_buf;

    // avoiding zero-sized vla is still ugly
    const size_t tp_in_size = tpdkg_tp_input_size(&tp);
    uint8_t tp_in_buf[tp_in_size==0?1:tp_in_size], *tp_in;
    if(tp_in_size==0) tp_in = NULL;
    else tp_in = tp_in_buf;

    _recv(network_buf[0], &pkt_len[0], tp_in, tp_in_size);

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    fuzz_loop(&tp, tp_in, tp_in_size);
#endif
#ifdef FUZZ_DUMP
    fuzz_dump(&tp, tp_in, tp_in_size, argv, argc);
#endif

    ret = tpdkg_tp_next(&tp, tp_in, tp_in_size, tp_out, tp_out_size);
    if(0!=ret) {
      // clean up peers
      for(uint8_t i=0;i<n;i++) tpdkg_peer_free(&peers[i]);
      if(tp.cheater_len > 0) break;
      return ret;
    }

    for(uint8_t i=0;i<tp.n;i++) {
      const uint8_t *msg;
      size_t len;
      if(0!=tpdkg_tp_peer_msg(&tp, tp_out, tp_out_size, i, &msg, &len)) {
        return 1;
      }
      _send(network_buf[i+1], &pkt_len[i+1], msg, len);
    }

    while(pkt_len[0]==0 && tpdkg_peer_not_done(&peers[1])) {
      for(uint8_t i=0;i<n;i++) {
        // 0sized vla meh
        const size_t peer_out_size = tpdkg_peer_output_size(&peers[i]);
        uint8_t peers_out_buf[peer_out_size==0?1:peer_out_size], *peers_out;
        if(peer_out_size==0) peers_out = NULL;
        else peers_out = peers_out_buf;

        // 0sized vla meh for the last time..
        const size_t peer_in_size = tpdkg_peer_input_size(&peers[i]);
        uint8_t peer_in_buf[peer_in_size==0?1:peer_in_size], *peer_in;
        if(peer_in_size==0) peer_in = NULL;
        else peer_in = peer_in_buf;

        _recv(network_buf[i+1], &pkt_len[i+1], peer_in, peer_in_size);
        ret = tpdkg_peer_next(&peers[i],
                              peer_in, peer_in_size,
                              peers_out, peer_out_size);

        if(0!=ret) {
          // clean up peers
          for(uint8_t i=0;i<n;i++) tpdkg_peer_free(&peers[i]);
          return ret;
        }

        _send(network_buf[0], &pkt_len[0], peers_out, peer_out_size);
      }
    }
  }

  // we are done. let's check the shares...
  TOPRF_Share shares[n];
  if(tp.cheater_len == 0) {
    for(uint8_t i=0;i<n;i++) {
      memcpy(&shares[i], (uint8_t*) &peers[i].share, sizeof(TOPRF_Share));
      dump((uint8_t*) &shares[i], sizeof(TOPRF_Share), "share[%d]", i+1);
    }

    if(0!=verify_shares(n, shares, t)) {
        fprintf(stderr, "verify_shares failed\n");
        return 1;
    }
  } else {
    int total_cheaters=0;
    uint8_t tmp[n+1];
    memset(tmp,0,n+1);
    for(int i=0;i<tp.cheater_len;i++) {
      char err[tpdkg_max_err_SIZE];
      uint8_t p = tpdkg_cheater_msg(&(*tp.cheaters)[i], err, sizeof(err));
      fprintf(stderr,"\e[0;31m%s\e[0m\n", err);
      if(p > n) return 1;
      if(tmp[p]==0) total_cheaters++;
      tmp[p]++;
    }
    fprintf(stderr, "\e[0;31m:/ dkg failed, total cheaters %d, list of cheaters:", total_cheaters);
    for(int i=1;i<=n;i++) {
      if(tmp[i]==0) continue;
      fprintf(stderr," %d(%d)", i, tmp[i]);
    }
    fprintf(stderr, "\e[0m\n");
    return 1;
  }

  // clean up peers
  for(uint8_t i=0;i<n;i++) tpdkg_peer_free(&peers[i]);

  fprintf(stderr, "\e[0;32meverything correct!\e[0m\n");
  return 0;
}
#endif //UNITTEST
