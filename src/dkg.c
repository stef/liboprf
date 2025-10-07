#include <sodium.h>
#include <stdint.h>
#include <string.h>
#include <time.h> // time
#include <arpa/inet.h> //htons
#include "toprf.h"
#include "utils.h"
#include "dkg.h"
#include "noise_private.h"

#ifdef __ZEPHYR__
uint64_t ztime(void);
#endif

/*
    @copyright 2023-24, Stefan Marsiske toprf@ctrlc.hu
    This file is part of liboprf.

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
   warning this is a low-level interface. Do not use directly unless
   you use it to implement DKG protocols which have proper sessionids
   and other protections against replay and confused deputy attacks.

   for an example of a high-level DKG protocol see tp-dkg.[ch]
 */


// calculates polynomial f(j) given the polynomials threshold coefficients in
// array a
void __attribute__((visibility("hidden"))) polynom(const uint8_t j, const uint8_t threshold,
                    const uint8_t a[threshold][crypto_core_ristretto255_SCALARBYTES],
                    TOPRF_Share *result) {
  //f(z) = a_0 + a_1*z + a_2*z^2 + a_3*z^3 + ⋯ + (a_t)*(z^t)
  result->index=j;
  // f(z) = result = a[0] +.....
  memcpy(result->value, a[0], crypto_core_ristretto255_SCALARBYTES);

  // z = j
  uint8_t z[crypto_core_ristretto255_SCALARBYTES]={j};
  // z^t ->
  for(int t=1;t<threshold;t++) {
    // tmp = 1
    uint8_t tmp[crypto_core_ristretto255_SCALARBYTES]={1};
    for(int exp=1;exp<=t;exp++) {
      // tmp *= z
      crypto_core_ristretto255_scalar_mul(tmp, tmp, z);
    }
    // a[t] * z^t
    crypto_core_ristretto255_scalar_mul(tmp, a[t], tmp);
    // add into result
    crypto_core_ristretto255_scalar_add(result->value, result->value, tmp);
  }
}

int dkg_start(const uint8_t n,
              const uint8_t threshold,
              uint8_t commitments[threshold][crypto_core_ristretto255_BYTES],
              TOPRF_Share shares[n]) {

  uint8_t a[threshold][crypto_core_ristretto255_SCALARBYTES];
  if(0!=sodium_mlock(a,sizeof a)) {
    return -1;
  }

  for(int k=0;k<threshold;k++) {
#ifndef UNIT_TEST
    crypto_core_ristretto255_scalar_random(a[k]);
#else
    debian_rng_scalar(a[k]);
    dump(a[k],crypto_core_ristretto255_SCALARBYTES,"a[%d] ", k);
#endif

    // compute commitments
    // A_ik = g^a_ik
    crypto_scalarmult_ristretto255_base(commitments[k], a[k]);
  }

  // calculate shares s_ij
  for(uint8_t j=1;j<=n;j++) {
    //f(x) = a_0 + a_1*x + a_2*x^2 + a_3*x^3 + ⋯ + a_(t)*x^(t)
    polynom(j, threshold, a, &shares[j-1]);
  }

  sodium_munlock(a,sizeof a);

  return 0;
}

int dkg_verify_commitment(const uint8_t n,
                          const uint8_t threshold,
                          const uint8_t self,
                          const uint8_t i,
                          const uint8_t commitments[threshold][crypto_core_ristretto255_BYTES],
                          const TOPRF_Share share) {
  uint8_t j[crypto_core_ristretto255_SCALARBYTES]={self};
  //dump(j,sizeof(j), "\nj        ");

  if(i==self) return 0;
  uint8_t v0[crypto_core_ristretto255_BYTES];

  // v0 = g*(s_ij)
  //dump((uint8_t*)&shares[i-1], sizeof(TOPRF_Share), "s(%d,%d) ", i, self);
  // g*(s_ij)
  crypto_scalarmult_ristretto255_base(v0, share.value);

  // v1=sum(C_ik*j*k for k=0..t)
  uint8_t v1[crypto_core_ristretto255_BYTES];
  //dump(commitments[i-1],crypto_core_ristretto255_BYTES, "c(%d,%d)   ", i, 0);
  // v1 = C_i0*j
  memcpy(v1, &commitments[0], sizeof v1);
  // sum
  for(uint8_t k=1;k<threshold;k++) {
    uint8_t tmp[crypto_core_ristretto255_SCALARBYTES];
    memcpy(tmp, j, sizeof j); // tmp = j^1
    for(int exp=1;exp<k;exp++) {
      // tmp *= j
      crypto_core_ristretto255_scalar_mul(tmp, tmp, j);
    }
    uint8_t tmP[crypto_core_ristretto255_BYTES];
    //dump(tmp, sizeof tmp, "%d tmp", k);
    //dump(commitments[i-1][k], crypto_core_ristretto255_BYTES, "c[%d][%d]", i-1, k);
    if(crypto_scalarmult_ristretto255(tmP, tmp, commitments[k])) return -1;
    crypto_core_ristretto255_add(v1,v1,tmP);
  }

  // v0 == v1
  if(sodium_memcmp(v0,v1,sizeof v1)!=0) {
    // complain about P_i
    if(liboprf_debug) fprintf(stderr, "\x1b[0;31mfailed to verify proof of P_%d in stage 2\x1b[0m\n", i);
    return 1;
  }

  return 0;
}

int dkg_verify_commitments(const uint8_t n,
                           const uint8_t threshold,
                           const uint8_t self,
                           const uint8_t commitments[n][threshold][crypto_core_ristretto255_BYTES],
                           const TOPRF_Share shares[n],
                           uint8_t fails[n],
                           uint8_t *fails_len) {
  *fails_len = 0;
  for(uint8_t i=1;i<=n;i++) {
    if(i==self) continue;
    int ret = dkg_verify_commitment(n, threshold, self, i, commitments[i-1], shares[i-1]);
    if(-1 == ret) return ret;
    if(0 == ret) continue;
    fails[(*fails_len)++] = i;
  }
  if(*fails_len!=0) return 1;

  return 0;
}

int dkg_finish(const uint8_t n,
                const TOPRF_Share shares[n],
                const uint8_t self,
                TOPRF_Share *xi) {
  memset(xi->value, 0, crypto_core_ristretto255_SCALARBYTES);
  for(int i=0;i<n;i++) {
    if(self!=shares[i].index) {
      if(liboprf_debug) fprintf(stderr, "\x1b[0;31mbad share i=%d index=%d\x1b[0m\n", i, shares[i].index);
      return 1;
    }
    crypto_core_ristretto255_scalar_add(xi->value, xi->value, shares[i].value);
    //dump((uint8_t*)&shares[i][0], sizeof(TOPRF_Share), "s[%d,%d] ", qual[i], self);
  }
  //dump(xi->value, crypto_core_ristretto255_SCALARBYTES, "x[%d]     ", self);
  return 0;
}

void dkg_reconstruct(const size_t threshold,
                     const TOPRF_Share shares[threshold],
                     uint8_t secret[crypto_scalarmult_ristretto255_BYTES]) {
  uint8_t lpoly[crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t tmp[crypto_scalarmult_ristretto255_SCALARBYTES];
  memset(secret,0,crypto_scalarmult_ristretto255_SCALARBYTES);

  uint8_t indexes[threshold];
  for(size_t i=0;i<threshold;i++) {
    indexes[i]=shares[i].index;
  }
  for(size_t i=0;i<threshold;i++) {
    coeff(shares[i].index, threshold, indexes, lpoly);
    crypto_core_ristretto255_scalar_mul(tmp, shares[i].value, lpoly);
    crypto_core_ristretto255_scalar_add(secret, secret, tmp);
  }
}


//////////////////// utility functions for [s]tp-dkg  ////////////////////

int __attribute__((visibility("hidden"))) check_ts(const uint64_t ts_epsilon, uint64_t *last_ts, const uint64_t ts) {
  if(*last_ts == 0) {
#ifdef __ZEPHYR__
    uint64_t now = ztime();
#else
    uint64_t now = (uint64_t)time(NULL);
#endif
    if(ts < now - ts_epsilon) return 3;
    if(ts > now + ts_epsilon) return 4;
  } else {
    if(*last_ts > ts) return 1;
    if(ts > *last_ts + ts_epsilon) return 2;
  }
  *last_ts = ts;
  return 0;
}

int __attribute__((visibility("hidden"))) send_msg(uint8_t* msg_buf, const size_t msg_buf_len, const uint8_t type, const uint8_t version, const uint8_t msgno, const uint8_t from, const uint8_t to, const uint8_t *sig_sk, const uint8_t sessionid[dkg_sessionid_SIZE]) {
  if(msg_buf==NULL) return 1;
  DKG_Message* msg = (DKG_Message*) msg_buf;
  msg->type = type;
  msg->version = version;
  msg->len = htonl((uint32_t)msg_buf_len);
  msg->msgno = msgno;
  msg->from = from;
  msg->to = to;
#ifdef __ZEPHYR__
  msg->ts = htonll((uint64_t) ztime());
#else
  msg->ts = htonll((uint64_t)time(NULL));
#endif
  memcpy(msg->sessionid, sessionid, dkg_sessionid_SIZE);

  crypto_sign_detached(msg->sig, NULL, &msg->type, sizeof(DKG_Message) - crypto_sign_BYTES, sig_sk);
  return 0;
}

int __attribute__((visibility("hidden"))) recv_msg(const uint8_t *msg_buf, const size_t msg_buf_len, const uint8_t type, const uint8_t version, const uint8_t msgno, const uint8_t from, const uint8_t to, const uint8_t *sig_pk, const uint8_t sessionid[dkg_sessionid_SIZE], const uint64_t ts_epsilon, uint64_t *last_ts ) {
  if(msg_buf==NULL) return 8;
  const DKG_Message* msg = (const DKG_Message*) msg_buf;
  if(msg->type != type) return 9;
  if(msg->version != version) return 10;
  if(ntohl(msg->len) != msg_buf_len) return 1;
  if(msg->msgno != msgno) return 2;
  if(msg->from != from) return 3;
  if(msg->to != to) return 4;
  if(sodium_memcmp(msg->sessionid, sessionid, dkg_sessionid_SIZE)!=0) return 7;

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(NO_TIME)
  int ret = check_ts(ts_epsilon, last_ts, ntohll(msg->ts));
  if(0!=ret) {
    if(liboprf_log_file!=NULL) {
      fprintf(liboprf_log_file, "checkts fail: %d, last_ts: %ld, ts: %ld, lt+e: %ld\n", ret, *last_ts, ntohll(msg->ts),*last_ts + ts_epsilon);
    }
    return 5;
  }
#endif

  const size_t unsigned_buf_len = msg_buf_len - crypto_sign_BYTES;

  uint8_t with_sessionid[unsigned_buf_len + dkg_sessionid_SIZE];
  memcpy(with_sessionid, msg_buf + crypto_sign_BYTES, unsigned_buf_len);
  memcpy(with_sessionid + unsigned_buf_len, sessionid, dkg_sessionid_SIZE);

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
  if(0!=crypto_sign_verify_detached(msg->sig, &msg->type, sizeof(DKG_Message) - crypto_sign_BYTES, sig_pk)) return 6;
#endif

  return 0;
}

int dkg_init_noise_handshake(const uint8_t index,
                             Noise_XK_device_t *dev,
                             uint8_t rpk[crypto_scalarmult_BYTES],
                             uint8_t *rname,
                             Noise_XK_session_t** session,
                             uint8_t msg[noise_xk_handshake1_SIZE]) {
  //if(liboprf_log_file != NULL) fprintf(liboprf_log_file, "[%d] creating noise session -> %s\n", index, rname);
  // fixme: damnit this allocates stuff on the heap...
  Noise_XK_peer_t *peer = Noise_XK_device_add_peer(dev, rname, rpk);
  if(!peer) return 1;

  uint32_t peer_id = Noise_XK_peer_get_id(peer);
  *session = Noise_XK_session_create_initiator(dev, peer_id);
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

int dkg_respond_noise_handshake(const uint8_t index,
                                Noise_XK_device_t *dev,
                                uint8_t *rname,
                                Noise_XK_session_t** session,
                                uint8_t inmsg[noise_xk_handshake1_SIZE],
                                uint8_t outmsg[noise_xk_handshake2_SIZE]) {
  //if(liboprf_log_file != NULL) fprintf(liboprf_log_file, "[%d] responding noise session -> %s\n", index, rname);
  // fixme: damnit this allocates stuff on the heap...

  *session = Noise_XK_session_create_responder(dev);
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

int dkg_finish_noise_handshake(const uint8_t index,
                               Noise_XK_device_t *dev,
                               Noise_XK_session_t** session,
                               uint8_t msg[noise_xk_handshake2_SIZE]) {
  if(!*session) {
    return 1;
  }

  if(liboprf_log_file!=NULL) {
    // get peer name
    uint32_t peer_id = Noise_XK_session_get_peer_id(*session);
    Noise_XK_peer_t *peer = Noise_XK_device_lookup_peer_by_id(dev, peer_id);
    if(peer==NULL) {
      Noise_XK_session_free(*session);
      return 2;
    }
    uint8_t *pinfo;
    Noise_XK_peer_get_info(&pinfo, peer);
    if(pinfo==NULL) {
      Noise_XK_session_free(*session);
      return 3;
    }
    //fprintf(liboprf_log_file, "[%d] finishing noise session -> %s\n", index, pinfo);
    free(pinfo);
  }

  Noise_XK_encap_message_t *encap_msg;
  Noise_XK_rcode ret = Noise_XK_session_read(&encap_msg, *session, noise_xk_handshake2_SIZE, msg);
  if(!Noise_XK_rcode_is_success(ret)) {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "session read fail: %d\n", ret.val.case_Error);
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

int dkg_noise_encrypt(uint8_t *input,
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

int dkg_noise_decrypt(const uint8_t *input,
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
  Noise_XK_rcode ret = Noise_XK_session_read(&encap_msg, *session, (uint32_t) input_len, (uint8_t*) input);
  if(!Noise_XK_rcode_is_success(ret)) {
    if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, "session read fail: %d\n", ret.val.case_Error);
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

/**
  Return the session unique send key, needed for tp-dkg reveal share.
*/
uint8_t __attribute__((visibility("hidden"))) *Noise_XK_session_get_key(const Noise_XK_session_t *sn) {
  Noise_XK_session_t st = sn[0U];
  if (st.tag == Noise_XK_DS_Initiator && st.val.case_DS_Initiator.state.tag == Noise_XK_IMS_Transport)
    return st.val.case_DS_Initiator.state.val.case_IMS_Transport.send_key;
  if (st.tag == Noise_XK_DS_Responder && st.val.case_DS_Responder.state.tag == Noise_XK_IMS_Transport)
    return st.val.case_DS_Responder.state.val.case_IMS_Transport.receive_key;
  return NULL;
}

void __attribute__((visibility("hidden"))) update_transcript(crypto_generichash_state *transcript, const uint8_t *msg, const size_t msg_len) {
  uint32_t msg_size_32b = htonl((uint32_t)msg_len);
  crypto_generichash_update(transcript, (uint8_t*) &msg_size_32b, sizeof(msg_size_32b));
  crypto_generichash_update(transcript, msg, msg_len);
}

char* dkg_recv_err(const int code) {
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

void dkg_dump_msg(const uint8_t* ptr, const size_t msglen, const uint8_t type) {
  if(liboprf_log_file!=NULL) {
     const DKG_Message *msg = (const DKG_Message*) ptr;
     if(type==0) {
        fprintf(liboprf_log_file,"[!] msgno: %d, len: %d, from: %d to: %x ", msg->msgno, htonl(msg->len), msg->from, msg->to);
     } else {
        fprintf(liboprf_log_file,"[%d] msgno: %d, len: %d, from: %d to: %x ", type, msg->msgno, htonl(msg->len), msg->from, msg->to);
     }
     dump(ptr, msglen, "msg");
     if(liboprf_debug==0) fprintf(liboprf_log_file, "\n");
  }
}
