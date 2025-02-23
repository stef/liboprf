#ifndef DKG_H
#define DKG_H

/*
 * warning this is a low-level interface. Do not use directly unless
 * you use it to implement DKG protocols which have proper sessionids
 * and other protections against replay and confused deputy attacks.
 *
 * for an example of a high-level DKG protocol see tp-dkg.[ch]
 *
 */

#include <sodium.h>
#include <stdint.h>
#include "XK.h"

#define dkg_hash_BYTES crypto_generichash_BYTES
#define dkg_commitment_BYTES(threshold) (threshold*crypto_core_ristretto255_BYTES)

typedef struct {
  uint8_t index;
  uint8_t value[crypto_core_ristretto255_SCALARBYTES];
} __attribute((packed)) TOPRF_Share;

#define HASH ((uint8_t) 1)
#define COMMITMENT ((uint8_t) 2)

typedef struct {
  uint8_t type;
  uint8_t index;
} __attribute((packed)) DKG_Fail;

void polynom(const uint8_t j, const uint8_t threshold,
                    const uint8_t a[threshold][crypto_core_ristretto255_SCALARBYTES],
                    TOPRF_Share *result);
/**
 * 1st step in the DKG protocol to be executed by all peers participating.
 *
 * @param [in] n - the number of peers participating in the DKG
 * @param [in] threshold - the threshold (must be greater 1 and less than n)
 * @param [out] commitments[dkg_signed_commitment_BYTES] - to
 *              be broadcast after receiving all hashes
 *              broadcasts
 * @param [out] shares[n] - one share for each peer, to be sent
 *              privately to each peer after receving all of the
 *              commitment_hash broadcasts
 * @return The function returns 0 if everything is correct.
 */
int dkg_start(const uint8_t n,
              const uint8_t threshold,
              uint8_t commitments[threshold][crypto_core_ristretto255_BYTES],
              TOPRF_Share shares[n]);

int dkg_verify_commitment(const uint8_t n,
                          const uint8_t threshold,
                          const uint8_t self,
                          const uint8_t i,
                          const uint8_t commitments[threshold][crypto_core_ristretto255_BYTES],
                          const TOPRF_Share share);

int dkg_verify_commitments(const uint8_t n,
                           const uint8_t threshold,
                           const uint8_t self,
                           const uint8_t commitments[n][threshold][crypto_core_ristretto255_BYTES],
                           const TOPRF_Share shares[n],
                           uint8_t fails[n],
                           uint8_t *fails_len);

int dkg_finish(const uint8_t n,
                const TOPRF_Share shares[n],
                const uint8_t self,
                TOPRF_Share *xi);

void dkg_reconstruct(const size_t response_len,
                     const TOPRF_Share responses[response_len],
                     uint8_t result[crypto_scalarmult_ristretto255_SCALARBYTES]);

#define dkg_freshness_TIMEOUT 120000

#define noise_xk_handshake1_SIZE 48UL
#define noise_xk_handshake2_SIZE 48UL
#define noise_xk_handshake3_SIZE 64UL
#define dkg_noise_key_SIZE (32UL)
#define dkg_sessionid_SIZE 32U
#define dkg_max_err_SIZE 128

/** @struct DKG_Message
    This is the header for each message sent in this protocol.

    @var DKG_Message::sig This field contains a signature over the
         message header, the message body and the sessionid which is
         normally not included in the message

    @var DKG_Message::msgno This field contains the "type" of this
         message, which is strictly tied to the current step of the
         protocol

    @var DKG_Message::len This field contains the length of the
         complete message including the header.

    @var DKG_Message::from This field contains the id of the
         sender, the STP is 0, otherwise its the index of the peer.

    @var DKG_Message::to This field contains the recipient of the
         message, value 0 represents the STP, value 0xff represents a
         broadcast message, all other values (<=N) are the indexes of
         the peers.

    @var DKG_Message::ts This field contains a timestamp proving
         the freshness of the message, the timestamp is a 64 bit value
         counting seconds since 1970-01-01.

    @var STP_DKG_Message::data This field contains the payload of the
         message.

 */
typedef struct {
  uint8_t sig[crypto_sign_BYTES];
  uint8_t type;
  uint8_t version;
  uint8_t msgno;
  uint32_t len;
  uint8_t from;
  uint8_t to;
  uint64_t ts;
  uint8_t sessionid[dkg_sessionid_SIZE];
  uint8_t data[];
} __attribute((packed)) DKG_Message;

#define MSG_TYPE_DKG          0
#define MSG_TYPE_UPDATE       1
#define MSG_TYPE_SEMI_TRUSTED (1 << 7)
#define MSG_TYPE_TRUSTED      (0 << 7)

int check_ts(const uint64_t ts_epsilon, uint64_t *last_ts, const uint64_t ts);

int send_msg(uint8_t* msg_buf, const size_t msg_buf_len, const uint8_t type, const uint8_t version, const uint8_t msgno, const uint8_t from, const uint8_t to, const uint8_t *sig_sk, const uint8_t sessionid[dkg_sessionid_SIZE]);

int recv_msg(const uint8_t *msg_buf, const size_t msg_buf_len, const uint8_t type, const uint8_t version, const uint8_t msgno, const uint8_t from, const uint8_t to, const uint8_t *sig_pk, const uint8_t sessionid[dkg_sessionid_SIZE], const uint64_t ts_epsilon, uint64_t *last_ts );

int dkg_init_noise_handshake(const uint8_t index,
                             Noise_XK_device_t *dev,
                             uint8_t rpk[crypto_scalarmult_BYTES],
                             uint8_t *rname,
                             Noise_XK_session_t** session,
                             uint8_t msg[noise_xk_handshake1_SIZE]);
int dkg_respond_noise_handshake(const uint8_t index,
                                Noise_XK_device_t *dev,
                                uint8_t *rname,
                                Noise_XK_session_t** session,
                                uint8_t inmsg[noise_xk_handshake1_SIZE],
                                uint8_t outmsg[noise_xk_handshake2_SIZE]);
int dkg_finish_noise_handshake(const uint8_t index,
                               Noise_XK_device_t *dev,
                               Noise_XK_session_t** session,
                               uint8_t msg[noise_xk_handshake2_SIZE]);
int dkg_noise_encrypt(uint8_t *input,
                      const size_t input_len,
                      uint8_t *output,
                      const size_t output_len,
                      Noise_XK_session_t** session);
int dkg_noise_decrypt(const uint8_t *input,
                      const size_t input_len,
                      uint8_t *output,
                      const size_t output_len,
                      Noise_XK_session_t** session);
uint8_t* Noise_XK_session_get_key(const Noise_XK_session_t *sn);

void update_transcript(crypto_generichash_state *transcript, const uint8_t *msg, const size_t msg_len);

char* dkg_recv_err(const int code);

void dkg_dump_msg(const uint8_t* ptr, const size_t msglen, const uint8_t type);

#endif // DKG_H
