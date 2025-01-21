#ifndef stp_dkg_h
#define stp_dkg_h
/**
 * @file stp-dkg.h

  SPDX-FileCopyrightText: 2024, Marsiske Stefan
  SPDX-License-Identifier: LGPL-3.0-or-later

  API for the Trusted Party Distributed Key Generation Protocol

  In this protocol there is two roles, the trusted party (STP) and the
  peers. The trusted party connects to all peers and orchestrates the
  protocol which commuicate only via the STP with each other. This way
  the STP acts also as a broadcast medium which is an essential part of
  all DKG protocols.

  In this protocol the trusted party is - as the name implies -
  trusted, but does not learn the result of the DKG. If the trusted
  party is so trusted that it can learn the result of the DKG, then it
  is much simpler to just randomly generate a secret and then share it
  using Shamir's Secret Sharing.

  The peers only identify themselves towards the STP using long-term
  keys, but use ephemeral keys when communicating with each other,
  this makes them unaware of the identities of the others. However
  peers might be using the ephemeral public keys, or any of the
  generated random values to use as a side-channel to leak their
  identity to the other peers.

  The protocol consists of more than 20 steps, but the API hides this
  and provides a state-engine loop, which any user can call
  iteratively while implementing the networking communication
  themselves. This makes it possible to support different
  communication channels like TCP/IP, Bluetooth, UART, etc. A peer
  needs only to support the medium they use, the STP however must of
  course be able to support all the media that the peers require.

  Both the peers and the STP share a similar API schema:

  (0. msg0 = read()) // only for peers
  1. start_{stp|peer}(state, ...)
  (1.5 send(msg0)) // only for STP
  2. {stp|peer}_set_bufs()
  3. while {stp|peer}_not_done(state):
     - input = allocate_memory( dkg_{stp|peer}_input_size(state) )
     - output = allocate_memory( dkg_{stp|peer}_output_size(state) )
     - input = read()
     - res = {stp|peer}_next_step(state, input, output)
     - if res!=0: fail&abort
     (- dkg_stp_peer_msg(state, output, peer_index, msg) // for STP
     (- msg = output) // for peers
     - send(msg)

  // only for peers
  (4. store share)
  (5. peer_free(state))

 */

#include <stdint.h>
#include <sodium.h>
#include "XK.h"
#include "dkg.h"

#define stpdkg_commitment_HASHBYTES 32U
#define stpdkg_sessionid_SIZE 32U
#define stpdkg_msg0_SIZE ( sizeof(STP_DKG_Message)                                       \
                        + crypto_generichash_BYTES/*dst*/                                \
                        + 2 /*n,t*/                                                      )
#define noise_xk_handshake3_SIZE 64UL
#define stpdkg_msg10_SIZE (sizeof(STP_DKG_Message) /* header */                           \
                          + noise_xk_handshake3_SIZE /* 4th&final noise handshake */      \
                          + sizeof(TOPRF_Share) /* msg: the noise_xk wrapped share */     \
                          + crypto_secretbox_xchacha20poly1305_MACBYTES /* mac of msg */  \
                          + crypto_auth_hmacsha256_BYTES /* key-committing mac over msg*/ )
#define stpdkg_max_err_SIZE 128

/** @struct STP_DKG_Message
    This is the header for each message sent in this protocol.

    @var STP_DKG_Message::sig This field contains a signature over the
         message header, the message body and the sessionid which is
         normally not included in the message

    @var STP_DKG_Message::msgno This field contains the "type" of this
         message, which is strictly tied to the current step of the
         protocol

    @var STP_DKG_Message::len This field contains the length of the
         complete message including the header.

    @var STP_DKG_Message::from This field contains the id of the
         sender, the STP is 0, otherwise its the index of the peer.

    @var STP_DKG_Message::to This field contains the recipient of the
         message, value 0 represents the STP, value 0xff represents a
         broadcast message, all other values (<=N) are the indexes of
         the peers.

    @var STP_DKG_Message::ts This field contains a timestamp proving
         the freshness of the message, the timestamp is a 64 bit value
         counting seconds since 1970-01-01.

    @var STP_DKG_Message::data This field contains the payload of the
         message.

 */
typedef struct {
  uint8_t sig[crypto_sign_BYTES];
  uint8_t msgno;
  uint32_t len;
  uint8_t from;
  uint8_t to;
  uint64_t ts;
  uint8_t sessionid[stpdkg_sessionid_SIZE];
  uint8_t data[];
} __attribute((packed)) STP_DKG_Message;

/** @struct STP_DKG_PeerState

    This struct contains the state of a peer during the execution of
    the STP DKG protocol.

    Most values of this struct are internal variables and should not
    be used. The following variables are useful and can be used by
    users of this API:

    @var STP_DKG_PeerState:n This field contains the value N,
         specifying the total number of peers participating in this
         protocol.

    @var STP_DKG_PeerState:t This field contains the value T,
         specifying the threshold necessary to use shared secret
         generated by this DKG.

    @var STP_DKG_PeerState:index This field contains the index of the
         peer, it is a value between 1 and and N inclusive.

    @var STP_DKG_PeerState:share This field contains the resulting
         share at the end of the DKG and should most probably be
         persisted for later usage. This is the output of the DKG for
         a peer.
 */
typedef struct {
  int step;
  int prev;
  uint8_t sessionid[stpdkg_sessionid_SIZE];
  uint8_t n;
  uint8_t t;
  uint8_t index;
  uint8_t sig_pk[crypto_sign_PUBLICKEYBYTES];
  uint8_t sig_sk[crypto_sign_SECRETKEYBYTES];
  uint8_t noise_pk[crypto_scalarmult_BYTES];
  uint8_t noise_sk[crypto_scalarmult_SCALARBYTES];
  uint64_t stp_last_ts;
  uint64_t *last_ts;
  uint64_t ts_epsilon;
  const uint8_t (*sig_pks)[][crypto_sign_PUBLICKEYBYTES];
  uint8_t (*peer_noise_pks)[][crypto_scalarmult_BYTES];
  Noise_XK_device_t *dev;
  Noise_XK_session_t *(*noise_outs)[];
  Noise_XK_session_t *(*noise_ins)[];
  uint8_t (*commitment_hashes)[][stpdkg_commitment_HASHBYTES];
  uint8_t (*commitments)[][crypto_core_ristretto255_BYTES];
  TOPRF_Share (*shares)[];
  TOPRF_Share (*xshares)[];
  uint16_t complaints_len;
  uint16_t *complaints;
  uint8_t my_complaints_len;
  uint8_t *my_complaints;
  crypto_generichash_state transcript;
  TOPRF_Share share;
} STP_DKG_PeerState;

size_t stpdkg_peerstate_size(void);
uint8_t stpdkg_peerstate_n(STP_DKG_PeerState *ctx);
uint8_t stpdkg_peerstate_t(STP_DKG_PeerState *ctx);
uint8_t* stpdkg_peerstate_sessionid(STP_DKG_PeerState *ctx);
uint8_t* stpdkg_peerstate_lt_sk(STP_DKG_PeerState *ctx);
uint8_t* stpdkg_peerstate_share(STP_DKG_PeerState *ctx);
int stpdkg_peerstate_step(STP_DKG_PeerState *ctx);

/** @struct STP_DKG_Cheater

    This struct communicates one detected violation of the protocol.

    @var STP_DKG_Cheater::step This is the step in which the violation occured.

    @var STP_DKG_Cheater::error This is the error code specifying the violation.

    @var STP_DKG_Cheater::peer This specifies which peer caused the violation.

    @var STP_DKG_Cheater::other_peer This optionally specifies which
         peer reported the violation, set to 0xfe if unused.
 */
typedef struct {
  int step;
  int error;
  uint8_t peer;
  uint8_t other_peer;
  int invalid_index;
} STP_DKG_Cheater;

// error codes:
// step 18
//    6; accused revealed a key that was not complained about
//    3; hmac verification failure
//    4; share decryption failure
//    5; invalid share index
//    7; unchecked complaint
//    16 + recv_msg error code - invalid msg 8 (final noise hs + hmac-ed share)
//    32 + recv_msg error code - invalid msg11 - key reveal message
//    127 invalid params for verification from accused
//    128 false complaint
//    129 correct complaint

// recv_msg error codes
// 1 invalid msg len
// 2 unexpected msgno
// 3 from
// 4 to
// 5 expired
// 6 signature fail

/** @struct STP_DKG_STPState

    This struct contains the state of the STP during the execution of
    the STP DKG protocol.

    Most values of this struct are internal variables and should not
    be used. The following variables are useful and can be used by
    users of this API:

    @var STP_DKG_PeerState:n This field contains the value N,
         specifying the total number of peers participating in this
         protocol.

    @var STP_DKG_PeerState:t This field contains the value T,
         specifying the threshold necessary to use shared secret
         generated by this DKG.

    @var STP_DKG_PeerState:cheaters This field contains a list of
         cheaters and protocol violators at the end of a failed
         protocol run.

*/
typedef struct {
  int step;
  int prev;
  uint8_t sessionid[stpdkg_sessionid_SIZE];
  uint8_t n;
  uint8_t t;
  uint8_t sig_pk[crypto_sign_PUBLICKEYBYTES]; // todo?
  uint8_t sig_sk[crypto_sign_SECRETKEYBYTES];
  uint64_t *last_ts;
  uint64_t ts_epsilon;
  const uint8_t (*sig_pks)[][crypto_sign_PUBLICKEYBYTES];
  uint8_t (*commitments)[][crypto_core_ristretto255_BYTES];
  // note this could be optimized by only storing the encrypted share and the hmac
  // and also dropping all items where i==j
  uint8_t (*encrypted_shares)[][stpdkg_msg10_SIZE];
  uint16_t complaints_len;
  uint16_t (*complaints)[];
  size_t cheater_len;
  STP_DKG_Cheater (*cheaters)[];
  size_t cheater_max;
  crypto_generichash_state transcript;
} STP_DKG_STPState;

size_t stpdkg_stpstate_size(void);
uint8_t stpdkg_stpstate_n(STP_DKG_STPState *ctx);
uint8_t stpdkg_stpstate_t(STP_DKG_STPState *ctx);
size_t stpdkg_stpstate_cheater_len(STP_DKG_STPState *ctx);
uint8_t* stpdkg_stpstate_sessionid(STP_DKG_STPState *ctx);
int stpdkg_stpstate_step(STP_DKG_STPState *ctx);

/*
 * Trusted Party functions
 */

/** Starts a new execution of a STP DKG protocol.

    This function initializes the state of the STP and creates an
    initial message containing the parameters for the peers.

    @param [in] ctx : pointer to a STP_DKG_STPState struct, this struct
                will be initialized by this function.

    @param [in] ts_epsilon: how many seconds a message can be old,
                before it is considered unfresh and is rejected. The
                correct value here is difficult to set, small local
                executions with only 2-out-of-3 setups will work with
                as few as 2-3 seconds, big deployments with
                126-out-of-127 might need up to a few hours...

    @param [in] n: the number of peers participating in this execution.

    @param [in] t: the threshold necessary to use the results of this DKG.

    @param [in] proto_name: an array of bytes used as a domain
           seperation tag (DST). Set it to the name of your application.

    @param [in] proto_name_len: the size of the array proto_name, to
           allow non-zero terminated DSTs.

    @param [in] sig_pks: list of all participants ordered long-term
           signing pubkeys, with the STP pubkey at index 0

    @param [in] ltssk: the STPs long-term signing private key

    @param [out] msg0_len: the size of memory allocated to the msg0 parameter.
           should be exactly stpdkg_msg0_SIZE;

    @param [out] msg0: a message to be sent to all peers to initalize them.
    @return 0 if no errors.
 **/
int stpdkg_start_stp(STP_DKG_STPState *ctx, const uint64_t ts_epsilon,
                     const uint8_t n, const uint8_t t,
                     const char *proto_name, const size_t proto_name_len,
                     const uint8_t (*sig_pks)[][crypto_sign_PUBLICKEYBYTES],
                     const uint8_t ltssk[crypto_sign_SECRETKEYBYTES],
                     const size_t msg0_len, STP_DKG_Message *msg0);

/**
   This function sets all the variable sized buffers in the STP_DKG_PeerState structure.

   A number of buffers are needed in the STP state that depend on the N and T parameters.
   These can be allocated on the stack as follows:

   @param [in] cheater_max: is the number of max cheat attempts to be
          recorded. Normally the maximum is t*t-1. It should be provided as
          (sizeof(cheaters) / sizeof(STP_DKG_Cheater))

   @code
   uint8_t stp_commitments[n*t][crypto_core_ristretto255_BYTES];
   uint16_t stp_complaints[n*n];
   uint8_t encrypted_shares[n*n][stpdkg_msg10_SIZE];
   STP_DKG_Cheater cheaters[t*t - 1];
  uint64_t last_ts[n];

   stpdkg_stp_set_bufs(&stp, &stp_commitments, &stp_complaints, &encrypted_shares,
                     &cheaters, sizeof(cheaters) / sizeof(STP_DKG_Cheater),
                     last_ts);
   @endcode

   Important to note that peer_lt_pks should contain the long-term
   signing public-keys of each peer. This array must be populated in
   the correct order before the first call to stpdkg_stp_next().
 */
void stpdkg_stp_set_bufs(STP_DKG_STPState *ctx,
                       uint8_t (*commitments)[][crypto_core_ristretto255_BYTES],
                       uint16_t (*complaints)[],
                       uint8_t (*encrypted_shares)[][stpdkg_msg10_SIZE],
                       STP_DKG_Cheater (*cheaters)[], const size_t cheater_max,
                       uint64_t *last_ts);

/**
   This function calculates the size of the buffer needed to hold all
   outputs from the peers serving as input to the next step of the STP.

   An implementer should allocate a buffer of this size, and
   concatenate all messages from all peers in the order of the peers.

   The allocated buffer is to be passed as an input to the
   stpdkg_pt_next() function, after this the buffer SHOULD be
   deallocated.

   @param [in] ctx: an initialized STP_DKG_STPState struct.
   @return 1 on error, otherwise the size to be allocated (can be 0)
 */
size_t stpdkg_stp_input_size(const STP_DKG_STPState *ctx);

/**
   This function calculates the size of the message from each peer to
   be received by the STP.

   @param [in] ctx: an initialized STP_DKG_STPState struct.
   @param [out] sizes: a array of type size_t with exactly N elements.

   @return 0 on if the sizes differ from peer to peer, otherwise all
           peers will be sending messages of equal size. In the latter
           case all items of the sizes array hold the same valid value.
 */
int stpdkg_stp_input_sizes(const STP_DKG_STPState *ctx, size_t *sizes);

/**
   This function calculates the size of the buffer needed to hold the
   output from the stpdkg_stp_next() function.

   An implementer should allocate a buffer of this size and pass it as
   parameter to stpdkg_stp_next().

   @param [in] ctx: an initialized STP_DKG_STPState struct.
   @return 1 on error, otherwise the size to be allocated (can be 0)
*/
size_t stpdkg_stp_output_size(const STP_DKG_STPState *ctx);

/**
   This function exeutes the next step of the STP DKG protocol for the
   trusted party.

   @param [in] ctx: pointer to a valid STP_DKG_STPState.
   @param [in] input: buffer to the input of the current step.
   @param [in] input_len: size of the input buffer.
   @param [out] output: buffer to the output of the current step.
   @param [in] output_len: size of the output buffer.
   @return 0 if no error

   An example of how to use this in concert with stpdkg_stp_input_size()
   and stpdkg_stp_output_size():

   @code
    uint8_t stp_out[stpdkg_stp_output_size(&stp)];
    uint8_t stp_in[stpdkg_stp_input_size(&stp)];
    recv(socket, stp_in, sizeof(stp_in));
    ret = stpdkg_stp_next(&stp, stp_in, sizeof(stp_in), stp_out, sizeof stp_out);
   @endcode
 */
int stpdkg_stp_next(STP_DKG_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len);

/**
   This function "converts" the output of stpdkg_stp_next() into a message for the ith peer.

   The outputs of steps of the protocol are sometimes broadcast
   messages where the output is the same for all peers, but some of
   the outputs are dedicated and unique messages for each peer. This
   function returns a pointer to a message and the size of the message
   to be sent for a particular peer specified as a parameter.


   @param [in] ctx: pointer to a valid STP_DKG_STPState.
   @param [in] base: a pointer to the output of the stpdkg_stp_next() function.
   @param [in] base_size: the size of the output of the stpdkg_stp_next() function.
   @param [in] peer: the index of the peer (starting with 0 for the first)
   @param [out] msg: pointer to a pointer to the message to be sent to the ith peer.
   @param [out] len: pointer to the length of the message to be sent to the ith peer.
   @return 0 if no error

   example how to use this in concert with stpdkg_stp_next():

   @code
    ret = stpdkg_stp_next(&stp, stp_in, sizeof(stp_in), stp_out, sizeof stp_out);
    if(0!=ret) {
      // clean up peers
      for(int i=0;i<n;i++) stpdkg_peer_free(&peers[i]);
      return ret;
    }

    for(int i=0;i<stp.n;i++) {
      const uint8_t *msg;
      size_t len;
      if(0!=stpdkg_stp_peer_msg(&stp, stp_out, sizeof stp_out, i, &msg, &len)) {
        return 1;
      }
      _send(network_buf[i+1], &pkt_len[i+1], msg, len);
    }
    @endcode

 */
int stpdkg_stp_peer_msg(const STP_DKG_STPState *ctx, const uint8_t *base, const size_t base_size, const uint8_t peer, const uint8_t **msg, size_t *len);

/** This function checks if the protocol has finished for the STP or
    more stpdk_stp_next() calls are necessary.

   @return 1 if more steps outstanding
 */
int stpdkg_stp_not_done(const STP_DKG_STPState *stp);

/** This function converts a cheater object to a human readable string.

    @param [in] c: the cheater object.
    @param [out] out: the pointer to the pre-allocated buffer receiving the string
    @param [in] outlen: the size of the pre-allocated buffer
    @return the index of the cheating peer.
 */
uint8_t stpdkg_cheater_msg(const STP_DKG_Cheater *c, char *out, const size_t outlen);

/*
 * Peer functions
 */

/** Starts a new execution of a STP DKG protocol for a peer.

    This function initializes the state of the peer.

    @param [in] ctx : pointer to a STP_DKG_STPState struct, this struct
                will be initialized by this function.

    @param [in] ts_epsilon: how many seconds a message can be old,
                before it is considered unfresh and is rejected. The
                correct value here is difficult to set, small local
                executions with only 2-out-of-3 setups will work with
                as few as 2-3 seconds, big deployments with
                126-out-of-127 might need up to a few hours...

    @param [in] sig_pks: list of all participants ordered long-term
           signing pubkeys, with the STP pubkey at index 0

    @param [in] peer_lt_sk: the long-term private signing key of the peer.

    @param [in] t: the msg0 sent from the STP after the STP run stpdkg_stp_start().

    @return 0 if no errors.
 **/
int stpdkg_start_peer(STP_DKG_PeerState *ctx, const uint64_t ts_epsilon,
                      const uint8_t (*sig_pks)[][crypto_sign_PUBLICKEYBYTES],
                      const uint8_t peer_lt_sk[crypto_sign_SECRETKEYBYTES],
                      const STP_DKG_Message *msg0);

/** This function sets all the variable sized buffers in the STP_DKG_PeerState structure.

  The buffer sizes depend on the N and T parameters to the DKG, if
  they are known in advance, great. If not, they are announced by the
  STP in msg0, which is an input to the stpdkg_start_peer() function,
  after this stpdkg_start_peer() function the peerstate is initialized
  and can be used to find out the N and T parameters.

  If you want you can allocate all the buffers on the stack like this:

  @code
  uint8_t peers_sig_pks[peerstate.n][crypto_sign_PUBLICKEYBYTES];
  uint8_t peers_noise_pks[peerstate.n][crypto_scalarmult_BYTES];
  Noise_XK_session_t *noise_outs[peerstate.n];
  Noise_XK_session_t *noise_ins[peerstate.n];
  TOPRF_Share ishares[peerstate.n];
  TOPRF_Share xshares[peerstate.n];
  uint8_t commitments[peerstate.n *peerstate.t][crypto_core_ristretto255_BYTES];
  uint16_t peer_complaints[peersstate.n*peersstate.n];
  uint8_t peer_my_complaints[peerstate.n];
  @endcode

**/
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
                         uint64_t *last_ts);



/**
   This function calculates the size of the buffer needed to hold the
   output from the STP serving as input to the next step of the peer.

   An implementer should allocate a buffer of this size.

   The allocated buffer is to be passed as an input to the
   stpdkg_peer_next() function, after this the buffer SHOULD be
   deallocated.

   @param [in] ctx: an initialized STP_DKG_PeerState struct.
   @return 1 on error, otherwise the size to be allocated (can be 0)
 */
size_t stpdkg_peer_input_size(const STP_DKG_PeerState *ctx);

/**
   This function calculates the size of the buffer needed to hold the
   output from the stpdkg_peer_next() function.

   An implementer should allocate a buffer of this size and pass it as
   parameter to stpdkg_peer_next().

   @param [in] ctx: an initialized STP_DKG_PeerState struct.
   @return 1 on error, otherwise the size to be allocated (can be 0)
*/
size_t stpdkg_peer_output_size(const STP_DKG_PeerState *ctx);

/**
   This function exeutes the next step of the STP DKG protocol for a
   peer.

   @param [in] ctx: pointer to a valid STP_DKG_PeerState.
   @param [in] input: buffer to the input of the current step.
   @param [in] input_len: size of the input buffer.
   @param [out] output: buffer to the output of the current step.
   @param [in] output_len: size of the output buffer.
   @return 0 if no error

   An example of how to use this in concert with stpdkg_peer_input_size()
   and stpdkg_peer_output_size() while allocating the buffers on the stack:

   @code
   uint8_t peers_out[stpdkg_peer_output_size(&peers[i])];

   uint8_t peer_in[stpdkg_peer_input_size(&peers[i])];
   recv(socket, peer_in, sizeof(peer_in));
   ret = stpdkg_peer_next(&peer,
                         peer_in, sizeof(peer_in),
                         peers_out, sizeof(peers_out));
   @endcode
 */
int stpdkg_peer_next(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len);

/**
   This function checks if the protocol has finished for the peer or
   more stpdk_peer_next() calls are necessary.

   @return 1 if more steps outstanding
 */
int stpdkg_peer_not_done(const STP_DKG_PeerState *peer);

/**
   This function MUST be called before a peers state is
   deallocated.

   Unfortunately the underlying (but very cool and formally verified)
   Noise XK implementation does allocate a lot of internal state on
   the heap, and thus this must be freed manually.
 */
void stpdkg_peer_free(STP_DKG_PeerState *ctx);

extern FILE* log_file;

#endif //stp_dkg_h
