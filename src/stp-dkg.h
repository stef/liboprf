#ifndef STP_DKG_H
#define STP_DKG_H
/**
 * @file stp_dkg.h
 * @brief API for the Semi-Trusted Party Distributed Key Generation
 *        (STP-DKG) Protocol
 *
 * SPDX-FileCopyrightText: 2025, Marsiske Stefan
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * This API implements a Distributed Key Generation (DKG) protocol involving
 * two roles: the semi-trusted party (STP) and multiple peers.
 *
 * ## Protocol Overview
 *
 * The STP orchestrates the entire protocol, relaying and broadcasting
 * messages between peers. Communication between peers occurs only through
 * the STP. This way, the STP also acts as a broadcast medium which is an
 * essential part of all DKG protocols.
 *
 * The protocol consists of over 20 internal steps, but the API hides this
 * complexity behind a state-driven loop, which any user can call iteratively
 * while implementing the networking communication themselves. This simplifies
 * the network model and enables usage across different communication channels
 * like TCP/IP, Bluetooth, USB, UART, etc.
 * The STP must support all communication channels that its peers require,
 * while each peer only needs to support its chosen medium.
 *
 * This protocol is based on R. Gennaro, M. O. Rabin, and T. Rabin.
 * "Simplified VSS and fast-track multiparty computations
 * with applications to threshold cryptography", in B. A. Coan and
 * Y. Afek, editors, 17th ACM PODC, pages 101–111. ACM, June / July.
 *
 * The full specification is available in `/docs/stp-dkg.txt`.
 *
 * ## Common Protocol Flow
 *
 * Both the peers and the STP share a similar API schema:
 *
 * - For peers:
 *   ```
 *   msg0 = read(); // from the STP
 *   start_peer(state, ...);
 *   peer_set_bufs();
 *   while (peer_not_done(state)) {
 *       input = allocate_memory( dkg_peer_input_size(state) )
 *       output = allocate_memory( dkg_peer_output_size(state) )
 *       input = read()
 *       res = peer_next_step(state, input, output)
 *       if res!=0: fail&abort
 *       msg = output
 *       send(msg)
 *   }
 *   store share
 *   peer_free(state);
 *   ```
 *
 * - For the STP:
 *   ```
 *   start_stp(state, ...);
 *   set_bufs(...);
 *   send(msg0); // to all peers
 *   while (!stp_done(state)) {
 *       input = allocate_memory( dkg_stp_input_size(state) )
 *       output = allocate_memory( dkg_stp_output_size(state) )
 *       input = read()
 *       res = stp_next_step(state, input, output)
 *       if res!=0: fail&abort
 *       dkg_stp_peer_msg(state, output, peer_index, msg)
 *   }
 *   ```
 */
#include <stdint.h>
#include <sodium.h>
#include "dkg.h"
#include "toprf.h"

typedef DKG_Message STP_DKG_Message;
typedef DKG_Cheater STP_DKG_Cheater;

#define stp_dkg_commitment_HASHBYTES 32U
#define stp_dkg_encrypted_share_SIZE (TOPRF_Share_BYTES * 2 + crypto_secretbox_xchacha20poly1305_MACBYTES)
#define stpvssdkg_start_msg_SIZE ( sizeof(STP_DKG_Message)                            \
                                 + crypto_generichash_BYTES/*dst*/                    \
                                 + 2 /* n&t */                                        \
                                 + crypto_sign_PUBLICKEYBYTES                         )

/**
 * @enum STP_DKG_Err
 * @brief Error codes returned by the STP DKG protocol functions
 *
 * These error codes represent the various failures and exceptional
 * conditions that can occur during the execution of the STP-based
 * DKG protocol.
 */
typedef enum {
  STP_DKG_Err_OK = 0,
  STP_DKG_Err_ISize,
  STP_DKG_Err_OSize,
  STP_DKG_Err_OOB,
  STP_DKG_Err_Send,
  STP_DKG_Err_CheatersFound,
  STP_DKG_Err_CheatersFull,
  STP_DKG_Err_InvSessionID,
  STP_DKG_Err_Share,
  STP_DKG_Err_Noise,
  STP_DKG_Err_NoiseEncrypt,
  STP_DKG_Err_NoiseDecrypt,
  STP_DKG_Err_HMac,
  STP_DKG_Err_Index,
  STP_DKG_Err_NoSubVSPSFail,
  STP_DKG_Err_NotEnoughDealers,
  STP_DKG_Err_TooManyCheaters,
  STP_DKG_Err_DKGFinish,
  STP_DKG_Err_BroadcastEnv = 32,
  STP_DKG_Err_Env = 64
} STP_DKG_Err;

/**
 * @enum STP_DKG_STP_Steps
 * @brief Steps executed by the STP in the DKG protocol
 *
 * This defines each logical step in the protocol that the STP must
 * execute to complete the DKG.
 */
typedef enum {
  STP_DKG_STP_Send_Index,
  STP_DKG_STP_Broadcast_NPKs,
  STP_DKG_STP_Route_Noise_Handshakes1,
  STP_DKG_STP_Route_Noise_Handshakes2,
  STP_DKG_STP_Broadcast_DKG_Hash_Commitments,
  STP_DKG_STP_Broadcast_DKG_Commitments,
  STP_DKG_STP_Route_Encrypted_Shares,
  STP_DKG_STP_Broadcast_Complaints,
  STP_DKG_STP_Broadcast_DKG_Defenses,
  STP_DKG_STP_Broadcast_DKG_Transcripts,
  STP_DKG_STP_Broadcast_DKG_Final_Commitments,
  STP_DKG_STP_Done
} STP_DKG_STP_Steps;

/**
 * @enum STP_DKG_Message_Type
 * @brief Message types used during the STP DKG protocol
 *
 * Each type represents a stage-specific message exchanged between
 * the STP and peers during the distributed key generation process.
 */
typedef enum {
  stpvssdkg_stp_start_msg,
  stpvssdkg_stp_index_msg,
  stpvssdkg_peer_init1_msg,
  stpvssdkg_stp_bc_init1_msg,
  stpvssdkg_peer_start_noise_msg,
  stpvssdkg_peer_respond_noise_msg,
  stpvssdkg_peer_dkg1_msg,
  stpvssdkg_stp_bc_dkg1_msg,
  stpvssdkg_peer_dkg2_msg,
  stpvssdkg_stp_bc_dkg2_msg,
  stpvssdkg_peer_dkg3_msg,
  stpvssdkg_stp_bc_dkg3_msg,
  stpvssdkg_peer_verify_shares_msg,
  stpvssdkg_stp_bc_verify_shares_msg,
  stpvssdkg_peer_share_key_msg,
  stpvssdkg_stp_bc_key_msg,
  stpvssdkg_peer_bc_transcript_msg,
  stpvssdkg_stp_bc_transcript_msg,
} STP_DKG_Message_Type;

/**
 * @struct STP_DKG_STPState
 * @brief State for the STP during the  execution of the DKG protocol
 *
 * Some fields in this struct are internal variables and should not
 * be used. The following fields are useful and can be accessed by
 * users of the API:
 *
 * @var STP_DKG_STPState::n Total number of peers participating in
 *      this protocol
 *
 * @var STP_DKG_STPState::t The threshold, the minimum number of
 *      peers required to use the shared secret generated by this DKG
 *
 * @var STP_DKG_STPState::cheaters List of detected cheaters and protocol
 *      violators at the end of a failed protocol run
 *
 * @var STP_DKG_STPState::cheater_len Length of the `cheaters` list
 */
typedef struct {
  STP_DKG_STP_Steps step;
  STP_DKG_STP_Steps prev;
  uint8_t sessionid[dkg_sessionid_SIZE];
  uint8_t n;
  uint8_t t;
  uint8_t sig_pk[crypto_sign_PUBLICKEYBYTES];
  uint8_t sig_sk[crypto_sign_SECRETKEYBYTES];
  uint64_t *last_ts;
  uint64_t ts_epsilon;
  uint8_t (*sig_pks)[][crypto_sign_PUBLICKEYBYTES];
  uint8_t (*commitment_hashes)[][stp_dkg_commitment_HASHBYTES];
  uint8_t (*share_macs)[][crypto_auth_hmacsha256_BYTES];
  uint8_t (*commitments)[][crypto_core_ristretto255_BYTES];
  uint16_t share_complaints_len;
  uint16_t (*share_complaints)[];
  size_t cheater_len;
  STP_DKG_Cheater (*cheaters)[];
  size_t cheater_max;
  crypto_generichash_state transcript;
} STP_DKG_STPState;

/**
 * @brief Gets the size needed for allocation of a STP_DKG_STPState struct
 *
 * WARNING: if you use this to allocate space for the state struct, it
 * is essential to have this aligned at 32 bytes.
 *
 * @return The size in bytes required for STP_DKG_STPState
 */
size_t stp_dkg_stpstate_size(void);

/**
 * @brief Gets the number of peers (`n`) participating in the protocol
 *        from the STP state
 *
 * @param[in] ctx Pointer to an initialized STP_DKG_STPState struct
 *
 * @return The number of peers (`n`)
 */
uint8_t stp_dkg_stpstate_n(const STP_DKG_STPState *ctx);

/**
 * @brief Gets the threshold (`t`) required for the DKG from the STP state
 *
 * @param[in] ctx Pointer to an initialized STP_DKG_STPState struct
 *
 * @return The threshold value (`t`)
 */
uint8_t stp_dkg_stpstate_t(const STP_DKG_STPState *ctx);

/**
 * @brief Gets the number of cheaters detected in the protocol from
 *        the STP state
 *
 * @param[in] ctx Pointer to an initialized STP_DKG_STPState struct
 *
 * @return The number of cheaters detected (length of the `cheaters` list)
 */
size_t stp_dkg_stpstate_cheater_len(const STP_DKG_STPState *ctx);

/**
 * @brief Gets the session ID associated with the current STP state
 *
 * @param[in] ctx Pointer to an initialized STP_DKG_STPState struct
 *
 * @return Pointer to the session ID buffer
 */
const uint8_t *stp_dkg_stpstate_sessionid(const STP_DKG_STPState *ctx);

/**
 * @brief Gets the current step number in the protocol
 *
 * @param[in] ctx Pointer to an initialized STP_DKG_STPState struct
 *
 * @return The current step as an integer
 */
int stp_dkg_stpstate_step(const STP_DKG_STPState *ctx);

/*
 * Semi-Trusted Party functions
 */

/**
 * @brief Starts a new execution of a STP DKG protocol for the STP
 *
 * This function initializes the state of the STP and creates an
 * initial message containing the parameters for the peers.
 *
 * @param[in] ctx Pointer to a STP_DKG_STPState struct. This struct
 *            will be initialized by this function
 * @param[in] ts_epsilon Maximum allowed message age in seconds before
 *            it is considered stale and rejected. This value is used to
 *            prevent replay attacks and enforce freshness. For small,
 *            local setups (e.g., 2-out-of-3 participants), values as low
 *            as 2–3 seconds may suffice. For large-scale deployments
 *            (e.g., 126-out-of-127), this may need to be increased to
 *            several hours
 * @param[in] n Number of peers participating in this execution
 * @param[in] t Threshold necessary to use the results of this DKG
 * @param[in] proto_name An array of bytes used as a domain separation tag
 *            (DST). Set it to the name of your application
 * @param[in] proto_name_len The size of the array `proto_name`, to allow
 *            non-zero terminated DSTs
 * @param[in] sig_pks Pointer to a (n+1)-element array of signing public
 *            keys. The STP's public key must be at index 0. The rest of the
 *            items must be in order
 * @param[in] ltssk STP’s private long-term signing key
 * @param[in] msg0_len Size of allocated memory for the output message,
 *            `msg0`. Should be exactly `stpvssdkg_msg0_SIZE` long
 * @param[out] msg0 Output parameter, the message to be sent to peers
 *             to initialize them
 *
 * @return 0 on success, non-zero on error
 **/
int stp_dkg_start_stp(STP_DKG_STPState *ctx, const uint64_t ts_epsilon,
                      const uint8_t n, const uint8_t t,
                      const char *proto_name, const size_t proto_name_len,
                      uint8_t (*sig_pks)[][crypto_sign_PUBLICKEYBYTES],
                      const uint8_t ltssk[crypto_sign_SECRETKEYBYTES],
                      const size_t msg0_len, STP_DKG_Message *msg0);

/**
 * @brief Sets all the variable sized buffers in the STP DKG state
 *
 * This function sets all the variable-sized buffers in the STP_DKG_STPState
 * struct. These buffers must be preallocated by the caller, typically on
 * the stack, based on the number of participants `n` and the threshold `t`
 *
 * A number of buffers are needed in the STP state that depend on the `n`
 * (number of participants) and `t` (threshold) parameters.
 * These can be allocated on the stack as follows:
 * @code
 * uint16_t stp_share_complaints[n * n];
 * uint64_t last_ts[n];
 * STP_DKG_Cheater stp_cheaters[t * t - 1];
 * uint8_t tp_commitments_hashes[n][stp_dkg_commitment_HASHBYTES];
 * uint8_t tp_share_macs[n * n][crypto_auth_hmacsha256_BYTES];
 * uint8_t tp_commitments[n * n][crypto_core_ristretto255_BYTES];
 *
 * stp_dkg_stp_set_bufs(&stp,
 *                      &tp_commitments_hashes,
 *                      &tp_share_macs,
 *                      &tp_commitments,
 *                      &stp_share_complaints,
 *                      &stp_cheaters,
 *                      sizeof(stp_cheaters) / sizeof(STP_DKG_Cheater),
 *                      last_ts);
 * @endcode
 *
 * @param[in] ctx Pointer to the STP_DKG_STPState structure being
 *                initialized
 * @param[in] commitment_hashes Pointer to a list of DKG commitment hashes
 * @param[in] share_macs Pointer to a list of Hash-based Message
 *            Authentication Codes (HMACs) for encrypted shares
 * @param[in] commitments Pointer to a list of curve points representing
 *            commitments
 * @param[in] share_complaints Pointer to a list of share complaint flags
 * @param[in] cheaters List of detected cheaters and protocol violators at
 *            the end of a failed protocol run
 * @param[in] cheater_max Maximum number of cheat attempts to be recorded.
 *            Normally, the maximum number of cheaters is `t * t - 1`, where
 *            `t` is the threshold parameter. It should be provided as
 *            (sizeof(cheaters) / sizeof(TP_DKG_Cheater))
 * @param[in] last_ts Pointer to a list of last timestamps
 */
void stp_dkg_stp_set_bufs(STP_DKG_STPState *ctx,
                          uint8_t (*commitment_hashes)[][stp_dkg_commitment_HASHBYTES],
                          uint8_t (*share_macs)[][crypto_auth_hmacsha256_BYTES],
                          uint8_t (*commitments)[][crypto_core_ristretto255_BYTES],
                          uint16_t (*share_complaints)[],
                          STP_DKG_Cheater (*cheaters)[], const size_t cheater_max,
                          uint64_t *last_ts);

/**
 * @brief Enum representing the steps of the STP DKG peer state engine
 *
 * Each value corresponds to a stage in the peer-side execution of the
 * STP DKG protocol. The protocol transitions between these states as
 * messages are received and processed.
 */
typedef enum {
  STP_DKG_Peer_Broadcast_NPK_SIDNonce,
  STP_DKG_Peer_Rcv_NPK_SIDNonce,
  STP_DKG_Peer_Noise_Handshake,
  STP_DKG_Peer_Finish_Noise_Handshake,
  STP_DKG_Peer_Rcv_Commitments_Send_Commitments,
  STP_DKG_Peer_Rcv_Commitments_Send_Shares,
  STP_DKG_Peer_Verify_Commitments,
  STP_DKG_Peer_Handle_DKG_Complaints,
  STP_DKG_Peer_Defend_DKG_Accusations,
  STP_DKG_Peer_Check_Shares,
  STP_DKG_Peer_Finish_DKG,
  STP_DKG_Peer_Confirm_Transcripts,
  STP_DKG_Peer_Done
} STP_DKG_Peer_Steps;

/**
 * @brief Callback type for loading the corresponding long-term signing
 *        public keys and Noise_XK public keys of a peer
 *
 * The user of this API may provide a callback function that gets called
 * when processing the first message by a peer to look up the long-term
 * signing key and Noise_XK key for a given peer ID.
 *
 * @param[in] id  Peer ID
 * @param[in] arg A void pointer to some argument stored in the peers state
 *            context. This can be set during `stp_dkg_peer_set_bufs()`
 * @param[out] sigpk Buffer to fill with the peer's long-term signing public
 *             key
 * @param[out] noise_pk Buffer to fill with the peer's long-term noise
 *             public key
 *
 * @return 0 on success, non-zero on error
 */
typedef int (*Keyloader_CB)(const uint8_t id[crypto_generichash_BYTES],
                            void *arg,
                            uint8_t sigpk[crypto_sign_PUBLICKEYBYTES],
                            uint8_t noise_pk[crypto_scalarmult_BYTES]);

/**
 * @struct STP_DKG_PeerState
 * @brief Struct representing the state of a peer during STP DKG execution
 *
 * This struct contains the state of a peer during the execution of the
 * protocol.
 * Some fields in this struct are internal variables and should not
 * be used. The following fields are useful and can be accessed by
 * users of the API:
 *
 * @var STP_DKG_PeerState::n Total number of peers participating in the
 *      DKG session
 *
 * @var STP_DKG_PeerState::t The threshold, the minimum number of peers
 *      required to use the shared secret generated by this DKG generated
 *      by this DKG
 *
 * @var STP_DKG_PeerState::index Index of this peer (1-based). This value
 *      is between 1 to `n` inclusive
 *
 * @var STP_DKG_PeerState::peerids Pointer to a list of `n` items,
 *      containing the hashes of all peers long-term signing keys
 *
 * @var STP_DKG_PeerState::sig_pks Pointer to a list of `n` items,
 *      containing the long-term signing public keys of all peers
 *
 * @var STP_DKG_PeerState::peer_noise_pks Pointer to a list of `n` items
 *      containing the Noise_XK public keys of all peers
 *
 * @var STP_DKG_PeerState::share Resulting secret share output of the DKG for
 *      a peer. This value should probably be persisted for later usage
 *
 * @var STP_DKG_PeerState::cheaters List of detected cheaters and protocol
 *      violators at the end of a failed protocol run
 *
 * @var STP_DKG_PeerState::cheater_len Length of the `cheaters` list
 */
typedef struct {
  uint8_t (*peerids)[][crypto_generichash_BYTES];
  STP_DKG_Peer_Steps step;
  STP_DKG_Peer_Steps prev;
  uint8_t sessionid[dkg_sessionid_SIZE];
  uint8_t n;
  uint8_t t;
  uint8_t index;
  Keyloader_CB keyloader_cb;
  void *keyloader_cb_arg;
  uint8_t sig_pk[crypto_sign_PUBLICKEYBYTES];
  uint8_t sig_sk[crypto_sign_SECRETKEYBYTES];
  uint8_t stp_sig_pk[crypto_sign_PUBLICKEYBYTES];
  uint8_t noise_pk[crypto_scalarmult_BYTES];
  uint8_t noise_sk[crypto_scalarmult_SCALARBYTES];
  uint64_t stp_last_ts;
  uint64_t *last_ts;
  uint64_t ts_epsilon;
  uint8_t (*sig_pks)[][crypto_sign_PUBLICKEYBYTES];
  uint8_t (*peer_noise_pks)[][crypto_scalarmult_BYTES];
  Noise_XK_device_t *dev;
  Noise_XK_session_t *(*noise_outs)[];
  Noise_XK_session_t *(*noise_ins)[];
  TOPRF_Share (*k_shares)[][2];
  uint8_t (*encrypted_shares)[][noise_xk_handshake3_SIZE + stp_dkg_encrypted_share_SIZE];
  uint8_t (*share_macs)[][crypto_auth_hmacsha256_BYTES];
  uint8_t (*ki_commitments)[][crypto_core_ristretto255_BYTES];
  uint8_t (*k_commitments)[][crypto_core_ristretto255_BYTES];
  uint8_t (*commitments_hashes)[][stp_dkg_commitment_HASHBYTES];
  uint16_t share_complaints_len;
  uint16_t *share_complaints;
  uint8_t my_share_complaints_len;
  uint8_t *my_share_complaints;
  uint8_t k_commitment[crypto_core_ristretto255_BYTES];
  size_t cheater_len;
  STP_DKG_Cheater (*cheaters)[];
  size_t cheater_max;
  crypto_generichash_state transcript;
  uint8_t final_transcript[crypto_generichash_BYTES];
  TOPRF_Share share[2];
} STP_DKG_PeerState;

/**
 * @brief Gets the size needed for allocation of a STP_DKG_PeerState struct
 *
 * WARNING: if you use this to allocate space for the state struct, it
 * is essential to have this aligned at 32 bytes.
 *
 * @return Size in bytes of STP_DKG_PeerState
 */
size_t stp_dkg_peerstate_size(void);

/**
 * @brief Gets the total number of peers in the DKG
 *
 * @param[in] ctx Pointer to the peer state
 *
 * @return The total number of peers (`n`)
 */
uint8_t stp_dkg_peerstate_n(const STP_DKG_PeerState *ctx);

/**
 * @brief Gets the threshold value used in the DKG
 *
 * @param[in] ctx Pointer to the peer state
 *
 * @return The threshold value (`t`)
 */
uint8_t stp_dkg_peerstate_t(const STP_DKG_PeerState *ctx);

/**
 * @brief Gets the session ID for this DKG execution
 *
 * @param[in] ctx Pointer to the peer state
 *
 * @return Pointer to a buffer containing the session ID.
 */
const uint8_t *stp_dkg_peerstate_sessionid(const STP_DKG_PeerState *ctx);

/**
 * @brief Gets the long-term signing secret key of the local peer
 *
 * @param[in] ctx Pointer to the peer state
 *
 * @return Pointer to the secret key buffer
 */
const uint8_t *stp_dkg_peerstate_lt_sk(const STP_DKG_PeerState *ctx);

/**
 * @brief Gets the DKG output share of the local peer
 *
 * @param[in] ctx Pointer to the peer state
 *
 * @return Pointer to the share buffer
 */
const uint8_t *stp_dkg_peerstate_share(const STP_DKG_PeerState *ctx);

/**
 * @brief Gets for the commitments of the generated shares result of this
 *        protocol
 *
 * @param[in] ctx Pointer to the peer state
 *
 * @return Pointer to the commitments of the generated shares result
 */
const uint8_t *stp_dkg_peerstate_commitments(const STP_DKG_PeerState *ctx);

/**
 * @brief Gets the current step of the peer in the DKG protocol
 *
 * @param[in] ctx Pointer to the peer state
 *
 * @return The current `STP_DKG_Peer_Steps` enum value
 */
int stp_dkg_peerstate_step(const STP_DKG_PeerState *ctx);

/*
 * Peer functions
 */

/**
 * @brief Starts a new execution of a STP DKG protocol for a peer
 *
 * Initializes the internal state of a peer participating in the protocol,
 * using the message received from the STP initiator (`msg0`). It sets up
 * the protocol context, extracts relevant information from `msg0`, verifies
 * freshness and structure, and begins the transcript for future protocol
 * messages.
 *
 * @param[out] ctx Pointer to a STP_DKG_PeerState struct. This struct
 *            will be initialized by this function
 * @param[in] ts_epsilon Maximum allowed message age in seconds before
 *            it is considered stale and rejected. This value is used to
 *            prevent replay attacks and enforce freshness. For small,
 *            local setups (e.g., 2-out-of-3 participants), values as low
 *            as 2–3 seconds may suffice. For large-scale deployments
 *            (e.g., 126-out-of-127), this may need to be increased to
 *            several hours
 * @param[in] lt_sk The long-term private signing secret key of the peer
 * @param[in] noise_sks The long-term Noise_XK protocol secret key of the
 *            peer
 * @param[in] msg0 The initiating message received from the STP (created
 *            after running `stp_dkg_start_stp()`)
 * @param[out] stp_ltpk Output buffer where the STP's long-term public
 *             signing key is copied. It should be used to verify if this
 *             key is actually authorized to initiate an STP DKG with the
 *             peer
 *
 * @return 0 on success, non-zero on error
 */
STP_DKG_Err stp_dkg_start_peer(STP_DKG_PeerState *ctx,
                               const uint64_t ts_epsilon,
                               const uint8_t lt_sk[crypto_sign_SECRETKEYBYTES],
                               const uint8_t noise_sks[crypto_scalarmult_SCALARBYTES],
                               const STP_DKG_Message *msg0,
                               uint8_t stp_ltpk[crypto_sign_PUBLICKEYBYTES]);

/**
 * @brief Sets all variable-sized buffers in the STP_DKG_STPState structure
 *
 * The buffer sizes depend on the `n` and `t` parameters of the DKG
 * protocol, which could be known in advance. If not, these parameters
 * are announced by the TP in `msg0`, which is an input to the
 * `stp_dkg_start_peer()` function. After this `stp_dkg_start_peer()` call,
 * the peer state is initialized and can be used to find out the `n` and
 * `t` parameters.
 *
 * To allocate all the buffers on the stack:
 * @code
 * STP_DKG_PeerState ctx;
 * stp_dkg_start_peer(&ctx,....);
 * const uint8_t n = ctx->n;
 * const uint8_t t = ctx->t;
 *
 * uint8_t peerids[n][crypto_generichash_BYTES];
 * Noise_XK_session_t *noise_outs[n];
 * Noise_XK_session_t *noise_ins[n];
 * TOPRF_Share dealer_shares[n][2];
 * uint8_t encrypted_shares[n][noise_xk_handshake3_SIZE + stp_dkg_encrypted_share_SIZE];
 * uint8_t dealer_commitments[n*n][crypto_core_ristretto255_BYTES];
 * uint8_t share_macs[n][n*n][crypto_auth_hmacsha256_BYTES];
 * uint8_t peer_k_commitments[n][crypto_core_ristretto255_BYTES];
 * uint8_t commitments_hashes[n][stp_dkg_commitment_HASHBYTES];
 * uint16_t peer_dealer_share_complaints[n*n];
 * uint8_t peer_my_dealer_share_complaints[n];
 * uint64_t peer_last_ts[n];
 * STP_DKG_Cheater peer_cheaters[t*t - 1];
 * if(0!=stp_dkg_peer_set_bufs(&peer, &peerids,
 *                           &keyloader_cb, &cb_arg,
 *                           &lt_pks,
 *                           &peers_noise_pks,
 *                           &noise_outs, &noise_ins,
 *                           &dealer_shares,
 *                           &encrypted_shares,
 *                           &share_macs,
 *                           &dealer_commitments,
 *                           &peer_k_commitments,
 *                           &commitments_hashes,
 *                           &peer_cheaters, sizeof(peer_cheaters) / sizeof(STP_DKG_Cheater) / n,
 *                           peer_dealer_share_complaints,
 *                           peer_my_dealer_share_complaints,
 *                           peer_last_ts)) return 1;
 * @endcode
 *
 *
 * TODO document the missing parameters
 *
 * @param[in] ctx Pointer to the STP_DKG_STPState structure being
 *                initialized
 * @param[in] commitment_hashes Pointer to a list of DKG commitment hashes
 * @param[in] share_macs Pointer to a list of Hash-based Message
 *            Authentication Codes (HMACs) for encrypted shares
 * @param[in] commitments Pointer to a list of curve points representing
 *            commitments
 * @param[in] share_complaints Pointer to a list of share complaint flags
 * @param[in] cheaters List of detected cheaters and protocol violators at
 *            the end of a failed protocol run
 * @param[in] cheater_max Maximum number of cheat attempts to be recorded.
 *            Normally, the maximum number of cheaters is `t * t - 1`, where
 *            `t` is the threshold parameter. It should be provided as
 *            (sizeof(cheaters) / sizeof(TP_DKG_Cheater))
 * @param[in] last_ts Pointer to a list of last timestamps for each peer
 */
int stp_dkg_peer_set_bufs(STP_DKG_PeerState *ctx,
                          uint8_t (*peerids)[][crypto_generichash_BYTES],
                          Keyloader_CB keyloader_cb,
                          void *keyloader_cb_arg,
                          uint8_t (*peers_sig_pks)[][crypto_sign_PUBLICKEYBYTES],
                          uint8_t (*peers_noise_pks)[][crypto_scalarmult_BYTES],
                          Noise_XK_session_t *(*noise_outs)[],
                          Noise_XK_session_t *(*noise_ins)[],
                          TOPRF_Share (*k_shares)[][2],
                          uint8_t (*encrypted_shares)[][noise_xk_handshake3_SIZE + stp_dkg_encrypted_share_SIZE],
                          uint8_t (*share_macs)[][crypto_auth_hmacsha256_BYTES],
                          uint8_t (*ki_commitments)[][crypto_core_ristretto255_BYTES],
                          uint8_t (*k_commitments)[][crypto_core_ristretto255_BYTES],
                          uint8_t (*commitments_hashes)[][stp_dkg_commitment_HASHBYTES],
                          STP_DKG_Cheater (*cheaters)[], const size_t cheater_max,
                          uint16_t *share_complaints,
                          uint8_t *my_share_complaints,
                          uint64_t *last_ts);

/**
 * @brief Calculates the size of the buffer needed to hold all peer
 *        outputs for the next STP step
 *
 * This function determines the total size required to collect all
 * peer messages that will be used as input for the next step of the
 * STP in the DKG protocol.
 *
 * An implementer should allocate a buffer of this size and concatenate
 * all messages from all peers in the order of the peers' indices.
 * The allocated buffer is to be passed as an input  `stp_dkg_stp_next()`.
 * After this, the buffer SHOULD be deallocated.
 *
 * @param[in] ctx An initialized STP_DKG_STPState struct
 *
 * @return 1 on error, otherwise the size to be allocated (can be 0)
 */
size_t stp_dkg_stp_input_size(const STP_DKG_STPState *ctx);

/**
 * @brief Calculates the size of the message from each peer to be
 *        received by the STP
 *
 * Fills a list with the expected message size from each peer for the
 * current step. If all peers send messages of equal size, returns 0
 * and fills all entries with the same value. Otherwise, returns 1 and
 * fills each entry with the corresponding peer's message size.
 *
 * @param[in] ctx An initialized STP_DKG_STPState struct
 * @param[out] sizes Array of size_t with exactly `n` elements to be filled
 *             with message sizes
 *
 * @return  0 on if the sizes differ from peer to peer, otherwise all peers
 *          will be sending messages of equal size. In the latter case, all
 *          items of the `sizes` array hold the same valid value.
 */
int stp_dkg_stp_input_sizes(const STP_DKG_STPState *ctx, size_t *sizes);

/**
 * @brief Calculates the size of the buffer needed to hold the output from
 *        the `stp_dkg_stp_next()` function
 *
 * Determines the buffer size required to hold the output of
 * `stp_dkg_stp_next()` for the current protocol step.
 * An implementer should allocate a buffer of this size and pass it as the
 * `output` parameter to `stp_dkg_stp_next()`.
 *
 * @param[in] ctx An initialized STP_DKG_STPState struct
 *
 * @return 1 on error, otherwise the size to be allocated (can be 0)
 */
size_t stp_dkg_stp_output_size(const STP_DKG_STPState *ctx);

/**
 * @brief Executes the next step of the STP DKG protocol for the STP
 *
 * Processes the current protocol step using the provided input buffer
 * and writes the result to the output buffer. Then, it advances the
 * protocol state.
 *
 * This is an example of how to use this function in concert with
 * `stp_dkg_stp_input_size()` and `stp_dkg_stp_output_size()`:
 * @code
 *   uint8_t stp_out[stp_dkg_stp_output_size(&tp)];
 *   uint8_t stp_in[stp_dkg_stp_input_size(&tp)];
 *   recv(socket, stp_in, sizeof(stp_in));
 *   int ret = stp_dkg_stp_next(&tp, stp_in, sizeof(stp_in), stp_out, sizeof(stp_out));
 * @endcode
 *
 * @param[in] ctx Pointer to a valid STP_DKG_STPState
 * @param[in] input Buffer containing input data for the current step
 * @param[in] input_len Size of the input buffer
 * @param[out] output Buffer to receive the output of the current step
 * @param[in] output_len Size of the output buffer
 *
 * @return 0 on success, non-zero on error
 */
int stp_dkg_stp_next(STP_DKG_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len);

/**
 * @brief Extracts the message for a specific peer from the STP's
 *        output buffer
 *
 * This function converts the output of `stp_dkg_stp_next()` into a message
 * to be sent to the i-th peer.
 * Depending on the current STP step, the
 * output may be a broadcast (same messages to all) or dedicated and
 * unique messages for each peer.
 * This function returns a pointer to a message and the size of the message
 * to be sent for a particular peer specified as a parameter.
 *
 * This is an example of how to use this function in concert with
 * `stp_dkg_stp_next()`:
 * @code
 *   ret = stp_dkg_stp_next(&tp, tp_in, sizeof(tp_in), tp_out, sizeof(tp_out));
 *   for (int i = 0; i < tp.n; i++) {
 *     const uint8_t *msg;
 *     size_t len;
 *     if (0 != stp_dkg_stp_peer_msg(&tp, tp_out, sizeof(tp_out), i, &msg, &len)) {
 *       return 1;
 *     }
 *     send(i, msg, len);
 *   }
 * @endcode
 *
 * @param[in] ctx Pointer to a valid STP_DKG_STPState
 * @param[in] base Pointer to the output buffer from `stp_dkg_stp_next()`
 * @param[in] base_size Size of the output buffer of `stp_dkg_stp_next()`
 * @param[in] peer Index of the peer (0-based)
 * @param[out] msg Pointer to the message to be sent to the i-th peer
 * @param[out] len Pointer to the length of the message to be sent to the
 *             i-th peer
 *
 * @return 0 on success, non-zero on error
 */
int stp_dkg_stp_peer_msg(const STP_DKG_STPState *ctx, const uint8_t *base, const size_t base_size, const uint8_t peer, const uint8_t **msg, size_t *len);

/**
 * @brief Checks if the STP protocol has more steps to execute or more
 * `stp_dkg_stp_next()` calls are necessary
 *
 * @param[in] stp Pointer to the STP_DKG_STPState
 *
 * @return 1 if more steps are outstanding
 */
int stp_dkg_stp_not_done(const STP_DKG_STPState *stp);

/**
 * @brief Converts a cheater object to a human-readable string
 *
 * This function takes a STP_DKG_Cheater object (produced when cheating
 * behavior is detected) and formats a descriptive string explaining the
 * nature of the cheating incident.
 *
 * This variant is used for cheater objects created by STP
 *
 * @param[in] c Pointer to the cheater object
 * @param[out] out Pointer to the pre-allocated buffer to receive the
 *             formatted string
 * @param[in] outlen Size of the output buffer
 *
 * @return The index of the cheating peer
 */
uint8_t stp_dkg_stp_cheater_msg(const STP_DKG_Cheater *c, char *out, const size_t outlen);

/**
 * @brief Computes the size of the input buffer required for the next
 *        call to `stp_dkg_peer_next()`
 *
 * This function calculates how much memory the caller needs to allocate
 * for the buffer that will be passed as input to `stp_dkg_peer_next()`.
 * An implementer should allocate a buffer of this size.
 * The allocated buffer is to be passed as an input to the
 * `stp_dkg_peer_next()` function. After this, the buffer SHOULD be
 * deallocated.
 *
 * @param[in] ctx An initialized STP_DKG_PeerState struct
 *
 * @return 1 on error, otherwise the size to be allocated (can be 0)
 */
size_t stp_dkg_peer_input_size(const STP_DKG_PeerState *ctx);

/**
 * @brief Calculates the size of the buffer needed to hold the output
 *        from the `stp_dkg_peer_next()` function
 *
 * An implementer should allocate a buffer of this size and pass it as
 * the `output` parameter to `stp_dkg_peer_next()`.
 * for the next protocol step.
 *
 * @param[in] ctx An initialized STP_DKG_PeerState struct
 *
 * @return 1 on error, otherwise the size to be allocated (can be 0)
 */
size_t stp_dkg_peer_output_size(const STP_DKG_PeerState *ctx);

/**
 * @brief Executes the next step of the STP DKG protocol for a peer
 *
 * Processes the current protocol step for the peer using the provided
 * input buffer, writes the result to the output buffer, and advances the
 * protocol state.
 *
 * This is an example of how to use this function in concert with
 * `stp_dkg_peer_input_size()` and `stp_dkg_peer_output_size()` while
 * allocating the buffers on the stack:
 * @code
 *  uint8_t peers_out[stp_dkg_peer_output_size(&peer)];
 *
 * uint8_t peer_in[stp_dkg_peer_input_size(&peer)];
 * recv(socket, peer_in, sizeof(peer_in));
 * ret = stp_dkg_peer_next(&peer,
 *                         peer_in, sizeof(peer_in),
 *                         peers_out, sizeof(peers_out));
 * @endcode
 *
 * @param[in] ctx Pointer to a valid STP_DKG_PeerState
 * @param[in] input Buffer containing input data for the current step
 * @param[in] input_len Size of the input buffer
 * @param[out] output Buffer to receive the output of the current step
 * @param[in] output_len Size of the output buffer
 *
 * @return 0 on success, non-zero on error
 */
int stp_dkg_peer_next(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len);

/**
 * @brief Checks if the peer protocol has more steps to execute
 *
 * This function checks if more steps are outstanding and further
 * calls to `stp_dkg_peer_next()` are necessary or if the protocol is
 * finished for this peer.
 *
 * @param[in] peer Pointer to the STP_DKG_PeerState
 * @return 1 if more steps are outstanding
 */
int stp_dkg_peer_not_done(const STP_DKG_PeerState *peer);

/**
 * @brief Frees all resources allocated by the peer state
 *
 * This function MUST be called before a peer's state is deallocated.
 * The underlying Noise_XK implementation allocates a lot of internal
 * state on the heap, which must be freed manually to avoid memory leaks.
 *
 * @param[in] ctx Pointer to the STP_DKG_PeerState to be freed
 */
void stp_dkg_peer_free(STP_DKG_PeerState *ctx);

/**
 * @brief Converts a cheater object to a human readable string
 *
 * Use this variant for cheater objects created by a peer.
 *
 * @param[in] c Pointer to the cheater object
 * @param[out] out Pointer to the pre-allocated buffer receiving the string
 * @param[in] outlen Size of the pre-allocated buffer
 *
 * @return The index of the cheating peer, or 0 if undetermined
 */
uint8_t stp_dkg_peer_cheater_msg(const STP_DKG_Cheater *c, char *out, const size_t outlen);

extern FILE* log_file;

#endif //STP_DKG_H
