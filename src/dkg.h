#ifndef DKG_H
#define DKG_H

/**
 * @file dkg.h
 * @brief API for the Distributed Key Generation (DKG) protocol
 *
 * SPDX-FileCopyrightText: 2025, Marsiske Stefan
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * 
 * @warning This is a low-level interface. Do not use directly unless
 * you use it to implement DKG protocols which have proper sessionids
 * and other protections against replay and confused deputy attacks.
 *
 * For an example of a high-level DKG protocol, see tp-dkg.[ch]
 *
 * This library provides the core cryptographic operations for implementing
 * a secure Distributed Key Generation protocol. In DKG, a group of participants
 * jointly generate a cryptographic key without any single party knowing the
 * complete key. Each participant receives a share of the key, and a threshold
 * of these shares is required to perform operations with the key.
 *
 * The library also uses the Noise_XK handshake pattern
 * (https://noiseexplorer.com/patterns/XK/) to establish a secure
 * communication channel between participants.
 **/

#include <sodium.h>
#include <stdint.h>
#include "XK.h"
#include "toprf.h"

#define dkg_hash_BYTES crypto_generichash_BYTES
#define dkg_commitment_BYTES(threshold) (threshold * crypto_core_ristretto255_BYTES)

/** @struct DKG_Cheater

    This struct communicates one detected violation of the protocol.

    @var DKG_Cheater::step The step in which the violation occurred
    @var DKG_Cheater::error The error code specifying the violation
    @var DKG_Cheater::peer The peer that caused the violation
    @var DKG_Cheater::other_peer Optionally the peer that reported the
         violation (set to 0xfe if unused)
    @var DKG_Cheater::invalid_index
 */
typedef struct
{
     int step;
     int error;
     uint8_t peer;
     uint8_t other_peer;
     int invalid_index;
} DKG_Cheater;

/**
 * @brief Evaluates a polynomial at a given point
 *
 * Evaluates a polynomial defined by coefficients in array `a` at point `j`.
 * It is used in the DKG protocol for share generation. The result is stored
 * as a share.
 *
 * @param[in] j The index at which to evaluate the polynomial
 * @param[in] threshold The number of coefficients
 * @param[in] a Array of coefficients defining the polynomial
 * @param[out] result The resulting share containing the polynomial
 *             evaluation at `j`
 */
void polynom(const uint8_t j, const uint8_t threshold,
             const uint8_t a[threshold][crypto_core_ristretto255_SCALARBYTES],
             TOPRF_Share *result);

/**
 * @brief Initiates the first step in the DKG protocol
 *
 * Generates polynomial coefficients, calculates commitments, and creates
 * shares for all participants. Each peer should execute this function
 * at the start of the DKG protocol.
 *
 * @param[in] n The number of peers participating in the DKG
 * @param[in] threshold The minimum number of shares needed to reconstruct
 *            the secret (must be greater 1 and less than `n`)
 * @param[out] commitments Array of commitments to be broadcast to all
 *             peers. NOTE: in this scheme the commitments are to the
 *             coefficients of the polynomial.
 * @param[out] shares Array of `n` shares, one for each peer, to be sent
 *             privately to each peer after receiving all of the commitment
 *             broadcasts
 *
 * @return 0 on success, non-zero on error
 */
int dkg_start(const uint8_t n,
              const uint8_t threshold,
              uint8_t commitments[threshold][crypto_core_ristretto255_BYTES],
              TOPRF_Share shares[n]);

/**
 * @brief Verifies a commitment from a specific peer
 *
 * Validates that a received share matches the corresponding commitment
 * from a specific peer.
 *
 * @param[in] n The number of peers participating in the DKG
 * @param[in] threshold The minimum number of shares needed to reconstruct
 *            the secret
 * @param[in] self The index of the current peer (1-based)
 * @param[in] i The index of the peer whose commitment is being verified
 *            (1-based)
 * @param[in] commitments The commitments from peer `i`
 * @param[in] share The share received from peer `i`
 *
 * @return 0 if the commitment is valid, non-zero otherwise
 */
int dkg_verify_commitment(const uint8_t n,
                          const uint8_t threshold,
                          const uint8_t self,
                          const uint8_t i,
                          const uint8_t commitments[threshold][crypto_core_ristretto255_BYTES],
                          const TOPRF_Share share);

/**
 * @brief Verifies commitments from all peers
 *
 * Validates that all received shares match their corresponding commitments
 * from all peers. It collects IDs of participants whose shares are invalid.
 *
 * @param[in] n The number of peers participating in the DKG
 * @param[in] threshold The minimum number of shares needed to reconstruct
 *            the secret
 * @param[in] self The index of the current peer (1-based)
 * @param[in] commitments Array of commitments from all peers
 * @param[in] shares Array of shares received from all peers
 * @param[out] fails Array to hold IDs of peers whose shares failed
 *             verification
 * @param[out] fails_len Number of peers whose shares failed
 *
 * @return 0 if all shares are valid, non-zero otherwise
 */
int dkg_verify_commitments(const uint8_t n,
                           const uint8_t threshold,
                           const uint8_t self,
                           const uint8_t commitments[n][threshold][crypto_core_ristretto255_BYTES],
                           const TOPRF_Share shares[n],
                           uint8_t fails[n],
                           uint8_t *fails_len);

/**
 * @brief Finalizes the DKG protocol for a peer
 *
 * Combines the shares received from all peers to compute the final
 * secret share for this peer.
 *
 * @param[in] n The number of peers participating in the DKG
 * @param[in] shares Array of shares addressed to this peer received
 *            from all peers
 * @param[in] self The index of the current peer (1-based)
 * @param[out] xi Final computed secret share for this peer
 *
 * @return 0 on success, non-zero on error
 */
int dkg_finish(const uint8_t n,
               const TOPRF_Share shares[n],
               const uint8_t self,
               TOPRF_Share *xi);

/**
 * @brief Reconstructs the shared secret from a set of shares
 *
 * Combines shares into the group secret. This is used in the final
 * phase of DKG, where a threshold of participants collaborate to
 * recover the secret.
 *
 * @param[in] threshold the threshold of the sharing
 * @param[in] shares Array of participant shares used in reconstruction
 * @param[out] secret Output buffer to store the reconstructed secret
 */
void dkg_reconstruct(const size_t threshold,
                     const TOPRF_Share shares[threshold],
                     uint8_t secret[crypto_scalarmult_ristretto255_SCALARBYTES]);

#define dkg_freshness_TIMEOUT 120000

#define noise_xk_handshake1_SIZE 48UL
#define noise_xk_handshake2_SIZE 48UL
#define noise_xk_handshake3_SIZE 64UL
#define dkg_noise_key_SIZE 32UL
#define dkg_sessionid_SIZE 32U
#define dkg_max_err_SIZE 128

/** @struct DKG_Message This is the header for messages sent in higher
    level instantiations of DKG/MPC protocols in liboprf

    @var DKG_Message::sig Signature over the message header and the
         message body

    @var DKG_Message::type Message type identifier

    @var DKG_Message::version Protocol version

    @var DKG_Message::msgno The "type" of this message, which is strictly
         tied to the current step of the protocol

    @var DKG_Message::len Length of the complete message, including the header

    @var DKG_Message::from Sender ID (0 for STP, otherwise the peer index)

    @var DKG_Message::to Recipient of the message (0 for STP, 0xff for
          broadcast, all other values <= `n` are the indices of the peers)

    @var DKG_Message::ts Timestamp proving the freshness of the message.
         The timestamp is a 64 bit value counting seconds since 1970-01-01

    @var DKG_Message::sessionid Unique session identifier

    @var STP_DKG_Message::data The payload of the message

 */
typedef struct
{
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

#define MSG_TYPE_DKG 0
#define MSG_TYPE_UPDATE 1
#define MSG_TYPE_SEMI_TRUSTED (1 << 7)
#define MSG_TYPE_TRUSTED (0 << 7)

/**
 * @brief Validates message timestamp for freshness
 *
 * If `last_ts` is 0, compares `ts` to the current system time with an
 * allowed epsilon. Otherwise, checks monotonically increasing timestamps
 * within a window of `ts_epsilon`.
 *
 * @param[in] ts_epsilon Maximum allowed time difference in seconds
 * @param[in,out] last_ts Pointer to the last seen timestamp
 * @param[in] ts The timestamp to check
 *
 * @return 0 if timestamp is valid, non-zero otherwise
 */
int check_ts(const uint64_t ts_epsilon, uint64_t *last_ts, const uint64_t ts);

/**
 * @brief Creates and signs a protocol message
 *
 * Populates a `DKG_Message` structure and signs it using the provided
 * signing key. Used to exchange protocol messages between participants
 * securely.
 *
 * @param[out] msg_buf Pointer to the buffer to fill with the message header
 * @param[in] msg_buf_len Size of the message buffer
 * @param[in] type Message type
 * @param[in] version Protocol version
 * @param[in] msgno Message sequence number
 * @param[in] from Sender ID
 * @param[in] to Recipient ID
 * @param[in] sig_sk Signing key
 * @param[in] sessionid Session identifier
 *
 * @return 0 on success, non-zero on error
 */
int send_msg(uint8_t *msg_buf, const size_t msg_buf_len, const uint8_t type, const uint8_t version, const uint8_t msgno, const uint8_t from, const uint8_t to, const uint8_t *sig_sk, const uint8_t sessionid[dkg_sessionid_SIZE]);

/**
 * @brief Receives, validates, and verifies a DKG protocol message
 *
 * Performs multiple checks: type, version, size, sequence numbers,
 * session ID, timestamp validation, and signature verification.
 *
 * @param[in] msg_buf Buffer containing the received message
 * @param[in] msg_buf_len Size of the message buffer
 * @param[in] type Expected message type
 * @param[in] version Expected protocol version
 * @param[in] msgno Expected message number
 * @param[in] from Expected sender ID
 * @param[in] to Expected recipient ID
 * @param[in] sig_pk Sender's public signing key
 * @param[in] sessionid Expected session identifier
 * @param[in] ts_epsilon Maximum allowed time difference in seconds
 * @param[in,out] last_ts Pointer to the last accepted timestamp
 *
 * @return 0 if message is valid, non-zero otherwise
 */
int recv_msg(const uint8_t *msg_buf, const size_t msg_buf_len, const uint8_t type, const uint8_t version, const uint8_t msgno, const uint8_t from, const uint8_t to, const uint8_t *sig_pk, const uint8_t sessionid[dkg_sessionid_SIZE], const uint64_t ts_epsilon, uint64_t *last_ts);

/**
 * @brief Initializes a Noise_XK handshake session with a given remote peer
 *
 * Adds the peer to the local Noise_XK context, creates a session as
 * initiator, and generates the first handshake message
 *
 * @param[in] index Index of the current peer
 * @param[in] dev Pointer to the local Noise_XK device
 * @param[in] rpk Remote peer's static public key
 * @param[in] rname Remote peer's name
 * @param[out] session Active Noise_XK session pointer
 * @param[out] msg First handshake message
 *
 * @return 0 on success, non-zero on error
 */
int dkg_init_noise_handshake(const uint8_t index,
                             Noise_XK_device_t *dev,
                             uint8_t rpk[crypto_scalarmult_BYTES],
                             uint8_t *rname,
                             Noise_XK_session_t **session,
                             uint8_t msg[noise_xk_handshake1_SIZE]);

/**
 * @brief Responds to a Noise_XK handshake initiation from a remote peer
 *
 * Processes the first handshake message and produces the second handshake
 * message to send back to the initiator.
 *
 * @param[in] index Peer index
 * @param[in] dev Pointer to the local Noise_XK device
 * @param[in] rname Remote peer's name
 * @param[out] session Active Noise_XK session pointer
 * @param[in] inmsg First handshake message
 * @param[out] outmsg Second handshake message
 *
 * @return 0 on success, non-zero on error
 */
int dkg_respond_noise_handshake(const uint8_t index,
                                Noise_XK_device_t *dev,
                                uint8_t *rname,
                                Noise_XK_session_t **session,
                                uint8_t inmsg[noise_xk_handshake1_SIZE],
                                uint8_t outmsg[noise_xk_handshake2_SIZE]);

/**
 * @brief Completes a Noise_XK handshake
 *
 * Processes the second handshake message and finalizes the handshake.
 *
 * @param[in] index Peer index
 * @param[in] dev Pointer to the local Noise_XK device
 * @param[in,out] session Active Noise_XK session pointer
 * @param[in] msg Second handshake message
 *
 * @return 0 on success, non-zero on error
 */
int dkg_finish_noise_handshake(const uint8_t index,
                               Noise_XK_device_t *dev,
                               Noise_XK_session_t **session,
                               uint8_t msg[noise_xk_handshake2_SIZE]);

/**
 * @brief Encrypts data using a Noise_XK session
 *
 * @param[in] input Data to encrypt
 * @param[in] input_len Length of input data (must be <= 1024)
 * @param[out] output Buffer for encrypted data
 * @param[in] output_len Size of output buffer
 * @param[in,out] session Active Noise_XK session pointer
 *
 * @return 0 on success, non-zero on error
 */
int dkg_noise_encrypt(uint8_t *input,
                      const size_t input_len,
                      uint8_t *output,
                      const size_t output_len,
                      Noise_XK_session_t **session);

/**
 * @brief Decrypts data using a Noise_XK session
 *
 * @param[in] input Encrypted data
 * @param[in] input_len Length of encrypted data
 * @param[out] output Buffer for decrypted data
 * @param[in] output_len Size of output buffer
 * @param[in,out] session Active Noise_XK session pointer
 *
 * @return 0 on success, non-zero on error
 */
int dkg_noise_decrypt(const uint8_t *input,
                      const size_t input_len,
                      uint8_t *output,
                      const size_t output_len,
                      Noise_XK_session_t **session);

/**
 * @brief Gets the current Noise_XK transport key used for
 *        sending or receiving
 *
 * Depending on whether the session is an initiator or responder,
 * this function returns the appropriate session key.
 *
 * @param[in] sn Pointer to the Noise_XK session object
 *
 * @return Pointer to the session key if available, or NULL on error
 */
uint8_t *Noise_XK_session_get_key(const Noise_XK_session_t *sn);

/**
 * @brief Updates the protocol transcript with a new message
 *
 * Adds a message to the transcript hash.
 *
 * @param[in,out] transcript Pointer to the transcript state
 * @param[in] msg Message to add to the transcript
 * @param[in] msg_len Size of the message
 */
void update_transcript(crypto_generichash_state *transcript, const uint8_t *msg, const size_t msg_len);

/**
 * @brief Returns a human-readable error message for a DKG error code returned by the recv_msg() fn
 *
 * Maps integer error codes to descriptive strings
 *
 * @param[in] code The error code
 *
 * @return String containing the error message
 */
char *dkg_recv_err(const int code);

/**
 * @brief Logs metadata and hex dump of a DKG message
 *
 * Prints the message number, size, sender, and recipient to
 * the log file, followed by a hex dump of the full message.
 *
 * @param[in] ptr Pointer to the message buffer
 * @param[in] msglen Size of the message buffer in bytes
 * @param[in] type Message type
 */
void dkg_dump_msg(const uint8_t *ptr, const size_t msglen, const uint8_t type);

#endif // DKG_H
