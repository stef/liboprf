#ifndef STP_DKG_H
#define STP_DKG_H
#include <stdint.h>
#include <sodium.h>
#include "dkg.h"
#include "toprf.h"

#define noise_xk_handshake1_SIZE 48UL
#define noise_xk_handshake2_SIZE 48UL
#define noise_xk_handshake3_SIZE 64UL
#define stp_dkg_noise_key_SIZE (32UL)
#define stp_dkg_sessionid_SIZE 32U
#define toprf_keyid_SIZE 32U
#define stp_dkg_commitment_HASHBYTES 32U
#define stp_dkg_encrypted_share_SIZE (TOPRF_Share_BYTES * 2 + crypto_secretbox_xchacha20poly1305_MACBYTES)

typedef DKG_Message STP_DKG_Message;

// todo refactor this, it's the same in stp-dkg and stp-dkg
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

typedef enum {
  Err_OK = 0,
  Err_ISize,
  Err_OSize,
  Err_OOB,
  Err_Send,
  Err_CheatersFound,
  Err_CheatersFull,
  Err_InvSessionID,
  ErrShare,
  ErrCommit,
  Err_NoiseEncrypt,
  Err_NoiseDecrypt,
  Err_HMac,
  Err_Index,
  Err_NoSubVSPSFail,
  Err_NotEnoughDealers,
  Err_TooManyCheaters,
  Err_DKGFinish,
  Err_BroadcastEnv = 32,
  Err_Env = 64
} STP_DKG_Err;

typedef enum {
  STP_DKG_STP_Send_Index,
  STP_DKG_STP_Broadcast_NPKs,
  STP_DKG_STP_Route_Noise_Handshakes1,
  STP_DKG_STP_Route_Noise_Handshakes2,
  STP_DKG_STP_Broadcast_DGK_Hash_Commitments,
  STP_DKG_STP_Broadcast_DGK_Commitments,
  STP_DKG_STP_Route_Encrypted_Shares,
  STP_DKG_STP_Broadcast_Complaints,
  STP_DKG_STP_Broadcast_DKG_Defenses,
  STP_DKG_STP_Broadcast_DKG_Transcripts,
  STP_DKG_STP_Broadcast_DKG_Final_Commitments,
  STP_DKG_STP_Done
} STP_DKG_STP_Steps;

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
} SSTP_DKG_Message_Type;

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

size_t stp_dkg_stpstate_size(void);
uint8_t stp_dkg_stpstate_n(const STP_DKG_STPState *ctx);
uint8_t stp_dkg_stpstate_t(const STP_DKG_STPState *ctx);
size_t stp_dkg_stpstate_cheater_len(const STP_DKG_STPState *ctx);
const uint8_t* stp_dkg_stpstate_sessionid(const STP_DKG_STPState *ctx);
int stp_dkg_stpstate_step(const STP_DKG_STPState *ctx);

#define stpvssdkg_start_msg_SIZE ( sizeof(STP_DKG_Message)                         \
                               + crypto_generichash_BYTES/*dst*/                      \
                               + 2 /* n&t */                                          \
                               + crypto_sign_PUBLICKEYBYTES                           )

int stp_dkg_start_stp(STP_DKG_STPState *ctx, const uint64_t ts_epsilon,
                           const uint8_t n, const uint8_t t,
                           const char *proto_name, const size_t proto_name_len,
                           uint8_t (*sig_pks)[][crypto_sign_PUBLICKEYBYTES],
                           const uint8_t ltssk[crypto_sign_SECRETKEYBYTES],
                           const size_t msg0_len, STP_DKG_Message *msg0);

void stp_dkg_stp_set_bufs(STP_DKG_STPState *ctx,
                              uint8_t (*commitment_hashes)[][stp_dkg_commitment_HASHBYTES],
                              uint8_t (*share_macs)[][crypto_auth_hmacsha256_BYTES],
                              uint8_t (*commitments)[][crypto_core_ristretto255_BYTES],
                              uint16_t (*share_complaints)[],
                              STP_DKG_Cheater (*cheaters)[], const size_t cheater_max,
                              uint64_t *last_ts);
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

typedef struct {
  uint8_t (*peerids)[][crypto_generichash_BYTES];
  STP_DKG_Peer_Steps step;
  STP_DKG_Peer_Steps prev;
  uint8_t sessionid[dkg_sessionid_SIZE];
  uint8_t n;
  uint8_t t;
  uint8_t index;
  int (*keyloader_cb)(const uint8_t id[crypto_generichash_BYTES], void *arg, uint8_t sigpk[crypto_sign_PUBLICKEYBYTES], uint8_t noise_pk[crypto_scalarmult_BYTES]);
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
  TOPRF_Share k_share[2];
  uint8_t k_commitment[crypto_core_ristretto255_BYTES];
  size_t cheater_len;
  STP_DKG_Cheater (*cheaters)[];
  size_t cheater_max;
  crypto_generichash_state transcript;
  uint8_t final_transcript[crypto_generichash_BYTES];
  TOPRF_Share share;
} STP_DKG_PeerState;

size_t stp_dkg_peerstate_size(void);
uint8_t stp_dkg_peerstate_n(const STP_DKG_PeerState *ctx);
uint8_t stp_dkg_peerstate_t(const STP_DKG_PeerState *ctx);
const uint8_t* stp_dkg_peerstate_sessionid(const STP_DKG_PeerState *ctx);
const uint8_t* stp_dkg_peerstate_lt_sk(const STP_DKG_PeerState *ctx);
const uint8_t* stp_dkg_peerstate_share(const STP_DKG_PeerState *ctx);
int stp_dkg_peerstate_step(const STP_DKG_PeerState *ctx);

STP_DKG_Err stp_dkg_start_peer(STP_DKG_PeerState *ctx,
                                         const uint64_t ts_epsilon,
                                         const uint8_t lt_sk[crypto_sign_SECRETKEYBYTES],
                                         const STP_DKG_Message *msg0,
                                         uint8_t stp_ltpk[crypto_sign_PUBLICKEYBYTES]);

int stp_dkg_peer_set_bufs(STP_DKG_PeerState *ctx,
                              uint8_t (*peerids)[][crypto_generichash_BYTES],
                              int (*keyloader_cb)(const uint8_t id[crypto_generichash_BYTES], void *arg, uint8_t sigpk[crypto_sign_PUBLICKEYBYTES], uint8_t noise_pk[crypto_scalarmult_BYTES]),
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

size_t stp_dkg_stp_input_size(const STP_DKG_STPState *ctx);
int stp_dkg_stp_input_sizes(const STP_DKG_STPState *ctx, size_t *sizes);
size_t stp_dkg_stp_output_size(const STP_DKG_STPState *ctx);
int stp_dkg_stp_next(STP_DKG_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len);
int stp_dkg_stp_peer_msg(const STP_DKG_STPState *ctx, const uint8_t *base, const size_t base_size, const uint8_t peer, const uint8_t **msg, size_t *len);
int stp_dkg_stp_not_done(const STP_DKG_STPState *stp);

size_t stp_dkg_peer_input_size(const STP_DKG_PeerState *ctx);
size_t stp_dkg_peer_output_size(const STP_DKG_PeerState *ctx);
int stp_dkg_peer_next(STP_DKG_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len);
int stp_dkg_peer_not_done(const STP_DKG_PeerState *peer);
void stp_dkg_peer_free(STP_DKG_PeerState *ctx);

uint8_t stp_dkg_tp_cheater_msg(const STP_DKG_Cheater *c, char *out, const size_t outlen);
uint8_t stp_dkg_peer_cheater_msg(const STP_DKG_Cheater *c, char *out, const size_t outlen);

extern FILE* log_file;


#endif //STP_DKG_H
