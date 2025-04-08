#ifndef TOPRF_UPDATE_H
#define TOPRF_UPDATE_H
#include <stdint.h>
#include <sodium.h>
#include "dkg.h"
#include "toprf.h"

#define noise_xk_handshake1_SIZE 48UL
#define noise_xk_handshake2_SIZE 48UL
#define noise_xk_handshake3_SIZE 64UL
#define toprf_update_noise_key_SIZE (32UL)
#define toprf_update_sessionid_SIZE 32U
#define toprf_update_commitment_HASHBYTES 32U
#define toprf_update_encrypted_shares_SIZE (TOPRF_Share_BYTES * 2)
#define toprf_keyid_SIZE 32U

typedef DKG_Message TOPRF_Update_Message;

// todo refactor this, it's the same in tp-dkg and stp-dkg
/** @struct TOPRF_Update_Cheater
    This struct communicates one detected violation of the protocol.

    @var TOPRF_Update_Cheater::step This is the step in which the violation occured.
    @var TOPRF_Update_Cheater::error This is the error code specifying the violation.
    @var TOPRF_Update_Cheater::peer This specifies which peer caused the violation.
    @var TOPRF_Update_Cheater::other_peer This optionally specifies which
         peer reported the violation, set to 0xfe if unused.
 */
typedef struct {
  int step;
  int error;
  uint8_t peer;
  uint8_t other_peer;
  int invalid_index;
} TOPRF_Update_Cheater;

typedef enum {
  Err_OK = 0,
  Err_ISize,
  Err_OSize,
  Err_OOB,
  Err_Send,
  Err_CheatersFound,
  Err_CheatersFull,
  Err_InvSessionID,
  Err_VSSShare,
  Err_VSSCommit,
  Err_NoiseEncrypt,
  Err_NoiseDecrypt,
  Err_HMac,
  Err_NoSubVSPSFail,
  Err_NotEnoughDealers,
  Err_TooManyCheaters,
  Err_DKGFinish,
  Err_FTMULTStep1,
  Err_FTMULTZKCommitments,
  Err_InvPoint,
  Err_CommmitmentsMismatch,
  Err_Proto,
  Err_BadReconstruct,
  Err_Reconstruct,
  Err_BroadcastEnv = 32,
  Err_Env = 64
} TOPRF_Update_Err;

typedef enum {
  TOPRF_Update_STP_Broadcast_NPKs,
  TOPRF_Update_STP_Route_Noise_Handshakes1,
  TOPRF_Update_STP_Route_Noise_Handshakes2,
  TOPRF_Update_STP_Broadcast_DKG_Hash_Commitments,
  TOPRF_Update_STP_Broadcast_DKG_Commitments,
  TOPRF_Update_STP_Route_Encrypted_Shares,
  TOPRF_Update_STP_Broadcast_Complaints,
  TOPRF_Update_STP_Broadcast_DKG_Defenses,
  TOPRF_Update_STP_Broadcast_DKG_Transcripts,
  TOPRF_Update_STP_Route_Mult_Step1,
  TOPRF_Update_STP_Broadcast_Mult_Commitments,
  TOPRF_Update_STP_Route_Encrypted_Mult_Shares,
  TOPRF_Update_STP_Broadcast_Mult_Complaints,
  TOPRF_Update_STP_Broadcast_Mult_Defenses,
  TOPRF_Update_STP_Broadcast_Reconst_Mult_Shares,
  TOPRF_Update_STP_Route_ZK_Challenge_Commitments,
  TOPRF_Update_STP_Route_ZK_commitments,
  TOPRF_Update_STP_Broadcast_ZK_nonces,
  TOPRF_Update_STP_Broadcast_ZK_Proofs,
  TOPRF_Update_STP_Broadcast_ZK_Disclosures,
  TOPRF_Update_STP_Broadcast_Mult_Ci,
  TOPRF_Update_STP_Broadcast_VSPS_Disclosures,
  TOPRF_Update_STP_Reconstruct_Delta,
  TOPRF_Update_STP_Done
} TOPRF_Update_STP_Steps;

typedef struct {
  TOPRF_Update_STP_Steps step;
  TOPRF_Update_STP_Steps prev;
  uint8_t sessionid[dkg_sessionid_SIZE];
  uint8_t n;
  uint8_t t;
  uint8_t sig_pk[crypto_sign_PUBLICKEYBYTES];
  uint8_t sig_sk[crypto_sign_SECRETKEYBYTES];
  uint64_t *last_ts;
  uint64_t ts_epsilon;
  const uint8_t (*sig_pks)[][crypto_sign_PUBLICKEYBYTES];

  uint8_t (*kc1_commitments_hashes)[][toprf_update_commitment_HASHBYTES];
  uint8_t (*kc1_share_macs)[][crypto_auth_hmacsha256_BYTES];
  uint8_t (*kc1_commitments)[][crypto_core_ristretto255_BYTES];
  uint16_t kc1_complaints_len;
  uint16_t *kc1_complaints;
  uint16_t *x2_complaints;
  uint16_t x2_complaints_len;

  uint8_t (*p_commitments_hashes)[][toprf_update_commitment_HASHBYTES];
  uint8_t (*p_share_macs)[][crypto_auth_hmacsha256_BYTES];
  uint8_t (*p_commitments)[][crypto_core_ristretto255_BYTES];
  uint16_t p_complaints_len;
  uint16_t *p_complaints;
  uint16_t y2_complaints_len;
  uint16_t *y2_complaints;

  uint8_t (*kc0_commitments)[][crypto_core_ristretto255_BYTES];
  uint8_t (*k0p_commitments)[][crypto_core_ristretto255_BYTES];
  uint8_t (*k1p_commitments)[][crypto_core_ristretto255_BYTES];
  uint8_t (*zk_challenge_commitments)[][3][crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t (*zk_challenge_e_i)[][crypto_scalarmult_ristretto255_SCALARBYTES];

  size_t cheater_len;
  TOPRF_Update_Cheater (*cheaters)[];
  size_t cheater_max;
  uint8_t (*k0p_final_commitments)[][crypto_scalarmult_ristretto255_BYTES];
  uint8_t (*k1p_final_commitments)[][crypto_scalarmult_ristretto255_BYTES];
  uint8_t delta[crypto_scalarmult_ristretto255_BYTES];
  crypto_generichash_state transcript_state;
  uint8_t transcript[crypto_generichash_BYTES];
} TOPRF_Update_STPState;

size_t toprf_update_stpstate_size(void);
uint8_t toprf_update_stpstate_n(const TOPRF_Update_STPState *ctx);
uint8_t toprf_update_stpstate_t(const TOPRF_Update_STPState *ctx);
size_t toprf_update_stpstate_cheater_len(const TOPRF_Update_STPState *ctx);
const uint8_t* toprf_update_stpstate_sessionid(const TOPRF_Update_STPState *ctx);
const uint8_t* toprf_update_stpstate_delta(const TOPRF_Update_STPState *ctx);
const uint8_t* toprf_update_stpstate_commitments(const TOPRF_Update_STPState *ctx);
int toprf_update_stpstate_step(const TOPRF_Update_STPState *ctx);

#define toprfupdate_stp_start_msg_SIZE ( sizeof(TOPRF_Update_Message)                          \
                                       + crypto_generichash_BYTES/*dst*/                       \
                                       + toprf_keyid_SIZE                                      \
                                       + crypto_sign_PUBLICKEYBYTES                            )

int toprf_update_start_stp(TOPRF_Update_STPState *ctx, const uint64_t ts_epsilon,
                           const uint8_t n, const uint8_t t,
                           const char *proto_name, const size_t proto_name_len,
                           const uint8_t keyid[toprf_keyid_SIZE],
                           const uint8_t (*sig_pks)[][crypto_sign_PUBLICKEYBYTES],
                           const uint8_t ltssk[crypto_sign_SECRETKEYBYTES],
                           const size_t msg0_len, TOPRF_Update_Message *msg0);

void toprf_update_stp_set_bufs(TOPRF_Update_STPState *ctx,
                               uint16_t kc1_complaints[],
                               uint16_t p_complaints[],
                               uint16_t x2_complaints[],
                               uint16_t y2_complaint[],
                               TOPRF_Update_Cheater (*cheaters)[], const size_t cheater_max,
                               uint8_t (*kc1_commitments_hashes)[][toprf_update_commitment_HASHBYTES],
                               uint8_t (*kc1_share_macs)[][crypto_auth_hmacsha256_BYTES],
                               uint8_t (*p_commitments_hashes)[][toprf_update_commitment_HASHBYTES],
                               uint8_t (*p_share_macs)[][crypto_auth_hmacsha256_BYTES],
                               uint8_t (*kc1_commitments)[][crypto_core_ristretto255_BYTES],
                               uint8_t (*p_commitments)[][crypto_core_ristretto255_BYTES],
                               uint8_t (*kc0_commitments)[][crypto_core_ristretto255_BYTES],
                               uint8_t (*k0p_commitments)[][crypto_core_ristretto255_BYTES],
                               uint8_t (*k1p_commitments)[][crypto_core_ristretto255_BYTES],
                               uint8_t (*zk_challenge_commitments)[][3][crypto_scalarmult_ristretto255_SCALARBYTES],
                               uint8_t (*zk_challenge_e_i)[][crypto_scalarmult_ristretto255_SCALARBYTES],
                               uint8_t (*k0p_final_commitments)[][crypto_scalarmult_ristretto255_BYTES],
                               uint8_t (*k1p_final_commitments)[][crypto_scalarmult_ristretto255_BYTES],
                               uint64_t *last_ts);
typedef enum {
  TOPRF_Update_Peer_Broadcast_NPK_SIDNonce,
  TOPRF_Update_Peer_Rcv_NPK_SIDNonce,
  TOPRF_Update_Peer_Noise_Handshake,
  TOPRF_Update_Peer_Finish_Noise_Handshake,
  TOPRF_Update_Peer_Rcv_CHashes_Send_Commitments,
  TOPRF_Update_Peer_Rcv_Commitments_Send_Shares,
  TOPRF_Update_Peer_Verify_Commitments,
  TOPRF_Update_Peer_Handle_DKG_Complaints,
  TOPRF_Update_Peer_Defend_DKG_Accusations,
  TOPRF_Update_Peer_Check_Shares,
  TOPRF_Update_Peer_Finish_DKG,
  TOPRF_Update_Peer_Confirm_Transcripts,
  TOPRF_Update_Peer_Rcv_Mult_CHashes_Send_Commitments,
  TOPRF_Update_Peer_Send_K1P_Shares,
  TOPRF_Update_Peer_Recv_K1P_Shares,
  TOPRF_Update_Peer_Handle_Mult_Share_Complaints,
  TOPRF_Update_Peer_Defend_Mult_Accusations,
  TOPRF_Update_Peer_Check_Mult_Shares,
  TOPRF_Update_Peer_Disclose_Mult_Shares,
  TOPRF_Update_Peer_Reconstruct_Mult_Shares,
  TOPRF_Update_Peer_Send_ZK_Challenge_Commitments,
  TOPRF_Update_Peer_Send_ZK_Commitments,
  TOPRF_Update_Peer_Send_ZK_nonces,
  TOPRF_Update_Peer_Send_ZK_proofs,
  TOPRF_Update_Peer_Verify_ZK_proofs,
  TOPRF_Update_Peer_Disclose_ZK_Cheaters,
  TOPRF_Update_Peer_Reconstruct_ZK_Shares,
  TOPRF_Update_Peer_Send_Mult_Ci,
  TOPRF_Update_Peer_Final_VSPS_Checks,
  TOPRF_Update_Peer_Disclose_VSPS_Cheaters,
  TOPRF_Update_Peer_Reconstruct_VSPS_Shares,
  TOPRF_Update_Peer_Send_k0p_k1p_Share,
  TOPRF_Update_Peer_Final_OK,
  TOPRF_Update_Peer_Done
} TOPRF_Update_Peer_Steps;

typedef enum {
  toprfupdate_stp_start_msg,
  toprfupdate_peer_init_msg,
  toprfupdate_stp_bc_init_msg,
  toprfupdate_peer_ake1_msg,
  toprfupdate_peer_ake2_msg,
  toprfupdate_peer_dkg1_msg,
  toprfupdate_stp_bc_dkg1_msg,
  toprfupdate_peer_dkg2_msg,
  toprfupdate_stp_bc_dkg2_msg,
  toprfupdate_peer_dkg3_msg,
  toprfupdate_peer_verify_shares_msg,
  toprfupdate_stp_bc_verify_shares_msg,
  toprfupdate_peer_share_key_msg,
  toprfupdate_stp_bc_key_msg,
  toprfupdate_peer_bc_transcript_msg,
  toprfupdate_stp_bc_transcript_msg,
  toprfupdate_peer_mult1_msg,
  toprfupdate_stp_bc_mult1_msg,
  toprfupdate_peer_mult_coms_msg,
  toprfupdate_stp_bc_mult_coms_msg,
  toprfupdate_peer_mult2_msg,
  toprfupdate_peer_verify_mult_shares_msg,
  toprfupdate_peer_share_mult_key_msg,
  toprfupdate_stp_bc_mult_key_msg,
  toprfupdate_peer_reconst_mult_shares_msg,
  toprfupdate_stp_bc_reconst_mult_shares_msg,

  toprfupdate_peer_zkp1_msg,
  toprfupdate_stp_bc_zkp1_msg,
  toprfupdate_peer_zkp2_msg,
  toprfupdate_stp_bc_zkp2_msg,
  toprfupdate_peer_zkp3_msg,
  toprfupdate_stp_bc_zkp3_msg,
  toprfupdate_peer_zkp4_msg,
  toprfupdate_stp_bc_zkp4_msg,

  toprfupdate_peer_zk_disclose_msg,
  toprfupdate_stp_bc_zk_disclose_msg,

  toprfupdate_peer_mult3_msg,
  toprfupdate_stp_bc_mult3_msg,

  toprfupdate_peer_vsps_disclose_msg,
  toprfupdate_stp_bc_vsps_disclose_msg,

  toprfupdate_peer_end1_msg,
  toprfupdate_stp_bc_end1_msg,
  toprfupdate_peer_end2_msg,
  toprfupdate_stp_end3_msg,
}TOPRF_Update_Message_Type;

typedef struct {
  uint8_t d[crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t s[crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t x[crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t s_1[crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t s_2[crypto_scalarmult_ristretto255_SCALARBYTES];
} TOPRF_Update_ZK_params;

typedef struct {
  uint8_t y[crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t w[crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t z[crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t w_1[crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t w_2[crypto_scalarmult_ristretto255_SCALARBYTES];
} TOPRF_Update_ZK_proof;

typedef struct {
  TOPRF_Update_Peer_Steps step;
  TOPRF_Update_Peer_Steps prev;
  uint8_t sessionid[dkg_sessionid_SIZE];
  uint8_t n;
  uint8_t t;
  uint8_t index;
  TOPRF_Share kc0_share[2];
  uint8_t (*kc0_commitments)[][crypto_core_ristretto255_BYTES];
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

  uint8_t (*encrypted_shares)[][noise_xk_handshake3_SIZE + toprf_update_encrypted_shares_SIZE*2];

  TOPRF_Share (*kc1_shares)[][2];
  uint8_t (*kc1_commitments)[][crypto_core_ristretto255_BYTES];
  uint8_t (*kc1_commitments_hashes)[][toprf_update_commitment_HASHBYTES];
  uint8_t (*kc1_share_macs)[][crypto_auth_hmacsha256_BYTES];
  uint16_t kc1_complaints_len;
  uint16_t *kc1_complaints;
  uint8_t my_kc1_complaints_len;
  uint8_t *my_kc1_complaints;
  TOPRF_Share kc1_share[2];
  uint8_t kc1_commitment[crypto_core_ristretto255_BYTES];

  TOPRF_Share (*p_shares)[][2];
  uint8_t (*p_commitments)[][crypto_core_ristretto255_BYTES];
  uint8_t (*p_commitments_hashes)[][toprf_update_commitment_HASHBYTES];
  uint8_t (*p_share_macs)[][crypto_auth_hmacsha256_BYTES];
  uint16_t p_complaints_len;
  uint16_t *p_complaints;
  uint8_t my_p_complaints_len;
  uint8_t *my_p_complaints;
  TOPRF_Share p_share[2];
  uint8_t p_commitment[crypto_core_ristretto255_BYTES];

  uint8_t (*lambdas)[][crypto_core_ristretto255_SCALARBYTES];
  TOPRF_Share (*k0p_shares)[][2];
  uint8_t (*k0p_commitments)[][crypto_core_ristretto255_BYTES];
  uint8_t k0p_tau[crypto_core_ristretto255_SCALARBYTES];
  TOPRF_Share (*k1p_shares)[][2];
  uint8_t (*k1p_commitments)[][crypto_core_ristretto255_BYTES];
  uint8_t k1p_tau[crypto_core_ristretto255_SCALARBYTES];
  uint8_t zk_chal_nonce[2][2][crypto_core_ristretto255_SCALARBYTES];
  uint8_t (*zk_challenge_nonces)[][2][crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t (*zk_challenge_nonce_commitments)[][crypto_scalarmult_ristretto255_BYTES];
  uint8_t (*zk_challenge_commitments)[][3][crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t (*zk_challenge_e_i)[][crypto_scalarmult_ristretto255_SCALARBYTES];
  TOPRF_Update_ZK_params zk_params[2];
  TOPRF_Share k0p_share[2];
  TOPRF_Share k1p_share[2];
  size_t cheater_len;
  TOPRF_Update_Cheater (*cheaters)[];
  size_t cheater_max;
  crypto_generichash_state transcript_state;
  uint8_t transcript[crypto_generichash_BYTES];
} TOPRF_Update_PeerState;

size_t toprf_update_peerstate_size(void);
uint8_t toprf_update_peerstate_n(const TOPRF_Update_PeerState *ctx);
uint8_t toprf_update_peerstate_t(const TOPRF_Update_PeerState *ctx);
const uint8_t* toprf_update_peerstate_sessionid(const TOPRF_Update_PeerState *ctx);
const uint8_t* toprf_update_peerstate_lt_sk(const TOPRF_Update_PeerState *ctx);
const uint8_t* toprf_update_peerstate_share(const TOPRF_Update_PeerState *ctx);
const uint8_t* toprf_update_peerstate_commitment(const TOPRF_Update_PeerState *ctx);
const uint8_t* toprf_update_peerstate_commitments(const TOPRF_Update_PeerState *ctx);
int toprf_update_peerstate_step(const TOPRF_Update_PeerState *ctx);

TOPRF_Update_Err toprf_update_start_peer(TOPRF_Update_PeerState *ctx,
                                         const uint64_t ts_epsilon,
                                         const uint8_t lt_sk[crypto_sign_SECRETKEYBYTES],
                                         const TOPRF_Update_Message *msg0,
                                         uint8_t keyid[toprf_keyid_SIZE],
                                         uint8_t stp_ltpk[crypto_sign_PUBLICKEYBYTES]);

int toprf_update_peer_set_bufs(TOPRF_Update_PeerState *ctx,
                               const uint8_t self,
                               const uint8_t n, const uint8_t t,
                               const TOPRF_Share k0[2],
                               uint8_t (*kc0_commitments)[][crypto_core_ristretto255_BYTES],
                               const uint8_t (*sig_pks)[][crypto_sign_PUBLICKEYBYTES],
                               uint8_t (*peers_noise_pks)[][crypto_scalarmult_BYTES],
                               uint8_t noise_sk[crypto_scalarmult_BYTES],
                               Noise_XK_session_t *(*noise_outs)[],
                               Noise_XK_session_t *(*noise_ins)[],
                               TOPRF_Share (*kc1_shares)[][2],
                               TOPRF_Share (*p_shares)[][2],
                               uint8_t (*kc1_commitments)[][crypto_core_ristretto255_BYTES],
                               uint8_t (*p_commitments)[][crypto_core_ristretto255_BYTES],
                               uint8_t (*kc1_commitments_hashes)[][toprf_update_commitment_HASHBYTES],
                               uint8_t (*p_commitments_hashes)[][toprf_update_commitment_HASHBYTES],
                               uint8_t (*kc1_share_macs)[][crypto_auth_hmacsha256_BYTES],
                               uint8_t (*p_share_macs)[][crypto_auth_hmacsha256_BYTES],
                               uint8_t (*encrypted_shares)[][noise_xk_handshake3_SIZE + toprf_update_encrypted_shares_SIZE*2],
                               TOPRF_Update_Cheater (*cheaters)[], const size_t cheater_max,
                               uint8_t (*lambdas)[][crypto_core_ristretto255_SCALARBYTES],
                               TOPRF_Share (*k0p_shares)[][2],
                               uint8_t (*k0p_commitments)[][crypto_core_ristretto255_BYTES],
                               TOPRF_Share (*k1p_shares)[][2],
                               uint8_t (*k1p_commitments)[][crypto_core_ristretto255_BYTES],
                               uint8_t (*zk_challenge_nonce_commitments)[][crypto_scalarmult_ristretto255_BYTES],
                               uint8_t (*zk_challenge_nonces)[][2][crypto_scalarmult_ristretto255_SCALARBYTES],
                               uint8_t (*zk_challenge_commitments)[][3][crypto_scalarmult_ristretto255_SCALARBYTES],
                               uint8_t (*zk_challenge_e_i)[][crypto_scalarmult_ristretto255_SCALARBYTES],
                               uint16_t *kc1_complaints, uint16_t *p_complaints,
                               uint8_t *my_kc1_complaints, uint8_t *my_p_complaints,
                               uint64_t *last_ts);

size_t toprf_update_stp_input_size(const TOPRF_Update_STPState *ctx);
int toprf_update_stp_input_sizes(const TOPRF_Update_STPState *ctx, size_t *sizes);
size_t toprf_update_stp_output_size(const TOPRF_Update_STPState *ctx);
int toprf_update_stp_next(TOPRF_Update_STPState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len);
int toprf_update_stp_peer_msg(const TOPRF_Update_STPState *ctx, const uint8_t *base, const size_t base_size, const uint8_t peer, const uint8_t **msg, size_t *len);
int toprf_update_stp_not_done(const TOPRF_Update_STPState *stp);

size_t toprf_update_peer_input_size(const TOPRF_Update_PeerState *ctx);
size_t toprf_update_peer_output_size(const TOPRF_Update_PeerState *ctx);
int toprf_update_peer_next(TOPRF_Update_PeerState *ctx, const uint8_t *input, const size_t input_len, uint8_t *output, const size_t output_len);
int toprf_update_peer_not_done(const TOPRF_Update_PeerState *peer);
void toprf_update_peer_free(TOPRF_Update_PeerState *ctx);

extern FILE* log_file;


#endif //TOPRF_UPDATE_H
