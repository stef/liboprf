#include <stdio.h>

#include "stp-dkg.h"
#include "toprf-update.h"
#include "utils.h"

static size_t stp_peer_ctx_size(const size_t n, const size_t t) {
  size_t ret = 0;
  uint8_t peerids[n][crypto_generichash_BYTES];
  ret+=sizeof(peerids);
  Noise_XK_session_t *noise_outs[n];
  ret+=sizeof(noise_outs);
  Noise_XK_session_t *noise_ins[n];
  ret+=sizeof(noise_ins);
  TOPRF_Share dealer_shares[n][2];
  ret+=sizeof(dealer_shares);
  uint8_t encrypted_shares[n][noise_xk_handshake3_SIZE + stp_dkg_encrypted_share_SIZE];
  ret+=sizeof(encrypted_shares);
  uint8_t dealer_commitments[n*n][crypto_core_ristretto255_BYTES];
  ret+=sizeof(dealer_commitments);
  uint8_t share_macs[n*n][crypto_auth_hmacsha256_BYTES];
  ret+=sizeof(share_macs);
  uint8_t peer_k_commitments[n][crypto_core_ristretto255_BYTES];
  ret+=sizeof(peer_k_commitments);
  uint8_t commitments_hashes[n][stp_dkg_commitment_HASHBYTES];
  ret+=sizeof(commitments_hashes);
  uint16_t peer_dealer_share_complaints[n*n];
  ret+=sizeof(peer_dealer_share_complaints);
  uint8_t peer_my_dealer_share_complaints[n];
  ret+=sizeof(peer_my_dealer_share_complaints);
  uint64_t peer_last_ts[n];
  ret+=sizeof(peer_last_ts);
  STP_DKG_Cheater peer_cheaters[t*t - 1];
  ret+=sizeof(peer_cheaters);
  return ret;
}

static size_t toprf_update_ctx_size(const size_t n, const size_t t) {
  const uint8_t dealers = (t-1)*2 + 1;
  size_t ret = 0;

  TOPRF_Share k0_share[2] = {0};
  ret+=sizeof k0_share;
  uint8_t k0_commitments[n][crypto_core_ristretto255_BYTES];
  ret+=sizeof k0_commitments;
  ret+=sizeof k0_commitments;
  uint8_t kid[toprf_keyid_SIZE];
  ret+=sizeof kid;
  uint8_t lt_pks[n+1][crypto_sign_PUBLICKEYBYTES];
  ret+=sizeof lt_pks;
  uint8_t lt_sks[crypto_sign_SECRETKEYBYTES];
  ret+=sizeof lt_sks;
  uint8_t peers_noise_pks[n][crypto_scalarmult_BYTES];
  ret+=sizeof peers_noise_pks;
  uint8_t peers_noise_sks[crypto_scalarmult_SCALARBYTES];
  ret+=sizeof peers_noise_sks;
  uint8_t pkid[toprf_keyid_SIZE];
  ret+=sizeof pkid;
  uint8_t stp_ltpk[crypto_sign_PUBLICKEYBYTES];
  ret+=sizeof stp_ltpk;
  Noise_XK_session_t *noise_outs[n];
  ret+=sizeof noise_outs;
  Noise_XK_session_t *noise_ins[n];
  ret+=sizeof noise_ins;
  TOPRF_Share pshares[n][2];
  ret+=sizeof pshares;
  uint8_t p_commitments[n*n][crypto_core_ristretto255_BYTES];
  ret+=sizeof p_commitments;
  uint8_t p_commitments_hashes[n][toprf_update_commitment_HASHBYTES];
  ret+=sizeof p_commitments_hashes;
  uint8_t peers_p_share_macs[n*n][crypto_auth_hmacsha256_BYTES];
  ret+=sizeof peers_p_share_macs;
  uint16_t peer_p_complaints[n*n];
  ret+=sizeof peer_p_complaints;
  uint8_t peer_my_p_complaints[n];
  ret+=sizeof peer_my_p_complaints;
  uint8_t encrypted_shares[n][noise_xk_handshake3_SIZE + toprf_update_encrypted_shares_SIZE];
  ret+=sizeof encrypted_shares;
  uint64_t peer_last_ts[n];
  ret+=sizeof peer_last_ts;
  uint8_t lambdas[dealers][crypto_core_ristretto255_SCALARBYTES];
  ret+=sizeof lambdas;
  TOPRF_Share k0p_shares[dealers][2];
  ret+=sizeof k0p_shares;
  uint8_t k0p_commitments[dealers*(n+1)][crypto_core_ristretto255_BYTES];
  ret+=sizeof k0p_commitments;
  uint8_t zk_challenge_nonce_commitments[n][crypto_scalarmult_ristretto255_BYTES];
  ret+=sizeof zk_challenge_nonce_commitments;
  uint8_t zk_challenge_nonces[n][2][crypto_scalarmult_ristretto255_SCALARBYTES];
  ret+=sizeof zk_challenge_nonces;
  uint8_t zk_challenge_commitments[dealers][3][crypto_scalarmult_ristretto255_SCALARBYTES];
  ret+=sizeof zk_challenge_commitments;
  uint8_t zk_challenge_e_i[dealers][crypto_scalarmult_ristretto255_SCALARBYTES];
  ret+=sizeof zk_challenge_e_i;
  TOPRF_Update_Cheater peer_cheaters[n*n - 1];
  ret+=sizeof peer_cheaters;
  return ret;
}

static void stp_dkg(void) {
  STP_DKG_PeerState ctx;
  ctx.share_complaints_len=0;
  for(ctx.t=2;ctx.t<64;ctx.t++) {
    printf("t=%2d\n", ctx.t);
    for(ctx.n=ctx.t+1;ctx.n<129;ctx.n++) {
      ctx.step=0;
      //ctx.share_complaints_len=ctx.t;
      //ctx.my_share_complaints_len=ctx.t-1;
      size_t itot=0, otot=0;
      int i=0;
      while(stp_dkg_peer_not_done(&ctx)) {
        const size_t out_size = stp_dkg_peer_output_size(&ctx);
        const size_t in_size = stp_dkg_peer_input_size(&ctx);
        if(itot<in_size) itot=in_size;
        if(otot<out_size) {
          otot=out_size;
          i=ctx.step;
        }
        ctx.step++;
      }
      const size_t ctx_size = stp_peer_ctx_size(ctx.n, ctx.t)+sizeof ctx;
      const size_t total = (ctx_size+itot+otot) >> 10;

      if(total<16) printf(GREEN);
      else if(total>64) printf(RED);
      printf("n=%3d total: %7ldKB ctx size: %7ldKB max: %6ldKB/%6ldKB %d"NORMAL"\n", ctx.n, total, ctx_size >> 10, itot >> 10, otot >> 10, i);
    }
  }
}

static void toprf_update(void) {
  TOPRF_Update_PeerState ctx;
  ctx.p_complaints_len = 0;
  ctx.my_p_complaints_len = 0;
  ctx.index = 1;
  for(ctx.n=5;ctx.n<129;ctx.n++) {
    printf("n=%2d\n", ctx.n);
    for(ctx.t=2;ctx.t<=((ctx.n-1)>>1)+1;ctx.t++) {
      ctx.step=0;
      //ctx.p_complaints_len=ctx.n;
      size_t itot=0, otot=0;
      while(toprf_update_peer_not_done(&ctx)) {
        const size_t out_size = toprf_update_peer_output_size(&ctx);
        const size_t in_size = toprf_update_peer_input_size(&ctx);
        if(in_size>itot) itot=in_size;
        if(out_size>otot) otot=out_size;
        ctx.step++;
      }
      const size_t ctx_size=toprf_update_ctx_size(ctx.n, ctx.t)+sizeof ctx;
      const size_t total = (ctx_size+itot+otot) >> 10;
      if(total<16) printf(GREEN);
      else if(total>64) printf(RED);
      printf("t=%3d total: %7ldKB ctx size: %7ldKB max: %6ldKB/%6ldKB"NORMAL"\n", ctx.t, total, ctx_size >> 10, itot >> 10, otot >> 10);
    }
  }
}

int main(void) {
  //printf("xxx: %ld\n",
  //       (sizeof(STP_DKG_Message) /* header */                        \
  //        + noise_xk_handshake3_SIZE /* 4th&final noise handshake */    \
  //        + sizeof(TOPRF_Share) /* msg: the noise_xk wrapped k share */ \
  //        + sizeof(TOPRF_Share) /* msg: the noise_xk wrapped k blind */ \
  //        + crypto_secretbox_xchacha20poly1305_MACBYTES /* mac of msg */ ));
  printf("toprf-update allocations\n");
  toprf_update();
  printf("stp-dkg allocations\n");
  stp_dkg();
  return 0;
}
