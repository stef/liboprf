#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../dkg-vss.h"
#include "../utils.h"
#include "../mpmult.h"
#include "../toprf.h"

static void corrupt_ci_good_ci0(const uint8_t n, const uint8_t t,
                                const uint8_t peer,
                                TOPRF_Share shares[][2],
                                uint8_t commitments[][crypto_core_ristretto255_BYTES],
                                uint8_t blind[crypto_core_ristretto255_SCALARBYTES]) {
  // is not detected by anything, corrupts final result
  uint8_t secret[crypto_core_ristretto255_SCALARBYTES]={0};
  secret[31]=0x10;
  //secret[0]=1;
  //crypto_core_ristretto255_scalar_random(secret);
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"!!! Corrupting sharing of λ_iα_iβ_i %d, C_i0 is correct though\n"NORMAL, peer);
  (void)dkg_vss_share(n, t, secret, commitments, shares, blind);
}

static void corrupt_random_ci0_ci(const uint8_t n, const uint8_t t,
                                  const uint8_t peer,
                                  TOPRF_Share shares[][2],
                                  uint8_t commitments[][crypto_core_ristretto255_BYTES],
                                  uint8_t blind[crypto_core_ristretto255_SCALARBYTES]) {
  // is detected by zpk, but even if we reconstruct the secret
  // committed by C_i0 the end result will be corrupt.
  uint8_t secret[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_random(secret);
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"!!! Corrupting with totally random sharing instead of λ_iα_iβ_i %d\n"NORMAL, peer);
  (void)dkg_vss_share(n, t, secret, &commitments[1], shares, blind);
  (void)dkg_vss_commit(secret, blind, commitments[0]);
}

static void corrupt_ci0_good_ci(const uint8_t peer, uint8_t commitments[][crypto_core_ristretto255_BYTES]) {
  // is detected by both zkp and vsps, but even if ignored does not
  // influence the correctness of the calculation.
  uint8_t secret[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_random(secret);
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"!!! Corrupting C_i0 λ_iα_iβ_i %d\n"NORMAL, peer);
  dkg_vss_commit(secret,secret,commitments[0]);
}

static void corrupt_vsps_t1(const uint8_t n, const uint8_t t, const int8_t delta,
                            const uint8_t peer,
                            const uint8_t secret[crypto_core_ristretto255_SCALARBYTES],
                            TOPRF_Share shares[][2],
                            uint8_t commitments[][crypto_core_ristretto255_BYTES],
                            uint8_t blind[crypto_core_ristretto255_SCALARBYTES]) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"!!! Corrupting with wrong degree of the polynom peer %d\n"NORMAL, peer);
  (void)dkg_vss_share(n, t+delta, secret, &commitments[1], shares, blind);
  (void)dkg_vss_commit(secret, blind, commitments[0]);
}

static void corrupt_commitment(const uint8_t peer,
                               uint8_t commitments[][crypto_core_ristretto255_BYTES]) { // corrupts the 1st commitment with the 2nd
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"!!! Corrupting commitment of peer %d\n"NORMAL, peer);
  memcpy(commitments[0], commitments[1], crypto_core_ristretto255_BYTES);
}


static void corrupt_share(const uint8_t peer,
                          const uint8_t share_idx,
                          const uint8_t share_type,
                          TOPRF_Share shares[][2]) {
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"!!! Corrupting share of peer %d\n"NORMAL, peer);
  shares[share_idx][share_type].value[2]^=0xff; // flip some bits
}

static void corrupt_wrongshare_correct_commitment(const uint8_t peer,
                                                  const uint8_t share_idx,
                                                  TOPRF_Share shares[][2],
                                                  uint8_t commitments[][crypto_core_ristretto255_BYTES]) {
  TOPRF_Share tmp;
  // swap shares
  memcpy(&tmp, &shares[share_idx][0], sizeof tmp);
  memcpy(&shares[share_idx][0], &shares[share_idx][1], sizeof tmp);
  memcpy(&shares[share_idx][1], &tmp, sizeof tmp);
  if(liboprf_log_file!=NULL) fprintf(liboprf_log_file, RED"!!! Corrupting share (but correct commitment) of peer %d\n"NORMAL, peer);
  dkg_vss_commit(shares[share_idx][0].value,shares[share_idx][1].value,commitments[share_idx]);
}

static int vss_share(const uint8_t n,
                     const uint8_t threshold,
                     const uint8_t secret[crypto_core_ristretto255_SCALARBYTES],
                     const uint8_t blind[crypto_core_ristretto255_SCALARBYTES],
                     uint8_t commitments[n][crypto_core_ristretto255_BYTES],
                     TOPRF_Share shares[n][2]) {
  uint8_t a[threshold][crypto_core_ristretto255_SCALARBYTES];
  uint8_t b[threshold][crypto_core_ristretto255_SCALARBYTES];
  if(secret!=NULL) memcpy(a[0], secret, crypto_core_ristretto255_SCALARBYTES);
  if(blind !=NULL) memcpy(b[0], blind,  crypto_core_ristretto255_SCALARBYTES);
  for(int k=0;k<threshold;k++) {
#ifndef UNIT_TEST
    if(k!=0 || secret==NULL) crypto_core_ristretto255_scalar_random(a[k]);
    if(k!=0 || blind==NULL)  crypto_core_ristretto255_scalar_random(b[k]);
#else
    if(k!=0 || secret==NULL) debian_rng_scalar(a[k]);
    dump(a[k],crypto_core_ristretto255_SCALARBYTES,"a[%d] ", k);
    if(k!=0 || blind==NULL) debian_rng_scalar(b[k]);
    dump(b[k],crypto_core_ristretto255_SCALARBYTES,"b[%d] ", k);
#endif
  }

  // compute commitments
  //if(0!=dkg_vss_commit(a[0], b[0], commitments[0])) return 1;
  //dump((uint8_t*) &commitments[k],crypto_core_ristretto255_BYTES, "c[%d]     ", k);

  for(uint8_t j=1;j<=n;j++) {
    //f(x) = a_0 + a_1*x + a_2*x^2 + a_3*x^3 + ⋯ + a_(t)*x^(t)
    polynom(j, threshold, a, &shares[j-1][0]);
    //f'(x) = b_0 + b_1*x + b_2*x^2 + b_3*x^3 + ⋯ + b_(t)*x^(t)
    polynom(j, threshold, b, &shares[j-1][1]);

    if(0!=dkg_vss_commit(shares[j-1][0].value, shares[j-1][1].value, commitments[j-1])) return 1;
  }

  return 0;
}


int ft_mult(const uint8_t n, const uint8_t t,
            const TOPRF_Share alpha_shares[n][2], const uint8_t A_i[n][crypto_core_ristretto255_BYTES],
            const TOPRF_Share beta_shares[n][2], const uint8_t B_i[n][crypto_core_ristretto255_BYTES],
            TOPRF_Share r_shares[n][2],
            uint8_t r_commitments[n][crypto_core_ristretto255_BYTES]) {
  fprintf(stderr, "start ft_mult\n");

  if(t<2) return 1;
  const uint8_t dealers = (t-1)*2 + 1;
  if(n<dealers) return 1;

  // pubic inputs, for i:=0..n
  // 𝓐_i = 𝓗(α_i,ρ_i) = g^(α_i)*h^(ρ_i)
  // 𝓑_i = 𝓗(β_i,σ_i) = g^(β_i)*h^(σ_i)
  // we assume the VSPS property has been checked on the commitments

  // step 1. Each player P_i shares λ_iα_iβ_i, using VSS
  uint8_t indexes[dealers];
  for(unsigned i=0;i<dealers;i++) indexes[i]=i+1;

  // λ_i is row 1 of inv VDM matrix
  uint8_t lambdas[dealers][dealers][crypto_core_ristretto255_SCALARBYTES];
  invertedVDMmatrix(dealers, indexes, lambdas);

  TOPRF_Share ci_shares[dealers][n][2];
  uint8_t ci_commitments[dealers][n+1][crypto_core_ristretto255_BYTES];
  uint8_t ci_tau[dealers][crypto_core_ristretto255_SCALARBYTES];
  for(unsigned i=0;i<dealers;i++) {
    // c_ij = 𝑓_αβ,i(j), where 𝑓_αβ,i is a random polynomial of degree t, such that 𝑓_αβ,i(0) = λ_iα_iβ_i
    // τ_ij = u_i(j), where u_i(j) is a random polynomial of degree t

    uint8_t lambda_ai_bi[crypto_scalarmult_ristretto255_SCALARBYTES];
    crypto_core_ristretto255_scalar_mul(lambda_ai_bi, alpha_shares[i][0].value, beta_shares[i][0].value);
    crypto_core_ristretto255_scalar_mul(lambda_ai_bi, lambda_ai_bi, lambdas[0][i]);
    if(0!=dkg_vss_share(n,t,lambda_ai_bi, &ci_commitments[i][1], ci_shares[i], ci_tau[i])) return 1;

    // c_i0 for the sake of the ZK proof is g^λab * h^t
    if(0!=dkg_vss_commit(lambda_ai_bi, ci_tau[i], ci_commitments[i][0])) return 1;

    // sanity check
    uint8_t s[crypto_scalarmult_ristretto255_SCALARBYTES];
    uint8_t r[crypto_scalarmult_ristretto255_SCALARBYTES];
    if(0!=dkg_vss_reconstruct(t, 0, n, &ci_shares[i][0], &ci_commitments[i][1], s, r)) return 1;
    if(0!=memcmp(s, lambda_ai_bi, sizeof s)) {
      liboprf_debug=1;dump(s, sizeof s, "reconstructed");
      dump(lambda_ai_bi, sizeof lambda_ai_bi, "expected     ");liboprf_debug=0;
    }

    // c_i0 is correct ablambda, but the shares are of a random sharing.
    //c_i0 is fully correct, c_i is sharing of a random value
    //is not detected by zkp, nor ft-vsps, corrupts final result
    if(i==0) {
      corrupt_ci_good_ci0(n, t, i+1, ci_shares[i], &ci_commitments[i][1], ci_tau[i]);
      if(0==toprf_mpc_vsps_check(t-1, ci_commitments[i])) continue;
      fprintf(stderr, GREEN"vsps for corrupted peer %d failed\n"NORMAL, i+1);
    }
    // share with polynom of degree smaller than t - not an error at all? not detected, and completes correctly
    //if(i==0) corrupt_vsps_t1(n, t, -4, i+1, lambda_ai_bi, ci_shares[i], ci_commitments[i], ci_tau[i]);

    // detected by ZK can be reconstructed
    // is detected by both zkp and vsps, but even if ignored does not
    // influence the correctness of the calculation.
    //if(i==0) corrupt_ci0_good_ci(i+1,ci_commitments[i]);

    // shares a random value, c_i0 is calculated over random value
    // is detected by zpk, but even if we reconstruct the secret
    // committed by C_i0 the end result will be corrupt.
    //if(i==0) corrupt_random_ci0_ci(n, t, i+1, ci_shares[i], ci_commitments[i], ci_tau[i]);

    // caught by vsps cannot be reconstructed, only if correctly guessed x for degree t+x
    //if(i==0) corrupt_vsps_t1(n, t, 1, i+1, lambda_ai_bi, ci_shares[i], ci_commitments[i], ci_tau[i]);

    // caught by vsps, can be reconstructed, by excluding the
    // corrupted share(s), which can be checked by checking if the
    // reconstructed value is committed by C_i0
    //if(i==3) corrupt_wrongshare_correct_commitment(i+1,3,ci_shares[i],ci_commitments[i]);

    //if(i==1) corrupt_commitment(i+1,ci_commitments[i]);
    //if(i==2) corrupt_share(i+1,n-2,0,ci_shares[i]);
    //if(i==2) corrupt_share(i+1,3,1,ci_shares[i]);

    uint8_t v[crypto_scalarmult_ristretto255_SCALARBYTES];
    if(0!=dkg_vss_reconstruct(t, 0, n, ci_shares[i], &ci_commitments[i][1], v, NULL)) return 1;
    liboprf_debug=1; dump(v, sizeof v, "[%d] λ_iα_iβ_i", i+1);liboprf_debug=0;
    if(memcmp(v, lambda_ai_bi, sizeof v)!=0) {
      fprintf(liboprf_log_file, RED"failed reconstruction of lambda_ai_bi for %d\n"NORMAL, i+1);
      liboprf_debug=1;dump(lambda_ai_bi, sizeof lambda_ai_bi, "correct");liboprf_debug=0;
    }

    // send ci_shares[j] to P_j
    // broadcast ci_commitments
  }
  fprintf(stderr, "[1] calculated shares and commitments of a*b\n");

  for(unsigned i=0;i<n;i++) {
    for(unsigned j=0;j<dealers;j++) {
      if(dkg_vss_verify_commitment(ci_commitments[j][i+1], ci_shares[j][i])==0) continue;
      fprintf(liboprf_log_file, RED"[%d] invalid commitment for share from %d\n"NORMAL, i+1, j+1);

      // aggregate shares/commitments
      TOPRF_Share shares[n][2];
      uint8_t commitments[n][crypto_core_ristretto255_BYTES];
      unsigned k=0;
      memcpy(shares, ci_shares[j], sizeof shares);
      memcpy(commitments, ci_commitments[j][1], sizeof commitments);

      TOPRF_Share secret[2];
        if(0!=dkg_vss_reconstruct(t, 0, n, &shares[0], &commitments[0], secret[0].value, secret[1].value)) continue;
        if(dkg_vss_verify_commitment(ci_commitments[j][0],secret)!=0) continue;
        liboprf_debug=1;dump(secret[0].value, sizeof secret[0].value, "reconstructed %d", k);liboprf_debug=0;
        if(memcmp(secret[1].value, ci_tau[j], crypto_scalarmult_ristretto255_SCALARBYTES)!=0) {
          fprintf(liboprf_log_file, RED"tau[%d] != reconstructed tau\n"NORMAL, i);
          continue;
        }
        if(0!=vss_share(n,t,secret[0].value, ci_tau[j], commitments, shares)) return 1;
      memcpy(&ci_shares[j], shares, sizeof shares);
      memcpy(&ci_commitments[j][1], commitments, sizeof commitments);
      // restart this loop
      i=-1;
      break;
    }
  }

  // step 2. P_i proves in zk that 𝓒_i0 is a commitment of the product λ_iα_iβ_i.
  // As per Appendix F: ZK Proof for multiplication of committed values from GRR98
  // step 2.1 all P_j generate a challenge share, and broadcast a commitment to it
  uint8_t zk_challenge_shares[n][2][crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t zk_challenge_commitments[n][crypto_scalarmult_ristretto255_BYTES];
  for(unsigned i=0;i<n;i++) {
    crypto_core_ristretto255_scalar_random(zk_challenge_shares[i][0]);
    crypto_core_ristretto255_scalar_random(zk_challenge_shares[i][1]);
    if(0!=dkg_vss_commit(zk_challenge_shares[i][0], zk_challenge_shares[i][1], zk_challenge_commitments[i])) return 1;
  }
  // every P_j broadcasts their  zk_challenge_commitment[i]
  fprintf(stderr, "[2.1] broadcast e_i commitment share\n");

  // step 2.2 P_i chooses d, s, x, s_1, s_2 ∈ Z_q. Sends to the verifier the messages:
  //  M   = g^d * h^s,
  //  M_1 = g^x * h^s_1,
  //  M_2 = B^x * h^s_2
  uint8_t d[dealers][crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t s[dealers][crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t x[dealers][crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t s_1[dealers][crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t s_2[dealers][crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t zk_commitments[dealers][3][crypto_scalarmult_ristretto255_SCALARBYTES];
  for(unsigned i=0;i<dealers;i++) {
    crypto_core_ristretto255_scalar_random(d[i]);
    crypto_core_ristretto255_scalar_random(s[i]);
    crypto_core_ristretto255_scalar_random(x[i]);
    crypto_core_ristretto255_scalar_random(s_1[i]);
    crypto_core_ristretto255_scalar_random(s_2[i]);
    //  M   = g^d * h^s,
    if(0!=dkg_vss_commit(d[i],s[i], zk_commitments[i][0])) return 1;
    //  M_1 = g^x * h^s_1,
    if(0!=dkg_vss_commit(x[i],s_1[i], zk_commitments[i][1])) return 1;
    //  M_2 = B^x * h^s_2
    uint8_t tmp[crypto_scalarmult_ristretto255_BYTES];
    if(crypto_scalarmult_ristretto255(tmp, x[i], B_i[i])) return 1;
    if(crypto_scalarmult_ristretto255(zk_commitments[i][2], s_2[i], H)) return 1;
    crypto_core_ristretto255_add(zk_commitments[i][2], zk_commitments[i][2], tmp);
  }
  fprintf(stderr, "[2.2] broadcast M, M_1 and M_2\n");

  // step 2.3. P_j broadcasts  e_j,r_j
  fprintf(stderr, "[2.3] broadcast e_j, r_j\n");

  // step 2.4. P_i verifies the commitment from 0. against e:
  uint8_t y[dealers][crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t w[dealers][crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t z[dealers][crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t w_1[dealers][crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t w_2[dealers][crypto_scalarmult_ristretto255_SCALARBYTES];
  for(unsigned i=0;i<dealers;i++) {
    // P_i verifies commitments for e_j,r_j
    // P_i computes e'_i:
    //  e'_i = Σ e_j
    //       j!=i
    uint8_t e_i[crypto_scalarmult_ristretto255_SCALARBYTES]={0};
    uint8_t zk_challenge_commitment[crypto_scalarmult_ristretto255_BYTES];
    for(unsigned j=0;j<n;j++) {
      if(j==i) continue;
      if(0!=dkg_vss_commit(zk_challenge_shares[j][0], zk_challenge_shares[j][1], zk_challenge_commitment)) return 1;
      if(memcmp(zk_challenge_commitment, zk_challenge_commitments[j], crypto_scalarmult_ristretto255_BYTES)!=0) return 1;

      crypto_core_ristretto255_scalar_add(e_i, e_i, zk_challenge_shares[j][0]);
    }

    // P_i replies with the following values:
    // y   = d + e'_iβ,
    crypto_core_ristretto255_scalar_mul(y[i], e_i, beta_shares[i][0].value);
    crypto_core_ristretto255_scalar_add(y[i], y[i], d[i]);
    // w   = s + e'_iσ
    crypto_core_ristretto255_scalar_mul(w[i], e_i, beta_shares[i][1].value);
    crypto_core_ristretto255_scalar_add(w[i], w[i], s[i]);
    // z   = x + e'_iα
    crypto_core_ristretto255_scalar_mul(z[i], e_i, alpha_shares[i][0].value);
    crypto_core_ristretto255_scalar_mul(z[i], z[i], lambdas[0][i]);
    crypto_core_ristretto255_scalar_add(z[i], z[i], x[i]);
    // w_1 = s_1 + e'_iρ
    crypto_core_ristretto255_scalar_mul(w_1[i], e_i, alpha_shares[i][1].value);
    crypto_core_ristretto255_scalar_mul(w_1[i], w_1[i], lambdas[0][i]);
    crypto_core_ristretto255_scalar_add(w_1[i], w_1[i], s_1[i]);
    // w_2 = s_2 + e'_i(τ - σα)
    crypto_core_ristretto255_scalar_mul(w_2[i], beta_shares[i][1].value, alpha_shares[i][0].value);
    crypto_core_ristretto255_scalar_mul(w_2[i], w_2[i], lambdas[0][i]);
    crypto_core_ristretto255_scalar_sub(w_2[i], ci_tau[i], w_2[i]);
    crypto_core_ristretto255_scalar_mul(w_2[i], e_i, w_2[i]);
    crypto_core_ristretto255_scalar_add(w_2[i], w_2[i], s_2[i]);
  }
  fprintf(stderr, "[2.4] calculate proof of a*b\n");

  // step 2.5. P_j checks zk proof
  for(unsigned j=0;j<n;j++) {
    // for each P_i zk proof
    for(unsigned i=0;i<dealers;i++) {
      //  P_j computes e'_i:
      //    e'_i = Σ e_j
      //         j!=i
      uint8_t e_i[crypto_scalarmult_ristretto255_SCALARBYTES]={0};
      for(unsigned k=0;k<n;k++) {
        if(k==i) continue;
        crypto_core_ristretto255_scalar_add(e_i, e_i, zk_challenge_shares[k][0]);
      }

      uint8_t v0[crypto_scalarmult_ristretto255_BYTES];
      uint8_t v1[crypto_scalarmult_ristretto255_BYTES];
      //   g^y * h^w   == M * B^e'_i
      if(0!=dkg_vss_commit(y[i], w[i], v0)) return 1;

      if(crypto_scalarmult_ristretto255(v1, e_i, B_i[i])) return 1;
      crypto_core_ristretto255_add(v1, zk_commitments[i][0], v1);
      if(memcmp(v1, v0, crypto_scalarmult_ristretto255_BYTES)!=0) {
        fprintf(liboprf_log_file, RED"[%d] failed ZK proof_B (g^y * h^w   == M * B^e'_i) for dealer %d\n"NORMAL, j, i+1);
        return 1;
      }

      //   g^z * h^w_1 == M_1 * A^e'_i
      if(0!=dkg_vss_commit(z[i], w_1[i], v0)) return 1;

      if(crypto_scalarmult_ristretto255(v1, e_i, A_i[i])) return 1;
      if(crypto_scalarmult_ristretto255(v1, lambdas[0][i], v1)) return 1;
      crypto_core_ristretto255_add(v1, zk_commitments[i][1], v1);
      if(memcmp(v1, v0, crypto_scalarmult_ristretto255_BYTES)!=0) {
        fprintf(liboprf_log_file, RED"[%d] failed ZK proof_A (g^z * h^w_1 == M_1 * A^e'_i) for dealer %d\n"NORMAL, j, i+1);
        return 1;
      }

      //   B^z * h^w_2 == M_2 * C^e'_i
      if(crypto_scalarmult_ristretto255(v0, z[i], B_i[i])) return 1;
      // we abuse v1 as a temp storage, v1 = h^w_2
      if(crypto_scalarmult_ristretto255(v1, w_2[i], H)) return 1;
      crypto_core_ristretto255_add(v0, v0, v1);

      if(crypto_scalarmult_ristretto255(v1, e_i, ci_commitments[i][0])) return 1;
      crypto_core_ristretto255_add(v1, zk_commitments[i][2], v1);
      if(memcmp(v1, v0, crypto_scalarmult_ristretto255_BYTES)!=0) {
        fprintf(liboprf_log_file, RED"[%d] failed ZK proof_C (B^z * h^w_2 == M_2 * C^e'_i) for dealer %d\n"NORMAL, j, i+1);

        TOPRF_Share secret[2];
        if(0!=dkg_vss_reconstruct(t, 0, n, ci_shares[i], &ci_commitments[i][1], secret[0].value, secret[1].value)) return 1;
        liboprf_debug=1;dump(secret[0].value, sizeof secret[0].value, "reconstructed");liboprf_debug=0;
        if(0!=dkg_vss_commit(secret[0].value, secret[1].value, ci_commitments[i][0])) return 1;
        i--;
        break;
        //return 1;
      }
    }
  }
  fprintf(stderr, "[2.5] verified proof of a*b\n");

  uint8_t C_i[n+1][crypto_scalarmult_ristretto255_BYTES];
  for(unsigned i=0;i<n;i++) {
    // step 3. P_i computes:
    //      2t+1
    //  γ_i = Σ c_ji
    //       j=1
    //  which is a share of γ = αβ, via random polynomial of degree t and
    //      2t+1
    //  τ_i = Σ τ_ji
    //       j=1
    memcpy(&r_shares[i][0], &ci_shares[0][i][0], TOPRF_Share_BYTES);
    memcpy(&r_shares[i][1], &ci_shares[0][i][1], TOPRF_Share_BYTES);
    for(unsigned j=1;j<dealers;j++) {
      crypto_core_ristretto255_scalar_add(r_shares[i][0].value, r_shares[i][0].value, ci_shares[j][i][0].value);
      crypto_core_ristretto255_scalar_add(r_shares[i][1].value, r_shares[i][1].value, ci_shares[j][i][1].value);
    }

    // step 4. P_i computes and broadcasts
    //    𝓒_i = 𝓗(γ_i, τ_i)
    //        = g^(γ_i)*h^(τ_i)
    //
    //        2t+1
    //        = Π 𝓒_ji
    //         j=1
    if(0!=dkg_vss_commit(r_shares[i][0].value, r_shares[i][1].value, C_i[i+1])) return 1;
    // use this below to calculate all commitments for the other peers
    uint8_t Cx_i[crypto_scalarmult_ristretto255_BYTES];
    memcpy(Cx_i,ci_commitments[0][i+1], crypto_scalarmult_ristretto255_BYTES);
    for(unsigned j=1;j<dealers;j++) {
      crypto_core_ristretto255_add(Cx_i, Cx_i, ci_commitments[j][i+1]);
    }
    if(memcmp(Cx_i, C_i[i+1], sizeof Cx_i) != 0) {
      fprintf(liboprf_log_file, RED"[%d] failed final commitment\n"NORMAL, i+1);
    }
  }
  memcpy(C_i, ci_commitments[0][0], crypto_scalarmult_ristretto255_BYTES);
  for(unsigned j=1;j<dealers;j++) {
    crypto_core_ristretto255_add(C_i[0], C_i[0], ci_commitments[j][0]);
  }

  fprintf(stderr, "[3&4] calculated final shares of a*b and their commitments\n");

  int fail = 0;
  for(unsigned i=0;i<n;i++) {
    // step 5. players run a VSPS Check on 𝓒_i, i:=1..n,
    // if the test succeeds:
    // Secret information of P_i: share γ_i
    // Public information: 𝓒_i, for i:=1..n
    // protocol terminates successfully

    if(0==toprf_mpc_vsps_check(t-1, C_i)) {
      fprintf(liboprf_log_file, GREEN"ft-vsps checks out for C_i\n"NORMAL);
    } else {
      fail = 1;
      fprintf(liboprf_log_file, RED"[%d] ft-vsps fails for C_i\n"NORMAL, i+1);
    }

    // If the test fails STOP and run MULT from step 2.
  }
  if(!fail) {
    memcpy(r_commitments, &C_i[1], n*crypto_scalarmult_ristretto255_BYTES);
    return 0;
  }

  fprintf(stderr, "[5] failed vsps check for C_i\n");

  // step 6. only if 5. fails, as per Mult algorithm from fig. 3. step 2
  // Players run a VSPS Check on P_i's sharing. If a sharing fails the test
  // then expose the secret through the VSS reconstruction.
  for(unsigned i=0;i<n;i++) {
    // each P_i VSPS checks P_j (i!=j) sharing
    for(unsigned j=0;j<dealers;j++) {
      if(j==i) continue;
      if(0==toprf_mpc_vsps_check(t-1, ci_commitments[j])) continue;
      fprintf(stderr, RED"[%d] vsps for peer %d failed\n"NORMAL, i+1, j+1);

      // expose the secret of P_j through vss reconstruction
      TOPRF_Share s[2];
      for(unsigned t1=t;t1<n;t1++) {
        fprintf(liboprf_log_file, "trying degree t+%d\n", t1-t);
        if(0!=dkg_vss_reconstruct(t1, 0, n, &ci_shares[j][0], &ci_commitments[j][1], s[0].value, s[1].value)) continue;
        if(dkg_vss_verify_commitment(ci_commitments[j][0],s)!=0) continue;
        liboprf_debug=1;dump(s[0].value, sizeof s[0].value, "reconstructed");liboprf_debug=0;
        if(memcmp(s[1].value, ci_tau[j], crypto_scalarmult_ristretto255_SCALARBYTES)!=0) {
          // tau[j] is only available to the cheater, so this check
          // makes little sense, it is only a sanity test for the test
          // itself.
          fprintf(liboprf_log_file, RED"tau[%d] != reconstructed tau\n"NORMAL, j);
          liboprf_debug = 1;
          dump(s[1].value, 32, "reconstructed tau");
          dump(ci_tau[j], 32, "originalistic tau");
          liboprf_debug = 0;
        }
        if(0!=vss_share(n,t,s[0].value, ci_tau[j], &ci_commitments[j][1], ci_shares[j])) return 1;
        break;
      }
    }
  }
  fprintf(stderr, "[6] VSPS check on P_i sharing\n");

  for(unsigned i=0;i<n;i++) { // todo possibly needs adjustment due to usage of reconstructed values.
    // step 7. P_i computes:
    //      2t+1
    //  γ_i = Σ c_ji
    //       j=1
    //  which is a share of γ = αβ, via random polynomial of degree t and
    //      2t+1
    //  τ_i = Σ τ_ji
    //       j=1
    memcpy(&r_shares[i][0], &ci_shares[0][i][0], TOPRF_Share_BYTES);
    memcpy(&r_shares[i][1], &ci_shares[0][i][1], TOPRF_Share_BYTES);
    for(unsigned j=1;j<dealers;j++) {
      crypto_core_ristretto255_scalar_add(r_shares[i][0].value, r_shares[i][0].value, ci_shares[j][i][0].value);
      crypto_core_ristretto255_scalar_add(r_shares[i][1].value, r_shares[i][1].value, ci_shares[j][i][1].value);
    }

    // step 8. P_i computes and broadcasts
    //    𝓒_i = 𝓗(γ_i, τ_i)
    //        = g^(γ_i)*h^(τ_i)
    //
    //        2t+1
    //        = Π 𝓒_ji
    //         j=1
    if(0!=dkg_vss_commit(r_shares[i][0].value, r_shares[i][1].value, C_i[i])) return 1;
    // use this below to calculate all commitments for the other peers
    uint8_t Cx_i[crypto_scalarmult_ristretto255_BYTES];
    memcpy(Cx_i,ci_commitments[0][i+1], crypto_scalarmult_ristretto255_BYTES);
    for(unsigned j=1;j<dealers;j++) {
      crypto_core_ristretto255_add(Cx_i, Cx_i, ci_commitments[j][i+1]);
    }
    if(memcmp(Cx_i, C_i[i], sizeof Cx_i) != 0) return 1;
  }
  fprintf(stderr, "[7&8] calculated final shares of a*b and their commitments\n");

  memcpy(r_commitments, C_i, n*crypto_scalarmult_ristretto255_BYTES);

  return 0;
}

int test_interpol(void) {
  fprintf(stderr, "testing interpol()\n");
  liboprf_debug = 1;
  uint8_t n=13, t=6;
  TOPRF_Share vss_shares[n][2];
  uint8_t commitments[n][crypto_core_ristretto255_BYTES];
  if(dkg_vss_share(n, t, NULL, commitments, vss_shares, NULL)) return 1;

  TOPRF_Share shares[n];
  for(unsigned i=0;i<n;i++) {
    for(unsigned j=0,k=0;j<t;k++) {
      if(k==i) {
        //dump(vss_shares[i][0].value, 32, "target %d", vss_shares[i][0].index);
        continue;
      }
      memcpy(&shares[j++], &vss_shares[k][0], TOPRF_Share_BYTES);
    }
    TOPRF_Share share;
    share.index=i+1;
    interpolate(i+1, t, shares, share.value);
    if(memcmp(vss_shares[i][0].value,share.value, 32)!=0) return 1;
    //dump(vss_shares[i][0].value, 32, "vshare %d", vss_shares[i][0].index);
    //dump(share.value, 32, "rshare %d", i+1);
  }

  TOPRF_Share share;
  share.index=0;
  interpolate(0, t, shares, share.value);
  dump(share.value, 32, "secret   ");

  fprintf(stderr, "success: interpol()\n");
  return 0;
}

static void sort_shares(const int n, uint8_t arr[n], uint8_t indexes[n]) {
  for (uint8_t c = 1 ; c <= n - 1; c++) {
    uint8_t d = c, t, t1;
    while(d > 0 && arr[d] < arr[d-1]) {
      t = arr[d];
      t1 = indexes[d];
      arr[d] = arr[d-1];
      indexes[d] = indexes[d-1];
      arr[d-1] = t;
      indexes[d-1] = t1;
      d--;
    }
  }
}

int test_sort_shares(void) {
  //uint8_t shares[8] = { 12, 1, 8, 7, 3, 11, 10, 5 };
  uint8_t qual[4] =       { 12, 3, 7, 5 };
  uint8_t sorted_qual[4] = { 0, 4, 3, 7 };
  sort_shares(4, qual, sorted_qual);
  const uint8_t vqual[4] =        { 3, 5, 7, 12};
  const uint8_t vsorted_qual[4] = { 4, 7, 3,  0};
  if(memcmp(vqual, qual, 4)!=0) return 1;
  if(memcmp(vsorted_qual, sorted_qual, 4)!=0) return 1;
  return 0;
}

int main(void) {
  liboprf_log_file = stderr;
  liboprf_debug = 0;

  if(test_sort_shares()!=0) return 1;
  if(test_interpol()!=0) return 1;

  uint8_t n=13, t=6;
  TOPRF_Share a_shares[n][2];
  uint8_t a_commitments[n][crypto_core_ristretto255_BYTES];
  if(dkg_vss_share(n, t, NULL, a_commitments, a_shares, NULL)) return 1;

  uint8_t a[crypto_scalarmult_ristretto255_SCALARBYTES];
  if(0!=dkg_vss_reconstruct(t, 0, n, a_shares, a_commitments, a, NULL)) return 1;
  liboprf_debug=1; dump(a, sizeof a, "a");liboprf_debug=0;

  // step 2. generate ρ
  TOPRF_Share b_shares[n][2];
  uint8_t b_commitments[n][crypto_core_ristretto255_BYTES];
  // generate kc, the original old key, we are gonna update
  if(dkg_vss_share(n, t, NULL, b_commitments, b_shares, NULL)) return 1;

  uint8_t b[crypto_scalarmult_ristretto255_SCALARBYTES];
  if(0!=dkg_vss_reconstruct(t, 0, n, b_shares, b_commitments, b, NULL)) return 1;
  liboprf_debug=1; dump(b, sizeof b, "b");liboprf_debug=0;

  if(0!=toprf_mpc_vsps_check(t-1, a_commitments)) return 1;
  if(0!=toprf_mpc_vsps_check(t-1, b_commitments)) return 1;
  fprintf(stderr, "[0] vsps(A_i) & vsps(B_i) ok\n");

  // 3. execute the FT-Mult protocol, to calculate FT-Mult(kc, ρ), generating sharings of r.
  TOPRF_Share r_shares[n][2];
  uint8_t r_commitments[n][crypto_core_ristretto255_BYTES];
  if(0!=ft_mult(n, t, a_shares, a_commitments, b_shares, b_commitments, r_shares, r_commitments)) return 1;

  uint8_t r[crypto_scalarmult_ristretto255_SCALARBYTES];
  if(0!=dkg_vss_reconstruct(t, 0, n, r_shares, r_commitments, r, NULL)) return 1;
  liboprf_debug=1;dump(r, sizeof r, "r  ");liboprf_debug=0;

  uint8_t tmp[crypto_scalarmult_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_mul(tmp, a, b);
  liboprf_debug=1;dump(tmp, sizeof tmp, "a*b");liboprf_debug=0;

  if(memcmp(tmp, r, sizeof tmp)!=0) {
    fprintf(liboprf_log_file,RED"fail a*b != ft-mul(a,b)\n"NORMAL);
    return 1;
  }
  fprintf(stderr, GREEN"everything correct!\n"NORMAL);
  return 0;
}
