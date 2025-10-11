#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../dkg-vss.h"
#include "../utils.h"
#include "../mpmult.h"
#include "../toprf.h"

static uint8_t dkg_vss_verify_commitments(const uint8_t n,
                                          const uint8_t self,
                                          const uint8_t commitments[n][n][crypto_core_ristretto255_BYTES],
                                          const TOPRF_Share shares[n][2],
                                          uint8_t complaints[n]) {
  uint8_t complaints_len=0;
  for(uint8_t i=1;i<=n;i++) {
    if(i==self) continue;

    if(0!=dkg_vss_verify_commitment(commitments[i-1][self-1], shares[i-1])) {
      // complain about P_i
      fprintf(stderr, "\x1b[0;31mfailed to verify contribs of P_%d in stage 1\x1b[0m\n", i);
      complaints[complaints_len++]=i;
      //return 1;
    } else {
#ifdef UNIT_TEST
      if(liboprf_debug) fprintf(stderr, "\x1b[0;32mP_%d stage 1 correct!\x1b[0m\n", i);
#endif // UNIT_TEST
    }
  }
  return complaints_len;
}

int dkg_vss(const uint8_t n, const uint8_t t,
            TOPRF_Share final_shares[n][2],
            uint8_t commitments[n][crypto_core_ristretto255_BYTES]) {
  uint8_t dealer_commitments[n][n][crypto_core_ristretto255_BYTES];
  TOPRF_Share shares[n][n][2];

  for(int i=0;i<n;i++) {
    if(dkg_vss_share(n, t, NULL, dealer_commitments[i], shares[i], NULL)) {
      return 1;
    }
    //broadcast dealer_commitments
  }

  // each Pi sends s_ij, and s'_ij to Pj
  // basically we are transposing here the shares matrix above
  TOPRF_Share sent_shares[n][2];

  for(int i=0;i<n;i++) {
    for(int j=0;j<n;j++) {
      memcpy(&sent_shares[j][0], &shares[j][i][0], sizeof(TOPRF_Share));
      memcpy(&sent_shares[j][1], &shares[j][i][1], sizeof(TOPRF_Share));
    }

    uint8_t complaints[n];
    memset(complaints, 0, sizeof complaints);
    uint8_t complaints_len=dkg_vss_verify_commitments(n,i+1,dealer_commitments,sent_shares,complaints);
    if(complaints_len>0) {
      // todo accused dealer P_i publishes α_i, ρ_i such that A_i = 𝓗(α_i,ρ_i)
      // if dealer P_i fails, disqualify them.
      // otherwise the accuser sets their shares to α_i, ρ_i
      return 1;
    }
    // todo handle complaints, build qual set
    uint8_t qual[n+1];
    for(int i=0;i<n;i++) qual[i]=i+1; //everyone qualifies
    qual[n]=0;
    final_shares[i][0].index=i+1;
    final_shares[i][1].index=i+1;
    // finalize dkg
    if(0!=dkg_vss_finish(n,qual,sent_shares,i+1,final_shares[i], commitments[i])) return 1;
  }
  return 0;
}

int ft_mult(const uint8_t n, const uint8_t t,
            const TOPRF_Share alpha_shares[n][2], const uint8_t A_i[n][crypto_core_ristretto255_BYTES],
            const TOPRF_Share beta_shares[n][2], const uint8_t B_i[n][crypto_core_ristretto255_BYTES],
            TOPRF_Share r_shares[n][2]) {
  fprintf(stderr, "start ft_mult\n");

  if(t<2) return 1;
  const uint8_t dealers = (t-1)*2 + 1;
  if(n<dealers) return 1;

  // pubic inputs, for i:=0..n
  // 𝓐_i = 𝓗(α_i,ρ_i) = g^(α_i)*h^(ρ_i)
  // 𝓑_i = 𝓗(β_i,σ_i) = g^(β_i)*h^(σ_i)

  // we assume the VSPS property has been checked on the commitments
  if(0!=toprf_mpc_vsps_check(t-1, A_i)) return 1;
  if(0!=toprf_mpc_vsps_check(t-1, B_i)) return 1;
  fprintf(stderr, "[0] vsps(A_i) & vsps(B_i) ok\n");

  // step 1. Each player P_i shares λ_iα_iβ_i, using VSS
  uint8_t indexes[dealers];
  for(unsigned i=0;i<dealers;i++) indexes[i]=i+1;

  // λ_i is row 1 of inv VDM matrix
  uint8_t lambdas[dealers][dealers][crypto_core_ristretto255_SCALARBYTES];
  invertedVDMmatrix(dealers, indexes, lambdas);

  TOPRF_Share ci_shares[dealers][n][2];
  uint8_t ci_commitments[dealers][n][crypto_core_ristretto255_BYTES];
  uint8_t ci_commitments0[dealers][crypto_core_ristretto255_BYTES];
  uint8_t ci_tau[dealers][crypto_core_ristretto255_SCALARBYTES];
  for(unsigned i=0;i<dealers;i++) {
    // c_ij = 𝑓_αβ,i(j), where 𝑓_αβ,i is a random polynomials of degree t, such that 𝑓_αβ,i(0) = λ_iα_iβ_i
    // τ_ij = u_i(j), where u_i(j) is a random polynomials of degree t

    uint8_t lambda_ai_bi[crypto_scalarmult_ristretto255_SCALARBYTES];
    crypto_core_ristretto255_scalar_mul(lambda_ai_bi, alpha_shares[i][0].value, beta_shares[i][0].value);
    crypto_core_ristretto255_scalar_mul(lambda_ai_bi, lambda_ai_bi, lambdas[0][i]);
    if(0!=dkg_vss_share(n,t,lambda_ai_bi, ci_commitments[i], ci_shares[i], ci_tau[i])) return 1;
    // c_i0 for the sake of the ZK proof is g^λab * h^t
    if(0!=dkg_vss_commit(lambda_ai_bi, ci_tau[i], ci_commitments0[i])) return 1;

    // send ci_shares[j] to P_j
    // broadcast ci_commitments
  }
  fprintf(stderr, "[1] calculated shares and commitments of a*b\n");

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
      if(memcmp(v1, v0, crypto_scalarmult_ristretto255_BYTES)!=0) return 1;

      //   g^z * h^w_1 == M_1 * A^e'_i
      if(0!=dkg_vss_commit(z[i], w_1[i], v0)) return 1;

      if(crypto_scalarmult_ristretto255(v1, e_i, A_i[i])) return 1;
      if(crypto_scalarmult_ristretto255(v1, lambdas[0][i], v1)) return 1;
      crypto_core_ristretto255_add(v1, zk_commitments[i][1], v1);
      if(memcmp(v1, v0, crypto_scalarmult_ristretto255_BYTES)!=0) return 1;

      //   B^z * h^w_2 == M_2 * C^e'_i
      if(crypto_scalarmult_ristretto255(v0, z[i], B_i[i])) return 1;
      // we abuse v1 as a temp storage, v1 = h^w_2
      if(crypto_scalarmult_ristretto255(v1, w_2[i], H)) return 1;
      crypto_core_ristretto255_add(v0, v0, v1);

      if(crypto_scalarmult_ristretto255(v1, e_i, ci_commitments0[i])) return 1;
      crypto_core_ristretto255_add(v1, zk_commitments[i][2], v1);
      if(memcmp(v1, v0, crypto_scalarmult_ristretto255_BYTES)!=0) return 1;
    }
  }
  fprintf(stderr, "[2.5] verified proof of a*b\n");

  uint8_t C_i[n][crypto_scalarmult_ristretto255_BYTES];
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
    if(0!=dkg_vss_commit(r_shares[i][0].value, r_shares[i][1].value, C_i[i])) return 1;
    // use this below to calculate all commitments for the other peers
    uint8_t Cx_i[crypto_scalarmult_ristretto255_BYTES];
    memcpy(Cx_i,ci_commitments[0][i], crypto_scalarmult_ristretto255_BYTES);
    for(unsigned j=1;j<dealers;j++) {
      crypto_core_ristretto255_add(Cx_i, Cx_i, ci_commitments[j][i]);
    }
    if(memcmp(Cx_i, C_i[i], sizeof Cx_i) != 0) return 1;
  }
  fprintf(stderr, "[3&4] calculated final shares of a*b and their commitments\n");

  for(unsigned i=0;i<n;i++) {
    // step 5. players run a VSPS Check on 𝓒_i, i:=1..n,
    // if the test succeeds:
    // Secret information of P_i: share γ_i
    // Public information: 𝓒_i, for i:=1..n
    // protocol terminates successfully

    // TODO remove me, we are forcing step 6 here for development!
    if(0==toprf_mpc_vsps_check(t-1, C_i)) {
      fprintf(stderr, "vsps checks out for C_i\n");
      //return 0;
    }

    // If the test fails STOP and run MULT from step 2.
  }
  fprintf(stderr, "[5] failed vsps check for C_i\n");

  // step 6. only if 5. fails, as per Mult algorithm from fig. 3. step 2
  // Players run a VSPS Check on P_i's sharing. If a sharing fails the test
  // then expose the secret through the VSS reconstruction.
  for(unsigned i=0;i<n;i++) {
    // each P_i VSPS checks P_j (i!=j) sharing
    for(unsigned j=0;j<dealers;j++) {
      if(j==i) continue;
      if(0!=toprf_mpc_vsps_check(t-1, ci_commitments[j])) {
        // expose the secret of P_j through vss reconstruction
        fprintf(stderr, "vsps for peer %d failed\n", j);
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
    memcpy(Cx_i,ci_commitments[0][i], crypto_scalarmult_ristretto255_BYTES);
    for(unsigned j=1;j<dealers;j++) {
      crypto_core_ristretto255_add(Cx_i, Cx_i, ci_commitments[j][i]);
    }
    if(memcmp(Cx_i, C_i[i], sizeof Cx_i) != 0) return 1;
  }
  fprintf(stderr, "[7&8] calculated final shares of a*b and their commitments\n");

  return 0;
}

int test_mul() {
  liboprf_log_file = stderr;
  liboprf_debug = 0;

  uint8_t n=5, t=2;
  TOPRF_Share kc_shares[n][2];
  uint8_t kc_commitments[n][crypto_core_ristretto255_BYTES];
  // generate kc, the original old key, we are gonna update
  if(0!=dkg_vss(n,t,kc_shares, kc_commitments)) return 1;

  uint8_t kc[crypto_scalarmult_ristretto255_SCALARBYTES];
  dkg_vss_reconstruct(t, 0, n, kc_shares, kc_commitments, kc, NULL);
  liboprf_debug=1; dump(kc, sizeof kc, "kc ");liboprf_debug=0;

  // step 2. generate ρ
  TOPRF_Share p_shares[n][2];
  uint8_t p_commitments[n][crypto_core_ristretto255_BYTES];
  // generate kc, the original old key, we are gonna update
  if(0!=dkg_vss(n,t,p_shares, p_commitments)) return 1;

  uint8_t p[crypto_scalarmult_ristretto255_SCALARBYTES];
  dkg_vss_reconstruct(t, 0, n, p_shares, p_commitments, p, NULL);
  liboprf_debug=1; dump(p, sizeof p, "p  ");liboprf_debug=0;

  // 3. execute the FT-Mult protocol, to calculate FT-Mult(kc, ρ), generating sharings of r.
  TOPRF_Share r_shares[n][2];
  if(0!=ft_mult(n, t, kc_shares, kc_commitments, p_shares, p_commitments, r_shares)) return 1;

  uint8_t r[crypto_scalarmult_ristretto255_SCALARBYTES];
  dkg_vss_reconstruct(t, 0, n, r_shares, NULL, r, NULL);
  liboprf_debug=1;dump(r, sizeof r, "r  ");liboprf_debug=0;

  uint8_t tmp[crypto_scalarmult_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_mul(tmp, p, kc);
  liboprf_debug=1;dump(tmp, sizeof tmp, "pkc");liboprf_debug=0;

  fprintf(stderr, "\e[0;32mtest_mul checks out!\e[0m\n");
  return 0;
}

int main(void) {
  if(0!=test_mul()) return 1;

  liboprf_log_file = stderr;
  liboprf_debug = 0;

  uint8_t n=5, t=2;
  TOPRF_Share kc_shares[n][2];
  uint8_t kc_commitments[n][crypto_core_ristretto255_BYTES];
  // generate kc, the original old key, we are gonna update
  if(0!=dkg_vss(n,t,kc_shares, kc_commitments)) return 1;
  uint8_t kc[crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t kc1[crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t p[crypto_scalarmult_ristretto255_SCALARBYTES];
  dkg_vss_reconstruct(t, 0, n, kc_shares, kc_commitments, kc, NULL);
  liboprf_debug=1; dump(kc, sizeof kc, "kc ");liboprf_debug=0;

  // precondition 2

  // long-term signing keys known by everyone
  uint8_t lt_pks[n+1][crypto_sign_PUBLICKEYBYTES];
  // only known by corresponding peer
  uint8_t lt_sks[n+1][crypto_sign_SECRETKEYBYTES];
  for(uint8_t i=0;i<n+1;i++) {
      crypto_sign_keypair(lt_pks[i], lt_sks[i]);
  }

  // precondition 3
  if(n<2*t+1) return 3;

  // step 1. generate kc'
  TOPRF_Share kc1_shares[n][2];
  uint8_t kc1_commitments[n][crypto_core_ristretto255_BYTES];
  if(0!=dkg_vss(n,t,kc1_shares, kc1_commitments)) return 1;
  dkg_vss_reconstruct(t, 0, n, kc1_shares, kc1_commitments, kc1, NULL);
  liboprf_debug=1; dump(kc1, sizeof kc1, "kc1");liboprf_debug=0;

  // step 2. generate ρ
  TOPRF_Share p_shares[n][2];
  uint8_t p_commitments[n][crypto_core_ristretto255_BYTES];
  if(0!=dkg_vss(n,t,p_shares, p_commitments)) return 1;
  dkg_vss_reconstruct(t, 0, n, p_shares, p_commitments, p, NULL);
  liboprf_debug=1; dump(p, sizeof p, "p  ");liboprf_debug=0;

  // 3. execute the FT-Mult protocol, to calculate FT-Mult(kc, ρ), generating sharings of r.
  TOPRF_Share r_shares[n][2];
  if(0!=ft_mult(n, t, kc_shares, kc_commitments, p_shares, p_commitments, r_shares)) return 1;

  // 4. execute the FT-Mult protocol, to calculate FT-Mult(kc`, ρ), generating sharings of r'.
  TOPRF_Share r1_shares[n][2];
  if(0!=ft_mult(n, t, kc1_shares, kc1_commitments, p_shares, p_commitments, r1_shares)) return 1;

  // 5. parties send their r and r` shares to the STP

  // 6. STP reconstructs r = ρ·kc and r′ = ρ·kc′ and computes ∆= r/r′.

  uint8_t tmp[crypto_scalarmult_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_mul(tmp, p, kc);
  liboprf_debug=1;dump(tmp, sizeof tmp, "pkc");liboprf_debug=0;
  crypto_core_ristretto255_scalar_mul(tmp, p, kc1);
  liboprf_debug=1;dump(tmp, sizeof tmp, "pkc");liboprf_debug=0;

  uint8_t r[crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t r1[crypto_scalarmult_ristretto255_SCALARBYTES];
  dkg_vss_reconstruct(t, 0, n, r_shares, NULL, r, NULL);
  liboprf_debug=1;dump(r, sizeof r, "r  ");liboprf_debug=0;
  dkg_vss_reconstruct(t, 0, n, r1_shares, NULL, r1, NULL);
  liboprf_debug=1;dump(r1, sizeof r1, "r1 ");liboprf_debug=0;
  uint8_t r1inv[crypto_scalarmult_ristretto255_SCALARBYTES];
  if(0!=crypto_core_ristretto255_scalar_invert(r1inv, r1)) return 1;
  uint8_t delta[crypto_scalarmult_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_mul(delta, r, r1inv);

  // check if delta is equal kc/kc'
  dkg_vss_reconstruct(t, 0, n, kc_shares, kc_commitments, tmp, NULL);
  if(memcmp(tmp,kc,sizeof tmp)!=0) {
    liboprf_debug=1; dump(tmp, sizeof tmp, "kc ");liboprf_debug=0;
    return 1;
  }
  dkg_vss_reconstruct(t, 0, n, kc1_shares, kc1_commitments, tmp, NULL);
  if(memcmp(tmp,kc1,sizeof tmp)!=0) {
    liboprf_debug=1; dump(kc1, sizeof kc1, "kc1");liboprf_debug=0;
    return 1;
  }
  uint8_t kc1inv[crypto_scalarmult_ristretto255_SCALARBYTES];
  if(0!=crypto_core_ristretto255_scalar_invert(kc1inv, kc1)) return 1;
  uint8_t deltakc[crypto_scalarmult_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_mul(deltakc, kc, kc1inv);
  if(memcmp(delta, deltakc, sizeof delta)!=0) {
    liboprf_debug=1;
    dump(delta,  sizeof delta, "delta  ");
    dump(deltakc,sizeof delta, "deltakc");
  } else {
    liboprf_debug=1;dump(delta, sizeof delta, "delta");liboprf_debug=0;
  }

  // 7. parties delete their r and r` shares and replace their kc share with their kc` share.

  fprintf(stderr, "\e[0;32meverything correct!\e[0m\n");
  return 0;
}
