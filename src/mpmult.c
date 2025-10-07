#include <sodium.h>
#include <stdint.h>
#include <string.h>
#include "toprf.h"
#include "dkg-vss.h"
#include "dkg.h"
#ifdef UNIT_TEST
#include "utils.h"
#endif

/** Implements the Simple-Mult algorithm from page 5 fig. 2 of
    "Simplified VSS and Fast-track Multiparty Computations with
    Applications to Threshold Cryptography" by Gennaro, Rabin, Rabin,
    1998.
 */

static int cmp(const uint8_t a[crypto_core_ristretto255_SCALARBYTES], const uint8_t b[crypto_core_ristretto255_SCALARBYTES]) {
  // non-const time! but its ok, this operates on the vandermonde matrix, no secrets involved
  for(int i=crypto_core_ristretto255_SCALARBYTES-1;i>=0;i--) {
    if(a[i]>b[i]) return 1;
    if(a[i]<b[i]) return -1;
  }
  return 0;
}

static void r255div(uint8_t r[crypto_core_ristretto255_SCALARBYTES],
         const uint8_t a[crypto_core_ristretto255_SCALARBYTES],
         const uint8_t b[crypto_core_ristretto255_SCALARBYTES]) {
      uint8_t b_inv[crypto_core_ristretto255_SCALARBYTES];
      crypto_core_ristretto255_scalar_invert(b_inv, b);
      crypto_core_ristretto255_scalar_mul(r, a, b_inv);
}

static void gaussian(const uint8_t n, uint8_t a[n][n][crypto_core_ristretto255_SCALARBYTES], uint8_t index[n]) {
  uint8_t c[n][crypto_core_ristretto255_SCALARBYTES];
  memset(c,0,sizeof c);

  for(uint8_t i=0;i<n;i++) {
    index[i]=i;
  }

  for(uint8_t i=0; i<n; i++) {
    uint8_t c1[crypto_core_ristretto255_SCALARBYTES]={0};
    for(uint8_t j=0; j<n; j++) {
      if(cmp(a[i][j],c1)>0) {// a[i][j] > c1
        memcpy(c1,&a[i][j],crypto_core_ristretto255_SCALARBYTES);
      }
    }
    memcpy(&c[i],c1,crypto_core_ristretto255_SCALARBYTES);
  }

  uint8_t k=0;
  for(uint8_t j=0;j<n - 1;j++) {
    uint8_t pi1[crypto_core_ristretto255_SCALARBYTES]={0};
    for(uint8_t i=j;i<n;i++) {
      uint8_t pi0[crypto_core_ristretto255_SCALARBYTES];

      // pi0 = a[index[i]][j] / c[index[i]]
      r255div(pi0, a[index[i]][j], c[index[i]]);
      // pi0 > pi1?
      if(cmp(pi0,pi1)>0) {// pi0 > pi1
        memcpy(pi1,pi0,crypto_core_ristretto255_SCALARBYTES);
        k=i;
      }
    }

    // swap index[j] and index[k]
    uint8_t prev_index_j=index[j];
    index[j] = index[k];
    index[k] = prev_index_j;

    for(uint8_t i=j+1; i<n; i++) {
      // pj = a[index[i]][j] / a[index[j]][j]
      uint8_t pj[crypto_core_ristretto255_SCALARBYTES];
      r255div(pj, a[index[i]][j], a[index[j]][j]);

      memcpy(&a[index[i]][j], pj, crypto_core_ristretto255_SCALARBYTES);

      for(uint8_t l=j+1; l<n; l++) {
        uint8_t tmp[crypto_core_ristretto255_SCALARBYTES];
        // a[index[i]][l] -= pj * a[index[j]][l]
        crypto_core_ristretto255_scalar_mul(tmp, pj, a[index[j]][l]);
        crypto_core_ristretto255_scalar_sub(a[index[i]][l], a[index[i]][l], tmp);
      }
    }
  }
}

static void invert(const uint8_t n,
                   uint8_t a[n][n][crypto_core_ristretto255_SCALARBYTES],
                   uint8_t x[n][n][crypto_core_ristretto255_SCALARBYTES]) {
  uint8_t b[n][n][crypto_core_ristretto255_SCALARBYTES];
  memset(b,0,sizeof b);

  for(int i=0;i<n;i++) {
    b[i][i][0]=1;
  }
  uint8_t index[n];

  gaussian(n, a, index);

  for(uint8_t i=0; i < n-1; i++) {
    for(uint8_t j= i+1 ; j<n; j++) {
      for(uint8_t k=0; k<n; k++) {
        uint8_t tmp[crypto_core_ristretto255_SCALARBYTES];
        // b[index[j]][k] -= a[index[j]][i] * b[index[i]][k]
        crypto_core_ristretto255_scalar_mul(tmp, a[index[j]][i], b[index[i]][k]);
        crypto_core_ristretto255_scalar_sub(b[index[j]][k], b[index[j]][k], tmp);
      }
    }
  }

  for(uint8_t i=0; i<n; i++) {
    uint8_t tmp[crypto_core_ristretto255_SCALARBYTES];
    // x[n-1][i] = b[index[n-1]][i] / a[index[n-1]][n-1]
    crypto_core_ristretto255_scalar_invert(tmp, a[index[n-1]][n-1]);
    crypto_core_ristretto255_scalar_mul(x[n-1][i], b[index[n-1]][i], tmp);
    for(int j = n-2; j>=0; j--) {
      memcpy(&x[j][i], &b[index[j]][i], crypto_core_ristretto255_SCALARBYTES);
      for(int k = j+1; k<n; k++) {
        // x[j][i] -= a[index[j]][k] * x[k][i]
        crypto_core_ristretto255_scalar_mul(tmp, a[index[j]][k],x[k][i]);
        crypto_core_ristretto255_scalar_sub(x[j][i],x[j][i], tmp);
      }
      // x[j][i] /= a[index[j]][j]
      crypto_core_ristretto255_scalar_invert(tmp, a[index[j]][j]);
      crypto_core_ristretto255_scalar_mul(x[j][i], x[j][i], tmp);
    }
  }
}

static void genVDMmatrix(const uint8_t indexes[], const uint8_t index_len,
                         uint8_t matrix[index_len][index_len][crypto_core_ristretto255_SCALARBYTES]) {
  memset(matrix,0,index_len*index_len*((unsigned) crypto_core_ristretto255_SCALARBYTES));
  for(uint8_t i=0;i<index_len;i++) {
    uint8_t base[crypto_core_ristretto255_SCALARBYTES]={0};
    base[0]=indexes[i];
    for(uint8_t j=0;j<index_len;j++) {
      matrix[i][j][0]=1;
      for(uint8_t k=0;k<j;k++) {
        crypto_core_ristretto255_scalar_mul(matrix[i][j], matrix[i][j], base);
      }
    }
  }
}

void __attribute__((visibility("hidden"))) invertedVDMmatrix(const uint8_t dealers,
                                                             const uint8_t indexes[dealers],
                                                             uint8_t inverted[dealers][dealers][crypto_core_ristretto255_SCALARBYTES]) {
  uint8_t vdm[dealers][dealers][crypto_core_ristretto255_SCALARBYTES];
  genVDMmatrix(indexes, dealers, vdm);
  invert(dealers, vdm, inverted);
}

int toprf_mpc_mul_start(const uint8_t _a[TOPRF_Share_BYTES],
                        const uint8_t _b[TOPRF_Share_BYTES],
                        const uint8_t peers, const uint8_t threshold,
                        uint8_t shares[peers][TOPRF_Share_BYTES]) {
  const TOPRF_Share *a=(TOPRF_Share*) _a;
  const TOPRF_Share *b=(TOPRF_Share*) _b;

  if(a->index!=b->index ||
     peers<threshold ||
     threshold == 0) return 1;

  uint8_t ab[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_mul(ab, a->value, b->value);
  //dump(ab, sizeof ab, "ab");
  toprf_create_shares(ab, peers, threshold, shares);
  //for(unsigned j=0;j<peers;j++)
    //dump(shares[j], TOPRF_Share_BYTES, "mulshare");
  return 0;
}

void toprf_mpc_mul_finish(const uint8_t dealers,
                          const uint8_t indexes[dealers],
                          const uint8_t peer,
                          const uint8_t shares[dealers][TOPRF_Share_BYTES],
                          uint8_t _share[TOPRF_Share_BYTES]) {
  TOPRF_Share *share=(TOPRF_Share*) _share;

  // pre-calculate inverted vandermonde matrix of the indexes of the peers
  uint8_t inverted[dealers][dealers][crypto_core_ristretto255_SCALARBYTES];
  invertedVDMmatrix(dealers, indexes, inverted);
  // todo optimization
  // note this can be precomputed and broadcast to all peers, and only
  // the first row of this matix is actually needed by the peers.

  // execute step 2 of simple mult
  // H(j) = sum(lambda[i] * h[i](j) for i in 1..2t+1)
  memset(share,0,TOPRF_Share_BYTES);
  share->index=peer;
  uint8_t tmp[crypto_core_ristretto255_SCALARBYTES];
  for(unsigned i=0;i<dealers;i++) {
    crypto_core_ristretto255_scalar_mul(tmp, shares[i]+1, inverted[0][i]);
    //dump(shares[i], TOPRF_Share_BYTES, "mulshare[i][j]");
    crypto_core_ristretto255_scalar_add(share->value, share->value, tmp);
  }
  //dump(share->value, sizeof share->value, "share");
}

static int vsps_check(const uint8_t t,
                      const uint8_t A[t][crypto_core_ristretto255_BYTES],
                      const uint8_t lambda[t+1][t+1][crypto_core_ristretto255_SCALARBYTES],
                      const uint8_t delta_exp[t+1][crypto_core_ristretto255_SCALARBYTES],
                      uint8_t v[crypto_core_ristretto255_BYTES]) {
  // calculates Π(A_i ^ Δ_i), where i=1..t+1,  Δ_i = Σ(λ_ji * δ^j,  j= 0..t

  // v = 0
  memset(v, 0,crypto_core_ristretto255_BYTES);

  for(int i=0;i<=t;i++) {
    uint8_t delta_i[crypto_core_ristretto255_SCALARBYTES]={0};
    for(int j=0;j<=t;j++) {
      // calculate λ_ji * δ^j
      uint8_t tmp[crypto_core_ristretto255_SCALARBYTES];
#ifdef UNIT_TEST
      dump(lambda[j][i], crypto_core_ristretto255_SCALARBYTES, "vdm[%d,%d]", j, i);
      dump(delta_exp[j], crypto_core_ristretto255_SCALARBYTES, "d^%d", j);
#endif
      crypto_core_ristretto255_scalar_mul(tmp, lambda[j][i], delta_exp[j]);
      // Δ_i = sum_(j=0..t) (λ_ji * δ^j)
      crypto_core_ristretto255_scalar_add(delta_i, delta_i, tmp);
    }
#ifdef UNIT_TEST
    dump(delta_i,sizeof delta_i, "Δ%d", i);
#endif
    uint8_t tmp[crypto_core_ristretto255_BYTES];
    // A_i ^ Δ_i
    if(0!=crypto_scalarmult_ristretto255(tmp, delta_i, A[i])) return 1;
#ifdef UNIT_TEST
    dump(tmp, crypto_scalarmult_ristretto255_BYTES, "A%d^Δ%d", i, i);
#endif
    // Π, but we are in an additive group
    crypto_core_ristretto255_add(v, v, tmp);
  }

  return 0;
}

int toprf_mpc_vsps_check(const uint8_t t, const uint8_t A[t*2][crypto_core_ristretto255_BYTES]) {
  uint8_t indexes[t+1]; // p8para3L2: A0..At & At+1..A2t+1
  // left-hand side of the equation (1)
  for(uint8_t i=0;i<=t;i++) indexes[i]=i; // left side of equation Π i:=1..t, which is a typo? should be 0..t
  uint8_t lambda[t+1][t+1][crypto_core_ristretto255_SCALARBYTES];
  invertedVDMmatrix(t+1,indexes,lambda);
#ifdef UNIT_TEST
  if(liboprf_log_file!=NULL && liboprf_debug) fprintf(liboprf_log_file,"vdm1\n");
  for(int i=0;i<t+1;i++) {
    for(int j=0;j<t+1;j++) {
      if(liboprf_log_file!=NULL && liboprf_debug) fprintf(liboprf_log_file,"\t");
      dump(lambda[i][j], crypto_core_ristretto255_SCALARBYTES, "vdm[%d,%d]", i, j);
    }
  }
#endif

  // chose random δ, p8para3L4
  uint8_t delta[crypto_core_ristretto255_SCALARBYTES] = {0};
#ifdef UNIT_TEST
  debian_rng_scalar(delta);
  dump(delta,sizeof delta, "δ");
#else
  crypto_core_ristretto255_scalar_random(delta);
#endif

  // pre-calculate δ^j for j=0..t
  uint8_t delta_exp[t+1][crypto_core_ristretto255_SCALARBYTES];
  memset(delta_exp,0,sizeof delta_exp);
  delta_exp[0][0]=1;
  for(int exp=1;exp<=t;exp++) {
    crypto_core_ristretto255_scalar_mul(delta_exp[exp], delta_exp[exp-1], delta);
  }

  uint8_t lhs[crypto_core_ristretto255_BYTES] = {0};
  if(0!=vsps_check(t, A, lambda, delta_exp, lhs)) return 1;
#ifdef UNIT_TEST
  dump(lhs, sizeof lhs, "lhs");
#endif

  // right-hand side of the equation (1)
  // since the RHS has A_i, i:=t+1..2t+1 see p8para3L2
  for(uint8_t i=0;i<=t;i++) indexes[i]=(uint8_t) (t+1U+i);
  invertedVDMmatrix(t+1,indexes,lambda);
#ifdef UNIT_TEST
  if(liboprf_log_file!=NULL && liboprf_debug) fprintf(liboprf_log_file,"vdm2\n");
  for(int i=0;i<t+1;i++) {
    for(int j=0;j<t+1;j++) {
      if(liboprf_log_file!=NULL && liboprf_debug) fprintf(liboprf_log_file,"\t");
      dump(lambda[i][j], crypto_core_ristretto255_SCALARBYTES, "vdm[%d,%d]", i, j);
    }
  }
#endif

  uint8_t rhs[crypto_core_ristretto255_BYTES] = {0};
  if(0!=vsps_check(t, &A[t+1], lambda, delta_exp, rhs)) return 1;
#ifdef UNIT_TEST
  dump(rhs, sizeof rhs, "rhs");
#endif

  // lhs == rhs
  if(memcmp(lhs,rhs,sizeof lhs)!=0) return 1;
  return 0;
}

// todo remove dealers param, can be calculatted from t param
int toprf_mpc_ftmult_step1(const uint8_t dealers, const uint8_t n, const uint8_t t, const uint8_t self,
                           const TOPRF_Share alpha[2], const TOPRF_Share beta[2],
                           const uint8_t lambdas[dealers][crypto_core_ristretto255_SCALARBYTES],
                           TOPRF_Share ci_shares[n][2],
                           uint8_t ci_commitments[n+1][crypto_core_ristretto255_BYTES],
                           uint8_t ci_tau[crypto_core_ristretto255_SCALARBYTES]) {
  // step 1. Each player P_i shares λ_iα_iβ_i, using VSS
  if(lambdas==NULL) {
     uint8_t indexes[dealers];
     for(uint8_t i=0;i<dealers;i++) indexes[i]=i+1;

     // λ_i is row 1 of inv VDM matrix
     uint8_t vdm[dealers][dealers][crypto_core_ristretto255_SCALARBYTES];
     invertedVDMmatrix(dealers, indexes, vdm);
     lambdas = vdm[0];
  }

  //dump((uint8_t*) alpha, sizeof(TOPRF_Share)*2, "alpha[%d]", self);
  //dump((uint8_t*) beta, sizeof(TOPRF_Share)*2, "beta[%d]", self);

  // c_ij = 𝑓_αβ,i(j), where 𝑓_αβ,i is a random polynomials of degree t, such that 𝑓_αβ,i(0) = λ_iα_iβ_i
  // τ_ij = u_i(j), where u_i(j) is a random polynomials of degree t

  uint8_t lambda_ai_bi[crypto_scalarmult_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_mul(lambda_ai_bi, alpha[0].value, beta[0].value);
  crypto_core_ristretto255_scalar_mul(lambda_ai_bi, lambda_ai_bi, lambdas[self]);
  if(0!=dkg_vss_share(n,t,lambda_ai_bi, &ci_commitments[1], ci_shares, ci_tau)) return 1;
  // c_i0 for the sake of the ZK proof is g^λab * h^t
  if(0!=dkg_vss_commit(lambda_ai_bi, ci_tau, ci_commitments[0])) return 1;

  //fprintf(stderr, "ftmult s1: %d\n", self);
  //for(unsigned i=0;i<n+1;i++) dump(ci_commitments[i], crypto_core_ristretto255_BYTES, "c_%d%d", self, i);
  //for(unsigned i=0;i<n;i++) dump((uint8_t*) ci_shares[i], sizeof(TOPRF_Share)*2, "s_%d%d", self, i);

  // send ci_shares[j] to P_j
  // broadcast ci_commitments
  return 0;
}

int toprf_mpc_ftmult_zk_commitments(const uint8_t B_i[crypto_core_ristretto255_BYTES],
                                    uint8_t d[crypto_scalarmult_ristretto255_SCALARBYTES],
                                    uint8_t s[crypto_scalarmult_ristretto255_SCALARBYTES],
                                    uint8_t x[crypto_scalarmult_ristretto255_SCALARBYTES],
                                    uint8_t s_1[crypto_scalarmult_ristretto255_SCALARBYTES],
                                    uint8_t s_2[crypto_scalarmult_ristretto255_SCALARBYTES],
                                    uint8_t zk_commitments[3][crypto_scalarmult_ristretto255_BYTES]) {
  // step 2.2 P_i chooses d, s, x, s_1, s_2 ∈ Z_q. Sends to the verifier the messages:
  //  M   = g^d * h^s,
  //  M_1 = g^x * h^s_1,
  //  M_2 = B^x * h^s_2
  crypto_core_ristretto255_scalar_random(d);
  crypto_core_ristretto255_scalar_random(s);
  crypto_core_ristretto255_scalar_random(x);
  crypto_core_ristretto255_scalar_random(s_1);
  crypto_core_ristretto255_scalar_random(s_2);

  //dump(d, crypto_scalarmult_ristretto255_SCALARBYTES, "    d");
  //dump(s, crypto_scalarmult_ristretto255_SCALARBYTES, "    s");
  //dump(x, crypto_scalarmult_ristretto255_SCALARBYTES, "    x");
  //dump(s_1, crypto_scalarmult_ristretto255_SCALARBYTES, "    s_1");
  //dump(s_2, crypto_scalarmult_ristretto255_SCALARBYTES, "    s_2");
  //  M   = g^d * h^s,
  if(0!=dkg_vss_commit(d,s, zk_commitments[0])) return 1;
  //dump(zk_commitments[0], crypto_scalarmult_ristretto255_BYTES, "    M");
  //  M_1 = g^x * h^s_1,
  if(0!=dkg_vss_commit(x,s_1, zk_commitments[1])) return 1;
  //dump(zk_commitments[1], crypto_scalarmult_ristretto255_BYTES, "   M1");
  //  M_2 = B^x * h^s_2
  uint8_t tmp[crypto_scalarmult_ristretto255_BYTES];
  if(crypto_scalarmult_ristretto255(tmp, x, B_i)) return 1;
  if(crypto_scalarmult_ristretto255(zk_commitments[2], s_2, H)) return 1;
  crypto_core_ristretto255_add(zk_commitments[2], zk_commitments[2], tmp);
  //dump(zk_commitments[2], crypto_scalarmult_ristretto255_BYTES, "   M2");
  return 0;
}
