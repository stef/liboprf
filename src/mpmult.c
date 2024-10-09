#include <sodium.h>
#include <stdint.h>
#include <string.h>
#include "toprf.h"

/** Implements the Simple-Mult algorithm from page 5 fig. 2 of
    "Simplified VSS and Fast-track Multiparty Computations with
    Applications to Threshold Cryptography" by Gennaro, Rabin, Rabin,
    1998.
 */

typedef struct {
  uint8_t index;
  uint8_t value[crypto_core_ristretto255_SCALARBYTES];
} __attribute((packed)) TOPRF_Share;

static int cmp(uint8_t a[crypto_core_ristretto255_SCALARBYTES], uint8_t b[crypto_core_ristretto255_SCALARBYTES]) {
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
    for(int i=j;i<n;i++) {
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
  memset(matrix,0,index_len*index_len*crypto_core_ristretto255_SCALARBYTES);
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
  uint8_t vdm[dealers][dealers][crypto_core_ristretto255_SCALARBYTES];
  genVDMmatrix(indexes, dealers, vdm);
  uint8_t inverted[dealers][dealers][crypto_core_ristretto255_SCALARBYTES];
  invert(dealers, vdm, inverted);
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
