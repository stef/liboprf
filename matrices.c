#include <sodium.h>
#include <stdint.h>
#include <string.h>

static int cmp(uint8_t a[crypto_core_ristretto255_SCALARBYTES], uint8_t b[crypto_core_ristretto255_SCALARBYTES]) {
  // non-const time!
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

void invert(const uint8_t n,
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

void genVDMmatrix(const uint8_t indexes[], const uint8_t index_len,
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

#ifdef UNIT_TEST
#include <assert.h>
#include <stdio.h>

static void dump(const uint8_t *p, const size_t len, const char* msg) {
  size_t i;
  fprintf(stderr,"%s ",msg);
  for(i=0;i<len;i++)
    fprintf(stderr,"%02x", p[i]);
  //fprintf(stderr,"\n");
}

static void print_matrix(const uint8_t size, const uint8_t matrix[size][size][crypto_core_ristretto255_SCALARBYTES]) {
  for(int i=0;i<size;i++) {
    for(int j=0;j<size;j++) {
      uint8_t len=crypto_core_ristretto255_SCALARBYTES-1;
      for(; matrix[i][j][len]==0; len--);
      dump(matrix[i][j],len+1,"");
      fprintf(stderr, " ");
    }
    fprintf(stderr, "\n");
  }
}

int main(void) {
  const uint8_t indexes[]={1,3,5,7,9,11,13};
  //const uint8_t indexes[]={1,3,5,7,9,11,13,2,4,6,8,10,12,14,15,16,17,18,19,20,21,22,23,24,25,26,27};
  const uint8_t t=(sizeof(indexes)-1)/2;
  uint8_t vdm[t*2+1][t*2+1][crypto_core_ristretto255_SCALARBYTES];
  memset(vdm,0,(t*2+1)*(t*2+1)*crypto_core_ristretto255_SCALARBYTES);
  genVDMmatrix(indexes, sizeof indexes, vdm);
  print_matrix(t*2+1, vdm);
  printf("\n");
  uint8_t inverted[sizeof indexes][sizeof indexes][crypto_core_ristretto255_SCALARBYTES];
  assert(sizeof inverted == sizeof vdm);
  invert(sizeof indexes, vdm, inverted);
  print_matrix(t*2+1, inverted);
  printf("\n");
  uint8_t original[sizeof indexes][sizeof indexes][crypto_core_ristretto255_SCALARBYTES];
  invert(sizeof indexes, inverted, original);
  print_matrix(t*2+1, original);
  printf("\n");

  return 0;
}
#endif // unittest
