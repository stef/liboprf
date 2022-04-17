/*
    @copyright 2022, toprf@ctrlc.hu
    This file is part of liboprf.

    liboprf is free software: you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public License
    as published by the Free Software Foundation, either version 3 of
    the License, or (at your option) any later version.

    liboprf is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with liboprf. If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "sss.h"
#include "oprf.h"

#ifndef HAVE_SODIUM_HKDF
#include "aux/crypto_kdf_hkdf_sha512.h"
#endif

static void dump(const uint8_t *p, const size_t len, const char* msg) {
  size_t i;
  printf("%s ",msg);
  for(i=0;i<len;i++)
    printf("%02x", p[i]);
  printf("\n");
}

int toprf_init(const unsigned shares,
               const uint8_t *input, const size_t input_len,
               uint8_t r[shares][crypto_core_ristretto255_SCALARBYTES],
               uint8_t alphas[shares][crypto_core_ristretto255_BYTES]) {
  unsigned i;
  int err;
  for(i=0;i<shares;i++) {
    err = oprf_Blind(input, input_len, r[i], alphas[i]);
    if(err) return err;
  }
  return 0;
}

int toprf_share(const unsigned shares,
                const unsigned threshold,
                const uint8_t *input, const size_t input_len,
                const uint8_t r[shares][crypto_core_ristretto255_SCALARBYTES],
                const uint8_t betas[shares][crypto_core_ristretto255_BYTES],
                sss_Share xshares[shares],
                uint8_t result[sss_MLEN]) {
  unsigned i,j;
  int err;
  uint8_t N[shares][crypto_core_ristretto255_BYTES];
  uint8_t o[shares][OPRF_BYTES];

  memset(result,0,sss_MLEN);

  printf("oprf results:\n");
  for(i=0;i<shares;i++) {
    err = oprf_Unblind(r[i], betas[i], N[i]);
    if(err) return err;
    err = oprf_Finalize(input, input_len, N[i], o[i]);
    if(err) return err;
    printf("%d ",i);
    dump(N[i],crypto_core_ristretto255_BYTES, "\tN");
    dump(o[i],OPRF_BYTES, "\to");
    for(j=0;j<sss_MLEN;j++) result[j]^=o[i][j];
  }
  dump(result,sss_MLEN,"toprf output");

  sss_create_shares(xshares, result, shares, threshold);

  // xor-encrypt shares with hkdf(oprf_i)
  printf("shares:\n");
  uint8_t tmp[sizeof(sss_Share)];
  for(i=0;i<shares;i++) {
    err = crypto_kdf_hkdf_sha512_expand(tmp, sizeof tmp, "T-OPRF Share Key", 16, o[i]);
    printf("%d ",i);
    dump(xshares[i],sizeof(sss_Share),"share");
    for(j=0;j<sizeof tmp;j++) xshares[i][j]^=tmp[j];
  }

  return 0;
}


int toprf_recover(const unsigned shares_len,
                  const uint8_t *input, const size_t input_len,
                  const uint8_t r[shares_len][crypto_core_ristretto255_SCALARBYTES],
                  const uint8_t betas[shares_len][crypto_core_ristretto255_BYTES],
                  sss_Share xshares[shares_len],
                  uint8_t result[sss_MLEN]) {
  unsigned i,j;
  int err;
  uint8_t N[shares_len][crypto_core_ristretto255_BYTES];
  uint8_t o[shares_len][OPRF_BYTES];

  memset(result,0,sss_MLEN);

  printf("oprf results:\n");
  for(i=0;i<shares_len;i++) {
    err = oprf_Unblind(r[i], betas[i], N[i]);
    if(err) return err;
    err = oprf_Finalize(input, input_len, N[i], o[i]);
    if(err) return err;
    printf("%d ",i);
    dump(N[i],crypto_core_ristretto255_BYTES, "\tN");
    dump(o[i],OPRF_BYTES, "\to");
  }

  // xor-decrypt shares with hkdf(oprf_i)
  sss_Share shares[shares_len];
  uint8_t tmp[sizeof(sss_Share)];
  printf("shares:\n");
  for(i=0;i<shares_len;i++) {
    err = crypto_kdf_hkdf_sha512_expand(tmp, sizeof tmp, "T-OPRF Share Key", 16, o[i]);
    for(j=0;j<sizeof tmp;j++) shares[i][j]=xshares[i][j]^tmp[j];
    printf("%d ",i);
    dump(shares[i],sizeof(sss_Share),"share");
  }

  err = sss_combine_shares(result, shares, 4);
  if(err) return err;
  dump(result,sss_MLEN,"toprf output");

  return 0;
}
