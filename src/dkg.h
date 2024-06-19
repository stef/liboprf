#ifndef DKG_H
#define DKG_H

#include <sodium.h>
#include <stdint.h>

#define dkg_hash_BYTES crypto_generichash_BYTES
#define dkg_commitment_BYTES(threshold) (threshold*crypto_core_ristretto255_BYTES)

typedef struct {
  uint8_t index;
  uint8_t value[crypto_core_ristretto255_SCALARBYTES];
} __attribute((packed)) TOPRF_Share;

#define HASH ((uint8_t) 1)
#define COMMITMENT ((uint8_t) 2)

typedef struct {
  uint8_t type;
  uint8_t index;
} __attribute((packed)) DKG_Fail;

/**
 * 1st step in the DKG protocol to be executed by all peers participating.
 *
 * @param [in] n - the number of peers participating in the DKG
 * @param [in] threshold - the threshold (must be greater 1 and less than n)
 * @param [out] commitment_hash[dkg_hash_BYTES] - a hash - to be broadcast first
 * @param [out] commitments[dkg_signed_commitment_BYTES] - to
 *              be broadcast after receiving all hashes
 *              broadcasts
 * @param [out] shares[n] - one share for each peer, to be sent
 *              privately to each peer after receving all of the
 *              commitment_hash broadcasts
 * @return The function returns 0 if everything is correct.
 */
int dkg_start(const uint8_t n,
              const uint8_t threshold,
              uint8_t commitment_hash[dkg_hash_BYTES],
              uint8_t commitments[threshold][crypto_core_ristretto255_BYTES],
              TOPRF_Share shares[n]);

int dkg_verify_commitments(const uint8_t n,
                           const uint8_t threshold,
                           const uint8_t self,
                           const uint8_t hashes[n][crypto_generichash_BYTES],
                           const uint8_t commitments[n][threshold][crypto_core_ristretto255_BYTES],
                           const TOPRF_Share shares[n],
                           DKG_Fail fails[2*n],
                           uint16_t *fails_len);

void dkg_finish(const uint8_t n,
                const TOPRF_Share shares[n],
                const uint8_t self,
                TOPRF_Share *xi);

void dkg_reconstruct(const size_t response_len,
                     const TOPRF_Share responses[response_len],
                     uint8_t result[crypto_scalarmult_ristretto255_BYTES]);

#endif // DKG_H
