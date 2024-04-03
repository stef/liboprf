#ifndef DKG_H
#define DKG_H

#include <sodium.h>
#include <stdint.h>

#define dkg_hash_BYTES crypto_generichash_BYTES
#define dkg_sign_SECRETKEYBYTES crypto_sign_SECRETKEYBYTES
#define dkg_commitment_BYTES(threshold) (threshold*crypto_core_ristretto255_BYTES)
#define dkg_signed_commitment_BYTES(threshold) (crypto_sign_BYTES+dkg_commitment_BYTES(threshold))

typedef struct {
  uint8_t index;
  uint8_t value[crypto_core_ristretto255_SCALARBYTES];
} __attribute((packed)) TOPRF_Share;

/**
 * 1st step in the DKG protocol to be executed by all peers participating.
 *
 * @param [in] n - the number of peers participating in the DKG
 * @param [in] threshold - the threshold (must be greater 1 and less than n)
 * @param [in] sk[dkg_sign_SECRETKEYBYTES] - an crypto_sign private
 *             key to sign all broadcast messages
 * @param [out] commitment_hash[dkg_hash_BYTES] - a hash - to be
 *              broadcast first
 * @param [out] signed_commitments[dkg_signed_commitment_BYTES] - to
 *              be broadcast after receiving all commitment_hash
 *              broadcasts
 * @param [out] shares[n] - one share for each peer, to be sent
 *              privately to each peer after receving all of the
 *              commitment_hash broadcasts
 * @param [out] transcript - a running hash of all broadcasts through
 *              all steps of the protocol.
 * @return The function returns 0 if everything is correct.
 */
int dkg_start(const uint8_t n,
              const uint8_t threshold,
              const uint8_t sk[dkg_sign_SECRETKEYBYTES],
              uint8_t commitment_hash[dkg_hash_BYTES],
              uint8_t signed_commitments[dkg_signed_commitment_BYTES(threshold)],
              TOPRF_Share shares[n],
              crypto_generichash_state *transcript);

int dkg_verify_commitments(const uint8_t n,
                           const uint8_t threshold,
                           const uint8_t self,
                           const uint8_t commitment_hashes[n][crypto_generichash_BYTES],
                           const uint8_t signed_commitments[n][crypto_sign_BYTES+(threshold*crypto_core_ristretto255_BYTES)],
                           const uint8_t pk[n][crypto_sign_PUBLICKEYBYTES],
                           const TOPRF_Share shares[n],
                           uint8_t failed_sigs[n],
                           uint8_t *failed_sigs_len,
                           uint8_t failed_hashes[n],
                           uint8_t *failed_hashes_len,
                           uint8_t complaints[n],
                           uint8_t *complaints_len,
                           crypto_generichash_state *transcript);

void dkg_finish(const uint8_t n,
                const TOPRF_Share shares[n],
                const uint8_t self,
                const uint8_t sk[crypto_sign_SECRETKEYBYTES],
                crypto_generichash_state *transcript,
                TOPRF_Share *xi,
                uint8_t final_message[1+crypto_generichash_BYTES+crypto_sign_BYTES]);

int dkg_agree(const uint8_t n,
              const uint8_t pks[n][crypto_sign_PUBLICKEYBYTES],
              const uint8_t final_messages[n][1+crypto_generichash_BYTES+crypto_sign_BYTES]);

void dkg_reconstruct(const size_t response_len,
                     const TOPRF_Share responses[response_len][2],
                     uint8_t result[crypto_scalarmult_ristretto255_BYTES]);

#endif // DKG_H
