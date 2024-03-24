/** This file was automatically generated */

#include "Noise_XK.h"

inline bool Noise_XK_lbytes_eq(uint32_t len, uint8_t *b1, uint8_t *b2)
{
  uint8_t accp = (uint8_t)0U;
  for (uint32_t i = (uint32_t)0U; i < len; i++)
  {
    uint8_t x1 = b1[i];
    uint8_t x2 = b2[i];
    uint8_t diff = x1 ^ x2;
    uint8_t acc = accp;
    uint8_t acc_ = diff | acc;
    accp = acc_;
  }
  uint8_t r = accp;
  return r == (uint8_t)0U;
}

uint64_t Noise_XK_bytes_to_nonce(uint8_t *n8)
{
  uint64_t u = load64_le(n8);
  uint64_t nonce = u;
  return nonce;
}

Noise_XK_error_code Noise_XK_dh_secret_to_public(uint8_t *dest, uint8_t *priv)
{
#ifdef WITH_SODIUM
  crypto_scalarmult_base(dest, priv);
#else // WITH_SODIUM
  Hacl_Curve25519_64_secret_to_public(dest, priv);
#endif // WITH_SODIUM
  return Noise_XK_CSuccess;
}

Noise_XK_error_code Noise_XK_dh(uint8_t *dest, uint8_t *priv, uint8_t *pub)
{
#ifdef WITH_SODIUM
  bool b = crypto_scalarmult(dest, priv, pub) == 0;
#else // WITH_SODIUM
  bool b = Hacl_Curve25519_64_ecdh(dest, priv, pub);
#endif // WITH_SODIUM

  if (b)
    return Noise_XK_CSuccess;
  else
    return Noise_XK_CDH_error;
}

void
Noise_XK_aead_encrypt(
  uint8_t *key,
  uint64_t nonce,
  uint32_t aad_len,
  uint8_t *aad,
  uint32_t plen,
  uint8_t *plain,
  uint8_t *cipher
)
{
  uint8_t n12[12U] = { 0U };
  uint8_t *nonce12_end = n12 + (uint32_t)4U;
  store64_le(nonce12_end, nonce);
#ifdef WITH_SODIUM
  crypto_aead_chacha20poly1305_ietf_encrypt(cipher, NULL, plain, plen, aad, aad_len, NULL, n12, key);
  sodium_memzero(n12, (uint32_t)12U * sizeof (n12[0U]));
#else
  uint8_t *output = cipher;
  uint8_t *tag = cipher + plen;
  Hacl_Chacha20Poly1305_32_aead_encrypt(key, n12, aad_len, aad, plen, plain, output, tag);
  Lib_Memzero0_memzero(n12, (uint32_t)12U * sizeof (n12[0U]));
#endif // WITH_SODIUM
}

Noise_XK_error_code
Noise_XK_aead_decrypt(
  uint8_t *key,
  uint64_t nonce,
  uint32_t aad_len,
  uint8_t *aad,
  uint32_t plen,
  uint8_t *plain,
  uint8_t *cipher
)
{
  uint8_t n12[12U] = { 0U };
  uint8_t *nonce12_end = n12 + (uint32_t)4U;
  store64_le(nonce12_end, nonce);
#ifdef WITH_SODIUM
  uint32_t
    r = crypto_aead_chacha20poly1305_ietf_decrypt(plain,
                                              NULL,  // *plen
                                              NULL,  // nsec
                                              cipher,
                                              plen + crypto_aead_chacha20poly1305_ABYTES,
                                              aad,
                                              aad_len,
                                              n12,
                                              key);
  sodium_memzero(n12, (uint32_t)12U * sizeof (n12[0U]));
#else // WITH_SODIUM
  uint8_t *output = cipher;
  uint8_t *tag = cipher + plen;
  uint32_t
  r = Hacl_Chacha20Poly1305_32_aead_decrypt(key, n12, aad_len, aad, plen, plain, output, tag);
  Lib_Memzero0_memzero(n12, (uint32_t)12U * sizeof (n12[0U]));
#endif // WITH_SODIUM
  if (r == (uint32_t)0U)
    return Noise_XK_CSuccess;
  else
    return Noise_XK_CDecrypt_error;
}

void Noise_XK_hash(uint8_t *output, uint32_t inlen, uint8_t *input)
{
#ifdef WITH_SODIUM
  crypto_generichash(output, (uint32_t)64U, input, inlen, NULL, 0);
#else // WITH_SODIUM
  Hacl_Blake2b_32_blake2b((uint32_t)64U, output, inlen, input, (uint32_t)0U, NULL);
#endif // WITH_SODIUM
}

void Noise_XK_mix_hash(uint8_t *hash1, uint32_t inlen, uint8_t *input)
{
#ifdef WITH_SODIUM
  crypto_generichash_state state;
  crypto_generichash_init(&state, NULL, 0, 64);
  crypto_generichash_update(&state, hash1, 64);
  crypto_generichash_update(&state, input, inlen);
  crypto_generichash_final(&state, hash1, 64);
#else // WITH_SODIUM
  KRML_CHECK_SIZE(sizeof (uint8_t),
    Hacl_Streaming_Blake2_blocks_state_len(Spec_Blake2_Blake2B, Hacl_Impl_Blake2_Core_M32));
  uint8_t
  buf[Hacl_Streaming_Blake2_blocks_state_len(Spec_Blake2_Blake2B, Hacl_Impl_Blake2_Core_M32)];
  memset(buf,
    0U,
    Hacl_Streaming_Blake2_blocks_state_len(Spec_Blake2_Blake2B,
      Hacl_Impl_Blake2_Core_M32)
    * sizeof (uint8_t));
  KRML_CHECK_SIZE(sizeof (uint64_t), (uint32_t)4U * (uint32_t)4U);
  uint64_t wv[(uint32_t)4U * (uint32_t)4U];
  memset(wv, 0U, (uint32_t)4U * (uint32_t)4U * sizeof (uint64_t));
  KRML_CHECK_SIZE(sizeof (uint64_t), (uint32_t)4U * (uint32_t)4U);
  uint64_t b[(uint32_t)4U * (uint32_t)4U];
  memset(b, 0U, (uint32_t)4U * (uint32_t)4U * sizeof (uint64_t));
  Hacl_Streaming_Blake2_blake2b_32_block_state block_state = { .fst = wv, .snd = b };
  Hacl_Streaming_Blake2_blake2b_32_state
  s = { .block_state = block_state, .buf = buf, .total_len = (uint64_t)0U };
  Hacl_Streaming_Blake2_blake2b_32_state p = s;
  Hacl_Blake2b_32_blake2b_init(block_state.fst,
    block_state.snd,
    (uint32_t)0U,
    NULL,
    (uint32_t)64U);
  Hacl_Streaming_Blake2_blake2b_32_state *s0 = &p;
  Hacl_Streaming_Blake2_blake2b_32_no_key_update(s0, hash1, (uint32_t)64U);
  Hacl_Streaming_Blake2_blake2b_32_no_key_update(s0, input, inlen);
  Hacl_Streaming_Blake2_blake2b_32_no_key_finish(s0, hash1);
#endif // WITH_SODIUM
}

#ifdef WITH_SODIUM
#define HMAC_IPAD   0x36
#define HMAC_OPAD   0x5C

static void Noise_XK_hashstate_xor_key(uint8_t *key, size_t key_len, uint8_t value) {
  while (key_len > 0) {
    *key++ ^= value;
    --key_len;
  }
}
#endif // WITH_SODIUM

void
Noise_XK_hmac(uint8_t *output, uint32_t keylen, uint8_t *key, uint32_t datalen, uint8_t *data)
{
#ifdef WITH_SODIUM
  size_t hash_len = 64;
  size_t block_len = 128;
  uint8_t key_block[block_len];
  crypto_generichash_state state;

  /* Format the key for the inner hashing context */
  if (keylen <= block_len) {
    memcpy(key_block, key, keylen);
    memset(key_block + keylen, 0, block_len - keylen);
  } else {
    crypto_generichash_blake2b_init(&state, NULL, 0, crypto_generichash_blake2b_BYTES_MAX);
    crypto_generichash_blake2b_update(&state, key, keylen);
    crypto_generichash_blake2b_final(&state, key_block, crypto_generichash_blake2b_BYTES_MAX);
    memset(key_block + hash_len, 0, block_len - hash_len);
  }
  Noise_XK_hashstate_xor_key(key_block, block_len, HMAC_IPAD);

  /* Calculate the inner hash */
  crypto_generichash_blake2b_init(&state, NULL, 0, crypto_generichash_blake2b_BYTES_MAX);
  crypto_generichash_blake2b_update(&state, key_block, block_len);
  crypto_generichash_blake2b_update(&state, data, datalen);
  crypto_generichash_blake2b_final(&state, output, crypto_generichash_blake2b_BYTES_MAX);

  /* Format the key for the outer hashing context */
  Noise_XK_hashstate_xor_key(key_block, block_len, HMAC_IPAD ^ HMAC_OPAD);

  /* Calculate the outer hash */
  crypto_generichash_blake2b_init(&state, NULL, 0, crypto_generichash_blake2b_BYTES_MAX);
  crypto_generichash_blake2b_update(&state, key_block, block_len);
  crypto_generichash_blake2b_update(&state, output, hash_len);
  crypto_generichash_blake2b_final(&state, output, crypto_generichash_blake2b_BYTES_MAX);

  /* Clean up and exit */
  sodium_memzero(key_block,sizeof key_block);
#else // WITH_SODIUM
  Hacl_HMAC_compute_blake2b_32(output, key, keylen, data, datalen);
#endif // WITH_SODIUM
}

void
Noise_XK_kdf(
  uint8_t *hash1,
  uint32_t keylen,
  uint8_t *key,
  uint8_t *dst1,
  uint8_t *dst2,
  uint8_t *dst3
)
{
  uint8_t output[65U] = { 0U };
  uint8_t secret[64U] = { 0U };
  uint8_t *output_hash = output;
  uint8_t *output1 = output;
  Noise_XK_hmac(secret, (uint32_t)64U, hash1, keylen, key);
  if (!(dst1 == NULL))
  {
    output[0U] = (uint8_t)1U;
    Noise_XK_hmac(output_hash, (uint32_t)64U, secret, (uint32_t)1U, output1);
    memcpy(dst1, output_hash, (uint32_t)64U * sizeof (uint8_t));
    if (!(dst2 == NULL))
    {
      output[64U] = (uint8_t)2U;
      Noise_XK_hmac(output_hash, (uint32_t)64U, secret, (uint32_t)65U, output);
      memcpy(dst2, output_hash, (uint32_t)64U * sizeof (uint8_t));
      if (!(dst3 == NULL))
      {
        output[64U] = (uint8_t)3U;
        Noise_XK_hmac(output_hash, (uint32_t)64U, secret, (uint32_t)65U, output);
        memcpy(dst3, output_hash, (uint32_t)64U * sizeof (uint8_t));
      }
    }
  }
#ifdef WITH_SODIUM
  sodium_memzero(output, (uint32_t)65U * sizeof (output[0U]));
  sodium_memzero(secret, (uint32_t)64U * sizeof (secret[0U]));
#else // WITH_SODIUM
  Lib_Memzero0_memzero(output, (uint32_t)65U * sizeof (output[0U]));
  Lib_Memzero0_memzero(secret, (uint32_t)64U * sizeof (secret[0U]));
#endif // WITH_SODIUM
}

void Noise_XK_mix_psk(uint8_t *psk, uint8_t *st_cs_k, uint8_t *st_ck, uint8_t *st_h)
{
  uint8_t temp_hash[64U] = { 0U };
  uint8_t temp_k[64U] = { 0U };
  Noise_XK_kdf(st_ck, (uint32_t)32U, psk, st_ck, temp_hash, temp_k);
  memcpy(st_cs_k, temp_k, (uint32_t)32U * sizeof (uint8_t));
#ifdef WITH_SODIUM
  sodium_memzero(temp_k, (uint32_t)64U * sizeof (temp_k[0U]));
#else // WITH_SODIUM
  Lib_Memzero0_memzero(temp_k, (uint32_t)64U * sizeof (temp_k[0U]));
#endif // WITH_SODIUM
  Noise_XK_mix_hash(st_h, (uint32_t)64U, temp_hash);
#ifdef WITH_SODIUM
  sodium_memzero(temp_hash, (uint32_t)64U * sizeof (temp_hash[0U]));
#else // WITH_SODIUM
  Lib_Memzero0_memzero(temp_hash, (uint32_t)64U * sizeof (temp_hash[0U]));
#endif // WITH_SODIUM
}

void
Noise_XK_encrypt_and_hash(
  uint32_t msg_len,
  uint8_t *msg,
  uint8_t *cipher,
  uint8_t *st_cs_k,
  uint8_t *st_h,
  uint64_t nonce
)
{
  Noise_XK_aead_encrypt(st_cs_k, nonce, (uint32_t)64U, st_h, msg_len, msg, cipher);
  uint32_t cipher_len = msg_len + (uint32_t)16U;
  Noise_XK_mix_hash(st_h, cipher_len, cipher);
}

Noise_XK_error_code
Noise_XK_decrypt_and_hash(
  uint32_t msg_len,
  uint8_t *msg,
  uint8_t *cipher,
  uint8_t *st_cs_k,
  uint8_t *st_h,
  uint64_t nonce
)
{
  Noise_XK_error_code
  r1 = Noise_XK_aead_decrypt(st_cs_k, nonce, (uint32_t)64U, st_h, msg_len, msg, cipher);
  if (r1 == Noise_XK_CSuccess)
  {
    Noise_XK_mix_hash(st_h, msg_len + (uint32_t)16U, cipher);
    return Noise_XK_CSuccess;
  }
  else
    return r1;
}

Noise_XK_error_code
Noise_XK_mix_dh(uint8_t *sec, uint8_t *pub, uint8_t *cipher_key, uint8_t *ck, uint8_t *hash1)
{
  uint8_t dh_key[32U] = { 0U };
  Noise_XK_error_code r1 = Noise_XK_dh(dh_key, sec, pub);
  Noise_XK_error_code r2;
  if (r1 == Noise_XK_CSuccess)
  {
    uint8_t temp_k[64U] = { 0U };
    Noise_XK_kdf(ck, (uint32_t)32U, dh_key, ck, temp_k, NULL);
    memcpy(cipher_key, temp_k, (uint32_t)32U * sizeof (uint8_t));
#ifdef WITH_SODIUM
    sodium_memzero(temp_k, (uint32_t)64U * sizeof (temp_k[0U]));
#else // WITH_SODIUM
    Lib_Memzero0_memzero(temp_k, (uint32_t)64U * sizeof (temp_k[0U]));
#endif // WITH_SODIUM
    r2 = Noise_XK_CSuccess;
  }
  else
    r2 = r1;
  Noise_XK_error_code r = r2;
#ifdef WITH_SODIUM
  sodium_memzero(dh_key, (uint32_t)32U * sizeof (dh_key[0U]));
#else // WITH_SODIUM
  Lib_Memzero0_memzero(dh_key, (uint32_t)32U * sizeof (dh_key[0U]));
#endif // WITH_SODIUM
  return r;
}

