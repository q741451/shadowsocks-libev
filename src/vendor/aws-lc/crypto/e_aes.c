// Copyright (c) 2001-2011 The OpenSSL Project.  All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// AES-GCM with a 12-byte nonce and a 16-byte tag.

#include "aead_internal.h"
#include "gcm.h"

#define AES_GCM_NONCE_LENGTH 12

#if defined(BSAES)
static void vpaes_ctr32_encrypt_blocks_with_bsaes(const uint8_t *in,
                                                  uint8_t *out, size_t blocks,
                                                  const AES_KEY *key,
                                                  const uint8_t ivec[16]) {
  // |bsaes_ctr32_encrypt_blocks| is faster than |vpaes_ctr32_encrypt_blocks|,
  // but it takes at least one full 8-block batch to amortize the conversion.
  if (blocks < 8) {
    vpaes_ctr32_encrypt_blocks(in, out, blocks, key, ivec);
    return;
  }

  size_t bsaes_blocks = blocks;
  if (bsaes_blocks % 8 < 6) {
    // |bsaes_ctr32_encrypt_blocks| internally works in 8-block batches. If the
    // final batch is too small (under six blocks), it is faster to loop over
    // |vpaes_encrypt|. Round |bsaes_blocks| down to a multiple of 8.
    bsaes_blocks -= bsaes_blocks % 8;
  }

  AES_KEY bsaes;
  vpaes_encrypt_key_to_bsaes(&bsaes, key);
  bsaes_ctr32_encrypt_blocks(in, out, bsaes_blocks, &bsaes, ivec);
  OPENSSL_cleanse(&bsaes, sizeof(bsaes));

  in += 16 * bsaes_blocks;
  out += 16 * bsaes_blocks;
  blocks -= bsaes_blocks;

  uint8_t new_ivec[16];
  memcpy(new_ivec, ivec, 12);
  uint32_t ctr = CRYPTO_load_u32_be(ivec + 12) + bsaes_blocks;
  CRYPTO_store_u32_be(new_ivec + 12, ctr);

  // Finish any remaining blocks with |vpaes_ctr32_encrypt_blocks|.
  vpaes_ctr32_encrypt_blocks(in, out, blocks, key, new_ivec);
}
#endif  // BSAES

// aes_ctr_set_key expands |key| for the fastest AES on this CPU, keys
// |gcm_key| for GHASH, and returns the matching counter-mode function.
static ctr128_f aes_ctr_set_key(AES_KEY *aes_key, GCM128_KEY *gcm_key,
                                const uint8_t *key, size_t key_bytes) {
#if defined(HWAES)
  if (hwaes_capable()) {
    aes_hw_set_encrypt_key(key, (int)key_bytes * 8, aes_key);
    CRYPTO_gcm128_init_key(gcm_key, aes_key, aes_hw_encrypt, 1);
    return aes_hw_ctr32_encrypt_blocks;
  }
#endif

#if defined(VPAES)
  if (vpaes_capable()) {
    vpaes_set_encrypt_key(key, (int)key_bytes * 8, aes_key);
    CRYPTO_gcm128_init_key(gcm_key, aes_key, vpaes_encrypt, 0);
#if defined(BSAES)
    return vpaes_ctr32_encrypt_blocks_with_bsaes;
#else
    return vpaes_ctr32_encrypt_blocks;
#endif
  }
#endif

  aes_nohw_set_encrypt_key(key, (unsigned)key_bytes * 8, aes_key);
  CRYPTO_gcm128_init_key(gcm_key, aes_key, aes_nohw_encrypt, 0);
  return aes_nohw_ctr32_encrypt_blocks;
}

struct aead_aes_gcm_ctx {
  union {
    double align;
    AES_KEY ks;
  } ks;
  GCM128_KEY gcm_key;
  ctr128_f ctr;
};

OPENSSL_STATIC_ASSERT(sizeof(((EVP_AEAD_CTX *)NULL)->state) >=
                          sizeof(struct aead_aes_gcm_ctx),
                      AEAD_state_is_too_small)
OPENSSL_STATIC_ASSERT(alignof(union evp_aead_ctx_st_state) >=
                          alignof(struct aead_aes_gcm_ctx),
                      AEAD_state_has_insufficient_alignment)

static int aead_aes_gcm_init(EVP_AEAD_CTX *ctx, const uint8_t *key) {
  struct aead_aes_gcm_ctx *gcm_ctx = (struct aead_aes_gcm_ctx *)&ctx->state;
  gcm_ctx->ctr = aes_ctr_set_key(&gcm_ctx->ks.ks, &gcm_ctx->gcm_key, key,
                                 ctx->aead->key_len);
  return 1;
}

static int aead_aes_gcm_seal(const EVP_AEAD_CTX *ctx, uint8_t *out,
                             uint8_t *out_tag, const uint8_t *nonce,
                             const uint8_t *in, size_t in_len,
                             const uint8_t *ad, size_t ad_len) {
  const struct aead_aes_gcm_ctx *gcm_ctx =
      (const struct aead_aes_gcm_ctx *)&ctx->state;
  const AES_KEY *key = &gcm_ctx->ks.ks;

  GCM128_CONTEXT gcm;
  OPENSSL_memset(&gcm, 0, sizeof(gcm));
  OPENSSL_memcpy(&gcm.gcm_key, &gcm_ctx->gcm_key, sizeof(gcm.gcm_key));
  CRYPTO_gcm128_setiv(&gcm, key, nonce);

  if (ad_len > 0 && !CRYPTO_gcm128_aad(&gcm, ad, ad_len)) {
    return 0;
  }

  if (!CRYPTO_gcm128_encrypt_ctr32(&gcm, key, in, out, in_len, gcm_ctx->ctr)) {
    return 0;
  }

  CRYPTO_gcm128_tag(&gcm, out_tag, AEAD_TAG_LEN);
  return 1;
}

static int aead_aes_gcm_open(const EVP_AEAD_CTX *ctx, uint8_t *out,
                             const uint8_t *nonce, const uint8_t *in,
                             size_t in_len, const uint8_t *in_tag,
                             const uint8_t *ad, size_t ad_len) {
  const struct aead_aes_gcm_ctx *gcm_ctx =
      (const struct aead_aes_gcm_ctx *)&ctx->state;
  const AES_KEY *key = &gcm_ctx->ks.ks;
  uint8_t tag[AEAD_TAG_LEN];

  GCM128_CONTEXT gcm;
  OPENSSL_memset(&gcm, 0, sizeof(gcm));
  OPENSSL_memcpy(&gcm.gcm_key, &gcm_ctx->gcm_key, sizeof(gcm.gcm_key));
  CRYPTO_gcm128_setiv(&gcm, key, nonce);

  if (!CRYPTO_gcm128_aad(&gcm, ad, ad_len)) {
    return 0;
  }

  if (!CRYPTO_gcm128_decrypt_ctr32(&gcm, key, in, out, in_len, gcm_ctx->ctr)) {
    return 0;
  }

  CRYPTO_gcm128_tag(&gcm, tag, AEAD_TAG_LEN);
  return CRYPTO_memcmp(tag, in_tag, AEAD_TAG_LEN) == 0;
}

static const EVP_AEAD aead_aes_128_gcm = {
    16, AES_GCM_NONCE_LENGTH,
    aead_aes_gcm_init, aead_aes_gcm_seal, aead_aes_gcm_open,
};

static const EVP_AEAD aead_aes_192_gcm = {
    24, AES_GCM_NONCE_LENGTH,
    aead_aes_gcm_init, aead_aes_gcm_seal, aead_aes_gcm_open,
};

static const EVP_AEAD aead_aes_256_gcm = {
    32, AES_GCM_NONCE_LENGTH,
    aead_aes_gcm_init, aead_aes_gcm_seal, aead_aes_gcm_open,
};

const EVP_AEAD *EVP_aead_aes_128_gcm(void) { return &aead_aes_128_gcm; }
const EVP_AEAD *EVP_aead_aes_192_gcm(void) { return &aead_aes_192_gcm; }
const EVP_AEAD *EVP_aead_aes_256_gcm(void) { return &aead_aes_256_gcm; }
