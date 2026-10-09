// Copyright (c) 2014, Google Inc.
// SPDX-License-Identifier: ISC

#include "aead_internal.h"

void EVP_AEAD_CTX_zero(EVP_AEAD_CTX *ctx) {
  OPENSSL_memset(ctx, 0, sizeof(EVP_AEAD_CTX));
}

int EVP_AEAD_CTX_init(EVP_AEAD_CTX *ctx, const EVP_AEAD *aead,
                      const uint8_t *key, size_t key_len, size_t tag_len,
                      ENGINE *impl) {
  if (impl != NULL || key_len != aead->key_len ||
      (tag_len != EVP_AEAD_DEFAULT_TAG_LENGTH && tag_len != AEAD_TAG_LEN)) {
    ctx->aead = NULL;
    return 0;
  }
  ctx->aead = aead;
  if (!aead->init(ctx, key)) {
    ctx->aead = NULL;
    return 0;
  }
  return 1;
}

void EVP_AEAD_CTX_cleanup(EVP_AEAD_CTX *ctx) { ctx->aead = NULL; }

// check_alias returns 1 if |out| is compatible with |in| and 0 otherwise. If
// |in| and |out| alias, we require that |in| == |out|.
static int check_alias(const uint8_t *in, size_t in_len, const uint8_t *out,
                       size_t out_len) {
  if (!buffers_alias(in, in_len, out, out_len)) {
    return 1;
  }

  return in == out;
}

int EVP_AEAD_CTX_seal(const EVP_AEAD_CTX *ctx, uint8_t *out, size_t *out_len,
                      size_t max_out_len, const uint8_t *nonce,
                      size_t nonce_len, const uint8_t *in, size_t in_len,
                      const uint8_t *ad, size_t ad_len) {
  if (in_len + AEAD_TAG_LEN < in_len /* overflow */ ||
      max_out_len < in_len + AEAD_TAG_LEN ||
      nonce_len != ctx->aead->nonce_len ||
      !check_alias(in, in_len, out, max_out_len)) {
    goto error;
  }

  if (ctx->aead->seal(ctx, out, out + in_len, nonce, in, in_len, ad, ad_len)) {
    *out_len = in_len + AEAD_TAG_LEN;
    return 1;
  }

error:
  // In the event of an error, clear the output buffer so that a caller
  // that doesn't check the return value doesn't send raw data.
  OPENSSL_memset(out, 0, max_out_len);
  *out_len = 0;
  return 0;
}

int EVP_AEAD_CTX_open(const EVP_AEAD_CTX *ctx, uint8_t *out, size_t *out_len,
                      size_t max_out_len, const uint8_t *nonce,
                      size_t nonce_len, const uint8_t *in, size_t in_len,
                      const uint8_t *ad, size_t ad_len) {
  if (in_len < AEAD_TAG_LEN || max_out_len < in_len - AEAD_TAG_LEN ||
      nonce_len != ctx->aead->nonce_len ||
      !check_alias(in, in_len, out, max_out_len)) {
    goto error;
  }

  size_t plaintext_len = in_len - AEAD_TAG_LEN;
  if (ctx->aead->open(ctx, out, nonce, in, plaintext_len, in + plaintext_len,
                      ad, ad_len)) {
    *out_len = plaintext_len;
    return 1;
  }

error:
  // In the event of an error, clear the output buffer so that a caller
  // that doesn't check the return value doesn't try and process bad
  // data.
  OPENSSL_memset(out, 0, max_out_len);
  *out_len = 0;
  return 0;
}
