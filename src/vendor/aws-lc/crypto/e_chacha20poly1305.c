// Copyright (c) 2014, Google Inc.
// SPDX-License-Identifier: ISC

// ChaCha20-Poly1305 (RFC 8439) and XChaCha20-Poly1305, with 16-byte tags.

#include <openssl/chacha.h>

#include "aead_internal.h"
#include "chacha_internal.h"
#include "poly1305.h"

#define CHACHA_KEY_LEN 32
#define CHACHA_IV_LEN 12
#define XCHACHA_IV_LEN 24

struct aead_chacha20_poly1305_ctx {
  uint8_t key[CHACHA_KEY_LEN];
};

OPENSSL_STATIC_ASSERT(sizeof(((EVP_AEAD_CTX *)NULL)->state) >=
                          sizeof(struct aead_chacha20_poly1305_ctx),
                      AEAD_state_is_too_small)
OPENSSL_STATIC_ASSERT(alignof(union evp_aead_ctx_st_state) >=
                          alignof(struct aead_chacha20_poly1305_ctx),
                      AEAD_state_has_insufficient_alignment)

static int aead_chacha20_poly1305_init(EVP_AEAD_CTX *ctx, const uint8_t *key) {
  struct aead_chacha20_poly1305_ctx *c20_ctx =
      (struct aead_chacha20_poly1305_ctx *)&ctx->state;
  OPENSSL_memcpy(c20_ctx->key, key, CHACHA_KEY_LEN);
  return 1;
}

static void poly1305_update_length(poly1305_state *poly1305, size_t data_len) {
  uint8_t length_bytes[8];

  for (unsigned i = 0; i < sizeof(length_bytes); i++) {
    length_bytes[i] = data_len;
    data_len >>= 8;
  }

  CRYPTO_poly1305_update(poly1305, length_bytes, sizeof(length_bytes));
}

// calc_tag fills |tag| with the authentication tag for the given inputs.
static void calc_tag(uint8_t tag[AEAD_TAG_LEN], const uint8_t *key,
                     const uint8_t nonce[CHACHA_IV_LEN], const uint8_t *ad,
                     size_t ad_len, const uint8_t *ciphertext,
                     size_t ciphertext_len) {
  alignas(16) uint8_t poly1305_key[CHACHA_KEY_LEN];
  OPENSSL_memset(poly1305_key, 0, sizeof(poly1305_key));
  CRYPTO_chacha_20(poly1305_key, poly1305_key, sizeof(poly1305_key), key, nonce,
                   0);

  static const uint8_t padding[16] = {0};  // Padding is all zeros.
  poly1305_state ctx;
  CRYPTO_poly1305_init(&ctx, poly1305_key);
  CRYPTO_poly1305_update(&ctx, ad, ad_len);
  if (ad_len % 16 != 0) {
    CRYPTO_poly1305_update(&ctx, padding, sizeof(padding) - (ad_len % 16));
  }
  CRYPTO_poly1305_update(&ctx, ciphertext, ciphertext_len);
  if (ciphertext_len % 16 != 0) {
    CRYPTO_poly1305_update(&ctx, padding,
                           sizeof(padding) - (ciphertext_len % 16));
  }
  poly1305_update_length(&ctx, ad_len);
  poly1305_update_length(&ctx, ciphertext_len);
  CRYPTO_poly1305_finish(&ctx, tag);

  OPENSSL_cleanse(poly1305_key, sizeof(poly1305_key));
  OPENSSL_cleanse(&ctx, sizeof(ctx));
}

static int seal_with_key(const uint8_t *key, uint8_t *out, uint8_t *out_tag,
                         const uint8_t *nonce, const uint8_t *in,
                         size_t in_len, const uint8_t *ad, size_t ad_len) {
  // |CRYPTO_chacha_20| uses a 32-bit block counter. Therefore we disallow
  // individual operations that work on more than 256GB at a time.
  // |in_len_64| is needed because, on 32-bit platforms, size_t is only
  // 32-bits and this produces a warning because it's always false.
  // Casting to uint64_t inside the conditional is not sufficient to stop
  // the warning.
  const uint64_t in_len_64 = in_len;
  if (in_len_64 >= (UINT64_C(1) << 32) * 64 - 64) {
    return 0;
  }

  union chacha20_poly1305_seal_data data;
#if defined(CHACHA20_POLY1305_ASM)
  if (chacha20_poly1305_asm_capable()) {
    OPENSSL_memcpy(data.in.key, key, CHACHA_KEY_LEN);
    data.in.counter = 0;
    OPENSSL_memcpy(data.in.nonce, nonce, CHACHA_IV_LEN);
    data.in.extra_ciphertext = NULL;
    data.in.extra_ciphertext_len = 0;
    chacha20_poly1305_seal(out, in, in_len, ad, ad_len, &data);
  } else
#endif
  {
    CRYPTO_chacha_20(out, in, in_len, key, nonce, 1);
    calc_tag(data.out.tag, key, nonce, ad, ad_len, out, in_len);
  }

  OPENSSL_memcpy(out_tag, data.out.tag, AEAD_TAG_LEN);
  OPENSSL_cleanse(&data, sizeof(data));
  return 1;
}

static int open_with_key(const uint8_t *key, uint8_t *out,
                         const uint8_t *nonce, const uint8_t *in,
                         size_t in_len, const uint8_t *in_tag,
                         const uint8_t *ad, size_t ad_len) {
  // |CRYPTO_chacha_20| uses a 32-bit block counter. Therefore we disallow
  // individual operations that work on more than 256GB at a time.
  // |in_len_64| is needed because, on 32-bit platforms, size_t is only
  // 32-bits and this produces a warning because it's always false.
  // Casting to uint64_t inside the conditional is not sufficient to stop
  // the warning.
  const uint64_t in_len_64 = in_len;
  if (in_len_64 >= (UINT64_C(1) << 32) * 64 - 64) {
    return 0;
  }

  union chacha20_poly1305_open_data data;
#if defined(CHACHA20_POLY1305_ASM)
  if (chacha20_poly1305_asm_capable()) {
    OPENSSL_memcpy(data.in.key, key, CHACHA_KEY_LEN);
    data.in.counter = 0;
    OPENSSL_memcpy(data.in.nonce, nonce, CHACHA_IV_LEN);
    chacha20_poly1305_open(out, in, in_len, ad, ad_len, &data);
  } else
#endif
  {
    calc_tag(data.out.tag, key, nonce, ad, ad_len, in, in_len);
    CRYPTO_chacha_20(out, in, in_len, key, nonce, 1);
  }

  int ok = CRYPTO_memcmp(data.out.tag, in_tag, AEAD_TAG_LEN) == 0;
  OPENSSL_cleanse(&data, sizeof(data));
  return ok;
}

static int aead_chacha20_poly1305_seal(const EVP_AEAD_CTX *ctx, uint8_t *out,
                                       uint8_t *out_tag, const uint8_t *nonce,
                                       const uint8_t *in, size_t in_len,
                                       const uint8_t *ad, size_t ad_len) {
  const struct aead_chacha20_poly1305_ctx *c20_ctx =
      (const struct aead_chacha20_poly1305_ctx *)&ctx->state;
  return seal_with_key(c20_ctx->key, out, out_tag, nonce, in, in_len, ad,
                       ad_len);
}

static int aead_chacha20_poly1305_open(const EVP_AEAD_CTX *ctx, uint8_t *out,
                                       const uint8_t *nonce, const uint8_t *in,
                                       size_t in_len, const uint8_t *in_tag,
                                       const uint8_t *ad, size_t ad_len) {
  const struct aead_chacha20_poly1305_ctx *c20_ctx =
      (const struct aead_chacha20_poly1305_ctx *)&ctx->state;
  return open_with_key(c20_ctx->key, out, nonce, in, in_len, in_tag, ad,
                       ad_len);
}

// XChaCha20 derives a subkey from the key and the first 16 nonce bytes with
// HChaCha20, then runs ChaCha20 with the last 8 nonce bytes.
static void xchacha20_derive(uint8_t derived_key[CHACHA_KEY_LEN],
                             uint8_t derived_nonce[CHACHA_IV_LEN],
                             const uint8_t *key, const uint8_t *nonce) {
  CRYPTO_hchacha20(derived_key, key, nonce);
  OPENSSL_memset(derived_nonce, 0, 4);
  OPENSSL_memcpy(&derived_nonce[4], &nonce[16], 8);
}

static int aead_xchacha20_poly1305_seal(const EVP_AEAD_CTX *ctx, uint8_t *out,
                                        uint8_t *out_tag, const uint8_t *nonce,
                                        const uint8_t *in, size_t in_len,
                                        const uint8_t *ad, size_t ad_len) {
  const struct aead_chacha20_poly1305_ctx *c20_ctx =
      (const struct aead_chacha20_poly1305_ctx *)&ctx->state;
  alignas(4) uint8_t derived_key[CHACHA_KEY_LEN];
  alignas(4) uint8_t derived_nonce[CHACHA_IV_LEN];
  xchacha20_derive(derived_key, derived_nonce, c20_ctx->key, nonce);
  int ok = seal_with_key(derived_key, out, out_tag, derived_nonce, in, in_len,
                         ad, ad_len);
  OPENSSL_cleanse(derived_key, sizeof(derived_key));
  return ok;
}

static int aead_xchacha20_poly1305_open(const EVP_AEAD_CTX *ctx, uint8_t *out,
                                        const uint8_t *nonce, const uint8_t *in,
                                        size_t in_len, const uint8_t *in_tag,
                                        const uint8_t *ad, size_t ad_len) {
  const struct aead_chacha20_poly1305_ctx *c20_ctx =
      (const struct aead_chacha20_poly1305_ctx *)&ctx->state;
  alignas(4) uint8_t derived_key[CHACHA_KEY_LEN];
  alignas(4) uint8_t derived_nonce[CHACHA_IV_LEN];
  xchacha20_derive(derived_key, derived_nonce, c20_ctx->key, nonce);
  int ok = open_with_key(derived_key, out, derived_nonce, in, in_len, in_tag,
                         ad, ad_len);
  OPENSSL_cleanse(derived_key, sizeof(derived_key));
  return ok;
}

static const EVP_AEAD aead_chacha20_poly1305 = {
    CHACHA_KEY_LEN, CHACHA_IV_LEN,
    aead_chacha20_poly1305_init,
    aead_chacha20_poly1305_seal,
    aead_chacha20_poly1305_open,
};

static const EVP_AEAD aead_xchacha20_poly1305 = {
    CHACHA_KEY_LEN, XCHACHA_IV_LEN,
    aead_chacha20_poly1305_init,
    aead_xchacha20_poly1305_seal,
    aead_xchacha20_poly1305_open,
};

const EVP_AEAD *EVP_aead_chacha20_poly1305(void) {
  return &aead_chacha20_poly1305;
}

const EVP_AEAD *EVP_aead_xchacha20_poly1305(void) {
  return &aead_xchacha20_poly1305;
}
