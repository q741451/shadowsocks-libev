// Copyright (c) 2014, Google Inc.
// SPDX-License-Identifier: ISC

#ifndef OPENSSL_HEADER_AEAD_H
#define OPENSSL_HEADER_AEAD_H

#include <stddef.h>
#include <stdint.h>

// Authenticated encryption with additional data. Only what shadowsocks uses:
// AES-GCM with a 12-byte nonce, ChaCha20-Poly1305 and XChaCha20-Poly1305,
// all with 16-byte tags.

typedef struct evp_aead_st EVP_AEAD;
typedef struct evp_aead_ctx_st EVP_AEAD_CTX;
typedef struct engine_st ENGINE;

const EVP_AEAD *EVP_aead_aes_128_gcm(void);
const EVP_AEAD *EVP_aead_aes_192_gcm(void);
const EVP_AEAD *EVP_aead_aes_256_gcm(void);
const EVP_AEAD *EVP_aead_chacha20_poly1305(void);
const EVP_AEAD *EVP_aead_xchacha20_poly1305(void);

// The keyed state of an AEAD. Its size covers the largest of them, AES-GCM's
// key schedule plus the GHASH table.
union evp_aead_ctx_st_state {
  uint8_t opaque[564];
  uint64_t alignment;
  void *ptr;
};

struct evp_aead_ctx_st {
  const EVP_AEAD *aead;
  union evp_aead_ctx_st_state state;
};

// The tag length to pass for the AEAD's default, 16 bytes for all of these.
#define EVP_AEAD_DEFAULT_TAG_LENGTH 0

// EVP_AEAD_CTX_zero sets an uninitialized |ctx| to the zero state, which is
// safe to pass to EVP_AEAD_CTX_cleanup.
void EVP_AEAD_CTX_zero(EVP_AEAD_CTX *ctx);

// EVP_AEAD_CTX_init keys |ctx| for |aead|. |tag_len| must be 16 or
// EVP_AEAD_DEFAULT_TAG_LENGTH, |impl| NULL. Returns one on success.
int EVP_AEAD_CTX_init(EVP_AEAD_CTX *ctx, const EVP_AEAD *aead,
                      const uint8_t *key, size_t key_len, size_t tag_len,
                      ENGINE *impl);

// EVP_AEAD_CTX_cleanup frees anything |ctx| holds; |ctx| may be zeroed.
void EVP_AEAD_CTX_cleanup(EVP_AEAD_CTX *ctx);

// EVP_AEAD_CTX_seal encrypts and authenticates |in_len| bytes from |in| and
// authenticates |ad_len| bytes from |ad|, writing the ciphertext and tag to
// |out| and their length to |*out_len|. |out| may equal |in| but must not
// otherwise overlap it. Returns one on success.
int EVP_AEAD_CTX_seal(const EVP_AEAD_CTX *ctx, uint8_t *out, size_t *out_len,
                      size_t max_out_len, const uint8_t *nonce,
                      size_t nonce_len, const uint8_t *in, size_t in_len,
                      const uint8_t *ad, size_t ad_len);

// EVP_AEAD_CTX_open authenticates |in| (ciphertext then tag) and |ad| and
// decrypts the ciphertext to |out|, writing its length to |*out_len|. Returns
// one on success, zero, with |out| cleared, if authentication fails.
int EVP_AEAD_CTX_open(const EVP_AEAD_CTX *ctx, uint8_t *out, size_t *out_len,
                      size_t max_out_len, const uint8_t *nonce,
                      size_t nonce_len, const uint8_t *in, size_t in_len,
                      const uint8_t *ad, size_t ad_len);

#endif  // OPENSSL_HEADER_AEAD_H
