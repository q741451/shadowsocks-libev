// Copyright (c) 2014, Google Inc.
// SPDX-License-Identifier: ISC

#ifndef OPENSSL_HEADER_AEAD_INTERNAL_H
#define OPENSSL_HEADER_AEAD_INTERNAL_H

#include <openssl/aead.h>

#include "internal.h"

#define AEAD_TAG_LEN 16

// An AEAD method. The generic layer in aead.c has already checked the key
// and nonce lengths, buffer sizes and aliasing when these are called.
struct evp_aead_st {
  uint8_t key_len;
  uint8_t nonce_len;

  int (*init)(EVP_AEAD_CTX *ctx, const uint8_t *key);

  // seal encrypts |in_len| bytes from |in| to |out| and writes the
  // AEAD_TAG_LEN-byte tag to |out_tag|.
  int (*seal)(const EVP_AEAD_CTX *ctx, uint8_t *out, uint8_t *out_tag,
              const uint8_t *nonce, const uint8_t *in, size_t in_len,
              const uint8_t *ad, size_t ad_len);

  // open checks |in_tag| and decrypts |in_len| bytes from |in| to |out|.
  int (*open)(const EVP_AEAD_CTX *ctx, uint8_t *out, const uint8_t *nonce,
              const uint8_t *in, size_t in_len, const uint8_t *in_tag,
              const uint8_t *ad, size_t ad_len);
};

#endif  // OPENSSL_HEADER_AEAD_INTERNAL_H
