// Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com) All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENSSL_HEADER_SHA_H
#define OPENSSL_HEADER_SHA_H

#include <stddef.h>
#include <stdint.h>

// SHA-1. Only for HKDF-SHA1, which shadowsocks derives its AEAD subkeys with;
// not for anything that needs collision resistance.

// SHA_CBLOCK is the block size of SHA-1.
#define SHA_CBLOCK 64

// SHA_DIGEST_LENGTH is the length of a SHA-1 digest.
#define SHA_DIGEST_LENGTH 20

typedef struct sha_state_st {
  uint32_t h[5];
  uint32_t Nl, Nh;
  uint8_t data[SHA_CBLOCK];
  unsigned num;
} SHA_CTX;

// SHA1_Init initialises |sha|.
void SHA1_Init(SHA_CTX *sha);

// SHA1_Update adds |len| bytes from |data| to |sha|.
void SHA1_Update(SHA_CTX *sha, const void *data, size_t len);

// SHA1_Final writes the digest of |sha| to |out|.
void SHA1_Final(uint8_t out[SHA_DIGEST_LENGTH], SHA_CTX *sha);

#endif  // OPENSSL_HEADER_SHA_H
