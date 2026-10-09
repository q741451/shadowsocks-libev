// Copyright (c) 2014, Google Inc.
// SPDX-License-Identifier: ISC

#ifndef OPENSSL_HEADER_CHACHA_H
#define OPENSSL_HEADER_CHACHA_H

#include <stddef.h>
#include <stdint.h>

// CRYPTO_chacha_20 XORs |in_len| bytes from |in| with the ChaCha20 keystream
// for |key|, the 12-byte |nonce| and the 32-bit block |counter| (RFC 8439),
// writing to |out|. |in| and |out| may be equal but must not otherwise
// overlap. The counter wraps to zero after 2^32 blocks.
void CRYPTO_chacha_20(uint8_t *out, const uint8_t *in, size_t in_len,
                      const uint8_t key[32], const uint8_t nonce[12],
                      uint32_t counter);

#endif  // OPENSSL_HEADER_CHACHA_H
