// Copyright (c) 2014, Google Inc.
// SPDX-License-Identifier: ISC

#ifndef OPENSSL_HEADER_POLY1305_H
#define OPENSSL_HEADER_POLY1305_H

#include "cpucap.h"

typedef uint8_t poly1305_state[512];

// CRYPTO_poly1305_init sets up |state| so that it can be used to calculate an
// authentication tag with the one-time key |key|. Note that |key| is a
// one-time key and therefore there is no `reset' method because that would
// enable several messages to be authenticated with the same key.
void CRYPTO_poly1305_init(poly1305_state *state, const uint8_t key[32]);

// CRYPTO_poly1305_update processes |in_len| bytes from |in|. It can be called
// zero or more times after poly1305_init.
void CRYPTO_poly1305_update(poly1305_state *state, const uint8_t *in,
                            size_t in_len);

// CRYPTO_poly1305_finish completes the poly1305 calculation and writes a 16
// byte authentication tag to |mac|.
void CRYPTO_poly1305_finish(poly1305_state *state, uint8_t mac[16]);

// poly1305_vec.c, used on x86_64, has its own state layout.
#if !defined(BORINGSSL_HAS_UINT128) || !defined(OPENSSL_X86_64)
static inline struct poly1305_state_st *poly1305_aligned_state(
    poly1305_state *state) {
  return align_pointer(state, 64);
}
#endif

#if defined(OPENSSL_ARM) && !defined(OPENSSL_NO_ASM)
#define OPENSSL_POLY1305_NEON

void CRYPTO_poly1305_init_neon(poly1305_state *state, const uint8_t key[32]);

void CRYPTO_poly1305_update_neon(poly1305_state *state, const uint8_t *in,
                                 size_t in_len);

void CRYPTO_poly1305_finish_neon(poly1305_state *state, uint8_t mac[16]);
#endif

#endif  // OPENSSL_HEADER_POLY1305_H
