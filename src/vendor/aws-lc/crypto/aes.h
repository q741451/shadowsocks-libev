// Copyright (c) 2002-2006 The OpenSSL Project.  All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENSSL_HEADER_AES_H
#define OPENSSL_HEADER_AES_H

#include "cpucap.h"

// AES encryption only: GCM never runs the block cipher backwards.

#define AES_MAXNR 14

// The layout is shared with the assembly.
typedef struct aes_key_st {
  uint32_t rd_key[4 * (AES_MAXNR + 1)];
  unsigned rounds;
} AES_KEY;

// block128_f encrypts one block; ctr128_f encrypts |blocks| blocks in counter
// mode, incrementing only the last 32 bits of |ivec|.
typedef void (*block128_f)(const uint8_t in[16], uint8_t out[16],
                           const AES_KEY *key);
typedef void (*ctr128_f)(const uint8_t *in, uint8_t *out, size_t blocks,
                         const AES_KEY *key, const uint8_t ivec[16]);

// Three implementations, picked at run time: the CPU's AES instructions,
// vector permutes (vpaes; on 32-bit ARM with bit-sliced bsaes for bulk), and
// portable constant-time C (aes_nohw).

#if !defined(OPENSSL_NO_ASM)

#define HWAES
#define VPAES

#if defined(OPENSSL_X86_64)
static inline int hwaes_capable(void) { return CRYPTO_is_AESNI_capable(); }
static inline int vpaes_capable(void) { return CRYPTO_is_SSSE3_capable(); }
#else
static inline int hwaes_capable(void) { return CRYPTO_is_ARMv8_AES_capable(); }
static inline int vpaes_capable(void) { return CRYPTO_is_NEON_capable(); }
#endif

#if defined(OPENSSL_ARM)
#define BSAES
void bsaes_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out, size_t len,
                                const AES_KEY *key, const uint8_t ivec[16]);
void vpaes_encrypt_key_to_bsaes(AES_KEY *out_bsaes, const AES_KEY *vpaes);
#endif

int aes_hw_set_encrypt_key(const uint8_t *user_key, const int bits,
                           AES_KEY *key);
void aes_hw_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
void aes_hw_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out, size_t len,
                                 const AES_KEY *key, const uint8_t ivec[16]);

int vpaes_set_encrypt_key(const uint8_t *userKey, int bits, AES_KEY *key);
void vpaes_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
void vpaes_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out, size_t len,
                                const AES_KEY *key, const uint8_t ivec[16]);

#endif  // !OPENSSL_NO_ASM

int aes_nohw_set_encrypt_key(const uint8_t *key, unsigned bits,
                             AES_KEY *aeskey);
void aes_nohw_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
void aes_nohw_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out,
                                   size_t blocks, const AES_KEY *key,
                                   const uint8_t ivec[16]);

#endif  // OPENSSL_HEADER_AES_H
