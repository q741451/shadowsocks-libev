// Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENSSL_HEADER_GCM_H
#define OPENSSL_HEADER_GCM_H

#include "aes.h"

typedef struct { uint64_t hi,lo; } u128;

typedef void (*gmult_func)(uint8_t Xi[16], const u128 Htable[16]);
typedef void (*ghash_func)(uint8_t Xi[16], const u128 Htable[16],
                           const uint8_t *inp, size_t len);

// GCM128_KEY is the key-dependent part: the GHASH table and the functions
// picked for this CPU.
typedef struct gcm128_key_st {
  u128 Htable[16];
  gmult_func gmult;
  ghash_func ghash;
  block128_f block;
  // Set when AES and GHASH both run in the stitched assembly.
  unsigned use_hw_gcm_crypt:1;
} GCM128_KEY;

// GCM128_CONTEXT is the state of one message.
typedef struct {
  uint8_t Yi[16];
  uint8_t EKi[16];
  uint8_t EK0[16];
  struct {
    uint64_t aad;
    uint64_t msg;
  } len;
  uint8_t Xi[16];
  alignas(16) GCM128_KEY gcm_key;
  unsigned mres, ares;
} GCM128_CONTEXT;

static inline void CRYPTO_xor16(uint8_t out[16], const uint8_t a[16],
                                const uint8_t b[16]) {
  for (size_t i = 0; i < 16; i += sizeof(crypto_word_t)) {
    CRYPTO_store_word_le(
        out + i, CRYPTO_load_word_le(a + i) ^ CRYPTO_load_word_le(b + i));
  }
}

// CRYPTO_gcm128_init_key derives the GHASH key from |aes_key| with |block|.
// |block_is_hwaes| tells whether |block| is the CPU's AES instructions, which
// the stitched AES-GCM assembly requires.
void CRYPTO_gcm128_init_key(GCM128_KEY *gcm_key, const AES_KEY *aes_key,
                            block128_f block, int block_is_hwaes);

// CRYPTO_gcm128_setiv starts a message with the 12-byte |iv|.
void CRYPTO_gcm128_setiv(GCM128_CONTEXT *ctx, const AES_KEY *key,
                         const uint8_t iv[12]);

// CRYPTO_gcm128_aad authenticates |len| bytes of additional data. It must come
// before the message. Returns one on success.
int CRYPTO_gcm128_aad(GCM128_CONTEXT *ctx, const uint8_t *aad, size_t len);

// CRYPTO_gcm128_encrypt_ctr32 and CRYPTO_gcm128_decrypt_ctr32 process |len|
// bytes of the message with the counter-mode function |stream|. They may be
// called repeatedly. Return one on success.
int CRYPTO_gcm128_encrypt_ctr32(GCM128_CONTEXT *ctx, const AES_KEY *key,
                                const uint8_t *in, uint8_t *out, size_t len,
                                ctr128_f stream);
int CRYPTO_gcm128_decrypt_ctr32(GCM128_CONTEXT *ctx, const AES_KEY *key,
                                const uint8_t *in, uint8_t *out, size_t len,
                                ctr128_f stream);

// CRYPTO_gcm128_tag finishes the message and writes |len| bytes of the tag.
void CRYPTO_gcm128_tag(GCM128_CONTEXT *ctx, uint8_t *tag, size_t len);

// Portable constant-time GHASH.
void gcm_init_nohw(u128 Htable[16], const uint64_t H[2]);
void gcm_gmult_nohw(uint8_t Xi[16], const u128 Htable[16]);
void gcm_ghash_nohw(uint8_t Xi[16], const u128 Htable[16], const uint8_t *inp,
                    size_t len);

#if !defined(OPENSSL_NO_ASM)

#if defined(OPENSSL_X86_64)
#define GHASH_ASM_X86_64
void gcm_init_clmul(u128 Htable[16], const uint64_t Xi[2]);
void gcm_gmult_clmul(uint8_t Xi[16], const u128 Htable[16]);
void gcm_ghash_clmul(uint8_t Xi[16], const u128 Htable[16], const uint8_t *inp,
                     size_t len);

void gcm_init_ssse3(u128 Htable[16], const uint64_t Xi[2]);
void gcm_gmult_ssse3(uint8_t Xi[16], const u128 Htable[16]);
void gcm_ghash_ssse3(uint8_t Xi[16], const u128 Htable[16], const uint8_t *in,
                     size_t len);

void gcm_init_avx(u128 Htable[16], const uint64_t Xi[2]);
void gcm_gmult_avx(uint8_t Xi[16], const u128 Htable[16]);
void gcm_ghash_avx(uint8_t Xi[16], const u128 Htable[16], const uint8_t *in,
                   size_t len);

#define HW_GCM
size_t aesni_gcm_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                         const AES_KEY *key, uint8_t ivec[16],
                         const u128 Htable[16], uint8_t Xi[16]);
size_t aesni_gcm_decrypt(const uint8_t *in, uint8_t *out, size_t len,
                         const AES_KEY *key, uint8_t ivec[16],
                         const u128 Htable[16], uint8_t Xi[16]);

static inline int crypto_gcm_clmul_enabled(void) {
  return CRYPTO_is_FXSR_capable() && CRYPTO_is_PCLMUL_capable();
}

#else  // ARM or AARCH64
#define GHASH_ASM_ARM

static inline int gcm_pmull_capable(void) {
  return CRYPTO_is_ARMv8_PMULL_capable();
}

static inline int gcm_neon_capable(void) { return CRYPTO_is_NEON_capable(); }

void gcm_init_v8(u128 Htable[16], const uint64_t H[2]);
void gcm_gmult_v8(uint8_t Xi[16], const u128 Htable[16]);
void gcm_ghash_v8(uint8_t Xi[16], const u128 Htable[16], const uint8_t *inp,
                  size_t len);

void gcm_init_neon(u128 Htable[16], const uint64_t H[2]);
void gcm_gmult_neon(uint8_t Xi[16], const u128 Htable[16]);
void gcm_ghash_neon(uint8_t Xi[16], const u128 Htable[16], const uint8_t *inp,
                    size_t len);

#if defined(OPENSSL_AARCH64)
#define HW_GCM
void aes_gcm_enc_kernel(const uint8_t *in, uint64_t in_bits, void *out,
                        void *Xi, uint8_t *ivec, const AES_KEY *key,
                        const u128 Htable[16]);
void aes_gcm_dec_kernel(const uint8_t *in, uint64_t in_bits, void *out,
                        void *Xi, uint8_t *ivec, const AES_KEY *key,
                        const u128 Htable[16]);
size_t aesv8_gcm_8x_enc_128(const uint8_t *in, size_t bit_len, uint8_t *out,
                            uint8_t *Xi, uint8_t ivec[16], const AES_KEY *key,
                            const u128 Htable[16]);
size_t aesv8_gcm_8x_dec_128(const uint8_t *in, size_t bit_len, uint8_t *out,
                            uint8_t *Xi, uint8_t ivec[16], const AES_KEY *key,
                            const u128 Htable[16]);
size_t aesv8_gcm_8x_enc_192(const uint8_t *in, size_t bit_len, uint8_t *out,
                            uint8_t *Xi, uint8_t ivec[16], const AES_KEY *key,
                            const u128 Htable[16]);
size_t aesv8_gcm_8x_dec_192(const uint8_t *in, size_t bit_len, uint8_t *out,
                            uint8_t *Xi, uint8_t ivec[16], const AES_KEY *key,
                            const u128 Htable[16]);
size_t aesv8_gcm_8x_enc_256(const uint8_t *in, size_t bit_len, uint8_t *out,
                            uint8_t *Xi, uint8_t ivec[16], const AES_KEY *key,
                            const u128 Htable[16]);
size_t aesv8_gcm_8x_dec_256(const uint8_t *in, size_t bit_len, uint8_t *out,
                            uint8_t *Xi, uint8_t ivec[16], const AES_KEY *key,
                            const u128 Htable[16]);
#endif  // OPENSSL_AARCH64

#endif

#endif  // !OPENSSL_NO_ASM

#endif  // OPENSSL_HEADER_GCM_H
