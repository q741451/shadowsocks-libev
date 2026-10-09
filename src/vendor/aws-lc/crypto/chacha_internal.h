// Copyright (c) 2018, Google Inc.
// SPDX-License-Identifier: ISC

#ifndef OPENSSL_HEADER_CHACHA_INTERNAL
#define OPENSSL_HEADER_CHACHA_INTERNAL

#include "cpucap.h"

// CRYPTO_hchacha20 computes the HChaCha20 function, which should only be used
// as part of XChaCha20.
void CRYPTO_hchacha20(uint8_t out[32], const uint8_t key[32],
                      const uint8_t nonce[16]);

#if !defined(OPENSSL_NO_ASM) && \
    (defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64))

#define CHACHA20_ASM_NOHW

#define CHACHA20_ASM_NEON
static inline int ChaCha20_ctr32_neon_capable(size_t len) {
  return len >= 192 && CRYPTO_is_NEON_capable();
}
void ChaCha20_ctr32_neon(uint8_t *out, const uint8_t *in, size_t in_len,
                         const uint32_t key[8], const uint32_t counter[4]);

#elif !defined(OPENSSL_NO_ASM) && defined(OPENSSL_X86_64)

#define CHACHA20_ASM_NOHW

#define CHACHA20_ASM_AVX2
static inline int ChaCha20_ctr32_avx2_capable(size_t len) {
  return len > 128 && CRYPTO_is_AVX2_capable();
}
void ChaCha20_ctr32_avx2(uint8_t *out, const uint8_t *in, size_t in_len,
                         const uint32_t key[8], const uint32_t counter[4]);

#define CHACHA20_ASM_SSSE3_4X
static inline int ChaCha20_ctr32_ssse3_4x_capable(size_t len) {
  int capable = len > 128 && CRYPTO_is_SSSE3_capable();
  int faster = len > 192 || !CRYPTO_cpu_perf_is_like_silvermont();
  return capable && faster;
}
void ChaCha20_ctr32_ssse3_4x(uint8_t *out, const uint8_t *in, size_t in_len,
                             const uint32_t key[8], const uint32_t counter[4]);

#define CHACHA20_ASM_SSSE3
static inline int ChaCha20_ctr32_ssse3_capable(size_t len) {
  return len > 128 && CRYPTO_is_SSSE3_capable();
}
void ChaCha20_ctr32_ssse3(uint8_t *out, const uint8_t *in, size_t in_len,
                          const uint32_t key[8], const uint32_t counter[4]);
#endif

#if defined(CHACHA20_ASM_NOHW)
// ChaCha20_ctr32_nohw encrypts |in_len| bytes from |in| and writes the result
// to |out|. If |in| and |out| alias, they must be equal. |in_len| may not be
// zero.
//
// |counter[0]| is the initial 32-bit block counter, and the remainder is the
// 96-bit nonce. If the counter overflows, the output is undefined. The function
// will produce output, but the output may vary by machine and may not be
// self-consistent. (On some architectures, the assembly implements a mix of
// 64-bit and 32-bit counters.)
void ChaCha20_ctr32_nohw(uint8_t *out, const uint8_t *in, size_t in_len,
                         const uint32_t key[8], const uint32_t counter[4]);
#endif

// The stitched assembly's arguments and result.
union chacha20_poly1305_open_data {
  struct {
    alignas(16) uint8_t key[32];
    uint32_t counter;
    uint8_t nonce[12];
  } in;
  struct {
    uint8_t tag[16];
  } out;
};

union chacha20_poly1305_seal_data {
  struct {
    alignas(16) uint8_t key[32];
    uint32_t counter;
    uint8_t nonce[12];
    const uint8_t *extra_ciphertext;
    size_t extra_ciphertext_len;
  } in;
  struct {
    uint8_t tag[16];
  } out;
};

#if (defined(OPENSSL_X86_64) || defined(OPENSSL_AARCH64)) && \
    !defined(OPENSSL_NO_ASM)

#define CHACHA20_POLY1305_ASM

OPENSSL_STATIC_ASSERT(sizeof(union chacha20_poly1305_open_data) == 48,
                      _wrong_chacha20_poly1305_open_data_size)
OPENSSL_STATIC_ASSERT(sizeof(union chacha20_poly1305_seal_data) == 48 + 8 + 8,
                      _wrong_chacha20_poly1305_seal_data_size)

static inline int chacha20_poly1305_asm_capable(void) {
#if defined(OPENSSL_X86_64)
  return CRYPTO_is_SSE4_1_capable();
#else
  return CRYPTO_is_NEON_capable();
#endif
}

// chacha20_poly1305_open is defined in chacha20_poly1305_*.pl. It decrypts
// |plaintext_len| bytes from |ciphertext| and writes them to |out_plaintext|.
// Additional input parameters are passed in |aead_data->in|. On exit, it will
// write calculated tag value to |aead_data->out.tag|, which the caller must
// check.
void chacha20_poly1305_open(uint8_t *out_plaintext, const uint8_t *ciphertext,
                            size_t plaintext_len, const uint8_t *ad,
                            size_t ad_len,
                            union chacha20_poly1305_open_data *data);

// chacha20_poly1305_open is defined in chacha20_poly1305_*.pl. It encrypts
// |plaintext_len| bytes from |plaintext| and writes them to |out_ciphertext|.
// Additional input parameters are passed in |aead_data->in|. The calculated tag
// value is over the computed ciphertext concatenated with |extra_ciphertext|
// and written to |aead_data->out.tag|.
void chacha20_poly1305_seal(uint8_t *out_ciphertext, const uint8_t *plaintext,
                            size_t plaintext_len, const uint8_t *ad,
                            size_t ad_len,
                            union chacha20_poly1305_seal_data *data);

#else

static inline int chacha20_poly1305_asm_capable(void) { return 0; }

#endif

#endif  // OPENSSL_HEADER_CHACHA_INTERNAL
