// Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com) All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENSSL_HEADER_SHA1_INTERNAL_H
#define OPENSSL_HEADER_SHA1_INTERNAL_H

#include "cpucap.h"

// The SHA-1 block function is assembly where the CPU has something better
// than the portable C below, picked at run time.

#if !defined(OPENSSL_NO_ASM) && defined(OPENSSL_X86_64)

#define SHA1_ASM_NOHW

#define SHA1_ASM_HW
static inline int sha1_hw_capable(void) {
  return CRYPTO_is_SHAEXT_capable() && CRYPTO_is_SSSE3_capable();
}

#define SHA1_ASM_AVX2
static inline int sha1_avx2_capable(void) {
  return CRYPTO_is_AVX2_capable() && CRYPTO_is_BMI2_capable() &&
         CRYPTO_is_BMI1_capable() && CRYPTO_is_SSSE3_capable();
}
void sha1_block_data_order_avx2(uint32_t state[5], const uint8_t *data,
                                size_t num);

#define SHA1_ASM_AVX
static inline int sha1_avx_capable(void) {
  // Pre-Zen AMD CPUs had slow SHLD/SHRD; Zen added the SHA extension; see the
  // discussion in sha1-586.pl.
  return CRYPTO_is_AVX_capable() && CRYPTO_is_SSSE3_capable() &&
         CRYPTO_is_intel_cpu();
}
void sha1_block_data_order_avx(uint32_t state[5], const uint8_t *data,
                               size_t num);

#define SHA1_ASM_SSSE3
static inline int sha1_ssse3_capable(void) {
  return CRYPTO_is_SSSE3_capable() && CRYPTO_is_FXSR_capable();
}
void sha1_block_data_order_ssse3(uint32_t state[5], const uint8_t *data,
                                 size_t num);

#elif !defined(OPENSSL_NO_ASM) && \
    (defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64))

#define SHA1_ASM_NOHW

#define SHA1_ASM_HW
static inline int sha1_hw_capable(void) {
  return CRYPTO_is_ARMv8_SHA1_capable();
}

#if defined(OPENSSL_ARM)
#define SHA1_ASM_NEON
void sha1_block_data_order_neon(uint32_t state[5], const uint8_t *data,
                                size_t num);
#endif

#endif

#if defined(SHA1_ASM_HW)
void sha1_block_data_order_hw(uint32_t state[5], const uint8_t *data,
                              size_t num);
#endif
#if defined(SHA1_ASM_NOHW)
void sha1_block_data_order_nohw(uint32_t state[5], const uint8_t *data,
                                size_t num);
#endif

#endif  // OPENSSL_HEADER_SHA1_INTERNAL_H
