// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#ifndef OPENSSL_HEADER_CPUCAP_H
#define OPENSSL_HEADER_CPUCAP_H

#include "internal.h"

#if !defined(OPENSSL_NO_ASM)

// Set by CRYPTO_library_init once the CPU features below are known.
extern uint8_t OPENSSL_cpucap_initialized;

#if defined(OPENSSL_X86_64)

// CPUID leaf 1 EDX and ECX in words 0 and 1, leaf 7 EBX and ECX in 2 and 3.
// The assembly reads it too, so the layout is fixed.
extern uint32_t OPENSSL_ia32cap_P[4];

static inline int CRYPTO_is_FXSR_capable(void) {
  return (OPENSSL_ia32cap_P[0] & (1 << 24)) != 0;
}

// Not a CPUID bit: set by CRYPTO_library_init on Intel CPUs.
static inline int CRYPTO_is_intel_cpu(void) {
  return (OPENSSL_ia32cap_P[0] & (1 << 30)) != 0;
}

static inline int CRYPTO_is_PCLMUL_capable(void) {
  return (OPENSSL_ia32cap_P[1] & (1 << 1)) != 0;
}

static inline int CRYPTO_is_SSSE3_capable(void) {
  return (OPENSSL_ia32cap_P[1] & (1 << 9)) != 0;
}

static inline int CRYPTO_is_SSE4_1_capable(void) {
  return (OPENSSL_ia32cap_P[1] & (1 << 19)) != 0;
}

static inline int CRYPTO_is_MOVBE_capable(void) {
  return (OPENSSL_ia32cap_P[1] & (1 << 22)) != 0;
}

static inline int CRYPTO_is_AESNI_capable(void) {
  return (OPENSSL_ia32cap_P[1] & (1 << 25)) != 0;
}

static inline int CRYPTO_is_AVX_capable(void) {
  return (OPENSSL_ia32cap_P[1] & (1 << 28)) != 0;
}

static inline int CRYPTO_is_BMI1_capable(void) {
  return (OPENSSL_ia32cap_P[2] & (1 << 3)) != 0;
}

static inline int CRYPTO_is_AVX2_capable(void) {
  return (OPENSSL_ia32cap_P[2] & (1 << 5)) != 0;
}

static inline int CRYPTO_is_BMI2_capable(void) {
  return (OPENSSL_ia32cap_P[2] & (1 << 8)) != 0;
}

static inline int CRYPTO_is_SHAEXT_capable(void) {
  return (OPENSSL_ia32cap_P[2] & (1 << 29)) != 0;
}

// Silvermont and Goldmont lack XSAVE but have MOVBE; there the 4-way SSSE3
// ChaCha20 is slower than the plain one for short inputs.
static inline int CRYPTO_cpu_perf_is_like_silvermont(void) {
  int hardware_supports_xsave = (OPENSSL_ia32cap_P[1] & (1u << 26)) != 0;
  return !hardware_supports_xsave && CRYPTO_is_MOVBE_capable();
}

#endif  // OPENSSL_X86_64

#if defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64)

#include <openssl/arm_arch.h>

extern uint32_t OPENSSL_armcap_P;

static inline int CRYPTO_is_NEON_capable(void) {
  return (OPENSSL_armcap_P & ARMV7_NEON) != 0;
}

static inline int CRYPTO_is_ARMv8_AES_capable(void) {
  return (OPENSSL_armcap_P & ARMV8_AES) != 0;
}

static inline int CRYPTO_is_ARMv8_PMULL_capable(void) {
  return (OPENSSL_armcap_P & ARMV8_PMULL) != 0;
}

static inline int CRYPTO_is_ARMv8_SHA1_capable(void) {
  return (OPENSSL_armcap_P & ARMV8_SHA1) != 0;
}

// The 8-way unrolled AES-GCM needs SHA3's EOR3 and pays off on the wide
// Neoverse V cores.
static inline int CRYPTO_is_ARMv8_GCM_8x_capable(void) {
  return (OPENSSL_armcap_P & ARMV8_SHA3) != 0 &&
         (OPENSSL_armcap_P &
          (ARMV8_NEOVERSE_V1 | ARMV8_NEOVERSE_V2 | ARMV8_NEOVERSE_V3)) != 0;
}

#endif  // OPENSSL_ARM || OPENSSL_AARCH64

#endif  // !OPENSSL_NO_ASM

#endif  // OPENSSL_HEADER_CPUCAP_H
