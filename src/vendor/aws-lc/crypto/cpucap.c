// Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com) All rights reserved.
// Copyright (c) 2016, Google Inc.
// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Run-time CPU feature detection, from AWS-LC's cpucap/cpu_intel.c,
// cpu_aarch64*.c and cpu_arm_linux.c, for Linux only.

#include <openssl/crypto.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cpucap.h"

#if !defined(OPENSSL_NO_ASM)

#include <sys/auxv.h>

uint8_t OPENSSL_cpucap_initialized = 0;

#if defined(OPENSSL_X86_64) || defined(OPENSSL_AARCH64)
// parse_cap parses one value of OPENSSL_ia32cap or OPENSSL_armcap: an
// optional '~' (clear these bits) or '|' (set them), then a decimal or
// 0x-prefixed hexadecimal number. Without a number it returns zero.
static int parse_cap(const char *in, char *out_op, uint64_t *out_v) {
  *out_op = (in[0] == '~' || in[0] == '|') ? in[0] : 0;
  const char *p = in + (*out_op != 0);
  int base = 10;
  if (p[0] == '0' && p[1] == 'x') {
    base = 16;
    p += 2;
  }
  char *end;
  *out_v = strtoull(p, &end, base);
  return end != p;
}
#endif

#if defined(OPENSSL_X86_64)

uint32_t OPENSSL_ia32cap_P[4] = {0};

static void OPENSSL_cpuid(uint32_t *out_eax, uint32_t *out_ebx,
                          uint32_t *out_ecx, uint32_t *out_edx, uint32_t leaf) {
  __asm__ volatile (
    "xor %%ecx, %%ecx\n"
    "cpuid\n"
    : "=a"(*out_eax), "=b"(*out_ebx), "=c"(*out_ecx), "=d"(*out_edx)
    : "a"(leaf)
  );
}

static uint64_t OPENSSL_xgetbv(uint32_t xcr) {
  uint32_t eax, edx;
  __asm__ volatile ("xgetbv" : "=a"(eax), "=d"(edx) : "c"(xcr));
  return (((uint64_t)edx) << 32) | eax;
}

// handle_cpu_env applies one OPENSSL_ia32cap value to |out[0]| and |out[1]|.
// Setting a feature the CPU lacks is refused, since the code would crash.
static void handle_cpu_env(uint32_t *out, const char *in) {
  char op;
  uint64_t v;
  if (!parse_cap(in, &op, &v)) {
    return;
  }
  uint32_t reqcap0 = (uint32_t)(v & UINT32_MAX);
  uint32_t reqcap1 = (uint32_t)(v >> 32);
  if (op != '~' && (out[0] || out[1]) &&
      ((~(1u << 30 | out[0]) & reqcap0) || (~out[1] & reqcap1))) {
    fprintf(stderr,
            "Fatal Error: HW capability found: 0x%02X 0x%02X, but HW "
            "capability requested: 0x%02X 0x%02X.\n",
            out[0], out[1], reqcap0, reqcap1);
    abort();
  }
  if (op == '~') {
    out[0] &= ~reqcap0;
    out[1] &= ~reqcap1;
  } else if (op == '|') {
    out[0] |= reqcap0;
    out[1] |= reqcap1;
  } else {
    out[0] = reqcap0;
    out[1] = reqcap1;
  }
}

static void OPENSSL_cpuid_setup(void) {
  uint32_t eax, ebx, ecx, edx;
  OPENSSL_cpuid(&eax, &ebx, &ecx, &edx, 0);

  uint32_t num_ids = eax;

  int is_intel = ebx == 0x756e6547 /* Genu */ &&
                 edx == 0x49656e69 /* ineI */ &&
                 ecx == 0x6c65746e /* ntel */;

  uint32_t extended_features[2] = {0};
  if (num_ids >= 7) {
    OPENSSL_cpuid(&eax, &ebx, &ecx, &edx, 7);
    extended_features[0] = ebx;
    extended_features[1] = ecx;
  }

  OPENSSL_cpuid(&eax, &ebx, &ecx, &edx, 1);

  // Force the hyper-threading bit so that the more conservative path is always
  // chosen.
  edx |= 1u << 28;

  // Reserved bit #20 was historically repurposed to control the in-memory
  // representation of RC4 state. Always set it to zero.
  edx &= ~(1u << 20);

  // Reserved bit #30 is repurposed to signal an Intel CPU.
  if (is_intel) {
    edx |= (1u << 30);

    // Clear the XSAVE bit on Knights Landing to mimic Silvermont. This enables
    // some Silvermont-specific codepaths which perform better.
    if ((eax & 0x0fff0ff0) == 0x00050670 /* Knights Landing */ ||
        (eax & 0x0fff0ff0) == 0x00080650 /* Knights Mill (per SDE) */) {
      ecx &= ~(1u << 26);
    }
  } else {
    edx &= ~(1u << 30);
  }

  // The SDBG bit is repurposed to denote AMD XOP support. Don't ever use AMD
  // XOP code paths.
  ecx &= ~(1u << 11);

  uint64_t xcr0 = 0;
  if (ecx & (1u << 27)) {
    // XCR0 may only be queried if the OSXSAVE bit is set.
    xcr0 = OPENSSL_xgetbv(0);
  }
  // See Intel manual, volume 1, section 14.3.
  if ((xcr0 & 6) != 6) {
    // YMM registers cannot be used.
    ecx &= ~(1u << 28);  // AVX
    ecx &= ~(1u << 12);  // FMA
    ecx &= ~(1u << 11);  // AMD XOP
    extended_features[0] &=
        ~((1u << 5) | (1u << 16) | (1u << 21) | (1u << 30) | (1u << 31));
  }
  // See Intel manual, volume 1, sections 15.2 ("Detection of AVX-512 Foundation
  // Instructions") through 15.4 ("Detection of Intel AVX-512 Instruction Groups
  // Operating at 256 and 128-bit Vector Lengths").
  if ((xcr0 & 0xe6) != 0xe6) {
    // Without XCR0.111xx11x, no AVX512 feature can be used. This includes ZMM
    // registers, masking, SIMD registers 16-31 (even if accessed as YMM or
    // XMM), and EVEX-coded instructions (even on YMM or XMM). Even if only
    // XCR0.ZMM_Hi256 is missing, it isn't valid to use AVX512 features on
    // shorter vectors, since AVX512 ties everything to the availability of
    // 512-bit vectors. See the above-mentioned sections of the Intel manual,
    // which say that *all* these XCR0 bits must be checked even when just
    // using 128-bit or 256-bit vectors, and also volume 2a section 2.7.2.2
    // ("Instruction Exception Specification") which says that MXCSR must be
    // set to 0x1F80 before using the EVEX-encoded versions of instructions.
    extended_features[0] &= ~(1u << 16);
  }

  // Disable ADX instructions on Knights Landing. See OpenSSL commit
  // 64d92d74985ebb3d0be58a9718f9e080a14a8e7f.
  if ((ecx & (1u << 26)) == 0) {
    extended_features[0] &= ~(1u << 19);
  }

  OPENSSL_ia32cap_P[0] = edx;
  OPENSSL_ia32cap_P[1] = ecx;
  OPENSSL_ia32cap_P[2] = extended_features[0];
  OPENSSL_ia32cap_P[3] = extended_features[1];

  OPENSSL_cpucap_initialized = 1;

  // OPENSSL_ia32cap holds zero, one or two values separated by ':', for words
  // 0 and 1 and for words 2 and 3. Each is a 64-bit value as parse_cap reads.
  const char *env1 = getenv("OPENSSL_ia32cap");
  if (env1 == NULL) {
    return;
  }
  handle_cpu_env(&OPENSSL_ia32cap_P[0], env1);
  const char *env2 = strchr(env1, ':');
  if (env2 != NULL) {
    handle_cpu_env(&OPENSSL_ia32cap_P[2], env2 + 1);
  }
}

#elif defined(OPENSSL_AARCH64)

uint32_t OPENSSL_armcap_P = 0;

// MIDR_EL1 fields identifying the Neoverse V cores.
#define ARM_CPU_IMP_ARM 0x41
#define ARM_CPU_PART_V1 0xD40
#define ARM_CPU_PART_V2 0xD4F
#define ARM_CPU_PART_V3 0xD84
#define MIDR_CPU_MODEL_MASK 0xff0ffff0UL
#define MIDR_CPU_MODEL(imp, partnum) \
  (((imp) << 24) | (0xfUL << 16) | ((partnum) << 4))
#define MIDR_IS_CPU_MODEL(midr, imp, partnum) \
  (((midr) & MIDR_CPU_MODEL_MASK) == MIDR_CPU_MODEL(imp, partnum))

static uint64_t armv8_cpuid_probe(void) {
  uint64_t val;
  __asm__ volatile("mrs %0, MIDR_EL1" : "=r" (val));
  return val;
}

// handle_cpu_env applies an OPENSSL_armcap value to |*out|. Setting a feature
// the CPU lacks is refused, since the code would crash.
static void handle_cpu_env(uint32_t *out, const char *in) {
  char op;
  uint64_t v64;
  if (!parse_cap(in, &op, &v64)) {
    return;
  }
  uint32_t v = (uint32_t)v64;
  if (op != '~' && *out && (~*out & v)) {
    fprintf(stderr,
            "Fatal Error: HW capability found: 0x%02X, but HW capability "
            "requested: 0x%02X.\n",
            *out, v);
    abort();
  }
  if (op == '~') {
    *out &= ~v;
  } else if (op == '|') {
    *out |= v;
  } else {
    *out = v;
  }
}

static void OPENSSL_cpuid_setup(void) {
  unsigned long hwcap = getauxval(AT_HWCAP);

  // See /usr/include/asm/hwcap.h on an aarch64 installation for the source of
  // these values.
  static const unsigned long kNEON = 1 << 1;
  static const unsigned long kAES = 1 << 3;
  static const unsigned long kPMULL = 1 << 4;
  static const unsigned long kSHA1 = 1 << 5;
  static const unsigned long kCPUID = 1 << 11;
  static const unsigned long kSHA3 = 1 << 17;

  if ((hwcap & kNEON) == 0) {
    // Matching OpenSSL, if NEON is missing, don't report other features
    // either.
    OPENSSL_cpucap_initialized = 1;
    return;
  }

  OPENSSL_armcap_P |= ARMV7_NEON;

  if (hwcap & kAES) {
    OPENSSL_armcap_P |= ARMV8_AES;
  }
  if (hwcap & kPMULL) {
    OPENSSL_armcap_P |= ARMV8_PMULL;
  }
  if (hwcap & kSHA1) {
    OPENSSL_armcap_P |= ARMV8_SHA1;
  }
  if (hwcap & kSHA3) {
    OPENSSL_armcap_P |= ARMV8_SHA3;
  }
  if (hwcap & kCPUID) {
    uint64_t midr = armv8_cpuid_probe();
    if (MIDR_IS_CPU_MODEL(midr, ARM_CPU_IMP_ARM, ARM_CPU_PART_V1)) {
      OPENSSL_armcap_P |= ARMV8_NEOVERSE_V1;
    }
    if (MIDR_IS_CPU_MODEL(midr, ARM_CPU_IMP_ARM, ARM_CPU_PART_V2)) {
      OPENSSL_armcap_P |= ARMV8_NEOVERSE_V2;
    }
    if (MIDR_IS_CPU_MODEL(midr, ARM_CPU_IMP_ARM, ARM_CPU_PART_V3)) {
      OPENSSL_armcap_P |= ARMV8_NEOVERSE_V3;
    }
  }

  const char *env = getenv("OPENSSL_armcap");
  if (env != NULL) {
    handle_cpu_env(&OPENSSL_armcap_P, env);
  }

  OPENSSL_cpucap_initialized = 1;
}

#elif defined(OPENSSL_ARM)

uint32_t OPENSSL_armcap_P = 0;

// Linux's asm/hwcap.h for 32-bit ARM.
#define HWCAP_NEON (1 << 12)
#define HWCAP2_AES (1 << 0)
#define HWCAP2_PMULL (1 << 1)
#define HWCAP2_SHA1 (1 << 2)

static void OPENSSL_cpuid_setup(void) {
  unsigned long hwcap = getauxval(AT_HWCAP);
  if (hwcap & HWCAP_NEON) {
    OPENSSL_armcap_P |= ARMV7_NEON;

    // The ARMv8 crypto extensions are reported in AT_HWCAP2, which every
    // kernel this is built for provides.
    unsigned long hwcap2 = getauxval(AT_HWCAP2);
    if (hwcap2 & HWCAP2_AES) {
      OPENSSL_armcap_P |= ARMV8_AES;
    }
    if (hwcap2 & HWCAP2_PMULL) {
      OPENSSL_armcap_P |= ARMV8_PMULL;
    }
    if (hwcap2 & HWCAP2_SHA1) {
      OPENSSL_armcap_P |= ARMV8_SHA1;
    }
  }

  OPENSSL_cpucap_initialized = 1;
}

#endif

void CRYPTO_library_init(void) { OPENSSL_cpuid_setup(); }

#else  // OPENSSL_NO_ASM

void CRYPTO_library_init(void) {}

#endif  // !OPENSSL_NO_ASM
