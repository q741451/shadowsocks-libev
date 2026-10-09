// Copyright (c) 1998-2011 The OpenSSL Project.  All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENSSL_HEADER_ARM_ARCH_H
#define OPENSSL_HEADER_ARM_ARCH_H

#include <openssl/target.h>

#if defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64)

// Bits of OPENSSL_armcap_P, the ARM features detected at run time.
#define ARMV7_NEON (1 << 0)
#define ARMV8_AES (1 << 2)
#define ARMV8_PMULL (1 << 5)
#define ARMV8_SHA3 (1 << 11)
#define ARMV8_NEOVERSE_V1 (1 << 12)
#define ARMV8_NEOVERSE_V2 (1 << 14)
#define ARMV8_NEOVERSE_V3 (1 << 18)

#endif  // ARM || AARCH64

#endif  // OPENSSL_HEADER_ARM_ARCH_H
