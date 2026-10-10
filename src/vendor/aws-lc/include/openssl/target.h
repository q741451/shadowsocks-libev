// Copyright (c) 2023, Google Inc.
// SPDX-License-Identifier: ISC

#ifndef OPENSSL_HEADER_TARGET_H
#define OPENSSL_HEADER_TARGET_H

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define OPENSSL_BIG_ENDIAN
#endif

#if defined(__SIZEOF_POINTER__) && __SIZEOF_POINTER__ == 8
#define OPENSSL_64_BIT
#endif

#if defined(__x86_64__)
#define OPENSSL_X86_64
#elif defined(__AARCH64EL__)
#define OPENSSL_AARCH64
#elif defined(__ARMEL__)
#define OPENSSL_ARM
#endif

// The assembly is generated for these, as ELF on Linux. Everything else is
// portable C; the assembly files then preprocess to nothing.
#if !(defined(OPENSSL_X86_64) || defined(OPENSSL_AARCH64) || \
      defined(OPENSSL_ARM)) || !defined(__linux__) || !defined(__ELF__)
#define OPENSSL_NO_ASM
#endif

#endif  // OPENSSL_HEADER_TARGET_H
