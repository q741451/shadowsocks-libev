// Copyright (c) 2023, Google Inc.
// SPDX-License-Identifier: ISC

#ifndef OPENSSL_HEADER_ASM_BASE_H
#define OPENSSL_HEADER_ASM_BASE_H

#include <openssl/target.h>

#if defined(__ASSEMBLER__)

// The stack is not executable.
.pushsection .note.GNU-stack, "", %progbits
.popsection

// Intel CET: _CET_ENDBR marks indirect branch targets.
#if defined(__CET__) && defined(OPENSSL_X86_64)
#include <cet.h>
#elif !defined(_CET_ENDBR)
#define _CET_ENDBR .byte 0xf3,0x0f,0x1e,0xfa
#endif

#if defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64)

#if defined(__aarch64__) && !defined(__ARM_ARCH)
#define __ARM_ARCH 8
#endif
#if !defined(__ARM_ARCH)
#error "ARM assembler must define __ARM_ARCH"
#endif

// The highest ARM architecture the code may use; anything above the baseline
// is only reached after a run-time CPU check.
#define __ARM_MAX_ARCH__ 8

// Branch target identification and pointer authentication, when the
// compiler builds the rest of the program with them.
#if defined(__ARM_FEATURE_BTI_DEFAULT) && __ARM_FEATURE_BTI_DEFAULT == 1
#define GNU_PROPERTY_AARCH64_BTI (1 << 0)
#define AARCH64_VALID_CALL_TARGET hint #34  // BTI 'c'
#else
#define GNU_PROPERTY_AARCH64_BTI 0
#define AARCH64_VALID_CALL_TARGET
#endif

#if defined(__ARM_FEATURE_PAC_DEFAULT) && \
    (__ARM_FEATURE_PAC_DEFAULT & 1) == 1  // Signed with A-key
#define GNU_PROPERTY_AARCH64_POINTER_AUTH (1 << 1)
#define AARCH64_SIGN_LINK_REGISTER hint #25      // PACIASP
#define AARCH64_VALIDATE_LINK_REGISTER hint #29  // AUTIASP
#elif defined(__ARM_FEATURE_PAC_DEFAULT) && \
    (__ARM_FEATURE_PAC_DEFAULT & 2) == 2  // Signed with B-key
#define GNU_PROPERTY_AARCH64_POINTER_AUTH (1 << 1)
#define AARCH64_SIGN_LINK_REGISTER hint #27      // PACIBSP
#define AARCH64_VALIDATE_LINK_REGISTER hint #31  // AUTIBSP
#else
#define GNU_PROPERTY_AARCH64_POINTER_AUTH 0
#if GNU_PROPERTY_AARCH64_BTI != 0
#define AARCH64_SIGN_LINK_REGISTER AARCH64_VALID_CALL_TARGET
#else
#define AARCH64_SIGN_LINK_REGISTER
#endif
#define AARCH64_VALIDATE_LINK_REGISTER
#endif

#if GNU_PROPERTY_AARCH64_POINTER_AUTH != 0 || GNU_PROPERTY_AARCH64_BTI != 0
.pushsection .note.gnu.property, "a";
.balign 8;
.long 4;
.long 0x10;
.long 0x5;
.asciz "GNU";
.long 0xc0000000; /* GNU_PROPERTY_AARCH64_FEATURE_1_AND */
.long 4;
.long (GNU_PROPERTY_AARCH64_POINTER_AUTH | GNU_PROPERTY_AARCH64_BTI);
.long 0;
.popsection;
#endif

#endif  // ARM || AARCH64

#endif  // __ASSEMBLER__

#endif  // OPENSSL_HEADER_ASM_BASE_H
