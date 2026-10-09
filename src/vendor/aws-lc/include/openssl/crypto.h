// Copyright (c) 2014, Google Inc.
// SPDX-License-Identifier: ISC

#ifndef OPENSSL_HEADER_CRYPTO_H
#define OPENSSL_HEADER_CRYPTO_H

// CRYPTO_library_init detects the CPU features the assembly selects its code
// by. It must run before anything else here; without it everything runs, more
// slowly, as portable C.
void CRYPTO_library_init(void);

#endif  // OPENSSL_HEADER_CRYPTO_H
