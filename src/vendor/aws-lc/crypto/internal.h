// Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
// Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENSSL_HEADER_CRYPTO_INTERNAL_H
#define OPENSSL_HEADER_CRYPTO_INTERNAL_H

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <openssl/target.h>

#if defined(OPENSSL_64_BIT)
#define BORINGSSL_HAS_UINT128
typedef __uint128_t uint128_t;
typedef uint64_t crypto_word_t;
#else
typedef uint32_t crypto_word_t;
#endif

#if defined(__SSE2__)
#define OPENSSL_SSE2
#endif

#define OPENSSL_STATIC_ASSERT(cond, msg) _Static_assert(cond, #msg);

// buffers_alias returns one if |a| and |b| alias and zero otherwise.
static inline int buffers_alias(const uint8_t *a, size_t a_len,
                                const uint8_t *b, size_t b_len) {
  uintptr_t a_u = (uintptr_t)a;
  uintptr_t b_u = (uintptr_t)b;
  return a_u + a_len > b_u && b_u + b_len > a_u;
}

// align_pointer returns |ptr|, advanced to |alignment|, a power of two.
static inline void *align_pointer(void *ptr, size_t alignment) {
  uintptr_t offset = (0u - (uintptr_t)ptr) & (alignment - 1);
  return (char *)ptr + offset;
}

// memcpy and memset are undefined for NULL even with a zero length.
static inline void *OPENSSL_memcpy(void *dst, const void *src, size_t n) {
  if (n == 0) {
    return dst;
  }
  return memcpy(dst, src, n);
}

static inline void *OPENSSL_memset(void *dst, int c, size_t n) {
  if (n == 0) {
    return dst;
  }
  return memset(dst, c, n);
}

// OPENSSL_cleanse zeroes |len| bytes at |ptr| in a way the compiler does not
// remove as a dead store.
static inline void OPENSSL_cleanse(void *ptr, size_t len) {
  OPENSSL_memset(ptr, 0, len);
  __asm__ __volatile__("" : : "r"(ptr) : "memory");
}

// CRYPTO_memcmp returns zero iff the |len| bytes at |a| and |b| are equal, in
// time independent of their contents.
static inline int CRYPTO_memcmp(const void *in_a, const void *in_b,
                                size_t len) {
  const uint8_t *a = in_a;
  const uint8_t *b = in_b;
  uint8_t x = 0;
  for (size_t i = 0; i < len; i++) {
    x |= a[i] ^ b[i];
  }
  return x;
}

static inline uint32_t CRYPTO_rotl_u32(uint32_t value, int shift) {
  return (value << shift) | (value >> ((-shift) & 31));
}

static inline uint32_t CRYPTO_load_u32_le(const void *in) {
  uint32_t v;
  OPENSSL_memcpy(&v, in, sizeof(v));
#if defined(OPENSSL_BIG_ENDIAN)
  return __builtin_bswap32(v);
#else
  return v;
#endif
}

static inline void CRYPTO_store_u32_le(void *out, uint32_t v) {
#if defined(OPENSSL_BIG_ENDIAN)
  v = __builtin_bswap32(v);
#endif
  OPENSSL_memcpy(out, &v, sizeof(v));
}

static inline uint32_t CRYPTO_load_u32_be(const void *in) {
  uint32_t v;
  OPENSSL_memcpy(&v, in, sizeof(v));
#if defined(OPENSSL_BIG_ENDIAN)
  return v;
#else
  return __builtin_bswap32(v);
#endif
}

static inline void CRYPTO_store_u32_be(void *out, uint32_t v) {
#if !defined(OPENSSL_BIG_ENDIAN)
  v = __builtin_bswap32(v);
#endif
  OPENSSL_memcpy(out, &v, sizeof(v));
}

static inline uint64_t CRYPTO_load_u64_le(const void *in) {
  uint64_t v;
  OPENSSL_memcpy(&v, in, sizeof(v));
#if defined(OPENSSL_BIG_ENDIAN)
  return __builtin_bswap64(v);
#else
  return v;
#endif
}

static inline void CRYPTO_store_u64_le(void *out, uint64_t v) {
#if defined(OPENSSL_BIG_ENDIAN)
  v = __builtin_bswap64(v);
#endif
  OPENSSL_memcpy(out, &v, sizeof(v));
}

static inline uint64_t CRYPTO_load_u64_be(const void *in) {
  uint64_t v;
  OPENSSL_memcpy(&v, in, sizeof(v));
#if defined(OPENSSL_BIG_ENDIAN)
  return v;
#else
  return __builtin_bswap64(v);
#endif
}

static inline void CRYPTO_store_u64_be(void *out, uint64_t v) {
#if !defined(OPENSSL_BIG_ENDIAN)
  v = __builtin_bswap64(v);
#endif
  OPENSSL_memcpy(out, &v, sizeof(v));
}

static inline crypto_word_t CRYPTO_load_word_le(const void *in) {
#if defined(OPENSSL_64_BIT)
  return CRYPTO_load_u64_le(in);
#else
  return CRYPTO_load_u32_le(in);
#endif
}

static inline void CRYPTO_store_word_le(void *out, crypto_word_t v) {
#if defined(OPENSSL_64_BIT)
  CRYPTO_store_u64_le(out, v);
#else
  CRYPTO_store_u32_le(out, v);
#endif
}

#endif  // OPENSSL_HEADER_CRYPTO_INTERNAL_H
