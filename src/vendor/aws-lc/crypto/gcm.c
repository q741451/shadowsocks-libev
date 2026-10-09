// Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <stdlib.h>

#include "gcm.h"

static const size_t kSizeTWithoutLower4Bits = (size_t) -16;

#if defined(OPENSSL_NO_ASM)
#define GCM_MUL(ctx, Xi) gcm_gmult_nohw((ctx)->Xi, (ctx)->gcm_key.Htable)
#define GHASH(ctx, in, len) \
  gcm_ghash_nohw((ctx)->Xi, (ctx)->gcm_key.Htable, in, len)
#else
#define GCM_MUL(ctx, Xi) \
  (*(ctx)->gcm_key.gmult)((ctx)->Xi, (ctx)->gcm_key.Htable)
#define GHASH(ctx, in, len) \
  (*(ctx)->gcm_key.ghash)((ctx)->Xi, (ctx)->gcm_key.Htable, in, len)
#endif

// GHASH_CHUNK is "stride parameter" missioned to mitigate cache trashing
// effect. In other words idea is to hash data while it's still in L1 cache
// after encryption pass...
#define GHASH_CHUNK (3 * 1024)

#if defined(GHASH_ASM_X86_64)
static inline void gcm_reduce_1bit(u128 *V) {
  uint64_t T = UINT64_C(0xe100000000000000) & (0 - (V->hi & 1));
  V->hi = (V->lo << 63) | (V->hi >> 1);
  V->lo = (V->lo >> 1) ^ T;
}

void gcm_init_ssse3(u128 Htable[16], const uint64_t H[2]) {
  Htable[0].hi = 0;
  Htable[0].lo = 0;
  u128 V;
  V.hi = H[1];
  V.lo = H[0];

  Htable[8] = V;
  gcm_reduce_1bit(&V);
  Htable[4] = V;
  gcm_reduce_1bit(&V);
  Htable[2] = V;
  gcm_reduce_1bit(&V);
  Htable[1] = V;
  Htable[3].hi = V.hi ^ Htable[2].hi, Htable[3].lo = V.lo ^ Htable[2].lo;
  V = Htable[4];
  Htable[5].hi = V.hi ^ Htable[1].hi, Htable[5].lo = V.lo ^ Htable[1].lo;
  Htable[6].hi = V.hi ^ Htable[2].hi, Htable[6].lo = V.lo ^ Htable[2].lo;
  Htable[7].hi = V.hi ^ Htable[3].hi, Htable[7].lo = V.lo ^ Htable[3].lo;
  V = Htable[8];
  Htable[9].hi = V.hi ^ Htable[1].hi, Htable[9].lo = V.lo ^ Htable[1].lo;
  Htable[10].hi = V.hi ^ Htable[2].hi, Htable[10].lo = V.lo ^ Htable[2].lo;
  Htable[11].hi = V.hi ^ Htable[3].hi, Htable[11].lo = V.lo ^ Htable[3].lo;
  Htable[12].hi = V.hi ^ Htable[4].hi, Htable[12].lo = V.lo ^ Htable[4].lo;
  Htable[13].hi = V.hi ^ Htable[5].hi, Htable[13].lo = V.lo ^ Htable[5].lo;
  Htable[14].hi = V.hi ^ Htable[6].hi, Htable[14].lo = V.lo ^ Htable[6].lo;
  Htable[15].hi = V.hi ^ Htable[7].hi, Htable[15].lo = V.lo ^ Htable[7].lo;

  // Treat |Htable| as a 16x16 byte table and transpose it. Thus, Htable[i]
  // contains the i'th byte of j*H for all j.
  uint8_t *Hbytes = (uint8_t *)Htable;
  for (int i = 0; i < 16; i++) {
    for (int j = 0; j < i; j++) {
      uint8_t tmp = Hbytes[16*i + j];
      Hbytes[16*i + j] = Hbytes[16*j + i];
      Hbytes[16*j + i] = tmp;
    }
  }
}
#endif  // GHASH_ASM_X86_64

#if defined(HW_GCM) && defined(OPENSSL_X86_64)
static size_t hw_gcm_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                             const AES_KEY *key, uint8_t ivec[16],
                             uint8_t Xi[16], const u128 Htable[16]) {
  return aesni_gcm_encrypt(in, out, len, key, ivec, Htable, Xi);
}

static size_t hw_gcm_decrypt(const uint8_t *in, uint8_t *out, size_t len,
                             const AES_KEY *key, uint8_t ivec[16],
                             uint8_t Xi[16], const u128 Htable[16]) {
  return aesni_gcm_decrypt(in, out, len, key, ivec, Htable, Xi);
}
#endif  // HW_GCM && X86_64

#if defined(HW_GCM) && defined(OPENSSL_AARCH64)
static size_t hw_gcm_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                             const AES_KEY *key, uint8_t ivec[16],
                             uint8_t Xi[16], const u128 Htable[16]) {
  const size_t len_blocks = len & kSizeTWithoutLower4Bits;
  if (!len_blocks) {
    return 0;
  }

  if (CRYPTO_is_ARMv8_GCM_8x_capable() && len >= 256) {
    switch(key->rounds) {
    case 10:
      aesv8_gcm_8x_enc_128(in, len_blocks * 8, out, Xi, ivec, key, Htable);
      break;
    case 12:
      aesv8_gcm_8x_enc_192(in, len_blocks * 8, out, Xi, ivec, key, Htable);
      break;
    case 14:
      aesv8_gcm_8x_enc_256(in, len_blocks * 8, out, Xi, ivec, key, Htable);
      break;
    default:
      return 0;
    }
  } else {
    aes_gcm_enc_kernel(in, len_blocks * 8, out, Xi, ivec, key, Htable);
  }

  return len_blocks;
}

static size_t hw_gcm_decrypt(const uint8_t *in, uint8_t *out, size_t len,
                             const AES_KEY *key, uint8_t ivec[16],
                             uint8_t Xi[16], const u128 Htable[16]) {
  const size_t len_blocks = len & kSizeTWithoutLower4Bits;
  if (!len_blocks) {
    return 0;
  }

  if (CRYPTO_is_ARMv8_GCM_8x_capable() && len >= 256) {
    switch(key->rounds) {
    case 10:
      aesv8_gcm_8x_dec_128(in, len_blocks * 8, out, Xi, ivec, key, Htable);
      break;
    case 12:
      aesv8_gcm_8x_dec_192(in, len_blocks * 8, out, Xi, ivec, key, Htable);
      break;
    case 14:
      aesv8_gcm_8x_dec_256(in, len_blocks * 8, out, Xi, ivec, key, Htable);
      break;
    default:
      return 0;
    }
  } else {
    aes_gcm_dec_kernel(in, len_blocks * 8, out, Xi, ivec, key, Htable);
  }

  return len_blocks;
}
#endif  // HW_GCM && AARCH64

// ghash_init picks the GHASH implementation for this CPU and computes its
// table from |gcm_key|. |*out_is_avx| is set for the AVX one, which the
// stitched x86_64 AES-GCM assembly requires.
static void ghash_init(GCM128_KEY *key, int *out_is_avx,
                       const uint8_t gcm_key[16]) {
  *out_is_avx = 0;

  // H is passed to |gcm_init_*| as a pair of byte-swapped, 64-bit values.
  uint64_t H[2] = {CRYPTO_load_u64_be(gcm_key),
                   CRYPTO_load_u64_be(gcm_key + 8)};

#if defined(GHASH_ASM_X86_64)
  if (crypto_gcm_clmul_enabled()) {
    if (CRYPTO_is_AVX_capable() && CRYPTO_is_MOVBE_capable()) {
      gcm_init_avx(key->Htable, H);
      key->gmult = gcm_gmult_avx;
      key->ghash = gcm_ghash_avx;
      *out_is_avx = 1;
      goto out;
    }
    gcm_init_clmul(key->Htable, H);
    key->gmult = gcm_gmult_clmul;
    key->ghash = gcm_ghash_clmul;
    goto out;
  }
  if (CRYPTO_is_SSSE3_capable()) {
    gcm_init_ssse3(key->Htable, H);
    key->gmult = gcm_gmult_ssse3;
    key->ghash = gcm_ghash_ssse3;
    goto out;
  }
#elif defined(GHASH_ASM_ARM)
  if (gcm_pmull_capable()) {
    gcm_init_v8(key->Htable, H);
    key->gmult = gcm_gmult_v8;
    key->ghash = gcm_ghash_v8;
    goto out;
  }
  if (gcm_neon_capable()) {
    gcm_init_neon(key->Htable, H);
    key->gmult = gcm_gmult_neon;
    key->ghash = gcm_ghash_neon;
    goto out;
  }
#endif

  gcm_init_nohw(key->Htable, H);
  key->gmult = gcm_gmult_nohw;
  key->ghash = gcm_ghash_nohw;

#if defined(GHASH_ASM_X86_64) || defined(GHASH_ASM_ARM)
out:
#endif
  OPENSSL_cleanse(H, sizeof(H));
}

void CRYPTO_gcm128_init_key(GCM128_KEY *gcm_key, const AES_KEY *aes_key,
                            block128_f block, int block_is_hwaes) {
  OPENSSL_memset(gcm_key, 0, sizeof(*gcm_key));
  gcm_key->block = block;

  uint8_t ghash_key[16];
  OPENSSL_memset(ghash_key, 0, sizeof(ghash_key));
  (*block)(ghash_key, ghash_key, aes_key);

  int is_avx;
  ghash_init(gcm_key, &is_avx, ghash_key);
  OPENSSL_cleanse(ghash_key, sizeof(ghash_key));

#if defined(OPENSSL_AARCH64) && !defined(OPENSSL_NO_ASM)
  gcm_key->use_hw_gcm_crypt = (gcm_pmull_capable() && block_is_hwaes) ? 1 : 0;
#else
  gcm_key->use_hw_gcm_crypt = (is_avx && block_is_hwaes) ? 1 : 0;
#endif
}

void CRYPTO_gcm128_setiv(GCM128_CONTEXT *ctx, const AES_KEY *key,
                         const uint8_t iv[12]) {
  OPENSSL_memset(&ctx->Yi, 0, sizeof(ctx->Yi));
  OPENSSL_memset(&ctx->Xi, 0, sizeof(ctx->Xi));
  ctx->len.aad = 0;
  ctx->len.msg = 0;
  ctx->ares = 0;
  ctx->mres = 0;

  // A 12-byte IV is the counter block itself, with the counter at 1.
  OPENSSL_memcpy(ctx->Yi, iv, 12);
  ctx->Yi[15] = 1;

  (*ctx->gcm_key.block)(ctx->Yi, ctx->EK0, key);
  CRYPTO_store_u32_be(ctx->Yi + 12, 2);
}

int CRYPTO_gcm128_aad(GCM128_CONTEXT *ctx, const uint8_t *aad, size_t len) {
  if (ctx->len.msg != 0) {
    // The caller must have finished the AAD before providing other input.
    return 0;
  }

  uint64_t alen = ctx->len.aad + len;
  if (alen > (UINT64_C(1) << 61) || (sizeof(len) == 8 && alen < len)) {
    return 0;
  }
  ctx->len.aad = alen;

  unsigned n = ctx->ares;
  if (n) {
    while (n && len) {
      ctx->Xi[n] ^= *(aad++);
      --len;
      n = (n + 1) % 16;
    }
    if (n == 0) {
      GCM_MUL(ctx, Xi);
    } else {
      ctx->ares = n;
      return 1;
    }
  }

  // Process a whole number of blocks.
  size_t len_blocks = len & kSizeTWithoutLower4Bits;
  if (len_blocks != 0) {
    GHASH(ctx, aad, len_blocks);
    aad += len_blocks;
    len -= len_blocks;
  }

  // Process the remainder.
  if (len != 0) {
    n = (unsigned int)len;
    for (size_t i = 0; i < len; ++i) {
      ctx->Xi[i] ^= aad[i];
    }
  }

  ctx->ares = n;
  return 1;
}

int CRYPTO_gcm128_encrypt_ctr32(GCM128_CONTEXT *ctx, const AES_KEY *key,
                                const uint8_t *in, uint8_t *out, size_t len,
                                ctr128_f stream) {
  uint64_t mlen = ctx->len.msg + len;
  if (mlen > ((UINT64_C(1) << 36) - 32) ||
      (sizeof(len) == 8 && mlen < len)) {
    return 0;
  }
  ctx->len.msg = mlen;

  if (ctx->ares) {
    // First call to encrypt finalizes GHASH(AAD)
    GCM_MUL(ctx, Xi);
    ctx->ares = 0;
  }

  unsigned n = ctx->mres;
  if (n) {
    while (n && len) {
      ctx->Xi[n] ^= *(out++) = *(in++) ^ ctx->EKi[n];
      --len;
      n = (n + 1) % 16;
    }
    if (n == 0) {
      GCM_MUL(ctx, Xi);
    } else {
      ctx->mres = n;
      return 1;
    }
  }

#if defined(HW_GCM)
  // Check |len| to work around a C language bug. See https://crbug.com/1019588.
  if (ctx->gcm_key.use_hw_gcm_crypt && len > 0) {
    // |hw_gcm_encrypt| may not process all the input given to it. It may
    // not process *any* of its input if it is deemed too small.
    size_t bulk = hw_gcm_encrypt(in, out, len, key, ctx->Yi, ctx->Xi,
                                 ctx->gcm_key.Htable);
    in += bulk;
    out += bulk;
    len -= bulk;
  }
#endif

  uint32_t ctr = CRYPTO_load_u32_be(ctx->Yi + 12);
  while (len >= GHASH_CHUNK) {
    (*stream)(in, out, GHASH_CHUNK / 16, key, ctx->Yi);
    ctr += GHASH_CHUNK / 16;
    CRYPTO_store_u32_be(ctx->Yi + 12, ctr);
    GHASH(ctx, out, GHASH_CHUNK);
    out += GHASH_CHUNK;
    in += GHASH_CHUNK;
    len -= GHASH_CHUNK;
  }
  size_t len_blocks = len & kSizeTWithoutLower4Bits;
  if (len_blocks != 0) {
    size_t j = len_blocks / 16;

    (*stream)(in, out, j, key, ctx->Yi);
    ctr += (unsigned int)j;
    CRYPTO_store_u32_be(ctx->Yi + 12, ctr);
    in += len_blocks;
    len -= len_blocks;
    GHASH(ctx, out, len_blocks);
    out += len_blocks;
  }
  if (len) {
    (*ctx->gcm_key.block)(ctx->Yi, ctx->EKi, key);
    ++ctr;
    CRYPTO_store_u32_be(ctx->Yi + 12, ctr);
    if ((n + len) > 16) {
      abort();
    }
    while (len--) {
      ctx->Xi[n] ^= out[n] = in[n] ^ ctx->EKi[n];
      ++n;
    }
  }

  ctx->mres = n;
  return 1;
}

int CRYPTO_gcm128_decrypt_ctr32(GCM128_CONTEXT *ctx, const AES_KEY *key,
                                const uint8_t *in, uint8_t *out, size_t len,
                                ctr128_f stream) {
  uint64_t mlen = ctx->len.msg + len;
  if (mlen > ((UINT64_C(1) << 36) - 32) ||
      (sizeof(len) == 8 && mlen < len)) {
    return 0;
  }
  ctx->len.msg = mlen;

  if (ctx->ares) {
    // First call to decrypt finalizes GHASH(AAD)
    GCM_MUL(ctx, Xi);
    ctx->ares = 0;
  }

  unsigned n = ctx->mres;
  if (n) {
    while (n && len) {
      uint8_t c = *(in++);
      *(out++) = c ^ ctx->EKi[n];
      ctx->Xi[n] ^= c;
      --len;
      n = (n + 1) % 16;
    }
    if (n == 0) {
      GCM_MUL(ctx, Xi);
    } else {
      ctx->mres = n;
      return 1;
    }
  }

#if defined(HW_GCM)
  // Check |len| to work around a C language bug. See https://crbug.com/1019588.
  if (ctx->gcm_key.use_hw_gcm_crypt && len > 0) {
    // |hw_gcm_decrypt| may not process all the input given to it. It may
    // not process *any* of its input if it is deemed too small.
    size_t bulk = hw_gcm_decrypt(in, out, len, key, ctx->Yi, ctx->Xi,
                                 ctx->gcm_key.Htable);
    in += bulk;
    out += bulk;
    len -= bulk;
  }
#endif

  uint32_t ctr = CRYPTO_load_u32_be(ctx->Yi + 12);
  while (len >= GHASH_CHUNK) {
    GHASH(ctx, in, GHASH_CHUNK);
    (*stream)(in, out, GHASH_CHUNK / 16, key, ctx->Yi);
    ctr += GHASH_CHUNK / 16;
    CRYPTO_store_u32_be(ctx->Yi + 12, ctr);
    out += GHASH_CHUNK;
    in += GHASH_CHUNK;
    len -= GHASH_CHUNK;
  }
  size_t len_blocks = len & kSizeTWithoutLower4Bits;
  if (len_blocks != 0) {
    size_t j = len_blocks / 16;

    GHASH(ctx, in, len_blocks);
    (*stream)(in, out, j, key, ctx->Yi);
    ctr += (unsigned int)j;
    CRYPTO_store_u32_be(ctx->Yi + 12, ctr);
    out += len_blocks;
    in += len_blocks;
    len -= len_blocks;
  }
  if (len) {
    (*ctx->gcm_key.block)(ctx->Yi, ctx->EKi, key);
    ++ctr;
    CRYPTO_store_u32_be(ctx->Yi + 12, ctr);
    if ((n + len) > 16) {
      abort();
    }
    while (len--) {
      uint8_t c = in[n];
      ctx->Xi[n] ^= c;
      out[n] = c ^ ctx->EKi[n];
      ++n;
    }
  }

  ctx->mres = n;
  return 1;
}

void CRYPTO_gcm128_tag(GCM128_CONTEXT *ctx, uint8_t *tag, size_t len) {
  if (ctx->mres || ctx->ares) {
    GCM_MUL(ctx, Xi);
  }

  uint8_t len_block[16];
  CRYPTO_store_u64_be(len_block, ctx->len.aad << 3);
  CRYPTO_store_u64_be(len_block + 8, ctx->len.msg << 3);
  CRYPTO_xor16(ctx->Xi, ctx->Xi, len_block);
  GCM_MUL(ctx, Xi);
  CRYPTO_xor16(ctx->Xi, ctx->Xi, ctx->EK0);

  OPENSSL_memcpy(tag, ctx->Xi, len <= sizeof(ctx->Xi) ? len : sizeof(ctx->Xi));
}
