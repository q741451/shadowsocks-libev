/*
 * hkdf.c - SHA-1 (FIPS 180-4), HMAC (RFC 2104) and HKDF (RFC 5869)
 */

#include "hkdf.h"
#include <string.h>

#define SHA1_BLOCK_LENGTH 64

typedef struct {
    uint32_t state[5];
    uint64_t count;          /* bytes processed so far */
    uint8_t  buffer[SHA1_BLOCK_LENGTH];
} sha1_ctx;

static uint32_t
load32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void
store32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)(v);
}

static uint32_t
rotl32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

static void
sha1_transform(uint32_t state[5], const uint8_t block[SHA1_BLOCK_LENGTH])
{
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3],
             e = state[4];
    uint32_t w[80], f, k, tmp;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = load32_be(block + 4 * i);
    for (i = 16; i < 80; i++)
        w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    for (i = 0; i < 80; i++) {
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5a827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdc;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6;
        }
        tmp = rotl32(a, 5) + f + e + k + w[i];
        e   = d;
        d   = c;
        c   = rotl32(b, 30);
        b   = a;
        a   = tmp;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

static void
sha1_init(sha1_ctx *ctx)
{
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xc3d2e1f0;
    ctx->count    = 0;
}

static void
sha1_update(sha1_ctx *ctx, const uint8_t *data, size_t len)
{
    size_t used = (size_t)(ctx->count & 0x3f);
    size_t free_space;

    ctx->count += len;

    if (used) {
        free_space = SHA1_BLOCK_LENGTH - used;
        if (len < free_space) {
            memcpy(ctx->buffer + used, data, len);
            return;
        }
        memcpy(ctx->buffer + used, data, free_space);
        sha1_transform(ctx->state, ctx->buffer);
        data += free_space;
        len  -= free_space;
    }

    while (len >= SHA1_BLOCK_LENGTH) {
        sha1_transform(ctx->state, data);
        data += SHA1_BLOCK_LENGTH;
        len  -= SHA1_BLOCK_LENGTH;
    }

    if (len)
        memcpy(ctx->buffer, data, len);
}

static void
sha1_final(sha1_ctx *ctx, uint8_t digest[SHA1_DIGEST_LENGTH])
{
    static const uint8_t pad[SHA1_BLOCK_LENGTH] = { 0x80 };
    uint64_t bits = ctx->count << 3;
    uint8_t  bitlen[8];
    size_t   used = (size_t)(ctx->count & 0x3f);
    size_t   padlen = (used < 56) ? (56 - used) : (120 - used);
    int i;

    for (i = 0; i < 8; i++)
        bitlen[i] = (uint8_t)(bits >> (56 - 8 * i));

    sha1_update(ctx, pad, padlen);
    sha1_update(ctx, bitlen, 8);

    for (i = 0; i < 5; i++)
        store32_be(digest + 4 * i, ctx->state[i]);

    memset(ctx, 0, sizeof(*ctx));
}

typedef struct {
    sha1_ctx inner;
    sha1_ctx outer;
} hmac_sha1_ctx;

static void
hmac_sha1_init(hmac_sha1_ctx *ctx, const uint8_t *key, size_t key_len)
{
    uint8_t k[SHA1_BLOCK_LENGTH] = { 0 };
    uint8_t pad[SHA1_BLOCK_LENGTH];
    int i;

    if (key_len > SHA1_BLOCK_LENGTH) {
        sha1_init(&ctx->inner);
        sha1_update(&ctx->inner, key, key_len);
        sha1_final(&ctx->inner, k);
    } else {
        memcpy(k, key, key_len);
    }

    for (i = 0; i < SHA1_BLOCK_LENGTH; i++)
        pad[i] = k[i] ^ 0x36;
    sha1_init(&ctx->inner);
    sha1_update(&ctx->inner, pad, SHA1_BLOCK_LENGTH);

    for (i = 0; i < SHA1_BLOCK_LENGTH; i++)
        pad[i] = k[i] ^ 0x5c;
    sha1_init(&ctx->outer);
    sha1_update(&ctx->outer, pad, SHA1_BLOCK_LENGTH);

    memset(k, 0, sizeof(k));
    memset(pad, 0, sizeof(pad));
}

static void
hmac_sha1_final(hmac_sha1_ctx *ctx, uint8_t mac[SHA1_DIGEST_LENGTH])
{
    uint8_t inner[SHA1_DIGEST_LENGTH];

    sha1_final(&ctx->inner, inner);
    sha1_update(&ctx->outer, inner, SHA1_DIGEST_LENGTH);
    sha1_final(&ctx->outer, mac);
    memset(inner, 0, sizeof(inner));
}

int
ss_hkdf_sha1(const uint8_t *salt, size_t salt_len,
             const uint8_t *ikm, size_t ikm_len,
             const uint8_t *info, size_t info_len,
             uint8_t *okm, size_t okm_len)
{
    static const uint8_t zero_salt[SHA1_DIGEST_LENGTH];
    uint8_t prk[SHA1_DIGEST_LENGTH];
    uint8_t t[SHA1_DIGEST_LENGTH];
    hmac_sha1_ctx ctx, prk_ctx;
    size_t done = 0, n;
    uint8_t i;

    if (okm_len > 255 * SHA1_DIGEST_LENGTH)
        return -1;

    /* Extract: an absent salt is a string of HashLen zeros */
    if (salt == NULL) {
        salt     = zero_salt;
        salt_len = sizeof(zero_salt);
    }
    hmac_sha1_init(&ctx, salt, salt_len);
    sha1_update(&ctx.inner, ikm, ikm_len);
    hmac_sha1_final(&ctx, prk);

    /* Expand: T(i) = HMAC(PRK, T(i-1) | info | i). UDP derives a subkey per
     * packet, so the keyed state is set up once and copied for each block.
     */
    hmac_sha1_init(&prk_ctx, prk, sizeof(prk));
    for (i = 1; done < okm_len; i++) {
        ctx = prk_ctx;
        if (i > 1)
            sha1_update(&ctx.inner, t, sizeof(t));
        sha1_update(&ctx.inner, info, info_len);
        sha1_update(&ctx.inner, &i, 1);
        hmac_sha1_final(&ctx, t);

        n = okm_len - done < sizeof(t) ? okm_len - done : sizeof(t);
        memcpy(okm + done, t, n);
        done += n;
    }

    memset(prk, 0, sizeof(prk));
    memset(t, 0, sizeof(t));
    memset(&prk_ctx, 0, sizeof(prk_ctx));
    return 0;
}
