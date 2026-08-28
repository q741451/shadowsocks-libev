/*
 * md5.c - MD5 digest as defined by RFC 1321, replacing the one from mbedTLS
 */

#include "md5.h"
#include <string.h>

static uint32_t
load32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void
store32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);       p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static const uint32_t K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const int S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static uint32_t
rotl32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

static void
md5_transform(uint32_t state[4], const uint8_t block[64])
{
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t m[16], f, tmp;
    int i, g;

    for (i = 0; i < 16; i++)
        m[i] = load32_le(block + 4 * i);

    for (i = 0; i < 64; i++) {
        if (i < 16) {
            f = (b & c) | (~b & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | ~d);
            g = (7 * i) % 16;
        }
        tmp = d;
        d   = c;
        c   = b;
        b   = b + rotl32(a + f + K[i] + m[g], S[i]);
        a   = tmp;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

void
ss_md5_init(ss_md5_ctx *ctx)
{
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    ctx->count    = 0;
}

void
ss_md5_update(ss_md5_ctx *ctx, const uint8_t *data, size_t len)
{
    size_t used = (size_t)(ctx->count & 0x3f);
    size_t free_space;

    ctx->count += len;

    if (used) {
        free_space = 64 - used;
        if (len < free_space) {
            memcpy(ctx->buffer + used, data, len);
            return;
        }
        memcpy(ctx->buffer + used, data, free_space);
        md5_transform(ctx->state, ctx->buffer);
        data += free_space;
        len  -= free_space;
    }

    while (len >= 64) {
        md5_transform(ctx->state, data);
        data += 64;
        len  -= 64;
    }

    if (len)
        memcpy(ctx->buffer, data, len);
}

void
ss_md5_final(ss_md5_ctx *ctx, uint8_t digest[MD5_DIGEST_LENGTH])
{
    static const uint8_t pad[64] = { 0x80 };
    uint64_t bits = ctx->count << 3;
    uint8_t  bitlen[8];
    size_t   used = (size_t)(ctx->count & 0x3f);
    size_t   padlen = (used < 56) ? (56 - used) : (120 - used);
    int i;

    for (i = 0; i < 8; i++)
        bitlen[i] = (uint8_t)(bits >> (8 * i));

    ss_md5_update(ctx, pad, padlen);
    ss_md5_update(ctx, bitlen, 8);

    for (i = 0; i < 4; i++)
        store32_le(digest + 4 * i, ctx->state[i]);

    memset(ctx, 0, sizeof(*ctx));
}

void
ss_md5(const uint8_t *data, size_t len, uint8_t digest[MD5_DIGEST_LENGTH])
{
    ss_md5_ctx ctx;

    ss_md5_init(&ctx);
    ss_md5_update(&ctx, data, len);
    ss_md5_final(&ctx, digest);
}
