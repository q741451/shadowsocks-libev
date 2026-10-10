/*
 * hkdf.c - HMAC-SHA1 (RFC 2104) and HKDF-SHA1 (RFC 5869)
 *
 * SHA-1 itself comes from vendor/, which uses the CPU's SHA instructions or
 * vector code where it can: every UDP packet derives a subkey.
 */

#include "hkdf.h"
#include <string.h>

#include <openssl/sha.h>

typedef struct {
    SHA_CTX inner;
    SHA_CTX outer;
} hmac_sha1_ctx;

static void
hmac_sha1_init(hmac_sha1_ctx *ctx, const uint8_t *key, size_t key_len)
{
    uint8_t k[SHA_CBLOCK] = { 0 };
    uint8_t pad[SHA_CBLOCK];
    int i;

    if (key_len > SHA_CBLOCK) {
        SHA1_Init(&ctx->inner);
        SHA1_Update(&ctx->inner, key, key_len);
        SHA1_Final(k, &ctx->inner);
    } else {
        memcpy(k, key, key_len);
    }

    for (i = 0; i < SHA_CBLOCK; i++)
        pad[i] = k[i] ^ 0x36;
    SHA1_Init(&ctx->inner);
    SHA1_Update(&ctx->inner, pad, SHA_CBLOCK);

    for (i = 0; i < SHA_CBLOCK; i++)
        pad[i] = k[i] ^ 0x5c;
    SHA1_Init(&ctx->outer);
    SHA1_Update(&ctx->outer, pad, SHA_CBLOCK);

    memset(k, 0, sizeof(k));
    memset(pad, 0, sizeof(pad));
}

static void
hmac_sha1_final(hmac_sha1_ctx *ctx, uint8_t mac[SHA_DIGEST_LENGTH])
{
    uint8_t inner[SHA_DIGEST_LENGTH];

    SHA1_Final(inner, &ctx->inner);
    SHA1_Update(&ctx->outer, inner, SHA_DIGEST_LENGTH);
    SHA1_Final(mac, &ctx->outer);
    memset(inner, 0, sizeof(inner));
}

int
ss_hkdf_sha1(const uint8_t *salt, size_t salt_len,
             const uint8_t *ikm, size_t ikm_len,
             const uint8_t *info, size_t info_len,
             uint8_t *okm, size_t okm_len)
{
    static const uint8_t zero_salt[SHA_DIGEST_LENGTH];
    uint8_t prk[SHA_DIGEST_LENGTH];
    uint8_t t[SHA_DIGEST_LENGTH];
    hmac_sha1_ctx ctx, prk_ctx;
    size_t done = 0, n;
    uint8_t i;

    if (okm_len > 255 * SHA_DIGEST_LENGTH)
        return -1;

    /* Extract: an absent salt is a string of HashLen zeros */
    if (salt == NULL) {
        salt     = zero_salt;
        salt_len = sizeof(zero_salt);
    }
    hmac_sha1_init(&ctx, salt, salt_len);
    SHA1_Update(&ctx.inner, ikm, ikm_len);
    hmac_sha1_final(&ctx, prk);

    /* Expand: T(i) = HMAC(PRK, T(i-1) | info | i). UDP derives a subkey per
     * packet, so the keyed state is set up once and copied for each block.
     */
    hmac_sha1_init(&prk_ctx, prk, sizeof(prk));
    for (i = 1; done < okm_len; i++) {
        ctx = prk_ctx;
        if (i > 1)
            SHA1_Update(&ctx.inner, t, sizeof(t));
        SHA1_Update(&ctx.inner, info, info_len);
        SHA1_Update(&ctx.inner, &i, 1);
        hmac_sha1_final(&ctx, t);

        n = okm_len - done < sizeof(t) ? okm_len - done : sizeof(t);
        memcpy(okm + done, t, n);
        done += n;
    }

    memset(prk, 0, sizeof(prk));
    memset(t, 0, sizeof(t));
    memset(&ctx, 0, sizeof(ctx));
    memset(&prk_ctx, 0, sizeof(prk_ctx));
    return 0;
}
