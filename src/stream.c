/*
 * stream.c - Manage stream ciphers
 *
 * Copyright (C) 2013 - 2019, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ppbloom.h"
#include "stream.h"
#include "utils.h"
#include <openssl/chacha.h>

/* ChaCha20 block size; the counter must stay aligned across calls */
#define CHACHA20_BLOCK_SIZE 64

/*
 * Spec: http://shadowsocks.org/en/spec/Stream-Ciphers.html
 *
 * Stream ciphers provide only confidentiality. Data integrity and authenticity
 * is not guaranteed. This branch keeps chacha20 alone of them, for setups
 * where an outer layer already provides authentication; without one, use an
 * AEAD cipher instead.
 *
 * The other stream methods (table, rc4, aes-*, bf, camellia, cast5, des, idea,
 * rc2, seed, salsa20, chacha20-ietf) are deprecated upstream and not built.
 */

#define CHACHA20 0

const char *supported_stream_ciphers[STREAM_CIPHER_NUM] = {
    "chacha20"
};

static const int supported_stream_ciphers_nonce_size[STREAM_CIPHER_NUM] = { 8 };
static const int supported_stream_ciphers_key_size[STREAM_CIPHER_NUM]   = { 32 };

/* The original ChaCha20: a 64-bit block counter followed by a 64-bit nonce.
 * AWS-LC implements the RFC 8439 layout, a 32-bit counter followed by a
 * 96-bit nonce, so the high half of the counter goes in front of the nonce.
 * AWS-LC wraps its 32-bit counter to zero, hence the split every 2^32
 * blocks, where the carry moves into the high half.
 */
static void
chacha20_xor_ic(uint8_t *out, const uint8_t *in, uint64_t len,
                const uint8_t nonce[8], uint64_t ic, const uint8_t key[32])
{
    uint8_t n[12];
    uint32_t hi;
    uint64_t todo;

    memcpy(n + 4, nonce, 8);
    while (len > 0) {
        hi   = (uint32_t)(ic >> 32);
        n[0] = (uint8_t)hi;         n[1] = (uint8_t)(hi >> 8);
        n[2] = (uint8_t)(hi >> 16); n[3] = (uint8_t)(hi >> 24);

        todo = ((UINT64_C(1) << 32) - (uint32_t)ic) * CHACHA20_BLOCK_SIZE;
        if (todo > len)
            todo = len;
        CRYPTO_chacha_20(out, in, (size_t)todo, key, n, (uint32_t)ic);

        out += todo;
        in  += todo;
        len -= todo;
        ic   = (ic | UINT32_MAX) + 1;
    }
}

/* chacha20 derives the keystream from (key, nonce, block counter) alone, so
 * there is no cipher context to set up or tear down here.
 */
void
stream_ctx_release(cipher_ctx_t *cipher_ctx)
{
    if (cipher_ctx->chunk != NULL) {
        bfree(cipher_ctx->chunk);
        ss_free(cipher_ctx->chunk);
        cipher_ctx->chunk = NULL;
    }
}

int
stream_encrypt_all(buffer_t *plaintext, cipher_t *cipher, size_t capacity)
{
    cipher_ctx_t cipher_ctx;
    stream_ctx_init(cipher, &cipher_ctx, 1);

    size_t nonce_len = cipher->nonce_len;

    static buffer_t tmp = { 0, 0, 0, NULL };
    brealloc(&tmp, nonce_len + plaintext->len, capacity);
    buffer_t *ciphertext = &tmp;
    ciphertext->len = plaintext->len;

    uint8_t *nonce = cipher_ctx.nonce;
    memcpy(ciphertext->data, nonce, nonce_len);

#ifdef MODULE_REMOTE
    ppbloom_add((void *)nonce, nonce_len);
#endif

    chacha20_xor_ic((uint8_t *)(ciphertext->data + nonce_len),
                    (const uint8_t *)plaintext->data,
                    (uint64_t)(plaintext->len),
                    (const uint8_t *)nonce, 0, cipher->key);

    stream_ctx_release(&cipher_ctx);

#ifdef SS_DEBUG
    dump("PLAIN", plaintext->data, plaintext->len);
    dump("CIPHER", ciphertext->data + nonce_len, ciphertext->len);
    dump("NONCE", ciphertext->data, nonce_len);
#endif

    brealloc(plaintext, nonce_len + ciphertext->len, capacity);
    memcpy(plaintext->data, ciphertext->data, nonce_len + ciphertext->len);
    plaintext->len = nonce_len + ciphertext->len;

    return CRYPTO_OK;
}

int
stream_encrypt(buffer_t *plaintext, cipher_ctx_t *cipher_ctx, size_t capacity)
{
    if (cipher_ctx == NULL)
        return CRYPTO_ERROR;

    cipher_t *cipher = cipher_ctx->cipher;

    static buffer_t tmp = { 0, 0, 0, NULL };

    size_t nonce_len = 0;
    if (!cipher_ctx->init)
        nonce_len = cipher_ctx->cipher->nonce_len;

    brealloc(&tmp, nonce_len + plaintext->len, capacity);
    buffer_t *ciphertext = &tmp;
    ciphertext->len = plaintext->len;

    if (!cipher_ctx->init) {
        memcpy(ciphertext->data, cipher_ctx->nonce, nonce_len);
        cipher_ctx->counter = 0;
        cipher_ctx->init    = 1;

#ifdef MODULE_REMOTE
        ppbloom_add((void *)cipher_ctx->nonce, nonce_len);
#endif
    }

    /* The keystream must continue where the previous call left off. Pad the
     * head up to a block boundary, encrypt, then drop the padding.
     */
    int padding = cipher_ctx->counter % CHACHA20_BLOCK_SIZE;
    brealloc(ciphertext, nonce_len + (padding + ciphertext->len) * 2, capacity);
    if (padding) {
        brealloc(plaintext, plaintext->len + padding, capacity);
        memmove(plaintext->data + padding, plaintext->data, plaintext->len);
        memset(plaintext->data, 0, padding);
    }
    chacha20_xor_ic((uint8_t *)(ciphertext->data + nonce_len),
                    (const uint8_t *)plaintext->data,
                    (uint64_t)(plaintext->len + padding),
                    (const uint8_t *)cipher_ctx->nonce,
                    cipher_ctx->counter / CHACHA20_BLOCK_SIZE,
                    cipher->key);
    cipher_ctx->counter += plaintext->len;
    if (padding) {
        memmove(ciphertext->data + nonce_len,
                ciphertext->data + nonce_len + padding, ciphertext->len);
    }

#ifdef SS_DEBUG
    dump("PLAIN", plaintext->data, plaintext->len);
    dump("CIPHER", ciphertext->data + nonce_len, ciphertext->len);
#endif

    brealloc(plaintext, nonce_len + ciphertext->len, capacity);
    memcpy(plaintext->data, ciphertext->data, nonce_len + ciphertext->len);
    plaintext->len = nonce_len + ciphertext->len;

    return CRYPTO_OK;
}

int
stream_decrypt_all(buffer_t *ciphertext, cipher_t *cipher, size_t capacity)
{
    size_t nonce_len = cipher->nonce_len;

    if (ciphertext->len <= nonce_len)
        return CRYPTO_ERROR;

    cipher_ctx_t cipher_ctx;
    stream_ctx_init(cipher, &cipher_ctx, 0);

    static buffer_t tmp = { 0, 0, 0, NULL };
    brealloc(&tmp, ciphertext->len, capacity);
    buffer_t *plaintext = &tmp;
    plaintext->len = ciphertext->len - nonce_len;

    uint8_t *nonce = cipher_ctx.nonce;
    memcpy(nonce, ciphertext->data, nonce_len);

    if (ppbloom_check((void *)nonce, nonce_len) == 1) {
        LOGE("crypto: stream: repeat IV detected");
        return CRYPTO_ERROR;
    }

    chacha20_xor_ic((uint8_t *)plaintext->data,
                    (const uint8_t *)(ciphertext->data + nonce_len),
                    (uint64_t)(ciphertext->len - nonce_len),
                    (const uint8_t *)nonce, 0, cipher->key);

    stream_ctx_release(&cipher_ctx);

#ifdef SS_DEBUG
    dump("PLAIN", plaintext->data, plaintext->len);
    dump("CIPHER", ciphertext->data + nonce_len, ciphertext->len - nonce_len);
    dump("NONCE", ciphertext->data, nonce_len);
#endif

    ppbloom_add((void *)nonce, nonce_len);

    brealloc(ciphertext, plaintext->len, capacity);
    memcpy(ciphertext->data, plaintext->data, plaintext->len);
    ciphertext->len = plaintext->len;

    return CRYPTO_OK;
}

int
stream_decrypt(buffer_t *ciphertext, cipher_ctx_t *cipher_ctx, size_t capacity)
{
    if (cipher_ctx == NULL)
        return CRYPTO_ERROR;

    cipher_t *cipher = cipher_ctx->cipher;

    static buffer_t tmp = { 0, 0, 0, NULL };

    brealloc(&tmp, ciphertext->len, capacity);
    buffer_t *plaintext = &tmp;
    plaintext->len = ciphertext->len;

    if (!cipher_ctx->init) {
        if (cipher_ctx->chunk == NULL) {
            cipher_ctx->chunk = (buffer_t *)ss_malloc(sizeof(buffer_t));
            memset(cipher_ctx->chunk, 0, sizeof(buffer_t));
            balloc(cipher_ctx->chunk, cipher->nonce_len);
        }

        size_t left_len = min(cipher->nonce_len - cipher_ctx->chunk->len,
                              ciphertext->len);

        if (left_len > 0) {
            memcpy(cipher_ctx->chunk->data + cipher_ctx->chunk->len, ciphertext->data, left_len);
            memmove(ciphertext->data, ciphertext->data + left_len,
                    ciphertext->len - left_len);
            cipher_ctx->chunk->len += left_len;
            ciphertext->len        -= left_len;
        }

        if (cipher_ctx->chunk->len < cipher->nonce_len)
            return CRYPTO_NEED_MORE;

        uint8_t *nonce   = cipher_ctx->nonce;
        size_t nonce_len = cipher->nonce_len;
        plaintext->len -= left_len;

        memcpy(nonce, cipher_ctx->chunk->data, nonce_len);
        cipher_ctx->counter = 0;
        cipher_ctx->init    = 1;

        if (ppbloom_check((void *)nonce, nonce_len) == 1) {
            LOGE("crypto: stream: repeat IV detected");
            return CRYPTO_ERROR;
        }
    }

    if (ciphertext->len <= 0)
        return CRYPTO_NEED_MORE;

    int padding = cipher_ctx->counter % CHACHA20_BLOCK_SIZE;
    brealloc(plaintext, (plaintext->len + padding) * 2, capacity);

    if (padding) {
        brealloc(ciphertext, ciphertext->len + padding, capacity);
        memmove(ciphertext->data + padding, ciphertext->data, ciphertext->len);
        memset(ciphertext->data, 0, padding);
    }
    chacha20_xor_ic((uint8_t *)plaintext->data,
                    (const uint8_t *)(ciphertext->data),
                    (uint64_t)(ciphertext->len + padding),
                    (const uint8_t *)cipher_ctx->nonce,
                    cipher_ctx->counter / CHACHA20_BLOCK_SIZE,
                    cipher->key);
    cipher_ctx->counter += ciphertext->len;
    if (padding)
        memmove(plaintext->data, plaintext->data + padding, plaintext->len);

#ifdef SS_DEBUG
    dump("PLAIN", plaintext->data, plaintext->len);
    dump("CIPHER", ciphertext->data, ciphertext->len);
#endif

    if (cipher_ctx->init == 1) {
        if (ppbloom_check((void *)cipher_ctx->nonce, cipher->nonce_len) == 1) {
            LOGE("crypto: stream: repeat IV detected");
            return CRYPTO_ERROR;
        }
        ppbloom_add((void *)cipher_ctx->nonce, cipher->nonce_len);
        cipher_ctx->init = 2;
    }

    brealloc(ciphertext, plaintext->len, capacity);
    memcpy(ciphertext->data, plaintext->data, plaintext->len);
    ciphertext->len = plaintext->len;

    return CRYPTO_OK;
}

void
stream_ctx_init(cipher_t *cipher, cipher_ctx_t *cipher_ctx, int enc)
{
    memset(cipher_ctx, 0, sizeof(cipher_ctx_t));
    cipher_ctx->cipher = cipher;

    if (enc)
        rand_bytes(cipher_ctx->nonce, cipher->nonce_len);
}

cipher_t *
stream_key_init(int method, const char *pass, const char *key)
{
    if (method < 0 || method >= STREAM_CIPHER_NUM) {
        LOGE("cipher->key_init(): Illegal method");
        return NULL;
    }

    cipher_t *cipher = (cipher_t *)ss_malloc(sizeof(cipher_t));
    memset(cipher, 0, sizeof(cipher_t));

    size_t key_len = supported_stream_ciphers_key_size[method];
    if (key != NULL)
        cipher->key_len = crypto_parse_key(key, cipher->key, key_len);
    else
        cipher->key_len = crypto_derive_key(pass, cipher->key, key_len);

    if (cipher->key_len == 0)
        FATAL("Cannot generate key and NONCE");

    cipher->nonce_len = supported_stream_ciphers_nonce_size[method];
    cipher->method    = method;

    return cipher;
}

cipher_t *
stream_init(const char *pass, const char *key, const char *method)
{
    int m = -1;

    if (method != NULL) {
        for (m = 0; m < STREAM_CIPHER_NUM; m++)
            if (strcmp(method, supported_stream_ciphers[m]) == 0)
                break;
    }
    if (m < 0 || m >= STREAM_CIPHER_NUM) {
        LOGE("Invalid cipher name: %s, this build only supports chacha20", method);
        return NULL;
    }
    return stream_key_init(m, pass, key);
}
