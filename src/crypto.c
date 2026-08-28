/*
 * crypto.c - Manage the global crypto
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

#if defined(__linux__) && defined(HAVE_LINUX_RANDOM_H)
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/random.h>
#endif

#include <stdint.h>

#include "base64.h"
#include "crypto.h"
#include "md5.h"
#include "stream.h"
#include "utils.h"
#include "ppbloom.h"
#include "vendor/sodium_shim.h"

int
balloc(buffer_t *ptr, size_t capacity)
{
    sodium_memzero(ptr, sizeof(buffer_t));
    ptr->data     = ss_malloc(capacity);
    ptr->capacity = capacity;
    return capacity;
}

int
brealloc(buffer_t *ptr, size_t len, size_t capacity)
{
    if (ptr == NULL)
        return -1;
    size_t real_capacity = max(len, capacity);
    if (ptr->capacity < real_capacity) {
        ptr->data     = ss_realloc(ptr->data, real_capacity);
        ptr->capacity = real_capacity;
    }
    return real_capacity;
}

void
bfree(buffer_t *ptr)
{
    if (ptr == NULL)
        return;
    ptr->idx      = 0;
    ptr->len      = 0;
    ptr->capacity = 0;
    if (ptr->data != NULL) {
        ss_free(ptr->data);
    }
}

int
bprepend(buffer_t *dst, buffer_t *src, size_t capacity)
{
    brealloc(dst, dst->len + src->len, capacity);
    memmove(dst->data + src->len, dst->data, dst->len);
    memcpy(dst->data, src->data, src->len);
    dst->len = dst->len + src->len;
    return dst->len;
}

int
rand_bytes(void *output, int len)
{
    randombytes_buf(output, (size_t)len);
    // always return success
    return 0;
}

unsigned char *
crypto_md5(const unsigned char *d, size_t n, unsigned char *md)
{
    static unsigned char m[MD5_DIGEST_LENGTH];
    if (md == NULL) {
        md = m;
    }
    ss_md5(d, n, md);
    return md;
}

static void
entropy_check(void)
{
#if defined(__linux__) && defined(HAVE_LINUX_RANDOM_H) && defined(RNDGETENTCNT)
    int fd;
    int c;

    if ((fd = open("/dev/random", O_RDONLY)) != -1) {
        if (ioctl(fd, RNDGETENTCNT, &c) == 0 && c < 160) {
            LOGI("This system doesn't provide enough entropy to quickly generate high-quality random numbers.\n"
                 "Installing the rng-utils/rng-tools, jitterentropy or haveged packages may help.\n"
                 "On virtualized Linux environments, also consider using virtio-rng.\n"
                 "The service will not start until enough entropy has been collected.\n");
        }
        close(fd);
    }
#endif
}

crypto_t *
crypto_init(const char *password, const char *key, const char *method)
{
    int i, m = -1;

    entropy_check();

    /*
     * 选定 ChaCha20 的实现（AVX2 / SSSE3 / 纯 C）。这里把结果打进日志：
     * vendor/ 依赖构建系统定义 HAVE_* 宏，漏定义不会报错，只会静默退回纯 C，
     * 唯有日志能暴露这种退化。
     */
    ss_chacha20_init();
    LOGI("chacha20 implementation: %s", ss_chacha20_impl_name());

    // Initialize NONCE bloom filter
#ifdef MODULE_REMOTE
    ppbloom_init(BF_NUM_ENTRIES_FOR_SERVER, BF_ERROR_RATE_FOR_SERVER);
#else
    ppbloom_init(BF_NUM_ENTRIES_FOR_CLIENT, BF_ERROR_RATE_FOR_CLIENT);
#endif

    if (method != NULL) {
        for (i = 0; i < STREAM_CIPHER_NUM; i++)
            if (strcmp(method, supported_stream_ciphers[i]) == 0) {
                m = i;
                break;
            }
        if (m != -1) {
            LOGI("Stream ciphers are insecure, therefore deprecated, and should be almost always avoided.");
            cipher_t *cipher = stream_init(password, key, method);
            if (cipher == NULL)
                return NULL;
            crypto_t *crypto = (crypto_t *)ss_malloc(sizeof(crypto_t));
            crypto_t tmp     = {
                .cipher      = cipher,
                .encrypt_all = &stream_encrypt_all,
                .decrypt_all = &stream_decrypt_all,
                .encrypt     = &stream_encrypt,
                .decrypt     = &stream_decrypt,
                .ctx_init    = &stream_ctx_init,
                .ctx_release = &stream_ctx_release,
            };
            memcpy(crypto, &tmp, sizeof(crypto_t));
            return crypto;
        }

    }

    LOGE("invalid cipher name: %s", method);
    return NULL;
}

int
crypto_derive_key(const char *pass, uint8_t *key, size_t key_len)
{
    /*
     * 沿用 OpenSSL 的 EVP_BytesToKey（MD5、无 salt、迭代 1 次），
     * 这是 shadowsocks 流加密的既定派生方式，换算法会与现有配置不兼容。
     */
    size_t  datal;
    uint8_t md_buf[MD5_DIGEST_LENGTH];
    ss_md5_ctx c;
    int      addmd;
    unsigned int i, j;

    if (pass == NULL)
        return key_len;

    datal = strlen((const char *)pass);

    for (j = 0, addmd = 0; j < key_len; addmd++) {
        ss_md5_init(&c);
        if (addmd)
            ss_md5_update(&c, md_buf, MD5_DIGEST_LENGTH);
        ss_md5_update(&c, (const uint8_t *)pass, datal);
        ss_md5_final(&c, md_buf);

        for (i = 0; i < MD5_DIGEST_LENGTH; i++, j++) {
            if (j >= key_len)
                break;
            key[j] = md_buf[i];
        }
    }

    return key_len;
}

int
crypto_parse_key(const char *base64, uint8_t *key, size_t key_len)
{
    size_t base64_len = strlen(base64);
    int out_len       = BASE64_SIZE(base64_len);
    uint8_t out[out_len];

    out_len = base64_decode(out, base64, out_len);
    if (out_len > 0 && out_len >= key_len) {
        memcpy(key, out, key_len);
#ifdef SS_DEBUG
        dump("KEY", (char *)key, key_len);
#endif
        return key_len;
    }

    out_len = BASE64_SIZE(key_len);
    char out_key[out_len];
    rand_bytes(key, key_len);
    base64_encode(out_key, out_len, key, key_len);
    LOGE("Invalid key for your chosen cipher!");
    LOGE("It requires a " SIZE_FMT "-byte key encoded with URL-safe Base64", key_len);
    LOGE("Generating a new random key: %s", out_key);
    FATAL("Please use the key above or input a valid key");
    return key_len;
}

#ifdef SS_DEBUG
void
dump(char *tag, char *text, int len)
{
    int i;
    printf("%s: ", tag);
    for (i = 0; i < len; i++)
        printf("0x%02x ", (uint8_t)text[i]);
    printf("\n");
}

#endif
