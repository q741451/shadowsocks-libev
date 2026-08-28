/*
 * md5.h - MD5 digest, replacing the one from mbedTLS
 *
 * shadowsocks derives keys with OpenSSL's EVP_BytesToKey, which is defined in
 * terms of MD5; another digest would break existing configurations. Used for
 * key derivation only, never for integrity checking.
 */

#ifndef _SS_MD5_H
#define _SS_MD5_H

#include <stddef.h>
#include <stdint.h>

#define MD5_DIGEST_LENGTH 16

typedef struct {
    uint32_t state[4];
    uint64_t count;          /* bytes processed so far */
    uint8_t  buffer[64];
} ss_md5_ctx;

void ss_md5_init(ss_md5_ctx *ctx);
void ss_md5_update(ss_md5_ctx *ctx, const uint8_t *data, size_t len);
void ss_md5_final(ss_md5_ctx *ctx, uint8_t digest[MD5_DIGEST_LENGTH]);
void ss_md5(const uint8_t *data, size_t len, uint8_t digest[MD5_DIGEST_LENGTH]);

#endif
