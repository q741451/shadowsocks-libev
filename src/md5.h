/*
 * md5.h - MD5 摘要（本地实现，替代 mbedTLS）
 *
 * shadowsocks 的密钥派生沿用 OpenSSL 的 EVP_BytesToKey，其中固定使用 MD5，
 * 换成别的摘要就与既有配置不兼容，因此这里必须保留 MD5。
 * 它只用于密钥派生，不用于任何完整性校验。
 */

#ifndef _SS_MD5_H
#define _SS_MD5_H

#include <stddef.h>
#include <stdint.h>

#define MD5_DIGEST_LENGTH 16

typedef struct {
    uint32_t state[4];
    uint64_t count;          /* 已处理的字节数 */
    uint8_t  buffer[64];
} ss_md5_ctx;

void ss_md5_init(ss_md5_ctx *ctx);
void ss_md5_update(ss_md5_ctx *ctx, const uint8_t *data, size_t len);
void ss_md5_final(ss_md5_ctx *ctx, uint8_t digest[MD5_DIGEST_LENGTH]);
void ss_md5(const uint8_t *data, size_t len, uint8_t digest[MD5_DIGEST_LENGTH]);

#endif
