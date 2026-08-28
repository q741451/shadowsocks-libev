#ifndef _SS_SODIUM_SHIM_H
#define _SS_SODIUM_SHIM_H

#include <stddef.h>

void sodium_memzero(void *const pnt, const size_t len);
void randombytes_buf(void *const buf, const size_t size);

/* 选定 ChaCha20 实现；必须在首次加解密前调用一次 */
void ss_chacha20_init(void);
/* 实际选中的实现名，用于启动日志，便于发现静默退回纯 C 的情况 */
const char *ss_chacha20_impl_name(void);

#endif
