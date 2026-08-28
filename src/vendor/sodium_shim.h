#ifndef _SS_SODIUM_SHIM_H
#define _SS_SODIUM_SHIM_H

#include <stddef.h>

void sodium_memzero(void *const pnt, const size_t len);
void randombytes_buf(void *const buf, const size_t size);

/* Select the ChaCha20 implementation; call once before any encryption */
void ss_chacha20_init(void);
/* Name of the implementation actually selected, for the startup log */
const char *ss_chacha20_impl_name(void);

#endif
