#ifndef _SS_AWS_LC_H
#define _SS_AWS_LC_H

/* The implementations AWS-LC selected on this CPU, for the startup log, e.g.
 * "aes hw, ghash clmul, chacha20 avx2, chacha20-poly1305 asm, sha1 hw". NULL
 * if CPU capability detection has not run, i.e. CRYPTO_library_init() was
 * not called first.
 */
const char *ss_crypto_impl(void);

#endif
