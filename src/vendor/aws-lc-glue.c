/*
 * aws-lc-glue.c - what the vendored AWS-LC subset needs from the rest of
 * libcrypto, and a report of the implementations it selected
 *
 * The extracted sources call into two services shadowsocks does not need in
 * full: the error queue (callers check return values instead) and the random
 * generator.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/random.h>

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "crypto/internal.h"
#include "crypto/chacha/internal.h"
#include "crypto/cipher_extra/internal.h"
#include "crypto/fipsmodule/aes/internal.h"
#include "crypto/fipsmodule/cpucap/internal.h"
#include "crypto/fipsmodule/modes/internal.h"

#include "aws-lc-ss.h"

/* Set by the CPU detection; cpucap/internal.h declares it for ARM only */
extern uint8_t OPENSSL_cpucap_initialized;

void
ERR_put_error(int library, int unused, int reason, const char *file,
              unsigned line)
{
    (void)library;
    (void)unused;
    (void)reason;
    (void)file;
    (void)line;
}

int
RAND_bytes(uint8_t *buf, size_t len)
{
    while (len > 0) {
        ssize_t r = getrandom(buf, len, 0);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return 0;
        }
        buf += r;
        len -= (size_t)r;
    }
    return 1;
}

/* Each name is decided by the same predicates, in the same order, as the
 * dispatch code in aes/internal.h, cipher/e_aes.c, modes/gcm.c,
 * chacha/chacha.c and cipher_extra/e_chacha20poly1305.c, so this reports the
 * code that actually runs rather than what the build might allow.
 */

static const char *
aes_impl(void)
{
#if defined(HWAES)
    if (hwaes_capable())
        return "hw";
#endif
#if defined(BSAES)
    if (bsaes_capable())
        return "bsaes";
#elif defined(VPAES)
    if (vpaes_capable())
        return "vpaes";
#endif
    return "c";
}

static const char *
ghash_impl(void)
{
#if defined(GHASH_ASM_X86_64)
    if (crypto_gcm_clmul_enabled())
        return CRYPTO_is_AVX_capable() && CRYPTO_is_MOVBE_capable()
               ? "avx" : "clmul";
    if (CRYPTO_is_SSSE3_capable())
        return "ssse3";
#elif defined(GHASH_ASM_ARM)
    if (gcm_pmull_capable())
        return "pmull";
    if (gcm_neon_capable())
        return "neon";
#endif
    return "c";
}

/* For the long inputs the relay encrypts; short ones may take a smaller path */
static const char *
chacha20_impl(void)
{
#if defined(CHACHA20_ASM_NOHW)
    const size_t len = 16384;
#if defined(CHACHA20_ASM_NEON)
    if (ChaCha20_ctr32_neon_capable(len))
        return "neon";
#endif
#if defined(CHACHA20_ASM_AVX2) && !defined(MY_ASSEMBLER_IS_TOO_OLD_FOR_AVX)
    if (ChaCha20_ctr32_avx2_capable(len))
        return "avx2";
#endif
#if defined(CHACHA20_ASM_SSSE3_4X)
    if (ChaCha20_ctr32_ssse3_4x_capable(len))
        return "ssse3";
#endif
#if defined(CHACHA20_ASM_SSSE3)
    if (ChaCha20_ctr32_ssse3_capable(len))
        return "ssse3";
#endif
    return "asm";
#else
    return "c";
#endif
}

static const char *
chacha20_poly1305_impl(void)
{
    if (chacha20_poly1305_asm_capable())
        return "asm";
    return "generic";
}

const char *
ss_crypto_impl(void)
{
    static char buf[96];

#if defined(OPENSSL_X86_64) || defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64)
#if !defined(OPENSSL_NO_ASM)
    /* The assembly reads the capabilities without checking that they were
     * ever detected; with no detection everything silently runs as C.
     */
    if (!OPENSSL_cpucap_initialized)
        return NULL;
#endif
#endif

    snprintf(buf, sizeof(buf),
             "aes %s, ghash %s, chacha20 %s, chacha20-poly1305 %s",
             aes_impl(), ghash_impl(), chacha20_impl(),
             chacha20_poly1305_impl());
    return buf;
}
