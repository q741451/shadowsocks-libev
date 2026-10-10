/*
 * aws-lc-glue.c - which implementations the AWS-LC code selected
 */

#include <stdio.h>

#include "crypto/aes.h"
#include "crypto/chacha_internal.h"
#include "crypto/gcm.h"
#include "crypto/sha1_internal.h"

#include "aws-lc-ss.h"

/* Each name is decided by the same predicates, in the same order, as the
 * dispatch code in e_aes.c, gcm.c, chacha.c, e_chacha20poly1305.c and
 * sha1.c, so this reports the code that actually runs rather than what the
 * build might allow.
 */

static const char *
aes_impl(void)
{
#if defined(HWAES)
    if (hwaes_capable())
        return "hw";
#endif
#if defined(BSAES)
    if (vpaes_capable())
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
#if defined(CHACHA20_ASM_AVX2)
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

static const char *
sha1_impl(void)
{
#if defined(SHA1_ASM_HW)
    if (sha1_hw_capable())
        return "hw";
#endif
#if defined(SHA1_ASM_AVX2)
    if (sha1_avx2_capable())
        return "avx2";
#endif
#if defined(SHA1_ASM_AVX)
    if (sha1_avx_capable())
        return "avx";
#endif
#if defined(SHA1_ASM_SSSE3)
    if (sha1_ssse3_capable())
        return "ssse3";
#endif
#if defined(SHA1_ASM_NEON)
    if (CRYPTO_is_NEON_capable())
        return "neon";
#endif
#if defined(SHA1_ASM_NOHW)
    return "asm";
#else
    return "c";
#endif
}

const char *
ss_crypto_impl(void)
{
    static char buf[128];

#if !defined(OPENSSL_NO_ASM)
    /* The assembly reads the capabilities without checking that they were
     * ever detected; with no detection everything silently runs as C.
     */
    if (!OPENSSL_cpucap_initialized)
        return NULL;
#endif

    snprintf(buf, sizeof(buf),
             "aes %s, ghash %s, chacha20 %s, chacha20-poly1305 %s, sha1 %s",
             aes_impl(), ghash_impl(), chacha20_impl(),
             chacha20_poly1305_impl(), sha1_impl());
    return buf;
}
