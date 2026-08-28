/*
 * sodium_shim.c - the few libsodium runtime symbols vendor/ still needs
 *
 * Importing them from libsodium would drag in sodium_init() and with it every
 * other subsystem, which is exactly what vendoring ChaCha20 avoids. Only the
 * symbols actually referenced are provided here.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "chacha20/stream_chacha20.h"
#include "sodium/runtime.h"
#include "sodium/private/implementations.h"
#include "sodium_shim.h"


/* Called by libsodium on API misuse */
void
sodium_misuse(void)
{
    abort();
}

void
sodium_memzero(void *const pnt, const size_t len)
{
    memset(pnt, 0, len);
}

/* /dev/urandom rather than getrandom(2), which needs Linux 3.17 or newer;
 * some target routers run older kernels.
 */
void
randombytes_buf(void *const buf, const size_t size)
{
    static int fd = -1;
    unsigned char *p = (unsigned char *)buf;
    size_t remain    = size;
    ssize_t n;

    if (fd < 0) {
        while ((fd = open("/dev/urandom", O_RDONLY)) < 0) {
            if (errno == EINTR)
                continue;
            abort();
        }
    }

    while (remain > 0) {
        n = read(fd, p, remain);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            abort();
        }
        if (n == 0)
            abort();
        p      += n;
        remain -= (size_t)n;
    }
}

/* Pick the best ChaCha20 implementation. sodium_init() normally chains these
 * two steps together, along with every other subsystem.
 */
static const char *chacha20_impl = "ref";

void
ss_chacha20_init(void)
{
    _sodium_runtime_get_cpu_features();
    _crypto_stream_chacha20_pick_best_implementation();

    /* Mirror the conditions above just to record what was picked; libsodium
     * exposes no query for it. Worth logging: a missing HAVE_* macro silently
     * falls back to the reference code.
     */
#if defined(HAVE_AVX2INTRIN_H) && defined(HAVE_EMMINTRIN_H) && \
    defined(HAVE_TMMINTRIN_H) && defined(HAVE_SMMINTRIN_H)
    if (sodium_runtime_has_avx2()) {
        chacha20_impl = "avx2";
        return;
    }
#endif
#if defined(HAVE_EMMINTRIN_H) && defined(HAVE_TMMINTRIN_H)
    if (sodium_runtime_has_ssse3()) {
        chacha20_impl = "ssse3";
        return;
    }
#endif
}

const char *
ss_chacha20_impl_name(void)
{
    return chacha20_impl;
}
