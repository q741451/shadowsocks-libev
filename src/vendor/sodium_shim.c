/*
 * sodium_shim.c - 替代 libsodium 的少量运行时支撑
 *
 * vendor/ 下抠出来的 ChaCha20 需要几个 libsodium 的全局设施，但把它们
 * 原样搬过来会连带 sodium_init() 那一整套子系统初始化（正是要避开的东西）。
 * 这里只补上真正被引用到的三个符号。
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


/* libsodium 在参数误用时调用它；这里等同于 abort */
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

/*
 * 取随机字节。用 /dev/urandom 而不是 getrandom(2)：后者要 Linux 3.17+，
 * 而本项目的目标里有相当老的路由器内核。
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

/*
 * 挑选 ChaCha20 的最佳实现。平时这两步由 sodium_init() 串起来，
 * 这里单独调用，避开它对其它子系统的初始化。
 */
static const char *chacha20_impl = "ref";

void
ss_chacha20_init(void)
{
    _sodium_runtime_get_cpu_features();
    _crypto_stream_chacha20_pick_best_implementation();

    /*
     * 这里重复一次 pick_best 的判定条件，只为记下实际选中的实现。
     * libsodium 没有公开查询接口，而这个信息很值得打进启动日志：
     * HAVE_* 宏漏定义时不会报错，只会静默退回 ref，靠日志才发现得了。
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
