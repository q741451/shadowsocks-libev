# 从 libsodium 抠出的 ChaCha20，单独建一个 convenience library。
#
# 之所以放在独立子目录而不是并入 src/Makefile.am：vendor 的源码里有
# #include "utils.h"，而 src/ 下也有同名头文件，automake 的 DEFAULT_INCLUDES
# 会让 src/utils.h 抢先匹配，导致 SODIUM_C99 等宏取不到。放到子目录后
# $(srcdir) 即本目录，不会撞名。
#
# 另外这些是外来代码，不套用本项目的 -Werror。

# ChaCha20 是全项目唯一逐字节执行的代码，单独提高优化等级。
# 等级取自 build-aux/optflags.sh，不在这里写死。
#
# 必须追加在 @CFLAGS@ 之后：automake 的编译行是 $(AM_CFLAGS) $(CFLAGS)，
# gcc 取最后一个 -O，写进 AM_CFLAGS 会被全局等级盖掉。
CFLAGS = @CFLAGS@ @SS_OPT_CRYPTO@

AM_CFLAGS = -g -Wall -fno-strict-aliasing -std=gnu99 -D_GNU_SOURCE
AM_CFLAGS += -Wno-error -Wno-unused-function
# libsodium 的 private/common.h 在未定义 CONFIGURED 时会发三条 #warning，
# 提示"正在以未记录的方式编译"。这里的用法正是如此且已充分验证，故消掉噪音。
AM_CFLAGS += -DCONFIGURED=1
AM_CFLAGS += $(CHACHA20_SIMD_CFLAGS)
AM_CFLAGS += -I$(srcdir) -I$(srcdir)/sodium

noinst_LTLIBRARIES = libsschacha20.la

libsschacha20_la_SOURCES = sodium_shim.c \
                           runtime.c \
                           chacha20/stream_chacha20.c \
                           chacha20/ref/chacha20_ref.c

libsschacha20_la_LIBADD =

# SSSE3 / AVX2 实现各需自己的 -m 开关，automake 只能按库粒度设编译参数，
# 因此再拆两个小库。非 x86 平台不参与构建，运行时自动用纯 C 实现。
if ARCH_X86
noinst_LTLIBRARIES += libchacha20_ssse3.la libchacha20_avx2.la
libchacha20_ssse3_la_SOURCES = chacha20/dolbeau/chacha20_dolbeau-ssse3.c
libchacha20_ssse3_la_CFLAGS  = $(AM_CFLAGS) -mssse3
libchacha20_avx2_la_SOURCES  = chacha20/dolbeau/chacha20_dolbeau-avx2.c
libchacha20_avx2_la_CFLAGS   = $(AM_CFLAGS) -mavx2 -mssse3
libsschacha20_la_LIBADD += libchacha20_ssse3.la libchacha20_avx2.la
endif
