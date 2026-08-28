# ChaCha20 vendored from libsodium, built as a convenience library.
#
# It lives in its own subdirectory rather than in src/Makefile.am because the
# vendored sources include "utils.h" and src/ has a file by that name; with
# automake's DEFAULT_INCLUDES the wrong one would win and macros such as
# SODIUM_C99 would go undefined. Here $(srcdir) is this directory.
#
# Being third-party code, it is not held to this project's -Werror.

# ChaCha20 is the only code on the per-byte path, so it gets its own
# optimisation level, taken from build-aux/optflags.sh.
#
# It has to come after @CFLAGS@: automake compiles with $(AM_CFLAGS) $(CFLAGS)
# and gcc honours the last -O, so AM_CFLAGS would be overridden.
CFLAGS = @CFLAGS@ @SS_OPT_CRYPTO@

AM_CFLAGS = -g -Wall -fno-strict-aliasing -std=gnu99 -D_GNU_SOURCE
AM_CFLAGS += -Wno-error -Wno-unused-function
# Without CONFIGURED, libsodium's private/common.h warns about being built in
# an undocumented way, which is exactly what this is.
AM_CFLAGS += -DCONFIGURED=1
AM_CFLAGS += $(CHACHA20_SIMD_CFLAGS)
AM_CFLAGS += -I$(srcdir) -I$(srcdir)/sodium

noinst_LTLIBRARIES = libsschacha20.la

libsschacha20_la_SOURCES = sodium_shim.c \
                           runtime.c \
                           chacha20/stream_chacha20.c \
                           chacha20/ref/chacha20_ref.c

libsschacha20_la_LIBADD =

# The SSSE3 and AVX2 implementations each need their own -m flag and automake
# only sets flags per library, hence two more of them. Not built off x86, where
# the portable C code is used.
if ARCH_X86
noinst_LTLIBRARIES += libchacha20_ssse3.la libchacha20_avx2.la
libchacha20_ssse3_la_SOURCES = chacha20/dolbeau/chacha20_dolbeau-ssse3.c
libchacha20_ssse3_la_CFLAGS  = $(AM_CFLAGS) -mssse3
libchacha20_avx2_la_SOURCES  = chacha20/dolbeau/chacha20_dolbeau-avx2.c
libchacha20_avx2_la_CFLAGS   = $(AM_CFLAGS) -mavx2 -mssse3
libsschacha20_la_LIBADD += libchacha20_ssse3.la libchacha20_avx2.la
endif
