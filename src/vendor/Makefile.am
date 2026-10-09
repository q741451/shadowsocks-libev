# The AES-GCM and ChaCha20-Poly1305 subset of AWS-LC, built as a convenience
# library. See README.md.
#
# Being third-party code, it is not held to this project's -Werror.

# Everything here is on the per-byte path, so it gets its own optimisation
# level, taken from build-aux/optflags.sh.
#
# It has to come after @CFLAGS@: automake compiles with $(AM_CFLAGS) $(CFLAGS)
# and gcc honours the last -O, so AM_CFLAGS would be overridden.
CFLAGS = @CFLAGS@ @SS_OPT_CRYPTO@

# The definitions AWS-LC's own CMake build passes to every file, taken from
# its compile commands. AWS_LC_* and HAVE_* are results of compiler probes
# that every gcc this project supports passes. AVX-512 is left out (see
# README.md); MY_ASSEMBLER_IS_TOO_OLD_FOR_512AVX is AWS-LC's switch for that.
AM_CPPFLAGS = -I$(srcdir)/aws-lc/include -I$(srcdir)/aws-lc \
              -DAWS_LC_BUILTIN_SWAP_SUPPORTED -DAWS_LC_STDALIGN_AVAILABLE \
              -DBORINGSSL_IMPLEMENTATION -DBORINGSSL_RELEASE_BUILD \
              -DHAVE_LINUX_RANDOM_H -DNDEBUG -D_XOPEN_SOURCE=700 \
              -DMY_ASSEMBLER_IS_TOO_OLD_FOR_512AVX \
              $(AWSLC_CPPFLAGS)
AM_CFLAGS = -std=gnu11 -fvisibility=hidden -fno-common

# Only part of AWS-LC is vendored, and some functions in these files refer to
# parts that are not, e.g. EVP_CIPHER_name() to the OID table. shadowsocks
# never calls them; one section per function lets the --gc-sections in
# ../Makefile.am drop them along with their references. A function that is
# reachable and still missing fails the link.
AM_CFLAGS += -ffunction-sections -fdata-sections

noinst_LTLIBRARIES = libssawslc.la

# aws-lc-bcm.c includes the AES, GCM and CPU capability sources itself, the
# way AWS-LC's bcm.c does; the files below are compiled one by one, as AWS-LC
# compiles them.
libssawslc_la_SOURCES = aws-lc-bcm.c \
                        aws-lc-glue.c \
                        aws-lc/crypto/crypto.c \
                        aws-lc/crypto/mem.c \
                        aws-lc/crypto/thread_pthread.c \
                        aws-lc/crypto/fipsmodule/cpucap/cpucap.c \
                        aws-lc/crypto/bytestring/cbs.c \
                        aws-lc/crypto/chacha/chacha.c \
                        aws-lc/crypto/cipher_extra/e_chacha20poly1305.c \
                        aws-lc/crypto/poly1305/poly1305.c \
                        aws-lc/crypto/poly1305/poly1305_arm.c \
                        aws-lc/crypto/poly1305/poly1305_vec.c

# Assembly, chosen by configure. Each file checks the CPU at run time and
# falls back to the next best path, down to portable C.
if AWSLC_X86_64
libssawslc_la_SOURCES += aws-lc/generated-src/linux-x86_64/crypto/fipsmodule/aesni-x86_64.S \
                         aws-lc/generated-src/linux-x86_64/crypto/fipsmodule/aesni-gcm-x86_64.S \
                         aws-lc/generated-src/linux-x86_64/crypto/fipsmodule/vpaes-x86_64.S \
                         aws-lc/generated-src/linux-x86_64/crypto/fipsmodule/ghash-x86_64.S \
                         aws-lc/generated-src/linux-x86_64/crypto/fipsmodule/ghash-ssse3-x86_64.S \
                         aws-lc/generated-src/linux-x86_64/crypto/chacha/chacha-x86_64.S \
                         aws-lc/generated-src/linux-x86_64/crypto/cipher_extra/chacha20_poly1305_x86_64.S
endif
if AWSLC_AARCH64
libssawslc_la_SOURCES += aws-lc/generated-src/linux-aarch64/crypto/fipsmodule/aesv8-armx.S \
                         aws-lc/generated-src/linux-aarch64/crypto/fipsmodule/aesv8-gcm-armv8.S \
                         aws-lc/generated-src/linux-aarch64/crypto/fipsmodule/aesv8-gcm-armv8-unroll8.S \
                         aws-lc/generated-src/linux-aarch64/crypto/fipsmodule/vpaes-armv8.S \
                         aws-lc/generated-src/linux-aarch64/crypto/fipsmodule/ghashv8-armx.S \
                         aws-lc/generated-src/linux-aarch64/crypto/fipsmodule/ghash-neon-armv8.S \
                         aws-lc/generated-src/linux-aarch64/crypto/chacha/chacha-armv8.S \
                         aws-lc/generated-src/linux-aarch64/crypto/cipher_extra/chacha20_poly1305_armv8.S
endif
if AWSLC_ARM
libssawslc_la_SOURCES += aws-lc/generated-src/linux-arm/crypto/fipsmodule/aesv8-armx.S \
                         aws-lc/generated-src/linux-arm/crypto/fipsmodule/bsaes-armv7.S \
                         aws-lc/generated-src/linux-arm/crypto/fipsmodule/vpaes-armv7.S \
                         aws-lc/generated-src/linux-arm/crypto/fipsmodule/ghash-armv4.S \
                         aws-lc/generated-src/linux-arm/crypto/fipsmodule/ghashv8-armx.S \
                         aws-lc/generated-src/linux-arm/crypto/chacha/chacha-armv4.S \
                         aws-lc/crypto/poly1305/poly1305_arm_asm.S
endif

noinst_HEADERS = aws-lc-ss.h
EXTRA_DIST = README.md import-aws-lc.sh aws-lc.files aws-lc
