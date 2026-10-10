# The AES-GCM and ChaCha20-Poly1305 code taken from AWS-LC, built as a
# convenience library. See README.md.
#
# Being third-party code, it is not held to this project's -Werror.

# Everything here is on the per-byte path, so it gets its own optimisation
# level, taken from build-aux/optflags.sh.
#
# It has to come after @CFLAGS@: automake compiles with $(AM_CFLAGS) $(CFLAGS)
# and gcc honours the last -O, so AM_CFLAGS would be overridden.
CFLAGS = @CFLAGS@ @SS_OPT_CRYPTO@

AM_CPPFLAGS = -I$(srcdir)/aws-lc/include -I$(srcdir)/aws-lc -DNDEBUG
AM_CFLAGS = -std=gnu11 -fvisibility=hidden

noinst_LTLIBRARIES = libssawslc.la

libssawslc_la_SOURCES = aws-lc-glue.c \
                        aws-lc/crypto/cpucap.c \
                        aws-lc/crypto/aes_nohw.c \
                        aws-lc/crypto/gcm.c \
                        aws-lc/crypto/gcm_nohw.c \
                        aws-lc/crypto/aead.c \
                        aws-lc/crypto/e_aes.c \
                        aws-lc/crypto/chacha.c \
                        aws-lc/crypto/poly1305.c \
                        aws-lc/crypto/poly1305_vec.c \
                        aws-lc/crypto/poly1305_arm.c \
                        aws-lc/crypto/e_chacha20poly1305.c \
                        aws-lc/crypto/sha1.c

# Assembly. Every file is built on every target: each one checks the target
# itself and is empty elsewhere (see aws-lc/include/openssl/target.h). At run
# time it checks the CPU and falls back to the next best path, down to
# portable C.
libssawslc_la_SOURCES += aws-lc/asm/x86_64/aesni-x86_64.S \
                         aws-lc/asm/x86_64/aesni-gcm-x86_64.S \
                         aws-lc/asm/x86_64/vpaes-x86_64.S \
                         aws-lc/asm/x86_64/ghash-x86_64.S \
                         aws-lc/asm/x86_64/ghash-ssse3-x86_64.S \
                         aws-lc/asm/x86_64/chacha-x86_64.S \
                         aws-lc/asm/x86_64/chacha20_poly1305_x86_64.S \
                         aws-lc/asm/x86_64/sha1-x86_64.S \
                         aws-lc/asm/aarch64/aesv8-armx.S \
                         aws-lc/asm/aarch64/aesv8-gcm-armv8.S \
                         aws-lc/asm/aarch64/aesv8-gcm-armv8-unroll8.S \
                         aws-lc/asm/aarch64/vpaes-armv8.S \
                         aws-lc/asm/aarch64/ghashv8-armx.S \
                         aws-lc/asm/aarch64/ghash-neon-armv8.S \
                         aws-lc/asm/aarch64/chacha-armv8.S \
                         aws-lc/asm/aarch64/chacha20_poly1305_armv8.S \
                         aws-lc/asm/aarch64/sha1-armv8.S \
                         aws-lc/asm/arm/aesv8-armx.S \
                         aws-lc/asm/arm/bsaes-armv7.S \
                         aws-lc/asm/arm/vpaes-armv7.S \
                         aws-lc/asm/arm/ghash-armv4.S \
                         aws-lc/asm/arm/ghashv8-armx.S \
                         aws-lc/asm/arm/chacha-armv4.S \
                         aws-lc/asm/arm/poly1305_arm_asm.S \
                         aws-lc/asm/arm/sha1-armv4-large.S

noinst_HEADERS = aws-lc-ss.h
EXTRA_DIST = README.md kat.c aws-lc
