# vendor/ — the AEAD and ChaCha20 subset of AWS-LC 5.11.0

All ciphers come from here: AES-128/192/256-GCM, ChaCha20-Poly1305,
XChaCha20-Poly1305 and the original ChaCha20. MD5 (key derivation) and
HKDF-SHA1 (AEAD subkeys) are implemented in `src/`.

## Why AWS-LC

It carries the same OpenSSL/BoringSSL assembly that picks the fastest code at
run time, and is plain C with versioned releases:

| Target | Chosen at run time |
|---|---|
| x86_64 | AES-NI with PCLMUL GHASH (stitched when AVX is there), else SSSE3 vector-permute AES; ChaCha20 AVX2 / SSSE3 |
| aarch64 | ARMv8 AES + PMULL, else NEON; ChaCha20 / Poly1305 NEON |
| 32-bit ARM | ARMv8 AES + PMULL, else NEON bit-sliced AES; ChaCha20 / Poly1305 NEON; integer assembly and C on ARMv5/v6 |
| others, MIPS included | portable C, constant time |

libsodium has AES-GCM only as AES-256 and only on AES-NI, mbedTLS does not
pipeline AES, and Nettle's ARM detection does not work on musl.

AVX-512 is left out: its GCM code alone adds about 700K, and every CPU with
AVX-512 has AES-NI, which is already faster than the relay.

## Where the files come from

`aws-lc/` holds the files listed in `aws-lc.files`, copied unmodified from the
release tarball by `import-aws-lc.sh`, which checks its sha256:

    aws-lc-5.11.0.tar.gz  8cb24c6e6be1fa7ff05075c4560ca8b537a7ef48f9e6f465af4ea455794d74f4

The other files here are this project's:

- `aws-lc-bcm.c` includes the AES, GCM, AEAD and CPU capability sources the
  way AWS-LC's `crypto/fipsmodule/bcm.c` does, in its order, without the rest
  of the module.
- `aws-lc-glue.c` replaces the error queue (a no-op; callers check return
  values), the random generator (`getrandom()`), and reports the code paths
  selected for the startup log.

AWS-LC is Apache-2.0 / ISC licensed, see `aws-lc/LICENSE`; both are
compatible with GPL-3.

## Building

`Makefile.am` passes the definitions AWS-LC's own CMake build passes, taken
from its compile commands, and builds at `SS_OPT_CRYPTO` (`-O3`). configure
picks the assembly for x86_64, aarch64 and little-endian 32-bit ARM on Linux;
everything else gets `-DOPENSSL_NO_ASM`. The ARM assembly needs no ARMv7
baseline: like OpenSSL's, it assembles its NEON and ARMv8 code for those CPUs
and calls it only when the CPU reports them, so one build serves ARMv5 to
ARMv8.

Some vendored functions refer to parts of AWS-LC that are not vendored, such
as `EVP_CIPHER_name()` to the OID table. shadowsocks never calls them, so the
link relies on `--gc-sections` to drop them; a function that is reachable and
missing fails the link.

## At run time

`crypto_init()` must call `CRYPTO_library_init()` first: it detects the CPU
features. Without it the assembly sees no features and runs, correctly but
slowly, as portable C. `crypto_init()` therefore exits if detection has not
run, and logs what was selected:

    crypto: aes hw, ghash pmull, chacha20 neon, chacha20-poly1305 asm

For testing, AWS-LC's `OPENSSL_ia32cap` and `OPENSSL_armcap` environment
variables mask CPU features to force the slower paths.
