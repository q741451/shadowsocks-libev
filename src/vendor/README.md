# vendor/ — AES-GCM, ChaCha20-Poly1305 and SHA-1 from AWS-LC 5.11.0

All ciphers come from here: AES-128/192/256-GCM, ChaCha20-Poly1305,
XChaCha20-Poly1305 and the original ChaCha20, and SHA-1 for the HKDF that
derives the AEAD subkeys. MD5 (key derivation from the password) and the
HMAC/HKDF on top of SHA-1 are in `src/`.

## Why AWS-LC

It carries the OpenSSL/BoringSSL assembly that picks the fastest code at run
time:

| Target | Chosen at run time |
|---|---|
| x86_64 | AES-NI with PCLMUL GHASH (stitched when AVX is there), else SSSE3 vector-permute AES; ChaCha20 AVX2 / SSSE3 |
| aarch64 | ARMv8 AES + PMULL, else NEON; ChaCha20 / Poly1305 NEON |
| 32-bit ARM | ARMv8 AES + PMULL, else NEON bit-sliced AES; ChaCha20 / Poly1305 NEON; integer assembly and C on ARMv5/v6 |
| others, MIPS included | portable C, constant time |

SHA-1 likewise uses SHA-NI, AVX2, AVX or SSSE3 on x86_64, the ARMv8 SHA1
instructions on aarch64 and 32-bit ARM, NEON on older ARM, and portable C
elsewhere. It matters because every UDP packet derives its own subkey.

libsodium has AES-GCM only as AES-256 and only on AES-NI, mbedTLS does not
pipeline AES, and Nettle's ARM detection does not work on musl.

## What was taken, and what was cut

`aws-lc/asm/` holds the generated assembly of the release tarball
(aws-lc-5.11.0.tar.gz, sha256
8cb24c6e6be1fa7ff05075c4560ca8b537a7ef48f9e6f465af4ea455794d74f4),
unmodified, by architecture.

The C in `aws-lc/crypto/` and `aws-lc/include/` was cut down from the same
release to what shadowsocks calls, keeping the code of what remains as it
was. Cut were:

- the EVP_CIPHER interface, the TLS and random-nonce AEAD variants, state
  serialisation, the FIPS service indicator and the error queue;
- every digest but SHA-1, and of SHA-1 everything but init, update and final;
- AES decryption, CBC, CFB, OFB, XTS, key wrap and POLYVAL;
- GCM with nonces other than 12 bytes and tags other than 16 bytes, and the
  GCM paths for CPUs without a counter-mode AES function (there are none);
- AVX-512 (its GCM code alone is about 700K, and every CPU with it has
  AES-NI, already faster than the relay), 32-bit x86, PowerPC, Windows,
  Apple and the other platforms;
- `sscanf` in the parsing of `OPENSSL_ia32cap` / `OPENSSL_armcap`, which
  also took an empty value for a valid one;
- reading `/proc/cpuinfo` on 32-bit ARM for kernels without `AT_HWCAP2`
  (older than any OpenWrt release).

Each file keeps the copyright lines of the files it came from. AWS-LC is
Apache-2.0 / ISC licensed, see `aws-lc/LICENSE`; both are compatible with
GPL-3.

`aws-lc-glue.c` is this project's: it reports the code paths selected, for
the startup log.

## Testing a change

The output must not change: every AEAD over many lengths, with its tamper
checks, the AWS-LC test vectors for the sizes shadowsocks uses, and SHA-1
over many lengths and update splits (`kat.c`), on every code path: x86_64
with `OPENSSL_ia32cap` masking SHA-NI, AES-NI, AVX2 and SSSE3, aarch64 with
`OPENSSL_armcap`, ARMv5 to ARMv8 and both MIPS byte orders under qemu.
`scripts/test-static.py` then checks the binaries against shadowsocks-rust.

## At run time

`crypto_init()` must call `CRYPTO_library_init()` first: it detects the CPU
features. Without it the assembly sees no features and runs, correctly but
slowly, as portable C. `crypto_init()` therefore exits if detection has not
run, and logs what was selected:

    crypto: aes hw, ghash pmull, chacha20 neon, chacha20-poly1305 asm, sha1 hw

For testing, `OPENSSL_ia32cap` and `OPENSSL_armcap` mask CPU features to
force the slower paths.
