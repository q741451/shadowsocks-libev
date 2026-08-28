# vendor/ — ChaCha20 taken from libsodium 1.0.18

Only the files needed for the ChaCha20 stream cipher; the rest of libsodium is
not used.

## Why not just link libsodium

`sodium_init()` calls every subsystem's `pick_best_implementation`, and those
functions reference all of their implementations, so `--gc-sections` cannot
drop any of them. In a static build that pulls in the ed25519 base point table,
four blake2b implementations, argon2 and more — an order of magnitude more code
than ChaCha20 itself. `--enable-minimal` barely helps because the anchor is
`sodium_init()`, not the configure options.

Measured on x86_64: the full library contributes about ten times as much to the
binary as this directory does, at the same throughput.

## Where the files come from

| Here | In libsodium 1.0.18 |
|---|---|
| `chacha20/stream_chacha20.*` | `src/libsodium/crypto_stream/chacha20/` |
| `chacha20/ref/*` | `src/libsodium/crypto_stream/chacha20/ref/` |
| `chacha20/dolbeau/*` | `src/libsodium/crypto_stream/chacha20/dolbeau/` |
| `runtime.c` | `src/libsodium/sodium/runtime.c` |
| `sodium/*.h` | `src/libsodium/include/sodium/` |

Unmodified. libsodium is ISC licensed, which is compatible with GPL-3; the
copyright headers are kept as they are.

`sodium_shim.c` is not from libsodium: it provides the handful of runtime
symbols the vendored code still refers to, without `sodium_init()`.

## The HAVE_* macros must be defined by the build system

These files switch features on `HAVE_*` macros that libsodium's own configure
would define. Getting them wrong is not a build error — it silently selects the
portable C implementation:

- without `HAVE_CPUID` the CPU feature detection never runs, so SSSE3 and AVX2
  are never chosen;
- `HAVE__XGETBV` is an MSVC builtin, GCC needs `HAVE_AVX_ASM` instead.

Because of that, `crypto_init()` logs the implementation it ended up with.
