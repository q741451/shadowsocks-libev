# vendor/ —— 从 libsodium 1.0.18 抠出的 ChaCha20

只取 ChaCha20 流加密所需的文件，不引入 libsodium 其余部分。

## 为什么不直接链 libsodium

`sodium_init()` 会挨个调用每个子系统的 `pick_best_implementation`，那些函数
引用了全部实现，`--gc-sections` 因此一个都删不掉：ed25519 基点表 30.0K、
blake2b 四份实现 20.3K、argon2 的 fill_segment_* 约 10K、salsa20 与 poly1305
约 9K，全被拖进产物。而 ChaCha20 本体只有 11.5K。

实测（x86_64，本机）：

| 方案 | 吞吐 | 加密代码体积 |
|---|---|---|
| 完整 libsodium | 3000 MB/s | 135.0K |
| libsodium --enable-minimal + --gc-sections | 3000 MB/s | 102.6K |
| 本目录 | 3258 MB/s | 14.2K |

## 文件来源

| 本目录 | libsodium 1.0.18 中的路径 |
|---|---|
| `chacha20/stream_chacha20.*` | `src/libsodium/crypto_stream/chacha20/` |
| `chacha20/ref/*` | `src/libsodium/crypto_stream/chacha20/ref/` |
| `chacha20/dolbeau/*` | `src/libsodium/crypto_stream/chacha20/dolbeau/` |
| `runtime.c` | `src/libsodium/sodium/runtime.c` |
| `sodium/*.h` | `src/libsodium/include/sodium/` |

均未改动，许可证为 ISC，与本项目的 GPL-3 兼容，版权头原样保留。

## 注意：HAVE_* 宏必须由构建系统正确定义

这些文件用 configure 生成的 `HAVE_*` 宏开关功能。抠出来后由本项目的
configure.ac 负责定义，漏定义**不会报错，只会静默退回纯 C 实现**：

- 漏 `HAVE_CPUID` → CPU 特性检测整个不执行，AVX2/SSSE3 永远选不中
- `HAVE__XGETBV` 是 MSVC 风格内建，GCC 上须改用 `HAVE_AVX_ASM`

因此 `crypto_init()` 启动时会打印实际选中的实现，便于发现这类静默退化。
