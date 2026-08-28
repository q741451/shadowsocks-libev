#!/bin/bash
# 静态交叉编译 shadowsocks-libev。产物是完全静态的可执行文件，不依赖任何 libc。
#
#   scripts/build-static.sh x86_64-linux-musl
#   scripts/build-static.sh mipsel-linux-muslsf
#
# 依赖库版本与 shadowsocks-all.sh 保持一致（mbedTLS 2.16.12 + libsodium 1.0.18）。
# 全部钉死版本并校验 sha256：这些是加密库，下载内容必须可验证。
set -euo pipefail

HOST=${1:?用法: $0 <musl 三元组>，例如 x86_64-linux-musl}

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DL=$ROOT/build/dl
DEPS=$ROOT/build/$HOST/deps
OBJ=$ROOT/build/$HOST/obj
DIST=$ROOT/dist

# mbedTLS 必须是 2.x：3.0 移除了 mbedtls_md5_ret()，而 src/crypto.c 用到了它
LIBSODIUM=1.0.18;  LIBSODIUM_SHA=6f504490b342a4f8a4c4a02fc9b866cbef8622d5df4e5452b46be121e46636c1
MBEDTLS=2.16.12;   MBEDTLS_SHA=294871ab1864a65d0b74325e9219d5bcd6e91c34a3c59270c357bb9ae4d5c393
LIBEV=4.33;        LIBEV_SHA=507eb7b8d1015fbec5b935f34ebed15bf346bed04a11ab82b8eee848c4205aea
PCRE=8.45;         PCRE_SHA=4e6ce03e0336e8b4a3d6c2b70b1c5e18590a5673a98186da90d4f33c23defc09
CARES=1.18.1;      CARES_SHA=1a7d52a8a84a9fbffb1be9133c0f6e17217d91ea5a6fa61f6b4729cda78ebbcf

export CC=$HOST-gcc AR=$HOST-ar RANLIB=$HOST-ranlib STRIP=$HOST-strip
# musl.cc 的工具链默认 PIE，不给 -no-pie 的话 -static 出来的仍是动态对象
export CFLAGS="-Os -fno-pie"
export LDFLAGS="-no-pie"

mkdir -p "$DL" "$DEPS" "$OBJ" "$DIST"

# 主源 + 备用源；下载后一律校验 sha256
fetch() {
    local file=$1 sha=$2; shift 2
    if [ -f "$DL/$file" ] && echo "$sha  $DL/$file" | sha256sum -c --status; then return; fi
    for url in "$@"; do
        echo "  下载 $url"
        curl -fsSL --retry 3 --max-time 900 -o "$DL/$file.tmp" "$url" || continue
        if echo "$sha  $DL/$file.tmp" | sha256sum -c --status; then
            mv "$DL/$file.tmp" "$DL/$file"; return
        fi
        echo "  !! 校验和不符，换下一个源"; rm -f "$DL/$file.tmp"
    done
    echo "!! $file 下载或校验失败"; exit 1
}

unpack() { [ -d "$OBJ/$2" ] || tar xf "$DL/$1" -C "$OBJ"; }

# 走 autotools 的依赖统一处理
build_ac() {
    local tarball=$1 dir=$2; shift 2
    echo "===== $dir ====="
    unpack "$tarball" "$dir"
    cd "$OBJ/$dir"
    [ -f .built ] && { cd "$ROOT"; return; }
    ./configure --host="$HOST" --prefix="$DEPS" --disable-shared --enable-static "$@" >/dev/null
    make -j"$(nproc)" >/dev/null
    make install >/dev/null
    touch .built
    cd "$ROOT"
}

fetch libsodium-$LIBSODIUM.tar.gz $LIBSODIUM_SHA \
  "https://github.com/jedisct1/libsodium/releases/download/$LIBSODIUM-RELEASE/libsodium-$LIBSODIUM.tar.gz" \
  "https://sources.openwrt.org/libsodium-$LIBSODIUM.tar.gz"
fetch mbedtls-$MBEDTLS.tar.gz $MBEDTLS_SHA \
  "https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v$MBEDTLS.tar.gz"
fetch libev-$LIBEV.tar.gz $LIBEV_SHA \
  "https://sources.openwrt.org/libev-$LIBEV.tar.gz" \
  "https://dist.schmorp.de/libev/Attic/libev-$LIBEV.tar.gz"
fetch pcre-$PCRE.tar.gz $PCRE_SHA \
  "https://sourceforge.net/projects/pcre/files/pcre/$PCRE/pcre-$PCRE.tar.gz/download" \
  "https://ftp.exim.org/pub/pcre/pcre-$PCRE.tar.gz"
fetch c-ares-$CARES.tar.gz $CARES_SHA \
  "https://github.com/c-ares/c-ares/releases/download/cares-${CARES//./_}/c-ares-$CARES.tar.gz" \
  "https://sources.openwrt.org/c-ares-$CARES.tar.gz"

build_ac libsodium-$LIBSODIUM.tar.gz libsodium-$LIBSODIUM
build_ac libev-$LIBEV.tar.gz         libev-$LIBEV
build_ac pcre-$PCRE.tar.gz           pcre-$PCRE      --disable-cpp
build_ac c-ares-$CARES.tar.gz        c-ares-$CARES

echo "===== mbedtls-$MBEDTLS ====="
unpack mbedtls-$MBEDTLS.tar.gz mbedtls-$MBEDTLS
cd "$OBJ/mbedtls-$MBEDTLS"
if [ ! -f .built ]; then
    # mbedTLS 不用 autotools，SHARED= 表示只出静态库
    make lib CC="$CC" AR="$AR" SHARED= CFLAGS="$CFLAGS -I./include" >/dev/null
    make install DESTDIR="$DEPS" >/dev/null
    touch .built
fi
cd "$ROOT"

echo "===== shadowsocks-libev ====="
[ -f "$ROOT/configure" ] || (cd "$ROOT" && ./autogen.sh >/dev/null 2>&1)
mkdir -p "$OBJ/ss" && cd "$OBJ/ss"
[ -f config.status ] || "$ROOT/configure" --host="$HOST" --prefix="$OBJ/ss-install" \
    --disable-shared --enable-static --disable-documentation \
    --with-mbedtls="$DEPS" --with-sodium="$DEPS" \
    --with-pcre="$DEPS" --with-ev="$DEPS" --with-cares="$DEPS" \
    CFLAGS="$CFLAGS -I$DEPS/include" >/dev/null
# -all-static 是 libtool 的参数、编译器不认，放进 configure 会让它的编译器测试失败，
# 只能在 make 时传；且必须一并带上 -L$DEPS/lib，否则会盖掉 configure 记下的库路径
SSLD="-no-pie -all-static -L$DEPS/lib"
make -j"$(nproc)" LDFLAGS="$SSLD" >/dev/null
make install LDFLAGS="$SSLD" >/dev/null
cd "$ROOT"

echo "===== 产物 ====="
OUTDIR=$DIST/$HOST
rm -rf "$OUTDIR"; mkdir -p "$OUTDIR"
for b in ss-local ss-redir ss-tunnel ss-server ss-manager; do
    install -m755 "$OBJ/ss-install/bin/$b" "$OUTDIR/$b"
    "$STRIP" "$OUTDIR/$b"
done
install -m755 "$OBJ/ss-install/bin/ss-nat" "$OUTDIR/ss-nat" 2>/dev/null || true

for f in "$OUTDIR"/*; do
    printf "  %-11s %8s  %s\n" "$(basename "$f")" "$(stat -c%s "$f")" "$(file -b "$f" | cut -c1-60)"
done

# 静态性自检：动态链接的产物在目标机上会因缺少 libc 直接跑不起来
for b in ss-local ss-redir ss-tunnel ss-server ss-manager; do
    if file -b "$OUTDIR/$b" | grep -q "dynamically linked"; then
        echo "!! $b 不是静态链接"; exit 1
    fi
done
echo "  静态性自检通过"
