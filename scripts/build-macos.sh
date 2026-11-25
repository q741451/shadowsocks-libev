#!/usr/bin/env bash
# Build macOS binaries (ss-local, ss-tunnel, ss-server, ss-manager) and kat
# for arm64 or x86_64 (cross-compiled natively via Apple Clang -arch on Apple Silicon),
# statically linking libev, pcre and c-ares.
set -euo pipefail

ARCH=${1:-$(uname -m)}
HOST_ARCH=$(uname -m)
TARGET="macos-${ARCH}"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-11.0}"

ARCH_FLAG="-arch ${ARCH}"
HOST_ARG=""
if [ "$ARCH" != "$HOST_ARCH" ]; then
    HOST_ARG="--host=${ARCH}-apple-darwin"
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DL=$ROOT/build/dl
DEPS=$ROOT/build/$TARGET/deps
OBJ=$ROOT/build/$TARGET/obj
DIST=$ROOT/dist/$TARGET

LIBEV=4.33;   LIBEV_SHA=507eb7b8d1015fbec5b935f34ebed15bf346bed04a11ab82b8eee848c4205aea
PCRE=8.45;    PCRE_SHA=4e6ce03e0336e8b4a3d6c2b70b1c5e18590a5673a98186da90d4f33c23defc09
CARES=1.18.1; CARES_SHA=1a7d52a8a84a9fbffb1be9133c0f6e17217d91ea5a6fa61f6b4729cda78ebbcf

NPROC=$(sysctl -n hw.ncpu)
mkdir -p "$DL" "$DEPS" "$OBJ" "$DIST"

fetch() {
    local file=$1 sha=$2; shift 2
    if [ -f "$DL/$file" ] && echo "$sha  $DL/$file" | shasum -a 256 -c --status; then return; fi
    for url in "$@"; do
        echo "  fetching $url"
        curl -fsSL --retry 3 --max-time 300 -o "$DL/$file.tmp" "$url" || continue
        if echo "$sha  $DL/$file.tmp" | shasum -a 256 -c --status; then
            mv "$DL/$file.tmp" "$DL/$file"; return
        fi
        echo "  !! checksum mismatch, trying next mirror"; rm -f "$DL/$file.tmp"
    done
    echo "!! could not fetch or verify $file"; exit 1
}

build_ac() {
    local tarball=$1 dir=$2; shift 2
    echo "===== $dir ($ARCH) ====="
    [ -d "$OBJ/$dir" ] || tar xf "$DL/$tarball" -C "$OBJ"
    cd "$OBJ/$dir"
    [ -f .built ] && { cd "$ROOT"; return; }
    ./configure $HOST_ARG --prefix="$DEPS" --disable-shared --enable-static "$@" >/dev/null
    make -j"$NPROC" >/dev/null
    make install >/dev/null
    touch .built
    cd "$ROOT"
}

fetch libev-$LIBEV.tar.gz $LIBEV_SHA \
  "https://sources.openwrt.org/libev-$LIBEV.tar.gz" \
  "https://dist.schmorp.de/libev/Attic/libev-$LIBEV.tar.gz"
fetch pcre-$PCRE.tar.gz $PCRE_SHA \
  "https://sourceforge.net/projects/pcre/files/pcre/$PCRE/pcre-$PCRE.tar.gz/download" \
  "https://ftp.exim.org/pub/pcre/pcre-$PCRE.tar.gz"
fetch c-ares-$CARES.tar.gz $CARES_SHA \
  "https://github.com/c-ares/c-ares/releases/download/cares-${CARES//./_}/c-ares-$CARES.tar.gz" \
  "https://sources.openwrt.org/c-ares-$CARES.tar.gz"

CFLAGS="-O2 $ARCH_FLAG" LDFLAGS="$ARCH_FLAG" build_ac libev-$LIBEV.tar.gz libev-$LIBEV
CFLAGS="-Os $ARCH_FLAG" LDFLAGS="$ARCH_FLAG" build_ac pcre-$PCRE.tar.gz pcre-$PCRE --disable-cpp
CFLAGS="-Os $ARCH_FLAG" LDFLAGS="$ARCH_FLAG" build_ac c-ares-$CARES.tar.gz c-ares-$CARES

echo "===== shadowsocks-libev ($ARCH) ====="
[ -f "$ROOT/configure" ] || (cd "$ROOT" && ./autogen.sh >/dev/null 2>&1)
mkdir -p "$OBJ/ss" && cd "$OBJ/ss"
[ -f config.status ] || "$ROOT/configure" $HOST_ARG --prefix="$OBJ/ss-install" \
    --disable-shared --enable-static --disable-documentation \
    --with-pcre="$DEPS" --with-ev="$DEPS" --with-cares="$DEPS" \
    CFLAGS="-O2 $ARCH_FLAG -I$DEPS/include" \
    LDFLAGS="$ARCH_FLAG -L$DEPS/lib -Wl,-dead_strip" >/dev/null

# Override GNU ld's --gc-sections from src/Makefile.am with Apple ld's -dead_strip
make -j"$NPROC" AM_LDFLAGS="$ARCH_FLAG -Wl,-dead_strip" LDFLAGS="$ARCH_FLAG -L$DEPS/lib -Wl,-dead_strip" >/dev/null
make install AM_LDFLAGS="$ARCH_FLAG -Wl,-dead_strip" LDFLAGS="$ARCH_FLAG -L$DEPS/lib -Wl,-dead_strip" >/dev/null

rm -rf "$DIST" && mkdir -p "$DIST"
for b in ss-local ss-tunnel ss-server ss-manager; do
    cp "$OBJ/ss-install/bin/$b" "$DIST/$b"
    strip "$DIST/$b"
done

cc -O2 $ARCH_FLAG -I"$ROOT/src/vendor/aws-lc/include" -I"$ROOT/src/vendor" \
    "$ROOT/src/vendor/kat.c" "$OBJ/ss/src/vendor/.libs/libssawslc.a" \
    -Wl,-dead_strip -o "$ROOT/build/$TARGET/kat"
strip "$ROOT/build/$TARGET/kat"

echo "===== output ($ARCH, minos=$MACOSX_DEPLOYMENT_TARGET) ====="
for f in "$DIST"/* "$ROOT/build/$TARGET/kat"; do
    file "$f"
    deps=$(otool -L "$f" | tail -n +2 | awk '{print $1}')
    echo "    dylibs: $(echo "$deps" | tr '\n' ' ')"
    for d in $deps; do
        case "$d" in
            /usr/lib/*|/System/Library/*) ;;
            *) echo "!! unexpected non-system dylib: $d in $f"; exit 1 ;;
        esac
    done
done
