#!/bin/bash
# Cross-compile shadowsocks-libev into fully static executables.
#
#   scripts/build-static.sh x86_64-linux-musl
#   scripts/build-static.sh mipsel-linux-muslsf
#
# libsodium and mbedTLS are not needed: ChaCha20 is vendored under src/vendor
# and MD5 is implemented locally. See src/vendor/README.md.
# The remaining dependencies are pinned by version and checked by sha256.
set -euo pipefail

HOST=${1:?usage: $0 <musl triplet>, e.g. x86_64-linux-musl}

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DL=$ROOT/build/dl
DEPS=$ROOT/build/$HOST/deps
OBJ=$ROOT/build/$HOST/obj
DIST=$ROOT/dist

LIBEV=4.33;        LIBEV_SHA=507eb7b8d1015fbec5b935f34ebed15bf346bed04a11ab82b8eee848c4205aea
PCRE=8.45;         PCRE_SHA=4e6ce03e0336e8b4a3d6c2b70b1c5e18590a5673a98186da90d4f33c23defc09
CARES=1.18.1;      CARES_SHA=1a7d52a8a84a9fbffb1be9133c0f6e17217d91ea5a6fa61f6b4729cda78ebbcf

export CC=$HOST-gcc AR=$HOST-ar RANLIB=$HOST-ranlib STRIP=$HOST-strip
# The musl.cc toolchains default to PIE; without -no-pie, -static still
# produces a dynamic object.
# Optimisation levels come from build-aux/optflags.sh, which configure.ac
# sources as well.
. "$ROOT/build-aux/optflags.sh"
CFLAGS_HOT="$SS_OPT_HOT $SS_CFLAGS_COMMON"
CFLAGS_COLD="$SS_OPT_COLD $SS_CFLAGS_COMMON"
export CFLAGS="$CFLAGS_HOT"
export LDFLAGS="-no-pie"

mkdir -p "$DL" "$DEPS" "$OBJ" "$DIST"

# Primary and fallback mirrors; every download is checked by sha256
fetch() {
    local file=$1 sha=$2; shift 2
    if [ -f "$DL/$file" ] && echo "$sha  $DL/$file" | sha256sum -c --status; then return; fi
    for url in "$@"; do
        echo "  fetching $url"
        curl -fsSL --retry 3 --max-time 900 -o "$DL/$file.tmp" "$url" || continue
        if echo "$sha  $DL/$file.tmp" | sha256sum -c --status; then
            mv "$DL/$file.tmp" "$DL/$file"; return
        fi
        echo "  !! checksum mismatch, trying next mirror"; rm -f "$DL/$file.tmp"
    done
    echo "!! could not fetch or verify $file"; exit 1
}

unpack() { [ -d "$OBJ/$2" ] || tar xf "$DL/$1" -C "$OBJ"; }

# Dependencies that use autotools
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

fetch libev-$LIBEV.tar.gz $LIBEV_SHA \
  "https://sources.openwrt.org/libev-$LIBEV.tar.gz" \
  "https://dist.schmorp.de/libev/Attic/libev-$LIBEV.tar.gz"
fetch pcre-$PCRE.tar.gz $PCRE_SHA \
  "https://sourceforge.net/projects/pcre/files/pcre/$PCRE/pcre-$PCRE.tar.gz/download" \
  "https://ftp.exim.org/pub/pcre/pcre-$PCRE.tar.gz"
fetch c-ares-$CARES.tar.gz $CARES_SHA \
  "https://github.com/c-ares/c-ares/releases/download/cares-${CARES//./_}/c-ares-$CARES.tar.gz" \
  "https://sources.openwrt.org/c-ares-$CARES.tar.gz"

CFLAGS="$CFLAGS_HOT"  build_ac libev-$LIBEV.tar.gz      libev-$LIBEV
CFLAGS="$CFLAGS_COLD" build_ac pcre-$PCRE.tar.gz        pcre-$PCRE      --disable-cpp
CFLAGS="$CFLAGS_COLD" build_ac c-ares-$CARES.tar.gz     c-ares-$CARES
CFLAGS="$CFLAGS_HOT"

echo "===== shadowsocks-libev ====="
[ -f "$ROOT/configure" ] || (cd "$ROOT" && ./autogen.sh >/dev/null 2>&1)
mkdir -p "$OBJ/ss" && cd "$OBJ/ss"
[ -f config.status ] || "$ROOT/configure" --host="$HOST" --prefix="$OBJ/ss-install" \
    --disable-shared --enable-static --disable-documentation \
    --with-pcre="$DEPS" --with-ev="$DEPS" --with-cares="$DEPS" \
    CFLAGS="$CFLAGS -I$DEPS/include" >/dev/null
# -all-static is a libtool flag, not a compiler one: putting it in configure's
# LDFLAGS makes its compiler test fail, so it is passed at make time. -L must
# be repeated there or it overrides the library path configure recorded.
SSLD="-no-pie -all-static -Wl,--gc-sections -L$DEPS/lib"
make -j"$(nproc)" LDFLAGS="$SSLD" >/dev/null
make install LDFLAGS="$SSLD" >/dev/null
cd "$ROOT"

echo "===== output ====="
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

# A dynamically linked result would not start on the target at all
for b in ss-local ss-redir ss-tunnel ss-server ss-manager; do
    if file -b "$OUTDIR/$b" | grep -q "dynamically linked"; then
        echo "!! $b is not statically linked"; exit 1
    fi
done
echo "  all binaries are statically linked"
