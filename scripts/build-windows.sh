#!/usr/bin/env bash
# Cross-compile static Windows binaries (ss-local.exe, ss-tunnel.exe) and kat.exe
# using mingw-w64 (x86_64-w64-mingw32 or i686-w64-mingw32).
# Enforces Windows XP-safe PE imports (no Vista+ DLLs or symbols).
set -euo pipefail

HOST=${1:-x86_64-w64-mingw32}

case "$HOST" in
    i686-*)   SUBSYS="console:5.01" ;;
    x86_64-*) SUBSYS="console:5.02" ;;
    *)        SUBSYS="console" ;;
esac

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DL=$ROOT/build/dl
DEPS=$ROOT/build/$HOST/deps
OBJ=$ROOT/build/$HOST/obj
DIST=$ROOT/dist/$HOST

LIBEV=4.33;   LIBEV_SHA=507eb7b8d1015fbec5b935f34ebed15bf346bed04a11ab82b8eee848c4205aea
PCRE=8.45;    PCRE_SHA=4e6ce03e0336e8b4a3d6c2b70b1c5e18590a5673a98186da90d4f33c23defc09
CARES=1.18.1; CARES_SHA=1a7d52a8a84a9fbffb1be9133c0f6e17217d91ea5a6fa61f6b4729cda78ebbcf

export CC=$HOST-gcc AR=$HOST-ar RANLIB=$HOST-ranlib STRIP=$HOST-strip

mkdir -p "$DL" "$DEPS/include" "$DEPS/lib" "$OBJ" "$DIST"

fetch() {
    local file=$1 sha=$2; shift 2
    if [ -f "$DL/$file" ] && echo "$sha  $DL/$file" | sha256sum -c --status; then return; fi
    for url in "$@"; do
        echo "  fetching $url"
        curl -fsSL --retry 3 --max-time 300 -o "$DL/$file.tmp" "$url" || continue
        if echo "$sha  $DL/$file.tmp" | sha256sum -c --status; then
            mv "$DL/$file.tmp" "$DL/$file"; return
        fi
        echo "  !! checksum mismatch, trying next mirror"; rm -f "$DL/$file.tmp"
    done
    echo "!! could not fetch or verify $file"; exit 1
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

# 1. libev: standalone Winsock select backend with raw SOCKET handles
echo "===== libev-$LIBEV ====="
[ -d "$OBJ/libev-$LIBEV" ] || tar xf "$DL/libev-$LIBEV.tar.gz" -C "$OBJ"
if [ ! -f "$OBJ/libev-$LIBEV/.built" ]; then
    cd "$OBJ/libev-$LIBEV"
    if ! grep -q '!EV_SELECT_IS_WINSOCKET' ev_select.c; then
        sed -i 's/assert (("libev: fd >= FD_SETSIZE passed to fd_set-based select backend", fd < FD_SETSIZE));/#if !EV_SELECT_IS_WINSOCKET\n    assert (("libev: fd >= FD_SETSIZE passed to fd_set-based select backend", fd < FD_SETSIZE));\n#endif/' ev_select.c
    fi
    "$CC" -O2 -DFD_SETSIZE=1024 -DEV_STANDALONE=1 -DEV_USE_SELECT=1 -DEV_SELECT_IS_WINSOCKET=1 \
      -DEV_USE_MONOTONIC=0 -DEV_USE_REALTIME=0 -DEV_USE_CLOCK_SYSCALL=0 -DEV_USE_NANOSLEEP=0 \
      '-DEV_FD_TO_WIN32_HANDLE(fd)=(fd)' \
      '-DEV_WIN32_HANDLE_TO_FD(h)=(h)' \
      '-DEV_WIN32_CLOSE_FD(fd)=closesocket(fd)' \
      -ffunction-sections -fdata-sections -c ev.c -o ev.o
    "$AR" rcs "$DEPS/lib/libev.a" ev.o
    "$RANLIB" "$DEPS/lib/libev.a"
    cp ev.h "$DEPS/include/ev.h"
    touch .built
    cd "$ROOT"
fi

# 2. pcre
echo "===== pcre-$PCRE ====="
[ -d "$OBJ/pcre-$PCRE" ] || tar xf "$DL/pcre-$PCRE.tar.gz" -C "$OBJ"
if [ ! -f "$OBJ/pcre-$PCRE/.built" ]; then
    cd "$OBJ/pcre-$PCRE"
    CFLAGS="-Os -ffunction-sections -fdata-sections" \
      ./configure --build=x86_64-pc-linux-gnu --host="$HOST" --prefix="$DEPS" \
      --disable-shared --enable-static --disable-cpp >/dev/null
    make -j"$(nproc)" >/dev/null
    make install >/dev/null
    touch .built
    cd "$ROOT"
fi

# 3. c-ares (cache Win32 recv/recvfrom/send signatures; c-ares uses GetProcAddress
#    for Vista+ APIs at runtime, but its headers need _WIN32_WINNT=0x0600 to compile)
echo "===== c-ares-$CARES ====="
[ -d "$OBJ/c-ares-$CARES" ] || tar xf "$DL/c-ares-$CARES.tar.gz" -C "$OBJ"
if [ ! -f "$OBJ/c-ares-$CARES/.built" ]; then
    cd "$OBJ/c-ares-$CARES"
    CFLAGS="-Os -ffunction-sections -fdata-sections -D_WIN32_WINNT=0x0600" \
      ./configure --build=x86_64-pc-linux-gnu --host="$HOST" --prefix="$DEPS" \
      --disable-shared --enable-static --disable-tests \
      curl_cv_func_recv_args="SOCKET,char *,int,int,int" \
      curl_cv_func_recvfrom_args="SOCKET,char *,int,int,struct sockaddr *,int *,int,void" \
      curl_cv_func_send_args="SOCKET,const char *,int,int,int" >/dev/null
    make -j"$(nproc)" >/dev/null
    make install >/dev/null
    touch .built
    cd "$ROOT"
fi

# 4. shadowsocks-libev (ss-local.exe, ss-tunnel.exe, ss-server.exe, kat.exe)
echo "===== shadowsocks-libev ====="
[ -f "$ROOT/configure" ] || (cd "$ROOT" && ./autogen.sh >/dev/null 2>&1)
mkdir -p "$OBJ/ss" && cd "$OBJ/ss"
[ -f config.status ] || "$ROOT/configure" --build=x86_64-pc-linux-gnu --host="$HOST" \
    --prefix="$OBJ/ss-install" --disable-shared --enable-static --disable-documentation \
    --with-pcre="$DEPS" --with-ev="$DEPS" --with-cares="$DEPS" \
    CFLAGS="-O2 -DFD_SETSIZE=1024 -DCARES_STATICLIB -DPCRE_STATIC -ffunction-sections -fdata-sections -I$DEPS/include" \
    LDFLAGS="-L$DEPS/lib" \
    LIBS="-lws2_32 -ladvapi32" >/dev/null

make -C libbloom -j"$(nproc)" >/dev/null
make -C libcork -j"$(nproc)" >/dev/null
make -C libipset -j"$(nproc)" >/dev/null
make -C src/vendor -j"$(nproc)" >/dev/null
make -C src -j"$(nproc)" ss-local.exe ss-tunnel.exe ss-server.exe \
    LDFLAGS="-all-static -Wl,--gc-sections -Wl,--subsystem,$SUBSYS -L$DEPS/lib" \
    LIBS="-lws2_32 -ladvapi32" >/dev/null

rm -rf "$DIST" && mkdir -p "$DIST"
for b in ss-local.exe ss-tunnel.exe ss-server.exe; do
    "$STRIP" -o "$DIST/$b" "src/$b"
done

"$CC" -O2 -fstack-protector -I"$ROOT/src/vendor/aws-lc/include" -I"$ROOT/src/vendor" \
    "$ROOT/src/vendor/kat.c" "$OBJ/ss/src/vendor/.libs/libssawslc.a" \
    -static -Wl,--subsystem,"$SUBSYS" -s -o "$ROOT/build/$HOST/kat.exe"

# 5. XP-safe PE import check (reject any Vista+ DLL or symbol)
echo "===== output & XP-safe import check ====="
OK_DLL='^(ADVAPI32|KERNEL32|MSVCRT|SHELL32|WS2_32)\.DLL$'
VISTA_SYM='^(BCryptGenRandom|GetTickCount64|InitOnceExecuteOnce|InitializeSRWLock|AcquireSRWLock.*|ReleaseSRWLock.*|InitializeConditionVariable|SleepConditionVariable.*|Wake(All)?ConditionVariable|GetSystemTimePreciseAsFileTime|CancelIoEx|GetThreadId|WSAPoll|inet_ntop|inet_pton|if_nametoindex|if_indextoname|RegGetValue[AW]|CreateThreadpool.*|_putenv_s)$'

for f in "$DIST"/*.exe "$ROOT/build/$HOST/kat.exe"; do
    printf "  %-16s %8s\n" "$(basename "$f")" "$(stat -c%s "$f")"
    dlls=$("$HOST-objdump" -p "$f" | awk '/DLL Name:/{print toupper($3)}' | sort -u)
    syms=$("$HOST-objdump" -p "$f" | awk '/^\t[0-9a-f]+\s+/{print $NF}' | sort -u)
    echo "    DLLs: $(echo "$dlls" | tr '\n' ' ')"
    bad_dll=$(echo "$dlls" | grep -vE "$OK_DLL" || true)
    if [ -n "$bad_dll" ]; then
        echo "!! unexpected DLL import in $f (not XP-safe): $bad_dll"
        exit 1
    fi
    bad_sym=$(echo "$syms" | grep -E "$VISTA_SYM" || true)
    if [ -n "$bad_sym" ]; then
        echo "!! Vista+ symbol imported in $f (not XP-safe): $bad_sym"
        exit 1
    fi
done
echo "  all binaries passed XP-safe import check"
