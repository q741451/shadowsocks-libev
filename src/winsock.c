/*
 * winsock.c - Windows socket compatibility layer
 *
 * Copyright (C) 2013 - 2019, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifdef __MINGW32__

#include <errno.h>
#include "winsock.h"
#include "utils.h"

#ifndef ENABLE_QUICK_EDIT
#define ENABLE_QUICK_EDIT 0x0040
#endif

#ifndef STD_INPUT_HANDLE
#define STD_INPUT_HANDLE ((DWORD)-10)
#endif

#ifndef ENABLE_EXTENDED_FLAGS
#define ENABLE_EXTENDED_FLAGS 0x0080
#endif

#ifndef STD_OUTPUT_HANDLE
#define STD_OUTPUT_HANDLE ((DWORD)-11)
#endif

static void
disable_quick_edit(void)
{
    DWORD mode     = 0;
    HANDLE console = GetStdHandle(STD_INPUT_HANDLE);

    // Get current console mode
    if (console == NULL ||
        console == INVALID_HANDLE_VALUE ||
        !GetConsoleMode(console, &mode)) {
        return;
    }

    // Clear the quick edit bit in the mode flags
    mode &= ~ENABLE_QUICK_EDIT;
    mode |= ENABLE_EXTENDED_FLAGS;
    SetConsoleMode(console, mode);
}

void
winsock_init(void)
{
    int ret;
    WSADATA wsa_data;
    ret = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (ret != 0) {
        FATAL("Failed to initialize winsock");
    }
    // Disable quick edit mode to prevent stuck
    disable_quick_edit();
}

void
winsock_cleanup(void)
{
    WSACleanup();
}

int
setnonblocking(SOCKET socket)
{
    u_long arg = 1;
    return ioctlsocket(socket, FIONBIO, &arg);
}

void
ss_error(const char *s)
{
    char *msg = NULL;
    DWORD err = WSAGetLastError();
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, err,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&msg, 0, NULL);
    if (msg != NULL) {
        // Remove trailing newline character
        ssize_t len = strlen(msg) - 1;
        if (len >= 0 && msg[len] == '\n') {
            msg[len] = '\0';
        }
        LOGE("%s: [%ld] %s", s, err, msg);
        LocalFree(msg);
    }
}

char *
ss_gai_strerror(int ecode)
{
    static TCHAR buff[GAI_STRERROR_BUFFER_SIZE + 1];
    FormatMessage(
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS |
        FORMAT_MESSAGE_MAX_WIDTH_MASK,
        NULL, ecode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)buff, GAI_STRERROR_BUFFER_SIZE, NULL);
    return (char *)buff;
}

static BOOL
get_conattr(HANDLE console, WORD *out_attr)
{
    static BOOL done       = FALSE;
    static WORD saved_attr = 0;
    if (!done) {
        CONSOLE_SCREEN_BUFFER_INFO info;
        if (GetConsoleScreenBufferInfo(console, &info)) {
            saved_attr = info.wAttributes;
            done       = TRUE;
        }
    }
    if (out_attr != NULL) {
        *out_attr = saved_attr;
    }
    return done;
}

static BOOL
set_concolor(WORD color, BOOL reset)
{
    static HANDLE console = NULL;
    if (console == NULL) {
        console = GetStdHandle(STD_OUTPUT_HANDLE);
    }
    if (console == NULL ||
        console == INVALID_HANDLE_VALUE) {
        // If no console is available, we will not try again
        console = INVALID_HANDLE_VALUE;
        return FALSE;
    }
    WORD attr;
    if (!get_conattr(console, &attr)) {
        return FALSE;
    }
    if (!reset) {
        // Only override foreground color without changing background
        attr &= ~(FOREGROUND_RED | FOREGROUND_GREEN |
                  FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        attr |= (color | FOREGROUND_INTENSITY);
    }
    return SetConsoleTextAttribute(console, attr);
}

void
ss_color_info(void)
{
    set_concolor(FOREGROUND_GREEN, FALSE);
}

void
ss_color_error(void)
{
    set_concolor(FOREGROUND_RED | FOREGROUND_BLUE, FALSE);
}

void
ss_color_reset(void)
{
    set_concolor(0, TRUE);
}

#ifdef TCP_FASTOPEN_WINSOCK
LPFN_CONNECTEX
winsock_getconnectex(void)
{
    static LPFN_CONNECTEX pConnectEx = NULL;
    if (pConnectEx != NULL) {
        return pConnectEx;
    }

    // Dummy socket for WSAIoctl
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        ERROR("socket");
        return NULL;
    }

    // Load ConnectEx function
    GUID guid = WSAID_CONNECTEX;
    DWORD numBytes;
    int ret = -1;
    ret = WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER,
                   (void *)&guid, sizeof(guid),
                   (void *)&pConnectEx, sizeof(pConnectEx),
                   &numBytes, NULL, NULL);
    if (ret != 0) {
        ERROR("WSAIoctl");
        closesocket(s);
        return NULL;
    }
    closesocket(s);
    return pConnectEx;
}

int
winsock_dummybind(SOCKET fd, struct sockaddr *sa)
{
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    if (sa->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
        sin->sin_family      = AF_INET;
        sin->sin_addr.s_addr = INADDR_ANY;
    } else if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr   = in6addr_any;
    } else {
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&ss, sizeof(ss)) < 0 &&
        WSAGetLastError() != WSAEINVAL) {
        return -1;
    }
    return 0;
}

#endif

/* XP-compatible inet_pton / inet_ntop (WS2_32.dll added them in Vista). */
static int
ss_inet_pton4(const char *src, unsigned char *dst)
{
    int saw_digit = 0, octets = 0, ch;
    unsigned char tmp[4], *tp = tmp;

    *tp = 0;
    while ((ch = *src++) != '\0') {
        if (ch >= '0' && ch <= '9') {
            unsigned int nw = *tp * 10 + (unsigned int)(ch - '0');
            if (saw_digit && *tp == 0)
                return 0;
            if (nw > 255)
                return 0;
            *tp = (unsigned char)nw;
            if (!saw_digit) {
                if (++octets > 4)
                    return 0;
                saw_digit = 1;
            }
        } else if (ch == '.' && saw_digit) {
            if (octets == 4)
                return 0;
            *++tp     = 0;
            saw_digit = 0;
        } else {
            return 0;
        }
    }
    if (octets < 4)
        return 0;
    memcpy(dst, tmp, 4);
    return 1;
}

static int
ss_inet_pton6(const char *src, unsigned char *dst)
{
    unsigned char tmp[16], *tp = tmp, *endp = tmp + 16, *colonp = NULL;
    const char *curtok;
    int ch, saw_xdigit = 0;
    unsigned int val = 0;

    memset(tmp, 0, sizeof(tmp));
    if (*src == ':') {
        if (*++src != ':')
            return 0;
    }
    curtok = src;
    while ((ch = *src++) != '\0') {
        int digit = -1;
        if (ch >= '0' && ch <= '9')
            digit = ch - '0';
        else if (ch >= 'a' && ch <= 'f')
            digit = ch - 'a' + 10;
        else if (ch >= 'A' && ch <= 'F')
            digit = ch - 'A' + 10;

        if (digit >= 0) {
            val <<= 4;
            val |= (unsigned int)digit;
            if (val > 0xffff)
                return 0;
            saw_xdigit = 1;
            continue;
        }
        if (ch == ':') {
            curtok = src;
            if (!saw_xdigit) {
                if (colonp)
                    return 0;
                colonp = tp;
                continue;
            } else if (*src == '\0') {
                return 0;
            }
            if (tp + 2 > endp)
                return 0;
            *tp++      = (unsigned char)((val >> 8) & 0xff);
            *tp++      = (unsigned char)(val & 0xff);
            saw_xdigit = 0;
            val        = 0;
            continue;
        }
        if (ch == '.' && (tp + 4) <= endp && ss_inet_pton4(curtok, tp) > 0) {
            tp        += 4;
            saw_xdigit = 0;
            break;
        }
        return 0;
    }
    if (saw_xdigit) {
        if (tp + 2 > endp)
            return 0;
        *tp++ = (unsigned char)((val >> 8) & 0xff);
        *tp++ = (unsigned char)(val & 0xff);
    }
    if (colonp != NULL) {
        int n = (int)(tp - colonp);
        int i;
        if (tp == endp)
            return 0;
        for (i = 1; i <= n; i++) {
            endp[-i]      = colonp[n - i];
            colonp[n - i] = 0;
        }
        tp = endp;
    }
    if (tp != endp)
        return 0;
    memcpy(dst, tmp, 16);
    return 1;
}

int
ss_inet_pton(int af, const char *src, void *dst)
{
    if (af == AF_INET)
        return ss_inet_pton4(src, (unsigned char *)dst);
    if (af == AF_INET6)
        return ss_inet_pton6(src, (unsigned char *)dst);
    WSASetLastError(WSAEAFNOSUPPORT);
    return -1;
}

const char *
ss_inet_ntop(int af, const void *src, char *dst, socklen_t size)
{
    if (size <= 0) {
        WSASetLastError(WSAEINVAL);
        return NULL;
    }
    if (af == AF_INET) {
        const unsigned char *b = (const unsigned char *)src;
        char tmp[16];
        int len = snprintf(tmp, sizeof(tmp), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
        if (len < 0 || (socklen_t)(len + 1) > size) {
            WSASetLastError(WSAEINVAL);
            return NULL;
        }
        memcpy(dst, tmp, (size_t)len + 1);
        return dst;
    }
    if (af == AF_INET6) {
        const unsigned char *b = (const unsigned char *)src;
        unsigned int words[8];
        int i, best_base = -1, best_len = 0, cur_base = -1, cur_len = 0;
        char tmp[64], *tp = tmp;

        for (i = 0; i < 8; i++)
            words[i] = ((unsigned int)b[2 * i] << 8) | (unsigned int)b[2 * i + 1];

        for (i = 0; i < 8; i++) {
            if (words[i] == 0) {
                if (cur_base == -1) {
                    cur_base = i;
                    cur_len  = 1;
                } else {
                    cur_len++;
                }
            } else if (cur_base != -1) {
                if (best_base == -1 || cur_len > best_len) {
                    best_base = cur_base;
                    best_len  = cur_len;
                }
                cur_base = -1;
            }
        }
        if (cur_base != -1 && (best_base == -1 || cur_len > best_len)) {
            best_base = cur_base;
            best_len  = cur_len;
        }
        if (best_base != -1 && best_len < 2)
            best_base = -1;

        for (i = 0; i < 8; i++) {
            if (best_base != -1 && i >= best_base && i < best_base + best_len) {
                if (i == best_base)
                    *tp++ = ':';
                continue;
            }
            if (i != 0)
                *tp++ = ':';
            if (i == 6 && best_base == 0 &&
                (best_len == 6 || (best_len == 5 && words[5] == 0xffff))) {
                if (!ss_inet_ntop(AF_INET, b + 12, tp,
                                  (socklen_t)(sizeof(tmp) - (size_t)(tp - tmp))))
                    return NULL;
                tp += strlen(tp);
                break;
            }
            tp += sprintf(tp, "%x", words[i]);
        }
        if (best_base != -1 && (best_base + best_len) == 8)
            *tp++ = ':';
        *tp++ = '\0';

        if ((socklen_t)(tp - tmp) > size) {
            WSASetLastError(WSAEINVAL);
            return NULL;
        }
        memcpy(dst, tmp, (size_t)(tp - tmp));
        return dst;
    }
    WSASetLastError(WSAEAFNOSUPPORT);
    return NULL;
}

/* XP-compatible _putenv_s shim for libcork (not exported by XP msvcrt.dll). */
static int __cdecl
ss_putenv_s(const char *name, const char *value)
{
    if (!name || !value)
        return EINVAL;
    size_t nlen = strlen(name), vlen = strlen(value);
    char *buf   = (char *)malloc(nlen + 1 + vlen + 1);
    if (!buf)
        return ENOMEM;
    memcpy(buf, name, nlen);
    buf[nlen] = '=';
    memcpy(buf + nlen + 1, value, vlen + 1);
    int r = _putenv(buf);
    free(buf);
    return r == 0 ? 0 : EINVAL;
}

#ifdef _WIN64
int (__cdecl *__imp__putenv_s)(const char *, const char *) = ss_putenv_s;
#else
int (__cdecl *_imp___putenv_s)(const char *, const char *) = ss_putenv_s;
#endif

/* XP-compatible iphlpapi.dll shims for c-ares (resolve Vista+ APIs at run time). */
unsigned long WINAPI
GetUnicastIpAddressTable(unsigned short family, void **table)
{
    typedef unsigned long (WINAPI *pfn_t)(unsigned short, void **);
    HMODULE hmod = LoadLibraryA("iphlpapi.dll");
    if (!hmod)
        return ERROR_NOT_SUPPORTED;
    pfn_t pfn = (pfn_t)(void *)GetProcAddress(hmod, "GetUnicastIpAddressTable");
    unsigned long ret = pfn ? pfn(family, table) : ERROR_NOT_SUPPORTED;
    FreeLibrary(hmod);
    return ret;
}

void WINAPI
FreeMibTable(void *memory)
{
    typedef void (WINAPI *pfn_t)(void *);
    HMODULE hmod = LoadLibraryA("iphlpapi.dll");
    if (!hmod)
        return;
    pfn_t pfn = (pfn_t)(void *)GetProcAddress(hmod, "FreeMibTable");
    if (pfn)
        pfn(memory);
    FreeLibrary(hmod);
}

char *
if_indextoname(unsigned int ifindex, char *ifname)
{
    typedef char *(WINAPI *pfn_t)(unsigned int, char *);
    HMODULE hmod = LoadLibraryA("iphlpapi.dll");
    if (!hmod)
        return NULL;
    pfn_t pfn = (pfn_t)(void *)GetProcAddress(hmod, "if_indextoname");
    char *ret = pfn ? pfn(ifindex, ifname) : NULL;
    FreeLibrary(hmod);
    return ret;
}

#endif // __MINGW32__
