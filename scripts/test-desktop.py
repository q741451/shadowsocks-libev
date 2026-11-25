#!/usr/bin/env python3
"""Cross-platform smoke test for Windows and macOS builds of shadowsocks-libev.

Runs:
  1. kat against AWS-LC 5.11.0 cipher_extra/test vectors
  2. End-to-end TCP (ss-local SOCKS5, ss-tunnel TCP, dual-stack :: -> 127.0.0.1)
     and UDP (ss-tunnel -U) across all supported ciphers + none.
"""
import argparse
import os
import platform
import socket
import struct
import subprocess
import sys
import threading
import time

METHODS_ALL = [
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "chacha20",
    "none",
]

# Prebuilt shadowsocks-rust 1.25.0 binaries do not enable xchacha20 / stream
# ciphers by default, so test the common subset when using ssserver.exe.
METHODS_RUST = [
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "none",
]


def free_port(kind=socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def start_echo_servers():
    stop = threading.Event()

    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.bind(("127.0.0.1", 0))
    tcp_port = tcp_sock.getsockname()[1]
    tcp_sock.listen(32)

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(("127.0.0.1", 0))
    udp_port = udp_sock.getsockname()[1]

    def tcp_loop():
        tcp_sock.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = tcp_sock.accept()
            except socket.timeout:
                continue
            with conn:
                data = conn.recv(65536)
                if data:
                    conn.sendall(b"TCPECHO:" + data)

    def udp_loop():
        udp_sock.settimeout(0.5)
        while not stop.is_set():
            try:
                data, addr = udp_sock.recvfrom(65536)
            except socket.timeout:
                continue
            udp_sock.sendto(b"UDPECHO:" + data, addr)

    threading.Thread(target=tcp_loop, daemon=True).start()
    threading.Thread(target=udp_loop, daemon=True).start()
    return stop, tcp_sock, tcp_port, udp_sock, udp_port


def socks5_tcp_echo(proxy_port, target_port, payload):
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
    try:
        s.settimeout(5)
        s.sendall(b"\x05\x01\x00")
        assert s.recv(2) == b"\x05\x00", "SOCKS5 greeting failed"
        req = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", target_port)
        s.sendall(req)
        resp = s.recv(10)
        assert len(resp) >= 2 and resp[:2] == b"\x05\x00", f"SOCKS5 connect failed: {resp!r}"
        s.sendall(payload)
        got = s.recv(4096)
        assert got == b"TCPECHO:" + payload, f"SOCKS5 echo mismatch: {got!r}"
    finally:
        s.close()


def tunnel_tcp_echo(tun_port, payload):
    s = socket.create_connection(("127.0.0.1", tun_port), timeout=5)
    try:
        s.settimeout(5)
        s.sendall(payload)
        got = s.recv(4096)
        assert got == b"TCPECHO:" + payload, f"tunnel TCP mismatch: {got!r}"
    finally:
        s.close()


def tunnel_udp_echo(tun_port, payload):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        u.settimeout(5)
        u.sendto(payload, ("127.0.0.1", tun_port))
        got, _ = u.recvfrom(4096)
        assert got == b"UDPECHO:" + payload, f"tunnel UDP mismatch: {got!r}"
    finally:
        u.close()


def wait_tcp(port, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.3)
            s.close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"port {port} did not open within {timeout}s")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bindir", help="directory containing ss-local / ss-tunnel")
    ap.add_argument("--server", required=True, help="path to ss-server or ssserver.exe")
    ap.add_argument("--server-kind", choices=["libev", "rust"], default="libev")
    ap.add_argument("--kat", required=True, help="path to kat / kat.exe")
    ap.add_argument("--vectors", required=True, help="path to AWS-LC cipher_extra/test")
    args = ap.parse_args()

    exe = ".exe" if platform.system() == "Windows" else ""
    ss_local = os.path.join(args.bindir, "ss-local" + exe)
    ss_tunnel = os.path.join(args.bindir, "ss-tunnel" + exe)

    print("=== 1. Running KAT ===")
    r = subprocess.run([args.kat, args.vectors], capture_output=True, text=True)
    print(r.stdout.strip())
    if r.stderr.strip():
        print(r.stderr.strip(), file=sys.stderr)
    assert r.returncode == 0 and "RESULT: ok" in r.stdout, f"KAT failed (rc={r.returncode})"

    methods = METHODS_RUST if args.server_kind == "rust" else METHODS_ALL
    print("=== 2. Running E2E TCP/UDP/dual-stack tests ===")
    stop, tcp_sock, tcp_port, udp_sock, udp_port = start_echo_servers()
    try:
        for method in methods:
            srv_port = free_port()
            loc_port = free_port()
            tun_tcp_port = free_port()
            tun_udp_port = free_port(socket.SOCK_DGRAM)

            if args.server_kind == "rust":
                srv_cmd = [
                    args.server, "-s", f"127.0.0.1:{srv_port}",
                    "-k", "testpass123", "-m", method, "-U",
                ]
            else:
                srv_cmd = [
                    args.server, "-s", "127.0.0.1", "-p", str(srv_port),
                    "-k", "testpass123", "-m", method, "-u",
                ]

            loc_cmd = [
                ss_local, "-s", "127.0.0.1", "-p", str(srv_port),
                "-b", "::", "-l", str(loc_port),
                "-k", "testpass123", "-m", method,
            ]
            tun_tcp_cmd = [
                ss_tunnel, "-s", "127.0.0.1", "-p", str(srv_port),
                "-b", "127.0.0.1", "-l", str(tun_tcp_port),
                "-L", f"127.0.0.1:{tcp_port}",
                "-k", "testpass123", "-m", method,
            ]
            tun_udp_cmd = [
                ss_tunnel, "-s", "127.0.0.1", "-p", str(srv_port),
                "-b", "127.0.0.1", "-l", str(tun_udp_port),
                "-L", f"127.0.0.1:{udp_port}",
                "-k", "testpass123", "-m", method, "-U",
            ]

            procs = [
                ("server", subprocess.Popen(srv_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)),
                ("ss-local", subprocess.Popen(loc_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)),
                ("ss-tunnel-tcp", subprocess.Popen(tun_tcp_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)),
                ("ss-tunnel-udp", subprocess.Popen(tun_udp_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)),
            ]
            try:
                wait_tcp(srv_port)
                wait_tcp(loc_port)
                wait_tcp(tun_tcp_port)
                time.sleep(0.3)

                socks5_tcp_echo(loc_port, tcp_port, f"socks5-{method}".encode())
                tunnel_tcp_echo(tun_tcp_port, f"tuntcp-{method}".encode())
                tunnel_udp_echo(tun_udp_port, f"tunudp-{method}".encode())
                print(f"[PASS] {method:24s} | ss-local(::->v4) OK | ss-tunnel TCP OK | ss-tunnel UDP OK")
            except Exception as e:
                print(f"[FAIL] {method}: {e}", file=sys.stderr)
                for name, p in procs:
                    p.terminate()
                    out = p.communicate(timeout=3)[0].decode(errors="replace")
                    print(f"--- {name} ---\n{out}", file=sys.stderr)
                raise
            finally:
                for _, p in procs:
                    p.terminate()
                    try:
                        p.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        p.kill()
    finally:
        stop.set()
        tcp_sock.close()
        udp_sock.close()

    print("ALL DESKTOP TESTS PASSED!")


if __name__ == "__main__":
    main()
