#!/usr/bin/env python3
"""Test the static binaries in a dist directory, on any architecture.

    scripts/test-static.py dist/x86_64-linux-musl --rust /opt/ssrust \\
        --kat build/x86_64-linux-musl/kat --vectors aws-lc/test \\
        --path hw --path vpaes OPENSSL_ia32cap=~0x1200000200000000:~0x20

Each --path names the AES implementation the startup log must report, then
the environment that forces that code path. For every path, --kat runs the
crypto code's known-answer test (src/vendor/kat.c) on AWS-LC's test vectors,
then every method is sent through ss-local (TCP) and ss-tunnel (UDP) to an
echo server, both against this build's ss-server and, with --rust, against
shadowsocks-rust in both directions. --runner runs the binaries under an
emulator, e.g. "qemu-aarch64-static -cpu max".
"""

import argparse
import os
import shlex
import socket
import struct
import subprocess
import sys
import threading
import time

METHODS = ["aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
           "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "chacha20",
           "none"]
# The ones shadowsocks-rust release builds include
RUST_METHODS = {"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "none"}

HOST = "127.0.0.1"
ECHO_TCP, ECHO_UDP = 18080, 18053
SERVER, SOCKS, TUNNEL = 18388, 18389, 18390
UDP_SIZES = (1, 100, 1300)


def echo_servers():
    tcp = socket.socket()
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((HOST, ECHO_TCP))
    tcp.listen(16)

    def serve(conn):
        with conn:
            while True:
                data = conn.recv(65536)
                if not data:
                    return
                conn.sendall(data)

    def accept():
        while True:
            conn, _ = tcp.accept()
            threading.Thread(target=serve, args=(conn,), daemon=True).start()

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((HOST, ECHO_UDP))

    def bounce():
        while True:
            data, addr = udp.recvfrom(65535)
            udp.sendto(data, addr)

    threading.Thread(target=accept, daemon=True).start()
    threading.Thread(target=bounce, daemon=True).start()


def wait_port(port, proc, what):
    deadline = time.time() + 30
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("%s exited: %s" % (what, proc.stdout.read()))
        try:
            socket.create_connection((HOST, port), timeout=1).close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("%s did not listen on %d" % (what, port))


def tcp_roundtrip(size=1 << 20):
    data = os.urandom(size)
    s = socket.create_connection((HOST, SOCKS), timeout=20)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        raise RuntimeError("socks5 greeting refused")
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(HOST) +
              struct.pack(">H", ECHO_TCP))
    reply = s.recv(10)
    if len(reply) < 2 or reply[1] != 0:
        raise RuntimeError("socks5 connect refused")
    threading.Thread(target=s.sendall, args=(data,), daemon=True).start()
    got = b""
    while len(got) < size:
        chunk = s.recv(65536)
        if not chunk:
            break
        got += chunk
    s.close()
    return got == data


def udp_roundtrip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    for n in UDP_SIZES:
        data = os.urandom(n)
        s.sendto(data, (HOST, TUNNEL))
        try:
            got, _ = s.recvfrom(65535)
        except socket.timeout:
            return False
        if got != data:
            return False
    return True


class Impl:
    def __init__(self, name, server, local, tunnel):
        self.name, self.server, self.local, self.tunnel = \
            name, server, local, tunnel


def libev(bindir, runner):
    pre = shlex.split(runner) if runner else []
    b = lambda n: pre + [os.path.join(bindir, n)]
    return Impl(
        "libev",
        lambda m, k: b("ss-server") + ["-s", HOST, "-p", str(SERVER),
                                       "-k", k, "-m", m, "-u"],
        lambda m, k: b("ss-local") + ["-s", HOST, "-p", str(SERVER),
                                      "-l", str(SOCKS), "-k", k, "-m", m],
        lambda m, k: b("ss-tunnel") + ["-s", HOST, "-p", str(SERVER),
                                       "-l", str(TUNNEL), "-u", "-L",
                                       "%s:%d" % (HOST, ECHO_UDP),
                                       "-k", k, "-m", m])


def rust(bindir):
    remote = ["-s", "%s:%d" % (HOST, SERVER)]
    return Impl(
        "rust",
        lambda m, k: [os.path.join(bindir, "ssserver")] + remote +
        ["-k", k, "-m", m, "-U"],
        lambda m, k: [os.path.join(bindir, "sslocal")] + remote +
        ["-b", "%s:%d" % (HOST, SOCKS), "-k", k, "-m", m],
        lambda m, k: [os.path.join(bindir, "sslocal")] + remote +
        ["--protocol", "tunnel", "-b", "%s:%d" % (HOST, TUNNEL), "-U",
         "-f", "%s:%d" % (HOST, ECHO_UDP), "-k", k, "-m", m])


def start(cmd, env):
    return subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)


def run_pair(srv, cli, method, env):
    key = "test-" + method
    procs = []
    try:
        procs.append(start(srv.server(method, key), env))
        wait_port(SERVER, procs[-1], srv.name + " server")
        procs.append(start(cli.local(method, key), env))
        wait_port(SOCKS, procs[-1], cli.name + " local")
        procs.append(start(cli.tunnel(method, key), env))
        wait_port(TUNNEL, procs[-1], cli.name + " tunnel")
        return tcp_roundtrip(), udp_roundtrip()
    finally:
        for p in procs:
            p.kill()
            p.wait()


def aes_impl(impl, env):
    """The AES implementation the startup log reports"""
    p = start(impl.server("aes-128-gcm", "x"), env)
    try:
        wait_port(SERVER, p, "server")
    finally:
        p.kill()
        out = p.communicate()[0]
    for line in out.splitlines():
        if "crypto: aes " in line:
            return line.split("crypto: aes ")[1].split(",")[0]
    raise RuntimeError("no crypto line in the startup log:\n" + out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bindir")
    ap.add_argument("--runner", default="")
    ap.add_argument("--rust")
    ap.add_argument("--kat")
    ap.add_argument("--vectors")
    ap.add_argument("--path", nargs="+", action="append", required=True,
                    metavar=("AES_IMPL", "VAR=VALUE"))
    args = ap.parse_args()
    if args.kat and not args.vectors:
        ap.error("--kat needs --vectors")

    echo_servers()
    new = libev(args.bindir, args.runner)
    other = rust(args.rust) if args.rust else None
    failed = 0

    for path in args.path:
        expect, assigns = path[0], path[1:]
        env = dict(os.environ)
        env.update(a.split("=", 1) for a in assigns)
        label = " ".join(assigns) or "default"

        if args.kat:
            cmd = shlex.split(args.runner) + [args.kat, args.vectors]
            r = subprocess.run(cmd, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True)
            ok = r.returncode == 0
            failed += not ok
            print("[%s] crypto known answers: %s"
                  % (label, "ok" if ok else "FAIL\n" + r.stdout))

        got = aes_impl(new, env)
        ok = got == expect
        failed += not ok
        print("[%s] aes %s, expected %s: %s"
              % (label, got, expect, "ok" if ok else "FAIL"))

        for m in METHODS:
            pairs = [(new, new)]
            if other and m in RUST_METHODS:
                pairs += [(new, other), (other, new)]
            for srv, cli in pairs:
                tcp, udp = run_pair(srv, cli, m, env)
                ok = tcp and udp
                failed += not ok
                print("  %-24s %s server, %s client: tcp %s, udp %s"
                      % (m, srv.name, cli.name, "ok" if tcp else "FAIL",
                         "ok" if udp else "FAIL"))

    print("FAILED: %d" % failed if failed else "all passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
