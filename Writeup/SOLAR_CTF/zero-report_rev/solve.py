#!/usr/bin/env python3
"""Zero Report solver.

Usage:
    python3 solve.py                 # build + verify locally, print base64 payload
    python3 solve.py HOST PORT       # build + verify locally, then send to the server

Idea: the server accepts a report (a, b) != (0, 0) with
    (1 - h) * a + h * b = 0  (mod P),   h = sha256(source) mod P.
Take a = h, b = h - 1:  (1-h)h + h(h-1) = 0.
The evaluator resolves H(SOURCE) to exactly that h, so the body is just:
    h = H(SOURCE)
    return [h, h - 1]
"""
import base64
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pack

BODY = "h = H(SOURCE)\nreturn [h, h - 1]\n"


def build() -> bytes:
    return pack.pack(BODY).encode("utf-8")


def verify_local(source: bytes) -> None:
    try:
        import service
    except ImportError:
        print("[!] service.py not next to solve.py, skipping local check")
        return
    report, accepted = service.audit(source)
    print(f"[local] report = {list(report)}")
    print(f"[local] accepted = {accepted}")
    if not accepted:
        raise SystemExit("local verification failed")


def recv_until_idle(s: socket.socket, stop: bytes = b"") -> bytes:
    """Read until EOF, until `stop` appears at the end, or until the socket times out."""
    buf = b""
    try:
        while not (stop and buf.endswith(stop)):
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    return buf


def talk(host: str, port: int, payload: str, idle: float = 10.0) -> str:
    print(f"[net] connecting to {host}:{port} ...")
    with socket.create_connection((host, port), timeout=15) as s:
        s.settimeout(idle)
        banner = recv_until_idle(s, stop=b"> ")
        if banner:
            print(banner.decode(errors="replace"), end="", flush=True)
        else:
            print(f"[!] no banner within {idle:.0f}s - wrong host/port? sending anyway")
        s.sendall(payload.encode() + b"\n")
        out = recv_until_idle(s)
        if not out:
            return "<empty reply: check host/port, or the service is not this auditor>"
        return out.decode(errors="replace")


def main() -> None:
    source = build()
    verify_local(source)
    payload = base64.b64encode(source).decode()
    if len(sys.argv) == 3:
        port_arg = sys.argv[2]
        if port_arg.startswith("0") and len(port_arg) > 1:
            print(f"[!] port '{port_arg}' has a leading zero and is parsed as {int(port_arg)}")
        print("\n[server] response:", talk(sys.argv[1], int(port_arg), payload))
    else:
        print("[payload]", payload)


if __name__ == "__main__":
    main()