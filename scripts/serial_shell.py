#!/usr/bin/env python3
"""Minimal serial-console driver.

Reads a sequence of lines from stdin. Each line is written to the serial
socket with \r\n. After the last line, keeps reading output for OUTPUT_WAIT
seconds then prints everything captured since the script started.

Usage: echo -e 'cmd1\ncmd2' | python3 serial_shell.py
       python3 serial_shell.py < commands.txt
"""
import os
import socket
import sys
import time
import re
import selectors

SOCK = os.environ.get("SERIAL_SOCK", "/run/quickfw-qemu.serial")
USER = os.environ.get("SERIAL_USER", "root")
PASSWORD = os.environ.get("SERIAL_PASS", "quickfw")
OUTPUT_WAIT = float(os.environ.get("OUTPUT_WAIT", "8"))
LOGIN_WAIT = float(os.environ.get("LOGIN_WAIT", "20"))

ANSI = re.compile(rb"\x1b\[[0-9;?]*[a-zA-Z]")


def strip_ansi(b):
    return ANSI.sub(b"", b).replace(b"\r", b"")


def drain(sock, secs):
    """Read anything available within `secs` seconds and return bytes."""
    buf = b""
    sel = selectors.DefaultSelector()
    sel.register(sock, selectors.EVENT_READ)
    deadline = time.monotonic() + secs
    while time.monotonic() < deadline:
        for _, _ in sel.select(timeout=0.3):
            try:
                chunk = sock.recv(8192)
                if chunk:
                    buf += chunk
            except BlockingIOError:
                pass
    return buf


def main():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(SOCK)
    sock.setblocking(False)

    # Wake and read banner
    sock.send(b"\r")
    time.sleep(0.5)
    banner = drain(sock, 1.0)
    stripped = strip_ansi(banner)

    if b"login:" in stripped:
        sock.send(USER.encode() + b"\r")
        drain(sock, 1.5)
        sock.send(PASSWORD.encode() + b"\r")
        drain(sock, LOGIN_WAIT)

    # Send each command line from stdin
    lines = sys.stdin.read().splitlines()
    all_output = b""
    for line in lines:
        if not line.strip():
            continue
        sock.send(line.encode() + b"\r")
        chunk = drain(sock, OUTPUT_WAIT)
        all_output += chunk

    print(strip_ansi(all_output).decode("utf-8", errors="replace"))
    sock.close()


if __name__ == "__main__":
    main()
