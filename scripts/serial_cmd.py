#!/usr/bin/env python3
"""Log in via QEMU's unix-socket serial console and run a shell command.

Usage: python3 serial_cmd.py 'command args'
Reads login creds from env: SERIAL_USER (root), SERIAL_PASS (quickfw).

Writes all raw console traffic to /var/log/quickfw-qemu/serial.log
as a side effect (append mode).
"""
import os
import socket
import sys
import time
import re

SOCK = os.environ.get("SERIAL_SOCK", "/run/quickfw-qemu.serial")
LOGFILE = os.environ.get("SERIAL_LOG", "/var/log/quickfw-qemu/serial.log")
USER = os.environ.get("SERIAL_USER", "root")
PASSWORD = os.environ.get("SERIAL_PASS", "quickfw")
TIMEOUT_SECS = 60

ANSI_RE = re.compile(rb"\x1b\[[0-9;?]*[a-zA-Z]")


def strip_ansi(b: bytes) -> bytes:
    return ANSI_RE.sub(b"", b).replace(b"\r", b"")


def read_until(sock, pattern: bytes, timeout=TIMEOUT_SECS, log=None) -> bytes:
    """Read from sock until pattern appears (or timeout). Returns accumulated bytes."""
    buf = b""
    deadline = time.monotonic() + timeout
    sock.settimeout(2)
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                time.sleep(0.1)
                continue
            if log:
                log.write(chunk)
                log.flush()
            buf += chunk
            if pattern in strip_ansi(buf):
                return buf
        except socket.timeout:
            continue
    return buf


def send(sock, data: bytes, log=None):
    sock.sendall(data)
    if log:
        log.write(b"\n>>> " + data + b"\n")
        log.flush()


def main():
    if len(sys.argv) < 2:
        print("usage: serial_cmd.py 'cmd'", file=sys.stderr)
        sys.exit(2)
    cmd = sys.argv[1]

    log = open(LOGFILE, "ab")

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(SOCK)

    # Wake the console
    send(sock, b"\r\n", log)

    # Wait for login prompt
    buf = read_until(sock, b"login:", timeout=15, log=log)
    if b"login:" not in strip_ansi(buf):
        # Maybe already logged in (prompt shows $ or #)
        pass
    else:
        send(sock, USER.encode() + b"\r\n", log)
        read_until(sock, b"Password:", timeout=10, log=log)
        send(sock, PASSWORD.encode() + b"\r\n", log)

    # Wait for shell prompt (# or $ at end of line)
    # QuickFW drops root into bash by default; look for "# " or "$ "
    marker = b"__CMDMARKER_%s__" % os.urandom(4).hex().encode()
    # Wait a moment for login motd, then send an echo marker
    time.sleep(1)
    send(sock, b"\r\n", log)
    time.sleep(0.3)
    send(sock, b"echo " + marker + b"\r\n", log)
    read_until(sock, marker, timeout=15, log=log)

    # Send the real command and a trailing echo-marker
    end_marker = b"__END_%s__" % os.urandom(4).hex().encode()
    full_cmd = cmd.encode() + b"; echo " + end_marker + b"\r\n"
    send(sock, full_cmd, log)
    buf = read_until(sock, end_marker, timeout=120, log=log)

    # Extract output between the command echo and the end_marker
    text = strip_ansi(buf).decode("utf-8", errors="replace")
    # Find end marker
    idx = text.rfind(end_marker.decode())
    if idx >= 0:
        text = text[:idx]
    # Trim to after last instance of the full_cmd echo
    lines = text.splitlines()
    # Print raw captured
    print("\n".join(lines))

    sock.close()
    log.close()


if __name__ == "__main__":
    main()
