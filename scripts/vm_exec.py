#!/usr/bin/env python3
"""Execute a shell command on the firewall VM over SSH with password auth.

Usage:
  python vm_exec.py "command..."
  echo "local stdin" | python vm_exec.py "cmd reading stdin"

Output: writes remote stdout+stderr to local stdout; exit code matches remote.
"""
import sys
import paramiko

HOST = "172.16.60.145"
USER = "root"
PASSWORD = "tBUHvA8MzZ5wPBYQb9gm"

def main() -> int:
    if len(sys.argv) < 2:
        print("usage: vm_exec.py 'remote command'", file=sys.stderr)
        return 2

    cmd = sys.argv[1]
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=HOST,
            username=USER,
            password=PASSWORD,
            timeout=15,
            look_for_keys=False,
            allow_agent=False,
        )
    except Exception as e:
        print(f"SSH connect failed: {e}", file=sys.stderr)
        return 1

    try:
        stdin, stdout, stderr = client.exec_command(cmd, timeout=1800, get_pty=False)
        # Pipe local stdin to remote if present
        if not sys.stdin.isatty():
            try:
                data = sys.stdin.buffer.read()
                if data:
                    stdin.write(data)
                    stdin.flush()
            except Exception:
                pass
        stdin.channel.shutdown_write()

        # Stream output
        while True:
            if stdout.channel.recv_ready():
                chunk = stdout.channel.recv(65536)
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
            if stdout.channel.recv_stderr_ready():
                chunk = stdout.channel.recv_stderr(65536)
                sys.stderr.buffer.write(chunk)
                sys.stderr.buffer.flush()
            if stdout.channel.exit_status_ready() and not stdout.channel.recv_ready() and not stdout.channel.recv_stderr_ready():
                break

        exit_code = stdout.channel.recv_exit_status()
        # Drain any remaining
        rest = stdout.read()
        if rest:
            sys.stdout.buffer.write(rest)
        rest_err = stderr.read()
        if rest_err:
            sys.stderr.buffer.write(rest_err)
        return exit_code
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
