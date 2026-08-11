#!/usr/bin/env python3
"""Run ECS Exec through a PTY and send a fixture only after the remote ready marker."""

import errno
import os
import pty
import select
import signal
import sys
import time


READY = b"MSCQR_FIXTURE_READY"


def stop(child, sig):
    try:
        os.killpg(child, sig)
    except ProcessLookupError:
        pass
    except PermissionError:
        try:
            os.kill(child, sig)
        except ProcessLookupError:
            pass


def main(argv):
    if len(argv) < 7 or argv[0] != "--input-file" or argv[4] != "--":
        return 64
    input_path = argv[1]
    try:
        timeout = float(argv[2])
        output_limit = int(argv[3])
    except ValueError:
        return 64
    command = argv[5:]
    if not command or not 0.05 <= timeout <= 900 or not 256 <= output_limit <= 32 * 1024 * 1024:
        return 64
    try:
        fixture = open(input_path, "rb").read()
    except OSError:
        return 66

    child, master = pty.fork()
    if child == 0:
        try:
            os.execvpe(command[0], command, os.environ)
        except OSError:
            os._exit(127)

    deadline = time.monotonic() + timeout
    output = bytearray()
    sent = False
    status = None
    failure = None
    try:
        while True:
            if time.monotonic() >= deadline:
                failure = 124
                break
            readable, _, _ = select.select([master], [], [], min(0.25, deadline - time.monotonic()))
            if readable:
                try:
                    chunk = os.read(master, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        chunk = b""
                    else:
                        failure = 125
                        break
                if chunk:
                    output.extend(chunk)
                    if len(output) > output_limit:
                        failure = 126
                        break
                    if not sent and READY in output:
                        os.write(master, fixture)
                        os.write(master, b"\x04")
                        sent = True
                else:
                    break
            waited, wait_status = os.waitpid(child, os.WNOHANG)
            if waited:
                status = wait_status
                break
        if status is None:
            stop(child, signal.SIGTERM)
            _, status = os.waitpid(child, 0)
    finally:
        try:
            os.close(master)
        except OSError:
            pass

    if not sent or fixture in output:
        return 125
    if failure is not None:
        return failure
    sys.stdout.buffer.write(output)
    sys.stdout.buffer.flush()
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return 125


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
