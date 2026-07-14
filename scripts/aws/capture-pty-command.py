#!/usr/bin/env python3
"""Run one argv vector in a PTY and copy its merged terminal stream to stdout."""

import errno
import os
import pty
import sys


def main(argv):
    if not argv:
        return 64
    child, master = pty.fork()
    if child == 0:
        try:
            os.execvpe(argv[0], argv, os.environ)
        except OSError:
            os._exit(127)

    read_failed = False
    try:
        while True:
            try:
                chunk = os.read(master, 65536)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                read_failed = True
                break
            if not chunk:
                break
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
    finally:
        os.close(master)

    _, status = os.waitpid(child, 0)
    if read_failed:
        return 125
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return 125


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (BrokenPipeError, OSError):
        raise SystemExit(125)
