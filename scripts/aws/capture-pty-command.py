#!/usr/bin/env python3
"""Run one argv vector in a PTY and copy its merged terminal stream to stdout."""

import errno
import math
import os
import pty
import select
import signal
import sys
import time


def wait_until(child, deadline, interrupted=None):
    while True:
        try:
            waited, status = os.waitpid(child, os.WNOHANG)
        except ChildProcessError:
            return 0
        if waited:
            return status
        if interrupted and interrupted[0] is not None:
            return None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        time.sleep(min(0.05, remaining))


def terminate_and_wait(child):
    status = wait_until(child, time.monotonic())
    if status is not None:
        return status
    signal_child(child, signal.SIGTERM)
    status = wait_until(child, time.monotonic() + 5)
    if status is not None:
        return status
    signal_child(child, signal.SIGKILL)
    try:
        return os.waitpid(child, 0)[1]
    except ChildProcessError:
        return 0


def signal_child(child, child_signal):
    try:
        os.killpg(child, child_signal)
        return
    except ProcessLookupError:
        return
    except PermissionError:
        pass
    try:
        os.kill(child, child_signal)
    except ProcessLookupError:
        pass


def main(argv):
    if len(argv) < 4 or argv[2] != "--":
        return 64
    try:
        timeout = float(argv[0])
        output_limit = int(argv[1])
    except ValueError:
        return 64
    if not math.isfinite(timeout) or not 0.05 <= timeout <= 900 or not 256 <= output_limit <= 32 * 1024 * 1024:
        return 64

    command = argv[3:]
    child, master = pty.fork()
    if child == 0:
        try:
            os.execvpe(command[0], command, os.environ)
        except OSError:
            os._exit(127)

    deadline = time.monotonic() + timeout
    failure = None
    status = None
    received_signal = [None]
    handled_signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    previous_handlers = {}
    output_size = 0
    try:
        for name in handled_signals:
            previous_handlers[name] = signal.signal(name, lambda received, _frame: received_signal.__setitem__(0, received))
        while True:
            if received_signal[0] is not None:
                failure = 128 + received_signal[0]
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = 124
                break
            readable, _, _ = select.select([master], [], [], min(0.25, remaining))
            if not readable:
                continue
            try:
                chunk = os.read(master, 65536)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                failure = 125
                break
            if not chunk:
                break
            output_size += len(chunk)
            if output_size > output_limit:
                failure = 126
                break
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
        if failure is None:
            status = wait_until(child, deadline, received_signal)
            if received_signal[0] is not None:
                failure = 128 + received_signal[0]
            elif status is None:
                failure = 124
    except Exception:
        failure = 125
    finally:
        try:
            os.close(master)
        except OSError:
            pass
        if status is None:
            terminate_and_wait(child)
        for name, handler in previous_handlers.items():
            signal.signal(name, handler)

    if failure is not None:
        return failure
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return 125


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception:
        raise SystemExit(125)
