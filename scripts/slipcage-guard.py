#!/usr/bin/env python3
"""Gate deployment against active research processes with POSIX advisory locks."""
from __future__ import annotations
import argparse
import fcntl
import os
from pathlib import Path
import sys
import time

STATE = Path("/var/lib/slipcage")


def paths(state):
    return state / "deployment.lock", state / "maintenance"


def run(state, command):
    if not command:
        raise ValueError("run requires a command")
    lock, marker = paths(state)
    fd = os.open(lock, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_SH)
        if marker.exists():
            print("Maintenance active: deferring research (exit 75)", file=sys.stderr)
            return 75
        os.set_inheritable(fd, True)
        os.execvp(command[0], command)
    finally:
        os.close(fd)


def begin(state, wait):
    if wait < 0:
        raise ValueError("wait must be nonnegative")
    lock, marker = paths(state)
    fd = os.open(lock, os.O_RDONLY)
    created = False
    try:
        with os.fdopen(os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644), "w") as out:
            out.write(f"pid={os.getpid()} time={time.time()}\n")
        created = True
        deadline = time.monotonic() + wait
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                print("Research drained; safe to deploy.")
                return 0
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("drain timed out; installed files unchanged")
                time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    except TimeoutError:
        if created:
            marker.unlink()
        raise
    finally:
        os.close(fd)


def end(state):
    lock, marker = paths(state)
    fd = os.open(lock, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        if not marker.exists():
            raise ValueError("no maintenance marker")
        marker.unlink()
        print("Maintenance released.")
        return 0
    finally:
        os.close(fd)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--state-dir", type=Path, default=STATE)
    subs = p.add_subparsers(dest="cmd", required=True)
    begin_cmd = subs.add_parser("begin")
    begin_cmd.add_argument("--wait-seconds", type=float, default=3600)
    subs.add_parser("end")
    subs.add_parser("run").add_argument("command", nargs=argparse.REMAINDER)
    a = p.parse_args()
    try:
        if a.cmd == "begin":
            return begin(a.state_dir, a.wait_seconds)
        if a.cmd == "end":
            return end(a.state_dir)
        if a.cmd == "run":
            argv = a.command[1:] if a.command[:1] == ["--"] else a.command
            return run(a.state_dir, argv)
    except (OSError, ValueError, TimeoutError) as exc:
        print(f"slipcage-guard: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
