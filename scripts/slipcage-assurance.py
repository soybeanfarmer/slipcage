#!/usr/bin/env python3
"""Weekly bounded, local-only SQLite/report backup restore assurance.

Restores only to a disposable dedicated cache directory. No writes to the
live research database, reports or backup source; no offsite transport.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile

BACKUPS = Path("/var/backups/slipcage")
SCRATCH = Path("/var/cache/slipcage-assurance")
STATUS_DIR = Path("/var/lib/slipcage-assurance")
BACKUP_NAME = re.compile(r"^backup-\d{8}T\d{12}Z$")
MAX_DB_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MIN_FREE_MARGIN = 2 * 1024 * 1024 * 1024
MAX_BACKUPS_TO_SCAN = 90


def backup_latest(root: Path) -> Path:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Unsafe or unavailable local backup directory")
    names = [p for p in root.iterdir() if BACKUP_NAME.fullmatch(p.name)]
    if len(names) > MAX_BACKUPS_TO_SCAN:
        raise ValueError("Too many backup candidates")
    for candidate in sorted(names, key=lambda p: p.name, reverse=True):
        if not candidate.is_symlink() and candidate.is_dir():
            return candidate
    raise ValueError("No completed local backup found")


def regular_size(path: Path, maximum: int) -> int:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > maximum:
        raise ValueError(f"Unsafe or oversized backup artifact: {path.name}")
    return info.st_size


def atomic_status(destination: Path, value: dict) -> None:
    fd, name = tempfile.mkstemp(prefix=".assurance-", dir=destination.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(value, out, sort_keys=True, indent=2)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def check(*, backups: Path = BACKUPS, scratch: Path = SCRATCH,
          state: Path = STATUS_DIR, drill_fn=None,
          disk_usage=shutil.disk_usage) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    if any(p.is_symlink() or not p.is_dir() for p in (scratch, state)):
        raise ValueError("Assurance cache/state must exist as real directories")
    if drill_fn is None:
        from importlib.machinery import SourceFileLoader
        script = Path("/usr/local/sbin/slipcage-restore-check")
        if not script.is_file():
            script = Path(__file__).resolve().parent / "slipcage-restore-check.py"
        loader = SourceFileLoader("assurance_restore", str(script))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        drill_fn = mod.drill
    # Serializes scheduled and operator-started checks, not regular backups.
    with (state / ".assurance.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        source = None
        try:
            source = backup_latest(backups)
            db_bytes = regular_size(source / "research.sqlite3", MAX_DB_BYTES)
            archive_bytes = regular_size(source / "reports.tar.gz", MAX_ARCHIVE_BYTES)
            regular_size(source / "manifest.json", 64 * 1024)
            required = MIN_FREE_MARGIN + 2 * (db_bytes + archive_bytes)
            if disk_usage(scratch).free < required:
                raise ValueError("Insufficient free space for a disposable restore")
            # A private, unique, disposable stage is created only after all gates.
            # Always clean this exact temporary path after the drill (not arbitrary old dirs).
            with tempfile.TemporaryDirectory(prefix="check-", dir=scratch) as directory:
                destination = Path(directory) / "restored"
                result = drill_fn(source, destination)
                if result.get("verified") is not True or result.get("live_data_modified") is not False:
                    raise ValueError("Restore drill reported incomplete validation")
                if not destination.is_dir() or destination.is_symlink():
                    raise ValueError("Restore drill did not produce a private destination")
                report = {
                    "schema_version": 1, "checked_utc": now,
                    "passed": True, "latest_backup": source.name,
                    "candidates": result.get("candidates"),
                    "reports": result.get("reports"),
                    "live_data_modified": False,
                    "note": "Scratch restore confirmed. Backup remains local to this VPS.",
                }
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            report = {
                "schema_version": 1, "checked_utc": now,
                "passed": False,
                "latest_backup": source.name if source is not None else None,
                "reason": type(exc).__name__,
                "live_data_modified": False,
            }
        atomic_status(state / "status.json", report)
        return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    os.umask(0o077)
    try:
        report = check()
    except (OSError, ValueError, BlockingIOError) as exc:
        print("SLIPCAGE_ASSURANCE_ERROR " + type(exc).__name__, file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
