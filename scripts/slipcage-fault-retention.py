#!/usr/bin/env python3
"""Conservative preview-only-by-default pruning of completed synthetic fault drills.

Never accesses /var/backups/slipcage or /var/lib/slipcage-guest. Cleanup
requires explicit --apply and --confirm, is locked, and fails closed on
symlinks, unexpected files, incomplete runs, or modified candidates.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys

DEFAULT_STATE = Path("/var/lib/slipcage-fault")
NAME = re.compile(r"^drill-\d{8}T\d{12}Z-[a-zA-Z0-9_]+$")
KEEP_LATEST = 20
MIN_AGE_DAYS = 30
MAX_FILES = 32
MAX_BYTES = 1024 * 1024
MAX_DIRECTORIES = 2000
MODES = ("timeout", "report", "limits", "all")
EXPECTED_FILES = {"summary.json", "timeout.json", "report.json", "limits.json"}
ALLOWED_NESTED = {"fixture-state"}


def scan_tree(directory: Path) -> tuple[int, int]:
    """Return file count and size for an expected complete fixture tree."""
    files = 0
    size = 0
    for root, dirs, names in os.walk(directory, followlinks=False):
        current = Path(root)
        if current.is_symlink():
            raise ValueError("Symlinked directory rejected")
        for name in dirs:
            p = current / name
            if p.is_symlink() or not p.is_dir():
                raise ValueError("Non-directory or symlinked child rejected")
        for name in names:
            p = current / name
            info = p.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("Non-regular file rejected")
            files += 1
            size += info.st_size
            if files > MAX_FILES or size > MAX_BYTES:
                raise ValueError("Overlarge or unrecognized drill data rejected")
    return files, size


def inspect_candidate(directory: Path) -> dict | None:
    if directory.is_symlink() or not directory.is_dir() or not NAME.fullmatch(directory.name):
        return None
    summary_path = directory / "summary.json"
    if summary_path.is_symlink() or not summary_path.is_file():
        return None
    try:
        if summary_path.stat().st_size > 32768:
            return None
        info = json.loads(summary_path.read_text(encoding="utf-8"))
        if (not isinstance(info, dict) or info.get("mode") not in MODES
                or info.get("passed") is not True
                or info.get("live_data_modified") is not False
                or info.get("qemu_started") is not False
                or info.get("run_dir") != str(directory)):
            return None
        if not isinstance(info.get("results"), list) or not info["results"] or not all(
            isinstance(item, dict) and item.get("passed") is True
            for item in info["results"]
        ):
            return None
        files = {x.name for x in directory.iterdir()}
        if not {"summary.json"}.issubset(files) or not files.issubset(
            EXPECTED_FILES | ALLOWED_NESTED
        ):
            return None
        count, bytes_used = scan_tree(directory)
        return {"run": directory.name, "files": count, "bytes": bytes_used,
                "summary_sha256": __import__("hashlib").sha256(
                    summary_path.read_bytes()
                ).hexdigest()}
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None


def eligible(state: Path, *, now: datetime) -> dict:
    if state.is_symlink() or not state.is_dir():
        raise ValueError("Unsafe or absent fault-drill state directory")
    entries = [p for p in state.iterdir() if NAME.fullmatch(p.name)]
    if len(entries) > MAX_DIRECTORIES:
        raise ValueError("Too many drill entries for conservative cleanup")
    complete = []
    skipped = 0
    for item in sorted(entries, key=lambda p: p.name, reverse=True):
        info = inspect_candidate(item)
        if info is None:
            skipped += 1
        else:
            complete.append(info)
    old = []
    for record in complete[KEEP_LATEST:]:
        item = state / record["run"]
        # Use directory creation timestamp encoded in reviewed name, not mtime.
        stamp = record["run"].split("-")[1].split("Z")[0] + "Z"
        when = datetime.strptime(stamp, "%Y%m%dT%H%M%S%fZ").replace(
            tzinfo=timezone.utc
        )
        if (now - when).total_seconds() >= MIN_AGE_DAYS * 86400:
            old.append(record)
    return {"eligible": old, "completed": len(complete), "skipped": skipped,
            "retained_minimum": KEEP_LATEST, "minimum_age_days": MIN_AGE_DAYS}


def cleanup(*, state: Path = DEFAULT_STATE, apply: bool = False,
            confirm: bool = False, now: datetime | None = None) -> dict:
    if apply and not confirm:
        raise ValueError("Applying cleanup requires --confirm")
    if state.is_symlink() or not state.is_dir():
        raise ValueError("Unsafe or absent fault-drill state directory")
    lock = state / ".drill.lock"
    if lock.is_symlink():
        raise ValueError("Symlinked drill lock")
    # The reviewed existing fault drill uses the same lock.
    with lock.open("a+b") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        plan = eligible(state, now=now or datetime.now(timezone.utc))
        deleted = []
        if apply:
            for entry in plan["eligible"]:
                directory = state / entry["run"]
                # Recheck the full candidate before any deletion.
                if inspect_candidate(directory) != entry:
                    raise ValueError("Candidate changed after preview")
                shutil.rmtree(directory)
                deleted.append(entry["run"])
        return {"mode": "apply" if apply else "dry_run",
                "eligible_count": len(plan["eligible"]),
                "candidates": [x["run"] for x in plan["eligible"]],
                "deleted": deleted, "completed_seen": plan["completed"],
                "skipped_incomplete_or_unsafe": plan["skipped"],
                "minimum_age_days": plan["minimum_age_days"],
                "retained_minimum": plan["retained_minimum"],
                "scope": "completed_successful_fault_drills_only",
                "note": "No guest evidence, failed drill, backup or active run is deleted."}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm", action="store_true",
                        help="Explicit confirmation for deleting eligible old successful synthetic drills.")
    args = parser.parse_args(argv)
    try:
        result = cleanup(apply=args.apply, confirm=args.confirm)
    except (OSError, ValueError, BlockingIOError) as exc:
        print(f"slipcage-fault-retention: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
