#!/usr/bin/env python3
"""Consistent SQLite snapshots and bounded local report backups for Slipcage.

No writes to the live research database; no archive extraction during verification.
Backups on the same VPS are NOT disaster recovery against loss of that VPS.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import stat
import sys
import tarfile
import tempfile
from urllib.parse import quote

DEFAULT_DB = Path("/srv/isolab/research.sqlite3")
DEFAULT_REPORTS = Path("/srv/isolab/reports")
DEFAULT_DEST = Path("/var/backups/slipcage")
BACKUP_NAME = re.compile(r"^backup-\d{8}T\d{12}Z$")
MAX_REPORT_BYTES = 128 * 1024 * 1024
MAX_REPORTS_TOTAL = 512 * 1024 * 1024
FREE_MARGIN = 256 * 1024 * 1024


def digest(path: Path) -> dict:
    h = hashlib.sha256()
    length = 0
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            h.update(block)
            length += len(block)
    return {"sha256": h.hexdigest(), "bytes": length}


def readonly_connection(path: Path):
    uri = "file:" + quote(str(path.resolve()), safe="/") + "?mode=ro"
    return sqlite3.connect(uri, uri=True, timeout=30)


def check_sqlite(path: Path) -> int:
    with readonly_connection(path) as conn:
        check = conn.execute("PRAGMA integrity_check").fetchone()
        if not check or check[0] != "ok":
            raise ValueError("SQLite backup did not pass integrity_check")
        # A recovered snapshot must be readable as a Slipcage database.
        return int(conn.execute("SELECT COUNT(*) FROM candidates").fetchone()[0])


def report_files(reports: Path) -> list[Path]:
    if not reports.is_dir() or reports.is_symlink():
        raise ValueError("Reports directory missing or symlinked")
    files = []
    total = 0
    # Reports are flat in v0.2; fail loudly if the structure changes.
    for path in sorted(reports.iterdir()):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"Unsupported report entry (not regular file): {path.name}")
        if info.st_size > MAX_REPORT_BYTES:
            raise ValueError(f"Report exceeds 128 MiB backup limit: {path.name}")
        total += info.st_size
        if total > MAX_REPORTS_TOTAL:
            raise ValueError("Reports exceed the 512 MiB local backup limit")
        files.append(path)
    return files


def archive_reports(reports: Path, files: list[Path], archive: Path) -> int:
    with tarfile.open(archive, "w:gz") as out:
        for path in files:
            # Refuse symlinks swapped into place after directory enumeration.
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT_BYTES:
                    raise ValueError(f"Report is no longer a supported regular file: {path.name}")
                item = tarfile.TarInfo("reports/" + path.name)
                item.size = info.st_size
                item.mtime = int(info.st_mtime)
                item.mode = 0o600
                out.addfile(item, stream)
    return len(files)


def verify_backup(backup: Path) -> dict:
    if not backup.is_dir() or backup.is_symlink():
        raise ValueError("Backup directory missing or symlinked")
    manifest = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("format") != 1 or set(manifest.get("files", {})) != {
        "research.sqlite3", "reports.tar.gz"
    }:
        raise ValueError("Unsupported backup manifest")
    for name, expected in manifest["files"].items():
        file = backup / name
        if not file.is_file() or file.is_symlink() or digest(file) != expected:
            raise ValueError(f"Backup checksum/size mismatch: {name}")
    if check_sqlite(backup / "research.sqlite3") != manifest.get("candidates"):
        raise ValueError("SQLite snapshot count differs from manifest")

    count = 0
    with tarfile.open(backup / "reports.tar.gz", "r:gz") as archive:
        names = set()
        for member in archive:
            p = PurePosixPath(member.name)
            if (not member.isfile() or len(p.parts) != 2 or p.parts[0] != "reports"
                    or p.parts[1] in ("", ".", "..") or member.name in names
                    or member.size > MAX_REPORT_BYTES):
                raise ValueError("Invalid entry in archived reports")
            names.add(member.name)
            reader = archive.extractfile(member)
            if reader is None:
                raise ValueError("Unreadable archived report")
            with reader:
                while reader.read(1024 * 1024):
                    pass
            count += 1
    if count != manifest.get("report_count"):
        raise ValueError("Report count differs from backup manifest")
    return {"backup": str(backup), "candidates": manifest["candidates"],
            "reports": count, "verified": True}


def prune(destination: Path, keep: int) -> int:
    completed = sorted(
        (p for p in destination.iterdir()
         if p.is_dir() and not p.is_symlink() and BACKUP_NAME.fullmatch(p.name)),
        key=lambda p: p.name, reverse=True,
    )
    for old in completed[keep:]:
        shutil.rmtree(old)
    return max(0, len(completed) - keep)


def create_backup(db: Path, reports: Path, destination: Path, *,
                  keep: int = 14, now: datetime | None = None) -> dict:
    if not (1 <= keep <= 90):
        raise ValueError("Backup retention must be between 1 and 90 snapshots")
    if not db.is_file() or db.is_symlink():
        raise ValueError(f"Research database missing or symlinked: {db}")
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    if destination.is_symlink():
        raise ValueError("Backup destination must not be a symlink")
    os.chmod(destination, 0o700)
    with (destination / ".backup.lock").open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        files = report_files(reports)
        estimated = db.stat().st_size + sum(p.stat().st_size for p in files)
        if shutil.disk_usage(destination).free < (estimated + FREE_MARGIN):
            raise ValueError("Insufficient free disk for safe local backup")
        moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        final = destination / ("backup-" + moment.strftime("%Y%m%dT%H%M%S%fZ"))
        if final.exists():
            raise FileExistsError(f"Backup already exists: {final}")
        stage = Path(tempfile.mkdtemp(dir=destination, prefix=".incomplete-"))
        try:
            with readonly_connection(db) as source:
                with sqlite3.connect(stage / "research.sqlite3", timeout=30) as snapshot:
                    source.backup(snapshot, pages=100, sleep=0.1)
            candidates = check_sqlite(stage / "research.sqlite3")
            count = archive_reports(reports, files, stage / "reports.tar.gz")
            manifest = {
                "format": 1,
                "created_utc": moment.isoformat(),
                "candidates": candidates,
                "report_count": count,
                "files": {name: digest(stage / name)
                          for name in ("research.sqlite3", "reports.tar.gz")},
            }
            (stage / "manifest.json").write_text(
                json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            os.chmod(stage, 0o700)
            result = verify_backup(stage)
            os.replace(stage, final)  # Publish only a fully verified set.
            result["backup"] = str(final)
        except BaseException:
            shutil.rmtree(stage, ignore_errors=True)
            raise
        result["pruned"] = prune(destination, keep)  # Never prune on backup failure.
        return result


def main(argv=None):
    cli = argparse.ArgumentParser(description=__doc__)
    commands = cli.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--db", type=Path, default=DEFAULT_DB)
    create.add_argument("--reports", type=Path, default=DEFAULT_REPORTS)
    create.add_argument("--destination", type=Path, default=DEFAULT_DEST)
    create.add_argument("--keep", type=int, default=14)
    verify = commands.add_parser("verify")
    verify.add_argument("backup_dir", type=Path)
    args = cli.parse_args(argv)
    os.umask(0o077)
    try:
        if args.command == "create":
            result = create_backup(args.db, args.reports, args.destination,
                                   keep=args.keep)
        else:
            result = verify_backup(args.backup_dir)
    except (OSError, sqlite3.Error, ValueError, tarfile.TarError, json.JSONDecodeError) as exc:
        print(f"slipcage-backup: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
