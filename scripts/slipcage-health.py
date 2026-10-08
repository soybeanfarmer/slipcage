#!/usr/bin/env python3
"""Bounded read-only VPS health checks and local journal alerts.

No webhooks, guests, workload restarts or alert credentials. Hourly systemd
oneshot emits an ordinary JSON status and a WARNING line only on a change.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

BACKUP_ROOT = Path("/var/backups/slipcage")
DEPLOY_SHA = Path("/var/lib/slipcage/deployed-sha")
GUEST_RUNS = Path("/var/lib/slipcage-guest/runs")
FAULT_RUNS = Path("/var/lib/slipcage-fault")
STATUS = Path("/var/lib/slipcage-health/status.json")
ACTIVE_SERVICES = ("isolab-dagu.service",)
ACTIVE_TIMERS = (
    "slipcage-backup.timer", "slipcage-recover.timer",
    "slipcage-pull-deploy.timer",
)
FAILED_UNITS = (
    "slipcage-backup.service", "slipcage-recover.service",
    "slipcage-pull-deploy.service",
)
BACKUP_PATTERN = re.compile(r"^backup-\d{8}T\d{12}Z$")
GUEST_PATTERN = re.compile(r"^run-\d{8}T\d{12}Z-[a-zA-Z0-9_]+$")
FAULT_PATTERN = re.compile(r"^drill-\d{8}T\d{12}Z-[a-zA-Z0-9_]+$")
SHA_PATTERN = re.compile(r"^[a-f0-9]{40}$")
MIN_FREE_BYTES = 1024 * 1024 * 1024
MAX_USED_PERCENT = 90.0
MAX_BACKUP_AGE_H = 42.0
STALE_H = 24.0
MAX_SCAN = 2000


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def systemctl_state(unit: str, verb: str, *, runner=subprocess.run) -> str:
    if verb not in ("is-active", "is-failed") or unit not in (
        ACTIVE_SERVICES + ACTIVE_TIMERS + FAILED_UNITS
    ):
        raise ValueError("Unsupported systemd probe")
    try:
        r = runner(["/usr/bin/systemctl", verb, unit],
                   text=True, capture_output=True, timeout=6, check=False)
        return r.stdout.strip()[:60]
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"


def backup_check(root: Path, now: datetime) -> dict:
    if root.is_symlink() or not root.is_dir():
        return {"ok": False, "reason": "missing_backup_directory"}
    snapshots = sorted(
        (p for p in root.iterdir() if BACKUP_PATTERN.fullmatch(p.name)
         and not p.is_symlink() and p.is_dir()), key=lambda p: p.name,
        reverse=True,
    )
    if not snapshots:
        return {"ok": False, "reason": "no_completed_backup"}
    latest = snapshots[0]
    try:
        stamp = datetime.strptime(latest.name, "backup-%Y%m%dT%H%M%S%fZ").replace(
            tzinfo=timezone.utc
        )
        age = (now - stamp).total_seconds() / 3600
        manifest = latest / "manifest.json"
        if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > 65536:
            return {"ok": False, "reason": "missing_or_unsafe_manifest",
                    "latest": latest.name}
        # A manifest must be syntactically valid with expected structure;
        # this is NOT a backup checksum verification or restore drill.
        obj = json.loads(manifest.read_text(encoding="utf-8"))
        valid = (isinstance(obj, dict) and obj.get("format") == 1 and
                 set(obj.get("files", {})) == {"research.sqlite3", "reports.tar.gz"})
        if not valid:
            return {"ok": False, "reason": "invalid_manifest",
                    "latest": latest.name}
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {"ok": False, "reason": "unreadable_or_invalid_backup",
                "latest": latest.name}
    return {
        "ok": 0 <= age <= MAX_BACKUP_AGE_H,
        "latest": latest.name,
        "age_hours": round(age, 2),
        "reason": "recent_manifest_present" if 0 <= age <= MAX_BACKUP_AGE_H
                  else "backup_too_old_or_future",
    }


def stale_runs(root: Path, pattern: re.Pattern, now: datetime, *,
               summary_name: str = "summary.json") -> dict:
    if not root.exists():
        return {"stale_count": 0, "scanned": 0, "missing": True}
    if root.is_symlink() or not root.is_dir():
        return {"error": "unsafe_run_root"}
    stale = 0
    scanned = 0
    for path in root.iterdir():
        if not pattern.fullmatch(path.name):
            continue
        scanned += 1
        if scanned > MAX_SCAN:
            return {"error": "too_many_runs_to_scan", "scanned": scanned}
        if path.is_symlink() or not path.is_dir():
            return {"error": "unsafe_run_entry"}
        if not (path / summary_name).is_file():
            try:
                if (now.timestamp() - path.stat().st_mtime) > STALE_H * 3600:
                    stale += 1
            except OSError:
                return {"error": "cannot_stat_run"}
    return {"stale_count": stale, "scanned": scanned}


def inspect(*, now: datetime | None = None, disk_path: Path = Path("/"),
            backup_root: Path = BACKUP_ROOT, deploy_sha: Path = DEPLOY_SHA,
            guest_runs: Path = GUEST_RUNS, fault_runs: Path = FAULT_RUNS,
            unit_probe=systemctl_state, disk_usage=shutil.disk_usage) -> dict:
    now = now or utc_now()
    issues = []
    units = {}
    for unit in ACTIVE_SERVICES + ACTIVE_TIMERS:
        state = unit_probe(unit, "is-active")
        units[unit] = state
        if state != "active":
            issues.append("inactive_unit:" + unit)
    for unit in FAILED_UNITS:
        state = unit_probe(unit, "is-failed")
        units[unit] = state
        if state in ("failed", "unknown"):
            issues.append("failed_or_unknown_unit:" + unit)
    try:
        usage = disk_usage(disk_path)
        used_percent = 100 * (usage.total - usage.free) / usage.total
        disk = {"free_bytes": usage.free, "used_percent": round(used_percent, 2)}
        if usage.free < MIN_FREE_BYTES or used_percent >= MAX_USED_PERCENT:
            issues.append("disk_space_low")
    except (OSError, ValueError, ZeroDivisionError):
        disk = {"error": "disk_usage_unknown"}
        issues.append("disk_usage_unknown")
    try:
        sha = deploy_sha.read_text(encoding="ascii").strip() if not deploy_sha.is_symlink() else ""
        if not SHA_PATTERN.fullmatch(sha):
            raise ValueError("Unrecognized deployed SHA")
    except (OSError, ValueError):
        sha = None
        issues.append("deployment_sha_missing")
    backup = backup_check(backup_root, now)
    if not backup["ok"]:
        issues.append("local_backup:" + backup["reason"])
    guest = stale_runs(guest_runs, GUEST_PATTERN, now)
    fault = stale_runs(fault_runs, FAULT_PATTERN, now)
    for name, value in (("guest", guest), ("fault", fault)):
        if "error" in value:
            issues.append(name + "_artifact_scan_failed")
        elif value["stale_count"]:
            issues.append(name + "_stale_incomplete_artifacts")
    return {
        "schema_version": 1,
        "checked_utc": now.isoformat(),
        "healthy": not issues,
        "issues": sorted(set(issues)),
        "deployed_sha": sha,
        "units": units, "disk": disk,
        "backup": backup, "artifacts": {"guest": guest, "fault": fault},
        "note": ("Checks service state, backup freshness/manifest shape, disk space and "
                 "stale artifacts. Does not restore backups, execute a VM, or send remote alerts."),
    }


def write_status(result: dict, destination: Path = STATUS) -> bool:
    """Store one current snapshot and return whether the issue set changed."""
    if destination.parent.is_symlink() or not destination.parent.is_dir():
        raise ValueError("Health state directory not present or is symlinked")
    if destination.is_symlink():
        raise ValueError("Health state file must not be a symlink")
    previous = None
    if destination.exists():
        try:
            if destination.stat().st_size <= 32768:
                previous = json.loads(destination.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    changed = (not isinstance(previous, dict) or previous.get("issues") != result["issues"])
    fd, name = tempfile.mkstemp(prefix=".health-status-", dir=destination.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(result, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return changed


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--persist", action="store_true",
                        help="Save root-private last status for deduplicated local journal alerts.")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        result = inspect()
        changed = write_status(result) if args.persist else False
    except (OSError, ValueError) as exc:
        print(f"SLIPCAGE_HEALTH_ERROR {type(exc).__name__}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    if changed:
        # systemd collects stderr in local journal. No mail/webhook is configured.
        label = "SLIPCAGE_HEALTH_WARNING" if result["issues"] else "SLIPCAGE_HEALTH_RECOVERED"
        print(label + " " + json.dumps({"issues": result["issues"]}, sort_keys=True),
              file=sys.stderr)
    return 0 if result["healthy"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
