#!/usr/bin/env python3
"""Read-only audit of bounded disposable-guest run artifacts (no VM execution).

Status is inferred from local artifacts, not independently authenticated:
checksums are reproducible fingerprints, not signatures or security proofs.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import statistics
import sys

DEFAULT_STATE = Path("/var/lib/slipcage-guest")
RUN_NAME = re.compile(r"^run-\d{8}T\d{12}Z-[a-zA-Z0-9_]+$")
MAX_RECORD_BYTES = 64 * 1024
MAX_LOG_BYTES = 64 * 1024
MAX_RUNS = 20
MODES = ("fixed_arithmetic_sha256_v1", "benign_diskless_guest_lifecycle")


class EvidenceError(Exception):
    pass


def regular_file(path: Path, max_bytes: int) -> bool:
    try:
        mode = path.lstat().st_mode
        return (stat.S_ISREG(mode) and 0 <= path.lstat().st_size <= max_bytes)
    except OSError:
        return False


def read_bytes(path: Path, max_bytes: int) -> bytes:
    if not regular_file(path, max_bytes):
        raise EvidenceError(f"Missing, unsafe or oversized file: {path.name}")
    try:
        # NOFOLLOW prevents racing a checked filename into a symlink.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as file:
            if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
                raise EvidenceError(f"Not a regular file: {path.name}")
            data = file.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise EvidenceError(f"Oversized file: {path.name}")
            return data
    except OSError as exc:
        raise EvidenceError(f"Unable to read {path.name}: {type(exc).__name__}") from exc


def read_json(path: Path) -> tuple[dict, str]:
    data = read_bytes(path, MAX_RECORD_BYTES)
    try:
        obj = json.loads(data)
    except (UnicodeDecodeError, ValueError) as exc:
        raise EvidenceError(f"Invalid JSON: {path.name}") from exc
    if not isinstance(obj, dict):
        raise EvidenceError(f"Expected JSON object: {path.name}")
    return obj, hashlib.sha256(data).hexdigest()


def numeric(value) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def audit_run(directory: Path, *, lock_held: bool = False) -> dict:
    name = directory.name
    report = {
        "run": name, "status": "inconsistent_evidence",
        "mode": None, "requested_cycles": None, "completed_cycles": 0,
        "successful_cycles": 0, "issues": [], "artifacts": [],
        "resource_statistics": None, "manifest_present": False,
    }
    if directory.is_symlink() or not directory.is_dir() or not RUN_NAME.fullmatch(name):
        report["issues"].append("unsafe_run_directory")
        return report

    summary_path = directory / "summary.json"
    manifest = directory / "run.json"
    if regular_file(manifest, MAX_RECORD_BYTES):
        try:
            header, digest = read_json(manifest)
            report["manifest_present"] = True
            report["artifacts"].append({"name": "run.json", "sha256": digest})
            if header.get("schema_version") != 1 or header.get("profile") not in ("boot", "experiment"):
                report["issues"].append("invalid_run_manifest")
        except EvidenceError:
            report["issues"].append("invalid_run_manifest")
    elif manifest.exists() or manifest.is_symlink():
        report["issues"].append("unsafe_run_manifest")

    if not summary_path.exists() and not summary_path.is_symlink():
        report["status"] = "possibly_active" if lock_held else "interrupted_or_incomplete"
        report["issues"].append("missing_summary")
        return report
    try:
        summary, digest = read_json(summary_path)
        report["artifacts"].append({"name": "summary.json", "sha256": digest})
    except EvidenceError:
        report["issues"].append("invalid_summary")
        return report

    mode = summary.get("mode")
    report["mode"] = mode if mode in MODES else "unrecognized"
    requested = summary.get("requested_cycles")
    completed = summary.get("completed_cycles")
    successes = summary.get("successful_cycles")
    cycles = summary.get("cycles")
    if (mode not in MODES or type(requested) is not int or not 1 <= requested <= 5
            or (mode == MODES[0] and requested > 3)
            or type(completed) is not int or not 1 <= completed <= requested
            or type(successes) is not int or not 0 <= successes <= completed
            or type(summary.get("passed")) is not bool
            or not isinstance(cycles, list) or len(cycles) != completed
            or summary.get("network") != "disabled"
            or summary.get("persistent_guest_disk") is not False):
        report["issues"].append("invalid_summary_fields")
        return report

    report.update({
        "requested_cycles": requested,
        "completed_cycles": completed,
        "successful_cycles": successes,
    })
    if report["manifest_present"] and not report["issues"]:
        header, _ = read_json(manifest)
        if header.get("requested_cycles") != requested or (
            header.get("profile") == "experiment") != (mode == MODES[0]):
            report["issues"].append("manifest_summary_mismatch")

    measured = []
    passed_count = 0
    for index in range(1, completed + 1):
        json_name = f"cycle-{index:02}.json"
        log_name = f"cycle-{index:02}.log"
        try:
            cycle, digest = read_json(directory / json_name)
            log_digest = hashlib.sha256(read_bytes(directory / log_name, MAX_LOG_BYTES)).hexdigest()
            report["artifacts"].extend([
                {"name": json_name, "sha256": digest},
                {"name": log_name, "sha256": log_digest},
            ])
        except EvidenceError:
            report["issues"].append(f"missing_or_invalid_cycle_{index:02}")
            continue
        if cycle != cycles[index - 1] or type(cycle.get("cycle")) is not int or cycle["cycle"] != index:
            report["issues"].append(f"cycle_{index:02}_summary_mismatch")
            continue
        if type(cycle.get("passed")) is not bool:
            report["issues"].append(f"invalid_cycle_{index:02}_result")
            continue
        if cycle["passed"]:
            passed_count += 1
        if mode == MODES[0] and cycle["passed"]:
            resources = cycle.get("qemu_resources")
            if not isinstance(resources, dict) or not all(
                numeric(resources.get(key)) for key in
                ("wall_seconds", "cpu_user_seconds", "cpu_system_seconds", "qemu_peak_rss_kib")
            ) or cycle.get("known_answers_verified") is not True:
                report["issues"].append(f"invalid_cycle_{index:02}_measurement")
                continue
            measured.append(resources)
    if passed_count != successes:
        report["issues"].append("success_count_mismatch")
    if summary["passed"] != (completed == requested and successes == requested):
        report["issues"].append("pass_flag_mismatch")
    if successes < completed and completed != len(cycles):
        report["issues"].append("cycle_count_mismatch")
    if report["issues"]:
        report["status"] = "inconsistent_evidence"
    elif summary["passed"]:
        report["status"] = "complete_pass"
    else:
        report["status"] = "complete_failed"

    if measured:
        wall = [x["wall_seconds"] for x in measured]
        rss = [x["qemu_peak_rss_kib"] for x in measured]
        report["resource_statistics"] = {
            "measured_cycles": len(measured),
            "qemu_wall_min_seconds": round(min(wall), 3),
            "qemu_wall_mean_seconds": round(statistics.fmean(wall), 3),
            "qemu_wall_max_seconds": round(max(wall), 3),
            "qemu_peak_rss_max_kib": max(rss),
        }
    return report


def inspect_lock(state: Path) -> bool:
    """Return True if another run may still be active; never interrupt it."""
    lock = state / ".cycle.lock"
    if not lock.exists():
        return False
    if not regular_file(lock, 1024):
        raise EvidenceError("Unsafe or inaccessible lifecycle lock")
    try:
        fd = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise EvidenceError("Cannot read lifecycle lock") from exc
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        finally:
            # Closing releases any lock acquired here; no files are modified.
            pass
        return False
    finally:
        os.close(fd)


def audit(state: Path = DEFAULT_STATE, *, limit: int = MAX_RUNS) -> dict:
    if type(limit) is not int or not 1 <= limit <= MAX_RUNS:
        raise ValueError("Choose 1–20 runs")
    if state.is_symlink() or not state.is_dir():
        raise EvidenceError("State directory unavailable or symlinked")
    runs = state / "runs"
    if runs.is_symlink() or not runs.is_dir():
        raise EvidenceError("Runs directory unavailable or symlinked")
    active = inspect_lock(state)
    entries = sorted(
        (path for path in runs.iterdir() if RUN_NAME.fullmatch(path.name)
         and (path.is_dir() or path.is_symlink())),
        key=lambda path: path.name, reverse=True,
    )
    results = [audit_run(entry, lock_held=active) for entry in entries[:limit]]
    counts = {}
    for item in results:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    return {
        "schema_version": 1,
        "source": str(runs),
        "selected_runs": len(results),
        "lifecycle_lock_held": active,
        "status_counts": dict(sorted(counts.items())),
        "runs": results,
        "note": "Read-only checksums and consistency checks do not prove authentic or safe guest execution.",
    }


def render_markdown(report: dict) -> str:
    lines = [
        "# Slipcage guest experiment audit",
        "",
        f"Audited runs: {report['selected_runs']}. Lifecycle lock held: "
        f"{'yes' if report['lifecycle_lock_held'] else 'no'}.",
        "",
        "| Run | Mode | Completed | Result | QEMU mean / peak |",
        "| --- | --- | ---: | --- | --- |",
    ]
    for item in report["runs"]:
        stats = item["resource_statistics"]
        resources = (
            f"{stats['qemu_wall_mean_seconds']:.3f}s / {stats['qemu_peak_rss_max_kib']} KiB"
            if stats else "—"
        )
        lines.append(
            f"| {item['run']} | {item['mode'] or 'unknown'} | "
            f"{item['completed_cycles']}/{item['requested_cycles'] or '?'} | "
            f"{item['status']} | {resources} |"
        )
        if item["issues"]:
            lines.append(f"\nEvidence issues in {item['run']}: "
                         + ", ".join(item["issues"]) + "\n")
    lines += [
        "", "Fingerprints for each JSON and log artifact appear in the JSON audit output.",
        "These fingerprints are not signed attestations or a security-isolation test.",
    ]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--limit", type=int, default=MAX_RUNS)
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    args = parser.parse_args(argv)
    try:
        result = audit(args.state, limit=args.limit)
    except (OSError, ValueError, EvidenceError) as exc:
        print(f"slipcage-experiment-audit: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2) if args.format == "json"
          else render_markdown(result), end="\n" if args.format == "json" else "")
    if not result["runs"]:
        return 2
    return 0 if all(x["status"] == "complete_pass" for x in result["runs"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
