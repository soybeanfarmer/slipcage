#!/usr/bin/env python3
"""Manually run a bounded series of harmless, disposable nested Linux guest boots.

Only the already-reviewed, fixed Slipcage microguest probe is invoked. No
advisory data, guest disks, networks, shell, or dynamic guest inputs are used.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

DEFAULT_PROBE = Path("/usr/local/lib/slipcage/kvm-probe.py")
DEFAULT_STATE = Path("/var/lib/slipcage-guest")
MAX_CYCLES = 5
MAX_EXPERIMENT_CYCLES = 3
ALLOWED_PROFILES = ('boot', 'experiment')
KEEP_RUNS = 20
TIMEOUT_SECONDS = 85
LOG_TAIL_BYTES = 16384
MAX_PROVENANCE_BYTES = 64 * 1024 * 1024
RUN_DIRECTORY = re.compile(r"^run-\d{8}T\d{12}Z-[a-zA-Z0-9_]+$")


def utc_stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_boot_result(log: str, profile: str = 'boot') -> dict | None:
    """Extract only the fixed profile's structured result; ignore other text."""
    if profile not in ALLOWED_PROFILES:
        raise ValueError("Unsupported guest profile")
    expected_key = "experiment_passed" if profile == "experiment" else "guest_booted"
    for line in reversed(log.splitlines()):
        try:
            value = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(value, dict) and expected_key in value:
            return value
    return None


def run_cycle(probe: Path = DEFAULT_PROBE, *,
              timeout: float = TIMEOUT_SECONDS,
              profile: str = "boot") -> tuple[dict, str]:
    if not (0 < timeout <= TIMEOUT_SECONDS):
        raise ValueError("Cycle timeout out of permitted range")
    if profile not in ALLOWED_PROFILES:
        raise ValueError("Unsupported guest profile")
    start = time.monotonic()
    timed_out = False
    error = None
    returncode = None
    output = b""
    child = None
    try:
        # Session isolation lets the supervisor kill the probe AND any QEMU
        # process it spawned if the outer time limit fires.
        child = subprocess.Popen(
            [sys.executable, str(probe), "--experiment" if profile == "experiment" else "--boot"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
        )
        try:
            output, _ = child.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            # Killing only Python could leave its QEMU child running.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            output, _ = child.communicate(timeout=5)
        returncode = child.returncode
    except OSError as exc:
        error = type(exc).__name__
    finally:
        if child is not None and child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
    log = output[-LOG_TAIL_BYTES:].decode("utf-8", errors="replace")
    payload = parse_boot_result(log, profile)
    numeric_keys = ("wall_seconds", "cpu_user_seconds",
                    "cpu_system_seconds", "qemu_peak_rss_kib")
    resource_evidence_valid = (payload is not None and all(
        type(payload.get(key)) in (int, float)
        and math.isfinite(payload[key]) and payload[key] >= 0
        for key in numeric_keys
    ))
    agreed = (payload is not None and (
        payload.get("experiment_passed") is True
        and payload.get("known_answers_verified") is True
        and payload.get("workload") == "fixed_arithmetic_sha256_v1"
        and resource_evidence_valid
        if profile == "experiment" else payload.get("guest_booted") is True
    ))
    passed = (
        not timed_out and error is None and returncode == 0 and agreed
        and type(payload.get("exit_code")) is int and payload["exit_code"] == 0
        and payload.get("network") == "disabled"
        and payload.get("persistent_guest_disk") is False
    )
    result = {
        "passed": passed,
        "reason": ("passed" if passed else
                   "timeout" if timed_out else
                   error if error else
                   "probe_failed_or_incomplete"),
        "supervisor_exit_code": returncode,
        "probe_exit_code": payload.get("exit_code") if payload else None,
        "seconds": round(time.monotonic() - start, 3),
        "timestamp_utc": utc_stamp(),
        "failure_category": classify_failure(
            passed=passed, timed_out=timed_out, error=error,
            returncode=returncode, payload=payload, profile=profile,
            resource_ok=resource_evidence_valid,
        ),
    }
    if profile == "experiment" and payload is not None:
        # Resource figures come from the QEMU subprocess, not host-wide load.
        result["qemu_resources"] = {
            key: payload.get(key)
            for key in ("wall_seconds", "cpu_user_seconds",
                        "cpu_system_seconds", "qemu_peak_rss_kib")
        }
        result["known_answers_verified"] = payload.get("known_answers_verified") is True
    return result, log



def file_sha256_if_safe(path: Path) -> str | None:
    """Hash only fixed, regular, bounded files; no symlinks or unknown trees."""
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_PROVENANCE_BYTES:
            return None
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def run_manifest(profile: str, cycles: int, probe: Path) -> dict:
    image = ("experiment-v1.cpio.gz" if profile == "experiment"
             else "microguest.cpio.gz")
    root = Path("/usr/local/lib/slipcage")
    return {
        "schema_version": 1,
        "started_utc": utc_stamp(),
        "profile": profile,
        "requested_cycles": cycles,
        "kernel_release": os.uname().release,
        "artifact_sha256": {
            "controller": file_sha256_if_safe(Path(__file__)),
            "probe": file_sha256_if_safe(probe),
            "guest_initramfs": file_sha256_if_safe(root / image),
            "staged_kernel": file_sha256_if_safe(
                root / f"vmlinuz-{os.uname().release}"
            ),
        },
        "note": "Local fingerprints only; null denotes unavailable artifact, not trusted proof.",
    }


def classify_failure(*, passed: bool, timed_out: bool,
                     error: str | None, returncode: int | None,
                     payload: dict | None, profile: str,
                     resource_ok: bool) -> str:
    if passed:
        return "none"
    if timed_out:
        return "outer_timeout_process_group_killed"
    if error:
        return "probe_launch_failed"
    if returncode is None:
        return "probe_missing_exit_status"
    if payload is None:
        return "missing_structured_probe_result"
    if profile == "experiment" and not resource_ok:
        return "resource_evidence_missing_or_invalid"
    if payload.get("network") != "disabled" or payload.get("persistent_guest_disk") is not False:
        return "unexpected_guest_configuration"
    if type(payload.get("exit_code")) is not int or payload["exit_code"] != 0:
        return "qemu_error"
    if profile == "experiment" and (
        payload.get("experiment_passed") is not True
        or payload.get("known_answers_verified") is not True
        or payload.get("workload") != "fixed_arithmetic_sha256_v1"
    ):
        return "known_answer_mismatch"
    if profile == "boot" and payload.get("guest_booted") is not True:
        return "boot_validation_failed"
    if returncode != 0:
        return "probe_nonzero_exit"
    return "unknown_failed_invariant"

def write_json(path: Path, value: dict) -> None:
    temp = path.with_name(path.name + ".tmp")
    with temp.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
    os.chmod(temp, 0o600)
    os.replace(temp, path)


def prune_runs(runs: Path, keep: int = KEEP_RUNS) -> int:
    if not 1 <= keep <= KEEP_RUNS:
        raise ValueError("Retention must be between 1 and 20")
    directories = sorted(
        (item for item in runs.iterdir() if not item.is_symlink()
         and item.is_dir() and RUN_DIRECTORY.fullmatch(item.name)
         and (item / "summary.json").is_file()),
        key=lambda item: item.name, reverse=True,
    )
    for old in directories[keep:]:
        shutil.rmtree(old)
    return max(0, len(directories) - keep)


def run_lifecycle(cycles: int, *, probe: Path = DEFAULT_PROBE,
                  state: Path = DEFAULT_STATE, timeout: float = TIMEOUT_SECONDS,
                  cycle_fn=None, profile: str = "boot") -> dict:
    if not isinstance(cycles, int) or not 1 <= cycles <= MAX_CYCLES:
        raise ValueError("Use between 1 and 5 cycles")
    if profile not in ALLOWED_PROFILES:
        raise ValueError("Unsupported guest profile")
    if profile == "experiment" and cycles > MAX_EXPERIMENT_CYCLES:
        raise ValueError("Use at most 3 controlled experiment cycles")
    if not (0 < timeout <= TIMEOUT_SECONDS):
        raise ValueError("Invalid cycle timeout")
    if state.is_symlink():
        raise ValueError("State directory must not be a symlink")
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    runs = state / "runs"
    if runs.is_symlink():
        raise ValueError("Runs directory must not be a symlink")
    runs.mkdir(mode=0o700, exist_ok=True)
    with (state / ".cycle.lock").open("a+b") as lock:
        # Do not allow overlapping systemd template instances.
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        start = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        directory = Path(tempfile.mkdtemp(dir=runs, prefix=f"run-{start}-"))
        os.chmod(directory, 0o700)
        # Created before launching any guest: interrupted series remain
        # identifiable without guessing missing state after a crash.
        write_json(directory / "run.json", run_manifest(profile, cycles, probe))
        results = []
        for index in range(1, cycles + 1):
            outcome, log = ((cycle_fn(probe=probe, timeout=timeout, profile=profile))
                            if cycle_fn is not None else
                            run_cycle(probe, timeout=timeout, profile=profile))
            outcome = dict(outcome)
            outcome["cycle"] = index
            log_path = directory / f"cycle-{index:02}.log"
            log_path.write_text(log[-LOG_TAIL_BYTES:], encoding="utf-8")
            os.chmod(log_path, 0o600)
            write_json(directory / f"cycle-{index:02}.json", outcome)
            results.append(outcome)
            if not outcome["passed"]:
                # Don't repeatedly boot guests after a failure.
                break
        summary = {
            "mode": ("fixed_arithmetic_sha256_v1" if profile == "experiment" else
                     "benign_diskless_guest_lifecycle"),
            "run_dir": str(directory),
            "requested_cycles": cycles,
            "completed_cycles": len(results),
            "successful_cycles": sum(1 for item in results if item["passed"]),
            "passed": len(results) == cycles and all(item["passed"] for item in results),
            "first_failure": next((item["cycle"] for item in results
                                   if not item["passed"]), None),
            "network": "disabled",
            "persistent_guest_disk": False,
            "timestamp_utc": utc_stamp(),
            "cycles": results,
        }
        write_json(directory / "summary.json", summary)
        summary["pruned_runs"] = prune_runs(runs)
        return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cycles", type=int, required=True,
                        help="Number of sequential manual guest boots, from 1 to 5.")
    parser.add_argument("--profile", choices=ALLOWED_PROFILES, default="boot",
                        help="Fixed packaged workload only; no guest payload arguments.")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        report = run_lifecycle(args.cycles, profile=args.profile)
    except (OSError, ValueError) as exc:
        print(f"slipcage-guest-lifecycle: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
