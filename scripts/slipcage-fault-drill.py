#!/usr/bin/env python3
"""Manual, bounded, guest-free fault drills. No QEMU, network, or live run data."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time

DEFAULT_STATE = Path("/var/lib/slipcage-fault")
AUDIT_SCRIPT = Path("/usr/local/lib/slipcage/experiment-audit.py")
MODES = ("timeout", "report", "limits", "all")
MI_B = 1024 * 1024
PROBE_TIMEOUT = 1.0
REPORT_READY_TIMEOUT = 5.0


def utc_stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def atomic_write(path: Path, obj: dict) -> None:
    temp = path.with_name(path.name + ".tmp")
    with temp.open("x", encoding="utf-8") as stream:
        json.dump(obj, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temp, 0o600)
    os.replace(temp, path)


def proc_identity(pid: int) -> tuple[str, int] | None:
    """Check process identity/liveness without signaling arbitrary PIDs."""
    try:
        data = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        tail = data.rsplit(")", 1)[1].split()
        return tail[0], int(tail[19])  # Linux state and /proc starttime
    except (OSError, ValueError, IndexError):
        return None


def child_gone(pid: int, start_ticks: int | None) -> bool:
    current = proc_identity(pid)
    return (current is None or current[0] in ("Z", "X")
            or (start_ticks is not None and current[1] != start_ticks))


def kill_group(child: subprocess.Popen) -> None:
    # Every drill worker is a newly-created session/process group.
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    child.communicate(timeout=3)


def timeout_drill() -> dict:
    """Timeout a fixed local Python parent AND its sleeping subprocess."""
    worker = """
import json, subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
line = open("/proc/%d/stat" % child.pid).read()
print(json.dumps({"pid":child.pid, "ticks":int(line.rsplit(")", 1)[1].split()[19])}),
      flush=True)
time.sleep(30)
"""
    p = subprocess.Popen(
        [sys.executable, "-c", worker],
        start_new_session=True, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    timed_out = False
    output = b""
    started = time.monotonic()
    try:
        try:
            output, _ = p.communicate(timeout=PROBE_TIMEOUT)
        except subprocess.TimeoutExpired:
            timed_out = True
            kill_group(p)
            output, _ = p.communicate(timeout=1)
    finally:
        if p.poll() is None:
            kill_group(p)
    identity = None
    try:
        identity = json.loads(output.decode("utf-8").strip().splitlines()[0])
    except (UnicodeDecodeError, IndexError, json.JSONDecodeError, ValueError):
        pass
    terminated = bool(identity and isinstance(identity.get("pid"), int)
                      and isinstance(identity.get("ticks"), int))
    if terminated:
        for _ in range(30):
            if child_gone(identity["pid"], identity["ticks"]):
                break
            time.sleep(0.02)
        terminated = child_gone(identity["pid"], identity["ticks"])
    passed = timed_out and p.returncode == -signal.SIGKILL and terminated
    return {
        "drill": "timeout", "passed": passed,
        "timeout_exercised": timed_out, "worker_killed": p.returncode == -signal.SIGKILL,
        "child_no_longer_running": terminated,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "note": "Only a fixed local sleeper and its child were terminated; no VM launched.",
    }


def report_drill(workspace: Path, *, audit_script: Path = AUDIT_SCRIPT) -> dict:
    """SIGKILL an isolated fixture writer before atomic publish, then audit."""
    state = workspace / "fixture-state"
    runs = state / "runs"
    runs.mkdir(parents=True, mode=0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    run = Path(tempfile.mkdtemp(prefix=f"run-{stamp}-", dir=runs))
    os.chmod(run, 0o700)
    atomic_write(run / "run.json", {
        "schema_version": 1, "profile": "experiment",
        "requested_cycles": 1, "note": "Synthetic drill fixture, NOT a guest run",
    })
    partial = run / "summary.json.tmp"
    final = run / "summary.json"
    writer = """
import os, sys, time
with open(sys.argv[1], "xb") as stream:
    stream.write(b'{"interrupted":')
    stream.flush()
    os.fsync(stream.fileno())
time.sleep(30)
"""
    p = subprocess.Popen(
        [sys.executable, "-c", writer, str(partial)],
        start_new_session=True, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    ready = False
    started = time.monotonic()
    try:
        while time.monotonic() - started < REPORT_READY_TIMEOUT:
            if partial.is_file() and partial.stat().st_size > 0:
                ready = True
                break
            if p.poll() is not None:
                break
            time.sleep(0.02)
    finally:
        if p.poll() is None:
            kill_group(p)
    module_spec = importlib.util.spec_from_file_location("slipcage_drill_audit", audit_script)
    if module_spec is None or module_spec.loader is None:
        raise RuntimeError("Unable to load read-only audit")
    audit = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(audit)
    entry = audit.audit(state, limit=1)["runs"][0]
    passed = (
        ready and p.returncode == -signal.SIGKILL
        and not final.exists() and partial.is_file()
        and entry["status"] == "interrupted_or_incomplete"
        and "missing_summary" in entry["issues"]
    )
    return {
        "drill": "report", "passed": passed,
        "partial_report_preserved": partial.is_file(),
        "final_report_not_published": not final.exists(),
        "audit_classification": entry["status"],
        "writer_killed": p.returncode == -signal.SIGKILL,
        "note": "The artificial report lives only in this drill workspace; production artifacts untouched.",
    }


def cgroup_drill(*, cgroup_root: Path = Path("/sys/fs/cgroup"),
                 proc_cgroup: Path = Path("/proc/self/cgroup")) -> dict:
    """Read kernel cgroup v2 enforcement settings; do NOT exhaust resources."""
    path = None
    for line in proc_cgroup.read_text(encoding="ascii").splitlines():
        if line.startswith("0::"):
            path = line[3:]
            break
    if path is None or not path.startswith("/") or ".." in Path(path).parts:
        return {"drill": "limits", "passed": False, "reason": "cgroup_v2_unavailable"}
    group = cgroup_root / path.lstrip("/")
    def read(name: str) -> str:
        return (group / name).read_text(encoding="ascii").strip()
    memory = read("memory.max")
    tasks = read("pids.max")
    cpu = read("cpu.max").split()
    try:
        mem = int(memory)
        pids = int(tasks)
        quota = int(cpu[0])
        period = int(cpu[1])
        ratio = quota / period
    except (ValueError, IndexError, ZeroDivisionError):
        return {"drill": "limits", "passed": False, "reason": "missing_finite_cgroup_bounds"}
    passed = (
        0 < mem <= 128 * MI_B and 0 < pids <= 32
        and period > 0 and 0 < quota <= period and 0 < ratio <= 0.25
    )
    return {
        "drill": "limits", "passed": passed,
        "memory_max_bytes": mem, "pids_max": pids,
        "cpu_quota_fraction": round(ratio, 4),
        "note": "Kernel cgroup v2 files inspected. No memory exhaustion, CPU stress, or QEMU executed.",
    }


def run_drill(mode: str, *, state: Path = DEFAULT_STATE,
              audit_script: Path = AUDIT_SCRIPT) -> dict:
    if mode not in MODES:
        raise ValueError("Only fixed, reviewed drill modes may run")
    if state.is_symlink():
        raise ValueError("Drill state must not be a symlink")
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (state / ".drill.lock").open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        run = Path(tempfile.mkdtemp(prefix=f"drill-{stamp}-", dir=state))
        os.chmod(run, 0o700)
        results = []
        for selected in (("timeout", "report", "limits") if mode == "all" else (mode,)):
            try:
                item = (timeout_drill() if selected == "timeout" else
                        report_drill(run, audit_script=audit_script)
                        if selected == "report" else cgroup_drill())
            except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
                item = {
                    "drill": selected, "passed": False,
                    "reason": type(exc).__name__,
                }
            results.append(item)
            atomic_write(run / f"{selected}.json", item)
            if not item["passed"]:
                break
        summary = {
            "mode": mode, "passed": len(results) == (
                3 if mode == "all" else 1
            ) and all(item["passed"] for item in results),
            "results": results, "run_dir": str(run), "timestamp_utc": utc_stamp(),
            "live_data_modified": False, "qemu_started": False,
        }
        atomic_write(run / "summary.json", summary)
        return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=MODES, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        result = run_drill(args.mode)
    except (OSError, ValueError, BlockingIOError) as exc:
        print(f"slipcage-fault-drill: {type(exc).__name__}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
