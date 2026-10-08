#!/usr/bin/env python3
"""Read-only host preflight and optional, inert nested-KVM QMP smoke test.

The manual smoke creates no guest OS, disk, network interface or persistent VM.
QMP query-kvm confirms acceleration initializes; it does NOT prove guest boot.
"""
from __future__ import annotations

import argparse
import json
import resource
import time
import os
from pathlib import Path
import stat
import subprocess
import sys

QEMU = "/usr/bin/qemu-system-x86_64"
QMP_INPUT = (
    '{"execute":"qmp_capabilities","id":"enable"}\n'
    '{"execute":"query-kvm","id":"inspect-kvm"}\n'
    '{"execute":"quit","id":"exit"}\n'
)
GUEST_INITRD = Path("/usr/local/lib/slipcage/microguest.cpio.gz")
BOOT_MARKER = "SLIPCAGE_MICROGUEST_OK"
QEMU_ARGS = (
    QEMU, "-no-user-config", "-nodefaults", "-machine", "q35,accel=kvm",
    "-m", "256", "-smp", "1", "-display", "none", "-monitor", "none",
    "-serial", "none", "-nic", "none", "-no-reboot", "-S", "-qmp", "stdio",
)


def inspect(kvm: Path = Path("/dev/kvm")) -> dict:
    result = {
        "host_kvm_device": kvm.exists(),
        "host_kvm_character_device": False,
        "process_can_open_kvm": False,
        "qemu_binary_available": Path(QEMU).is_file(),
        "cpu_count": os.cpu_count(),
        "note": "Presence or permissions alone do not prove a nested guest boots.",
    }
    try:
        result["host_kvm_character_device"] = stat.S_ISCHR(kvm.stat().st_mode)
    except OSError:
        pass
    if result["host_kvm_character_device"]:
        try:
            fd = os.open(kvm, os.O_RDWR | os.O_CLOEXEC | os.O_NONBLOCK)
        except OSError:
            pass
        else:
            os.close(fd)
            result["process_can_open_kvm"] = True
    return result


def parse_kvm_status(stdout: str) -> bool:
    """Reject greetings or check results that don't explicitly enable KVM."""
    allowed = False
    for line in stdout.splitlines():
        try:
            item = json.loads(line.strip())
        except json.JSONDecodeError:
            continue
        if item.get("id") == "inspect-kvm":
            response = item.get("return")
            if isinstance(response, dict):
                allowed = response.get("present") is True and response.get("enabled") is True
            else:
                return False
    return allowed


def smoke(*, runner=subprocess.run) -> dict:
    result = inspect()
    if not (result["process_can_open_kvm"] and result["qemu_binary_available"]):
        return {"kvm_initialized": False, "reason": "KVM device or QEMU binary unavailable",
                "inspection": result}
    try:
        process = runner(
            list(QEMU_ARGS), input=QMP_INPUT, text=True, capture_output=True,
            timeout=15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"kvm_initialized": False, "reason": type(exc).__name__,
                "inspection": result}
    success = process.returncode == 0 and parse_kvm_status(process.stdout[:65536])
    return {
        "kvm_initialized": success,
        "qemu_exit_code": process.returncode,
        "inspection": result,
        "meaning": (
            "QEMU initialized KVM with an inert paused machine; NO guest boot validated."
            if success else
            "QEMU could not confirm nested KVM initialization; do not assume it works."
        ),
        "stderr_tail": process.stderr[-2000:] if not success else "",
    }


def boot_guest(*, runner=subprocess.run,
               kernel_path: Path | None = None, initrd_path: Path | None = None) -> dict:
    """Start a tiny Linux guest without network, drives, or persistent changes."""
    preflight = inspect()
    # /boot kernels can be root-readable only on Ubuntu. Ansible copies the
    # currently running kernel to a public-read, root-owned location for this
    # unprivileged probe; never broaden /boot permissions or run QEMU as root.
    kernel = (kernel_path if kernel_path is not None
              else Path("/usr/local/lib/slipcage") / f"vmlinuz-{os.uname().release}")
    initrd = initrd_path if initrd_path is not None else GUEST_INITRD
    if not (preflight["process_can_open_kvm"] and preflight["qemu_binary_available"]
            and kernel.is_file() and initrd.is_file()):
        return {"guest_booted": False, "reason": "KVM, QEMU, kernel or initramfs unavailable",
                "inspection": preflight}
    args = [
        QEMU, "-no-user-config", "-nodefaults", "-machine", "q35,accel=kvm",
        "-cpu", "host", "-m", "384", "-smp", "1",
        "-display", "none", "-monitor", "none", "-serial", "stdio",
        "-nic", "none", "-no-reboot", "-kernel", str(kernel),
        "-initrd", str(initrd),
        "-append", "console=ttyS0 rdinit=/init panic=1 quiet",
    ]
    try:
        process = runner(args, text=True, capture_output=True, timeout=75, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"guest_booted": False, "reason": type(exc).__name__,
                "inspection": preflight}
    passed = process.returncode == 0 and BOOT_MARKER in process.stdout
    return {
        "guest_booted": passed, "exit_code": process.returncode,
        "inspection": preflight,
        "network": "disabled", "persistent_guest_disk": False,
        "meaning": "A disposable nested guest booted and powered off; no security boundary was tested."
                   if passed else "The disposable guest did not pass the boot test.",
        # Capture a small, bounded console excerpt even on success so that
        # the lifecycle supervisor can preserve evidence of actual boot.
        "console_tail": process.stdout[-1200:],
        "stderr_tail": process.stderr[-1000:],
    }



EXPERIMENT_INITRD = Path("/usr/local/lib/slipcage/experiment-v1.cpio.gz")
EXPERIMENT_MARKERS = (
    "SLIPCAGE_EXPERIMENT_V1_SUM=500500",
    "SLIPCAGE_EXPERIMENT_V1_SQUARES=333833500",
    "SLIPCAGE_EXPERIMENT_V1_SHA256=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "SLIPCAGE_EXPERIMENT_V1_OK",
)


def run_experiment(*, runner=subprocess.run,
                   kernel_path: Path | None = None,
                   initrd_path: Path | None = None) -> dict:
    """Boot only the packaged deterministic guest and verify its known answers."""
    preflight = inspect()
    kernel = (kernel_path if kernel_path is not None
              else Path("/usr/local/lib/slipcage") / f"vmlinuz-{os.uname().release}")
    initrd = initrd_path if initrd_path is not None else EXPERIMENT_INITRD
    if not (preflight["process_can_open_kvm"] and preflight["qemu_binary_available"]
            and kernel.is_file() and initrd.is_file()):
        return {"experiment_passed": False, "reason": "KVM, QEMU, kernel or guest unavailable",
                "inspection": preflight}
    args = [
        QEMU, "-no-user-config", "-nodefaults", "-machine", "q35,accel=kvm",
        "-cpu", "host", "-m", "384", "-smp", "1",
        "-display", "none", "-monitor", "none", "-serial", "stdio",
        "-nic", "none", "-no-reboot",
        "-kernel", str(kernel), "-initrd", str(initrd),
        "-append", "console=ttyS0 rdinit=/init panic=1 quiet",
    ]
    started = time.monotonic()
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    try:
        process = runner(args, text=True, capture_output=True, timeout=75, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "experiment_passed": False, "reason": type(exc).__name__,
            "wall_seconds": round(time.monotonic() - started, 3),
            "inspection": preflight, "network": "disabled",
            "persistent_guest_disk": False,
        }
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    # Exact expected console lines are required. A mere "OK" string cannot
    # count as an experimental result; the guest checks both workloads too.
    console_lines = {line.strip() for line in process.stdout.splitlines()}
    missing = [marker for marker in EXPERIMENT_MARKERS if marker not in console_lines]
    passed = process.returncode == 0 and not missing
    return {
        "experiment_passed": passed,
        "exit_code": process.returncode,
        "known_answers_verified": not missing,
        "missing_markers": missing,
        "workload": "fixed_arithmetic_sha256_v1",
        "wall_seconds": round(time.monotonic() - started, 3),
        "cpu_user_seconds": round(max(0.0, after.ru_utime - before.ru_utime), 3),
        "cpu_system_seconds": round(max(0.0, after.ru_stime - before.ru_stime), 3),
        # Linux ru_maxrss is KiB. One QEMU child per probe process; this
        # is subprocess peak RSS, not guest RAM, cgroup peak or host total.
        "qemu_peak_rss_kib": after.ru_maxrss,
        "inspection": preflight,
        "network": "disabled",
        "persistent_guest_disk": False,
        "console_tail": process.stdout[-1600:],
        "stderr_tail": process.stderr[-1000:] if not passed else "",
    }

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--smoke", action="store_true",
                      help="Initialize paused, diskless QEMU with KVM (manual).")
    mode.add_argument("--boot", action="store_true",
                      help="Boot and shut down a locally built, diskless Linux guest (manual).")
    mode.add_argument("--experiment", action="store_true",
                      help="Run only the packaged deterministic arithmetic/hash microguest (manual).")
    args = parser.parse_args(argv)
    result = (run_experiment() if args.experiment else
              boot_guest() if args.boot else smoke() if args.smoke else inspect())
    print(json.dumps(result, sort_keys=True))
    return 0 if (not args.smoke and not args.boot and not args.experiment) or (
        result.get("guest_booted") is True or result.get("kvm_initialized") is True
        or result.get("experiment_passed") is True
    ) else 2


if __name__ == "__main__":
    raise SystemExit(main())
