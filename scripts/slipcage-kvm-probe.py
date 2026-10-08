#!/usr/bin/env python3
"""Read-only host preflight and optional, inert nested-KVM QMP smoke test.

The manual smoke creates no guest OS, disk, network interface or persistent VM.
QMP query-kvm confirms acceleration initializes; it does NOT prove guest boot.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

QEMU = "/usr/bin/qemu-system-x86_64"
QMP_INPUT = (
    '{"execute":"qmp_capabilities","id":"enable"}\n'
    '{"execute":"query-kvm","id":"inspect-kvm"}\n'
    '{"execute":"quit","id":"exit"}\n'
)
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


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke", action="store_true",
                        help="Initialize QEMU with KVM; must be manually approved and run.")
    args = parser.parse_args(argv)
    result = smoke() if args.smoke else inspect()
    print(json.dumps(result, sort_keys=True))
    return 0 if not args.smoke or result["kvm_initialized"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
