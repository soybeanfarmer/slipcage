#!/usr/bin/env python3
"""Read-only check of configured guest systemd quotas, NOT actual enforcement.

Safe: invokes only 'systemctl show'; never starts, stops or modifies a unit.
"""
from __future__ import annotations
import argparse
import json
import re
import subprocess
import sys

ALLOWED_UNITS = (
    "slipcage-experiment@1.service",
    "slipcage-experiment@3.service",
    "slipcage-guest-cycles@1.service",
    "slipcage-guest-cycles@5.service",
)
PROPERTIES = (
    "User", "PrivateNetwork", "ProtectSystem", "NoNewPrivileges",
    "MemoryMax", "CPUQuotaPerSecUSec", "TasksMax",
    "DevicePolicy", "DeviceAllow", "KillMode",
)
TIME_VALUE = re.compile(r"^(\d+(?:\.\d+)?)(us|ms|s|min)$")


def microseconds(value: str) -> float | None:
    """Parse simple documented systemd timespan units, not infinity."""
    match = TIME_VALUE.fullmatch(value)
    if match is None:
        return None
    number = float(match.group(1))
    factor = {"us": 1, "ms": 1000, "s": 1000000, "min": 60000000}[match.group(2)]
    return number * factor


def read_config(text: str) -> dict:
    result = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key in PROPERTIES:
            # systemctl can show DeviceAllow multiple times.
            if key == "DeviceAllow":
                result.setdefault(key, []).append(value.strip())
            else:
                result[key] = value.strip()
    return result


def check_unit(unit: str, *, runner=subprocess.run) -> dict:
    if unit not in ALLOWED_UNITS:
        raise ValueError("Only fixed Slipcage guest unit instances may be inspected")
    cmd = ["systemctl", "show", unit]
    for name in PROPERTIES:
        cmd.extend(["-p", name])
    result = runner(cmd, capture_output=True, text=True, timeout=10, check=False)
    if result.returncode:
        return {"unit": unit, "configured_within_bounds": False,
                "issues": ["systemctl_show_failed"], "measurements": {},
                "note": "No guest workload was launched."}
    properties = read_config(result.stdout)
    issues = []
    exact = {
        "User": "slipcage-vmprobe",
        "PrivateNetwork": "yes",
        "ProtectSystem": "strict",
        "NoNewPrivileges": "yes",
        "DevicePolicy": "closed",
        "KillMode": "control-group",
    }
    for name, value in exact.items():
        if properties.get(name) != value:
            issues.append("unexpected_" + name)
    limits = {"MemoryMax": 1280 * 1024 * 1024, "TasksMax": 64}
    for key, maximum in limits.items():
        raw = properties.get(key, "")
        try:
            actual = int(raw)
        except ValueError:
            actual = None
        if actual is None or actual < 1 or actual > maximum:
            issues.append("unsafe_or_unknown_" + key)
    quota = microseconds(properties.get("CPUQuotaPerSecUSec", ""))
    if quota is None or not 0 < quota <= 1000000:
        issues.append("unsafe_or_unknown_CPUQuotaPerSecUSec")
    # The configured device exception should be only /dev/kvm, no generic
    # host block/network devices. systemctl versions can format this
    # property's value differently; fail closed if unexpected.
    devices = properties.get("DeviceAllow", [])
    if not devices or any(
        not re.fullmatch(r"/dev/kvm\s+rw[m]?", item) for item in devices
    ):
        issues.append("unexpected_device_allowlist")
    return {
        "unit": unit,
        "configured_within_bounds": not issues,
        "issues": issues,
        "measurements": {
            "memory_max_bytes": properties.get("MemoryMax"),
            "cpu_quota_per_second": properties.get("CPUQuotaPerSecUSec"),
            "tasks_max": properties.get("TasksMax"),
        },
        "note": ("Read-only systemctl configuration check only. Does not demonstrate "
                 "that limits trigger under pressure, or validate VM isolation."),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unit", choices=ALLOWED_UNITS,
                        default="slipcage-experiment@1.service")
    args = parser.parse_args(argv)
    try:
        report = check_unit(args.unit)
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        print(f"slipcage-limits-check: {type(exc).__name__}", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0 if report["configured_within_bounds"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
