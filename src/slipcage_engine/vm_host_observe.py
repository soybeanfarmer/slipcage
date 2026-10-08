"""SC-13b3: explicit-invocation, read-only Linux VM host fact inspection.

The command exists for a future separately owner-approved host inspection.
It neither contacts a remote host nor uses privileged probes: no /dev/kvm
open, QEMU, /proc process enumeration, shell, network, or filesystem writes.

Returned numbers reflect ONE local moment and one nominated filesystem.
They are NOT attestations, KVM usability, cgroup quota, provider permission,
active guest count, VM boot readiness, or an authorization to execute.

Test-only paths and clock can be injected into the Python API; the CLI has
fixed kernel paths and accepts only the selected scratch filesystem root.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
from typing import Callable

from .vm_plan import (
    K3sVMPlan, VMPlanError, validate_vm_plan_bytes, CPU_RESERVE_THREADS,
    MEMORY_RESERVE_MIB, DISK_HEADROOM_GIB,
)

API_VERSION = "slipcage.dev/local-host-observation/v1alpha1"
MEMINFO_LIMIT = 16 * 1024
CONTROLLERS_LIMIT = 4096
GIB_BYTES = 1024 ** 3
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_MEM_LINE = re.compile(r"^MemAvailable:\s+([0-9]+)\s+kB\s*$")


class HostObservationError(ValueError):
    """Host fact could not be read safely, or the plan is inconsistent."""


@dataclass(frozen=True, slots=True)
class LocalHostObservation:
    plan_id: str
    plan_digest_sha256: str
    collected_at_utc: str
    logical_cpu_threads_visible: int
    mem_available_mib: int
    filesystem_free_gib: int
    filesystem_available_inodes: int
    kvm_character_device_observed: bool
    cgroup_v2_controllers_observed: bool
    observed_thresholds: str
    blockers: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "api_version": API_VERSION,
            "kind": "read_only_local_host_observation",
            "plan_id": self.plan_id,
            "plan_digest_sha256": self.plan_digest_sha256,
            "collected_at_utc": self.collected_at_utc,
            "logical_cpu_threads_visible": self.logical_cpu_threads_visible,
            "mem_available_mib": self.mem_available_mib,
            "filesystem_free_gib": self.filesystem_free_gib,
            "filesystem_available_inodes": self.filesystem_available_inodes,
            "kvm_character_device_observed": self.kvm_character_device_observed,
            "cgroup_v2_controllers_observed": self.cgroup_v2_controllers_observed,
            "observed_thresholds": self.observed_thresholds,
            "blockers": list(self.blockers),
            "snapshot_source": "local_read_only_inspection_unattested",
            "measurement_authenticity_verified": False,
            "capacity_reservation_performed": False,
            "effective_cgroup_limits_verified": False,
            "kvm_usable_verified": False,
            "provider_permission_verified": False,
            "active_guest_count_verified": False,
            "guest_network_isolation_verified": False,
            "guest_boot_verified": False,
            "execution_authorized": False,
            "host_modified": False,
            "vm_launched": False,
        }

    def canonical_json(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")


def _read_fixed_regular(path: Path, cap: int) -> bytes:
    fd = None
    try:
        fd = os.open(path, _FILE_FLAGS)
        identity = os.fstat(fd)
        if not stat.S_ISREG(identity.st_mode) or identity.st_size > cap:
            raise HostObservationError("Required host fact source not a bounded regular file")
        with os.fdopen(fd, "rb") as input_file:
            fd = None
            payload = input_file.read(cap + 1)
        if not payload or len(payload) > cap:
            raise HostObservationError("Host fact source empty or oversized")
        return payload
    except OSError as exc:
        raise HostObservationError("Required read-only host fact unavailable") from exc
    finally:
        if fd is not None:
            os.close(fd)


def _parse_available_memory(raw: bytes) -> int:
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise HostObservationError("Invalid /proc/meminfo encoding") from exc
    matches = [_MEM_LINE.fullmatch(line) for line in lines]
    values = [int(m.group(1)) for m in matches if m is not None]
    if len(values) != 1 or values[0] < 0 or values[0] > 2**52:
        raise HostObservationError("Unique bounded MemAvailable missing from /proc/meminfo")
    return values[0] // 1024


def _is_kvm_character_device(path: Path) -> bool:
    try:
        return stat.S_ISCHR(os.stat(path, follow_symlinks=False).st_mode)
    except OSError:
        return False


def _has_cgroup_v2_controllers(path: Path) -> bool:
    try:
        raw = _read_fixed_regular(path, CONTROLLERS_LIMIT)
    except HostObservationError:
        return False
    try:
        controllers = raw.decode("ascii").split()
    except UnicodeError:
        return False
    return bool(controllers) and all(
        word in {"cpu", "cpuset", "io", "memory", "hugetlb", "pids", "rdma", "misc"} 
        for word in controllers
    )


def inspect_local_host(
    plan: K3sVMPlan,
    scratch_root: str | Path,
    *,
    meminfo_path: Path = Path("/proc/meminfo"),
    kvm_path: Path = Path("/dev/kvm"),
    controllers_path: Path = Path("/sys/fs/cgroup/cgroup.controllers"),
    cpu_count: Callable[[], int | None] = os.cpu_count,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> LocalHostObservation:
    """Collect minimal local facts by explicit invocation. No guest operations.

    Untrusted ancestor directories and same-UID racing writers are OUTSIDE
    this tool's filesystem threat boundary; the nominated scratch root must
    be operator-controlled. Path is never included in output.
    """
    if type(plan) is not K3sVMPlan:
        raise HostObservationError("Validated SC-12 plan required")
    try:
        validated = validate_vm_plan_bytes(plan.canonical_json)
    except (VMPlanError, AttributeError, TypeError, ValueError) as exc:
        raise HostObservationError("Invalid SC-12 plan") from exc
    if validated != plan:
        raise HostObservationError("VM plan digest or identity changed")
    fd = None
    try:
        fd = os.open(Path(scratch_root), _DIR_FLAGS)
        identity = os.fstat(fd)
        if not stat.S_ISDIR(identity.st_mode):
            raise HostObservationError("Scratch root must be an existing directory")
        filesystem = os.fstatvfs(fd)
    except OSError as exc:
        raise HostObservationError("Cannot inspect selected existing non-symlink scratch root") from exc
    finally:
        if fd is not None:
            os.close(fd)
    if filesystem.f_frsize <= 0 or filesystem.f_bavail < 0 or filesystem.f_favail < 0:
        raise HostObservationError("Scratch filesystem returned invalid capacity counters")
    free_gib = (filesystem.f_frsize * filesystem.f_bavail) // GIB_BYTES
    free_inodes = filesystem.f_favail
    ncpu = cpu_count()
    if type(ncpu) is not int or not 1 <= ncpu <= 1024:
        raise HostObservationError("Logical CPU count unavailable or invalid")
    available_mib = _parse_available_memory(_read_fixed_regular(meminfo_path, MEMINFO_LIMIT))
    stamp = now()
    if type(stamp) is not datetime or stamp.tzinfo is None or stamp.utcoffset() is None:
        raise HostObservationError("Timestamp must be timezone-aware")
    stamp = stamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    kvm_present = _is_kvm_character_device(kvm_path)
    cgroups_present = _has_cgroup_v2_controllers(controllers_path)
    guest = validated.design["guest"]
    blockers: list[str] = []
    if ncpu < guest["vcpu"] + CPU_RESERVE_THREADS:
        blockers.append("visible_cpu_threads_below_declared_headroom")
    if available_mib < guest["ram_mib"] + MEMORY_RESERVE_MIB:
        blockers.append("mem_available_below_declared_headroom")
    if free_gib < guest["disk_gib"] + DISK_HEADROOM_GIB:
        blockers.append("scratch_free_disk_below_declared_headroom")
    if free_inodes < 100000:
        blockers.append("scratch_available_inodes_below_threshold")
    if not kvm_present:
        blockers.append("kvm_character_device_not_observed")
    if not cgroups_present:
        blockers.append("cgroup_v2_controllers_not_observed")
    numeric_fit = not any(s in blockers for s in (
        "visible_cpu_threads_below_declared_headroom",
        "mem_available_below_declared_headroom",
        "scratch_free_disk_below_declared_headroom",
        "scratch_available_inodes_below_threshold",
    ))
    blockers.extend((
        "kvm_device_presence_does_not_verify_nested_kvm_usability",
        "effective_cgroup_quotas_and_concurrent_load_not_verified",
        "provider_permission_and_active_guest_count_not_verified",
        "real_vm_image_network_isolation_and_cleanup_not_verified",
        "guest_execution_requires_separate_owner_approval",
    ))
    return LocalHostObservation(
        validated.name, validated.digest_sha256, stamp,
        ncpu, available_mib, free_gib, free_inodes,
        kvm_present, cgroups_present,
        "observed_numeric_thresholds_met" if numeric_fit else "observed_numeric_thresholds_not_met",
        tuple(blockers),
    )
