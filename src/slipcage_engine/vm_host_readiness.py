"""SC-13b2 conservative OFFLINE evaluation of operator-supplied host snapshots.

No SSH or /dev/kvm access. Caller-provided values are not independently
measured, authenticated, timestamp-verified, or permission to launch a VM.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path

from .vm_plan import (
    K3sVMPlan, VMPlanError, _read_file, _strict_pairs,
    _reject_constant, _reject_float, _canonical, validate_vm_plan_bytes,
    CPU_RESERVE_THREADS, MEMORY_RESERVE_MIB, DISK_HEADROOM_GIB,
)

API_VERSION = "slipcage.dev/vm-host-snapshot/v1alpha1"
CHECK_VERSION = "slipcage.dev/vm-host-readiness/v1alpha1"
_REQUIRED = {
    "api_version", "source", "captured_at_utc", "plan_digest_sha256",
    "logical_cpu_threads", "available_memory_mib", "free_disk_gib", "free_inodes",
    "kvm_device_reported", "kvm_usable_reported", "cgroup_v2_reported",
    "provider_scope", "active_guest_count",
}


class VMHostReadinessError(ValueError):
    """Invalid or insufficient operator-declared VM host evidence."""


@dataclass(frozen=True, slots=True)
class VMHostSnapshot:
    canonical_json: bytes

    @property
    def fields(self) -> dict:
        return json.loads(self.canonical_json)


@dataclass(frozen=True, slots=True)
class HostReadinessAssessment:
    plan_id: str
    plan_digest_sha256: str
    capacity_assessment: str
    blockers: tuple[str, ...]
    declared: dict

    def to_dict(self) -> dict:
        return {
            "api_version": CHECK_VERSION,
            "status": "operator_reported_snapshot_assessed",
            "plan_id": self.plan_id,
            "plan_digest_sha256": self.plan_digest_sha256,
            "capacity_assessment": self.capacity_assessment,
            "blockers": list(self.blockers),
            "declared_snapshot": dict(self.declared),
            "snapshot_source": "operator_supplied_unverified",
            "snapshot_authenticity_verified": False,
            "snapshot_freshness_verified": False,
            "host_readiness_independently_verified": False,
            "nested_kvm_test_performed": False,
            "provider_permission_verified": False,
            "vm_image_verified": False,
            "network_isolation_verified": False,
            "execution_authorized": False,
            "host_modified": False,
            "vm_launched": False,
        }

    def canonical_json(self) -> bytes:
        return _canonical(self.to_dict())


def validate_host_snapshot_bytes(data: bytes) -> VMHostSnapshot:
    if type(data) is not bytes or not 1 <= len(data) <= 32 * 1024:
        raise VMHostReadinessError("Host snapshot JSON size invalid")
    try:
        obj = json.loads(
            data.decode("utf-8"), object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant, parse_float=_reject_float,
        )
    except (UnicodeError, ValueError, RecursionError, OverflowError, TypeError) as exc:
        raise VMHostReadinessError("Invalid host snapshot JSON") from exc
    if type(obj) is not dict or set(obj) != _REQUIRED:
        raise VMHostReadinessError("Unknown or missing host snapshot fields")
    if obj["api_version"] != API_VERSION or obj["source"] != "operator_supplied_unverified":
        raise VMHostReadinessError("Unsupported host snapshot version or source")
    stamp = obj["captured_at_utc"]
    if type(stamp) is not str or len(stamp) != 20 or not stamp.endswith("Z"):
        raise VMHostReadinessError("Host snapshot timestamp must be UTC seconds")
    try:
        date = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ")
        if date.strftime("%Y-%m-%dT%H:%M:%SZ") != stamp:
            raise ValueError("timestamp")
    except ValueError as exc:
        raise VMHostReadinessError("Invalid host snapshot timestamp") from exc
    digest = obj["plan_digest_sha256"]
    if type(digest) is not str or len(digest) != 64 or any(x not in "0123456789abcdef" for x in digest):
        raise VMHostReadinessError("Invalid plan digest")
    bounds = {
        "logical_cpu_threads": (1, 1024),
        "available_memory_mib": (0, 2**22),
        "free_disk_gib": (0, 2**22),
        "free_inodes": (0, 2**42),
        "active_guest_count": (0, 1024),
    }
    for key, (minimum, maximum) in bounds.items():
        if type(obj[key]) is not int or not minimum <= obj[key] <= maximum:
            raise VMHostReadinessError(f"Invalid operator-declared {key}")
    for key in ("kvm_device_reported", "kvm_usable_reported", "cgroup_v2_reported"):
        if type(obj[key]) is not bool:
            raise VMHostReadinessError(f"Invalid operator-declared {key}")
    if obj["provider_scope"] not in ("unknown", "not_authorized", "operator_reports_permission"):
        raise VMHostReadinessError("Unsupported provider scope value")
    return VMHostSnapshot(_canonical(obj))


def load_host_snapshot(path: str | Path) -> VMHostSnapshot:
    if Path(path).suffix != ".json":
        raise VMHostReadinessError("Host snapshot requires a local JSON file")
    try:
        return validate_host_snapshot_bytes(_read_file(path))
    except VMPlanError as exc:
        raise VMHostReadinessError("Unable to read private local snapshot JSON") from exc


def assess_host_snapshot(plan: K3sVMPlan, snapshot: VMHostSnapshot) -> HostReadinessAssessment:
    if type(plan) is not K3sVMPlan or type(snapshot) is not VMHostSnapshot:
        raise VMHostReadinessError("Validated plan and snapshot required")
    try:
        checked = validate_vm_plan_bytes(plan.canonical_json)
        same = checked == plan
        verified = validate_host_snapshot_bytes(snapshot.canonical_json)
    except (VMPlanError, VMHostReadinessError, AttributeError, TypeError) as exc:
        raise VMHostReadinessError("Invalid or forged assessment input") from exc
    if not same or verified != snapshot:
        raise VMHostReadinessError("Inconsistent assessment fields")
    host = snapshot.fields
    if host["plan_digest_sha256"] != plan.digest_sha256:
        raise VMHostReadinessError("Host snapshot does not bind to supplied plan")
    required = plan.design["guest"]
    blockers = []
    if host["logical_cpu_threads"] < required["vcpu"] + CPU_RESERVE_THREADS:
        blockers.append("reported_cpu_headroom_insufficient")
    if host["available_memory_mib"] < required["ram_mib"] + MEMORY_RESERVE_MIB:
        blockers.append("reported_available_memory_insufficient")
    if host["free_disk_gib"] < required["disk_gib"] + DISK_HEADROOM_GIB:
        blockers.append("reported_free_disk_insufficient")
    if host["free_inodes"] < 100000:
        blockers.append("reported_inode_headroom_insufficient")
    if not host["kvm_device_reported"] or not host["kvm_usable_reported"]:
        blockers.append("nested_kvm_not_reported_usable")
    if not host["cgroup_v2_reported"]:
        blockers.append("cgroup_v2_not_reported")
    if host["active_guest_count"] != 0:
        blockers.append("preexisting_guest_activity")
    if host["provider_scope"] != "operator_reports_permission":
        blockers.append("provider_permission_not_reported")
    blockers.extend([
        "operator_snapshot_is_not_authenticated_or_remeasured",
        "host_services_and_cgroup_limits_not_independently_benchmarked",
        "live_guest_network_isolation_and_cleanup_not_verified",
        "real_vm_launch_requires_separate_explicit_approval",
    ])
    # Even without numeric deficits there is no verified permission/readiness.
    fit = "reported_thresholds_met" if len(blockers) == 4 else "reported_thresholds_not_met"
    declared = {key: host[key] for key in (
        "captured_at_utc", "logical_cpu_threads", "available_memory_mib",
        "free_disk_gib", "free_inodes", "kvm_device_reported",
        "kvm_usable_reported", "cgroup_v2_reported", "provider_scope",
        "active_guest_count",
    )}
    return HostReadinessAssessment(plan.name, plan.digest_sha256, fit, tuple(blockers), declared)
