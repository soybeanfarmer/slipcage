"""SC-12 non-executable, pinned K3s VM design and capacity feasibility.

Validates declared digests/versions and *operator-reported* host figures only.
It never inspects a real host, hashes actual VM assets, launches QEMU, creates
disks, changes network config, invokes a shell, or authorizes any workload.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any

import jsonschema

VM_PLAN_API_VERSION = "slipcage.dev/vm-plan/v1alpha1"
HOST_INVENTORY_API_VERSION = "slipcage.dev/host-inventory/v1alpha1"
ASSESSMENT_API_VERSION = "slipcage.dev/vm-assessment/v1alpha1"
MAX_INPUT_BYTES = 32 * 1024
CPU_RESERVE_THREADS = 2
MEMORY_RESERVE_MIB = 4096
DISK_HEADROOM_GIB = 16


class VMPlanError(ValueError):
    """Invalid, non-pinned, unsafe or unsupported offline design input."""


def _reject_constant(_value):
    raise VMPlanError("JSON nonfinite values are forbidden")


def _reject_float(_value):
    raise VMPlanError("JSON fractional values are forbidden in pinned plans")


def _strict_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise VMPlanError("Duplicate keys are forbidden")
        value[key] = item
    return value


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


@lru_cache(maxsize=2)
def _validator(name: str) -> jsonschema.Draft202012Validator:
    if name not in ("k3s-vm-plan-v1alpha1.schema.json",
                    "operator-host-inventory-v1alpha1.schema.json"):
        raise VMPlanError("Unsupported schema")
    source = resources.files("slipcage_engine").joinpath("schemas", name)
    with source.open("r", encoding="utf-8") as stream:
        schema = json.load(stream)
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def _parse(data: bytes, schema_name: str) -> tuple[dict, bytes]:
    if type(data) is not bytes or not 1 <= len(data) <= MAX_INPUT_BYTES:
        raise VMPlanError("Plan/inventory JSON must be 1 to 32768 bytes")
    try:
        document = json.loads(data.decode("utf-8"), object_pairs_hook=_strict_pairs,
                              parse_constant=_reject_constant, parse_float=_reject_float)
    except VMPlanError:
        raise
    except (UnicodeError, ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise VMPlanError("Input must contain strict UTF-8 JSON") from exc
    errors = sorted(_validator(schema_name).iter_errors(document),
                    key=lambda e: ("/".join(map(str, e.absolute_path)), e.validator))
    if errors:
        issue = errors[0]
        position = "/" + "/".join(map(str, issue.absolute_path))
        raise VMPlanError(f"Invalid SC-12 input at {position}: {issue.validator}")
    return document, _canonical(document)


def _read_file(path: str | Path) -> bytes:
    path = Path(path)
    if path.suffix != ".json":
        raise VMPlanError("Only local .json files are supported")
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as source:
            fd = None
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_INPUT_BYTES:
                raise VMPlanError("Input must be a bounded regular file")
            value = source.read(MAX_INPUT_BYTES + 1)
            if len(value) != info.st_size:
                raise VMPlanError("Input size changed while being read")
            return value
    except OSError as exc:
        raise VMPlanError("Could not read non-symlink local input") from exc
    finally:
        if fd is not None:
            os.close(fd)


@dataclass(frozen=True, slots=True)
class K3sVMPlan:
    name: str
    digest_sha256: str
    canonical_json: bytes

    @property
    def design(self) -> dict:
        return json.loads(self.canonical_json)


@dataclass(frozen=True, slots=True)
class ReportedHostInventory:
    canonical_json: bytes

    @property
    def inventory(self) -> dict:
        return json.loads(self.canonical_json)


def validate_vm_plan_bytes(data: bytes) -> K3sVMPlan:
    value, canonical = _parse(data, "k3s-vm-plan-v1alpha1.schema.json")
    # Do not permit a moving q35 alias, and pin the QEMU machine series
    # to the major/minor of the declared QEMU binary.
    machine = value["runtime"]["machine_type"].removeprefix("pc-q35-")
    qemu_series = ".".join(value["runtime"]["qemu_version"].split(".")[:2])
    if machine != qemu_series:
        raise VMPlanError("Machine type version must match declared QEMU major/minor")
    if value["provenance"]["pin_status"] == "operator_supplied_unverified":
        if "synthetic" in value["software"]["guest_kernel_release"].lower():
            raise VMPlanError("Synthetic kernel label cannot be an operator artifact pin")
    return K3sVMPlan(value["metadata"]["id"], hashlib.sha256(canonical).hexdigest(), canonical)


def load_vm_plan(path: str | Path) -> K3sVMPlan:
    return validate_vm_plan_bytes(_read_file(path))


def validate_host_inventory_bytes(data: bytes) -> ReportedHostInventory:
    _, canonical = _parse(data, "operator-host-inventory-v1alpha1.schema.json")
    return ReportedHostInventory(canonical)


def load_host_inventory(path: str | Path) -> ReportedHostInventory:
    return validate_host_inventory_bytes(_read_file(path))


@dataclass(frozen=True, slots=True)
class VMFeasibility:
    plan_id: str
    plan_digest_sha256: str
    pin_status: str
    requirements: dict[str, int]
    declared_capacity: dict[str, Any] | None
    capacity_result: str
    blockers: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "api_version": ASSESSMENT_API_VERSION,
            "kind": "offline_design_assessment",
            "plan_id": self.plan_id,
            "plan_digest_sha256": self.plan_digest_sha256,
            "pin_status": self.pin_status,
            "requirements": dict(self.requirements),
            "declared_capacity": dict(self.declared_capacity) if self.declared_capacity is not None else None,
            "capacity_result": self.capacity_result,
            "blockers": list(self.blockers),
            "status": "design_only",
            "capacity_source": "operator_reported_unverified" if self.declared_capacity is not None else "unknown",
            "artifacts_verified": False,
            "kvm_verified_on_target_host": False,
            "provider_permission_verified": False,
            "network_isolation_verified": False,
            "k3s_boot_verified": False,
            "execution_authorized": False,
            "executable": False,
            "host_modified": False,
            "vm_launched": False,
        }

    def canonical_json(self) -> bytes:
        return _canonical(self.to_dict())


def assess_vm_plan(plan: K3sVMPlan,
                   inventory: ReportedHostInventory | None = None) -> VMFeasibility:
    """Compare operator-provided capacity numbers, not measured host facts."""
    if type(plan) is not K3sVMPlan:
        raise VMPlanError("Expected a validated K3sVMPlan")
    checked = validate_vm_plan_bytes(plan.canonical_json)
    if plan != checked:
        raise VMPlanError("Plan metadata does not match canonical contents")
    if inventory is not None:
        if type(inventory) is not ReportedHostInventory:
            raise VMPlanError("Expected a typed operator-reported inventory")
        checked_inventory = validate_host_inventory_bytes(inventory.canonical_json)
        if inventory != checked_inventory:
            raise VMPlanError("Host inventory is not canonical")
        host = inventory.inventory
    else:
        host = None
    guest = plan.design["guest"]
    required = {
        "minimum_cpu_threads": guest["vcpu"] + CPU_RESERVE_THREADS,
        "minimum_memory_mib": guest["ram_mib"] + MEMORY_RESERVE_MIB,
        "minimum_free_disk_gib": guest["disk_gib"] + DISK_HEADROOM_GIB,
        "guest_vcpu": guest["vcpu"],
        "guest_memory_mib": guest["ram_mib"],
        "guest_disk_gib": guest["disk_gib"],
        "max_parallel_vms": 1,
    }
    blockers = [
        "VM images, kernel, K3s, CNI and container image bytes were not verified",
        "VM execution and guest networking are not implemented or approved",
        "Nested-KVM guest boot and provider permission require independent operator proof",
        "CPU model compatibility and guest-internal networking require live testing",
    ]
    fit = "unknown"
    declared = None
    if host is not None:
        declared = {
            "cpu_threads": host["cpu_threads"],
            "memory_mib": host["memory_mib"],
            "free_disk_gib": host["free_disk_gib"],
            "kvm_status": host["kvm_status"],
            "provider_authorization": host["provider_authorization"],
        }
        good = (
            host["cpu_threads"] >= required["minimum_cpu_threads"]
            and host["memory_mib"] >= required["minimum_memory_mib"]
            and host["free_disk_gib"] >= required["minimum_free_disk_gib"]
        )
        fit = "fits_reported_capacity" if good else "reported_capacity_insufficient"
        if not good:
            blockers.append("Operator-reported CPU, RAM or free-disk capacity is insufficient")
        if host["kvm_status"] != "reported_ready":
            blockers.append("Operator has not reported working nested KVM")
        if host["provider_authorization"] != "operator_reports_permission":
            blockers.append("Provider permission has not been reported by the operator")
    else:
        blockers.append("No operator-reported host capacity inventory was provided")
    if plan.design["provenance"]["pin_status"] == "synthetic_fixture":
        blockers.append("Artifact digests and software versions are synthetic test values")
    return VMFeasibility(plan.name, plan.digest_sha256,
                         plan.design["provenance"]["pin_status"], required,
                         declared, fit, tuple(blockers))
