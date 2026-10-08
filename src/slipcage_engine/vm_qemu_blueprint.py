"""SC-13b4 — immutable, NON-EXECUTING QEMU intent from local byte checks.

This module intentionally offers NO process launcher, overlay creator, disk
writer, guest boot, KVM open, network setup, environment variable forwarding,
shell invocation, or real resource supervisor. The argv *prefix* lacks any
kernel/disk/firmware attachment and is NOT a runnable K3s guest configuration.

SC-12 example pins are synthetic; non-synthetic operator-supplied declarations
and SC-13b1 local byte hashing are required. Neither authenticates publishers,
QEMU binaries, guest contents, host readiness or operator permission.
"""
from __future__ import annotations

from dataclasses import dataclass
import json

from .vm_assets import ARTIFACTS, VMAssetPreflight, VerifiedLocalAsset
from .vm_plan import K3sVMPlan, VMPlanError, validate_vm_plan_bytes

API_VERSION = "slipcage.dev/qemu-launch-blueprint/v1alpha1"


class QemuBlueprintError(ValueError):
    """An unsafe, unverified or inconsistent QEMU blueprint input."""


class QemuLaunchDisabled(QemuBlueprintError):
    """Real QEMU execution has no implementation or authorization."""


@dataclass(frozen=True, slots=True)
class QemuLaunchBlueprint:
    plan_id: str
    plan_digest_sha256: str
    qemu_version_declared: str
    argv_prefix: tuple[str, ...]
    backing_image_digest_sha256: str
    kernel_digest_sha256: str
    guest_vcpu: int
    guest_ram_mib: int
    guest_disk_gib: int
    max_runtime_seconds: int

    def to_dict(self) -> dict:
        return {
            "api_version": API_VERSION,
            "kind": "offline_incomplete_qemu_launch_blueprint",
            "plan_id": self.plan_id,
            "plan_digest_sha256": self.plan_digest_sha256,
            "qemu_version_declared": self.qemu_version_declared,
            "qemu_argv_prefix": list(self.argv_prefix),
            "backing_image_sha256_declared_and_locally_matched": self.backing_image_digest_sha256,
            "kernel_sha256_declared_and_locally_matched": self.kernel_digest_sha256,
            "guest_vcpu_declared": self.guest_vcpu,
            "guest_ram_mib_declared": self.guest_ram_mib,
            "guest_disk_gib_declared": self.guest_disk_gib,
            "max_runtime_seconds_declared": self.max_runtime_seconds,
            "max_parallel_vms_declared": 1,
            "disk_attachment": "absent",
            "guest_kernel_attachment": "absent",
            "network_attachment": "absent",
            "console_attachment": "absent",
            "qemu_paused_if_prefix_executed": True,
            "argv_is_complete_launch_command": False,
            "guest_boot_possible_from_blueprint": False,
            "asset_byte_integrity_checked_locally": True,
            "asset_software_origin_authenticated": False,
            "qemu_binary_version_verified": False,
            "guest_image_contents_verified": False,
            "guest_network_isolation_verified": False,
            "host_kvm_usable_verified": False,
            "host_resources_reserved": False,
            "process_cgroup_limits_enforced": False,
            "runtime_deadline_enforced": False,
            "guest_overlay_created": False,
            "crash_cleanup_verified": False,
            "operator_launch_approved": False,
            "execution_authorized": False,
            "real_vm_launched": False,
            "host_modified": False,
            "blockers": [
                "qemu_binary_and_machine_compatibility_not_verified",
                "publisher_identity_and_guest_contents_not_authenticated",
                "trusted_immutable_backing_chain_not_configured",
                "private_disposable_overlay_and_cleanup_not_implemented",
                "console_control_channel_and_boot_image_not_attached",
                "guest_network_and_k3s_isolation_not_proven",
                "host_kvm_cgroup_disk_runtime_limits_not_verified_or_enforced",
                "provider_and_owner_vm_launch_permission_not_verified",
                "real_launcher_intentionally_absent",
            ],
        }

    def canonical_json(self) -> bytes:
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("ascii")


def _validated_inputs(plan: K3sVMPlan, preflight: VMAssetPreflight) -> dict:
    if type(plan) is not K3sVMPlan or type(preflight) is not VMAssetPreflight:
        raise QemuBlueprintError("Require typed SC-12 plan and SC-13b1 byte preflight")
    try:
        checked = validate_vm_plan_bytes(plan.canonical_json)
    except (VMPlanError, AttributeError, ValueError, TypeError) as exc:
        raise QemuBlueprintError("VM plan is malformed") from exc
    if checked != plan:
        raise QemuBlueprintError("VM plan identity, digest or canonical bytes changed")
    config = checked.design
    if config["provenance"]["pin_status"] != "operator_supplied_unverified":
        raise QemuBlueprintError("Synthetic example VM pins are never acceptable")
    if preflight.plan_id != checked.name or preflight.plan_digest_sha256 != checked.digest_sha256:
        raise QemuBlueprintError("Local preflight is not bound to exact VM plan")
    if type(preflight.assets) is not tuple or len(preflight.assets) != len(ARTIFACTS):
        raise QemuBlueprintError("Five ordered locally checked assets required")
    for actual, (digest_field, filename, max_bytes) in zip(preflight.assets, ARTIFACTS):
        if (
            type(actual) is not VerifiedLocalAsset
            or actual.digest_field != digest_field
            or actual.filename != filename
            or type(actual.sha256) is not str
            or actual.sha256 != config["artifacts"][digest_field]
            or type(actual.size_bytes) is not int
            or not 1 <= actual.size_bytes <= max_bytes
        ):
            raise QemuBlueprintError("Preflight asset identity, size or digest mismatch")
    if (
        config["safety"]["vm_execution_enabled"] is not False
        or config["safety"]["network_configuration_enabled"] is not False
        or config["network"]["public_egress"] is not False
        or config["network"]["host_bridging"] is not False
        or config["guest"]["max_parallel_vms"] != 1
        or config["guest"]["ephemeral_overlay"] is not True
    ):
        raise QemuBlueprintError("Unsupported guest execution or network intent")
    return config


def build_qemu_blueprint(plan: K3sVMPlan, preflight: VMAssetPreflight) -> QemuLaunchBlueprint:
    """Construct ONLY the intentionally incomplete, paused, diskless argv prefix.

    The binary name in this prefix is descriptive, not resolved via PATH,
    verified on disk, or invoked. No user-supplied argv/paths/extra options are
    accepted. An actual launch adapter requires a future independent PR.
    """
    config = _validated_inputs(plan, preflight)
    guest = config["guest"]
    runtime = config["runtime"]
    argv = (
        "qemu-system-x86_64",
        "-no-user-config",
        "-nodefaults",
        "-machine", runtime["machine_type"] + ",accel=kvm",
        "-cpu", "x86-64-v2",
        "-smp", str(guest["vcpu"]),
        "-m", str(guest["ram_mib"]),
        "-display", "none",
        "-monitor", "none",
        "-serial", "none",
        "-nic", "none",
        "-S",
        "-no-reboot",
    )
    return QemuLaunchBlueprint(
        plan_id=plan.name,
        plan_digest_sha256=plan.digest_sha256,
        qemu_version_declared=runtime["qemu_version"],
        argv_prefix=argv,
        backing_image_digest_sha256=config["artifacts"]["os_image_sha256"],
        kernel_digest_sha256=config["artifacts"]["kernel_sha256"],
        guest_vcpu=guest["vcpu"],
        guest_ram_mib=guest["ram_mib"],
        guest_disk_gib=guest["disk_gib"],
        max_runtime_seconds=guest["max_runtime_seconds"],
    )


def launch_qemu(_blueprint: QemuLaunchBlueprint) -> None:
    """Intentionally unimplemented. Never create a process or host artifact."""
    raise QemuLaunchDisabled(
        "QEMU launching is not implemented or authorized; an approved "
        "resource-supervised adapter and real host evidence are required"
    )
