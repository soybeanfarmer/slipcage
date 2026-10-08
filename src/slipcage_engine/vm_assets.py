"""SC-13b1: read-only local-byte verification for proposed K3s VM assets.

This deliberately has NO QEMU invocation, disk creation, image mounting,
archive extraction, network activity, provider probing, or launch capability.
Matching operator-supplied hashes is NOT authentication of software origin,
host readiness, image contents, or permission to execute a guest.

Trusted operator controls the root and all its ancestors. This code does not
claim hostile same-UID or multi-tenant filesystem race resistance.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat

from .vm_plan import K3sVMPlan, VMPlanError, validate_vm_plan_bytes

API_VERSION = "slipcage.dev/vm-assets-local-check/v1alpha1"
CHUNK_BYTES = 1024 * 1024

# Exactly five fixed file names. These are opaque byte streams, not formats
# to parse, execute, boot, mount, unpack, or trust.
# Limits cap the read workload and reject unexpected resource consumption.
ARTIFACTS: tuple[tuple[str, str, int], ...] = (
    ("os_image_sha256", "os-image.qcow2", 20 * 1024**3),
    ("kernel_sha256", "kernel.bin", 512 * 1024**2),
    ("k3s_binary_sha256", "k3s.bin", 512 * 1024**2),
    ("cni_assets_sha256", "cni-assets.tar", 1024**3),
    ("container_images_sha256", "container-images.tar", 16 * 1024**3),
)
TOTAL_MAX_BYTES = sum(row[2] for row in ARTIFACTS)
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)


class VMAssetError(ValueError):
    """An artifact is missing, unsafe, changed, or inconsistent with the plan."""


@dataclass(frozen=True, slots=True)
class VerifiedLocalAsset:
    digest_field: str
    filename: str
    sha256: str
    size_bytes: int

    def to_dict(self) -> dict:
        return {
            "digest_field": self.digest_field,
            "filename": self.filename,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "local_bytes_match_declared_hash": True,
        }


@dataclass(frozen=True, slots=True)
class VMAssetPreflight:
    plan_id: str
    plan_digest_sha256: str
    assets: tuple[VerifiedLocalAsset, ...]

    def to_dict(self) -> dict:
        return {
            "api_version": API_VERSION,
            "status": "local_bytes_match_untrusted_pin_declarations",
            "plan_id": self.plan_id,
            "plan_digest_sha256": self.plan_digest_sha256,
            "artifact_count": len(self.assets),
            "total_size_bytes": sum(a.size_bytes for a in self.assets),
            "assets": [a.to_dict() for a in self.assets],
            "content_sha256_matches_declared_pins": True,
            "software_origin_authenticated": False,
            "image_contents_security_reviewed": False,
            "host_kvm_verified": False,
            "provider_permission_verified": False,
            "host_capacity_verified": False,
            "guest_network_isolation_verified": False,
            "guest_boot_verified": False,
            "execution_authorized": False,
            "host_modified": False,
            "vm_launched": False,
        }

    def canonical_json(self) -> bytes:
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("ascii")


def _opened_regular_digest(
    directory_fd: int,
    name: str,
    max_bytes: int,
    expected: str,
) -> tuple[str, int]:
    try:
        fd = os.open(name, _FILE_FLAGS, dir_fd=directory_fd)
    except OSError as exc:
        raise VMAssetError(f"Artifact {name} missing or unsafe") from exc
    # An opened directory cannot be wrapped by fdopen(..., "rb").
    # Reject nonregular descriptors first, closing them before returning.
    first = os.fstat(fd)
    if not stat.S_ISREG(first.st_mode):
        os.close(fd)
        raise VMAssetError(f"Artifact {name} must be a single-link regular file")
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if before.st_nlink != 1:
            raise VMAssetError(f"Artifact {name} must be a single-link regular file")
        if stat.S_IMODE(before.st_mode) & 0o077:
            raise VMAssetError(f"Artifact {name} must be private (0600)")
        if before.st_size < 1 or before.st_size > max_bytes:
            raise VMAssetError(f"Artifact {name} exceeds its safe size bounds")

        digest = hashlib.sha256()
        consumed = 0
        while True:
            block = stream.read(min(CHUNK_BYTES, max_bytes + 1 - consumed))
            if not block:
                break
            digest.update(block)
            consumed += len(block)
            if consumed > max_bytes:
                raise VMAssetError(f"Artifact {name} grew past its safe byte cap")
        after = os.fstat(stream.fileno())
        if (
            consumed != before.st_size
            or (before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns)
        ):
            raise VMAssetError(f"Artifact {name} changed during verification")
        # Detect simple replacement of the path during hashing. This is not
        # full same-UID adversarial race protection.
        try:
            path_info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise VMAssetError(f"Artifact {name} disappeared during verification") from exc
        if (
            not stat.S_ISREG(path_info.st_mode)
            or (path_info.st_dev, path_info.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise VMAssetError(f"Artifact {name} was replaced during verification")

        actual = digest.hexdigest()
        if actual != expected:
            raise VMAssetError(f"Artifact {name} does not match its declared SHA-256")
        return actual, consumed


def verify_local_vm_assets(
    plan: K3sVMPlan,
    root: str | Path,
) -> VMAssetPreflight:
    """Hash five exact private files in an operator-controlled directory.

    A success proves *only* SHA-256 equality to the supplied, unauthenticated
    SC-12 declarations. A synthetic SC-12 sample plan is refused.
    """
    if type(plan) is not K3sVMPlan:
        raise VMAssetError("A validated K3sVMPlan is required")
    try:
        checked = validate_vm_plan_bytes(plan.canonical_json)
    except (VMPlanError, ValueError, AttributeError, TypeError) as exc:
        raise VMAssetError("Pinned VM plan is invalid") from exc
    if checked != plan:
        raise VMAssetError("Pinned VM plan identity or digest is inconsistent")

    design = plan.design
    if design["provenance"]["pin_status"] != "operator_supplied_unverified":
        raise VMAssetError("Synthetic plan assets are not accepted for local verification")
    # Do not accept a plan that could authorize runtime or external networking.
    if (
        design["safety"]["vm_execution_enabled"] is not False
        or design["safety"]["network_configuration_enabled"] is not False
        or design["network"]["public_egress"] is not False
        or design["guest"]["max_parallel_vms"] != 1
    ):
        raise VMAssetError("Asset verification cannot authorize a VM or network")

    try:
        root_fd = os.open(Path(root), _DIR_FLAGS)
    except OSError as exc:
        raise VMAssetError("Artifact root must be an existing non-symlink directory") from exc

    try:
        info = os.fstat(root_fd)
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            raise VMAssetError("Artifact root must be a private directory (0700)")
        expected_names = {row[1] for row in ARTIFACTS}
        if set(os.listdir(root_fd)) != expected_names:
            raise VMAssetError("Artifact root must contain exactly five pinned files")

        verified: list[VerifiedLocalAsset] = []
        total = 0
        for field, name, max_bytes in ARTIFACTS:
            digest, count = _opened_regular_digest(
                root_fd, name, max_bytes, design["artifacts"][field]
            )
            total += count
            if total > TOTAL_MAX_BYTES:
                raise VMAssetError("Combined artifact size exceeds resource budget")
            verified.append(VerifiedLocalAsset(field, name, digest, count))
    finally:
        os.close(root_fd)

    return VMAssetPreflight(checked.name, checked.digest_sha256, tuple(verified))
