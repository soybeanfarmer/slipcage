"""SC-13b7: read-only, conservative QCOW2 BASE header / overlay-intent preflight.

This does NOT parse the full QCOW2 refcount/L1/L2 graph, authenticate upstream
publishers, prove base immutability, allocate overlays, call qemu-img/QEMU,
inspect a live host, mount guest disks, or prove a runtime backing chain.

The operator controls private file roots and their ancestors. Same-UID
adversarial writes and hostile ancestor traversal are outside this scope.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat

from .vm_assets import ARTIFACTS, VMAssetPreflight
from .vm_plan import K3sVMPlan
from .vm_qemu_blueprint import QemuBlueprintError, build_qemu_blueprint
from .vm_reservation import LocalReservation, OVERLAY_INTENT_NAME

API_VERSION = "slipcage.dev/qcow2-overlay-preflight/v1alpha1"
BASE_NAME = "os-image.qcow2"
CLUSTER_BITS = 16
CLUSTER_BYTES = 1 << CLUSTER_BITS
HEADER_BYTES = 112  # v3 standard 104-byte header + 8-byte extension terminator
GIB = 1024 ** 3
_MAX_BASE_BYTES = next(cap for field, name, cap in ARTIFACTS if name == BASE_NAME)
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)


class OverlayPreflightError(ValueError):
    """Base shape, hash, or reservation binding fails closed."""


def _uint(raw: bytes, start: int, end: int) -> int:
    return int.from_bytes(raw[start:end], "big")


def _inspect_base_header(header: bytes, actual_size: int, expected_virtual: int) -> dict:
    """Allow only a deliberately narrow v3 header subset.

    This is NOT a full QCOW2 structural validity or integrity check.
    """
    if len(header) != HEADER_BYTES or header[:4] != b"QFI\xfb":
        raise OverlayPreflightError("QCOW2 magic or minimum header is missing")
    if _uint(header, 4, 8) != 3:
        raise OverlayPreflightError("Only QCOW2 version 3 base headers are supported")
    if _uint(header, 8, 16) or _uint(header, 16, 20):
        raise OverlayPreflightError("Base image must have NO backing file reference")
    if _uint(header, 20, 24) != CLUSTER_BITS:
        raise OverlayPreflightError("Only fixed 64-KiB QCOW2 clusters are supported")
    virtual_size = _uint(header, 24, 32)
    if virtual_size != expected_virtual or virtual_size % 512 != 0:
        raise OverlayPreflightError("QCOW2 virtual size does not match pinned guest disk budget")
    if _uint(header, 32, 36) != 0:
        raise OverlayPreflightError("Encrypted QCOW2 bases are unsupported")
    l1_count = _uint(header, 36, 40)
    l1_offset = _uint(header, 40, 48)
    ref_offset = _uint(header, 48, 56)
    ref_clusters = _uint(header, 56, 60)
    if _uint(header, 60, 64) or _uint(header, 64, 72):
        raise OverlayPreflightError("QCOW2 internal snapshots are unsupported")
    if (
        _uint(header, 72, 80) != 0
        or _uint(header, 80, 88) != 0
        or _uint(header, 88, 96) != 0
    ):
        raise OverlayPreflightError("QCOW2 dirty, external, compatible and autoclear features forbidden")
    if _uint(header, 96, 100) != 4 or _uint(header, 100, 104) != 104:
        raise OverlayPreflightError("Unexpected QCOW2 refcount order or header length")
    if any(header[104:112]):
        raise OverlayPreflightError("QCOW2 header extensions are not allowed")
    if not (1 <= l1_count <= 1048576 and 1 <= ref_clusters <= 16):
        raise OverlayPreflightError("QCOW2 L1/refcount table sizes outside supported bounds")
    l1_length = ((l1_count * 8 + CLUSTER_BYTES - 1) // CLUSTER_BYTES) * CLUSTER_BYTES
    ref_length = ref_clusters * CLUSTER_BYTES
    for offset, length in ((l1_offset, l1_length), (ref_offset, ref_length)):
        if (offset < CLUSTER_BYTES or offset % CLUSTER_BYTES
                or offset + length > actual_size):
            raise OverlayPreflightError("QCOW2 header table offsets outside physical image")
    if l1_offset < ref_offset + ref_length and ref_offset < l1_offset + l1_length:
        raise OverlayPreflightError("QCOW2 active L1/refcount table ranges overlap")
    return {
        "qcow2_version": 3,
        "cluster_bytes": CLUSTER_BYTES,
        "virtual_size_bytes": virtual_size,
        "observed_backing_file_reference": False,
        "observed_internal_snapshots": False,
        "observed_incompatible_features": False,
    }


def _read_and_hash_base(asset_root: str | Path, expected_digest: str,
                        expected_virtual: int) -> tuple[dict, int]:
    root_fd = None
    try:
        root_fd = os.open(Path(asset_root), _DIR_FLAGS)
        root_info = os.fstat(root_fd)
        if not stat.S_ISDIR(root_info.st_mode) or stat.S_IMODE(root_info.st_mode) & 0o077:
            raise OverlayPreflightError("Base image root must be an existing private directory")
        if set(os.listdir(root_fd)) != {name for _, name, _ in ARTIFACTS}:
            raise OverlayPreflightError("Private asset directory contains unexpected entries")
        fd = os.open(BASE_NAME, _FILE_FLAGS, dir_fd=root_fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            os.close(fd)
            raise OverlayPreflightError("QCOW2 base must be a regular file, not directory/device")
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077
                    or not HEADER_BYTES <= info.st_size <= _MAX_BASE_BYTES):
                raise OverlayPreflightError("QCOW2 base must be private, single-link and size-bounded")
            header = stream.read(HEADER_BYTES)
            summary = _inspect_base_header(header, info.st_size, expected_virtual)
            digest = hashlib.sha256()
            digest.update(header)
            total = len(header)
            while True:
                chunk = stream.read(min(1024 * 1024, _MAX_BASE_BYTES + 1 - total))
                if not chunk:
                    break
                digest.update(chunk)
                total += len(chunk)
                if total > _MAX_BASE_BYTES:
                    raise OverlayPreflightError("QCOW2 base exceeds byte cap")
            after = os.fstat(stream.fileno())
            if (total != info.st_size
                    or (info.st_dev, info.st_ino, info.st_size,
                        info.st_mtime_ns, info.st_ctime_ns)
                    != (after.st_dev, after.st_ino, after.st_size,
                        after.st_mtime_ns, after.st_ctime_ns)):
                raise OverlayPreflightError("QCOW2 base changed during reading")
            path_info = os.stat(BASE_NAME, dir_fd=root_fd, follow_symlinks=False)
            if (not stat.S_ISREG(path_info.st_mode)
                    or (path_info.st_dev, path_info.st_ino) != (after.st_dev, after.st_ino)):
                raise OverlayPreflightError("QCOW2 base filename changed during reading")
            if digest.hexdigest() != expected_digest:
                raise OverlayPreflightError("QCOW2 base SHA-256 differs from pinned artifact")
            return summary, total
    except OSError as exc:
        raise OverlayPreflightError("Could not inspect existing private QCOW2 base file") from exc
    finally:
        if root_fd is not None:
            os.close(root_fd)


@dataclass(frozen=True, slots=True)
class OverlayIntentPreflight:
    plan_id: str
    plan_digest_sha256: str
    reservation_digest_sha256: str
    base_sha256: str
    base_size_bytes: int
    header: dict
    overlay_budget_gib: int
    runtime_budget_seconds: int

    def to_dict(self) -> dict:
        return {
            "api_version": API_VERSION,
            "kind": "nonexecuting_overlay_backing_intent",
            "plan_id": self.plan_id,
            "plan_digest_sha256": self.plan_digest_sha256,
            "reservation_digest_sha256": self.reservation_digest_sha256,
            "base_filename_token": BASE_NAME,
            "base_sha256_matches_operator_declared_digest": True,
            "base_digest_sha256": self.base_sha256,
            "base_file_size_bytes": self.base_size_bytes,
            "qcow2_header_shape": dict(self.header),
            "base_has_no_declared_backing_file": True,
            "overlay_filename_token": OVERLAY_INTENT_NAME,
            "overlay_budget_gib_declared": self.overlay_budget_gib,
            "runtime_budget_seconds_declared": self.runtime_budget_seconds,
            "overlay_create_command_present": False,
            "overlay_created": False,
            "backing_chain_created": False,
            "backing_chain_traversed": False,
            "qcow2_refcount_l1_l2_integrity_verified": False,
            "immutable_base_enforced": False,
            "actual_backing_file_resolution_verified": False,
            "host_disk_quota_enforced": False,
            "host_kvm_usable_verified": False,
            "software_publisher_authenticated": False,
            "qemu_or_qemu_img_executed": False,
            "guest_boot_verified": False,
            "cleanup_verified_on_host": False,
            "execution_authorized": False,
            "host_modified": False,
        }

    def canonical_json(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")


def inspect_overlay_intent(
    plan: K3sVMPlan, preflight: VMAssetPreflight, reservation: LocalReservation,
    asset_root: str | Path,
) -> OverlayIntentPreflight:
    """Check fixed QCOW2 BASE header + hash and binding to single-use intent.

    No writable overlay path or complete QEMU command is produced.
    The CLI freshly rechecks local asset bytes and reads reservation record.
    """
    if type(reservation) is not LocalReservation:
        raise OverlayPreflightError("Typed SC-13b6 reservation required")
    try:
        blueprint = build_qemu_blueprint(plan, preflight)
    except QemuBlueprintError as exc:
        raise OverlayPreflightError("Exact plan and byte-checked assets required") from exc
    if (reservation.quarantined
            or reservation.quarantine_reason is not None
            or reservation.plan_id != blueprint.plan_id
            or reservation.plan_digest_sha256 != blueprint.plan_digest_sha256
            or reservation.overlay_name != OVERLAY_INTENT_NAME
            or reservation.overlay_budget_gib != blueprint.guest_disk_gib
            or reservation.runtime_budget_seconds != blueprint.max_runtime_seconds
            or type(reservation.record_digest_sha256) is not str
            or len(reservation.record_digest_sha256) != 64
            or any(c not in "0123456789abcdef" for c in reservation.record_digest_sha256)):
        raise OverlayPreflightError("Staged reservation is unsafe, quarantined or belongs to another VM plan")
    header, count = _read_and_hash_base(
        asset_root, blueprint.backing_image_digest_sha256, blueprint.guest_disk_gib * GIB,
    )
    return OverlayIntentPreflight(
        blueprint.plan_id, blueprint.plan_digest_sha256,
        reservation.record_digest_sha256, blueprint.backing_image_digest_sha256,
        count, header, blueprint.guest_disk_gib, blueprint.max_runtime_seconds,
    )
