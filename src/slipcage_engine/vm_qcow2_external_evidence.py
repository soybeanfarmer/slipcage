"""SC-13b17: read-only QEMU *operator-supplied* image-check evidence reconciliation.

The evaluator never invokes qemu-img, QEMU, a guest, shell or host probe.
Uploaded JSON transcripts are unauthenticated and can be entirely forged.
Checking them against a plan and local pinned image DOES NOT prove the
claimed external tool ran, that it was read-only or that image is safe.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .vm_assets import verify_local_vm_assets
from .vm_overlay_preflight import (
    BASE_NAME, CLUSTER_BYTES, GIB, _read_and_hash_base,
)
from .vm_plan import K3sVMPlan

API_VERSION = "slipcage.dev/qcow2-external-evidence/v1alpha1"
_NAMES = frozenset({"capture.json", "info.json", "check.json"})
_CAP = 16384
_HEX = re.compile(r"^[0-9a-f]{64}$")
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
_INFO_COMMAND = ("qemu-img", "info", "--output=json", "-f", "qcow2", BASE_NAME)
_CHECK_COMMAND = ("qemu-img", "check", "--output=json", "-f", "qcow2", BASE_NAME)
_CAPTURE_KEYS = frozenset({
    "api_version", "capture_kind", "capture_origin", "plan_digest_sha256",
    "base_sha256", "base_size_bytes", "qemu_img_version",
    "qemu_img_binary_sha256", "info_command", "check_command",
    "info_exit_code", "check_exit_code", "info_output_sha256",
    "check_output_sha256",
})
_INFO_REQUIRED = frozenset({
    "filename", "format", "virtual-size", "actual-size", "cluster-size",
    "dirty-flag", "encrypted", "compressed", "snapshots",
})
_INFO_OPTIONAL = frozenset({"format-specific"})
_CHECK_REQUIRED = frozenset({"filename", "format", "check-errors"})
_CHECK_OPTIONAL = frozenset({
    "corruptions", "leaks", "corruptions-fixed", "leaks-fixed",
    "total-clusters", "allocated-clusters", "fragmented-clusters",
    "compressed-clusters", "image-end-offset",
})


class Qcow2ExternalEvidenceError(ValueError):
    """Unsafe, noncanonical, changed or mismatched operator-supplied evidence."""


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Qcow2ExternalEvidenceError("Repeated JSON evidence key")
        result[key] = value
    return result


def _reject_number(_):
    raise Qcow2ExternalEvidenceError("Floats/nonfinite JSON evidence forbidden")


def _decode(raw: bytes, *, required: frozenset[str], optional: frozenset[str] = frozenset()) -> dict:
    try:
        obj = json.loads(
            raw.decode("ascii"), object_pairs_hook=_unique,
            parse_float=_reject_number, parse_constant=_reject_number,
        )
        if (type(obj) is not dict
                or not required <= obj.keys()
                or not obj.keys() <= (required | optional)):
            raise Qcow2ExternalEvidenceError("Evidence must contain only permitted QAPI JSON fields")
        return obj
    except (ValueError, UnicodeError, TypeError, OverflowError, RecursionError) as exc:
        raise Qcow2ExternalEvidenceError("Invalid or duplicate-key QEMU evidence JSON") from exc


def _read_file(fd: int, name: str) -> bytes:
    handle = None
    try:
        handle = os.open(name, _FILE, dir_fd=fd)
        before = os.fstat(handle)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600
                or not 1 <= before.st_size <= _CAP):
            raise Qcow2ExternalEvidenceError("Evidence must be a private 0600, bounded single-link file")
        with os.fdopen(handle, "rb") as stream:
            handle = None
            raw = stream.read(_CAP + 1)
            after = os.fstat(stream.fileno())
            if (len(raw) != before.st_size
                    or (before.st_dev, before.st_ino, before.st_size,
                        before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_dev, after.st_ino, after.st_size,
                        after.st_mtime_ns, after.st_ctime_ns)):
                raise Qcow2ExternalEvidenceError("Evidence file changed while reading")
        name_info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if (not stat.S_ISREG(name_info.st_mode)
                or (name_info.st_dev, name_info.st_ino) != (after.st_dev, after.st_ino)):
            raise Qcow2ExternalEvidenceError("Evidence path replaced during read")
        return raw
    except OSError as exc:
        raise Qcow2ExternalEvidenceError("Missing or unsafe private QEMU evidence file") from exc
    finally:
        if handle is not None:
            os.close(handle)


def _is_digest(text: object) -> bool:
    return type(text) is str and _HEX.fullmatch(text) is not None


def _int_in(value: object, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def _validate_info(info: dict, *, virtual: int, physical: int) -> None:
    if (info["filename"] != BASE_NAME or info["format"] != "qcow2"
            or not _int_in(info["virtual-size"], virtual, virtual)
            or not _int_in(info["actual-size"], 0, physical + CLUSTER_BYTES)
            or not _int_in(info["cluster-size"], CLUSTER_BYTES, CLUSTER_BYTES)
            or any(info[key] is not False for key in ("dirty-flag", "encrypted", "compressed"))
            or type(info["snapshots"]) is not list or info["snapshots"]):
        raise Qcow2ExternalEvidenceError("QEMU image-info does not match safe local base shape")
    if "format-specific" in info:
        fmt = info["format-specific"]
        if type(fmt) is not dict or set(fmt) != {"type", "data"} or fmt["type"] != "qcow2":
            raise Qcow2ExternalEvidenceError("Unsupported image-info format-specific descriptor")
        data = fmt["data"]
        # This is a narrow read-only report adapter, not a complete QAPI
        # parser: reject complex or unknown specific features conservatively.
        allowed = {"compat", "refcount-bits", "lazy-refcounts", "corrupt", "compression-type"}
        if (type(data) is not dict or not data.keys() <= allowed
                or data.get("compat") != "1.1"
                or not _int_in(data.get("refcount-bits"), 16, 16)
                or data.get("lazy-refcounts", False) is not False
                or data.get("corrupt", False) is not False
                or data.get("compression-type", "zlib") != "zlib"):
            raise Qcow2ExternalEvidenceError("QCOW2 format-specific metadata unsupported or unsafe")


def _validate_check(check: dict, *, physical: int) -> None:
    if check["filename"] != BASE_NAME or check["format"] != "qcow2":
        raise Qcow2ExternalEvidenceError("QEMU check output must refer to this fixed QCOW2 image")
    for key in ("check-errors", "corruptions", "leaks", "corruptions-fixed", "leaks-fixed"):
        if key in check and not _int_in(check[key], 0, 0):
            raise Qcow2ExternalEvidenceError("QEMU report contains corruption, leaks, repairs or errors")
    max_cluster_count = (physical + CLUSTER_BYTES - 1) // CLUSTER_BYTES + 1
    for key in ("total-clusters", "allocated-clusters", "fragmented-clusters", "compressed-clusters"):
        if key in check and not _int_in(check[key], 0, max_cluster_count):
            raise Qcow2ExternalEvidenceError("Invalid or unbounded QEMU cluster statistic")
    if "compressed-clusters" in check and check["compressed-clusters"] != 0:
        raise Qcow2ExternalEvidenceError("Compressed QCOW2 data not supported by this report policy")
    if ("total-clusters" in check and "allocated-clusters" in check
            and check["allocated-clusters"] > check["total-clusters"]):
        raise Qcow2ExternalEvidenceError("Impossible allocated/total QEMU cluster counts")
    if ("image-end-offset" in check
            and not _int_in(check["image-end-offset"], 0, physical)):
        raise Qcow2ExternalEvidenceError("Reported image end offset outside pinned base")


@dataclass(frozen=True, slots=True)
class Qcow2ExternalEvidenceReview:
    plan_digest_sha256: str
    base_sha256: str
    base_size_bytes: int
    capture_sha256: str
    info_sha256: str
    check_sha256: str
    declared_qemu_img_version: str
    declared_qemu_img_binary_sha256: str

    def to_dict(self) -> dict:
        return {
            "api_version": API_VERSION,
            "kind": "operator_supplied_external_qcow2_info_check_reconciliation",
            "status": "operator_qemu_report_consistent_but_untrusted",
            "plan_digest_sha256": self.plan_digest_sha256,
            "base_sha256": self.base_sha256,
            "base_size_bytes": self.base_size_bytes,
            "capture_manifest_sha256": self.capture_sha256,
            "info_json_sha256": self.info_sha256,
            "check_json_sha256": self.check_sha256,
            "declared_qemu_img_version": self.declared_qemu_img_version,
            "declared_qemu_img_binary_sha256": self.declared_qemu_img_binary_sha256,
            "operator_reports_clean_info_and_check": True,
            "reported_check_errors": 0,
            "reported_corruptions": 0,
            "reported_leaks": 0,
            "reported_repairs": 0,
            "input_base_hash_checked_against_plan": True,
            "external_qemu_img_executed_by_this_command": False,
            "external_qemu_img_execution_attested": False,
            "reported_qemu_img_binary_authenticated": False,
            "operator_report_authenticity_verified": False,
            "publisher_origin_authenticated": False,
            "qcow2_full_metadata_independently_verified": False,
            "immutable_backing_chain_verified": False,
            "host_kvm_readiness_verified": False,
            "host_global_vm_lease": False,
            "guest_execution_authorized": False,
            "execution_authorized": False,
            "vm_launched": False,
            "host_modified": False,
        }

    def canonical_json(self) -> bytes:
        return _canonical(self.to_dict())


def review_qcow2_external_evidence(
    plan: K3sVMPlan, assets_dir: str | Path, evidence_dir: str | Path,
) -> Qcow2ExternalEvidenceReview:
    """Check three existing JSON evidence files, without running qemu-img."""
    if type(plan) is not K3sVMPlan:
        raise Qcow2ExternalEvidenceError("Typed nonsynthetic pinned VM plan required")
    # Validates the typed plan and hashes all five private artifacts. This
    # provides image byte identity but NOT provenance or immutability.
    verified = verify_local_vm_assets(plan, assets_dir)
    base = next(a for a in verified.assets if a.filename == BASE_NAME)
    _read_and_hash_base(assets_dir, base.sha256, plan.design["guest"]["disk_gib"] * GIB)
    root_fd = None
    try:
        root_fd = os.open(Path(evidence_dir), _DIR)
        info = os.fstat(root_fd)
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
            raise Qcow2ExternalEvidenceError("Existing 0700 private QEMU evidence root required")
        if set(os.listdir(root_fd)) != _NAMES:
            raise Qcow2ExternalEvidenceError("Missing or unexpected QEMU evidence files")
        capture_raw = _read_file(root_fd, "capture.json")
        info_raw = _read_file(root_fd, "info.json")
        check_raw = _read_file(root_fd, "check.json")
    except OSError as exc:
        raise Qcow2ExternalEvidenceError("Existing private evidence root inaccessible") from exc
    finally:
        if root_fd is not None:
            os.close(root_fd)

    capture = _decode(capture_raw, required=_CAPTURE_KEYS)
    if capture_raw != _canonical(capture):
        raise Qcow2ExternalEvidenceError("Capture manifest must be canonical compact JSON")
    inf = _decode(info_raw, required=_INFO_REQUIRED, optional=_INFO_OPTIONAL)
    check = _decode(check_raw, required=_CHECK_REQUIRED, optional=_CHECK_OPTIONAL)
    if (capture["api_version"] != API_VERSION
            or capture["capture_kind"] != "declared_qemu_img_read_only_info_check"
            or capture["capture_origin"] != "operator_supplied_unverified"
            or capture["plan_digest_sha256"] != plan.digest_sha256
            or capture["base_sha256"] != base.sha256
            or not _int_in(capture["base_size_bytes"], base.size_bytes, base.size_bytes)
            or capture["qemu_img_version"] != plan.design["runtime"]["qemu_version"]
            or not _is_digest(capture["qemu_img_binary_sha256"])
            or capture["info_command"] != list(_INFO_COMMAND)
            or capture["check_command"] != list(_CHECK_COMMAND)
            or not _int_in(capture["info_exit_code"], 0, 0)
            or not _int_in(capture["check_exit_code"], 0, 0)
            or not _is_digest(capture["info_output_sha256"])
            or not _is_digest(capture["check_output_sha256"])
            or capture["info_output_sha256"] != hashlib.sha256(info_raw).hexdigest()
            or capture["check_output_sha256"] != hashlib.sha256(check_raw).hexdigest()):
        raise Qcow2ExternalEvidenceError("Reported QEMU invocation, image identity or transcript digests mismatch")

    _validate_info(inf, virtual=plan.design["guest"]["disk_gib"] * GIB,
                   physical=base.size_bytes)
    _validate_check(check, physical=base.size_bytes)
    return Qcow2ExternalEvidenceReview(
        plan.digest_sha256, base.sha256, base.size_bytes,
        hashlib.sha256(capture_raw).hexdigest(),
        hashlib.sha256(info_raw).hexdigest(), hashlib.sha256(check_raw).hexdigest(),
        capture["qemu_img_version"], capture["qemu_img_binary_sha256"],
    )
