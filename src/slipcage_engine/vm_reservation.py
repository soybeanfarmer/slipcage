"""SC-13b6: private, append-only LOCAL VM reservation records; NO guest work.

This is a deliberately single-use developer workspace, not a runnable VM
lease, global host lock, remote/distributed lock, exclusive guest fencing,
overlay creator, watchdog, cleanup executor or real host safety attestation.

An operator-controlled, existing private 0700 root on a trusted local POSIX
filesystem is required; root ancestors and same-UID adversaries are outside
this module's protection. No automatic deletion or recovery occurs.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .vm_plan import K3sVMPlan
from .vm_assets import VMAssetPreflight
from .vm_qemu_blueprint import QemuBlueprintError, build_qemu_blueprint

API_VERSION = "slipcage.dev/local-vm-reservation/v1alpha1"
RESERVATION_DIRECTORY = "vm-reservation-v1"
OVERLAY_INTENT_NAME = "overlay.qcow2"
MAX_RECORD_BYTES = 4096
_ATTEMPT_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)


class ReservationError(ValueError):
    """Unsafe or incomplete local staging record. Never auto-recover."""


class QuarantineReason(str, Enum):
    SIMULATED_CRASH = "simulated_crash"
    SIMULATED_CLEANUP_FAILURE = "simulated_cleanup_failure"
    OPERATOR_REVIEW_REQUIRED = "operator_review_required"


@dataclass(frozen=True, slots=True)
class LocalReservation:
    attempt_id: str
    plan_id: str
    plan_digest_sha256: str
    record_digest_sha256: str
    overlay_name: str
    overlay_budget_gib: int
    runtime_budget_seconds: int
    quarantined: bool
    quarantine_reason: str | None

    def to_dict(self) -> dict:
        return {
            "api_version": API_VERSION,
            "kind": "local_staging_reservation_record",
            "status": "quarantined" if self.quarantined else "staged_no_execution",
            "attempt_id": self.attempt_id,
            "plan_id": self.plan_id,
            "plan_digest_sha256": self.plan_digest_sha256,
            "record_digest_sha256": self.record_digest_sha256,
            "overlay_intent_filename": self.overlay_name,
            "overlay_budget_gib_declared": self.overlay_budget_gib,
            "runtime_budget_seconds_declared": self.runtime_budget_seconds,
            "quarantined": self.quarantined,
            "quarantine_reason": self.quarantine_reason,
            "local_record_persisted": True,
            "single_slot_per_selected_root": True,
            "real_host_exclusive_lease_enforced": False,
            "cross_process_execution_fencing_proven": False,
            "operator_clearance_implemented": False,
            "overlay_created": False,
            "overlay_deleted": False,
            "qemu_launched": False,
            "cgroup_limits_enforced": False,
            "watchdog_enforced": False,
            "actual_cleanup_verified": False,
            "provider_permission_verified": False,
            "execution_authorized": False,
            "host_vm_modified": False,
        }

    def canonical_json(self) -> bytes:
        return _canonical(self.to_dict())


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReservationError("Duplicate local reservation fields")
        result[key] = value
    return result


def _reject_number(_):
    raise ReservationError("Nonintegral or nonfinite reservation data")


def _strict_record(raw: bytes, expected_keys: set[str]) -> dict:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_RECORD_BYTES:
        raise ReservationError("Local record outside size bounds")
    try:
        record = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs,
                            parse_float=_reject_number, parse_constant=_reject_number)
        if type(record) is not dict or set(record) != expected_keys:
            raise ReservationError("Invalid local record layout")
        if raw != _canonical(record):
            raise ReservationError("Local record must be canonical JSON")
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError) as exc:
        raise ReservationError("Malformed local record") from exc
    return record


def _private_dir(parent_fd: int | None, path_or_name: str | Path) -> int:
    try:
        if parent_fd is None:
            fd = os.open(Path(path_or_name), _DIR_FLAGS)
        else:
            fd = os.open(path_or_name, _DIR_FLAGS, dir_fd=parent_fd)
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            raise ReservationError("Reservation root and staging directory must be private 0700")
        return fd
    except (OSError, ReservationError) as exc:
        if "fd" in locals():
            os.close(fd)
        raise ReservationError("Missing, unsafe, or nonprivate local reservation directory") from exc


def _write_new(fd: int, name: str, raw: bytes) -> None:
    if name not in ("intent.json", "manifest.json", "quarantine.json"):
        raise ReservationError("Unexpected reservation filename")
    if not 1 <= len(raw) <= MAX_RECORD_BYTES:
        raise ReservationError("Record size invalid")
    try:
        handle = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=fd)
        with os.fdopen(handle, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(fd)
    except OSError as exc:
        raise ReservationError("Exclusive local record write failed; inspect partial state") from exc


def _read_checked(fd: int, name: str) -> bytes:
    try:
        handle = os.open(name, _FILE_FLAGS, dir_fd=fd)
    except OSError as exc:
        raise ReservationError("Missing or symlinked local reservation record") from exc
    # Reject nonregular descriptors before fdopen: a directory descriptor
    # cannot be wrapped as an ordinary buffered binary file.
    info = os.fstat(handle)
    if not stat.S_ISREG(info.st_mode):
        os.close(handle)
        raise ReservationError("Unsafe nonregular local reservation record")
    with os.fdopen(handle, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) & 0o077
                or not 1 <= info.st_size <= MAX_RECORD_BYTES):
            raise ReservationError("Unsafe file mode, links or local record size")
        raw = stream.read(MAX_RECORD_BYTES + 1)
        after = os.fstat(stream.fileno())
        if (len(raw) != info.st_size or
                (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns)):
            raise ReservationError("Record changed while being read")
        return raw


_INTENT_KEYS = {
    "api_version", "kind", "attempt_id", "plan_id", "plan_digest_sha256",
    "overlay_intent_filename", "overlay_budget_gib_declared",
    "runtime_budget_seconds_declared", "execution_enabled",
}
_MANIFEST_KEYS = {"api_version", "kind", "intent_digest_sha256", "complete"}
_QUARANTINE_KEYS = {"api_version", "kind", "intent_digest_sha256", "reason"}


def _validate_sha(value: object) -> bool:
    return (type(value) is str and len(value) == 64
            and all(char in "0123456789abcdef" for char in value))


def _decode_existing(fd: int, *, allow_quarantine: bool = True) -> LocalReservation:
    try:
        names = set(os.listdir(fd))
    except OSError as exc:
        raise ReservationError("Unable to inspect reservation directory") from exc
    complete = {"intent.json", "manifest.json"}
    with_quarantine = complete | {"quarantine.json"}
    if names not in (complete, with_quarantine):
        raise ReservationError("Reservation incomplete or contains unexpected entries")
    if names == with_quarantine and not allow_quarantine:
        raise ReservationError("Reservation quarantined; no subsequent update allowed")
    raw_intent = _read_checked(fd, "intent.json")
    intent = _strict_record(raw_intent, _INTENT_KEYS)
    raw_manifest = _read_checked(fd, "manifest.json")
    manifest = _strict_record(raw_manifest, _MANIFEST_KEYS)
    digest = hashlib.sha256(raw_intent).hexdigest()
    if not (
        intent["api_version"] == API_VERSION
        and intent["kind"] == "private_overlay_intent_not_created"
        and type(intent["attempt_id"]) is str
        and _ATTEMPT_PATTERN.fullmatch(intent["attempt_id"]) is not None
        and type(intent["plan_id"]) is str
        and re.fullmatch(r"slipcage-k3s-[a-z0-9-]{1,67}", intent["plan_id"]) is not None
        and _validate_sha(intent["plan_digest_sha256"])
        and intent["overlay_intent_filename"] == OVERLAY_INTENT_NAME
        and type(intent["overlay_budget_gib_declared"]) is int
        and 24 <= intent["overlay_budget_gib_declared"] <= 48
        and type(intent["runtime_budget_seconds_declared"]) is int
        and 300 <= intent["runtime_budget_seconds_declared"] <= 1800
        and intent["execution_enabled"] is False
        and manifest == {
            "api_version": API_VERSION,
            "kind": "local_staging_completion_marker",
            "intent_digest_sha256": digest,
            "complete": True,
        }
    ):
        raise ReservationError("Reservation fields, intent hash, or safety contract invalid")
    reason = None
    if names == with_quarantine:
        marker = _strict_record(_read_checked(fd, "quarantine.json"), _QUARANTINE_KEYS)
        if not (
            marker["api_version"] == API_VERSION
            and marker["kind"] == "unresolved_local_reservation_quarantine"
            and marker["intent_digest_sha256"] == digest
            and type(marker["reason"]) is str
            and marker["reason"] in {r.value for r in QuarantineReason}
        ):
            raise ReservationError("Quarantine marker invalid or inconsistent")
        reason = marker["reason"]
    return LocalReservation(
        intent["attempt_id"], intent["plan_id"], intent["plan_digest_sha256"],
        digest, OVERLAY_INTENT_NAME, intent["overlay_budget_gib_declared"],
        intent["runtime_budget_seconds_declared"], reason is not None, reason,
    )


def inspect_local_reservation(root: str | Path) -> LocalReservation:
    """Read-only fixed-layout verification; no recovery or quarantine clearing."""
    root_fd = _private_dir(None, root)
    try:
        slot_fd = _private_dir(root_fd, RESERVATION_DIRECTORY)
        try:
            return _decode_existing(slot_fd)
        finally:
            os.close(slot_fd)
    finally:
        os.close(root_fd)


def stage_local_reservation(
    plan: K3sVMPlan,
    preflight: VMAssetPreflight,
    root: str | Path,
    attempt_id: str,
) -> LocalReservation:
    """Reserve the ONE permanent staging slot in an existing private root.

    Writes only a tiny intention record and a manifest; NO overlay data file.
    A crash may leave an incomplete permanent blocking directory. No deletion
    or retry semantics are offered, including after a 'clean' inspection.
    """
    if type(attempt_id) is not str or _ATTEMPT_PATTERN.fullmatch(attempt_id) is None:
        raise ReservationError("Attempt ID outside fixed allowlist")
    try:
        blueprint = build_qemu_blueprint(plan, preflight)
    except (QemuBlueprintError, ValueError) as exc:
        raise ReservationError("Need nonsynthetic verified local asset byte declarations") from exc
    root_fd = _private_dir(None, root)
    try:
        try:
            os.mkdir(RESERVATION_DIRECTORY, mode=0o700, dir_fd=root_fd)
        except OSError as exc:
            raise ReservationError("Reservation slot already exists or cannot be created") from exc
        slot_fd = _private_dir(root_fd, RESERVATION_DIRECTORY)
        try:
            # Never create the actual backing image or the proposed overlay.
            try:
                os.fsync(root_fd)
            except OSError as exc:
                raise ReservationError("Cannot durably sync private staging directory") from exc
            intent = _canonical({
                "api_version": API_VERSION,
                "kind": "private_overlay_intent_not_created",
                "attempt_id": attempt_id,
                "plan_id": blueprint.plan_id,
                "plan_digest_sha256": blueprint.plan_digest_sha256,
                "overlay_intent_filename": OVERLAY_INTENT_NAME,
                "overlay_budget_gib_declared": blueprint.guest_disk_gib,
                "runtime_budget_seconds_declared": blueprint.max_runtime_seconds,
                "execution_enabled": False,
            })
            _write_new(slot_fd, "intent.json", intent)
            _write_new(slot_fd, "manifest.json", _canonical({
                "api_version": API_VERSION,
                "kind": "local_staging_completion_marker",
                "intent_digest_sha256": hashlib.sha256(intent).hexdigest(),
                "complete": True,
            }))
            return _decode_existing(slot_fd)
        finally:
            os.close(slot_fd)
    finally:
        os.close(root_fd)


def quarantine_local_reservation(
    root: str | Path, *,
    attempt_id: str,
    expected_intent_sha256: str,
    reason: QuarantineReason,
) -> LocalReservation:
    """Append an irreversible, bounded quarantine marker. Never clean up."""
    if type(reason) is not QuarantineReason or type(attempt_id) is not str:
        raise ReservationError("Typed quarantine reason and attempt ID required")
    if not _validate_sha(expected_intent_sha256):
        raise ReservationError("Exact intent digest required for append")
    root_fd = _private_dir(None, root)
    try:
        slot_fd = _private_dir(root_fd, RESERVATION_DIRECTORY)
        try:
            record = _decode_existing(slot_fd, allow_quarantine=False)
            if record.attempt_id != attempt_id or record.record_digest_sha256 != expected_intent_sha256:
                raise ReservationError("Stale attempt identity or intent fingerprint")
            _write_new(slot_fd, "quarantine.json", _canonical({
                "api_version": API_VERSION,
                "kind": "unresolved_local_reservation_quarantine",
                "intent_digest_sha256": record.record_digest_sha256,
                "reason": reason.value,
            }))
            return _decode_existing(slot_fd)
        finally:
            os.close(slot_fd)
    finally:
        os.close(root_fd)
