"""SC-13b8: READ-ONLY local overlay/reservation recovery assessment.

This is not a recovery executor. It never opens or parses an overlay, deletes
files, clears quarantines, kills a process, launches QEMU, or validates a live
backing chain. It looks only at a fixed private local reservation slot.

Operators must control the root, ancestors and other same-UID writers. A
point-in-time scan cannot establish absence of racing processes or artifacts.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
import os
from pathlib import Path
import stat

from .vm_reservation import (
    RESERVATION_DIRECTORY, OVERLAY_INTENT_NAME, ReservationError,
    _decode_existing, _private_dir,  # reuse strict existing fd-based validation
)

API_VERSION = "slipcage.dev/vm-overlay-recovery-review/v1alpha1"
_MAX_DIRECTORY_ENTRIES = 16
_EXPECTED = frozenset(("intent.json", "manifest.json"))
_QUARANTINED = _EXPECTED | {"quarantine.json"}
_PERMITTED = _QUARANTINED | {OVERLAY_INTENT_NAME}
_SLOT_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


class OverlayRecoveryError(ValueError):
    """Unable to inspect an existing, controlled private reservation root."""


class RecoveryClassification(str, Enum):
    NO_SLOT = "no_staging_slot"
    STAGED_ONLY = "verified_staging_record_no_overlay"
    QUARANTINED = "quarantined_preserve"
    INCOMPLETE = "incomplete_staging_preserve"
    CORRUPT = "invalid_record_preserve"
    UNKNOWN_CONTENT = "unknown_entries_preserve"
    OVERLAY_PRESENT = "unexpected_overlay_node_preserve"


@dataclass(frozen=True, slots=True)
class OverlayRecoveryReview:
    classification: RecoveryClassification
    reason: str
    record_verified: bool
    attempt_id: str | None
    plan_digest_sha256: str | None
    reservation_digest_sha256: str | None
    quarantine_marker_observed: bool
    overlay_node_observed: bool
    overlay_node_kind: str
    overlay_node_size_bytes: int | None

    def to_dict(self) -> dict:
        return {
            "api_version": API_VERSION,
            "kind": "read_only_local_overlay_recovery_review",
            "classification": self.classification.value,
            "reason": self.reason,
            "record_verified": self.record_verified,
            "attempt_id": self.attempt_id,
            "plan_digest_sha256": self.plan_digest_sha256,
            "reservation_digest_sha256": self.reservation_digest_sha256,
            "quarantine_marker_observed": self.quarantine_marker_observed,
            "overlay_node_observed": self.overlay_node_observed,
            "overlay_node_kind": self.overlay_node_kind,
            "overlay_node_size_bytes_stat_only": self.overlay_node_size_bytes,
            "manual_preservation_and_operator_review_required": True,
            "automatic_recovery_attempted": False,
            "automatic_cleanup_permitted": False,
            "owner_clearance_implemented": False,
            "host_wide_guest_lock_held": False,
            "active_guest_processes_checked": False,
            "backing_chain_resolved": False,
            "overlay_bytes_opened_or_read": False,
            "overlay_created": False,
            "overlay_deleted": False,
            "reservation_removed": False,
            "quarantine_cleared": False,
            "watchdog_enforced": False,
            "real_guest_started": False,
            "real_guest_cleanup_verified": False,
            "execution_authorized": False,
            "host_modified": False,
        }

    def canonical_json(self) -> bytes:
        return json.dumps(self.to_dict(), ensure_ascii=True, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("ascii")


def _review(
    state: RecoveryClassification, reason: str, *,
    record=None, quarantine=False, node_kind="absent", node_size=None,
) -> OverlayRecoveryReview:
    return OverlayRecoveryReview(
        state, reason, record is not None,
        record.attempt_id if record is not None else None,
        record.plan_digest_sha256 if record is not None else None,
        record.record_digest_sha256 if record is not None else None,
        quarantine, node_kind != "absent", node_kind, node_size,
    )


def review_overlay_recovery(root: str | Path) -> OverlayRecoveryReview:
    """Inspect an existing private root and single known child, never mutate.

    Unknown files and suspect overlay nodes are *observed*, never opened.
    If metadata or records cannot be trusted, refuse all automated recovery.
    """
    try:
        root_fd = _private_dir(None, root)
    except ReservationError as exc:
        raise OverlayRecoveryError("Existing private operator-controlled root required") from exc
    try:
        try:
            slot_fd = os.open(RESERVATION_DIRECTORY, _SLOT_FLAGS, dir_fd=root_fd)
        except FileNotFoundError:
            return _review(RecoveryClassification.NO_SLOT, "no_reserved_attempt_seen")
        except OSError as exc:
            raise OverlayRecoveryError("Unsafe or inaccessible fixed reservation slot") from exc
        try:
            details = os.fstat(slot_fd)
            if not stat.S_ISDIR(details.st_mode) or stat.S_IMODE(details.st_mode) & 0o077:
                raise OverlayRecoveryError("Reservation slot directory is not private")
            try:
                entries = os.listdir(slot_fd)
            except OSError as exc:
                raise OverlayRecoveryError("Unable to inspect fixed reservation slot") from exc
            # Bound scanning and never emit untrusted filenames/paths.
            if len(entries) > _MAX_DIRECTORY_ENTRIES:
                return _review(RecoveryClassification.UNKNOWN_CONTENT,
                               "unbounded_or_unrecognized_slot_entries")
            names = set(entries)
            quarantine = "quarantine.json" in names
            if OVERLAY_INTENT_NAME in names:
                # Metadata only, no file open. Symlink targets cannot be read.
                try:
                    info = os.stat(OVERLAY_INTENT_NAME, dir_fd=slot_fd,
                                   follow_symlinks=False)
                except OSError:
                    return _review(RecoveryClassification.OVERLAY_PRESENT,
                                   "overlay_node_disappeared_or_unreadable",
                                   quarantine=quarantine, node_kind="unknown")
                kind = ("symlink" if stat.S_ISLNK(info.st_mode)
                        else "regular" if stat.S_ISREG(info.st_mode)
                        else "directory" if stat.S_ISDIR(info.st_mode)
                        else "other")
                return _review(RecoveryClassification.OVERLAY_PRESENT,
                               "overlay_node_must_be_preserved_for_manual_review",
                               quarantine=quarantine, node_kind=kind,
                               node_size=info.st_size if kind == "regular" else None)
            if not names.issubset(_PERMITTED):
                return _review(RecoveryClassification.UNKNOWN_CONTENT,
                               "unknown_slot_entries_require_manual_review",
                               quarantine=quarantine)
            if names not in (_EXPECTED, _QUARANTINED):
                return _review(RecoveryClassification.INCOMPLETE,
                               "incomplete_persisted_staging_record",
                               quarantine=quarantine)
            try:
                record = _decode_existing(slot_fd)
            except ReservationError:
                return _review(RecoveryClassification.CORRUPT,
                               "staging_record_not_integrity_verified",
                               quarantine=quarantine)
            if record.quarantined:
                return _review(RecoveryClassification.QUARANTINED,
                               "quarantine_persists_and_cannot_be_auto_cleared",
                               record=record, quarantine=True)
            return _review(RecoveryClassification.STAGED_ONLY,
                           "valid_intent_but_no_overlay_node_observed_at_scan",
                           record=record)
        finally:
            os.close(slot_fd)
    finally:
        os.close(root_fd)
