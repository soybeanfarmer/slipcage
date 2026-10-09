"""SC-13b10: durable OFFLINE attempt IDs and monotonic fencing generations.

Real local POSIX flock protects append-only records during short mutations.
The lock is NOT held by a VM process, and the journal does NOT control QEMU,
make overlays, enforce a host-wide lock or attest actual cleanup. This is
strictly a development-only intent ledger for a trusted private LOCAL root.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Iterator

from .vm_plan import K3sVMPlan, VMPlanError, validate_vm_plan_bytes
from .vm_reservation import ReservationError, _private_dir

API_VERSION = "slipcage.dev/offline-fencing-journal/v1alpha1"
LOCK_NAME = ".offline-fence.lock"
MAX_GENERATIONS = 16
MAX_RECORD_BYTES = 2048
_ZERO = "0" * 64
_ID = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_ISSUE_NAME = re.compile(r"^generation-([0-9]{8})\.json$")
_END_NAME = re.compile(r"^resolution-([0-9]{8})\.json$")
_FLAGS = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)


class FencingJournalError(ValueError):
    """Malformed, stale, conflicting or unsafe offline intent journal."""


class FencingJournalBusy(FencingJournalError):
    """Another cooperating local journal writer holds this root's advisory lock."""


class OfflineResolution(str, Enum):
    ABANDONED = "offline_intent_abandoned_not_vm_cleanup"
    QUARANTINED = "unresolved_quarantine"


@dataclass(frozen=True, slots=True)
class FencingSnapshot:
    generation: int
    state: str
    active_attempt: str | None
    active_record_sha256: str | None
    plan_digest_sha256: str | None
    record_count: int
    last_resolution: str | None

    def to_dict(self) -> dict:
        return {
            "api_version": API_VERSION,
            "kind": "local_durable_offline_intent_history",
            "last_generation": self.generation,
            "state": self.state,
            "active_attempt": self.active_attempt,
            "active_record_sha256": self.active_record_sha256,
            "plan_digest_sha256": self.plan_digest_sha256,
            "record_count": self.record_count,
            "last_resolution": self.last_resolution,
            "journal_persisted_locally": True,
            "monotonic_generations_for_cooperating_writers": True,
            "same_root_kernel_lock_acquired_during_operation": True,
            "lock_held_after_command": False,
            "host_global_execution_lease": False,
            "guest_process_fenced": False,
            "quarantine_clearance_available": False,
            "actual_guest_cleanup_verified": False,
            "operator_identity_authenticated": False,
            "software_provenance_authenticated": False,
            "qemu_or_overlay_created": False,
            "execution_authorized": False,
            "host_modified_except_private_journal_files": False,
            "vm_launched": False,
        }

    def canonical_json(self) -> bytes:
        return _canonical(self.to_dict())


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest(value: object) -> bool:
    return (type(value) is str and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _pairs(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise FencingJournalError("Duplicate fields in journal event")
        result[k] = v
    return result


def _reject_number(_):
    raise FencingJournalError("Floating or nonfinite JSON forbidden")


def _parse(raw: bytes, fields: frozenset[str]) -> dict:
    if not 1 <= len(raw) <= MAX_RECORD_BYTES:
        raise FencingJournalError("Unbounded or missing durable event")
    try:
        item = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs,
                          parse_float=_reject_number, parse_constant=_reject_number)
        if type(item) is not dict or frozenset(item) != fields or _canonical(item) != raw:
            raise FencingJournalError("Noncanonical or unexpected journal event fields")
        return item
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError) as exc:
        raise FencingJournalError("Invalid canonical journal event") from exc


_ISSUE_FIELDS = frozenset((
    "api_version", "kind", "generation", "attempt_id", "plan_digest_sha256",
    "previous_resolution_sha256", "execution_enabled",
))
_END_FIELDS = frozenset((
    "api_version", "kind", "generation", "attempt_id",
    "issue_sha256", "resolution",
))


def _event_filename(prefix: str, generation: int) -> str:
    return f"{prefix}-{generation:08d}.json"


def _read_event(fd: int, name: str) -> tuple[dict, str]:
    handle = None
    try:
        handle = os.open(name, _READ_FLAGS, dir_fd=fd)
        info = os.fstat(handle)
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1 or not 1 <= info.st_size <= MAX_RECORD_BYTES):
            raise FencingJournalError("Unsafe durable event inode/mode/size")
        with os.fdopen(handle, "rb") as stream:
            handle = None
            raw = stream.read(MAX_RECORD_BYTES + 1)
            after = os.fstat(stream.fileno())
            if (len(raw) != info.st_size
                    or (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)
                    != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns)):
                raise FencingJournalError("Journal event changed during read")
        kind = _ISSUE_FIELDS if name.startswith("generation-") else _END_FIELDS
        return _parse(raw, kind), _sha(raw)
    except OSError as exc:
        raise FencingJournalError("Unreadable or symlinked durable event") from exc
    finally:
        if handle is not None:
            os.close(handle)


def _write_event(fd: int, filename: str, record: dict) -> None:
    raw = _canonical(record)
    if len(raw) > MAX_RECORD_BYTES:
        raise FencingJournalError("Bounded journal event exceeded")
    handle = None
    try:
        handle = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                         0o600, dir_fd=fd)
        with os.fdopen(handle, "wb") as out:
            handle = None
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        os.fsync(fd)
    except OSError as exc:
        # Never unlink or repair partial events; they permanently block a
        # subsequent generation until separate offline operator investigation.
        raise FencingJournalError("Durable event publication failed; preserve partial record") from exc
    finally:
        if handle is not None:
            os.close(handle)


def _checked_lock(root_fd: int, lock_fd: int) -> None:
    identity = os.fstat(lock_fd)
    linked = os.stat(LOCK_NAME, dir_fd=root_fd, follow_symlinks=False)
    if (not stat.S_ISREG(identity.st_mode)
            or not stat.S_ISREG(linked.st_mode)
            or identity.st_nlink != 1 or linked.st_nlink != 1
            or stat.S_IMODE(identity.st_mode) != 0o600
            or stat.S_IMODE(linked.st_mode) != 0o600
            or identity.st_size != 0 or linked.st_size != 0
            or (identity.st_dev, identity.st_ino) != (linked.st_dev, linked.st_ino)):
        raise FencingJournalError("Unsafe/replaced persistent journal lockfile")


def _names(root_fd: int) -> set[str]:
    try:
        entries = os.listdir(root_fd)
    except OSError as exc:
        raise FencingJournalError("Cannot list private journal root") from exc
    if len(entries) > MAX_GENERATIONS * 2 + 1:
        raise FencingJournalError("Journal event limit or unexpected entries exceeded")
    names = set(entries)
    if len(names) != len(entries):
        raise FencingJournalError("Duplicate directory name entries")
    for name in names:
        if name == LOCK_NAME:
            continue
        match = _ISSUE_NAME.fullmatch(name) or _END_NAME.fullmatch(name)
        if match is None or not 1 <= int(match.group(1)) <= MAX_GENERATIONS:
            raise FencingJournalError("Unexpected journal entry: refuse automatic recovery")
    return names


@contextmanager
def _locked(root: str | Path, *, create_lock: bool) -> Iterator[int]:
    """Use existing controlled private root and a single fixed local lock inode."""
    try:
        root_fd = _private_dir(None, root)
    except ReservationError as exc:
        raise FencingJournalError("Existing trusted private 0700 local root required") from exc
    lock_fd = None
    acquired = False
    try:
        names = _names(root_fd)
        if LOCK_NAME not in names and not create_lock:
            raise FencingJournalError("Journal lockfile absent; no initialized history")
        try:
            lock_fd = os.open(LOCK_NAME, _FLAGS, dir_fd=root_fd)
        except FileNotFoundError:
            if not create_lock:
                raise FencingJournalError("Journal has no persistent lockfile")
            try:
                lock_fd = os.open(
                    LOCK_NAME, _FLAGS | os.O_CREAT | os.O_EXCL,
                    0o600, dir_fd=root_fd,
                )
                os.fsync(root_fd)
            except FileExistsError:
                lock_fd = os.open(LOCK_NAME, _FLAGS, dir_fd=root_fd)
        _checked_lock(root_fd, lock_fd)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                raise FencingJournalBusy("Cooperating journal writer holds this root lock") from exc
            raise FencingJournalError("Local journal advisory lock unavailable") from exc
        acquired = True
        _checked_lock(root_fd, lock_fd)
        yield root_fd
        _checked_lock(root_fd, lock_fd)
    except OSError as exc:
        raise FencingJournalError("Unsafe journal path or filesystem I/O") from exc
    finally:
        if lock_fd is not None:
            try:
                if acquired:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        os.close(root_fd)


def _replay(fd: int) -> tuple[FencingSnapshot, set[str], str]:
    names = _names(fd)
    if LOCK_NAME not in names:
        raise FencingJournalError("Missing persistent lock during journal replay")
    issue_names = {name for name in names if _ISSUE_NAME.fullmatch(name)}
    resolution_names = {name for name in names if _END_NAME.fullmatch(name)}
    generations = len(issue_names)
    if issue_names != {_event_filename("generation", i)
                      for i in range(1, generations + 1)}:
        raise FencingJournalError("Journal has missing or nonsequential generations")
    all_attempts = set()
    observed_resolutions = set()
    prior_resolution_hash = _ZERO
    last_resolution = None
    current = None
    record_sha = None
    plan_sha = None
    for gen in range(1, generations + 1):
        issue, issued_hash = _read_event(fd, _event_filename("generation", gen))
        if (issue["api_version"] != API_VERSION
                or issue["kind"] != "offline_intent_issued"
                or type(issue["generation"]) is not int or issue["generation"] != gen
                or type(issue["attempt_id"]) is not str
                or _ID.fullmatch(issue["attempt_id"]) is None
                or issue["attempt_id"] in all_attempts
                or not _digest(issue["plan_digest_sha256"])
                or issue["previous_resolution_sha256"] != prior_resolution_hash
                or issue["execution_enabled"] is not False):
            raise FencingJournalError("Invalid or reused journal generation identity")
        all_attempts.add(issue["attempt_id"])
        record_sha = issued_hash
        plan_sha = issue["plan_digest_sha256"]
        current = issue["attempt_id"]
        resolved_name = _event_filename("resolution", gen)
        if resolved_name in resolution_names:
            observed_resolutions.add(resolved_name)
            resolution, resolution_hash = _read_event(fd, resolved_name)
            if (resolution["api_version"] != API_VERSION
                    or resolution["kind"] != "offline_intent_resolution"
                    or type(resolution["generation"]) is not int
                    or resolution["generation"] != gen
                    or resolution["attempt_id"] != current
                    or resolution["issue_sha256"] != issued_hash
                    or resolution["resolution"] not in {v.value for v in OfflineResolution}):
                raise FencingJournalError("Invalid or stale offline resolution event")
            prior_resolution_hash = resolution_hash
            last_resolution = resolution["resolution"]
            current = None
            record_sha = None
            if last_resolution == OfflineResolution.QUARANTINED.value and gen < generations:
                raise FencingJournalError("Quarantined history cannot be superseded")
        else:
            if gen != generations:
                raise FencingJournalError("Unresolved earlier generation blocks all subsequent generations")
            last_resolution = None
    if resolution_names != observed_resolutions:
        raise FencingJournalError("Orphaned resolution without matching issue")
    status = ("empty" if generations == 0 else
              "unresolved_quarantine" if last_resolution == OfflineResolution.QUARANTINED.value else
              "outstanding_offline_intent" if current else
              "offline_abandoned_no_guest_claim_only")
    snap = FencingSnapshot(
        generations, status, current, record_sha,
        plan_sha, len(names) - 1, last_resolution,
    )
    return snap, all_attempts, prior_resolution_hash


def inspect_offline_fencing(root: str | Path) -> FencingSnapshot:
    """Verify all durable events under scoped flock. No writes or cleanup."""
    with _locked(root, create_lock=False) as fd:
        return _replay(fd)[0]


def issue_offline_generation(
    root: str | Path, plan: K3sVMPlan, attempt_id: str, expected_generation: int,
) -> FencingSnapshot:
    """Append a planned-only attempt, never a guest execution lease."""
    if type(attempt_id) is not str or _ID.fullmatch(attempt_id) is None:
        raise FencingJournalError("Bounded unique lowercase attempt ID required")
    if type(expected_generation) is not int or not 0 <= expected_generation < MAX_GENERATIONS:
        raise FencingJournalError("Expected generation outside bounded range")
    if type(plan) is not K3sVMPlan:
        raise FencingJournalError("Strict SC-12 plan required")
    try:
        checked = validate_vm_plan_bytes(plan.canonical_json)
    except (VMPlanError, ValueError, AttributeError, TypeError) as exc:
        raise FencingJournalError("Malformed SC-12 VM plan") from exc
    if checked != plan or checked.design["provenance"]["pin_status"] != "operator_supplied_unverified":
        raise FencingJournalError("Synthetic/forged VM plan cannot be journaled")
    with _locked(root, create_lock=True) as fd:
        snap, attempts, prior_sha = _replay(fd)
        if expected_generation != snap.generation:
            raise FencingJournalError("Stale expected generation: refuse issue")
        if attempt_id in attempts:
            raise FencingJournalError("Attempt ID cannot be reused across generations")
        if snap.state in ("outstanding_offline_intent", "unresolved_quarantine"):
            raise FencingJournalError("Prior offline attempt unresolved or quarantined")
        gen = snap.generation + 1
        _write_event(fd, _event_filename("generation", gen), {
            "api_version": API_VERSION,
            "kind": "offline_intent_issued",
            "generation": gen,
            "attempt_id": attempt_id,
            "plan_digest_sha256": checked.digest_sha256,
            "previous_resolution_sha256": prior_sha,
            "execution_enabled": False,
        })
        return _replay(fd)[0]


def resolve_offline_generation(
    root: str | Path, attempt_id: str, generation: int,
    expected_issue_sha256: str, resolution: OfflineResolution,
) -> FencingSnapshot:
    """Append an offline assertion; NEVER proof of real host/guest teardown."""
    if (type(resolution) is not OfflineResolution
            or type(attempt_id) is not str or _ID.fullmatch(attempt_id) is None
            or type(generation) is not int or not 1 <= generation <= MAX_GENERATIONS
            or not _digest(expected_issue_sha256)):
        raise FencingJournalError("Typed resolution, exact owner/generation/fingerprint required")
    with _locked(root, create_lock=False) as fd:
        snap, _, _ = _replay(fd)
        if (snap.state != "outstanding_offline_intent"
                or snap.generation != generation
                or snap.active_attempt != attempt_id
                or snap.active_record_sha256 != expected_issue_sha256):
            raise FencingJournalError("Stale or nonowner offline resolution refused")
        _write_event(fd, _event_filename("resolution", generation), {
            "api_version": API_VERSION,
            "kind": "offline_intent_resolution",
            "generation": generation,
            "attempt_id": attempt_id,
            "issue_sha256": expected_issue_sha256,
            "resolution": resolution.value,
        })
        return _replay(fd)[0]
