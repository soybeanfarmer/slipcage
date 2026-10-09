"""SC-13b9: scoped LOCAL POSIX flock around read-only recovery review.

Actual Linux advisory flock, not simulated, but NOT a host-global VM lease:
scope is one trusted existing 0700 local POSIX directory/inode. It is held
ONLY for the synchronous inspection, NOT for any QEMU/guest process. No guest,
overlay, image, process supervisor, network, or host recovery is performed.

Same-UID hostile writers, symlinked ancestor paths, remote/NFS locking,
fork-inherited descriptors and unrelated roots are outside this guarantee.
Never treat an unlocked/stale lockfile as proof that a guest has exited.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import errno
import fcntl
import json
import os
from pathlib import Path
import stat
from typing import Iterator

from .vm_reservation import (
    RESERVATION_DIRECTORY, ReservationError, _private_dir,
)
from .vm_overlay_recovery import (
    OverlayRecoveryError, OverlayRecoveryReview, RecoveryClassification,
    review_overlay_recovery,
)

API_VERSION = "slipcage.dev/scoped-overlay-review-lock/v1alpha1"
LOCK_NAME = ".vm-overlay-review.lock"
_FLAGS = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
_ALLOWED = frozenset((RESERVATION_DIRECTORY, LOCK_NAME))


class LocalReviewLockError(ValueError):
    """Unsafe lock path, filesystem, or unexpected lock state."""


class LocalReviewLockBusy(LocalReviewLockError):
    """Another cooperating process holds the same local lock inode."""


def _check_lock_file(parent_fd: int, lock_fd: int) -> None:
    """Guard against accidental replacement/mode changes by trusted operators."""
    try:
        by_fd = os.fstat(lock_fd)
        by_path = os.stat(LOCK_NAME, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise LocalReviewLockError("Persistent private lockfile disappeared") from exc
    if (
        not stat.S_ISREG(by_fd.st_mode)
        or not stat.S_ISREG(by_path.st_mode)
        or by_fd.st_nlink != 1
        or by_path.st_nlink != 1
        or stat.S_IMODE(by_fd.st_mode) != 0o600
        or stat.S_IMODE(by_path.st_mode) != 0o600
        or by_fd.st_size != 0
        or by_path.st_size != 0
        or (by_fd.st_dev, by_fd.st_ino) != (by_path.st_dev, by_path.st_ino)
    ):
        raise LocalReviewLockError("Private lockfile modified, replaced or unsafe")


@contextmanager
def scoped_local_review_lock(root: str | Path) -> Iterator[None]:
    """Hold one NONBLOCKING real kernel flock during caller's synchronous work.

    Only writes one new empty 0600 lockfile to the selected existing private
    root if absent; never truncates/unlinks/renames it. The file stays after
    unlock, including after crashes. The lock does not survive process death,
    cannot protect an executing VM and cannot enforce cross-root exclusion.
    """
    try:
        root_fd = _private_dir(None, root)
    except ReservationError as exc:
        raise LocalReviewLockError("Existing trusted private root required") from exc
    lock_fd: int | None = None
    locked = False
    try:
        if not set(os.listdir(root_fd)).issubset(_ALLOWED):
            raise LocalReviewLockError("Root contains unexpected entries: refusing lockfile creation")
        try:
            lock_fd = os.open(LOCK_NAME, _FLAGS, dir_fd=root_fd)
        except FileNotFoundError:
            try:
                lock_fd = os.open(
                    LOCK_NAME, _FLAGS | os.O_CREAT | os.O_EXCL,
                    0o600, dir_fd=root_fd,
                )
                os.fsync(root_fd)
            except FileExistsError:
                # A concurrent process may have created the same filename.
                lock_fd = os.open(LOCK_NAME, _FLAGS, dir_fd=root_fd)
        _check_lock_file(root_fd, lock_fd)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                raise LocalReviewLockBusy("Same-root local review lock is held") from exc
            raise LocalReviewLockError("Could not obtain scoped local review lock") from exc
        locked = True
        _check_lock_file(root_fd, lock_fd)
        yield
        _check_lock_file(root_fd, lock_fd)
    except (OSError, ReservationError) as exc:
        raise LocalReviewLockError("Local review lock I/O or path check failed") from exc
    finally:
        if lock_fd is not None:
            try:
                if locked:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        os.close(root_fd)


@dataclass(frozen=True, slots=True)
class LockedRecoveryReview:
    recovery: OverlayRecoveryReview

    def to_dict(self) -> dict:
        return {
            "api_version": API_VERSION,
            "kind": "scoped_local_lock_and_read_only_overlay_review",
            "recovery": self.recovery.to_dict(),
            "same_root_kernel_advisory_flock_acquired_during_review": True,
            "lockfile_persisted_for_future_review": True,
            "lock_held_after_command": False,
            "host_global_vm_lease_enforced": False,
            "guest_process_bound_to_lock": False,
            "lock_release_proves_vm_cleanup": False,
            "interprocess_execution_fencing_implemented": False,
            "backing_chain_validated": False,
            "overlay_created": False,
            "overlay_deleted": False,
            "automatic_cleanup_permitted": False,
            "real_guest_cleanup_verified": False,
            "execution_authorized": False,
            "host_modified_except_empty_local_lockfile": False,
            "vm_launched": False,
        }

    def canonical_json(self) -> bytes:
        return json.dumps(self.to_dict(), ensure_ascii=True, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("ascii")


def review_overlay_with_local_lock(root: str | Path) -> LockedRecoveryReview:
    """Acquire real same-inode flock, inspect fixed slot, then release lock.

    A 'verified_staging_record_no_overlay' result does NOT permit another
    guest; the purpose is to prevent cooperating *reviewers* from racing.
    """
    with scoped_local_review_lock(root):
        outcome = review_overlay_recovery(root)
        return LockedRecoveryReview(outcome)
