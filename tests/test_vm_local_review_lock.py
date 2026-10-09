"""SC-13b9: real OS advisory flock around OFFLINE review, never a VM lease."""
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from slipcage_engine.cli import main
from slipcage_engine.vm_assets import ARTIFACTS, verify_local_vm_assets
from slipcage_engine.vm_plan import load_vm_plan, validate_vm_plan_bytes
from slipcage_engine.vm_reservation import (
    RESERVATION_DIRECTORY, stage_local_reservation,
)
from slipcage_engine.vm_local_review_lock import (
    API_VERSION, LOCK_NAME, LocalReviewLockBusy, LocalReviewLockError,
    scoped_local_review_lock, review_overlay_with_local_lock,
)
from slipcage_engine.vm_overlay_recovery import RecoveryClassification

EXAMPLE = ROOT / "examples" / "vm-plans" / "k3s-synthetic-design.json"

CHILD_HOLD = """
import sys
from slipcage_engine.vm_local_review_lock import scoped_local_review_lock
with scoped_local_review_lock(sys.argv[1]):
    print("HELD", flush=True)
    sys.stdin.readline()
"""

CHILD_EXIT = """
import os
import sys
from slipcage_engine.vm_local_review_lock import scoped_local_review_lock
with scoped_local_review_lock(sys.argv[1]):
    print("HELD", flush=True)
    os._exit(19)
"""


class ScopedLocalReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.root = self.home / "root"
        self.root.mkdir(mode=0o700)
        self.root.chmod(0o700)

    def stage(self):
        assets = self.home / "assets"
        assets.mkdir(mode=0o700)
        assets.chmod(0o700)
        design = load_vm_plan(EXAMPLE).design
        design["provenance"]["pin_status"] = "operator_supplied_unverified"
        design["provenance"]["note"] = "SC-13b9 CI fake asset bytes, not verified software"
        design["software"]["guest_kernel_release"] = "6.8.0-test"
        for i, (field, filename, _) in enumerate(ARTIFACTS):
            content = (f"SC13b9-{field}-{i}".encode("ascii") * 2)
            child = assets / filename
            child.write_bytes(content)
            child.chmod(0o600)
            design["artifacts"][field] = hashlib.sha256(content).hexdigest()
        plan = validate_vm_plan_bytes(json.dumps(design).encode())
        preflight = verify_local_vm_assets(plan, assets)
        stage_local_reservation(plan, preflight, self.root, "baseline")

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = main(list(argv))
        return status, out.getvalue(), err.getvalue()

    def test_single_lockfile_created_private_persisted_and_empty(self):
        self.stage()
        self.assertFalse((self.root / LOCK_NAME).exists())
        with scoped_local_review_lock(self.root):
            lock = self.root / LOCK_NAME
            self.assertTrue(lock.is_file())
            self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)
            self.assertEqual(lock.read_bytes(), b"")
            self.assertEqual(lock.stat().st_nlink, 1)
            self.assertEqual(set(os.listdir(self.root)),
                             {RESERVATION_DIRECTORY, LOCK_NAME})
        self.assertTrue((self.root / LOCK_NAME).exists())
        with scoped_local_review_lock(self.root):
            self.assertTrue((self.root / LOCK_NAME).is_file())
        self.assertEqual((self.root / LOCK_NAME).read_bytes(), b"")

    def test_nested_independently_opened_same_inode_lock_conflicts(self):
        with scoped_local_review_lock(self.root):
            with self.assertRaises(LocalReviewLockBusy):
                with scoped_local_review_lock(self.root):
                    self.fail("same-root lock unexpectedly acquired")
        with scoped_local_review_lock(self.root):
            pass

    def test_distinct_roots_do_not_provide_host_global_exclusion(self):
        other = self.home / "other"
        other.mkdir(mode=0o700)
        other.chmod(0o700)
        with scoped_local_review_lock(self.root):
            with scoped_local_review_lock(other):
                self.assertNotEqual(
                    (self.root / LOCK_NAME).stat().st_ino,
                    (other / LOCK_NAME).stat().st_ino,
                )

    def test_cross_process_contention_real_linux_flock(self):
        process = subprocess.Popen(
            [sys.executable, "-c", CHILD_HOLD, str(self.root)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        try:
            self.assertEqual(process.stdout.readline().strip(), "HELD")
            with self.assertRaises(LocalReviewLockBusy):
                with scoped_local_review_lock(self.root):
                    self.fail("OS flock failed to exclude another process")
            out, err = process.communicate(input="\n", timeout=8)
            self.assertEqual((process.returncode, out, err), (0, "", ""))
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=8)
        with scoped_local_review_lock(self.root):
            pass

    def test_abrupt_child_exit_releases_lock_but_not_guest_clearance(self):
        self.stage()
        process = subprocess.Popen(
            [sys.executable, "-c", CHILD_EXIT, str(self.root)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=8)
            self.assertEqual(stdout.strip(), "HELD")
            self.assertEqual(stderr, "")
            self.assertEqual(process.returncode, 19)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=8)
        report = review_overlay_with_local_lock(self.root).to_dict()
        self.assertTrue(report["same_root_kernel_advisory_flock_acquired_during_review"])
        self.assertFalse(report["lock_held_after_command"])
        self.assertFalse(report["lock_release_proves_vm_cleanup"])
        self.assertFalse(report["host_global_vm_lease_enforced"])
        self.assertFalse(report["execution_authorized"])
        self.assertTrue((self.root / LOCK_NAME).exists())
        self.assertTrue((self.root / RESERVATION_DIRECTORY).exists())

    def test_locked_review_valid_stage_returns_local_status_only(self):
        self.stage()
        result = review_overlay_with_local_lock(self.root)
        self.assertEqual(result.recovery.classification, RecoveryClassification.STAGED_ONLY)
        self.assertEqual(result.to_dict()["api_version"], API_VERSION)
        self.assertTrue(result.to_dict()["lockfile_persisted_for_future_review"])
        self.assertFalse(result.to_dict()["guest_process_bound_to_lock"])
        self.assertFalse(result.to_dict()["real_guest_cleanup_verified"])
        self.assertFalse(result.to_dict()["vm_launched"])
        self.assertFalse(result.to_dict()["overlay_deleted"])

    def test_locked_review_partial_and_unknown_overlay_remain_blocked(self):
        self.stage()
        sentinel = self.root / RESERVATION_DIRECTORY / "overlay.qcow2"
        sentinel.write_bytes(b"UNTRUSTED-NOT-A-QCOW2-IMAGE")
        before = sentinel.read_bytes()
        outcome = review_overlay_with_local_lock(self.root)
        self.assertEqual(outcome.recovery.classification, RecoveryClassification.OVERLAY_PRESENT)
        self.assertFalse(outcome.to_dict()["automatic_cleanup_permitted"])
        self.assertFalse(outcome.to_dict()["backing_chain_validated"])
        self.assertEqual(sentinel.read_bytes(), before)
        self.assertEqual(self.cli("review-vm-overlay-locked", str(self.root), "--json")[0], 5)

    def test_no_slot_does_not_turn_into_success_after_lock(self):
        output = review_overlay_with_local_lock(self.root)
        self.assertEqual(output.recovery.classification, RecoveryClassification.NO_SLOT)
        self.assertTrue((self.root / LOCK_NAME).exists())
        self.assertFalse(output.to_dict()["execution_authorized"])
        self.assertEqual(self.cli("review-vm-overlay-locked", str(self.root), "--json")[0], 5)

    def test_symlinked_and_nonprivate_root_fail_without_lock_creation(self):
        alias = self.home / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(LocalReviewLockError):
            with scoped_local_review_lock(alias):
                pass
        self.root.chmod(0o755)
        with self.assertRaises(LocalReviewLockError):
            with scoped_local_review_lock(self.root):
                pass
        self.root.chmod(0o700)
        self.assertFalse((self.root / LOCK_NAME).exists())

    def test_unrecognized_root_entries_block_new_lockfile(self):
        extra = self.root / "my-research.sqlite"
        extra.write_bytes(b"DO NOT TOUCH")
        with self.assertRaisesRegex(LocalReviewLockError, "unexpected"):
            with scoped_local_review_lock(self.root):
                pass
        self.assertEqual(extra.read_bytes(), b"DO NOT TOUCH")
        self.assertFalse((self.root / LOCK_NAME).exists())

    def test_symlink_lockfile_and_nonregular_type_rejected(self):
        target = self.home / "private-neighbor"
        target.write_bytes(b"keep safe")
        (self.root / LOCK_NAME).symlink_to(target)
        with self.assertRaises(LocalReviewLockError):
            with scoped_local_review_lock(self.root):
                pass
        self.assertEqual(target.read_bytes(), b"keep safe")
        (self.root / LOCK_NAME).unlink()
        (self.root / LOCK_NAME).mkdir(mode=0o700)
        with self.assertRaises(LocalReviewLockError):
            with scoped_local_review_lock(self.root):
                pass

    def test_unsafe_lock_mode_hardlinks_and_content_rejected(self):
        with scoped_local_review_lock(self.root):
            pass
        lock = self.root / LOCK_NAME
        lock.chmod(0o644)
        with self.assertRaises(LocalReviewLockError):
            with scoped_local_review_lock(self.root):
                pass
        lock.chmod(0o600)
        second = self.home / "hardlinked-lock"
        os.link(lock, second)
        with self.assertRaises(LocalReviewLockError):
            with scoped_local_review_lock(self.root):
                pass
        second.unlink()
        lock.write_bytes(b"NOT AN EMPTY LOCKFILE")
        with self.assertRaises(LocalReviewLockError):
            with scoped_local_review_lock(self.root):
                pass

    def test_replaced_inode_detected_on_release_but_never_cleaned(self):
        with self.assertRaisesRegex(LocalReviewLockError, "modified"):
            with scoped_local_review_lock(self.root):
                first = self.root / LOCK_NAME
                saved = self.root / ".old-lock"
                first.rename(saved)
                first.write_bytes(b"")
                first.chmod(0o600)
        self.assertTrue((self.root / ".old-lock").exists())
        self.assertTrue((self.root / LOCK_NAME).exists())

    def test_CLI_json_is_stable_and_path_free_after_lock_release(self):
        self.stage()
        first = self.cli("review-vm-overlay-locked", str(self.root), "--json")
        second = self.cli("review-vm-overlay-locked", str(self.root), "--json")
        self.assertEqual(first, second)
        self.assertEqual((first[0], first[2]), (0, ""))
        obj = json.loads(first[1])
        self.assertEqual(obj["kind"], "scoped_local_lock_and_read_only_overlay_review")
        self.assertFalse(obj["lock_held_after_command"])
        self.assertFalse(obj["execution_authorized"])
        self.assertNotIn(str(self.home), first[1])

    def test_CLI_busy_is_unresolved_not_success(self):
        self.stage()
        with scoped_local_review_lock(self.root):
            code, output, error = self.cli(
                "review-vm-overlay-locked", str(self.root), "--json"
            )
            self.assertEqual(code, 5)
            self.assertEqual(output, "")
            self.assertIn("held", error)

    def test_CLI_unsafe_root_is_invalid_input(self):
        code, output, error = self.cli(
            "review-vm-overlay-locked", str(self.home / "absent"), "--json"
        )
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertIn("private root", error)

    def test_no_process_vm_or_network_spawn_inside_review(self):
        self.stage()
        with (
            patch.object(subprocess, "Popen", side_effect=AssertionError("VM process")),
            patch.object(subprocess, "run", side_effect=AssertionError("subprocess")),
            patch.object(socket, "socket", side_effect=AssertionError("network")),
        ):
            report = review_overlay_with_local_lock(self.root)
            self.assertFalse(report.to_dict()["vm_launched"])
        self.assertEqual(
            set(os.listdir(self.root)), {RESERVATION_DIRECTORY, LOCK_NAME}
        )
        self.assertFalse((self.root / RESERVATION_DIRECTORY / "overlay.qcow2").exists())

    def test_real_run_compare_report_still_disabled(self):
        for cmd in ("run", "compare", "report"):
            code, out, err = self.cli(cmd)
            self.assertEqual(code, 3)
            self.assertEqual(out, "")


if __name__ == "__main__":
    unittest.main()
