"""SC-13b8: recovery *review* only. All writes in tests are to temp fixtures."""
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import socket
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
    RESERVATION_DIRECTORY, QuarantineReason,
    stage_local_reservation, quarantine_local_reservation,
)
from slipcage_engine.vm_overlay_recovery import (
    API_VERSION, OverlayRecoveryError, RecoveryClassification, review_overlay_recovery,
)

SAMPLE = ROOT / "examples" / "vm-plans" / "k3s-synthetic-design.json"


class LocalRecoveryReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.root = self.home / "operator-root"
        self.root.mkdir(mode=0o700)
        self.root.chmod(0o700)
        self.assets = self.home / "assets"
        self.assets.mkdir(mode=0o700)
        self.assets.chmod(0o700)
        draft = load_vm_plan(SAMPLE).design
        draft["provenance"]["pin_status"] = "operator_supplied_unverified"
        draft["provenance"]["note"] = "Ephemeral CI-only bytes, not trusted software"
        draft["software"]["guest_kernel_release"] = "6.8.0-test"
        for index, (field, name, _) in enumerate(ARTIFACTS):
            content = ("CI-" + str(index) + "-" + field).encode("ascii")
            path = self.assets / name
            path.write_bytes(content)
            path.chmod(0o600)
            draft["artifacts"][field] = hashlib.sha256(content).hexdigest()
        self.plan = validate_vm_plan_bytes(json.dumps(draft).encode("utf-8"))
        self.preflight = verify_local_vm_assets(self.plan, self.assets)
        self.neighbor = self.home / "protected-report.txt"
        self.neighbor.write_text("preserve operator evidence", encoding="utf-8")

    @property
    def slot(self):
        return self.root / RESERVATION_DIRECTORY

    def stage(self):
        return stage_local_reservation(self.plan, self.preflight, self.root, "baseline")

    def invoke(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = main(["review-vm-overlay", str(self.root), "--json"])
        return status, out.getvalue(), err.getvalue()

    def test_no_slot_is_unresolved_not_a_clean_vm(self):
        review = review_overlay_recovery(self.root).to_dict()
        self.assertEqual(review["classification"], "no_staging_slot")
        self.assertFalse(review["record_verified"])
        self.assertFalse(review["overlay_node_observed"])
        self.assertTrue(review["manual_preservation_and_operator_review_required"])
        self.assertFalse(review["execution_authorized"])
        self.assertEqual(self.invoke()[0], 5)
        self.assertFalse(self.slot.exists())

    def test_valid_staged_record_with_no_overlay_is_only_point_in_time(self):
        original = self.stage()
        review = review_overlay_recovery(self.root)
        self.assertIs(review.classification, RecoveryClassification.STAGED_ONLY)
        self.assertTrue(review.record_verified)
        self.assertEqual(review.attempt_id, "baseline")
        self.assertEqual(review.plan_digest_sha256, self.plan.digest_sha256)
        self.assertEqual(review.reservation_digest_sha256, original.record_digest_sha256)
        self.assertFalse(review.overlay_node_observed)
        self.assertEqual(review.overlay_node_kind, "absent")
        self.assertEqual((self.invoke()[0], self.invoke()[2]), (0, ""))
        self.assertFalse((self.slot / "overlay.qcow2").exists())

    def test_no_positive_output_can_authorize_cleanup_or_guest(self):
        self.stage()
        report = review_overlay_recovery(self.root).to_dict()
        self.assertEqual(report["api_version"], API_VERSION)
        for field in (
            "automatic_recovery_attempted", "automatic_cleanup_permitted",
            "owner_clearance_implemented", "host_wide_guest_lock_held",
            "active_guest_processes_checked", "backing_chain_resolved",
            "overlay_bytes_opened_or_read", "overlay_created", "overlay_deleted",
            "reservation_removed", "quarantine_cleared", "watchdog_enforced",
            "real_guest_started", "real_guest_cleanup_verified",
            "execution_authorized", "host_modified",
        ):
            with self.subTest(field=field):
                self.assertIs(report[field], False)

    def test_incomplete_persisted_intent_does_not_get_repaired(self):
        self.slot.mkdir(mode=0o700)
        (self.slot / "intent.json").write_bytes(b"{}")
        before = (self.slot / "intent.json").read_bytes()
        review = review_overlay_recovery(self.root)
        self.assertIs(review.classification, RecoveryClassification.INCOMPLETE)
        self.assertFalse(review.record_verified)
        self.assertEqual((self.slot / "intent.json").read_bytes(), before)
        self.assertFalse((self.slot / "manifest.json").exists())
        self.assertEqual(self.invoke()[0], 5)

    def test_truncated_manifest_or_tampered_signature_is_not_verification(self):
        self.stage()
        manifest = self.slot / "manifest.json"
        manifest.write_bytes(b'{"complete":true}')
        result = review_overlay_recovery(self.root).to_dict()
        self.assertEqual(result["classification"], "invalid_record_preserve")
        self.assertFalse(result["record_verified"])
        self.assertEqual(self.invoke()[0], 5)
        self.assertEqual(manifest.read_bytes(), b'{"complete":true}')

    def test_quarantine_is_never_cleared(self):
        staged = self.stage()
        quarantine_local_reservation(
            self.root, attempt_id="baseline",
            expected_intent_sha256=staged.record_digest_sha256,
            reason=QuarantineReason.SIMULATED_CRASH,
        )
        review = review_overlay_recovery(self.root)
        self.assertIs(review.classification, RecoveryClassification.QUARANTINED)
        self.assertTrue(review.record_verified)
        self.assertTrue(review.quarantine_marker_observed)
        self.assertFalse(review.to_dict()["quarantine_cleared"])
        self.assertEqual(self.invoke()[0], 5)
        self.assertTrue((self.slot / "quarantine.json").exists())

    def test_unknown_files_do_not_get_removed_or_opened(self):
        self.stage()
        extra = self.slot / "unknown-k3s-guest-state"
        extra.write_bytes(b"never touch")
        record = review_overlay_recovery(self.root)
        self.assertIs(record.classification, RecoveryClassification.UNKNOWN_CONTENT)
        self.assertFalse(record.record_verified)
        self.assertEqual(extra.read_bytes(), b"never touch")
        self.assertEqual(self.invoke()[0], 5)
        self.assertFalse(record.to_dict()["automatic_cleanup_permitted"])

    def test_directory_entry_count_is_bounded_without_disclosing_names(self):
        self.stage()
        for i in range(17):
            (self.slot / f"file-{i:02d}").write_bytes(b"")
        review = review_overlay_recovery(self.root)
        self.assertEqual(review.classification, RecoveryClassification.UNKNOWN_CONTENT)
        self.assertNotIn("file-09", review.canonical_json().decode())
        self.assertEqual(len(list(self.slot.iterdir())), 19)

    def test_unexpected_overlay_regular_file_is_stat_only_and_preserved(self):
        self.stage()
        overlay = self.slot / "overlay.qcow2"
        overlay.write_bytes(b"UNTRUSTED-EVIDENCE-NOT-A-QCOW2-IMAGE")
        overlay.chmod(0o600)
        review = review_overlay_recovery(self.root)
        self.assertIs(review.classification, RecoveryClassification.OVERLAY_PRESENT)
        self.assertEqual(review.overlay_node_kind, "regular")
        self.assertEqual(review.overlay_node_size_bytes, overlay.stat().st_size)
        self.assertFalse(review.record_verified)
        self.assertFalse(review.to_dict()["overlay_bytes_opened_or_read"])
        self.assertFalse(review.to_dict()["overlay_deleted"])
        self.assertEqual(self.invoke()[0], 5)
        self.assertEqual(overlay.read_bytes(), b"UNTRUSTED-EVIDENCE-NOT-A-QCOW2-IMAGE")

    def test_overlay_symlink_is_not_followed_even_if_target_is_secret(self):
        self.stage()
        sentinel = self.home / "never-read-this-secret"
        sentinel.write_bytes(b"private-test-sentinel")
        link = self.slot / "overlay.qcow2"
        link.symlink_to(sentinel)
        review = review_overlay_recovery(self.root)
        self.assertEqual(review.classification, RecoveryClassification.OVERLAY_PRESENT)
        self.assertEqual(review.overlay_node_kind, "symlink")
        self.assertIsNone(review.overlay_node_size_bytes)
        self.assertTrue(link.is_symlink())
        self.assertNotIn(str(sentinel), review.canonical_json().decode())

    def test_overlay_directory_is_not_traversed_or_removed(self):
        self.stage()
        overlay = self.slot / "overlay.qcow2"
        overlay.mkdir()
        secret = overlay / "stay-here.txt"
        secret.write_text("unknown guest metadata")
        review = review_overlay_recovery(self.root)
        self.assertEqual(review.overlay_node_kind, "directory")
        self.assertTrue(secret.exists())
        self.assertEqual(self.invoke()[0], 5)

    def test_overlay_with_quarantine_is_still_an_explicit_overlay_hazard(self):
        staged = self.stage()
        quarantine_local_reservation(
            self.root, attempt_id="baseline",
            expected_intent_sha256=staged.record_digest_sha256,
            reason=QuarantineReason.OPERATOR_REVIEW_REQUIRED,
        )
        (self.slot / "overlay.qcow2").write_bytes(b"remnant")
        review = review_overlay_recovery(self.root)
        self.assertEqual(review.classification, RecoveryClassification.OVERLAY_PRESENT)
        self.assertTrue(review.quarantine_marker_observed)
        self.assertTrue((self.slot / "quarantine.json").exists())

    def test_unsafe_root_modes_or_symlink_slot_return_input_failure(self):
        self.root.chmod(0o755)
        with self.assertRaises(OverlayRecoveryError):
            review_overlay_recovery(self.root)
        self.root.chmod(0o700)
        other = self.home / "other-slot"
        other.mkdir()
        self.slot.symlink_to(other, target_is_directory=True)
        with self.assertRaises(OverlayRecoveryError):
            review_overlay_recovery(self.root)
        self.assertEqual(self.invoke()[0], 2)

    def test_inaccessible_untrusted_slot_mode_rejected_without_mutation(self):
        self.slot.mkdir()
        self.slot.chmod(0o755)
        with self.assertRaises(OverlayRecoveryError):
            review_overlay_recovery(self.root)
        self.assertTrue(self.slot.exists())

    def test_stable_json_excludes_paths_and_synthetic_host_claims(self):
        self.stage()
        one = review_overlay_recovery(self.root).canonical_json()
        two = review_overlay_recovery(self.root).canonical_json()
        self.assertEqual(one, two)
        self.assertEqual(json.loads(one), review_overlay_recovery(self.root).to_dict())
        self.assertNotIn(str(self.home), one.decode())
        self.assertNotIn("hostname", one.decode())
        self.assertNotIn("ssh_key", one.decode())

    def test_review_never_invokes_processes_sockets_or_writes_files(self):
        self.stage()
        before = {path.name: path.read_bytes() for path in self.slot.iterdir()}
        from slipcage_engine import vm_overlay_recovery
        with (
            patch.object(subprocess, "Popen", side_effect=AssertionError("Popen")),
            patch.object(subprocess, "run", side_effect=AssertionError("run")),
            patch.object(socket, "socket", side_effect=AssertionError("network")),
            patch.object(vm_overlay_recovery.os, "unlink", side_effect=AssertionError("unlink")),
            patch.object(vm_overlay_recovery.os, "remove", side_effect=AssertionError("remove")),
            patch.object(vm_overlay_recovery.os, "mkdir", side_effect=AssertionError("mkdir")),
        ):
            self.assertEqual(review_overlay_recovery(self.root).classification,
                             RecoveryClassification.STAGED_ONLY)
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.slot.iterdir()})
        self.assertEqual(self.neighbor.read_text(), "preserve operator evidence")

    def test_real_run_compare_report_remain_disabled(self):
        for cmd in ("run", "compare", "report"):
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = main([cmd])
            self.assertEqual(code, 3)
            self.assertEqual(out.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
