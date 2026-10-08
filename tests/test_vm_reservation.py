"""SC-13b6: local private reservation persistence and non-destructive faults."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
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
from slipcage_engine.vm_plan import load_vm_plan, validate_vm_plan_bytes
from slipcage_engine.vm_assets import ARTIFACTS, verify_local_vm_assets
from slipcage_engine.vm_reservation import (
    API_VERSION, RESERVATION_DIRECTORY, ReservationError, QuarantineReason,
    inspect_local_reservation, quarantine_local_reservation, stage_local_reservation,
)
from slipcage_engine.vm_qemu_blueprint import QemuLaunchDisabled, launch_qemu

EXAMPLE = ROOT / "examples" / "vm-plans" / "k3s-synthetic-design.json"


class PrivateReservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.private = self.root / "operator-root"
        self.private.mkdir()
        self.private.chmod(0o700)
        self.asset_dir = self.root / "assets"
        self.asset_dir.mkdir()
        self.asset_dir.chmod(0o700)
        config = load_vm_plan(EXAMPLE).design
        config["provenance"]["pin_status"] = "operator_supplied_unverified"
        config["provenance"]["note"] = "CI private reservation fixture only; no trusted upstream signature"
        config["software"]["guest_kernel_release"] = "6.8.0-test"
        for index, (field, filename, _) in enumerate(ARTIFACTS):
            data = (f"reservation-test-fixture-{field}-{index}".encode() * 2)
            path = self.asset_dir / filename
            path.write_bytes(data)
            path.chmod(0o600)
            config["artifacts"][field] = hashlib.sha256(data).hexdigest()
        self.plan = validate_vm_plan_bytes(json.dumps(config).encode())
        self.preflight = verify_local_vm_assets(self.plan, self.asset_dir)
        self.plan_path = self.root / "operator-plan.json"
        self.plan_path.write_bytes(self.plan.canonical_json)
        self.neighbor = self.root / "keep-me.txt"
        self.neighbor.write_text("never modify or remove this", encoding="utf-8")

    @property
    def slot(self):
        return self.private / RESERVATION_DIRECTORY

    def stage(self):
        return stage_local_reservation(self.plan, self.preflight, self.private, "baseline")

    def invoke(self, arguments):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = main(arguments)
        return status, out.getvalue(), err.getvalue()

    def test_new_private_record_and_manifest_last_verify_byte_for_byte(self):
        record = self.stage()
        self.assertEqual(record.plan_digest_sha256, self.plan.digest_sha256)
        self.assertEqual(record.overlay_name, "overlay.qcow2")
        self.assertEqual(record.overlay_budget_gib, 24)
        self.assertEqual(record.runtime_budget_seconds, 900)
        self.assertFalse(record.quarantined)
        self.assertEqual(record, inspect_local_reservation(self.private))
        self.assertEqual(set(os.listdir(self.private)), {RESERVATION_DIRECTORY})
        self.assertEqual(set(os.listdir(self.slot)), {"intent.json", "manifest.json"})
        self.assertEqual(stat.S_IMODE(self.slot.stat().st_mode), 0o700)
        for file in self.slot.iterdir():
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
        intent = (self.slot / "intent.json").read_bytes()
        manifest = json.loads((self.slot / "manifest.json").read_bytes())
        self.assertTrue(manifest["complete"])
        self.assertEqual(manifest["intent_digest_sha256"], hashlib.sha256(intent).hexdigest())
        self.assertEqual(record.record_digest_sha256, manifest["intent_digest_sha256"])
        self.assertFalse((self.slot / "overlay.qcow2").exists())
        self.assertEqual(self.neighbor.read_text(), "never modify or remove this")

    def test_positive_flags_never_claim_real_lease_cleanup_or_launch(self):
        record = self.stage().to_dict()
        self.assertEqual(record["api_version"], API_VERSION)
        self.assertEqual(record["status"], "staged_no_execution")
        self.assertTrue(record["local_record_persisted"])
        self.assertTrue(record["single_slot_per_selected_root"])
        for field in (
            "real_host_exclusive_lease_enforced", "cross_process_execution_fencing_proven",
            "operator_clearance_implemented", "overlay_created", "overlay_deleted",
            "qemu_launched", "cgroup_limits_enforced", "watchdog_enforced",
            "actual_cleanup_verified", "provider_permission_verified",
            "execution_authorized", "host_vm_modified",
        ):
            with self.subTest(field=field):
                self.assertIs(record[field], False)

    def test_two_attempts_race_one_wins_no_overwrite_or_cleanup(self):
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(stage_local_reservation, self.plan, self.preflight,
                                self.private, label)
                for label in ("baseline", "candidate")
            ]
            outcomes = []
            for item in futures:
                try:
                    outcomes.append(item.result())
                except ReservationError:
                    outcomes.append(None)
        self.assertEqual(sum(r is not None for r in outcomes), 1)
        winner = inspect_local_reservation(self.private)
        self.assertIn(winner.attempt_id, ("baseline", "candidate"))
        self.assertEqual(set(os.listdir(self.slot)), {"intent.json", "manifest.json"})
        with self.assertRaises(ReservationError):
            stage_local_reservation(self.plan, self.preflight, self.private, "third")
        self.assertEqual(winner, inspect_local_reservation(self.private))

    def test_existing_slot_cannot_be_reused_even_after_clean_staging(self):
        original = self.stage()
        for attempt in ("baseline", "candidate"):
            with self.subTest(attempt=attempt), self.assertRaises(ReservationError):
                stage_local_reservation(self.plan, self.preflight, self.private, attempt)
        self.assertEqual(inspect_local_reservation(self.private), original)

    def test_partial_manifest_failure_keeps_blocking_directory_and_intent(self):
        from slipcage_engine import vm_reservation
        real = vm_reservation._write_new
        def fail_manifest(fd, name, raw):
            if name == "manifest.json":
                raise ReservationError("test injected interrupted creation")
            return real(fd, name, raw)
        with patch.object(vm_reservation, "_write_new", side_effect=fail_manifest):
            with self.assertRaises(ReservationError):
                self.stage()
        self.assertEqual(set(os.listdir(self.slot)), {"intent.json"})
        with self.assertRaises(ReservationError):
            inspect_local_reservation(self.private)
        with self.assertRaises(ReservationError):
            self.stage()
        self.assertEqual(self.neighbor.read_text(), "never modify or remove this")

    def test_recovery_never_auto_claims_incomplete_write(self):
        self.stage()
        (self.slot / "manifest.json").unlink()  # ephemeral CI fault injection only
        with self.assertRaises(ReservationError):
            inspect_local_reservation(self.private)
        with self.assertRaises(ReservationError):
            quarantine_local_reservation(
                self.private, attempt_id="baseline",
                expected_intent_sha256="0"*64,
                reason=QuarantineReason.OPERATOR_REVIEW_REQUIRED,
            )
        self.assertFalse((self.slot / "quarantine.json").exists())

    def test_corrupt_intent_or_manifest_fails_closed(self):
        for file in ("intent.json", "manifest.json"):
            with self.subTest(file=file):
                target_root = self.root / file.replace(".", "-")
                target_root.mkdir()
                target_root.chmod(0o700)
                stage_local_reservation(self.plan, self.preflight, target_root, "baseline")
                path = target_root / RESERVATION_DIRECTORY / file
                raw = path.read_bytes()
                path.write_bytes(raw + b"\n")
                with self.assertRaises(ReservationError):
                    inspect_local_reservation(target_root)

    def test_rehashed_forgery_cannot_add_execution_flag(self):
        self.stage()
        intent_path = self.slot / "intent.json"
        manifest_path = self.slot / "manifest.json"
        content = json.loads(intent_path.read_bytes())
        content["execution_enabled"] = True
        changed = json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
        intent_path.write_bytes(changed)
        marker = json.loads(manifest_path.read_bytes())
        marker["intent_digest_sha256"] = hashlib.sha256(changed).hexdigest()
        manifest_path.write_bytes(json.dumps(marker, sort_keys=True,
                                             separators=(",", ":")).encode())
        with self.assertRaises(ReservationError):
            inspect_local_reservation(self.private)

    def test_unexpected_entries_nonprivate_record_symlinks_and_hardlinks_refused(self):
        self.stage()
        (self.slot / "junk.txt").write_text("extra")
        with self.assertRaises(ReservationError):
            inspect_local_reservation(self.private)
        (self.slot / "junk.txt").unlink()
        file = self.slot / "manifest.json"
        file.chmod(0o644)
        with self.assertRaises(ReservationError):
            inspect_local_reservation(self.private)
        file.chmod(0o600)
        outside = self.root / "linked"
        os.link(file, outside)
        with self.assertRaises(ReservationError):
            inspect_local_reservation(self.private)
        outside.unlink()
        file.unlink()
        file.symlink_to(self.root / "keep-me.txt")
        with self.assertRaises(ReservationError):
            inspect_local_reservation(self.private)

    def test_staging_root_must_be_private_and_not_symlink(self):
        outside = self.root / "link-to-root"
        outside.symlink_to(self.private, target_is_directory=True)
        with self.assertRaises(ReservationError):
            stage_local_reservation(self.plan, self.preflight, outside, "baseline")
        self.private.chmod(0o755)
        with self.assertRaises(ReservationError):
            self.stage()
        self.private.chmod(0o700)
        with self.assertRaises(ReservationError):
            stage_local_reservation(self.plan, self.preflight,
                                    self.root / "missing", "baseline")
        self.assertFalse(self.slot.exists())

    def test_plan_synthetic_or_mismatched_preflight_never_creates_slot(self):
        with self.assertRaises(ReservationError):
            stage_local_reservation(load_vm_plan(EXAMPLE), self.preflight,
                                    self.private, "baseline")
        with self.assertRaises(ReservationError):
            stage_local_reservation(self.plan,
                                    replace(self.preflight, plan_digest_sha256="f"*64),
                                    self.private, "baseline")
        self.assertFalse(self.slot.exists())

    def test_invalid_owner_ids_fail_before_any_write(self):
        for value in (None, "", "Upper", "bad/name", "a"*33, True):
            with self.subTest(value=value), self.assertRaises(ReservationError):
                stage_local_reservation(self.plan, self.preflight, self.private, value)
            self.assertFalse(self.slot.exists())

    def test_quarantine_is_irreversible_and_requires_exact_attempt_digest(self):
        record = self.stage()
        for attempt, digest in (
            ("candidate", record.record_digest_sha256),
            ("baseline", "f"*64),
        ):
            with self.subTest(attempt=attempt, digest=digest), self.assertRaises(ReservationError):
                quarantine_local_reservation(
                    self.private, attempt_id=attempt, expected_intent_sha256=digest,
                    reason=QuarantineReason.SIMULATED_CRASH,
                )
        self.assertFalse((self.slot / "quarantine.json").exists())
        updated = quarantine_local_reservation(
            self.private, attempt_id="baseline",
            expected_intent_sha256=record.record_digest_sha256,
            reason=QuarantineReason.SIMULATED_CLEANUP_FAILURE,
        )
        self.assertTrue(updated.quarantined)
        self.assertEqual(updated.quarantine_reason, "simulated_cleanup_failure")
        self.assertEqual(updated, inspect_local_reservation(self.private))
        with self.assertRaises(ReservationError):
            quarantine_local_reservation(
                self.private, attempt_id="baseline",
                expected_intent_sha256=record.record_digest_sha256,
                reason=QuarantineReason.OPERATOR_REVIEW_REQUIRED,
            )
        with self.assertRaises(ReservationError):
            self.stage()
        self.assertTrue((self.slot / "quarantine.json").exists())

    def test_tampered_quarantine_reason_or_digest_fails_closed(self):
        record = self.stage()
        quarantine_local_reservation(
            self.private, attempt_id="baseline",
            expected_intent_sha256=record.record_digest_sha256,
            reason=QuarantineReason.SIMULATED_CRASH,
        )
        file = self.slot / "quarantine.json"
        marker = json.loads(file.read_bytes())
        marker["reason"] = "cleanup_verified"
        file.write_bytes(json.dumps(marker, sort_keys=True,
                                    separators=(",", ":")).encode())
        with self.assertRaises(ReservationError):
            inspect_local_reservation(self.private)

    def test_cli_stage_inspect_quarantine_and_no_real_run(self):
        rc, out, err = self.invoke([
            "stage-vm-reservation", str(self.plan_path), "--assets-dir", str(self.asset_dir),
            "--root", str(self.private), "--attempt", "baseline", "--json",
        ])
        self.assertEqual((rc, err), (0, ""))
        record = json.loads(out)
        self.assertEqual(record["status"], "staged_no_execution")
        self.assertFalse(record["overlay_created"])
        self.assertFalse(record["execution_authorized"])
        rc, verified, err = self.invoke([
            "inspect-vm-reservation", str(self.private), "--json",
        ])
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(json.loads(verified), record)
        rc, checked, err = self.invoke([
            "quarantine-vm-reservation", str(self.private), "--attempt", "baseline",
            "--intent-sha256", record["record_digest_sha256"],
            "--reason", "operator_review_required", "--json",
        ])
        self.assertEqual((rc, err), (5, ""))
        self.assertTrue(json.loads(checked)["quarantined"])
        rc, checked, err = self.invoke([
            "inspect-vm-reservation", str(self.private), "--json",
        ])
        self.assertEqual((rc, err), (5, ""))
        self.assertTrue(json.loads(checked)["quarantined"])
        for forbidden in ("run", "compare", "report"):
            self.assertEqual(self.invoke([forbidden])[0], 3)

    def test_no_guest_process_network_disk_overlay_or_neighbour_mutation(self):
        from slipcage_engine import vm_reservation as module
        with (
            patch.object(subprocess, "Popen", side_effect=AssertionError("Popen")),
            patch.object(subprocess, "run", side_effect=AssertionError("subprocess")),
            patch.object(socket, "socket", side_effect=AssertionError("network")),
            patch.object(os, "system", side_effect=AssertionError("shell")),
        ):
            output = self.stage()
            self.assertFalse(output.to_dict()["qemu_launched"])
            self.assertFalse(output.to_dict()["overlay_created"])
            self.assertFalse(output.to_dict()["execution_authorized"])
            with self.assertRaises(QemuLaunchDisabled):
                launch_qemu(None)
        self.assertEqual(self.neighbor.read_text(), "never modify or remove this")
        self.assertFalse((self.slot / "overlay.qcow2").exists())
        self.assertEqual(set(os.listdir(self.root)), {
            "operator-root", "assets", "operator-plan.json", "keep-me.txt",
        })


if __name__ == "__main__":
    unittest.main()
