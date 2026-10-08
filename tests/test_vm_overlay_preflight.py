"""SC-13b7 read-only QCOW2 header-shape and base-overlay intent tests.

All QCOW2 fixtures are tiny hand-crafted HEADER SHAPES, not actual bootable
or metadata-validated QEMU images. No qemu-img, QEMU or overlays are created.
"""
from contextlib import redirect_stdout, redirect_stderr
from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
import socket
import stat
import struct
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
    stage_local_reservation, inspect_local_reservation,
    quarantine_local_reservation, QuarantineReason,
)
from slipcage_engine.vm_overlay_preflight import (
    API_VERSION, HEADER_BYTES, CLUSTER_BYTES, GIB,
    OverlayPreflightError, _inspect_base_header, inspect_overlay_intent,
)
from slipcage_engine.vm_qemu_blueprint import QemuLaunchDisabled, launch_qemu

EXAMPLE = ROOT / "examples" / "vm-plans" / "k3s-synthetic-design.json"


def u32(header: bytearray, offset: int, value: int):
    struct.pack_into(">I", header, offset, value)


def u64(header: bytearray, offset: int, value: int):
    struct.pack_into(">Q", header, offset, value)


def fake_qcow2_header(virtual_size: int = 24 * GIB) -> bytes:
    header = bytearray(HEADER_BYTES)
    header[:4] = b"QFI\xfb"
    u32(header, 4, 3)
    u32(header, 20, 16)
    u64(header, 24, virtual_size)
    u32(header, 36, 1)
    u64(header, 40, CLUSTER_BYTES)
    u64(header, 48, 2 * CLUSTER_BYTES)
    u32(header, 56, 1)
    u32(header, 96, 4)
    u32(header, 100, 104)
    return bytes(header)


class Qcow2OverlayIntentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.assets.chmod(0o700)
        self.reservation_root = self.root / "reservation-root"
        self.reservation_root.mkdir()
        self.reservation_root.chmod(0o700)
        self.neighbor = self.root / "leave-me-alone.txt"
        self.neighbor.write_text("protected unrelated fixture")

        self.base = self.assets / "os-image.qcow2"
        # Three tiny clusters with a header SHAPE only: not a bootable image.
        self.base.write_bytes(fake_qcow2_header() + bytes(3 * CLUSTER_BYTES - HEADER_BYTES))
        self.base.chmod(0o600)
        config = load_vm_plan(EXAMPLE).design
        config["provenance"]["pin_status"] = "operator_supplied_unverified"
        config["provenance"]["note"] = "CI header shape only; no valid bootable image or trusted origin"
        config["software"]["guest_kernel_release"] = "6.8.0-test"
        for index, (field, filename, _) in enumerate(ARTIFACTS):
            if filename != "os-image.qcow2":
                file = self.assets / filename
                file.write_bytes(f"offline-asset-fixture-{index}".encode())
                file.chmod(0o600)
            else:
                file = self.base
            config["artifacts"][field] = hashlib.sha256(file.read_bytes()).hexdigest()
        self.plan = validate_vm_plan_bytes(json.dumps(config).encode())
        self.plan_path = self.root / "plan.json"
        self.plan_path.write_bytes(self.plan.canonical_json)
        self.preflight = verify_local_vm_assets(self.plan, self.assets)
        self.record = stage_local_reservation(
            self.plan, self.preflight, self.reservation_root, "baseline"
        )

    def invoke(self, argv):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = main(argv)
        return code, output.getvalue(), errors.getvalue()

    def check(self):
        return inspect_overlay_intent(self.plan, self.preflight, self.record, self.assets)

    def test_valid_header_shape_binds_checked_digest_and_reservation(self):
        result = self.check().to_dict()
        self.assertEqual(result["api_version"], API_VERSION)
        self.assertEqual(result["kind"], "nonexecuting_overlay_backing_intent")
        self.assertEqual(result["plan_digest_sha256"], self.plan.digest_sha256)
        self.assertEqual(result["reservation_digest_sha256"], self.record.record_digest_sha256)
        self.assertEqual(result["base_digest_sha256"], self.plan.design["artifacts"]["os_image_sha256"])
        self.assertEqual(result["base_file_size_bytes"], 3 * CLUSTER_BYTES)
        self.assertEqual(result["qcow2_header_shape"]["qcow2_version"], 3)
        self.assertEqual(result["qcow2_header_shape"]["cluster_bytes"], CLUSTER_BYTES)
        self.assertEqual(result["qcow2_header_shape"]["virtual_size_bytes"], 24 * GIB)
        self.assertTrue(result["base_has_no_declared_backing_file"])
        self.assertFalse(result["qcow2_header_shape"]["observed_backing_file_reference"])

    def test_all_risky_or_unproven_flags_remain_false(self):
        result = self.check().to_dict()
        self.assertTrue(result["base_sha256_matches_operator_declared_digest"])
        for key in (
            "overlay_create_command_present", "overlay_created",
            "backing_chain_created", "backing_chain_traversed",
            "qcow2_refcount_l1_l2_integrity_verified", "immutable_base_enforced",
            "actual_backing_file_resolution_verified", "host_disk_quota_enforced",
            "host_kvm_usable_verified", "software_publisher_authenticated",
            "qemu_or_qemu_img_executed", "guest_boot_verified",
            "cleanup_verified_on_host", "execution_authorized", "host_modified",
        ):
            with self.subTest(key=key):
                self.assertIs(result[key], False)
        self.assertEqual(result["overlay_filename_token"], "overlay.qcow2")
        self.assertEqual(result["overlay_budget_gib_declared"], 24)
        self.assertFalse((self.reservation_root / "vm-reservation-v1" / "overlay.qcow2").exists())

    def test_reject_backing_paths_even_if_digest_is_updated(self):
        for off, val in ((8, 120), (16, 8)):
            with self.subTest(off=off):
                header = bytearray(fake_qcow2_header())
                (u64 if off == 8 else u32)(header, off, val)
                with self.assertRaisesRegex(OverlayPreflightError, "NO backing"):
                    _inspect_base_header(bytes(header), 3 * CLUSTER_BYTES, 24 * GIB)

    def test_reject_unsupported_header_metadata(self):
        cases = [
            (4, 2, 4, "version"),
            (20, 9, 4, "cluster"),
            (24, 32 * GIB, 8, "virtual size"),
            (32, 1, 4, "Encrypted"),
            (60, 1, 4, "snapshots"),
            (64, CLUSTER_BYTES, 8, "snapshots"),
            (72, 1, 8, "features"),
            (72, 2, 8, "features"),
            (72, 4, 8, "features"),
            (72, 16, 8, "features"),
            (80, 1, 8, "features"),
            (88, 1, 8, "features"),
            (96, 6, 4, "refcount order"),
            (100, 112, 4, "header length"),
            (36, 0, 4, "table sizes"),
            (56, 0, 4, "table sizes"),
            (40, 7, 8, "table offsets"),
            (48, CLUSTER_BYTES, 8, "overlap"),
            (48, 5 * CLUSTER_BYTES, 8, "table offsets"),
        ]
        for offset, value, width, reason in cases:
            with self.subTest(offset=offset, value=value):
                header = bytearray(fake_qcow2_header())
                (u32 if width == 4 else u64)(header, offset, value)
                with self.assertRaisesRegex(OverlayPreflightError, reason):
                    _inspect_base_header(bytes(header), 3 * CLUSTER_BYTES, 24 * GIB)

    def test_reject_header_extensions_or_wrong_magic_and_short_data(self):
        for patch_bytes in (
            b"XXXX" + fake_qcow2_header()[4:],
            fake_qcow2_header()[:-1],
            fake_qcow2_header()[:104] + b"\x00\x00\x00\x00\x00\x00\x00\x01",
        ):
            with self.subTest(patch_bytes=patch_bytes[:8]), self.assertRaises(OverlayPreflightError):
                _inspect_base_header(patch_bytes, 3 * CLUSTER_BYTES, 24 * GIB)

    def test_corrupt_base_bytes_rejected_even_when_header_unchanged(self):
        with self.base.open("r+b") as file:
            file.seek(2 * CLUSTER_BYTES + 25)
            file.write(b"X")
        with self.assertRaisesRegex(OverlayPreflightError, "SHA-256"):
            self.check()

    def test_missing_base_symlink_hardlink_root_modes_rejected(self):
        copy = self.root / "copy"
        copy.write_bytes(self.base.read_bytes())
        self.base.unlink()
        self.base.symlink_to(copy)
        with self.assertRaises(OverlayPreflightError):
            self.check()
        self.base.unlink()
        self.base.write_bytes(copy.read_bytes())
        self.base.chmod(0o600)
        outside = self.root / "hardlinked-base"
        import os
        os.link(self.base, outside)
        with self.assertRaises(OverlayPreflightError):
            self.check()
        outside.unlink()
        self.assets.chmod(0o755)
        with self.assertRaisesRegex(OverlayPreflightError, "private"):
            self.check()

    def test_forged_reservation_plan_or_quarantine_refused(self):
        examples = (
            replace(self.record, plan_digest_sha256="f" * 64),
            replace(self.record, plan_id="wrong-plan"),
            replace(self.record, record_digest_sha256="g" * 64),
            replace(self.record, overlay_name="not-an-overlay"),
            replace(self.record, overlay_budget_gib=48),
            replace(self.record, runtime_budget_seconds=1800),
            replace(self.record, quarantined=True),
        )
        for fake in examples:
            with self.subTest(fake=fake), self.assertRaises(OverlayPreflightError):
                inspect_overlay_intent(self.plan, self.preflight, fake, self.assets)

    def test_real_quarantine_cli_refuses_preflight(self):
        quarantine_local_reservation(
            self.reservation_root, attempt_id="baseline",
            expected_intent_sha256=self.record.record_digest_sha256,
            reason=QuarantineReason.OPERATOR_REVIEW_REQUIRED,
        )
        rc, output, errors = self.invoke([
            "inspect-vm-backing", str(self.plan_path), "--assets-dir", str(self.assets),
            "--reservation-root", str(self.reservation_root), "--json",
        ])
        self.assertEqual(rc, 2)
        self.assertEqual(output, "")
        self.assertIn("quarantined", errors)

    def test_cli_positive_path_is_only_an_incomplete_preflight(self):
        rc, out, errors = self.invoke([
            "inspect-vm-backing", str(self.plan_path), "--assets-dir", str(self.assets),
            "--reservation-root", str(self.reservation_root), "--json",
        ])
        self.assertEqual((rc, errors), (0, ""))
        body = json.loads(out)
        self.assertFalse(body["overlay_created"])
        self.assertFalse(body["qemu_or_qemu_img_executed"])
        self.assertFalse(body["execution_authorized"])
        self.assertEqual(body["base_file_size_bytes"], 3 * CLUSTER_BYTES)

    def test_readonly_no_guest_network_or_overlay_calls(self):
        from slipcage_engine import vm_overlay_preflight as module
        with (
            patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess launched")),
            patch.object(subprocess, "run", side_effect=AssertionError("qemu-img ran")),
            patch.object(socket, "socket", side_effect=AssertionError("network")),
            patch.object(module, "open", create=True, side_effect=AssertionError("file writer")),
        ):
            result = self.check()
            self.assertFalse(result.to_dict()["host_modified"])
            with self.assertRaises(QemuLaunchDisabled):
                launch_qemu(None)
        self.assertEqual(self.neighbor.read_text(), "protected unrelated fixture")
        self.assertFalse((self.reservation_root / "vm-reservation-v1" / "overlay.qcow2").exists())

    def test_deterministic_output_no_private_paths_or_confidential_data(self):
        one = self.check()
        two = self.check()
        self.assertEqual(one.canonical_json(), two.canonical_json())
        self.assertEqual(json.loads(one.canonical_json()), one.to_dict())
        output = one.canonical_json().decode()
        self.assertNotIn(str(self.root), output)
        self.assertNotIn("ssh_key", output)

    def test_real_run_compare_report_remain_disabled(self):
        for command in ("run", "compare", "report"):
            rc, out, errors = self.invoke([command])
            self.assertEqual(rc, 3)
            self.assertEqual(out, "")


if __name__ == "__main__":
    unittest.main()
