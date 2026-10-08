"""SC-13b4: QEMU blueprint is safe, incomplete, fixed and nonexecuting."""
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
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
from slipcage_engine.vm_plan import load_vm_plan, validate_vm_plan_bytes
from slipcage_engine.vm_assets import (
    ARTIFACTS, VMAssetPreflight, VerifiedLocalAsset, verify_local_vm_assets,
)
from slipcage_engine.vm_qemu_blueprint import (
    API_VERSION, QemuBlueprintError, QemuLaunchDisabled,
    build_qemu_blueprint, launch_qemu,
)

EXAMPLE = ROOT / "examples" / "vm-plans" / "k3s-synthetic-design.json"


class QemuBlueprintTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.assets.chmod(0o700)
        data = load_vm_plan(EXAMPLE).design
        data["provenance"]["pin_status"] = "operator_supplied_unverified"
        data["provenance"]["note"] = "Test-only operator-style pins, not authenticated release artifacts"
        data["software"]["guest_kernel_release"] = "6.8.0-test"
        self.contents = {}
        for i, (field, filename, _) in enumerate(ARTIFACTS):
            blob = (f"test-only-byte-content-{i}-{field}".encode() * 3)
            self.contents[filename] = blob
            path = self.assets / filename
            path.write_bytes(blob)
            path.chmod(0o600)
            data["artifacts"][field] = hashlib.sha256(blob).hexdigest()
        self.plan = validate_vm_plan_bytes(json.dumps(data).encode())
        self.plan_path = self.root / "operator-plan.json"
        self.plan_path.write_bytes(self.plan.canonical_json)
        self.preflight = verify_local_vm_assets(self.plan, self.assets)

    def call(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            rc = main(args)
        return rc, stdout.getvalue(), stderr.getvalue()

    def test_fixed_paused_diskless_networkless_argv_prefix(self):
        record = build_qemu_blueprint(self.plan, self.preflight).to_dict()
        self.assertEqual(record["api_version"], API_VERSION)
        self.assertEqual(record["plan_digest_sha256"], self.plan.digest_sha256)
        self.assertEqual(record["qemu_version_declared"], "9.0.0")
        self.assertEqual(
            record["qemu_argv_prefix"],
            ["qemu-system-x86_64", "-no-user-config", "-nodefaults",
             "-machine", "pc-q35-9.0,accel=kvm",
             "-cpu", "x86-64-v2", "-smp", "2", "-m", "4096",
             "-display", "none", "-monitor", "none", "-serial", "none",
             "-nic", "none", "-S", "-no-reboot"],
        )
        for forbidden in (
            "-drive", "-blockdev", "-device", "-kernel", "-initrd", "-bios",
            "-pflash", "-netdev", "-virtfs", "-fsdev", "-object", "-daemonize",
            "-qmp", "-chardev", "-incoming", "-runas",
        ):
            self.assertNotIn(forbidden, record["qemu_argv_prefix"])
        self.assertEqual(record["max_parallel_vms_declared"], 1)
        self.assertEqual(record["disk_attachment"], "absent")
        self.assertEqual(record["guest_kernel_attachment"], "absent")
        self.assertEqual(record["network_attachment"], "absent")
        self.assertTrue(record["qemu_paused_if_prefix_executed"])
        self.assertFalse(record["argv_is_complete_launch_command"])
        self.assertFalse(record["guest_boot_possible_from_blueprint"])

    def test_flags_never_claim_host_or_provenance_verification(self):
        data = build_qemu_blueprint(self.plan, self.preflight).to_dict()
        self.assertTrue(data["asset_byte_integrity_checked_locally"])
        for field in (
            "asset_software_origin_authenticated", "qemu_binary_version_verified",
            "guest_image_contents_verified", "guest_network_isolation_verified",
            "host_kvm_usable_verified", "host_resources_reserved",
            "process_cgroup_limits_enforced", "runtime_deadline_enforced",
            "guest_overlay_created", "crash_cleanup_verified",
            "operator_launch_approved", "execution_authorized",
            "real_vm_launched", "host_modified",
        ):
            with self.subTest(field=field):
                self.assertIs(data[field], False)
        self.assertIn("real_launcher_intentionally_absent", data["blockers"])

    def test_output_is_stable_json_without_private_host_paths(self):
        one = build_qemu_blueprint(self.plan, self.preflight)
        two = build_qemu_blueprint(self.plan, self.preflight)
        self.assertEqual(one.canonical_json(), two.canonical_json())
        self.assertEqual(json.loads(one.canonical_json()), one.to_dict())
        text = one.canonical_json().decode()
        self.assertNotIn(str(self.root), text)
        self.assertNotIn("ssh_key", text)
        self.assertNotIn("/dev/kvm", text)

    def test_requires_nonsynthetic_vm_plan(self):
        with self.assertRaisesRegex(QemuBlueprintError, "Synthetic"):
            build_qemu_blueprint(load_vm_plan(EXAMPLE), self.preflight)

    def test_fake_plan_identity_rejected(self):
        for fake in (
            replace(self.plan, digest_sha256="a"*64),
            replace(self.plan, canonical_json=b'{"bad":true}'),
        ):
            with self.subTest(fake=fake), self.assertRaises(QemuBlueprintError):
                build_qemu_blueprint(fake, self.preflight)

    def test_fake_preflight_wrong_plan_id_or_digest_rejected(self):
        for fake in (
            replace(self.preflight, plan_id="different-id"),
            replace(self.preflight, plan_digest_sha256="f"*64),
        ):
            with self.subTest(fake=fake), self.assertRaises(QemuBlueprintError):
                build_qemu_blueprint(self.plan, fake)

    def test_missing_extra_reordered_and_invalid_asset_bindings_rejected(self):
        assets = self.preflight.assets
        mutations = [
            replace(self.preflight, assets=()),
            replace(self.preflight, assets=assets[:4]),
            replace(self.preflight, assets=assets + (assets[0],)),
            replace(self.preflight, assets=tuple(reversed(assets))),
            replace(self.preflight, assets=("os-image.qcow2",) + assets[1:]),
            replace(self.preflight, assets=(replace(assets[0], sha256="0"*64),) + assets[1:]),
            replace(self.preflight, assets=(replace(assets[0], filename="other.qcow2"),) + assets[1:]),
            replace(self.preflight, assets=(replace(assets[0], size_bytes=True),) + assets[1:]),
            replace(self.preflight, assets=(replace(assets[0], size_bytes=0),) + assets[1:]),
        ]
        for fake in mutations:
            with self.subTest(fake=str(fake)[:90]), self.assertRaises(QemuBlueprintError):
                build_qemu_blueprint(self.plan, fake)

    def test_binary_version_machine_and_resource_bounds_inherited_from_sc12(self):
        data = self.plan.design
        data["runtime"]["machine_type"] = "pc-q35-8.2"
        with self.assertRaises(Exception):
            validate_vm_plan_bytes(json.dumps(data).encode())
        data = self.plan.design
        data["guest"]["max_parallel_vms"] = 2
        with self.assertRaises(Exception):
            validate_vm_plan_bytes(json.dumps(data).encode())
        data = self.plan.design
        data["network"]["public_egress"] = True
        with self.assertRaises(Exception):
            validate_vm_plan_bytes(json.dumps(data).encode())

    def test_no_process_network_shell_or_disk_creation_when_building(self):
        from slipcage_engine import vm_qemu_blueprint as module
        before = {name: (self.assets / name).read_bytes() for name in self.contents}
        with (
            patch.object(subprocess, "run", side_effect=AssertionError("subprocess")),
            patch.object(subprocess, "Popen", side_effect=AssertionError("Popen")),
            patch.object(socket, "socket", side_effect=AssertionError("network")),
            patch.object(module, "open", create=True, side_effect=AssertionError("open")),
            patch.object(os, "system", side_effect=AssertionError("shell")),
        ):
            output = build_qemu_blueprint(self.plan, self.preflight)
        self.assertFalse(output.to_dict()["real_vm_launched"])
        self.assertEqual(
            before, {name: (self.assets / name).read_bytes() for name in self.contents}
        )

    def test_launch_api_always_refuses_for_even_verified_prefix(self):
        blueprint = build_qemu_blueprint(self.plan, self.preflight)
        with patch.object(subprocess, "Popen", side_effect=AssertionError("process launched")):
            with self.assertRaisesRegex(QemuLaunchDisabled, "not implemented or authorized"):
                launch_qemu(blueprint)
            with self.assertRaises(QemuLaunchDisabled):
                launch_qemu(None)

    def test_cli_with_real_local_test_bytes_returns_only_design(self):
        rc, stdout, stderr = self.call([
            "plan-qemu", str(self.plan_path), "--assets-dir", str(self.assets), "--json",
        ])
        self.assertEqual((rc, stderr), (0, ""))
        result = json.loads(stdout)
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["real_vm_launched"])
        self.assertFalse(result["argv_is_complete_launch_command"])
        self.assertFalse(result["guest_boot_possible_from_blueprint"])
        self.assertEqual(result["plan_digest_sha256"], self.plan.digest_sha256)

    def test_cli_rejects_synthetic_example_without_success_output(self):
        rc, out, err = self.call([
            "plan-qemu", str(EXAMPLE), "--assets-dir", str(self.assets), "--json",
        ])
        self.assertEqual(rc, 2)
        self.assertEqual(out, "")
        self.assertIn("Synthetic plan", err)

    def test_cli_rejects_corrupted_local_asset_without_success_output(self):
        target = self.assets / "kernel.bin"
        target.write_bytes(b"corrupted")
        target.chmod(0o600)
        rc, out, err = self.call([
            "plan-qemu", str(self.plan_path), "--assets-dir", str(self.assets), "--json",
        ])
        self.assertEqual(rc, 2)
        self.assertEqual(out, "")
        self.assertIn("SHA-256", err)

    def test_cli_no_vm_start_commands_activated(self):
        for command in ("run", "compare", "report"):
            with self.subTest(command=command):
                rc, stdout, stderr = self.call([command])
                self.assertEqual(rc, 3)
                self.assertEqual(stdout, "")
                self.assertIn("unavailable", stderr)


if __name__ == "__main__":
    unittest.main()
