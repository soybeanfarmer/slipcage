"""SC-13b1: bounded local hash checks, no QEMU, archive extraction or host mutation."""
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
from slipcage_engine.vm_assets import (
    ARTIFACTS, VMAssetError, verify_local_vm_assets,
)
from slipcage_engine.vm_plan import (
    load_vm_plan, validate_vm_plan_bytes,
)

SAMPLE = ROOT / "examples" / "vm-plans" / "k3s-synthetic-design.json"


class LocalVMAssetVerificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.root = self.home / "assets"
        self.root.mkdir(mode=0o700)
        self.root.chmod(0o700)
        self.blobs = {}
        draft = load_vm_plan(SAMPLE).design
        draft["provenance"]["pin_status"] = "operator_supplied_unverified"
        draft["provenance"]["note"] = "Untrusted pins: unit-test bytes only; not verified software origins"
        draft["software"]["guest_kernel_release"] = "6.8.0-test"
        for index, (field, filename, _) in enumerate(ARTIFACTS):
            content = (f"SC13-test-bytes-{field}-{index}".encode("ascii") * 3)
            path = self.root / filename
            path.write_bytes(content)
            path.chmod(0o600)
            draft["artifacts"][field] = hashlib.sha256(content).hexdigest()
            self.blobs[filename] = content
        self.plan = validate_vm_plan_bytes(json.dumps(draft).encode())
        self.planpath = self.home / "plan.json"
        self.planpath.write_bytes(self.plan.canonical_json)

    def test_happy_path_proves_local_bytes_only(self):
        result = verify_local_vm_assets(self.plan, self.root).to_dict()
        self.assertEqual(result["status"], "local_bytes_match_untrusted_pin_declarations")
        self.assertTrue(result["content_sha256_matches_declared_pins"])
        self.assertEqual(result["artifact_count"], 5)
        self.assertEqual(result["total_size_bytes"], sum(map(len, self.blobs.values())))
        self.assertEqual(result["plan_digest_sha256"], self.plan.digest_sha256)
        self.assertEqual(
            [x["filename"] for x in result["assets"]],
            [entry[1] for entry in ARTIFACTS],
        )
        for key in (
            "software_origin_authenticated", "image_contents_security_reviewed",
            "host_kvm_verified", "provider_permission_verified",
            "host_capacity_verified", "guest_network_isolation_verified",
            "guest_boot_verified", "execution_authorized", "host_modified",
            "vm_launched",
        ):
            with self.subTest(key=key):
                self.assertIs(result[key], False)

    def test_stable_canonical_json_contains_no_host_paths(self):
        first = verify_local_vm_assets(self.plan, self.root)
        second = verify_local_vm_assets(self.plan, self.root)
        self.assertEqual(first.canonical_json(), second.canonical_json())
        self.assertEqual(json.loads(first.canonical_json()), first.to_dict())
        self.assertNotIn(str(self.home), first.canonical_json().decode("ascii"))
        self.assertNotIn("kubeconfig", first.canonical_json().decode("ascii"))

    def test_byte_corruption_even_with_same_length_rejected(self):
        for _, name, _ in ARTIFACTS:
            with self.subTest(name=name):
                path = self.root / name
                path.write_bytes(b"X" * len(self.blobs[name]))
                with self.assertRaisesRegex(VMAssetError, "does not match"):
                    verify_local_vm_assets(self.plan, self.root)
                path.write_bytes(self.blobs[name])
                path.chmod(0o600)

    def test_refuses_synthetic_input_even_with_path(self):
        with self.assertRaisesRegex(VMAssetError, "Synthetic plan"):
            verify_local_vm_assets(load_vm_plan(SAMPLE), self.root)

    def test_rejects_missing_extra_and_empty_files(self):
        for _, name, _ in ARTIFACTS:
            with self.subTest(name=name):
                p = self.root / name
                p.unlink()
                with self.assertRaises(VMAssetError):
                    verify_local_vm_assets(self.plan, self.root)
                p.write_bytes(self.blobs[name])
                p.chmod(0o600)
        extra = self.root / "untrusted-payload.sh"
        extra.write_text("never executed")
        with self.assertRaisesRegex(VMAssetError, "exactly five"):
            verify_local_vm_assets(self.plan, self.root)
        extra.unlink()
        p = self.root / ARTIFACTS[0][1]
        p.write_bytes(b"")
        with self.assertRaises(VMAssetError):
            verify_local_vm_assets(self.plan, self.root)

    def test_symlinked_root_or_artifact_rejected(self):
        other = self.home / "symlink"
        other.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(VMAssetError):
            verify_local_vm_assets(self.plan, other)
        p = self.root / ARTIFACTS[0][1]
        p.unlink()
        p.symlink_to(self.home / "plan.json")
        with self.assertRaises(VMAssetError):
            verify_local_vm_assets(self.plan, self.root)

    def test_hardlink_and_directory_as_artifact_rejected(self):
        p = self.root / ARTIFACTS[0][1]
        outside = self.home / "other"
        os.link(p, outside)
        with self.assertRaisesRegex(VMAssetError, "single-link"):
            verify_local_vm_assets(self.plan, self.root)
        outside.unlink()
        p.unlink()
        p.mkdir()
        with self.assertRaises(VMAssetError):
            verify_local_vm_assets(self.plan, self.root)

    def test_reject_world_readable_asset_and_untrusted_root_mode(self):
        p = self.root / ARTIFACTS[0][1]
        p.chmod(0o644)
        with self.assertRaisesRegex(VMAssetError, "private"):
            verify_local_vm_assets(self.plan, self.root)
        p.chmod(0o600)
        self.root.chmod(0o755)
        with self.assertRaisesRegex(VMAssetError, "private"):
            verify_local_vm_assets(self.plan, self.root)

    def test_file_exceeding_size_cap_rejected_without_hashing(self):
        field, filename, cap = ARTIFACTS[2]
        p = self.root / filename
        with p.open("wb") as writer:
            writer.truncate(cap + 1)  # sparse file: no large disk allocation
        p.chmod(0o600)
        with self.assertRaisesRegex(VMAssetError, "size bounds"):
            verify_local_vm_assets(self.plan, self.root)

    def test_spoofed_plan_digest_or_contents_rejected(self):
        with self.assertRaises(VMAssetError):
            verify_local_vm_assets(replace(self.plan, digest_sha256="0" * 64), self.root)
        with self.assertRaises(VMAssetError):
            verify_local_vm_assets(replace(self.plan, canonical_json=b"{}"), self.root)
        with self.assertRaises(VMAssetError):
            verify_local_vm_assets(None, self.root)

    def test_failure_does_not_modify_or_remove_operator_data(self):
        before = {name: (self.root / name).read_bytes() for name in self.blobs}
        self.assertEqual(before, self.blobs)
        verify_local_vm_assets(self.plan, self.root)
        after = {name: (self.root / name).read_bytes() for name in self.blobs}
        self.assertEqual(before, after)
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)

    def test_no_execution_or_network_even_on_hash_match(self):
        from slipcage_engine import vm_assets
        with (
            patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess")),
            patch.object(subprocess, "run", side_effect=AssertionError("subprocess")),
            patch.object(socket, "socket", side_effect=AssertionError("network")),
            patch.object(vm_assets.os, "system", side_effect=AssertionError("shell")),
        ):
            result = verify_local_vm_assets(self.plan, self.root)
        self.assertFalse(result.to_dict()["vm_launched"])
        self.assertFalse(result.to_dict()["execution_authorized"])

    def _cli(self, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_cli_local_byte_check_succeeds_but_does_not_grant_permission(self):
        rc, output, stderr = self._cli([
            "verify-vm-artifacts", str(self.planpath),
            "--directory", str(self.root), "--json",
        ])
        self.assertEqual((rc, stderr), (0, ""))
        data = json.loads(output)
        self.assertTrue(data["content_sha256_matches_declared_pins"])
        self.assertFalse(data["software_origin_authenticated"])
        self.assertFalse(data["execution_authorized"])
        self.assertFalse(data["vm_launched"])

    def test_cli_rejects_synthetic_plan_without_success(self):
        rc, output, stderr = self._cli([
            "verify-vm-artifacts", str(SAMPLE),
            "--directory", str(self.root), "--json",
        ])
        self.assertEqual(rc, 2)
        self.assertEqual(output, "")
        self.assertIn("Synthetic plan assets", stderr)

    def test_cli_nonexistent_artifact_root_returns_no_success(self):
        rc, output, stderr = self._cli([
            "verify-vm-artifacts", str(self.planpath),
            "--directory", str(self.home / "missing"), "--json",
        ])
        self.assertEqual(rc, 2)
        self.assertEqual(output, "")
        self.assertIn("non-symlink directory", stderr)

    def test_existing_real_run_commands_remain_disabled(self):
        for command in ("run", "compare", "report"):
            with self.subTest(command=command):
                code, output, stderr = self._cli([command])
                self.assertEqual(code, 3)
                self.assertEqual(output, "")
                self.assertIn("unavailable", stderr)


if __name__ == "__main__":
    unittest.main()
