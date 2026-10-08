"""SC-13b2 fail-closed detached signature and reported host snapshot tests."""
from contextlib import redirect_stdout, redirect_stderr
from dataclasses import replace
import io
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from slipcage_engine.cli import main
from slipcage_engine.vm_plan import load_vm_plan, validate_vm_plan_bytes
from slipcage_engine.vm_host_readiness import (
    API_VERSION as SNAPSHOT_VERSION,
    VMHostReadinessError, validate_host_snapshot_bytes, assess_host_snapshot,
    load_host_snapshot,
)
from slipcage_engine.vm_provenance import (
    API_VERSION as PROVENANCE_VERSION,
    VMProvenanceError, verify_provenance,
)
from slipcage_engine.vm_assets import ARTIFACTS

SAMPLE = ROOT / "examples" / "vm-plans" / "k3s-synthetic-design.json"


def canon(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


class ProvenanceAndHostTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        design = load_vm_plan(SAMPLE).design
        design["provenance"]["pin_status"] = "operator_supplied_unverified"
        design["provenance"]["note"] = "Unit-test declarations; publisher identity NOT verified"
        design["software"]["guest_kernel_release"] = "6.8.0-test"
        self.plan = validate_vm_plan_bytes(canon(design))
        self.plan_path = self.root / "plan.json"
        self.plan_path.write_bytes(self.plan.canonical_json)
        self.private = Ed25519PrivateKey.generate()  # ephemeral test key only
        self.other = Ed25519PrivateKey.generate()
        self.pub = self.root / "trusted-public-key.raw"
        self.pub.write_bytes(self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        ))
        self.statement = self.root / "statement.json"
        self.signature = self.root / "statement.sig"
        self.document = {
            "api_version": PROVENANCE_VERSION,
            "release_id": "ci-test-only",
            "plan_digest_sha256": self.plan.digest_sha256,
            "artifacts": self.plan.design["artifacts"],
        }
        self.resign()

    def resign(self):
        data = canon(self.document)
        self.statement.write_bytes(data)
        self.signature.write_bytes(self.private.sign(b"SLIPCAGE_VM_PROVENANCE_V1\0" + data))

    def check(self):
        return verify_provenance(self.plan, self.statement, self.signature, self.pub)

    def snapshot(self, **kw):
        data = {
            "api_version": SNAPSHOT_VERSION,
            "source": "operator_supplied_unverified",
            "captured_at_utc": "2026-10-08T20:00:00Z",
            "plan_digest_sha256": self.plan.digest_sha256,
            "logical_cpu_threads": 8,
            "available_memory_mib": 16384,
            "free_disk_gib": 80,
            "free_inodes": 400000,
            "kvm_device_reported": True,
            "kvm_usable_reported": True,
            "cgroup_v2_reported": True,
            "provider_scope": "operator_reports_permission",
            "active_guest_count": 0,
        }
        data.update(kw)
        return data

    def cli(self, argv):
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            code = main(argv)
        return code, output.getvalue(), error.getvalue()

    def test_valid_detached_signature_is_not_publisher_authentication(self):
        result = self.check().to_dict()
        self.assertEqual(result["status"], "signature_valid_for_supplied_public_key")
        self.assertTrue(result["signature_cryptographically_valid"])
        self.assertFalse(result["key_identity_verified_out_of_band"])
        self.assertFalse(result["software_origin_independently_authenticated"])
        self.assertFalse(result["local_artifact_bytes_checked_by_this_command"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["vm_launched"])
        self.assertEqual(len(result["trusted_key_fingerprint_sha256"]), 64)
        self.assertNotIn(str(self.root), self.check().canonical_json().decode())

    def test_tampering_release_or_digest_breaks_signature(self):
        for key, value in (
            ("release_id", "malicious-test"),
            ("plan_digest_sha256", "0" * 64),
            ("artifacts", {**self.document["artifacts"], "os_image_sha256": "0"*64}),
        ):
            with self.subTest(key=key):
                self.resign()
                data = dict(self.document)
                data[key] = value
                self.statement.write_bytes(canon(data))
                with self.assertRaises(VMProvenanceError):
                    self.check()

    def test_wrong_key_or_wrong_signature_rejected(self):
        self.pub.write_bytes(self.other.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        with self.assertRaisesRegex(VMProvenanceError, "signature invalid"):
            self.check()
        self.pub.write_bytes(self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        self.signature.write_bytes(self.other.sign(b"SLIPCAGE_VM_PROVENANCE_V1\0" + self.statement.read_bytes()))
        with self.assertRaises(VMProvenanceError):
            self.check()

    def test_correct_signature_cannot_authorize_wrong_plan_or_asset(self):
        self.document["plan_digest_sha256"] = "0"*64
        self.resign()
        with self.assertRaisesRegex(VMProvenanceError, "not bound"):
            self.check()
        self.document["plan_digest_sha256"] = self.plan.digest_sha256
        self.document["artifacts"] = {**self.document["artifacts"], "kernel_sha256": "0"*64}
        self.resign()
        with self.assertRaisesRegex(VMProvenanceError, "differs"):
            self.check()

    def test_synthetic_plan_never_accepted(self):
        with self.assertRaises(VMProvenanceError):
            verify_provenance(load_vm_plan(SAMPLE), self.statement, self.signature, self.pub)
        with self.assertRaises(VMProvenanceError):
            verify_provenance(replace(self.plan, digest_sha256="0"*64),
                              self.statement, self.signature, self.pub)

    def test_statement_duplicate_noncanonical_extra_fields_refused(self):
        for raw in (
            b'{"api_version":"a","api_version":"b"}', b'[]', b'{}',
            canon(self.document) + b"\n",
            canon({**self.document, "shell_command": "/bin/bash"}),
            b'{"number":NaN}', b'\xff',
        ):
            with self.subTest(raw=raw[:30]):
                self.statement.write_bytes(raw)
                with self.assertRaises(VMProvenanceError):
                    self.check()

    def test_missing_short_or_symlinked_signature_and_key_refused(self):
        self.signature.write_bytes(b"\0" * 63)
        with self.assertRaises(VMProvenanceError):
            self.check()
        self.resign()
        self.pub.write_bytes(b"\0" * 31)
        with self.assertRaises(VMProvenanceError):
            self.check()
        self.pub.unlink()
        self.pub.symlink_to(self.root / "elsewhere")
        with self.assertRaises(VMProvenanceError):
            self.check()

    def test_host_snapshot_can_meet_reported_thresholds_without_proving_readiness(self):
        record = assess_host_snapshot(
            self.plan, validate_host_snapshot_bytes(canon(self.snapshot()))
        ).to_dict()
        self.assertEqual(record["capacity_assessment"], "reported_thresholds_met")
        self.assertIn("operator_snapshot_is_not_authenticated_or_remeasured", record["blockers"])
        self.assertFalse(record["host_readiness_independently_verified"])
        self.assertFalse(record["provider_permission_verified"])
        self.assertFalse(record["snapshot_freshness_verified"])
        self.assertFalse(record["execution_authorized"])
        self.assertFalse(record["vm_launched"])

    def test_reported_capacity_failures_and_sequential_gate(self):
        cases = [
            ("logical_cpu_threads", 2, "reported_cpu_headroom_insufficient"),
            ("available_memory_mib", 4096, "reported_available_memory_insufficient"),
            ("free_disk_gib", 4, "reported_free_disk_insufficient"),
            ("free_inodes", 5, "reported_inode_headroom_insufficient"),
            ("kvm_device_reported", False, "nested_kvm_not_reported_usable"),
            ("kvm_usable_reported", False, "nested_kvm_not_reported_usable"),
            ("cgroup_v2_reported", False, "cgroup_v2_not_reported"),
            ("provider_scope", "unknown", "provider_permission_not_reported"),
            ("active_guest_count", 1, "preexisting_guest_activity"),
        ]
        for field, value, expected in cases:
            with self.subTest(field=field):
                snapshot = validate_host_snapshot_bytes(canon(self.snapshot(**{field:value})))
                result = assess_host_snapshot(self.plan, snapshot).to_dict()
                self.assertEqual(result["capacity_assessment"], "reported_thresholds_not_met")
                self.assertIn(expected, result["blockers"])
                self.assertFalse(result["execution_authorized"])

    def test_snapshot_mismatch_unknown_fields_and_nonint_refused(self):
        invalid = [
            {"plan_digest_sha256":"0"*64},
            {"captured_at_utc":"2026-14-66T99:99:99Z"},
            {"source":"independently_verified"},
            {"logical_cpu_threads":True},
            {"free_disk_gib":"80"},
            {"host_ssh_token":"secret"},
            {"kvm_device_reported":"true"},
        ]
        for item in invalid:
            with self.subTest(item=item):
                data=self.snapshot(**item)
                if item.get("plan_digest_sha256"):
                    snap=validate_host_snapshot_bytes(canon(data))
                    with self.assertRaises(VMHostReadinessError):
                        assess_host_snapshot(self.plan,snap)
                else:
                    with self.assertRaises(VMHostReadinessError):
                        validate_host_snapshot_bytes(canon(data))
        with self.assertRaises(VMHostReadinessError):
            validate_host_snapshot_bytes(b'{"a":1,"a":2}')
        with self.assertRaises(VMHostReadinessError):
            validate_host_snapshot_bytes(b'{"a":Infinity}')

    def test_cli_commands_are_offline_and_do_not_enable_real_run(self):
        rc,out,err=self.cli([
            "verify-vm-provenance",str(self.plan_path),
            "--statement",str(self.statement),"--signature",str(self.signature),
            "--public-key",str(self.pub),"--json",
        ])
        self.assertEqual((rc,err),(0,""))
        self.assertFalse(json.loads(out)["execution_authorized"])
        snapshot_path=self.root/"host.json"
        snapshot_path.write_bytes(canon(self.snapshot()))
        rc,out,err=self.cli(["assess-vm-host",str(self.plan_path),
                             "--snapshot",str(snapshot_path),"--json"])
        self.assertEqual((rc,err),(0,""))
        self.assertEqual(json.loads(out)["capacity_assessment"],"reported_thresholds_met")
        self.assertFalse(json.loads(out)["host_readiness_independently_verified"])
        for cmd in ("run","compare","report"):
            self.assertEqual(self.cli([cmd])[0],3)

    def test_cli_missing_files_and_bad_key_emit_no_success(self):
        rc,out,err=self.cli([
            "verify-vm-provenance",str(self.plan_path),
            "--statement",str(self.statement),"--signature","/missing.sig",
            "--public-key",str(self.pub),"--json",
        ])
        self.assertEqual(rc,2)
        self.assertEqual(out,"")
        self.assertIn("verify-vm-provenance",err)


if __name__=="__main__":
    unittest.main()
