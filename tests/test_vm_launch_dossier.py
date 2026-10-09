"""SC-13b12: file-backed offline launch-gate coherence, NEVER launch readiness.

Fixtures include a fake QCOW2 *header only*, test-only signing keys,
unverified operator-style host data, and private developer staging records.
"""
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from slipcage_engine.cli import main
from slipcage_engine.vm_assets import ARTIFACTS, verify_local_vm_assets
from slipcage_engine.vm_plan import load_vm_plan, validate_vm_plan_bytes
from slipcage_engine.vm_provenance import API_VERSION as PROVENANCE_API
from slipcage_engine.vm_key_policy import API_VERSION as KEY_POLICY_API
from slipcage_engine.vm_artifact_sources import API_VERSION as SOURCES_API, RECEIPT_API as RECEIPT_VERSION
from slipcage_engine.vm_host_readiness import API_VERSION as SNAPSHOT_API
from slipcage_engine.vm_reservation import (
    stage_local_reservation, quarantine_local_reservation, QuarantineReason,
)
from slipcage_engine.vm_offline_fencing import (
    issue_offline_generation, resolve_offline_generation, OfflineResolution,
)
from slipcage_engine.vm_launch_dossier import (
    API_VERSION, LaunchDossierError, review_vm_launch_prerequisites,
)

SAMPLE = ROOT / "examples" / "vm-plans" / "k3s-synthetic-design.json"
CLUSTER = 65536


def canon(data):
    return json.dumps(data, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


def header_shape():
    """Three clusters with a valid-looking header, but NO valid metadata graph."""
    header = bytearray(112)
    header[:4] = b"QFI\xfb"
    struct.pack_into(">I", header, 4, 3)
    struct.pack_into(">I", header, 20, 16)
    struct.pack_into(">Q", header, 24, 24 * 1024**3)
    struct.pack_into(">I", header, 36, 1)
    struct.pack_into(">Q", header, 40, CLUSTER)
    struct.pack_into(">Q", header, 48, 2 * CLUSTER)
    struct.pack_into(">I", header, 56, 1)
    struct.pack_into(">I", header, 96, 4)
    struct.pack_into(">I", header, 100, 104)
    return bytes(header) + bytes(3 * CLUSTER - 112)


class LaunchPrerequisiteDossierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.assets = self.root / "assets"
        self.reservation_root = self.root / "reservation"
        self.journal_root = self.root / "journal"
        for directory in (self.assets, self.reservation_root, self.journal_root):
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
        data = load_vm_plan(SAMPLE).design
        data["provenance"]["pin_status"] = "operator_supplied_unverified"
        data["provenance"]["note"] = "CI ONLY; no trusted publisher or real QCOW2 guest"
        data["software"]["guest_kernel_release"] = "6.8.0-test"
        for i, (field, name, _) in enumerate(ARTIFACTS):
            raw = header_shape() if name == "os-image.qcow2" else (
                f"test-only-artifact-{i}-{field}".encode() * 2
            )
            f = self.assets / name
            f.write_bytes(raw)
            f.chmod(0o600)
            data["artifacts"][field] = hashlib.sha256(raw).hexdigest()
        self.plan = validate_vm_plan_bytes(canon(data))
        self.planfile = self.root / "plan.json"
        self.planfile.write_bytes(self.plan.canonical_json)
        self.preflight = verify_local_vm_assets(self.plan, self.assets)
        self.reservation = stage_local_reservation(
            self.plan, self.preflight, self.reservation_root, "baseline")
        self.generation = issue_offline_generation(
            self.journal_root, self.plan, "baseline", 0)
        key = Ed25519PrivateKey.generate()
        self.pubkey = self.root / "public-key.raw"
        self.pubkey.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        self.statement = self.root / "statement.json"
        self.signature = self.root / "statement.sig"
        statement = canon({
            "api_version": PROVENANCE_API, "release_id": "ci-test-not-trusted",
            "plan_digest_sha256": self.plan.digest_sha256,
            "artifacts": self.plan.design["artifacts"],
        })
        self.statement.write_bytes(statement)
        self.signature.write_bytes(key.sign(b"SLIPCAGE_VM_PROVENANCE_V1\0" + statement))
        self.hostfile = self.root / "host.json"
        self.host = {
            "api_version": SNAPSHOT_API,
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
        self.write_host()
        self.neighbor = self.root / "existing-backup.db"
        self.neighbor.write_bytes(b"DO NOT CHANGE")

    def write_host(self):
        self.hostfile.write_bytes(canon(self.host))

    def args(self):
        return [
            "review-vm-launch-gates", str(self.planfile),
            "--assets-dir", str(self.assets),
            "--statement", str(self.statement),
            "--signature", str(self.signature),
            "--public-key", str(self.pubkey),
            "--host-snapshot", str(self.hostfile),
            "--reservation-root", str(self.reservation_root),
            "--journal-root", str(self.journal_root), "--json",
        ]

    def review(self, **overrides):
        source = {
            "plan_file": self.planfile,
            "asset_dir": self.assets,
            "statement_file": self.statement,
            "signature_file": self.signature,
            "public_key_file": self.pubkey,
            "snapshot_file": self.hostfile,
            "reservation_root": self.reservation_root,
            "journal_root": self.journal_root,
        }
        source.update(overrides)
        return review_vm_launch_prerequisites(**source)

    def cli(self, args=None):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = main(self.args() if args is None else args)
        return status, out.getvalue(), err.getvalue()

    def policy_file(self):
        policy_path = self.root / "operator-key-policy.json"
        policy_path.write_bytes(canon({
            "api_version": KEY_POLICY_API,
            "policy_origin": "operator_supplied_unverified",
            "source_label": "ci-test-not-publisher-authentication",
            "release_id": "ci-test-not-trusted",
            "plan_digest_sha256": self.plan.digest_sha256,
            "statement_sha256": hashlib.sha256(self.statement.read_bytes()).hexdigest(),
            "allowed_key_sha256": hashlib.sha256(self.pubkey.read_bytes()).hexdigest(),
            "revoked_key_sha256": [],
        }))
        policy_path.chmod(0o600)
        return policy_path

    def test_dossier_without_optional_policy_marks_pin_unchecked(self):
        report = self.review().to_dict()
        self.assertIsNone(report["operator_key_policy_sha256"])
        self.assertFalse(report["operator_key_pin_consistency_checked"])
        self.assertFalse(report["policy_identity_authenticated_out_of_band"])
        self.assertFalse(report["execution_authorized"])

    def test_dossier_with_matched_policy_remains_blocked(self):
        policy = self.policy_file()
        report = self.review(key_policy_file=policy).to_dict()
        self.assertTrue(report["operator_key_pin_consistency_checked"])
        self.assertEqual(report["operator_key_policy_sha256"],
                         hashlib.sha256(policy.read_bytes()).hexdigest())
        self.assertFalse(report["policy_identity_authenticated_out_of_band"])
        self.assertFalse(report["source_publisher_authenticated"])
        self.assertIn("publisher_key_identity_not_authenticated_out_of_band",
                      report["blockers"])
        args = self.args()
        args.insert(-1, str(policy))
        args.insert(-2, "--key-policy")
        code, output, error = self.cli(args)
        self.assertEqual((code, error), (5, ""))
        self.assertTrue(json.loads(output)["operator_key_pin_consistency_checked"])

    def test_dossier_mismatched_key_policy_rejected_not_promoted_to_blocked(self):
        policy = self.policy_file()
        doc = json.loads(policy.read_bytes())
        doc["allowed_key_sha256"] = "f"*64
        policy.write_bytes(canon(doc))
        with self.assertRaises(Exception):
            self.review(key_policy_file=policy)
        args = self.args()
        args[-1:-1] = ["--key-policy", str(policy)]
        code, output, error = self.cli(args)
        self.assertEqual((code, output), (2, ""))
        self.assertTrue(error)

    def test_dossier_revoked_key_policy_refused(self):
        policy = self.policy_file()
        doc = json.loads(policy.read_bytes())
        doc["revoked_key_sha256"] = [doc["allowed_key_sha256"]]
        policy.write_bytes(canon(doc))
        with self.assertRaises(Exception):
            self.review(key_policy_file=policy)
        self.assertFalse(self.review().to_dict()["execution_authorized"])

    def k3s_manifests(self):
        binary = self.root / "upstream-style-sha256sum-amd64.txt"
        airgap = self.root / "upstream-style-airgap-amd64.sha256sum"
        binary.write_bytes((
            self.plan.design["artifacts"]["k3s_binary_sha256"] + "  k3s" + chr(10)
        ).encode("ascii"))
        airgap.write_bytes((
            self.plan.design["artifacts"]["container_images_sha256"]
            + "  k3s-airgap-images-amd64.tar" + chr(10)
        ).encode("ascii"))
        binary.chmod(0o600)
        airgap.chmod(0o600)
        return binary, airgap

    def test_optional_k3s_release_checksum_sources_still_cannot_authorize_launch(self):
        bin_manifest, tar_manifest = self.k3s_manifests()
        # Strict positional binding and full local five-asset byte verification
        # happens again in the optional standalone vendor-style checksum step.
        report = self.review(
            k3s_binary_checksums=bin_manifest,
            k3s_airgap_checksums=tar_manifest,
        ).to_dict()
        self.assertTrue(report["k3s_release_checksums_checked"])
        self.assertEqual(report["status"], "blocked_no_execution_permission")
        self.assertFalse(report["k3s_release_checksum_source_authenticated"])
        self.assertFalse(report["execution_authorized"])
        self.assertEqual(report["k3s_binary_checksum_manifest_sha256"],
                         hashlib.sha256(bin_manifest.read_bytes()).hexdigest())
        args = self.args()
        args[-1:-1] = [
            "--k3s-binary-checksums", str(bin_manifest),
            "--k3s-airgap-checksums", str(tar_manifest),
        ]
        code, stdout, stderr = self.cli(args)
        self.assertEqual((code, stderr), (5, ""))
        self.assertFalse(json.loads(stdout)["execution_authorized"])

    def test_optional_k3s_checksums_require_both_manifest_paths(self):
        binary, _ = self.k3s_manifests()
        with self.assertRaises(LaunchDossierError):
            self.review(k3s_binary_checksums=binary)
        args = self.args()
        args[-1:-1] = ["--k3s-binary-checksums", str(binary)]
        code, output, stderr = self.cli(args)
        self.assertEqual((code, output), (2, ""))
        self.assertTrue(stderr)

    def test_optional_k3s_manifest_tamper_fails_no_dossier(self):
        binary, airgap = self.k3s_manifests()
        binary.write_bytes(("f"*64 + "  k3s" + chr(10)).encode("ascii"))
        code, output, error = self.cli(
            self.args()[:-1] + [
                "--k3s-binary-checksums", str(binary),
                "--k3s-airgap-checksums", str(airgap),
                "--json",
            ]
        )
        self.assertEqual((code, output), (2, ""))
        self.assertTrue(error)

    def artifact_sources(self):
        from urllib.parse import quote
        root = self.root / "five-source-receipts"
        root.mkdir(mode=0o700)
        root.chmod(0o700)
        ledger = self.root / "operator-source-ledger.json"
        tag = self.plan.design["software"]["k3s_version"]
        prefix = ("https://github.com/k3s-io/k3s/releases/download/"
                  + quote(tag, safe="") + "/")
        names = (
            "os-image.source.json", "kernel.source.json", "k3s.source.json",
            "cni.source.json", "container-images.source.json",
        )
        sources = (
            "https://example.org/test-os-image", "https://example.org/test-kernel",
            prefix + "k3s", "https://example.org/test-cni",
            prefix + "k3s-airgap-images-amd64.tar",
        )
        entries = []
        for idx, (field, _, _) in enumerate(ARTIFACTS):
            ver = tag if idx in (2, 4) else "ci-test-v1"
            receipt = {
                "api_version": RECEIPT_VERSION,
                "digest_field": field,
                "artifact_sha256": self.plan.design["artifacts"][field],
                "source_uri": sources[idx],
                "version_ref": ver,
                "observation": "operator_supplied_unverified",
            }
            receipt_bytes = canon(receipt)
            evidence = root / names[idx]
            evidence.write_bytes(receipt_bytes)
            evidence.chmod(0o600)
            entries.append({
                "digest_field": field,
                "artifact_sha256": receipt["artifact_sha256"],
                "source_uri": sources[idx], "version_ref": ver,
                "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
            })
        ledger.write_bytes(canon({
            "api_version": SOURCES_API, "kind": "VMArtifactSourceLedger",
            "plan_digest_sha256": self.plan.digest_sha256,
            "operator_assertion": "source_reference_recorded_unverified",
            "artifacts": entries,
        }))
        ledger.chmod(0o600)
        return ledger, root

    def test_source_receipts_integrate_with_dossier_but_always_block(self):
        ledger, receipts = self.artifact_sources()
        result = self.review(
            artifact_source_ledger=ledger, artifact_source_receipts=receipts,
        ).to_dict()
        self.assertTrue(result["artifact_source_receipts_checked"])
        self.assertFalse(result["artifact_source_origin_authenticated"])
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(result["artifact_source_ledger_sha256"],
                         hashlib.sha256(ledger.read_bytes()).hexdigest())
        args = self.args()
        args[-1:-1] = [
            "--artifact-source-ledger", str(ledger),
            "--artifact-source-receipts", str(receipts),
        ]
        status, out, error = self.cli(args)
        self.assertEqual((status, error), (5, ""))
        self.assertEqual(json.loads(out)["status"], "blocked_no_execution_permission")

    def test_source_receipts_require_both_inputs(self):
        ledger, _ = self.artifact_sources()
        with self.assertRaises(LaunchDossierError):
            self.review(artifact_source_ledger=ledger)
        args = self.args()
        args[-1:-1] = ["--artifact-source-ledger", str(ledger)]
        status, out, err = self.cli(args)
        self.assertEqual((status, out), (2, ""))
        self.assertTrue(err)

    def test_tampered_source_receipt_cannot_produce_dossier(self):
        ledger, receipts = self.artifact_sources()
        changed = receipts / "kernel.source.json"
        changed.write_bytes(b"unverified tamper")
        with self.assertRaises(Exception):
            self.review(artifact_source_ledger=ledger, artifact_source_receipts=receipts)
        args = self.args()
        args[-1:-1] = [
            "--artifact-source-ledger", str(ledger),
            "--artifact-source-receipts", str(receipts),
        ]
        status, output, error = self.cli(args)
        self.assertEqual((status, output), (2, ""))
        self.assertTrue(error)

    def test_absent_optional_source_receipts_do_not_imply_authentication(self):
        result = self.review().to_dict()
        self.assertFalse(result["artifact_source_receipts_checked"])
        self.assertIsNone(result["artifact_source_ledger_sha256"])
        self.assertFalse(result["artifact_source_origin_authenticated"])

    def qcow2_external_fixture(self):
        root = self.root / "operator-qemu-json"
        root.mkdir(mode=0o700)
        root.chmod(0o700)
        size = (self.assets / "os-image.qcow2").stat().st_size
        data_info = {
            "filename": "os-image.qcow2", "format": "qcow2",
            "virtual-size": self.plan.design["guest"]["disk_gib"] * 1024**3,
            "actual-size": size, "cluster-size": CLUSTER,
            "encrypted": False, "dirty-flag": False,
            "compressed": False, "snapshots": [],
        }
        data_check = {
            "filename": "os-image.qcow2", "format": "qcow2",
            "check-errors": 0, "corruptions": 0, "leaks": 0,
        }
        info_bytes, check_bytes = canon(data_info), canon(data_check)
        capture = {
            "api_version": "slipcage.dev/qcow2-external-evidence/v1alpha1",
            "capture_kind": "declared_qemu_img_read_only_info_check",
            "capture_origin": "operator_supplied_unverified",
            "plan_digest_sha256": self.plan.digest_sha256,
            "base_sha256": self.plan.design["artifacts"]["os_image_sha256"],
            "base_size_bytes": size,
            "qemu_img_version": self.plan.design["runtime"]["qemu_version"],
            "qemu_img_binary_sha256": hashlib.sha256(b"FAKE qemu-img in CI").hexdigest(),
            "info_command": [
                "qemu-img", "info", "--output=json", "-f", "qcow2", "os-image.qcow2",
            ],
            "check_command": [
                "qemu-img", "check", "--output=json", "-f", "qcow2", "os-image.qcow2",
            ],
            "info_exit_code": 0, "check_exit_code": 0,
            "info_output_sha256": hashlib.sha256(info_bytes).hexdigest(),
            "check_output_sha256": hashlib.sha256(check_bytes).hexdigest(),
        }
        for name, data in (
            ("capture.json", canon(capture)),
            ("info.json", info_bytes),
            ("check.json", check_bytes),
        ):
            f = root / name
            f.write_bytes(data)
            f.chmod(0o600)
        return root

    def test_optional_fake_qemu_reports_keep_dossier_always_blocked(self):
        evidence = self.qcow2_external_fixture()
        report = self.review(qcow2_evidence_dir=evidence).to_dict()
        self.assertTrue(report["qcow2_external_reports_locally_checked"])
        self.assertFalse(report["qcow2_external_check_execution_attested"])
        self.assertFalse(report["full_guest_image_structure_verified"])
        self.assertFalse(report["execution_authorized"])
        self.assertEqual(report["status"], "blocked_no_execution_permission")
        args = self.args()
        args[-1:-1] = ["--qcow2-evidence-dir", str(evidence)]
        status, out, err = self.cli(args)
        self.assertEqual((status, err), (5, ""))
        self.assertFalse(json.loads(out)["execution_authorized"])

    def test_optional_qemu_check_repair_claim_fails_no_dossier(self):
        evidence = self.qcow2_external_fixture()
        f = evidence / "check.json"
        report = json.loads(f.read_bytes())
        report["corruptions-fixed"] = 2
        raw = canon(report)
        f.write_bytes(raw)
        with self.assertRaises(Exception):
            self.review(qcow2_evidence_dir=evidence)
        args = self.args()
        args[-1:-1] = ["--qcow2-evidence-dir", str(evidence)]
        status, out, error = self.cli(args)
        self.assertEqual((status, out), (2, ""))
        self.assertTrue(error)

    def test_optional_fake_qemu_report_wrong_plan_fails_closed(self):
        evidence = self.qcow2_external_fixture()
        manifest = evidence / "capture.json"
        data = json.loads(manifest.read_bytes())
        data["plan_digest_sha256"] = "f" * 64
        manifest.write_bytes(canon(data))
        with self.assertRaises(Exception):
            self.review(qcow2_evidence_dir=evidence)

    def test_absent_optional_qemu_report_never_implies_verification(self):
        report = self.review().to_dict()
        self.assertFalse(report["qcow2_external_reports_locally_checked"])
        self.assertIsNone(report["qcow2_external_report_capture_sha256"])
        self.assertFalse(report["qcow2_external_check_execution_attested"])

    def test_all_valid_local_checks_still_block_launch(self):
        report = self.review().to_dict()
        self.assertEqual(report["api_version"], API_VERSION)
        self.assertEqual(report["status"], "blocked_no_execution_permission")
        self.assertTrue(report["consistency_checks_completed"])
        self.assertEqual(report["plan_digest_sha256"], self.plan.digest_sha256)
        self.assertEqual(report["reported_capacity_assessment"], "reported_thresholds_met")
        self.assertEqual(report["offline_intent_attempt_id"], "baseline")
        self.assertEqual(report["offline_intent_generation"], 1)
        self.assertEqual(report["offline_intent_issue_sha256"], self.generation.active_record_sha256)
        self.assertEqual(report["reservation_digest_sha256"], self.reservation.record_digest_sha256)
        self.assertEqual(report["base_qcow2_sha256"], self.plan.design["artifacts"]["os_image_sha256"])
        self.assertEqual(report["base_qcow2_file_size_bytes"], 3 * CLUSTER)
        self.assertEqual(len(report["blockers"]), 10)

    def test_verified_local_key_signature_not_authenticated_publisher(self):
        report = self.review().to_dict()
        self.assertEqual(len(report["signed_statement_sha256"]), 64)
        self.assertEqual(len(report["supplied_key_fingerprint_sha256"]), 64)
        self.assertIn("publisher_key_identity_not_authenticated_out_of_band", report["blockers"])
        self.assertIn("software_and_guest_contents_not_independently_authenticated", report["blockers"])
        self.assertFalse(report["source_publisher_authenticated"])
        self.assertFalse(report["public_key_identity_authenticated"])

    def test_every_runtime_or_permission_claim_must_be_false(self):
        output = self.review().to_dict()
        for key in (
            "real_host_telemetry_authenticated", "host_snapshot_freshness_verified",
            "usable_kvm_proven_on_target", "provider_permission_independently_verified",
            "full_guest_image_structure_verified", "immutable_backing_chain_verified",
            "host_global_execution_lease_held", "runtime_cgroup_disk_watchdog_enforced",
            "real_guest_process_fenced", "overlay_created", "vm_launched",
            "cleanup_verified_on_host", "owner_live_execution_approved",
            "execution_authorized", "host_modified",
        ):
            with self.subTest(key=key):
                self.assertIs(output[key], False)

    def test_cli_exit_5_even_when_all_local_checks_match(self):
        code, stdout, stderr = self.cli()
        self.assertEqual((code, stderr), (5, ""))
        self.assertEqual(json.loads(stdout), self.review().to_dict())
        self.assertIn("owner_approved_live_vm_test_not_provided",
                      json.loads(stdout)["blockers"])

    def test_deterministic_path_free_json(self):
        first = self.review().canonical_json()
        second = self.review().canonical_json()
        self.assertEqual(first, second)
        self.assertEqual(json.loads(first), self.review().to_dict())
        self.assertNotIn(str(self.root), first.decode())
        self.assertNotIn("ssh_key", first.decode())

    def test_reported_shortage_remains_blocked_and_explicit(self):
        self.host["available_memory_mib"] = 1024
        self.write_host()
        report = self.review().to_dict()
        self.assertEqual(report["reported_capacity_assessment"], "reported_thresholds_not_met")
        self.assertIn("operator_reported_host_thresholds_not_met", report["blockers"])
        self.assertIn("reported_available_memory_insufficient", report["reported_host_blockers"])
        self.assertFalse(report["execution_authorized"])
        self.assertEqual(self.cli()[0], 5)

    def test_unverified_provider_or_kvm_declared_false_is_not_ignored(self):
        self.host["provider_scope"] = "unknown"
        self.host["kvm_usable_reported"] = False
        self.write_host()
        out = self.review().to_dict()
        self.assertIn("provider_permission_not_reported", out["reported_host_blockers"])
        self.assertIn("nested_kvm_not_reported_usable", out["reported_host_blockers"])
        self.assertEqual(self.cli()[0], 5)

    def test_host_snapshot_for_wrong_plan_rejected(self):
        self.host["plan_digest_sha256"] = "f"*64
        self.write_host()
        code, stdout, stderr = self.cli()
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("not bind", stderr)

    def test_local_asset_content_tampering_fails_before_dossier(self):
        file = self.assets / "kernel.bin"
        file.write_bytes(b"MODIFIED")
        code, stdout, stderr = self.cli()
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("SHA-256", stderr)

    def test_wrong_signer_key_fails_before_dossier(self):
        key = Ed25519PrivateKey.generate()
        self.pubkey.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        code, stdout, stderr = self.cli()
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("signature invalid", stderr)

    def test_tampered_statement_fails_before_dossier(self):
        self.statement.write_bytes(b"{}")
        code, stdout, stderr = self.cli()
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("provenance", stderr.lower())

    def test_synthetic_plan_never_passes_prerequisite_dossier(self):
        _, stdout, stderr = self.cli([*self.args()[:1], str(SAMPLE), *self.args()[2:]])
        self.assertEqual(stdout, "")
        self.assertTrue(stderr)

    def test_quarantined_reservation_never_passes(self):
        quarantine_local_reservation(
            self.reservation_root, attempt_id="baseline",
            expected_intent_sha256=self.reservation.record_digest_sha256,
            reason=QuarantineReason.OPERATOR_REVIEW_REQUIRED,
        )
        code, stdout, stderr = self.cli()
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertTrue(stderr)

    def test_unknown_overlay_remnant_never_passes(self):
        target = self.reservation_root / "vm-reservation-v1" / "overlay.qcow2"
        target.write_bytes(b"UNKNOWN; NEVER DELETE")
        code, stdout, stderr = self.cli()
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertEqual(target.read_bytes(), b"UNKNOWN; NEVER DELETE")
        self.assertTrue(stderr)

    def test_unresolved_or_quarantined_offline_journal_never_passes(self):
        resolve_offline_generation(
            self.journal_root, "baseline", 1, self.generation.active_record_sha256,
            OfflineResolution.QUARANTINED,
        )
        code, stdout, stderr = self.cli()
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("mismatched", stderr.lower())

    def test_mismatched_reservation_and_journal_attempts_rejected(self):
        other = self.root / "alternative-reservation"
        other.mkdir(mode=0o700)
        other.chmod(0o700)
        stage_local_reservation(self.plan, self.preflight, other, "candidate")
        with self.assertRaisesRegex(LaunchDossierError, "mismatched"):
            self.review(reservation_root=other)
        self.assertEqual(self.neighbor.read_bytes(), b"DO NOT CHANGE")

    def test_same_root_for_reservation_and_journal_rejected(self):
        with self.assertRaisesRegex(LaunchDossierError, "separate private roots"):
            self.review(journal_root=self.reservation_root)

    def test_old_or_forged_offline_attempt_generation_not_usable(self):
        resolve_offline_generation(
            self.journal_root, "baseline", 1, self.generation.active_record_sha256,
            OfflineResolution.ABANDONED,
        )
        code, stdout, stderr = self.cli()
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertTrue(stderr)

    def test_base_qcow2_hash_or_header_mismatch_rejected(self):
        base = self.assets / "os-image.qcow2"
        raw = bytearray(base.read_bytes())
        raw[8] = 1  # embedded backing reference (and now wrong pinned hash)
        base.write_bytes(bytes(raw))
        self.assertEqual(self.cli()[0], 2)

    def test_no_process_network_filesystem_mutation_on_review(self):
        records_before = {
            "reservation": sorted(x.name for x in (self.reservation_root / "vm-reservation-v1").iterdir()),
            "journal": sorted(x.name for x in self.journal_root.iterdir()),
            "root": self.neighbor.read_bytes(),
        }
        with (
            patch.object(subprocess, "Popen", side_effect=AssertionError("QEMU subprocess")),
            patch.object(subprocess, "run", side_effect=AssertionError("subprocess")),
            patch.object(socket, "socket", side_effect=AssertionError("network")),
            patch.object(os, "system", side_effect=AssertionError("shell")),
        ):
            self.assertFalse(self.review().to_dict()["execution_authorized"])
        self.assertEqual(records_before["reservation"],
                         sorted(x.name for x in (self.reservation_root / "vm-reservation-v1").iterdir()))
        self.assertEqual(records_before["journal"], sorted(x.name for x in self.journal_root.iterdir()))
        self.assertEqual(records_before["root"], self.neighbor.read_bytes())

    def test_real_run_compare_report_still_refuse(self):
        for cmd in ("run", "compare", "report"):
            status, stdout, stderr = self.cli([cmd])
            self.assertEqual((status, stdout), (3, ""))
            self.assertIn("unavailable", stderr)


if __name__ == "__main__":
    unittest.main()
