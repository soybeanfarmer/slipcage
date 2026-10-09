"""SC-13b15: read-only local custody/source receipts, not publisher trust."""
from contextlib import redirect_stdout, redirect_stderr
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
from urllib.parse import quote
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from slipcage_engine.cli import main
from slipcage_engine.vm_assets import ARTIFACTS
from slipcage_engine.vm_plan import load_vm_plan, validate_vm_plan_bytes
from slipcage_engine.vm_artifact_sources import (
    API_VERSION, RECEIPT_API, ArtifactSourceError, review_artifact_source_ledger,
)

SAMPLE = ROOT / "examples" / "vm-plans" / "k3s-synthetic-design.json"
RECEIPT_NAMES = (
    "os-image.source.json", "kernel.source.json", "k3s.source.json",
    "cni.source.json", "container-images.source.json",
)


def canon(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("ascii")


class ArtifactCustodyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.assets = self.home / "assets"
        self.receipts = self.home / "receipts"
        for d in (self.assets, self.receipts):
            d.mkdir(mode=0o700)
            d.chmod(0o700)
        draft = load_vm_plan(SAMPLE).design
        draft["provenance"]["pin_status"] = "operator_supplied_unverified"
        draft["provenance"]["note"] = "CI invented bytes; sources NOT authenticated"
        draft["software"]["guest_kernel_release"] = "6.8.0-test"
        self.asset_data = {}
        for i, (field, filename, _) in enumerate(ARTIFACTS):
            data = f"fake-artifact-source-{field}-{i}".encode()
            self.asset_data[field] = data
            file = self.assets / filename
            file.write_bytes(data)
            file.chmod(0o600)
            draft["artifacts"][field] = hashlib.sha256(data).hexdigest()
        self.plan = validate_vm_plan_bytes(canon(draft))
        self.planfile = self.home / "plan.json"
        self.planfile.write_bytes(self.plan.canonical_json)
        self.ledger = self.home / "ledger.json"
        tag = quote(self.plan.design["software"]["k3s_version"], safe="")
        base = "https://github.com/k3s-io/k3s/releases/download/" + tag + "/"
        self.sources = [
            "https://example.org/releases/os-image.qcow2",
            "https://example.org/releases/kernel.bin",
            base + "k3s",
            "https://example.org/releases/cni-assets.tar",
            base + "k3s-airgap-images-amd64.tar",
        ]
        self.packet = {
            "api_version": API_VERSION,
            "kind": "VMArtifactSourceLedger",
            "plan_digest_sha256": self.plan.digest_sha256,
            "operator_assertion": "source_reference_recorded_unverified",
            "artifacts": [],
        }
        self.rebuild()
        self.neighbor = self.home / "backups.sqlite"
        self.neighbor.write_bytes(b"PRESERVE BACKUPS")

    def rebuild(self):
        self.packet["artifacts"] = []
        for index, (field, _name, _) in enumerate(ARTIFACTS):
            uri = self.sources[index]
            version = (self.plan.design["software"]["k3s_version"]
                       if index in (2, 4) else "operator-review-v1")
            receipt = {
                "api_version": RECEIPT_API,
                "digest_field": field,
                "artifact_sha256": self.plan.design["artifacts"][field],
                "source_uri": uri,
                "version_ref": version,
                "observation": "operator_supplied_unverified",
            }
            raw = canon(receipt)
            file = self.receipts / RECEIPT_NAMES[index]
            file.write_bytes(raw)
            file.chmod(0o600)
            self.packet["artifacts"].append({
                "digest_field": field,
                "artifact_sha256": self.plan.design["artifacts"][field],
                "source_uri": uri,
                "version_ref": version,
                "receipt_sha256": hashlib.sha256(raw).hexdigest(),
            })
        self.write_packet()

    def write_packet(self):
        self.ledger.write_bytes(canon(self.packet))
        self.ledger.chmod(0o600)

    def review(self):
        return review_artifact_source_ledger(
            self.plan, self.assets, self.ledger, self.receipts,
        )

    def cli(self, argv=None):
        args = argv if argv is not None else [
            "review-vm-artifact-sources", str(self.planfile),
            "--assets-dir", str(self.assets),
            "--ledger", str(self.ledger),
            "--receipts-dir", str(self.receipts), "--json",
        ]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = main(args)
        return status, out.getvalue(), err.getvalue()

    def test_matching_five_receipts_remain_operator_unverified(self):
        result = self.review().to_dict()
        self.assertEqual(result["api_version"], API_VERSION)
        self.assertEqual(result["artifact_count"], 5)
        self.assertEqual(result["plan_digest_sha256"], self.plan.digest_sha256)
        self.assertTrue(result["all_five_local_asset_bytes_match_plan"])
        self.assertTrue(result["ledger_and_receipt_metadata_match"])
        self.assertEqual(result["status"], "operator_source_authentication_pending")
        self.assertEqual(len(result["receipt_sha256_by_fixed_asset_order"]), 5)

    def test_all_trust_and_runtime_flags_remain_false(self):
        result = self.review().to_dict()
        for flag in (
            "publisher_origin_authenticated", "receipt_authenticity_independently_verified",
            "release_version_resolved_from_upstream", "operator_identity_authenticated",
            "source_url_retrieved_or_validated_online",
            "artifact_contents_or_build_reproducibility_verified",
            "guest_image_and_cni_provenance_authenticated",
            "provider_permission_verified", "kvm_ready_verified",
            "execution_authorized", "vm_launched", "host_modified",
        ):
            with self.subTest(flag=flag):
                self.assertIs(result[flag], False)

    def test_positive_cli_exit_5_still_requires_human_publisher_review(self):
        status, output, error = self.cli()
        self.assertEqual((status, error), (5, ""))
        self.assertEqual(json.loads(output), self.review().to_dict())
        self.assertFalse(json.loads(output)["execution_authorized"])

    def test_wrong_or_reordered_asset_slots_rejected(self):
        for new in (
            list(reversed(self.packet["artifacts"])),
            self.packet["artifacts"][:-1],
            self.packet["artifacts"][:4] + [self.packet["artifacts"][0]],
        ):
            saved = self.packet["artifacts"]
            self.packet["artifacts"] = new
            self.write_packet()
            with self.assertRaises(ArtifactSourceError):
                self.review()
            self.packet["artifacts"] = saved
        self.write_packet()

    def test_wrong_receipt_digest_and_entry_sha_rejected(self):
        for key in ("receipt_sha256", "artifact_sha256"):
            old = self.packet["artifacts"][1][key]
            self.packet["artifacts"][1][key] = "f" * 64
            self.write_packet()
            with self.assertRaises(ArtifactSourceError):
                self.review()
            self.packet["artifacts"][1][key] = old
        self.write_packet()

    def test_changed_receipt_content_even_valid_json_rejected(self):
        file = self.receipts / RECEIPT_NAMES[1]
        doc = json.loads(file.read_bytes())
        doc["version_ref"] = "operator-forged-v2"
        file.write_bytes(canon(doc))
        with self.assertRaisesRegex(ArtifactSourceError, "Receipt mismatch"):
            self.review()

    def test_wrong_k3s_release_url_version_filename_and_architecture(self):
        for uri in (
            "https://github.com/k3s-io/k3s/releases/download/v9.9.9%2Bk3s1/k3s",
            "https://github.com/k3s-io/k3s/releases/download/v1.30.1%2Bk3s1/k3s-arm64",
            "https://mirror.example.org/k3s",
            "https://github.com/k3s-io/k3s/releases/download/v1.30.1+k3s1/k3s",
        ):
            with self.subTest(uri=uri):
                self.sources[2] = uri
                self.rebuild()
                with self.assertRaises(ArtifactSourceError):
                    self.review()
        self.sources[2] = self.sources[4].rsplit("/", 1)[0] + "/k3s"
        self.rebuild()

    def test_wrong_k3s_airgap_tar_url_rejected(self):
        self.sources[4] = self.sources[4].replace(".tar", ".tar.zst")
        self.rebuild()
        with self.assertRaises(ArtifactSourceError):
            self.review()

    def test_non_https_private_dns_credentials_query_or_fragment_rejected(self):
        for value in (
            "http://example.org/releases/base",
            "https://localhost/private",
            "https://127.0.0.1/private",
            "https://operator:secret@example.org/bytes",
            "https://example.org:443/release",
            "https://example.org/release?token=abc",
            "https://example.org/release#ref",
            "https://example.org/release with space",
            "file:///etc/passwd",
        ):
            with self.subTest(value=value):
                self.sources[0] = value
                self.rebuild()
                with self.assertRaises(ArtifactSourceError):
                    self.review()

    def test_source_version_type_and_k3s_tag_binding_refused(self):
        for value in ("v1.99.0+k3s1", "../bad", True, 2, ""):
            with self.subTest(value=value):
                current = self.packet["artifacts"][2]["version_ref"]
                self.packet["artifacts"][2]["version_ref"] = value
                self.write_packet()
                with self.assertRaises(ArtifactSourceError):
                    self.review()
                self.packet["artifacts"][2]["version_ref"] = current
        self.write_packet()

    def test_untrusted_source_status_must_never_be_trusted(self):
        self.packet["operator_assertion"] = "verified_by_publisher"
        self.write_packet()
        with self.assertRaises(ArtifactSourceError):
            self.review()
        self.packet["operator_assertion"] = "source_reference_recorded_unverified"
        self.write_packet()
        file = self.receipts / RECEIPT_NAMES[0]
        doc = json.loads(file.read_bytes())
        doc["observation"] = "authenticated"
        raw = canon(doc)
        file.write_bytes(raw)
        self.packet["artifacts"][0]["receipt_sha256"] = hashlib.sha256(raw).hexdigest()
        self.write_packet()
        with self.assertRaises(ArtifactSourceError):
            self.review()

    def test_ledger_duplicate_keys_extra_fields_and_noncanonical_refused(self):
        good = self.ledger.read_bytes()
        for raw in (
            good + b"\n", b"{}", b"[]",
            b'{"api_version":"x","api_version":"y"}',
            canon({**self.packet, "execution_authorized": True}),
            b"\xff", b"x" * 17000,
        ):
            self.ledger.write_bytes(raw)
            with self.assertRaises(ArtifactSourceError):
                self.review()
        self.ledger.write_bytes(good)

    def test_evidence_dir_unknown_entries_missing_file_nonprivate_refused(self):
        unknown = self.receipts / "unknown"
        unknown.write_bytes(b"KEEP")
        with self.assertRaises(ArtifactSourceError):
            self.review()
        unknown.unlink()
        missing = self.receipts / RECEIPT_NAMES[0]
        missing.unlink()
        with self.assertRaises(ArtifactSourceError):
            self.review()
        self.rebuild()
        self.receipts.chmod(0o755)
        with self.assertRaises(ArtifactSourceError):
            self.review()

    def test_symlinks_hardlinks_and_nonprivate_receipt_refused(self):
        receipt = self.receipts / RECEIPT_NAMES[0]
        actual = self.home / "target"
        actual.write_bytes(receipt.read_bytes())
        receipt.unlink()
        receipt.symlink_to(actual)
        with self.assertRaises(ArtifactSourceError):
            self.review()
        receipt.unlink()
        self.rebuild()
        receipt.chmod(0o644)
        with self.assertRaises(ArtifactSourceError):
            self.review()
        receipt.chmod(0o600)
        os.link(receipt, self.home / "duplicate")
        with self.assertRaises(ArtifactSourceError):
            self.review()

    def test_symlink_hardlink_and_bad_ledger_permissions_refused(self):
        self.ledger.chmod(0o644)
        with self.assertRaises(ArtifactSourceError):
            self.review()
        self.ledger.chmod(0o600)
        os.link(self.ledger, self.home / "linked-ledger")
        with self.assertRaises(ArtifactSourceError):
            self.review()
        (self.home / "linked-ledger").unlink()
        raw = self.ledger.read_bytes()
        self.ledger.unlink()
        outside = self.home / "outside-ledger"
        outside.write_bytes(raw)
        self.ledger.symlink_to(outside)
        with self.assertRaises(ArtifactSourceError):
            self.review()

    def test_changed_local_assets_including_unrelated_slots_refused(self):
        (self.assets / "kernel.bin").write_bytes(b"changed")
        with self.assertRaises(Exception):
            self.review()

    def test_synthetic_plan_rejected(self):
        with self.assertRaises(ArtifactSourceError):
            review_artifact_source_ledger(
                load_vm_plan(SAMPLE), self.assets, self.ledger, self.receipts,
            )

    def test_deterministic_path_free_report(self):
        first = self.review().canonical_json()
        self.assertEqual(first, self.review().canonical_json())
        self.assertNotIn(str(self.home), first.decode())
        self.assertNotIn("example.org/releases/", first.decode())
        self.assertEqual(json.loads(first), self.review().to_dict())

    def test_no_network_or_process_file_mutation(self):
        before = self.ledger.read_bytes()
        backup = self.neighbor.read_bytes()
        with (
            patch.object(subprocess, "Popen", side_effect=AssertionError("process")),
            patch.object(subprocess, "run", side_effect=AssertionError("process")),
            patch.object(socket, "socket", side_effect=AssertionError("network")),
        ):
            self.assertFalse(self.review().to_dict()["execution_authorized"])
        self.assertEqual(self.ledger.read_bytes(), before)
        self.assertEqual(self.neighbor.read_bytes(), backup)

    def test_real_run_compare_report_stay_disabled(self):
        for cmd in ("run", "compare", "report"):
            code, out, _ = self.cli([cmd])
            self.assertEqual((code, out), (3, ""))


if __name__ == "__main__":
    unittest.main()
