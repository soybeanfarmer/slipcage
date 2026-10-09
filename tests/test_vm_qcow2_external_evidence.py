"""SC-13b17 read-only QEMU output *review*, not QEMU execution.

All QAPI-looking transcripts are invented and explicitly unauthenticated.
Even perfect locally coherent fake JSON must NEVER authorize a VM.
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from slipcage_engine.cli import main
from slipcage_engine.vm_assets import ARTIFACTS
from slipcage_engine.vm_plan import load_vm_plan, validate_vm_plan_bytes
from slipcage_engine.vm_qcow2_external_evidence import (
    API_VERSION, Qcow2ExternalEvidenceError, review_qcow2_external_evidence,
)

SAMPLE = ROOT / "examples/vm-plans/k3s-synthetic-design.json"
C = 65536


def canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("ascii")


def fake_header():
    header = bytearray(112)
    header[:4] = b"QFI\xfb"
    struct.pack_into(">I", header, 4, 3)
    struct.pack_into(">I", header, 20, 16)
    struct.pack_into(">Q", header, 24, 24 * 1024**3)
    struct.pack_into(">I", header, 36, 1)
    struct.pack_into(">Q", header, 40, C)
    struct.pack_into(">Q", header, 48, 2*C)
    struct.pack_into(">I", header, 56, 1)
    struct.pack_into(">I", header, 96, 4)
    struct.pack_into(">I", header, 100, 104)
    return bytes(header) + bytes(3*C-112)


class ExternalQcow2EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.assets = self.root / "assets"
        self.evidence = self.root / "evidence"
        for d in (self.assets, self.evidence):
            d.mkdir(mode=0o700)
            d.chmod(0o700)
        draft = load_vm_plan(SAMPLE).design
        draft["provenance"]["pin_status"] = "operator_supplied_unverified"
        draft["provenance"]["note"] = "Only fake transcripts and fake artifact bytes in CI"
        draft["software"]["guest_kernel_release"] = "6.8.0-test"
        self.base = self.assets / "os-image.qcow2"
        for index, (field, filename, _) in enumerate(ARTIFACTS):
            asset = self.assets / filename
            asset.write_bytes(fake_header() if index == 0
                              else f"test-only-{filename}".encode("ascii"))
            asset.chmod(0o600)
            draft["artifacts"][field] = hashlib.sha256(asset.read_bytes()).hexdigest()
        self.plan = validate_vm_plan_bytes(canonical(draft))
        self.planfile = self.root / "plan.json"
        self.planfile.write_bytes(self.plan.canonical_json)
        self.info = {
            "filename": "os-image.qcow2", "format": "qcow2",
            "virtual-size": 24 * 1024**3, "actual-size": 3*C,
            "cluster-size": C, "dirty-flag": False,
            "encrypted": False, "compressed": False, "snapshots": [],
        }
        self.check_data = {
            "filename": "os-image.qcow2", "format": "qcow2", "check-errors": 0,
            "image-end-offset": 3*C,
            "total-clusters": 3, "allocated-clusters": 3,
            "corruptions": 0, "leaks": 0,
        }
        self.capture = {
            "api_version": API_VERSION,
            "capture_kind": "declared_qemu_img_read_only_info_check",
            "capture_origin": "operator_supplied_unverified",
            "plan_digest_sha256": self.plan.digest_sha256,
            "base_sha256": self.plan.design["artifacts"]["os_image_sha256"],
            "base_size_bytes": 3*C,
            "qemu_img_version": self.plan.design["runtime"]["qemu_version"],
            "qemu_img_binary_sha256": hashlib.sha256(b"FAKE qemu-img").hexdigest(),
            "info_command": [
                "qemu-img", "info", "--output=json", "-f", "qcow2", "os-image.qcow2",
            ],
            "check_command": [
                "qemu-img", "check", "--output=json", "-f", "qcow2", "os-image.qcow2",
            ],
            "info_exit_code": 0, "check_exit_code": 0,
        }
        self.write()
        self.neighbor = self.root / "do-not-touch.db"
        self.neighbor.write_bytes(b"KEEP")

    def write(self):
        info_bytes, check_bytes = canonical(self.info), canonical(self.check_data)
        self.capture["info_output_sha256"] = hashlib.sha256(info_bytes).hexdigest()
        self.capture["check_output_sha256"] = hashlib.sha256(check_bytes).hexdigest()
        for name, data in (
            ("info.json", info_bytes), ("check.json", check_bytes),
            ("capture.json", canonical(self.capture)),
        ):
            path = self.evidence / name
            path.write_bytes(data)
            path.chmod(0o600)

    def review(self):
        return review_qcow2_external_evidence(self.plan, self.assets, self.evidence)

    def cli(self, argv=None):
        if argv is None:
            argv = [
                "review-vm-qcow2-external-evidence", str(self.planfile),
                "--assets-dir", str(self.assets),
                "--evidence-dir", str(self.evidence), "--json",
            ]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_local_report_coherence_is_not_independent_image_integrity(self):
        doc = self.review().to_dict()
        self.assertEqual(doc["api_version"], API_VERSION)
        self.assertEqual(doc["status"], "operator_qemu_report_consistent_but_untrusted")
        self.assertEqual(doc["plan_digest_sha256"], self.plan.digest_sha256)
        self.assertEqual(doc["base_sha256"], self.plan.design["artifacts"]["os_image_sha256"])
        self.assertEqual(doc["base_size_bytes"], 3*C)
        self.assertTrue(doc["operator_reports_clean_info_and_check"])
        self.assertEqual(doc["reported_repairs"], 0)

    def test_fake_transcripts_can_pass_but_all_runtime_trust_flags_remain_false(self):
        doc = self.review().to_dict()
        for flag in (
            "external_qemu_img_executed_by_this_command", "external_qemu_img_execution_attested",
            "reported_qemu_img_binary_authenticated", "operator_report_authenticity_verified",
            "publisher_origin_authenticated", "qcow2_full_metadata_independently_verified",
            "immutable_backing_chain_verified", "host_kvm_readiness_verified",
            "host_global_vm_lease", "guest_execution_authorized", "vm_launched",
            "host_modified",
        ):
            with self.subTest(flag=flag):
                self.assertIs(doc[flag], False)

    def test_positive_cli_always_exit_5_and_path_free(self):
        status, out, err = self.cli()
        self.assertEqual((status, err), (5, ""))
        self.assertEqual(json.loads(out), self.review().to_dict())
        self.assertNotIn(str(self.root), out)
        self.assertNotIn("example.org", out)
        self.assertEqual(self.review().canonical_json(), out.strip().encode())

    def test_changed_base_bytes_fail_even_with_matching_forged_reports(self):
        with self.base.open("r+b") as file:
            file.seek(C + 100)
            file.write(b"X")
        with self.assertRaises(Exception):
            self.review()

    def test_stale_and_other_plan_identity_rejected(self):
        self.capture["plan_digest_sha256"] = "f"*64
        self.write()
        with self.assertRaisesRegex(Qcow2ExternalEvidenceError, "mismatch"):
            self.review()

    def test_changed_info_without_rehashed_manifest_rejected(self):
        (self.evidence / "info.json").write_bytes(canonical({
            **self.info, "actual-size": 1,
        }))
        with self.assertRaisesRegex(Qcow2ExternalEvidenceError, "mismatch"):
            self.review()

    def test_changed_check_without_rehashed_manifest_rejected(self):
        (self.evidence / "check.json").write_bytes(canonical({
            **self.check_data, "corruptions": 1,
        }))
        with self.assertRaises(Qcow2ExternalEvidenceError):
            self.review()

    def test_forged_clean_report_with_updated_hashes_cannot_authenticate_execution(self):
        # This deliberately proves a malicious caller can fabricate the
        # entire report; even matching digests/exit codes have NO authority.
        self.info["format-specific"] = {
            "type": "qcow2",
            "data": {
                "compat": "1.1", "refcount-bits": 16,
                "lazy-refcounts": False, "corrupt": False,
                "compression-type": "zlib",
            },
        }
        self.write()
        doc = self.review().to_dict()
        self.assertFalse(doc["external_qemu_img_execution_attested"])
        self.assertFalse(doc["qcow2_full_metadata_independently_verified"])
        self.assertFalse(doc["guest_execution_authorized"])
        self.assertFalse(doc["execution_authorized"])

    def test_pretty_printed_qapi_json_allowed_with_exact_raw_byte_hash(self):
        # Real qemu-img emits pretty JSON and a newline. SHA covers actual
        # supplied transcript bytes, including whitespace.
        for key, data in (("info", self.info), ("check", self.check_data)):
            pretty = (json.dumps(data, sort_keys=True, indent=2) + chr(10)).encode()
            (self.evidence / (key + ".json")).write_bytes(pretty)
            self.capture[key + "_output_sha256"] = hashlib.sha256(pretty).hexdigest()
        (self.evidence / "capture.json").write_bytes(canonical(self.capture))
        doc = self.review().to_dict()
        self.assertFalse(doc["operator_report_authenticity_verified"])
        self.assertEqual(doc["info_json_sha256"], hashlib.sha256(
            (self.evidence / "info.json").read_bytes()).hexdigest())

    def test_repaired_reports_fail_even_when_exit_success(self):
        for key in ("corruptions-fixed", "leaks-fixed"):
            self.check_data[key] = 1
            self.write()
            with self.subTest(key=key), self.assertRaises(Qcow2ExternalEvidenceError):
                self.review()
            del self.check_data[key]
        self.write()

    def test_nonzero_check_corruptions_leaks_and_errors_rejected(self):
        for key in ("corruptions", "leaks", "check-errors"):
            self.check_data[key] = 1
            self.write()
            with self.subTest(key=key), self.assertRaises(Qcow2ExternalEvidenceError):
                self.review()
            self.check_data[key] = 0
        self.write()

    def test_image_info_rejects_backing_encryption_compression_dirty_snapshots(self):
        for field, value in (
            ("backing-filename", "/tmp/other.qcow2"),
            ("backing-image", {}),
            ("encrypted", True),
            ("compressed", True),
            ("dirty-flag", True),
            ("snapshots", [{}]),
            ("format", "raw"),
        ):
            old = self.info.get(field)
            self.info[field] = value
            self.write()
            with self.subTest(field=field), self.assertRaises(Qcow2ExternalEvidenceError):
                self.review()
            if old is None:
                del self.info[field]
            else:
                self.info[field] = old
        self.write()

    def test_report_wrong_image_name_or_virtual_size_rejected(self):
        for attr, value in (
            ("filename", "/sensitive/path/os-image.qcow2"),
            ("virtual-size", 48*1024**3),
            ("cluster-size", 4096),
            ("actual-size", 2**50),
        ):
            old = self.info[attr]
            self.info[attr] = value
            self.write()
            with self.subTest(attr=attr), self.assertRaises(Qcow2ExternalEvidenceError):
                self.review()
            self.info[attr] = old
        self.write()

    def test_check_report_filename_and_negative_counters_rejected(self):
        for key, value in (
            ("filename", "other.qcow2"),
            ("check-errors", -1),
            ("check-errors", True),
            ("allocated-clusters", 999999),
            ("image-end-offset", 2**45),
        ):
            old = self.check_data[key] if key in self.check_data else None
            self.check_data[key] = value
            self.write()
            with self.subTest(key=key), self.assertRaises(Qcow2ExternalEvidenceError):
                self.review()
            if old is None:
                del self.check_data[key]
            else:
                self.check_data[key] = old
        self.write()

    def test_reported_qemu_img_flags_and_repair_commands_rejected(self):
        for key, val in (
            ("check_command", ["qemu-img","check","-r","all","--output=json","os-image.qcow2"]),
            ("check_command", ["qemu-img","check","-U","--output=json","-f","qcow2","os-image.qcow2"]),
            ("info_command", ["qemu-img","info","-f","raw","--output=json","os-image.qcow2"]),
            ("capture_origin", "independently_attested"),
            ("qemu_img_binary_sha256", "BAD"),
            ("qemu_img_version", "999.0.0"),
            ("check_exit_code", 3),
            ("info_exit_code", 1),
        ):
            old = self.capture[key]
            self.capture[key] = val
            self.write()
            with self.subTest(key=key), self.assertRaises(Qcow2ExternalEvidenceError):
                self.review()
            self.capture[key] = old
        self.write()

    def test_info_format_specific_corrupt_or_unknown_rejected(self):
        for extra in (
            {"compat":"1.1", "refcount-bits": 16, "corrupt": True},
            {"compat":"1.1", "refcount-bits": 16, "lazy-refcounts": True},
            {"compat":"1.1", "refcount-bits": 16, "bitmaps":[]},
            {"compat":"1.1", "refcount-bits": 64},
        ):
            self.info["format-specific"] = {"type": "qcow2", "data": extra}
            self.write()
            with self.subTest(extra=extra), self.assertRaises(Qcow2ExternalEvidenceError):
                self.review()
        del self.info["format-specific"]
        self.write()

    def test_duplicate_noncanonical_json_and_extra_fields_rejected(self):
        originals = {
            name: (self.evidence / name).read_bytes()
            for name in ("capture.json", "info.json", "check.json")
        }
        for name in originals:
            for payload in (
                b'{"format":"qcow2","format":"raw"}',
                b'[]', b"{}", b"\xff",
                b'{"execution_authorized":true}',
            ):
                (self.evidence / name).write_bytes(payload)
                with self.subTest(name=name, payload=payload[:24]), self.assertRaises(Qcow2ExternalEvidenceError):
                    self.review()
            (self.evidence / name).write_bytes(originals[name])

    def test_unsafe_evidence_dir_symlink_modes_extra_entries_rejected(self):
        self.evidence.chmod(0o755)
        with self.assertRaises(Qcow2ExternalEvidenceError):
            self.review()
        self.evidence.chmod(0o700)
        extra = self.evidence / "overlay.qcow2"
        extra.write_bytes(b"preserve")
        with self.assertRaises(Qcow2ExternalEvidenceError):
            self.review()
        extra.unlink()
        linked = self.root / "evidence-link"
        linked.symlink_to(self.evidence, target_is_directory=True)
        with self.assertRaises(Qcow2ExternalEvidenceError):
            review_qcow2_external_evidence(self.plan, self.assets, linked)

    def test_unsafe_evidence_file_symlink_mode_hardlink_and_nonregular(self):
        path = self.evidence / "check.json"
        orig = path.read_bytes()
        path.chmod(0o644)
        with self.assertRaises(Qcow2ExternalEvidenceError):
            self.review()
        path.chmod(0o600)
        hard = self.root / "hard"
        os.link(path, hard)
        with self.assertRaises(Qcow2ExternalEvidenceError):
            self.review()
        hard.unlink()
        path.unlink()
        path.symlink_to(self.root / "nonexistent")
        with self.assertRaises(Qcow2ExternalEvidenceError):
            self.review()
        path.unlink()
        path.mkdir()
        with self.assertRaises(Qcow2ExternalEvidenceError):
            self.review()
        path.rmdir()
        path.write_bytes(orig)
        path.chmod(0o600)

    def test_absent_and_oversized_json_files_fail_closed(self):
        (self.evidence / "capture.json").write_bytes(b"A"*18000)
        with self.assertRaises(Qcow2ExternalEvidenceError):
            self.review()
        (self.evidence / "capture.json").unlink()
        with self.assertRaises(Qcow2ExternalEvidenceError):
            self.review()

    def test_compressed_cluster_claim_does_not_pass_uncompressed_report(self):
        self.check_data["compressed-clusters"] = 1
        self.write()
        with self.assertRaisesRegex(Qcow2ExternalEvidenceError, "Compressed"):
            self.review()

    def test_capture_manifest_must_be_canonical_even_if_reports_are_pretty(self):
        path = self.evidence / "capture.json"
        capture = json.loads(path.read_bytes())
        path.write_bytes((json.dumps(capture, indent=2) + chr(10)).encode("ascii"))
        with self.assertRaisesRegex(Qcow2ExternalEvidenceError, "canonical"):
            self.review()

    def test_observed_external_statistics_must_be_self_consistent(self):
        self.check_data["allocated-clusters"] = 5
        self.check_data["total-clusters"] = 3
        self.write()
        with self.assertRaises(Qcow2ExternalEvidenceError):
            self.review()

    def test_no_qemu_subprocess_kvm_shell_network_or_host_modifications(self):
        before = [(name, (self.evidence/name).read_bytes()) for name in sorted(("capture.json","check.json","info.json"))]
        with (
            patch.object(subprocess, "Popen", side_effect=AssertionError("process")),
            patch.object(subprocess, "run", side_effect=AssertionError("process")),
            patch.object(socket, "socket", side_effect=AssertionError("network")),
            patch.object(os, "system", side_effect=AssertionError("shell")),
        ):
            self.assertFalse(self.review().to_dict()["guest_execution_authorized"])
        self.assertEqual(before, [(n, (self.evidence/n).read_bytes()) for n,_ in before])
        self.assertEqual(self.neighbor.read_bytes(), b"KEEP")

    def test_real_run_compare_report_still_disabled(self):
        for command in ("run", "compare", "report"):
            code, out, _ = self.cli([command])
            self.assertEqual((code, out), (3, ""))


if __name__ == "__main__":
    unittest.main()
