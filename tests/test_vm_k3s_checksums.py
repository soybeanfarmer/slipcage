"""SC-13b14: offline upstream-style K3s checksum reconciliation, never trust."""
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
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from slipcage_engine.cli import main
from slipcage_engine.vm_assets import ARTIFACTS
from slipcage_engine.vm_plan import load_vm_plan, validate_vm_plan_bytes
from slipcage_engine.vm_k3s_checksums import (
    API_VERSION, K3sReleaseChecksumError, verify_k3s_release_checksums,
)

SAMPLE = ROOT / "examples" / "vm-plans" / "k3s-synthetic-design.json"


def canon(obj):
    return json.dumps(obj, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


class K3sReleaseChecksumTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.assets.chmod(0o700)
        self.binary_manifest = self.root / "sha256sum-amd64.txt"
        self.archive_manifest = self.root / "k3s-airgap-images-amd64.sha256sum"
        spec = load_vm_plan(SAMPLE).design
        spec["provenance"]["pin_status"] = "operator_supplied_unverified"
        spec["provenance"]["note"] = "CI only; not fetched or signed by K3s"
        spec["software"]["guest_kernel_release"] = "6.8.0-test"
        self.bytes_by_name = {}
        for i, (field, name, _) in enumerate(ARTIFACTS):
            data = f"untrusted-CI-bytes-{field}-{i}".encode("ascii")
            self.bytes_by_name[name] = data
            dst = self.assets / name
            dst.write_bytes(data)
            dst.chmod(0o600)
            spec["artifacts"][field] = hashlib.sha256(data).hexdigest()
        self.plan = validate_vm_plan_bytes(canon(spec))
        self.plan_file = self.root / "plan.json"
        self.plan_file.write_bytes(self.plan.canonical_json)
        self.write_manifests()
        self.neighbor = self.root / "preserve-research.sqlite"
        self.neighbor.write_bytes(b"KEEP ME")

    def write_manifests(self, *, binary=None, archive=None):
        bin_hash = hashlib.sha256(self.bytes_by_name["k3s.bin"]).hexdigest()
        air_hash = hashlib.sha256(self.bytes_by_name["container-images.tar"]).hexdigest()
        self.binary_manifest.write_bytes(
            binary if binary is not None else f"{bin_hash}  k3s\n".encode()
        )
        self.archive_manifest.write_bytes(
            archive if archive is not None else (
                f"{air_hash}  k3s-airgap-images-amd64.tar\n"
                f"{'f'*64}  k3s-airgap-images-amd64.tar.gz\n"
                f"{'e'*64}  k3s-airgap-images-amd64.tar.zst\n"
            ).encode()
        )
        self.binary_manifest.chmod(0o600)
        self.archive_manifest.chmod(0o600)

    def check(self):
        return verify_k3s_release_checksums(
            self.plan, self.assets, self.binary_manifest, self.archive_manifest,
        )

    def cli(self, argv=None):
        cmd = argv or [
            "verify-k3s-upstream-checksums", str(self.plan_file),
            "--assets-dir", str(self.assets),
            "--binary-checksums", str(self.binary_manifest),
            "--airgap-checksums", str(self.archive_manifest),
            "--json",
        ]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = main(cmd)
        return status, out.getvalue(), err.getvalue()

    def test_two_upstream_style_checksums_match_plan_and_actual_bytes(self):
        result = self.check().to_dict()
        self.assertEqual(result["api_version"], API_VERSION)
        self.assertEqual(result["release_tag_operator_declared"], "v1.30.1+k3s1")
        self.assertEqual(result["architecture"], "amd64")
        self.assertTrue(result["both_manifest_digests_match_local_bytes_and_plan"])
        self.assertTrue(result["all_five_local_assets_checked"])
        self.assertEqual(result["binary_upstream_asset"], "k3s")
        self.assertEqual(result["archive_upstream_asset"], "k3s-airgap-images-amd64.tar")
        self.assertEqual(result["plan_digest_sha256"], self.plan.digest_sha256)
        self.assertEqual(result["binary_size_bytes"], len(self.bytes_by_name["k3s.bin"]))
        self.assertEqual(result["airgap_archive_size_bytes"],
                         len(self.bytes_by_name["container-images.tar"]))

    def test_positive_checks_never_authenticate_publisher_or_launch(self):
        response = self.check().to_dict()
        for flag in (
            "publisher_checksum_source_authenticated", "release_tag_verified_against_upstream",
            "upstream_release_signatures_verified", "airgap_archive_contents_inspected",
            "container_images_provenance_authenticated", "cni_and_kernel_upstream_verified",
            "software_publisher_authenticated", "host_kvm_verified",
            "provider_permission_verified", "execution_authorized",
            "vm_launched", "host_modified",
        ):
            with self.subTest(flag=flag):
                self.assertFalse(response[flag])

    def test_binary_manifest_hash_mismatch_rejected(self):
        self.write_manifests(binary=(f"{'0'*64}  k3s\n").encode())
        with self.assertRaisesRegex(K3sReleaseChecksumError, "binary release checksum"):
            self.check()

    def test_airgap_manifest_hash_mismatch_rejected(self):
        self.write_manifests(archive=(f"{'0'*64}  k3s-airgap-images-amd64.tar\n").encode())
        with self.assertRaisesRegex(K3sReleaseChecksumError, "airgap tar release checksum"):
            self.check()

    def test_locally_tampered_binary_detected_even_when_manifest_matches_old_bytes(self):
        dst = self.assets / "k3s.bin"
        dst.write_bytes(b"locally tampered")
        with self.assertRaises(Exception):
            self.check()

    def test_all_five_local_assets_must_match_not_just_upstream_two(self):
        (self.assets / "kernel.bin").write_bytes(b"untrusted changed")
        with self.assertRaises(Exception):
            self.check()

    def test_missing_uncompressed_tar_cannot_be_replaced_by_compressed_checksum(self):
        self.write_manifests(archive=(
            f"{'e'*64}  k3s-airgap-images-amd64.tar.zst\n"
        ).encode())
        with self.assertRaisesRegex(K3sReleaseChecksumError, "uncompressed"):
            self.check()

    def test_both_manifests_must_be_distinct_sources(self):
        with self.assertRaisesRegex(K3sReleaseChecksumError, "Independent"):
            verify_k3s_release_checksums(
                self.plan, self.assets, self.binary_manifest, self.binary_manifest
            )

    def test_reject_duplicate_paths_traversal_and_unexpected_architecture(self):
        real_digest = hashlib.sha256(self.bytes_by_name["container-images.tar"]).hexdigest()
        for raw in (
            f"{real_digest}  k3s-airgap-images-amd64.tar\n"*2,
            f"{real_digest}  ../k3s-airgap-images-amd64.tar\n",
            f"{real_digest}  k3s-airgap-images-arm64.tar\n",
            f"{real_digest}  container-images.tar\n",
        ):
            with self.subTest(raw=raw[:70]):
                self.write_manifests(archive=raw.encode())
                with self.assertRaises(K3sReleaseChecksumError):
                    self.check()

    def test_reject_noncanonical_unsafe_binary_checksum_lines(self):
        digest = hashlib.sha256(self.bytes_by_name["k3s.bin"]).hexdigest()
        for raw in (
            f"{digest} *k3s\n", f"{digest}  k3s\r\n",
            f"{digest}  k3s", f"{digest.upper()}  k3s\n",
            f"{digest}  ./k3s\n", b"\xff", b"\x00",
            b"\n", b"x"*9000,
        ):
            value = raw.encode() if isinstance(raw, str) else raw
            with self.subTest(raw=value[:40]):
                self.write_manifests(binary=value)
                with self.assertRaises(K3sReleaseChecksumError):
                    self.check()

    def test_private_symlink_hardlink_mode_and_nonregular_manifest_refused(self):
        outside = self.root / "outside"
        outside.write_bytes(self.binary_manifest.read_bytes())
        self.binary_manifest.unlink()
        self.binary_manifest.symlink_to(outside)
        with self.assertRaises(K3sReleaseChecksumError):
            self.check()
        self.binary_manifest.unlink()
        self.write_manifests()
        self.binary_manifest.chmod(0o644)
        with self.assertRaises(K3sReleaseChecksumError):
            self.check()
        self.binary_manifest.chmod(0o600)
        os.link(self.binary_manifest, outside.with_suffix(".hardlink"))
        with self.assertRaises(K3sReleaseChecksumError):
            self.check()
        outside.with_suffix(".hardlink").unlink()
        self.binary_manifest.unlink()
        self.binary_manifest.mkdir()
        with self.assertRaises(K3sReleaseChecksumError):
            self.check()

    def test_synthetic_fixture_rejected_even_when_some_hashes_are_valid(self):
        with self.assertRaises(K3sReleaseChecksumError):
            verify_k3s_release_checksums(
                load_vm_plan(SAMPLE), self.assets,
                self.binary_manifest, self.archive_manifest,
            )

    def test_invalid_release_tag_is_refused_before_checksums(self):
        design = json.loads(self.plan.canonical_json)
        # A schema-permitted pre-release tag is intentionally unsupported here.
        design["software"]["k3s_version"] = "v1.30.1-rc1+k3s1"
        try:
            changed = validate_vm_plan_bytes(canon(design))
        except Exception:
            self.skipTest("SC-12 schema already rejects prerelease tags")
        with self.assertRaises(K3sReleaseChecksumError):
            verify_k3s_release_checksums(
                changed, self.assets, self.binary_manifest, self.archive_manifest,
            )

    def test_cli_rejects_bad_manifest_and_reports_valid_local_check(self):
        code, out, err = self.cli()
        self.assertEqual((code, err), (0, ""))
        body = json.loads(out)
        self.assertFalse(body["software_publisher_authenticated"])
        self.assertFalse(body["execution_authorized"])
        self.write_manifests(binary=(f"{'0'*64}  k3s\n").encode())
        rc, stdout, stderr = self.cli()
        self.assertEqual((rc, stdout), (2, ""))
        self.assertTrue(stderr)

    def test_output_is_deterministic_and_path_free(self):
        a = self.check().canonical_json()
        b = self.check().canonical_json()
        self.assertEqual(a, b)
        self.assertEqual(json.loads(a), self.check().to_dict())
        self.assertNotIn(str(self.root), a.decode())

    def test_no_subprocess_network_or_mutation_of_data(self):
        before = {p.name: p.read_bytes() for p in (
            self.binary_manifest, self.archive_manifest, self.neighbor
        )}
        with (
            patch.object(subprocess, "Popen", side_effect=AssertionError("process")),
            patch.object(subprocess, "run", side_effect=AssertionError("process")),
            patch.object(socket, "socket", side_effect=AssertionError("network")),
            patch.object(os, "system", side_effect=AssertionError("shell")),
        ):
            report = self.check()
            self.assertFalse(report.to_dict()["vm_launched"])
        self.assertEqual(before, {p.name: p.read_bytes() for p in (
            self.binary_manifest, self.archive_manifest, self.neighbor
        )})

    def test_real_run_compare_report_stay_disabled(self):
        for command in ("run", "compare", "report"):
            code, out, err = self.cli([command])
            self.assertEqual((code, out), (3, ""))


if __name__ == "__main__":
    unittest.main()
