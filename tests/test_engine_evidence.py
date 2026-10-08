"""SC-09: private, bounded, fail-closed LOCAL fixture evidence and verification."""
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from slipcage_engine import load_spec
from slipcage_engine.cli import main
from slipcage_engine.evidence import (
    ARTIFACT_NAMES, ALL_NAMES, BundleError, _canonical, _digest,
    verify_bundle, write_fixture_bundle,
)
from slipcage_engine.fixture_executor import FixtureScenario

FIXTURE_SPEC = ROOT / "examples" / "experiments" / "rbac-pod-create-denied.yaml"


class EvidenceBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.spec = load_spec(FIXTURE_SPEC)
        self.destination = self.root / "private-evidence"

    def create(self, scenario=FixtureScenario.DENIED):
        return write_fixture_bundle(self.spec, scenario, self.destination)

    def test_create_verify_all_five_scenarios(self):
        for scenario, expected in [
            (FixtureScenario.DENIED, "PASS"),
            (FixtureScenario.ALLOWED, "FAIL"),
            (FixtureScenario.AMBIGUOUS, "INCONCLUSIVE"),
            (FixtureScenario.ERROR, "ERROR"),
            (FixtureScenario.UNSUPPORTED, "SKIP"),
        ]:
            with self.subTest(scenario=scenario):
                target = self.root / scenario.value
                created = write_fixture_bundle(self.spec, scenario, target)
                again = verify_bundle(target)
                self.assertEqual(created, again)
                self.assertEqual(again.outcomes, (expected,))
                summary = again.to_dict()
                self.assertEqual(summary["status"], "verified_synthetic_bundle")
                self.assertTrue(summary["simulated"])
                self.assertFalse(summary["security_test_executed"])
                self.assertFalse(summary["real_security_evidence_verified"])
                self.assertEqual(set(os.listdir(target)), ALL_NAMES)
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
                for name in ALL_NAMES:
                    self.assertEqual(stat.S_IMODE((target / name).stat().st_mode), 0o600)
                record = json.loads((target / "results.json").read_text())
                self.assertEqual(record["evidence_status"], "not_collected")
                self.assertFalse(record["security_test_executed"])

    def test_canonical_json_and_verified_digest(self):
        verification = self.create()
        for name in ALL_NAMES:
            raw = (self.destination / name).read_bytes()
            self.assertEqual(raw, _canonical(json.loads(raw)))
        manifest_raw = (self.destination / "manifest.json").read_bytes()
        self.assertEqual(verification.manifest_digest_sha256, _digest(manifest_raw))
        manifest = json.loads(manifest_raw)
        self.assertTrue(manifest["complete"])
        self.assertEqual(manifest["spec_digest_sha256"], self.spec.digest_sha256)
        self.assertEqual(manifest["kind"], "synthetic_fixture")
        self.assertFalse(manifest["real_security_evidence_collected"])

    def test_output_must_be_new_and_existing_data_not_modified(self):
        before = b"precious-data"
        self.destination.mkdir(mode=0o700)
        (self.destination / "keep.txt").write_bytes(before)
        with self.assertRaises(BundleError):
            self.create()
        self.assertEqual((self.destination / "keep.txt").read_bytes(), before)

    def test_output_parent_rejects_symlink(self):
        real = self.root / "real"
        real.mkdir()
        indirect = self.root / "linked"
        indirect.symlink_to(real, target_is_directory=True)
        with self.assertRaises(BundleError):
            write_fixture_bundle(self.spec, FixtureScenario.DENIED, indirect / "data")
        self.assertFalse((real / "data").exists())

    def test_output_parent_must_exist(self):
        with self.assertRaises(BundleError):
            write_fixture_bundle(self.spec, FixtureScenario.DENIED, self.root / "missing" / "artifact")

    def test_reject_output_path_to_existing_file_or_symlink(self):
        self.destination.write_bytes(b"untouched")
        with self.assertRaises(BundleError):
            self.create()
        self.assertEqual(self.destination.read_bytes(), b"untouched")
        self.destination.unlink()
        self.destination.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(BundleError):
            self.create()

    def test_reject_spoofed_invalid_spec_and_scenario(self):
        from dataclasses import replace
        with self.assertRaises(BundleError):
            write_fixture_bundle(replace(self.spec, digest_sha256="f"*64),
                                 FixtureScenario.DENIED, self.destination)
        with self.assertRaises(BundleError):
            write_fixture_bundle(self.spec, "denied", self.destination)
        self.assertFalse(self.destination.exists())

    def test_refuses_extra_file_and_nested_directory(self):
        self.create()
        (self.destination / "untrusted.txt").write_text("secret")
        with self.assertRaises(BundleError):
            verify_bundle(self.destination)
        (self.destination / "untrusted.txt").unlink()
        (self.destination / "nested").mkdir()
        with self.assertRaises(BundleError):
            verify_bundle(self.destination)

    def test_refuses_missing_or_incomplete_manifest(self):
        self.create()
        (self.destination / "manifest.json").unlink()
        with self.assertRaises(BundleError):
            verify_bundle(self.destination)

    def test_refuses_tampered_result_even_without_hash_change(self):
        self.create()
        path = self.destination / "results.json"
        path.write_bytes(path.read_bytes().replace(b'"PASS"', b'"FAIL"'))
        with self.assertRaises(BundleError):
            verify_bundle(self.destination)

    def test_refuses_consistently_rehashed_fake_security_result(self):
        self.create()
        path = self.destination / "results.json"
        result = json.loads(path.read_bytes())
        result["security_test_executed"] = True
        path.write_bytes(_canonical(result))
        checksums_path = self.destination / "checksums.json"
        checksums = json.loads(checksums_path.read_bytes())
        checksums["files"]["results.json"] = _digest(path.read_bytes())
        checksums_path.write_bytes(_canonical(checksums))
        manifest_path = self.destination / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["checksums_sha256"] = _digest(checksums_path.read_bytes())
        manifest_path.write_bytes(_canonical(manifest))
        with self.assertRaisesRegex(BundleError, "replay"):
            verify_bundle(self.destination)

    def test_refuses_tampered_experiment_and_provenance(self):
        for name in ("experiment.json", "provenance.json"):
            with self.subTest(name=name):
                target = self.root / name.replace(".", "-")
                write_fixture_bundle(self.spec, FixtureScenario.DENIED, target)
                path = target / name
                path.write_bytes(path.read_bytes() + b" ")
                with self.assertRaises(BundleError):
                    verify_bundle(target)

    def test_refuses_symlink_hardlink_and_nonregular_artifacts(self):
        self.create()
        experiment = self.destination / "experiment.json"
        experiment.unlink()
        experiment.symlink_to(FIXTURE_SPEC)
        with self.assertRaises(BundleError):
            verify_bundle(self.destination)
        experiment.unlink()
        experiment.write_bytes(b'{}')
        experiment.chmod(0o600)
        peer = self.root / "peer.txt"
        os.link(experiment, peer)
        with self.assertRaises(BundleError):
            verify_bundle(self.destination)

    def test_private_permissions_required_for_verification(self):
        self.create()
        result_path = self.destination / "results.json"
        result_path.chmod(0o644)
        with self.assertRaises(BundleError):
            verify_bundle(self.destination)
        result_path.chmod(0o600)
        self.destination.chmod(0o755)
        with self.assertRaises(BundleError):
            verify_bundle(self.destination)

    def test_reject_symlink_bundle_root(self):
        self.create()
        link = self.root / "aliased"
        link.symlink_to(self.destination, target_is_directory=True)
        with self.assertRaises(BundleError):
            verify_bundle(link)

    def test_incomplete_publication_preserves_partial_data_and_never_overwrites(self):
        # A failure after creating a directory must NOT produce a manifest.
        from slipcage_engine import evidence
        original = evidence._write_file
        def fail_manifest(fd, name, data):
            if name == "manifest.json":
                raise OSError("injected write failure")
            return original(fd, name, data)
        with patch.object(evidence, "_write_file", side_effect=fail_manifest):
            with self.assertRaises(BundleError):
                self.create()
        self.assertTrue(self.destination.is_dir())
        self.assertFalse((self.destination / "manifest.json").exists())
        self.assertTrue((self.destination / "experiment.json").exists())
        with self.assertRaises(BundleError):
            verify_bundle(self.destination)
        with self.assertRaises(BundleError):
            self.create()

    def test_reject_noncanonical_duplicate_keys_bad_digest_and_manifest_status(self):
        self.create()
        manifest_path = self.destination / "manifest.json"
        original = manifest_path.read_bytes()
        for changed in (
            original + b"\n",
            b'{"complete":true,"complete":false}',
            _canonical({**json.loads(original), "simulated": False}),
            _canonical({**json.loads(original), "complete": False}),
            _canonical({**json.loads(original), "checksums_sha256": "0"*64}),
            _canonical({**json.loads(original), "created_at_utc": "not-a-date"}),
            _canonical({**json.loads(original), "unexpected": 1}),
        ):
            with self.subTest(changed=changed[:40]):
                manifest_path.write_bytes(changed)
                with self.assertRaises(BundleError):
                    verify_bundle(self.destination)

    def test_cli_bundle_and_verify_work_without_real_execution(self):
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            code = main(["bundle-fixture", str(FIXTURE_SPEC), "--scenario", "denied",
                         "--output", str(self.destination), "--json"])
        self.assertEqual(code, 0)
        record = json.loads(out.getvalue())
        self.assertTrue(record["simulated"])
        self.assertFalse(record["security_test_executed"])
        self.assertFalse(record["real_security_evidence_verified"])
        again_out = io.StringIO()
        with redirect_stdout(again_out), redirect_stderr(io.StringIO()):
            code = main(["verify-bundle", str(self.destination), "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(record, json.loads(again_out.getvalue()))

    def test_cli_bad_bundle_fails_no_success_output(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["verify-bundle", str(self.root / "missing"), "--json"])
        self.assertEqual(code, 2)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("verify-bundle", err.getvalue())

    def test_cli_synthetic_fail_bundle_is_successful_artifact_generation(self):
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            code = main(["bundle-fixture", str(FIXTURE_SPEC), "--scenario", "allowed",
                         "--output", str(self.destination), "--json"])
        self.assertEqual(code, 0)
        record = json.loads(out.getvalue())
        self.assertEqual(record["outcomes"], ["FAIL"])
        self.assertFalse(record["real_security_evidence_verified"])

    def test_cli_real_run_compare_report_still_unavailable(self):
        for command in ("run", "compare", "report"):
            with self.subTest(command=command):
                out, err = io.StringIO(), io.StringIO()
                with redirect_stdout(out), redirect_stderr(err):
                    code = main([command])
                self.assertEqual(code, 3)
                self.assertEqual(out.getvalue(), "")
                self.assertIn("unavailable", err.getvalue())


if __name__ == "__main__":
    unittest.main()
