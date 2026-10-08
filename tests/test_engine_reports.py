"""SC-11: deterministic synthetic reports and complete offline regression proof."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import os
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from slipcage_engine import load_spec
from slipcage_engine.cli import main
from slipcage_engine.comparison import ChangeKind, compare_fixture_bundles
from slipcage_engine.evidence import write_fixture_bundle
from slipcage_engine.fixture_executor import FixtureScenario
from slipcage_engine.reports import ReportError, render_fixture_report
from slipcage_engine.workflow import (
    DemoError, create_fixture_demo, verify_fixture_demo,
)

SPEC = ROOT / "examples" / "experiments" / "rbac-pod-create-denied.yaml"


class SyntheticReportsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.spec = load_spec(SPEC)
        self.b = self.root / "baseline"
        self.c = self.root / "candidate"

    def pair(self, b=FixtureScenario.DENIED, c=FixtureScenario.ALLOWED):
        write_fixture_bundle(self.spec, b, self.b)
        write_fixture_bundle(self.spec, c, self.c)
        return compare_fixture_bundles(self.b, self.c)

    def _cli(self, args):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            status = main(args)
        return status, output.getvalue(), errors.getvalue()

    def test_deterministic_json_and_markdown_from_same_verified_bundles(self):
        cmp = self.pair()
        report = render_fixture_report(cmp)
        other = render_fixture_report(compare_fixture_bundles(self.b, self.c))
        self.assertEqual(report, other)
        data = json.loads(report.json_bytes)
        self.assertEqual(
            report.json_bytes,
            json.dumps(data, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True).encode(),
        )
        self.assertEqual(data["api_version"], "slipcage.dev/fixture-report/v1alpha1")
        self.assertEqual(data["report_status"], "complete")
        self.assertEqual(data["comparison"]["classification"], "regression")
        self.assertEqual(data["comparison"]["assertions"][0]["classification"], "regression")
        self.assertTrue(data["simulated"])
        self.assertFalse(data["security_test_executed"])
        self.assertFalse(data["real_security_evidence_verified"])
        text = report.markdown_bytes.decode()
        self.assertIn("SYNTHETIC fixture comparison", text)
        self.assertIn("OFFLINE SIMULATION ONLY", text)
        self.assertIn("regression", text)
        self.assertIn(cmp.baseline.manifest_digest_sha256, text)
        self.assertIn(cmp.candidate.manifest_digest_sha256, text)
        self.assertNotIn(str(self.root), text)

    def test_report_uncertain_evidence_yields_incomparable_without_false_claim(self):
        write_fixture_bundle(self.spec, FixtureScenario.DENIED, self.b)
        cmp = compare_fixture_bundles(self.b, self.c)
        self.assertFalse(cmp.comparable)
        report = render_fixture_report(cmp)
        data = json.loads(report.json_bytes)
        self.assertEqual(data["report_status"], "incomparable")
        self.assertEqual(data["comparison"]["classification"], "incomparable")
        self.assertFalse(data["real_security_evidence_verified"])
        text = report.markdown_bytes.decode()
        self.assertIn("incomparable", text)
        self.assertIn("not a verified kubernetes security regression", text.lower())

    def test_report_refuses_noncomparison_input(self):
        with self.assertRaises(ReportError):
            render_fixture_report({"classification": "regression"})

    def test_report_fixtures_command_json_and_markdown_exit_codes(self):
        self.pair()
        rc, result, err = self._cli(["report-fixtures", str(self.b), str(self.c), "--format", "json"])
        self.assertEqual((rc, err), (1, ""))
        data = json.loads(result)
        self.assertEqual(data["comparison"]["classification"], "regression")
        rc, text, err = self._cli(["report-fixtures", str(self.b), str(self.c)])
        self.assertEqual((rc, err), (1, ""))
        self.assertIn("SYNTHETIC", text)
        self.assertIn("## Per-assertion outcomes", text)

    def test_invalid_candidate_report_is_incomparable_exit_four(self):
        write_fixture_bundle(self.spec, FixtureScenario.DENIED, self.b)
        rc, out, err = self._cli(["report-fixtures", str(self.b), str(self.c), "--format", "json"])
        self.assertEqual((rc, err), (4, ""))
        self.assertEqual(json.loads(out)["report_status"], "incomparable")

    def test_complete_private_demo_writes_and_reverifies_all_artifacts(self):
        root = self.root / "proof"
        done = create_fixture_demo(self.spec, FixtureScenario.DENIED,
                                   FixtureScenario.ALLOWED, root)
        self.assertEqual(done.comparison.classification, ChangeKind.REGRESSION)
        self.assertEqual(done, verify_fixture_demo(root))
        self.assertEqual(
            set(os.listdir(root)),
            {"baseline", "candidate", "report.json", "report.md", "manifest.json"},
        )
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
        for item in ("report.json", "report.md", "manifest.json"):
            self.assertEqual(stat.S_IMODE((root / item).stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((root / "baseline").stat().st_mode), 0o700)
        data = json.loads((root / "report.json").read_bytes())
        self.assertEqual(data["comparison"]["classification"], "regression")
        self.assertFalse(data["real_security_evidence_verified"])
        manifest = json.loads((root / "manifest.json").read_bytes())
        self.assertTrue(manifest["complete"])
        self.assertFalse(manifest["security_test_executed"])

    def test_cli_end_to_end_offline_regression_and_verification(self):
        root = self.root / "proof"
        rc, out, err = self._cli([
            "demo-fixtures", str(SPEC), "--baseline-scenario", "denied",
            "--candidate-scenario", "allowed", "--output", str(root), "--json",
        ])
        self.assertEqual((rc, err), (1, ""))
        record = json.loads(out)
        self.assertEqual(record["status"], "verified_synthetic_demo")
        self.assertEqual(record["classification"], "regression")
        self.assertFalse(record["real_security_evidence_verified"])
        self.assertFalse(record["security_test_executed"])
        verify_rc, verified, verify_err = self._cli(["verify-demo", str(root), "--json"])
        self.assertEqual((verify_rc, verify_err), (1, ""))
        self.assertEqual(json.loads(verified), record)

    def test_unchanged_pass_demo_exit_zero(self):
        root = self.root / "same"
        rc, out, err = self._cli([
            "demo-fixtures", str(SPEC), "--baseline-scenario", "denied",
            "--candidate-scenario", "denied", "--output", str(root), "--json",
        ])
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(json.loads(out)["classification"], "unchanged_pass")
        self.assertEqual(self._cli(["verify-demo", str(root)])[0], 0)

    def test_no_existing_directory_is_overwritten(self):
        target = self.root / "existing"
        target.mkdir()
        file = target / "keep.txt"
        file.write_bytes(b"unmodified")
        with self.assertRaises(DemoError):
            create_fixture_demo(self.spec, FixtureScenario.DENIED,
                                FixtureScenario.ALLOWED, target)
        self.assertEqual(file.read_bytes(), b"unmodified")

    def test_untrusted_parent_or_symlink_root_rejected(self):
        parent = self.root / "world-readable"
        parent.mkdir(mode=0o755)
        with self.assertRaises(DemoError):
            create_fixture_demo(self.spec, FixtureScenario.DENIED,
                                FixtureScenario.ALLOWED, parent / "proof")
        target = self.root / "real"
        create_fixture_demo(self.spec, FixtureScenario.DENIED,
                            FixtureScenario.ALLOWED, target)
        alias = self.root / "alias"
        alias.symlink_to(target, target_is_directory=True)
        with self.assertRaises(DemoError):
            verify_fixture_demo(alias)

    def test_partial_failure_preserves_evidence_without_complete_marker(self):
        from slipcage_engine import workflow
        original = workflow._write_private
        target = self.root / "partial"
        def fail_final(fd, name, data):
            if name == "manifest.json":
                raise OSError("injected crash before commit")
            return original(fd, name, data)
        with patch.object(workflow, "_write_private", side_effect=fail_final):
            with self.assertRaises(DemoError):
                create_fixture_demo(self.spec, FixtureScenario.DENIED,
                                    FixtureScenario.ALLOWED, target)
        self.assertTrue((target / "baseline" / "manifest.json").exists())
        self.assertTrue((target / "report.json").exists())
        self.assertFalse((target / "manifest.json").exists())
        with self.assertRaises(DemoError):
            verify_fixture_demo(target)
        with self.assertRaises(DemoError):
            create_fixture_demo(self.spec, FixtureScenario.DENIED,
                                FixtureScenario.ALLOWED, target)

    def test_ambiguous_candidate_never_creates_complete_demo(self):
        target = self.root / "uncertain"
        with self.assertRaisesRegex(DemoError, "incomparable"):
            create_fixture_demo(self.spec, FixtureScenario.DENIED,
                                FixtureScenario.AMBIGUOUS, target)
        self.assertFalse((target / "manifest.json").exists())
        with self.assertRaises(DemoError):
            verify_fixture_demo(target)

    def test_report_or_manifest_tampering_fails_closed(self):
        for which in ("report.json", "report.md", "manifest.json"):
            with self.subTest(which=which):
                target = self.root / which.replace(".", "-")
                create_fixture_demo(self.spec, FixtureScenario.DENIED,
                                    FixtureScenario.ALLOWED, target)
                original = (target / which).read_bytes()
                (target / which).write_bytes(original + b" ")
                with self.assertRaises(DemoError):
                    verify_fixture_demo(target)

    def test_rehashed_fake_report_cannot_be_accepted(self):
        from slipcage_engine.workflow import _canonical, _digest
        target = self.root / "altered"
        create_fixture_demo(self.spec, FixtureScenario.DENIED,
                            FixtureScenario.ALLOWED, target)
        path = target / "report.json"
        fake = json.loads(path.read_bytes())
        fake["comparison"]["classification"] = "unchanged_pass"
        path.write_bytes(_canonical(fake))
        manifest_path = target / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["report_json_sha256"] = _digest(path.read_bytes())
        manifest_path.write_bytes(_canonical(manifest))
        with self.assertRaises(DemoError):
            verify_fixture_demo(target)

    def test_bundle_tampering_fails_demo_reverification(self):
        target = self.root / "tampered-bundle"
        create_fixture_demo(self.spec, FixtureScenario.DENIED,
                            FixtureScenario.ALLOWED, target)
        path = target / "candidate" / "results.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(DemoError):
            verify_fixture_demo(target)

    def test_private_mode_and_stray_files_fail_closed(self):
        target = self.root / "private"
        create_fixture_demo(self.spec, FixtureScenario.DENIED,
                            FixtureScenario.ALLOWED, target)
        (target / "report.md").chmod(0o644)
        with self.assertRaises(DemoError):
            verify_fixture_demo(target)
        (target / "report.md").chmod(0o600)
        (target / "unexpected.txt").write_text("unexpected")
        with self.assertRaises(DemoError):
            verify_fixture_demo(target)

    def test_real_commands_remain_explicitly_disabled(self):
        for command in ("run", "compare", "report"):
            with self.subTest(command=command):
                rc, out, err = self._cli([command])
                self.assertEqual(rc, 3)
                self.assertEqual(out, "")
                self.assertIn("unavailable", err)


if __name__ == "__main__":
    unittest.main()
