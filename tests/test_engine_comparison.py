"""SC-10: differential classification uses reverified synthetic bundles only."""
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from slipcage_engine import load_spec, validate_spec_bytes
from slipcage_engine.cli import main
from slipcage_engine.comparison import (
    ChangeKind, ComparisonReason, compare_fixture_bundles,
)
from slipcage_engine.evidence import verify_bundle, write_fixture_bundle
from slipcage_engine.fixture_executor import FixtureScenario

EXAMPLE = ROOT / "examples" / "experiments" / "rbac-pod-create-denied.yaml"


class DifferentialFixtureTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.base = self.root / "baseline"
        self.candidate = self.root / "candidate"
        self.spec = load_spec(EXAMPLE)

    def make_pair(self, base=FixtureScenario.DENIED,
                  candidate=FixtureScenario.ALLOWED,
                  *, base_spec=None, candidate_spec=None):
        write_fixture_bundle(base_spec or self.spec, base, self.base)
        write_fixture_bundle(candidate_spec or self.spec, candidate, self.candidate)
        return compare_fixture_bundles(self.base, self.candidate)

    def test_all_four_verified_pass_fail_combinations(self):
        cases = (
            (FixtureScenario.DENIED, FixtureScenario.DENIED, ChangeKind.UNCHANGED_PASS),
            (FixtureScenario.DENIED, FixtureScenario.ALLOWED, ChangeKind.REGRESSION),
            (FixtureScenario.ALLOWED, FixtureScenario.DENIED, ChangeKind.IMPROVEMENT),
            (FixtureScenario.ALLOWED, FixtureScenario.ALLOWED, ChangeKind.UNCHANGED_FAIL),
        )
        for idx, (baseline, candidate, kind) in enumerate(cases):
            with self.subTest(baseline=baseline, candidate=candidate):
                left = self.root / f"baseline-{idx}"
                right = self.root / f"candidate-{idx}"
                write_fixture_bundle(self.spec, baseline, left)
                write_fixture_bundle(self.spec, candidate, right)
                compared = compare_fixture_bundles(left, right)
                self.assertEqual(compared.classification, kind)
                self.assertTrue(compared.comparable)
                self.assertIs(compared.reason_code, ComparisonReason.COMPARABLE)
                self.assertEqual(compared.comparisons[0].classification, kind)
                self.assertEqual(compared.comparisons[0].assertion_id, "restricted-create-pod")
                record = compared.to_dict()
                self.assertTrue(record["simulated"])
                self.assertFalse(record["security_test_executed"])
                self.assertFalse(record["real_security_evidence_verified"])
                self.assertEqual(record["comparison_status"], "comparable")
                self.assertEqual(record["experiment_id"], self.spec.experiment_id)
                self.assertEqual(record["spec_digest_sha256"], self.spec.digest_sha256)

    def test_unreliable_observations_always_incomparable(self):
        noncomparable = (
            FixtureScenario.AMBIGUOUS, FixtureScenario.ERROR, FixtureScenario.UNSUPPORTED,
        )
        for invalid in noncomparable:
            for baseline, candidate in (
                (invalid, FixtureScenario.DENIED),
                (FixtureScenario.DENIED, invalid),
                (invalid, FixtureScenario.ALLOWED),
            ):
                with self.subTest(baseline=baseline, candidate=candidate):
                    left = self.root / f"b-{invalid.value}-{candidate.value}-{baseline.value}"
                    right = self.root / f"c-{invalid.value}-{candidate.value}-{baseline.value}"
                    write_fixture_bundle(self.spec, baseline, left)
                    write_fixture_bundle(self.spec, candidate, right)
                    comparison = compare_fixture_bundles(left, right)
                    self.assertFalse(comparison.comparable)
                    self.assertIs(comparison.classification, ChangeKind.INCOMPARABLE)
                    self.assertIs(comparison.reason_code, ComparisonReason.INCONCLUSIVE_OBSERVATION)
                    self.assertEqual(comparison.comparisons[0].classification, ChangeKind.INCOMPARABLE)

    def test_both_missing_are_incomparable_not_a_security_failure(self):
        result = compare_fixture_bundles(self.base, self.candidate)
        self.assertEqual(result.classification, ChangeKind.INCOMPARABLE)
        self.assertIs(result.reason_code, ComparisonReason.BOTH_INVALID)
        self.assertEqual(result.to_dict()["assertions"], [])
        self.assertIsNone(result.to_dict()["spec_digest_sha256"])

    def test_invalid_one_side_reasons_are_distinct_and_do_not_expose_data(self):
        write_fixture_bundle(self.spec, FixtureScenario.DENIED, self.base)
        missing_candidate = compare_fixture_bundles(self.base, self.candidate)
        self.assertIs(missing_candidate.reason_code, ComparisonReason.CANDIDATE_INVALID)
        self.assertTrue(missing_candidate.to_dict()["baseline"]["local_bundle_verified"])
        self.assertFalse(missing_candidate.to_dict()["candidate"]["local_bundle_verified"])
        self.assertNotIn(str(self.root), missing_candidate.canonical_json().decode())
        (self.base / "manifest.json").unlink()
        both = compare_fixture_bundles(self.base, self.candidate)
        self.assertIs(both.reason_code, ComparisonReason.BOTH_INVALID)
        write_fixture_bundle(self.spec, FixtureScenario.ALLOWED, self.candidate)
        baseline_missing = compare_fixture_bundles(self.base, self.candidate)
        self.assertIs(baseline_missing.reason_code, ComparisonReason.BASELINE_INVALID)

    def test_tampered_result_does_not_become_regression(self):
        write_fixture_bundle(self.spec, FixtureScenario.DENIED, self.base)
        write_fixture_bundle(self.spec, FixtureScenario.ALLOWED, self.candidate)
        file = self.candidate / "results.json"
        file.write_bytes(file.read_bytes().replace(b'"FAIL"', b'"PASS"'))
        compared = compare_fixture_bundles(self.base, self.candidate)
        self.assertIs(compared.classification, ChangeKind.INCOMPARABLE)
        self.assertIs(compared.reason_code, ComparisonReason.CANDIDATE_INVALID)
        self.assertEqual(compared.comparisons, ())

    def test_extra_file_and_symlink_bundle_are_incomparable(self):
        self.make_pair()
        (self.candidate / "surprise.json").write_text("tamper", encoding="utf-8")
        self.assertIs(
            compare_fixture_bundles(self.base, self.candidate).reason_code,
            ComparisonReason.CANDIDATE_INVALID,
        )
        link = self.root / "linked"
        link.symlink_to(self.base, target_is_directory=True)
        self.assertIs(
            compare_fixture_bundles(link, self.base).classification,
            ChangeKind.INCOMPARABLE,
        )

    def test_identical_directory_is_not_an_independent_comparison(self):
        write_fixture_bundle(self.spec, FixtureScenario.DENIED, self.base)
        result = compare_fixture_bundles(self.base, self.base)
        self.assertIs(result.classification, ChangeKind.INCOMPARABLE)
        self.assertIs(result.reason_code, ComparisonReason.SAME_BUNDLE)

    def test_same_spec_digest_required_even_if_both_are_valid(self):
        data = json.loads(self.spec.canonical_json)
        data["metadata"]["version"] = "0.2.0"
        alternate = validate_spec_bytes(json.dumps(data).encode(), extension=".json")
        comparison = self.make_pair(candidate_spec=alternate)
        self.assertIs(comparison.classification, ChangeKind.INCOMPARABLE)
        self.assertIs(comparison.reason_code, ComparisonReason.EXPERIMENT_MISMATCH)
        self.assertIsNone(comparison.to_dict()["experiment_id"])

    def test_synthetic_pack_digest_mismatch_fail_closed(self):
        left = write_fixture_bundle(self.spec, FixtureScenario.DENIED, self.base)
        right = write_fixture_bundle(self.spec, FixtureScenario.ALLOWED, self.candidate)
        with patch("slipcage_engine.comparison.verify_bundle",
                   side_effect=[left, replace(right, fixture_digest_sha256="0"*64)]):
            result = compare_fixture_bundles(self.base, self.candidate)
        self.assertIs(result.classification, ChangeKind.INCOMPARABLE)
        self.assertIs(result.reason_code, ComparisonReason.FIXTURE_MISMATCH)

    def test_assertion_identity_mismatch_fail_closed(self):
        left = write_fixture_bundle(self.spec, FixtureScenario.DENIED, self.base)
        right = write_fixture_bundle(self.spec, FixtureScenario.ALLOWED, self.candidate)
        for corrupt in (
            replace(right, assertion_ids=("wrong-assertion",)),
            replace(right, assertion_ids=()),
            replace(right, outcomes=()),
            replace(right, assertion_ids=("first", "first"), outcomes=("PASS", "FAIL")),
        ):
            with self.subTest(corrupt=corrupt):
                with patch("slipcage_engine.comparison.verify_bundle",
                           side_effect=[left, corrupt]):
                    result = compare_fixture_bundles(self.base, self.candidate)
                self.assertIs(result.classification, ChangeKind.INCOMPARABLE)
                self.assertIs(result.reason_code, ComparisonReason.ASSERTION_MISMATCH)

    def test_multiple_assertions_mixed_change_is_not_hidden(self):
        data = json.loads(self.spec.canonical_json)
        data["assertions"].append({
            "id": "create-pod-allowed-control",
            "operation": "create_pod",
            "expected": "allowed",
        })
        spec = validate_spec_bytes(json.dumps(data).encode(), extension=".json")
        result = self.make_pair(base_spec=spec, candidate_spec=spec)
        self.assertIs(result.classification, ChangeKind.MIXED_CHANGE)
        self.assertEqual(
            [item.classification for item in result.comparisons],
            [ChangeKind.REGRESSION, ChangeKind.IMPROVEMENT],
        )
        self.assertEqual(
            [item.assertion_id for item in result.comparisons],
            ["restricted-create-pod", "create-pod-allowed-control"],
        )

    def test_noncomparable_member_makes_entire_comparison_incomparable(self):
        data = json.loads(self.spec.canonical_json)
        data["assertions"].append({
            "id": "second-denial", "operation": "create_pod", "expected": "denied",
        })
        spec = validate_spec_bytes(json.dumps(data).encode(), extension=".json")
        result = self.make_pair(FixtureScenario.DENIED, FixtureScenario.ERROR,
                                base_spec=spec, candidate_spec=spec)
        self.assertIs(result.classification, ChangeKind.INCOMPARABLE)
        self.assertEqual(len(result.comparisons), 2)
        self.assertTrue(all(item.classification is ChangeKind.INCOMPARABLE
                            for item in result.comparisons))

    def test_comparison_read_only_and_canonical_repeated_output(self):
        self.make_pair()
        snapshots = {
            str(path): path.read_bytes()
            for root in (self.base, self.candidate) for path in root.iterdir()
        }
        first = compare_fixture_bundles(self.base, self.candidate)
        second = compare_fixture_bundles(self.base, self.candidate)
        self.assertEqual(first.canonical_json(), second.canonical_json())
        self.assertEqual(json.loads(first.canonical_json()), first.to_dict())
        self.assertEqual(
            snapshots,
            {str(path): path.read_bytes()
             for root in (self.base, self.candidate) for path in root.iterdir()},
        )

    def _cli(self, args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            exit_code = main(args)
        return exit_code, out.getvalue(), err.getvalue()

    def test_cli_regression_nonzero_json_and_no_real_security_claim(self):
        self.make_pair()
        code, out, err = self._cli(["compare-fixtures", str(self.base),
                                    str(self.candidate), "--json"])
        self.assertEqual(code, 1)
        self.assertEqual(err, "")
        record = json.loads(out)
        self.assertEqual(record["classification"], "regression")
        self.assertEqual(record["comparison_status"], "comparable")
        self.assertFalse(record["real_security_evidence_verified"])
        self.assertFalse(record["security_test_executed"])

    def test_cli_incomparable_exit_is_distinct_from_regression(self):
        write_fixture_bundle(self.spec, FixtureScenario.DENIED, self.base)
        code, out, err = self._cli(["compare-fixtures", str(self.base),
                                    str(self.candidate), "--json"])
        self.assertEqual(code, 4)
        self.assertEqual(err, "")
        self.assertEqual(json.loads(out)["classification"], "incomparable")

    def test_cli_improvement_and_unchanged_are_successful(self):
        write_fixture_bundle(self.spec, FixtureScenario.ALLOWED, self.base)
        write_fixture_bundle(self.spec, FixtureScenario.DENIED, self.candidate)
        code, out, err = self._cli(["compare-fixtures", str(self.base), str(self.candidate)])
        self.assertEqual(code, 0)
        self.assertIn("synthetic", out.lower())
        self.assertIn("improvement", out)
        self.assertEqual(err, "")

    def test_cli_real_compare_remains_explicitly_disabled(self):
        code, out, err = self._cli(["compare"])
        self.assertEqual(code, 3)
        self.assertEqual(out, "")
        self.assertIn("unavailable", err)
        for command in ("run", "report"):
            with self.subTest(command=command):
                self.assertEqual(self._cli([command])[0], 3)


if __name__ == "__main__":
    unittest.main()
