"""SC-08 bounded packaged-fixture interpreter: no VM, network or shell."""
from dataclasses import FrozenInstanceError, replace
from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from slipcage_engine import (
    AssertionOutcome, FixtureExecutionError, FixtureRunState, FixtureScenario,
    load_spec, run_fixture, validate_spec_bytes,
)
from slipcage_engine.cli import main
from slipcage_engine.fixture_executor import (
    MAX_FIXTURE_WALL_SECONDS, _load_fixture_catalog,
)
from slipcage_engine.specification import ExperimentSpec

EXAMPLE = ROOT / "examples/experiments/rbac-pod-create-denied.yaml"


class FixtureExecutorTests(unittest.TestCase):
    def setUp(self):
        self.spec = load_spec(EXAMPLE)

    def test_denied_fixture_is_synthetic_pass(self):
        run = run_fixture(self.spec, FixtureScenario.DENIED)
        self.assertIs(run.status, FixtureRunState.COMPLETED)
        self.assertEqual(len(run.results), 1)
        self.assertIs(run.results[0].outcome, AssertionOutcome.PASS)
        record = run.to_dict()
        self.assertEqual(record["mode"], "synthetic_offline_fixture")
        self.assertTrue(record["simulated"])
        self.assertFalse(record["security_test_executed"])
        self.assertEqual(record["evidence_status"], "not_collected")
        self.assertEqual(record["assertions"][0]["evidence_status"], "not_collected")
        self.assertLessEqual(record["max_wall_seconds"], MAX_FIXTURE_WALL_SECONDS)

    def test_allowed_fixture_is_synthetic_fail_not_infrastructure_error(self):
        run = run_fixture(self.spec, FixtureScenario.ALLOWED)
        self.assertIs(run.results[0].outcome, AssertionOutcome.FAIL)
        self.assertEqual(run.to_dict()["state"], "completed")

    def test_ambiguous_error_and_unsupported_remain_distinct(self):
        for scenario, expected in [
            (FixtureScenario.AMBIGUOUS, AssertionOutcome.INCONCLUSIVE),
            (FixtureScenario.ERROR, AssertionOutcome.ERROR),
            (FixtureScenario.UNSUPPORTED, AssertionOutcome.SKIP),
        ]:
            with self.subTest(scenario=scenario):
                run = run_fixture(self.spec, scenario)
                self.assertIs(run.status, FixtureRunState.COMPLETED)
                self.assertIs(run.results[0].outcome, expected)
                self.assertIsNone(run.results[0].observed)

    def test_multiple_assertions_bounded_and_identity_preserved(self):
        content = json.loads(self.spec.canonical_json)
        content["assertions"].append({
            "id": "restricted-create-pod-again",
            "operation": "create_pod",
            "expected": "allowed",
        })
        spec = validate_spec_bytes(json.dumps(content).encode(), extension=".json")
        run = run_fixture(spec, FixtureScenario.DENIED)
        self.assertEqual(run.requested_assertions, 2)
        self.assertEqual([r.assertion_id for r in run.results],
                         ["restricted-create-pod", "restricted-create-pod-again"])
        self.assertEqual([r.outcome for r in run.results],
                         [AssertionOutcome.PASS, AssertionOutcome.FAIL])
        self.assertTrue(all(r.spec_digest_sha256 == spec.digest_sha256 for r in run.results))

    def test_cancel_before_first_assertion_records_no_false_success(self):
        run = run_fixture(self.spec, FixtureScenario.DENIED, cancelled=lambda: True)
        self.assertIs(run.status, FixtureRunState.CANCELLED)
        self.assertEqual(run.requested_assertions, 1)
        self.assertEqual(len(run.results), 0)
        self.assertFalse(run.to_dict()["security_test_executed"])

    def test_cancel_between_assertions_preserves_only_completed_results(self):
        content = json.loads(self.spec.canonical_json)
        content["assertions"].append({
            "id": "other-assertion", "operation": "create_pod", "expected": "denied",
        })
        spec = validate_spec_bytes(json.dumps(content).encode(), extension=".json")
        calls = [False, False, True]
        def cancelled():
            return calls.pop(0)
        run = run_fixture(spec, FixtureScenario.DENIED, cancelled=cancelled)
        self.assertIs(run.status, FixtureRunState.CANCELLED)
        self.assertEqual(len(run.results), 1)
        self.assertEqual(run.results[0].assertion_id, "restricted-create-pod")

    def test_expired_before_first_assertion_records_no_result(self):
        clock_values = iter((0.0, 6.0))
        run = run_fixture(self.spec, FixtureScenario.DENIED, clock=lambda: next(clock_values))
        self.assertIs(run.status, FixtureRunState.TIMED_OUT)
        self.assertEqual(len(run.results), 0)

    def test_expired_after_observation_discarded(self):
        clock_values = iter((0.0, 0.0, 6.0))
        run = run_fixture(self.spec, FixtureScenario.DENIED, clock=lambda: next(clock_values))
        self.assertIs(run.status, FixtureRunState.TIMED_OUT)
        self.assertEqual(len(run.results), 0)

    def test_spec_timeout_below_cap_is_honored(self):
        content = json.loads(self.spec.canonical_json)
        content["limits"]["timeout_seconds"] = 1
        spec = validate_spec_bytes(json.dumps(content).encode(), extension=".json")
        run = run_fixture(spec, FixtureScenario.DENIED)
        self.assertEqual(run.max_wall_seconds, 1)

    def test_canonical_output_is_repeatable_without_clock_metadata(self):
        first = run_fixture(self.spec, FixtureScenario.DENIED)
        second = run_fixture(self.spec, FixtureScenario.DENIED)
        self.assertEqual(first.canonical_json(), second.canonical_json())
        result = json.loads(first.canonical_json())
        self.assertEqual(len(result["fixture_digest_sha256"]), 64)
        self.assertNotIn("kubeconfig", first.canonical_json().decode())
        self.assertLess(len(first.canonical_json()), 3000)

    def test_unknown_or_untyped_scenario_rejected(self):
        for scenario in ("denied", "../outside", "", None):
            with self.subTest(scenario=scenario), self.assertRaises(FixtureExecutionError):
                run_fixture(self.spec, scenario)

    def test_spoofed_spec_digest_and_canonical_data_fail_closed(self):
        for changes in [{"digest_sha256": "0"*64}, {"canonical_json": b"{}"}]:
            with self.subTest(changes=changes), self.assertRaises(FixtureExecutionError):
                run_fixture(replace(self.spec, **changes), FixtureScenario.DENIED)
        with self.assertRaises(FixtureExecutionError):
            run_fixture(None, FixtureScenario.DENIED)

    def test_missing_or_broken_packaged_fixture_fails_closed(self):
        _load_fixture_catalog.cache_clear()
        with patch("slipcage_engine.fixture_executor.resources.files",
                   side_effect=OSError("missing fixture")):
            with self.assertRaisesRegex(FixtureExecutionError, "unavailable"):
                run_fixture(self.spec, FixtureScenario.DENIED)
        _load_fixture_catalog.cache_clear()
        self.assertEqual(len(_load_fixture_catalog()[1]), 64)

    def test_run_records_are_immutable(self):
        run = run_fixture(self.spec, FixtureScenario.DENIED)
        with self.assertRaises(FrozenInstanceError):
            run.status = FixtureRunState.TIMED_OUT

    def test_cli_fixture_success_and_nonpass_exit_codes(self):
        for scenario, expected_exit in [
            ("denied", 0), ("allowed", 1), ("ambiguous", 1),
            ("error", 1), ("unsupported", 1),
        ]:
            with self.subTest(scenario=scenario):
                out, err = io.StringIO(), io.StringIO()
                with redirect_stdout(out), redirect_stderr(err):
                    rc = main(["run-fixture", str(EXAMPLE), "--scenario", scenario, "--json"])
                self.assertEqual(rc, expected_exit)
                self.assertEqual(err.getvalue(), "")
                record = json.loads(out.getvalue())
                self.assertTrue(record["simulated"])
                self.assertFalse(record["security_test_executed"])
                self.assertEqual(record["evidence_status"], "not_collected")

    def test_cli_refuses_real_run_compare_report(self):
        for command in ("run", "compare", "report"):
            with self.subTest(command=command):
                out, err = io.StringIO(), io.StringIO()
                with redirect_stdout(out), redirect_stderr(err):
                    rc = main([command])
                self.assertEqual(rc, 3)
                self.assertEqual(out.getvalue(), "")
                self.assertIn("unavailable", err.getvalue())

    def test_cli_missing_file_does_not_claim_success(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(["run-fixture", "/no/such/file.json", "--scenario", "denied", "--json"])
        self.assertEqual(rc, 2)
        self.assertFalse(out.getvalue())

if __name__ == "__main__":
    unittest.main()
