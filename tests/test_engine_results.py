"""SC-07: assertion results are typed, fail closed and do not execute workloads."""
from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from slipcage_engine import load_spec
from slipcage_engine.results import (
    AssertionOutcome,
    AssertionResult,
    ExpectedDecision,
    Observation,
    ObservedDecision,
    ObservationStatus,
    ReasonCode,
    ResultValidationError,
    result_for_observation,
)
from slipcage_engine.specification import ExperimentSpec, validate_spec_bytes

EXAMPLE = ROOT / "examples" / "experiments" / "rbac-pod-create-denied.yaml"
ASSERTION = "restricted-create-pod"


class TypedAssertionResultTests(unittest.TestCase):
    def setUp(self):
        self.spec = load_spec(EXAMPLE)

    def evaluate(self, status, decision=None, *, spec=None):
        return result_for_observation(
            self.spec if spec is None else spec,
            ASSERTION,
            Observation(status, decision),
        )

    def test_expected_denial_is_pass_only_for_verified_denial(self):
        result = self.evaluate(ObservationStatus.VERIFIED, ObservedDecision.DENIED)
        self.assertIs(result.outcome, AssertionOutcome.PASS)
        self.assertIs(result.reason_code, ReasonCode.MATCHED_EXPECTATION)
        self.assertIs(result.expected, ExpectedDecision.DENIED)
        self.assertIs(result.observed, ObservedDecision.DENIED)
        self.assertEqual(result.spec_digest_sha256, self.spec.digest_sha256)

    def test_unexpected_allowed_is_fail_not_error(self):
        result = self.evaluate(ObservationStatus.VERIFIED, ObservedDecision.ALLOWED)
        self.assertIs(result.outcome, AssertionOutcome.FAIL)
        self.assertIs(result.reason_code, ReasonCode.UNEXPECTED_BEHAVIOR)

    def test_expected_allowed_inverse_semantics(self):
        example = json.loads(self.spec.canonical_json)
        example["assertions"][0]["expected"] = "allowed"
        spec = validate_spec_bytes(json.dumps(example).encode(), extension=".json")
        self.assertIs(
            self.evaluate(ObservationStatus.VERIFIED, ObservedDecision.ALLOWED, spec=spec).outcome,
            AssertionOutcome.PASS,
        )
        self.assertIs(
            self.evaluate(ObservationStatus.VERIFIED, ObservedDecision.DENIED, spec=spec).outcome,
            AssertionOutcome.FAIL,
        )

    def test_ambiguous_cannot_create_false_pass_or_failure(self):
        result = self.evaluate(ObservationStatus.AMBIGUOUS)
        self.assertIs(result.outcome, AssertionOutcome.INCONCLUSIVE)
        self.assertIsNone(result.observed)
        self.assertEqual(result.to_dict()["evidence_status"], "not_collected")

    def test_infrastructure_error_is_not_security_failure(self):
        result = self.evaluate(ObservationStatus.EXECUTION_ERROR)
        self.assertIs(result.outcome, AssertionOutcome.ERROR)
        self.assertIs(result.reason_code, ReasonCode.EXECUTION_ERROR)

    def test_unsupported_prerequisite_skips_without_asserting_behavior(self):
        result = self.evaluate(ObservationStatus.UNSUPPORTED)
        self.assertIs(result.outcome, AssertionOutcome.SKIP)
        self.assertIsNone(result.observed)

    def test_verified_requires_typed_decision(self):
        for decision in (None, "denied", "403", False, 403):
            with self.subTest(decision=decision), self.assertRaises(ResultValidationError):
                Observation(ObservationStatus.VERIFIED, decision)

    def test_inconclusive_error_skip_refuse_security_decision(self):
        for status in (
            ObservationStatus.AMBIGUOUS,
            ObservationStatus.EXECUTION_ERROR,
            ObservationStatus.UNSUPPORTED,
        ):
            for decision in (ObservedDecision.ALLOWED, ObservedDecision.DENIED):
                with self.subTest(status=status, decision=decision), self.assertRaises(ResultValidationError):
                    Observation(status, decision)

    def test_unknown_states_and_untyped_inputs_refused(self):
        for state in ("verified", "", None, 1, True):
            with self.subTest(state=state), self.assertRaises(ResultValidationError):
                Observation(state)
        for spec, aid, obs in (
            (None, ASSERTION, Observation(ObservationStatus.AMBIGUOUS)),
            (self.spec, 123, Observation(ObservationStatus.AMBIGUOUS)),
            (self.spec, ASSERTION, {"status": "verified", "decision": "denied"}),
        ):
            with self.subTest(spec=spec, aid=aid, obs=obs), self.assertRaises(ResultValidationError):
                result_for_observation(spec, aid, obs)

    def test_assertion_must_exist_in_validated_definition(self):
        for name in ("missing-assertion", "", "../etc/passwd"):
            with self.subTest(name=name), self.assertRaises(ResultValidationError):
                result_for_observation(
                    self.spec, name, Observation(ObservationStatus.AMBIGUOUS)
                )

    def test_spoofed_spec_fields_cannot_be_used(self):
        for replacement in (
            {"digest_sha256": "0" * 64},
            {"experiment_id": "kubernetes.rbac.spoofed"},
            {"version": "9.9.9"},
            {"canonical_json": b"{}"},
        ):
            with self.subTest(replacement=replacement), self.assertRaises(ResultValidationError):
                self.evaluate(ObservationStatus.VERIFIED, ObservedDecision.DENIED,
                              spec=replace(self.spec, **replacement))

    def test_outcome_result_is_immutable_and_consistent(self):
        result = self.evaluate(ObservationStatus.VERIFIED, ObservedDecision.DENIED)
        with self.assertRaises(FrozenInstanceError):
            result.outcome = AssertionOutcome.FAIL
        for changed in (
            {"outcome": AssertionOutcome.FAIL},
            {"reason_code": ReasonCode.EXECUTION_ERROR},
            {"observed": None},
            {"expected": ExpectedDecision.ALLOWED},
            {"observation_status": ObservationStatus.EXECUTION_ERROR},
            {"outcome": "PASS"},
            {"spec_digest_sha256": "bogus"},
        ):
            with self.subTest(changed=changed), self.assertRaises(ResultValidationError):
                replace(result, **changed)

    def test_serialization_is_stable_bounded_and_never_claims_evidence(self):
        result = self.evaluate(ObservationStatus.VERIFIED, ObservedDecision.DENIED)
        canonical = result.canonical_json()
        self.assertEqual(canonical, result.canonical_json())
        record = json.loads(canonical)
        self.assertEqual(record["api_version"], "slipcage.dev/result/v1alpha1")
        self.assertEqual(record["outcome"], "PASS")
        self.assertEqual(record["observation_status"], "verified")
        self.assertEqual(record["evidence_status"], "not_collected")
        self.assertEqual(record["reason_code"], "matched_expectation")
        self.assertNotIn("kubeconfig", record)
        self.assertLess(len(canonical), 1024)

    def test_constructor_rejects_untyped_and_inconsistent_result(self):
        valid = self.evaluate(ObservationStatus.UNSUPPORTED)
        with self.assertRaises(ResultValidationError):
            replace(valid, outcome=AssertionOutcome.PASS)
        with self.assertRaises(ResultValidationError):
            replace(valid, observed=ObservedDecision.DENIED)
        with self.assertRaises(ResultValidationError):
            replace(valid, reason_code=ReasonCode.MATCHED_EXPECTATION)
        with self.assertRaises(ResultValidationError):
            replace(valid, observation_status="unsupported")

if __name__ == "__main__":
    unittest.main()
