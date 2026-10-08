"""SC-10: conservative differential comparison of OFFLINE fixture bundles.

Only paths to existing SC-09 private synthetic bundles are accepted. Each
bundle is reverified against its packaged scenario before classification.
No subprocess, Kubernetes, QEMU, network, signing or untrusted plugin execution.

The output is synthetic test-fixture behavior, NOT proof of real security
regression. Broken/incomplete evidence always yields INCOMPARABLE.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
import os
from pathlib import Path

from .evidence import BundleError, BundleVerification, verify_bundle
from .fixture_executor import MAX_FIXTURE_ASSERTIONS
from .results import AssertionOutcome

COMPARISON_API_VERSION = "slipcage.dev/fixture-comparison/v1alpha1"


class ChangeKind(str, Enum):
    UNCHANGED_PASS = "unchanged_pass"
    REGRESSION = "regression"
    IMPROVEMENT = "improvement"
    UNCHANGED_FAIL = "unchanged_fail"
    MIXED_CHANGE = "mixed_change"
    INCOMPARABLE = "incomparable"


class ComparisonReason(str, Enum):
    COMPARABLE = "comparable"
    BASELINE_INVALID = "baseline_bundle_invalid"
    CANDIDATE_INVALID = "candidate_bundle_invalid"
    BOTH_INVALID = "both_bundles_invalid"
    SAME_BUNDLE = "same_bundle"
    INPUT_UNAVAILABLE = "input_unavailable"
    EXPERIMENT_MISMATCH = "experiment_spec_mismatch"
    FIXTURE_MISMATCH = "fixture_version_mismatch"
    ASSERTION_MISMATCH = "assertion_identity_mismatch"
    INCONCLUSIVE_OBSERVATION = "noncomparable_assertion_outcome"


@dataclass(frozen=True, slots=True)
class AssertionDifference:
    assertion_id: str
    baseline_outcome: str
    candidate_outcome: str
    classification: ChangeKind

    def to_dict(self) -> dict:
        return {
            "assertion_id": self.assertion_id,
            "baseline_outcome": self.baseline_outcome,
            "candidate_outcome": self.candidate_outcome,
            "classification": self.classification.value,
        }


@dataclass(frozen=True, slots=True)
class FixtureComparison:
    classification: ChangeKind
    reason_code: ComparisonReason
    baseline: BundleVerification | None
    candidate: BundleVerification | None
    comparisons: tuple[AssertionDifference, ...]

    @property
    def comparable(self) -> bool:
        return self.classification is not ChangeKind.INCOMPARABLE

    def to_dict(self) -> dict:
        """Never claim real security execution or externally attested evidence."""
        b, c = self.baseline, self.candidate
        matching_spec = bool(
            b is not None and c is not None
            and b.experiment_id == c.experiment_id
            and b.spec_digest_sha256 == c.spec_digest_sha256
        )
        matching_fixture = bool(
            matching_spec and b.fixture_digest_sha256 == c.fixture_digest_sha256
        )

        def side(value: BundleVerification | None) -> dict:
            if value is None:
                return {"local_bundle_verified": False}
            return {
                "local_bundle_verified": True,
                "scenario": value.scenario,
                "manifest_digest_sha256": value.manifest_digest_sha256,
                "spec_digest_sha256": value.spec_digest_sha256,
                "fixture_digest_sha256": value.fixture_digest_sha256,
            }

        return {
            "api_version": COMPARISON_API_VERSION,
            "mode": "synthetic_offline_fixture_comparison",
            "simulated": True,
            "security_test_executed": False,
            "real_security_evidence_verified": False,
            "comparison_status": "comparable" if self.comparable else "incomparable",
            "classification": self.classification.value,
            "reason_code": self.reason_code.value,
            "experiment_id": b.experiment_id if matching_spec else None,
            "spec_digest_sha256": b.spec_digest_sha256 if matching_spec else None,
            "fixture_digest_sha256": b.fixture_digest_sha256 if matching_fixture else None,
            "baseline": side(b),
            "candidate": side(c),
            "assertions": [item.to_dict() for item in self.comparisons],
        }

    def canonical_json(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")


def _classify_one(baseline: str, candidate: str) -> ChangeKind:
    """Only verified PASS/FAIL fixture results can be compared."""
    accepted = (AssertionOutcome.PASS.value, AssertionOutcome.FAIL.value)
    if baseline not in accepted or candidate not in accepted:
        return ChangeKind.INCOMPARABLE
    if baseline == candidate:
        return (
            ChangeKind.UNCHANGED_PASS
            if baseline == AssertionOutcome.PASS.value
            else ChangeKind.UNCHANGED_FAIL
        )
    return (
        ChangeKind.REGRESSION
        if baseline == AssertionOutcome.PASS.value
        else ChangeKind.IMPROVEMENT
    )


def _result(
    classification: ChangeKind, reason: ComparisonReason,
    baseline: BundleVerification | None, candidate: BundleVerification | None,
    comparisons: tuple[AssertionDifference, ...] = (),
) -> FixtureComparison:
    return FixtureComparison(classification, reason, baseline, candidate, comparisons)


def compare_fixture_bundles(
    baseline_directory: str | Path,
    candidate_directory: str | Path,
) -> FixtureComparison:
    """Verify both synthetic bundles independently before examining outcomes.

    A failed verification yields an explicit typed INCOMPARABLE with no
    arbitrary filesystem error text or unverified result values. The two
    bundles must describe exactly the same experiment/pack and assertions;
    future real-environment comparisons require a different adapter.
    """
    b: BundleVerification | None
    c: BundleVerification | None
    try:
        b = verify_bundle(baseline_directory)
    except (BundleError, OSError):
        b = None
    try:
        c = verify_bundle(candidate_directory)
    except (BundleError, OSError):
        c = None

    if b is None or c is None:
        reason = (
            ComparisonReason.BOTH_INVALID if b is None and c is None
            else ComparisonReason.BASELINE_INVALID if b is None
            else ComparisonReason.CANDIDATE_INVALID
        )
        return _result(ChangeKind.INCOMPARABLE, reason, b, c)

    try:
        if os.path.samefile(baseline_directory, candidate_directory):
            return _result(ChangeKind.INCOMPARABLE, ComparisonReason.SAME_BUNDLE, b, c)
    except OSError:
        return _result(ChangeKind.INCOMPARABLE, ComparisonReason.INPUT_UNAVAILABLE, b, c)

    if b.experiment_id != c.experiment_id or b.spec_digest_sha256 != c.spec_digest_sha256:
        return _result(ChangeKind.INCOMPARABLE, ComparisonReason.EXPERIMENT_MISMATCH, b, c)
    if b.fixture_digest_sha256 != c.fixture_digest_sha256:
        return _result(ChangeKind.INCOMPARABLE, ComparisonReason.FIXTURE_MISMATCH, b, c)

    if (
        not 1 <= len(b.assertion_ids) <= MAX_FIXTURE_ASSERTIONS
        or b.assertion_ids != c.assertion_ids
        or len(set(b.assertion_ids)) != len(b.assertion_ids)
        or len(b.outcomes) != len(b.assertion_ids)
        or len(c.outcomes) != len(c.assertion_ids)
    ):
        return _result(ChangeKind.INCOMPARABLE, ComparisonReason.ASSERTION_MISMATCH, b, c)

    comparisons = tuple(
        AssertionDifference(assertion_id, baseline, candidate, _classify_one(baseline, candidate))
        for assertion_id, baseline, candidate in zip(b.assertion_ids, b.outcomes, c.outcomes)
    )
    kinds = {item.classification for item in comparisons}
    if ChangeKind.INCOMPARABLE in kinds:
        return _result(ChangeKind.INCOMPARABLE, ComparisonReason.INCONCLUSIVE_OBSERVATION, b, c, comparisons)
    if ChangeKind.REGRESSION in kinds and ChangeKind.IMPROVEMENT in kinds:
        classification = ChangeKind.MIXED_CHANGE
    elif ChangeKind.REGRESSION in kinds:
        classification = ChangeKind.REGRESSION
    elif ChangeKind.IMPROVEMENT in kinds:
        classification = ChangeKind.IMPROVEMENT
    elif ChangeKind.UNCHANGED_FAIL in kinds:
        classification = ChangeKind.UNCHANGED_FAIL
    else:
        classification = ChangeKind.UNCHANGED_PASS
    return _result(classification, ComparisonReason.COMPARABLE, b, c, comparisons)
