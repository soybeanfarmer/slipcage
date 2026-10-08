"""Typed, offline-only security assertion result semantics.

Do not confuse a typed outcome with proof of a security boundary. A future
reviewed environment adapter must verify identities and API responses before
supplying a VERIFIED observation. No code in this module executes assertions,
opens a connection, or collects cryptographically verified evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json

from .specification import (
    ExperimentSpec,
    SpecValidationError,
    validate_spec_bytes,
)

RESULT_API_VERSION = "slipcage.dev/result/v1alpha1"


class ResultValidationError(ValueError):
    """An observation or spec cannot safely yield a typed assertion result."""


class ExpectedDecision(str, Enum):
    ALLOWED = "allowed"
    DENIED = "denied"


class ObservedDecision(str, Enum):
    ALLOWED = "allowed"
    DENIED = "denied"


class ObservationStatus(str, Enum):
    VERIFIED = "verified"
    AMBIGUOUS = "ambiguous"
    EXECUTION_ERROR = "execution_error"
    UNSUPPORTED = "unsupported"


class AssertionOutcome(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    SKIP = "SKIP"
    INCONCLUSIVE = "INCONCLUSIVE"


class ReasonCode(str, Enum):
    MATCHED_EXPECTATION = "matched_expectation"
    UNEXPECTED_BEHAVIOR = "unexpected_behavior"
    AMBIGUOUS_OBSERVATION = "ambiguous_observation"
    EXECUTION_ERROR = "execution_error"
    UNSUPPORTED_PREREQUISITE = "unsupported_prerequisite"


@dataclass(frozen=True, slots=True)
class Observation:
    """A trusted-adapter's normalized observation *claim*, not evidence.

    Never infer VERIFIED from an HTTP status alone. The future adapter must
    check operation, resource, namespace, identity, and API response context.
    """

    status: ObservationStatus
    decision: ObservedDecision | None = None

    def __post_init__(self) -> None:
        if type(self.status) is not ObservationStatus:
            raise ResultValidationError("Observation status must be an ObservationStatus enum")
        if self.status is ObservationStatus.VERIFIED:
            if type(self.decision) is not ObservedDecision:
                raise ResultValidationError("Verified observations require a typed decision")
        elif self.decision is not None:
            raise ResultValidationError("Unverified, error or unsupported observations cannot assert a decision")


@dataclass(frozen=True, slots=True)
class AssertionResult:
    """Immutable outcome tied to a validated spec and one assertion.

    No evidence collection or verification takes place at this stage.
    """

    experiment_id: str
    spec_digest_sha256: str
    assertion_id: str
    expected: ExpectedDecision
    observed: ObservedDecision | None
    observation_status: ObservationStatus
    outcome: AssertionOutcome
    reason_code: ReasonCode

    def __post_init__(self) -> None:
        if type(self.experiment_id) is not str or not self.experiment_id:
            raise ResultValidationError("Invalid experiment ID")
        if (
            type(self.spec_digest_sha256) is not str
            or len(self.spec_digest_sha256) != 64
            or any(char not in "0123456789abcdef" for char in self.spec_digest_sha256)
        ):
            raise ResultValidationError("Invalid specification digest")
        if type(self.assertion_id) is not str or not self.assertion_id:
            raise ResultValidationError("Invalid assertion ID")
        if type(self.expected) is not ExpectedDecision:
            raise ResultValidationError("Expected decision must be a typed enum")
        if type(self.observation_status) is not ObservationStatus:
            raise ResultValidationError("Observation status must be a typed enum")
        if type(self.outcome) is not AssertionOutcome or type(self.reason_code) is not ReasonCode:
            raise ResultValidationError("Outcome and reason must be typed enums")
        if self.observation_status is ObservationStatus.VERIFIED:
            if type(self.observed) is not ObservedDecision:
                raise ResultValidationError("Verified result requires a typed observed decision")
            if self.observed.value == self.expected.value:
                allowed = (AssertionOutcome.PASS, ReasonCode.MATCHED_EXPECTATION)
            else:
                allowed = (AssertionOutcome.FAIL, ReasonCode.UNEXPECTED_BEHAVIOR)
        else:
            if self.observed is not None:
                raise ResultValidationError("Nonverified result cannot assert observed security behavior")
            allowed = {
                ObservationStatus.AMBIGUOUS: (AssertionOutcome.INCONCLUSIVE, ReasonCode.AMBIGUOUS_OBSERVATION),
                ObservationStatus.EXECUTION_ERROR: (AssertionOutcome.ERROR, ReasonCode.EXECUTION_ERROR),
                ObservationStatus.UNSUPPORTED: (AssertionOutcome.SKIP, ReasonCode.UNSUPPORTED_PREREQUISITE),
            }[self.observation_status]
        if (self.outcome, self.reason_code) != allowed:
            raise ResultValidationError("Outcome/reason is inconsistent with the observation")

    def to_dict(self) -> dict[str, str | None]:
        """Stable primitive values, never raw HTTP logs, tokens or observations."""
        return {
            "api_version": RESULT_API_VERSION,
            "experiment_id": self.experiment_id,
            "spec_digest_sha256": self.spec_digest_sha256,
            "assertion_id": self.assertion_id,
            "expected": self.expected.value,
            "observed": self.observed.value if self.observed is not None else None,
            "observation_status": self.observation_status.value,
            "outcome": self.outcome.value,
            "reason_code": self.reason_code.value,
            "evidence_status": "not_collected",
        }

    def canonical_json(self) -> bytes:
        """Stable bytes for future evidence plumbing; not a signed attestation."""
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")


def result_for_observation(
    spec: ExperimentSpec,
    assertion_id: str,
    observation: Observation,
) -> AssertionResult:
    """Normalize a typed observation under the expectations of a valid spec.

    No raw HTTP status, arbitrary outcome string, or unvalidated assertion ID
    is accepted. The supplied Observation is a trusted-adapter claim only;
    calling this helper does not independently prove its provenance.
    """
    if type(spec) is not ExperimentSpec:
        raise ResultValidationError("A validated ExperimentSpec is required")
    if type(assertion_id) is not str or not assertion_id:
        raise ResultValidationError("A nonempty assertion ID is required")
    if type(observation) is not Observation:
        raise ResultValidationError("A typed Observation is required")

    try:
        checked = validate_spec_bytes(spec.canonical_json, extension=".json")
    except (SpecValidationError, TypeError, AttributeError) as exc:
        raise ResultValidationError("The supplied experiment specification is invalid") from exc
    if checked != spec:
        raise ResultValidationError("Experiment specification fields or digest do not match canonical input")

    data = json.loads(spec.canonical_json)
    matched = [row for row in data["assertions"] if row["id"] == assertion_id]
    if len(matched) != 1:
        raise ResultValidationError("Assertion ID is absent or ambiguous in the validated spec")
    expected = ExpectedDecision(matched[0]["expected"])

    if observation.status is ObservationStatus.VERIFIED:
        outcome = (
            AssertionOutcome.PASS
            if expected.value == observation.decision.value
            else AssertionOutcome.FAIL
        )
        reason = (
            ReasonCode.MATCHED_EXPECTATION
            if outcome is AssertionOutcome.PASS
            else ReasonCode.UNEXPECTED_BEHAVIOR
        )
    elif observation.status is ObservationStatus.AMBIGUOUS:
        outcome, reason = AssertionOutcome.INCONCLUSIVE, ReasonCode.AMBIGUOUS_OBSERVATION
    elif observation.status is ObservationStatus.EXECUTION_ERROR:
        outcome, reason = AssertionOutcome.ERROR, ReasonCode.EXECUTION_ERROR
    else:
        outcome, reason = AssertionOutcome.SKIP, ReasonCode.UNSUPPORTED_PREREQUISITE

    return AssertionResult(
        experiment_id=checked.experiment_id,
        spec_digest_sha256=checked.digest_sha256,
        assertion_id=assertion_id,
        expected=expected,
        observed=observation.decision,
        observation_status=observation.status,
        outcome=outcome,
        reason_code=reason,
    )
