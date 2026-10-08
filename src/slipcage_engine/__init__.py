"""Portable Slipcage experiment contracts; no execution adapters in this release."""

__version__ = "0.1.0a1"

from .specification import (
    ExperimentSpec,
    SpecValidationError,
    load_spec,
    validate_spec_bytes,
)

from .results import (
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

__all__ = [
    "ExperimentSpec", "SpecValidationError", "load_spec", "validate_spec_bytes",
    "AssertionOutcome", "AssertionResult", "ExpectedDecision", "Observation",
    "ObservedDecision", "ObservationStatus", "ReasonCode", "ResultValidationError",
    "result_for_observation",
]
