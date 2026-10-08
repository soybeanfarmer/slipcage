"""Portable Slipcage experiment contracts and offline fixture simulation."""

__version__ = "0.1.0a1"

from .specification import (
    ExperimentSpec, SpecValidationError, load_spec, validate_spec_bytes,
)
from .results import (
    AssertionOutcome, AssertionResult, ExpectedDecision, Observation,
    ObservedDecision, ObservationStatus, ReasonCode, ResultValidationError,
    result_for_observation,
)
from .fixture_executor import (
    FixtureExecutionError, FixtureRun, FixtureRunState, FixtureScenario,
    run_fixture,
)

__all__ = [
    "ExperimentSpec", "SpecValidationError", "load_spec", "validate_spec_bytes",
    "AssertionOutcome", "AssertionResult", "ExpectedDecision", "Observation",
    "ObservedDecision", "ObservationStatus", "ReasonCode", "ResultValidationError",
    "result_for_observation", "FixtureExecutionError", "FixtureRun",
    "FixtureRunState", "FixtureScenario", "run_fixture",
]
