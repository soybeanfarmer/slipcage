"""SC-08: only packaged static fixtures, never external workloads or user code.

Deadline checks are cooperative for this bounded in-process interpreter, NOT
OS-enforced preemption suitable for blocking or adversarial future adapters.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from importlib import resources
import hashlib
import json
import time
from typing import Callable

from .results import (
    AssertionOutcome, AssertionResult, Observation, ObservationStatus,
    ObservedDecision, ResultValidationError, result_for_observation,
)
from .specification import ExperimentSpec, SpecValidationError, validate_spec_bytes

FIXTURE_API_VERSION = "slipcage.dev/fixture/v1alpha1"
RUN_API_VERSION = "slipcage.dev/fixture-run/v1alpha1"
MAX_FIXTURE_BYTES = 4096
MAX_FIXTURE_ASSERTIONS = 8
MAX_FIXTURE_WALL_SECONDS = 5


class FixtureExecutionError(ValueError):
    """Fixture data, a caller argument or validated specification is invalid."""


class FixtureScenario(str, Enum):
    """Names are a finite allowlist, NOT external paths or script strings."""
    DENIED = "denied"
    ALLOWED = "allowed"
    AMBIGUOUS = "ambiguous"
    ERROR = "error"
    UNSUPPORTED = "unsupported"


class FixtureRunState(str, Enum):
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise FixtureExecutionError("Duplicate key in packaged fixture")
        value[key] = item
    return value


def _reject_nonfinite(value):
    raise FixtureExecutionError("Nonfinite fixture values are forbidden")


@lru_cache(maxsize=1)
def _load_fixture_catalog() -> tuple[dict[str, Observation], str]:
    """Read and validate fixed installed fixtures, never a requested path."""
    try:
        source = resources.files("slipcage_engine").joinpath(
            "fixtures", "rbac-observations-v1alpha1.json"
        )
        with source.open("rb") as handle:
            raw = handle.read(MAX_FIXTURE_BYTES + 1)
    except OSError as exc:
        raise FixtureExecutionError("Packaged fixture is unavailable") from exc
    if not raw or len(raw) > MAX_FIXTURE_BYTES:
        raise FixtureExecutionError("Packaged fixture exceeds safe size")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_pairs,
                              parse_constant=_reject_nonfinite)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise FixtureExecutionError("Invalid packaged fixture JSON") from exc
    if type(document) is not dict or set(document) != {
        "api_version", "profile_id", "scenarios"
    } or document["api_version"] != FIXTURE_API_VERSION or document["profile_id"] != "kubernetes.rbac":
        raise FixtureExecutionError("Unsupported packaged fixture metadata")
    rows = document["scenarios"]
    if type(rows) is not dict or set(rows) != {scenario.value for scenario in FixtureScenario}:
        raise FixtureExecutionError("Packaged fixture names are invalid")

    expected_rows = {
        FixtureScenario.DENIED: (ObservationStatus.VERIFIED, ObservedDecision.DENIED),
        FixtureScenario.ALLOWED: (ObservationStatus.VERIFIED, ObservedDecision.ALLOWED),
        FixtureScenario.AMBIGUOUS: (ObservationStatus.AMBIGUOUS, None),
        FixtureScenario.ERROR: (ObservationStatus.EXECUTION_ERROR, None),
        FixtureScenario.UNSUPPORTED: (ObservationStatus.UNSUPPORTED, None),
    }
    catalog = {}
    for scenario, expected in expected_rows.items():
        row = rows[scenario.value]
        if type(row) is not dict or set(row) != {"status", "decision"}:
            raise FixtureExecutionError("Packaged observation has invalid fields")
        try:
            status = ObservationStatus(row["status"])
            decision = ObservedDecision(row["decision"]) if row["decision"] is not None else None
            observation = Observation(status, decision)
        except (TypeError, ValueError, ResultValidationError) as exc:
            raise FixtureExecutionError("Packaged observation is invalid") from exc
        if (observation.status, observation.decision) != expected:
            raise FixtureExecutionError("Packaged scenario and observation disagree")
        catalog[scenario.value] = observation
    return catalog, hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class FixtureRun:
    status: FixtureRunState
    scenario: FixtureScenario
    experiment_id: str
    spec_digest_sha256: str
    fixture_digest_sha256: str
    requested_assertions: int
    results: tuple[AssertionResult, ...]
    max_wall_seconds: int

    def to_dict(self) -> dict:
        return {
            "api_version": RUN_API_VERSION,
            "mode": "synthetic_offline_fixture",
            "simulated": True,
            "security_test_executed": False,
            "evidence_status": "not_collected",
            "state": self.status.value,
            "scenario": self.scenario.value,
            "experiment_id": self.experiment_id,
            "spec_digest_sha256": self.spec_digest_sha256,
            "fixture_digest_sha256": self.fixture_digest_sha256,
            "requested_assertions": self.requested_assertions,
            "completed_assertions": len(self.results),
            "max_wall_seconds": self.max_wall_seconds,
            "assertions": [entry.to_dict() for entry in self.results],
        }

    def canonical_json(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")


def run_fixture(
    spec: ExperimentSpec,
    scenario: FixtureScenario,
    *,
    clock: Callable[[], float] = time.monotonic,
    cancelled: Callable[[], bool] | None = None,
) -> FixtureRun:
    """Interpret one finite scenario for all assertions, with bounded work.

    clock/cancelled are trusted Python test hooks only. No untrusted spec can
    inject a callable, executable payload, fixture file path, or adapter.
    """
    if type(spec) is not ExperimentSpec or type(scenario) is not FixtureScenario:
        raise FixtureExecutionError("A validated spec and typed scenario are required")
    try:
        checked = validate_spec_bytes(spec.canonical_json, extension=".json")
    except (SpecValidationError, TypeError, AttributeError) as exc:
        raise FixtureExecutionError("Invalid experiment specification") from exc
    if checked != spec:
        raise FixtureExecutionError("Spec identity, digest or content mismatch")
    document = json.loads(spec.canonical_json)
    if document["profile"]["id"] != "kubernetes.rbac":
        raise FixtureExecutionError("Unsupported fixture profile")
    assertion_ids = tuple(entry["id"] for entry in document["assertions"])
    if not 1 <= len(assertion_ids) <= MAX_FIXTURE_ASSERTIONS:
        raise FixtureExecutionError("Assertion count exceeds fixture budget")
    catalog, fixture_digest = _load_fixture_catalog()
    observation = catalog[scenario.value]
    seconds = min(document["limits"]["timeout_seconds"], MAX_FIXTURE_WALL_SECONDS)
    stop_requested = cancelled if cancelled is not None else lambda: False
    deadline = clock() + seconds
    results: list[AssertionResult] = []
    state = FixtureRunState.COMPLETED

    for assertion_id in assertion_ids:
        if stop_requested():
            state = FixtureRunState.CANCELLED
            break
        if clock() >= deadline:
            state = FixtureRunState.TIMED_OUT
            break
        result = result_for_observation(spec, assertion_id, observation)
        if stop_requested():
            state = FixtureRunState.CANCELLED
            break
        if clock() >= deadline:
            state = FixtureRunState.TIMED_OUT
            break
        results.append(result)

    return FixtureRun(
        status=state, scenario=scenario, experiment_id=spec.experiment_id,
        spec_digest_sha256=spec.digest_sha256,
        fixture_digest_sha256=fixture_digest,
        requested_assertions=len(assertion_ids), results=tuple(results),
        max_wall_seconds=seconds,
    )
