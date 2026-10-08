"""SC-13a: bounded, fully IN-MEMORY disposable VM lifecycle simulation.

No implementation in this module can boot a VM, allocate disk, run a command,
open /dev/kvm, make a network connection, or delete any host evidence.
The closed scenario enum is test input, NOT permission to execute a workload.

An actual QEMU/K3s backend is deliberately absent until real image provenance,
resource measurements, provider permission, isolation and operator-run test
gates are approved in a separate PR.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json

from .vm_plan import K3sVMPlan, VMPlanError, validate_vm_plan_bytes

API_VERSION = "slipcage.dev/vm-lifecycle-simulation/v1alpha1"
MAX_EVENTS = 12


class VMLifecycleError(ValueError):
    """Invalid plan, transition, scenario, or inconsistent synthetic result."""


class VMSimulationScenario(str, Enum):
    SUCCESS = "success"
    START_FAILURE = "start_failure"
    RUNTIME_FAILURE = "runtime_failure"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    CLEANUP_FAILURE = "cleanup_failure"
    CAPACITY_BLOCKED = "capacity_blocked"


class VMFinalState(str, Enum):
    SIMULATED_TERMINATED = "simulated_terminated"
    SIMULATED_BLOCKED = "simulated_blocked"
    SIMULATED_CLEANUP_UNRESOLVED = "simulated_cleanup_unresolved"


class VMFailureReason(str, Enum):
    NONE = "none"
    REPORTED_CAPACITY_BLOCK = "reported_capacity_block"
    START_FAILED = "start_failed"
    RUNTIME_FAILED = "runtime_failed"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    USER_CANCELLED = "user_cancelled"
    CLEANUP_FAILED = "cleanup_failed"


@dataclass(frozen=True, slots=True)
class VMEvent:
    sequence: int
    phase: str
    detail: str

    def to_dict(self) -> dict:
        return {
            "sequence": self.sequence,
            "phase": self.phase,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class VMLifecycleSimulation:
    plan_id: str
    plan_digest_sha256: str
    scenario: VMSimulationScenario
    final_state: VMFinalState
    failure_reason: VMFailureReason
    allocation_simulated: bool
    cleanup_attempted: bool
    cleanup_simulated_successful: bool
    simulated_elapsed_seconds: int
    max_runtime_seconds: int
    events: tuple[VMEvent, ...]

    def __post_init__(self):
        if type(self.scenario) is not VMSimulationScenario:
            raise VMLifecycleError("Scenario must be a typed enum")
        if type(self.final_state) is not VMFinalState or type(self.failure_reason) is not VMFailureReason:
            raise VMLifecycleError("State and reason must be typed enums")
        if not 1 <= len(self.events) <= MAX_EVENTS:
            raise VMLifecycleError("Lifecycle event count outside bounds")
        if tuple(e.sequence for e in self.events) != tuple(range(1, len(self.events) + 1)):
            raise VMLifecycleError("Lifecycle event sequence invalid")
        if self.final_state is VMFinalState.SIMULATED_TERMINATED:
            if not (self.allocation_simulated and self.cleanup_attempted
                    and self.cleanup_simulated_successful):
                raise VMLifecycleError("Terminated simulation requires cleanup")
        elif self.final_state is VMFinalState.SIMULATED_BLOCKED:
            if self.allocation_simulated or self.cleanup_attempted or self.cleanup_simulated_successful:
                raise VMLifecycleError("Blocked simulation cannot allocate or clean up")
        else:
            if not self.allocation_simulated or not self.cleanup_attempted or self.cleanup_simulated_successful:
                raise VMLifecycleError("Unresolved cleanup must be explicitly recorded")
        if self.failure_reason is VMFailureReason.CLEANUP_FAILED:
            if self.final_state is not VMFinalState.SIMULATED_CLEANUP_UNRESOLVED:
                raise VMLifecycleError("Cleanup failure cannot be marked terminated")
        elif self.final_state is VMFinalState.SIMULATED_CLEANUP_UNRESOLVED:
            raise VMLifecycleError("Unresolved cleanup must have cleanup_failed reason")

    def to_dict(self) -> dict:
        return {
            "api_version": API_VERSION,
            "kind": "offline_vm_lifecycle_simulation",
            "plan_id": self.plan_id,
            "plan_digest_sha256": self.plan_digest_sha256,
            "scenario": self.scenario.value,
            "final_state": self.final_state.value,
            "failure_reason": self.failure_reason.value,
            "allocation_simulated": self.allocation_simulated,
            "cleanup_attempted": self.cleanup_attempted,
            "cleanup_simulated_successful": self.cleanup_simulated_successful,
            "operator_attention_required": self.final_state is VMFinalState.SIMULATED_CLEANUP_UNRESOLVED,
            "simulated_elapsed_seconds": self.simulated_elapsed_seconds,
            "max_runtime_seconds": self.max_runtime_seconds,
            "maximum_concurrent_vms": 1,
            "events": [entry.to_dict() for entry in self.events],
            "simulated": True,
            "real_vm_allocated": False,
            "real_vm_booted": False,
            "host_storage_modified": False,
            "guest_network_modified": False,
            "provider_permission_verified": False,
            "artifacts_verified": False,
            "execution_authorized": False,
            "cleanup_verified_on_host": False,
        }

    def canonical_json(self) -> bytes:
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("ascii")


def simulate_vm_lifecycle(plan: K3sVMPlan,
                          scenario: VMSimulationScenario) -> VMLifecycleSimulation:
    """Run a finite deterministic state machine, NO side effects.

    The state machine is a test double for future resource/control-plane code.
    Timeout and cancellation are simulated transitions, NOT real watchdogs.
    """
    if type(plan) is not K3sVMPlan or type(scenario) is not VMSimulationScenario:
        raise VMLifecycleError("Validated VM plan and typed scenario required")
    try:
        checked = validate_vm_plan_bytes(plan.canonical_json)
    except (VMPlanError, AttributeError, TypeError) as exc:
        raise VMLifecycleError("Invalid pinned VM plan") from exc
    if checked != plan:
        raise VMLifecycleError("Pinned VM plan fields or digest disagree")
    configuration = checked.design
    if (configuration["guest"]["max_parallel_vms"] != 1
            or configuration["safety"]["vm_execution_enabled"] is not False
            or configuration["network"]["host_bridging"] is not False):
        raise VMLifecycleError("VM plan exceeds the offline-only safety boundary")

    events: list[VMEvent] = []
    def record(phase: str, detail: str):
        if len(events) >= MAX_EVENTS:
            raise VMLifecycleError("Lifecycle event budget exceeded")
        events.append(VMEvent(len(events) + 1, phase, detail))

    budget = configuration["guest"]["max_runtime_seconds"]
    record("validated", "schema_valid_not_authorized")
    if scenario is VMSimulationScenario.CAPACITY_BLOCKED:
        record("blocked", "synthetic_capacity_guard_denied")
        return VMLifecycleSimulation(
            checked.name, checked.digest_sha256, scenario,
            VMFinalState.SIMULATED_BLOCKED,
            VMFailureReason.REPORTED_CAPACITY_BLOCK, False, False, False,
            0, budget, tuple(events),
        )

    # Everything below changes only Python values; not even scratch disk is
    # created. The real resource adapter remains deliberately nonexistent.
    record("allocating", "synthetic_private_overlay_reserved")
    record("allocated", "synthetic_guest_handle_created")
    failure = VMFailureReason.NONE
    elapsed = 1
    if scenario is VMSimulationScenario.START_FAILURE:
        record("starting", "synthetic_guest_start_requested")
        record("start_failed", "synthetic_guest_start_error")
        failure = VMFailureReason.START_FAILED
    else:
        record("starting", "synthetic_guest_start_requested")
        record("running", "synthetic_guest_started")
        elapsed = 2
        if scenario is VMSimulationScenario.RUNTIME_FAILURE:
            record("runtime_failed", "synthetic_runtime_error")
            failure = VMFailureReason.RUNTIME_FAILED
        elif scenario is VMSimulationScenario.TIMEOUT:
            elapsed = budget
            record("deadline", "synthetic_deadline_expired")
            failure = VMFailureReason.DEADLINE_EXCEEDED
        elif scenario is VMSimulationScenario.CANCELLED:
            record("cancelled", "synthetic_owner_cancel_request")
            failure = VMFailureReason.USER_CANCELLED
        else:
            record("workload", "synthetic_noop_only")

    record("stopping", "synthetic_cleanup_attempt")
    if scenario is VMSimulationScenario.CLEANUP_FAILURE:
        record("cleanup_unresolved", "synthetic_cleanup_failed_preserve_evidence")
        return VMLifecycleSimulation(
            checked.name, checked.digest_sha256, scenario,
            VMFinalState.SIMULATED_CLEANUP_UNRESOLVED,
            VMFailureReason.CLEANUP_FAILED, True, True, False,
            elapsed, budget, tuple(events),
        )

    record("terminated", "synthetic_handle_released")
    return VMLifecycleSimulation(
        checked.name, checked.digest_sha256, scenario,
        VMFinalState.SIMULATED_TERMINATED, failure, True, True, True,
        elapsed, budget, tuple(events),
    )


def simulate_sequential_pair(plan: K3sVMPlan,
                             baseline: VMSimulationScenario,
                             candidate: VMSimulationScenario) -> dict:
    """Fenced sequential *simulation*: never start candidate on unsafe baseline.

    The baseline cleanup must be simulated as complete and baseline must have
    no simulated failure; otherwise candidate is not attempted. No parallelism.
    """
    first = simulate_vm_lifecycle(plan, baseline)
    second = None
    if (first.final_state is VMFinalState.SIMULATED_TERMINATED
            and first.failure_reason is VMFailureReason.NONE):
        second = simulate_vm_lifecycle(plan, candidate)
    return {
        "api_version": API_VERSION,
        "kind": "offline_sequential_vm_lifecycle_simulation",
        "plan_id": first.plan_id,
        "plan_digest_sha256": first.plan_digest_sha256,
        "baseline": first.to_dict(),
        "candidate": second.to_dict() if second is not None else None,
        "candidate_attempted": second is not None,
        "maximum_concurrent_vms": 1,
        "simulated": True,
        "real_vm_booted": False,
        "execution_authorized": False,
        "host_storage_modified": False,
        "cleanup_verified_on_host": False,
    }
