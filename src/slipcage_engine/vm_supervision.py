"""SC-13b5 OFFLINE supervision contract: single-owner fencing and crash quarantine.

This is a pure, in-memory fault model, NOT an implementation of OS locks,
durable journals, systemd, cgroups, QEMU, overlay storage, or watchdogs.
Simulated cleanup or resource enforcement is NEVER evidence of real cleanup.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
import re

from .vm_plan import K3sVMPlan, VMPlanError, validate_vm_plan_bytes
from .vm_assets import VMAssetPreflight
from .vm_qemu_blueprint import QemuBlueprintError, build_qemu_blueprint

SUPERVISION_API_VERSION = "slipcage.dev/vm-supervision-simulation/v1alpha1"
MAX_AUDIT_EVENTS = 24
TASKS_BUDGET = 256
_RAM_SUPERVISOR_MARGIN_MIB = 512
_ATTEMPT_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")


class SupervisionError(ValueError):
    """A stale, unsafe, mismatched or disallowed simulated transition."""


class SupervisionPhase(str, Enum):
    IDLE = "idle"
    RESERVED = "reserved"
    RUNNING = "running"
    STOPPING = "stopping"
    CLEAN = "clean"
    QUARANTINED = "quarantined"


class SupervisionEvent(str, Enum):
    RESERVE = "reserve"
    START = "start"
    START_FAILED = "start_failed"
    OBSERVE = "observe"
    FINISH = "finish"
    CANCEL = "cancel"
    CRASH = "crash"
    CLEANUP_OK = "cleanup_ok"
    CLEANUP_FAILED = "cleanup_failed"


class SupervisionOutcome(str, Enum):
    NONE = "none"
    COMPLETED = "completed"
    START_FAILED = "start_failed"
    CANCELLED = "cancelled"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    RESOURCE_LIMIT_EXCEEDED = "resource_limit_exceeded"
    CRASH_UNRESOLVED = "crash_unresolved"
    CLEANUP_UNRESOLVED = "cleanup_unresolved"


class SupervisionScenario(str, Enum):
    SUCCESS = "success"
    START_FAILURE = "start_failure"
    DEADLINE = "deadline"
    RESOURCE_PRESSURE = "resource_pressure"
    CANCELLED = "cancelled"
    CRASH = "crash"
    CLEANUP_FAILURE = "cleanup_failure"


@dataclass(frozen=True, slots=True)
class SupervisorDesign:
    """Derived bounded OS supervisor *intent*, not actual enforcement."""
    plan_id: str
    plan_digest_sha256: str
    guest_vcpu: int
    guest_memory_mib: int
    disk_overlay_limit_gib: int
    max_runtime_seconds: int
    proposed_cpu_quota_percent: int
    proposed_memory_max_mib: int
    proposed_tasks_max: int = TASKS_BUDGET

    def to_dict(self) -> dict:
        return {
            "plan_id": self.plan_id,
            "plan_digest_sha256": self.plan_digest_sha256,
            "guest_vcpu": self.guest_vcpu,
            "guest_memory_mib": self.guest_memory_mib,
            "disk_overlay_limit_gib": self.disk_overlay_limit_gib,
            "max_runtime_seconds": self.max_runtime_seconds,
            "proposed_cpu_quota_percent": self.proposed_cpu_quota_percent,
            "proposed_memory_max_mib": self.proposed_memory_max_mib,
            "proposed_tasks_max": self.proposed_tasks_max,
            "max_parallel_guests": 1,
            "private_scratch_required": True,
            "overlay_creation_implemented": False,
            "overlay_limit_enforced_on_host": False,
            "os_cgroup_limits_enforced": False,
            "watchdog_process_enforced": False,
            "exclusive_host_lease_implemented": False,
        }


@dataclass(frozen=True, slots=True)
class SupervisorAuditEvent:
    revision: int
    attempt_id: str
    action: SupervisionEvent
    phase: SupervisionPhase
    outcome: SupervisionOutcome

    def to_dict(self) -> dict:
        return {
            "revision": self.revision,
            "attempt_id": self.attempt_id,
            "action": self.action.value,
            "phase": self.phase.value,
            "outcome": self.outcome.value,
        }


@dataclass(frozen=True, slots=True)
class SupervisionJournal:
    """An ephemeral value, never a real interprocess lock or host audit trail."""
    design: SupervisorDesign
    revision: int
    phase: SupervisionPhase
    active_attempt: str | None
    last_attempt: str | None
    outcome: SupervisionOutcome
    elapsed_seconds: int
    events: tuple[SupervisorAuditEvent, ...]

    def to_dict(self) -> dict:
        return {
            "api_version": SUPERVISION_API_VERSION,
            "kind": "ephemeral_supervision_fault_simulation",
            "design": self.design.to_dict(),
            "revision": self.revision,
            "phase": self.phase.value,
            "active_attempt": self.active_attempt,
            "last_attempt": self.last_attempt,
            "outcome": self.outcome.value,
            "elapsed_seconds": self.elapsed_seconds,
            "events": [e.to_dict() for e in self.events],
            "simulated": True,
            "single_guest_fencing_simulated": True,
            "real_exclusive_lease_acquired": False,
            "durable_journal_written": False,
            "real_guest_started": False,
            "real_guest_stopped": False,
            "host_resources_reserved": False,
            "cgroup_supervision_verified": False,
            "watchdog_enforced": False,
            "overlay_created": False,
            "overlay_deleted": False,
            "reconciliation_verified_on_host": False,
            "operator_clearance_granted": False,
            "execution_authorized": False,
            "host_modified": False,
        }

    def canonical_json(self) -> bytes:
        return json.dumps(self.to_dict(), ensure_ascii=True, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("ascii")


def design_supervision(plan: K3sVMPlan, preflight: VMAssetPreflight) -> SupervisorDesign:
    """Only strict nonsynthetic SC-12 plans plus SC-13b1 digest checks."""
    try:
        blueprint = build_qemu_blueprint(plan, preflight)
    except (QemuBlueprintError, VMPlanError) as exc:
        raise SupervisionError("Safe plan and locally matched assets required") from exc
    # The blueprint has no disk, guest kernel, NIC or real launcher.
    if type(plan) is not K3sVMPlan:
        raise SupervisionError("Typed VM plan required")
    checked = validate_vm_plan_bytes(plan.canonical_json)
    if checked != plan:
        raise SupervisionError("VM plan identity mismatch")
    guest = checked.design["guest"]
    if (guest["max_parallel_vms"] != 1
            or blueprint.guest_vcpu != guest["vcpu"]
            or blueprint.guest_ram_mib != guest["ram_mib"]
            or blueprint.guest_disk_gib != guest["disk_gib"]
            or blueprint.max_runtime_seconds != guest["max_runtime_seconds"]):
        raise SupervisionError("Incompatible VM design")
    return SupervisorDesign(
        plan.name, plan.digest_sha256, guest["vcpu"], guest["ram_mib"],
        guest["disk_gib"], guest["max_runtime_seconds"], guest["vcpu"] * 100,
        guest["ram_mib"] + _RAM_SUPERVISOR_MARGIN_MIB,
    )


def new_journal(design: SupervisorDesign) -> SupervisionJournal:
    if type(design) is not SupervisorDesign:
        raise SupervisionError("Typed supervisor intent required")
    if (not 2 <= design.guest_vcpu <= 4
            or not 4096 <= design.guest_memory_mib <= 8192
            or not 24 <= design.disk_overlay_limit_gib <= 48
            or not 300 <= design.max_runtime_seconds <= 1800
            or design.proposed_cpu_quota_percent != design.guest_vcpu * 100
            or design.proposed_memory_max_mib != design.guest_memory_mib + 512
            or design.proposed_tasks_max != TASKS_BUDGET
            or type(design.plan_digest_sha256) is not str
            or len(design.plan_digest_sha256) != 64
            or any(c not in "0123456789abcdef" for c in design.plan_digest_sha256)):
        raise SupervisionError("Supervisor budgets inconsistent with bounded VM plan")
    return SupervisionJournal(design, 0, SupervisionPhase.IDLE, None, None,
                              SupervisionOutcome.NONE, 0, ())


def _check_journal(journal: SupervisionJournal) -> None:
    if type(journal) is not SupervisionJournal:
        raise SupervisionError("Typed journal required")
    if type(journal.revision) is not int or journal.revision != len(journal.events):
        raise SupervisionError("Revision does not match audit events")
    if not 0 <= journal.revision <= MAX_AUDIT_EVENTS:
        raise SupervisionError("Audit event count exceeded")
    if (type(journal.phase) is not SupervisionPhase
            or type(journal.outcome) is not SupervisionOutcome
            or type(journal.elapsed_seconds) is not int
            or not 0 <= journal.elapsed_seconds <= journal.design.max_runtime_seconds):
        raise SupervisionError("Invalid journal state")
    for i, event in enumerate(journal.events, 1):
        if type(event) is not SupervisorAuditEvent or type(event.action) is not SupervisionEvent:
            raise SupervisionError("Invalid event")
        if event.revision != i:
            raise SupervisionError("Nonsequential audit events")
    if journal.events and (
        journal.events[-1].phase != journal.phase
        or journal.events[-1].outcome != journal.outcome
    ):
        raise SupervisionError("Terminal event and journal mismatch")
    if journal.phase in (SupervisionPhase.RESERVED, SupervisionPhase.RUNNING,
                         SupervisionPhase.STOPPING, SupervisionPhase.QUARANTINED):
        if not journal.active_attempt:
            raise SupervisionError("Active owner must be retained until resolved")
    elif journal.active_attempt is not None:
        raise SupervisionError("Clean/idle journal cannot hold a lease")
    if journal.phase is SupervisionPhase.QUARANTINED and journal.outcome not in (
        SupervisionOutcome.CRASH_UNRESOLVED, SupervisionOutcome.CLEANUP_UNRESOLVED
    ):
        raise SupervisionError("Quarantine must be unresolved")
    if journal.phase is SupervisionPhase.IDLE and journal.revision:
        raise SupervisionError("Idle journal must be pristine")


def transition(
    journal: SupervisionJournal,
    action: SupervisionEvent,
    attempt_id: str,
    *,
    expected_revision: int,
    elapsed_seconds: int = 0,
    memory_mib: int = 0,
    overlay_mib: int = 0,
    tasks: int = 0,
) -> SupervisionJournal:
    """Pure compare-and-swap *simulation*. No OS-backed lock exists.

    Stale revisions, mismatched owners and invalid transitions raise without
    changing the input. A crashed or cleanup-failed owner is NEVER auto-cleared.
    """
    _check_journal(journal)
    if type(action) is not SupervisionEvent:
        raise SupervisionError("Closed enum action required")
    if type(attempt_id) is not str or _ATTEMPT_RE.fullmatch(attempt_id) is None:
        raise SupervisionError("Bounded attempt ID required")
    if type(expected_revision) is not int or expected_revision != journal.revision:
        raise SupervisionError("Stale revision or forged write")
    for val in (elapsed_seconds, memory_mib, overlay_mib, tasks):
        if type(val) is not int or val < 0 or val > 2**31:
            raise SupervisionError("Only bounded nonnegative integer samples accepted")
    if journal.revision >= MAX_AUDIT_EVENTS:
        raise SupervisionError("Audit capacity reached; fail closed")
    if journal.phase is SupervisionPhase.QUARANTINED:
        raise SupervisionError("Unresolved crash/cleanup quarantine requires external operator review")

    phase = journal.phase
    active = journal.active_attempt
    outcome = journal.outcome
    elapsed = journal.elapsed_seconds
    last = journal.last_attempt

    if action is SupervisionEvent.RESERVE:
        if phase not in (SupervisionPhase.IDLE, SupervisionPhase.CLEAN):
            raise SupervisionError("Single simulated lease already occupied")
        if journal.last_attempt == attempt_id:
            raise SupervisionError("Attempt ID cannot be reused")
        active, last, phase = attempt_id, attempt_id, SupervisionPhase.RESERVED
        outcome, elapsed = SupervisionOutcome.NONE, 0
    else:
        if attempt_id != active:
            raise SupervisionError("Action by nonowner or stale attempt ID")
        if action is SupervisionEvent.START:
            if phase is not SupervisionPhase.RESERVED:
                raise SupervisionError("Start requires reserved lease")
            phase = SupervisionPhase.RUNNING
        elif action is SupervisionEvent.START_FAILED:
            if phase is not SupervisionPhase.RESERVED:
                raise SupervisionError("Start failure requires reserved lease")
            phase, outcome = SupervisionPhase.STOPPING, SupervisionOutcome.START_FAILED
        elif action is SupervisionEvent.OBSERVE:
            if phase is not SupervisionPhase.RUNNING or elapsed_seconds < elapsed:
                raise SupervisionError("Monitoring samples require monotonic running time")
            elapsed = min(elapsed_seconds, journal.design.max_runtime_seconds)
            if (memory_mib > journal.design.proposed_memory_max_mib
                    or overlay_mib > journal.design.disk_overlay_limit_gib * 1024
                    or tasks > journal.design.proposed_tasks_max):
                phase, outcome = SupervisionPhase.STOPPING, SupervisionOutcome.RESOURCE_LIMIT_EXCEEDED
            elif elapsed_seconds >= journal.design.max_runtime_seconds:
                phase, outcome = SupervisionPhase.STOPPING, SupervisionOutcome.DEADLINE_EXCEEDED
        elif action in (SupervisionEvent.FINISH, SupervisionEvent.CANCEL):
            if phase is not SupervisionPhase.RUNNING:
                raise SupervisionError("Finish/cancel requires running lease")
            phase = SupervisionPhase.STOPPING
            outcome = (SupervisionOutcome.COMPLETED if action is SupervisionEvent.FINISH
                       else SupervisionOutcome.CANCELLED)
        elif action is SupervisionEvent.CRASH:
            if phase not in (SupervisionPhase.RESERVED, SupervisionPhase.RUNNING,
                             SupervisionPhase.STOPPING):
                raise SupervisionError("Crash requires outstanding owner")
            phase, outcome = SupervisionPhase.QUARANTINED, SupervisionOutcome.CRASH_UNRESOLVED
        elif action is SupervisionEvent.CLEANUP_FAILED:
            if phase is not SupervisionPhase.STOPPING:
                raise SupervisionError("Failed cleanup requires stopping state")
            phase, outcome = SupervisionPhase.QUARANTINED, SupervisionOutcome.CLEANUP_UNRESOLVED
        elif action is SupervisionEvent.CLEANUP_OK:
            if phase is not SupervisionPhase.STOPPING:
                raise SupervisionError("Cleanup requires stopping state")
            phase, active = SupervisionPhase.CLEAN, None
        else:
            raise SupervisionError("Unknown action")
    revision = journal.revision + 1
    event = SupervisorAuditEvent(revision, attempt_id, action, phase, outcome)
    return SupervisionJournal(journal.design, revision, phase, active, last,
                              outcome, elapsed, journal.events + (event,))


def simulate_supervision(
    plan: K3sVMPlan, preflight: VMAssetPreflight,
    scenario: SupervisionScenario,
    *, attempt_id: str = "baseline",
    journal: SupervisionJournal | None = None,
) -> SupervisionJournal:
    """Drive one modeled attempt through closed failure-injection transitions."""
    if type(scenario) is not SupervisionScenario:
        raise SupervisionError("Typed, allowlisted scenario required")
    design = design_supervision(plan, preflight)
    if journal is None:
        journal = new_journal(design)
    _check_journal(journal)
    if journal.design != design:
        raise SupervisionError("Cannot rebind existing simulation to another plan")
    def apply(action: SupervisionEvent, **kw):
        nonlocal journal
        journal = transition(journal, action, attempt_id,
                             expected_revision=journal.revision, **kw)
    apply(SupervisionEvent.RESERVE)
    if scenario is SupervisionScenario.START_FAILURE:
        apply(SupervisionEvent.START_FAILED)
    else:
        apply(SupervisionEvent.START)
        if scenario is SupervisionScenario.CRASH:
            apply(SupervisionEvent.CRASH)
            return journal
        if scenario is SupervisionScenario.DEADLINE:
            apply(SupervisionEvent.OBSERVE, elapsed_seconds=design.max_runtime_seconds)
        elif scenario is SupervisionScenario.RESOURCE_PRESSURE:
            apply(SupervisionEvent.OBSERVE, elapsed_seconds=1,
                  memory_mib=design.proposed_memory_max_mib + 1)
        elif scenario is SupervisionScenario.CANCELLED:
            apply(SupervisionEvent.CANCEL)
        else:
            apply(SupervisionEvent.OBSERVE, elapsed_seconds=1,
                  memory_mib=design.guest_memory_mib, tasks=1, overlay_mib=1)
            apply(SupervisionEvent.FINISH)
    if scenario is SupervisionScenario.CLEANUP_FAILURE:
        apply(SupervisionEvent.CLEANUP_FAILED)
    else:
        apply(SupervisionEvent.CLEANUP_OK)
    return journal


def simulate_supervision_pair(
    plan: K3sVMPlan, preflight: VMAssetPreflight,
    baseline: SupervisionScenario, candidate: SupervisionScenario,
) -> dict:
    """The candidate is NEVER attempted unless baseline was clean and successful."""
    first = simulate_supervision(plan, preflight, baseline, attempt_id="baseline")
    second = None
    if (first.phase is SupervisionPhase.CLEAN
            and first.outcome is SupervisionOutcome.COMPLETED):
        second = simulate_supervision(plan, preflight, candidate, attempt_id="candidate",
                                      journal=first)
    return {
        "api_version": SUPERVISION_API_VERSION,
        "kind": "offline_sequential_supervision_simulation",
        "baseline": first.to_dict(),
        "candidate": second.to_dict() if second else None,
        "candidate_attempted": second is not None,
        "simulated": True,
        "max_parallel_guests": 1,
        "real_guest_started": False,
        "real_exclusive_lease_acquired": False,
        "durable_journal_written": False,
        "host_modified": False,
        "execution_authorized": False,
    }
