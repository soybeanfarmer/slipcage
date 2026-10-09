"""SC-13b11: NONEXECUTING process-supervisor safety/fault contract.

All PID, cgroup, and process observations are invented test data. No syscall
to signal, spawn, kill, waitpid, inspect /proc, cgroup, QEMU, host filesystem,
or guest occurs here. Only declarative *signal intents* are returned.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
import re

from .vm_assets import VMAssetPreflight
from .vm_plan import K3sVMPlan
from .vm_supervision import SupervisionError, design_supervision
from .vm_offline_fencing import FencingSnapshot

API_VERSION = "slipcage.dev/process-supervision-fault-model/v1alpha1"
STOP_GRACE_SECONDS = 15
KILL_REAP_SECONDS = 10
MAX_FAKE_STEPS = 24
_FAKE_LABEL = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")


class ProcessSafetyError(ValueError):
    """Invalid fake observation, stale journal, or unsafe simulated transition."""


class ProcessPhase(str, Enum):
    OBSERVING = "observing"
    TERM_REQUESTED = "term_requested"
    KILL_REQUESTED = "kill_requested"
    SIMULATED_REAPED = "simulated_reaped"
    QUARANTINED = "quarantined"


class ProcessScenario(str, Enum):
    SUCCESS = "success"
    DEADLINE = "deadline"
    MEMORY_PRESSURE = "memory_pressure"
    TASK_PRESSURE = "task_pressure"
    OVERLAY_PRESSURE = "overlay_pressure"
    CANCELLATION = "cancellation"
    UNREAPED = "unreaped"
    KILL_TIMEOUT = "kill_timeout"
    PID_REUSE = "pid_reuse"
    UNEXPECTED_EXIT = "unexpected_exit"


@dataclass(frozen=True, slots=True)
class FakeProcessIdentity:
    pid: int
    start_ticks: int
    process_group: int

    def validate(self) -> None:
        if (any(type(x) is not int for x in (self.pid, self.start_ticks, self.process_group))
                or not 100 <= self.pid <= 4_194_304
                or not 1 <= self.start_ticks <= 2**63 - 1
                or self.process_group != self.pid):
            raise ProcessSafetyError("Bounded fake PID, start ticks and dedicated group required")

    def to_dict(self) -> dict:
        return {"fake_pid": self.pid, "fake_start_ticks": self.start_ticks,
                "fake_process_group": self.process_group}


@dataclass(frozen=True, slots=True)
class ProcessSafetyPolicy:
    attempt_id: str
    generation: int
    issue_sha256: str
    plan_digest_sha256: str
    max_runtime_seconds: int
    memory_max_mib: int
    tasks_max: int
    overlay_max_mib: int
    proposed_cpu_quota_percent: int

    def to_dict(self) -> dict:
        return {
            "attempt_id": self.attempt_id,
            "offline_generation": self.generation,
            "offline_issue_sha256": self.issue_sha256,
            "plan_digest_sha256": self.plan_digest_sha256,
            "max_runtime_seconds": self.max_runtime_seconds,
            "proposed_memory_max_mib": self.memory_max_mib,
            "proposed_tasks_max": self.tasks_max,
            "proposed_overlay_max_mib": self.overlay_max_mib,
            "proposed_cpu_quota_percent": self.proposed_cpu_quota_percent,
            "term_grace_seconds": STOP_GRACE_SECONDS,
            "kill_reap_grace_seconds": KILL_REAP_SECONDS,
            "required_shared_host_guest_slot": "slipcage-vm-host-slot-v1",
            "shared_host_slot_enforced": False,
            "actual_host_process_or_cgroup_supervision_implemented": False,
        }


@dataclass(frozen=True, slots=True)
class FakeProcessObservation:
    elapsed_seconds: int
    pid: int
    start_ticks: int
    process_group: int
    alive: bool
    reaped: bool
    cgroup_empty: bool
    memory_mib: int = 0
    tasks: int = 0
    overlay_mib: int = 0
    cancel: bool = False


@dataclass(frozen=True, slots=True)
class ProcessSafetyTrace:
    policy: ProcessSafetyPolicy
    identity: FakeProcessIdentity
    revision: int
    phase: ProcessPhase
    elapsed_seconds: int
    term_requested_at: int | None
    kill_requested_at: int | None
    reason: str
    action_intents: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "api_version": API_VERSION,
            "kind": "nonexecuting_fake_process_supervision",
            "policy": self.policy.to_dict(),
            "identity": self.identity.to_dict(),
            "revision": self.revision,
            "phase": self.phase.value,
            "elapsed_seconds": self.elapsed_seconds,
            "term_requested_at": self.term_requested_at,
            "kill_requested_at": self.kill_requested_at,
            "reason": self.reason,
            "action_intents": list(self.action_intents),
            "observations_are_injected_fake_data": True,
            "pid_identity_verified_on_host": False,
            "shared_host_guest_lock_held": False,
            "offline_fencing_lock_held_during_simulation": False,
            "actual_signals_sent": False,
            "real_reaping_performed": False,
            "os_cgroup_or_disk_quota_enforced": False,
            "actual_process_termination_verified": False,
            "overlay_deleted_or_created": False,
            "execution_authorized": False,
            "vm_launched": False,
            "host_modified": False,
        }

    def canonical_json(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")


def bind_fake_supervisor(
    plan: K3sVMPlan, preflight: VMAssetPreflight,
    journal: FencingSnapshot,
) -> ProcessSafetyPolicy:
    """Bind design to outstanding *offline-only* SC-13b10 issue identity."""
    if type(journal) is not FencingSnapshot:
        raise ProcessSafetyError("Typed offline fencing snapshot required")
    try:
        design = design_supervision(plan, preflight)
    except (SupervisionError, ValueError, TypeError) as exc:
        raise ProcessSafetyError("Strict non-synthetic VM plan and byte preflight required") from exc
    if (journal.state != "outstanding_offline_intent"
            or type(journal.generation) is not int
            or not 1 <= journal.generation <= 16
            or type(journal.active_attempt) is not str
            or _FAKE_LABEL.fullmatch(journal.active_attempt) is None
            or type(journal.active_record_sha256) is not str
            or _SHA.fullmatch(journal.active_record_sha256) is None
            or journal.plan_digest_sha256 != design.plan_digest_sha256):
        raise ProcessSafetyError("No matching outstanding offline attempt/fingerprint")
    return ProcessSafetyPolicy(
        journal.active_attempt, journal.generation, journal.active_record_sha256,
        design.plan_digest_sha256, design.max_runtime_seconds,
        design.proposed_memory_max_mib, design.proposed_tasks_max,
        design.disk_overlay_limit_gib * 1024, design.proposed_cpu_quota_percent,
    )


def begin_fake_process(policy: ProcessSafetyPolicy,
                       identity: FakeProcessIdentity) -> ProcessSafetyTrace:
    if type(policy) is not ProcessSafetyPolicy or type(identity) is not FakeProcessIdentity:
        raise ProcessSafetyError("Typed fake policy and process identity required")
    identity.validate()
    if (type(policy.generation) is not int or not 1 <= policy.generation <= 16
            or type(policy.attempt_id) is not str
            or _FAKE_LABEL.fullmatch(policy.attempt_id) is None
            or type(policy.issue_sha256) is not str
            or _SHA.fullmatch(policy.issue_sha256) is None
            or type(policy.plan_digest_sha256) is not str
            or _SHA.fullmatch(policy.plan_digest_sha256) is None
            or type(policy.max_runtime_seconds) is not int
            or not 300 <= policy.max_runtime_seconds <= 1800
            or type(policy.memory_max_mib) is not int
            or not 4608 <= policy.memory_max_mib <= 8704
            or type(policy.tasks_max) is not int or policy.tasks_max != 256
            or type(policy.overlay_max_mib) is not int
            or not 24 * 1024 <= policy.overlay_max_mib <= 48 * 1024
            or type(policy.proposed_cpu_quota_percent) is not int
            or policy.proposed_cpu_quota_percent not in (200, 300, 400)):
        raise ProcessSafetyError("Fake safety budgets are outside strict design bounds")
    return ProcessSafetyTrace(policy, identity, 0, ProcessPhase.OBSERVING,
                              0, None, None, "none", ())


def step_fake_process(
    trace: ProcessSafetyTrace, observation: FakeProcessObservation,
    *, expected_revision: int,
) -> ProcessSafetyTrace:
    """Pure fake observation reducer: only string *intents*, never syscalls."""
    if type(trace) is not ProcessSafetyTrace or type(observation) is not FakeProcessObservation:
        raise ProcessSafetyError("Typed trace and fake observation required")
    if (type(expected_revision) is not int or expected_revision != trace.revision
            or trace.revision >= MAX_FAKE_STEPS or type(trace.phase) is not ProcessPhase
            or trace.phase in (ProcessPhase.QUARANTINED, ProcessPhase.SIMULATED_REAPED)):
        raise ProcessSafetyError("Stale, terminal, or bounded fake process state")
    if (any(type(x) is not int for x in (
            observation.elapsed_seconds, observation.pid,
            observation.start_ticks, observation.process_group,
            observation.memory_mib, observation.tasks, observation.overlay_mib))
            or any(type(x) is not bool for x in (
                observation.alive, observation.reaped,
                observation.cgroup_empty, observation.cancel))
            or not trace.elapsed_seconds < observation.elapsed_seconds <= 2**31 - 1
            or any(x < 0 or x > 2**31 - 1
                   for x in (observation.memory_mib, observation.tasks,
                             observation.overlay_mib))
            or (observation.alive and (observation.reaped or observation.cgroup_empty))
            or (observation.reaped and observation.alive)):
        raise ProcessSafetyError("Untrustworthy, nonmonotonic or inconsistent fake observation")
    identity = trace.identity
    if (observation.pid, observation.start_ticks, observation.process_group) != (
            identity.pid, identity.start_ticks, identity.process_group):
        # Never emit a signal request against a possibly reused or alien PID.
        return _next(trace, observation.elapsed_seconds, ProcessPhase.QUARANTINED,
                     "process_identity_changed_preserve", "no_signal_quarantine")
    phase = trace.phase
    if not observation.alive and observation.reaped and observation.cgroup_empty:
        return _next(trace, observation.elapsed_seconds,
                     ProcessPhase.SIMULATED_REAPED,
                     "fake_process_reaped_and_cgroup_empty", "no_signal_fake_reaped")
    if phase is ProcessPhase.OBSERVING:
        if not observation.alive:
            return _next(trace, observation.elapsed_seconds, ProcessPhase.QUARANTINED,
                         "unexpected_unreaped_or_nonempty_process", "no_signal_quarantine")
        causes = [
            (observation.cancel, "cancel_requested"),
            (observation.elapsed_seconds >= trace.policy.max_runtime_seconds, "deadline"),
            (observation.memory_mib > trace.policy.memory_max_mib, "memory_budget"),
            (observation.tasks > trace.policy.tasks_max, "tasks_budget"),
            (observation.overlay_mib > trace.policy.overlay_max_mib, "overlay_budget"),
        ]
        for triggered, reason in causes:
            if triggered:
                return _next(trace, observation.elapsed_seconds,
                             ProcessPhase.TERM_REQUESTED, reason, "sigterm_intent",
                             term_at=observation.elapsed_seconds)
        return _next(trace, observation.elapsed_seconds,
                     ProcessPhase.OBSERVING, "fake_observation_within_budget", "observe_only")
    if phase is ProcessPhase.TERM_REQUESTED:
        if observation.elapsed_seconds - trace.term_requested_at >= STOP_GRACE_SECONDS:
            if observation.alive:
                return _next(trace, observation.elapsed_seconds, ProcessPhase.KILL_REQUESTED,
                             "term_grace_exceeded", "sigkill_intent",
                             kill_at=observation.elapsed_seconds)
            return _next(trace, observation.elapsed_seconds, ProcessPhase.QUARANTINED,
                         "unreaped_or_nonempty_after_term", "no_signal_quarantine")
        return _next(trace, observation.elapsed_seconds,
                     ProcessPhase.TERM_REQUESTED, trace.reason, "wait_for_fake_reap")
    if phase is ProcessPhase.KILL_REQUESTED:
        if observation.elapsed_seconds - trace.kill_requested_at >= KILL_REAP_SECONDS:
            return _next(trace, observation.elapsed_seconds, ProcessPhase.QUARANTINED,
                         "kill_reap_deadline_exceeded", "no_signal_quarantine")
        return _next(trace, observation.elapsed_seconds,
                     ProcessPhase.KILL_REQUESTED, trace.reason, "wait_for_fake_reap")
    raise ProcessSafetyError("Unknown process supervision state")


def _next(trace: ProcessSafetyTrace, elapsed: int, phase: ProcessPhase,
          reason: str, intent: str, *, term_at: int | None = None,
          kill_at: int | None = None) -> ProcessSafetyTrace:
    return ProcessSafetyTrace(
        trace.policy, trace.identity, trace.revision + 1, phase, elapsed,
        term_at if term_at is not None else trace.term_requested_at,
        kill_at if kill_at is not None else trace.kill_requested_at,
        reason, trace.action_intents + (intent,),
    )


def simulate_fake_supervision(
    plan: K3sVMPlan, preflight: VMAssetPreflight,
    snapshot: FencingSnapshot, scenario: ProcessScenario,
) -> ProcessSafetyTrace:
    """Deterministic, fabricated process observations: ZERO real process work."""
    if type(scenario) is not ProcessScenario:
        raise ProcessSafetyError("Closed fake scenario enum required")
    policy = bind_fake_supervisor(plan, preflight, snapshot)
    identity = FakeProcessIdentity(pid=42420, start_ticks=314159, process_group=42420)
    state = begin_fake_process(policy, identity)

    def sample(t: int, *, alive=True, reaped=False, empty=False, **kwargs):
        nonlocal state
        state = step_fake_process(
            state,
            FakeProcessObservation(t, identity.pid, identity.start_ticks,
                                   identity.process_group, alive, reaped, empty, **kwargs),
            expected_revision=state.revision,
        )

    if scenario is ProcessScenario.SUCCESS:
        sample(1, memory_mib=policy.memory_max_mib - 1, tasks=2)
        sample(2, alive=False, reaped=True, empty=True)
    elif scenario is ProcessScenario.PID_REUSE:
        state = step_fake_process(state, FakeProcessObservation(
            1, identity.pid, identity.start_ticks + 1, identity.process_group,
            True, False, False), expected_revision=0)
    elif scenario is ProcessScenario.UNEXPECTED_EXIT:
        sample(1, alive=False, reaped=False, empty=False)
    else:
        if scenario is ProcessScenario.CANCELLATION:
            sample(1, cancel=True)
        elif scenario is ProcessScenario.MEMORY_PRESSURE:
            sample(1, memory_mib=policy.memory_max_mib + 1)
        elif scenario is ProcessScenario.TASK_PRESSURE:
            sample(1, tasks=policy.tasks_max + 1)
        elif scenario is ProcessScenario.OVERLAY_PRESSURE:
            sample(1, overlay_mib=policy.overlay_max_mib + 1)
        else:
            sample(policy.max_runtime_seconds)
        if scenario is ProcessScenario.UNREAPED:
            sample(policy.max_runtime_seconds + STOP_GRACE_SECONDS, alive=False)
        else:
            when = state.elapsed_seconds + STOP_GRACE_SECONDS
            sample(when)
            if scenario is ProcessScenario.KILL_TIMEOUT:
                sample(when + KILL_REAP_SECONDS)
            else:
                sample(when + 1, alive=False, reaped=True, empty=True)
    return state
