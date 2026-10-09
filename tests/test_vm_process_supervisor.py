"""SC-13b11 safety contract: injected FAKE PIDs/observations only."""
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from slipcage_engine.cli import main
from slipcage_engine.vm_assets import ARTIFACTS, verify_local_vm_assets
from slipcage_engine.vm_plan import load_vm_plan, validate_vm_plan_bytes
from slipcage_engine.vm_offline_fencing import (
    issue_offline_generation, resolve_offline_generation, OfflineResolution,
    inspect_offline_fencing,
)
from slipcage_engine.vm_process_supervisor import (
    API_VERSION, FakeProcessIdentity, FakeProcessObservation, ProcessSafetyError,
    ProcessPhase, ProcessScenario, bind_fake_supervisor, begin_fake_process,
    step_fake_process, simulate_fake_supervision,
)

SAMPLE = ROOT / "examples" / "vm-plans" / "k3s-synthetic-design.json"


class FakeProcessSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.assets = self.root / "assets"
        self.assets.mkdir(mode=0o700)
        self.assets.chmod(0o700)
        self.journal = self.root / "journal"
        self.journal.mkdir(mode=0o700)
        self.journal.chmod(0o700)
        draft = load_vm_plan(SAMPLE).design
        draft["provenance"]["pin_status"] = "operator_supplied_unverified"
        draft["provenance"]["note"] = "CI fake PID and bytes, NOT trusted release software"
        draft["software"]["guest_kernel_release"] = "6.8.0-test"
        for i, (field, filename, _) in enumerate(ARTIFACTS):
            blob = f"fake-supervision-asset-{field}-{i}".encode()
            path = self.assets / filename
            path.write_bytes(blob)
            path.chmod(0o600)
            draft["artifacts"][field] = hashlib.sha256(blob).hexdigest()
        self.plan = validate_vm_plan_bytes(json.dumps(draft).encode())
        self.preflight = verify_local_vm_assets(self.plan, self.assets)
        self.planfile = self.root / "fake-plan.json"
        self.planfile.write_bytes(self.plan.canonical_json)
        self.snapshot = issue_offline_generation(self.journal, self.plan, "baseline", 0)
        self.policy = bind_fake_supervisor(self.plan, self.preflight, self.snapshot)
        self.pid = FakeProcessIdentity(42420, 314159, 42420)

    def start(self):
        return begin_fake_process(self.policy, self.pid)

    def event(self, state, elapsed, **kwargs):
        defaults = dict(
            alive=True, reaped=False, cgroup_empty=False,
            memory_mib=0, tasks=0, overlay_mib=0, cancel=False,
        )
        defaults.update(kwargs)
        obs = FakeProcessObservation(
            elapsed, self.pid.pid, self.pid.start_ticks,
            self.pid.process_group, **defaults,
        )
        return step_fake_process(state, obs, expected_revision=state.revision)

    def cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_policy_is_plan_bound_to_outstanding_offline_attempt(self):
        val = self.policy.to_dict()
        self.assertEqual(val["offline_generation"], 1)
        self.assertEqual(val["attempt_id"], "baseline")
        self.assertEqual(val["plan_digest_sha256"], self.plan.digest_sha256)
        self.assertEqual(val["offline_issue_sha256"], self.snapshot.active_record_sha256)
        self.assertEqual(val["max_runtime_seconds"], 900)
        self.assertEqual(val["proposed_memory_max_mib"], 4608)
        self.assertEqual(val["proposed_tasks_max"], 256)
        self.assertEqual(val["proposed_overlay_max_mib"], 24 * 1024)
        self.assertEqual(val["proposed_cpu_quota_percent"], 200)
        self.assertEqual(val["term_grace_seconds"], 15)
        self.assertEqual(val["kill_reap_grace_seconds"], 10)
        self.assertFalse(val["shared_host_slot_enforced"])

    def test_success_is_fabricated_reap_never_real_host_cleanup(self):
        state = simulate_fake_supervision(
            self.plan, self.preflight, self.snapshot, ProcessScenario.SUCCESS)
        self.assertIs(state.phase, ProcessPhase.SIMULATED_REAPED)
        self.assertEqual(state.revision, 2)
        self.assertEqual(state.action_intents, (
            "observe_only", "no_signal_fake_reaped",
        ))
        out = state.to_dict()
        self.assertEqual(out["api_version"], API_VERSION)
        self.assertTrue(out["observations_are_injected_fake_data"])
        for k in (
            "pid_identity_verified_on_host", "shared_host_guest_lock_held",
            "offline_fencing_lock_held_during_simulation", "actual_signals_sent",
            "real_reaping_performed", "os_cgroup_or_disk_quota_enforced",
            "actual_process_termination_verified", "overlay_deleted_or_created",
            "execution_authorized", "vm_launched", "host_modified",
        ):
            with self.subTest(k=k):
                self.assertIs(out[k], False)

    def test_deadline_produces_intents_for_term_then_kill(self):
        state = self.start()
        term = self.event(state, self.policy.max_runtime_seconds)
        self.assertIs(term.phase, ProcessPhase.TERM_REQUESTED)
        self.assertEqual(term.action_intents[-1], "sigterm_intent")
        self.assertEqual(term.reason, "deadline")
        kill = self.event(term, self.policy.max_runtime_seconds + 15)
        self.assertIs(kill.phase, ProcessPhase.KILL_REQUESTED)
        self.assertEqual(kill.action_intents[-1], "sigkill_intent")
        fake_reap = self.event(kill, self.policy.max_runtime_seconds + 16,
                               alive=False, reaped=True, cgroup_empty=True)
        self.assertIs(fake_reap.phase, ProcessPhase.SIMULATED_REAPED)
        self.assertFalse(fake_reap.to_dict()["actual_signals_sent"])

    def test_proposed_limits_trigger_term_intent_not_enforcement(self):
        for kwargs, reason in (
            ({"memory_mib": self.policy.memory_max_mib + 1}, "memory_budget"),
            ({"tasks": self.policy.tasks_max + 1}, "tasks_budget"),
            ({"overlay_mib": self.policy.overlay_max_mib + 1}, "overlay_budget"),
            ({"cancel": True}, "cancel_requested"),
        ):
            with self.subTest(kwargs=kwargs):
                term = self.event(self.start(), 1, **kwargs)
                self.assertEqual((term.phase, term.reason, term.action_intents[-1]),
                                 (ProcessPhase.TERM_REQUESTED, reason, "sigterm_intent"))
                self.assertFalse(term.to_dict()["os_cgroup_or_disk_quota_enforced"])

    def test_exact_budget_and_pre_deadline_stay_observing(self):
        val = self.event(
            self.start(), self.policy.max_runtime_seconds - 1,
            memory_mib=self.policy.memory_max_mib, tasks=self.policy.tasks_max,
            overlay_mib=self.policy.overlay_max_mib,
        )
        self.assertIs(val.phase, ProcessPhase.OBSERVING)
        self.assertEqual(val.action_intents, ("observe_only",))

    def test_pid_reuse_quarantined_without_signal_intent(self):
        state = self.start()
        foreign = FakeProcessObservation(1, self.pid.pid, self.pid.start_ticks + 1,
                                         self.pid.process_group, True, False, False)
        result = step_fake_process(state, foreign, expected_revision=0)
        self.assertIs(result.phase, ProcessPhase.QUARANTINED)
        self.assertEqual(result.reason, "process_identity_changed_preserve")
        self.assertNotIn("sigterm_intent", result.action_intents)
        self.assertNotIn("sigkill_intent", result.action_intents)
        with self.assertRaises(ProcessSafetyError):
            self.event(result, 2)

    def test_different_pid_and_process_group_quarantine(self):
        for pid, start, group in ((42421, 314159, 42421), (42420, 314159, 2)):
            with self.subTest(pid=pid,group=group):
                result = step_fake_process(
                    self.start(),
                    FakeProcessObservation(1, pid, start, group, True, False, False),
                    expected_revision=0,
                )
                self.assertIs(result.phase, ProcessPhase.QUARANTINED)
                self.assertEqual(result.action_intents, ("no_signal_quarantine",))

    def test_unreaped_fake_process_at_term_deadline_quarantines_not_kills(self):
        term = self.event(self.start(), 900)
        missing = self.event(term, 915, alive=False, reaped=False, cgroup_empty=False)
        self.assertIs(missing.phase, ProcessPhase.QUARANTINED)
        self.assertEqual(missing.reason, "unreaped_or_nonempty_after_term")
        self.assertNotIn("sigkill_intent", missing.action_intents)

    def test_kill_timeout_quarantines_instead_of_claiming_reap(self):
        trace = simulate_fake_supervision(self.plan, self.preflight,
                                          self.snapshot, ProcessScenario.KILL_TIMEOUT)
        self.assertIs(trace.phase, ProcessPhase.QUARANTINED)
        self.assertEqual(trace.reason, "kill_reap_deadline_exceeded")
        self.assertEqual(trace.action_intents[-1], "no_signal_quarantine")
        self.assertFalse(trace.to_dict()["actual_process_termination_verified"])

    def test_fake_unexpected_exit_without_reap_quarantines(self):
        state = self.event(self.start(), 1, alive=False, reaped=False)
        self.assertIs(state.phase, ProcessPhase.QUARANTINED)
        self.assertEqual(state.action_intents, ("no_signal_quarantine",))

    def test_reaped_but_cgroup_not_empty_is_not_clean(self):
        state = self.event(self.start(), 1, alive=False, reaped=True,
                           cgroup_empty=False)
        self.assertIs(state.phase, ProcessPhase.QUARANTINED)

    def test_nonmonotonic_or_stale_revision_rejected_without_state_change(self):
        first = self.event(self.start(), 5)
        with self.assertRaises(ProcessSafetyError):
            self.event(first, 5)
        with self.assertRaises(ProcessSafetyError):
            step_fake_process(
                first, FakeProcessObservation(6, 42420, 314159, 42420,
                                              True, False, False),
                expected_revision=0,
            )
        self.assertEqual(first.revision, 1)

    def test_invalid_and_contradictory_fake_observations_refused(self):
        for kwargs in (
            {"alive": True, "reaped": True},
            {"alive": True, "cgroup_empty": True},
            {"memory_mib": -1},
            {"tasks": True},
            {"overlay_mib": 2**35},
            {"cancel": 1},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ProcessSafetyError):
                self.event(self.start(), 1, **kwargs)

    def test_bad_fake_identity_and_budget_policy_refused(self):
        for identity in (
            FakeProcessIdentity(0, 10, 0),
            FakeProcessIdentity(True, 10, True),
            FakeProcessIdentity(42420, 0, 42420),
            FakeProcessIdentity(42420, 1, 2),
        ):
            with self.subTest(identity=identity), self.assertRaises(ProcessSafetyError):
                begin_fake_process(self.policy, identity)
        for fake in (
            replace(self.policy, max_runtime_seconds=10),
            replace(self.policy, memory_max_mib=True),
            replace(self.policy, tasks_max=999),
            replace(self.policy, generation=0),
        ):
            with self.assertRaises(ProcessSafetyError):
                begin_fake_process(fake, self.pid)

    def test_stale_or_resolved_offline_journal_refused(self):
        bogus = replace(self.snapshot, active_record_sha256="g"*64)
        with self.assertRaises(ProcessSafetyError):
            bind_fake_supervisor(self.plan, self.preflight, bogus)
        bogus = replace(self.snapshot, plan_digest_sha256="f"*64)
        with self.assertRaises(ProcessSafetyError):
            bind_fake_supervisor(self.plan, self.preflight, bogus)
        resolved = resolve_offline_generation(
            self.journal, "baseline", 1, self.snapshot.active_record_sha256,
            OfflineResolution.ABANDONED,
        )
        with self.assertRaises(ProcessSafetyError):
            bind_fake_supervisor(self.plan, self.preflight, resolved)
        self.assertEqual(inspect_offline_fencing(self.journal), resolved)

    def test_synthetic_and_bad_asset_preflight_rejected(self):
        from dataclasses import replace
        with self.assertRaises(ProcessSafetyError):
            bind_fake_supervisor(load_vm_plan(SAMPLE), self.preflight, self.snapshot)
        with self.assertRaises(ProcessSafetyError):
            bind_fake_supervisor(
                self.plan, replace(self.preflight, plan_digest_sha256="f"*64),
                self.snapshot,
            )

    def test_every_allowlisted_scenario_has_bounded_terminal_state(self):
        expected = {
            ProcessScenario.SUCCESS: ProcessPhase.SIMULATED_REAPED,
            ProcessScenario.DEADLINE: ProcessPhase.SIMULATED_REAPED,
            ProcessScenario.MEMORY_PRESSURE: ProcessPhase.SIMULATED_REAPED,
            ProcessScenario.TASK_PRESSURE: ProcessPhase.SIMULATED_REAPED,
            ProcessScenario.OVERLAY_PRESSURE: ProcessPhase.SIMULATED_REAPED,
            ProcessScenario.CANCELLATION: ProcessPhase.SIMULATED_REAPED,
            ProcessScenario.UNREAPED: ProcessPhase.QUARANTINED,
            ProcessScenario.KILL_TIMEOUT: ProcessPhase.QUARANTINED,
            ProcessScenario.PID_REUSE: ProcessPhase.QUARANTINED,
            ProcessScenario.UNEXPECTED_EXIT: ProcessPhase.QUARANTINED,
        }
        for scenario, phase in expected.items():
            with self.subTest(scenario=scenario):
                result = simulate_fake_supervision(
                    self.plan, self.preflight, self.snapshot, scenario)
                self.assertIs(result.phase, phase)
                self.assertLessEqual(result.revision, 24)
                self.assertFalse(result.to_dict()["execution_authorized"])
                self.assertEqual(json.loads(result.canonical_json()), result.to_dict())

    def test_terminal_trace_cannot_be_resumed_or_cleared(self):
        complete = simulate_fake_supervision(
            self.plan, self.preflight, self.snapshot, ProcessScenario.SUCCESS)
        quarantine = simulate_fake_supervision(
            self.plan, self.preflight, self.snapshot, ProcessScenario.PID_REUSE)
        for trace in (complete, quarantine):
            with self.assertRaises(ProcessSafetyError):
                self.event(trace, trace.elapsed_seconds + 1)

    def test_cli_fake_scenarios_and_real_run_remain_disabled(self):
        for scenario, status in (("success", 0), ("deadline", 0),
                                 ("pid_reuse", 5), ("kill_timeout", 5)):
            with self.subTest(scenario=scenario):
                code, stdout, stderr = self.cli(
                    "simulate-vm-process-supervision", str(self.planfile),
                    "--assets-dir", str(self.assets),
                    "--journal-root", str(self.journal),
                    "--scenario", scenario, "--json",
                )
                self.assertEqual((code, stderr), (status, ""))
                result = json.loads(stdout)
                self.assertFalse(result["actual_signals_sent"])
                self.assertFalse(result["execution_authorized"])
                self.assertFalse(result["vm_launched"])
        for cmd in ("run", "compare", "report"):
            code, stdout, stderr = self.cli(cmd)
            self.assertEqual(code, 3)
            self.assertEqual(stdout, "")

    def test_pure_reducer_no_subprocess_socket_or_host_mutation(self):
        manifest_before = sorted(x.name for x in self.journal.iterdir())
        with (
            patch.object(subprocess, "Popen", side_effect=AssertionError("Popen")),
            patch.object(subprocess, "run", side_effect=AssertionError("run")),
            patch.object(socket, "socket", side_effect=AssertionError("socket")),
        ):
            result = simulate_fake_supervision(
                self.plan, self.preflight, self.snapshot, ProcessScenario.PID_REUSE,
            )
            self.assertEqual(result.phase, ProcessPhase.QUARANTINED)
        self.assertEqual(manifest_before, sorted(x.name for x in self.journal.iterdir()))
        self.assertFalse((self.root / "overlay.qcow2").exists())


if __name__ == "__main__":
    unittest.main()
