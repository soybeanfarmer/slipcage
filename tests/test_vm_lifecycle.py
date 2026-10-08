"""SC-13a: deterministic VM lifecycle *simulation*, no guest or storage activity."""
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import FrozenInstanceError, replace
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from slipcage_engine import load_vm_plan
from slipcage_engine.cli import main
from slipcage_engine.vm_lifecycle import (
    API_VERSION, MAX_EVENTS, VMEvent, VMLifecycleError, VMLifecycleSimulation,
    VMFailureReason, VMFinalState, VMSimulationScenario,
    simulate_vm_lifecycle, simulate_sequential_pair,
)

PLAN = ROOT / "examples" / "vm-plans" / "k3s-synthetic-design.json"


class LifecycleSimulationTests(unittest.TestCase):
    def setUp(self):
        self.plan = load_vm_plan(PLAN)

    def _invoke(self, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_success_is_in_memory_and_labels_all_physical_checks_false(self):
        sim = simulate_vm_lifecycle(self.plan, VMSimulationScenario.SUCCESS)
        self.assertIs(sim.final_state, VMFinalState.SIMULATED_TERMINATED)
        self.assertIs(sim.failure_reason, VMFailureReason.NONE)
        self.assertTrue(sim.allocation_simulated)
        self.assertTrue(sim.cleanup_attempted)
        self.assertTrue(sim.cleanup_simulated_successful)
        result = sim.to_dict()
        self.assertEqual(result["api_version"], API_VERSION)
        self.assertEqual(result["plan_digest_sha256"], self.plan.digest_sha256)
        self.assertEqual(result["maximum_concurrent_vms"], 1)
        self.assertTrue(result["simulated"])
        for key in (
            "real_vm_allocated", "real_vm_booted", "host_storage_modified",
            "guest_network_modified", "provider_permission_verified",
            "artifacts_verified", "execution_authorized", "cleanup_verified_on_host",
            "operator_attention_required",
        ):
            with self.subTest(key=key):
                self.assertIs(result[key], False)

    def test_failure_paths_all_attempt_simulated_cleanup(self):
        cases = (
            (VMSimulationScenario.START_FAILURE, VMFailureReason.START_FAILED),
            (VMSimulationScenario.RUNTIME_FAILURE, VMFailureReason.RUNTIME_FAILED),
            (VMSimulationScenario.TIMEOUT, VMFailureReason.DEADLINE_EXCEEDED),
            (VMSimulationScenario.CANCELLED, VMFailureReason.USER_CANCELLED),
        )
        for scenario, reason in cases:
            with self.subTest(scenario=scenario):
                result = simulate_vm_lifecycle(self.plan, scenario)
                self.assertIs(result.final_state, VMFinalState.SIMULATED_TERMINATED)
                self.assertIs(result.failure_reason, reason)
                self.assertTrue(result.cleanup_attempted)
                self.assertTrue(result.cleanup_simulated_successful)
                self.assertEqual(result.events[-1].phase, "terminated")
                self.assertNotEqual(result.failure_reason, VMFailureReason.NONE)

    def test_cleanup_failure_is_unresolved_and_requests_operator_review(self):
        result = simulate_vm_lifecycle(self.plan, VMSimulationScenario.CLEANUP_FAILURE)
        self.assertIs(result.final_state, VMFinalState.SIMULATED_CLEANUP_UNRESOLVED)
        self.assertIs(result.failure_reason, VMFailureReason.CLEANUP_FAILED)
        self.assertTrue(result.cleanup_attempted)
        self.assertFalse(result.cleanup_simulated_successful)
        self.assertTrue(result.to_dict()["operator_attention_required"])
        self.assertEqual(result.events[-1].phase, "cleanup_unresolved")
        with self.assertRaises(VMLifecycleError):
            replace(result, final_state=VMFinalState.SIMULATED_TERMINATED)

    def test_capacity_blocked_never_allocates_and_never_calls_cleanup(self):
        result = simulate_vm_lifecycle(self.plan, VMSimulationScenario.CAPACITY_BLOCKED)
        self.assertIs(result.final_state, VMFinalState.SIMULATED_BLOCKED)
        self.assertIs(result.failure_reason, VMFailureReason.REPORTED_CAPACITY_BLOCK)
        self.assertFalse(result.allocation_simulated)
        self.assertFalse(result.cleanup_attempted)
        self.assertFalse(result.cleanup_simulated_successful)
        self.assertEqual([event.phase for event in result.events], ["validated", "blocked"])

    def test_event_log_is_bounded_sequential_and_has_no_outside_inputs(self):
        for scenario in VMSimulationScenario:
            with self.subTest(scenario=scenario):
                result = simulate_vm_lifecycle(self.plan, scenario)
                self.assertLessEqual(len(result.events), MAX_EVENTS)
                self.assertEqual(
                    [item.sequence for item in result.events],
                    list(range(1, len(result.events) + 1)),
                )
                self.assertNotIn("ssh", result.canonical_json().decode())
                self.assertNotIn("kubeconfig", result.canonical_json().decode())

    def test_time_budget_is_from_validated_plan_and_only_simulated(self):
        for secs in (300, 900, 1800):
            with self.subTest(seconds=secs):
                plan = self.plan.design
                plan["guest"]["max_runtime_seconds"] = secs
                from slipcage_engine.vm_plan import validate_vm_plan_bytes
                checked = validate_vm_plan_bytes(json.dumps(plan).encode())
                timed = simulate_vm_lifecycle(checked, VMSimulationScenario.TIMEOUT)
                self.assertEqual(timed.max_runtime_seconds, secs)
                self.assertEqual(timed.simulated_elapsed_seconds, secs)
                self.assertFalse(timed.to_dict()["real_vm_booted"])

    def test_plan_spoofing_and_scenarios_strings_fail_closed(self):
        for bad in (None, "success", "start_failure", True, 123):
            with self.subTest(bad=bad), self.assertRaises(VMLifecycleError):
                simulate_vm_lifecycle(self.plan, bad)
        with self.assertRaises(VMLifecycleError):
            simulate_vm_lifecycle(None, VMSimulationScenario.SUCCESS)
        with self.assertRaises(VMLifecycleError):
            simulate_vm_lifecycle(replace(self.plan, digest_sha256="0" * 64),
                                  VMSimulationScenario.SUCCESS)
        with self.assertRaises(VMLifecycleError):
            simulate_vm_lifecycle(replace(self.plan, canonical_json=b"{}"),
                                  VMSimulationScenario.SUCCESS)

    def test_frozen_result_refuses_fake_terminal_state(self):
        simulated = simulate_vm_lifecycle(self.plan, VMSimulationScenario.SUCCESS)
        with self.assertRaises(FrozenInstanceError):
            simulated.cleanup_simulated_successful = False
        with self.assertRaises(VMLifecycleError):
            replace(simulated, cleanup_simulated_successful=False)
        with self.assertRaises(VMLifecycleError):
            replace(simulated, events=())

    def test_sequential_pair_runs_candidate_only_after_clean_success(self):
        pair = simulate_sequential_pair(
            self.plan, VMSimulationScenario.SUCCESS, VMSimulationScenario.SUCCESS,
        )
        self.assertIsNotNone(pair["candidate"])
        self.assertTrue(pair["candidate_attempted"])
        self.assertEqual(pair["maximum_concurrent_vms"], 1)
        self.assertFalse(pair["real_vm_booted"])
        self.assertFalse(pair["host_storage_modified"])
        self.assertEqual(pair["baseline"]["final_state"], "simulated_terminated")
        self.assertEqual(pair["candidate"]["final_state"], "simulated_terminated")

    def test_sequential_pair_stops_after_baseline_failure(self):
        for bad in (
            VMSimulationScenario.CAPACITY_BLOCKED,
            VMSimulationScenario.START_FAILURE,
            VMSimulationScenario.RUNTIME_FAILURE,
            VMSimulationScenario.TIMEOUT,
            VMSimulationScenario.CANCELLED,
            VMSimulationScenario.CLEANUP_FAILURE,
        ):
            with self.subTest(bad=bad):
                pair = simulate_sequential_pair(
                    self.plan, bad, VMSimulationScenario.SUCCESS,
                )
                self.assertIsNone(pair["candidate"])
                self.assertFalse(pair["candidate_attempted"])
                self.assertFalse(pair["real_vm_booted"])
                self.assertFalse(pair["host_storage_modified"])

    def test_sequential_pair_records_candidate_cleanup_failure_explicitly(self):
        result = simulate_sequential_pair(
            self.plan, VMSimulationScenario.SUCCESS, VMSimulationScenario.CLEANUP_FAILURE,
        )
        self.assertTrue(result["candidate_attempted"])
        self.assertEqual(result["candidate"]["final_state"], "simulated_cleanup_unresolved")
        self.assertTrue(result["candidate"]["operator_attention_required"])

    def test_simulation_outputs_are_deterministic_and_serializable(self):
        left = simulate_vm_lifecycle(self.plan, VMSimulationScenario.SUCCESS)
        right = simulate_vm_lifecycle(self.plan, VMSimulationScenario.SUCCESS)
        self.assertEqual(left.canonical_json(), right.canonical_json())
        self.assertEqual(json.loads(left.canonical_json()), left.to_dict())
        pair1 = simulate_sequential_pair(
            self.plan, VMSimulationScenario.SUCCESS, VMSimulationScenario.CANCELLED)
        pair2 = simulate_sequential_pair(
            self.plan, VMSimulationScenario.SUCCESS, VMSimulationScenario.CANCELLED)
        self.assertEqual(pair1, pair2)

    def test_cli_success_still_explicitly_synthetic(self):
        status, out, err = self._invoke([
            "simulate-vm-lifecycle", str(PLAN), "--scenario", "success", "--json"])
        self.assertEqual((status, err), (0, ""))
        data = json.loads(out)
        self.assertFalse(data["real_vm_booted"])
        self.assertFalse(data["execution_authorized"])
        self.assertEqual(data["failure_reason"], "none")
        self.assertTrue(data["cleanup_simulated_successful"])

    def test_cli_failure_codes_are_distinct(self):
        for scenario, expected in (
            ("start_failure", 4), ("runtime_failure", 4),
            ("timeout", 4), ("cancelled", 4),
            ("capacity_blocked", 4), ("cleanup_failure", 5),
        ):
            with self.subTest(scenario=scenario):
                rc, out, err = self._invoke(
                    ["simulate-vm-lifecycle", str(PLAN),
                     "--scenario", scenario, "--json"])
                self.assertEqual((rc, err), (expected, ""))
                self.assertTrue(json.loads(out)["simulated"])

    def test_cli_sequential_gate_and_stale_candidate_refusal(self):
        rc, out, err = self._invoke(
            ["simulate-vm-pair", str(PLAN),
             "--baseline-scenario", "cleanup_failure",
             "--candidate-scenario", "success", "--json"])
        self.assertEqual((rc, err), (5, ""))
        self.assertFalse(json.loads(out)["candidate_attempted"])
        rc, out, err = self._invoke(
            ["simulate-vm-pair", str(PLAN),
             "--baseline-scenario", "success",
             "--candidate-scenario", "success", "--json"])
        self.assertEqual((rc, err), (0, ""))
        self.assertTrue(json.loads(out)["candidate_attempted"])

    def test_cli_invalid_plan_and_unimplemented_real_run_fail(self):
        rc, out, err = self._invoke(
            ["simulate-vm-lifecycle", "/nonexistent/path.json",
             "--scenario", "success", "--json"])
        self.assertEqual(rc, 2)
        self.assertEqual(out, "")
        self.assertIn("simulate-vm-lifecycle", err)
        for command in ("run", "compare", "report"):
            self.assertEqual(self._invoke([command])[0], 3)

    def test_vm_simulation_never_uses_process_network_or_disk_writes(self):
        import subprocess
        import socket
        from slipcage_engine import vm_lifecycle
        with (
            patch.object(subprocess, "Popen", side_effect=AssertionError("Popen")),
            patch.object(subprocess, "run", side_effect=AssertionError("run")),
            patch.object(socket, "socket", side_effect=AssertionError("network")),
            patch.object(vm_lifecycle, "open", create=True, side_effect=AssertionError("file open")),
        ):
            simulate_vm_lifecycle(self.plan, VMSimulationScenario.SUCCESS)
            simulate_sequential_pair(
                self.plan, VMSimulationScenario.SUCCESS, VMSimulationScenario.TIMEOUT)
        # No guest assets were created by these in-memory simulations.
        self.assertFalse((ROOT / "examples" / "vm-plans" / "guest.qcow2").exists())


if __name__ == "__main__":
    unittest.main()
