"""SC-13b5: pure VM supervision fault model, NEVER a host/guest runner."""
from contextlib import redirect_stdout, redirect_stderr
from dataclasses import replace, FrozenInstanceError
import hashlib
import io
import json
import os
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
from slipcage_engine.vm_plan import load_vm_plan, validate_vm_plan_bytes
from slipcage_engine.vm_assets import ARTIFACTS, verify_local_vm_assets
from slipcage_engine.vm_supervision import (
    MAX_AUDIT_EVENTS, SupervisionError, SupervisionEvent, SupervisionOutcome,
    SupervisionPhase, SupervisionScenario, design_supervision, new_journal,
    simulate_supervision, simulate_supervision_pair, transition,
)

EXAMPLE = ROOT / "examples" / "vm-plans" / "k3s-synthetic-design.json"


class SupervisorContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.asset_root = self.root / "assets"
        self.asset_root.mkdir()
        self.asset_root.chmod(0o700)
        config = load_vm_plan(EXAMPLE).design
        config["provenance"]["pin_status"] = "operator_supplied_unverified"
        config["provenance"]["note"] = "CI-only fake asset bytes; no verified upstream publisher"
        config["software"]["guest_kernel_release"] = "6.8.0-test"
        for i, (digest_field, filename, _) in enumerate(ARTIFACTS):
            data = (f"SC-13b5 fake bytes {digest_field} {i}".encode() * 2)
            file = self.asset_root / filename
            file.write_bytes(data)
            file.chmod(0o600)
            config["artifacts"][digest_field] = hashlib.sha256(data).hexdigest()
        self.plan = validate_vm_plan_bytes(json.dumps(config).encode())
        self.plan_path = self.root / "vm-plan.json"
        self.plan_path.write_bytes(self.plan.canonical_json)
        self.preflight = verify_local_vm_assets(self.plan, self.asset_root)
        self.design = design_supervision(self.plan, self.preflight)

    def call(self, args):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            returncode = main(args)
        return returncode, output.getvalue(), errors.getvalue()

    def test_bounded_supervisor_design_is_never_real_enforcement(self):
        p = self.design.to_dict()
        self.assertEqual(p["guest_vcpu"], 2)
        self.assertEqual(p["guest_memory_mib"], 4096)
        self.assertEqual(p["disk_overlay_limit_gib"], 24)
        self.assertEqual(p["max_runtime_seconds"], 900)
        self.assertEqual(p["proposed_cpu_quota_percent"], 200)
        self.assertEqual(p["proposed_memory_max_mib"], 4608)
        self.assertEqual(p["proposed_tasks_max"], 256)
        self.assertEqual(p["max_parallel_guests"], 1)
        for field in (
            "overlay_creation_implemented", "overlay_limit_enforced_on_host",
            "os_cgroup_limits_enforced", "watchdog_process_enforced",
            "exclusive_host_lease_implemented",
        ):
            self.assertIs(p[field], False)

    def test_simulated_success_full_state_sequence(self):
        journal = simulate_supervision(self.plan, self.preflight, SupervisionScenario.SUCCESS)
        self.assertIs(journal.phase, SupervisionPhase.CLEAN)
        self.assertIs(journal.outcome, SupervisionOutcome.COMPLETED)
        self.assertIsNone(journal.active_attempt)
        self.assertEqual(journal.revision, len(journal.events))
        self.assertEqual(
            [e.action for e in journal.events],
            [SupervisionEvent.RESERVE, SupervisionEvent.START, SupervisionEvent.OBSERVE,
             SupervisionEvent.FINISH, SupervisionEvent.CLEANUP_OK],
        )
        data = journal.to_dict()
        self.assertTrue(data["simulated"])
        self.assertTrue(data["single_guest_fencing_simulated"])
        self.assertFalse(data["real_exclusive_lease_acquired"])
        for flag in (
            "durable_journal_written", "real_guest_started", "real_guest_stopped",
            "host_resources_reserved", "cgroup_supervision_verified",
            "watchdog_enforced", "overlay_created", "overlay_deleted",
            "reconciliation_verified_on_host", "operator_clearance_granted",
            "execution_authorized", "host_modified",
        ):
            with self.subTest(flag=flag):
                self.assertIs(data[flag], False)

    def test_all_failure_scenarios_are_explicit_and_never_claim_cleanup(self):
        expectations = (
            (SupervisionScenario.START_FAILURE, SupervisionPhase.CLEAN, SupervisionOutcome.START_FAILED),
            (SupervisionScenario.DEADLINE, SupervisionPhase.CLEAN, SupervisionOutcome.DEADLINE_EXCEEDED),
            (SupervisionScenario.RESOURCE_PRESSURE, SupervisionPhase.CLEAN, SupervisionOutcome.RESOURCE_LIMIT_EXCEEDED),
            (SupervisionScenario.CANCELLED, SupervisionPhase.CLEAN, SupervisionOutcome.CANCELLED),
            (SupervisionScenario.CRASH, SupervisionPhase.QUARANTINED, SupervisionOutcome.CRASH_UNRESOLVED),
            (SupervisionScenario.CLEANUP_FAILURE, SupervisionPhase.QUARANTINED, SupervisionOutcome.CLEANUP_UNRESOLVED),
        )
        for scenario, phase, outcome in expectations:
            with self.subTest(scenario=scenario):
                journal = simulate_supervision(self.plan, self.preflight, scenario)
                self.assertIs(journal.phase, phase)
                self.assertIs(journal.outcome, outcome)
                self.assertFalse(journal.to_dict()["reconciliation_verified_on_host"])
                self.assertFalse(journal.to_dict()["real_guest_started"])
                if phase is SupervisionPhase.QUARANTINED:
                    self.assertEqual(journal.active_attempt, "baseline")
                    with self.assertRaises(SupervisionError):
                        transition(journal, SupervisionEvent.RESERVE, "candidate",
                                   expected_revision=journal.revision)
                else:
                    self.assertIsNone(journal.active_attempt)

    def test_stale_revision_cannot_release_or_start_lease(self):
        idle = new_journal(self.design)
        reserved = transition(idle, SupervisionEvent.RESERVE, "baseline", expected_revision=0)
        with self.assertRaisesRegex(SupervisionError, "Stale revision"):
            transition(reserved, SupervisionEvent.START, "baseline", expected_revision=0)
        with self.assertRaises(SupervisionError):
            transition(reserved, SupervisionEvent.START, "candidate", expected_revision=1)
        with self.assertRaises(SupervisionError):
            transition(reserved, SupervisionEvent.RESERVE, "candidate", expected_revision=1)
        self.assertIs(reserved.phase, SupervisionPhase.RESERVED)
        self.assertEqual(reserved.revision, 1)

    def test_illegal_stage_transitions_fail_closed(self):
        idle = new_journal(self.design)
        for action in (
            SupervisionEvent.START, SupervisionEvent.FINISH,
            SupervisionEvent.CANCEL, SupervisionEvent.CLEANUP_OK,
            SupervisionEvent.CLEANUP_FAILED, SupervisionEvent.CRASH,
        ):
            with self.subTest(action=action), self.assertRaises(SupervisionError):
                transition(idle, action, "baseline", expected_revision=0)
        reserved = transition(idle, SupervisionEvent.RESERVE, "baseline", expected_revision=0)
        with self.assertRaises(SupervisionError):
            transition(reserved, SupervisionEvent.CLEANUP_OK, "baseline", expected_revision=1)
        with self.assertRaises(SupervisionError):
            transition(reserved, SupervisionEvent.FINISH, "baseline", expected_revision=1)
        running = transition(reserved, SupervisionEvent.START, "baseline", expected_revision=1)
        with self.assertRaises(SupervisionError):
            transition(running, SupervisionEvent.START, "baseline", expected_revision=2)
        with self.assertRaises(SupervisionError):
            transition(running, SupervisionEvent.CLEANUP_FAILED, "baseline", expected_revision=2)

    def test_monotonic_watchdog_and_resource_budget_signals_are_only_simulated(self):
        reserved = transition(new_journal(self.design), SupervisionEvent.RESERVE, "baseline",
                              expected_revision=0)
        running = transition(reserved, SupervisionEvent.START, "baseline", expected_revision=1)
        sampling = transition(running, SupervisionEvent.OBSERVE, "baseline",
                              expected_revision=2, elapsed_seconds=50,
                              memory_mib=4096, overlay_mib=50, tasks=4)
        self.assertIs(sampling.phase, SupervisionPhase.RUNNING)
        with self.assertRaises(SupervisionError):
            transition(sampling, SupervisionEvent.OBSERVE, "baseline",
                       expected_revision=3, elapsed_seconds=49)
        at_deadline = transition(sampling, SupervisionEvent.OBSERVE, "baseline",
                                 expected_revision=3,
                                 elapsed_seconds=self.design.max_runtime_seconds)
        self.assertIs(at_deadline.phase, SupervisionPhase.STOPPING)
        self.assertIs(at_deadline.outcome, SupervisionOutcome.DEADLINE_EXCEEDED)
        self.assertFalse(at_deadline.to_dict()["watchdog_enforced"])

    def test_cpu_memory_tasks_overlay_policy_bounds_are_modeled(self):
        for kw in (
            {"memory_mib": self.design.proposed_memory_max_mib + 1},
            {"overlay_mib": self.design.disk_overlay_limit_gib * 1024 + 1},
            {"tasks": self.design.proposed_tasks_max + 1},
        ):
            with self.subTest(kw=kw):
                a = transition(new_journal(self.design), SupervisionEvent.RESERVE,
                               "baseline", expected_revision=0)
                b = transition(a, SupervisionEvent.START, "baseline", expected_revision=1)
                c = transition(b, SupervisionEvent.OBSERVE, "baseline",
                               expected_revision=2, elapsed_seconds=1, **kw)
                self.assertIs(c.phase, SupervisionPhase.STOPPING)
                self.assertIs(c.outcome, SupervisionOutcome.RESOURCE_LIMIT_EXCEEDED)

    def test_forged_bad_samples_and_owner_ids_rejected(self):
        j = new_journal(self.design)
        for attempt in (None, "", "two/words", "UPPER", "a"*34, "foo\nbar"):
            with self.subTest(attempt=attempt), self.assertRaises(SupervisionError):
                transition(j, SupervisionEvent.RESERVE, attempt, expected_revision=0)
        for value in (True, -1, "1", 2**40):
            with self.subTest(value=value), self.assertRaises(SupervisionError):
                transition(j, SupervisionEvent.RESERVE, "baseline",
                           expected_revision=0, memory_mib=value)
        with self.assertRaises(SupervisionError):
            transition(j, "reserve", "baseline", expected_revision=0)
        with self.assertRaises(SupervisionError):
            transition(j, SupervisionEvent.RESERVE, "baseline", expected_revision=True)

    def test_successful_sequential_pair_and_no_reused_lease(self):
        pair = simulate_supervision_pair(
            self.plan, self.preflight, SupervisionScenario.SUCCESS, SupervisionScenario.SUCCESS)
        self.assertTrue(pair["candidate_attempted"])
        self.assertEqual(pair["baseline"]["phase"], "clean")
        self.assertEqual(pair["candidate"]["phase"], "clean")
        self.assertEqual(pair["candidate"]["last_attempt"], "candidate")
        self.assertGreater(pair["candidate"]["revision"], pair["baseline"]["revision"])
        self.assertEqual(pair["max_parallel_guests"], 1)
        with self.assertRaises(SupervisionError):
            simulate_supervision(self.plan, self.preflight, SupervisionScenario.SUCCESS,
                                 attempt_id="baseline", journal=simulate_supervision(
                                     self.plan, self.preflight, SupervisionScenario.SUCCESS))

    def test_baseline_not_successful_blocks_candidate_under_all_failures(self):
        for scenario in (
            SupervisionScenario.START_FAILURE, SupervisionScenario.DEADLINE,
            SupervisionScenario.RESOURCE_PRESSURE, SupervisionScenario.CANCELLED,
            SupervisionScenario.CRASH, SupervisionScenario.CLEANUP_FAILURE,
        ):
            with self.subTest(scenario=scenario):
                pair = simulate_supervision_pair(self.plan, self.preflight,
                                                 scenario, SupervisionScenario.SUCCESS)
                self.assertFalse(pair["candidate_attempted"])
                self.assertIsNone(pair["candidate"])
                self.assertFalse(pair["real_guest_started"])
                self.assertFalse(pair["execution_authorized"])

    def test_audit_is_bounded_canonical_and_immutable(self):
        journal = simulate_supervision(self.plan, self.preflight, SupervisionScenario.SUCCESS)
        self.assertLessEqual(journal.revision, MAX_AUDIT_EVENTS)
        self.assertEqual(json.loads(journal.canonical_json()), journal.to_dict())
        self.assertEqual(journal.canonical_json(),
                         simulate_supervision(self.plan, self.preflight,
                                              SupervisionScenario.SUCCESS).canonical_json())
        with self.assertRaises(FrozenInstanceError):
            journal.revision = 0
        with self.assertRaises(SupervisionError):
            transition(replace(journal, revision=1), SupervisionEvent.RESERVE, "other",
                       expected_revision=1)
        with self.assertRaises(SupervisionError):
            transition(replace(journal, events=()), SupervisionEvent.RESERVE, "other",
                       expected_revision=journal.revision)
        record = journal.canonical_json().decode()
        self.assertNotIn(str(self.root), record)
        self.assertNotIn("/dev/kvm", record)

    def test_plan_synthetic_and_preflight_mismatch_rejected(self):
        with self.assertRaises(SupervisionError):
            design_supervision(load_vm_plan(EXAMPLE), self.preflight)
        with self.assertRaises(SupervisionError):
            design_supervision(replace(self.plan, digest_sha256="0"*64), self.preflight)
        with self.assertRaises(SupervisionError):
            design_supervision(self.plan, replace(self.preflight, plan_digest_sha256="0"*64))
        with self.assertRaises(SupervisionError):
            simulate_supervision(self.plan, self.preflight, "success")

    def test_cli_explicitly_synthetic_failure_and_quarantine_exit_codes(self):
        for scenario, code, outcome in (
            ("success", 0, "completed"),
            ("start_failure", 4, "start_failed"),
            ("deadline", 4, "deadline_exceeded"),
            ("resource_pressure", 4, "resource_limit_exceeded"),
            ("cancelled", 4, "cancelled"),
            ("crash", 5, "crash_unresolved"),
            ("cleanup_failure", 5, "cleanup_unresolved"),
        ):
            with self.subTest(scenario=scenario):
                rc, out, err = self.call([
                    "simulate-vm-supervision", str(self.plan_path),
                    "--assets-dir", str(self.asset_root),
                    "--scenario", scenario, "--json",
                ])
                self.assertEqual((rc,err),(code,""))
                record=json.loads(out)
                self.assertEqual(record["outcome"],outcome)
                self.assertFalse(record["real_exclusive_lease_acquired"])
                self.assertFalse(record["execution_authorized"])

    def test_cli_pair_and_refusal_of_real_commands(self):
        rc, output, err = self.call([
            "simulate-vm-supervision-pair", str(self.plan_path),
            "--assets-dir", str(self.asset_root),
            "--baseline-scenario", "cleanup_failure",
            "--candidate-scenario", "success", "--json",
        ])
        self.assertEqual((rc,err),(5,""))
        self.assertFalse(json.loads(output)["candidate_attempted"])
        rc,output,err=self.call([
            "simulate-vm-supervision-pair", str(self.plan_path),
            "--assets-dir", str(self.asset_root),
            "--baseline-scenario", "success",
            "--candidate-scenario", "success", "--json",
        ])
        self.assertEqual((rc,err),(0,""))
        self.assertTrue(json.loads(output)["candidate_attempted"])
        for command in ("run","compare","report"):
            self.assertEqual(self.call([command])[0],3)

    def test_no_host_side_effects_in_supervision_design(self):
        from slipcage_engine import vm_supervision as module
        blobs={p.name:p.read_bytes() for p in self.asset_root.iterdir()}
        with (
            patch.object(subprocess,"Popen",side_effect=AssertionError("Popen")),
            patch.object(subprocess,"run",side_effect=AssertionError("run")),
            patch.object(socket,"socket",side_effect=AssertionError("socket")),
            patch.object(os,"system",side_effect=AssertionError("shell")),
            patch.object(module,"open",create=True,side_effect=AssertionError("open")),
        ):
            result=simulate_supervision(self.plan,self.preflight,SupervisionScenario.CRASH)
            self.assertEqual(result.phase,SupervisionPhase.QUARANTINED)
        self.assertEqual(blobs,{p.name:p.read_bytes() for p in self.asset_root.iterdir()})


if __name__=="__main__":
    unittest.main()
