"""v0.8: no-QEMU fault recovery drills in isolated disposable fixtures."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "slipcage-fault-drill.py"
AUDIT = ROOT / "scripts" / "slipcage-experiment-audit.py"
spec = importlib.util.spec_from_file_location("fault_drill", SCRIPT)
drill = importlib.util.module_from_spec(spec)
spec.loader.exec_module(drill)


class FaultDrillTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.state = self.root / "isolated-fault"
        self.cg = self.root / "cgroup"
        self.cg.mkdir()

    def cgroup_fixture(self, *, memory="134217728", cpu="25000 100000",
                       tasks="32", member="/system.slice/test.service"):
        (self.root / "proc-cgroup").write_text(f"0::{member}\n")
        leaf = self.cg / member.lstrip("/")
        leaf.mkdir(parents=True, exist_ok=True)
        (leaf / "memory.max").write_text(memory)
        (leaf / "cpu.max").write_text(cpu)
        (leaf / "pids.max").write_text(tasks)
        return self.root / "proc-cgroup"

    def test_sleeping_local_process_tree_is_terminated(self):
        result = drill.timeout_drill()
        self.assertTrue(result["passed"], result)
        self.assertTrue(result["timeout_exercised"])
        self.assertTrue(result["worker_killed"])
        self.assertTrue(result["child_no_longer_running"])
        self.assertLess(result["elapsed_seconds"], 4)

    def test_partial_report_writer_is_killed_and_auditor_detects_it(self):
        workspace = self.root / "fixture"
        workspace.mkdir()
        result = drill.report_drill(workspace, audit_script=AUDIT)
        self.assertTrue(result["passed"], result)
        self.assertTrue(result["partial_report_preserved"])
        self.assertTrue(result["final_report_not_published"])
        self.assertEqual(result["audit_classification"], "interrupted_or_incomplete")
        run = next((workspace / "fixture-state" / "runs").glob("run-*"))
        self.assertTrue((run / "run.json").is_file())
        self.assertFalse((run / "summary.json").exists())
        self.assertTrue((run / "summary.json.tmp").is_file())

    def test_cgroup_v2_bounds_detected_without_exhausting_resources(self):
        proc = self.cgroup_fixture()
        result = drill.cgroup_drill(cgroup_root=self.cg, proc_cgroup=proc)
        self.assertTrue(result["passed"], result)
        self.assertEqual(result["memory_max_bytes"], 134217728)
        self.assertEqual(result["pids_max"], 32)
        self.assertEqual(result["cpu_quota_fraction"], 0.25)

    def test_overlarge_or_unbounded_kernel_quotas_fail_closed(self):
        for key, value in (
            ("memory", "max"), ("memory", "268435456"),
            ("cpu", "max 100000"), ("cpu", "50000 100000"),
            ("tasks", "max"), ("tasks", "1024"),
        ):
            kw = {key: value}
            proc = self.cgroup_fixture(**kw)
            result = drill.cgroup_drill(cgroup_root=self.cg, proc_cgroup=proc)
            self.assertFalse(result["passed"], (key, value, result))

    def test_rejects_missing_or_legacy_cgroup_hierarchy(self):
        proc = self.root / "proc-cgroup"
        proc.write_text("5:cpu,cpuacct:/somewhere\n")
        result = drill.cgroup_drill(cgroup_root=self.cg, proc_cgroup=proc)
        self.assertFalse(result["passed"])
        self.assertEqual(result["reason"], "cgroup_v2_unavailable")

    def test_single_report_mode_keeps_all_evidence_private(self):
        result = drill.run_drill("report", state=self.state, audit_script=AUDIT)
        self.assertTrue(result["passed"], result)
        self.assertFalse(result["qemu_started"])
        self.assertFalse(result["live_data_modified"])
        folder = Path(result["run_dir"])
        self.assertEqual(folder.stat().st_mode & 0o777, 0o700)
        self.assertEqual((folder / "summary.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual((folder / "report.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads((folder / "summary.json").read_text())["passed"], True)

    def test_all_modes_stop_on_first_failure_without_vm(self):
        with patch.object(drill, "timeout_drill", return_value={
            "drill": "timeout", "passed": False, "reason": "fake_failure"
        }), patch.object(drill, "report_drill") as report, patch.object(
            drill, "cgroup_drill"
        ) as cg:
            result = drill.run_drill("all", state=self.state, audit_script=AUDIT)
        self.assertFalse(result["passed"])
        self.assertEqual([x["drill"] for x in result["results"]], ["timeout"])
        report.assert_not_called()
        cg.assert_not_called()
        self.assertFalse(result["qemu_started"])

    def test_disallowed_modes_and_symlinked_state_fail_before_work(self):
        with self.assertRaises(ValueError):
            drill.run_drill("qemu", state=self.state)
        target = self.root / "another"
        target.mkdir()
        self.state.symlink_to(target)
        with self.assertRaises(ValueError):
            drill.run_drill("timeout", state=self.state)

    def test_instance_is_serialized_by_flock(self):
        self.state.mkdir()
        import fcntl
        with (self.state / ".drill.lock").open("a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                drill.run_drill("timeout", state=self.state)

    def test_manual_systemd_unit_never_grants_kvm_or_network(self):
        text = (ROOT / "systemd" / "slipcage-fault-drill@.service").read_text()
        playbook = (ROOT / "playbooks" / "site.yml").read_text()
        for item in (
            "User=slipcage-vmprobe", "PrivateNetwork=yes", "PrivateDevices=yes",
            "ProtectSystem=strict", "NoNewPrivileges=yes",
            "MemoryMax=128M", "CPUQuota=25%", "TasksMax=32",
            "TimeoutStartSec=40s", "KillMode=control-group",
            "StateDirectory=slipcage-fault",
        ):
            self.assertIn(item, text)
        self.assertNotIn("DeviceAllow=/dev/kvm", text)
        self.assertNotIn("WantedBy=", text)
        self.assertNotIn("RuntimeMaxSec=", text)
        self.assertNotIn("enabled: true", playbook.split(
            "- name: Install disabled-by-default manual fault drill template")[1].split(
            "- name: Restrict offsite-credential directory")[0])

    def test_safety_no_unsafe_external_payloads_or_vms(self):
        source = SCRIPT.read_text()
        self.assertNotIn("qemu-system", source)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("sudo ", source)
        self.assertNotIn("stress-ng", source)
        self.assertNotIn("curl ", source)
        self.assertNotIn("wget ", source)


if __name__ == "__main__":
    unittest.main()
