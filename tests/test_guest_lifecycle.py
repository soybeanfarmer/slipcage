"""Offline v0.5 reliability tests: bounded rootless benign guest lifecycle."""
from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "scripts" / "slipcage-guest-lifecycle.py"
spec = importlib.util.spec_from_file_location("guest_lifecycle", PATH)
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)


class GuestLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.probe = self.root / "probe.py"

    def tearDown(self):
        self.tmp.cleanup()

    def fake_probe(self, *, passed=True):
        self.probe.write_text(
            "import json\n"
            f"print(json.dumps({{'guest_booted': {passed}, 'exit_code': "
            f"{0 if passed else 1}, 'network': 'disabled', "
            "'persistent_guest_disk': False}))\n"
            f"raise SystemExit({0 if passed else 2})\n", encoding="utf-8"
        )
        return self.probe

    def test_fixed_probe_executes_sequentially_and_writes_private_artifacts(self):
        self.fake_probe()
        report = lifecycle.run_lifecycle(3, probe=self.probe, state=self.state, timeout=5)
        self.assertTrue(report["passed"])
        self.assertEqual((report["completed_cycles"], report["successful_cycles"]), (3, 3))
        run = Path(report["run_dir"])
        self.assertEqual(run.stat().st_mode & 0o777, 0o700)
        self.assertEqual(len(list(run.glob("cycle-*.json"))), 3)
        self.assertEqual(len(list(run.glob("cycle-*.log"))), 3)
        self.assertEqual((run / "summary.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads((run / "summary.json").read_text())["passed"], True)
        for log in run.glob("*.log"):
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)
            self.assertIn("guest_booted", log.read_text())

    def test_stops_after_first_bad_boot_and_preserves_failure(self):
        self.fake_probe(passed=False)
        report = lifecycle.run_lifecycle(5, probe=self.probe, state=self.state, timeout=5)
        self.assertFalse(report["passed"])
        self.assertEqual(report["completed_cycles"], 1)
        self.assertEqual(report["first_failure"], 1)
        self.assertEqual(len(list(Path(report["run_dir"]).glob("cycle-*.json"))), 1)
        self.assertFalse(json.loads((Path(report["run_dir"]) / "summary.json").read_text())["passed"])

    def test_probe_success_requires_structured_guest_boot_and_clean_shutdown(self):
        for content in [
            "SLIPCAGE_MICROGUEST_OK\n",
            '{"guest_booted": true, "exit_code": 0, "network":"enabled",'
            ' "persistent_guest_disk":false}\n',
            '{"guest_booted": true, "exit_code": 1, "network":"disabled",'
            ' "persistent_guest_disk":false}\n',
            '{"guest_booted": 1, "exit_code": 0, "network":"disabled",'
            ' "persistent_guest_disk":false}\n',
        ]:
            self.probe.write_text(f"print({content!r})\n")
            result, _ = lifecycle.run_cycle(self.probe, timeout=5)
            self.assertFalse(result["passed"], content)

    def test_timeout_kills_guest_probe_process_group(self):
        self.probe.write_text("import time\ntime.sleep(30)\n")
        with patch.object(lifecycle.os, "killpg", wraps=lifecycle.os.killpg) as kill:
            result, log = lifecycle.run_cycle(self.probe, timeout=0.05)
        self.assertFalse(result["passed"])
        self.assertEqual(result["reason"], "timeout")
        self.assertTrue(kill.called)
        self.assertEqual(kill.call_args.args[1], signal.SIGKILL)

    def test_negative_or_over_limit_cycles_are_rejected_without_running(self):
        for bad in [-1, 0, 6, 100]:
            with self.assertRaises(ValueError):
                lifecycle.run_lifecycle(bad, state=self.state, cycle_fn=lambda **kwargs: None)
        self.assertFalse(self.state.exists())

    def test_overlapping_instances_refuse_shared_lock(self):
        self.fake_probe()
        self.state.mkdir()
        import fcntl
        lock_path = self.state / ".cycle.lock"
        with lock_path.open("wb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                lifecycle.run_lifecycle(1, probe=self.probe, state=self.state, timeout=5)

    def test_retention_prunes_only_completed_matching_directories(self):
        counter = [0]

        def fake_cycle(**_):
            counter[0] += 1
            return ({"passed": True, "seconds": 0.01}, "benign boot\n")

        for i in range(23):
            report = lifecycle.run_lifecycle(1, state=self.state, cycle_fn=fake_cycle)
            self.assertTrue(report["passed"])
        valid = list((self.state / "runs").glob("run-*"))
        self.assertEqual(len(valid), 20)
        self.assertEqual(counter[0], 23)
        # An unrelated directory is never deleted, regardless of its age.
        sentinel = self.state / "runs" / "unrelated"
        sentinel.mkdir()
        (sentinel / "do-not-remove").write_text("keep")
        lifecycle.run_lifecycle(1, state=self.state, cycle_fn=fake_cycle)
        self.assertEqual((sentinel / "do-not-remove").read_text(), "keep")

    def test_symlinked_state_is_rejected(self):
        target = self.root / "real"
        target.mkdir()
        self.state.symlink_to(target)
        with self.assertRaises(ValueError):
            lifecycle.run_lifecycle(1, state=self.state)

    def test_systemd_unit_is_manual_sandboxed_and_bounded(self):
        unit = (ROOT / "systemd" / "slipcage-guest-cycles@.service").read_text()
        playbook = (ROOT / "playbooks" / "site.yml").read_text()
        self.assertIn("User=slipcage-vmprobe", unit)
        self.assertIn("SupplementaryGroups=kvm", unit)
        self.assertIn("PrivateNetwork=yes", unit)
        self.assertIn("DevicePolicy=closed", unit)
        self.assertIn("DeviceAllow=/dev/kvm rw", unit)
        self.assertIn("MemoryMax=1280M", unit)
        self.assertIn("CPUQuota=100%", unit)
        self.assertIn("TimeoutStartSec=", unit)
        self.assertIn("KillMode=control-group", unit)
        self.assertIn("StateDirectory=slipcage-guest", unit)
        self.assertIn("--cycles %i", unit)
        self.assertNotIn("RuntimeMaxSec=", unit)
        self.assertNotIn("WantedBy=", unit)
        self.assertNotIn("enabled: true", playbook.split(
            "- name: Install manual only nested guest cycle template")[1].split(
            "\n    - name: ", 1)[0])
        self.assertNotIn("slipcage-guest-cycles@", (
            ROOT / "scripts" / "discover.sh").read_text())

    def test_existing_kvm_boot_is_fixed_and_not_general_payload(self):
        source = PATH.read_text()
        self.assertIn('"--experiment" if profile == "experiment" else "--boot"', source)
        self.assertIn("start_new_session=True", source)
        self.assertIn("os.killpg(child.pid, signal.SIGKILL)", source)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("subprocess.run(args", source)


if __name__ == "__main__":
    unittest.main()
