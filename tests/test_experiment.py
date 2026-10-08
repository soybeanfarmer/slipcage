"""Offline tests for fixed benign arithmetic + SHA-256 microguest experiments."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


probe = load("experiment_probe", ROOT / "scripts" / "slipcage-kvm-probe.py")
lifecycle = load("experiment_lifecycle", ROOT / "scripts" / "slipcage-guest-lifecycle.py")


def markers():
    return "\n".join(probe.EXPERIMENT_MARKERS) + "\n"


class ControlledExperimentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.kernel = self.root / "vmlinuz"
        self.initrd = self.root / "experiment-v1.cpio.gz"
        self.kernel.write_bytes(b"dummy")
        self.initrd.write_bytes(b"dummy")

    def execute_mock(self, stdout=None, rc=0):
        command = []
        def runner(args, **kwargs):
            command.extend(args)
            self.assertIn("q35,accel=kvm", args)
            self.assertEqual(args[args.index("-nic") + 1], "none")
            self.assertIn("-no-user-config", args)
            self.assertIn("-nodefaults", args)
            self.assertIn("-kernel", args)
            self.assertIn("-initrd", args)
            self.assertIn(str(self.kernel), args)
            self.assertIn(str(self.initrd), args)
            self.assertNotIn("-drive", args)
            self.assertNotIn("-netdev", args)
            self.assertNotIn("-virtfs", args)
            self.assertNotIn("-cdrom", args)
            self.assertEqual(kwargs["timeout"], 75)
            return Mock(returncode=rc, stdout=markers() if stdout is None else stdout,
                        stderr="")
        with patch.object(probe, "inspect", return_value={
            "process_can_open_kvm": True, "qemu_binary_available": True,
        }):
            result = probe.run_experiment(runner=runner,
                                          kernel_path=self.kernel, initrd_path=self.initrd)
        self.assertEqual(command[0], probe.QEMU)
        return result

    def test_both_known_answers_and_clean_shutdown_required(self):
        result = self.execute_mock()
        self.assertTrue(result["experiment_passed"])
        self.assertTrue(result["known_answers_verified"])
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["workload"], "fixed_arithmetic_sha256_v1")
        self.assertEqual(result["missing_markers"], [])
        self.assertGreaterEqual(result["wall_seconds"], 0)
        self.assertGreaterEqual(result["cpu_user_seconds"], 0)
        self.assertGreaterEqual(result["cpu_system_seconds"], 0)
        self.assertIsInstance(result["qemu_peak_rss_kib"], int)
        self.assertEqual(result["network"], "disabled")
        self.assertIs(result["persistent_guest_disk"], False)

    def test_missing_any_known_answer_fails_closed(self):
        for absent in probe.EXPERIMENT_MARKERS:
            lines = [x for x in probe.EXPERIMENT_MARKERS if x != absent]
            result = self.execute_mock(stdout="\n".join(lines) + "\n")
            self.assertFalse(result["experiment_passed"])
            self.assertFalse(result["known_answers_verified"])
            self.assertIn(absent, result["missing_markers"])

    def test_console_substrings_are_not_results(self):
        fake = "prefix" + probe.EXPERIMENT_MARKERS[0] + "\n"
        result = self.execute_mock(stdout=fake)
        self.assertFalse(result["experiment_passed"])

    def test_nonzero_qemu_exit_rejects_otherwise_correct_result(self):
        result = self.execute_mock(rc=1)
        self.assertFalse(result["experiment_passed"])
        self.assertTrue(result["known_answers_verified"])

    def test_inner_timeout_refuses_success(self):
        with patch.object(probe, "inspect", return_value={
            "process_can_open_kvm": True, "qemu_binary_available": True,
        }):
            def fail_runner(*_args, **_kwargs):
                raise subprocess.TimeoutExpired(cmd="qemu", timeout=75)
            result = probe.run_experiment(runner=fail_runner,
                                          kernel_path=self.kernel, initrd_path=self.initrd)
        self.assertFalse(result["experiment_passed"])
        self.assertEqual(result["reason"], "TimeoutExpired")

    def make_probe(self, *, valid=True, success=True):
        data = {
            "experiment_passed": success,
            "known_answers_verified": valid,
            "workload": "fixed_arithmetic_sha256_v1",
            "network": "disabled",
            "persistent_guest_disk": False,
            "exit_code": 0 if success else 1,
            "cpu_user_seconds": 0.1, "cpu_system_seconds": 0.2,
            "qemu_peak_rss_kib": 14000, "wall_seconds": 0.3,
        }
        script = self.root / "fake-fixed-guest.py"
        script.write_text(
            "import json\nprint(json.dumps(" + repr(data) + "))\n",
            encoding="utf-8",
        )
        return script

    def test_three_experiments_collect_resource_evidence_and_private_logs(self):
        script = self.make_probe()
        report = lifecycle.run_lifecycle(3, probe=script,
                                         state=self.root / "state", timeout=5,
                                         profile="experiment")
        self.assertTrue(report["passed"])
        self.assertEqual(report["successful_cycles"], 3)
        self.assertEqual(report["mode"], "fixed_arithmetic_sha256_v1")
        run_path = Path(report["run_dir"])
        self.assertEqual(len(list(run_path.glob("cycle-*.log"))), 3)
        self.assertEqual(len(list(run_path.glob("cycle-*.json"))), 3)
        for cycle in report["cycles"]:
            self.assertTrue(cycle["known_answers_verified"])
            self.assertEqual(cycle["qemu_resources"]["qemu_peak_rss_kib"], 14000)
            self.assertEqual(cycle["qemu_resources"]["cpu_system_seconds"], 0.2)
        self.assertEqual((run_path / "summary.json").stat().st_mode & 0o777, 0o600)

    def test_missing_known_answer_in_probe_json_fails_closed(self):
        script = self.make_probe(valid=False)
        report = lifecycle.run_lifecycle(3, probe=script,
                                         state=self.root / "state",
                                         timeout=5, profile="experiment")
        self.assertFalse(report["passed"])
        self.assertEqual(report["completed_cycles"], 1)
        self.assertEqual(report["first_failure"], 1)

    def test_missing_or_invalid_resource_measurement_fails_closed(self):
        script = self.make_probe()
        source = script.read_text()
        for replacement in ["None", "'not-a-number'", "float('nan')"]:
            script.write_text(source.replace("'qemu_peak_rss_kib': 14000",
                                              "'qemu_peak_rss_kib': " + replacement))
            report = lifecycle.run_lifecycle(1, probe=script,
                                             state=self.root / "state",
                                             timeout=5, profile="experiment")
            self.assertFalse(report["passed"])
            self.assertEqual(report["completed_cycles"], 1)
            self.assertEqual(report["first_failure"], 1)

    def test_experiment_cycle_limit_and_profile_allowlist(self):
        for value in [4, 5, 100]:
            with self.assertRaises(ValueError):
                lifecycle.run_lifecycle(value, profile="experiment",
                                        state=self.root / "state")
        with self.assertRaises(ValueError):
            lifecycle.run_lifecycle(1, profile="custom-payload",
                                    state=self.root / "state")
        with self.assertRaises(ValueError):
            lifecycle.run_cycle(profile="custom-payload")
        self.assertFalse((self.root / "state").exists())

    def test_guest_image_builder_is_fixed_benign_and_offline(self):
        source = (ROOT / "scripts" / "build-experiment-guest.sh").read_text()
        for line in ("500500", "333833500",
                     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                     "SLIPCAGE_EXPERIMENT_V1_OK", "exec /bin/busybox poweroff -f"):
            self.assertIn(line, source)
        self.assertIn("printf abc | /bin/busybox sha256sum", source)
        self.assertNotIn("curl ", source)
        self.assertNotIn("wget ", source)
        self.assertNotIn("/dev/tcp", source)

    def test_manual_service_is_unprivileged_bounded_and_no_schedule(self):
        unit = (ROOT / "systemd" / "slipcage-experiment@.service").read_text()
        playbook = (ROOT / "playbooks" / "site.yml").read_text()
        for setting in (
            "User=slipcage-vmprobe", "SupplementaryGroups=kvm",
            "PrivateNetwork=yes", "ProtectSystem=strict", "DevicePolicy=closed",
            "DeviceAllow=/dev/kvm rw", "MemoryMax=1280M", "CPUQuota=100%",
            "TasksMax=64", "TimeoutStartSec=5min", "KillMode=control-group",
            "StateDirectory=slipcage-guest", "--profile experiment --cycles %i",
        ):
            self.assertIn(setting, unit)
        self.assertNotIn("WantedBy=", unit)
        self.assertNotIn("RuntimeMaxSec=", unit)
        self.assertIn("Build inert arithmetic and SHA-256 Linux guest image", playbook)
        section = playbook.split("- name: Install manual controlled experiment systemd template")[1]
        self.assertNotIn("enabled: true", section.split(
            "- name: Restrict offsite-credential directory")[0])


if __name__ == "__main__":
    unittest.main()
