"""SC-13b3 local Linux host observation: all tests use synthetic data/mocks."""
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from slipcage_engine.cli import main
from slipcage_engine.vm_plan import load_vm_plan
from slipcage_engine.vm_host_observe import (
    API_VERSION, HostObservationError, LocalHostObservation,
    _has_cgroup_v2_controllers, _parse_available_memory,
    inspect_local_host,
)

PLAN = ROOT / "examples" / "vm-plans" / "k3s-synthetic-design.json"
FIXED_TIME = datetime(2026, 10, 8, 23, 45, 0, tzinfo=timezone.utc)


class LocalHostObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.scratch = self.root / "scratch"
        self.scratch.mkdir(mode=0o700)
        self.memory = self.root / "meminfo"
        self.memory.write_bytes(b"MemTotal:       32768000 kB\nMemAvailable:   16384000 kB\n")
        self.controllers = self.root / "controllers"
        self.controllers.write_bytes(b"cpu io memory pids\n")
        self.plan = load_vm_plan(PLAN)

    def inspect(self, *, fake_disk_gib=96, fake_inodes=250000,
                cpu=8, mem=None, kvm=True, cgroups=True):
        if mem is not None:
            self.memory.write_bytes(mem)
        filesystem = SimpleNamespace(
            f_frsize=4096, f_bavail=fake_disk_gib * (1024**3 // 4096),
            f_favail=fake_inodes,
        )
        from slipcage_engine import vm_host_observe
        with (
            patch.object(vm_host_observe.os, "fstatvfs", return_value=filesystem),
            patch.object(vm_host_observe, "_is_kvm_character_device", return_value=kvm),
            patch.object(vm_host_observe, "_has_cgroup_v2_controllers", return_value=cgroups),
        ):
            return inspect_local_host(
                self.plan, self.scratch, meminfo_path=self.memory,
                controllers_path=self.controllers,
                cpu_count=lambda: cpu, now=lambda: FIXED_TIME,
            )

    def test_nominal_values_do_not_grant_host_readiness(self):
        result = self.inspect().to_dict()
        self.assertEqual(result["api_version"], API_VERSION)
        self.assertEqual(result["observed_thresholds"], "observed_numeric_thresholds_met")
        self.assertEqual(result["logical_cpu_threads_visible"], 8)
        self.assertEqual(result["mem_available_mib"], 16000)
        self.assertEqual(result["filesystem_free_gib"], 96)
        self.assertEqual(result["filesystem_available_inodes"], 250000)
        self.assertEqual(result["plan_digest_sha256"], self.plan.digest_sha256)
        self.assertTrue(result["kvm_character_device_observed"])
        self.assertTrue(result["cgroup_v2_controllers_observed"])
        for name in (
            "measurement_authenticity_verified", "capacity_reservation_performed",
            "effective_cgroup_limits_verified", "kvm_usable_verified",
            "provider_permission_verified", "active_guest_count_verified",
            "guest_network_isolation_verified", "guest_boot_verified",
            "execution_authorized", "host_modified", "vm_launched",
        ):
            with self.subTest(name=name):
                self.assertIs(result[name], False)

    def test_each_numeric_capacity_deficit_is_explicit(self):
        for kwargs, blocker in (
            ({"cpu": 2}, "visible_cpu_threads_below_declared_headroom"),
            ({"mem": b"MemAvailable: 4096000 kB\n"}, "mem_available_below_declared_headroom"),
            ({"fake_disk_gib": 3}, "scratch_free_disk_below_declared_headroom"),
            ({"fake_inodes": 100}, "scratch_available_inodes_below_threshold"),
        ):
            with self.subTest(kwargs=kwargs):
                result = self.inspect(**kwargs).to_dict()
                self.assertEqual(result["observed_thresholds"], "observed_numeric_thresholds_not_met")
                self.assertIn(blocker, result["blockers"])
                self.assertFalse(result["execution_authorized"])

    def test_missing_kvm_or_cgroup_is_never_reported_ready(self):
        record = self.inspect(kvm=False, cgroups=False).to_dict()
        self.assertIn("kvm_character_device_not_observed", record["blockers"])
        self.assertIn("cgroup_v2_controllers_not_observed", record["blockers"])
        self.assertFalse(record["kvm_usable_verified"])

    def test_short_memory_file_and_duplicate_or_missing_keys_rejected(self):
        for invalid in (
            b"",
            b"MemTotal: 1000 kB\n",
            b"MemAvailable: 1000 kB\nMemAvailable: 2000 kB\n",
            b"MemAvailable: -100 kB\n",
            b"MemAvailable: 1024 MB\n",
            b"\xff\xff",
            b"MemAvailable: 999999999999999999999999999 kB\n",
        ):
            with self.subTest(invalid=invalid[:50]):
                with self.assertRaises(HostObservationError):
                    self.inspect(mem=invalid)

    def test_memory_parser_rounds_down_and_does_not_accept_duplicate_lines(self):
        self.assertEqual(_parse_available_memory(b"MemAvailable: 2047 kB\n"), 1)
        with self.assertRaises(HostObservationError):
            _parse_available_memory(b"MemAvailable: 100 kB\nMemAvailable: 200 kB\n")

    def test_untrusted_scratch_root_symlink_and_missing_path_rejected(self):
        indirect = self.root / "linked"
        indirect.symlink_to(self.scratch, target_is_directory=True)
        with self.assertRaises(HostObservationError):
            inspect_local_host(self.plan, indirect, meminfo_path=self.memory)
        with self.assertRaises(HostObservationError):
            inspect_local_host(self.plan, self.root / "missing", meminfo_path=self.memory)

    def test_spoofed_plan_fails_closed(self):
        with self.assertRaises(HostObservationError):
            inspect_local_host(replace(self.plan, digest_sha256="0"*64), self.scratch)
        with self.assertRaises(HostObservationError):
            inspect_local_host(None, self.scratch)

    def test_invalid_cpu_and_filesystem_counters_rejected(self):
        for count in (None, True, 0, -1, 1025):
            with self.subTest(count=count), self.assertRaises(HostObservationError):
                self.inspect(cpu=count)
        from slipcage_engine import vm_host_observe
        with patch.object(vm_host_observe.os, "fstatvfs", return_value=SimpleNamespace(
            f_frsize=-1, f_bavail=5, f_favail=10,
        )):
            with self.assertRaises(HostObservationError):
                inspect_local_host(self.plan, self.scratch, meminfo_path=self.memory)

    def test_controller_check_is_fixed_read_only_and_rejects_unknown_names(self):
        self.assertTrue(_has_cgroup_v2_controllers(self.controllers))
        self.controllers.write_bytes(b"nonsense-control")
        self.assertFalse(_has_cgroup_v2_controllers(self.controllers))

    def test_output_is_canonical_without_sensitive_host_identifiers(self):
        first = self.inspect()
        second = self.inspect()
        self.assertEqual(first.canonical_json(), second.canonical_json())
        text = first.canonical_json().decode()
        self.assertEqual(json.loads(text), first.to_dict())
        self.assertNotIn(str(self.root), text)
        for forbidden in ("hostname", "username", "ip_address", "mount_path", "ssh_key", "serial_number"):
            self.assertNotIn(forbidden, text)

    def test_cli_calls_collector_only_on_explicit_host_inspection_command(self):
        from slipcage_engine import cli
        fake = self.inspect()
        buf, err = io.StringIO(), io.StringIO()
        with patch.object(cli, "inspect_local_host", return_value=fake) as callback:
            with redirect_stdout(buf), redirect_stderr(err):
                status = main(["inspect-vm-host", str(PLAN),
                               "--scratch-root", str(self.scratch), "--json"])
            self.assertEqual(status, 0)
            self.assertEqual(err.getvalue(), "")
            self.assertEqual(json.loads(buf.getvalue()), fake.to_dict())
            callback.assert_called_once()
            self.assertEqual(callback.call_args.args[1], str(self.scratch))

    def test_unchanged_real_run_compare_report_disabled(self):
        out, err = io.StringIO(), io.StringIO()
        for command in ("run", "compare", "report"):
            with self.subTest(command=command):
                with redirect_stdout(out), redirect_stderr(err):
                    rc = main([command])
                self.assertEqual(rc, 3)


if __name__ == "__main__":
    unittest.main()
