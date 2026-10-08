"""v0.7: read-only experiment audits, interrupted runs and quota configuration."""
from __future__ import annotations
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]


def import_script(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


audit = import_script("evidence_audit", "slipcage-experiment-audit.py")
lifecycle = import_script("evidence_lifecycle", "slipcage-guest-lifecycle.py")
limits = import_script("passive_limits", "slipcage-limits-check.py")

GOOD_PROPERTIES = """
User=slipcage-vmprobe
PrivateNetwork=yes
ProtectSystem=strict
NoNewPrivileges=yes
MemoryMax=1342177280
CPUQuotaPerSecUSec=1s
TasksMax=64
DevicePolicy=closed
DeviceAllow=/dev/kvm rw
KillMode=control-group
"""


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / "state"

    @staticmethod
    def cycle(*, profile, **_):
        if profile == "boot":
            return {"passed": True, "seconds": 1.0}, "guest boot complete\n"
        return ({
            "passed": True, "seconds": 1.4, "known_answers_verified": True,
            "qemu_resources": {
                "wall_seconds": 1.2, "cpu_user_seconds": 0.9,
                "cpu_system_seconds": 0.2, "qemu_peak_rss_kib": 10000,
            },
        }, "fixed known answer\n")

    def completed(self, *, profile="experiment", cycles=2):
        return lifecycle.run_lifecycle(
            cycles, state=self.state, profile=profile, cycle_fn=self.cycle
        )

    def test_complete_experiment_is_audited_and_report_is_reproducible(self):
        recorded = self.completed()
        result = audit.audit(self.state)
        self.assertEqual(result["selected_runs"], 1)
        entry = result["runs"][0]
        self.assertEqual(entry["status"], "complete_pass")
        self.assertTrue(entry["manifest_present"])
        self.assertEqual(entry["completed_cycles"], 2)
        self.assertEqual(entry["successful_cycles"], 2)
        self.assertEqual(entry["resource_statistics"]["qemu_wall_mean_seconds"], 1.2)
        self.assertEqual(entry["resource_statistics"]["qemu_peak_rss_max_kib"], 10000)
        self.assertEqual(len(entry["artifacts"]), 6)
        self.assertEqual(audit.render_markdown(result),
                         audit.render_markdown(audit.audit(self.state)))
        self.assertIn("complete_pass", audit.render_markdown(result))
        self.assertEqual((Path(recorded["run_dir"]) / "run.json").stat().st_mode & 0o777, 0o600)

    def test_boot_only_run_from_existing_version_remains_supported(self):
        result = self.completed(profile="boot", cycles=2)
        (Path(result["run_dir"]) / "run.json").unlink()
        item = audit.audit(self.state)["runs"][0]
        self.assertEqual(item["status"], "complete_pass")
        self.assertFalse(item["manifest_present"])
        self.assertIsNone(item["resource_statistics"])

    def test_incomplete_directory_with_header_is_detected_without_mutation(self):
        result = self.completed(cycles=1)
        directory = Path(result["run_dir"])
        (directory / "summary.json").unlink()
        before = sorted(p.name for p in directory.iterdir())
        item = audit.audit(self.state)["runs"][0]
        self.assertEqual(item["status"], "interrupted_or_incomplete")
        self.assertIn("missing_summary", item["issues"])
        self.assertEqual(before, sorted(p.name for p in directory.iterdir()))

    def test_active_lock_results_in_cautious_possible_active_status(self):
        result = self.completed(cycles=1)
        (Path(result["run_dir"]) / "summary.json").unlink()
        # Read-only audit doesn't lock out an active run or mislabel it dead.
        with (self.state / ".cycle.lock").open("rb") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            report = audit.audit(self.state)
        self.assertTrue(report["lifecycle_lock_held"])
        self.assertEqual(report["runs"][0]["status"], "possibly_active")

    def test_corrupted_cycle_json_is_reported_as_inconsistent(self):
        result = self.completed(cycles=2)
        (Path(result["run_dir"]) / "cycle-02.json").write_text("{ broken")
        report = audit.audit(self.state)["runs"][0]
        self.assertEqual(report["status"], "inconsistent_evidence")
        self.assertIn("missing_or_invalid_cycle_02", report["issues"])

    def test_summary_mismatch_is_detected(self):
        result = self.completed()
        path = Path(result["run_dir"]) / "summary.json"
        data = json.loads(path.read_text())
        data["successful_cycles"] = 1
        path.write_text(json.dumps(data))
        entry = audit.audit(self.state)["runs"][0]
        self.assertEqual(entry["status"], "inconsistent_evidence")
        self.assertIn("success_count_mismatch", entry["issues"])

    def test_bad_manifest_and_unexpected_symlink_fail_closed(self):
        result = self.completed()
        directory = Path(result["run_dir"])
        (directory / "run.json").write_text('{"profile": "evil"}')
        item = audit.audit(self.state)["runs"][0]
        self.assertEqual(item["status"], "inconsistent_evidence")
        self.assertIn("invalid_run_manifest", item["issues"])
        log = directory / "cycle-01.log"
        log.unlink()
        log.symlink_to("/etc/passwd")
        item = audit.audit(self.state)["runs"][0]
        self.assertIn("missing_or_invalid_cycle_01", item["issues"])

    def test_missing_manifest_legacy_is_not_counted_as_breakage(self):
        result = self.completed()
        (Path(result["run_dir"]) / "run.json").unlink()
        self.assertEqual(audit.audit(self.state)["runs"][0]["status"], "complete_pass")

    def test_retention_limit_and_no_empty_runs_fail_success(self):
        for _ in range(3):
            self.completed()
        self.assertEqual(audit.audit(self.state, limit=2)["selected_runs"], 2)
        with self.assertRaises(ValueError):
            audit.audit(self.state, limit=21)
        with self.assertRaises(audit.EvidenceError):
            audit.audit(self.state.parent / "missing")

    def test_markdown_never_reports_sensitive_contents_from_console(self):
        result = self.completed()
        (Path(result["run_dir"]) / "cycle-01.log").write_text("secret token in fake log")
        summary = audit.render_markdown(audit.audit(self.state))
        self.assertNotIn("secret token", summary)
        self.assertIn("complete_pass", summary)

    def test_failure_reason_fields_make_fault_modes_distinct(self):
        p = {
            "guest_booted": False, "exit_code": 1,
            "network": "disabled", "persistent_guest_disk": False,
        }
        params = dict(passed=False, timed_out=False, error=None,
                      returncode=2, payload=p, profile="boot", resource_ok=True)
        self.assertEqual(lifecycle.classify_failure(**params), "qemu_error")
        self.assertEqual(lifecycle.classify_failure(**{**params, "timed_out": True}),
                         "outer_timeout_process_group_killed")
        self.assertEqual(lifecycle.classify_failure(**{**params, "payload": None}),
                         "missing_structured_probe_result")
        p2 = {"experiment_passed": True, "exit_code": 0,
              "network": "disabled", "persistent_guest_disk": False}
        self.assertEqual(lifecycle.classify_failure(**{**params,
                         "payload": p2, "profile": "experiment",
                         "resource_ok": False}), "resource_evidence_missing_or_invalid")

    def test_audit_unit_is_read_only_not_scheduled_and_limited(self):
        unit = (ROOT / "systemd" / "slipcage-experiment-audit.service").read_text()
        playbook = (ROOT / "playbooks" / "site.yml").read_text()
        for required in [
            "User=slipcage-vmprobe", "PrivateNetwork=yes", "PrivateDevices=yes",
            "ProtectSystem=strict", "ReadOnlyPaths=/var/lib/slipcage-guest",
            "NoNewPrivileges=yes", "MemoryMax=128M", "CPUQuota=25%",
            "TimeoutStartSec=30s",
        ]:
            self.assertIn(required, unit)
        self.assertNotIn("WantedBy=", unit)
        self.assertNotIn("DeviceAllow=/dev/kvm", unit)
        self.assertIn("Install passive runtime quota configuration check", playbook)


class ConfiguredLimitTests(unittest.TestCase):
    def test_approved_unit_meets_limits_without_starting_vm(self):
        seen = []
        def runner(cmd, **kwargs):
            seen.append(cmd)
            return Mock(returncode=0, stdout=GOOD_PROPERTIES)
        result = limits.check_unit("slipcage-experiment@1.service", runner=runner)
        self.assertTrue(result["configured_within_bounds"])
        self.assertEqual(seen[0][:3], ["systemctl", "show", "slipcage-experiment@1.service"])
        self.assertNotIn("start", seen[0])

    def test_wrong_privileges_and_oversized_quotas_fail(self):
        for before, after in (
            ("PrivateNetwork=yes", "PrivateNetwork=no"),
            ("User=slipcage-vmprobe", "User=root"),
            ("MemoryMax=1342177280", "MemoryMax=infinity"),
            ("TasksMax=64", "TasksMax=100"),
            ("CPUQuotaPerSecUSec=1s", "CPUQuotaPerSecUSec=2s"),
            ("DeviceAllow=/dev/kvm rw", "DeviceAllow=/dev/sda rw"),
            ("DevicePolicy=closed", "DevicePolicy=auto"),
        ):
            result = limits.check_unit("slipcage-guest-cycles@5.service", runner=lambda *a, **k: Mock(
                returncode=0, stdout=GOOD_PROPERTIES.replace(before, after)))
            self.assertFalse(result["configured_within_bounds"], (before, after))
            self.assertTrue(result["issues"])

    def test_unknown_unit_rejected_before_systemctl(self):
        with self.assertRaises(ValueError):
            limits.check_unit("evil.service", runner=lambda *_a, **_k:
                              self.fail("Should not run systemctl"))


if __name__ == "__main__":
    unittest.main()
