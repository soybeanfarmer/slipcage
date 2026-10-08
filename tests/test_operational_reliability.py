"""Offline v0.9 operational-health and conservative synthetic retention tests."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


health = load("health_v9", "slipcage-health.py")
retention = load("fault_retention_v9", "slipcage-fault-retention.py")


class HealthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.now = datetime(2026, 10, 8, 21, 0, tzinfo=timezone.utc)
        self.backup = self.root / "backups"
        self.backup.mkdir()
        self.sha = self.root / "deployed-sha"
        self.sha.write_text("a" * 40 + "\n")
        self.guest = self.root / "runs"
        self.guest.mkdir()
        self.fault = self.root / "fault"
        self.fault.mkdir()
        self.assurance = self.root / "assurance-status.json"
        self.assurance.write_text(json.dumps({
            "schema_version": 1, "checked_utc": (self.now - timedelta(hours=6)).isoformat(),
            "passed": True, "latest_backup": "backup-fixture",
        }))
        self.status = self.root / "health" / "status.json"
        self.status.parent.mkdir()

        stamp = (self.now - timedelta(hours=12)).strftime("%Y%m%dT%H%M%S%fZ")
        snapshot = self.backup / ("backup-" + stamp)
        snapshot.mkdir()
        (snapshot / "manifest.json").write_text(json.dumps({
            "format": 1, "files": {
                "research.sqlite3": {"sha256": "abc", "bytes": 5},
                "reports.tar.gz": {"sha256": "def", "bytes": 10},
            },
        }))

    @staticmethod
    def unit(unit, verb):
        return "active" if verb == "is-active" else "inactive"

    @staticmethod
    def disk(_):
        return shutil._ntuple_diskusage(10 * 1024**3, 2 * 1024**3, 8 * 1024**3)

    def inspect(self, **overrides):
        args = dict(now=self.now, backup_root=self.backup,
                    deploy_sha=self.sha, guest_runs=self.guest,
                    fault_runs=self.fault, assurance_status=self.assurance,
                    unit_probe=self.unit,
                    disk_usage=self.disk)
        args.update(overrides)
        return health.inspect(**args)

    def test_healthy_system_with_fresh_backup(self):
        result = self.inspect()
        self.assertTrue(result["healthy"], result)
        self.assertEqual(result["issues"], [])
        self.assertEqual(result["units"]["isolab-dagu.service"], "active")
        self.assertEqual(result["backup"]["age_hours"], 12.0)

    def test_stale_backup_detected(self):
        self.assertFalse(self.inspect(now=self.now + timedelta(days=2))["healthy"])
        self.assertIn("local_backup:backup_too_old_or_future",
                      self.inspect(now=self.now + timedelta(days=2))["issues"])

    def test_missing_or_corrupt_backup_manifest_detected(self):
        snap = next(self.backup.iterdir())
        manifest = snap / "manifest.json"
        manifest.write_text("not-json")
        r = self.inspect()
        self.assertFalse(r["healthy"])
        self.assertIn("local_backup:unreadable_or_invalid_backup", r["issues"])

    def test_private_guest_directory_permission_denial_is_an_alert(self):
        original = Path.iterdir
        guarded = self.guest
        def restricted(path):
            if path == guarded:
                raise PermissionError("simulated private guest evidence")
            return original(path)
        with patch.object(Path, "iterdir", restricted):
            report = self.inspect()
        self.assertFalse(report["healthy"])
        self.assertEqual(report["artifacts"]["guest"]["error"], "permission_denied")
        self.assertIn("guest_artifact_scan_failed", report["issues"])

    def test_root_backup_directory_read_denial_is_an_alert(self):
        original = Path.iterdir
        guarded = self.backup
        def restricted(path):
            if path == guarded:
                raise PermissionError("simulated unreadable root-only backups")
            return original(path)
        with patch.object(Path, "iterdir", restricted):
            report = self.inspect()
        self.assertFalse(report["healthy"])
        self.assertIn("local_backup:backup_directory_unreadable", report["issues"])

    def test_health_unit_has_only_required_read_search_capability(self):
        unit = (ROOT / "systemd" / "slipcage-health.service").read_text()
        self.assertIn("User=root", unit)
        self.assertIn("CapabilityBoundingSet=CAP_DAC_READ_SEARCH", unit)
        self.assertIn("AmbientCapabilities=", unit)
        self.assertIn("PrivateNetwork=yes", unit)
        self.assertIn("ProtectHome=yes", unit)
        self.assertNotIn("CapabilityBoundingSet=CAP_DAC_OVERRIDE", unit)

    def test_low_disk_and_failed_timer_detected(self):
        def unit(name, verb):
            if name == "slipcage-backup.timer":
                return "inactive"
            if name == "slipcage-backup.service":
                return "failed"
            return self.unit(name, verb)
        low = lambda _: shutil._ntuple_diskusage(10*1024**3, 9*1024**3, 512*1024**2)
        result = self.inspect(unit_probe=unit, disk_usage=low)
        self.assertIn("disk_space_low", result["issues"])
        self.assertIn("inactive_unit:slipcage-backup.timer", result["issues"])
        self.assertIn("failed_or_unknown_unit:slipcage-backup.service", result["issues"])

    def test_overdue_or_failed_weekly_restore_assurance_alerts(self):
        record = json.loads(self.assurance.read_text())
        record["passed"] = False
        self.assurance.write_text(json.dumps(record))
        result = self.inspect()
        self.assertFalse(result["healthy"])
        self.assertIn("restore_assurance:restore_check_failed", result["issues"])
        record["passed"] = True
        self.assurance.write_text(json.dumps(record))
        result = self.inspect(now=self.now + timedelta(days=11))
        self.assertIn("restore_assurance:restore_check_stale_or_future", result["issues"])

    def test_missing_weekly_restore_assurance_is_not_silently_healthy(self):
        self.assurance.unlink()
        result = self.inspect()
        self.assertIn("restore_assurance:never_checked", result["issues"])

    def test_stale_incomplete_run_detected_without_deletion(self):
        run = self.guest / "run-20261001T010000000000Z-fixture"
        run.mkdir()
        os.utime(run, (self.now.timestamp() - 2*86400,) * 2)
        r = self.inspect()
        self.assertIn("guest_stale_incomplete_artifacts", r["issues"])
        self.assertTrue(run.is_dir())

    def test_health_status_transition_deduplicated_and_atomic(self):
        result = self.inspect()
        self.assertTrue(health.write_status(result, destination=self.status))
        self.assertFalse(health.write_status(result, destination=self.status))
        self.assertEqual(self.status.stat().st_mode & 0o777, 0o600)
        self.assertTrue(health.write_status({**result, "issues": ["disk_space_low"]},
                                           destination=self.status))
        self.assertTrue(health.write_status(result, destination=self.status))
        self.assertEqual(json.loads(self.status.read_text())["issues"], [])

    def test_symlinked_or_missing_status_directory_rejected(self):
        other = self.root / "outside"
        other.mkdir()
        self.status.unlink(missing_ok=True)
        self.status.parent.rmdir()
        self.status.parent.symlink_to(other)
        with self.assertRaises(ValueError):
            health.write_status(self.inspect(), destination=self.status)
        self.assertEqual(list(other.iterdir()), [])

    def test_no_external_alerts_or_guest_execution(self):
        text = (ROOT / "scripts" / "slipcage-health.py").read_text()
        for forbidden in ("qemu-system", "curl ", "wget ", "requests.post",
                          "subprocess.Popen", "shell=True", "smtp", "requests.post"):
            self.assertNotIn(forbidden, text)
        unit = (ROOT / "systemd" / "slipcage-health.service").read_text()
        timer = (ROOT / "systemd" / "slipcage-health.timer").read_text()
        for required in (
            "PrivateNetwork=yes", "PrivateDevices=yes", "MemoryMax=128M",
            "CPUQuota=25%", "StateDirectory=slipcage-health", "ProtectSystem=strict",
            "NoNewPrivileges=yes", "CapabilityBoundingSet=CAP_DAC_READ_SEARCH",
        ):
            self.assertIn(required, unit)
        self.assertIn("OnUnitInactiveSec=1h", timer)
        self.assertIn("Unit=slipcage-health.service", timer)
        self.assertNotIn("DeviceAllow=/dev/kvm", unit)


class RetentionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.state = Path(tmp.name) / "fault"
        self.state.mkdir()
        self.now = datetime(2026, 10, 8, tzinfo=timezone.utc)

    def create(self, i, *, days=40, passed=True):
        stamp = (self.now - timedelta(days=days) + timedelta(microseconds=i)
                 ).strftime("%Y%m%dT%H%M%S%fZ")
        folder = self.state / ("drill-" + stamp + f"-t{i}")
        folder.mkdir()
        (folder / "summary.json").write_text(json.dumps({
            "mode": "limits", "passed": passed, "live_data_modified": False,
            "qemu_started": False, "run_dir": str(folder),
            "results": [{"drill": "limits", "passed": passed}],
        }))
        (folder / "limits.json").write_text("{}")
        return folder

    def test_preview_does_not_delete_and_retains_at_least_20(self):
        entries = [self.create(i) for i in range(24)]
        plan = retention.cleanup(state=self.state, now=self.now)
        self.assertEqual(plan["mode"], "dry_run")
        self.assertEqual(plan["eligible_count"], 4)
        self.assertEqual(plan["deleted"], [])
        self.assertEqual(len([p for p in entries if p.exists()]), 24)

    def test_apply_requires_confirmation_and_deletes_only_eligible_old_drills(self):
        entries = [self.create(i) for i in range(23)]
        with self.assertRaises(ValueError):
            retention.cleanup(state=self.state, now=self.now, apply=True)
        applied = retention.cleanup(state=self.state, now=self.now,
                                    apply=True, confirm=True)
        self.assertEqual(len(applied["deleted"]), 3)
        self.assertEqual(len([p for p in entries if p.exists()]), 20)

    def test_recent_runs_and_failed_or_incomplete_runs_never_deleted(self):
        old = [self.create(i) for i in range(23)]
        recent = self.create(40, days=1)
        failed = self.create(41, passed=False)
        broken = self.state / "drill-20260801T000000000000Z-incomplete"
        broken.mkdir()
        report = retention.cleanup(state=self.state, now=self.now, apply=True, confirm=True)
        self.assertTrue(recent.exists())
        self.assertTrue(failed.exists())
        self.assertTrue(broken.exists())
        self.assertEqual(report["scope"], "completed_successful_fault_drills_only")
        self.assertGreaterEqual(len([x for x in old if x.exists()]), 19)

    def test_symlinks_and_unknown_files_fail_closed(self):
        entries = [self.create(i) for i in range(24)]
        oldest = entries[0]
        (oldest / "unsafe").symlink_to("/etc/passwd")
        report = retention.cleanup(state=self.state, now=self.now, apply=True, confirm=True)
        self.assertTrue(oldest.exists())
        self.assertGreaterEqual(report["skipped_incomplete_or_unsafe"], 1)

    def test_lock_blocks_overlapping_drill_and_cleanup(self):
        with (self.state / ".drill.lock").open("a+b") as locked:
            fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                retention.cleanup(state=self.state, now=self.now)

    def test_cleanup_has_no_timer_and_no_guest_or_backup_deletion(self):
        source = (ROOT / "scripts" / "slipcage-fault-retention.py").read_text()
        playbook = (ROOT / "playbooks" / "site.yml").read_text()
        self.assertIn("DEFAULT_STATE = Path(\"/var/lib/slipcage-fault\")", source)
        self.assertIn("if apply and not confirm:", source)
        self.assertIn("Install manual dry-run fault artifact retention tool", playbook)
        self.assertNotIn("slipcage-fault-retention.service", playbook)


if __name__ == "__main__":
    unittest.main()
