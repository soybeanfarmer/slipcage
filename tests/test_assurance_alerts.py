"""v0.10: true local scratch restores, opt-in incident alerts and timer boundaries."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch
import shutil

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


assurance = load("assurance_v10", "slipcage-assurance.py")
alerts = load("alerts_v10", "slipcage-alert-dispatch.py")
backup = load("backup_v10", "slipcage-backup.py")
restore = load("restore_v10", "slipcage-restore-check.py")

NOW = datetime(2026, 10, 8, 21, 0, tzinfo=timezone.utc)


class AssuranceTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.cache = self.root / "cache"
        self.cache.mkdir()
        self.state = self.root / "state"
        self.state.mkdir()
        self.db = self.root / "research.sqlite3"
        self.reports = self.root / "reports"
        self.reports.mkdir()
        with sqlite3.connect(self.db) as conn:
            conn.execute("CREATE TABLE candidates (id TEXT PRIMARY KEY)")
            conn.execute("INSERT INTO candidates VALUES ('fixture')")
        (self.reports / "sample.md").write_text("sample harmless report", encoding="utf-8")
        self.backups = self.root / "backups"
        backup.create_backup(self.db, self.reports, self.backups, now=NOW)
        self.original_db = self.db.read_bytes()
        self.original_report = (self.reports / "sample.md").read_bytes()

    def check(self, **kwargs):
        return assurance.check(
            backups=self.backups, scratch=self.cache, state=self.state,
            drill_fn=restore.drill, **kwargs
        )

    def test_real_scratch_restore_matches_sqlite_and_reports_without_mutation(self):
        result = self.check()
        self.assertTrue(result["passed"], result)
        self.assertEqual(result["candidates"], 1)
        self.assertEqual(result["reports"], 1)
        self.assertFalse(result["live_data_modified"])
        self.assertEqual(self.db.read_bytes(), self.original_db)
        self.assertEqual((self.reports / "sample.md").read_bytes(), self.original_report)
        self.assertEqual(sorted(p.name for p in self.cache.iterdir()), [])
        persisted = json.loads((self.state / "status.json").read_text())
        self.assertTrue(persisted["passed"])
        self.assertEqual((self.state / "status.json").stat().st_mode & 0o777, 0o600)

    def test_corrupted_backup_fails_and_records_status(self):
        source = assurance.backup_latest(self.backups)
        (source / "reports.tar.gz").write_bytes(b"broken")
        result = self.check()
        self.assertFalse(result["passed"])
        self.assertEqual(sorted(p.name for p in self.cache.iterdir()), [])
        self.assertFalse(json.loads((self.state / "status.json").read_text())["passed"])
        self.assertEqual(self.db.read_bytes(), self.original_db)

    def test_low_disk_blocks_restore_before_invoking_callback(self):
        called = []
        low = lambda _: shutil._ntuple_diskusage(1000, 999, 1)
        result = assurance.check(
            backups=self.backups, scratch=self.cache, state=self.state,
            drill_fn=lambda *a: called.append(True),
            disk_usage=low,
        )
        self.assertFalse(result["passed"])
        self.assertEqual(called, [])
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_oversized_backup_rejected_without_allocating_large_file(self):
        source = assurance.backup_latest(self.backups)
        with (source / "research.sqlite3").open("ab") as out:
            out.truncate(assurance.MAX_DB_BYTES + 1)
        result = self.check()
        self.assertFalse(result["passed"])
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_invalid_drill_output_fails_closed_and_cleanup_occurs(self):
        def fake_drill(source, target):
            target.mkdir()
            (target / "fixture").write_text("hi")
            return {"verified": False, "live_data_modified": False}
        result = assurance.check(backups=self.backups, scratch=self.cache,
                                 state=self.state, drill_fn=fake_drill)
        self.assertFalse(result["passed"])
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_unit_is_weekly_no_network_and_resource_bounded(self):
        unit = (ROOT / "systemd/slipcage-assurance.service").read_text()
        timer = (ROOT / "systemd/slipcage-assurance.timer").read_text()
        for item in ("PrivateNetwork=yes", "PrivateDevices=yes",
                     "MemoryMax=512M", "CPUQuota=35%", "TasksMax=32",
                     "TimeoutStartSec=10min", "LimitFSIZE=768M",
                     "StateDirectory=slipcage-assurance", "CacheDirectory=slipcage-assurance",
                     "ProtectSystem=strict", "ReadOnlyPaths=/var/backups/slipcage"):
            self.assertIn(item, unit)
        self.assertIn("OnCalendar=Sun", timer)
        self.assertIn("Unit=slipcage-assurance.service", timer)
        self.assertNotIn("qemu", unit.lower())


class AlertTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.now = NOW
        self.health = self.root / "health.json"
        self.state = self.root / "state"
        self.state.mkdir()
        self.endpoint = self.root / "secret.url"
        self.endpoint.write_text("https://alerts.example.org/unique-test-placeholder\n")
        self.endpoint.chmod(0o600)
        self.events = []
        self.sender = lambda url, event: self.events.append(event)
        self.set_health([])

    def set_health(self, issues, when=None):
        self.health.write_text(json.dumps({
            "checked_utc": (when or self.now).isoformat(),
            "healthy": not issues, "issues": issues,
            "secret_research": "must-never-be-transmitted",
        }))

    def dispatch(self, *, send=False, sender=None):
        return alerts.dispatch(health=self.health, state=self.state,
                               destination=self.endpoint, send=send,
                               sender=sender or self.sender, now=self.now)

    def test_preview_never_transmits_or_requires_webhook_credentials(self):
        self.set_health(["disk_space_low"])
        self.endpoint.unlink()
        result = self.dispatch()
        self.assertEqual(result["mode"], "preview")
        self.assertTrue(result["will_notify"])
        self.assertFalse(result["delivered"])
        self.assertEqual(self.events, [])
        self.assertEqual(list(self.state.iterdir()), [])
        self.assertNotIn("must-never-be-transmitted", json.dumps(result))

    def test_initial_healthy_state_sends_nothing(self):
        result = self.dispatch(send=True)
        self.assertFalse(result["delivered"])
        self.assertEqual(self.events, [])

    def test_warning_change_and_recovery_each_deliver_once(self):
        self.set_health(["disk_space_low"])
        self.assertTrue(self.dispatch(send=True)["delivered"])
        self.assertFalse(self.dispatch(send=True)["delivered"])
        self.set_health(["disk_space_low", "inactive_unit:slipcage-backup.timer"])
        self.assertTrue(self.dispatch(send=True)["delivered"])
        self.assertEqual(len(self.events), 2)
        self.set_health([])
        self.assertTrue(self.dispatch(send=True)["delivered"])
        self.assertFalse(self.dispatch(send=True)["delivered"])
        self.assertEqual(self.events[-1]["type"], "recovered")
        self.assertNotIn("secret_research", json.dumps(self.events))
        self.assertEqual(len(self.events), 3)

    def test_failed_delivery_not_recorded_and_retries_next_time(self):
        self.set_health(["local_backup:backup_too_old_or_future"])
        def fail(url, event):
            raise OSError("simulated failure")
        with self.assertRaises(OSError):
            self.dispatch(send=True, sender=fail)
        self.assertFalse((self.state / "last-delivered.json").exists())
        self.assertTrue(self.dispatch(send=True)["delivered"])

    def test_stale_health_status_or_malformed_issue_codes_block_transmission(self):
        self.set_health(["disk_space_low"], when=self.now - timedelta(days=1))
        with self.assertRaises(ValueError):
            self.dispatch(send=True)
        self.set_health(["invalid issue \n value"])
        with self.assertRaises(ValueError):
            self.dispatch(send=True)
        self.assertEqual(self.events, [])

    def test_endpoint_rejects_insecure_symlink_nonprivate_and_redirects(self):
        self.endpoint.write_text("http://example.org/hook\n")
        with self.assertRaises(ValueError):
            alerts.endpoint_url(self.endpoint)
        self.endpoint.write_text("https://example.org/hook\n")
        self.endpoint.chmod(0o644)
        with self.assertRaises(ValueError):
            alerts.endpoint_url(self.endpoint)
        self.endpoint.chmod(0o600)
        self.endpoint.unlink()
        self.endpoint.symlink_to("/etc/passwd")
        with self.assertRaises(ValueError):
            alerts.endpoint_url(self.endpoint)

    def test_opt_in_service_and_timer_are_not_enabled_by_ansible(self):
        service = (ROOT / "systemd/slipcage-alert-dispatch.service").read_text()
        timer = (ROOT / "systemd/slipcage-alert-dispatch.timer").read_text()
        playbook = (ROOT / "playbooks/site.yml").read_text()
        self.assertIn("ConditionPathExists=/etc/slipcage/health-webhook.url", service)
        self.assertIn("ExecStart=/usr/bin/python3 /usr/local/lib/slipcage/alert-dispatch.py --send", service)
        self.assertIn("NoNewPrivileges=yes", service)
        self.assertIn("ProtectSystem=strict", service)
        self.assertIn("Unit=slipcage-alert-dispatch.service", timer)
        self.assertNotIn("enable", playbook.split(
            "- name: Install disabled-by-default HTTPS alert timer")[1].split(
            "\n    - name: ", 1)[0].lower())
        self.assertNotIn("slipcage-alert-dispatch.timer\n        daemon_reload", playbook)

if __name__ == "__main__":
    unittest.main()
