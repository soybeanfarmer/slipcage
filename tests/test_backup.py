"""Offline regression tests for atomic, bounded, non-destructive backups."""
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[1] / "scripts" / "slipcage-backup.py"
spec = importlib.util.spec_from_file_location("slipcage_backup", MODULE)
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)
NOW = datetime(2026, 10, 8, 20, 0, 0, tzinfo=timezone.utc)


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.db = self.base / "research.sqlite3"
        self.reports = self.base / "reports"
        self.reports.mkdir()
        self.dest = self.base / "backups"
        with sqlite3.connect(self.db) as conn:
            conn.execute("CREATE TABLE candidates (id TEXT PRIMARY KEY)")
            conn.execute("INSERT INTO candidates VALUES ('candidate-1')")
        (self.reports / "report-one.md").write_text("# Research report\n")
        (self.reports / "smoke-ok.json").write_text('{"status":"ok"}')

    def tearDown(self):
        self.temp.cleanup()

    def create(self, *, now=NOW, keep=14):
        return backup.create_backup(self.db, self.reports, self.dest,
                                    now=now, keep=keep)

    def test_valid_snapshot_replays_reports_without_live_database_changes(self):
        result = self.create()
        stored = Path(result["backup"])
        self.assertEqual((result["candidates"], result["reports"]), (1, 2))
        self.assertEqual(backup.verify_backup(stored)["reports"], 2)
        self.assertEqual(stored.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.dest.stat().st_mode & 0o777), 0o700)
        self.assertEqual(backup.check_sqlite(stored / "research.sqlite3"), 1)
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM candidates").fetchone()[0], 1)
        manifest = json.loads((stored / "manifest.json").read_text())
        self.assertEqual(set(manifest["files"]), {"reports.tar.gz", "research.sqlite3"})

    def test_database_wal_snapshot_captures_committed_rows(self):
        with sqlite3.connect(self.db) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("INSERT INTO candidates VALUES ('candidate-2')")
        result = self.create()
        self.assertEqual(result["candidates"], 2)
        self.assertEqual(backup.check_sqlite(Path(result["backup"]) /
                                             "research.sqlite3"), 2)

    def test_corruption_detected_and_previous_backup_retained(self):
        result = self.create()
        stored = Path(result["backup"])
        (stored / "research.sqlite3").write_bytes(b"corrupted")
        with self.assertRaises(ValueError):
            backup.verify_backup(stored)
        (self.reports / "unsafe-report").symlink_to(self.db)
        with self.assertRaises(ValueError):
            self.create(now=NOW + timedelta(seconds=1))
        self.assertTrue(stored.exists())
        self.assertEqual(len(list(self.dest.glob("backup-*"))), 1)
        self.assertEqual(list(self.dest.glob(".incomplete-*")), [])

    def test_retention_only_prunes_completed_backup_sets(self):
        for i in range(4):
            self.create(now=NOW + timedelta(seconds=i), keep=2)
        completed = sorted(p.name for p in self.dest.glob("backup-*"))
        self.assertEqual(len(completed), 2)
        self.assertTrue(completed[0].endswith("000002000000Z"))
        self.assertTrue(completed[1].endswith("000003000000Z"))
        for path in self.dest.glob("backup-*"):
            self.assertTrue(backup.verify_backup(path)["verified"])

    def test_refuse_symlinked_data_and_invalid_retention(self):
        with self.assertRaises(ValueError):
            self.create(keep=0)
        (self.reports / "linked.md").symlink_to(self.db)
        with self.assertRaises(ValueError):
            self.create()
        self.assertFalse(list(self.dest.glob("backup-*")))

    def test_empty_report_directory_is_preserved(self):
        for p in self.reports.iterdir():
            p.unlink()
        result = self.create()
        self.assertEqual(result["reports"], 0)
        self.assertEqual(backup.verify_backup(Path(result["backup"]))["reports"], 0)

    def test_cli_verify_and_error_exit_codes(self):
        result = self.create()
        self.assertEqual(backup.main(["verify", result["backup"]]), 0)
        self.assertEqual(backup.main(["verify", str(self.base / "missing")]), 1)


if __name__ == "__main__":
    unittest.main()
