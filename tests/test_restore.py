"""Isolated restore drills never touch live research data."""
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import sqlite3
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
def load(path, name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

backup = load("slipcage-backup.py", "backup_for_restore_tests")
restore = load("slipcage-restore-check.py", "restore_drill_tests")
NOW = datetime(2026, 10, 8, tzinfo=timezone.utc)


class RestoreDrillTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.db = self.base / "research.sqlite3"
        self.reports = self.base / "reports"
        self.reports.mkdir()
        with sqlite3.connect(self.db) as conn:
            conn.execute("CREATE TABLE candidates (id TEXT PRIMARY KEY)")
            conn.execute("INSERT INTO candidates VALUES ('example')")
        (self.reports / "sample.md").write_text("Original report\n")
        self.snapshot = Path(backup.create_backup(
            self.db, self.reports, self.base / "backups", now=NOW)["backup"])

    def tearDown(self):
        self.temp.cleanup()

    def test_reconstructs_into_new_staging_directory_only(self):
        dest = self.base / "test-restore"
        result = restore.drill(self.snapshot, dest)
        self.assertTrue(result["verified"])
        self.assertFalse(result["live_data_modified"])
        self.assertEqual(result["reports"], 1)
        self.assertEqual((dest / "reports" / "sample.md").read_text(), "Original report\n")
        self.assertEqual(backup.check_sqlite(dest / "research.sqlite3"), 1)
        self.assertEqual(backup.check_sqlite(self.db), 1)
        self.assertEqual((dest.stat().st_mode & 0o777), 0o700)
        self.assertEqual((dest / "research.sqlite3").stat().st_mode & 0o777, 0o600)

    def test_refuses_to_replace_existing_destination(self):
        dest = self.base / "existing"
        dest.mkdir()
        (dest / "important.txt").write_text("do not overwrite")
        with self.assertRaises(FileExistsError):
            restore.drill(self.snapshot, dest)
        self.assertEqual((dest / "important.txt").read_text(), "do not overwrite")

    def test_tampering_aborts_before_creating_restore(self):
        dest = self.base / "not-created"
        (self.snapshot / "reports.tar.gz").write_bytes(b"tampered")
        with self.assertRaises(ValueError):
            restore.drill(self.snapshot, dest)
        self.assertFalse(dest.exists())

    def test_destination_is_private_and_no_staging_left_after_error(self):
        bad = self.base / "not-created"
        with self.assertRaises(ValueError):
            restore.drill(self.base / "missing", bad)
        self.assertFalse(list(self.base.glob(".restore-drill-*")))


if __name__ == "__main__":
    unittest.main()
