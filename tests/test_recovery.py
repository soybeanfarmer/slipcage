"""Crash/reboot/retry and fenced-delivery regression tests (offline)."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import importlib.util
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

APP = Path(__file__).resolve().parents[1] / "app"
sys.path.insert(0, str(APP))
import recovery

spec = importlib.util.spec_from_file_location("isolab_recovery_tests", APP / "isolab.py")
isolab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(isolab)

NOW = datetime(2026, 10, 8, 20, 0, 0, tzinfo=timezone.utc)
ID = "b" * 64


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = str(self.root / "research.sqlite3")
        self.conn = isolab.connect(self.db)
        self.conn.execute("""INSERT INTO candidates
            (id,source,source_id,cve,title,summary,reference_url,track,score,
             discovered_at,status)
            VALUES (?, 'github','GHSA-example','CVE-2026-12345','runc procfs',
                    'runc procfs race','https://github.com/advisories/fixture',
                    'container',70,?,'pending')""", (ID, recovery.stamp(NOW)))
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        self.temp.cleanup()

    def state(self):
        return self.conn.execute("SELECT status FROM candidates WHERE id=?", (ID,)).fetchone()[0]

    def test_claim_serialized_and_token_fenced(self):
        task = recovery.claim_next(self.conn, 1, NOW)
        self.assertEqual(task[0], ID)
        self.assertEqual(len(task[1]), 32)
        self.assertIsNone(recovery.claim_next(self.conn, 1, NOW))
        self.assertFalse(recovery.start(self.conn, ID, "0" * 32))
        with patch.object(recovery, "boot_id", return_value="boot-1"), patch.object(
                recovery, "process_start", return_value="1234"):
            self.assertTrue(recovery.start(self.conn, ID, task[1], NOW))
        self.assertEqual(self.state(), "running")
        self.assertFalse(recovery.start(self.conn, ID, task[1], NOW))
        self.assertTrue(recovery.finish(self.conn, ID, task[1], NOW))
        self.assertEqual(self.state(), "reviewed")
        self.assertFalse(recovery.finish(self.conn, ID, task[1], NOW))

    def test_stale_queued_retry_and_old_delivery_is_inert(self):
        first = recovery.claim_next(self.conn, 3, NOW)
        with self.conn:
            status = recovery.reconcile(self.conn, NOW + timedelta(minutes=31))
        self.assertEqual(status["queued_reclaimed"], 1)
        self.assertEqual(self.state(), "pending")
        second = recovery.claim_next(self.conn, 3, NOW + timedelta(minutes=31))
        self.assertNotEqual(first[1], second[1])
        self.assertFalse(recovery.start(self.conn, ID, first[1],
                                         NOW + timedelta(minutes=31)))

    def test_running_worker_not_reclaimed_even_if_old(self):
        task = recovery.claim_next(self.conn, 3, NOW)
        with patch.object(recovery, "boot_id", return_value="boot-1"), patch.object(
                recovery, "process_start", return_value="1234"):
            self.assertTrue(recovery.start(self.conn, ID, task[1], NOW))
        with patch.object(recovery, "worker_alive", return_value=True):
            stats = recovery.reconcile(self.conn, NOW + timedelta(hours=5))
        self.assertEqual(stats["running_reclaimed"], 0)
        self.assertEqual(self.state(), "running")

    def test_dead_worker_or_reboot_reclaimed(self):
        task = recovery.claim_next(self.conn, 3, NOW)
        with patch.object(recovery, "boot_id", return_value="boot-1"), patch.object(
                recovery, "process_start", return_value="1234"):
            recovery.start(self.conn, ID, task[1], NOW)
        with patch.object(recovery, "worker_alive", return_value=False):
            stats = recovery.reconcile(self.conn, NOW + timedelta(minutes=3))
        self.assertEqual(stats["running_reclaimed"], 1)
        self.assertEqual(self.state(), "pending")
        self.assertNotEqual(recovery.claim_next(self.conn, 3)[1], task[1])

    def test_ambiguous_liveness_is_not_guessed(self):
        task = recovery.claim_next(self.conn, 3, NOW)
        with patch.object(recovery, "boot_id", return_value="boot-1"), patch.object(
                recovery, "process_start", return_value="1234"):
            recovery.start(self.conn, ID, task[1], NOW)
        with patch.object(recovery, "worker_alive", return_value=None):
            stats = recovery.reconcile(self.conn, NOW + timedelta(hours=1))
        self.assertEqual(stats["ambiguous_running"], 1)
        self.assertEqual(self.state(), "running")

    def test_retry_cap_yields_manual_attention(self):
        for i in range(3):
            recovery.claim_next(self.conn, 3, NOW + timedelta(hours=i))
            recovery.reconcile(self.conn, NOW + timedelta(hours=i + 1))
        self.assertIsNone(recovery.claim_next(self.conn, 3, NOW + timedelta(hours=4)))
        self.assertEqual(self.state(), "needs_attention")

    def test_old_v02_queue_is_not_blindly_replayed(self):
        with self.conn:
            self.conn.execute(
                "UPDATE candidates SET status='queued' WHERE id=?", (ID,))
        stats = recovery.reconcile(self.conn, NOW + timedelta(days=1))
        self.assertEqual(stats["legacy_untracked"], 1)
        self.assertEqual(self.state(), "queued")

    def test_delivery_exception_rolls_back_for_future_retry(self):
        def failed(*_args, **_kw):
            raise OSError("Dagu unavailable")
        result = recovery.enqueue(self.conn, "workflow.yaml", 3, runner=failed, now=NOW)
        self.assertEqual(result["delivery_failures"], 1)
        self.assertEqual(self.state(), "pending")
        self.assertEqual(self.conn.execute(
            "SELECT attempts FROM review_attempts WHERE candidate_id=?", (ID,)
        ).fetchone()[0], 1)

    def test_worker_completes_once_and_generates_one_stable_report(self):
        captured = []
        def passed(cmd, **kwargs):
            captured.append(cmd)
        self.assertEqual(recovery.enqueue(self.conn, "review.yaml", 3, runner=passed,
                                          now=NOW)["enqueued"], 1)
        token = captured[0][-1].split("=", 1)[1]
        self.assertTrue(captured[0][-2].startswith("candidate_id="))
        out = str(self.root / "reports")
        self.assertEqual(isolab.run_review(self.db, out, ID, token), 0)
        self.assertEqual(isolab.run_review(self.db, out, ID, token), 0)
        self.assertEqual(self.state(), "reviewed")
        self.assertEqual(len(list(Path(out).glob("candidate-*.md"))), 1)

    def test_crash_after_report_before_commit_retries_without_duplicate_file(self):
        first = recovery.claim_next(self.conn, 3, NOW)
        out = str(self.root / "reports")
        with patch.object(recovery, "boot_id", return_value="boot"), patch.object(
                recovery, "process_start", return_value="tick"):
            self.assertTrue(recovery.start(self.conn, ID, first[1], NOW))
        # Simulate a process termination after its report was durably written,
        # but before SQLite was marked reviewed.
        isolab.report(self.db, out, ID, commit_status=False, stable_name=True)
        self.assertEqual(self.state(), "running")
        with patch.object(recovery, "worker_alive", return_value=False):
            self.assertEqual(recovery.reconcile(
                self.conn, NOW + timedelta(minutes=3))["running_reclaimed"], 1)
        second = recovery.claim_next(self.conn, 3, NOW + timedelta(minutes=3))
        self.assertNotEqual(second[1], first[1])
        self.assertEqual(isolab.run_review(self.db, out, ID, second[1]), 0)
        self.assertEqual(self.state(), "reviewed")
        self.assertEqual(len(list(Path(out).glob("candidate-*.md"))), 1)

    def test_boot_id_changes_make_worker_provably_dead(self):
        with patch.object(recovery, "boot_id", return_value="new-boot"):
            self.assertFalse(recovery.worker_alive(123, "1234", "old-boot"))

    def test_recovery_preserves_report_marked_reviewed(self):
        task = recovery.claim_next(self.conn, 3, NOW)
        with patch.object(recovery, "boot_id", return_value="boot"), patch.object(
                recovery, "process_start", return_value="1234"):
            recovery.start(self.conn, ID, task[1], NOW)
        recovery.finish(self.conn, ID, task[1], NOW)
        self.assertEqual(recovery.reconcile(
            self.conn, NOW + timedelta(days=1))["running_reclaimed"], 0)
        self.assertEqual(self.state(), "reviewed")


if __name__ == "__main__":
    unittest.main()
