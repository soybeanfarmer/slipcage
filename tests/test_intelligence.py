"""Offline tests for v0.2 intelligence and migration from v0.1 data."""
from datetime import datetime, timezone
import importlib.util
import json
import sqlite3
from pathlib import Path
import sys
import tempfile
import unittest

APP = Path(__file__).resolve().parents[1] / "app"
sys.path.insert(0, str(APP))
import intelligence

spec = importlib.util.spec_from_file_location("isolab", APP / "isolab.py")
isolab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(isolab)
NOW = datetime(2026, 10, 8, tzinfo=timezone.utc)


class IntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.temp.name) / "research.sqlite3")
        self.conn = isolab.connect(self.db)

    def tearDown(self):
        self.conn.close()
        self.temp.cleanup()

    def add(self, source, source_id, cve, title, summary, published, references=None):
        isolab.record(self.conn, dict(source=source, source_id=source_id, cve=cve,
                     title=title, summary=summary, published=published,
                     url="https://github.com/advisories/fixture",
                     references=references or []))
        return self.conn.execute("SELECT id FROM candidates WHERE source=? AND source_id=?",
                                 (source, source_id)).fetchone()[0]

    def test_deduplicate_across_feeds_and_stay_idempotent(self):
        a = self.add("github", "GHSA-aaa", "CVE-2026-12345",
                     "runc race condition", "runc security issue", "2026-09-01")
        b = self.add("nvd", "CVE-2026-12345", "CVE-2026-12345",
                     "runc issue", "runc issue", "2026-09-01")
        with self.conn:
            stats = intelligence.analyze(self.conn, NOW)
        self.assertEqual(stats["duplicates"], 1)
        statuses = [r[0] for r in self.conn.execute(
            "SELECT status FROM candidates WHERE id IN (?,?)", (a, b))]
        self.assertEqual(sorted(statuses), ["duplicate", "pending"])
        with self.conn:
            self.assertEqual(intelligence.analyze(self.conn, NOW)["duplicates"], 0)
        related = json.loads(self.conn.execute(
            "SELECT related_json FROM candidate_intelligence WHERE candidate_id=?", (a,)
        ).fetchone()[0])
        self.assertIn("same CVE", related[0]["reasons"])

    def test_preserve_reviewed_entry_during_migration(self):
        a = self.add("github", "GHSA-original", "CVE-2019-19921",
                     "runc procfs race", "runc race condition", "2019-12-01")
        self.conn.execute("UPDATE candidates SET status='reviewed' WHERE id=?", (a,))
        self.conn.commit()
        b = self.add("nvd", "CVE-2019-19921", "CVE-2019-19921",
                     "runc shared mounts", "runc race", "2019-12-01")
        with self.conn:
            intelligence.analyze(self.conn, NOW)
        self.assertEqual(self.conn.execute(
            "SELECT status FROM candidates WHERE id=?", (a,)).fetchone()[0], "reviewed")
        self.assertEqual(self.conn.execute(
            "SELECT status FROM candidates WHERE id=?", (b,)).fetchone()[0], "duplicate")

    def test_cross_cve_mentions_are_leads_not_same_family(self):
        a = self.add("github", "GHSA-old", "CVE-2019-19921",
                     "runc procfs race condition",
                     "Fixed in 1.0.0-rc10; requires custom mount configurations.",
                     "2019-12-01")
        b = self.add("github", "GHSA-new", "CVE-2025-52881",
                     "runc procfs issue",
                     "Related to CVE-2019-19921. Fixed in version 2.",
                     "2025-09-01")
        with self.conn:
            intelligence.analyze(self.conn, NOW)
        old = self.conn.execute(
            "SELECT * FROM candidate_intelligence WHERE candidate_id=?", (a,)
        ).fetchone()
        self.assertEqual(old["age_bucket"], "historical")
        self.assertLess(old["research_score"], 80)
        related = json.loads(old["related_json"])
        self.assertEqual(related[0]["cve"], "CVE-2025-52881")
        self.assertIn("unverified", related[0]["reasons"][0])
        newer = self.conn.execute(
            "SELECT family_key FROM candidate_intelligence WHERE candidate_id=?", (b,)
        ).fetchone()[0]
        self.assertNotEqual(old["family_key"], newer)

    def test_patch_reference_allowlist_prevents_untrusted_links(self):
        sha = "1" * 40
        valid = f"https://github.com/opencontainers/runc/commit/{sha}"
        self.assertEqual(intelligence.patch_ref(valid), valid)
        for bad in [valid + "?download=1",
                    "http://github.com/opencontainers/runc/commit/" + sha,
                    "https://github.evil.example/opencontainers/runc/commit/" + sha,
                    "https://github.com/evil/runc/commit/" + sha,
                    "https://github.com:broken/opencontainers/runc/commit/" + sha]:
            self.assertIsNone(intelligence.patch_ref(bad), bad)
        cid = self.add("github", "GHSA-patch", "CVE-2026-00001",
                       "runc regression", "fixed in version 2", "2026-08-01",
                       [valid, "https://attacker.example/run"])
        with self.conn:
            intelligence.analyze(self.conn, NOW)
        self.assertEqual(json.loads(self.conn.execute(
            "SELECT patch_refs_json FROM candidate_intelligence WHERE candidate_id=?",
            (cid,)).fetchone()[0]), [valid])

    def test_historical_scores_lower_than_recent(self):
        row = dict(title="runc procfs race condition",
                   summary="Fixed in v1; requires privileged access and custom mount configurations.",
                   published="2019-01-01")
        old, age, _ = intelligence.score_candidate(row, [], NOW)
        row["published"] = "2026-09-01"
        new, age_new, _ = intelligence.score_candidate(row, [], NOW)
        self.assertEqual((age, age_new), ("historical", "recent"))
        self.assertGreater(new, old)

    def test_enriched_report_never_claims_a_reproduced_vulnerability(self):
        cid = self.add("github", "GHSA-report", "CVE-2019-19921",
                       "runc procfs race", "Fixed in 1.0.0-rc10.", "2019-12-01")
        with self.conn:
            intelligence.analyze(self.conn, NOW)
        reports = str(Path(self.temp.name) / "reports")
        self.assertEqual(isolab.report(self.db, reports, cid), 0)
        body = next(Path(reports).glob("*.md")).read_text()
        self.assertIn("Research intelligence", body)
        self.assertIn("historical", body)
        self.assertIn("Do not infer exploitability", body)
        self.assertIn("No vulnerability has been reproduced", body)

    def test_migrate_legacy_sqlite_database_without_erasing_candidates(self):
        """Simulate v0.1 tables, then open them using the additive v0.2 schema."""
        self.conn.close()
        legacy = sqlite3.connect(self.db)
        legacy.executescript(isolab.SCHEMA.split("CREATE INDEX IF NOT EXISTS")[0])
        legacy.execute("""INSERT INTO candidates
            (id,source,source_id,cve,title,summary,reference_url,track,score,
             published,updated,status,discovered_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("a" * 64, "github", "GHSA-legacy", "CVE-2019-19921",
             "runc procfs bug", "old advisory", "https://github.com/advisories/example",
             "container", 80, "2019-12-01", "2026-10-08", "reviewed",
             "2026-10-08T00:00:00+00:00"))
        legacy.commit()
        legacy.close()
        self.conn = isolab.connect(self.db)
        self.assertEqual(self.conn.execute(
            "SELECT status FROM candidates WHERE source_id='GHSA-legacy'"
        ).fetchone()[0], "reviewed")
        with self.conn:
            intelligence.analyze(self.conn, NOW)
        self.assertIsNotNone(self.conn.execute(
            "SELECT * FROM candidate_intelligence WHERE candidate_id=?",
            ("a" * 64,)).fetchone())


if __name__ == "__main__":
    unittest.main()
