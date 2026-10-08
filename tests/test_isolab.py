import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parents[1] / 'app' / 'isolab.py'
spec = importlib.util.spec_from_file_location('isolab', MODULE_PATH)
isolab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(isolab)

class LabTests(unittest.TestCase):
    def test_scope_matching(self):
        self.assertEqual(isolab.classify('QEMU out of bounds', 'memory corruption')[0], 'hypervisor')
        self.assertEqual(isolab.classify('runc issue', 'container escape')[0], 'container')
        self.assertIsNone(isolab.classify('OpenSSL issue', 'certificate parsing'))

    def test_duplicate_and_safe_report(self):
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d)/'research.db')
            conn = isolab.connect(db)
            item = dict(source='github', source_id='GHSA-test-test-test', cve='CVE-2026-12345',
                        title='QEMU <test>', summary='An out-of-bounds issue in QEMU.',
                        url='https://github.com/advisories/GHSA-test-test-test')
            self.assertTrue(isolab.record(conn, item))
            self.assertTrue(isolab.record(conn, item))
            conn.commit()
            row = conn.execute('SELECT * FROM candidates').fetchone()
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM candidates').fetchone()[0], 1)
            self.assertEqual(isolab.report(db, str(Path(d)/'reports'), row['id']), 0)
            output = next((Path(d)/'reports').glob('*.md')).read_text()
            self.assertIn('No vulnerability has been reproduced', output)
            self.assertNotIn('<test>', output)
            self.assertEqual(isolab.connect(db).execute('SELECT status FROM candidates').fetchone()[0], 'reviewed')

    def test_queue_uses_only_opaque_ids_and_no_shell(self):
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d)/'research.db')
            conn = isolab.connect(db)
            isolab.record(conn, dict(source='nvd', source_id='CVE-2026-0001', title='runc escape',
                                     summary='runc bug', url='https://nvd.nist.gov/'))
            conn.commit()
            with patch.object(isolab.subprocess, 'run') as sub:
                self.assertEqual(isolab.enqueue(db, '/tmp/review-candidate.yaml', 3), 0)
                cmd = sub.call_args.args[0]
                self.assertEqual(cmd[0:3], ['/usr/local/bin/dagu','enqueue','/tmp/review-candidate.yaml'])
                self.assertFalse('shell' in sub.call_args.kwargs)
                self.assertTrue(cmd[-1].startswith('candidate_id='))

    def test_bad_id_rejected(self):
        with self.assertRaises(ValueError):
            isolab.report('/tmp/unused.db', '/tmp/unused', '$(id)')

if __name__ == '__main__':
    unittest.main()
