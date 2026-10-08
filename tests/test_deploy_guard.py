"""Regression tests for the deployment-aware research drain."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "slipcage-guard.py"
spec = importlib.util.spec_from_file_location("slipcage_guard", SOURCE)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

class DeploymentGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name)
        (self.state / "deployment.lock").touch()

    def tearDown(self):
        self.tmp.cleanup()

    def run_command(self):
        return [sys.executable, str(SOURCE), "--state-dir", str(self.state),
                "run", "--", sys.executable, "-c", "print(123)"]

    def active_worker(self):
        marker = self.state / "ready"
        code = f"from pathlib import Path; Path({str(marker)!r}).touch(); import time; time.sleep(0.7)"
        worker = subprocess.Popen([sys.executable, str(SOURCE), "--state-dir",
                   str(self.state), "run", "--", sys.executable, "-c", code])
        deadline = time.monotonic() + 3
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(marker.exists())
        return worker

    def test_maintenance_defers_new_work(self):
        self.assertEqual(guard.begin(self.state, 1), 0)
        self.assertEqual(subprocess.run(self.run_command(), capture_output=True).returncode, 75)
        self.assertEqual(guard.end(self.state), 0)
        self.assertEqual(subprocess.run(self.run_command(), capture_output=True).returncode, 0)

    def test_waits_for_active_worker(self):
        worker = self.active_worker()
        try:
            start = time.monotonic()
            self.assertEqual(guard.begin(self.state, 3), 0)
            self.assertGreater(time.monotonic() - start, 0.2)
            self.assertEqual(worker.wait(timeout=2), 0)
            self.assertEqual(guard.end(self.state), 0)
        finally:
            if worker.poll() is None:
                worker.kill()
                worker.wait()

    def test_timeout_does_not_start_deployment(self):
        worker = self.active_worker()
        try:
            with self.assertRaises(TimeoutError):
                guard.begin(self.state, 0.05)
            self.assertFalse((self.state / "maintenance").exists())
        finally:
            worker.wait(timeout=2)

    def test_concurrent_deployment_refused(self):
        guard.begin(self.state, 1)
        with self.assertRaises(FileExistsError):
            guard.begin(self.state, 1)
        guard.end(self.state)

if __name__ == "__main__":
    unittest.main()
