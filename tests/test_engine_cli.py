"""Public CLI safety and exit-code contract."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from slipcage_engine.cli import main

FIXTURE = ROOT / "examples" / "experiments" / "rbac-pod-create-denied.yaml"

class EngineCLITests(unittest.TestCase):
    def invoke(self, args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(args)
        return code, out.getvalue(), err.getvalue()

    def test_validate_json_succeeds_with_explicit_non_executable_flag(self):
        code, out, err = self.invoke(["validate", str(FIXTURE), "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        result = json.loads(out)
        self.assertEqual(result["status"], "valid")
        self.assertFalse(result["executable"])
        self.assertEqual(result["api_version"], "slipcage.dev/v1alpha1")

    def test_validate_text_succeeds_without_execution_claim(self):
        code, out, err = self.invoke(["validate", str(FIXTURE)])
        self.assertEqual(code, 0)
        self.assertIn("validation only; execution disabled", out)
        self.assertEqual(err, "")

    def test_unsafe_invalid_input_returns_error_without_success(self):
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "evil.yaml"
            bad.write_text("kind: ArbitraryScript\n", encoding="utf-8")
            code, out, err = self.invoke(["validate", str(bad), "--json"])
            self.assertEqual(code, 2)
            self.assertFalse(out)
            self.assertIn("Invalid definition", err)

    def test_missing_file_returns_error_without_success(self):
        code, out, err = self.invoke(["validate", "/no/such/slipcage/spec.yaml"])
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("Could not read", err)

    def test_unavailable_actions_always_fail_closed(self):
        for command in ("run", "compare", "report"):
            with self.subTest(command=command):
                code, out, err = self.invoke([command])
                self.assertEqual(code, 3)
                self.assertEqual(out, "")
                self.assertIn("no execution, comparison or report has been performed", err)

    def test_help_and_version_are_non_executing(self):
        for args in [["--help"], ["--version"]]:
            with self.subTest(args=args):
                with redirect_stdout(io.StringIO()):
                    with self.assertRaises(SystemExit) as exited:
                        main(args)
                self.assertEqual(exited.exception.code, 0)

if __name__ == "__main__":
    unittest.main()
