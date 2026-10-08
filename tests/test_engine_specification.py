"""Offline contract regression tests: no network, QEMU, Kubernetes or subprocesses."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from slipcage_engine import SpecValidationError, load_spec, validate_spec_bytes

FIXTURE = ROOT / "examples" / "experiments" / "rbac-pod-create-denied.yaml"

def sample():
    import yaml
    return yaml.safe_load(FIXTURE.read_text(encoding="utf-8"))

def as_json(data):
    return json.dumps(data, sort_keys=True).encode("utf-8")

class ExperimentSpecificationTests(unittest.TestCase):
    def test_valid_example_is_non_executable_data_with_stable_digest(self):
        result = load_spec(FIXTURE)
        self.assertEqual(result.experiment_id, "kubernetes.rbac.pod-create-denied")
        self.assertEqual(result.version, "0.1.0")
        self.assertEqual(result.profile_id, "kubernetes.rbac")
        self.assertEqual(len(result.digest_sha256), 64)
        self.assertEqual(result.digest_sha256, load_spec(FIXTURE).digest_sha256)

    def test_yaml_json_and_key_order_have_identical_canonical_digest(self):
        yml = load_spec(FIXTURE)
        data = sample()
        payload = as_json(data)
        js = validate_spec_bytes(payload, extension=".json")
        self.assertEqual(yml.digest_sha256, js.digest_sha256)
        self.assertEqual(js.canonical_json, yml.canonical_json)

    def test_unsupported_type_and_oversized_documents_fail_closed(self):
        for extension in [".txt", ".exe", ""]:
            with self.subTest(extension=extension):
                with self.assertRaises(SpecValidationError):
                    validate_spec_bytes(FIXTURE.read_bytes(), extension=extension)
        for document in [b"", b"x" * (65536 + 1), b"\xff"]:
            with self.subTest(size=len(document)):
                with self.assertRaises(SpecValidationError):
                    validate_spec_bytes(document, extension=".yaml")

    def test_unsafe_syntax_and_duplicate_keys_are_rejected(self):
        docs = [
            (b'{"kind":"SecurityExperiment","kind":"SecurityExperiment"}', ".json"),
            (b'{"value":NaN}', ".json"),
            (b"kind: SecurityExperiment\nkind: SecurityExperiment\n", ".yaml"),
            (b"left: &anchor test\nright: *anchor\n", ".yaml"),
            (b"<<: {kind: SecurityExperiment}\n", ".yaml"),
            (b"kind: !!python/name:os.system\n", ".yaml"),
            (b"a: hello\n---\nb: world\n", ".yml"),
            (b"true: wrong-mapping-key\n", ".yaml"),
        ]
        for doc, extension in docs:
            with self.subTest(doc=doc):
                with self.assertRaises(SpecValidationError):
                    validate_spec_bytes(doc, extension=extension)

    def test_unsupported_versions_profiles_and_unknown_fields_fail_closed(self):
        invalid_fields = [
            (("api_version",), "slipcage.dev/v999"),
            (("kind",), "ArbitraryScript"),
            (("metadata", "id"), "other.rbac.pod"),
            (("metadata", "version"), "latest"),
            (("profile", "id"), "kubernetes.shell"),
            (("profile", "pack_version"), "master"),
            (("parameters", "namespace"), "kube-system"),
            (("parameters", "namespace"), "slipcage-../etc"),
            (("parameters", "subject"), "admin; id"),
            (("assertions", 0, "operation"), "run_shell"),
            (("assertions", 0, "expected"), "exploit"),
            (("limits", "timeout_seconds"), 301),
            (("limits", "timeout_seconds"), True),
            (("limits", "timeout_seconds"), 0),
            (("limits", "max_artifact_bytes"), 8388609),
            (("limits", "max_artifact_bytes"), 64),
        ]
        for path, value in invalid_fields:
            with self.subTest(path=path, value=value):
                data = sample()
                current = data
                for key in path[:-1]:
                    current = current[key]
                current[path[-1]] = value
                with self.assertRaises(SpecValidationError):
                    validate_spec_bytes(as_json(data), extension=".json")

    def test_disallowed_unknown_keys_and_missing_fields(self):
        cases = [
            lambda d: d.update({"command": "echo hi"}),
            lambda d: d["parameters"].update({"shell": "$(id)"}),
            lambda d: d["limits"].update({"cpu": 999}),
            lambda d: d["assertions"][0].update({"script": "curl http://invalid"}),
            lambda d: d["metadata"].pop("id"),
            lambda d: d.pop("limits"),
            lambda d: d["parameters"].pop("subject"),
        ]
        for modify in cases:
            with self.subTest(case=str(modify)):
                data = sample()
                modify(data)
                with self.assertRaises(SpecValidationError):
                    validate_spec_bytes(as_json(data), extension=".json")

    def test_duplicate_assertion_ids_and_too_many_assertions(self):
        data = sample()
        data["assertions"] *= 2
        with self.assertRaisesRegex(SpecValidationError, "unique"):
            validate_spec_bytes(as_json(data), extension=".json")
        data = sample()
        data["assertions"] *= 9
        with self.assertRaises(SpecValidationError):
            validate_spec_bytes(as_json(data), extension=".json")

    def test_non_mapping_root_and_bogus_scalar_fields(self):
        for data in [None, [], 42, "hello", {"api_version": "slipcage.dev/v1alpha1"}]:
            with self.subTest(data=data):
                with self.assertRaises(SpecValidationError):
                    validate_spec_bytes(as_json(data), extension=".json")

    def test_symlink_and_non_regular_file_refused(self):
        with tempfile.TemporaryDirectory() as td:
            symlink = Path(td) / "test.yaml"
            symlink.symlink_to(FIXTURE)
            with self.assertRaises(SpecValidationError):
                load_spec(symlink)
            with self.assertRaises(SpecValidationError):
                load_spec(Path(td))
            with self.assertRaises(SpecValidationError):
                load_spec(Path(td) / "missing.yaml")

    def test_schema_is_bundled_and_json_validation_is_strict(self):
        # Import-time resources must work from editable / wheel installs.
        from slipcage_engine.specification import _validator
        validator = _validator()
        self.assertEqual(validator.schema["properties"]["profile"]["properties"]["id"]["const"], "kubernetes.rbac")
        self.assertTrue(validator.is_valid(sample()))

if __name__ == "__main__":
    unittest.main()
