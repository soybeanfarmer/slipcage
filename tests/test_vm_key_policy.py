"""SC-13b13 offline signing-key policy: never independent publisher trust."""
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from slipcage_engine.cli import main
from slipcage_engine.vm_plan import load_vm_plan, validate_vm_plan_bytes
from slipcage_engine.vm_provenance import API_VERSION as PROVENANCE_VERSION
from slipcage_engine.vm_key_policy import (
    API_VERSION, VMKeyPolicyError, verify_vm_signing_key_policy,
)

EXAMPLE = ROOT / "examples" / "vm-plans" / "k3s-synthetic-design.json"


def canon(item):
    return json.dumps(item, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


class SigningPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        design = load_vm_plan(EXAMPLE).design
        design["provenance"]["pin_status"] = "operator_supplied_unverified"
        design["provenance"]["note"] = "CI only; NOT authentic source or software"
        design["software"]["guest_kernel_release"] = "6.8.0-test"
        self.plan = validate_vm_plan_bytes(canon(design))
        self.plan_file = self.root / "plan.json"
        self.plan_file.write_bytes(self.plan.canonical_json)
        self.private = Ed25519PrivateKey.generate()
        self.public_file = self.root / "signing-key.raw"
        self.statement_file = self.root / "statement.json"
        self.signature_file = self.root / "signature.bin"
        self.policy_file = self.root / "key-policy.json"
        self.release_id = "ci-test-only"
        self.resign(self.private)
        self.policy = {
            "api_version": API_VERSION,
            "policy_origin": "operator_supplied_unverified",
            "source_label": "ci-source-not-a-real-publisher",
            "release_id": self.release_id,
            "plan_digest_sha256": self.plan.digest_sha256,
            "statement_sha256": hashlib.sha256(self.statement_file.read_bytes()).hexdigest(),
            "allowed_key_sha256": hashlib.sha256(self.public_file.read_bytes()).hexdigest(),
            "revoked_key_sha256": [],
        }
        self.write_policy()
        self.neighbor = self.root / "keep-me.txt"
        self.neighbor.write_text("never read or change other data")

    def resign(self, private):
        raw_key = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        self.public_file.write_bytes(raw_key)
        raw_statement = canon({
            "api_version": PROVENANCE_VERSION,
            "release_id": self.release_id,
            "plan_digest_sha256": self.plan.digest_sha256,
            "artifacts": self.plan.design["artifacts"],
        })
        self.statement_file.write_bytes(raw_statement)
        self.signature_file.write_bytes(private.sign(
            b"SLIPCAGE_VM_PROVENANCE_V1\0" + raw_statement
        ))

    def write_policy(self):
        self.policy_file.write_bytes(canon(self.policy))
        self.policy_file.chmod(0o600)

    def verify(self):
        return verify_vm_signing_key_policy(
            self.plan, self.statement_file, self.signature_file,
            self.public_file, self.policy_file,
        )

    def cli(self, argv=None):
        argv = argv or [
            "verify-vm-signing-policy", str(self.plan_file),
            "--statement", str(self.statement_file),
            "--signature", str(self.signature_file),
            "--public-key", str(self.public_file),
            "--key-policy", str(self.policy_file), "--json",
        ]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = main(argv)
        return status, out.getvalue(), err.getvalue()

    def test_matching_policy_signature_is_local_only_not_publisher_identity(self):
        x = self.verify().to_dict()
        self.assertEqual(x["api_version"], API_VERSION)
        self.assertTrue(x["signature_valid_for_supplied_public_key"])
        self.assertTrue(x["key_matches_operator_policy_fingerprint"])
        self.assertTrue(x["key_absent_from_policy_denylist"])
        self.assertEqual(x["statement_digest_sha256"], self.policy["statement_sha256"])
        self.assertEqual(x["policy_digest_sha256"], hashlib.sha256(self.policy_file.read_bytes()).hexdigest())
        self.assertEqual(x["release_id"], self.release_id)
        self.assertFalse(x["publisher_identity_authenticated"])
        self.assertFalse(x["policy_authenticity_verified"])
        self.assertFalse(x["key_identity_verified_out_of_band"])
        self.assertFalse(x["revocation_information_complete_or_current"])
        self.assertFalse(x["execution_authorized"])

    def test_forged_self_signed_key_cannot_pass_existing_policy(self):
        intruder = Ed25519PrivateKey.generate()
        self.resign(intruder)  # Signature is now valid for INTRUDER's key.
        with self.assertRaisesRegex(VMKeyPolicyError, "differs"):
            self.verify()
        self.assertEqual(self.cli()[0], 2)

    def test_policy_substitution_exposes_trust_limit_without_claiming_authentication(self):
        intruder = Ed25519PrivateKey.generate()
        self.resign(intruder)
        # Attackers controlling BOTH files can evade local consistency check.
        # Positive status MUST NOT claim origin authentication.
        self.policy["allowed_key_sha256"] = hashlib.sha256(self.public_file.read_bytes()).hexdigest()
        self.write_policy()
        result = self.verify().to_dict()
        self.assertTrue(result["key_matches_operator_policy_fingerprint"])
        self.assertFalse(result["publisher_identity_authenticated"])
        self.assertFalse(result["policy_authenticity_verified"])

    def test_explicitly_revoked_key_is_refused(self):
        self.policy["revoked_key_sha256"] = [self.policy["allowed_key_sha256"]]
        self.write_policy()
        with self.assertRaisesRegex(VMKeyPolicyError, "revoked"):
            self.verify()

    def test_wrong_release_plan_and_statement_hash_refused(self):
        for key, value in (
            ("release_id", "other-release"),
            ("plan_digest_sha256", "f" * 64),
            ("statement_sha256", "f" * 64),
        ):
            with self.subTest(key=key):
                before = self.policy[key]
                self.policy[key] = value
                self.write_policy()
                with self.assertRaisesRegex(VMKeyPolicyError, "not scoped"):
                    self.verify()
                self.policy[key] = before
        self.write_policy()

    def test_swapped_signature_fails_even_with_pinned_key(self):
        other = Ed25519PrivateKey.generate()
        self.signature_file.write_bytes(other.sign(
            b"SLIPCAGE_VM_PROVENANCE_V1\0" + self.statement_file.read_bytes()
        ))
        with self.assertRaisesRegex(VMKeyPolicyError, "signature"):
            self.verify()

    def test_synthetic_plan_rejected_before_policy_check(self):
        with self.assertRaises(VMKeyPolicyError):
            verify_vm_signing_key_policy(
                load_vm_plan(EXAMPLE), self.statement_file, self.signature_file,
                self.public_file, self.policy_file,
            )

    def test_duplicate_fields_noncanonical_and_unknown_fields_fail(self):
        for raw in (
            self.policy_file.read_bytes() + b"\n",
            b'{"api_version":"x","api_version":"y"}',
            canon({**self.policy, "allow_shell": True}),
            b"[]", b"{}", b"\xff",
        ):
            with self.subTest(raw=raw[:35]):
                self.policy_file.write_bytes(raw)
                with self.assertRaises(VMKeyPolicyError):
                    self.verify()
        self.write_policy()

    def test_reject_unbounded_bad_revocation_lists(self):
        invalid = (
            ["f"*64, "f"*64],
            ["f"*64, "0"*64],  # wrong lexical order
            ["not-a-digest"],
            ["0"*64] * 33,
            True,
            ["a"*64, False],
        )
        for value in invalid:
            with self.subTest(value=str(value)[:90]):
                self.policy["revoked_key_sha256"] = value
                self.write_policy()
                with self.assertRaises(VMKeyPolicyError):
                    self.verify()
        self.policy["revoked_key_sha256"] = []
        self.write_policy()

    def test_invalid_policy_origin_and_digest_types_rejected(self):
        for name, invalid in (
            ("policy_origin", "trusted_by_tool"),
            ("source_label", "../unsafe"),
            ("release_id", "not a release"),
            ("plan_digest_sha256", True),
            ("statement_sha256", 1),
            ("allowed_key_sha256", "A" * 64),
        ):
            with self.subTest(name=name):
                original = self.policy[name]
                self.policy[name] = invalid
                self.write_policy()
                with self.assertRaises(VMKeyPolicyError):
                    self.verify()
                self.policy[name] = original
        self.write_policy()

    def test_symlink_hardlink_nonprivate_policy_refused(self):
        raw = self.policy_file.read_bytes()
        target = self.root / "outside"
        target.write_bytes(raw)
        self.policy_file.unlink()
        self.policy_file.symlink_to(target)
        with self.assertRaises(VMKeyPolicyError):
            self.verify()
        self.policy_file.unlink()
        self.write_policy()
        self.policy_file.chmod(0o644)
        with self.assertRaises(VMKeyPolicyError):
            self.verify()
        self.policy_file.chmod(0o600)
        os.link(self.policy_file, self.root / "second-link")
        with self.assertRaises(VMKeyPolicyError):
            self.verify()

    def test_policy_file_size_cap_and_nonregular_rejected(self):
        self.policy_file.write_bytes(b"x" * 5000)
        with self.assertRaises(VMKeyPolicyError):
            self.verify()
        self.policy_file.unlink()
        self.policy_file.mkdir()
        with self.assertRaises(VMKeyPolicyError):
            self.verify()

    def test_sorted_nonempty_revocations_other_than_signer_pass_locally(self):
        self.policy["revoked_key_sha256"] = ["0"*64, "f"*64]
        self.write_policy()
        report = self.verify().to_dict()
        self.assertEqual(report["listed_revocation_count"], 2)
        self.assertFalse(report["revocation_information_complete_or_current"])

    def test_cli_status_and_path_free_deterministic_output(self):
        first = self.cli()
        second = self.cli()
        self.assertEqual(first, second)
        self.assertEqual((first[0], first[2]), (0, ""))
        self.assertEqual(json.loads(first[1]), self.verify().to_dict())
        self.assertNotIn(str(self.root), first[1])

    def test_no_external_process_network_or_host_mutation(self):
        before = {p.name: p.read_bytes() for p in (
            self.public_file, self.statement_file, self.signature_file,
            self.policy_file, self.neighbor)}
        with (
            patch.object(subprocess, "Popen", side_effect=AssertionError("process")),
            patch.object(subprocess, "run", side_effect=AssertionError("process")),
            patch.object(socket, "socket", side_effect=AssertionError("network")),
        ):
            self.assertFalse(self.verify().to_dict()["execution_authorized"])
        after = {p.name: p.read_bytes() for p in (
            self.public_file, self.statement_file, self.signature_file,
            self.policy_file, self.neighbor)}
        self.assertEqual(before, after)

    def test_real_run_compare_report_remain_disabled(self):
        for command in ("run", "compare", "report"):
            code, out, err = self.cli([command])
            self.assertEqual((code, out), (3, ""))


if __name__ == "__main__":
    unittest.main()
