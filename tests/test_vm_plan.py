"""SC-12: pinned K3s VM plans remain read-only, synthetic and unapproved."""
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from slipcage_engine.cli import main
from slipcage_engine.vm_plan import (
    VMPlanError, assess_vm_plan, load_host_inventory, load_vm_plan,
    validate_host_inventory_bytes, validate_vm_plan_bytes,
)

FIXTURE = ROOT / "examples" / "vm-plans" / "k3s-synthetic-design.json"
HOST = ROOT / "examples" / "vm-plans" / "host-capacity-synthetic.json"


def as_json(value):
    return json.dumps(value, sort_keys=True).encode("utf-8")


class PinnedVMPlanTests(unittest.TestCase):
    def setUp(self):
        self.plan = load_vm_plan(FIXTURE)
        self.host = load_host_inventory(HOST)

    def test_valid_schema_has_pinned_versions_digests_and_stable_identity(self):
        result = self.plan.design
        self.assertEqual(result["runtime"]["machine_type"], "pc-q35-9.0")
        self.assertEqual(result["software"]["k3s_version"], "v1.30.1+k3s1")
        self.assertEqual(result["provenance"]["pin_status"], "synthetic_fixture")
        self.assertEqual(len(self.plan.digest_sha256), 64)
        self.assertEqual(load_vm_plan(FIXTURE).digest_sha256, self.plan.digest_sha256)
        self.assertEqual(self.plan.digest_sha256,
                         validate_vm_plan_bytes(as_json(result)).digest_sha256)
        self.assertEqual(len(set(result["artifacts"].values())), 5)
        for value in result["artifacts"].values():
            self.assertEqual(len(value), 64)

    def test_declared_capacity_fit_is_not_execution_authorization(self):
        result = assess_vm_plan(self.plan, self.host).to_dict()
        self.assertEqual(result["capacity_result"], "fits_reported_capacity")
        self.assertEqual(result["capacity_source"], "operator_reported_unverified")
        self.assertEqual(result["requirements"]["minimum_cpu_threads"], 4)
        self.assertEqual(result["requirements"]["minimum_memory_mib"], 8192)
        self.assertEqual(result["requirements"]["minimum_free_disk_gib"], 40)
        self.assertEqual(result["requirements"]["max_parallel_vms"], 1)
        self.assertFalse(result["artifacts_verified"])
        self.assertFalse(result["kvm_verified_on_target_host"])
        self.assertFalse(result["provider_permission_verified"])
        self.assertFalse(result["network_isolation_verified"])
        self.assertFalse(result["k3s_boot_verified"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["executable"])
        self.assertFalse(result["host_modified"])
        self.assertFalse(result["vm_launched"])
        self.assertIn("synthetic test values", " ".join(result["blockers"]))

    def test_no_inventory_has_unknown_capacity_not_a_pass(self):
        result = assess_vm_plan(self.plan).to_dict()
        self.assertEqual(result["capacity_result"], "unknown")
        self.assertIsNone(result["declared_capacity"])
        self.assertFalse(result["execution_authorized"])

    def test_insufficient_inventory_is_reported_without_guest_launch(self):
        value = self.host.inventory
        value.update(cpu_threads=1, memory_mib=2048, free_disk_gib=10)
        inventory = validate_host_inventory_bytes(as_json(value))
        result = assess_vm_plan(self.plan, inventory).to_dict()
        self.assertEqual(result["capacity_result"], "reported_capacity_insufficient")
        self.assertTrue(any("insufficient" in reason for reason in result["blockers"]))
        self.assertFalse(result["vm_launched"])

    def test_even_claimed_ready_host_and_permission_cannot_authorize_execution(self):
        value = self.host.inventory
        value.update(kvm_status="reported_ready",
                     provider_authorization="operator_reports_permission")
        result = assess_vm_plan(
            self.plan, validate_host_inventory_bytes(as_json(value))
        ).to_dict()
        self.assertFalse(result["provider_permission_verified"])
        self.assertFalse(result["kvm_verified_on_target_host"])
        self.assertFalse(result["execution_authorized"])

    def test_qemu_series_must_match_versioned_machine_type(self):
        data = self.plan.design
        data["runtime"]["machine_type"] = "pc-q35-8.2"
        with self.assertRaisesRegex(VMPlanError, "match declared QEMU"):
            validate_vm_plan_bytes(as_json(data))

    def test_reject_missing_invalid_or_unpinned_artifact_hashes(self):
        for artifact in self.plan.design["artifacts"]:
            for invalid in (None, "UNKNOWN", "sha256:invalid", "f"*63, "g"*64, "", True):
                with self.subTest(artifact=artifact, invalid=invalid):
                    data = self.plan.design
                    data["artifacts"][artifact] = invalid
                    with self.assertRaises(VMPlanError):
                        validate_vm_plan_bytes(as_json(data))

    def test_reject_unsafe_network_guest_and_runtime_settings(self):
        changes = [
            (("status",), "approved"),
            (("kind",), "QEMUExecutable"),
            (("runtime", "acceleration"), "tcg"),
            (("runtime", "machine_type"), "q35"),
            (("runtime", "cpu_model"), "host"),
            (("runtime", "qemu_version"), "latest"),
            (("runtime", "architecture"), "aarch64"),
            (("software", "k3s_version"), "latest"),
            (("software", "cni"), "unknown"),
            (("guest", "vcpu"), 0),
            (("guest", "ram_mib"), 128),
            (("guest", "max_parallel_vms"), 2),
            (("guest", "ephemeral_overlay"), False),
            (("guest", "max_runtime_seconds"), 99999),
            (("network", "design"), "bridged_to_public"),
            (("network", "host_bridging"), True),
            (("network", "public_egress"), True),
            (("network", "provider_metadata_access"), True),
            (("network", "guest_image_supply"), "internet_download"),
            (("network", "policy_enforcement_proven"), True),
            (("safety", "arbitrary_commands"), True),
            (("safety", "host_mounts"), True),
            (("safety", "provider_testing"), True),
            (("safety", "vm_execution_enabled"), True),
            (("safety", "network_configuration_enabled"), True),
        ]
        for path, value in changes:
            with self.subTest(path=path, value=value):
                data = self.plan.design
                target = data
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaises(VMPlanError):
                    validate_vm_plan_bytes(as_json(data))

    def test_reject_unknown_keys_missing_fields_bad_values(self):
        for modify in (
            lambda data: data.update({"shell": "bash"}),
            lambda data: data["guest"].update({"qemu_args": ["-device", "vfio"]}),
            lambda data: data["network"].update({"host_interface": "eth0"}),
            lambda data: data["metadata"].pop("id"),
            lambda data: data.pop("artifacts"),
            lambda data: data["guest"].update({"vcpu": True}),
            lambda data: data["provenance"].update({"note": "bad\ntext"}),
        ):
            data = self.plan.design
            modify(data)
            with self.assertRaises(VMPlanError):
                validate_vm_plan_bytes(as_json(data))

    def test_operator_real_pin_cannot_use_synthetic_kernel_name(self):
        data = self.plan.design
        data["provenance"]["pin_status"] = "operator_supplied_unverified"
        with self.assertRaisesRegex(VMPlanError, "Synthetic kernel"):
            validate_vm_plan_bytes(as_json(data))
        data["software"]["guest_kernel_release"] = "6.8.0-52-generic"
        result = assess_vm_plan(validate_vm_plan_bytes(as_json(data))).to_dict()
        self.assertEqual(result["pin_status"], "operator_supplied_unverified")
        self.assertFalse(result["artifacts_verified"])

    def test_duplicate_key_json_nonfinite_and_array_root_refused(self):
        payloads = (
            b'{"kind":"K3sVMPlan","kind":"K3sVMPlan"}',
            b'{"n":NaN}',
            b'{"n":1.5}',
            b'[]',
            b'{}',
            b'x' * 32769,
            b'\xff',
            b'',
        )
        for payload in payloads:
            with self.subTest(payload=payload[:30]), self.assertRaises(VMPlanError):
                validate_vm_plan_bytes(payload)

    def test_host_inventory_is_strict_not_secret_leaking(self):
        for update in (
            {"source": "verified_by_operator"},
            {"api_version": "v2"},
            {"cpu_threads": False},
            {"cpu_threads": -1},
            {"memory_mib": "12GB"},
            {"kvm_status": "boot_success"},
            {"provider_authorization": True},
            {"ssh_key": "secret"},
            {"free_disk_gib": None},
        ):
            with self.subTest(update=update):
                info = self.host.inventory
                info.update(update)
                with self.assertRaises(VMPlanError):
                    validate_host_inventory_bytes(as_json(info))

    def test_forged_dataclass_digest_or_inventory_rejected(self):
        with self.assertRaises(VMPlanError):
            assess_vm_plan(replace(self.plan, digest_sha256="0"*64), self.host)
        with self.assertRaises(VMPlanError):
            assess_vm_plan(self.plan, replace(self.host, canonical_json=b"{}"))
        with self.assertRaises(VMPlanError):
            assess_vm_plan(self.plan, {})

    def test_refuse_symlink_dir_file_absence_and_wrong_extension(self):
        with tempfile.TemporaryDirectory() as td:
            link = Path(td) / "linked.json"
            link.symlink_to(FIXTURE)
            for path in (link, Path(td), Path(td)/"nonexistent.json", Path(td)/"plan.txt"):
                with self.subTest(path=path), self.assertRaises(VMPlanError):
                    load_vm_plan(path)

    def test_cli_offline_design_output_canonical_and_non_executable(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(["plan-vm", str(FIXTURE), "--inventory", str(HOST), "--json"])
        self.assertEqual(rc, 0)
        self.assertEqual(err.getvalue(), "")
        data = json.loads(out.getvalue())
        self.assertFalse(data["execution_authorized"])
        self.assertFalse(data["vm_launched"])
        self.assertEqual(data["status"], "design_only")
        self.assertEqual(out.getvalue().strip(),
                         assess_vm_plan(self.plan, self.host).canonical_json().decode())

    def test_cli_invalid_plan_returns_two_no_success(self):
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "bad.json"
            bad.write_text('{"kind":"Executable"}')
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = main(["plan-vm", str(bad), "--json"])
            self.assertEqual(rc, 2)
            self.assertEqual(out.getvalue(), "")
            self.assertIn("plan-vm", err.getvalue())

    def test_never_launch_qemu_or_enable_existing_run_commands(self):
        from slipcage_engine import vm_plan
        with patch.object(vm_plan.os, "system", side_effect=AssertionError("shell called")):
            assess_vm_plan(self.plan, self.host)
        for cmd in ("run", "compare", "report"):
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = main([cmd])
            self.assertEqual(code, 3)
            self.assertEqual(out.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
