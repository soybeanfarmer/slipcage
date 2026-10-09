"""SC-13b16: narrow QCOW2 metadata checks using tiny nonbootable fixtures.

Tests build artificial QCOW2 v3 metadata in disposable local files. None
contain a real OS, launch a guest or rely on qemu-img/QEMU.
"""
from contextlib import redirect_stdout, redirect_stderr
import hashlib
import io
import json
from pathlib import Path
import os
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from slipcage_engine.cli import main
from slipcage_engine.vm_assets import ARTIFACTS
from slipcage_engine.vm_plan import load_vm_plan, validate_vm_plan_bytes
from slipcage_engine.vm_qcow2_metadata import (
    API_VERSION, CLUSTER_BYTES, MAX_PHYSICAL_BYTES, Qcow2MetadataError,
    _scan_graph, inspect_bounded_qcow2_metadata,
)
from slipcage_engine.vm_overlay_preflight import GIB

SAMPLE = ROOT / "examples" / "vm-plans" / "k3s-synthetic-design.json"
C = CLUSTER_BYTES
COPIED = 1 << 63


def make_qcow2(mapped=2):
    """Canonical test-only metadata layout; **not a bootable OS image**.

      cluster 0 header, 1 L1, 2 ref table, 3 refcount block,
      cluster 4 L2 (if mapped), remaining clusters invented data.
    """
    count = 4 + (1 + mapped if mapped else 0)
    buf = bytearray(C * count)
    buf[0:4] = b"QFI\xfb"
    struct.pack_into(">I", buf, 4, 3)
    struct.pack_into(">I", buf, 20, 16)
    struct.pack_into(">Q", buf, 24, 24 * GIB)
    struct.pack_into(">I", buf, 36, 48)  # cover full 24-GiB virtual address range
    struct.pack_into(">Q", buf, 40, C)  # L1 at cluster 1
    struct.pack_into(">Q", buf, 48, 2*C)
    struct.pack_into(">I", buf, 56, 1)
    struct.pack_into(">I", buf, 96, 4)  # 16-bit refcounts
    struct.pack_into(">I", buf, 100, 104)
    struct.pack_into(">Q", buf, 2*C, 3*C)  # refcount-table[0]
    for i in range(count):
        struct.pack_into(">H", buf, 3*C + 2*i, 1)
    if mapped:
        struct.pack_into(">Q", buf, C, COPIED | 4*C)  # L1[0]
        for i in range(mapped):
            struct.pack_into(">Q", buf, 4*C + 8*i, COPIED | ((5+i)*C))
            buf[(5+i)*C:(5+i)*C+9] = b"FAKE-DATA"
    return bytes(buf)


def canonical(obj):
    return json.dumps(obj, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


class BoundedQcow2MetadataTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.assets = self.root / "assets"
        self.assets.mkdir(mode=0o700)
        self.assets.chmod(0o700)
        self.base = self.assets / "os-image.qcow2"
        self.base.write_bytes(make_qcow2())
        self.base.chmod(0o600)
        plan = load_vm_plan(SAMPLE).design
        plan["provenance"]["pin_status"] = "operator_supplied_unverified"
        plan["provenance"]["note"] = "CI fake QCOW2 metadata and artificial guest data only"
        plan["software"]["guest_kernel_release"] = "6.8.0-test"
        for i, (field, name, _) in enumerate(ARTIFACTS):
            f = self.assets / name
            if not f.exists():
                f.write_bytes(f"tiny-ci-only-{field}-{i}".encode())
                f.chmod(0o600)
            plan["artifacts"][field] = hashlib.sha256(f.read_bytes()).hexdigest()
        self.plan = validate_vm_plan_bytes(canonical(plan))
        self.planfile = self.root / "plan.json"
        self.planfile.write_bytes(self.plan.canonical_json)
        self.neighbor = self.root / "backup-stays.txt"
        self.neighbor.write_text("preserve this fixture", encoding="utf-8")

    def scan(self):
        with self.base.open("rb") as f:
            return _scan_graph(f.fileno(), f.stat().st_size if hasattr(f, "stat") else os.fstat(f.fileno()).st_size, 24*GIB)

    def patch_u64(self, offset, value):
        with self.base.open("r+b") as f:
            f.seek(offset)
            f.write(struct.pack(">Q", value))

    def patch_u32(self, offset, value):
        with self.base.open("r+b") as f:
            f.seek(offset)
            f.write(struct.pack(">I", value))

    def check(self):
        return inspect_bounded_qcow2_metadata(self.plan, self.assets)

    def cli(self, args=None):
        args = args if args is not None else [
            "inspect-vm-qcow2-metadata", str(self.planfile),
            "--assets-dir", str(self.assets), "--json",
        ]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(args)
        return code, out.getvalue(), err.getvalue()

    def test_small_nonbootable_valid_l1_l2_refcounts(self):
        review = self.check().to_dict()
        self.assertEqual(review["api_version"], API_VERSION)
        self.assertEqual(review["status"], "small_subset_locally_consistent_not_guest_verified")
        self.assertEqual(review["l1_entries_examined"], 48)
        self.assertEqual(review["l2_table_clusters_examined"], 1)
        self.assertEqual(review["guest_data_clusters_examined"], 2)
        self.assertEqual(review["refcount_blocks_examined"], 1)
        self.assertEqual(review["virtual_bytes"], 24*GIB)
        self.assertEqual(review["physical_bytes"], 7*C)
        self.assertEqual(review["operator_pinned_base_sha256"],
                         self.plan.design["artifacts"]["os_image_sha256"])

    def test_unmapped_empty_virtual_image_graph_is_consistent_only(self):
        self.base.write_bytes(make_qcow2(mapped=0))
        self.assertEqual(self.scan(), (48, 0, 0))
        # Original operator-declared bytes now differ, so full check cannot pass.
        with self.assertRaises(Exception):
            self.check()

    def test_every_host_or_guest_claim_remains_false(self):
        response = self.check().to_dict()
        for field in (
            "source_publisher_authenticated", "whole_qcow2_format_support_claimed",
            "real_os_image_contents_authenticated", "qcow2_backing_chain_traversed",
            "base_immutability_enforced", "filesystem_quota_enforced",
            "qemu_img_executed", "qemu_executed", "host_kvm_verified",
            "guest_boot_verified", "overlay_created", "execution_authorized",
            "host_modified",
        ):
            with self.subTest(field=field):
                self.assertIs(response[field], False)

    def test_ci_header_only_previous_subset_is_rejected(self):
        bad = bytearray(make_qcow2())
        # Previous header-only fixtures contained no refcount block pointer.
        struct.pack_into(">Q", bad, 2*C, 0)
        self.base.write_bytes(bad)
        with self.assertRaises(Qcow2MetadataError):
            self.scan()

    def test_copied_bit_missing_from_l1_or_l2_rejected(self):
        for offset, pointer in ((C, 4*C), (4*C, 5*C)):
            with self.subTest(offset=offset):
                self.patch_u64(offset, pointer)
                with self.assertRaisesRegex(Qcow2MetadataError, "copied"):
                    self.scan()
                self.patch_u64(offset, COPIED | pointer)

    def test_compressed_zero_and_unaligned_l2_rejected(self):
        for pointer in (COPIED | (1<<62) | 5*C, COPIED | 5*C | 1,
                        COPIED | 5*C | 16):
            self.patch_u64(4*C, pointer)
            with self.subTest(pointer=pointer), self.assertRaises(Qcow2MetadataError):
                self.scan()

    def test_l1_l2_reserved_flags_rejected(self):
        for pointer in (COPIED | (1<<60) | 4*C, COPIED | (1<<56) | 4*C):
            self.patch_u64(C, pointer)
            with self.subTest(pointer=pointer), self.assertRaises(Qcow2MetadataError):
                self.scan()

    def test_data_cluster_alias_rejected(self):
        self.patch_u64(4*C + 8, COPIED | 5*C)
        with self.assertRaisesRegex(Qcow2MetadataError, "multiply referenced"):
            self.scan()

    def test_l2_pointer_aliases_header_l1_ref_table_or_block_rejected(self):
        for index in (1, 2, 3):
            self.patch_u64(C, COPIED | index*C)
            with self.subTest(index=index), self.assertRaisesRegex(Qcow2MetadataError, "Overlapping"):
                self.scan()

    def test_l2_data_pointer_outside_physical_file_rejected(self):
        self.patch_u64(4*C, COPIED | 12*C)
        with self.assertRaisesRegex(Qcow2MetadataError, "outside physical"):
            self.scan()

    def test_refcount_zero_for_allocated_cluster_rejected(self):
        with self.base.open("r+b") as f:
            f.seek(3*C + 2*5)
            f.write(b"\x00\x00")
        with self.assertRaisesRegex(Qcow2MetadataError, "refcount differs"):
            self.scan()

    def test_double_refcount_and_orphan_refcount_rejected(self):
        for index, count in ((5, 2), (100, 1)):
            with self.base.open("r+b") as f:
                f.seek(3*C + 2*index)
                f.write(struct.pack(">H", count))
            with self.subTest(index=index), self.assertRaisesRegex(Qcow2MetadataError, "refcount differs"):
                self.scan()
            with self.base.open("r+b") as f:
                f.seek(3*C + 2*index)
                f.write(struct.pack(">H", 1 if index == 5 else 0))

    def test_physical_unreferenced_trailing_cluster_is_rejected(self):
        with self.base.open("ab") as f:
            f.write(bytes(C))
        with self.assertRaisesRegex(Qcow2MetadataError, "orphan"):
            self.scan()

    def test_reference_table_pointer_alignment_missing_extra_entry_rejected(self):
        self.patch_u64(2*C, 3*C + 1)
        with self.assertRaises(Qcow2MetadataError):
            self.scan()
        self.patch_u64(2*C, 3*C)
        self.patch_u64(2*C+8, 4*C)
        with self.assertRaisesRegex(Qcow2MetadataError, "Extra refcount"):
            self.scan()

    def test_inadequate_l1_coverage_rejected(self):
        self.patch_u32(36, 1)
        with self.assertRaisesRegex(Qcow2MetadataError, "complete one-cluster"):
            self.scan()

    def test_l1_padded_entries_and_header_padding_rejected(self):
        self.patch_u64(C+48*8, COPIED | 4*C)
        with self.assertRaisesRegex(Qcow2MetadataError, "padded L1"):
            self.scan()
        self.patch_u64(C+48*8, 0)
        with self.base.open("r+b") as f:
            f.seek(300)
            f.write(b"X")
        with self.assertRaisesRegex(Qcow2MetadataError, "header cluster padding"):
            self.scan()

    def test_wrong_refcount_clusters_and_header_version_rejected(self):
        self.patch_u32(56, 2)
        with self.assertRaises(Qcow2MetadataError):
            self.scan()
        self.patch_u32(56, 1)
        self.patch_u32(4, 2)
        with self.assertRaises(Qcow2MetadataError):
            self.scan()

    def test_oversize_or_truncated_physical_file_fails_without_allocation(self):
        large = self.root / "large"
        with large.open("wb") as f:
            f.truncate(MAX_PHYSICAL_BYTES + C)
        with large.open("rb") as f:
            with self.assertRaisesRegex(Qcow2MetadataError, "Only small"):
                _scan_graph(f.fileno(), os.fstat(f.fileno()).st_size, 24*GIB)
        with self.base.open("r+b") as f:
            f.truncate(2*C)
        with self.assertRaises(Qcow2MetadataError):
            self.scan()

    def test_invalid_asset_digest_and_symlink_base_fail_closed(self):
        self.base.write_bytes(b"tampered")
        with self.assertRaises(Exception):
            self.check()
        self.base.unlink()
        private = self.root / "outside.img"
        private.write_bytes(make_qcow2())
        self.base.symlink_to(private)
        with self.assertRaises(Exception):
            self.check()

    def test_cli_reports_subset_only_and_invalid_input_exit_2(self):
        code, output, err = self.cli()
        self.assertEqual((code, err), (0, ""))
        report = json.loads(output)
        self.assertFalse(report["whole_qcow2_format_support_claimed"])
        self.assertFalse(report["execution_authorized"])
        self.assertEqual(self.check().canonical_json(), output.strip().encode())
        self.patch_u64(C, 2*C | COPIED)
        code, stdout, stderr = self.cli()
        self.assertEqual((code, stdout), (2, ""))
        self.assertTrue(stderr)

    def test_no_process_network_host_or_overlay_mutation(self):
        before = sorted((p.name, p.read_bytes()) for p in self.assets.iterdir())
        with (
            patch.object(subprocess, "Popen", side_effect=AssertionError("Popen")),
            patch.object(subprocess, "run", side_effect=AssertionError("run")),
            patch.object(socket, "socket", side_effect=AssertionError("network")),
        ):
            response = self.check()
            self.assertFalse(response.to_dict()["qemu_executed"])
        self.assertEqual(before, sorted((p.name, p.read_bytes()) for p in self.assets.iterdir()))
        self.assertEqual(self.neighbor.read_text(), "preserve this fixture")

    def test_real_run_compare_report_remain_disabled(self):
        for cmd in ("run", "compare", "report"):
            status, stdout, err = self.cli([cmd])
            self.assertEqual((status, stdout), (3, ""))


if __name__ == "__main__":
    unittest.main()
