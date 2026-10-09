"""SC-13b16: strictly bounded, read-only QCOW2 v3 metadata graph subset.

Accepts ONLY small, simple, uncompressed, non-backed images with one L1
cluster, one refcount-table cluster and one refcount block. Traverses all
their L1/L2 mappings and 16-bit refcounts. Deliberately rejects most real
OS images: NO full QCOW2 compatibility, content authentication, backing
chain, OS safety, QEMU invocation, guest boot or execution authorization.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat

from .vm_assets import ARTIFACTS, verify_local_vm_assets
from .vm_overlay_preflight import (
    BASE_NAME, CLUSTER_BYTES, HEADER_BYTES, GIB, OverlayPreflightError,
    _inspect_base_header,
)
from .vm_plan import K3sVMPlan

API_VERSION = "slipcage.dev/qcow2-bounded-metadata/v1alpha1"
MAX_PHYSICAL_BYTES = 64 * 1024 * 1024
MAX_PHYSICAL_CLUSTERS = MAX_PHYSICAL_BYTES // CLUSTER_BYTES
MAX_L2_CLUSTERS = 16
MAX_DATA_CLUSTERS = 960
_COPIED = 1 << 63
_OFFSET_MASK = ((1 << 56) - 1) & ~(CLUSTER_BYTES - 1)
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)


class Qcow2MetadataError(ValueError):
    """Unsupported or inconsistent narrow QCOW2 metadata subset."""


@dataclass(frozen=True, slots=True)
class BoundedQcow2MetadataReview:
    plan_digest_sha256: str
    base_sha256: str
    physical_bytes: int
    virtual_bytes: int
    l1_entries: int
    l2_clusters: int
    mapped_guest_clusters: int
    refcount_blocks: int

    def to_dict(self) -> dict:
        return {
            "api_version": API_VERSION,
            "kind": "bounded_no_backing_qcow2_metadata_consistency_review",
            "status": "small_subset_locally_consistent_not_guest_verified",
            "plan_digest_sha256": self.plan_digest_sha256,
            "operator_pinned_base_sha256": self.base_sha256,
            "physical_bytes": self.physical_bytes,
            "virtual_bytes": self.virtual_bytes,
            "l1_entries_examined": self.l1_entries,
            "l2_table_clusters_examined": self.l2_clusters,
            "guest_data_clusters_examined": self.mapped_guest_clusters,
            "refcount_blocks_examined": self.refcount_blocks,
            "l1_l2_refcount_graph_consistent_for_narrow_subset": True,
            "source_publisher_authenticated": False,
            "whole_qcow2_format_support_claimed": False,
            "real_os_image_contents_authenticated": False,
            "qcow2_backing_chain_traversed": False,
            "base_immutability_enforced": False,
            "filesystem_quota_enforced": False,
            "qemu_img_executed": False,
            "qemu_executed": False,
            "host_kvm_verified": False,
            "guest_boot_verified": False,
            "overlay_created": False,
            "execution_authorized": False,
            "host_modified": False,
        }

    def canonical_json(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=True,
                          separators=(",", ":"), allow_nan=False).encode("ascii")


def _u64(block: bytes, n: int) -> int:
    return int.from_bytes(block[n:n + 8], "big")


def _read_cluster(fd: int, index: int, total_clusters: int) -> bytes:
    if type(index) is not int or not 0 <= index < total_clusters:
        raise Qcow2MetadataError("Metadata pointer outside bounded QCOW2 physical file")
    data = os.pread(fd, CLUSTER_BYTES, index * CLUSTER_BYTES)
    if len(data) != CLUSTER_BYTES:
        raise Qcow2MetadataError("Short QCOW2 cluster read")
    return data


def _pointer(value: int, total_clusters: int, *, is_l2: bool) -> int:
    # Reject zero/compressed/special/reserved flags, require copied and aligned
    # cluster pointer; shared data clusters are outside this limited subset.
    if value == 0 or not value & _COPIED:
        raise Qcow2MetadataError("QCOW2 metadata/data pointer lacks copied bit")
    if value & ~(_OFFSET_MASK | _COPIED):
        raise Qcow2MetadataError("Compressed, zero, unaligned or reserved QCOW2 pointer")
    index = (value & _OFFSET_MASK) // CLUSTER_BYTES
    if not 1 <= index < total_clusters:
        raise Qcow2MetadataError("QCOW2 cluster pointer outside physical file")
    return index


def _scan_graph(fd: int, physical_size: int, virtual_size: int) -> tuple[int, int, int]:
    if (physical_size % CLUSTER_BYTES or not 4 * CLUSTER_BYTES <= physical_size <= MAX_PHYSICAL_BYTES):
        raise Qcow2MetadataError("Only small, cluster-aligned QCOW2 files can be scanned")
    n = physical_size // CLUSTER_BYTES
    header = os.pread(fd, HEADER_BYTES, 0)
    try:
        _inspect_base_header(header, physical_size, virtual_size)
    except OverlayPreflightError as exc:
        raise Qcow2MetadataError("Unsupported or invalid QCOW2 header-only preflight") from exc

    l1_count = int.from_bytes(header[36:40], "big")
    l1_off = int.from_bytes(header[40:48], "big") // CLUSTER_BYTES
    ref_off = int.from_bytes(header[48:56], "big") // CLUSTER_BYTES
    ref_clusters = int.from_bytes(header[56:60], "big")
    # One 64-KiB L1 cluster covers 8192*8192*64KiB, while the actual
    # required entries must cover every declared virtual guest cluster.
    required_l1 = (virtual_size + (CLUSTER_BYTES * (CLUSTER_BYTES // 8)) - 1) // (
        CLUSTER_BYTES * (CLUSTER_BYTES // 8))
    if not required_l1 <= l1_count <= CLUSTER_BYTES // 8 or ref_clusters != 1:
        raise Qcow2MetadataError("Only complete one-cluster L1 and refcount tables supported")
    if any(_read_cluster(fd, 0, n)[HEADER_BYTES:]):
        raise Qcow2MetadataError("Unknown header cluster padding/extensions")

    ownership: dict[int, str] = {}

    def reserve(index: int, kind: str) -> None:
        if index in ownership:
            raise Qcow2MetadataError("Overlapping or multiply referenced QCOW2 clusters")
        ownership[index] = kind

    reserve(0, "header")
    reserve(l1_off, "l1")
    reserve(ref_off, "refcount-table")
    table = _read_cluster(fd, ref_off, n)
    if any(table[8:]):
        raise Qcow2MetadataError("Extra refcount blocks/tables outside supported subset")
    first_ref = _u64(table, 0)
    if not first_ref or first_ref % CLUSTER_BYTES:
        raise Qcow2MetadataError("Missing or invalid refcount block pointer")
    ref_block_index = first_ref // CLUSTER_BYTES
    if not 1 <= ref_block_index < n:
        raise Qcow2MetadataError("Refcount block points outside physical file")
    reserve(ref_block_index, "refcount-block")

    l1 = _read_cluster(fd, l1_off, n)
    if any(l1[l1_count * 8:]):
        raise Qcow2MetadataError("Nonzero padded L1 entries")
    l2_count = 0
    mapped = 0
    remaining_guest_clusters = (virtual_size + CLUSTER_BYTES - 1) // CLUSTER_BYTES
    for l1_index in range(l1_count):
        value = _u64(l1, l1_index * 8)
        if not value:
            continue
        l2_count += 1
        if l2_count > MAX_L2_CLUSTERS:
            raise Qcow2MetadataError("QCOW2 L2 table count exceeds narrow inspection limit")
        l2_idx = _pointer(value, n, is_l2=False)
        reserve(l2_idx, "l2")
        l2 = _read_cluster(fd, l2_idx, n)
        valid_l2 = min(CLUSTER_BYTES // 8, max(0, remaining_guest_clusters - l1_index * (CLUSTER_BYTES // 8)))
        if any(l2[valid_l2 * 8:]):
            raise Qcow2MetadataError("L2 mappings beyond virtual disk bounds")
        for l2_index in range(valid_l2):
            item = _u64(l2, l2_index * 8)
            if not item:
                continue
            mapped += 1
            if mapped > MAX_DATA_CLUSTERS:
                raise Qcow2MetadataError("QCOW2 mapped guest cluster count exceeds supported limit")
            data_idx = _pointer(item, n, is_l2=True)
            reserve(data_idx, "data")

    # Read entire refcount block and require *exact* 16-bit refcounts:
    # every allocated metadata/data cluster is owned once, no orphans,
    # shared clusters, double allocation or references outside file.
    refcounts = _read_cluster(fd, ref_block_index, n)
    for index in range(CLUSTER_BYTES // 2):
        value = int.from_bytes(refcounts[2 * index:2 * index + 2], "big")
        if value != (1 if index in ownership else 0):
            raise Qcow2MetadataError("QCOW2 refcount differs from traversed metadata/data allocation")
    if len(ownership) != n:
        raise Qcow2MetadataError("Physical image has orphan/unreferenced clusters")
    return l1_count, l2_count, mapped


def inspect_bounded_qcow2_metadata(
    plan: K3sVMPlan, asset_root: str | Path,
) -> BoundedQcow2MetadataReview:
    """A limited read-only graph check; cannot certify arbitrary QEMU images."""
    # Rehash all five files against exact pinned plan before parsing QCOW2.
    preflight = verify_local_vm_assets(plan, asset_root)
    expected = next(a.sha256 for a in preflight.assets if a.filename == BASE_NAME)
    virtual = plan.design["guest"]["disk_gib"] * GIB
    root_fd = None
    try:
        root_fd = os.open(Path(asset_root), _DIR)
        folder = os.fstat(root_fd)
        if not stat.S_ISDIR(folder.st_mode) or stat.S_IMODE(folder.st_mode) & 0o077:
            raise Qcow2MetadataError("Existing trusted private directory required")
        if set(os.listdir(root_fd)) != {name for _, name, _ in ARTIFACTS}:
            raise Qcow2MetadataError("Unexpected existing asset-directory entries")
        fd = os.open(BASE_NAME, _FILE, dir_fd=root_fd)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or stat.S_IMODE(before.st_mode) & 0o077
                    or not 4 * CLUSTER_BYTES <= before.st_size <= MAX_PHYSICAL_BYTES):
                raise Qcow2MetadataError("QCOW2 file not private, small and regular")
            sizes = _scan_graph(stream.fileno(), before.st_size, virtual)
            digest = hashlib.sha256()
            while True:
                block = stream.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
            after = os.fstat(stream.fileno())
            now = os.stat(BASE_NAME, dir_fd=root_fd, follow_symlinks=False)
            if (not stat.S_ISREG(now.st_mode)
                    or (now.st_dev, now.st_ino) != (after.st_dev, after.st_ino)
                    or (before.st_dev, before.st_ino, before.st_size,
                        before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_dev, after.st_ino, after.st_size,
                        after.st_mtime_ns, after.st_ctime_ns)
                    or digest.hexdigest() != expected):
                raise Qcow2MetadataError("QCOW2 base changed or hash mismatch during metadata review")
            return BoundedQcow2MetadataReview(
                plan.digest_sha256, expected, before.st_size, virtual,
                sizes[0], sizes[1], sizes[2], 1,
            )
    except OSError as exc:
        raise Qcow2MetadataError("Unsafe or unreadable existing QCOW2 file/root") from exc
    finally:
        if root_fd is not None:
            os.close(root_fd)
