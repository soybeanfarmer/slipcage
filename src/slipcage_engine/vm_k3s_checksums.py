"""SC-13b14: OFFLINE K3s release checksum-file/local-asset reconciliation.

Not a remote fetch, publisher authentication, signed upstream attestation,
valid image inspection, or host permission check. The checksum text, VM plan
and files are supplied by the same untrusted local operator unless verified
independently outside this tool. No execution, writes, decompression or mount.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .vm_assets import VMAssetPreflight, verify_local_vm_assets
from .vm_plan import K3sVMPlan, VMPlanError, validate_vm_plan_bytes

API_VERSION = "slipcage.dev/k3s-upstream-checksum-check/v1alpha1"
ARCH = "amd64"
_BINARY_UPSTREAM_NAME = "k3s"
_ARCHIVE_UPSTREAM_NAME = "k3s-airgap-images-amd64.tar"
_ARCHIVE_CHOICES = frozenset({
    _ARCHIVE_UPSTREAM_NAME,
    "k3s-airgap-images-amd64.tar.gz",
    "k3s-airgap-images-amd64.tar.zst",
})
_HASH_LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,95})$")
_STABLE_TAG = re.compile(r"^v[1-9][0-9]*\.[0-9]+\.[0-9]+\+k3s[1-9][0-9]*$")
_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
_MAX_MANIFEST = 8192
_MAX_ENTRIES = 8


class K3sReleaseChecksumError(ValueError):
    """Unsafe local upstream-style checksum manifest or inconsistent asset."""


def _read_private_file(path: str | Path) -> bytes:
    fd: int | None = None
    try:
        fd = os.open(Path(path), _FLAGS)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or not 1 <= info.st_size <= _MAX_MANIFEST):
            raise K3sReleaseChecksumError(
                "Checksum source must be bounded private 0600 single-link regular file"
            )
        with os.fdopen(fd, "rb") as stream:
            fd = None
            raw = stream.read(_MAX_MANIFEST + 1)
            after = os.fstat(stream.fileno())
            if (len(raw) != info.st_size
                    or (info.st_dev, info.st_ino, info.st_size,
                        info.st_mtime_ns, info.st_ctime_ns)
                    != (after.st_dev, after.st_ino, after.st_size,
                        after.st_mtime_ns, after.st_ctime_ns)):
                raise K3sReleaseChecksumError("Checksum source changed while reading")
            linked = os.stat(path, follow_symlinks=False)
            if (not stat.S_ISREG(linked.st_mode)
                    or (linked.st_dev, linked.st_ino) != (after.st_dev, after.st_ino)):
                raise K3sReleaseChecksumError("Checksum source filename was replaced")
            return raw
    except OSError as exc:
        raise K3sReleaseChecksumError("Unsafe or unreadable local K3s checksum source") from exc
    finally:
        if fd is not None:
            os.close(fd)


def _parse_manifest(raw: bytes, allow: frozenset[str]) -> dict[str, str]:
    if not raw.endswith(b"\n") or b"\r" in raw or b"\x00" in raw:
        raise K3sReleaseChecksumError("Require complete LF-only sha256sum records")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise K3sReleaseChecksumError("Non-ASCII K3s checksum manifest") from exc
    if not 1 <= len(lines) <= _MAX_ENTRIES:
        raise K3sReleaseChecksumError("Checksum manifest line count outside strict bounds")
    result: dict[str, str] = {}
    for line in lines:
        match = _HASH_LINE.fullmatch(line)
        if match is None:
            raise K3sReleaseChecksumError("Invalid sha256sum line syntax or filename")
        digest, filename = match.groups()
        if filename not in allow or filename in result:
            raise K3sReleaseChecksumError("Unexpected, repeated or unsupported K3s release asset")
        result[filename] = digest
    return result


@dataclass(frozen=True, slots=True)
class K3sUpstreamChecksumCheck:
    plan_id: str
    plan_digest_sha256: str
    release_tag: str
    binary_manifest_sha256: str
    archive_manifest_sha256: str
    k3s_binary_sha256: str
    airgap_archive_sha256: str
    binary_size_bytes: int
    archive_size_bytes: int

    def to_dict(self) -> dict:
        return {
            "api_version": API_VERSION,
            "kind": "locally_supplied_k3s_release_checksum_reconciliation",
            "plan_id": self.plan_id,
            "plan_digest_sha256": self.plan_digest_sha256,
            "release_tag_operator_declared": self.release_tag,
            "architecture": ARCH,
            "binary_upstream_asset": _BINARY_UPSTREAM_NAME,
            "archive_upstream_asset": _ARCHIVE_UPSTREAM_NAME,
            "binary_manifest_sha256": self.binary_manifest_sha256,
            "airgap_manifest_sha256": self.archive_manifest_sha256,
            "binary_sha256": self.k3s_binary_sha256,
            "airgap_archive_sha256": self.airgap_archive_sha256,
            "binary_size_bytes": self.binary_size_bytes,
            "airgap_archive_size_bytes": self.archive_size_bytes,
            "both_manifest_digests_match_local_bytes_and_plan": True,
            "all_five_local_assets_checked": True,
            "publisher_checksum_source_authenticated": False,
            "release_tag_verified_against_upstream": False,
            "upstream_release_signatures_verified": False,
            "airgap_archive_contents_inspected": False,
            "container_images_provenance_authenticated": False,
            "cni_and_kernel_upstream_verified": False,
            "software_publisher_authenticated": False,
            "host_kvm_verified": False,
            "provider_permission_verified": False,
            "execution_authorized": False,
            "vm_launched": False,
            "host_modified": False,
        }

    def canonical_json(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")


def verify_k3s_release_checksums(
    plan: K3sVMPlan, asset_root: str | Path,
    binary_checksums: str | Path, airgap_checksums: str | Path,
) -> K3sUpstreamChecksumCheck:
    """Cross-check exact local uncompressed amd64 release bytes against
    *separately supplied* upstream-style checksum files; never executes them.
    """
    if type(plan) is not K3sVMPlan:
        raise K3sReleaseChecksumError("Strict SC-12 typed VM plan required")
    try:
        checked = validate_vm_plan_bytes(plan.canonical_json)
    except (VMPlanError, ValueError, TypeError, AttributeError) as exc:
        raise K3sReleaseChecksumError("Invalid SC-12 VM plan") from exc
    if checked != plan or checked.design["provenance"]["pin_status"] != "operator_supplied_unverified":
        raise K3sReleaseChecksumError("Synthetic/forged plan must not be accepted")
    if checked.design["runtime"]["architecture"] != "x86_64":
        raise K3sReleaseChecksumError("Only amd64/x86_64 upstream release assets supported")
    tag = checked.design["software"]["k3s_version"]
    if type(tag) is not str or _STABLE_TAG.fullmatch(tag) is None:
        raise K3sReleaseChecksumError("Require pinned stable K3s release tag")
    if Path(binary_checksums).absolute() == Path(airgap_checksums).absolute():
        raise K3sReleaseChecksumError("Independent binary and airgap manifest paths required")

    # Preflight checks actual existing bytes for ALL five private assets and
    # matches them to operator-declared plan pins. Does not trust byte origins.
    preflight: VMAssetPreflight = verify_local_vm_assets(checked, asset_root)
    assets = {a.digest_field: a for a in preflight.assets}
    binary = assets["k3s_binary_sha256"]
    archive = assets["container_images_sha256"]

    braw = _read_private_file(binary_checksums)
    araw = _read_private_file(airgap_checksums)
    bfiles = _parse_manifest(braw, frozenset({_BINARY_UPSTREAM_NAME}))
    afiles = _parse_manifest(araw, _ARCHIVE_CHOICES)
    if _BINARY_UPSTREAM_NAME not in bfiles or _ARCHIVE_UPSTREAM_NAME not in afiles:
        raise K3sReleaseChecksumError(
            "Exact k3s binary and uncompressed amd64 airgap tar checksums required"
        )
    if bfiles[_BINARY_UPSTREAM_NAME] != binary.sha256:
        raise K3sReleaseChecksumError("K3s binary release checksum mismatches local file/plan")
    if afiles[_ARCHIVE_UPSTREAM_NAME] != archive.sha256:
        raise K3sReleaseChecksumError("K3s airgap tar release checksum mismatches local file/plan")
    return K3sUpstreamChecksumCheck(
        checked.name, checked.digest_sha256, tag,
        hashlib.sha256(braw).hexdigest(), hashlib.sha256(araw).hexdigest(),
        binary.sha256, archive.sha256, binary.size_bytes, archive.size_bytes,
    )
