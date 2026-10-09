"""SC-13b15: offline, read-only per-artifact source custody receipts.

The caller supplies both ledger and receipts: matching them and the actual
asset bytes does NOT authenticate the origin of either source, the publisher,
an operator, or an upstream release. Never execute or acquire an artifact.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import quote, urlsplit

from .vm_assets import ARTIFACTS, verify_local_vm_assets
from .vm_plan import K3sVMPlan, VMPlanError, validate_vm_plan_bytes

API_VERSION = "slipcage.dev/vm-artifact-source-ledger/v1alpha1"
RECEIPT_API = "slipcage.dev/vm-artifact-source-receipt/v1alpha1"
_MAX_LEDGER_BYTES = 16384
_MAX_RECEIPT_BYTES = 4096
_SHA = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,79}$")
_DNS = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_ENTRIES = (
    ("os_image_sha256", "os-image.source.json", None),
    ("kernel_sha256", "kernel.source.json", None),
    ("k3s_binary_sha256", "k3s.source.json", "k3s"),
    ("cni_assets_sha256", "cni.source.json", None),
    ("container_images_sha256", "container-images.source.json", "k3s-airgap-images-amd64.tar"),
)
_LEDGER_FIELDS = frozenset(("api_version", "kind", "plan_digest_sha256", "operator_assertion", "artifacts"))
_ENTRY_FIELDS = frozenset(("digest_field", "artifact_sha256", "source_uri", "version_ref", "receipt_sha256"))
_RECEIPT_FIELDS = frozenset(("api_version", "digest_field", "artifact_sha256", "source_uri", "version_ref", "observation"))


class ArtifactSourceError(ValueError):
    """Offline provenance references are missing, forged or unsafe."""


def _pairs(values):
    data = {}
    for k, value in values:
        if k in data:
            raise ArtifactSourceError("Duplicate JSON keys in source evidence")
        data[k] = value
    return data


def _reject_number(_):
    raise ArtifactSourceError("Floating or nonfinite source evidence forbidden")


def _canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def _decode(raw: bytes, *, cap: int, exact_fields: frozenset[str]) -> dict:
    if not 1 <= len(raw) <= cap:
        raise ArtifactSourceError("Missing or oversized source evidence")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
        if type(value) is not dict or frozenset(value) != exact_fields or raw != _canonical(value):
            raise ArtifactSourceError("Source evidence must be exact canonical JSON")
        return value
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError) as exc:
        raise ArtifactSourceError("Malformed or noncanonical source evidence") from exc


def _read_fd(parent_fd: int | None, filename: str | Path, max_bytes: int) -> bytes:
    fd = None
    try:
        fd = os.open(filename, _READ, **({"dir_fd": parent_fd} if parent_fd is not None else {}))
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or not 1 <= info.st_size <= max_bytes):
            raise ArtifactSourceError("Source evidence must be private 0600 single-link bounded file")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            raw = stream.read(max_bytes + 1)
            after = os.fstat(stream.fileno())
            if (len(raw) != info.st_size
                    or (info.st_dev, info.st_ino, info.st_size,
                        info.st_mtime_ns, info.st_ctime_ns)
                    != (after.st_dev, after.st_ino, after.st_size,
                        after.st_mtime_ns, after.st_ctime_ns)):
                raise ArtifactSourceError("Source evidence changed during read")
        current = os.stat(filename, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(current.st_mode)
                or (current.st_dev, current.st_ino) != (after.st_dev, after.st_ino)):
            raise ArtifactSourceError("Source evidence replaced during inspection")
        return raw
    except OSError as exc:
        raise ArtifactSourceError("Missing, unsafe or unreadable source evidence file") from exc
    finally:
        if fd is not None:
            os.close(fd)


def _url(value: object, upstream_asset: str | None, release_tag: str) -> bool:
    if type(value) is not str or not 18 <= len(value) <= 320 or not value.isascii():
        return False
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.netloc or not parsed.path
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment or parsed.port is not None
                or parsed.hostname != parsed.netloc
                or not _DNS.fullmatch(parsed.hostname or "")
                or any(c in value for c in ("\\", " ", "\n", "\r", "\x00"))):
            return False
    except ValueError:
        return False
    if upstream_asset is not None:
        prefix = "https://github.com/k3s-io/k3s/releases/download/"
        canonical = prefix + quote(release_tag, safe="") + "/" + upstream_asset
        return value == canonical
    return True


@dataclass(frozen=True, slots=True)
class ArtifactSourceReview:
    plan_id: str
    plan_digest_sha256: str
    ledger_sha256: str
    receipt_fingerprints: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "api_version": API_VERSION,
            "kind": "read_only_local_artifact_source_custody_review",
            "status": "operator_source_authentication_pending",
            "plan_id": self.plan_id,
            "plan_digest_sha256": self.plan_digest_sha256,
            "ledger_sha256": self.ledger_sha256,
            "artifact_count": len(self.receipt_fingerprints),
            "receipt_sha256_by_fixed_asset_order": list(self.receipt_fingerprints),
            "all_five_local_asset_bytes_match_plan": True,
            "ledger_and_receipt_metadata_match": True,
            "release_url_shapes_checked": True,
            "publisher_origin_authenticated": False,
            "receipt_authenticity_independently_verified": False,
            "release_version_resolved_from_upstream": False,
            "operator_identity_authenticated": False,
            "source_url_retrieved_or_validated_online": False,
            "artifact_contents_or_build_reproducibility_verified": False,
            "guest_image_and_cni_provenance_authenticated": False,
            "provider_permission_verified": False,
            "kvm_ready_verified": False,
            "execution_authorized": False,
            "vm_launched": False,
            "host_modified": False,
        }

    def canonical_json(self) -> bytes:
        return _canonical(self.to_dict())


def review_artifact_source_ledger(
    plan: K3sVMPlan, assets_directory: str | Path,
    ledger_path: str | Path, receipts_directory: str | Path,
) -> ArtifactSourceReview:
    """Reconcile five private custody receipts to pinned real local bytes.

    Does not trust or authenticate any supplied source URL or receipt.
    """
    if type(plan) is not K3sVMPlan:
        raise ArtifactSourceError("Exact SC-12 plan required")
    try:
        checked = validate_vm_plan_bytes(plan.canonical_json)
    except (VMPlanError, ValueError, TypeError, AttributeError) as exc:
        raise ArtifactSourceError("Malformed pinned plan") from exc
    if checked != plan or checked.design["provenance"]["pin_status"] != "operator_supplied_unverified":
        raise ArtifactSourceError("Synthetic or forged plan cannot be source-reviewed")
    asset_preflight = verify_local_vm_assets(checked, assets_directory)
    assets = {a.digest_field: a for a in asset_preflight.assets}
    lraw = _read_fd(None, ledger_path, _MAX_LEDGER_BYTES)
    ledger = _decode(lraw, cap=_MAX_LEDGER_BYTES, exact_fields=_LEDGER_FIELDS)
    if (ledger["api_version"] != API_VERSION
            or ledger["kind"] != "VMArtifactSourceLedger"
            or ledger["operator_assertion"] != "source_reference_recorded_unverified"
            or ledger["plan_digest_sha256"] != checked.digest_sha256
            or type(ledger["artifacts"]) is not list
            or len(ledger["artifacts"]) != len(_ENTRIES)):
        raise ArtifactSourceError("Ledger not bound to the exact plan/five source slots")
    release_tag = checked.design["software"]["k3s_version"]
    fd = None
    try:
        fd = os.open(receipts_directory, _DIR)
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ArtifactSourceError("Existing 0700 private receipts directory required")
        if set(os.listdir(fd)) != {name for _, name, _ in _ENTRIES}:
            raise ArtifactSourceError("Missing or unexpected receipt-directory entries")
        receipt_hashes: list[str] = []
        for (field, name, upstream_name), entry in zip(_ENTRIES, ledger["artifacts"]):
            if type(entry) is not dict or frozenset(entry) != _ENTRY_FIELDS:
                raise ArtifactSourceError("Wrong entry fields/order")
            source, version = entry["source_uri"], entry["version_ref"]
            if (entry["digest_field"] != field
                    or entry["artifact_sha256"] != assets[field].sha256
                    or type(entry["receipt_sha256"]) is not str
                    or _SHA.fullmatch(entry["receipt_sha256"]) is None
                    or type(version) is not str or _VERSION.fullmatch(version) is None
                    or (upstream_name is not None and version != release_tag)
                    or not _url(source, upstream_name, release_tag)):
                raise ArtifactSourceError("Source entry mismatches plan, release, URL shape or byte digest")
            raw = _read_fd(fd, name, _MAX_RECEIPT_BYTES)
            receipt = _decode(raw, cap=_MAX_RECEIPT_BYTES, exact_fields=_RECEIPT_FIELDS)
            digest = hashlib.sha256(raw).hexdigest()
            if (digest != entry["receipt_sha256"]
                    or receipt["api_version"] != RECEIPT_API
                    or receipt["observation"] != "operator_supplied_unverified"
                    or any(receipt[k] != entry[k] for k in (
                        "digest_field", "artifact_sha256", "source_uri", "version_ref"
                    ))):
                raise ArtifactSourceError("Receipt mismatch or unsupported operator assertion")
            receipt_hashes.append(digest)
        return ArtifactSourceReview(
            checked.name, checked.digest_sha256, hashlib.sha256(lraw).hexdigest(),
            tuple(receipt_hashes),
        )
    except OSError as exc:
        raise ArtifactSourceError("Cannot inspect existing private receipt directory") from exc
    finally:
        if fd is not None:
            os.close(fd)
