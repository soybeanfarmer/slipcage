"""SC-13b2 offline detached Ed25519 provenance verification.

The operator must obtain the public key independently from a trusted publisher
channel. Any attacker can sign with their OWN key; successful verification only
authenticates possession of the SUPPLIED key and binds it to a plan. No keys
are bundled; no online certificate/identity/revocation checks are performed.
No VM/image archive execution or host probing.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import base64
import hashlib
import json
import os
import stat

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .vm_plan import K3sVMPlan, VMPlanError, validate_vm_plan_bytes
from .vm_assets import ARTIFACTS

API_VERSION = "slipcage.dev/vm-provenance/v1alpha1"
_MAX_JSON = 16 * 1024
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
_FIELDS = {x[0] for x in ARTIFACTS}


class VMProvenanceError(ValueError):
    """Bad, untrusted or unverifiable detached provenance."""


def _read_regular(path: str | Path, limit: int) -> bytes:
    fd = None
    try:
        fd = os.open(Path(path), _FILE_FLAGS)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 1 <= info.st_size <= limit:
            raise VMProvenanceError("Provenance input must be a bounded single-link regular file")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            data = stream.read(limit + 1)
        if len(data) != info.st_size:
            raise VMProvenanceError("Provenance file changed or exceeded size cap")
        return data
    except OSError as exc:
        raise VMProvenanceError("Unavailable or unsafe provenance input") from exc
    finally:
        if fd is not None:
            os.close(fd)


def _duplicate(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise VMProvenanceError("Duplicate provenance JSON keys")
        out[k] = v
    return out


def _reject_numeric(_):
    raise VMProvenanceError("Floating or nonfinite numbers are forbidden")


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


@dataclass(frozen=True, slots=True)
class VMProvenanceCheck:
    plan_id: str
    plan_digest_sha256: str
    statement_digest_sha256: str
    trusted_key_fingerprint_sha256: str

    def to_dict(self) -> dict:
        return {
            "api_version": API_VERSION,
            "status": "signature_valid_for_supplied_public_key",
            "plan_id": self.plan_id,
            "plan_digest_sha256": self.plan_digest_sha256,
            "statement_digest_sha256": self.statement_digest_sha256,
            "trusted_key_fingerprint_sha256": self.trusted_key_fingerprint_sha256,
            "signature_cryptographically_valid": True,
            "key_identity_verified_out_of_band": False,
            "software_origin_independently_authenticated": False,
            "source_revocation_checked": False,
            "local_artifact_bytes_checked_by_this_command": False,
            "host_kvm_verified": False,
            "provider_permission_verified": False,
            "execution_authorized": False,
            "host_modified": False,
            "vm_launched": False,
        }

    def canonical_json(self) -> bytes:
        return _canonical(self.to_dict())


def verify_provenance(
    plan: K3sVMPlan,
    statement_path: str | Path,
    signature_path: str | Path,
    trusted_public_key_path: str | Path,
) -> VMProvenanceCheck:
    """Verify a strict, context-separated detached signature and plan pins.

    Public key must be independently authenticated OUTSIDE this tool, not
    fetched or accepted merely because it accompanied the statement.
    """
    if type(plan) is not K3sVMPlan:
        raise VMProvenanceError("Validated SC-12 VM plan required")
    try:
        checked = validate_vm_plan_bytes(plan.canonical_json)
    except (VMPlanError, AttributeError, TypeError, ValueError) as exc:
        raise VMProvenanceError("Invalid VM plan") from exc
    if checked != plan or checked.design["provenance"]["pin_status"] != "operator_supplied_unverified":
        raise VMProvenanceError("Only internally consistent nonsynthetic VM plans are supported")
    raw = _read_regular(statement_path, _MAX_JSON)
    try:
        document = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_duplicate,
            parse_constant=_reject_numeric, parse_float=_reject_numeric,
        )
        if type(document) is not dict or _canonical(document) != raw:
            raise VMProvenanceError("Statement must be canonical UTF-8 JSON")
    except (UnicodeError, ValueError, RecursionError, OverflowError, TypeError) as exc:
        raise VMProvenanceError("Malformed provenance statement") from exc
    if set(document) != {"api_version", "release_id", "plan_digest_sha256", "artifacts"}:
        raise VMProvenanceError("Unsupported provenance fields")
    if document["api_version"] != API_VERSION:
        raise VMProvenanceError("Unsupported provenance version")
    release = document["release_id"]
    if type(release) is not str or not 3 <= len(release) <= 80 or not release.replace("-", "").replace(".", "").replace("_", "").isalnum() or not release.isascii():
        raise VMProvenanceError("Invalid release reference")
    if document["plan_digest_sha256"] != checked.digest_sha256:
        raise VMProvenanceError("Signed statement is not bound to this VM plan")
    if type(document["artifacts"]) is not dict or set(document["artifacts"]) != _FIELDS:
        raise VMProvenanceError("Signed statement must cover all five assets")
    for field in _FIELDS:
        if document["artifacts"][field] != checked.design["artifacts"][field]:
            raise VMProvenanceError("Signed artifact digest differs from VM plan")
    signature = _read_regular(signature_path, 256)
    pubbytes = _read_regular(trusted_public_key_path, 256)
    # Raw Ed25519 keys/signatures; format forbids permissive PEM parsing and
    # ambiguous DER key wrappers. SHA-256 fingerprint is printed for manual
    # comparison with an OUT-OF-BAND publisher fingerprint.
    if len(pubbytes) != 32 or len(signature) != 64:
        raise VMProvenanceError("Only raw Ed25519 public keys/signatures are supported")
    try:
        Ed25519PublicKey.from_public_bytes(pubbytes).verify(
            signature, b"SLIPCAGE_VM_PROVENANCE_V1\0" + raw
        )
    except (ValueError, InvalidSignature) as exc:
        raise VMProvenanceError("Detached Ed25519 signature invalid") from exc
    return VMProvenanceCheck(
        checked.name, checked.digest_sha256,
        hashlib.sha256(raw).hexdigest(),
        hashlib.sha256(pubbytes).hexdigest(),
    )
