"""SC-13b13: offline operator-supplied signing-key fingerprint policy.

A separately obtained *trusted* fingerprint is required for real publisher
authentication, but this module CANNOT determine whether the input policy is
genuine or complete. A matching operator-supplied policy and key only proves
local consistency; any adversary supplying both can forge that consistency.

No network, release fetching, signed transparency log, provider or host ops,
filesystem writes, VM, QEMU, or guest execution.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat

from .vm_plan import K3sVMPlan
from .vm_provenance import VMProvenanceError, verify_provenance, _read_regular

API_VERSION = "slipcage.dev/vm-key-pin-policy/v1alpha1"
_MAX_POLICY_BYTES = 4096
_MAX_REVOKED = 32
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
_HEX = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,79}$")
_FIELDS = {
    "api_version", "policy_origin", "source_label", "release_id",
    "plan_digest_sha256", "statement_sha256",
    "allowed_key_sha256", "revoked_key_sha256",
}


class VMKeyPolicyError(ValueError):
    """Unsafe, mismatched or malformed independently supplied key policy."""


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _pairs(items):
    found = {}
    for k, v in items:
        if k in found:
            raise VMKeyPolicyError("Duplicate policy fields")
        found[k] = v
    return found


def _reject_numeric(_):
    raise VMKeyPolicyError("Floating and nonfinite policy numbers forbidden")


def _read_private_policy(path: str | Path) -> bytes:
    handle = None
    try:
        handle = os.open(Path(path), _FILE_FLAGS)
        info = os.fstat(handle)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or not 1 <= info.st_size <= _MAX_POLICY_BYTES):
            raise VMKeyPolicyError("Policy must be bounded private single-link regular file 0600")
        with os.fdopen(handle, "rb") as stream:
            handle = None
            raw = stream.read(_MAX_POLICY_BYTES + 1)
            after = os.fstat(stream.fileno())
            if (len(raw) != info.st_size
                    or (info.st_dev, info.st_ino, info.st_size,
                        info.st_mtime_ns, info.st_ctime_ns)
                    != (after.st_dev, after.st_ino, after.st_size,
                        after.st_mtime_ns, after.st_ctime_ns)):
                raise VMKeyPolicyError("Policy changed during read")
            by_path = os.stat(path, follow_symlinks=False)
            if (not stat.S_ISREG(by_path.st_mode)
                    or (after.st_dev, after.st_ino) != (by_path.st_dev, by_path.st_ino)):
                raise VMKeyPolicyError("Policy name replaced during inspection")
            return raw
    except OSError as exc:
        raise VMKeyPolicyError("Missing, symlinked or unreadable private policy") from exc
    finally:
        if handle is not None:
            os.close(handle)


@dataclass(frozen=True, slots=True)
class SigningKeyPolicyCheck:
    plan_digest_sha256: str
    policy_digest_sha256: str
    statement_digest_sha256: str
    supplied_public_key_fingerprint_sha256: str
    release_id: str
    source_label: str
    listed_revocation_count: int

    def to_dict(self) -> dict:
        return {
            "api_version": API_VERSION,
            "kind": "operator_supplied_signing_fingerprint_consistency",
            "plan_digest_sha256": self.plan_digest_sha256,
            "policy_digest_sha256": self.policy_digest_sha256,
            "statement_digest_sha256": self.statement_digest_sha256,
            "supplied_public_key_fingerprint_sha256": self.supplied_public_key_fingerprint_sha256,
            "release_id": self.release_id,
            "source_label_operator_declared": self.source_label,
            "listed_revocation_count": self.listed_revocation_count,
            "signature_valid_for_supplied_public_key": True,
            "key_matches_operator_policy_fingerprint": True,
            "key_absent_from_policy_denylist": True,
            "policy_authenticity_verified": False,
            "key_identity_verified_out_of_band": False,
            "publisher_identity_authenticated": False,
            "revocation_information_complete_or_current": False,
            "transparency_log_checked": False,
            "local_asset_bytes_verified_by_policy": False,
            "host_kvm_verified": False,
            "provider_permission_verified": False,
            "execution_authorized": False,
            "host_modified": False,
            "vm_launched": False,
        }

    def canonical_json(self) -> bytes:
        return _canonical(self.to_dict())


def verify_vm_signing_key_policy(
    plan: K3sVMPlan,
    statement_path: str | Path,
    signature_path: str | Path,
    public_key_path: str | Path,
    policy_path: str | Path,
) -> SigningKeyPolicyCheck:
    """Check supplied key/signature against an independent *local* pin policy.

    The caller is responsible for independently authenticating policy source,
    publisher key identity, and revocation status outside this implementation.
    """
    try:
        proven = verify_provenance(plan, statement_path, signature_path, public_key_path)
    except VMProvenanceError as exc:
        raise VMKeyPolicyError("Underlying detached signature/plan validation failed") from exc

    raw = _read_private_policy(policy_path)
    try:
        policy = json.loads(
            raw.decode("ascii"), object_pairs_hook=_pairs,
            parse_float=_reject_numeric, parse_constant=_reject_numeric,
        )
        if type(policy) is not dict or set(policy) != _FIELDS or raw != _canonical(policy):
            raise VMKeyPolicyError("Policy must contain exact canonical fields")
    except (UnicodeError, ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise VMKeyPolicyError("Invalid canonical key policy") from exc
    if (policy["api_version"] != API_VERSION
            or policy["policy_origin"] != "operator_supplied_unverified"):
        raise VMKeyPolicyError("Unsupported policy schema or source")
    for name in ("release_id", "source_label"):
        value = policy[name]
        if type(value) is not str or _TOKEN.fullmatch(value) is None:
            raise VMKeyPolicyError("Invalid policy release/source label")
    for name in ("plan_digest_sha256", "statement_sha256", "allowed_key_sha256"):
        if type(policy[name]) is not str or _HEX.fullmatch(policy[name]) is None:
            raise VMKeyPolicyError("Invalid strict policy digest field")
    revoked = policy["revoked_key_sha256"]
    if (type(revoked) is not list or len(revoked) > _MAX_REVOKED
            or any(type(item) is not str or _HEX.fullmatch(item) is None for item in revoked)
            or revoked != sorted(set(revoked))):
        raise VMKeyPolicyError("Revocation list must be unique, sorted and bounded")

    # Refetch the exact statement; accept no mismatch to the bytes whose
    # detached signature was just checked, even if files changed between reads.
    try:
        signed_statement = _read_regular(statement_path, 16 * 1024)
        release = json.loads(signed_statement.decode("ascii"))["release_id"]
    except (VMProvenanceError, UnicodeError, ValueError, KeyError, TypeError) as exc:
        raise VMKeyPolicyError("Signed statement disappeared or changed") from exc

    if (not secrets.compare_digest(hashlib.sha256(signed_statement).hexdigest(),
                                   proven.statement_digest_sha256)
            or policy["release_id"] != release
            or not secrets.compare_digest(policy["plan_digest_sha256"],
                                          proven.plan_digest_sha256)
            or not secrets.compare_digest(policy["statement_sha256"],
                                          proven.statement_digest_sha256)):
        raise VMKeyPolicyError("Policy not scoped to signed release, plan and statement")
    if not secrets.compare_digest(policy["allowed_key_sha256"],
                                  proven.trusted_key_fingerprint_sha256):
        raise VMKeyPolicyError("Signing public key differs from independently supplied pin")
    if proven.trusted_key_fingerprint_sha256 in revoked:
        raise VMKeyPolicyError("Signing key explicitly revoked in supplied policy")
    return SigningKeyPolicyCheck(
        proven.plan_digest_sha256,
        hashlib.sha256(raw).hexdigest(),
        proven.statement_digest_sha256,
        proven.trusted_key_fingerprint_sha256,
        release, policy["source_label"], len(revoked),
    )
