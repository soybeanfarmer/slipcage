"""SC-09 private, integrity-checked evidence bundles for OFFLINE fixtures.

This format describes synthetic fixture observations, not real security evidence.
Hashes detect inconsistency but do not authenticate the author of a bundle.

Writes reserve a NEW private directory, write fixed-name files with exclusive
creation, and publish manifest.json LAST. Interrupted directories are preserved
as incomplete evidence; there is never overwrite or destructive auto-cleanup.

Parent directories must be operator-controlled (no adversarial same-UID process
or symlinked intermediate parent components). This is not a general archive
unpacker or multi-tenant artifact service.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from . import __version__
from .fixture_executor import (
    FixtureExecutionError, FixtureRun, FixtureRunState, FixtureScenario,
    run_fixture,
)
from .specification import (
    ExperimentSpec, SpecValidationError, validate_spec_bytes,
)

BUNDLE_API_VERSION = "slipcage.dev/evidence-bundle/v1alpha1"
PROVENANCE_API_VERSION = "slipcage.dev/fixture-provenance/v1alpha1"
CHECKSUMS_API_VERSION = "slipcage.dev/checksums/v1alpha1"
ARTIFACT_NAMES = ("experiment.json", "results.json", "provenance.json")
ALL_NAMES = frozenset((*ARTIFACT_NAMES, "checksums.json", "manifest.json"))
MAX_ARTIFACT_BYTES = 128 * 1024
MAX_BUNDLE_BYTES = 5 * MAX_ARTIFACT_BYTES
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


class BundleError(ValueError):
    """Missing, unsafe, incomplete, inconsistent or unauthenticated-local bundle."""


@dataclass(frozen=True, slots=True)
class BundleVerification:
    """Successful LOCAL integrity check, not an assertion of real security."""

    experiment_id: str
    spec_digest_sha256: str
    fixture_digest_sha256: str
    scenario: str
    assertion_ids: tuple[str, ...]
    outcomes: tuple[str, ...]
    manifest_digest_sha256: str

    def to_dict(self) -> dict:
        return {
            "status": "verified_synthetic_bundle",
            "bundle_api_version": BUNDLE_API_VERSION,
            "experiment_id": self.experiment_id,
            "spec_digest_sha256": self.spec_digest_sha256,
            "fixture_digest_sha256": self.fixture_digest_sha256,
            "scenario": self.scenario,
            "assertion_ids": list(self.assertion_ids),
            "outcomes": list(self.outcomes),
            "manifest_digest_sha256": self.manifest_digest_sha256,
            "integrity_check": "local_checksums_and_packaged_fixture_replay",
            "simulated": True,
            "security_test_executed": False,
            "real_security_evidence_verified": False,
        }


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _strict_pairs(pairs):
    found = {}
    for name, value in pairs:
        if name in found:
            raise BundleError("Duplicate JSON keys are not allowed in evidence")
        found[name] = value
    return found


def _reject_nonfinite(_):
    raise BundleError("Nonfinite JSON numbers are forbidden")


def _decode_json(raw: bytes, label: str) -> dict:
    try:
        result = json.loads(raw.decode("utf-8"),
                            object_pairs_hook=_strict_pairs,
                            parse_constant=_reject_nonfinite,
                            parse_float=_reject_nonfinite)
        if type(result) is not dict or _canonical(result) != raw:
            raise BundleError(f"Noncanonical or invalid JSON in {label}")
    except (ValueError, UnicodeError, TypeError, RecursionError, OverflowError) as exc:
        raise BundleError(f"Invalid JSON in {label}") from exc
    return result


def _checked_spec(spec: ExperimentSpec) -> ExperimentSpec:
    if type(spec) is not ExperimentSpec:
        raise BundleError("Expected a validated ExperimentSpec")
    try:
        validated = validate_spec_bytes(spec.canonical_json, extension=".json")
    except (SpecValidationError, ValueError, TypeError, AttributeError) as exc:
        raise BundleError("Invalid experiment specification") from exc
    if validated != spec:
        raise BundleError("Experiment definition or digest mismatch")
    return validated


def _provenance(spec: ExperimentSpec, run: FixtureRun) -> dict:
    return {
        "api_version": PROVENANCE_API_VERSION,
        "source": "packaged_offline_fixture",
        "engine_version": __version__,
        "experiment_id": spec.experiment_id,
        "spec_digest_sha256": spec.digest_sha256,
        "fixture_digest_sha256": run.fixture_digest_sha256,
        "scenario": run.scenario.value,
        "environment_kind": "none",
        "simulated": True,
        "security_test_executed": False,
        "real_security_evidence_collected": False,
    }


def _write_file(directory_fd: int, name: str, content: bytes) -> None:
    if name not in ALL_NAMES or not content or len(content) > MAX_ARTIFACT_BYTES:
        raise BundleError("Unsafe evidence artifact name, emptiness or size")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=directory_fd)
    with os.fdopen(fd, "wb") as writer:
        writer.write(content)
        writer.flush()
        os.fsync(writer.fileno())


def write_fixture_bundle(
    spec: ExperimentSpec,
    scenario: FixtureScenario,
    destination: str | Path,
) -> BundleVerification:
    """Create exactly one new private directory; never overwrite or delete.

    No partial work is called complete: manifest.json is written last. On an
    error the incomplete directory is preserved, not silently cleaned up.
    This entry point executes only the static in-process fixture interpreter.
    """
    spec = _checked_spec(spec)
    if type(scenario) is not FixtureScenario:
        raise BundleError("Scenario must be a typed, packaged fixture")
    run = run_fixture(spec, scenario)
    if run.status is not FixtureRunState.COMPLETED:
        raise BundleError("Incomplete fixture run is not publishable")
    target = Path(destination)
    if target.name in ("", ".", ".."):
        raise BundleError("Evidence directory must be a new child path")
    try:
        parent_fd = os.open(target.parent, _DIR_FLAGS)
    except OSError as exc:
        raise BundleError("Output parent must be an existing, non-symlink directory") from exc
    try:
        try:
            os.mkdir(target.name, 0o700, dir_fd=parent_fd)
        except OSError as exc:
            raise BundleError("Output evidence directory must not already exist") from exc
        directory_fd = os.open(target.name, _DIR_FLAGS, dir_fd=parent_fd)
        try:
            os.fchmod(directory_fd, 0o700)
            artifacts = {
                "experiment.json": spec.canonical_json,
                "results.json": run.canonical_json(),
                "provenance.json": _canonical(_provenance(spec, run)),
            }
            checksums = {
                "api_version": CHECKSUMS_API_VERSION,
                "files": {name: _digest(data) for name, data in artifacts.items()},
            }
            checksum_bytes = _canonical(checksums)
            for name in ARTIFACT_NAMES:
                _write_file(directory_fd, name, artifacts[name])
            _write_file(directory_fd, "checksums.json", checksum_bytes)
            # Last: an incomplete/crashed directory has no valid published manifest.
            manifest = {
                "api_version": BUNDLE_API_VERSION,
                "kind": "synthetic_fixture",
                "complete": True,
                "created_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "experiment_id": spec.experiment_id,
                "spec_digest_sha256": spec.digest_sha256,
                "fixture_digest_sha256": run.fixture_digest_sha256,
                "checksums_sha256": _digest(checksum_bytes),
                "simulated": True,
                "security_test_executed": False,
                "real_security_evidence_collected": False,
            }
            _write_file(directory_fd, "manifest.json", _canonical(manifest))
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        os.fsync(parent_fd)
    except (OSError, FixtureExecutionError) as exc:
        raise BundleError("Could not finish private fixture bundle; incomplete data preserved") from exc
    finally:
        os.close(parent_fd)
    return verify_bundle(target)


def _read_private_file(directory_fd: int, name: str) -> bytes:
    try:
        fd = os.open(name, _FILE_FLAGS, dir_fd=directory_fd)
    except OSError as exc:
        raise BundleError(f"Required evidence file {name} is unavailable or unsafe") from exc
    with os.fdopen(fd, "rb") as handle:
        identity = os.fstat(handle.fileno())
        if not stat.S_ISREG(identity.st_mode) or identity.st_nlink != 1:
            raise BundleError(f"Evidence file {name} must be a single-link regular file")
        if stat.S_IMODE(identity.st_mode) & 0o077:
            raise BundleError(f"Evidence file {name} is accessible to group/others")
        if identity.st_size < 1 or identity.st_size > MAX_ARTIFACT_BYTES:
            raise BundleError(f"Evidence file {name} has invalid size")
        data = handle.read(MAX_ARTIFACT_BYTES + 1)
        if len(data) != identity.st_size:
            raise BundleError(f"Evidence file {name} changed or exceeded size cap")
        return data


def verify_bundle(directory: str | Path) -> BundleVerification:
    """Check private files, exact layout, checksums, schema and synthetic replay.

    A malicious writer with access to bundle contents can rewrite both files
    and checksums. No secret key, signed attestation, or host API probe is used.
    """
    try:
        directory_fd = os.open(Path(directory), _DIR_FLAGS)
    except OSError as exc:
        raise BundleError("Evidence bundle must be a non-symlink directory") from exc
    try:
        identity = os.fstat(directory_fd)
        if not stat.S_ISDIR(identity.st_mode) or stat.S_IMODE(identity.st_mode) & 0o077:
            raise BundleError("Evidence directory must be private")
        names = set(os.listdir(directory_fd))
        if names != ALL_NAMES:
            raise BundleError("Evidence directory is incomplete or contains unexpected artifacts")
        data = {name: _read_private_file(directory_fd, name) for name in ALL_NAMES}
        if sum(map(len, data.values())) > MAX_BUNDLE_BYTES:
            raise BundleError("Evidence bundle exceeds size cap")
    finally:
        os.close(directory_fd)

    manifest = _decode_json(data["manifest.json"], "manifest.json")
    expected_manifest_keys = {
        "api_version", "kind", "complete", "created_at_utc", "experiment_id",
        "spec_digest_sha256", "fixture_digest_sha256", "checksums_sha256",
        "simulated", "security_test_executed", "real_security_evidence_collected",
    }
    if set(manifest) != expected_manifest_keys or any((
        manifest["api_version"] != BUNDLE_API_VERSION,
        manifest["kind"] != "synthetic_fixture",
        manifest["complete"] is not True,
        manifest["simulated"] is not True,
        manifest["security_test_executed"] is not False,
        manifest["real_security_evidence_collected"] is not False,
    )):
        raise BundleError("Unsupported or misleading evidence manifest")
    stamp = manifest["created_at_utc"]
    try:
        if type(stamp) is not str or datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%dT%H:%M:%SZ") != stamp:
            raise ValueError()
    except ValueError as exc:
        raise BundleError("Evidence manifest timestamp invalid") from exc
    for key in ("spec_digest_sha256", "fixture_digest_sha256", "checksums_sha256"):
        if type(manifest[key]) is not str or not _HEX.fullmatch(manifest[key]):
            raise BundleError(f"Invalid manifest digest for {key}")
    if type(manifest["experiment_id"]) is not str or not manifest["experiment_id"]:
        raise BundleError("Invalid experiment identity in manifest")

    checksums = _decode_json(data["checksums.json"], "checksums.json")
    if _digest(data["checksums.json"]) != manifest["checksums_sha256"]:
        raise BundleError("Checksum catalog digest mismatch")
    if set(checksums) != {"api_version", "files"} or checksums["api_version"] != CHECKSUMS_API_VERSION:
        raise BundleError("Unsupported checksum catalog")
    expected_hashes = checksums["files"]
    if type(expected_hashes) is not dict or set(expected_hashes) != set(ARTIFACT_NAMES):
        raise BundleError("Checksums do not cover exact required evidence files")
    for name in ARTIFACT_NAMES:
        claimed = expected_hashes[name]
        if type(claimed) is not str or not _HEX.fullmatch(claimed) or claimed != _digest(data[name]):
            raise BundleError(f"Checksum verification failed for {name}")

    try:
        spec = validate_spec_bytes(data["experiment.json"], extension=".json")
    except (SpecValidationError, ValueError, TypeError) as exc:
        raise BundleError("Evidence experiment definition is not valid") from exc
    if spec.canonical_json != data["experiment.json"] or spec.digest_sha256 != manifest["spec_digest_sha256"]:
        raise BundleError("Evidence definition differs from pinned identity")
    if spec.experiment_id != manifest["experiment_id"]:
        raise BundleError("Evidence experiment ID does not match manifest")
    results = _decode_json(data["results.json"], "results.json")
    scenario = results.get("scenario")
    try:
        if type(scenario) is not str:
            raise ValueError()
        replay = run_fixture(spec, FixtureScenario(scenario))
    except (ValueError, FixtureExecutionError) as exc:
        raise BundleError("Evidence references unsupported fixture scenario") from exc
    if replay.status is not FixtureRunState.COMPLETED or replay.canonical_json() != data["results.json"]:
        raise BundleError("Evidence results disagree with trusted packaged-fixture replay")
    if replay.fixture_digest_sha256 != manifest["fixture_digest_sha256"]:
        raise BundleError("Evidence fixture digest disagrees with manifest")
    provenance = _decode_json(data["provenance.json"], "provenance.json")
    if data["provenance.json"] != _canonical(_provenance(spec, replay)):
        raise BundleError("Fixture provenance is inconsistent with the installed runner")

    return BundleVerification(
        experiment_id=spec.experiment_id,
        spec_digest_sha256=spec.digest_sha256,
        fixture_digest_sha256=replay.fixture_digest_sha256,
        scenario=scenario,
        assertion_ids=tuple(result.assertion_id for result in replay.results),
        outcomes=tuple(result.outcome.value for result in replay.results),
        manifest_digest_sha256=_digest(data["manifest.json"]),
    )
