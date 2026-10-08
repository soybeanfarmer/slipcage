"""SC-11 integrated OFFLINE synthetic demo and strict read-only verification.

Creates two private SC-09 fixture bundles and SC-11 reports in a NEW private
root. Publishes manifest.json LAST, preserves interrupted directories, never
overwrites existing data, and never invokes Kubernetes, QEMU or shell code.

The parent/ancestors must be local operator-controlled directories. This is
not a malicious-same-UID or multi-tenant filesystem security boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat

from .comparison import FixtureComparison, compare_fixture_bundles
from .evidence import BundleError, _checked_spec, _read_private_file, write_fixture_bundle
from .fixture_executor import FixtureScenario
from .reports import render_fixture_report
from .specification import ExperimentSpec

DEMO_API_VERSION = "slipcage.dev/fixture-demo/v1alpha1"
ROOT_ENTRIES = frozenset(("baseline", "candidate", "report.json", "report.md", "manifest.json"))
MAX_REPORT_BYTES = 64 * 1024
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


class DemoError(ValueError):
    """A synthetic demo is invalid, incomplete, unsafe or inconsistent."""


@dataclass(frozen=True, slots=True)
class DemoVerification:
    comparison: FixtureComparison
    manifest_digest_sha256: str

    def to_dict(self) -> dict:
        return {
            "api_version": DEMO_API_VERSION,
            "status": "verified_synthetic_demo",
            "simulated": True,
            "security_test_executed": False,
            "real_security_evidence_verified": False,
            "manifest_digest_sha256": self.manifest_digest_sha256,
            "classification": self.comparison.classification.value,
            "comparison_status": "comparable" if self.comparison.comparable else "incomparable",
            "reason_code": self.comparison.reason_code.value,
            "report_files": ["report.json", "report.md"],
        }


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _root_fd(directory: str | Path) -> int:
    try:
        fd = os.open(Path(directory), _DIR_FLAGS)
    except OSError as exc:
        raise DemoError("Directory missing, inaccessible, or a symlink") from exc
    identity = os.fstat(fd)
    if not stat.S_ISDIR(identity.st_mode) or stat.S_IMODE(identity.st_mode) & 0o077:
        os.close(fd)
        raise DemoError("Demo directory/parent must be private")
    return fd


def _write_private(fd: int, name: str, data: bytes) -> None:
    if name not in ("report.json", "report.md", "manifest.json"):
        raise DemoError("Unexpected report artifact name")
    if not data or len(data) > MAX_REPORT_BYTES:
        raise DemoError("Report artifact outside size bounds")
    handle = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=fd)
    with os.fdopen(handle, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def create_fixture_demo(
    spec: ExperimentSpec, baseline: FixtureScenario,
    candidate: FixtureScenario, output: str | Path,
) -> DemoVerification:
    """Write a complete synthetic baseline/candidate proof in a NEW directory."""
    try:
        _checked_spec(spec)
    except BundleError as exc:
        raise DemoError("Invalid experiment definition") from exc
    if type(baseline) is not FixtureScenario or type(candidate) is not FixtureScenario:
        raise DemoError("Both sides require named packaged fixture scenarios")
    target = Path(output)
    if target.name in ("", ".", ".."):
        raise DemoError("Output must be a new child directory")
    try:
        parent_fd = _root_fd(target.parent)
    except DemoError as exc:
        raise DemoError("Output parent must be private, existing and non-symlink") from exc
    try:
        try:
            os.mkdir(target.name, 0o700, dir_fd=parent_fd)
        except OSError as exc:
            raise DemoError("Output directory exists or cannot be created; nothing overwritten") from exc
        root_fd = os.open(target.name, _DIR_FLAGS, dir_fd=parent_fd)
        try:
            os.fchmod(root_fd, 0o700)
            write_fixture_bundle(spec, baseline, target / "baseline")
            write_fixture_bundle(spec, candidate, target / "candidate")
            comparison = compare_fixture_bundles(target / "baseline", target / "candidate")
            if not comparison.comparable:
                raise DemoError("Synthetic comparison incomparable; incomplete files preserved")
            report = render_fixture_report(comparison)
            _write_private(root_fd, "report.json", report.json_bytes)
            _write_private(root_fd, "report.md", report.markdown_bytes)
            manifest = _canonical({
                "api_version": DEMO_API_VERSION,
                "kind": "synthetic_demo",
                "complete": True,
                "simulated": True,
                "security_test_executed": False,
                "real_security_evidence_verified": False,
                "baseline_manifest_sha256": comparison.baseline.manifest_digest_sha256,
                "candidate_manifest_sha256": comparison.candidate.manifest_digest_sha256,
                "report_json_sha256": _digest(report.json_bytes),
                "report_md_sha256": _digest(report.markdown_bytes),
            })
            # Completion marker MUST be written after both independently checkable reports.
            _write_private(root_fd, "manifest.json", manifest)
            os.fsync(root_fd)
        finally:
            os.close(root_fd)
        os.fsync(parent_fd)
    except (OSError, BundleError) as exc:
        raise DemoError("Synthetic demo incomplete; partial data retained") from exc
    finally:
        os.close(parent_fd)
    return verify_fixture_demo(target)


def _duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DemoError("Duplicate keys in demo manifest")
        result[key] = value
    return result


def _reject_nonfinite(_):
    raise DemoError("Nonfinite numeric data in demo manifest")


def verify_fixture_demo(directory: str | Path) -> DemoVerification:
    """Read-only recheck of exact private layout, artifacts and output bytes."""
    root_fd = _root_fd(directory)
    try:
        if set(os.listdir(root_fd)) != ROOT_ENTRIES:
            raise DemoError("Demo has missing or unexpected artifacts")
        raw_json = _read_private_file(root_fd, "report.json")
        raw_markdown = _read_private_file(root_fd, "report.md")
        raw_manifest = _read_private_file(root_fd, "manifest.json")
    except BundleError as exc:
        raise DemoError("Unsafe or missing report artifact") from exc
    finally:
        os.close(root_fd)

    try:
        manifest = json.loads(
            raw_manifest.decode("ascii"), object_pairs_hook=_duplicate_keys,
            parse_constant=_reject_nonfinite, parse_float=_reject_nonfinite,
        )
        if type(manifest) is not dict or raw_manifest != _canonical(manifest):
            raise DemoError("Demo manifest is noncanonical")
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError) as exc:
        raise DemoError("Invalid demo manifest") from exc
    keys = {
        "api_version", "kind", "complete", "simulated",
        "security_test_executed", "real_security_evidence_verified",
        "baseline_manifest_sha256", "candidate_manifest_sha256",
        "report_json_sha256", "report_md_sha256",
    }
    if set(manifest) != keys or any((
        manifest["api_version"] != DEMO_API_VERSION,
        manifest["kind"] != "synthetic_demo",
        manifest["complete"] is not True,
        manifest["simulated"] is not True,
        manifest["security_test_executed"] is not False,
        manifest["real_security_evidence_verified"] is not False,
    )):
        raise DemoError("Unsupported or misleading demo manifest")

    comparison = compare_fixture_bundles(
        Path(directory) / "baseline", Path(directory) / "candidate"
    )
    if not comparison.comparable:
        raise DemoError("Source bundles fail conservative differential comparison")
    report = render_fixture_report(comparison)
    expected = {
        "baseline_manifest_sha256": comparison.baseline.manifest_digest_sha256,
        "candidate_manifest_sha256": comparison.candidate.manifest_digest_sha256,
        "report_json_sha256": _digest(report.json_bytes),
        "report_md_sha256": _digest(report.markdown_bytes),
    }
    if any(type(manifest[key]) is not str or manifest[key] != value
           for key, value in expected.items()):
        raise DemoError("Demo manifest hashes disagree with verified evidence")
    if raw_json != report.json_bytes or raw_markdown != report.markdown_bytes:
        raise DemoError("Stored report does not match deterministic re-render")

    return DemoVerification(comparison=comparison,
                            manifest_digest_sha256=_digest(raw_manifest))
