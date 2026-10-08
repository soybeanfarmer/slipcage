"""SC-11 deterministic reports of local SYNTHETIC fixture comparisons only.

Reports render typed local comparison data. They do not execute experiments,
verify Kubernetes, or attest cryptographic authorship of fixture evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
import json

from .comparison import ChangeKind, FixtureComparison

REPORT_API_VERSION = "slipcage.dev/fixture-report/v1alpha1"


class ReportError(ValueError):
    """Unsupported or inconsistent synthetic comparison."""


def _canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _cell(value: object) -> str:
    """Do not allow caller-controlled Markdown table or HTML injection."""
    if value is None:
        return "unavailable"
    value = str(value)[:256]
    return (value.replace("\\", "\\\\").replace("|", "\\|")
            .replace("<", "&lt;").replace(">", "&gt;")
            .replace("\u0060", "&#96;").replace("\r", " ").replace("\n", " "))


@dataclass(frozen=True, slots=True)
class FixtureReport:
    json_bytes: bytes
    markdown_bytes: bytes

    def to_dict(self) -> dict:
        return json.loads(self.json_bytes)


def render_fixture_report(comparison: FixtureComparison) -> FixtureReport:
    """Render a deterministic report for an already checked synthetic pair."""
    if type(comparison) is not FixtureComparison:
        raise ReportError("Expected a typed fixture comparison")
    if type(comparison.classification) is not ChangeKind:
        raise ReportError("Unknown comparison classification")
    payload = comparison.to_dict()
    if (payload.get("simulated") is not True
            or payload.get("security_test_executed") is not False
            or payload.get("real_security_evidence_verified") is not False):
        raise ReportError("Only explicitly synthetic comparisons can be reported")

    record = {
        "api_version": REPORT_API_VERSION,
        "kind": "synthetic_fixture_comparison",
        "simulated": True,
        "security_test_executed": False,
        "real_security_evidence_verified": False,
        "report_status": "complete" if comparison.comparable else "incomparable",
        "comparison": payload,
    }
    lines = [
        "# Slipcage — SYNTHETIC fixture comparison",
        "",
        "**OFFLINE SIMULATION ONLY. No Kubernetes or VM security experiment was executed.**",
        "Local hashes and packaged-fixture replay are not authentication or real security evidence.",
        "",
        "## Classification",
        "",
        f"- Result: {_cell(payload['classification'])}",
        f"- Comparison status: {_cell(payload['comparison_status'])}",
        f"- Reason: {_cell(payload['reason_code'])}",
        f"- Experiment: {_cell(payload['experiment_id'])}",
        f"- Spec SHA-256: {_cell(payload['spec_digest_sha256'])}",
        f"- Fixture SHA-256: {_cell(payload['fixture_digest_sha256'])}",
        "",
        "## Source bundle manifests",
        "",
        "| Side | Local integrity | Scenario | Manifest SHA-256 |",
        "| --- | --- | --- | --- |",
    ]
    for side in ("baseline", "candidate"):
        entry = payload[side]
        lines.append(
            f"| {side} | {'yes' if entry['local_bundle_verified'] else 'no'} | "
            f"{_cell(entry.get('scenario'))} | "
            f"{_cell(entry.get('manifest_digest_sha256'))} |"
        )
    lines.extend([
        "",
        "## Per-assertion outcomes",
        "",
        "| Assertion | Baseline | Candidate | Classification |",
        "| --- | --- | --- | --- |",
    ])
    for entry in payload["assertions"]:
        lines.append(
            f"| {_cell(entry['assertion_id'])} | {_cell(entry['baseline_outcome'])} | "
            f"{_cell(entry['candidate_outcome'])} | {_cell(entry['classification'])} |"
        )
    if not payload["assertions"]:
        lines.append("| unavailable | unavailable | unavailable | incomparable |")
    lines.extend([
        "",
        "## Evidence limitations",
        "",
        "- Input bundles undergo local checksum validation and packaged-fixture replay.",
        "- Missing, incompatible or inconclusive evidence is reported as incomparable.",
        "- A synthetic regression is NOT a verified Kubernetes security regression.",
        "- SHA-256 is not an authenticated signature, trusted timestamp or remote attestation.",
        "- No real security assertions were executed or independently verified.",
        "",
    ])
    return FixtureReport(
        json_bytes=_canonical(record),
        markdown_bytes="\n".join(lines).encode("utf-8"),
    )
