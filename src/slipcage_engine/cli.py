"""Read-only Slipcage CLI; only synthetic fixture simulation is available."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import __version__
from .fixture_executor import (
    FixtureExecutionError, FixtureRunState, FixtureScenario, run_fixture,
)
from .results import AssertionOutcome
from .evidence import BundleError, write_fixture_bundle, verify_bundle
from .comparison import ChangeKind, compare_fixture_bundles
from .specification import SpecValidationError, load_spec

EXIT_ASSERTION_NOT_PASS = 1
EXIT_INVALID = 2
EXIT_NOT_IMPLEMENTED = 3
EXIT_INTERRUPTED = 4


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="slipcage",
        description="Offline contract and synthetic fixture tools (real execution disabled).",
    )
    parser.add_argument("--version", action="version", version=f"slipcage-engine {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate", help="Validate experiment definition, offline")
    validate.add_argument("file", help="Local .yaml, .yml or .json definition")
    validate.add_argument("--json", action="store_true", help="Machine-readable validation output")

    fixture = commands.add_parser("run-fixture", help="Simulate a packaged offline fixture ONLY")
    fixture.add_argument("file", help="Validated local experiment definition")
    fixture.add_argument("--scenario", required=True, choices=[s.value for s in FixtureScenario])
    fixture.add_argument("--json", action="store_true", help="Machine-readable simulation output")

    bundle = commands.add_parser("bundle-fixture", help="Write a NEW private synthetic fixture evidence bundle")
    bundle.add_argument("file", help="Local validated experiment definition")
    bundle.add_argument("--scenario", required=True, choices=[s.value for s in FixtureScenario])
    bundle.add_argument("--output", required=True, help="New directory under a trusted local parent")
    bundle.add_argument("--json", action="store_true", help="Machine-readable verification summary")

    verify = commands.add_parser("verify-bundle", help="Check existing local synthetic bundle (read-only)")
    verify.add_argument("directory", help="Existing private evidence directory")
    verify.add_argument("--json", action="store_true", help="Machine-readable verification summary")

    compare = commands.add_parser("compare-fixtures", help="Compare two PRIVATE verified synthetic bundles only")
    compare.add_argument("baseline", help="Private baseline bundle directory")
    compare.add_argument("candidate", help="Private candidate bundle directory")
    compare.add_argument("--json", action="store_true", help="Machine-readable synthetic comparison")

    for command in ("run", "compare", "report"):
        commands.add_parser(command, help="Unavailable: always refuses real execution")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command in ("run", "compare", "report"):
        print(
            f"slipcage {args.command}: unavailable in this release; "
            "no execution, comparison or report has been performed",
            file=sys.stderr,
        )
        return EXIT_NOT_IMPLEMENTED
    try:
        if args.command == "compare-fixtures":
            comparison = compare_fixture_bundles(args.baseline, args.candidate)
        elif args.command == "verify-bundle":
            verified = verify_bundle(args.directory)
        else:
            definition = load_spec(args.file)
            if args.command == "run-fixture":
                run = run_fixture(definition, FixtureScenario(args.scenario))
            elif args.command == "bundle-fixture":
                verified = write_fixture_bundle(definition, FixtureScenario(args.scenario), args.output)
    except (SpecValidationError, FixtureExecutionError, BundleError) as exc:
        print(f"slipcage {args.command}: {exc}", file=sys.stderr)
        return EXIT_INVALID

    if args.command == "compare-fixtures":
        if args.json:
            print(comparison.canonical_json().decode("ascii"))
        else:
            print(
                "SYNTHETIC FIXTURE COMPARISON ONLY; "
                f"classification={comparison.classification.value}; "
                f"reason={comparison.reason_code.value}; real security tests=0"
            )
        if not comparison.comparable:
            return EXIT_INTERRUPTED  # 4: incomparable, never a verified regression
        if comparison.classification in (ChangeKind.REGRESSION, ChangeKind.MIXED_CHANGE):
            return EXIT_ASSERTION_NOT_PASS  # 1: synthetic regression present
        return 0

    if args.command in ("bundle-fixture", "verify-bundle"):
        if args.json:
            print(json.dumps(verified.to_dict(), sort_keys=True, separators=(",", ":")))
        else:
            print(
                "SYNTHETIC BUNDLE VERIFIED LOCALLY; real security evidence=none; "
                f"experiment={verified.experiment_id}; scenario={verified.scenario}; "
                f"outcomes={','.join(verified.outcomes)}"
            )
        return 0

    if args.command == "run-fixture":
        if args.json:
            print(run.canonical_json().decode("ascii"))
        else:
            print(
                f"SYNTHETIC FIXTURE ONLY: {run.scenario.value}; "
                f"state={run.status.value}; completed={len(run.results)}/"
                f"{run.requested_assertions}; real security tests=0; evidence=none"
            )
        if run.status is not FixtureRunState.COMPLETED:
            return EXIT_INTERRUPTED
        if any(item.outcome is not AssertionOutcome.PASS for item in run.results):
            return EXIT_ASSERTION_NOT_PASS
        return 0

    result = {
        "status": "valid",
        "api_version": "slipcage.dev/v1alpha1",
        "experiment_id": definition.experiment_id,
        "experiment_version": definition.version,
        "profile_id": definition.profile_id,
        "digest_sha256": definition.digest_sha256,
        "executable": False,
    }
    if args.json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        print(
            f"VALID {definition.experiment_id}@{definition.version} "
            f"sha256:{definition.digest_sha256} (validation only; execution disabled)"
        )
    return 0
