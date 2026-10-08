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
        definition = load_spec(args.file)
        if args.command == "run-fixture":
            run = run_fixture(definition, FixtureScenario(args.scenario))
    except (SpecValidationError, FixtureExecutionError) as exc:
        print(f"slipcage {args.command}: {exc}", file=sys.stderr)
        return EXIT_INVALID

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
