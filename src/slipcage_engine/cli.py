"""Read-only Slipcage CLI.

The future execution, comparison and report commands are advertised as
unavailable and exit nonzero. They must not silently claim success.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import __version__
from .specification import SpecValidationError, load_spec

EXIT_INVALID = 2
EXIT_NOT_IMPLEMENTED = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="slipcage",
        description="Offline experiment contract tools (execution not enabled).",
    )
    parser.add_argument("--version", action="version", version=f"slipcage-engine {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate", help="Validate a reviewed-profile definition (offline only)")
    validate.add_argument("file", help="Local .yaml, .yml or .json experiment definition")
    validate.add_argument("--json", action="store_true", help="Emit machine-readable validation output")

    for command in ("run", "compare", "report"):
        commands.add_parser(
            command,
            help="Unavailable in this release; always refuses execution",
            description=f"{command} is not implemented in the contract-only engine",
        )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "validate":
        print(
            f"slipcage {args.command}: unavailable in this release; "
            "no execution, comparison or report has been performed",
            file=sys.stderr,
        )
        return EXIT_NOT_IMPLEMENTED

    try:
        definition = load_spec(args.file)
    except SpecValidationError as exc:
        print(f"slipcage validate: {exc}", file=sys.stderr)
        return EXIT_INVALID

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
