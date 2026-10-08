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
from .reports import ReportError, render_fixture_report
from .workflow import DemoError, create_fixture_demo, verify_fixture_demo
from .specification import SpecValidationError, load_spec
from .vm_plan import VMPlanError, assess_vm_plan, load_vm_plan, load_host_inventory
from .vm_lifecycle import (
    VMLifecycleError, VMSimulationScenario, VMFinalState, VMFailureReason,
    simulate_vm_lifecycle, simulate_sequential_pair,
)

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

    report = commands.add_parser("report-fixtures", help="Render synthetic JSON or Markdown from two verified bundles")
    report.add_argument("baseline", help="Private baseline bundle directory")
    report.add_argument("candidate", help="Private candidate bundle directory")
    report.add_argument("--format", choices=("json", "markdown"), default="markdown")

    demo = commands.add_parser("demo-fixtures", help="Generate a complete private OFFLINE synthetic baseline/candidate demo")
    demo.add_argument("file", help="Local validated experiment definition")
    demo.add_argument("--baseline-scenario", required=True, choices=[s.value for s in FixtureScenario])
    demo.add_argument("--candidate-scenario", required=True, choices=[s.value for s in FixtureScenario])
    demo.add_argument("--output", required=True, help="New directory under an existing PRIVATE local parent")
    demo.add_argument("--json", action="store_true", help="Machine-readable verification summary")

    verify_demo = commands.add_parser("verify-demo", help="Read-only verification of an existing synthetic demo")
    verify_demo.add_argument("directory", help="Private synthetic demo root")
    verify_demo.add_argument("--json", action="store_true", help="Machine-readable verification summary")

    vm_plan = commands.add_parser("plan-vm", help="Validate non-executable pinned K3s VM intent and declared capacity (SC-12)")
    vm_plan.add_argument("file", help="Local strict JSON VM design, NOT a QEMU config or executable")
    vm_plan.add_argument("--inventory", help="Optional strictly validated operator-reported host inventory JSON")
    vm_plan.add_argument("--json", action="store_true", help="Machine-readable offline feasibility assessment")

    lifecycle = commands.add_parser(
        "simulate-vm-lifecycle",
        help="Pure in-memory VM lifecycle state machine; NEVER starts QEMU",
    )
    lifecycle.add_argument("file", help="Local SC-12 non-executable VM plan")
    lifecycle.add_argument("--scenario", required=True, choices=[s.value for s in VMSimulationScenario])
    lifecycle.add_argument("--json", action="store_true", help="Machine-readable synthetic state log")

    pair = commands.add_parser(
        "simulate-vm-pair", help="Sequential baseline/candidate VM lifecycle simulation ONLY"
    )
    pair.add_argument("file", help="Local SC-12 non-executable VM plan")
    pair.add_argument("--baseline-scenario", required=True, choices=[s.value for s in VMSimulationScenario])
    pair.add_argument("--candidate-scenario", required=True, choices=[s.value for s in VMSimulationScenario])
    pair.add_argument("--json", action="store_true", help="Machine-readable synthetic pair state")

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
        if args.command in ("simulate-vm-lifecycle", "simulate-vm-pair"):
            vm_definition = load_vm_plan(args.file)
            if args.command == "simulate-vm-lifecycle":
                vm_simulation = simulate_vm_lifecycle(
                    vm_definition, VMSimulationScenario(args.scenario)
                )
            else:
                vm_pair = simulate_sequential_pair(
                    vm_definition,
                    VMSimulationScenario(args.baseline_scenario),
                    VMSimulationScenario(args.candidate_scenario),
                )
        elif args.command == "plan-vm":
            definition = load_vm_plan(args.file)
            inventory = load_host_inventory(args.inventory) if args.inventory is not None else None
            vm_assessment = assess_vm_plan(definition, inventory)
        elif args.command in ("compare-fixtures", "report-fixtures"):
            comparison = compare_fixture_bundles(args.baseline, args.candidate)
            if args.command == "report-fixtures":
                fixture_report = render_fixture_report(comparison)
        elif args.command == "verify-demo":
            demo_verification = verify_fixture_demo(args.directory)
        elif args.command == "verify-bundle":
            verified = verify_bundle(args.directory)
        else:
            definition = load_spec(args.file)
            if args.command == "run-fixture":
                run = run_fixture(definition, FixtureScenario(args.scenario))
            elif args.command == "bundle-fixture":
                verified = write_fixture_bundle(definition, FixtureScenario(args.scenario), args.output)
            elif args.command == "demo-fixtures":
                demo_verification = create_fixture_demo(
                    definition, FixtureScenario(args.baseline_scenario),
                    FixtureScenario(args.candidate_scenario), args.output,
                )
    except (SpecValidationError, FixtureExecutionError, BundleError, DemoError, ReportError, VMPlanError, VMLifecycleError) as exc:
        print(f"slipcage {args.command}: {exc}", file=sys.stderr)
        return EXIT_INVALID

    if args.command == "simulate-vm-lifecycle":
        if args.json:
            print(vm_simulation.canonical_json().decode("ascii"))
        else:
            print("SYNTHETIC VM LIFECYCLE ONLY; "
                  f"state={vm_simulation.final_state.value}; "
                  f"reason={vm_simulation.failure_reason.value}; "
                  "real VM launches=0")
        if vm_simulation.final_state is VMFinalState.SIMULATED_CLEANUP_UNRESOLVED:
            return 5  # synthetic cleanup unresolved: explicit operator attention
        return 0 if vm_simulation.failure_reason is VMFailureReason.NONE else EXIT_INTERRUPTED

    if args.command == "simulate-vm-pair":
        if args.json:
            print(json.dumps(vm_pair, sort_keys=True, separators=(",", ":")))
        else:
            state = (vm_pair["candidate"]["final_state"]
                     if vm_pair["candidate"] is not None else "not_attempted")
            print("SYNTHETIC SEQUENTIAL VMs ONLY; "
                  f"candidate={state}; real VM launches=0")
        if (vm_pair["baseline"]["final_state"] == VMFinalState.SIMULATED_CLEANUP_UNRESOLVED.value
                or (vm_pair["candidate"] is not None
                    and vm_pair["candidate"]["final_state"] == VMFinalState.SIMULATED_CLEANUP_UNRESOLVED.value)):
            return 5
        if vm_pair["candidate"] is None:
            return EXIT_INTERRUPTED
        return (0 if vm_pair["candidate"]["failure_reason"] == VMFailureReason.NONE.value
                else EXIT_INTERRUPTED)

    if args.command == "plan-vm":
        if args.json:
            print(vm_assessment.canonical_json().decode("ascii"))
        else:
            print("NON-EXECUTABLE VM DESIGN ONLY; "
                  f"plan={vm_assessment.plan_id}; capacity={vm_assessment.capacity_result}; "
                  "artifacts_verified=false; execution_authorized=false; vm_launched=false")
        return 0  # Schema validation success ONLY, never boot readiness.

    if args.command in ("demo-fixtures", "verify-demo"):
        if args.json:
            print(json.dumps(demo_verification.to_dict(), sort_keys=True, separators=(",", ":")))
        else:
            print("SYNTHETIC OFFLINE DEMO ONLY; "
                  f"classification={demo_verification.comparison.classification.value}; "
                  "no real security evidence")
        if demo_verification.comparison.classification in (ChangeKind.REGRESSION, ChangeKind.MIXED_CHANGE):
            return EXIT_ASSERTION_NOT_PASS
        return 0

    if args.command == "report-fixtures":
        if args.format == "json":
            print(fixture_report.json_bytes.decode("ascii"))
        else:
            print(fixture_report.markdown_bytes.decode("utf-8"), end="")
        if not comparison.comparable:
            return EXIT_INTERRUPTED
        if comparison.classification in (ChangeKind.REGRESSION, ChangeKind.MIXED_CHANGE):
            return EXIT_ASSERTION_NOT_PASS
        return 0

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
