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
from .vm_assets import VMAssetError, verify_local_vm_assets
from .vm_provenance import VMProvenanceError, verify_provenance
from .vm_host_readiness import VMHostReadinessError, load_host_snapshot, assess_host_snapshot
from .vm_host_observe import HostObservationError, inspect_local_host
from .vm_qemu_blueprint import QemuBlueprintError, build_qemu_blueprint
from .vm_supervision import (
    SupervisionError, SupervisionScenario, SupervisionPhase, SupervisionOutcome,
    simulate_supervision, simulate_supervision_pair,
)
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

    asset_check = commands.add_parser(
        "verify-vm-artifacts",
        help="Read-only local SHA-256 checks; NEVER authorizes or boots a VM",
    )
    asset_check.add_argument("file", help="Local operator-supplied SC-12 VM plan, not a synthetic sample")
    asset_check.add_argument("--directory", required=True, help="Trusted private directory with five fixed files")
    asset_check.add_argument("--json", action="store_true", help="Machine-readable local byte-integrity result")

    provenance = commands.add_parser(
        "verify-vm-provenance", help="Verify offline detached Ed25519 statement with an OUT-OF-BAND trusted key"
    )
    provenance.add_argument("file", help="Local nonsynthetic SC-12 VM plan")
    provenance.add_argument("--statement", required=True, help="Canonical JSON plan-bound provenance statement")
    provenance.add_argument("--signature", required=True, help="Raw detached Ed25519 signature (64 bytes)")
    provenance.add_argument("--public-key", required=True, help="Independently authenticated raw Ed25519 public key (32 bytes)")
    provenance.add_argument("--json", action="store_true")

    readiness = commands.add_parser("assess-vm-host", help="Evaluate UNVERIFIED operator-reported host numbers, no probing")
    readiness.add_argument("file", help="Local SC-12 VM plan")
    readiness.add_argument("--snapshot", required=True, help="Operator-supplied host snapshot JSON")
    readiness.add_argument("--json", action="store_true")

    observe = commands.add_parser(
        "inspect-vm-host",
        help="EXPLICIT manual read-only Linux host observation; no guest launch or approval"
    )
    observe.add_argument("file", help="Strict SC-12 VM plan")
    observe.add_argument("--scratch-root", required=True, help="Existing selected local filesystem root; never created")
    observe.add_argument("--json", action="store_true")

    qemu = commands.add_parser(
        "plan-qemu",
        help="Build an INCOMPLETE paused, diskless QEMU argv prefix; NEVER launch a guest",
    )
    qemu.add_argument("file", help="Strict non-synthetic SC-12 plan")
    qemu.add_argument("--assets-dir", required=True, help="Private SC-13b1 local asset directory")
    qemu.add_argument("--json", action="store_true")

    supervisor = commands.add_parser(
        "simulate-vm-supervision",
        help="IN-MEMORY single-lease, cgroup-budget, deadline and cleanup fault model; no QEMU",
    )
    supervisor.add_argument("file", help="Validated nonsynthetic SC-12 VM plan")
    supervisor.add_argument("--assets-dir", required=True, help="Private SC-13b1 asset directory")
    supervisor.add_argument("--scenario", required=True, choices=[s.value for s in SupervisionScenario])
    supervisor.add_argument("--json", action="store_true")

    supervisor_pair = commands.add_parser(
        "simulate-vm-supervision-pair",
        help="IN-MEMORY sequential baseline/candidate fencing; no host changes",
    )
    supervisor_pair.add_argument("file", help="Validated nonsynthetic SC-12 VM plan")
    supervisor_pair.add_argument("--assets-dir", required=True, help="Private SC-13b1 asset directory")
    supervisor_pair.add_argument("--baseline-scenario", required=True, choices=[s.value for s in SupervisionScenario])
    supervisor_pair.add_argument("--candidate-scenario", required=True, choices=[s.value for s in SupervisionScenario])
    supervisor_pair.add_argument("--json", action="store_true")

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
        if args.command in ("simulate-vm-supervision", "simulate-vm-supervision-pair"):
            vm_definition = load_vm_plan(args.file)
            asset_preflight = verify_local_vm_assets(vm_definition, args.assets_dir)
            if args.command == "simulate-vm-supervision":
                supervision = simulate_supervision(
                    vm_definition, asset_preflight, SupervisionScenario(args.scenario),
                )
            else:
                supervision_pair = simulate_supervision_pair(
                    vm_definition, asset_preflight,
                    SupervisionScenario(args.baseline_scenario),
                    SupervisionScenario(args.candidate_scenario),
                )
        elif args.command == "plan-qemu":
            vm_definition = load_vm_plan(args.file)
            asset_preflight = verify_local_vm_assets(vm_definition, args.assets_dir)
            blueprint = build_qemu_blueprint(vm_definition, asset_preflight)
        elif args.command == "inspect-vm-host":
            vm_definition = load_vm_plan(args.file)
            host_observation = inspect_local_host(vm_definition, args.scratch_root)
        elif args.command == "verify-vm-provenance":
            vm_definition = load_vm_plan(args.file)
            provenance_result = verify_provenance(
                vm_definition, args.statement, args.signature, args.public_key,
            )
        elif args.command == "assess-vm-host":
            vm_definition = load_vm_plan(args.file)
            host_result = assess_host_snapshot(vm_definition, load_host_snapshot(args.snapshot))
        elif args.command == "verify-vm-artifacts":
            vm_definition = load_vm_plan(args.file)
            asset_report = verify_local_vm_assets(vm_definition, args.directory)
        elif args.command in ("simulate-vm-lifecycle", "simulate-vm-pair"):
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
    except (SpecValidationError, FixtureExecutionError, BundleError, DemoError, ReportError, VMPlanError, VMLifecycleError, VMAssetError, VMProvenanceError, VMHostReadinessError, HostObservationError, QemuBlueprintError, SupervisionError) as exc:
        print(f"slipcage {args.command}: {exc}", file=sys.stderr)
        return EXIT_INVALID

    if args.command == "simulate-vm-supervision":
        if args.json:
            print(supervision.canonical_json().decode("ascii"))
        else:
            print("IN-MEMORY VM SUPERVISION MODEL ONLY; "
                  f"phase={supervision.phase.value}; outcome={supervision.outcome.value}; "
                  "real_guest_started=false; execution_authorized=false")
        if supervision.phase is SupervisionPhase.QUARANTINED:
            return 5
        return (0 if supervision.outcome is SupervisionOutcome.COMPLETED
                else EXIT_INTERRUPTED)

    if args.command == "simulate-vm-supervision-pair":
        if args.json:
            print(json.dumps(supervision_pair, sort_keys=True, separators=(",", ":")))
        else:
            print("IN-MEMORY SEQUENTIAL SUPERVISION MODEL ONLY; "
                  f"candidate_attempted={str(supervision_pair['candidate_attempted']).lower()}; "
                  "real_guest_started=false")
        last = supervision_pair["candidate"] or supervision_pair["baseline"]
        if last["phase"] == SupervisionPhase.QUARANTINED.value:
            return 5
        if (supervision_pair["candidate"] is None
                or last["outcome"] != SupervisionOutcome.COMPLETED.value):
            return EXIT_INTERRUPTED
        return 0

    if args.command == "plan-qemu":
        if args.json:
            print(blueprint.canonical_json().decode("ascii"))
        else:
            print("INCOMPLETE QEMU ARGV PREFIX ONLY; no disk, guest kernel, or NIC; "
                  "execution_authorized=false; real_vm_launched=false")
        return 0  # Planning only; NEVER host/guest readiness.

    if args.command == "inspect-vm-host":
        if args.json:
            print(host_observation.canonical_json().decode("ascii"))
        else:
            print("LOCAL HOST OBSERVATION ONLY; "
                  f"observed_thresholds={host_observation.observed_thresholds}; "
                  "kvm_usable_verified=false; execution_authorized=false")
        return 0  # A read-only collection result; not readiness.

    if args.command == "verify-vm-provenance":
        if args.json:
            print(provenance_result.canonical_json().decode("ascii"))
        else:
            print("DETACHED SIGNATURE VERIFIED AGAINST SUPPLIED KEY ONLY; "
                  "origin_verified=false; execution_authorized=false")
        return 0

    if args.command == "assess-vm-host":
        if args.json:
            print(host_result.canonical_json().decode("ascii"))
        else:
            print("OPERATOR-REPORTED HOST SNAPSHOT ONLY; "
                  f"capacity={host_result.capacity_assessment}; "
                  "independent_host_verification=false; execution_authorized=false")
        return 0

    if args.command == "verify-vm-artifacts":
        if args.json:
            print(asset_report.canonical_json().decode("ascii"))
        else:
            print("LOCAL SHA-256 BYTES MATCH UNTRUSTED VM PINS ONLY; "
                  f"plan={asset_report.plan_id}; "
                  "software_origin_authenticated=false; "
                  "execution_authorized=false; vm_launched=false")
        return 0  # Local byte equality ONLY, not trusted runtime readiness.

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
