"""Portable Slipcage experiment contracts and offline fixture simulation."""

__version__ = "0.1.0a1"

from .specification import (
    ExperimentSpec, SpecValidationError, load_spec, validate_spec_bytes,
)
from .results import (
    AssertionOutcome, AssertionResult, ExpectedDecision, Observation,
    ObservedDecision, ObservationStatus, ReasonCode, ResultValidationError,
    result_for_observation,
)
from .fixture_executor import (
    FixtureExecutionError, FixtureRun, FixtureRunState, FixtureScenario,
    run_fixture,
)

from .evidence import BundleError, BundleVerification, write_fixture_bundle, verify_bundle
from .comparison import (
    AssertionDifference, ChangeKind, ComparisonReason, FixtureComparison,
    compare_fixture_bundles,
)

from .reports import FixtureReport, ReportError, render_fixture_report
from .workflow import DemoError, DemoVerification, create_fixture_demo, verify_fixture_demo

from .vm_plan import (
    VMPlanError, K3sVMPlan, ReportedHostInventory, VMFeasibility,
    validate_vm_plan_bytes, load_vm_plan, validate_host_inventory_bytes,
    load_host_inventory, assess_vm_plan,
)

from .vm_lifecycle import (
    VMLifecycleError, VMSimulationScenario, VMFinalState, VMFailureReason,
    VMEvent, VMLifecycleSimulation, simulate_vm_lifecycle,
    simulate_sequential_pair,
)

__all__ = [
    "ExperimentSpec", "SpecValidationError", "load_spec", "validate_spec_bytes",
    "AssertionOutcome", "AssertionResult", "ExpectedDecision", "Observation",
    "ObservedDecision", "ObservationStatus", "ReasonCode", "ResultValidationError",
    "result_for_observation", "FixtureExecutionError", "FixtureRun",
    "FixtureRunState", "FixtureScenario", "run_fixture",
    "BundleError", "BundleVerification", "write_fixture_bundle", "verify_bundle",
    "AssertionDifference", "ChangeKind", "ComparisonReason", "FixtureComparison",
    "compare_fixture_bundles",
    "FixtureReport", "ReportError", "render_fixture_report",
    "DemoError", "DemoVerification", "create_fixture_demo", "verify_fixture_demo",
    "VMPlanError", "K3sVMPlan", "ReportedHostInventory", "VMFeasibility",
    "validate_vm_plan_bytes", "load_vm_plan", "validate_host_inventory_bytes",
    "load_host_inventory", "assess_vm_plan",
    "VMLifecycleError", "VMSimulationScenario", "VMFinalState",
    "VMFailureReason", "VMEvent", "VMLifecycleSimulation",
    "simulate_vm_lifecycle", "simulate_sequential_pair",
]
