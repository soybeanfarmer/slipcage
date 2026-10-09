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

from .vm_assets import (
    VMAssetError, VerifiedLocalAsset, VMAssetPreflight, verify_local_vm_assets,
)

from .vm_provenance import VMProvenanceError, VMProvenanceCheck, verify_provenance
from .vm_host_readiness import (
    VMHostReadinessError, VMHostSnapshot, HostReadinessAssessment,
    validate_host_snapshot_bytes, load_host_snapshot, assess_host_snapshot,
)

from .vm_host_observe import (
    HostObservationError, LocalHostObservation, inspect_local_host,
)

from .vm_qemu_blueprint import (
    QemuBlueprintError, QemuLaunchDisabled, QemuLaunchBlueprint,
    build_qemu_blueprint, launch_qemu,
)

from .vm_supervision import (
    SupervisionError, SupervisionPhase, SupervisionEvent, SupervisionOutcome,
    SupervisionScenario, SupervisorDesign, SupervisorAuditEvent,
    SupervisionJournal, design_supervision, new_journal, transition,
    simulate_supervision, simulate_supervision_pair,
)

from .vm_reservation import (
    ReservationError, QuarantineReason, LocalReservation,
    stage_local_reservation, inspect_local_reservation,
    quarantine_local_reservation,
)

from .vm_overlay_preflight import (
    OverlayPreflightError, OverlayIntentPreflight, inspect_overlay_intent,
)

from .vm_overlay_recovery import (
    OverlayRecoveryError, RecoveryClassification, OverlayRecoveryReview,
    review_overlay_recovery,
)

from .vm_local_review_lock import (
    LocalReviewLockError, LocalReviewLockBusy, LockedRecoveryReview,
    scoped_local_review_lock, review_overlay_with_local_lock,
)

from .vm_offline_fencing import (
    FencingJournalError, FencingJournalBusy, OfflineResolution,
    FencingSnapshot, inspect_offline_fencing, issue_offline_generation,
    resolve_offline_generation,
)

from .vm_process_supervisor import (
    ProcessSafetyError, ProcessPhase, ProcessScenario,
    FakeProcessIdentity, ProcessSafetyPolicy, FakeProcessObservation,
    ProcessSafetyTrace, bind_fake_supervisor, begin_fake_process,
    step_fake_process, simulate_fake_supervision,
)

from .vm_launch_dossier import (
    LaunchDossierError, VMLaunchPrerequisiteDossier,
    review_vm_launch_prerequisites,
)

from .vm_key_policy import (
    VMKeyPolicyError, SigningKeyPolicyCheck, verify_vm_signing_key_policy,
)

from .vm_k3s_checksums import (
    K3sReleaseChecksumError, K3sUpstreamChecksumCheck,
    verify_k3s_release_checksums,
)

from .vm_artifact_sources import (
    ArtifactSourceError, ArtifactSourceReview, review_artifact_source_ledger,
)

from .vm_qcow2_metadata import (
    Qcow2MetadataError, BoundedQcow2MetadataReview,
    inspect_bounded_qcow2_metadata,
)

from .vm_qcow2_external_evidence import (
    Qcow2ExternalEvidenceError, Qcow2ExternalEvidenceReview,
    review_qcow2_external_evidence,
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
    "VMAssetError", "VerifiedLocalAsset", "VMAssetPreflight", "verify_local_vm_assets",
    "VMProvenanceError", "VMProvenanceCheck", "verify_provenance",
    "VMHostReadinessError", "VMHostSnapshot", "HostReadinessAssessment",
    "validate_host_snapshot_bytes", "load_host_snapshot", "assess_host_snapshot",
    "HostObservationError", "LocalHostObservation", "inspect_local_host",
    "QemuBlueprintError", "QemuLaunchDisabled", "QemuLaunchBlueprint",
    "build_qemu_blueprint", "launch_qemu",
    "SupervisionError", "SupervisionPhase", "SupervisionEvent",
    "SupervisionOutcome", "SupervisionScenario", "SupervisorDesign",
    "SupervisorAuditEvent", "SupervisionJournal", "design_supervision",
    "new_journal", "transition", "simulate_supervision", "simulate_supervision_pair",
    "ReservationError", "QuarantineReason", "LocalReservation",
    "stage_local_reservation", "inspect_local_reservation",
    "quarantine_local_reservation",
    "OverlayPreflightError", "OverlayIntentPreflight", "inspect_overlay_intent",
    "OverlayRecoveryError", "RecoveryClassification", "OverlayRecoveryReview",
    "review_overlay_recovery",
    "LocalReviewLockError", "LocalReviewLockBusy", "LockedRecoveryReview",
    "scoped_local_review_lock", "review_overlay_with_local_lock",
    "FencingJournalError", "FencingJournalBusy", "OfflineResolution",
    "FencingSnapshot", "inspect_offline_fencing", "issue_offline_generation",
    "resolve_offline_generation",
    "ProcessSafetyError", "ProcessPhase", "ProcessScenario",
    "FakeProcessIdentity", "ProcessSafetyPolicy", "FakeProcessObservation",
    "ProcessSafetyTrace", "bind_fake_supervisor", "begin_fake_process",
    "step_fake_process", "simulate_fake_supervision",
    "LaunchDossierError", "VMLaunchPrerequisiteDossier",
    "review_vm_launch_prerequisites",
    "VMKeyPolicyError", "SigningKeyPolicyCheck", "verify_vm_signing_key_policy",
    "K3sReleaseChecksumError", "K3sUpstreamChecksumCheck",
    "verify_k3s_release_checksums",
    "ArtifactSourceError", "ArtifactSourceReview", "review_artifact_source_ledger",
    "Qcow2MetadataError", "BoundedQcow2MetadataReview",
    "inspect_bounded_qcow2_metadata",
    "Qcow2ExternalEvidenceError", "Qcow2ExternalEvidenceReview",
    "review_qcow2_external_evidence",
]
