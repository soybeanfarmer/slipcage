"""SC-13b12 read-only, fail-closed prerequisites DOSSIER; never launch-ready.

Reuses strict SC-12/SC-13 validators in one explicit local CLI flow. Success
means independently executed *local* consistency checks only. A user-supplied
Ed25519 public key does NOT establish publisher identity. An operator-supplied
host snapshot does NOT establish current host facts, provider authorization,
KVM availability, or cgroup enforcement. A QCOW2 header does NOT validate its
full metadata or immutable backing chain.

No process, host, network, scratch-root, journal, overlay or guest mutation.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from .vm_assets import verify_local_vm_assets
from .vm_host_readiness import assess_host_snapshot, load_host_snapshot
from .vm_offline_fencing import inspect_offline_fencing
from .vm_overlay_preflight import inspect_overlay_intent
from .vm_overlay_recovery import RecoveryClassification, review_overlay_recovery
from .vm_plan import load_vm_plan
from .vm_provenance import verify_provenance
from .vm_key_policy import verify_vm_signing_key_policy
from .vm_qemu_blueprint import build_qemu_blueprint
from .vm_reservation import inspect_local_reservation

API_VERSION = "slipcage.dev/vm-launch-prerequisite-dossier/v1alpha1"
_STATIC_BLOCKERS = (
    "publisher_key_identity_not_authenticated_out_of_band",
    "software_and_guest_contents_not_independently_authenticated",
    "snapshot_authenticity_and_freshness_not_verified",
    "target_host_kvm_and_provider_permission_not_independently_verified",
    "target_host_services_and_effective_cgroup_limits_not_verified",
    "full_qcow2_metadata_and_immutable_backing_chain_not_verified",
    "real_host_global_lease_and_process_fencing_not_implemented",
    "actual_overlay_quotas_watchdog_and_cleanup_not_implemented",
    "guest_network_isolation_not_verified",
    "owner_approved_live_vm_test_not_provided",
)


class LaunchDossierError(ValueError):
    """Mismatch between otherwise valid offline prerequisite inputs."""


@dataclass(frozen=True, slots=True)
class VMLaunchPrerequisiteDossier:
    plan_id: str
    plan_digest_sha256: str
    asset_digest_sha256: str
    asset_total_size_bytes: int
    statement_digest_sha256: str
    supplied_public_key_fingerprint_sha256: str
    snapshot_digest_sha256: str
    reported_capacity_assessment: str
    reported_host_blockers: tuple[str, ...]
    reservation_digest_sha256: str
    offline_generation: int
    offline_attempt_id: str
    offline_issue_sha256: str
    base_file_sha256: str
    base_file_size_bytes: int
    operator_policy_digest_sha256: str | None = None

    def to_dict(self) -> dict:
        blockers = list(_STATIC_BLOCKERS)
        if self.reported_capacity_assessment != "reported_thresholds_met":
            blockers.insert(0, "operator_reported_host_thresholds_not_met")
        return {
            "api_version": API_VERSION,
            "kind": "offline_read_only_vm_launch_prerequisite_dossier",
            "status": "blocked_no_execution_permission",
            "plan_id": self.plan_id,
            "plan_digest_sha256": self.plan_digest_sha256,
            "locally_checked_assets_digest_sha256": self.asset_digest_sha256,
            "local_asset_total_size_bytes": self.asset_total_size_bytes,
            "signed_statement_sha256": self.statement_digest_sha256,
            "supplied_key_fingerprint_sha256": self.supplied_public_key_fingerprint_sha256,
            "operator_key_policy_sha256": self.operator_policy_digest_sha256,
            "operator_key_pin_consistency_checked": self.operator_policy_digest_sha256 is not None,
            "policy_identity_authenticated_out_of_band": False,
            "operator_snapshot_sha256": self.snapshot_digest_sha256,
            "reported_capacity_assessment": self.reported_capacity_assessment,
            "reported_host_blockers": list(self.reported_host_blockers),
            "reservation_digest_sha256": self.reservation_digest_sha256,
            "offline_intent_generation": self.offline_generation,
            "offline_intent_attempt_id": self.offline_attempt_id,
            "offline_intent_issue_sha256": self.offline_issue_sha256,
            "base_qcow2_sha256": self.base_file_sha256,
            "base_qcow2_file_size_bytes": self.base_file_size_bytes,
            "consistency_checks_completed": True,
            "blockers": blockers,
            "source_publisher_authenticated": False,
            "public_key_identity_authenticated": False,
            "real_host_telemetry_authenticated": False,
            "host_snapshot_freshness_verified": False,
            "usable_kvm_proven_on_target": False,
            "provider_permission_independently_verified": False,
            "full_guest_image_structure_verified": False,
            "immutable_backing_chain_verified": False,
            "host_global_execution_lease_held": False,
            "runtime_cgroup_disk_watchdog_enforced": False,
            "real_guest_process_fenced": False,
            "overlay_created": False,
            "vm_launched": False,
            "cleanup_verified_on_host": False,
            "owner_live_execution_approved": False,
            "execution_authorized": False,
            "host_modified": False,
        }

    def canonical_json(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def review_vm_launch_prerequisites(
    plan_file: str | Path, asset_dir: str | Path,
    statement_file: str | Path, signature_file: str | Path,
    public_key_file: str | Path, snapshot_file: str | Path,
    reservation_root: str | Path, journal_root: str | Path,
    key_policy_file: str | Path | None = None,
) -> VMLaunchPrerequisiteDossier:
    """Repeat file-backed checks, cross-bind inputs, and ALWAYS block execution.

    The sources are not atomically snapshotted across all 8 independent
    paths. No filesystem or host security promises against malicious same-UID
    writers. A successful check is NOT an authority to run or release a VM.
    """
    if Path(reservation_root).absolute() == Path(journal_root).absolute():
        raise LaunchDossierError("Reservation and offline journal must use separate private roots")
    plan = load_vm_plan(plan_file)
    assets = verify_local_vm_assets(plan, asset_dir)
    # Already binding all asset digests, this only constructs a non-runnable prefix.
    blueprint = build_qemu_blueprint(plan, assets)
    provenance = verify_provenance(plan, statement_file, signature_file, public_key_file)
    policy_result = (
        verify_vm_signing_key_policy(
            plan, statement_file, signature_file, public_key_file, key_policy_file,
        ) if key_policy_file is not None else None
    )
    if policy_result is not None and (
        policy_result.plan_digest_sha256 != provenance.plan_digest_sha256
        or policy_result.statement_digest_sha256 != provenance.statement_digest_sha256
        or policy_result.supplied_public_key_fingerprint_sha256
            != provenance.trusted_key_fingerprint_sha256
    ):
        raise LaunchDossierError("Inconsistent policy signature, key and plan identities")
    snapshot = load_host_snapshot(snapshot_file)
    host = assess_host_snapshot(plan, snapshot)
    reservation = inspect_local_reservation(reservation_root)
    base = inspect_overlay_intent(plan, assets, reservation, asset_dir)
    recovery = review_overlay_recovery(reservation_root)
    journal = inspect_offline_fencing(journal_root)

    if (reservation.attempt_id != journal.active_attempt
            or reservation.plan_digest_sha256 != journal.plan_digest_sha256
            or reservation.plan_id != blueprint.plan_id
            or journal.state != "outstanding_offline_intent"
            or journal.generation < 1
            or journal.active_record_sha256 is None
            or recovery.classification is not RecoveryClassification.STAGED_ONLY
            or not recovery.record_verified
            or recovery.reservation_digest_sha256 != reservation.record_digest_sha256
            or recovery.plan_digest_sha256 != plan.digest_sha256
            or base.reservation_digest_sha256 != reservation.record_digest_sha256
            or base.plan_digest_sha256 != plan.digest_sha256
            or base.base_sha256 != blueprint.backing_image_digest_sha256
            or provenance.plan_digest_sha256 != plan.digest_sha256
            or host.plan_digest_sha256 != plan.digest_sha256):
        raise LaunchDossierError("Unsafe, mismatched or non-outstanding offline input identities")

    return VMLaunchPrerequisiteDossier(
        plan.name, plan.digest_sha256,
        _sha(assets.canonical_json()),
        sum(item.size_bytes for item in assets.assets),
        provenance.statement_digest_sha256,
        provenance.trusted_key_fingerprint_sha256,
        _sha(snapshot.canonical_json),
        host.capacity_assessment, host.blockers,
        reservation.record_digest_sha256,
        journal.generation, journal.active_attempt,
        journal.active_record_sha256,
        base.base_sha256, base.base_size_bytes,
        policy_result.policy_digest_sha256 if policy_result is not None else None,
    )
