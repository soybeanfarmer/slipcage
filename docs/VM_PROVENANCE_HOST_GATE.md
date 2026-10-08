# SC-13b2 — Offline VM provenance and host-readiness gates

**Status: CI/offline code only. No trusted publisher was authenticated; no VPS was measured or modified; no real VM was started.**

SC-13b1 matches local asset bytes against operator-supplied SHA-256 declarations. SC-13b2 adds a strict detached signature check and a conservative *operator-reported* host capacity assessment, but no runnable QEMU/K3s integration.

## Detached statement verification

Example command (requires an operator-selected non-synthetic SC-12 plan and a key independently authenticated from a trusted publisher):

~~~bash
slipcage verify-vm-provenance /private/operator-plan.json --statement /private/statement.json --signature /private/statement.sig --public-key /private/trusted-public-key.raw --json
~~~

The statement must be canonical JSON with exactly api_version, release_id, plan_digest_sha256, and artifacts (all five SC-12 SHA-256 digest fields). Its api_version is slipcage.dev/vm-provenance/v1alpha1. It cryptographically binds the plan digest and all five assets to the release label. The raw 64-byte Ed25519 signature covers these exact bytes: ASCII **SLIPCAGE_VM_PROVENANCE_V1**, a zero byte, and the canonical JSON statement. The public key is exactly 32 raw bytes (not PEM or base64). Inputs must be bounded, local, non-symlink, single-link regular files.

**Crucial trust caveat:** Any attacker can create a self-signed statement and supply their own key. The command verifies mathematical signature correctness **only against the operator-supplied public key**. It cannot authenticate the publisher, key distribution, revocation, upstream release channels, native release signatures, Sigstore/in-toto attestations or actual image contents. No publisher keys or private keys are bundled in this repository. Only ephemeral test keys are created by unit tests.

A successful output still explicitly marks key_identity_verified_out_of_band, software_origin_independently_authenticated, source_revocation_checked, provider_permission_verified, execution_authorized, host_modified and vm_launched **false**. The command does not read actual VM asset bytes; SC-13b1 covers independent local hash checking. Before treating provenance as trusted, the operator must separately authenticate actual upstream publishing identities and signatures through the publisher's documented method.

## Operator-reported host snapshot

~~~bash
slipcage assess-vm-host /private/operator-plan.json --snapshot /private/operator-host-snapshot.json --json
~~~

Strict JSON fields: api_version = slipcage.dev/vm-host-snapshot/v1alpha1; source = operator_supplied_unverified; captured_at_utc (UTC seconds); plan_digest_sha256; logical_cpu_threads; available_memory_mib; free_disk_gib; free_inodes; kvm_device_reported; kvm_usable_reported; cgroup_v2_reported; provider_scope (unknown/not_authorized/operator_reports_permission); active_guest_count.

The evaluator fails closed on unexpected keys, booleans as integers, invalid timestamps, duplicate keys, wrong plan digests, impossible values or claimed independently-verified sources. It evaluates only **declared** host quantities. Thresholds: guest vCPU + 2 host threads, guest RAM + 4096 MiB available RAM, guest disk + 16 GiB free space, 100,000 free inodes, reported usable KVM/cgroup v2, zero other guests and operator-reported provider permission. Meeting thresholds gives reported_thresholds_met—not host readiness, a KVM test or authorization.

The evaluator does not inspect /dev/kvm, SSH into VPS, collect host metrics, benchmark QEMU, inspect live processes, or launch anything. Output always marks snapshot_authenticity_verified, snapshot_freshness_verified, host_readiness_independently_verified, provider_permission_verified, execution_authorized, host_modified and vm_launched **false**.

## Remaining SC-13 full acceptance

- Verify genuine OS/kernel/K3s/QEMU/CNI/OCI artifact contents against independent trusted publisher identities and signatures; reject fabricated or untrusted inputs.
- Obtain current **owner-approved read-only** VPS capacity/KVM/cgroup/inode/resource evidence and provider scope, without publishing host identifiers, secret keys or private logs.
- Implement a separately reviewed real VM adapter with controlled guest images, exact allowlisted QEMU argv, hard cgroup/time/disk limits, unprivileged isolation, bounded one-VM concurrency, guest network containment and non-destructive, crash-safe cleanup.
- Require owner review/merge, separate release approval and **separately authorized single benign live VM test** executed by the owner over SSH. Compare deployed SHA and operator-supplied logs. No such approval or execution is implied here.

The original real SC-13 lifecycle milestone remains open under [Issue #25](https://github.com/soybeanfarmer/slipcage/issues/25), with real pin/host prerequisites under [Issue #23](https://github.com/soybeanfarmer/slipcage/issues/23).

## SC-13b3 — Operator-only local host fact collection

The new [read-only host observation command](VM_HOST_OBSERVATION.md) can collect bounded Linux CPU, MemAvailable, disk/inodes and basic KVM/cgroup presence **only when explicitly invoked locally by the operator**. No actual VPS observations have been collected, and the output deliberately cannot attest nested KVM usability, provider scope or guest readiness. Issue #23 and #25 remain open.
