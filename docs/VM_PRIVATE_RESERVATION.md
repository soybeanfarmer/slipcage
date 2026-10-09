# SC-13b6 — Private, append-only local VM reservation staging

**Scope: development-only filesystem safety primitive.** This is not a real QEMU guest lease, active process lock, deployed VPS service, secure overlay creator or verified host cleanup. The only writes are tiny, immutable JSON reservation markers under one explicitly chosen **existing, private local directory**. Nothing is installed or executed on the VPS through Ansible or CI.

## What the component does

The developer-only command can reserve exactly one **permanent staging slot** under an operator-controlled existing private directory:

~~~bash
slipcage stage-vm-reservation /private/approved-nonsynthetic-plan.json \
  --assets-dir /private/locally-hashed-assets \
  --root /private/development-root --attempt baseline --json
slipcage inspect-vm-reservation /private/development-root --json
~~~

The root must be an existing, trusted, operator-controlled local POSIX filesystem directory with no group/world mode bits (normally **0700**). Parent directories must also be trusted; this is not protection against malicious same-UID writers or hostile ancestor filesystem races. The new fixed child directory `vm-reservation-v1/` is created exclusively with `mkdir` and private mode. Its contents are:

~~~text
/private/development-root/                 # preexisting, private operator-controlled root
  vm-reservation-v1/                       # NEW private, single-use permanent staging slot
    intent.json                            # canonical immutable intent, 0600
    manifest.json                          # canonical SHA-256 completion marker, 0600, written last
    quarantine.json                        # optional permanent unresolved marker, 0600
~~~

**No `overlay.qcow2` is created.** The name is just a fixed literal in the intent; its proposed disk and time budgets come from the already validated SC-12 plan and SC-13b4 incomplete QEMU blueprint. Files are written with exclusive creation, flushed and `fsync`ed. If the process crashes before the final manifest, the directory remains **incomplete and blocking**, not silently repaired or deleted. Inspection verifies an exact file allowlist, private regular single-link files, canonical JSON, the intent SHA-256, compatible fixed safety fields and any quarantine digest.

After staging, any second attempt to claim the same root fails, even if it uses the same attempt ID. **The root cannot be reused through this tool.** For each permitted development fixture use a distinct, intentionally created private scratch root; the engine never creates/cleans such parent roots itself.

The operator can append a permanent quarantine marker after checking the exact intent SHA-256 and attempt ID:

~~~bash
slipcage quarantine-vm-reservation /private/development-root \
  --attempt baseline --intent-sha256 EXPECTED_INTENT_DIGEST \
  --reason operator_review_required --json
~~~

Supported reason values are `operator_review_required`, `simulated_crash` and `simulated_cleanup_failure`. Quarantine blocks further writes or reservation reuse and reports CLI exit 5. **No clearance or deletion method exists**. These reasons are local labels for offline fault-injection, not independently observed host crashes. The tool cannot inspect/kill/reap real guest processes or decide whether an overlay is safe to remove. The operator must separately review any ambiguous partial data; existing backup, SQLite, report and guest evidence trees must not be cleaned automatically.

## Fail-closed behavior and trust limitations

Tests cover simultaneous attempts racing on the same root, existing slot refusal, interrupted record publication, forged completion hashes, tampered JSON, symlinks, hardlinks, incorrect permissions, suspicious extra files and irreversible quarantine. Success means only **a local intent record was staged and its completion marker matches**. This is not an exclusive host-wide or distributed VM lock; multiple different roots still allow multiple reservations, and no process is fenced.

The `stage-vm-reservation` CLI re-hashes five local asset files and validates a non-synthetic SC-12 VM plan before creating the marker. Local SHA-256 equality **does not authenticate publisher origin**. Programmatic `stage_local_reservation` callers must treat an externally constructed preflight dataclass as untrusted evidence; only the CLI itself freshly checks asset bytes. A completion hash detects ordinary modifications, not an attacker capable of rewriting both intent and manifest in a writable operator-controlled directory.

All positive output explicitly sets `real_host_exclusive_lease_enforced: false`, `cross_process_execution_fencing_proven: false`, `overlay_created: false`, `qemu_launched: false`, `cgroup_limits_enforced: false`, `watchdog_enforced: false`, `actual_cleanup_verified: false`, `execution_authorized: false`, and `host_vm_modified: false`. The exact CLI exit semantics are 0 for a valid staged/readable marker, 2 for invalid/incomplete/unsafe data, and 5 for a valid quarantined marker. Real `run`, `compare` and `report` remain disabled with exit code 3.

**CI runs only in ephemeral runner-created directories** using invented tiny asset bytes, and it never starts QEMU, creates an overlay, touches the VPS, changes systemd or connects to network services. No real host capacity/provenance checks are claimed.

## Missing real SC-13 runtime acceptance

This staging work does **not** complete [trusted image/host gate #23](https://github.com/soybeanfarmer/slipcage/issues/23) or [real disposable VM lifecycle gate #25](https://github.com/soybeanfarmer/slipcage/issues/25). Before any live guest, the project still requires independently authenticated upstream software and actual asset bytes, operator-approved VPS capacity/nested KVM/provider evidence, a global/process-safe durable lease and crash reconciliation, inspected immutable backing disk with safe exclusive overlays, enforced systemd/cgroup quotas, hard process watchdog/kill/reap, bounded console/evidence handling, guest network isolation and explicit owner approval for one benign test.

**Do not run this staging command on the VPS or an existing production data root** as part of PR review. No such action is authorized by this milestone. All human merge, release, deployment and host-execution gates remain separate.

## SC-13b7 — Header-only QCOW2 base inspection

The new [QCOW2 base/overlay-intent preflight](VM_QCOW2_BASE_PREFLIGHT.md) can read this permanent non-quarantined reservation, then check the private base image's entire declared hash and a narrow no-backing QCOW2 v3 header shape. It makes **no** new overlay and cannot clear quarantine or certify a real backing chain.

## SC-13b8 — Recovery triage, not cleanup

The [SC-13b8 recovery reviewer](VM_OVERLAY_RECOVERY_REVIEW.md) now detects incomplete/invalid single-use slots, quarantine markers and unexpected overlay-named filesystem nodes. It does not remove or repair any record, inspect processes, or open a QCOW2 disk. Even a nominal staged record never grants operator clearance or guest launch permission.
