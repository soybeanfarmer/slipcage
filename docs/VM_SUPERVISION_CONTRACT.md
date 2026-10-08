# SC-13b5 — Resource-supervised VM lifecycle contract (offline simulation)

**Status: in-memory fault model only. No VM, host lease, overlay, cgroup, watchdog, resource quota or cleanup operation is implemented or executed.**

SC-13b5 turns the prior fixed, **incomplete** QEMU blueprint into an explicit future-supervisor policy and a finite, pure-Python single-owner lifecycle journal. It cannot launch a VM, reserve CPU/RAM, create or remove disks, call systemd, open KVM, connect to a network, or reconcile actual host processes.

The plan must be a nonsynthetic, schema-validated SC-12 K3s design bound to SC-13b1 **locally matched** private asset bytes. It does not authenticate software publishers, QEMU binary identity or actual guest contents. Existing source-only CI validates behavior with tiny fabricated files; CI cannot establish host readiness.

## Developer-only fault-injection commands

With an operator-controlled private asset directory and a **development-only nonsynthetic plan** whose declared hashes match local bytes:

~~~bash
slipcage simulate-vm-supervision /path/to/development-plan.json \
  --assets-dir /path/to/private-assets --scenario success --json
slipcage simulate-vm-supervision /path/to/development-plan.json \
  --assets-dir /path/to/private-assets --scenario cleanup_failure --json
slipcage simulate-vm-supervision-pair /path/to/development-plan.json \
  --assets-dir /path/to/private-assets \
  --baseline-scenario success --candidate-scenario deadline --json
~~~

Available closed scenarios: **success, start_failure, deadline, resource_pressure, cancelled, crash, cleanup_failure**. Invalid input/forged preflight fails with CLI status 2, clean simulated completion returns 0, a modeled start/deadline/resource/cancel failure returns 4, and unresolved simulated crash/cleanup returns 5. The real `slipcage run`, `compare`, and `report` commands still return 3.

These commands use no subprocess, OS lock, filesystem writer, process list, KVM access, filesystem overlay, systemd, guest NIC or VM boot operation. The CLI only loads the local plan and **read-only hashes** existing asset bytes before executing pure state transitions.

## Derived future supervisor intent

All values are bounded by the validated SC-12 plan:

| Parameter | Synthetic example design | What it means |
| --- | --- | --- |
| Guest vCPU | 2 | Proposed CPUQuota=200% (not applied) |
| Guest memory | 4096 MiB | Proposed MemoryMax=4608 MiB including 512 MiB margin (not applied) |
| Guest overlay | 24 GiB | Proposed overlay limit (not allocated or enforced) |
| Guest runtime | 900 seconds | Proposed hard watchdog deadline (not running) |
| Guest task count | 256 | Proposed TasksMax (not applied) |
| Parallel guests | 1 | In-memory admission/fencing only; **not a host lock** |
| Cleanup policy | preserve unresolved | Model quarantine; no filesystem deletion, no operator clearance API |

The sample numbers above originate from **synthetic** SC-12 guest sizing and are design guidance only. They do not prove that the host has spare resources, suitable cgroup accounting, a working KVM device, or correct QEMU startup behavior.

## Control and failure rules

The supervision model exposes revisioned, frozen values with at most 24 bounded audit events per journal. All updates require an exact expected revision, a bounded owner/attempt ID and a closed enum transition. A second reservation is refused while an attempt is reserved, running, stopping or quarantined. Stale revisions or commands from a different attempt ID fail rather than stealing the simulated lease.

The normal state sequence is `idle -> reserved -> running -> stopping -> clean`. An operator-cancel or simulated deadline/resource sample moves a running attempt to stopping; cleanup must be explicitly observed in the model. Startup failure also proceeds through modeled cleanup.

A simulated crash or cleanup failure enters **quarantined**. The active owner ID is retained, no release/retry/automatic clearance exists, and any future reserve/start/cleanup transition is rejected. Quarantine is **not** a real host isolation barrier and cannot prove a process is dead or a disk is safely retained.

A candidate is *attempted in the model* only after the baseline reaches clean **and** had outcome `completed`. Even a baseline failure with a simulated clean teardown does **not** authorize candidate execution. No two guests run concurrently, even synthetically.

Audit events and outputs are deterministic, bounded and contain no local host paths, credentials or process logs. Their revision checks are **not durable compare-and-swap**: in-memory dataclasses, test clock counters and mock results offer no cross-process fencing, durable recovery or tamper-proof evidence.

Every output reports **simulated=true** and **execution_authorized=false**, with `real_guest_started`, `host_resources_reserved`, `real_exclusive_lease_acquired`, `durable_journal_written`, `watchdog_enforced`, `cgroup_supervision_verified`, `overlay_created`, `overlay_deleted`, `reconciliation_verified_on_host` and `host_modified` false.

## Mandatory separately reviewed real adapter and owner gates

Nothing here satisfies the original live SC-13 disposable QEMU guest acceptance. Complete [real artifact/host verification #23](https://github.com/soybeanfarmer/slipcage/issues/23) and [real VM lifecycle #25](https://github.com/soybeanfarmer/slipcage/issues/25) first, then design the following in a separate focused PR:

1. Trusted publisher attestations and actual QEMU/guest/K3s binary and image verification; immutable image parent with approved private scratch/overlay backing-chain and no host secret mounts.
2. Owner-approved current VPS inventory, permitted provider scope, nested KVM access and measured CPU/RAM/disk/inode/cgroup headroom relative to existing Dagu, SQLite, backups and research tasks.
3. **Actual** exclusive single-VM lease with durable storage and authenticated owner/generation fencing; crash recovery must never assume in-memory state is authoritative.
4. OS process supervision under a dedicated unprivileged account, allowlisted QEMU argv, enforced CPUQuota/MemoryMax/TasksMax/runtime budget, process-group signal/kill/reap, bounded console/evidence, and a tested watchdog on abnormal boot/exit.
5. Exclusive private scratch creation and locked down base image/overlay lifecycle, safe crash quarantine and explicit reconciliation of orphan processes and ambiguous overlays. **No auto-deletion** of unresolved or unowned artifacts; never touch Slipcage backup/SQLite/report/guest evidence trees.
6. Verified guest-internal network requirements and host/provider/metadata/public egress containment; no new interfaces/bridges/egress without explicit authorization.
7. Manual human review/merge and separately approved release. The **owner** must explicitly authorize a single bounded live benign guest validation and manually run approved VPS commands, then share deployed SHA, journals and resource/cleanup evidence. Do not equate green CI or a simulated cleanup result with live acceptance.

No release, SSH action, VPS inspection, VM start, storage or networking change is authorized by this PR. See [QEMU blueprint](QEMU_BLUEPRINT.md), [VM lifecycle](VM_LIFECYCLE_DESIGN.md) and [roadmap](V1_ROADMAP.md).
