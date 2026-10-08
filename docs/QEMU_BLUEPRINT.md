# SC-13b4 — Incomplete, non-executing QEMU launch blueprint

**Status: development-only argument model, NOT a real QEMU adapter and NOT authorized guest execution.**

The SC-13b4 milestone provides a code-reviewed foundation for a future disposable-VM adapter: a strict, reproducible, **fixed argument prefix** derived from the SC-12 validated K3s VM plan and SC-13b1 local asset-byte hash preflight. It contains **no process launcher or disk writer**, no guest image/kernel/NIC attachment, and no host resource supervisor. SC-13 remains **runtime-incomplete** pending Issues [#23](https://github.com/soybeanfarmer/slipcage/issues/23) and [#25](https://github.com/soybeanfarmer/slipcage/issues/25).

## Development-only command

Using a **nonsynthetic**, operator-supplied SC-12 plan and an existing operator-controlled private (0700) asset directory containing exactly the five locally checked single-link private files:

~~~bash
slipcage plan-qemu /path/to/operator-plan.json --assets-dir /path/to/private-assets --json
~~~

The repository's synthetic example plan is intentionally **rejected**, even if file hashes happen to match. No supplied flag may insert QEMU argv, shell strings, NICs, drive paths, mounts, or host commands. The command rehashes local assets, checks the declared plan identity and outputs an incomplete blueprint with no private host paths.

A representative argument **prefix** is:

~~~text
qemu-system-x86_64
-no-user-config -nodefaults
-machine pc-q35-9.0,accel=kvm
-cpu x86-64-v2
-smp 2 -m 4096
-display none -monitor none -serial none
-nic none -S -no-reboot
~~~

The example QEMU version/machine are from the **synthetic sample**, not a selected real host binary. This is **not a complete or tested guest command**, and should **not be executed manually**. If executed, QEMU could still create a paused process; this tool never executes it. The prefix omits every drive, kernel/initrd/firmware, chardev, network backend, guest console and monitor socket and has `-S` for paused startup. It cannot demonstrate a bootable K3s VM or an isolated production workload.

The binary name is a descriptive, unresolved string, not a verified QEMU build/path or supply-chain pin. A correct QEMU command for a real K3s VM also needs carefully reviewed and pinned firmware/boot flow, **private disposable backing overlay**, verified immutable parent image and module/image dependencies, explicit safe transport for guest evidence, process supervision and networking/isolation tests. None are built in SC-13b4.

## Fail-closed input and output

The plan must have SC-12 `provenance.pin_status: operator_supplied_unverified`, versioned QEMU machine and CPU model, fixed resource bounds and one guest at a time. The local asset preflight must have the exact plan ID/digest, all five ordered filename/hash/size tuples and all declared digests equal to the plan. The CLI obtains the preflight by **re-hashing local bytes each invocation**; programmatic callers should not treat an arbitrary forged dataclass instance as trusted filesystem proof.

Each blueprint unconditionally reports `argv_is_complete_launch_command: false`, `guest_boot_possible_from_blueprint: false`, `execution_authorized: false`, `real_vm_launched: false`, `host_modified: false`, `host_kvm_usable_verified: false`, `qemu_binary_version_verified: false`, `process_cgroup_limits_enforced: false`, `runtime_deadline_enforced: false`, `guest_overlay_created: false`, and `operator_launch_approved: false`. Even with all local hashes matching, the signature/publisher identity remains **unauthenticated**.

The `launch_qemu(...)` library entrypoint deliberately raises `QemuLaunchDisabled` for *all* arguments; there is no CLI command to launch a guest. Generic `slipcage run`, `compare`, and `report` remain explicitly disabled. CLI exit code 0 means a structurally consistent, incomplete **offline blueprint was generated**, not that a VM was run or readiness was established; code 2 means validation/hash checking failed.

## Real SC-13 acceptance still outstanding

1. **Trusted provenance:** separately authenticate publisher native release keys/signatures and exact genuine bytes, plus QEMU binary identity, guest content and immutable backing-chain validation. The SC-13b2 detached statement against a caller-supplied key is not enough.
2. **Host and provider approval:** owner-supplied approved current VPS resource/cgroup/inode/KVM readings and explicit provider scope; SC-13b3's read-only observation is only partial and must not be auto-run as a side effect of this command.
3. **Real process adapter, separate reviewed PR:** pin the actual QEMU binary, implement safe argv with exclusively created private overlay under approved scratch, strict unprivileged service/cgroup budgets, bounded console/evidence, explicit guest network containment and exit signals. No arbitrary QEMU options, host mounts, credentials, network bridge or public egress.
4. **Durable lifecycle and cleanup:** exclusive leases and one-VM concurrency, outer OS watchdog/kill/reap, crash restart reconciliation, conservative preservation of ambiguous artifacts, operator override, and audit evidence without deleting backup/SQLite/guest research files.
5. **Manual one-guest validation:** owner separately approves any live VM launch, merges the reviewed PR, approves appropriate release promotion, manually runs approved VPS commands, and supplies deployed SHA and logs for verification. Green CI cannot stand in for any live host result.

**No release, VPS SSH command, systemd action or QEMU process is performed by this PR.** See [SC-13 lifecycle design](VM_LIFECYCLE_DESIGN.md), [asset preflight](VM_ASSET_PREFLIGHT.md), [host observation](VM_HOST_OBSERVATION.md), [security policy](../SECURITY.md) and [roadmap](V1_ROADMAP.md).
