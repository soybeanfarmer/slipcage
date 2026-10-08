# SC-13b3 — Explicit manual, read-only Linux host observation

**This adds development code, not an approved or executed VPS inspection.** It does not install a new production unit, start a VM, authenticate a publisher, grant provider permission, or inspect any host unless the operator deliberately invokes the new command on that host.

## Operator-only interface

After reviewing/merging the PR and separately authorizing any local inspection, an operator may run the development-only CLI **on the intended Linux host**:

~~~bash
slipcage inspect-vm-host /path/to/approved-vm-plan.json \
  --scratch-root /path/to/an-existing-approved-scratch-filesystem --json
~~~

**Do not run this command on the VPS as part of reviewing or merging the PR.** It is not installed by Ansible today and is not required for CI. Do not create a scratch path solely for this command. The selected path is only opened read-only to obtain free space/inode counts. The tool never creates files, changes ownership or permissions, opens `/dev/kvm`, launches QEMU, enumerates guest processes, or uses SSH/network calls.

The tool reads only a strict, bounded selection of local host facts:

- Visible logical CPU threads from `os.cpu_count()` (not effective cpuset/cgroup quotas).
- `MemAvailable` from a bounded read of `/proc/meminfo` (not host workload peak RSS).
- Free scratch filesystem bytes/inodes via `fstatvfs` on the operator-selected existing directory.
- Whether `/dev/kvm` is a character device by **stat only** (no open, ioctl or KVM test).
- Whether an expected cgroup-v2 controllers file exists and lists recognized controller names; this does not prove effective quota enforcement.

The parser rejects duplicate/missing `MemAvailable`, nonregular/unbounded files, invalid CPU/disk counters, nonsymlink-root mistakes, forged plan digests and malformed data. It computes numeric thresholds using the existing SC-12 budget, but always treats them as **a point-in-time observation**, not a guaranteed resource reservation.

## Expected output and trust

Canonical JSON binds the observation to the SC-12 plan digest, and gives a UTC collection timestamp and the above numbers without hostnames, usernames, usernames' home directories, paths, addresses, device serials or arbitrary process/host logs. The output does not disclose the nominated scratch path.

Even if all observed numeric thresholds are satisfied, the result remains `read_only_local_host_observation`, with `execution_authorized: false`, `kvm_usable_verified: false`, `effective_cgroup_limits_verified: false`, `provider_permission_verified: false`, `active_guest_count_verified: false`, `capacity_reservation_performed: false`, `vm_launched: false`, `host_modified: false`.

A character device at `/dev/kvm` does **not** prove nested virtualization works; `os.cpu_count()` does not reflect CPU throttling; available memory and free disk can change immediately. A report collected on CI or a developer laptop **cannot establish VPS readiness**. The collector does not produce SC-13b2's operator-attested snapshot automatically because it cannot truthfully claim KVM usability, provider permission, active guest count or measurement authenticity.

## Development test boundary and next review gate

GitHub CI tests with **synthetic meminfo strings, patched filesystem counters, injected clock and mocked KVM/cgroup observations**. No CI test runs the collector against real host paths or starts QEMU. The real `run`, `compare` and `report` commands remain disabled.

Before real SC-13 acceptance:

1. Independently authenticate trusted artifact release signatures and actual VM asset contents, including image format/guest kernel/K3s/CNI dependencies.
2. Human owner explicitly approves any operator-run read-only collection on the VPS and selects an existing safe scratch path, shares only reviewed/appropriately redacted output.
3. Independently confirm provider policy and actual nested KVM access using a **separately authorized** benign test, as well as effective cgroup limits, current concurrent guest activity and disk/inode headroom.
4. Review a separate fixed-argv, resource-bounded, one-guest-only QEMU adapter and explicit human approval for any live guest boot. Preserve backups/SQLite/reports/guest evidence and never auto-delete ambiguous artifacts.

Track remaining real-host/software acceptance under [Issue #23](https://github.com/soybeanfarmer/slipcage/issues/23) and [Issue #25](https://github.com/soybeanfarmer/slipcage/issues/25). Green CI and this collector alone do not close those issues.
