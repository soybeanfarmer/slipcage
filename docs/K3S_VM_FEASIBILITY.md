# SC-12 — Pinned Kubernetes VM design and host feasibility

**Status: offline contract and feasibility model only. NOT an installed or booted K3s VM.** SC-12 does not grant permission to launch QEMU, attach guest disks, enable networking, download assets, alter systemd/Ansible, or test a hosting provider.

SC-05–SC-11 established the validated synthetic experiment pipeline. This milestone prepares a conservative, pinned description of the *future* QEMU/KVM K3s environment and an auditable, operator-reported capacity estimate. [Roadmap](V1_ROADMAP.md) and [architecture](ARCHITECTURE.md) remain the high-level dependencies.

## What is implemented

The package now exposes read-only:

~~~bash
slipcage plan-vm examples/vm-plans/k3s-synthetic-design.json \
  --inventory examples/vm-plans/host-capacity-synthetic.json --json
~~~

The sample JSON files are **deliberately synthetic test data**. The digests are invented test strings, not the SHA-256 hashes of any downloaded OS image, Linux kernel, K3s binary, CNI assets, or container image archive. The QEMU/K3s versions and Linux release in that file are examples, not selected/installed versions for production. **Never feed this fixture to an executable VM adapter.**

The validator rejects unknown fields, syntax ambiguity, missing hashes, inconsistent versioned machine types, unsupported workloads, public egress, host mounts, arbitrary shell commands, parallel VMs, non-ephemeral disks and attempts to set execution-enabled flags. Both plan and inventory are strict UTF-8 JSON, at most 32 KiB and regular local non-symlink files. The result includes a canonical input SHA-256, exact declared resource requirements, conservative blockers and explicit:

~~~json
{
  "status": "design_only",
  "artifacts_verified": false,
  "kvm_verified_on_target_host": false,
  "provider_permission_verified": false,
  "network_isolation_verified": false,
  "k3s_boot_verified": false,
  "execution_authorized": false,
  "executable": false,
  "host_modified": false,
  "vm_launched": false
}
~~~

These fields are selected excerpts, not complete output. Exit status 0 means the input conforms to the **design-only** schema; it does not imply host capacity, provider permission, VM boot, or Kubernetes behavior have been independently verified. Unknown inputs fail closed.

### Reproducibility contract

Required fields and why they exist:

| Component | Required pin | Verification not yet done |
| --- | --- | --- |
| Host hypervisor | QEMU version, versioned \`pc-q35-M.m\` machine and CPU model \`x86-64-v2\` | Exact binary hash, supported CPU flags and host-version compatibility |
| Guest OS disk | Immutable image SHA-256; disposable copy-on-write overlay | Acquire/harden image, verify content digest and image backing-chain behavior |
| Guest kernel | Kernel release plus SHA-256 | Extract or reconstruct actual running kernel evidence from candidate image |
| Kubernetes | Exact K3s \`vX.Y.Z+k3sN\` version and binary SHA-256 | Obtain trusted release and verify binary |
| CNI and workload images | Digest of offline CNI assets and container image archive | Download/review/verify exact assets and CNI enforcement behavior |
| Guest resources | vCPU, RAM, disk, boot/runtime budget and maximum one active VM | Measure startup, RSS, storage exhaustion and teardown |
| Network | Guest-internal-only topology, preloaded images, disabled public egress and no host bridge | Prove air-gapped K3s bootstrap and containment with actual guest captures |
| Security | Reviewed benign RBAC-only workload, no host mounts/provider testing, explicit disabled execution/network flags | Operator signoff and isolation evaluation |

These are **declarations**. A SHA-256-shaped string is not proof that an artifact exists, was verified, was built from trusted sources, or corresponds to a specified version. The v1alpha1 SC-12 schema has no \`verified\` or \`deployable\` provenance state. Actual artifact acquisition and independent verification belong to a separately approved implementation.

A fixed \`x86-64-v2\` guest CPU model and versioned QEMU machine reduce implicit host coupling but do not guarantee that nested KVM or the selected guest CPU model works on the VPS. The guest OS image may contain additional kernel modules, OCI images and distribution packages that require a separately versioned inventory. Guest kernel and K3s digest must be verified against the actual guest environment before claiming replayability.

### Capacity planning, not benchmarking

Current design heuristic per **one sequential** K3s research VM:

| Reservation | Minimum |
| --- | --- |
| Guest vCPU | 2 threads |
| Guest RAM | 4 GiB |
| Disposable guest overlay | 24 GiB |
| Host CPU reserve | Additional 2 threads |
| Host RAM reserve | Additional 4 GiB |
| Host free-disk headroom | Additional 16 GiB |
| Concurrent research VMs | **1 only** |
| Guest runtime | Maximum 30 minutes, still requires future supervisor enforcement |

The estimator returns \`fits_reported_capacity\` if operator-supplied CPU/memory/free-disk numbers meet these simple thresholds. This is **not** a host probe, benchmark, permission check, quota reservation or guarantee of safe operation. It does not account for QEMU host RSS overhead, K3s peaks, overlay copy-on-write amplification, Dagu/SQLite workloads, inode depletion, hypervisor overhead or other VPS processes. Sequential baseline-then-candidate is the only proposed initial topology.

The synthetic inventory (\`6\` CPU threads, \`12288\` MiB memory, \`48\` GiB free disk) is a **test example**, not a statement of present VPS free space, available RAM or usable nested KVM. In particular, do not interpret the output as permission to allocate a real 24 GiB overlay.

## Why the current benign guest cannot just become K3s

Existing \`scripts/slipcage-kvm-probe.py\` and guest lifecycle units deliberately launch a fixed **diskless, networkless** microguest under restricted unprivileged systemd controls. They do not create persistent guest storage or boot a Kubernetes distribution. A K3s guest requires a designed disk/storage lifecycle; a preloaded, pinned image and container-runtime artifacts; guest-internal packet delivery and CNI behavior; a controlled evidence/control channel; and teardown that cannot delete live research/backup data.

For initial RBAC testing, the candidate topology is one disposable VM with no public egress, and the harness operating inside the VM. For later NetworkPolicy testing, a controlled pod/guest network with known enforcement semantics must be established; **Flannel alone is not proof that network policy works**, and the draft \`policy_enforcement_proven\` flag is fixed to false. No bridge or egress enabling code is included in SC-12.

## Human-approved SC-13/SC-14 prerequisites

Before *any* real VM boot or filesystem/network change, propose a separate PR and operator verification plan covering:

1. Select real, trusted OS/QEMU/kernel/K3s/CNI/container image versions; record artifact hashes and license/source origins; reject missing/mismatched digests.
2. Document provider permissions and permitted test scope for nested KVM and controlled K3s traffic.
3. Obtain a **read-only** operator-supplied capacity snapshot: total/available RAM, CPU load, free disk/inodes, existing Slipcage workers, cgroup and KVM capability; do not put host identifiers, tokens or access details in GitHub.
4. Benchmark representative VM startup, memory, overlay disk and cleanup on a separately approved disposable/scratch environment; enforce hard supervisor limits and prevent concurrent guest jobs.
5. Design the guest image's disk backing chain and snapshot cleanup without touching existing SQLite/reports/backup/guest-evidence trees. Use exclusive private scratch paths, crash reconciliation and conservative retention.
6. Prove no uncontrolled guest-to-host, management, provider metadata or public egress; only then introduce the minimal approved guest networking.
7. Define signed-off manual commands, expected systemd/VM/cluster evidence, negative tests, rollback and production release/verification gates.

**SC-12 acceptance for this PR:** schema and CLI work offline, unsafe configurations fail closed, pin declarations are deterministic, synthetic capacity estimates are correct, documentation distinguishes missing real artifacts from verified evidence, existing CI passes, no VM executes. **Actual image pin verification, VPS measurements and live K3s readiness remain outstanding** and must not be claimed by merging this PR.

The existing human approval workflow is unchanged: code/CI → owner PR review/merge → separately authorized release → owner-run VPS commands → evidence review. A documentation/contract change alone does not require a VPS promotion.

## SC-13a lifecycle controls (offline-only)

A pure in-memory lifecycle simulation now models the future one-VM-at-a-time admission, start, stop, failure/cancellation and cleanup transitions. It does not claim that the SC-12 image digest strings are real or that a VM is bootable. Live host measurements, provider authorization, independent image pin verification, guest networking and hard supervisor limits are still outstanding. See [SC-13a lifecycle design](VM_LIFECYCLE_DESIGN.md) and [Issue #23](https://github.com/soybeanfarmer/slipcage/issues/23).

## SC-13b1 — Local asset SHA-256 preflight

The optional `verify-vm-artifacts` command now checks **actual local bytes**
against operator-entered SC-12 artifact digests using fixed filenames and
private root/file permissions. It rejects the synthetic example plan and
does not authenticate an upstream publisher, verify guest image contents, boot
QEMU, prove KVM/host readiness or authorize execution. See
[read-only VM artifact preflight](VM_ASSET_PREFLIGHT.md). Issue #23 remains
open for **trusted artifact provenance** and independently checked VPS
measurements/permission.

## SC-13b2 offline trust/report checks

SC-13b2 adds bounded detached Ed25519 statement verification against an **independently supplied public key** and conservative parsing of operator-reported host snapshots. Neither is a publisher identity check, live KVM probe or permission to start a guest. See [SC-13b2 documentation](VM_PROVENANCE_HOST_GATE.md).
