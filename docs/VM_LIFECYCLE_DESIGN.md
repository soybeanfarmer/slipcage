# SC-13a — Disposable VM lifecycle control model (offline)

**Status: code/CI validation only. No QEMU/K3s guest lifecycle is implemented or approved.**

SC-13a supplies an **in-memory** finite-state model for future disposable VM environments: capacity admission, allocation, startup, runtime error, deadline, cancellation, cleanup and sequential baseline/candidate gating. The implementation does **not** create a disk, boot a guest, open KVM, modify a network, or check provider permission. All transitions are synthetic labels, not system operations.

SC-12 remains design-only and execution-disabled. Real artifact and host verification is tracked in [Issue #23](https://github.com/soybeanfarmer/slipcage/issues/23).

## Offline commands

The included plan contains **invented** SHA-256-shaped digests, not verified VM assets:

~~~bash
python3 -m pip install -e .
slipcage simulate-vm-lifecycle examples/vm-plans/k3s-synthetic-design.json --scenario success --json
slipcage simulate-vm-lifecycle examples/vm-plans/k3s-synthetic-design.json --scenario cleanup_failure --json
slipcage simulate-vm-pair examples/vm-plans/k3s-synthetic-design.json --baseline-scenario success --candidate-scenario timeout --json
~~~

Seven closed scenarios: **success, capacity_blocked, start_failure, runtime_failure, timeout, cancelled, cleanup_failure**. Scenario selection cannot inject a path, QEMU flags, code, network endpoint or callback. The simulator performs zero process launches or host writes.

Even if a cleanup simulation succeeds, **cleanup_verified_on_host is false**. Every result also sets **real_vm_allocated, real_vm_booted, host_storage_modified, guest_network_modified, execution_authorized** to false.

The simulated timeout advances the *model* to the plan deadline. It is **not an OS watchdog** for real processes.

## Synthetic outcomes

| Scenario | Final state | Simulated cleanup | CLI status |
| --- | --- | --- | --- |
| Success | simulated_terminated | Attempted, successful | 0 |
| Capacity blocked | simulated_blocked | No allocation or cleanup | 4 |
| Start/runtime failure | simulated_terminated | Attempted, successful | 4 |
| Timeout/cancellation | simulated_terminated | Attempted, successful | 4 |
| Cleanup failure | simulated_cleanup_unresolved | Attempted, unresolved; review required | 5 |

CLI status 2 means malformed input; the real run/compare/report commands remain unavailable with status 3. Simulated failures are **not real incidents**.

The two-environment simulation only attempts the candidate after the baseline has completed with **no failure and successful simulated teardown**. Failure to start, runtime error, timeout, cancellation, admission block or unresolved cleanup on baseline prevents candidate execution in the model. There is no parallelism, no mutable on-host job record and no separate authorization implied by a scenario named success.

## SC-13b — required real adapter work, separate human approval

The offline control model **does not satisfy** the original SC-13 acceptance gate for real VM start/teardown. Before any live VM boot, guest disk/network change, systemd addition or VPS command, prepare a separate PR with:

1. **Real pinned assets:** verify SHA-256 of exact OS image, QEMU build, guest kernel, K3s binary, CNI and offline OCI image archives. Reject mismatches; forbid mutable backing assets.
2. **Host/provider evidence:** read-only operator-supplied capacity, disk/inode headroom, nested KVM, cgroup configuration, concurrent service load and explicit provider-permitted scope; do not infer these from synthetic examples.
3. **Isolation and networking:** unprivileged QEMU, fixed argv instead of shell, no guest mounts/host secrets, deny metadata/management/provider/public egress. K3s bootstrap and CNI need controlled *guest-internal* networking; current diskless/networkless microguest is not sufficient.
4. **Resource limits:** one guest at a time, measured and enforced CPU/RAM/disk/inode/time budgets, OS-supervised process groups/cgroups and explicit timeout/kill/reap behavior.
5. **Failure reconciliation:** private scratch overlays with exclusive creation; crash cleanup and orphan reconciliation; preserve ambiguous remnants rather than silently deleting evidence or anything in SQLite/backups/reports/guest research data.
6. **Audit:** per-attempt verified provenance, bounded console/resource records, explicit unresolved cleanup state and operator remediation guidance.
7. **Manual validation:** reviewed PR + passing CI, separate owner merge/release decisions, and **separately approved single bounded VM test** on a permitted host. Owner runs all VPS commands and supplies logs; check deployed SHA and real cleanup before claiming production validation.

No live QEMU backend, generic VM run command, new host networking or systemd unit is introduced here. The simulated success case is neither guest readiness nor a security assertion.

See [SC-12 feasibility](K3S_VM_FEASIBILITY.md), [roadmap](V1_ROADMAP.md), [human-controlled workflow](DEVELOPMENT_WORKFLOW.md) and [security policy](../SECURITY.md).

## SC-13b1 — Byte-level preflight added, live lifecycle still absent

A separate development-only, read-only `verify-vm-artifacts` checker now
enforces local SHA-256 equality for five operator-supplied private asset
files. It neither authenticates the upstream source of the bytes nor changes
this state machine into a runnable backend. See
[SC-13b1 asset preflight](VM_ASSET_PREFLIGHT.md). All real disk, QEMU, network,
guest execution and cleanup gates remain unresolved in Issue #25.
