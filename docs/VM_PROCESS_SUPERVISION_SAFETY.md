# SC-13b11 — Process-supervision safety contract (fake processes only)

**Development-only safety specification. It does not start, inspect, signal, kill, wait for, or reap real processes.** It does not create QEMU disks/overlays, open KVM, manage systemd or cgroups, inspect the VPS, or grant permission to run a VM.

This milestone advances from SC-13b10's persisted **offline** attempt identity to an explicit bounded *process-event reducer* that describes the future QEMU supervisor's required behavior when presented with synthetic process observations. Its inputs are fabricated for the tests, and its outputs are textual **signal intents**, **not real signals**.

## Offline CLI

The operator/developer must supply a nonsynthetic SC-12 VM design, an existing private five-file asset directory whose bytes match the plan declarations (SC-13b1), and a separately staged, **outstanding** SC-13b10 offline-intent journal for that *exact* plan:

~~~bash
slipcage simulate-vm-process-supervision /private/test-plan.json \
  --assets-dir /private/test-assets \
  --journal-root /private/previously-staged-offline-journal \
  --scenario pid_reuse --json
~~~

This command hashes local assets, reads the offline journal under its existing short-lived local advisory lock, then performs pure in-memory simulation against a **fake** PID 42420, fake start-tick 314159 and fake process group. It never reads /proc, checks live PIDs, creates a new journal generation, locks a guest process, or performs any signal/kill/reap syscall. The real `run`, `compare` and `report` commands remain disabled (exit 3).

Available allowlisted scenarios: `success`, `deadline`, `memory_pressure`, `task_pressure`, `overlay_pressure`, `cancellation`, `unreaped`, `kill_timeout`, `pid_reuse`, `unexpected_exit`.

A real launcher does **not** exist. For legitimate live process supervision, the code would have to bind an actual pidfd/process start identity, verified cgroup and OS-managed child process, generation-fenced host-global lease, bounded watchdog, signal/kill/reap, audited cleanup and owner permission. This milestone implements none of those host mechanisms.

## Policy and state transitions

SC-13b11 inherits bounded guest sizing from SC-12 and SC-13b5, **not actual OS-enforced quotas**. The synthetic example yields 2 vCPU / proposed 200% CPU quota, 4096 MiB guest RAM with proposed 4608 MiB MemoryMax, proposed 256 TasksMax, a declared 24-GiB disk limit, a declared 900-second guest runtime deadline, 15 seconds for graceful TERM and a further 10 seconds for KILL/reap grace.

The proposed **one host guest slot**, `slipcage-vm-host-slot-v1`, is only a fixed policy token. It is not acquired, shared between deployed service instances, or associated with a QEMU process. Host-global execution fencing remains unavailable.

The fake process model recognizes:

| State | Meaning |
| --- | --- |
| `observing` | Fake process identity and resource observations are bounded and matched |
| `term_requested` | Text-only SIGTERM intent after cancellation, resource breach or deadline |
| `kill_requested` | Text-only SIGKILL intent after TERM grace expired with fake process still alive |
| `simulated_reaped` | Fabricated observation reports reaped child and empty cgroup; **no real cleanup proved** |
| `quarantined` | Fake PID/start time/group mismatch, unexpected/unreaped exit, or KILL/reap timeout; no automatic clearance |

Each update requires the exact expected revision and a strictly increasing nonnegative observed elapsed time. No more than 24 fake observations are accepted. Boolean/int-type confusion, contradictory alive+reaped inputs, oversized counters and terminal-state reuse are rejected. A mismatched PID, start-tick or process group transitions directly to quarantine with **no signal intent**; the intended real adapter must never signal a reused or unrelated PID. A process that has disappeared without reliable simulated reaping cannot be declared clean. In quarantine, no additional transitions or candidate execution are allowed.

The CLI returns 0 for a *completed fake scenario*, 5 for quarantined fake state, or 2 for invalid input. **Code 0 is strictly a successful synthetic state simulation**, not VM readiness, runtime permission or real process completion.

Every report says `observations_are_injected_fake_data: true`, and explicitly sets `shared_host_guest_lock_held: false`, `actual_signals_sent: false`, `real_reaping_performed: false`, `os_cgroup_or_disk_quota_enforced: false`, `actual_process_termination_verified: false`, `execution_authorized: false` and `vm_launched: false`. The SC-13b10 offline file lock is **not** held for the simulation's duration or for any guest. A caller-supplied fake observation cannot be promoted into trusted host evidence.

## Tests and future human gates

20 new tests use tiny, entirely synthetic files and simulated observations under ephemeral local CI roots. They prove the reducer's bounded control-flow decisions, not a running watchdog or QEMU teardown. No guest processes, qemu-img, overlay, provider calls, VPS access, release or deployment are involved.

Real runtime gates remain: independent trusted provenance and owner-approved VPS resource/KVM/provider evidence ([Issue #23](https://github.com/soybeanfarmer/slipcage/issues/23)); and a separately reviewed genuine OS-backed, single-guest QEMU adapter with fixed allowlisted argv, immutable-backed private overlay, cgroup+filesystem quotas, pidfd/group-aware watchdog/reaping, failure-preserving cleanup, isolation, host-global generation fencing and a **separately authorized bounded live guest test** ([Issue #25](https://github.com/soybeanfarmer/slipcage/issues/25)).

**No release publication, VM execution or change to VPS/production systems is authorized by this PR.**

## SC-13b12 — Cross-checked prelaunch dossier, never an execution gate

The new [SC-13b12 prerequisite review](VM_LAUNCH_PREREQUISITES.md) ties the exact offline plan/assets/provenance/host snapshot/reservation/base-header/attempt identity together and lists outstanding runtime blockers. Its **success is always blocked** (exit 5); it never treats the fake-process supervisor or caller-supplied keys/host facts as proof that QEMU may execute.
