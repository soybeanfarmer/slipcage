# SC-13b9 — Scoped OS-backed local review lock, not a VM lease

**Status:** Development-only OS primitive for cooperating **recovery reviewers**. It does not launch, isolate, lock, stop, reap, or clean up a VM. It creates **one empty persistent 0600 local lockfile** when first invoked under an existing operator-selected private directory. This is a deliberately narrow improvement over the purely simulated single-owner model, **not full SC-13 runtime fencing**.

## Interface and trust scope

~~~bash
slipcage review-vm-overlay-locked /private/operator-controlled-staging-root --json
~~~

The path must already exist, be a trusted nonsymlink private 0700 directory on a **local POSIX filesystem**, and contain only the optional fixed `vm-reservation-v1/` slot and optional `.vm-overlay-review.lock` file. The command makes **no** new staging slot, overlay, guest disk or host settings.

At most one cooperating process that chooses the *same existing root and lock inode* can inspect at a time, using `fcntl.flock(LOCK_EX|LOCK_NB)`. The lockfile is always a zero-length, private 0600 single-link regular file, and it is never truncated or removed. If absent, it is created exclusively with `O_CREAT|O_EXCL|O_NOFOLLOW`; the containing directory is fsynced. Existing symlinks, hardlinks, unusual nodes, unexpected root entries, changed inode or permissions fail closed. The exclusive kernel lock is held while the existing SC-13b8 read-only overlay recovery assessor examines the slot, then **released before the CLI returns**.

GitHub CI uses two separate ordinary Linux processes to verify that the second cannot acquire a held lock, and tests release after deliberate test-only abrupt child exit. These subprocesses are **test harnesses only**; no guest or QEMU process is ever started.

## Response and exits

The canonical JSON wraps SC-13b8's recovery classification and explicitly reports:

- `same_root_kernel_advisory_flock_acquired_during_review: true` only after actual acquisition.
- `lockfile_persisted_for_future_review: true`, `lock_held_after_command: false`.
- `host_global_vm_lease_enforced: false`, `guest_process_bound_to_lock: false`, `interprocess_execution_fencing_implemented: false`.
- `lock_release_proves_vm_cleanup: false`, `real_guest_cleanup_verified: false`, `automatic_cleanup_permitted: false`.
- `backing_chain_validated: false`, `overlay_created/deleted: false`, `execution_authorized: false`, `vm_launched: false`.

An intact staged record with no observed overlay returns **0 for local review only**. Missing/incomplete/corrupt/quarantined slots, unexpected overlay remnants and a busy lock all return **5, unresolved**. Invalid or unsafe root/lock paths return **2** with no successful JSON. The existing unlocked `review-vm-overlay` is unchanged and still strictly read-only. The locked command may create the one empty private lockfile, so it is *not* strictly read-only to the local root.

Do **not** treat exit 0, a lockfile on disk, or a lock released by process death as permission to reuse a VM, erase an overlay or schedule a candidate guest. A valid reservation record is a persisted intent; its hash is not authenticated against a hostile same-UID writer. A point-in-time absence of an overlay says nothing about guest process state.

## Boundaries that still matter

- **Same-root only:** two different roots can each obtain a lock. There is no host-global guest quota or unique lock namespace across service instances.
- **Volatile ownership:** POSIX advisory `flock` protects an open file description only while the holding process or inheriting descriptors retain it. An abrupt exit can release it even while a VM process, orphan or overlay persists. This command never starts guests and cannot bind a future QEMU process to the lease.
- **Trusted environment:** only a trusted local filesystem and controlled root/ancestors; no assurance about NFS/distributed behavior, same-UID adversarial inode replacement, unrelated noncooperating processes or fork-inherited descriptors.
- **No real overlay lifecycle:** a proposed overlay budget from SC-13b5/13b6 is *not* an enforced disk quota; this lock neither creates a QCOW2 overlay nor verifies its backing chain, actual base immutability or host cleanup.
- **No operator authorization:** no VPS SSH, host inventory collection, KVM probing, systemd/cgroup operations, launch, network change, production deployment, release or real guest execution is performed by this PR or CI.

## Required before genuine disposable VM execution

[Issue #23](https://github.com/soybeanfarmer/slipcage/issues/23) still requires independently authenticated image/QEMU/K3s artifacts, full QCOW2 content/chain verification, current owner-approved host resource/KVM and provider-permission evidence. [Issue #25](https://github.com/soybeanfarmer/slipcage/issues/25) still requires a **genuinely host-global** exclusive guest lease with *durable attempt ID + monotonic fencing generation*, private newly created overlay linked to an immutable trusted parent, OS-enforced quotas/watchdog/process-group kill and reap, conservative orphan reconciliation and guest network isolation. Those need separate source review and owner authorization for **one** bounded live benign test.

**Never run this lock-creating CLI on existing VPS or production data directories without independent explicit operator approval.** CI uses ephemeral disposable directories only. Green CI verifies the Linux kernel flock API in GitHub's runner environment, **not** the target VPS or QEMU.

## SC-13b10 — Separate local append-only intent ledger

The [SC-13b10 offline fencing journal](VM_OFFLINE_FENCING_JOURNAL.md) now uses a **separate** operator-controlled private directory and advisory lock to serialize hash-linked, monotonic **non-executing** attempt records. It cannot be mistaken for a real guest-process lease or proof of live cleanup; the SC-13b9 recovery inspection lock stays scoped to its original root and is unchanged.
