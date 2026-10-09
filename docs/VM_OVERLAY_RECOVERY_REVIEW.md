# SC-13b8 — Read-only overlay and reservation recovery triage

**Scope:** This is a fault-injection and **read-only inspection** milestone. It cannot create, modify, mount, parse, delete or repair a QCOW2 overlay; cannot clear any quarantine, start/stop/reap QEMU, inspect a process list, establish a host-global lock, or authorize VM execution.

SC-13b6 introduced a single-use private local staging record under one operator-controlled scratch root; SC-13b7 can inspect a narrow base QCOW2 header. The SC-13b8 recovery review intentionally **does not rely on a perfect staging record**: interrupted writes, corrupt manifests, quarantine markers and suspicious overlay remnants must still be recognizable and preserved rather than being treated as clean.

## Read-only operator interface

~~~bash
slipcage review-vm-overlay /private/existing-staging-root --json
~~~

This reads ONLY an existing operator-controlled private (0700) directory and the fixed `vm-reservation-v1` child. Both directories must be nonsymlink private directories; trust in root ancestors and other same-UID processes is outside the protection scope. The tool never allocates an overlay or creates its parent. It scans at most 16 directory entries and never prints arbitrary on-disk names, scratch paths or symlink targets.

If an `overlay.qcow2` entry exists in the fixed staging slot, the tool uses **no-follow stat only** to classify it as regular, symlink, directory or other; for regular files it reports the stat size. It deliberately does not open the data or assert that it is a real/valid QCOW2 disk. It preserves **all** file types, including suspicious symlinks and unknown directories. A file might appear/disappear during the scan: absence at scan time is not proof of process cleanup or that there is no live guest.

The command also reuses strict fd-based SC-13b6 verification only when the fixed allowlisted staging files are present, canonical, private and integrity-consistent. A missing, partial or forged manifest cannot imply a clean reservation. No recovery attempt is made. No automatic cleanup or owner-clearance API exists.

## Classifications and exit codes

| Classification | Meaning | Exit |
| --- | --- | --- |
| `verified_staging_record_no_overlay` | SC-13b6 intent verified; no overlay node observed **at scan time** | 0 |
| `no_staging_slot` | No fixed slot observed, **not** proof of safety | 5 |
| `incomplete_staging_preserve` | Interrupted/incomplete publication; keep evidence | 5 |
| `invalid_record_preserve` | Invalid canonical JSON, private mode, checksum or quarantine contents | 5 |
| `unknown_entries_preserve` | Non-allowlisted or excessive entries, never traverse/remove them | 5 |
| `unexpected_overlay_node_preserve` | Fixed overlay filename observed (regular/symlink/directory/other); highest-priority preservation flag | 5 |
| `quarantined_preserve` | Valid permanent quarantine; must not be automatically cleared | 5 |

An unsafe root/slot (e.g. symlink or non-private directory) is an **invalid input** (exit 2), not a classification claiming any contents were verified. Exit 0 certifies only a **point-in-time non-mutating staging inspection**. Even then manual preservation/review is required before real VM activity.

Every output states `manual_preservation_and_operator_review_required: true`, `automatic_cleanup_permitted: false`, `automatic_recovery_attempted: false`, `overlay_bytes_opened_or_read: false`, `overlay_deleted: false`, `reservation_removed: false`, `quarantine_cleared: false`, `real_guest_cleanup_verified: false`, `host_wide_guest_lock_held: false`, `execution_authorized: false`, and `host_modified: false`. The scan is informational only; do not use these classifications as permission to run a guest or remove any file.

## Test and threat boundaries

The 17 unit tests use **temporary developer/CI-only directories**, artificial private reservation records, and tiny invented overlay-named files. These are **not QCOW2 images**, are never booted or attached to QEMU, and are deleted only by the **test harness** when its own temporary fixture directory is disposed. Product code never deletes anything. Cases include:

- valid/absent staging, interrupted record and truncated manifest;
- valid quarantine and quarantine plus an unexpected overlay remnant;
- unexpected overlay regular files, symlinks, directories and unknown file entries;
- unsafe root or child directory, bounded directory scanning, deterministic path-free JSON;
- invariant checks that no subprocess, socket, mkdir/unlink/remove or guest operation runs.

CI execution is not VPS host observation, live KVM verification, software-publisher attestation, systemd supervision, or actual overlay/crash recovery.

## Required real overlay lifecycle work (separate approval)

The next actual SC-13 implementation still needs owner-verified upstream release signatures/image contents, host capacity and provider policy (Issue [#23](https://github.com/soybeanfarmer/slipcage/issues/23)), plus a separately reviewed, OS-backed host-global lease, exclusively created QCOW2 overlay with immutable trusted base, filesystem/cgroup budgets, watchdog/process-group kill and reap, guest network isolation, crash reconciliation and an owner-authorized bounded live VM test (Issue [#25](https://github.com/soybeanfarmer/slipcage/issues/25)).

**Do not run this command on production VPS paths without separate operator approval.** Do not manually remove a directory because a CLI reports `verified_staging_record_no_overlay`. Green GitHub CI never establishes real host cleanup or authorizes a QEMU/K3s launch.

## SC-13b9 — Optional Linux flock for cooperating reviewers

A separate [scoped local review-lock command](VM_LOCAL_REVIEW_LOCK.md) now takes a kernel advisory lock around this read-only scan (with an empty persistent local lockfile). This does **not** make recovery automatic, prove host cleanup, fence VM processes or establish a host-global guest lock. All preservation classifications and operator review gates are unchanged.
