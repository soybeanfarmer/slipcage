# SC-13b7 — Read-only QCOW2 base header and overlay-intent checks

**This is a conservative preflight, not a valid-image certificate or overlay creator.** The new code makes **no disk writes**, opens no KVM device, does not invoke `qemu-img` or QEMU, performs no filesystem mounts, does not traverse an actual overlay/backing chain and does not approve VM execution.

The [QEMU QCOW2 format specification](https://www.qemu.org/docs/master/interop/qcow2.html) defines the big-endian header fields checked here. This module supports **only a deliberately narrow subset**: v3 QCOW2, 64-KiB clusters, a 104-byte standard header followed by an empty extension terminator, unencrypted data, **no embedded backing-file path**, no internal snapshots, no optional/incompatible/compatible/autoclear features, standard refcount order and bounded, nonoverlapping active L1/refcount table offsets. The declared guest virtual size must match the SC-12 disk budget exactly.

These checks do not parse L1/L2/refcount *contents*, validate cluster allocations, identify malicious guest files, verify base immutability or establish software publisher authenticity. A maliciously constructed base can pass header-shape checks; an untrusted SHA-256 declaration authenticates nothing. **Never boot or mount an image merely because this check passes.**

## Developer-only command

With an existing private asset directory containing the five exact SC-13b1 files, a nonsynthetic operator-declared SC-12 plan whose hashes match their bytes, and a previously completed, non-quarantined SC-13b6 staging reservation bound to that same plan:

~~~bash
slipcage inspect-vm-backing /path/to/operator-plan.json \
  --assets-dir /path/to/private-assets \
  --reservation-root /path/to/existing-private-reservation-root --json
~~~

The CLI first calls SC-13b1 `verify_local_vm_assets`, then read-only SC-13b6 `inspect_local_reservation`. It reopens the existing `os-image.qcow2` safely (fixed basename, directory-relative, no-follow, private single-link regular file) and hashes the **entire file on the same opened descriptor as the header check**. Its SHA-256 must equal the declared base-image hash. The source directory must be private and contain the exact five known asset files. The code attempts to detect ordinary in-flight modification/replacement, but does **not** protect against a malicious same-UID writer or untrusted ancestor path.

The reservation must belong to the same plan ID and digest, have the fixed literal overlay name `overlay.qcow2`, and match declared disk/time budgets. A quarantined, forged, missing or incomplete reservation fails closed. The output contains only fixed filename **tokens**, not resolved host paths or QEMU arguments.

**No actual overlay is created.** The intended overlay's eventual backing relationship is described only by the base digest and plan/reservation fingerprints, not by creating or traversing a chain. The operator must **not** try to execute the JSON, infer valid guest boot capability or run `qemu-img create` based on it.

## Positive reports are intentionally limited

A passing response proves only: (a) local asset bytes matched operator-supplied digests when read, (b) the QCOW2 base header matches a conservative subset of structure, and (c) the existing stage record matched the plan at inspection time.

Regardless of input, a positive report explicitly retains:

- `overlay_create_command_present: false`, `overlay_created: false`, `backing_chain_created: false`, `backing_chain_traversed: false`;
- `qcow2_refcount_l1_l2_integrity_verified: false`, `actual_backing_file_resolution_verified: false`, `immutable_base_enforced: false`;
- `host_disk_quota_enforced: false`, `host_kvm_usable_verified: false`, `software_publisher_authenticated: false`;
- `qemu_or_qemu_img_executed: false`, `guest_boot_verified: false`, `cleanup_verified_on_host: false`, `execution_authorized: false`, `host_modified: false`.

Exit 0 means *offline preflight consistency*, not authorization or boot readiness. Exit 2 means invalid/unsafe data. The real `run`, `compare`, and `report` commands are still disabled (exit 3).

## CI scope and next actual-image gates

Tests generate **tiny, synthetic QCOW2 header-shaped byte arrays** in temporary directories. Their table contents do not establish valid or bootable images; they are intentionally never passed to QEMU. The tests cover nonzero backing path/length, wrong virtual size, encryption, snapshots, feature flags, unsafe metadata pointers, mismatched SHA-256, symlinks/hardlinks, corrupt/quarantined reservations, and zero process/network/disk-overlay execution.

To progress beyond SC-13b7, [Issue #23](https://github.com/soybeanfarmer/slipcage/issues/23) still requires independently authenticated upstream artifacts, actual base-image content and complete QEMU QCOW2 consistency validation (using **separately approved** read-only tooling), effective filesystem read-only controls and a checked backing chain with explicit format and path containment. [Issue #25](https://github.com/soybeanfarmer/slipcage/issues/25) still requires a reviewed bounded, **actual** overlay lifecycle (exclusive private creation, quotas, backed by immutable trusted parents, conservative crash cleanup), host-wide lease/fencing, process/cgroup watchdog, guest network isolation, and a separately authorized single benign VM test. CI does not verify VPS behavior.

**No QEMU launch, guest data, overlay, VPS access, production service change, release or deployment is authorized by this PR.**
