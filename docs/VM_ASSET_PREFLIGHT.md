# SC-13b1 — Read-only VM asset byte verification

**Status: offline code and CI only. No QEMU backend, guest boot or host deployment is authorized.**

This focused SC-13b preparation adds a **read-only local SHA-256 verifier** for asset bytes declared by the SC-12 VM plan. It is useful because the SC-12 plan only checked that digests *looked like* SHA-256 strings, whereas SC-13b1 checks that five locally available regular files actually have the declared contents.

**Crucial:** Matching an operator-provided hash is *not* trustworthy software provenance. A forged OS image can carry an internally consistent hash. These checks do not attest publishers, verify image contents or the actual guest kernel, validate a K3s release signature, prove KVM availability, enforce disk limits, grant provider permission or authorize any workload.

## Interface and fixed layout

This developer tool is **not installed on the VPS by Ansible**:

~~~bash
slipcage verify-vm-artifacts /path/to/operator-supplied-plan.json \
  --directory /path/to/operator-controlled-private-asset-dir --json
~~~

The input plan must use `provenance.pin_status: operator_supplied_unverified`. The included SC-12 `k3s-synthetic-design.json` example is explicitly rejected and **must not be treated as an actual image lockfile**.

The asset root must already exist, be a nonsymlink private directory (0700), and contain exactly these five single-link, private (0600) regular files:

| SC-12 digest field | Required filename | Maximum bytes |
| --- | --- | --- |
| `os_image_sha256` | `os-image.qcow2` | 20 GiB |
| `kernel_sha256` | `kernel.bin` | 512 MiB |
| `k3s_binary_sha256` | `k3s.bin` | 512 MiB |
| `cni_assets_sha256` | `cni-assets.tar` | 1 GiB |
| `container_images_sha256` | `container-images.tar` | 16 GiB |

These names **do not imply a format safety check**: the code only streams the bytes through SHA-256 in bounded 1 MiB chunks. It never opens image formats as a VM, mounts QEMU disks, parses archive members, extracts tar archives, downloads files, follows last-component symlinks, modifies files, or invokes external processes.

Missing files, unexpected entries, group/world-readable files, hardlinks, symlinks, oversized files, inconsistent digests and straightforward concurrent file replacements fail closed. The verifier requires an **operator-controlled directory and trusted ancestor paths**; this is not a multi-tenant storage mechanism and does not defeat a malicious process with the same UID racing filesystem changes.

## Verification output and trust boundaries

A successful status is `local_bytes_match_untrusted_pin_declarations`. It includes canonical stable JSON with plan ID/digest, exact names, byte counts and SHA-256 of each local file.

The flags remain explicitly false:

- `software_origin_authenticated`
- `image_contents_security_reviewed`
- `host_kvm_verified`
- `provider_permission_verified`
- `host_capacity_verified`
- `guest_network_isolation_verified`
- `guest_boot_verified`
- `execution_authorized`, `host_modified`, `vm_launched`

Exit code 0 means **local bytes matched declared operator pins** only. Exit code 2 means a malformed/unreadable/mismatched input; it prints no successful JSON. A hash mismatch is not an approval to redownload, overwrite, repair, rename, or remove any files. The tool never changes the file tree.

CI creates five **tiny invented test byte strings** in its ephemeral scratch directory and verifies they match a dynamically constructed unverified plan. This exercises the hashing and refusal paths; it is not testing an actual OS image, K3s distribution or QEMU binary.

## Remaining real-VM approval gates

The separate [SC-12 real asset/host verification issue #23](https://github.com/soybeanfarmer/slipcage/issues/23) and [SC-13 real lifecycle issue #25](https://github.com/soybeanfarmer/slipcage/issues/25) remain open. Before authorizing a disposable VM:

1. Select trusted actual software releases and repositories; authenticate distributor releases/signatures and obtain **exact content hashes independently** rather than trusting arbitrary strings in a self-authored plan.
2. Validate actual OS image format, immutable backing chain and dependencies, guest kernel/module compatibility, K3s binary and OCI/CNI image contents.
3. Obtain current read-only VPS capacity, inode/disk budgets, cgroup restrictions, actual nested KVM capability and provider authorization.
4. Review a separate real QEMU adapter PR with allowlisted argv, no host mount/credentials, preloaded guest assets, isolation from host/public/provider networks, one VM at a time and strict cgroup/process/disk/time limits.
5. Define durable per-attempt state, crash reconciliation and conservative cleanup. Never touch existing Slipcage reports/SQLite/backups or unowned guest evidence.
6. Obtain explicit owner approval for a bounded single-VM runtime test. Owner publishes any release and runs VPS commands; captured deployed SHA, journals and resource/cleanup logs are reviewed separately.

**SC-13 is still not fully accepted.** The only work in this PR is local byte matching and fail-closed tests; no real executable adapter, host changes or guest test is present.

## SC-13b2 linked provenance and host evidence

The separate read-only signed-statement and operator-snapshot gates now have strict CLI interfaces. They do **not** independently authenticate upstream publisher keys or verify live host facts. [See SC-13b2 implementation and outstanding security gates](VM_PROVENANCE_HOST_GATE.md). Real QEMU and VPS tests remain separately owner-approved work.
