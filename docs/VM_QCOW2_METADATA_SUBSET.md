# SC-13b16 — Small QCOW2 v3 metadata-graph inspection (read-only)

**Limited subset only. Not a general QCOW2 validator, not source authentication, and not proof that an OS image can be safely booted.**

The existing SC-13b7 `inspect-vm-backing` checked a fixed QCOW2 v3 **header shape** and SHA-256 but expressly did not parse metadata tables. SC-13b16 adds a **separate opt-in, read-only, strictly bounded** checker for simple *small* base images that traverses active L1/L2 pointers and compares the allocation graph to the 16-bit refcount table.

This deliberately rejects most real populated OS images. A negative result means **unsupported or inconsistent with this narrow subset**; a positive result means only local structural consistency for this subset. It neither validates arbitrary QEMU QCOW2 images nor removes Issue #23 host/artifact acceptance requirements.

## Existing local input

~~~bash
slipcage inspect-vm-qcow2-metadata /private/operator-plan.json \
  --assets-dir /private/existing-five-assets --json
~~~

Requires a strict nonsynthetic SC-12 plan and the existing SC-13b1 private asset directory with all **five** pinned files. This tool first rehashes all five against the operator-declared digests. It then opens the `os-image.qcow2` **read-only, no-follow** under the private directory and verifies the image's pinned SHA-256 again while inspecting it. It never writes to the QCOW2 file or any other file.

The supported subset is intentionally restrictive:

- **QCOW2 v3**, fixed 64-KiB clusters, 16-bit refcounts, no encryption, internal snapshots, backing paths, header extensions, dirty/external features, compressed mappings or extended-L2 entries.
- Physical file **cluster aligned, 4 clusters to 64 MiB maximum**; the pinned *virtual* disk budget still follows the SC-12 plan (for example 24 GiB). One L1 cluster, one refcount-table cluster, one refcount block; **no extra blocks**.
- L1 table length must cover the entire declared virtual disk. Pointers must be aligned, in bounds, nonoverlapping, singly owned, and have the expected "copied" bit for the narrow subset.
- At most **16 allocated L2 clusters** and **960 allocated guest-data clusters**. Supports unmapped holes but rejects zero/compressed descriptors and shared-COW mappings. Every physical cluster must belong exactly once to the reachable header/metadata/data allocation graph.
- Every single 16-bit refcount must exactly match that graph (1 if allocated, 0 otherwise), including unused entries. Extra refcount references, orphan clusters, aliases and map entries past virtual disk bounds fail closed.

These rules implement a **small, read-only consistency subset** informed by the official [QEMU qcow2 format specification](https://www.qemu.org/docs/master/interop/qcow2.html). Real images may be perfectly valid but use features, multiple refcount blocks, sparse layouts, compressed clusters or sizes not supported here. In particular, a 20-GiB QCOW2 base can satisfy SC-13b7 but **cannot** pass the SC-13b16 64-MiB cap.

## Result semantics and exit codes

Successful bounded inspection returns **0** with `status:small_subset_locally_consistent_not_guest_verified`, the pinned base SHA-256, physical/virtual byte counts, L1 count, L2 count and mapped cluster count. This status is deliberately **not** an execution readiness status. Unsupported, corrupt, truncated, symlinked, unpinned or nonprivate data returns **2** and no successful report.

Every successful report explicitly states:

- `l1_l2_refcount_graph_consistent_for_narrow_subset:true`
- `whole_qcow2_format_support_claimed:false`
- `source_publisher_authenticated:false`
- `real_os_image_contents_authenticated:false`
- `qcow2_backing_chain_traversed:false`
- `base_immutability_enforced:false`
- `qemu_img_executed:false`, `qemu_executed:false`, `guest_boot_verified:false`
- `execution_authorized:false`, `host_modified:false`, `overlay_created:false`

This command is **separate from the SC-13b12 launch dossier**. The dossier's prior header-only check remains unchanged and its outcome **always stays blocked (exit 5)**. An SC-13b16 success is not silently promoted to a dossier success or used as permission to create a guest overlay.

## Test boundary and future gates

The 22 CI tests construct only **hand-built nonbootable QCOW2-like fixtures** (4–7 clusters), with invented guest-data strings, tiny fake other assets, and synthetic-to-operator-*shaped* plans. Tests verify exact local metadata relationships, invalid refcounts, orphan/unmapped clusters, duplicates, flags, resource caps, bad headers, private file modes, unchanged backup fixtures, CLI status, and disabled `run`/`compare`/`report`.

The parser relies on trusted operator-controlled ancestors and absence of malicious same-UID concurrent filesystem replacement; hash/descriptor checks are not an atomic host snapshot or tamper-proof remote attestation. It does not inspect the semantic safety, executability or patch state of guest contents. It is not an independent replacement for a mature QCOW2 implementation such as `qemu-img check`, and **does not invoke `qemu-img`**.

Issue [#23](https://github.com/soybeanfarmer/slipcage/issues/23) remains open for genuine publisher-vetted OS/kernel/K3s/CNI/image bytes and signatures, full real QCOW2 backing/metadata verification by approved tools, actual owner-approved provider/VPS/KVM and quota measurements. Issue [#25](https://github.com/soybeanfarmer/slipcage/issues/25) still blocks any real host-global lease, disk overlay, runtime supervision, guest isolation, boot and crash-cleanup validation until separately approved.

**No release, VPS inspection or mutation, SSH, download, archive extraction, QEMU/qemu-img/KVM call, disk creation, or guest boot is performed by SC-13b16.**

## SC-13b17 — External QEMU check reports remain untrusted operator claims

The separate [SC-13b17 JSON report reviewer](VM_QCOW2_EXTERNAL_EVIDENCE.md) may reconcile an operator-supplied `qemu-img info`/`check` transcript to a pinned local base even when the image is larger than this parser's 64-MiB subset. It does **not** run QEMU tools, attest that a check occurred or establish full QCOW2 validity. Both commands remain non-executing and do not permit guest launch.
