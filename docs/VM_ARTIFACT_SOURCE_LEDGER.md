# SC-13b15 — Five-artifact source custody ledger (offline, untrusted)

**Operator source evidence is unverified, even when every digest and receipt matches.** This milestone makes missing, reordered, or conflicting source references *visible and mechanically rejectable*. It does **not** prove who published an OS image, kernel, K3s binary, CNI archive, or container image tar; and it cannot authorize guest execution.

## Inputs, never fetched or executed

The human operator prepares **existing local** inputs in a development workspace:

- A non-synthetic, strictly validated SC-12 VM plan, with all five declared SHA-256 pins;
- An existing private (0700) SC-13b1 asset directory containing exactly five bytes-on-disk assets with private file modes;
- One existing private (0600), bounded canonical `ledger.json`;
- A separate existing private (0700) receipt directory containing exactly five fixed private 0600 receipt files.

Each of the five ledger entries must appear **in the exact SC-13b1 asset order** and must have:
`digest_field`, `artifact_sha256`, `source_uri`, `version_ref`, `receipt_sha256`.
The root has exact fields `api_version`, `kind`, `plan_digest_sha256`, `operator_assertion`, `artifacts`.

The `operator_assertion` value must literally be `source_reference_recorded_unverified`. The receipt itself is a separate compact canonical JSON document with exact fields `api_version`, `digest_field`, `artifact_sha256`, `source_uri`, `version_ref`, `observation`; `observation` must literally be `operator_supplied_unverified`. Each receipt's SHA-256 must equal the ledger entry's corresponding `receipt_sha256`.

| SC-13b1 digest field | Required existing receipt basename | Source URI requirement |
| --- | --- | --- |
| `os_image_sha256` | `os-image.source.json` | Bounded, well-formed HTTPS DNS URL with no credentials/query/fragment |
| `kernel_sha256` | `kernel.source.json` | Same bounded HTTPS DNS-only URL shape |
| `k3s_binary_sha256` | `k3s.source.json` | Exact `https://github.com/k3s-io/k3s/releases/download/<encoded-plan-tag>/k3s` URL shape |
| `cni_assets_sha256` | `cni.source.json` | Bounded HTTPS DNS-only URL shape |
| `container_images_sha256` | `container-images.source.json` | Exact K3s release URL ending `k3s-airgap-images-amd64.tar` for **the same plan tag** |

In the two K3s cases, `<encoded-plan-tag>` is the URL-percent-encoded `software.k3s_version` from the plan (for example the `+` becomes `%2B`), and `version_ref` must equal that exact raw tag. For OS/kernel/CNI, `version_ref` is a bounded *operator-supplied unverified label*, not an authenticated release ID. **The URI shape check does not fetch the URL, prove it exists, or authenticate GitHub or the actual publisher.** None of these reference strings may contain local private filesystem paths, credentials, query tokens or fragments. Avoid placing private infrastructure identifiers in source URLs.

A valid positive local check means: all five bytes-on-disk asset hashes matched plan pins; the five ledger entries matched the plan and the narrow URI shapes; and five separate private receipt files' exact SHA-256 and metadata matched the ledger. A malicious operator who prepares both the ledger and receipts can trivially forge a coherent record. **SHA-256 ensures local consistency, not independent custody or a chain of trust.**

## Developer CLI

~~~bash
slipcage review-vm-artifact-sources /private/operator-plan.json \
  --assets-dir /private/five-assets \
  --ledger /private/source-ledger.json \
  --receipts-dir /private/source-receipts --json
~~~

A coherent ledger returns a compact report with `status: operator_source_authentication_pending` and exit **5**, not a launch authorization. Invalid input (wrong hashes, unsafe modes, symlinks/hardlinks, missing/extra receipts, changed files, bogus fields or URI/version mismatch) returns **2** and no success report. The positive report contains only source-document fingerprints, plan identity and fixed bounded status fields. It exposes no source URLs, arbitrary receipt content, private paths or host identifiers.

All outputs retain `publisher_origin_authenticated:false`, `receipt_authenticity_independently_verified:false`, `release_version_resolved_from_upstream:false`, `source_url_retrieved_or_validated_online:false`, `artifact_contents_or_build_reproducibility_verified:false`, `guest_image_and_cni_provenance_authenticated:false`, `execution_authorized:false`, `vm_launched:false`.

The command is **read-only**. It never downloads, unpacks, mounts or executes artifacts; never inspects a live host; never opens KVM; and never writes an overlay, guest filesystem, network, cgroup, systemd service or release.

## Optional SC-13b12 launch dossier gate

`slipcage review-vm-launch-gates` accepts both `--artifact-source-ledger FILE` and `--artifact-source-receipts DIR` together. It reruns the same five-byte/receipt checks and attaches the ledger SHA-256, `artifact_source_receipts_checked:true`, and `artifact_source_origin_authenticated:false` to the existing cross-checked dossier. A corrupt or mismatched ledger fails exit **2**; even perfect local receipts produce dossier **exit 5, blocked**. Without the optional pair the dossier marks the source-receipt check `false`, never implies provenance.

This new optional check does not replace the human-verified signing-key pin gate (SC-13b13) or K3s upstream-style checksum checks (SC-13b14), both of which also require **genuine independent source authentication** by an operator.

## Scope limits, tests and remaining human approvals

CI invents five tiny byte strings, a fake nonsynthetic-shaped SC-12 plan, artificial HTTPS source references and ephemeral receipt files. Negative tests exercise missing/reordered/forged entries, tampered receipts, unsafe/private modes, symlinks/hardlinks, unexpected entries, wrong release URLs/versions, credential-bearing sources, plan hash changes and immutable VM launch blockage. CI fixture cleanup is limited to test-created temporary directories.

The receipt paths are individually read via open file descriptors with no-follow and conservative inode checks; the caller must control parent directories, the filesystem and other same-UID writers. This is not a secure multi-party source attestation and not an atomic snapshot across the plan/assets/ledger/receipts.

**Issue [#23](https://github.com/soybeanfarmer/slipcage/issues/23) remains open:** the owner must independently source and vet **real** five-asset publisher/manufacturer provenance, attest actual local bytes and versions, approve read-only VPS/KVM/provider measurements, and review discrepancies. **Issue [#25](https://github.com/soybeanfarmer/slipcage/issues/25) remains open:** a true single-guest lease, resource-supervised QEMU adapter, bounded immutable-backed overlay, host isolation and independently authorized live test are not implemented/approved.

No PR merge, release, SSH, VPS inspection, QEMU, image acquisition, disk changes, or guest boot is performed or authorized by this development slice.
