# SC-13b14 — K3s upstream-style release checksums and local byte reconciliation

**Not upstream trust, an artifact downloader, guest readiness, or execution authorization.** This is a read-only operator-supplied *release-checksum consistency* step for a pinned **stable K3s amd64** version. It adds a more meaningful check than matching an artifact against its **own** operator-declared plan hash, but only if the human operator has separately established the checksum files' actual provenance.

K3s provides versioned releases at [k3s-io/k3s releases](https://github.com/k3s-io/k3s/releases), with binary checksum file `sha256sum-amd64.txt`. The upstream [installer](https://github.com/k3s-io/k3s/blob/main/install.sh) retrieves the binary checksum from the matching version's release and verifies the downloaded `k3s` against it. Its [air-gap packaging script](https://github.com/k3s-io/k3s/blob/main/scripts/package-airgap) emits a separate `k3s-airgap-images-amd64.sha256sum` containing the tar, tar.gz and tar.zst digests. The [official air-gap instructions](https://docs.k3s.io/installation/airgap) require binary and air-gap images from the **same release**.

**Do not use `curl | sh`, run the K3s installer, download assets to the VPS, unpack OCI images, import into containerd, or execute a binary** to perform this milestone. File acquisition/provenance review is an independent human change gate.

## Existing local inputs

The operator provides:
1. A previously validated nonsynthetic SC-12 plan with `software.k3s_version` pinned to a **stable** `vMAJOR.MINOR.PATCH+k3sBUILD` and `runtime.architecture: "x86_64"`.
2. An existing private (0700) SC-13b1 asset directory containing all five exact files with permissions 0600. `k3s.bin` holds the **unmodified raw upstream release `k3s` bytes**; `container-images.tar` holds the **uncompressed** upstream `k3s-airgap-images-amd64.tar` bytes. These renamed local paths are *not* official release asset filenames. The verifier requires that these bytes match the SC-12 plan pins.
3. An independently obtained, existing private (0600) `sha256sum-amd64.txt` file from the selected version and an existing private `k3s-airgap-images-amd64.sha256sum` from the **same** version. This code cannot establish that they were genuinely downloaded from K3s, that they correspond to the declared tag, or that GitHub/upstream accounts are untampered. Those are explicit operator-provenance tasks.

~~~bash
slipcage verify-k3s-upstream-checksums /private/operator-vm-plan.json \
  --assets-dir /private/private-five-assets \
  --binary-checksums /private/sha256sum-amd64.txt \
  --airgap-checksums /private/k3s-airgap-images-amd64.sha256sum \
  --json
~~~

For source review, select one **specific, not "latest"** release from GitHub and independently check that both files belong to exactly that release. The K3s release URL format is `https://github.com/k3s-io/k3s/releases/download/<version>/...`; the `+` in a tag may appear URL-encoded as `%2B`. **No URLs are constructed, fetched or trusted by the application.**

## Strict checks and limitations

- SC-13b1 rehashes **all five** fixed private asset files before the checksum comparison.
- The binary manifest must contain the exact literal upstream release filename `k3s`, and the archive manifest must contain the exact literal `k3s-airgap-images-amd64.tar`. The archive checksum file may additionally mention allowlisted `.tar.gz` and `.tar.zst` variants, but these are **not** accepted as substitutes for the required uncompressed tar.
- Input format is the strict LF-terminated, lowercase `sha256sum` text convention: `64hex  filename\n`. Files must be existing single-link regular private 0600 files, at most 8192 bytes, with no symlinks, duplicates, path traversal, binary-mode `*`, extra records, unsupported architectures or malformed entries.
- Exact checksum values must match the **SC-12 declared pins and newly checked local bytes**. The output hashes the complete two input manifest files, identifies the operator-declared tag and fixed upstream filename tokens, and reports asset byte counts without printing absolute paths or source-file bytes.
- A local match returns CLI **0**, meaning *only* byte/digest consistency across supplied local inputs. Invalid or unsafe input returns **2**, with no positive report. Both outputs are deterministic; no filesystem writes, host observations, processes, archive extraction or network activity.

All successful reports say `publisher_checksum_source_authenticated:false`, `release_tag_verified_against_upstream:false`, `upstream_release_signatures_verified:false`, `airgap_archive_contents_inspected:false`, `container_images_provenance_authenticated:false`, `cni_and_kernel_upstream_verified:false`, `execution_authorized:false`, `vm_launched:false`.

**These checksum text files are not signatures or transparency-log attestations.** An attacker controlling the checksum text *and* the local files can forge consistency. The verifier cannot independently check source origin, genuine release tag, upstream signing identity, CNI/kernel provenance, compressed file equivalence or air-gap tar contents. Private trusted ancestor directories and no same-UID hostile races remain preconditions; files are checked sequentially, not via an atomic snapshot.

## Optional use in the always-blocked SC-13b12 dossier

The existing `slipcage review-vm-launch-gates` also accepts **both together**, never singly:

~~~text
--k3s-binary-checksums /private/sha256sum-amd64.txt
--k3s-airgap-checksums /private/k3s-airgap-images-amd64.sha256sum
~~~

When provided, these inputs must pass the same strict checks in addition to all other dossier requirements. The dossier records two manifest digests and `k3s_release_checksums_checked:true`, while preserving `k3s_release_checksum_source_authenticated:false`, `execution_authorized:false` and **exit 5 (BLOCKED)**. When omitted, the optional check is explicitly `false`, with null digests; this never implies upstream authentication. Inconsistent/missing partial options fail exit 2.

## Tests and human-owned acceptance

GitHub CI tests only tiny invented asset bytes and synthetic `sha256sum` files in private ephemeral test directories. The fixtures are **not** actual K3s releases, K3s air-gap image archives, or verified publisher metadata. The tests reject altered hashes, uncompressed/compressed format confusion, unknown filenames/architectures, malformed data, symlinks, hardlinks, nonprivate files, synthetic plans, mismatched dossier inputs and any route to VM execution.

Real acceptance remains open under [Issue #23](https://github.com/soybeanfarmer/slipcage/issues/23): the owner must separately identify and verify **genuine** upstream signed release/publisher information, exact real local asset bytes, OS kernel/QEMU/CNI sources, actual VPS headroom, provider scope and usable KVM. [Issue #25](https://github.com/soybeanfarmer/slipcage/issues/25) still requires a reviewed true global lease, bounded overlay, OS watchdog/cleanup, guest isolation and explicitly authorized benign live validation.

**No merge, release, VPS SSH/probing, network action, QEMU/qemu-img, disk overlay, or VM launch is performed by this milestone.**
