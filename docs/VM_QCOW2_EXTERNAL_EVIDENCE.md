# SC-13b17 — Read-only reconciliation of operator-supplied `qemu-img` info/check evidence

**This command does not execute `qemu-img` or authenticate its output.** A consistent local report is **operator-supplied and untrusted**, cannot prove that a tool ran, cannot establish comprehensive QCOW2 integrity or actual immutable backing, and never authorizes QEMU/VM execution.

The previous SC-13b16 metadata scanner deliberately accepts only a small 64-MiB physical subset. Real QCOW2 images often exceed that bound and require a mature format-aware checker. QEMU publishes `qemu-img info --output=json` and `qemu-img check --output=json`. The `check` JSON conforms to QAPI `ImageCheck`, including `check-errors` and optional `corruptions`, `leaks` and `*-fixed` fields. The official [QEMU qemu-img manual](https://www.qemu.org/docs/master/tools/qemu-img.html) states that `check -r` attempts repair and exit codes 1/2/3/63 represent incomplete, corrupt, leaked and unsupported checks. Accordingly, this milestone **refuses** any recorded repair mode, fixes, nonzero check errors, leaks or corruptions. [QEMU QMP schema](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html) documents the JSON fields.

The operator must acquire any real tool output in a **separate, explicitly approved offline workspace**, after independent authentication of the QEMU binary and assessment of any tool effects. **Merging this PR is not permission to run qemu-img on a VPS, production image or network filesystem.** This code never invokes external programs.

## Existing private inputs

~~~bash
slipcage review-vm-qcow2-external-evidence /private/operator-plan.json \
  --assets-dir /private/existing-five-assets \
  --evidence-dir /private/operator-qemu-evidence --json
~~~

The asset directory must contain the exact private SC-13b1 five-file set; all five bytes-on-disk hashes are checked against a nonsynthetic SC-12 plan. The base `os-image.qcow2` must also pass the existing **read-only SC-13b7 fixed QCOW2 header preflight and independently rechecked SHA-256**. The evidence directory must be existing mode 0700 and contain exactly three fixed mode-0600 single-link regular files, each bounded to 16 KiB:

- `info.json` — the raw bounded QEMU `ImageInfo` JSON bytes for the fixed name `os-image.qcow2`; whitespace/pretty printing and a final newline are allowed.
- `check.json` — raw bounded `ImageCheck` JSON bytes for exactly the same image; errors, leaks, corruptions and fixed items must all be zero or omitted where the QAPI field is optional.
- `capture.json` — **canonical compact sorted-key JSON** with an operator-declared QEMU version, QEMU binary SHA-256, exact plan/base SHA-256 and file size, both raw JSON-file digests, both reported exit codes, and strictly fixed non-repair command arrays.

The two command arrays in `capture.json` are exactly:

~~~json
["qemu-img","info","--output=json","-f","qcow2","os-image.qcow2"]
~~~

~~~json
["qemu-img","check","--output=json","-f","qcow2","os-image.qcow2"]
~~~

The command arrays are **data only** and are never executed by Slipcage. No `-r`, `-U`, `--image-opts`, paths, shell operators, alternative image format, user-supplied arguments or `qemu-img create` are accepted. The working directory for an independently authorized operator collection would have to be an isolated private copy of the asset directory.

`capture.json` has exactly these 14 fields:

~~~text
api_version                 = "slipcage.dev/qcow2-external-evidence/v1alpha1"
capture_kind                = "declared_qemu_img_read_only_info_check"
capture_origin              = "operator_supplied_unverified"
plan_digest_sha256           = exact SC-12 digest
base_sha256                  = exact existing os-image.qcow2 SHA-256
base_size_bytes              = existing base file length
qemu_img_version             = exact SC-12 plan runtime.qemu_version
qemu_img_binary_sha256       = bounded lowercase 64-character hex (caller-declared)
info_command                = fixed string array above
check_command               = fixed string array above
info_exit_code              = integer 0
check_exit_code             = integer 0
info_output_sha256          = SHA-256 of exact info.json bytes
check_output_sha256         = SHA-256 of exact check.json bytes
~~~

The source reports may be QEMU-pretty-printed; digest the **exact saved bytes**, not a reserialized form. Duplicate JSON fields, unknown QAPI keys, nonfinite numbers, unsafe file permissions, symlinks, hardlinks, changed file identities, absolute or divergent image filenames, unsupported format-specific fields, backing-reference fields, encryption, compression, dirty flags, snapshots, nonzero repairs, bad counters or inconsistent sizes fail closed.

The narrow allowlist is deliberately **not a general QAPI parser**: optional/unrecognized QEMU fields and genuine format variants may require human review, but are never silently trusted. `ImageInfo` is required to explicitly report a qcow2 format, 64-KiB cluster size, correct virtual disk size, no snapshots/dirty/encryption/compression, and conservative bounded actual size. Optional qcow2 `format-specific` is permitted only for basic version `1.1`, 16-bit refcounts, no dirty/corrupt/lazy flags, and no bitmaps/other features.

## Output and guarantees

A coherent local report returns CLI exit **5** with `status: "operator_qemu_report_consistent_but_untrusted"`. An invalid, unsupported or mismatched file returns **2**, with no positive report. It never returns `launch_ready` or a host approval. JSON reports contain only bounded plan/base/transcript hashes, declared version, false trust flags and zero *operator-reported* integrity counts; they do not disclose input filenames/paths, arbitrary diagnostic strings, or reporter host data.

All successful reports explicitly set `external_qemu_img_executed_by_this_command: false`, `external_qemu_img_execution_attested: false`, `reported_qemu_img_binary_authenticated: false`, `operator_report_authenticity_verified: false`, `qcow2_full_metadata_independently_verified: false`, `immutable_backing_chain_verified: false`, `guest_execution_authorized: false`, `host_modified: false`.

A forger can create matching `capture.json`, `info.json` and `check.json` with false zero-error claims. Binding these inputs to the actual SHA-256 of local bytes **does not bind a real QEMU execution**. Input validation does not certify the qemu-img binary, its run environment, its return codes, that the file was unchanged while an external command ran, or that the report is complete. Reported zero corruptions are not guest content authenticity or runtime safety.

## Optional ALWAYS-BLOCKED dossier integration

`slipcage review-vm-launch-gates` accepts optional `--qcow2-evidence-dir /private/operator-qemu-evidence` and independently runs this **same read-only transcript consistency** check before returning its usual result. Valid transcripts add their capture fingerprint, `qcow2_external_reports_locally_checked:true` and `qcow2_external_check_execution_attested:false`; the dossier **still returns exit 5**, with full QCOW2 verification and launch authorization explicitly false. Invalid transcripts fail exit 2. The option does not change existing required inputs or the original header-only gate.

CI uses a tiny **nonbootable header-shaped image** and hand-built zero-error QAPI-style JSON, with tests deliberately showing that forged-clean reports can pass *local consistency* and never prove execution. Tests cover missing/unsafe files, fake repairs, mismatched image, replay/plan identity, wrong tool version, inconsistent counters, nonrepair argv, pretty JSON and no subprocess or network calls.

Real acceptance remains blocked in [Issue #23](https://github.com/soybeanfarmer/slipcage/issues/23) and [Issue #25](https://github.com/soybeanfarmer/slipcage/issues/25). The next meaningful human step is **genuine independently trusted QEMU and image bytes and explicitly authorized external read-only validation evidence**, followed by separately reviewed host/global-lease/overlay/guest runtime work.

**No release, VPS/SSH action, live VM test, qemu-img call, QEMU boot, disk repair or overlay creation is performed in this PR.**
