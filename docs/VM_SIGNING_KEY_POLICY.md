# SC-13b13 — Offline signing-key pin and scoped revocation policy

**Status: local consistency only.** This check does **not** authenticate a real publisher, verify that a policy came from an independent trusted source, check current upstream revocation/transparency data, or authorize any VM.

SC-13b2 verifies a valid Ed25519 detached statement against a **supplied** raw public key. A forged statement signed by an attacker's own key could pass that step if the attacker also replaces the key file. SC-13b13 adds a **second explicit local policy input** with an expected public-key SHA-256 fingerprint, exact release and signed-statement digest, exact SC-12 plan digest and an allowlisted sorted denylist of revoked key fingerprints.

An independent human must obtain and authenticate the expected publisher fingerprint and revocation information through a trusted external channel. This tool cannot do that. **If someone controls the policy and the key, they can replace both and produce a passing local check**. This is not certificate-chain validation, a vendor-signed trust root, or a transparency-log check.

## Private operator-supplied policy

The policy is a **preexisting canonical JSON file** (exact file mode 0600, regular single-link file, no symlinks, max 4096 bytes), with exactly these fields:

~~~json
{
  "allowed_key_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "api_version": "slipcage.dev/vm-key-pin-policy/v1alpha1",
  "plan_digest_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "policy_origin": "operator_supplied_unverified",
  "release_id": "example-release",
  "revoked_key_sha256": [],
  "source_label": "operator-described-upstream",
  "statement_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
}
~~~

*These are example digest placeholders, not actual upstream keys or releases.* The real file must be serialized as canonical compact sorted-key JSON with no trailing newline. It must never include private signing keys or credentials. The denylist must be lexically sorted, contain at most 32 unique lowercase hex digests, and must not include the expected signing key. A list of zero revoked keys only means **none were supplied**; it does not mean no keys have been revoked upstream.

With separately obtained files already present on the local development machine, run:

~~~bash
slipcage verify-vm-signing-policy /private/operator-plan.json \
  --statement /private/signed-statement.json \
  --signature /private/detached.sig \
  --public-key /private/supplied-ed25519-pub.raw \
  --key-policy /private/operator-key-policy.json --json
~~~

The command reuses existing SC-13b2 detached signature + five-artifact-digest coverage validation, requires an exact match to the **caller-supplied policy** across the release ID, plan digest, statement SHA-256 and raw public-key fingerprint, and fails closed if the key is on the local denylist. It reads no network or host state and creates no files.

Exit **0** means *the signed statement and operator-supplied pin policy agree*; it does **not** mean trusted publisher identity or artifact authenticity. Exit **2** means invalid signature, wrong pin/release, revoked-key listing, malformed policy or unsafe file. It never returns launch authorization.

## Integration with the ALWAYS-BLOCKED dossier

The existing SC-13b12 `review-vm-launch-gates` also accepts an **optional** `--key-policy /private/operator-key-policy.json`. When present, it must pass all the above validations *and* match the same signed statement and plan used by the dossier. Otherwise, the dossier fails with input error exit **2**. A coherent policy adds its SHA-256 and `operator_key_pin_consistency_checked: true` to the dossier, but the dossier **still returns exit 5 and `execution_authorized: false`**. With no policy supplied, `operator_key_policy_sha256: null` and `operator_key_pin_consistency_checked: false`. Neither path sets `policy_identity_authenticated_out_of_band` to true.

The old no-policy invocation remains supported for backwards compatibility, **not** as evidence of an authenticated key. It still reports the unresolved publisher-identity blocker. This does not upgrade SC-13b12 into a live launch readiness checker. All other supply-chain, VPS/cgroup/KVM/provider, image structural integrity, network isolation, resource-supervision and human authorization gates remain open.

## Threat boundary and tests

The code uses read-only no-follow opens and basic fd/inode/mode checks for the fixed private policy file and re-reads the signed statement to avoid accepting a mismatched **file** in a non-atomic multi-path inspection. Inputs are not locked into one atomic snapshot. Trusted directory ancestors and protection against hostile same-UID filesystem replacements are **not provided**. A SHA-256 over a caller-controlled policy is a content fingerprint, not proof of external authenticity or current revocation state.

GitHub tests generate throwaway Ed25519 keys, synthetic nonbootable host/VM artifacts and private ephemeral policy files. They exercise replaced signer keys, matched replacement policies (which **must not** claim authentication), revoked keys, swapped releases/plans/statements, invalid signatures, malformed canonical JSON, duplicate keys, modes/symlinks/hardlinks, policy bounds and unchanged VM execution blocks. No production artifacts or genuine vendor fingerprints are bundled.

Full [Issue #23](https://github.com/soybeanfarmer/slipcage/issues/23) remains pending actual publisher/source authentication and verified real asset bytes and current VPS readiness. [Issue #25](https://github.com/soybeanfarmer/slipcage/issues/25) remains pending a separate authorized real guest adapter, genuinely host-global lease/OS supervision, immutable backing image, private overlay, isolation and live cleanup evidence.

**No VPS inspection, SSH, VM boot, QEMU/qemu-img, network call, release publication or deployment is approved or performed by this change.**
