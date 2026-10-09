# SC-13b12 — Cross-checked offline VM launch prerequisite dossier

**Status: BLOCKED. This is an entirely read-only verification aid, not a QEMU launch permit, real host readiness certificate, or VM deployment.**

Earlier SC-12/SC-13 slices built separate read-only checks for typed VM plans, local artifact bytes, detached Ed25519 signatures, operator-declared host inventory, strict QCOW2 base-header shape, private staging markers, and an offline attempt journal. SC-13b12 connects these checks into **one reproducible local review**, refusing mismatched identities rather than promoting any single check's success to authority.

## Usage — an existing local development workspace only

~~~bash
slipcage review-vm-launch-gates /private/operator-plan.json \
  --assets-dir /private/existing-assets \
  --statement /private/provenance.json \
  --signature /private/provenance.sig \
  --public-key /private/supplied-ed25519-key.raw \
  --host-snapshot /private/operator-unverified-host-snapshot.json \
  --reservation-root /private/existing-nonquarantined-stage \
  --journal-root /private/existing-outstanding-offline-intent \
  --json
~~~

Every input is **required**. This command does **not** create a reservation, issue a generation, write a dossier, build an overlay, inspect the running host, invoke QEMU, or alter existing files. It only rehashes locally supplied existing asset files, parses locally supplied evidence, and reads the fixed private staging and journal files under the existing short-lived local advisory lock.

- The SC-12 plan must be nonsynthetic with exact validated canonical identity.
- SC-13b1 must rehash all **five** local private files against the supplied plan declarations.
- SC-13b2 must verify a detached statement signature against the **supplied** Ed25519 public key and check it covers the exact plan and all five asset digests. **The key is NOT authenticated as belonging to the publisher**: any person can generate a matching key and signature.
- SC-13b2 host snapshot must be valid, bound to the plan, and evaluated against declared CPU, RAM, free-disk/inode, KVM, cgroup, active-guest and provider-scope thresholds. **Numbers and reported permissions are neither authenticated nor freshly observed here.**
- SC-13b6 reservation must be canonical, complete, non-quarantined, bound to the exact plan, and the staged overlay name/budgets must match SC-12. SC-13b7 rehashes the QCOW2 base and checks its narrow v3 header-shape constraints; **the full refcount/L1/L2 graph, content and actual immutable backing chain are NOT verified**.
- SC-13b8 recovery review must see the same intact reservation and **no unexpected overlay node** at inspection time. The absence of a node does not prove that a QEMU process was stopped or that the filesystem state remains unchanged.
- SC-13b10 offline journal must have an **outstanding** attempt ID identical to the reservation owner, exact plan digest, generation and issue hash. The read lock protects only journal inspection, **not a guest's process lifetime or a host-global execution slot**.

An invalid signature, mismatched digest, synthetic plan, corrupt or quarantined record, missing/unsafe file, unexpected overlay entry, resolved/offline-quarantined journal, or mismatched owner fails closed (exit **2**, no success dossier). A valid but insufficient reported capacity also stays **blocked**; its specific reported deficiencies appear as blockers.

## Output and exit behavior

A successful *local consistency* review always emits `status: "blocked_no_execution_permission"`, `execution_authorized: false`, and CLI exit **5**. Even with every supplied local input matching, the following hard runtime gates remain open:

1. Publisher/public-key identity and guest image/software authenticity are not independently established.
2. Operator snapshot freshness/authenticity, real usable KVM and provider permission are not independently verified.
3. Target-host cgroup limits, other services and single guest slot are neither checked nor reserved.
4. Full QCOW2 structural validity, immutable backing chain and real disposable overlay are unverified/not implemented.
5. Host-global VM admission, pidfd/process isolation, OS watchdog/quotas/cleanup and guest network isolation are not implemented or validated.
6. No separately approved human live-VM test authorization exists.

For privacy the deterministic dossier contains only bounded plan/statement/key/snapshot/reservation/attempt/base SHA-256 identities, reported capacity outcome and **blocker codes**. It does not dump raw host inventory, arbitrary host paths, keys, signature material or commands. It is not a tamper-proof attestation; a same-UID adversary can replace caller-controlled inputs. These eight sources are inspected sequentially, not frozen in a single atomic filesystem snapshot, so an actively mutating workspace also lies outside the claim.

No API or flag in this change can transition the output into `launch_ready`. A successful signature against a developer-created key, a passing reported host snapshot and a fake QCOW2 header **must still block**. The only path to real execution goes through separately reviewed code, trusted live evidence and explicit owner permission.

## CI, ownership, and remaining acceptance

The 21 new SC-13b12 tests use only tiny fake QCOW2-header data, fabricated OS/kernel/K3s assets, a throwaway Ed25519 key, invented host metrics, a private test reservation and offline journal. Tests prove matching/mismatching local declarations, signature coverage, quarantine and no inadvertent filesystem/process/network mutation. They **do not** verify the publisher, inspect the VPS, or run VM software.

The necessary real prerequisites remain in [Issue #23](https://github.com/soybeanfarmer/slipcage/issues/23) (authentic software pins, current owner-approved provider/host/KVM evidence) and [Issue #25](https://github.com/soybeanfarmer/slipcage/issues/25) (actual OS-backed host-global lease, private bounded overlay/immutable base, pidfd/group-aware supervision, isolation, safe crash reconciliation and an explicitly owner-approved benign guest test). Any release, merge, VPS operations and VM boot remain separate human-controlled actions.

**No release, remote call, VPS inspection, SSH, deployment, image creation, network change, subprocess, or QEMU launch is made by this PR.**
