# SC-13b10 — Durable *offline* attempt IDs and fencing generations

**Scope: explicit development-only local filesystem writes and cross-process tests. Not a host-global VM lease, authorization to run a guest, proof of cleanup, or production service.**

SC-13b9 already introduced a real Linux advisory lock during a single recovery inspection. SC-13b10 adds **append-only, hash-chained, monotonically numbered intent records** under a *separate* pre-existing, operator-controlled private (0700) directory. Its Linux `fcntl.flock(LOCK_EX|LOCK_NB)` coordinates cooperating writers to that **same root** during each short operation. No lock is held for a QEMU/guest process.

The journal's public statuses refer to **offline intentions only**. A successful, hash-consistent record does not authenticate an operator, measure the host, validate a disk image, certify cleanup, confer a live execution lease, or grant VM launch permission.

## Manual developer CLI

Never run these commands on VPS/production paths as a consequence of PR review, CI or merging. Pick an **already-existing empty private local development root**, separate from the SC-13b6 reservation root. No parent directories are created.

~~~bash
slipcage stage-offline-vm-generation /path/to/operator-style-plan.json \
  --root /private/development-fence-root --attempt baseline \
  --expected-generation 0 --json

slipcage inspect-offline-vm-generations /private/development-fence-root --json
~~~

The stage command requires a nonsynthetic, strictly validated SC-12 plan and records its digest. The digest is **operator-supplied**, not authenticated release provenance. The first issue creates only an empty `.offline-fence.lock` (0600) and canonical `generation-00000001.json` (0600), using exclusive create and fsync for durability. The lock persists even when unlocked and is never unlinked or rewritten. Inspection reads under the same scoped lock but does not write.

An outstanding generation **blocks every subsequent issue**. To exercise a new offline identity, a developer must append an explicit resolution tied to the exact generation, attempt ID, and issue record SHA-256:

~~~bash
slipcage resolve-offline-vm-generation /private/development-fence-root \
  --attempt baseline --generation 1 --issue-sha256 EXACT_ISSUE_RECORD_SHA256 \
  --resolution offline_intent_abandoned_not_vm_cleanup --json

slipcage stage-offline-vm-generation /path/to/operator-style-plan.json \
  --root /private/development-fence-root --attempt candidate \
  --expected-generation 1 --json
~~~

This **offline abandonment does not verify host or guest cleanup**. It is merely a caller-declared end to an intent which this engine **cannot execute**; it must NEVER be reused as a real VM cleanup/lease release signal. A second allowed resolution, `unresolved_quarantine`, is terminal: no further generations may be issued, and no automatic clearance exists.

## Fixed journal format and fail-closed rules

An example private root layout after an offline abandonment and second issued generation:

~~~text
private-offline-journal-root/       # existing operator-controlled 0700 local directory
  .offline-fence.lock              # persistent empty 0600 regular single-link file
  generation-00000001.json         # exclusive canonical issue event
  resolution-00000001.json         # exclusive canonical abandoned intent marker
  generation-00000002.json         # next issue event, links previous resolution SHA-256
~~~

There can be at most **16 generations** and **32 immutable event files**, all private 0600, bounded to 2 KiB, no symlinks or hardlinks. Every generation has a strictly increasing sequence number, a unique bounded attempt ID, an exact SC-12 plan digest, `execution_enabled: false` and the prior resolution record's SHA-256 (or all-zero genesis digest). Every resolution references the issue's SHA-256, generation, owner and exactly one of the two typed resolutions. Duplicate keys, altered bytes, unexpected file types/names, gaps, missing prior resolutions, orphaned resolution records, reused attempt IDs, stale generation counters and excessive entries fail closed.

The tool **never deletes, overwrites, repairs or clears anything**, even if an exclusive creation fails midway. A partial/truncated record remains and blocks subsequent operations for operator review. This is a local integrity check, not an append-only medium protected from a same-UID adversary able to rewrite both events; trusted ancestors, operator-exclusive directory ownership and a local POSIX filesystem are required.

Exit statuses: **0** for a consistent offline snapshot (including outstanding or caller-declared abandoned intent), **5** for a held lock or a valid terminal quarantine, and **2** for malformed/untrusted/incomplete inputs. A return of 0 never means VM readiness or permission. No production `run`, `compare`, `report` capability is enabled.

All output explicitly reports `host_global_execution_lease: false`, `guest_process_fenced: false`, `actual_guest_cleanup_verified: false`, `operator_identity_authenticated: false`, `software_provenance_authenticated: false`, `qemu_or_overlay_created: false`, `execution_authorized: false`, `vm_launched: false`. A local lock protects only cooperating short journal operations, not host-wide VM admission or process lifetime.

## CI and remaining human gates

CI tests create private **ephemeral** roots and fabricated, nonsynthetic-*shaped* SC-12 plans, then test actual separate-process advisory lock contention, abrupt process exit with an outstanding intent retained, mutation/replay/hash-chain detection, torn writes, unknown entries, unsafe file modes, symlinks, hardlinks, stale attempts/generations, permanent quarantine and no VM or network launch. The test harness alone removes its own temporary directories.

[Issue #23](https://github.com/soybeanfarmer/slipcage/issues/23) remains open for independently authenticated real OS/kernel/K3s/QEMU artifacts and owner-approved fresh VPS capacity, provider permission and usable KVM evidence. [Issue #25](https://github.com/soybeanfarmer/slipcage/issues/25) still requires a genuinely host-global, OS-enforced guest lease across service roots, durable process identity and fencing, *actual* exclusively created bounded QCOW2 overlay with immutable verified base, enforced cgroups/watchdog, isolated guest network, verified crash recovery and an owner-approved bounded single-VM validation.

**This PR does not release, SSH, deploy, inspect the VPS, create an overlay, run qemu-img/QEMU, or modify existing production SQLite/reports/backups.**

## SC-13b11 — Binding a fake process safety policy to an outstanding offline attempt

The [process supervision fake-observation model](VM_PROCESS_SUPERVISION_SAFETY.md) can consume the **verified current outstanding** SC-13b10 journal snapshot and enforce its expected plan/attempt/generation digest in memory, but never binds the ledger to a live child PID, host-global lock or cleanup verifier. Abandoned/quarantined offline intents are rejected. Real VM fencing and signal/reap remain unimplemented.
