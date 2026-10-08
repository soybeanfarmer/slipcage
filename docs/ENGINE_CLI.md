# Slipcage offline experiment contract engine — v0.12 first implementation

This includes SC-05/SC-06 contract validation, SC-07 typed results, SC-08 **synthetic** fixture execution, SC-09 private synthetic evidence bundles, SC-10 offline differential comparison, and SC-11 deterministic reporting and complete synthetic demonstrations. It is still a local-only Python package, not a real infrastructure security test runner. The existing Dagu research lab, QEMU guest tests, deployment and backups are unchanged.

## Install and run locally

Use Python 3.11+ and an isolated development environment:

~~~bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
slipcage --version
slipcage validate examples/experiments/rbac-pod-create-denied.yaml --json
python -m unittest discover -s tests -v
~~~

Expected JSON shape (digest value is computed, not shown as an illustrative constant):

~~~json
{
  "status": "valid",
  "api_version": "slipcage.dev/v1alpha1",
  "experiment_id": "kubernetes.rbac.pod-create-denied",
  "experiment_version": "0.1.0",
  "profile_id": "kubernetes.rbac",
  "digest_sha256": "<computed 64-character hex digest>",
  "executable": false
}
~~~

A successful validation returns exit code 0, invalid file/spec returns 2, and unavailable real-workload actions return 3. Usage errors are handled by argparse (2). `slipcage run`, `slipcage compare` and `slipcage report` are deliberately fail-closed until their own separately reviewed milestones.

## Supported definition subset

The bundled JSON Schema is the only supported `slipcage.dev/v1alpha1` contract for this release. It recognizes `SecurityExperiment`, reviewed-profile identifier **syntax** for `kubernetes.rbac` with one bounded `create_pod` operation, versioned metadata, parameters `namespace` and `subject`, and CPU-independent duration/artifact budgets.

- A namespace must use `slipcage-` prefix and a valid DNS-like lowercase name; a subject must be a valid lowercase name.
- The only allowed observations are `expected: denied` or `expected: allowed`; **neither is executed or verified yet**.
- Definitions are UTF-8, regular local `.yaml`, `.yml` or `.json` files of at most 64 KiB.
- Duplicate mapping keys, aliases, YAML merges/custom types, unknown keys, unknown versions and unsupported profiles fail closed. JSON nonfinite numbers fail closed.
- Between 1 and 8 assertions are accepted; duplicate assertion IDs are refused. Timeouts are 1–300 seconds and output budgets 1 KiB–8 MiB (these are future policy requests, *not* enforcement of a running process yet).
- The canonical SHA-256 is a content fingerprint, **not** a signature, approved-pack attestation, evidence of an execution, or authorization to run.

JSON and YAML versions of the same logical data produce the same fingerprint. No arbitrary dynamic code, shell expression, network target or execution adapter is exposed by this package. No cloud credentials or VPS addresses are needed.

## Typed assertion outcomes (SC-07, offline library only)

The `slipcage_engine.results` module defines immutable, typed outcomes tied to
a revalidated experiment specification and an explicitly declared assertion ID:

- `PASS`: a **claimed verified** observation matches the security expectation.
- `FAIL`: a **claimed verified** observation contradicts the expectation.
- `ERROR`: an execution or infrastructure failure prevented evaluation.
- `SKIP`: a required capability is explicitly unsupported.
- `INCONCLUSIVE`: the security observation is ambiguous or unverified.

The observer status is separate from the observed allowed/denied decision. Only
a `verified` observation may carry a typed decision. Unknown statuses, raw
strings such as `"403"`, conflicting result fields, undeclared assertion IDs,
and spoofed spec digests fail closed. This ensures that future adapters cannot
accidentally convert a timeout, unsupported environment or API error into a
security assertion PASS.

Example using **manually constructed offline fixture data**:

~~~python
from slipcage_engine import (
    load_spec, Observation, ObservationStatus, ObservedDecision,
    result_for_observation,
)

spec = load_spec("examples/experiments/rbac-pod-create-denied.yaml")
observation = Observation(ObservationStatus.VERIFIED, ObservedDecision.DENIED)
result = result_for_observation(spec, "restricted-create-pod", observation)
assert result.outcome.value == "PASS"
assert result.to_dict()["evidence_status"] == "not_collected"
~~~

**Important:** A caller can construct an `Observation(VERIFIED, ...)`. This
means the future trusted adapter *claims* it verified identity, request,
resource and response. SC-07 does not check those facts, authenticate any
artifact, contact Kubernetes, produce an evidence bundle, or make the result
replayable. The emitted `evidence_status: not_collected` is deliberate;
never present this purely synthetic result as a proven security boundary.
There is no CLI command to evaluate or produce these results yet.


## SC-08: bounded offline fixture execution

This release adds `slipcage run-fixture`, a **synthetic, local-only** interpreter
for a finite set of prepackaged RBAC observation fixtures. It runs no real
Kubernetes assertion, QEMU guest or external process. The `run`,
`compare` and `report` commands continue to refuse execution.

~~~bash
slipcage run-fixture examples/experiments/rbac-pod-create-denied.yaml --scenario denied --json
slipcage run-fixture examples/experiments/rbac-pod-create-denied.yaml --scenario allowed --json
~~~

The first command creates **synthetic PASS** data for the expected denial;
the second creates **synthetic FAIL** data and deliberately exits nonzero.
The only supported scenario names are `denied`, `allowed`, `ambiguous`,
`error`, and `unsupported`. Scenario names are an enum, not filesystem
paths, command strings or user-selected plugins.

Outputs include `mode: synthetic_offline_fixture`, `simulated: true`,
`security_test_executed: false`, and `evidence_status: not_collected`,
plus immutable assertion results and SHA-256 content fingerprints of the
validated specification and installed fixture bytes. Those hashes are not
evidence signatures and the fixtures' "verified" observations are **synthetic
claims**, not actual API verifications.

A single call handles at most eight schema-declared assertions with a
cooperative time deadline capped at five seconds and checks for a trusted
in-process cancellation request before and after each assertion. Expired
or cancelled calls leave unprocessed assertions absent; they cannot fabricate
a successful security run. This time budget is **not OS-enforced isolation**
and must be replaced by supervisor-enforced limits for real/blocking adapters.

CLI exit codes for `run-fixture`: 0 when all synthetic assertions PASS,
1 when any synthetic assertion is not PASS, 2 for invalid inputs or fixture
data, and 4 for cancellation/deadline termination. Validating a definition
still returns 0/2; unimplemented real `run`/`compare`/`report` return 3.

For deterministic fault-injection tests, the Python `run_fixture` API
accepts trusted `clock` and `cancelled` callables. Neither can be selected
by experiment YAML/JSON or the CLI. Future SC-09 evidence bundles and SC-10
comparison remain separately planned; do not call this an actual security
regression or attempt to promote it as a Kubernetes runner.


## SC-09: private synthetic evidence bundles (local only)

The engine now supports writing a **new** private evidence directory containing
canonical experiment input, simulated assertion results, fixture provenance,
SHA-256 checksums and a completion manifest. This is collection of **synthetic
fixture artifacts**, **not** security evidence from a live Kubernetes system.

~~~bash
python -m pip install -e .
slipcage bundle-fixture examples/experiments/rbac-pod-create-denied.yaml \
  --scenario denied --output ./my-new-private-bundle --json
slipcage verify-bundle ./my-new-private-bundle --json
~~~

The writer requires an existing trusted local parent directory. It refuses
overwriting any existing path, creates its child directory mode 0700 and files
mode 0600, and writes `manifest.json` **last**, so interrupted bundles remain
incomplete and preserved. No automatic deletion, cleanup, or replacement is
performed. A named symlink parent is rejected; intermediate ancestor paths
must still be trusted and controlled by the operator.

Example layout:

~~~text
my-new-private-bundle/
  experiment.json  # validated canonical definition
  results.json     # simulated fixture observations, never real API results
  provenance.json  # locally installed engine/fixture identifiers
  checksums.json   # sha256 checksums for the three content artifacts
  manifest.json    # COMPLETE marker, hashes catalog, timestamp; written last
~~~

`verify-bundle` is read-only and refuses incomplete bundles, unexpected
entries, symlinks, hard-linked/nonregular files, unsafe permissions, oversized
data, invalid/noncanonical JSON, digest changes, or inconsistent provenance.
It also replays the **installed packaged fixture** under the stored validated
spec and requires the results to match byte-for-byte.

Successful verification emits `verified_synthetic_bundle`,
`simulated: true`, `security_test_executed: false`, and
`real_security_evidence_verified: false`. Verification establishes
**local structural/checksum consistency and fixture replay only**. A malicious
party who can change files and checksums can forge an internally consistent
bundle: no signature, remote attestation, trusted timestamp, identity proof,
tenant access control, or Kubernetes API verification exists in SC-09.

`bundle-fixture` returns 0 for successfully published synthetic bundles
**regardless of PASS/FAIL/ERROR/SKIP/INCONCLUSIVE**, because its success is
*artifact creation*, not assertion success. Invalid or incomplete bundles
return 2. No generic file import, user-controlled logs, uploaded evidence,
Cloudflare R2, off-server backup, or OS-level execution sandbox is enabled.

## SC-10: conservative synthetic differential comparison

The new `slipcage compare-fixtures` command reads and re-verifies **two
existing private SC-09 synthetic bundles**. It never modifies either bundle
and does not launch experiments or collect real security evidence.

~~~bash
slipcage bundle-fixture examples/experiments/rbac-pod-create-denied.yaml \
  --scenario denied --output ./baseline-fixture --json
slipcage bundle-fixture examples/experiments/rbac-pod-create-denied.yaml \
  --scenario allowed --output ./candidate-fixture --json
slipcage compare-fixtures ./baseline-fixture ./candidate-fixture --json
~~~

That example produces `classification: regression` (a **synthetic** PASS
versus synthetic FAIL). Both bundles must independently pass private layout,
hash, spec and packaged-fixture replay checks, refer to different directory
objects, and match the **same exact experiment spec digest**, fixture digest
and assertion IDs/order. Different scenarios represent fixture test cases,
**not baseline and candidate K3s clusters**. The two bundles may share a
manifest digest if separately created with identical inputs in the same second:
file identity, not digest equality, controls the same-bundle check.

| Baseline | Candidate | Per-assertion classification |
| --- | --- | --- |
| PASS | PASS | `unchanged_pass` |
| PASS | FAIL | `regression` |
| FAIL | PASS | `improvement` |
| FAIL | FAIL | `unchanged_fail` |
| Any ERROR, SKIP or INCONCLUSIVE | Any, or vice versa | `incomparable` |

Missing, corrupted or incompatible bundles are always **incomparable**;
they never become observed regressions. The comparison emits a stable
`slipcage.dev/fixture-comparison/v1alpha1` JSON representation with per-
assertion classifications and a conservative aggregate. If an aggregate
contains both regression and improvement, it is `mixed_change`. If **any**
assertion is incomparable, the aggregate is incomparable even when other
assertions were comparable.

CLI exit codes for `compare-fixtures`:
- `0` — comparable with no regression (improvement or unchanged).
- `1` — comparable with a **synthetic regression present**, including mixed.
- `4` — incomparable (missing, invalid, incompatible or uncertain inputs).
- `2` — invalid command usage.

Importantly, the generic `slipcage compare`, `run` and `report` remain
**disabled** and return code 3. A successful synthetic comparison does not
verify real environment provenance, authorized Kubernetes behavior, evidence
authorship, or separate infrastructure isolation. Output explicitly states
`simulated: true`, `security_test_executed: false`, and
`real_security_evidence_verified: false`.

## SC-11: deterministic reports and integrated offline proof

SC-11 completes the first **synthetic, offline** end-to-end path:

1. Validate the strict v1alpha1 experiment specification.
2. Produce two separate private SC-09 packaged-fixture evidence bundles.
3. Reverify both and compare every declared assertion using SC-10.
4. Render stable machine-readable JSON and human-readable Markdown.
5. Publish a final demo manifest with SHA-256 hashes **after** both report files are written.
6. Independently reverify all sources and re-render both reports byte-for-byte.

### Read-only reporting from existing fixture bundles

~~~bash
slipcage report-fixtures ./baseline-fixture ./candidate-fixture --format json
slipcage report-fixtures ./baseline-fixture ./candidate-fixture --format markdown
~~~

This command checks both source bundles before rendering. **Same pair of
unmodified bundles yields identical report bytes**. Reports include exact
source manifest digests, so two newly generated bundles may differ in byte
content because their evidence creation timestamps differ; their semantic
assertion classification remains stable. Missing/corrupted/incompatible
source evidence returns an *incomparable* report, never a confirmed regression.

### One-command complete synthetic demonstration

Use an **existing, private (0700), operator-controlled output parent**.
No path is automatically cleaned or overwritten.

~~~bash
scratch="$(mktemp -d)"
slipcage demo-fixtures examples/experiments/rbac-pod-create-denied.yaml \
  --baseline-scenario denied --candidate-scenario allowed \
  --output "$scratch/proof" --json
slipcage verify-demo "$scratch/proof" --json
~~~

Both commands return **exit code 1** for this deliberately injected
synthetic PASS -> FAIL regression. A failed security assertion is not a failed
artifact-generation operation; code 1 distinguishes the detected synthetic
regression from code 4 for incomparable source evidence (report-fixtures), code
2 for invalid input or incomplete demo data, and code 0 for comparable cases
without a regression.

The proof directory has this fixed layout:

~~~text
proof/                         # private 0700, never overwritten
  baseline/                    # independently SC-09-verified synthetic bundle
  candidate/                   # independently SC-09-verified synthetic bundle
  report.json                  # canonical deterministic JSON, private 0600
  report.md                    # deterministic Markdown, private 0600
  manifest.json                # COMPLETE marker written last, private 0600
~~~

A partial failure leaves the directory and original evidence untouched but
cannot satisfy verify-demo. Verification rejects unknown entries, tampering,
unexpected permissions, symlinks, invalid bundles, mismatched source fingerprints
and report files that do not match independent rendering. Output remains
explicitly **synthetic**, without signed attestation, live Kubernetes observations
or true environment provenance.

**Real environment commands remain disabled:** slipcage run, slipcage compare,
and slipcage report exit 3. The offline fixture commands do not install on the
VPS through Ansible, boot QEMU/K3s, run untrusted scripts, or contact Cloudflare.
The next phase begins with pinned VM definitions and an independently approved,
bounded live-environment feasibility test.

## SC-12: offline pinned VM planning (no VM execution)

SC-12 adds a strict JSON-based, **non-executable** K3s VM intent, read-only
pin validation and an operator-reported capacity estimator.

~~~bash
slipcage plan-vm examples/vm-plans/k3s-synthetic-design.json \
  --inventory examples/vm-plans/host-capacity-synthetic.json --json
~~~

**Those inputs are synthetic tests, not real verified images or a live VPS
inventory.** The output always sets `execution_authorized: false`,
`artifacts_verified: false`, `kvm_verified_on_target_host: false`,
`k3s_boot_verified: false`, and `vm_launched: false`. Exit code 0 means
valid *design data only*; 2 means an invalid plan or reported inventory.
No QEMU binary is invoked, disk is created, network changed, or worker
installed. See [SC-12 guest pinning and feasibility](K3S_VM_FEASIBILITY.md)
for resource assumptions, missing real artifact proofs, and manual gates.

## SC-13a: pure in-memory VM lifecycle simulation

The SC-12 non-executable K3s VM plan can be fed to a deterministic state
machine that **does not** start any VM. The closed scenarios are success,
capacity_blocked, start_failure, runtime_failure, timeout, cancelled,
and cleanup_failure.

~~~bash
slipcage simulate-vm-lifecycle examples/vm-plans/k3s-synthetic-design.json --scenario success --json
slipcage simulate-vm-lifecycle examples/vm-plans/k3s-synthetic-design.json --scenario cleanup_failure --json
slipcage simulate-vm-pair examples/vm-plans/k3s-synthetic-design.json --baseline-scenario start_failure --candidate-scenario success --json
~~~

The model records deterministic bounded transitions with explicit simulated
cleanup outcomes. A failed or incompletely cleaned baseline blocks the
candidate entirely. **No real VM, guest disk, host network, or Kubernetes
assertion is executed.** Real cleanup verification and artifact provenance
are always marked false. Timeouts and resource admission are **simulated
transitions**, not enforced host supervision.

Exit code 0 denotes synthetic completion without a failure; 4 denotes a
synthetic start/runtime/deadline/cancellation/admission failure; 5 denotes
synthetic unresolved cleanup requiring review; 2 is invalid input.
The real run/compare/report commands remain unavailable with exit code 3.
See [SC-13a design and real-adapter prerequisites](VM_LIFECYCLE_DESIGN.md).

## SC-13b1 — Private local VM asset byte checking (not a guest runner)

The new `slipcage verify-vm-artifacts` command performs bounded, read-only
SHA-256 checks over five fixed private files supplied by the operator and
compares them to the SC-12 plan's declared pins:

~~~bash
slipcage verify-vm-artifacts /path/to/operator-plan.json \
  --directory /path/to/private-assets --json
~~~

It **rejects the repository's synthetic example plan**; it requires a
non-synthetic, but still *untrusted*, operator-supplied declaration. Matching
byte hashes do not authenticate software origin, inspect image/archive
contents, check provider authorization or start any QEMU guest. Outputs always
record `execution_authorized: false`, `vm_launched: false` and
`software_origin_authenticated: false`. This is a development-time check
only; Ansible does not install it on the VPS. See
[SC-13b1 limits and live VM prerequisites](VM_ASSET_PREFLIGHT.md).

## SC-13b2 — Offline signed-statement and host snapshot checks

Two read-only commands add prerequisites for any future disposable VM:

~~~bash
slipcage verify-vm-provenance /private/operator-plan.json --statement /private/statement.json --signature /private/statement.sig --public-key /private/trusted-key.raw --json
slipcage assess-vm-host /private/operator-plan.json --snapshot /private/host-snapshot.json --json
~~~

The first verifies an Ed25519 signature *against a supplied raw public key* bound to all five asset digests and the plan. **Publisher key identity must be trusted independently**; the command cannot establish that trust, revocation, or upstream release authenticity. The second checks the operator's declared host headroom and KVM/cgroup flags **without accessing the VPS**, and cannot establish actual measured host readiness. Both commands always report execution_authorized=false and vm_launched=false. See [SC-13b2 trust and host gates](VM_PROVENANCE_HOST_GATE.md).

## SC-13b3 — Explicit read-only Linux host observation

SC-13b3 provides a **manual, operator-invoked** `slipcage inspect-vm-host`
command. It reads bounded Linux memory, visible CPU count, nominated scratch
filesystem free space/inodes, and KVM-character-device/cgroup-v2 *presence*:

~~~bash
slipcage inspect-vm-host /path/to/operator-plan.json \
  --scratch-root /path/to/existing-approved-scratch-directory --json
~~~

**Do not run this on the VPS until separately authorized.** No operator
commands are executed by CI; unit tests use injected synthetic data and
mocked host counters. The tool never boots guests, opens /dev/kvm, connects
to the network, creates disks or changes host settings. Even a numerically
favorable observation reports provider permission, KVM usability, cgroup
quotas, active guest safety and execution authorization as **unverified/false**.
See [SC-13b3 limitations and operator review](VM_HOST_OBSERVATION.md).

## SC-13b4 — Incomplete QEMU launch blueprint (offline only)

The `slipcage plan-qemu` command produces a fixed, **paused and incomplete**
QEMU argument prefix from a validated, nonsynthetic SC-12 plan and checked
local asset bytes. It **does not start QEMU**, attach disks/kernels/NICs,
create an overlay or enforce any host process limits:

~~~bash
slipcage plan-qemu /path/to/operator-plan.json \
  --assets-dir /path/to/operator-private-assets --json
~~~

Its output always marks `argv_is_complete_launch_command: false`,
`execution_authorized: false`, `real_vm_launched: false` and host/runtime
verification false. The CLI rehashes supplied private assets, but actual
software publisher identity, host KVM and provider approval remain unverified.
**Do not manually execute the displayed prefix**. The real launch library
unconditionally refuses. See [SC-13b4 incomplete blueprint](QEMU_BLUEPRINT.md)
and open runtime prerequisites under Issues #23 and #25.

## SC-13b5 — Offline supervisor budgets and crash fencing

The new `slipcage simulate-vm-supervision` and
`slipcage simulate-vm-supervision-pair` commands exercise a pure in-memory
resource/deadline and single-owner lease model using a nonsynthetic SC-12 plan
and read-only local asset checks:

~~~bash
slipcage simulate-vm-supervision /path/to/development-plan.json \
  --assets-dir /path/to/private-assets --scenario cleanup_failure --json
~~~

The model rejects stale revisions, overlapping attempts, invalid state
transitions, deadline and simulated resource breaches. A crash or failed
cleanup **quarantines** the simulated attempt and blocks subsequent attempts
without automatic clearance. The budget and journal are **not backed by
systemd, cgroups, disk quotas, process watchdogs or persistent OS locks**.
No guest is started and no disk is written. See
[SC-13b5 lifecycle supervision contract](VM_SUPERVISION_CONTRACT.md).

## Deployment boundary

Neither `pyproject.toml` nor the new CLI is installed on the VPS by `playbooks/site.yml`. Existing production behavior is unchanged even if the source commit is released via the standard pull mechanism. **Never interpret an installed importable package or a successful validation as a successfully completed Kubernetes experiment.**

CI now installs the package in the ephemeral GitHub runner, validates the sample and executes unit tests. The release workflow does the same pre-publication. These checks do not start QEMU, K3s, systemd units, external webhooks or any research workloads.

## Next separately approved milestones

SC-07 and SC-08 establish typed outcomes and offline synthetic fixtures; SC-09 introduces locally verified synthetic bundles; SC-10 adds synthetic, evidence-gated differential comparison; SC-11 provides offline synthetic reports and a complete reproducible fixture demonstration. SC-12 adds non-executable VM design validation, without measured host capability or genuine image/cluster evidence. Real environment execution, evidence and comparison require separately authorized later milestones. Real environment evidence and signed/hosted provenance are later, separately approved work. No hosted worker, arbitrary user code or VM workloads should be added before separate authorization.

See [contract](EXPERIMENT_CONTRACT.md), [roadmap](V1_ROADMAP.md), [security rules](../SECURITY.md) and [human review/release gates](DEVELOPMENT_WORKFLOW.md).
