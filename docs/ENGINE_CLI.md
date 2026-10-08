# Slipcage offline experiment contract engine — v0.12 first implementation

This includes SC-05/SC-06 contract validation, SC-07 typed results, and SC-08 **synthetic** fixture execution. It is still a local-only Python package, not a real infrastructure security test runner. The existing Dagu research lab, QEMU guest tests, deployment and backups are unchanged.

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

A successful validation returns exit code 0, invalid file/spec returns 2, and every unavailable action returns 3. Usage errors are handled by argparse (2). `slipcage run`, `slipcage compare` and `slipcage report` are deliberately fail-closed until their own separately reviewed milestones.

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

## Deployment boundary

Neither `pyproject.toml` nor the new CLI is installed on the VPS by `playbooks/site.yml`. Existing production behavior is unchanged even if the source commit is released via the standard pull mechanism. **Never interpret an installed importable package or a successful validation as a successfully completed Kubernetes experiment.**

CI now installs the package in the ephemeral GitHub runner, validates the sample and executes unit tests. The release workflow does the same pre-publication. These checks do not start QEMU, K3s, systemd units, external webhooks or any research workloads.

## Next separately approved milestones

SC-07 and SC-08 establish typed outcomes and offline synthetic fixtures; SC-09 introduces canonical evidence bundles; SC-10 differential comparison; SC-11 reporting. No hosted worker, arbitrary user code or VM workloads should be added before separate authorization.

See [contract](EXPERIMENT_CONTRACT.md), [roadmap](V1_ROADMAP.md), [security rules](../SECURITY.md) and [human review/release gates](DEVELOPMENT_WORKFLOW.md).
