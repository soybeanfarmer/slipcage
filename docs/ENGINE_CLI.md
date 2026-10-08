# Slipcage offline experiment contract engine — v0.12 first implementation

This is the **first coded product-facing milestone** (SC-05/SC-06 foundation). It is intentionally a small, local, non-executing Python package. The existing Dagu research lab, QEMU guest tests, deployment and backups are unchanged.

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

## Deployment boundary

Neither `pyproject.toml` nor the new CLI is installed on the VPS by `playbooks/site.yml`. Existing production behavior is unchanged even if the source commit is released via the standard pull mechanism. **Never interpret an installed importable package or a successful validation as a successfully completed Kubernetes experiment.**

CI now installs the package in the ephemeral GitHub runner, validates the sample and executes unit tests. The release workflow does the same pre-publication. These checks do not start QEMU, K3s, systemd units, external webhooks or any research workloads.

## Next separately approved milestones

SC-07 introduces typed security assertion outcomes; SC-08 a bounded, offline fixture executor; SC-09 canonical evidence bundles; SC-10 differential comparison; SC-11 reporting. No hosted worker, arbitrary user code or VM workloads should be added before separate authorization.

See [contract](EXPERIMENT_CONTRACT.md), [roadmap](V1_ROADMAP.md), [security rules](../SECURITY.md) and [human review/release gates](DEVELOPMENT_WORKFLOW.md).
